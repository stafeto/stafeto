// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The package file. A container `STAFPKG1` version 1 with the layout of the
//! boot image, then a trailer page:
//!
//! ```text
//! file 0  "meta"      text (see `meta`), at most 4 KiB
//! file 1  "rootfs"    a STAFROOT version 2 table; its file numbers are
//!                     the numbers of the container's files
//! file 2  "manifest"  text (see `manifest`)
//! file 3.. "3", "4", ... the contents; a file's name is its number
//! trailer: one 4 096-byte page, the signature block (`sig`) and zeros
//! ```
//!
//! `Package::parse` checks every rule of the layout and nothing needs the
//! clock or the keys; `verify` hashes the covered bytes and asks the trust.

use crate::manifest::Manifest;
use crate::meta::{self, Meta};
use crate::sig::{BLOCK_SIZE, Block, Kind};
use crate::{Error, PACKAGE, Revocation, Signer, Trust, sha, trust};
use bootimg::rootfs::Rootfs;
use bootimg::{BootImage, PAGE_SIZE};

/// The trailer page.
pub const TRAILER_SIZE: usize = PAGE_SIZE as usize;
/// The most entries in `rootfs`: half of what the table format allows, the
/// rest is for the base and the other layers.
pub const ENTRIES_MAX: usize = 1024;
/// The content files are at most as many as the entries.
const FILES_MAX: u32 = 3 + ENTRIES_MAX as u32;
const NOT_REFERENCED_WORDS: usize = (FILES_MAX as usize).div_ceil(64);

#[derive(Debug, Clone, Copy)]
pub struct Package<'a> {
    bytes: &'a [u8],
    pub image: BootImage<'a>,
    pub rootfs: Rootfs<'a>,
    pub meta: Meta<'a>,
    pub manifest: Manifest<'a>,
    pub trailer: Block,
    covered: usize,
}

fn text_of<'a>(bytes: &'a [u8], what: &'static str) -> Result<&'a str, Error> {
    core::str::from_utf8(bytes).map_err(|_| Error::BadLayout(what))
}

impl<'a> Package<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Package<'a>, Error> {
        let len = bytes.len();
        if !len.is_multiple_of(TRAILER_SIZE) || len < 2 * TRAILER_SIZE {
            return Err(Error::BadLayout(
                "the length is not whole pages, two at least",
            ));
        }
        let covered = len - TRAILER_SIZE;
        let tail = &bytes[covered..];
        let trailer = Block::parse(tail)?;
        if tail[BLOCK_SIZE..].iter().any(|&b| b != 0) {
            return Err(Error::BadTrailer);
        }
        if trailer.kind != Kind::Package {
            return Err(Error::WrongKind);
        }
        if trailer.covered != covered as u64 {
            return Err(Error::LengthMismatch);
        }
        // The reader of the table looks for a repeated name among all the
        // files before, so the number of files is bounded before it runs.
        if covered < 16 || crate::u32_at(bytes, 12) > FILES_MAX {
            return Err(Error::BadLayout(
                "more content files than entries are allowed",
            ));
        }
        let image = BootImage::parse_as(&bytes[..covered], &PACKAGE).map_err(Error::Container)?;
        let count = image.count();
        if count < 3 {
            return Err(Error::BadLayout("fewer than three files"));
        }
        if count > FILES_MAX {
            return Err(Error::BadLayout(
                "more content files than entries are allowed",
            ));
        }
        let mut last_end = 0;
        for (n, file) in image.files().enumerate() {
            let want: &[u8] = match n {
                0 => b"meta",
                1 => b"rootfs",
                2 => b"manifest",
                _ => &[],
            };
            let ok = if n < 3 {
                file.name.as_bytes() == want
            } else {
                file.name.bytes().all(|c| c.is_ascii_digit())
                    && crate::text::decimal(file.name) == Some(n as u64)
            };
            if !ok {
                return Err(Error::BadLayout("a file has not the name of its place"));
            }
            last_end = file.offset + file.data.len() as u64;
        }
        if last_end.next_multiple_of(PAGE_SIZE) != covered as u64 {
            return Err(Error::BadLayout("pages after the last file"));
        }
        let file = |n: u32| image.file_at(n).expect("count checked").data;
        if file(0).len() > meta::FILE_MAX {
            return Err(Error::BadLayout("meta is over 4 KiB"));
        }
        let rootfs = Rootfs::parse(file(1), count).map_err(Error::Rootfs)?;
        if rootfs.len() > ENTRIES_MAX {
            return Err(Error::BadLayout("more than 1024 entries"));
        }
        let mut referenced = [0u64; NOT_REFERENCED_WORDS];
        for n in 0..rootfs.len() as u32 {
            let e = rootfs.entry(n);
            if e.mode & 0o7000 != 0 {
                return Err(Error::BadEntry(n, "set-ID, set-GID or sticky bit"));
            }
            if e.uid != 0 || e.gid != 0 {
                return Err(Error::BadEntry(n, "owner is not 0:0"));
            }
            if !e.is_directory() {
                if e.file < 3 {
                    return Err(Error::BadEntry(
                        n,
                        "content is a file of the package itself",
                    ));
                }
                referenced[e.file as usize / 64] |= 1 << (e.file % 64);
            }
        }
        for f in 3..count {
            if referenced[f as usize / 64] >> (f % 64) & 1 == 0 {
                return Err(Error::BadLayout("a content file has no entry"));
            }
        }
        let meta = Meta::parse(text_of(file(0), "meta is not UTF-8")?)?;
        let manifest = Manifest::parse(text_of(file(2), "manifest is not UTF-8")?)?;
        if manifest.len() as usize != rootfs.len() {
            return Err(Error::BadManifest(
                manifest.len().min(rootfs.len() as u32) + 1,
            ));
        }
        let mut total = 0;
        for f in 3..count {
            total += file(f).len() as u64;
        }
        if meta.size != total {
            return Err(Error::BadLayout(
                "size in meta is not the size of the content",
            ));
        }
        for (n, m) in manifest.entries().enumerate() {
            let e = rootfs.entry(n as u32);
            let (size, elf) = if e.is_directory() {
                (0, false)
            } else {
                let d = file(e.file);
                (d.len() as u64, d.starts_with(b"\x7fELF"))
            };
            let digest_ok = m.sha256.is_some() != e.is_directory();
            if m.path != e.path || m.mode != e.mode || m.size != size || m.elf != elf || !digest_ok
            {
                return Err(Error::BadManifest(n as u32 + 1));
            }
        }
        Ok(Package {
            bytes,
            image,
            rootfs,
            meta,
            manifest,
            trailer,
            covered,
        })
    }

    /// The bytes the signature covers: everything before the trailer.
    pub fn covered(&self) -> &'a [u8] {
        &self.bytes[..self.covered]
    }

    /// The content of the entry `n`: empty for a directory.
    pub fn content(&self, n: u32) -> &'a [u8] {
        let e = self.rootfs.entry(n);
        if e.is_directory() {
            &[]
        } else {
            self.image
                .file_at(e.file)
                .expect("parse checked the number")
                .data
        }
    }

    /// Hashes the covered bytes and checks the trailer against the trust.
    pub fn verify(&self, trust: &Trust, revoked: &[Revocation]) -> Result<Signer, Error> {
        let mut s = sha::Stream::new();
        s.update(self.covered());
        trust::verify(
            &self.trailer,
            Kind::Package,
            &s.finish(),
            self.covered as u64,
            trust,
            revoked,
        )
    }

    /// The policy of the official packages: the licence and the source note
    /// are at `/usr/share/licenses/<name>/`, and nothing else lies under
    /// `/usr/share/licenses/` outside that directory.
    pub fn check_policy(&self, name: &str) -> Result<(), Error> {
        const ROOT: &str = "/usr/share/licenses";
        let (mut licence, mut source) = (false, false);
        for n in 0..self.rootfs.len() as u32 {
            let e = self.rootfs.entry(n);
            let Some(rest) = e.path.strip_prefix(ROOT) else {
                continue;
            };
            let Some(rest) = rest.strip_prefix('/') else {
                continue; // the directory itself
            };
            let inside = match rest.strip_prefix(name) {
                Some("") => true,
                Some(tail) => tail.starts_with('/'),
                None => false,
            };
            if !inside {
                return Err(Error::Policy(
                    "a path under /usr/share/licenses/ of another name",
                ));
            }
            let tail = &rest[name.len()..];
            licence |= tail == "/LICENSE" && !e.is_directory();
            source |= tail == "/SOURCE" && !e.is_directory();
        }
        if !licence {
            return Err(Error::Policy("no /usr/share/licenses/<name>/LICENSE"));
        }
        if !source {
            return Err(Error::Policy("no /usr/share/licenses/<name>/SOURCE"));
        }
        Ok(())
    }
}

/// Writing packages, for xtask on the host.
#[cfg(any(test, feature = "write"))]
pub mod write {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec::Vec;

    #[derive(Debug, Clone, Copy)]
    pub enum Content<'a> {
        Directory,
        /// A file, or the target text of a link.
        Data(&'a [u8]),
        /// Shares the content file of the item at this path (a hard link, or
        /// two links to one target).
        Same(&'a str),
    }

    #[derive(Debug, Clone, Copy)]
    pub struct Item<'a> {
        pub path: &'a str,
        pub mode: u32,
        pub content: Content<'a>,
    }

    /// The covered part of a package: the container, with `meta` (its `size`
    /// is filled in), the table `rootfs` of the items at `time` and the
    /// `manifest`. Content files are numbered in the order of their first
    /// mention in the table sorted by path.
    pub fn container<'a>(meta: &Meta<'_>, items: &[Item<'a>], time: u64) -> Result<Vec<u8>, Error> {
        let mut sorted = items.to_vec();
        sorted.sort_by(|a, b| a.path.cmp(b.path));
        let index: BTreeMap<&str, usize> = sorted
            .iter()
            .enumerate()
            .map(|(i, it)| (it.path, i))
            .collect();
        // File numbers by item; contents by number.
        let mut numbers: Vec<Option<u32>> = alloc::vec![None; sorted.len()];
        let mut contents: Vec<&'a [u8]> = Vec::new();
        let number_of = |i: usize,
                         numbers: &mut Vec<Option<u32>>,
                         contents: &mut Vec<&'a [u8]>|
         -> Result<u32, Error> {
            let mut at = i;
            loop {
                match sorted[at].content {
                    Content::Same(p) => {
                        at = *index.get(p).ok_or(Error::BadLayout("Same names no item"))?
                    }
                    Content::Data(d) => {
                        if numbers[at].is_none() {
                            numbers[at] = Some(3 + contents.len() as u32);
                            contents.push(d);
                        }
                        return Ok(numbers[at].expect("just set"));
                    }
                    Content::Directory => return Err(Error::BadLayout("Same names a directory")),
                }
            }
        };
        let mut entries = Vec::new();
        let mut manifest = String::new();
        for (i, it) in sorted.iter().enumerate() {
            let (file, data) = match it.content {
                Content::Directory => (0, None),
                _ => {
                    let n = number_of(i, &mut numbers, &mut contents)?;
                    (n, Some(contents[n as usize - 3]))
                }
            };
            entries.push(bootimg::rootfs::Entry {
                path: it.path,
                mode: it.mode,
                uid: 0,
                gid: 0,
                file,
            });
            manifest.push_str(&crate::manifest::line(data, it.mode, it.path));
        }
        let table = bootimg::rootfs::write::rootfs_at(&entries, 3 + contents.len() as u32, time)
            .map_err(Error::Rootfs)?;
        let mut sized = *meta;
        sized.size = contents.iter().map(|c| c.len() as u64).sum();
        let meta_text = sized.to_text()?;
        let names: Vec<String> = (3..3 + contents.len())
            .map(|n| alloc::format!("{n}"))
            .collect();
        let mut files: Vec<(&str, &[u8])> = alloc::vec![
            ("meta", meta_text.as_bytes()),
            ("rootfs", &table),
            ("manifest", manifest.as_bytes()),
        ];
        for (name, data) in names.iter().zip(&contents) {
            files.push((name, data));
        }
        bootimg::write::image_as(&PACKAGE, &files).map_err(Error::Container)
    }

    /// The covered part plus its trailer, signed with `seed`. The result is
    /// read back with `Package::parse`.
    pub fn sign(
        covered: Vec<u8>,
        seed: &[u8; 32],
        key: crate::Name,
        certificate: Option<[u8; crate::cert::SIZE]>,
        time: u64,
    ) -> Result<Vec<u8>, Error> {
        let digest = sha::sha256(&covered);
        let block = Block::sign(
            seed,
            Kind::Package,
            covered.len() as u64,
            digest,
            time,
            key,
            certificate,
        );
        let mut out = covered;
        let mut page = [0u8; TRAILER_SIZE];
        page[..BLOCK_SIZE].copy_from_slice(&block.to_bytes());
        out.extend_from_slice(&page);
        Package::parse(&out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::write::{Content, Item, container, sign};
    use super::*;
    use crate::cert::{Certificate, PURPOSE_PACKAGES};
    use crate::{Key, Name, sig};
    use alloc::vec::Vec;

    const ROOT: [u8; 32] = [1; 32];
    const REL: [u8; 32] = [2; 32];

    fn n(s: &str) -> Name {
        Name::new(s).unwrap()
    }

    fn items<'a>() -> Vec<Item<'a>> {
        let d = |path| Item {
            path,
            mode: 0o040755,
            content: Content::Directory,
        };
        let f = |path, mode, data: &'static [u8]| Item {
            path,
            mode,
            content: Content::Data(data),
        };
        alloc::vec![
            d("/bin"),
            d("/usr"),
            d("/usr/share"),
            d("/usr/share/licenses"),
            d("/usr/share/licenses/foo"),
            f("/bin/foo", 0o100755, b"\x7fELF program"),
            f("/bin/foo2", 0o100755, b"\x7fELF program"),
            Item {
                path: "/bin/hard",
                mode: 0o100755,
                content: Content::Same("/bin/foo")
            },
            f("/bin/ln", 0o120777, b"foo"),
            f(
                "/usr/share/licenses/foo/LICENSE",
                0o100644,
                b"licence text\n"
            ),
            f("/usr/share/licenses/foo/SOURCE", 0o100644, b"source note\n"),
        ]
    }

    fn sample_meta() -> Meta<'static> {
        meta::sample()
    }

    pub(crate) fn build(items: &[Item<'_>]) -> Vec<u8> {
        let cert = Certificate::issue(
            &ROOT,
            n("t-root"),
            n("t-release"),
            sig::public_key(&REL),
            PURPOSE_PACKAGES,
            1000,
            3_000_000_000,
        );
        let covered = container(&sample_meta(), items, 1_700_000_000).unwrap();
        sign(
            covered,
            &REL,
            n("t-release"),
            Some(cert.to_bytes()),
            1_800_000_000,
        )
        .unwrap()
    }

    fn trust_keys() -> [Key; 1] {
        [Key {
            name: n("t-root"),
            public: sig::public_key(&ROOT),
        }]
    }

    #[test]
    fn a_package_is_written_read_and_verified() {
        let bytes = build(&items());
        let p = Package::parse(&bytes).unwrap();
        assert_eq!(p.meta.name, "doomgeneric");
        assert_eq!(p.rootfs.time(), 1_700_000_000);
        assert_eq!(p.manifest.len() as usize, p.rootfs.len());
        // Hard links share one file; "foo2" has its own, equal bytes.
        let at = |path| p.rootfs.entry(p.rootfs.find(path).unwrap() as u32).file;
        assert_eq!(at("/bin/foo"), at("/bin/hard"));
        assert_ne!(at("/bin/foo"), at("/bin/foo2"));
        assert_eq!(p.image.count(), 3 + 5);
        assert_eq!(p.meta.size, (12 + 12 + 3 + 13 + 12) as u64);
        let roots = trust_keys();
        let signer = p
            .verify(
                &Trust {
                    roots: &roots,
                    direct: &[],
                },
                &[],
            )
            .unwrap();
        assert_eq!(signer.key, n("t-release"));
        assert_eq!(signer.time, 1_800_000_000);
        Manifest::check(&p).unwrap();
        p.check_policy("foo").unwrap();
        assert_eq!(
            p.check_policy("fo"),
            Err(Error::Policy(
                "a path under /usr/share/licenses/ of another name"
            ))
        );
        assert_eq!(bytes.len() % 4096, 0);
    }

    #[test]
    fn the_same_inputs_give_the_same_bytes() {
        assert_eq!(build(&items()), build(&items()));
    }

    fn verify_err(bytes: &[u8]) -> Error {
        let roots = trust_keys();
        match Package::parse(bytes) {
            Ok(p) => p
                .verify(
                    &Trust {
                        roots: &roots,
                        direct: &[],
                    },
                    &[],
                )
                .unwrap_err(),
            Err(e) => e,
        }
    }

    #[test]
    fn a_changed_byte_is_caught() {
        let good = build(&items());
        let p = Package::parse(&good).unwrap();
        // A byte of the covered part: the hash differs.
        let at = p.image.file_at(3).unwrap().offset as usize;
        let mut b = good.clone();
        b[at + 8] ^= 1;
        assert_eq!(verify_err(&b), Error::BadHash);
        // A byte of the signature.
        let tail = good.len() - TRAILER_SIZE;
        b = good.clone();
        b[tail + 128] ^= 1;
        assert_eq!(verify_err(&b), Error::BadSignature);
        // The covered length one page short.
        b = good.clone();
        b[tail + 16..tail + 24].copy_from_slice(&((tail - 4096) as u64).to_le_bytes());
        assert_eq!(verify_err(&b), Error::LengthMismatch);
        // A byte after the block in the trailer page.
        b = good.clone();
        b[tail + BLOCK_SIZE] = 1;
        assert_eq!(verify_err(&b), Error::BadTrailer);
        // A cut package and one with an extra page.
        assert!(matches!(
            verify_err(&good[..good.len() - 100]),
            Error::BadLayout(_)
        ));
        let mut more = good[..tail].to_vec();
        more.extend_from_slice(&[0; 4096]);
        more.extend_from_slice(&good[tail..]);
        assert!(matches!(verify_err(&more), Error::LengthMismatch));
    }

    #[test]
    fn a_huge_file_count_is_refused_before_the_table_is_read() {
        let good = build(&items());
        for count in [FILES_MAX + 1, 600_000, u32::MAX] {
            let mut b = good.clone();
            b[12..16].copy_from_slice(&count.to_le_bytes());
            assert_eq!(
                Package::parse(&b).err(),
                Some(Error::BadLayout(
                    "more content files than entries are allowed"
                ))
            );
        }
        // A hostile file of 30 MB with a table of 600 000 empty files at one
        // place is refused at once.
        let mut big = alloc::vec![0u8; 30_000_000 / 4096 * 4096];
        big[..8].copy_from_slice(b"STAFPKG1");
        big[8..12].copy_from_slice(&1u32.to_le_bytes());
        big[12..16].copy_from_slice(&600_000u32.to_le_bytes());
        let tail = big.len() - TRAILER_SIZE;
        let block = Block::sign(
            &REL,
            Kind::Package,
            tail as u64,
            [0; 32],
            1,
            n("t-release"),
            None,
        );
        big[tail..tail + BLOCK_SIZE].copy_from_slice(&block.to_bytes());
        let started = std::time::Instant::now();
        assert!(Package::parse(&big).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn corrupted_and_cut_packages_give_errors_and_no_panic() {
        let good = build(&items());
        let roots = trust_keys();
        let trust = Trust {
            roots: &roots,
            direct: &[],
        };
        let check = |b: &[u8]| match Package::parse(b) {
            Err(_) => true,
            Ok(p) => p.verify(&trust, &[]).is_err(),
        };
        // Every cut at a boundary of 8 bytes is an error.
        for cut in (0..good.len()).step_by(8) {
            assert!(Package::parse(&good[..cut]).is_err(), "cut at {cut}");
        }
        // Every changed byte of the header, the table, the three texts and the
        // trailer is an error of parse or of the signature check; so is every
        // 97th byte of the contents.
        let p = Package::parse(&good).unwrap();
        let table_end = 16 + 48 * p.image.count() as usize;
        let mut regions: Vec<core::ops::Range<usize>> =
            vec![0..table_end, good.len() - TRAILER_SIZE..good.len()];
        for n in 0..3 {
            let f = p.image.file_at(n).unwrap();
            regions.push(f.offset as usize..f.offset as usize + f.data.len());
        }
        let mut flips = 0;
        for r in regions {
            for at in r {
                let mut b = good.clone();
                b[at] ^= 0x55;
                assert!(check(&b), "byte {at}");
                flips += 1;
            }
        }
        for at in (0..good.len()).step_by(97) {
            let mut b = good.clone();
            b[at] ^= 0xff;
            assert!(check(&b), "byte {at}");
        }
        assert!(flips > 1000);
        // Garbage of every length up to two pages does not panic either.
        for len in 0..8192 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let _ = Package::parse(&junk);
        }
    }

    #[test]
    fn parse_alone_refuses_a_covered_length_that_is_not_the_package() {
        let good = build(&items());
        let tail = good.len() - TRAILER_SIZE;
        let mut b = good.clone();
        b[tail + 16..tail + 24].copy_from_slice(&((tail - 4096) as u64).to_le_bytes());
        assert_eq!(Package::parse(&b).err(), Some(Error::LengthMismatch));
        let mut b = good;
        b[tail + BLOCK_SIZE] = 1;
        assert_eq!(Package::parse(&b).err(), Some(Error::BadTrailer));
    }

    #[test]
    fn rules_of_the_layout() {
        let mut it = items();
        it[6].mode = 0o104755;
        let covered = container(&sample_meta(), &it, 0).unwrap();
        let bytes = sign(covered, &REL, n("t-release"), None, 1);
        assert!(matches!(
            bytes,
            Err(Error::BadEntry(_, "set-ID, set-GID or sticky bit"))
        ));
        let mut it = items();
        it[6].mode = 0o101755;
        assert!(matches!(
            sign(
                container(&sample_meta(), &it, 0).unwrap(),
                &REL,
                n("t-release"),
                None,
                1
            ),
            Err(Error::BadEntry(_, _))
        ));
    }

    #[test]
    fn ownership_and_names_of_files_are_checked() {
        let good = build(&items());
        let p = Package::parse(&good).unwrap();
        // The owner of entry 0 changed to 1: the table is in file 1.
        let table = p.image.file_at(1).unwrap().offset as usize;
        let mut b = good.clone();
        b[table + 24 + 12] = 1; // uid of the first entry (after the 24-byte header)
        assert!(matches!(verify_err(&b), Error::BadEntry(0, _)));
        // The name of file 3 is not its number.
        b = good.clone();
        let name_at = 16 + 48 * 3;
        b[name_at] = b'9';
        assert_eq!(
            verify_err(&b),
            Error::BadLayout("a file has not the name of its place")
        );
    }

    #[test]
    fn the_manifest_must_follow_the_table() {
        let it = items();
        let good = build(&it);
        let p = Package::parse(&good).unwrap();
        let at = p.image.file_at(2).unwrap();
        // Swap the first two lines of the manifest in place.
        let text = core::str::from_utf8(at.data).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.swap(0, 1);
        let swapped = lines.join("\n") + "\n";
        let mut b = good.clone();
        b[at.offset as usize..at.offset as usize + swapped.len()]
            .copy_from_slice(swapped.as_bytes());
        assert_eq!(verify_err(&b), Error::BadManifest(1));
        // The hashing check finds a flipped content byte; parse passes it.
        let mut b = good.clone();
        let c = p.image.file_at(7).unwrap().offset as usize;
        b[c] ^= 1;
        let q = Package::parse(&b).unwrap();
        assert!(matches!(Manifest::check(&q), Err(Error::BadManifest(_))));
    }

    #[test]
    fn policy_wants_licence_and_source() {
        let mut it = items();
        it.retain(|i| i.path != "/usr/share/licenses/foo/LICENSE");
        let p = build(&it);
        assert_eq!(
            Package::parse(&p).unwrap().check_policy("foo"),
            Err(Error::Policy("no /usr/share/licenses/<name>/LICENSE"))
        );
    }

    #[test]
    fn a_package_is_not_a_boot_image() {
        let bytes = build(&items());
        assert_eq!(
            BootImage::parse(&bytes).err(),
            Some(bootimg::Error::BadSignature("STAFBOOT"))
        );
        let img = bootimg::write::image(&[("init", b"x")]).unwrap();
        assert_eq!(
            Package::parse(&img)
                .err()
                .map(|e| matches!(e, Error::NoSignatureBlock | Error::BadLayout(_))),
            Some(true)
        );
    }
}
