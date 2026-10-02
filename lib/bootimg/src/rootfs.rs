// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The file `rootfs` of the boot image: the files that the RAM file service
//! shows besides its own tree. Each entry names a path, the `st_mode`, the
//! owner and the number of a file of the boot image, whose bytes are the
//! content (a program as its ELF file, as the linker wrote it). Entries
//! with one file number are hard links of one file, so they agree on mode
//! and owner. A directory has file number 0.
//!
//! Everything is little endian. A 16-byte header (the signature
//! `STAFROOT`, the version as u32, the number of entries as u32), a table
//! with a 24-byte entry per path (the offset of the path from the start of
//! the file as u32, its length as u16, 2 zero bytes, the mode, the user
//! and the group as u32 each, the file number as u32), then the paths. The
//! table is in strictly ascending order of the path bytes, so a lookup is
//! a binary search and a duplicate cannot hide. A path is absolute, at
//! most 511 bytes (512 with the terminator, `proto_fs::MAX_PATH`), has no
//! empty, `.` or `..` component and none over 255 bytes, and its parent is
//! a directory of the table or `/`. The reader checks all of it, so the
//! writer (feature `write`) cannot write what the service would refuse.

use core::fmt;

pub const MAGIC: [u8; 8] = *b"STAFROOT";
pub const VERSION: u32 = 1;
/// The entries of a table at most: the RAM service keeps a table of this
/// size.
pub const ENTRIES_MAX: usize = 1024;
/// The file numbers of the boot image the entries may name, below this.
pub const FILES_MAX: usize = 1024;
/// The longest path, without its terminator: `proto_fs::MAX_PATH`.
pub const PATH_MAX: usize = 511;
/// The longest name in a path.
pub const NAME_MAX: usize = 255;
pub const FORMAT: u32 = 0o170_000;
pub const DIRECTORY: u32 = 0o040_000;
pub const REGULAR: u32 = 0o100_000;
const HEADER_SIZE: usize = 16;
const ENTRY_SIZE: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes end before the header, the table or a path do.
    Truncated {
        need: u64,
        len: u64,
    },
    BadSignature,
    BadVersion {
        found: u32,
        known: u32,
    },
    /// The table has more entries than ENTRIES_MAX.
    TooMany(u32),
    /// Entry `n`'s path is not one the format allows.
    BadPath(u32),
    /// Entry `n` does not come after the entry before it in the strictly
    /// ascending order of the paths.
    Order(u32),
    /// Entry `n`'s mode is neither a directory's nor a regular file's, or
    /// has bits beyond the type and the 12 permission bits.
    BadMode(u32),
    /// Entry `n` is a directory with a file number, or a file with a number
    /// at or over the number of files of the image (or FILES_MAX).
    BadFile(u32),
    /// Entry `n` has no parent directory in the table.
    NoParent(u32),
    /// Entry `n` is hard linked with a file number whose mode or owner
    /// differs from the first entry's with it.
    LinkMismatch(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::Truncated { need, len } => {
                write!(f, "cut short: {need} bytes needed, {len} present")
            }
            Error::BadSignature => f.write_str("no STAFROOT signature"),
            Error::BadVersion { found, known } => {
                write!(f, "version {found}, only version {known} is known")
            }
            Error::TooMany(n) => write!(f, "{n} entries, over {ENTRIES_MAX}"),
            Error::BadPath(n) => write!(f, "the path of entry {n} is not a good absolute path"),
            Error::Order(n) => write!(f, "entry {n} does not follow its predecessor in the order"),
            Error::BadMode(n) => write!(f, "the mode of entry {n} is not a file's or directory's"),
            Error::BadFile(n) => write!(f, "the file number of entry {n} does not fit its kind"),
            Error::NoParent(n) => write!(f, "entry {n} has no parent directory in the table"),
            Error::LinkMismatch(n) => write!(
                f,
                "entry {n} is a hard link whose mode or owner differs from the first link's"
            ),
        }
    }
}

/// One entry of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    pub path: &'a str,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// The number of the boot image's file with the content; 0 for a
    /// directory.
    pub file: u32,
}

impl Entry<'_> {
    pub fn is_directory(&self) -> bool {
        self.mode & FORMAT == DIRECTORY
    }
}

/// A table whose header, entries and paths are checked.
#[derive(Debug, Clone, Copy)]
pub struct Rootfs<'a> {
    bytes: &'a [u8],
    count: u32,
}

impl<'a> Rootfs<'a> {
    /// `bytes` is the file `rootfs`; its regular files name files below
    /// `files`, the number of files of the boot image.
    pub fn parse(bytes: &'a [u8], files: u32) -> Result<Rootfs<'a>, Error> {
        let len = bytes.len() as u64;
        if len < HEADER_SIZE as u64 {
            return Err(Error::Truncated {
                need: HEADER_SIZE as u64,
                len,
            });
        }
        if bytes[..8] != MAGIC {
            return Err(Error::BadSignature);
        }
        let version = u32_at(bytes, 8);
        if version != VERSION {
            return Err(Error::BadVersion {
                found: version,
                known: VERSION,
            });
        }
        let count = u32_at(bytes, 12);
        if count as usize > ENTRIES_MAX {
            return Err(Error::TooMany(count));
        }
        let table_end = HEADER_SIZE as u64 + ENTRY_SIZE as u64 * u64::from(count);
        if len < table_end {
            return Err(Error::Truncated {
                need: table_end,
                len,
            });
        }
        let table = Rootfs { bytes, count };
        // The first entry of each file number, to compare its links with.
        let mut first = [u16::MAX; FILES_MAX];
        for n in 0..count {
            let entry = table.checked(n)?;
            if n > 0 && table.entry(n - 1).path >= entry.path {
                return Err(Error::Order(n));
            }
            match entry.mode & FORMAT {
                DIRECTORY | REGULAR if entry.mode & !(FORMAT | 0o7777) == 0 => {}
                _ => return Err(Error::BadMode(n)),
            }
            if entry.is_directory() {
                if entry.file != 0 {
                    return Err(Error::BadFile(n));
                }
            } else {
                if entry.file >= files || entry.file as usize >= FILES_MAX {
                    return Err(Error::BadFile(n));
                }
                let slot = &mut first[entry.file as usize];
                if *slot == u16::MAX {
                    *slot = n as u16;
                } else {
                    let other = table.entry(u32::from(*slot));
                    if (other.mode, other.uid, other.gid) != (entry.mode, entry.uid, entry.gid) {
                        return Err(Error::LinkMismatch(n));
                    }
                }
            }
            let parent = &entry.path[..entry.path.rfind('/').unwrap_or(0)];
            if !parent.is_empty() {
                match table.find_before(parent, n) {
                    Some(p) if table.entry(p as u32).is_directory() => {}
                    _ => return Err(Error::NoParent(n)),
                }
            }
        }
        Ok(table)
    }

    pub fn len(&self) -> usize {
        self.count as usize
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Entry `n`, which is below `len`.
    pub fn entry(&self, n: u32) -> Entry<'a> {
        self.checked(n).expect("parse checked every entry")
    }

    /// The entry with the path `path`, by binary search.
    pub fn find(&self, path: &str) -> Option<usize> {
        self.find_before(path, self.count)
    }

    /// `find` among the entries below `limit`, which `parse` has checked.
    fn find_before(&self, path: &str, limit: u32) -> Option<usize> {
        let (mut low, mut high) = (0, limit);
        while low < high {
            let middle = low + (high - low) / 2;
            match self.entry(middle).path.cmp(path) {
                core::cmp::Ordering::Less => low = middle + 1,
                core::cmp::Ordering::Greater => high = middle,
                core::cmp::Ordering::Equal => return Some(middle as usize),
            }
        }
        None
    }

    /// Entry `n` with its path checked; `parse` adds the rest.
    fn checked(&self, n: u32) -> Result<Entry<'a>, Error> {
        let at = HEADER_SIZE + ENTRY_SIZE * n as usize;
        let offset = u64::from(u32_at(self.bytes, at));
        let length = usize::from(u16_at(self.bytes, at + 4));
        let end = offset + length as u64;
        let table_end = HEADER_SIZE as u64 + ENTRY_SIZE as u64 * u64::from(self.count);
        if offset < table_end || end > self.bytes.len() as u64 {
            return Err(Error::BadPath(n));
        }
        if u16_at(self.bytes, at + 6) != 0 {
            return Err(Error::BadPath(n));
        }
        let path = core::str::from_utf8(&self.bytes[offset as usize..end as usize])
            .map_err(|_| Error::BadPath(n))?;
        if !good_path(path) {
            return Err(Error::BadPath(n));
        }
        Ok(Entry {
            path,
            mode: u32_at(self.bytes, at + 8),
            uid: u32_at(self.bytes, at + 12),
            gid: u32_at(self.bytes, at + 16),
            file: u32_at(self.bytes, at + 20),
        })
    }
}

/// An absolute path below `/` with names of 1 to 255 bytes, none `.` or
/// `..`, no NUL, and at most PATH_MAX bytes.
fn good_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    path.len() <= PATH_MAX
        && !path.contains('\0')
        && rest
            .split('/')
            .all(|name| (1..=NAME_MAX).contains(&name.len()) && name != "." && name != "..")
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let mut b = [0; 4];
    b.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(b)
}

/// Writing the file `rootfs`, for xtask on the host.
#[cfg(any(test, feature = "write"))]
pub mod write {
    use super::*;
    use alloc::vec::Vec;

    /// The file for `entries`, which may come in any order, sorted by path;
    /// `files` is the number of files of the boot image. The result is read
    /// back by the reader, which names what is wrong.
    pub fn rootfs(entries: &[Entry<'_>], files: u32) -> Result<Vec<u8>, Error> {
        let mut sorted = entries.to_vec();
        sorted.sort_by(|a, b| a.path.cmp(b.path));
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
        let mut offset = HEADER_SIZE + ENTRY_SIZE * sorted.len();
        for (n, entry) in sorted.iter().enumerate() {
            // The reader reports a path too long for the field.
            let length = u16::try_from(entry.path.len()).map_err(|_| Error::BadPath(n as u32))?;
            out.extend_from_slice(&(offset as u32).to_le_bytes());
            out.extend_from_slice(&length.to_le_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(&entry.mode.to_le_bytes());
            out.extend_from_slice(&entry.uid.to_le_bytes());
            out.extend_from_slice(&entry.gid.to_le_bytes());
            out.extend_from_slice(&entry.file.to_le_bytes());
            offset += entry.path.len();
        }
        for entry in &sorted {
            out.extend_from_slice(entry.path.as_bytes());
        }
        Rootfs::parse(&out, files)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::write::rootfs;
    use super::*;

    fn file(path: &str, mode: u32, file: u32) -> Entry<'_> {
        Entry {
            path,
            mode: REGULAR | mode,
            uid: 0,
            gid: 0,
            file,
        }
    }

    fn dir(path: &str) -> Entry<'_> {
        Entry {
            path,
            mode: DIRECTORY | 0o755,
            uid: 0,
            gid: 0,
            file: 0,
        }
    }

    fn sample() -> [Entry<'static>; 5] {
        [
            dir("/bin"),
            file("/bin/ash", 0o755, 3),
            Entry {
                uid: 1000,
                gid: 100,
                ..file("/bin/ls", 0o755, 3)
            },
            dir("/bin/sub"),
            file("/bin/sub/x", 0o4750, 4),
        ]
    }

    #[test]
    fn a_written_table_reads_back_sorted_with_every_field() {
        let mut entries = sample();
        // The hard links of one file agree on mode and owner.
        entries[2].uid = 0;
        entries[2].gid = 0;
        entries.reverse();
        let bytes = rootfs(&entries, 5).unwrap();
        let table = Rootfs::parse(&bytes, 5).unwrap();
        let paths: Vec<_> = (0..table.len() as u32)
            .map(|n| table.entry(n).path)
            .collect();
        assert_eq!(
            paths,
            ["/bin", "/bin/ash", "/bin/ls", "/bin/sub", "/bin/sub/x"]
        );
        let x = table.entry(4);
        assert_eq!((x.mode, x.file), (REGULAR | 0o4750, 4));
        assert!(table.entry(0).is_directory() && !x.is_directory());
        assert_eq!(table.entry(2).file, table.entry(1).file);
    }

    #[test]
    fn lookup_finds_every_path_and_nothing_else() {
        // "/a-b" sorts between "/a" and "/a/b" (0x2d below 0x2f).
        let entries = [
            dir("/a"),
            file("/a-b", 0o644, 1),
            file("/a/b", 0o644, 2),
            file("/a/c", 0o644, 3),
        ];
        let bytes = rootfs(&entries, 4).unwrap();
        let table = Rootfs::parse(&bytes, 4).unwrap();
        for (n, entry) in [(0, "/a"), (1, "/a-b"), (2, "/a/b"), (3, "/a/c")] {
            assert_eq!(table.find(entry), Some(n), "{entry}");
        }
        for missing in ["/", "/b", "/a/", "/a/bb", "/a-", "/z"] {
            assert_eq!(table.find(missing), None, "{missing}");
        }
    }

    #[test]
    fn a_table_of_the_most_entries_reads_and_one_more_is_refused() {
        let names: Vec<String> = (0..ENTRIES_MAX).map(|n| format!("/f{n:04}")).collect();
        let entries: Vec<_> = names.iter().map(|n| file(n, 0o644, 1)).collect();
        let bytes = rootfs(&entries, 2).unwrap();
        let table = Rootfs::parse(&bytes, 2).unwrap();
        assert_eq!(table.find("/f1023"), Some(1023));
        let mut more = bytes.clone();
        more[12..16].copy_from_slice(&(ENTRIES_MAX as u32 + 1).to_le_bytes());
        assert_eq!(
            Rootfs::parse(&more, 2).unwrap_err(),
            Error::TooMany(ENTRIES_MAX as u32 + 1)
        );
    }

    #[test]
    fn the_header_and_the_cut_bytes_are_refused() {
        let bytes = rootfs(&[dir("/d"), file("/d/f", 0o644, 1)], 2).unwrap();
        assert!(matches!(
            Rootfs::parse(&bytes[..10], 2),
            Err(Error::Truncated { .. })
        ));
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert_eq!(Rootfs::parse(&bad, 2).unwrap_err(), Error::BadSignature);
        bad = bytes.clone();
        bad[8] = 2;
        assert_eq!(
            Rootfs::parse(&bad, 2).unwrap_err(),
            Error::BadVersion { found: 2, known: 1 }
        );
        assert!(matches!(
            Rootfs::parse(&bytes[..HEADER_SIZE + ENTRY_SIZE], 2),
            Err(Error::Truncated { .. })
        ));
        // The two bytes after the length of a path are zero.
        bad = bytes.clone();
        bad[HEADER_SIZE + 6] = 1;
        assert_eq!(Rootfs::parse(&bad, 2).unwrap_err(), Error::BadPath(0));
        // The last path is cut: its end lies outside the file.
        assert_eq!(
            Rootfs::parse(&bytes[..bytes.len() - 1], 2).unwrap_err(),
            Error::BadPath(1)
        );
    }

    #[test]
    fn paths_the_format_forbids_are_refused() {
        // 512 bytes: every name is allowed, the whole path is one byte too long.
        let long = format!("/{}/{}", "a".repeat(NAME_MAX), "b".repeat(NAME_MAX));
        assert_eq!(long.len(), PATH_MAX + 1);
        let long_name = format!("/{}", "n".repeat(NAME_MAX + 1));
        for path in [
            "", "/", "x", "x/y", "/x/", "//x", "/x//y", "/./x", "/x/..", "/x\0y", &long, &long_name,
        ] {
            let result = rootfs(&[file(path, 0o644, 1)], 2);
            assert_eq!(result.unwrap_err(), Error::BadPath(0), "{path:?}");
        }
        // A name of 255 bytes in a path of 511 bytes is the limit.
        let name = "n".repeat(NAME_MAX);
        let deep = format!("/{name}/{}", "m".repeat(NAME_MAX - 1));
        assert_eq!(deep.len(), PATH_MAX);
        let entries = [dir(&deep[..=NAME_MAX]), file(&deep, 0o644, 1)];
        assert!(rootfs(&entries, 2).is_ok());
    }

    #[test]
    fn order_duplicates_and_parents_are_checked() {
        let bytes = rootfs(&[file("/a", 0o644, 1), file("/b", 0o644, 1)], 2).unwrap();
        // Swap the two table entries: no longer ascending.
        let mut swapped = bytes.clone();
        let (first, second) = (HEADER_SIZE, HEADER_SIZE + ENTRY_SIZE);
        for i in 0..ENTRY_SIZE {
            swapped.swap(first + i, second + i);
        }
        assert_eq!(Rootfs::parse(&swapped, 2).unwrap_err(), Error::Order(1));
        // The second entry takes the first's path: a duplicate.
        let mut duplicate = bytes.clone();
        let (offset, length) = (duplicate[first..first + 4].to_vec(), duplicate[first + 4]);
        duplicate[second..second + 4].copy_from_slice(&offset);
        duplicate[second + 4] = length;
        assert_eq!(Rootfs::parse(&duplicate, 2).unwrap_err(), Error::Order(1));
        assert_eq!(
            rootfs(&[file("/a", 0o644, 1), file("/a", 0o644, 1)], 2).unwrap_err(),
            Error::Order(1)
        );
        assert_eq!(
            rootfs(&[file("/d/f", 0o644, 1)], 2).unwrap_err(),
            Error::NoParent(0)
        );
        // A file is no parent.
        assert_eq!(
            rootfs(&[file("/f", 0o644, 1), file("/f/g", 0o644, 1)], 2).unwrap_err(),
            Error::NoParent(1)
        );
    }

    #[test]
    fn modes_file_numbers_and_links_are_checked() {
        let bad_mode = |mode| Entry {
            mode,
            ..file("/f", 0, 1)
        };
        for mode in [
            0,
            0o020_644,
            0o120_777,
            REGULAR | 0o10_000,
            DIRECTORY | 0o20_000,
            // A bit above the type: no stat field has it.
            REGULAR | 1 << 20,
        ] {
            assert_eq!(
                rootfs(&[bad_mode(mode)], 2).unwrap_err(),
                Error::BadMode(0),
                "{mode:o}"
            );
        }
        assert_eq!(
            rootfs(&[file("/f", 0o644, 2)], 2).unwrap_err(),
            Error::BadFile(0)
        );
        assert_eq!(
            rootfs(&[file("/f", 0o644, FILES_MAX as u32)], FILES_MAX as u32 + 1).unwrap_err(),
            Error::BadFile(0)
        );
        let numbered = Entry {
            file: 1,
            ..dir("/d")
        };
        assert_eq!(rootfs(&[numbered], 2).unwrap_err(), Error::BadFile(0));
        // Links of one file differ in mode, then in owner.
        assert_eq!(
            rootfs(&[file("/a", 0o644, 1), file("/b", 0o755, 1)], 2).unwrap_err(),
            Error::LinkMismatch(1)
        );
        let owned = Entry {
            uid: 5,
            ..file("/b", 0o644, 1)
        };
        assert_eq!(
            rootfs(&[file("/a", 0o644, 1), owned], 2).unwrap_err(),
            Error::LinkMismatch(1)
        );
        assert!(rootfs(&[file("/a", 0o644, 1), file("/b", 0o644, 1)], 2).is_ok());
    }
}
