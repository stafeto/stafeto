// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The settings layer (pk3-design R8): the owner's `repositories` and the
//! keys of his repositories, as the blob `STAFSET1` holds them, checked by
//! the rules below and made into a package container whose layer shows them
//! at `/etc/pkg`. The service builds the container itself, in a buffer, with
//! a trailer page of zeros: the file service reads its table alone.

use bootimg::PACKAGE;
use pkgfmt::{Key, Name, keyfile};
use proto_pkg::blob::{Blob, File};

/// The name of the official repository and of its key: not the owner's to set.
pub const OFFICIAL: &str = "stafeto";
/// The bytes of the container at most: 64 KiB of files, each at a page, the
/// table of two pages, `meta`, the header and the trailer.
pub const CONTAINER_MAX: usize = 224 * 1024;
const PAGE: usize = 4096;
const META: &[u8] = b"name settings\n";
const REPOSITORIES: &str = "repositories";
const KEYS: &str = "keys/";
const SUFFIX: &str = ".pub";

/// The blob is not one the rules allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid;

/// A blob that passed: its files by the rules.
#[derive(Debug)]
pub struct Settings<'a> {
    blob: Blob<'a>,
}

impl<'a> Settings<'a> {
    /// The rules: the structure of `Blob`; names only `repositories` and
    /// `keys/<name>.pub` with a name of `pkgfmt::Name` that is not
    /// `stafeto`; each key file a public key; `repositories` UTF-8 with
    /// lines `<name> <https address>` or `disable <name>`, every name that
    /// is not disabled with a key in the blob.
    pub fn parse(bytes: &'a [u8]) -> Result<Settings<'a>, Invalid> {
        let blob = Blob::parse(bytes).map_err(|_| Invalid)?;
        let settings = Settings { blob };
        for (i, file) in blob.files().enumerate() {
            if blob.files().take(i).any(|f| f.name == file.name) {
                return Err(Invalid);
            }
            if file.name == REPOSITORIES.as_bytes() {
                settings.check_repositories(file.data)?;
            } else {
                let stem = key_stem(file.name).ok_or(Invalid)?;
                if stem == OFFICIAL {
                    return Err(Invalid);
                }
                let text = core::str::from_utf8(file.data).map_err(|_| Invalid)?;
                keyfile::parse_public(text).map_err(|_| Invalid)?;
            }
        }
        Ok(settings)
    }

    fn check_repositories(&self, data: &[u8]) -> Result<(), Invalid> {
        let text = core::str::from_utf8(data).map_err(|_| Invalid)?;
        for line in text.lines() {
            let mut words = line.split(' ');
            match (words.next(), words.next(), words.next()) {
                (Some("disable"), Some(name), None) => {
                    Name::new(name).map_err(|_| Invalid)?;
                }
                (Some(name), Some(address), None) => {
                    Name::new(name).map_err(|_| Invalid)?;
                    if name == OFFICIAL || !address.starts_with("https://") || address.len() < 9 {
                        return Err(Invalid);
                    }
                    if self.key_of(name).is_none() {
                        return Err(Invalid);
                    }
                }
                _ => return Err(Invalid),
            }
        }
        Ok(())
    }

    /// The file `keys/<repository>.pub` of the blob.
    pub fn key_file(&self, repository: &str) -> Option<File<'a>> {
        self.blob
            .files()
            .find(|f| key_stem(f.name).is_some_and(|stem| stem == repository))
    }

    /// The key a repository of the owner is trusted by.
    pub fn key_of(&self, repository: &str) -> Option<Key> {
        let file = self.key_file(repository)?;
        keyfile::parse_public(core::str::from_utf8(file.data).ok()?).ok()
    }

    pub fn files(&self) -> impl Iterator<Item = File<'a>> + use<'a> {
        self.blob.files()
    }

    pub fn count(&self) -> u32 {
        self.blob.count
    }
}

/// `<name>` of `keys/<name>.pub`, when the name is one of `pkgfmt::Name`.
fn key_stem(file: &[u8]) -> Option<&str> {
    let text = core::str::from_utf8(file).ok()?;
    let stem = text.strip_prefix(KEYS)?.strip_suffix(SUFFIX)?;
    Name::new(stem).ok().map(|_| stem)
}

/// The container of the layer in `out`, whole pages: its length, or None
/// when the buffer is too small. The directories `/etc`, `/etc/pkg` and
/// `/etc/pkg/keys` are in it (0o040755, 0:0): a layer lists the directory
/// above each entry, the base has them all, and a layer merges its
/// directories with those; the files are 0o100644, 0:0.
pub fn container(settings: &Settings<'_>, out: &mut [u8]) -> Option<usize> {
    const PATH_MAX: usize = 96;
    let files = settings.count() as usize;
    // Entry i < 3 is a directory, entry 3 + k the file k of the blob; the
    // table wants them in ascending order of the path, so they are sorted
    // by path with their file numbers along.
    let mut paths = [[0u8; PATH_MAX]; 35];
    let mut lens = [0usize; 35];
    let mut contents: [&[u8]; 32] = [&[]; 32];
    for (i, dir) in [&b"/etc"[..], b"/etc/pkg", b"/etc/pkg/keys"]
        .into_iter()
        .enumerate()
    {
        paths[i][..dir.len()].copy_from_slice(dir);
        lens[i] = dir.len();
    }
    for (k, f) in settings.files().enumerate() {
        let (head, name) = (b"/etc/pkg/", f.name);
        paths[3 + k][..head.len()].copy_from_slice(head);
        paths[3 + k][head.len()..head.len() + name.len()].copy_from_slice(name);
        lens[3 + k] = head.len() + name.len();
        contents[k] = f.data;
    }
    let n = 3 + files;
    let mut order = [0usize; 35];
    for (i, slot) in order.iter_mut().enumerate().take(n) {
        *slot = i;
    }
    order[..n].sort_unstable_by(|&a, &b| paths[a][..lens[a]].cmp(&paths[b][..lens[b]]));
    // The table `rootfs`.
    let mut rootfs = [0u8; 2 * PAGE];
    rootfs[..8].copy_from_slice(b"STAFROOT");
    rootfs[8..12].copy_from_slice(&2u32.to_le_bytes());
    rootfs[12..16].copy_from_slice(&(n as u32).to_le_bytes());
    let mut at = 24 + 24 * n;
    for (row, &i) in order[..n].iter().enumerate() {
        let (mode, file) = if i < 3 {
            (0o040_755u32, 0)
        } else {
            (0o100_644, i)
        };
        let e = 24 + 24 * row;
        rootfs[e..e + 4].copy_from_slice(&(at as u32).to_le_bytes());
        rootfs[e + 4..e + 6].copy_from_slice(&(lens[i] as u16).to_le_bytes());
        rootfs[e + 8..e + 12].copy_from_slice(&mode.to_le_bytes());
        rootfs[e + 20..e + 24].copy_from_slice(&(file as u32).to_le_bytes());
        rootfs
            .get_mut(at..at + lens[i])?
            .copy_from_slice(&paths[i][..lens[i]]);
        at += lens[i];
    }
    let rootfs = &rootfs[..at];
    // The files of the container: meta, rootfs, an empty manifest, then the
    // contents, each at a page.
    let count = 3 + files;
    let data_of = |i: usize| -> &[u8] {
        match i {
            0 => META,
            1 => rootfs,
            2 => &[],
            _ => contents[i - 3],
        }
    };
    let mut offsets = [0usize; 35];
    let mut cursor = (16 + 48 * count).next_multiple_of(PAGE);
    for (i, offset) in offsets.iter_mut().enumerate().take(count) {
        *offset = cursor;
        cursor = (cursor + data_of(i).len()).next_multiple_of(PAGE);
    }
    let total = cursor + PAGE;
    let out = out.get_mut(..total)?;
    out.fill(0);
    out[..8].copy_from_slice(&PACKAGE.magic);
    out[8..12].copy_from_slice(&PACKAGE.version.to_le_bytes());
    out[12..16].copy_from_slice(&(count as u32).to_le_bytes());
    for i in 0..count {
        let e = 16 + 48 * i;
        match i {
            0 => out[e..e + 4].copy_from_slice(b"meta"),
            1 => out[e..e + 6].copy_from_slice(b"rootfs"),
            2 => out[e..e + 8].copy_from_slice(b"manifest"),
            _ => {
                let mut digits = [0u8; 4];
                let mut len = 0;
                let mut v = i;
                while v > 0 {
                    digits[len] = b'0' + (v % 10) as u8;
                    v /= 10;
                    len += 1;
                }
                for k in 0..len {
                    out[e + k] = digits[len - 1 - k];
                }
            }
        }
        let data = data_of(i);
        out[e + 32..e + 40].copy_from_slice(&(offsets[i] as u64).to_le_bytes());
        out[e + 40..e + 48].copy_from_slice(&(data.len() as u64).to_le_bytes());
        out[offsets[i]..offsets[i] + data.len()].copy_from_slice(data);
    }
    Some(total)
}
