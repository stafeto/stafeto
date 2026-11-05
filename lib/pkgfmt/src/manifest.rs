// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The file `manifest` of a package: one line for each entry of `rootfs`, in
//! its order:
//!
//! ```text
//! <sha256 or -> <size> <mode, 6 octal digits> <elf or -> <path>
//! ```
//!
//! A directory is `- 0 040755 - /usr`. A link has the SHA-256 and the length
//! of its target text. `elf` marks content that starts with `\x7fELF`. The
//! path comes last, so a space in it does not break the line.

use crate::text::{Lines, decimal};
use crate::{Error, sha};

pub const LINE_MAX: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestEntry<'a> {
    pub sha256: Option<[u8; 32]>,
    pub size: u64,
    pub mode: u32,
    pub elf: bool,
    pub path: &'a str,
}

fn parse_line(line: &str) -> Option<ManifestEntry<'_>> {
    let mut parts = line.splitn(5, ' ');
    let (digest, size, mode, elf, path) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let sha256 = if digest == "-" { None } else { Some(sha::unhex(digest)?) };
    if mode.len() != 6 || !mode.bytes().all(|c| (b'0'..=b'7').contains(&c)) || !path.starts_with('/') {
        return None;
    }
    let elf = match elf {
        "elf" => true,
        "-" => false,
        _ => return None,
    };
    Some(ManifestEntry {
        sha256,
        size: decimal(size)?,
        mode: u32::from_str_radix(mode, 8).ok()?,
        elf,
        path,
    })
}

#[derive(Debug, Clone, Copy)]
pub struct Manifest<'a> {
    text: &'a str,
    count: u32,
}

impl<'a> Manifest<'a> {
    pub fn parse(text: &'a str) -> Result<Manifest<'a>, Error> {
        let mut lines = Lines::new(text, LINE_MAX);
        let mut count = 0;
        loop {
            match lines.next_line() {
                Ok(None) => return Ok(Manifest { text, count }),
                Ok(Some((n, line))) => {
                    parse_line(line).ok_or(Error::BadManifest(n))?;
                    count += 1;
                }
                Err(n) => return Err(Error::BadManifest(n)),
            }
        }
    }

    pub fn len(&self) -> u32 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The entries in order.
    pub fn entries(&self) -> impl Iterator<Item = ManifestEntry<'a>> {
        self.text.lines().map(|l| parse_line(l).expect("parse checked every line"))
    }

    /// Entry `n`, without hashing anything.
    pub fn entry(&self, n: u32) -> Option<ManifestEntry<'a>> {
        self.entries().nth(n as usize)
    }
}

/// The line for one entry.
#[cfg(any(test, feature = "write"))]
pub fn line(content: Option<&[u8]>, mode: u32, path: &str) -> alloc::string::String {
    let (digest, size, elf) = match content {
        None => (alloc::string::String::from("-"), 0, false),
        Some(d) => {
            let mut buf = [0u8; 64];
            (
                alloc::string::String::from(sha::hex(&sha::sha256(d), &mut buf)),
                d.len(),
                d.starts_with(b"\x7fELF"),
            )
        }
    };
    alloc::format!("{digest} {size} {mode:06o} {} {path}\n", if elf { "elf" } else { "-" })
}

#[cfg(any(test, feature = "write"))]
impl Manifest<'_> {
    /// Hashes every file of the package and compares: the SHA-256, the size
    /// and the `elf` mark of each line.
    pub fn check(package: &crate::Package<'_>) -> Result<(), Error> {
        for (i, e) in package.manifest.entries().enumerate() {
            let n = i as u32;
            let entry = package.rootfs.entry(n);
            let bad = Error::BadManifest(n + 1);
            if entry.is_directory() {
                if e.sha256.is_some() || e.size != 0 || e.elf {
                    return Err(bad);
                }
                continue;
            }
            let data = package.image.file_at(entry.file).ok_or(bad)?.data;
            if e.sha256 != Some(sha::sha256(data))
                || e.size != data.len() as u64
                || e.elf != data.starts_with(b"\x7fELF")
            {
                return Err(bad);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_parse_and_write_the_same() {
        let text = alloc::format!(
            "{}{}{}",
            line(None, 0o040755, "/usr"),
            line(Some(b"\x7fELFxx"), 0o100755, "/bin/a b"),
            line(Some(b"busybox"), 0o120777, "/bin/ls"),
        );
        let m = Manifest::parse(&text).unwrap();
        assert_eq!(m.len(), 3);
        let e: alloc::vec::Vec<_> = m.entries().collect();
        assert_eq!(e[0].path, "/usr");
        assert_eq!(e[0].mode, 0o040755);
        assert!(e[1].elf);
        assert_eq!(e[1].path, "/bin/a b");
        assert_eq!(e[2].size, 7);
        assert_eq!(m.entry(1), Some(e[1]));
        assert_eq!(m.entry(3), None);
    }

    #[test]
    fn mistakes_name_their_line() {
        let good = line(None, 0o040755, "/usr");
        for bad in [
            "- 0 40755 - /usr\n",
            "- 0 040759 - /usr\n",
            "- 0 040755 x /usr\n",
            "- 0 040755 - usr\n",
            "ab 0 040755 - /usr\n",
            "- 00 040755 - /usr\n",
            "- 0 040755 - /usr",
            "- 0 040755 -\n",
        ] {
            assert_eq!(
                Manifest::parse(&alloc::format!("{good}{bad}")).err(),
                Some(Error::BadManifest(2)),
                "{bad:?}"
            );
        }
    }
}
