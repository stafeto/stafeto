// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The format of the volume: the attribute record every entry carries, the format mark and the
//! number counter at the root, and the defaults of an entry that has no record (a volume of
//! version 2). `proto_data` names the layout in its text; the constants and the record live here
//! because they describe the volume.
//!
//! An entry's record is the user attribute `ATTR_TYPE` of littlefs (`Attr`, `ATTR_LEN` bytes). The
//! kind of the entry (file or directory) comes from littlefs itself. The format mark is the attribute
//! `ATTR_FORMAT_TYPE` of the root, one u32, and the counter of file numbers is the attribute
//! `ATTR_COUNTER_TYPE` of the root, one u64.

use crate::fs::Kind;

/// The user attribute that holds the record of an entry.
pub const ATTR_TYPE: u8 = 0x70;
/// The user attribute of the root that holds the format mark of the volume.
pub const ATTR_FORMAT_TYPE: u8 = 0x66;
/// The user attribute of the root that holds the counter of file numbers.
pub const ATTR_COUNTER_TYPE: u8 = 0x69;
/// The `format` word of a record.
pub const ATTR_FORMAT: u32 = 1;
/// The format mark of the volume at the root: the volume of this service. A volume whose mark is
/// above it was written by a later service and is refused at the mount.
pub const VOLUME_FORMAT: u32 = 3;
/// The bytes of a record.
pub const ATTR_LEN: usize = 48;
/// The file numbers one commit of the counter reserves.
pub const INO_BLOCK: u64 = 1024;
/// The free blocks below which only user 0 writes or creates (the reserve): enough for the commits
/// that name a file, set an attribute or split a directory when a volume is full.
pub const RESERVE_BLOCKS: u64 = 64;
/// The mask of the mode bits.
pub const MODE_MASK: u32 = 0o7777;

/// The record of an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub ino: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
}

impl Attr {
    pub fn to_bytes(&self) -> [u8; ATTR_LEN] {
        let mut b = [0u8; ATTR_LEN];
        b[0..4].copy_from_slice(&self.uid.to_le_bytes());
        b[4..8].copy_from_slice(&self.gid.to_le_bytes());
        b[8..12].copy_from_slice(&self.mode.to_le_bytes());
        b[12..16].copy_from_slice(&ATTR_FORMAT.to_le_bytes());
        b[16..24].copy_from_slice(&self.ino.to_le_bytes());
        b[24..32].copy_from_slice(&self.atime.to_le_bytes());
        b[32..40].copy_from_slice(&self.mtime.to_le_bytes());
        b[40..48].copy_from_slice(&self.ctime.to_le_bytes());
        b
    }

    /// None for a length other than `ATTR_LEN`, a `format` other than `ATTR_FORMAT` or a mode
    /// outside the mode bits.
    pub fn from_bytes(bytes: &[u8]) -> Option<Attr> {
        if bytes.len() != ATTR_LEN {
            return None;
        }
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        if u32_at(12) != ATTR_FORMAT || u32_at(8) & !MODE_MASK != 0 {
            return None;
        }
        Some(Attr {
            uid: u32_at(0),
            gid: u32_at(4),
            mode: u32_at(8),
            ino: u64_at(16),
            atime: u64_at(24) as i64,
            mtime: u64_at(32) as i64,
            ctime: u64_at(40) as i64,
        })
    }

    /// The part the permission rules read.
    pub fn perm(&self, kind: Kind) -> posix_perm::Attr {
        posix_perm::Attr {
            kind: match kind {
                Kind::File => posix_perm::Kind::File,
                Kind::Directory => posix_perm::Kind::Directory,
            },
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
        }
    }
}

/// How an entry's record stands on the volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// The record is there and this service knows it.
    Stored,
    /// The entry has no record: a volume of version 2, or a file a cut left between the commit of
    /// its name and the commit of its record. It reads as the default, and a change writes a record.
    Missing,
    /// A record of a format or length this service does not know: it reads as the default and is
    /// never rewritten (a change that would write it answers CORRUPT).
    Foreign,
}

/// A record and how it stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub attr: Attr,
    pub standing: Standing,
}

/// The number of an entry that has no record: FNV-1a of its path, with the top bit set so that it
/// is clear of the numbers the counter hands out.
pub fn ino_of_path(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in path {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h | (1 << 63)
}

/// What an entry with no (or an unknown) record reads as: user 0, group 0, `0700` for a directory,
/// `0600` for a file and `0755` for the root; times 0.
pub fn default_attr(kind: Kind, path: &[u8]) -> Attr {
    let mode = match (kind, path) {
        (_, b"/") => 0o755,
        (Kind::Directory, _) => 0o700,
        (Kind::File, _) => 0o600,
    };
    Attr {
        uid: 0,
        gid: 0,
        mode,
        ino: ino_of_path(path),
        atime: 0,
        mtime: 0,
        ctime: 0,
    }
}

/// The record read from the bytes of the attribute (`len` bytes of `buf`, or None when there is
/// none) for the entry at `path`.
pub fn read_entry(kind: Kind, path: &[u8], stored: Option<&[u8]>) -> Entry {
    match stored {
        None => Entry {
            attr: default_attr(kind, path),
            standing: Standing::Missing,
        },
        Some(bytes) => match Attr::from_bytes(bytes) {
            Some(attr) => Entry {
                attr,
                standing: Standing::Stored,
            },
            None => Entry {
                attr: default_attr(kind, path),
                standing: Standing::Foreign,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_is_48_bytes_and_round_trips() {
        let attr = Attr {
            uid: 1,
            gid: 2,
            mode: 0o2755,
            ino: 0x1122_3344_5566_7788,
            atime: 10,
            mtime: 11,
            ctime: 12,
        };
        let bytes = attr.to_bytes();
        let mut want = [0u8; 48];
        want[0] = 1;
        want[4] = 2;
        want[8..10].copy_from_slice(&0o2755u16.to_le_bytes());
        want[12] = 1;
        want[16..24].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        want[24] = 10;
        want[32] = 11;
        want[40] = 12;
        assert_eq!(bytes, want);
        assert_eq!(Attr::from_bytes(&bytes), Some(attr));
        assert_eq!(Attr::from_bytes(&bytes[..47]), None);
        let mut other = bytes;
        other[12] = 2;
        assert_eq!(Attr::from_bytes(&other), None);
        let mut wide = bytes;
        wide[10] = 0x10;
        assert_eq!(Attr::from_bytes(&wide), None);
        assert_eq!(
            (ATTR_TYPE, ATTR_FORMAT_TYPE, ATTR_COUNTER_TYPE),
            (0x70, 0x66, 0x69)
        );
        assert_eq!((RESERVE_BLOCKS, INO_BLOCK, VOLUME_FORMAT), (64, 1024, 3));
    }

    #[test]
    fn an_entry_with_no_record_reads_as_the_closed_default() {
        let d = read_entry(Kind::Directory, b"/ssh", None);
        let f = read_entry(Kind::File, b"/ssh/host_key", None);
        let r = read_entry(Kind::Directory, b"/", None);
        assert_eq!(
            (d.attr.mode, d.attr.uid, d.attr.gid, d.standing),
            (0o700, 0, 0, Standing::Missing)
        );
        assert_eq!((f.attr.mode, f.attr.uid), (0o600, 0));
        assert_eq!(r.attr.mode, 0o755);
        // The number is the path's, with the top bit set, and differs by path.
        assert!(f.attr.ino >> 63 == 1 && d.attr.ino >> 63 == 1);
        assert_ne!(f.attr.ino, d.attr.ino);
        assert_eq!(f.attr.ino, ino_of_path(b"/ssh/host_key"));
    }

    #[test]
    fn a_record_of_a_format_this_service_does_not_know_reads_as_the_default_and_is_foreign() {
        let a = Attr {
            uid: 5,
            gid: 6,
            mode: 0o644,
            ino: 9,
            atime: 0,
            mtime: 0,
            ctime: 0,
        };
        let mut bytes = a.to_bytes();
        assert_eq!(
            read_entry(Kind::File, b"/x", Some(&bytes)).standing,
            Standing::Stored
        );
        bytes[12] = 2;
        let e = read_entry(Kind::File, b"/x", Some(&bytes));
        assert_eq!(
            (e.standing, e.attr.uid, e.attr.mode),
            (Standing::Foreign, 0, 0o600)
        );
        let short = read_entry(Kind::File, b"/x", Some(&bytes[..40]));
        assert_eq!(short.standing, Standing::Foreign);
    }
}
