// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! C ABI types and checked conversions for the stafeto Rust POSIX layer.

#![no_std]

pub mod constants;

/// Ordinary signal numbers use bits 0..30; unused bits remain reserved.
pub type SigSet = u64;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigAction {
    /// SIG_DFL = 0, SIG_IGN = 1, otherwise a live C handler address.
    pub handler: u64,
    pub mask: SigSet,
    pub flags: i32,
}

const _: () = {
    assert!(core::mem::size_of::<SigAction>() == 24);
    assert!(core::mem::align_of::<SigAction>() == 8);
};

#[derive(Debug, Eq, PartialEq)]
pub enum ConversionError {
    Malformed,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl Timespec {
    fn from_ns(ns: u64) -> Self {
        Self {
            tv_sec: (ns / 1_000_000_000) as i64,
            tv_nsec: (ns % 1_000_000_000) as i64,
        }
    }
}

#[repr(C)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u64,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atim: Timespec,
    pub st_mtim: Timespec,
    pub st_ctim: Timespec,
}

const _: () = {
    assert!(core::mem::size_of::<Timespec>() == 16);
    assert!(core::mem::size_of::<Stat>() == constants::STAFETO_STAT_SIZE as usize);
    assert!(core::mem::align_of::<Stat>() == 8);
    assert!(core::mem::offset_of!(Stat, st_size) == 48);
    assert!(core::mem::offset_of!(Stat, st_atim) == 72);
};

impl TryFrom<proto_fs::NodeInfo> for Stat {
    type Error = ConversionError;

    fn try_from(info: proto_fs::NodeInfo) -> Result<Self, Self::Error> {
        if info.permissions & !0o7777 != 0 || info.block_size == 0 {
            return Err(ConversionError::Malformed);
        }
        let kind = match info.kind {
            1 => constants::S_IFDIR,
            2 => constants::S_IFREG,
            3 => constants::S_IFCHR,
            _ => return Err(ConversionError::Malformed),
        };
        Ok(Self {
            st_dev: info.device,
            st_ino: info.inode,
            st_mode: kind | info.permissions,
            st_nlink: info.links,
            st_uid: info.uid,
            st_gid: info.gid,
            st_rdev: info.special_device,
            st_size: i64::try_from(info.size).map_err(|_| ConversionError::Overflow)?,
            st_blksize: i64::from(info.block_size),
            st_blocks: i64::try_from(info.blocks).map_err(|_| ConversionError::Overflow)?,
            st_atim: Timespec::from_ns(info.access_ns),
            st_mtim: Timespec::from_ns(info.modify_ns),
            st_ctim: Timespec::from_ns(info.change_ns),
        })
    }
}

/// Directory entry returned by the C ABI. d_type is a convenience extension.
#[repr(C)]
pub struct Dirent {
    pub d_ino: u64,
    pub d_type: u8,
    pub d_name: [u8; constants::NAME_MAX as usize + 1],
}

impl Dirent {
    pub const fn empty() -> Self {
        Self {
            d_ino: 0,
            d_type: 0,
            d_name: [0; constants::NAME_MAX as usize + 1],
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<Dirent>() == constants::STAFETO_DIRENT_SIZE as usize);
    assert!(core::mem::offset_of!(Dirent, d_name) == 9);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> proto_fs::NodeInfo {
        proto_fs::NodeInfo {
            kind: 2,
            permissions: 0o6754,
            device: u64::MAX,
            special_device: u64::MAX - 1,
            inode: u64::MAX - 2,
            links: u64::MAX - 3,
            uid: u32::MAX,
            gid: u32::MAX - 1,
            size: i64::MAX as u64,
            block_size: u32::MAX,
            blocks: i64::MAX as u64,
            access_ns: 1_000_000_001,
            modify_ns: u64::MAX,
            change_ns: 999_999_999,
        }
    }

    #[test]
    fn wide_fields_and_normalized_times_survive_conversion() {
        let value = Stat::try_from(node()).unwrap();
        assert_eq!(value.st_dev, u64::MAX);
        assert_eq!(value.st_rdev, u64::MAX - 1);
        assert_eq!(value.st_ino, u64::MAX - 2);
        assert_eq!(value.st_nlink, u64::MAX - 3);
        assert_eq!((value.st_uid, value.st_gid), (u32::MAX, u32::MAX - 1));
        assert_eq!(value.st_mode, constants::S_IFREG | 0o6754);
        assert_eq!((value.st_size, value.st_blocks), (i64::MAX, i64::MAX));
        assert_eq!(value.st_blksize, i64::from(u32::MAX));
        assert_eq!(
            value.st_atim,
            Timespec {
                tv_sec: 1,
                tv_nsec: 1
            }
        );
        assert_eq!(
            value.st_mtim,
            Timespec {
                tv_sec: 18_446_744_073,
                tv_nsec: 709_551_615
            }
        );
        assert_eq!(
            value.st_ctim,
            Timespec {
                tv_sec: 0,
                tv_nsec: 999_999_999
            }
        );
    }

    #[test]
    fn signed_overflow_and_invalid_modes_are_rejected() {
        let mut value = node();
        value.size += 1;
        assert!(matches!(
            Stat::try_from(value),
            Err(ConversionError::Overflow)
        ));
        value = node();
        value.blocks += 1;
        assert!(matches!(
            Stat::try_from(value),
            Err(ConversionError::Overflow)
        ));
        for (kind, permissions, block_size) in
            [(0, 0, 512), (4, 0, 512), (1, 0o10000, 512), (2, 0, 0)]
        {
            value = node();
            value.kind = kind;
            value.permissions = permissions;
            value.block_size = block_size;
            assert!(matches!(
                Stat::try_from(value),
                Err(ConversionError::Malformed)
            ));
        }
    }
}
