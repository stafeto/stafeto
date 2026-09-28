// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Version 1 of the RAM file service protocol. All numbers are little endian.
//! OPEN: header, flags u32, UTF-8 absolute path bytes. Reply: status, fd u32.
//! READ: header, fd u32, count u32. Reply: status, count u32, bytes.
//! WRITE: header, fd u32, bytes. Reply: status, count u32.
//! SEEK: header, fd u32, absolute offset u32. Reply: status, offset u32.
//! STAT: header, fd u32. Reply: status, size u32.
//! CLOSE: header, fd u32. Reply: status alone.
//! READ_DIR: header, index u32, UTF-8 absolute path bytes. Reply: status,
//! kind u32 (0 at end, 1 directory, 2 file), entry name bytes.
//! LOOKUP: header, UTF-8 absolute path bytes. Reply: status, kind u32,
//! size u32 (directories report zero until their metadata is available).
//! SEEK_FROM: header, fd u32, signed offset i64, origin u32. Reply:
//! status, resulting offset u64 (at most i64::MAX). Legacy SEEK is unchanged.
//! INFO_FD: header, fd u32. INFO_PATH: header, absolute path bytes. Replies:
//! status and NodeInfo fields (92 bytes), without C ABI padding.
//! READ_DIR_FD: header, fd u32. Reply: status u32, kind u32, inode u64,
//! name bytes. At end, kind/inode are zero and name is empty. The service
//! advances the open-description position and updates directory access time.

#![cfg_attr(not(test), no_std)]

mod directory;
pub use directory::DirectoryEntry;
mod info;
pub use info::NodeInfo;

use abi::MESSAGE_MAX;
use proto_wire::{HEADER_LEN, Header, Status};

pub const VERSION: u16 = 1;
pub const MAX_PATH: usize = 128;
pub const MAX_READ: usize = MESSAGE_MAX - 8;
pub const MAX_WRITE: usize = MESSAGE_MAX - HEADER_LEN - 4;

pub const READ_ONLY: u32 = 0;
pub const WRITE_ONLY: u32 = 1;
pub const READ_WRITE: u32 = 2;
/// Require a directory atomically when establishing the open description.
pub const DIRECTORY_ONLY: u32 = 4;

pub const NO_ENTRY: u32 = 300;
pub const BAD_FD: u32 = 301;
pub const IS_DIRECTORY: u32 = 302;
pub const NO_SPACE: u32 = 303;
pub const INVALID_ARGUMENT: u32 = 304;
pub const OFFSET_OVERFLOW: u32 = 305;
pub const NO_DATA: u32 = 306;
pub const TOO_MANY_OPEN_FILES: u32 = 307;
pub const ACCESS_DENIED: u32 = 308;
pub const NOT_DIRECTORY: u32 = 309;

/// Origins for the signed 64-bit SEEK_FROM request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SeekFrom {
    Start = 0,
    Current = 1,
    End = 2,
    Data = 3,
    Hole = 4,
}

impl SeekFrom {
    pub fn from_number(number: u32) -> Option<Self> {
        match number {
            0 => Some(Self::Start),
            1 => Some(Self::Current),
            2 => Some(Self::End),
            3 => Some(Self::Data),
            4 => Some(Self::Hole),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub kind: u32,
    pub size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Open = 1,
    Read = 2,
    Write = 3,
    Seek = 4,
    Stat = 5,
    Close = 6,
    ReadDir = 7,
    Lookup = 8,
    SeekFrom = 9,
    InfoFd = 10,
    InfoPath = 11,
    ReadDirFd = 12,
}

impl Method {
    pub const fn header(self) -> Header {
        Header::new(self as u16, VERSION)
    }

    pub fn from_number(n: u16) -> Option<Self> {
        match n {
            1 => Some(Self::Open),
            2 => Some(Self::Read),
            3 => Some(Self::Write),
            4 => Some(Self::Seek),
            5 => Some(Self::Stat),
            6 => Some(Self::Close),
            7 => Some(Self::ReadDir),
            8 => Some(Self::Lookup),
            9 => Some(Self::SeekFrom),
            10 => Some(Self::InfoFd),
            11 => Some(Self::InfoPath),
            12 => Some(Self::ReadDirFd),
            _ => None,
        }
    }
}

pub const METHODS: &[u16] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

pub fn valid_path(path: &[u8]) -> Result<&str, Status> {
    if path.is_empty() || path.len() > MAX_PATH || path[0] != b'/' || path.contains(&0) {
        return Err(Status::BadSize);
    }
    core::str::from_utf8(path).map_err(|_| Status::BadSize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_reject_empty_relative_nul_and_bad_utf8() {
        for path in [b"".as_slice(), b"tmp/a", b"/a\0b", b"/\xff"] {
            assert_eq!(valid_path(path), Err(Status::BadSize));
        }
        assert_eq!(valid_path(b"/tmp/a"), Ok("/tmp/a"));
        assert_eq!(valid_path(b"/"), Ok("/"));
    }
}
