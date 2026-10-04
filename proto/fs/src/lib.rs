// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Version 3 of the RAM file service protocol. All numbers are little endian.
//! OPEN: header, flags u32, UTF-8 absolute path bytes. Reply: status, fd u32,
//! and for a random device (`/dev/random`, `/dev/urandom`, step 5e') a third
//! word, RANDOM_DEVICE: the client's layer serves the reads of such a
//! description from its own generator, and the service refuses them.
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
//! READ_AT: header, fd u32, offset u64, count u32. Reply: status, count u32,
//! bytes. The bytes start at the offset of the file; the position of the
//! open description stays where it is (the model of pread).
//! Paths are at most MAX_PATH bytes, which leaves room for the terminator
//! within the 512 bytes of PATH_MAX.
//!
//! OPEN_EXEC (spec 2, 3.2; 5c), only through the session of the loaders,
//! whose label init marks with LOADERS and gives the process service
//! alone: header, the absolute path bytes, and one handle, a copy of the
//! loader's identity (proto_process). The service has the process service
//! vouch for it through its notary session, and only an identity of a
//! loader that loads passes; then in one step it resolves the path, checks
//! search on each directory and execute on the file by the effective IDs
//! of the record the loader loads, tells the process service the set-ID
//! bits of the file (SetId) and replies status and one handle, the image
//! session (SEND): a session of its own (IMAGE_SESSION) that takes
//! READ_AT, READ_INTO and INFO_FD of fd 0 alone and reads that file.
//! READ_INTO, through an image session alone: header, fd u32 (0), offset
//! u64, count u32 (at most READ_INTO_MAX), the place u64 in the object
//! (a whole page), and one handle, a memory object with MAP_READ and
//! MAP_WRITE that holds `count` bytes from the place: the service maps it,
//! copies the file's bytes from the offset into it and unmaps it. Reply:
//! status, count u32, short at the end of the file. A loader fills a
//! segment of a program this way in a few requests, where READ_AT takes
//! one for each MAX_READ bytes. PERMISSION
//! through any other session or for any other identity; NO_ENTRY,
//! ACCESS_DENIED, NOT_DIRECTORY.
//! CLONE: header, a count u32 (at most 32) and as many descriptors u32 of
//! the session, through a session of a client: reply status and one
//! handle, a new session (SEND, TRANSFER) of the service's own label
//! whose descriptors of the same numbers share the open descriptions,
//! their offsets and access modes, for a child of the client (5c); BAD_FD
//! for a number of no descriptor.
//! WRITE_AT: header, fd u32, offset u64, bytes. Reply: status, count u32.
//! The bytes go at the offset of the file; the position of the open
//! description stays where it is (the model of pwrite).

#![cfg_attr(not(test), no_std)]

mod directory;
pub use directory::DirectoryEntry;
mod info;
pub use info::NodeInfo;

use abi::MESSAGE_MAX;
use proto_wire::{HEADER_LEN, Header, Status};

pub const VERSION: u16 = 3;
pub const MAX_PATH: usize = 511;
pub const MAX_READ: usize = MESSAGE_MAX - 8;
pub const MAX_WRITE: usize = MESSAGE_MAX - HEADER_LEN - 4;
/// The bytes of one READ_INTO at most: the copy one request of an image
/// session makes in the service's step.
pub const READ_INTO_MAX: usize = 12 * 1024;

pub const READ_ONLY: u32 = 0;
pub const WRITE_ONLY: u32 = 1;
pub const READ_WRITE: u32 = 2;
/// Require a directory atomically when establishing the open description.
pub const DIRECTORY_ONLY: u32 = 4;
/// The caller asked for O_CREAT, O_TRUNC or O_APPEND: the null device takes
/// them (it has no contents to create, cut or follow), any other file
/// answers INVALID_ARGUMENT.
pub const CHANGES: u32 = 8;
/// The third word of the reply to an OPEN of a random device.
pub const RANDOM_DEVICE: u32 = 1;

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
/// EPERM: OPEN_EXEC through a session other than the loaders', or for an
/// identity that is no loader's.
pub const PERMISSION: u32 = 310;

/// The mark of the label of the session of the loaders: bit 62 with bit
/// 63 clear, which init gives only to the process service's session with
/// the RAM file service.
pub const LOADERS: u64 = 1 << 62;

/// Whether `label` is that of the session of the loaders.
pub const fn is_loaders(label: u64) -> bool {
    label & (1 << 63) == 0 && label & LOADERS != 0
}

/// The labels the service gives itself: bit 63, which no label of init
/// has; with bit 62 an image session, whose low 16 bits name the entry
/// of the image's table it reads.
pub const OWN: u64 = 1 << 63;
pub const IMAGE_SESSION: u64 = 1 << 62;

/// The label of the `count`th image session, for entry `entry`.
pub const fn image_label(count: u64, entry: u16) -> u64 {
    OWN | IMAGE_SESSION | (count & ((1 << 46) - 1)) << 16 | entry as u64
}

/// The entry an image session's label names.
pub const fn image_entry(label: u64) -> Option<u16> {
    if label & (OWN | IMAGE_SESSION) == OWN | IMAGE_SESSION {
        Some(label as u16)
    } else {
        None
    }
}

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
    ReadAt = 13,
    OpenExec = 14,
    Clone = 15,
    WriteAt = 16,
    ReadInto = 17,
    /// VerifySession: body require_fds u32 (0 or 1), one offered channel.
    /// A normal SEND|TRANSFER session returns unchanged. An unsuitable
    /// endpoint with required descriptors is refused; otherwise a fresh
    /// ordinary empty clone is returned.
    VerifySession = 18,
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
            13 => Some(Self::ReadAt),
            14 => Some(Self::OpenExec),
            15 => Some(Self::Clone),
            16 => Some(Self::WriteAt),
            17 => Some(Self::ReadInto),
            18 => Some(Self::VerifySession),
            _ => None,
        }
    }
}

pub const METHODS: &[u16] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
];

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

    #[test]
    fn paths_take_511_bytes_and_a_request_with_them_fits_a_message() {
        // PATH_MAX is 512 with the terminator.
        assert_eq!(MAX_PATH + 1, 512);
        let mut path = [b'a'; MAX_PATH + 1];
        path[0] = b'/';
        assert_eq!(valid_path(&path[..MAX_PATH]).map(str::len), Ok(MAX_PATH));
        assert_eq!(valid_path(&path), Err(Status::BadSize));
        const { assert!(HEADER_LEN + 4 + MAX_PATH <= MESSAGE_MAX) };
    }

    #[test]
    fn every_method_number_round_trips_and_is_listed() {
        for number in 0..=18u16 {
            let method = Method::from_number(number);
            assert_eq!(method.is_some(), METHODS.contains(&number), "{number}");
            if let Some(method) = method {
                assert_eq!(method as u16, number);
            }
        }
    }

    /// Only init's mark names the loaders; the service's own labels have
    /// bit 63, and an image session's carries its entry.
    #[test]
    fn labels_of_the_loaders_and_of_image_sessions() {
        assert!(is_loaders(LOADERS | 7));
        assert!(!is_loaders(7));
        assert!(!is_loaders(OWN | LOADERS | 7), "an image session");
        let label = image_label(5, 12);
        assert_eq!(image_entry(label), Some(12));
        assert_ne!(image_label(6, 12), label);
        assert_eq!(image_entry(OWN | 12), None, "a clone");
        assert_eq!(image_entry(LOADERS | 12), None);
    }
}
