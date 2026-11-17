// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the data file service (services/datafs), proto_wire, version 1. Every number goes
//! low byte first, every call is one request and one reply whose first four bytes are the status.
//!
//! The service holds the files of the volume mounted at `/data`: paths are absolute from the root of
//! the volume (`/ssh/host_key` for `/data/ssh/host_key`), canonical, with no `.` and `..`. An open file
//! or directory is a handle of the session, a small number the service picks. A call that reads or
//! writes carries its bytes in the message, at most `MAX_DATA`.
//!
//! | Request | Bytes after the header | Reply after the status |
//! |---|---|---|
//! | OPEN (1) | `flags` u32, the path | `handle` u32, `kind` u32 |
//! | CLOSE (2) | `handle` u32 | none |
//! | READ (3) | `handle` u32, `count` u32 | `count` u32, the bytes |
//! | WRITE (4) | `handle` u32, the bytes | `count` u32 |
//! | SEEK (5) | `handle` u32, `offset` i64, `whence` u32 | `position` u64 |
//! | FSYNC (6) | `handle` u32 | none |
//! | TRUNCATE (7) | `handle` u32, `size` u64 | none |
//! | STAT (8) | the path | `kind` u32, `size` u32 |
//! | FSTAT (9) | `handle` u32 | `kind` u32, `size` u32 |
//! | MKDIR (10), UNLINK (11), RMDIR (12) | the path | none |
//! | RENAME (13) | `from_len` u32, the path `from`, the path `to` | none |
//! | READDIR (14) | `handle` u32 | `more` u32, `kind` u32, `size` u32, the name |
//! | REWIND (15) | `handle` u32 | none |
//! | STATFS (16) | none | `blocks` u64, `used` u64, `block` u32 |
//!
//! FSYNC makes the file's data and its place in the tree durable before it answers. MKDIR, UNLINK,
//! RMDIR and RENAME are durable when they answer, and RENAME is one step: after a cut of the power the
//! old name or the new is there. A file the service made with OPEN and CREATE exists, empty, from the
//! open; its bytes are the file's after the FSYNC or the CLOSE that follows, and a cut before that
//! leaves the contents of the last sync.

#![cfg_attr(not(test), no_std)]

use abi::MESSAGE_MAX;
use proto_wire::{HEADER_LEN, Header, Reader, Status, Writer};

pub const VERSION: u16 = 1;

/// The longest path, in bytes: two of them and the fields of RENAME fit one message.
pub const MAX_PATH: usize = 480;
/// The bytes one READ or WRITE carries at most.
pub const MAX_READ: usize = MESSAGE_MAX - 8;
pub const MAX_WRITE: usize = MESSAGE_MAX - HEADER_LEN - 4;
/// The bytes of a block of the volume.
pub const BLOCK: u32 = 4096;

/// The flags of OPEN.
pub const READ: u32 = 1;
pub const WRITE: u32 = 2;
/// Both access bits: read and write.
pub const READ_WRITE_BOTH: u32 = READ | WRITE;
pub const CREATE: u32 = 4;
pub const EXCLUSIVE: u32 = 8;
pub const TRUNCATE: u32 = 16;
pub const APPEND: u32 = 32;
/// The path must name a directory (a handle for READDIR).
pub const DIRECTORY: u32 = 64;
pub const FLAGS_ALL: u32 = READ | WRITE | CREATE | EXCLUSIVE | TRUNCATE | APPEND | DIRECTORY;

/// The kinds of a file and of a directory, as a reply names them.
pub const KIND_FILE: u32 = 1;
pub const KIND_DIRECTORY: u32 = 2;

pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

/// The codes of the service (`Status::Unknown`), clear of the codes of the wire (below 512) and of the
/// other services (blk 1101, the file service's).
pub const NO_ENTRY: u32 = 1201;
pub const EXISTS: u32 = 1202;
pub const NOT_DIRECTORY: u32 = 1203;
pub const IS_DIRECTORY: u32 = 1204;
pub const NOT_EMPTY: u32 = 1205;
pub const BAD_HANDLE: u32 = 1206;
pub const TOO_BIG: u32 = 1207;
pub const INVALID: u32 = 1208;
pub const NO_SPACE: u32 = 1209;
pub const IO: u32 = 1210;
pub const TOO_MANY_OPEN: u32 = 1211;
pub const NAME_TOO_LONG: u32 = 1212;
/// A file or a directory in use cannot be removed or renamed.
pub const BUSY: u32 = 1213;
/// The volume is not mounted (no data volume, or it failed).
pub const NOT_READY: u32 = 1214;
pub const CORRUPT: u32 = 1215;

pub const CODES: [u32; 15] = [
    NO_ENTRY,
    EXISTS,
    NOT_DIRECTORY,
    IS_DIRECTORY,
    NOT_EMPTY,
    BAD_HANDLE,
    TOO_BIG,
    INVALID,
    NO_SPACE,
    IO,
    TOO_MANY_OPEN,
    NAME_TOO_LONG,
    BUSY,
    NOT_READY,
    CORRUPT,
];

pub const fn code(code: u32) -> Status {
    Status::Unknown(code)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Open = 1,
    Close = 2,
    Read = 3,
    Write = 4,
    Seek = 5,
    Fsync = 6,
    Truncate = 7,
    Stat = 8,
    Fstat = 9,
    Mkdir = 10,
    Unlink = 11,
    Rmdir = 12,
    Rename = 13,
    Readdir = 14,
    Rewind = 15,
    Statfs = 16,
}

impl Method {
    pub const ALL: [Method; 16] = [
        Method::Open,
        Method::Close,
        Method::Read,
        Method::Write,
        Method::Seek,
        Method::Fsync,
        Method::Truncate,
        Method::Stat,
        Method::Fstat,
        Method::Mkdir,
        Method::Unlink,
        Method::Rmdir,
        Method::Rename,
        Method::Readdir,
        Method::Rewind,
        Method::Statfs,
    ];

    pub const fn number(self) -> u16 {
        self as u16
    }

    pub fn from_number(number: u16) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.number() == number)
    }

    pub const fn header(self) -> Header {
        Header::new(self.number(), VERSION)
    }
}

/// The method numbers of every request, for a service's table.
pub const METHODS: [u16; 16] = {
    let mut numbers = [0; 16];
    let mut i = 0;
    while i < 16 {
        numbers[i] = Method::ALL[i].number();
        i += 1;
    }
    numbers
};

fn start(method: Method, w: &mut Writer) -> Result<(), Status> {
    method.header().write(w)
}

// The requests, written by a client.

pub fn open(path: &[u8], flags: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::Open, w)?;
    w.u32(flags)?;
    w.bytes(path)
}

pub fn handle_call(method: Method, handle: u32, w: &mut Writer) -> Result<(), Status> {
    start(method, w)?;
    w.u32(handle)
}

pub fn read(handle: u32, count: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::Read, w)?;
    w.u32(handle)?;
    w.u32(count)
}

pub fn write(handle: u32, bytes: &[u8], w: &mut Writer) -> Result<(), Status> {
    start(Method::Write, w)?;
    w.u32(handle)?;
    w.bytes(bytes)
}

pub fn seek(handle: u32, offset: i64, whence: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::Seek, w)?;
    w.u32(handle)?;
    w.u64(offset as u64)?;
    w.u32(whence)
}

pub fn truncate(handle: u32, size: u64, w: &mut Writer) -> Result<(), Status> {
    start(Method::Truncate, w)?;
    w.u32(handle)?;
    w.u64(size)
}

pub fn path_call(method: Method, path: &[u8], w: &mut Writer) -> Result<(), Status> {
    start(method, w)?;
    w.bytes(path)
}

pub fn rename(from: &[u8], to: &[u8], w: &mut Writer) -> Result<(), Status> {
    start(Method::Rename, w)?;
    w.u32(from.len() as u32)?;
    w.bytes(from)?;
    w.bytes(to)
}

pub fn statfs(w: &mut Writer) -> Result<(), Status> {
    start(Method::Statfs, w)
}

/// The two paths of RENAME from its body.
pub fn read_rename<'a>(mut body: Reader<'a>) -> Result<(&'a [u8], &'a [u8]), Status> {
    let from_len = body.u32()? as usize;
    let from = body.bytes(from_len)?;
    let to = body.bytes(body.left())?;
    Ok((from, to))
}

/// The status of a reply and the reader of the fields after it.
pub fn reply(bytes: &[u8]) -> Result<Reader<'_>, Status> {
    let mut r = Reader::new(bytes);
    match Status::from_code(r.u32()?) {
        Status::Ok => Ok(r),
        status => Err(status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_and_codes_are_fixed() {
        assert_eq!(
            Method::ALL.map(Method::number),
            core::array::from_fn(|i| i as u16 + 1)
        );
        for m in Method::ALL {
            assert_eq!(Method::from_number(m.number()), Some(m));
        }
        assert_eq!(Method::from_number(0), None);
        assert_eq!(Method::from_number(17), None);
        for (i, a) in CODES.iter().enumerate() {
            assert!(*a > 1200 && *a < 1300, "{a}");
            assert!(!CODES[i + 1..].contains(a));
        }
    }

    #[test]
    fn two_paths_fit_a_message() {
        const { assert!(HEADER_LEN + 4 + 2 * MAX_PATH <= MESSAGE_MAX) };
        let mut w = Writer::new();
        rename(&[b'a'; MAX_PATH], &[b'b'; MAX_PATH], &mut w).unwrap();
        let (from, to) = read_rename(Reader::new(&w.as_bytes()[HEADER_LEN..])).unwrap();
        assert_eq!((from.len(), to.len()), (MAX_PATH, MAX_PATH));
    }

    #[test]
    fn a_full_write_fits() {
        let mut w = Writer::new();
        write(1, &[0; MAX_WRITE], &mut w).unwrap();
        assert_eq!(w.as_bytes().len(), MESSAGE_MAX);
    }
}
