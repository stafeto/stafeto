// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the data file service (services/datafs), proto_wire, version 2. Every number goes
//! low byte first, every call is one request and one reply whose first four bytes are the status.
//!
//! The service holds the files of the volume mounted at `/data`: paths are absolute from the root of
//! the volume (`/ssh/host_key` for `/data/ssh/host_key`), canonical, with no `.` and `..`. An open file
//! or directory is a description: it has its own position and flags, and a count of the sessions (and
//! passes) that hold it. The number of a description (a handle, one u32) is the same in every session
//! that holds it, and a session that does not hold it gets BAD_HANDLE. A handle is the place of the
//! description (bits 0 to 7), its generation (8 to 15) and the epoch of the service instance (16 to
//! 31): a handle of an earlier instance, which a client keeps over a restart, answers STALE. A call
//! that reads or writes carries its bytes in the message, at most `MAX_READ` or `MAX_WRITE`.
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
//! | FSTAT (9) | `handle` u32 | `kind` u32, `size` u32, `nlink` u32 (1; 0 for a file that was unlinked while open) |
//! | MKDIR (10), UNLINK (11), RMDIR (12) | the path | none |
//! | RENAME (13) | `from_len` u32, the path `from`, the path `to` | none |
//! | READDIR (14) | `handle` u32 | `more` u32, `kind` u32, `size` u32, the name |
//! | REWIND (15) | `handle` u32 | none |
//! | STATFS (16) | none | `blocks` u64, `used` u64, `block` u32 |
//! | PREAD (17) | `handle` u32, `count` u32, `offset` u64 | `count` u32, the bytes |
//! | PWRITE (18) | `handle` u32, `offset` u64, the bytes | `count` u32 |
//! | CLONE (19) | `count` u32 (1 to `CLONE_MAX`), then that many handles | `birth` u32, and one handle: a new session of the service (SEND, TRANSFER) that holds the descriptions, for a child process |
//! | CLONE_MORE (20) | `birth` u32, `count` u32 (1 to `CLONE_MAX`), then the handles | none |
//! | EXPORT (21) | `handle` u32 | one handle: a pass for the description (TRANSFER alone) |
//! | ADOPT (22) | none, and one handle: a pass | `handle` u32, `kind` u32 |
//! | GET_FLAGS (23) | `handle` u32 | `flags` u32 (the access bits, APPEND, DIRECTORY) |
//! | SET_FLAGS (24) | `handle` u32, `flags` u32 (APPEND alone) | none |
//!
//! READ and WRITE use the position of the description and move it; PREAD and PWRITE take the
//! position in the call and leave the description's alone. A description opened with APPEND (or
//! given it by SET_FLAGS) writes every WRITE at the end of the file, and the end is taken when the
//! write runs: two writers never overwrite each other. PWRITE writes at its offset whatever the
//! flag says (POSIX.1-2024; Linux appends). Descriptions of one path share one
//! file, so a write through one is seen by a read through another at once. UNLINK of a file that is
//! open and RENAME over one succeed: the open descriptions keep the old file, which goes when the
//! last of them closes (the service keeps it under a hidden directory meanwhile and removes what a
//! stop left at the next mount; FSTAT then answers `nlink` 0). A RENAME over an open file takes two
//! commits of the volume (the old target moves to the hidden directory, then the source moves):
//! the target carries a mark with its home name between them, and the next mount puts a marked file
//! whose home name is missing back, so after a cut of the power the old name or the new is there once
//! the service has mounted again. The service never answers a request before that mount work is done.
//!
//! CLONE makes a session of the service for a child and gives it the descriptions listed (one
//! reference each, and the position shared with the parent). `birth` names that session for
//! CLONE_MORE, which the parent sends while the child has sent nothing, to add more; a description
//! the session holds already is passed over. EXPORT makes a pass that holds one reference of the
//! description; ADOPT, sent by whoever holds the pass, spends it and gives the description to the
//! sender's session (the reference of the pass becomes the session's). A pass whose last copy goes
//! unspent gives its reference up. A session holds `HELD_MAX` descriptions at most (TOO_MANY_OPEN).
//! The sessions of one process tree (a client and the clones made from it, and theirs) share
//! `ROOT_CLONES` live clones, `ROOT_DESCRIPTIONS` distinct descriptions and `PASSES_MAX` unspent
//! passes; past them TOO_MANY_OPEN. A table of the service that is full as a whole answers
//! TABLE_FULL. An ADOPT refused for either limit leaves the pass unspent, and the service gives
//! the pass handle back in the reply.
//!
//! FSYNC makes the file's data and its place in the tree durable before it answers. MKDIR, UNLINK,
//! RMDIR and RENAME are durable when they answer, and RENAME is one step: after a cut of the power the
//! old name or the new is there. A file the service made with OPEN and CREATE exists, empty, from the
//! open; its bytes are the file's after the FSYNC or the CLOSE that follows, and a cut before that
//! leaves the contents of the last sync.

#![cfg_attr(not(test), no_std)]

use abi::MESSAGE_MAX;
use proto_wire::{HEADER_LEN, Header, Reader, Status, Writer};

pub const VERSION: u16 = 2;

/// The longest path, in bytes: two of them and the fields of RENAME fit one message.
pub const MAX_PATH: usize = 480;
/// The bytes one READ or WRITE carries at most.
pub const MAX_READ: usize = MESSAGE_MAX - 8;
pub const MAX_WRITE: usize = MESSAGE_MAX - HEADER_LEN - 4;
/// The bytes of a block of the volume.
pub const BLOCK: u32 = 4096;
/// The descriptions one session holds at most (a read-write open file or directory each).
pub const HELD_MAX: usize = 6;
/// The descriptions CLONE and CLONE_MORE carry at most.
pub const CLONE_MAX: usize = HELD_MAX;
/// The passes one process tree has made and not spent at once.
pub const PASSES_MAX: usize = 4;
/// The live clones of one process tree (the sessions made by CLONE under one client).
pub const ROOT_CLONES: usize = 8;
/// The distinct descriptions the sessions of one process tree hold together.
pub const ROOT_DESCRIPTIONS: usize = 10;

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
/// The handle is of an earlier instance of the service (a restart since it was given).
pub const STALE: u32 = 1216;
/// The caller's identity does not allow the operation (EACCES).
pub const ACCESS: u32 = 1217;
/// A table of the service as a whole is full (descriptions, open files, directories, sessions,
/// passes): ENFILE. TOO_MANY_OPEN is a limit of the session or of its process tree: EMFILE.
pub const TABLE_FULL: u32 = 1218;

pub const CODES: [u32; 18] = [
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
    STALE,
    ACCESS,
    TABLE_FULL,
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
    Pread = 17,
    Pwrite = 18,
    Clone = 19,
    CloneMore = 20,
    Export = 21,
    Adopt = 22,
    GetFlags = 23,
    SetFlags = 24,
}

impl Method {
    pub const ALL: [Method; 24] = [
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
        Method::Pread,
        Method::Pwrite,
        Method::Clone,
        Method::CloneMore,
        Method::Export,
        Method::Adopt,
        Method::GetFlags,
        Method::SetFlags,
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
pub const METHODS: [u16; 24] = {
    let mut numbers = [0; 24];
    let mut i = 0;
    while i < 24 {
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

pub fn pread(handle: u32, count: u32, offset: u64, w: &mut Writer) -> Result<(), Status> {
    start(Method::Pread, w)?;
    w.u32(handle)?;
    w.u32(count)?;
    w.u64(offset)
}

pub fn pwrite(handle: u32, offset: u64, bytes: &[u8], w: &mut Writer) -> Result<(), Status> {
    start(Method::Pwrite, w)?;
    w.u32(handle)?;
    w.u64(offset)?;
    w.bytes(bytes)
}

/// CLONE of at most `CLONE_MAX` handles.
pub fn clone(handles: &[u32], w: &mut Writer) -> Result<(), Status> {
    start(Method::Clone, w)?;
    w.u32(handles.len() as u32)?;
    handles.iter().try_for_each(|&h| w.u32(h))
}

pub fn clone_more(birth: u32, handles: &[u32], w: &mut Writer) -> Result<(), Status> {
    start(Method::CloneMore, w)?;
    w.u32(birth)?;
    w.u32(handles.len() as u32)?;
    handles.iter().try_for_each(|&h| w.u32(h))
}

/// ADOPT: the header alone (the pass goes as a handle of the call).
pub fn adopt(w: &mut Writer) -> Result<(), Status> {
    start(Method::Adopt, w)
}

pub fn set_flags(handle: u32, flags: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::SetFlags, w)?;
    w.u32(handle)?;
    w.u32(flags)
}

/// The handles of CLONE or CLONE_MORE after their first words: the count was read, the rest are
/// `count` words. At most `CLONE_MAX`; a count that does not fit the body is BAD_SIZE.
pub fn read_handles(
    mut body: Reader<'_>,
    count: u32,
    out: &mut [u32; CLONE_MAX],
) -> Result<usize, Status> {
    let count = count as usize;
    if count > CLONE_MAX {
        return Err(code(INVALID));
    }
    for slot in out.iter_mut().take(count) {
        *slot = body.u32()?;
    }
    body.finish()?;
    Ok(count)
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
        assert_eq!(Method::from_number(25), None);
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
    fn clone_carries_its_handles() {
        let mut w = Writer::new();
        clone(&[5, 6, 7], &mut w).unwrap();
        let mut r = Reader::new(&w.as_bytes()[HEADER_LEN..]);
        let count = r.u32().unwrap();
        let mut out = [0; CLONE_MAX];
        assert_eq!(read_handles(r, count, &mut out), Ok(3));
        assert_eq!(out[..3], [5, 6, 7]);
        let mut w = Writer::new();
        clone_more(9, &[1], &mut w).unwrap();
        let mut r = Reader::new(&w.as_bytes()[HEADER_LEN..]);
        assert_eq!(r.u32(), Ok(9));
        let count = r.u32().unwrap();
        assert_eq!(read_handles(r, count, &mut out), Ok(1));
        // Too many, and a body that is not the count.
        let r = Reader::new(&[0; 4]);
        assert_eq!(read_handles(r, 99, &mut out), Err(code(INVALID)));
        let r = Reader::new(&[0; 4]);
        assert!(read_handles(r, 2, &mut out).is_err());
        let r = Reader::new(&[0; 8]);
        assert!(read_handles(r, 1, &mut out).is_err());
    }

    #[test]
    fn a_full_write_fits() {
        let mut w = Writer::new();
        write(1, &[0; MAX_WRITE], &mut w).unwrap();
        assert_eq!(w.as_bytes().len(), MESSAGE_MAX);
    }
}
