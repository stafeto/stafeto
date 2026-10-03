// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Version 1 of the protocol of the pipe service (spec 2, 2 and 3.4; 5e).
//! A pipe has two open descriptions, its read end and its write end, which
//! the service numbers across its sessions: pipe p has the read end 2p and
//! the write end 2p + 1. A session holds a description or not; the
//! descriptors of one process that name it count once, the process's own
//! table keeps them. Every number goes low byte first.
//!
//! - CREATE: body flags u32 (NONBLOCK alone). Reply: status, the read end
//!   u32, the write end u32. NFILE with every pipe of the service in use,
//!   MFILE past CREATED_MAX live pipes the session made or HELD_MAX
//!   descriptions it holds; NFILE past 48 live pipes of the session's
//!   root (a client of init and the chain of clones its process tree
//!   made), three quarters of the pool. The waiting operations of a root
//!   are bounded too (96 of 128): past them READ_START and WRITE_START
//!   answer AGAIN.
//! - READ_START: body the end u32, the count u32 (1 to MAX_READ). A long
//!   operation in two steps (proto_wire::long): READY with the bytes there
//!   are, at most the count; READY with none at the end of the data, when
//!   no session holds the write end (EOF); AGAIN for an empty pipe whose
//!   read end has NONBLOCK; otherwise WAIT k. READ_TAKE: body k u64, then
//!   the body of READ_START again (and, the first time, a handle with
//!   NOTIFY labelled k). READ_CANCEL: body k u64, the end u32; CANCELLED,
//!   and no byte is taken.
//! - WRITE_START: body the end u32, then 1 to MAX_WRITE bytes. Up to ATOMIC
//!   bytes go whole or wait for room; more go as far as there is room, and
//!   wait only for a full pipe. READY with the count u32 written; BROKEN
//!   when no session holds the read end (EPIPE); AGAIN where the write
//!   would wait and the write end has NONBLOCK. WRITE_TAKE: body k u64,
//!   then the body of WRITE_START again: the service keeps no byte of a
//!   write that waits, so WRITE_CANCEL (body k u64, the end u32) never
//!   has an effect.
//! - CLOSE: body the end u32: the session holds it no more. Reply: status.
//! - CLONE: body a count u32 (at most HELD_MAX) and as many ends u32, each
//!   held by the session. Reply: status and one handle, a new session
//!   (SEND, TRANSFER) of the service's own label that holds them, for a
//!   child of the client (5c), with the client's root; LIMIT_REACHED past
//!   255 live clones of the root (one for each record of the process
//!   service) or 320 in the service.
//! - GET_FLAGS: body the end u32. Reply: status, flags u32 (NONBLOCK, and
//!   WRITE_END for a write end). SET_FLAGS: body the end u32, flags u32
//!   (NONBLOCK alone): the flag of the description, which every session
//!   that holds it shares. STAT: body the end u32. Reply: status, the pipe
//!   u32, the bytes in it u32.
//! - ABANDON: no body: the session's long operations that wait go, as when
//!   the session goes (the threads of an old image at exec). Reply: status.
//!
//! WatchStart/Take/Cancel use proto_wire::watch: at most 32 descriptions,
//! one registration per actual description, READY through Cancel, which
//! recomputes every original element and frees the registration.
//!
//! BAD_FD for an end the session does not hold or of the wrong kind.
//! An end goes when its last session lets go of it: by CLOSE, or when the
//! session ends (CLIENT_GONE), in steps of one description each.

#![cfg_attr(not(test), no_std)]

use abi::MESSAGE_MAX;
use proto_wire::{HEADER_LEN, Header, Reader, Status, Writer};

pub const VERSION: u16 = 1;

/// The pipes of the service.
pub const PIPES: usize = 64;
/// The bytes a pipe holds.
pub const CAPACITY: usize = 4096;
/// {PIPE_BUF}: a write of at most this many bytes goes whole or not at all.
pub const ATOMIC: usize = 512;
/// The descriptions one session holds at most (the layer's OPEN_MAX).
pub const HELD_MAX: usize = 32;
/// The live pipes one session made at most.
pub const CREATED_MAX: usize = 16;
/// The operations that wait at one end at most; past them, AGAIN.
pub const WAITERS: usize = 8;

/// The most bytes one read asks for: a reply of status, READY and bytes.
pub const MAX_READ: usize = MESSAGE_MAX - 8;
/// The most bytes one write carries: WRITE_TAKE's header, key and end
/// come before them.
pub const MAX_WRITE: usize = MESSAGE_MAX - HEADER_LEN - 12;

/// The flag of a description that makes a read or write that would wait
/// answer AGAIN.
pub const NONBLOCK: u32 = 1;
/// GET_FLAGS: the description is a write end.
pub const WRITE_END: u32 = 2;

/// EBADF.
pub const BAD_FD: u32 = 701;
/// EAGAIN.
pub const AGAIN: u32 = 702;
/// EPIPE.
pub const BROKEN: u32 = 703;
/// ENFILE.
pub const NFILE: u32 = 704;
/// EMFILE.
pub const MFILE: u32 = 705;
/// EINVAL.
pub const INVALID: u32 = 706;

/// The labels the service gives itself: bit 63, which no label of init
/// has.
pub const OWN: u64 = 1 << 63;

/// The pipe of an end and whether it is the write end.
pub const fn end_of(description: u32) -> (usize, bool) {
    ((description / 2) as usize, description % 2 == 1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Create = 1,
    ReadStart = 2,
    ReadTake = 3,
    ReadCancel = 4,
    WriteStart = 5,
    WriteTake = 6,
    WriteCancel = 7,
    Close = 8,
    Clone = 9,
    GetFlags = 10,
    SetFlags = 11,
    Stat = 12,
    Abandon = 13,
    WatchStart = 14,
    WatchTake = 15,
    WatchCancel = 16,
}

impl Method {
    pub const ALL: [Method; 16] = [
        Method::Create,
        Method::ReadStart,
        Method::ReadTake,
        Method::ReadCancel,
        Method::WriteStart,
        Method::WriteTake,
        Method::WriteCancel,
        Method::Close,
        Method::Clone,
        Method::GetFlags,
        Method::SetFlags,
        Method::Stat,
        Method::Abandon,
        Method::WatchStart,
        Method::WatchTake,
        Method::WatchCancel,
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

pub const METHODS: &[u16] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

/// READ_START or READ_TAKE: the key of a take, the end and the count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Read {
    pub key: Option<u64>,
    pub end: u32,
    pub count: u32,
}

impl Read {
    /// READ_START without a key, READ_TAKE with one: BAD_SIZE for a count
    /// of 0 or past MAX_READ, or a key of 0.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if self.count == 0 || self.count as usize > MAX_READ || self.key == Some(0) {
            return Err(Status::BadSize);
        }
        match self.key {
            None => Method::ReadStart.header().write(w)?,
            Some(key) => {
                Method::ReadTake.header().write(w)?;
                w.u64(key)?;
            }
        }
        w.u32(self.end)?;
        w.u32(self.count)
    }

    /// The body of READ_START (`take` false) or READ_TAKE.
    pub fn parse(mut body: Reader<'_>, take: bool) -> Result<Read, Status> {
        let key = if take { Some(body.u64()?) } else { None };
        let (end, count) = (body.u32()?, body.u32()?);
        body.finish()?;
        let read = Read { key, end, count };
        if read.count == 0 || read.count as usize > MAX_READ || key == Some(0) {
            return Err(Status::BadSize);
        }
        Ok(read)
    }
}

/// WRITE_START or WRITE_TAKE: the key of a take, the end and the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Write<'a> {
    pub key: Option<u64>,
    pub end: u32,
    pub bytes: &'a [u8],
}

impl<'a> Write<'a> {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if self.bytes.is_empty() || self.bytes.len() > MAX_WRITE || self.key == Some(0) {
            return Err(Status::BadSize);
        }
        match self.key {
            None => Method::WriteStart.header().write(w)?,
            Some(key) => {
                Method::WriteTake.header().write(w)?;
                w.u64(key)?;
            }
        }
        w.u32(self.end)?;
        w.bytes(self.bytes)
    }

    pub fn parse(mut body: Reader<'a>, take: bool) -> Result<Write<'a>, Status> {
        let key = if take { Some(body.u64()?) } else { None };
        let end = body.u32()?;
        let len = body.left();
        if len == 0 || len > MAX_WRITE || key == Some(0) {
            return Err(Status::BadSize);
        }
        let bytes = body.bytes(len)?;
        body.finish()?;
        Ok(Write { key, end, bytes })
    }
}

/// READ_CANCEL or WRITE_CANCEL: the key and the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancel {
    pub key: u64,
    pub end: u32,
}

impl Cancel {
    pub fn write(&self, method: Method, w: &mut Writer) -> Result<(), Status> {
        if self.key == 0 || !matches!(method, Method::ReadCancel | Method::WriteCancel) {
            return Err(Status::BadSize);
        }
        method.header().write(w)?;
        w.u64(self.key)?;
        w.u32(self.end)
    }

    pub fn parse(mut body: Reader<'_>) -> Result<Cancel, Status> {
        let (key, end) = (body.u64()?, body.u32()?);
        body.finish()?;
        if key == 0 {
            return Err(Status::BadSize);
        }
        Ok(Cancel { key, end })
    }
}

/// The result of a READY write: the count written.
pub fn written(result: &[u8]) -> Result<u32, Status> {
    let mut r = Reader::new(result);
    let count = r.u32()?;
    r.finish()?;
    Ok(count)
}

/// A request of one end alone (CLOSE, GET_FLAGS, STAT) or of an end and a
/// word (SET_FLAGS).
pub fn end_request(
    method: Method,
    end: u32,
    word: Option<u32>,
    w: &mut Writer,
) -> Result<(), Status> {
    method.header().write(w)?;
    w.u32(end)?;
    match word {
        Some(word) => w.u32(word),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_numbers_are_fixed_and_listed() {
        for number in 0..=14u16 {
            let method = Method::from_number(number);
            assert_eq!(method.is_some(), METHODS.contains(&number), "{number}");
            if let Some(m) = method {
                assert_eq!(m.number(), number);
                assert_eq!(m.header(), Header::new(number, VERSION));
            }
        }
        assert_eq!(METHODS.len(), Method::ALL.len());
    }

    #[test]
    fn sizes_fit_a_message() {
        assert_eq!((MAX_READ, MAX_WRITE), (1016, 1004));
        const { assert!(ATOMIC <= MAX_WRITE, "an atomic write is one message") };
        const { assert!(ATOMIC < CAPACITY) };
        assert_eq!(end_of(7), (3, true));
        assert_eq!(end_of(6), (3, false));
    }

    #[test]
    fn reads_and_writes_round_trip() {
        for read in [
            Read {
                key: None,
                end: 4,
                count: 1,
            },
            Read {
                key: Some(0x1_0000_0002),
                end: 9,
                count: MAX_READ as u32,
            },
        ] {
            let mut w = Writer::new();
            read.write(&mut w).unwrap();
            let body = Reader::new(&w.as_bytes()[HEADER_LEN..]);
            assert_eq!(Read::parse(body, read.key.is_some()), Ok(read));
        }
        for bad in [
            Read {
                key: None,
                end: 0,
                count: 0,
            },
            Read {
                key: None,
                end: 0,
                count: MAX_READ as u32 + 1,
            },
            Read {
                key: Some(0),
                end: 0,
                count: 1,
            },
        ] {
            assert_eq!(bad.write(&mut Writer::new()), Err(Status::BadSize));
        }
        let bytes = [7u8; MAX_WRITE];
        for write in [
            Write {
                key: None,
                end: 5,
                bytes: b"x",
            },
            Write {
                key: Some(3),
                end: 5,
                bytes: &bytes,
            },
        ] {
            let mut w = Writer::new();
            write.write(&mut w).unwrap();
            assert!(w.as_bytes().len() <= MESSAGE_MAX);
            let body = Reader::new(&w.as_bytes()[HEADER_LEN..]);
            assert_eq!(Write::parse(body, write.key.is_some()), Ok(write));
        }
        let long = [7u8; MAX_WRITE + 1];
        assert_eq!(
            Write {
                key: None,
                end: 5,
                bytes: &long
            }
            .write(&mut Writer::new()),
            Err(Status::BadSize)
        );
        assert_eq!(
            Write {
                key: None,
                end: 5,
                bytes: b""
            }
            .write(&mut Writer::new()),
            Err(Status::BadSize)
        );
        let cancel = Cancel { key: 9, end: 2 };
        let mut w = Writer::new();
        cancel.write(Method::WriteCancel, &mut w).unwrap();
        assert_eq!(
            Cancel::parse(Reader::new(&w.as_bytes()[HEADER_LEN..])),
            Ok(cancel)
        );
        assert_eq!(
            cancel.write(Method::Close, &mut Writer::new()),
            Err(Status::BadSize)
        );
        assert_eq!(written(&5u32.to_le_bytes()), Ok(5));
        assert_eq!(written(&[1, 2, 3]), Err(Status::BadSize));
    }
}
