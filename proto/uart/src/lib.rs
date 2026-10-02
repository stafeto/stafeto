// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the UART driver (spec 13.5, 13.8, proto_wire): the
//! numbers of its methods, which never change once given, and their
//! bodies. Every number goes low byte first.
//!
//! WRITE: the request (`WriteRequest`) is the header and 0 to WRITE_MAX bytes to
//! show. The driver answers once all of them are in its ring of output: at
//! once when they fit, later when they wait for room; it never takes a
//! part. The reply that is no refusal (`WriteReply`):
//!
//! | Bytes | Field |
//! |---|---|
//! | 0..4 | status 0 |
//! | 4..8 | the bytes written: all of them |
//!
//! READ: the request (`ReadRequest`):
//!
//! | Bytes | Field |
//! |---|---|
//! | 0..8 | header |
//! | 8..12 | the most bytes to take, 1 to READ_MAX |
//! | 12..16 | zero |
//!
//! The first client that reads owns the console until it goes; a READ of
//! another gets BAD_STATE. The reply waits for input. The reply that is
//! no refusal (`ReadReply`): bytes 0..4 status 0, 4..8 the count of
//! bytes, 1 up to the most asked, then the bytes.
//!
//! CRASH: the request is the header alone; there is no reply: the driver
//! loads from address 0, which ends it with a fault, to show that a fault
//! stays inside its process. Only a driver built with the feature `crash`
//! has the method.
//!
//! READ_START (7), READ_TAKE (8) and READ_CANCEL (9) are a read in two
//! steps (proto_wire::long), for a client that waits on a channel of its
//! own: READ_START has the body of READ and answers READY with the bytes
//! there are, or WAIT k; READ_TAKE carries k (and, the first time, a
//! handle with NOTIFY labelled k) and answers READY or ARMED; the driver
//! sets bit 0 there once input came, and keeps the bytes until READ_TAKE;
//! READ_CANCEL carries k and answers CANCELLED, or READY with input that
//! came. A failed data reply leaves its bytes available to the next reader.
//! Number 4 belongs to TRACE, which comes with milestone 1.4e; 5 and 6
//! (READ_CANCELABLE, CANCEL_READ of version 1) are retired.

#![cfg_attr(not(test), no_std)]

use abi::MESSAGE_MAX;
use proto_wire::{HEADER_LEN, Header, Reader, Status, Writer};

/// The version of the protocol, in the header of each request.
pub const VERSION: u16 = 2;

/// The number kept for TRACE (milestone 1.4e): no method of this version.
pub const TRACE: u16 = 4;

/// The most bytes of one WRITE: a message less its header.
pub const WRITE_MAX: usize = MESSAGE_MAX - HEADER_LEN;
/// The most bytes one READ asks for and its reply brings.
pub const READ_MAX: usize = MESSAGE_MAX - HEADER_LEN;
/// The bytes of a reply to READ before its bytes.
pub const READ_FIXED: usize = 8;

/// The methods of the driver with their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Write = 1,
    Read = 2,
    Crash = 3,
    ReadStart = 7,
    ReadTake = 8,
    ReadCancel = 9,
}

impl Method {
    pub const ALL: [Method; 6] = [
        Method::Write,
        Method::Read,
        Method::Crash,
        Method::ReadStart,
        Method::ReadTake,
        Method::ReadCancel,
    ];

    pub const fn number(self) -> u16 {
        self as u16
    }

    pub fn from_number(number: u16) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.number() == number)
    }

    /// The header of a request of this method.
    pub const fn header(self) -> Header {
        Header::new(self.number(), VERSION)
    }
}

/// A request of WRITE: the bytes to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteRequest<'a> {
    pub bytes: &'a [u8],
}

impl<'a> WriteRequest<'a> {
    /// The header of WRITE, then the bytes: BAD_SIZE past WRITE_MAX.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if self.bytes.len() > WRITE_MAX {
            return Err(Status::BadSize);
        }
        Method::Write.header().write(w)?;
        w.bytes(self.bytes)
    }

    /// The request from `body`, its bytes after the header: BAD_SIZE past
    /// WRITE_MAX bytes.
    pub fn read(mut body: Reader<'a>) -> Result<WriteRequest<'a>, Status> {
        let len = body.left();
        if len > WRITE_MAX {
            return Err(Status::BadSize);
        }
        let bytes = body.bytes(len)?;
        body.finish()?;
        Ok(WriteRequest { bytes })
    }
}

/// A reply to WRITE that is no refusal: the bytes written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteReply {
    pub written: u32,
}

impl WriteReply {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(Status::Ok.code())?;
        w.u32(self.written)
    }

    /// The reply in `bytes`: BAD_SIZE unless its status is 0 and it is 8
    /// bytes.
    pub fn read(bytes: &[u8]) -> Result<WriteReply, Status> {
        let mut r = Reader::new(bytes);
        let (status, written) = (r.u32()?, r.u32()?);
        r.finish()?;
        if status != 0 {
            return Err(Status::BadSize);
        }
        Ok(WriteReply { written })
    }
}

/// A request of READ: the most bytes to take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    pub max: u32,
}

impl ReadRequest {
    fn check(max: u32) -> Result<(), Status> {
        if max == 0 || max as usize > READ_MAX {
            Err(Status::BadSize)
        } else {
            Ok(())
        }
    }

    /// The header of READ, the most bytes and four zeros: BAD_SIZE for a
    /// most of 0 or past READ_MAX.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        ReadRequest::check(self.max)?;
        Method::Read.header().write(w)?;
        w.u32(self.max)?;
        w.u32(0)
    }

    /// The request from `body`, its bytes after the header: BAD_SIZE
    /// unless they are a most of 1 to READ_MAX and four zeros.
    pub fn read(mut body: Reader<'_>) -> Result<ReadRequest, Status> {
        let (max, zero) = (body.u32()?, body.u32()?);
        body.finish()?;
        ReadRequest::check(max)?;
        if zero != 0 {
            return Err(Status::BadSize);
        }
        Ok(ReadRequest { max })
    }
}

impl ReadRequest {
    /// READ_START with this most: the body of READ.
    pub fn write_start(&self, w: &mut Writer) -> Result<(), Status> {
        ReadRequest::check(self.max)?;
        Method::ReadStart.header().write(w)?;
        w.u32(self.max)?;
        w.u32(0)
    }
}

/// READ_TAKE and READ_CANCEL: the header and the key k of the read (k above 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadKey {
    pub key: u64,
}

impl ReadKey {
    pub fn write(&self, method: Method, w: &mut Writer) -> Result<(), Status> {
        if self.key == 0 || !matches!(method, Method::ReadTake | Method::ReadCancel) {
            return Err(Status::BadSize);
        }
        method.header().write(w)?;
        w.u64(self.key)
    }

    pub fn read(mut body: Reader<'_>) -> Result<Self, Status> {
        let key = body.u64()?;
        body.finish()?;
        if key == 0 {
            return Err(Status::BadSize);
        }
        Ok(Self { key })
    }
}

/// A reply to READ that is no refusal: the bytes that came, at least one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadReply<'a> {
    pub bytes: &'a [u8],
}

impl<'a> ReadReply<'a> {
    /// Status 0, the count and the bytes: BAD_SIZE for none or past
    /// READ_MAX.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        let count = self.bytes.len();
        if count == 0 || count > READ_MAX {
            return Err(Status::BadSize);
        }
        w.u32(Status::Ok.code())?;
        w.u32(count as u32)?;
        w.bytes(self.bytes)
    }

    /// The reply in `bytes` to a READ of at most `max`: BAD_SIZE unless its
    /// status is 0 and its count is 1 to `max` and exactly the bytes after
    /// it.
    pub fn read(bytes: &'a [u8], max: u32) -> Result<ReadReply<'a>, Status> {
        let mut r = Reader::new(bytes);
        let (status, count) = (r.u32()?, r.u32()?);
        if status != 0 || count == 0 || count > max || count as usize != r.left() {
            return Err(Status::BadSize);
        }
        let bytes = r.bytes(count as usize)?;
        r.finish()?;
        Ok(ReadReply { bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_numbers_are_fixed() {
        assert_eq!(Method::ALL.map(Method::number), [1, 2, 3, 7, 8, 9]);
        for m in Method::ALL {
            assert_eq!(Method::from_number(m.number()), Some(m));
            assert_eq!(m.header(), Header::new(m.number(), VERSION));
        }
        assert_eq!(TRACE, 4);
        assert_eq!(Method::from_number(TRACE), None);
        assert_eq!(Method::from_number(0), None);
        assert_eq!(Method::from_number(5), None);
        assert_eq!(Method::from_number(6), None);
        assert_eq!(VERSION, 2);
        assert_eq!((WRITE_MAX, READ_MAX), (1016, 1016));
        assert_eq!(Method::Crash.header().bytes(), [3, 0, 2, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn two_step_reads_carry_their_key() {
        let mut w = Writer::new();
        ReadRequest { max: 2 }.write_start(&mut w).unwrap();
        assert_eq!(
            w.as_bytes(),
            [7, 0, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]
        );
        let key = ReadKey {
            key: 0x0807060504030201,
        };
        for (method, number) in [(Method::ReadTake, 8), (Method::ReadCancel, 9)] {
            let mut w = Writer::new();
            key.write(method, &mut w).unwrap();
            assert_eq!(
                w.as_bytes(),
                [number, 0, 2, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
            );
            assert_eq!(ReadKey::read(Reader::new(&w.as_bytes()[8..])), Ok(key));
        }
        for bytes in [&[0; 8][..], &[1; 7][..], &[1; 9][..]] {
            assert_eq!(ReadKey::read(Reader::new(bytes)), Err(Status::BadSize));
        }
        assert_eq!(
            ReadKey { key: 0 }.write(Method::ReadTake, &mut Writer::new()),
            Err(Status::BadSize)
        );
        assert_eq!(
            key.write(Method::Read, &mut Writer::new()),
            Err(Status::BadSize)
        );
    }

    #[test]
    fn write_request_round_trips() {
        for bytes in [&b""[..], b"stafeto> ", &[b'x'; WRITE_MAX]] {
            let request = WriteRequest { bytes };
            let mut w = Writer::new();
            request.write(&mut w).unwrap();
            assert_eq!(w.as_bytes()[..8], Method::Write.header().bytes());
            assert_eq!(&w.as_bytes()[8..], bytes);
            let body = Reader::new(&w.as_bytes()[HEADER_LEN..]);
            assert_eq!(WriteRequest::read(body), Ok(request));
        }
        let reply = WriteReply { written: 9 };
        let mut w = Writer::new();
        reply.write(&mut w).unwrap();
        assert_eq!(w.as_bytes(), [0, 0, 0, 0, 9, 0, 0, 0]);
        assert_eq!(WriteReply::read(w.as_bytes()), Ok(reply));
        let refused = proto_wire::reply(Status::Kernel(abi::Error::LimitReached));
        assert_eq!(WriteReply::read(&refused), Err(Status::BadSize));
        assert_eq!(WriteReply::read(&[0; 7]), Err(Status::BadSize));
    }

    #[test]
    fn write_refuses_more_than_1016_bytes() {
        let long = [b'x'; WRITE_MAX + 1];
        let mut w = Writer::new();
        assert_eq!(
            WriteRequest { bytes: &long }.write(&mut w),
            Err(Status::BadSize)
        );
        assert!(w.as_bytes().is_empty());
        assert_eq!(WriteRequest::read(Reader::new(&long)), Err(Status::BadSize));
        assert!(WriteRequest::read(Reader::new(&long[1..])).is_ok());
    }

    #[test]
    fn read_request_and_reply_round_trip() {
        let request = ReadRequest { max: 0x0102 };
        let mut w = Writer::new();
        request.write(&mut w).unwrap();
        assert_eq!(w.as_bytes()[..8], Method::Read.header().bytes());
        assert_eq!(w.as_bytes()[8..], [2, 1, 0, 0, 0, 0, 0, 0]);
        let body = Reader::new(&w.as_bytes()[HEADER_LEN..]);
        assert_eq!(ReadRequest::read(body), Ok(request));
        let mut dirty = w.as_bytes()[HEADER_LEN..].to_vec();
        dirty[7] = 1;
        assert_eq!(ReadRequest::read(Reader::new(&dirty)), Err(Status::BadSize));
        let reply = ReadReply { bytes: b"help\r" };
        let mut w = Writer::new();
        reply.write(&mut w).unwrap();
        assert_eq!(w.as_bytes()[..READ_FIXED], [0, 0, 0, 0, 5, 0, 0, 0]);
        assert_eq!(&w.as_bytes()[READ_FIXED..], b"help\r");
        assert_eq!(ReadReply::read(w.as_bytes(), 64), Ok(reply));
        assert_eq!(ReadReply::read(w.as_bytes(), 5), Ok(reply));
        let mut w = Writer::new();
        assert_eq!(ReadReply { bytes: b"" }.write(&mut w), Err(Status::BadSize));
    }

    #[test]
    fn read_refuses_a_max_of_0_or_past_1016() {
        for max in [0, READ_MAX as u32 + 1, u32::MAX] {
            let mut w = Writer::new();
            assert_eq!(
                ReadRequest { max }.write(&mut w),
                Err(Status::BadSize),
                "{max}"
            );
            let mut body = max.to_le_bytes().to_vec();
            body.extend([0; 4]);
            assert_eq!(
                ReadRequest::read(Reader::new(&body)),
                Err(Status::BadSize),
                "{max}"
            );
        }
        for max in [1, READ_MAX as u32] {
            let mut w = Writer::new();
            ReadRequest { max }.write(&mut w).unwrap();
            let body = Reader::new(&w.as_bytes()[HEADER_LEN..]);
            assert_eq!(ReadRequest::read(body), Ok(ReadRequest { max }));
        }
    }

    #[test]
    fn read_reply_refuses_a_count_past_its_bytes() {
        let mut w = Writer::new();
        ReadReply { bytes: b"abc" }.write(&mut w).unwrap();
        let mut bytes = w.as_bytes().to_vec();
        // Four bytes said, three came.
        bytes[4] = 4;
        assert_eq!(ReadReply::read(&bytes, 64), Err(Status::BadSize));
        // Two said, three came.
        bytes[4] = 2;
        assert_eq!(ReadReply::read(&bytes, 64), Err(Status::BadSize));
        // Three said and came, past the most asked.
        bytes[4] = 3;
        assert_eq!(ReadReply::read(&bytes, 2), Err(Status::BadSize));
        // None said.
        let empty = [0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(ReadReply::read(&empty, 64), Err(Status::BadSize));
        let refused = proto_wire::reply(Status::Kernel(abi::Error::BadState));
        assert_eq!(ReadReply::read(&refused, 64), Err(Status::BadSize));
    }

    /// The bytes of the driver's messages as it and its clients write
    /// them, from a writer made again over a longer message: the fields
    /// and nothing past them, whose reader takes them back.
    #[test]
    fn messages_carry_their_fields_and_nothing_more() {
        let write = |f: &dyn Fn(&mut Writer)| {
            let mut w = Writer::new();
            w.bytes(&[0xee; MESSAGE_MAX]).unwrap();
            assert_eq!(w.as_bytes().len(), MESSAGE_MAX);
            w = Writer::new();
            f(&mut w);
            w.as_bytes().to_vec()
        };
        let reply = write(&|w| WriteReply { written: 3 }.write(w).unwrap());
        assert_eq!(reply, [0, 0, 0, 0, 3, 0, 0, 0]);
        assert_eq!(WriteReply::read(&reply), Ok(WriteReply { written: 3 }));
        let reply = write(&|w| ReadReply { bytes: b"ok" }.write(w).unwrap());
        assert_eq!(reply, [0, 0, 0, 0, 2, 0, 0, 0, b'o', b'k']);
        assert_eq!(ReadReply::read(&reply, 64), Ok(ReadReply { bytes: b"ok" }));
        let request = write(&|w| WriteRequest { bytes: b"hi" }.write(w).unwrap());
        assert_eq!(request.len(), HEADER_LEN + 2);
        assert_eq!(&request[HEADER_LEN..], b"hi");
        let key = write(&|w| ReadKey { key: 0x0102 }.write(Method::ReadTake, w).unwrap());
        assert_eq!(key.len(), HEADER_LEN + 8);
        assert_eq!(&key[HEADER_LEN..], &[2, 1, 0, 0, 0, 0, 0, 0]);
    }
}
