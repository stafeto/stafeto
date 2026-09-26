// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of init (spec 13.3, 13.4, proto_wire): the numbers of its
//! seven methods, which never change once given, and the bodies of those
//! milestone 1.4b uses. REGISTER, CONNECT, LIST and STATS get their bodies
//! with the services of milestone 1.4c.
//!
//! START: a program asks its parent for its start data through its start
//! channel (spec 13.3); the request is the header alone, and each START
//! gets the next reply until one with LAST. A reply that is not a refusal
//! (`StartReply`):
//!
//! | Bytes | Field |
//! |---|---|
//! | 0..4 | status 0 |
//! | 4..6 | flags: bit 0 LAST, the others 0 |
//! | 6..8 | length of the piece of arguments, at most START_PIECE_MAX |
//! | 8..72 | four names of 16 bytes: name i names handle i of the reply |
//! | 72.. | the piece of arguments |
//!
//! The reply is 72 bytes and its piece long. Names past the count of
//! handles that came are 16 zeros. A refusal is its status alone
//! (proto_wire::reply).
//!
//! HEARTBEAT: a service tells init that it lives (spec 13.4); PING: a round
//! trip to init, for bench (spec 13.6). The request of each is the header
//! alone, the reply its status alone.

#![cfg_attr(not(test), no_std)]

use abi::{MESSAGE_HANDLES, MESSAGE_MAX};
use proto_wire::{HEADER_LEN, Header, NAME_LEN, Name, Reader, Status, Writer};

/// The version of the protocol, in the header of each request.
pub const VERSION: u16 = 1;

/// The methods of init with their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Start = 1,
    Register = 2,
    Connect = 3,
    Heartbeat = 4,
    List = 5,
    Stats = 6,
    Ping = 7,
}

impl Method {
    pub const ALL: [Method; 7] = [
        Method::Start,
        Method::Register,
        Method::Connect,
        Method::Heartbeat,
        Method::List,
        Method::Stats,
        Method::Ping,
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

/// Names in a reply to START: one per handle a message carries.
pub const START_NAMES: usize = MESSAGE_HANDLES;
/// The bytes of a reply to START before its piece of arguments.
pub const START_FIXED: usize = HEADER_LEN + START_NAMES * NAME_LEN;
/// The longest piece of arguments one reply carries.
pub const START_PIECE_MAX: usize = MESSAGE_MAX - START_FIXED;
/// The flag of the last reply to START.
pub const LAST: u16 = 1;

/// A reply to START that is no refusal (the table above).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartReply<'a> {
    pub last: bool,
    /// Name i names handle i of the reply; None past their count.
    pub names: [Option<Name>; START_NAMES],
    pub args: &'a [u8],
}

impl<'a> StartReply<'a> {
    /// BAD_SIZE for a piece longer than START_PIECE_MAX.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        let len = u16::try_from(self.args.len()).map_err(|_| Status::BadSize)?;
        if usize::from(len) > START_PIECE_MAX {
            return Err(Status::BadSize);
        }
        w.u32(Status::Ok.code())?;
        w.u16(if self.last { LAST } else { 0 })?;
        w.u16(len)?;
        for name in self.names {
            w.name(name)?;
        }
        w.bytes(self.args)
    }

    /// The reply in `bytes`, which came with `handles` handles: BAD_SIZE
    /// unless its status is 0, its flags are LAST or 0, its piece is at
    /// most START_PIECE_MAX and the bytes after the names, and exactly the
    /// first `handles` names are there.
    pub fn read(bytes: &'a [u8], handles: usize) -> Result<StartReply<'a>, Status> {
        let mut r = Reader::new(bytes);
        let (status, flags, len) = (r.u32()?, r.u16()?, usize::from(r.u16()?));
        if status != 0 || flags & !LAST != 0 || len > START_PIECE_MAX || handles > START_NAMES {
            return Err(Status::BadSize);
        }
        let mut names = [None; START_NAMES];
        for (i, name) in names.iter_mut().enumerate() {
            *name = r.name()?;
            if name.is_some() != (i < handles) {
                return Err(Status::BadSize);
            }
        }
        let args = r.bytes(len)?;
        r.finish()?;
        Ok(StartReply {
            last: flags == LAST,
            names,
            args,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Option<Name> {
        Some(Name::new(s.as_bytes()).unwrap())
    }

    fn written(reply: &StartReply<'_>) -> Vec<u8> {
        let mut w = Writer::new();
        reply.write(&mut w).unwrap();
        w.as_bytes().to_vec()
    }

    #[test]
    fn start_reply_round_trips() {
        let args = [0xA5; 40];
        let reply = StartReply {
            last: true,
            names: [name("process"), name("thread"), None, None],
            args: &args,
        };
        let bytes = written(&reply);
        assert_eq!(bytes.len(), START_FIXED + 40);
        assert_eq!(bytes[..8], [0, 0, 0, 0, 1, 0, 40, 0]);
        assert_eq!(&bytes[8..15], b"process");
        assert_eq!(&bytes[24..30], b"thread");
        assert_eq!(bytes[40..72], [0; 32]);
        assert_eq!(bytes[72..], args);
        assert_eq!(StartReply::read(&bytes, 2), Ok(reply));
        let piece = StartReply {
            last: false,
            names: [name("0"), name("1"), name("2"), name("3")],
            args: &[],
        };
        let bytes = written(&piece);
        assert_eq!(bytes.len(), START_FIXED);
        assert_eq!(StartReply::read(&bytes, 4), Ok(piece));
        // A refusal is no reply of this layout.
        let refused = proto_wire::reply(Status::BadVersion);
        assert_eq!(StartReply::read(&refused, 0), Err(Status::BadSize));
        // Nor are flags other than LAST.
        let mut flagged = written(&piece);
        flagged[4] = 2;
        assert_eq!(StartReply::read(&flagged, 4), Err(Status::BadSize));
    }

    #[test]
    fn start_reply_refuses_names_past_the_handles() {
        let reply = StartReply {
            last: true,
            names: [name("process"), name("thread"), name("extra"), None],
            args: &[],
        };
        let bytes = written(&reply);
        assert_eq!(StartReply::read(&bytes, 3), Ok(reply));
        // A name without its handle, and a handle without its name.
        assert_eq!(StartReply::read(&bytes, 2), Err(Status::BadSize));
        assert_eq!(StartReply::read(&bytes, 4), Err(Status::BadSize));
        assert_eq!(StartReply::read(&bytes, 5), Err(Status::BadSize));
    }

    #[test]
    fn start_reply_refuses_a_long_args_length() {
        let long = [7; START_PIECE_MAX + 1];
        let mut w = Writer::new();
        let too_long = StartReply {
            last: true,
            names: [None; START_NAMES],
            args: &long,
        };
        assert_eq!(too_long.write(&mut w), Err(Status::BadSize));
        let most = StartReply {
            args: &long[..START_PIECE_MAX],
            ..too_long
        };
        let mut bytes = written(&most);
        assert_eq!(bytes.len(), MESSAGE_MAX);
        assert_eq!(StartReply::read(&bytes, 0), Ok(most));
        // A length past the most, or other than the bytes after the names.
        bytes[6..8].copy_from_slice(&(START_PIECE_MAX as u16 + 1).to_le_bytes());
        assert_eq!(StartReply::read(&bytes, 0), Err(Status::BadSize));
        bytes[6..8].copy_from_slice(&(START_PIECE_MAX as u16 - 1).to_le_bytes());
        assert_eq!(StartReply::read(&bytes, 0), Err(Status::BadSize));
        assert_eq!(
            StartReply::read(&bytes[..MESSAGE_MAX - 2], 0),
            Err(Status::BadSize)
        );
    }

    #[test]
    fn method_numbers_are_fixed() {
        let numbers = Method::ALL.map(Method::number);
        assert_eq!(numbers, [1, 2, 3, 4, 5, 6, 7]);
        for m in Method::ALL {
            assert_eq!(Method::from_number(m.number()), Some(m));
            assert_eq!(m.header(), Header::new(m.number(), VERSION));
        }
        assert_eq!(Method::from_number(0), None);
        assert_eq!(Method::from_number(8), None);
        assert_eq!(VERSION, 1);
        assert_eq!(Method::Start.header().bytes(), [1, 0, 1, 0, 0, 0, 0, 0]);
        assert_eq!(START_PIECE_MAX, 952);
    }
}
