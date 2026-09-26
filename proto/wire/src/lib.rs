// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What every protocol of stafeto shares (spec 13.8): the header of a
//! request, the status of a reply, names, and messages read and written
//! one field at a time. A message is a plain Rust value with its own
//! `write` and `read`, and its layout is a table of offsets in the
//! description of its protocol; every number goes low byte first. No
//! message is a `#[repr(C)]` structure seen as bytes: each read checks the
//! size, and no padding of a structure goes out in a message.
//!
//! A request starts with its header:
//!
//! | Bytes | Field |
//! |---|---|
//! | 0..2 | the method |
//! | 2..4 | the version of the protocol |
//! | 4..8 | zero |
//!
//! A reply starts with its status, bytes 0..4 (`Status`); a reply that is
//! its status alone has 4 bytes of zero after it (`reply`).
//!
//! A protocol has one number `VERSION`, and its service takes that version
//! alone. A new method keeps the version: an old client never calls it,
//! and a new client gets UNKNOWN_METHOD from an old service. A new layout
//! of a method changes the version.

#![cfg_attr(not(test), no_std)]

use abi::{Error, MESSAGE_MAX};
use core::fmt;

/// The bytes of the header of a request, and of a reply that is its
/// status alone.
pub const HEADER_LEN: usize = 8;
/// The bytes of a name in a message.
pub const NAME_LEN: usize = 16;

/// The status of a reply for a method the service does not have, for a
/// version of the protocol it does not take, and for a request of the
/// wrong size or with bytes that must be zero and are not.
pub const UNKNOWN_METHOD: u32 = 256;
pub const BAD_VERSION: u32 = 257;
pub const BAD_SIZE: u32 = 258;

/// The status of a reply: 0 for success, the codes of the kernel's errors
/// (abi::Error, spec 12) with their numbers, so that a limit of a service
/// and a limit of the kernel are the same LIMIT_REACHED, and three codes
/// of the protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    /// Codes 1-255.
    Kernel(Error),
    UnknownMethod,
    BadVersion,
    BadSize,
    /// A code no protocol of this tree gives.
    Unknown(u32),
}

impl Status {
    pub const fn code(self) -> u32 {
        match self {
            Status::Ok => 0,
            Status::Kernel(e) => e.code() as u32,
            Status::UnknownMethod => UNKNOWN_METHOD,
            Status::BadVersion => BAD_VERSION,
            Status::BadSize => BAD_SIZE,
            Status::Unknown(code) => code,
        }
    }

    pub const fn from_code(code: u32) -> Status {
        match code {
            0 => Status::Ok,
            1..=255 => match Error::from_code(code as u64) {
                Some(e) => Status::Kernel(e),
                None => Status::Unknown(code),
            },
            UNKNOWN_METHOD => Status::UnknownMethod,
            BAD_VERSION => Status::BadVersion,
            BAD_SIZE => Status::BadSize,
            _ => Status::Unknown(code),
        }
    }
}

impl From<Error> for Status {
    fn from(e: Error) -> Status {
        Status::Kernel(e)
    }
}

/// The 8 bytes of a reply that is its status alone.
pub fn reply(status: Status) -> [u8; HEADER_LEN] {
    let mut bytes = [0; HEADER_LEN];
    bytes[..4].copy_from_slice(&status.code().to_le_bytes());
    bytes
}

/// The header of a request (the table above).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub method: u16,
    pub version: u16,
}

impl Header {
    pub const fn new(method: u16, version: u16) -> Header {
        Header { method, version }
    }

    /// The 8 bytes of a request that is its header alone, as `write`
    /// puts them.
    pub const fn bytes(self) -> [u8; HEADER_LEN] {
        let [m0, m1] = self.method.to_le_bytes();
        let [v0, v1] = self.version.to_le_bytes();
        [m0, m1, v0, v1, 0, 0, 0, 0]
    }

    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        w.u16(self.method)?;
        w.u16(self.version)?;
        w.u32(0)
    }

    /// BAD_SIZE when the bytes end before 8, or when bytes 4..8 are not
    /// zero.
    pub fn read(r: &mut Reader<'_>) -> Result<Header, Status> {
        let header = Header::new(r.u16()?, r.u16()?);
        match r.u32()? {
            0 => Ok(header),
            _ => Err(Status::BadSize),
        }
    }
}

/// A name in a message: 1 to 16 bytes, none of them zero, padded with
/// zeros to 16. A field of 16 zeros is no name.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Name([u8; NAME_LEN]);

impl Name {
    /// BAD_SIZE for an empty name, one longer than 16 bytes, or one with a
    /// zero byte.
    pub const fn new(name: &[u8]) -> Result<Name, Status> {
        if name.is_empty() || name.len() > NAME_LEN {
            return Err(Status::BadSize);
        }
        let mut field = [0; NAME_LEN];
        let mut i = 0;
        while i < name.len() {
            if name[i] == 0 {
                return Err(Status::BadSize);
            }
            field[i] = name[i];
            i += 1;
        }
        Ok(Name(field))
    }

    /// The name, without its padding.
    pub fn as_bytes(&self) -> &[u8] {
        let len = self.0.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
        &self.0[..len]
    }

    /// The name in a field of 16 bytes: None for 16 zeros; BAD_SIZE when
    /// a zero comes first or a byte other than zero comes after a zero.
    pub fn from_field(field: [u8; NAME_LEN]) -> Result<Option<Name>, Status> {
        if field == [0; NAME_LEN] {
            return Ok(None);
        }
        let len = field.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
        if len == 0 || field[len..].iter().any(|&b| b != 0) {
            return Err(Status::BadSize);
        }
        Ok(Some(Name(field)))
    }

    /// The field of 16 bytes.
    pub const fn field(self) -> [u8; NAME_LEN] {
        self.0
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match core::str::from_utf8(self.as_bytes()) {
            Ok(s) => write!(f, "{s:?}"),
            Err(_) => self.as_bytes().fmt(f),
        }
    }
}

/// Reads the fields of a message in order. A read past the end of the
/// bytes is BAD_SIZE and takes nothing.
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, at: 0 }
    }

    /// The next `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Status> {
        let end = self.at.checked_add(n).ok_or(Status::BadSize)?;
        let taken = self.bytes.get(self.at..end).ok_or(Status::BadSize)?;
        self.at = end;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Status> {
        let mut a = [0; N];
        a.copy_from_slice(self.bytes(N)?);
        Ok(a)
    }

    pub fn u16(&mut self) -> Result<u16, Status> {
        self.array().map(u16::from_le_bytes)
    }

    pub fn u32(&mut self) -> Result<u32, Status> {
        self.array().map(u32::from_le_bytes)
    }

    pub fn u64(&mut self) -> Result<u64, Status> {
        self.array().map(u64::from_le_bytes)
    }

    /// A field of a name (Name::from_field).
    pub fn name(&mut self) -> Result<Option<Name>, Status> {
        Name::from_field(self.array()?)
    }

    /// The bytes not read yet.
    pub fn left(&self) -> usize {
        self.bytes.len() - self.at
    }

    /// The end of the message: BAD_SIZE when bytes are left.
    pub fn finish(self) -> Result<(), Status> {
        match self.left() {
            0 => Ok(()),
            _ => Err(Status::BadSize),
        }
    }
}

/// Writes the fields of a message in order into a buffer of
/// abi::MESSAGE_MAX bytes, the most a message holds. A write past it is
/// BAD_SIZE and writes nothing.
pub struct Writer {
    buffer: [u8; MESSAGE_MAX],
    len: usize,
}

impl Writer {
    pub const fn new() -> Writer {
        Writer {
            buffer: [0; MESSAGE_MAX],
            len: 0,
        }
    }

    pub fn bytes(&mut self, bytes: &[u8]) -> Result<(), Status> {
        let end = self.len + bytes.len();
        let room = self.buffer.get_mut(self.len..end).ok_or(Status::BadSize)?;
        room.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    pub fn u16(&mut self, v: u16) -> Result<(), Status> {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u32(&mut self, v: u32) -> Result<(), Status> {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u64(&mut self, v: u64) -> Result<(), Status> {
        self.bytes(&v.to_le_bytes())
    }

    /// A field of a name; 16 zeros for None.
    pub fn name(&mut self, name: Option<Name>) -> Result<(), Status> {
        self.bytes(&name.map_or([0; NAME_LEN], Name::field))
    }

    /// The message written so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

impl Default for Writer {
    fn default() -> Writer {
        Writer::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        let h = Header::new(0x0102, 0x0304);
        assert_eq!(h.bytes(), [0x02, 0x01, 0x04, 0x03, 0, 0, 0, 0]);
        assert_eq!(Header::read(&mut Reader::new(&h.bytes())), Ok(h));
        let mut w = Writer::new();
        h.write(&mut w).unwrap();
        assert_eq!(w.as_bytes(), h.bytes());
        w.u32(7).unwrap();
        let mut r = Reader::new(w.as_bytes());
        assert_eq!(Header::read(&mut r), Ok(h));
        assert_eq!(r.u32(), Ok(7));
        assert_eq!(r.finish(), Ok(()));
        // Bytes 4..8 are zero, and all eight are there.
        let mut dirty = h.bytes();
        dirty[7] = 1;
        assert_eq!(Header::read(&mut Reader::new(&dirty)), Err(Status::BadSize));
        assert_eq!(
            Header::read(&mut Reader::new(&h.bytes()[..7])),
            Err(Status::BadSize)
        );
    }

    #[test]
    fn status_codes_are_the_kernel_codes() {
        assert_eq!(Status::Ok.code(), 0);
        for e in Error::KNOWN {
            assert_eq!(u64::from(Status::Kernel(e).code()), e.code(), "{e:?}");
            assert_eq!(Status::from_code(e.code() as u32), Status::Kernel(e));
            assert_eq!(Status::from(e), Status::Kernel(e));
        }
        assert_eq!(Status::from_code(10), Status::Kernel(Error::Unknown(10)));
        assert_eq!(Status::from_code(255), Status::Kernel(Error::Unknown(255)));
        for (status, code) in [
            (Status::UnknownMethod, 256),
            (Status::BadVersion, 257),
            (Status::BadSize, 258),
            (Status::Unknown(259), 259),
        ] {
            assert_eq!(status.code(), code);
            assert_eq!(Status::from_code(code), status);
        }
        assert_eq!(
            reply(Status::Kernel(Error::LimitReached)),
            [6, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(reply(Status::BadVersion), [1, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn reader_refuses_bytes_past_the_end() {
        let bytes = [1, 2, 3, 4, 5, 6, 7];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u64(), Err(Status::BadSize));
        // A refused read takes nothing.
        assert_eq!(r.left(), 7);
        assert_eq!(r.u32(), Ok(0x0403_0201));
        assert_eq!(r.u32(), Err(Status::BadSize));
        assert_eq!(r.u16(), Ok(0x0605));
        assert_eq!(r.bytes(2), Err(Status::BadSize));
        assert_eq!(r.name(), Err(Status::BadSize));
        assert_eq!(r.bytes(1), Ok(&[7][..]));
        assert_eq!(r.bytes(usize::MAX), Err(Status::BadSize));
        assert_eq!(r.u16(), Err(Status::BadSize));
        // The writer has its own end: abi::MESSAGE_MAX bytes.
        let mut w = Writer::new();
        w.bytes(&[0; MESSAGE_MAX - 2]).unwrap();
        assert_eq!(w.u32(1), Err(Status::BadSize));
        assert_eq!(w.as_bytes().len(), MESSAGE_MAX - 2);
        assert_eq!(w.u16(1), Ok(()));
    }

    #[test]
    fn reader_refuses_leftover_bytes() {
        let bytes = [1, 0, 2, 0];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u16(), Ok(1));
        assert_eq!(r.finish(), Err(Status::BadSize));
        let mut r = Reader::new(&bytes);
        assert_eq!((r.u16(), r.u16()), (Ok(1), Ok(2)));
        assert_eq!(r.finish(), Ok(()));
        assert_eq!(Reader::new(&[]).finish(), Ok(()));
    }

    #[test]
    fn name_is_1_to_16_bytes_without_zeros() {
        let name = Name::new(b"process").unwrap();
        assert_eq!(name.as_bytes(), b"process");
        assert_eq!(&name.field()[..8], b"process\0");
        let full = Name::new(b"0123456789abcdef").unwrap();
        assert_eq!(full.as_bytes(), b"0123456789abcdef");
        for bad in [&b""[..], b"0123456789abcdefg", b"a\0b", b"\0", b"ab\0"] {
            assert_eq!(Name::new(bad), Err(Status::BadSize), "{bad:?}");
        }
        // In a message: 16 zeros are no name; a zero first, or a byte after
        // a zero, is no field of a name.
        let mut w = Writer::new();
        w.name(Some(name)).unwrap();
        w.name(None).unwrap();
        w.name(Some(full)).unwrap();
        let mut r = Reader::new(w.as_bytes());
        assert_eq!(r.name(), Ok(Some(name)));
        assert_eq!(r.name(), Ok(None));
        assert_eq!(r.name(), Ok(Some(full)));
        assert_eq!(r.finish(), Ok(()));
        let mut inner = name.field();
        inner[9] = b'x';
        assert_eq!(Name::from_field(inner), Err(Status::BadSize));
        let mut first = [0; NAME_LEN];
        first[1] = b'x';
        assert_eq!(Name::from_field(first), Err(Status::BadSize));
    }
}
