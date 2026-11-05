// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the disk service (services/virtio-blk), proto_wire,
//! version 1: the numbers of its methods, which never change once given,
//! its codes and the bodies of its requests. Every number goes low byte
//! first.
//!
//! The service reads and writes runs of 512-byte sectors through the cells
//! of a shared buffer: the client makes a memory object of BUFFER_SIZE
//! bytes, gives it with BUFFER, and the service maps it for the session's
//! life. The buffer is CELLS cells of CELL_BYTES; one call names one cell.
//!
//! | Request | Bytes after the header | Reply |
//! |---|---|---|
//! | INFO (1) | none | status 0, `sectors` u64, `block` u32, `flags` u32, `cells` u32, `cell_bytes` u32 |
//! | READ (2), WRITE (3) | `cell` u32, `count` u32, `sector` u64 | WAIT k |
//! | FLUSH (4) | none | WAIT k |
//! | BUFFER (5) | `size` u32 and one handle: a memory object with MAP_READ and MAP_WRITE | status 0 |
//! | TAKE (6) | `key` u64; the first time also a handle with NOTIFY labelled k | READY (no bytes), ARMED, or the refusal of the operation |
//! | CANCEL (7) | `key` u64 | CANCELLED |
//! | CRASH (8) | none | none; only a service built with the feature `crash` has it |
//!
//! READ, WRITE and FLUSH answer WAIT k (proto_wire::long) always: the
//! device's interrupt brings the result. A cell is busy from WAIT until the
//! TAKE that gives READY or the refusal; for READ, the data are in the cell
//! of the shared buffer once TAKE says READY. After WAIT of a WRITE the
//! client may change its cell: the service has copied it already. CANCEL
//! ends the operation at once; a request the device has keeps its cell
//! busy until the device answers, and the result is dropped.
//!
//! FLUSH READY means the device answered OK to a flush, so every write that
//! had its answer before the service took the FLUSH is on the medium. A
//! WRITE READY means only that the device took the data. A FLUSH is refused
//! BUSY while a write is with the device, and a WRITE while a flush is.

#![cfg_attr(not(test), no_std)]

use proto_wire::{Header, Reader, Status, Writer};

/// The version of the protocol, in the header of each request.
pub const VERSION: u16 = 1;

/// The bytes of a sector.
pub const SECTOR: usize = 512;
/// The cells of the shared buffer and the bytes of each.
pub const CELLS: u32 = 4;
pub const CELL_BYTES: u32 = 16_384;
/// The most sectors one READ or WRITE names: one cell.
pub const SECTORS_MAX: u32 = CELL_BYTES / SECTOR as u32;
/// The bytes of the shared buffer BUFFER takes.
pub const BUFFER_SIZE: u32 = CELLS * CELL_BYTES;

/// Bit 0 of `Info::flags`: the device has a write cache that FLUSH reaches.
pub const FLAG_FLUSH: u32 = 1;
/// Bit 1: the device is read-only.
pub const FLAG_READ_ONLY: u32 = 2;

/// The codes of the service (`Status::Unknown`), clear of the codes of the
/// wire (below 512) and of the kernel's.
pub const RANGE: u32 = 1101;
pub const IO: u32 = 1102;
pub const UNSUPPORTED: u32 = 1103;
pub const READ_ONLY: u32 = 1104;
pub const INVALID: u32 = 1105;
pub const NO_BUFFER: u32 = 1106;
pub const EXISTS: u32 = 1107;
pub const BUSY: u32 = 1108;

/// Every code of the service, for the check that none repeats.
pub const CODES: [u32; 8] = [
    RANGE,
    IO,
    UNSUPPORTED,
    READ_ONLY,
    INVALID,
    NO_BUFFER,
    EXISTS,
    BUSY,
];

pub const fn code(code: u32) -> Status {
    Status::Unknown(code)
}

/// The methods with their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Info = 1,
    Read = 2,
    Write = 3,
    Flush = 4,
    Buffer = 5,
    Take = 6,
    Cancel = 7,
    Crash = 8,
}

impl Method {
    pub const ALL: [Method; 8] = [
        Method::Info,
        Method::Read,
        Method::Write,
        Method::Flush,
        Method::Buffer,
        Method::Take,
        Method::Cancel,
        Method::Crash,
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

/// READ and WRITE: the cell, the sectors from `sector` and how many.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Io {
    pub cell: u32,
    pub count: u32,
    pub sector: u64,
}

impl Io {
    /// The request of `method` (Read or Write): BAD_SIZE for another
    /// method, for `count` outside 1..=SECTORS_MAX, and INVALID for a cell
    /// past the buffer.
    pub fn write(&self, method: Method, w: &mut Writer) -> Result<(), Status> {
        if !matches!(method, Method::Read | Method::Write) {
            return Err(Status::BadSize);
        }
        self.check()?;
        method.header().write(w)?;
        w.u32(self.cell)?;
        w.u32(self.count)?;
        w.u64(self.sector)
    }

    /// The request from `body`: BAD_SIZE unless it is the three fields
    /// with a `count` of 1..=SECTORS_MAX, INVALID for a cell of CELLS or
    /// more.
    pub fn read(mut body: Reader<'_>) -> Result<Io, Status> {
        let io = Io {
            cell: body.u32()?,
            count: body.u32()?,
            sector: body.u64()?,
        };
        body.finish()?;
        io.check()?;
        Ok(io)
    }

    fn check(&self) -> Result<(), Status> {
        if !(1..=SECTORS_MAX).contains(&self.count) {
            Err(Status::BadSize)
        } else if self.cell >= CELLS {
            Err(code(INVALID))
        } else {
            Ok(())
        }
    }
}

/// The reply of INFO after its status 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub sectors: u64,
    pub block: u32,
    pub flags: u32,
}

impl Info {
    /// The fields after the status, the cells of the buffer included.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u64(self.sectors)?;
        w.u32(self.block)?;
        w.u32(self.flags)?;
        w.u32(CELLS)?;
        w.u32(CELL_BYTES)
    }

    /// The reply in `bytes`: the status when it is a refusal, BAD_SIZE for
    /// another layout or other cells than this version has.
    pub fn read(bytes: &[u8]) -> Result<Info, Status> {
        let mut r = Reader::new(bytes);
        match Status::from_code(r.u32()?) {
            Status::Ok => {}
            status => return Err(status),
        }
        let info = Info {
            sectors: r.u64()?,
            block: r.u32()?,
            flags: r.u32()?,
        };
        let (cells, cell_bytes) = (r.u32()?, r.u32()?);
        r.finish()?;
        if (cells, cell_bytes) != (CELLS, CELL_BYTES) {
            return Err(Status::BadSize);
        }
        Ok(info)
    }

    pub const fn flush(&self) -> bool {
        self.flags & FLAG_FLUSH != 0
    }

    pub const fn read_only(&self) -> bool {
        self.flags & FLAG_READ_ONLY != 0
    }
}

/// BUFFER: the header and the size; the object goes as the request's one
/// handle.
pub fn write_buffer(size: u32, w: &mut Writer) -> Result<(), Status> {
    Method::Buffer.header().write(w)?;
    w.u32(size)
}

/// The size of BUFFER from `body`: BAD_SIZE unless it is one u32.
pub fn read_buffer(mut body: Reader<'_>) -> Result<u32, Status> {
    let size = body.u32()?;
    body.finish()?;
    Ok(size)
}

/// TAKE and CANCEL: the key k of the operation, above 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub key: u64,
}

impl Key {
    pub fn write(&self, method: Method, w: &mut Writer) -> Result<(), Status> {
        if self.key == 0 || !matches!(method, Method::Take | Method::Cancel) {
            return Err(Status::BadSize);
        }
        method.header().write(w)?;
        w.u64(self.key)
    }

    pub fn read(mut body: Reader<'_>) -> Result<Key, Status> {
        let key = body.u64()?;
        body.finish()?;
        if key == 0 {
            return Err(Status::BadSize);
        }
        Ok(Key { key })
    }
}

/// Whether the run of `count` sectors from `sector` lies within a disk of
/// `sectors`.
pub const fn in_range(sectors: u64, sector: u64, count: u32) -> bool {
    match sector.checked_add(count as u64) {
        Some(end) => end <= sectors,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_numbers_are_fixed() {
        assert_eq!(Method::ALL.map(Method::number), [1, 2, 3, 4, 5, 6, 7, 8]);
        for m in Method::ALL {
            assert_eq!(Method::from_number(m.number()), Some(m));
            assert_eq!(m.header(), Header::new(m.number(), VERSION));
        }
        assert_eq!(Method::from_number(0), None);
        assert_eq!(Method::from_number(9), None);
    }

    #[test]
    fn codes_clear_of_the_wire_and_of_each_other() {
        for (i, a) in CODES.iter().enumerate() {
            assert!(*a > 1000, "{a} is a code of the wire or the kernel");
            assert!(!CODES[i + 1..].contains(a));
        }
        assert_eq!(code(BUSY), Status::Unknown(1108));
        assert_eq!(Status::from_code(RANGE), Status::Unknown(RANGE));
    }

    #[test]
    fn the_cells_make_the_buffer() {
        assert_eq!(BUFFER_SIZE, 65_536);
        assert_eq!(SECTORS_MAX, 32);
        assert_eq!(SECTORS_MAX as usize * SECTOR, CELL_BYTES as usize);
    }

    #[test]
    fn an_io_round_trips() {
        for method in [Method::Read, Method::Write] {
            let io = Io {
                cell: 3,
                count: 32,
                sector: 0x0102_0304_0506_0708,
            };
            let mut w = Writer::new();
            io.write(method, &mut w).unwrap();
            assert_eq!(
                w.as_bytes(),
                [
                    method.number() as u8,
                    0,
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    3,
                    0,
                    0,
                    0,
                    32,
                    0,
                    0,
                    0,
                    8,
                    7,
                    6,
                    5,
                    4,
                    3,
                    2,
                    1
                ]
            );
            assert_eq!(Io::read(Reader::new(&w.as_bytes()[8..])), Ok(io));
        }
    }

    #[test]
    fn an_io_refuses_a_bad_count_cell_or_length() {
        let body = |cell: u32, count: u32| {
            let mut b = cell.to_le_bytes().to_vec();
            b.extend(count.to_le_bytes());
            b.extend(7u64.to_le_bytes());
            b
        };
        for count in [0, 33, u32::MAX] {
            assert_eq!(Io::read(Reader::new(&body(0, count))), Err(Status::BadSize));
        }
        assert_eq!(Io::read(Reader::new(&body(0, 1))).unwrap().count, 1);
        assert_eq!(Io::read(Reader::new(&body(0, 32))).unwrap().count, 32);
        assert_eq!(Io::read(Reader::new(&body(CELLS, 1))), Err(code(INVALID)));
        assert_eq!(Io::read(Reader::new(&body(3, 1))).unwrap().cell, 3);
        let mut long = body(0, 1);
        long.push(0);
        assert_eq!(Io::read(Reader::new(&long)), Err(Status::BadSize));
        assert_eq!(
            Io::read(Reader::new(&body(0, 1)[..15])),
            Err(Status::BadSize)
        );
        let io = Io {
            cell: 0,
            count: 1,
            sector: 0,
        };
        assert_eq!(
            io.write(Method::Take, &mut Writer::new()),
            Err(Status::BadSize)
        );
        let bad = Io { count: 33, ..io };
        assert_eq!(
            bad.write(Method::Read, &mut Writer::new()),
            Err(Status::BadSize)
        );
    }

    #[test]
    fn info_round_trips_with_its_cells() {
        let info = Info {
            sectors: 131_072,
            block: 512,
            flags: FLAG_FLUSH,
        };
        let mut w = Writer::new();
        w.u32(0).unwrap();
        info.write(&mut w).unwrap();
        assert_eq!(Info::read(w.as_bytes()), Ok(info));
        assert!(info.flush() && !info.read_only());
        let mut other = w.as_bytes().to_vec();
        other[24] = 8;
        assert_eq!(Info::read(&other), Err(Status::BadSize));
        assert_eq!(
            Info::read(&1101u32.to_le_bytes()),
            Err(Status::Unknown(1101))
        );
        assert_eq!(Info::read(&w.as_bytes()[..27]), Err(Status::BadSize));
    }

    #[test]
    fn buffer_and_keys() {
        let mut w = Writer::new();
        write_buffer(BUFFER_SIZE, &mut w).unwrap();
        assert_eq!(
            read_buffer(Reader::new(&w.as_bytes()[8..])),
            Ok(BUFFER_SIZE)
        );
        assert_eq!(read_buffer(Reader::new(&[0; 5])), Err(Status::BadSize));
        let key = Key {
            key: 0x0807_0605_0403_0201,
        };
        for (method, number) in [(Method::Take, 6), (Method::Cancel, 7)] {
            let mut w = Writer::new();
            key.write(method, &mut w).unwrap();
            assert_eq!(
                w.as_bytes(),
                [number, 0, 1, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
            );
            assert_eq!(Key::read(Reader::new(&w.as_bytes()[8..])), Ok(key));
        }
        assert_eq!(Key::read(Reader::new(&[0; 8])), Err(Status::BadSize));
        assert_eq!(Key::read(Reader::new(&[1; 7])), Err(Status::BadSize));
        assert_eq!(
            Key { key: 0 }.write(Method::Take, &mut Writer::new()),
            Err(Status::BadSize)
        );
        assert_eq!(
            key.write(Method::Read, &mut Writer::new()),
            Err(Status::BadSize)
        );
        assert_eq!(Method::Crash.header().bytes(), [8, 0, 1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn the_range_is_checked_at_the_edge() {
        assert!(in_range(100, 68, 32));
        assert!(in_range(100, 99, 1));
        assert!(!in_range(100, 99, 2));
        assert!(!in_range(100, 69, 32));
        assert!(!in_range(100, u64::MAX, 1));
        assert!(!in_range(100, u64::MAX - 10, 32));
        assert!(!in_range(0, 0, 1));
    }
}
