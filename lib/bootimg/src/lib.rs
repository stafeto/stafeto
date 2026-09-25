// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The boot image (spec 13.1) and the simple program format of its first
//! file, init (spec 3.3). The kernel reads both in no_std; xtask writes
//! them on the host (feature `write`), and the writer reads its result back
//! with the same reader, so the two cannot disagree on the layout.
//!
//! Everything is little endian. The boot image: a 16-byte header (the
//! signature `STAFBOOT`, the version as u32, the number of files as u32),
//! a table with a 48-byte entry per file (the name, 1 to 32 bytes of UTF-8
//! padded with zeros; the offset of the file from the start of the image
//! and its size, both u64), then the files at 4 KiB boundaries in the order
//! of the table. The first file is init.
//!
//! A program: a 120-byte header (the signature `STAFPROG`, the version as
//! u32, the stack size in bytes as u32, the entry point as u64, then three
//! segments of four u64 each: address, size in memory, offset of its bytes
//! from the start of the program, number of those bytes), then the bytes.
//! The segments are code (read and execute), read-only data (read) and data
//! with bss (read and write), in that order; the file holds a segment's
//! first bytes, and the rest of its memory is zero. The protections come
//! with the place in the header, so no file can ask for a page that is
//! writable and executable (W^X).

#![cfg_attr(not(test), no_std)]

#[cfg(any(test, feature = "write"))]
extern crate alloc;

use abi::INIT_STACK_TOP;
use core::fmt;
use core::ops::Range;

/// Files, segments and the stack start at this boundary.
pub const PAGE_SIZE: u64 = 4096;
pub const MAGIC: [u8; 8] = *b"STAFBOOT";
pub const PROGRAM_MAGIC: [u8; 8] = *b"STAFPROG";
/// The version of the boot image's format.
pub const VERSION: u32 = 1;
/// The version of the program format; it changes on its own.
pub const PROGRAM_VERSION: u32 = 1;
pub const NAME_MAX: usize = 32;
const HEADER_SIZE: u64 = 16;
const ENTRY_SIZE: u64 = 48;
const PROGRAM_HEADER_SIZE: u64 = 120;
/// Where the first segment's fields start in a program's header.
const SEGMENTS_AT: usize = 24;
const SEGMENT_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes end before the header, the table, a file or a segment's
    /// bytes do: `need` bytes are needed, `len` are there.
    Truncated { need: u64, len: u64 },
    /// The first 8 bytes are not this signature.
    BadSignature(&'static str),
    /// The format's version is `found`; the reader knows `known`.
    BadVersion { found: u32, known: u32 },
    /// File `n`'s name is empty, longer than 32 bytes, not UTF-8 or not
    /// padded with zeros.
    BadName(u32),
    /// File `n` does not start at a 4 KiB boundary at or after the end of
    /// the table and of the file before it.
    Misplaced(u32),
    /// The image has no files, or its first file is not init.
    NoInit,
    /// The stack size is zero, not whole pages, or so large that the stack
    /// and its guard page leave nothing above page 0.
    BadStack(u32),
    /// The segment's address or the offset of its bytes is not at a 4 KiB
    /// boundary.
    Misaligned(Part),
    /// The program has no such segment, yet its address or the offset of
    /// its bytes is not 0.
    EmptyNotZero(Part),
    /// The file holds more of the segment than its size in memory.
    FileOverMemory(Part),
    /// The segment does not lie between page 0 and the stack's guard page.
    Outside(Part),
    /// The two segments have a page in common.
    Overlap(Part, Part),
    /// The entry point is not a 4-byte aligned address in the code segment.
    BadEntry(u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::Truncated { need, len } => {
                write!(f, "cut short: {need} bytes needed, {len} present")
            }
            Error::BadSignature(s) => write!(f, "no {s} signature"),
            Error::BadVersion { found, known } => {
                write!(f, "version {found}, only version {known} is known")
            }
            Error::BadName(n) => write!(
                f,
                "the name of file {n} is not 1 to 32 bytes of UTF-8 padded with zeros"
            ),
            Error::Misplaced(n) => write!(
                f,
                "file {n} is not at a 4 KiB boundary after the table and the file before it"
            ),
            Error::NoInit => f.write_str("the first file is not init"),
            Error::BadStack(s) => write!(
                f,
                "stack size {s:#x} is zero, not whole pages or leaves no room for the program"
            ),
            Error::Misaligned(p) => write!(
                f,
                "the {p} segment's address or file offset is not at a 4 KiB boundary"
            ),
            Error::EmptyNotZero(p) => write!(
                f,
                "the {p} segment is absent, but its address or file offset is not 0"
            ),
            Error::FileOverMemory(p) => {
                write!(f, "the file holds more of the {p} segment than its memory")
            }
            Error::Outside(p) => write!(
                f,
                "the {p} segment is not between page 0 and the stack's guard page"
            ),
            Error::Overlap(a, b) => write!(f, "the {a} and {b} segments share a page"),
            Error::BadEntry(e) => write!(
                f,
                "entry point {e:#x} is not an aligned address in the code segment"
            ),
        }
    }
}

/// A program's segments, in the order of its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// Read and execute.
    Code = 0,
    /// Read only.
    Rodata = 1,
    /// Read and write: initialised data, then bss.
    Data = 2,
}

impl Part {
    pub const ALL: [Part; 3] = [Part::Code, Part::Rodata, Part::Data];
}

impl fmt::Display for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Part::Code => "code",
            Part::Rodata => "rodata",
            Part::Data => "data",
        })
    }
}

/// One file of the boot image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct File<'a> {
    pub name: &'a str,
    /// From the start of the image, at a 4 KiB boundary.
    pub offset: u64,
    pub data: &'a [u8],
}

/// A boot image whose header and whole table are checked: every file has
/// a good name and lies inside the image, in order, at a 4 KiB boundary.
#[derive(Debug, Clone, Copy)]
pub struct BootImage<'a> {
    bytes: &'a [u8],
    count: u32,
}

impl<'a> BootImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<BootImage<'a>, Error> {
        let len = bytes.len() as u64;
        if len < HEADER_SIZE {
            return Err(Error::Truncated {
                need: HEADER_SIZE,
                len,
            });
        }
        if bytes[..8] != MAGIC {
            return Err(Error::BadSignature("STAFBOOT"));
        }
        let version = u32_at(bytes, 8);
        if version != VERSION {
            return Err(Error::BadVersion {
                found: version,
                known: VERSION,
            });
        }
        let count = u32_at(bytes, 12);
        let table_end = HEADER_SIZE + ENTRY_SIZE * u64::from(count);
        if len < table_end {
            return Err(Error::Truncated {
                need: table_end,
                len,
            });
        }
        let image = BootImage { bytes, count };
        let mut end = table_end;
        for n in 0..count {
            let file = image.file(n)?;
            if file.offset < end {
                return Err(Error::Misplaced(n));
            }
            end = file.offset + file.data.len() as u64;
        }
        Ok(image)
    }

    /// The files in the order of the table.
    pub fn files(self) -> impl Iterator<Item = File<'a>> {
        (0..self.count).filter_map(move |n| self.file(n).ok())
    }

    /// The first file, which must be init: a program in the simple format.
    pub fn init(self) -> Result<&'a [u8], Error> {
        match self.files().next() {
            Some(f) if f.name == "init" => Ok(f.data),
            _ => Err(Error::NoInit),
        }
    }

    /// File `n` of the table, with its name and place checked; `parse` adds
    /// the order.
    fn file(&self, n: u32) -> Result<File<'a>, Error> {
        let at = (HEADER_SIZE + ENTRY_SIZE * u64::from(n)) as usize;
        let field = &self.bytes[at..at + NAME_MAX];
        let used = field.iter().position(|&b| b == 0).unwrap_or(NAME_MAX);
        let name = match core::str::from_utf8(&field[..used]) {
            Ok(name) if used > 0 && field[used..].iter().all(|&b| b == 0) => name,
            _ => return Err(Error::BadName(n)),
        };
        let offset = u64_at(self.bytes, at + NAME_MAX);
        let size = u64_at(self.bytes, at + NAME_MAX + 8);
        if !offset.is_multiple_of(PAGE_SIZE) {
            return Err(Error::Misplaced(n));
        }
        let end = inside(self.bytes, offset, size)?;
        Ok(File {
            name,
            offset,
            data: &self.bytes[offset as usize..end],
        })
    }
}

/// A segment of a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {
    /// At a 4 KiB boundary.
    pub vaddr: u64,
    /// 0 when the program has no such segment.
    pub mem_size: u64,
    /// The segment's first bytes; the rest of its memory is zero.
    pub bytes: &'a [u8],
}

impl Segment<'_> {
    pub const EMPTY: Segment<'static> = Segment {
        vaddr: 0,
        mem_size: 0,
        bytes: &[],
    };

    /// The pages the segment covers: from its address to the 4 KiB
    /// boundary at or after its end.
    pub fn pages(&self) -> Range<u64> {
        self.vaddr..(self.vaddr + self.mem_size).next_multiple_of(PAGE_SIZE)
    }
}

/// A program in the simple format, checked: its segments lie at 4 KiB
/// boundaries between page 0 and the guard page under the stack, share no
/// page, and the file holds their bytes; the entry point is in the code.
/// The kernel maps the stack right under `abi::INIT_STACK_TOP` with an
/// unmapped guard page below it, and the message buffer of the first
/// thread at `abi::INIT_MSGBUF`, above the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Program<'a> {
    pub entry: u64,
    /// In bytes, whole pages.
    pub stack_size: u32,
    /// Indexed by `Part`: code, rodata, data.
    pub segments: [Segment<'a>; 3],
}

impl<'a> Program<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Program<'a>, Error> {
        let len = bytes.len() as u64;
        if len < PROGRAM_HEADER_SIZE {
            return Err(Error::Truncated {
                need: PROGRAM_HEADER_SIZE,
                len,
            });
        }
        if bytes[..8] != PROGRAM_MAGIC {
            return Err(Error::BadSignature("STAFPROG"));
        }
        let version = u32_at(bytes, 8);
        if version != PROGRAM_VERSION {
            return Err(Error::BadVersion {
                found: version,
                known: PROGRAM_VERSION,
            });
        }
        let stack_size = u32_at(bytes, 12);
        let room_end = room_end(stack_size).ok_or(Error::BadStack(stack_size))?;
        let mut segments = [Segment::EMPTY; 3];
        for part in Part::ALL {
            let at = SEGMENTS_AT + SEGMENT_SIZE * part as usize;
            let vaddr = u64_at(bytes, at);
            let mem_size = u64_at(bytes, at + 8);
            let offset = u64_at(bytes, at + 16);
            let file_size = u64_at(bytes, at + 24);
            if mem_size == 0 && file_size == 0 {
                // An absent segment's other fields stay 0, so that a value
                // there may get a meaning later without breaking old images.
                if vaddr != 0 || offset != 0 {
                    return Err(Error::EmptyNotZero(part));
                }
                continue;
            }
            if !vaddr.is_multiple_of(PAGE_SIZE) || !offset.is_multiple_of(PAGE_SIZE) {
                return Err(Error::Misaligned(part));
            }
            if file_size > mem_size {
                return Err(Error::FileOverMemory(part));
            }
            let end = inside(bytes, offset, file_size)?;
            let fits =
                vaddr >= PAGE_SIZE && vaddr.checked_add(mem_size).is_some_and(|e| e <= room_end);
            if !fits {
                return Err(Error::Outside(part));
            }
            segments[part as usize] = Segment {
                vaddr,
                mem_size,
                bytes: &bytes[offset as usize..end],
            };
        }
        for (i, &a) in Part::ALL.iter().enumerate() {
            for &b in &Part::ALL[i + 1..] {
                let (pa, pb) = (segments[a as usize].pages(), segments[b as usize].pages());
                if !pa.is_empty() && !pb.is_empty() && pa.start < pb.end && pb.start < pa.end {
                    return Err(Error::Overlap(a, b));
                }
            }
        }
        let entry = u64_at(bytes, 16);
        let code = &segments[Part::Code as usize];
        if !entry.is_multiple_of(4) || !(code.vaddr..code.vaddr + code.mem_size).contains(&entry) {
            return Err(Error::BadEntry(entry));
        }
        Ok(Program {
            entry,
            stack_size,
            segments,
        })
    }
}

/// The end of the room a program has: the bottom of the guard page under a
/// stack of `stack_size` bytes, if that size is whole pages, not zero, and
/// leaves room above page 0.
fn room_end(stack_size: u32) -> Option<u64> {
    let size = u64::from(stack_size);
    if size == 0 || !size.is_multiple_of(PAGE_SIZE) {
        return None;
    }
    INIT_STACK_TOP
        .checked_sub(size + PAGE_SIZE)
        .filter(|&end| end > PAGE_SIZE)
}

/// The end of `size` bytes at `offset`, if they lie inside `bytes`.
fn inside(bytes: &[u8], offset: u64, size: u64) -> Result<usize, Error> {
    let len = bytes.len() as u64;
    match offset.checked_add(size) {
        Some(end) if end <= len => Ok(end as usize),
        _ => Err(Error::Truncated {
            need: offset.saturating_add(size),
            len,
        }),
    }
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let mut b = [0; 4];
    b.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(b)
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut b = [0; 8];
    b.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(b)
}

/// Writing a boot image and programs, for xtask on the host. Each writer
/// reads its result back and returns the reader's error, so it never
/// writes what the kernel would refuse.
#[cfg(any(test, feature = "write"))]
pub mod write {
    use super::*;
    use alloc::vec::Vec;

    /// The program's header, then its segments' bytes, each at the next
    /// 4 KiB boundary.
    pub fn program(p: &Program<'_>) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0; PROGRAM_HEADER_SIZE as usize];
        out[..8].copy_from_slice(&PROGRAM_MAGIC);
        put(&mut out, 8, &PROGRAM_VERSION.to_le_bytes());
        put(&mut out, 12, &p.stack_size.to_le_bytes());
        put(&mut out, 16, &p.entry.to_le_bytes());
        for part in Part::ALL {
            let s = &p.segments[part as usize];
            let offset = if s.bytes.is_empty() {
                0
            } else {
                pad(&mut out);
                let offset = out.len() as u64;
                out.extend_from_slice(s.bytes);
                offset
            };
            let at = SEGMENTS_AT + SEGMENT_SIZE * part as usize;
            put(&mut out, at, &s.vaddr.to_le_bytes());
            put(&mut out, at + 8, &s.mem_size.to_le_bytes());
            put(&mut out, at + 16, &offset.to_le_bytes());
            put(&mut out, at + 24, &(s.bytes.len() as u64).to_le_bytes());
        }
        Program::parse(&out)?;
        Ok(out)
    }

    /// The header, the table, then the files, each at the next 4 KiB
    /// boundary, in the order given.
    pub fn image(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(files.len() as u32).to_le_bytes());
        let table_end = HEADER_SIZE + ENTRY_SIZE * files.len() as u64;
        let mut offset = table_end.next_multiple_of(PAGE_SIZE);
        for (n, (name, data)) in files.iter().enumerate() {
            if name.is_empty() || name.len() > NAME_MAX || name.contains('\0') {
                return Err(Error::BadName(n as u32));
            }
            let mut field = [0; NAME_MAX];
            field[..name.len()].copy_from_slice(name.as_bytes());
            out.extend_from_slice(&field);
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            offset = (offset + data.len() as u64).next_multiple_of(PAGE_SIZE);
        }
        for (_, data) in files {
            pad(&mut out);
            out.extend_from_slice(data);
        }
        BootImage::parse(&out)?;
        Ok(out)
    }

    fn pad(out: &mut Vec<u8>) {
        out.resize((out.len() as u64).next_multiple_of(PAGE_SIZE) as usize, 0);
    }

    fn put(out: &mut [u8], at: usize, bytes: &[u8]) {
        out[at..at + bytes.len()].copy_from_slice(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: [u8; 0x20] = [0xAA; 0x20];

    /// Read-only data, code above it, data with bss above that: the layout
    /// lld gives a program.
    fn sample() -> Program<'static> {
        Program {
            entry: 0x20_1010,
            stack_size: 0x1_0000,
            segments: [
                Segment {
                    vaddr: 0x20_1000,
                    mem_size: 0x1000,
                    bytes: &CODE,
                },
                Segment {
                    vaddr: 0x20_0000,
                    mem_size: 0x10,
                    bytes: b"read-only bytes!",
                },
                Segment {
                    vaddr: 0x20_2000,
                    mem_size: 0x3000,
                    bytes: b"data",
                },
            ],
        }
    }

    /// Whether the writer takes the sample program, changed.
    fn with(change: impl FnOnce(&mut Program<'static>)) -> Result<(), Error> {
        let mut p = sample();
        change(&mut p);
        write::program(&p).map(|_| ())
    }

    /// The sample program as init, and a second file.
    fn image() -> Vec<u8> {
        let init = write::program(&sample()).unwrap();
        write::image(&[("init", &init), ("hello", b"hello")]).unwrap()
    }

    /// Where file `n`'s entry starts in the table.
    fn entry_at(n: usize) -> usize {
        16 + 48 * n
    }

    fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn image_round_trip() {
        let init = write::program(&sample()).unwrap();
        let bytes = image();
        assert_eq!(&bytes[..8], b"STAFBOOT");
        let image = BootImage::parse(&bytes).unwrap();
        let files: Vec<File> = image.files().collect();
        assert_eq!(files.len(), 2);
        assert_eq!(
            (files[0].name, files[0].offset, files[0].data),
            ("init", 0x1000, &init[..])
        );
        let hello_at = (0x1000 + init.len() as u64).next_multiple_of(PAGE_SIZE);
        assert_eq!(
            (files[1].name, files[1].offset, files[1].data),
            ("hello", hello_at, &b"hello"[..])
        );
        assert_eq!(bytes.len() as u64, hello_at + 5);
        assert_eq!(image.init(), Ok(&init[..]));
    }

    #[test]
    fn program_round_trip() {
        let bytes = write::program(&sample()).unwrap();
        assert_eq!(&bytes[..8], b"STAFPROG");
        assert_eq!(Program::parse(&bytes), Ok(sample()));
        // After the header's page, each segment's bytes at a 4 KiB boundary.
        assert_eq!(bytes[0x1000..0x1020], CODE);
        assert_eq!(&bytes[0x2000..0x2010], b"read-only bytes!");
        assert_eq!(&bytes[0x3000..], b"data");
        assert_eq!(sample().segments[0].pages(), 0x20_1000..0x20_2000);
        assert_eq!(sample().segments[1].pages(), 0x20_0000..0x20_1000);
        assert_eq!(Segment::EMPTY.pages(), 0..0);
    }

    #[test]
    fn every_cut_of_an_image_is_truncated() {
        let bytes = image();
        for len in 0..bytes.len() {
            let got = BootImage::parse(&bytes[..len]).err();
            let cut = matches!(got, Some(Error::Truncated { need, len: l })
                if l == len as u64 && need > l);
            assert!(cut, "cut at {len}: {got:?}");
        }
    }

    #[test]
    fn every_cut_of_a_program_is_truncated() {
        let bytes = write::program(&sample()).unwrap();
        for len in 0..bytes.len() {
            let got = Program::parse(&bytes[..len]).err();
            let cut = matches!(got, Some(Error::Truncated { need, len: l })
                if l == len as u64 && need > l);
            assert!(cut, "cut at {len}: {got:?}");
        }
    }

    #[test]
    fn signatures_and_versions_are_checked() {
        let mut bytes = image();
        bytes[0] = b's';
        assert_eq!(
            BootImage::parse(&bytes).err(),
            Some(Error::BadSignature("STAFBOOT"))
        );
        let mut bytes = image();
        bytes[8] = 2;
        assert_eq!(
            BootImage::parse(&bytes).err(),
            Some(Error::BadVersion {
                found: 2,
                known: VERSION
            })
        );
        let mut bytes = write::program(&sample()).unwrap();
        bytes[7] = b'X';
        assert_eq!(Program::parse(&bytes), Err(Error::BadSignature("STAFPROG")));
        let mut bytes = write::program(&sample()).unwrap();
        bytes[8] = 0;
        assert_eq!(
            Program::parse(&bytes),
            Err(Error::BadVersion {
                found: 0,
                known: PROGRAM_VERSION
            })
        );
    }

    #[test]
    fn names_are_checked() {
        let long = "n".repeat(33);
        assert_eq!(write::image(&[("", b"x")]), Err(Error::BadName(0)));
        assert_eq!(
            write::image(&[("init", b"x"), (&long, b"x")]),
            Err(Error::BadName(1))
        );
        assert_eq!(
            write::image(&[("init", b"x"), ("a\0b", b"x")]),
            Err(Error::BadName(1))
        );
        let longest = "n".repeat(32);
        let bytes = write::image(&[(&longest, b"x")]).unwrap();
        let first = BootImage::parse(&bytes).unwrap().files().next().unwrap();
        assert_eq!(first.name, longest);
        let mut bytes = image();
        bytes[entry_at(0) + 6] = b'x'; // after "init" and a zero
        assert_eq!(BootImage::parse(&bytes).err(), Some(Error::BadName(0)));
        let mut bytes = image();
        bytes[entry_at(1)] = 0xFF; // "hello" is no longer UTF-8
        assert_eq!(BootImage::parse(&bytes).err(), Some(Error::BadName(1)));
    }

    #[test]
    fn files_lie_at_page_boundaries_in_order() {
        let good = image();
        let hello_at = BootImage::parse(&good)
            .unwrap()
            .files()
            .nth(1)
            .unwrap()
            .offset;
        // Off a boundary; over init; over the table.
        for (n, offset) in [(1, hello_at + 8), (1, 0x1000), (0, 0)] {
            let mut bytes = good.clone();
            put_u64(&mut bytes, entry_at(n) + 32, offset);
            assert_eq!(
                BootImage::parse(&bytes).err(),
                Some(Error::Misplaced(n as u32)),
                "file {n} at {offset:#x}"
            );
        }
    }

    #[test]
    fn the_first_file_must_be_init() {
        let bytes = write::image(&[("shell", b"x"), ("init", b"y")]).unwrap();
        assert_eq!(BootImage::parse(&bytes).unwrap().init(), Err(Error::NoInit));
        let bytes = write::image(&[]).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(BootImage::parse(&bytes).unwrap().init(), Err(Error::NoInit));
    }

    #[test]
    fn segments_are_page_aligned() {
        assert_eq!(
            with(|p| p.segments[1].vaddr += 0x10),
            Err(Error::Misaligned(Part::Rodata))
        );
        let mut bytes = write::program(&sample()).unwrap();
        put_u64(&mut bytes, 24 + 16, 0x1008); // the code's bytes, off their page
        assert_eq!(Program::parse(&bytes), Err(Error::Misaligned(Part::Code)));
    }

    #[test]
    fn file_bytes_fit_in_memory() {
        assert_eq!(
            with(|p| p.segments[1].mem_size = 0xF),
            Err(Error::FileOverMemory(Part::Rodata))
        );
        assert_eq!(
            with(|p| p.segments[2].mem_size = 0),
            Err(Error::FileOverMemory(Part::Data))
        );
    }

    /// A page in two segments would get both protections; code and data
    /// on one page would make it writable and executable (W^X).
    #[test]
    fn segments_do_not_share_pages() {
        assert_eq!(
            with(|p| p.segments[1].vaddr = 0x20_1000),
            Err(Error::Overlap(Part::Code, Part::Rodata))
        );
        // One byte more, and the code's last page is the data's first.
        assert_eq!(
            with(|p| p.segments[0].mem_size = 0x1001),
            Err(Error::Overlap(Part::Code, Part::Data))
        );
        assert_eq!(
            with(|p| {
                p.segments[2].vaddr = 0x1F_F000;
                p.segments[2].mem_size = 0x2000;
            }),
            Err(Error::Overlap(Part::Rodata, Part::Data))
        );
    }

    #[test]
    fn segments_lie_between_page_zero_and_the_stack_guard() {
        let room_end = abi::INIT_STACK_TOP - 0x1_0000 - PAGE_SIZE;
        assert_eq!(
            with(|p| p.segments[1].vaddr = 0),
            Err(Error::Outside(Part::Rodata))
        );
        assert!(with(|p| p.segments[2].vaddr = room_end - 0x3000).is_ok());
        for vaddr in [room_end - 0x2000, abi::INIT_STACK_TOP + 0x10_0000] {
            assert_eq!(
                with(|p| p.segments[2].vaddr = vaddr),
                Err(Error::Outside(Part::Data))
            );
        }
        assert_eq!(
            with(|p| p.segments[2].mem_size = u64::MAX - 0x1000),
            Err(Error::Outside(Part::Data))
        );
    }

    #[test]
    fn the_stack_is_whole_pages_with_room_below() {
        // The stack, its guard page and page 0 would fill everything.
        let no_room = u32::try_from(abi::INIT_STACK_TOP - 2 * PAGE_SIZE).unwrap();
        for size in [0, 0x1800, no_room] {
            assert_eq!(with(|p| p.stack_size = size), Err(Error::BadStack(size)));
        }
        assert_eq!(
            with(|p| p.stack_size = no_room - 0x1000),
            Err(Error::Outside(Part::Code))
        );
        assert!(with(|p| p.stack_size = 0x1000).is_ok());
    }

    #[test]
    fn the_entry_point_is_an_instruction_in_the_code() {
        for entry in [0x20_1002, 0x20_2000, 0x20_0000, 0] {
            assert_eq!(with(|p| p.entry = entry), Err(Error::BadEntry(entry)));
        }
        assert!(with(|p| p.entry = 0x20_1FFC).is_ok());
        assert_eq!(
            with(|p| p.segments[0] = Segment::EMPTY),
            Err(Error::BadEntry(0x20_1010))
        );
    }

    #[test]
    fn rodata_and_data_may_be_missing() {
        let code = sample().segments[0];
        let p = Program {
            segments: [code, Segment::EMPTY, Segment::EMPTY],
            ..sample()
        };
        let bytes = write::program(&p).unwrap();
        assert_eq!(bytes.len(), 0x1020);
        assert_eq!(Program::parse(&bytes), Ok(p));
        // Bss alone: memory without bytes in the file.
        let bss = Segment {
            vaddr: 0x20_2000,
            mem_size: 0x2000,
            bytes: &[],
        };
        let p = Program {
            segments: [code, Segment::EMPTY, bss],
            ..sample()
        };
        let bytes = write::program(&p).unwrap();
        assert_eq!(Program::parse(&bytes), Ok(p));
        // An absent segment has 0 for its address and its file offset.
        for field in [0, 16] {
            let mut bad = bytes.clone();
            put_u64(&mut bad, SEGMENTS_AT + SEGMENT_SIZE + field, 0x30_0000);
            assert_eq!(
                Program::parse(&bad),
                Err(Error::EmptyNotZero(Part::Rodata)),
                "field {field}"
            );
        }
    }

    #[test]
    fn sizes_that_wrap_around_are_truncated() {
        let mut bytes = image();
        put_u64(&mut bytes, entry_at(1) + 40, u64::MAX); // hello's size
        let got = BootImage::parse(&bytes).err();
        assert!(
            matches!(got, Some(Error::Truncated { need: u64::MAX, .. })),
            "{got:?}"
        );
        let mut bytes = write::program(&sample()).unwrap();
        put_u64(&mut bytes, SEGMENTS_AT + 8, u64::MAX); // the code's size in memory
        put_u64(&mut bytes, SEGMENTS_AT + 24, u64::MAX - 0xFFF); // and in the file
        let got = Program::parse(&bytes).err();
        assert!(
            matches!(got, Some(Error::Truncated { need: u64::MAX, .. })),
            "{got:?}"
        );
        let mut bytes = image();
        bytes[entry_at(1)..entry_at(1) + NAME_MAX].fill(0);
        assert_eq!(BootImage::parse(&bytes).err(), Some(Error::BadName(1)));
    }

    #[test]
    fn errors_say_what_is_wrong() {
        let says = |e: Error, text: &str| assert_eq!(e.to_string(), text);
        says(
            Error::Truncated {
                need: 8192,
                len: 8191,
            },
            "cut short: 8192 bytes needed, 8191 present",
        );
        says(Error::BadSignature("STAFBOOT"), "no STAFBOOT signature");
        says(
            Error::BadVersion { found: 2, known: 1 },
            "version 2, only version 1 is known",
        );
        says(Error::NoInit, "the first file is not init");
        says(
            Error::Overlap(Part::Code, Part::Data),
            "the code and data segments share a page",
        );
        says(
            Error::BadEntry(0),
            "entry point 0x0 is not an aligned address in the code segment",
        );
    }
}
