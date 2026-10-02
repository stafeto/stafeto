// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A program's ELF file as the simple program format wants it (spec 3.3,
//! 13.2): the entry point and one loadable segment per protection.
//! Programs are static AArch64 executables, linked with 4 KiB pages, each
//! segment on pages of its own and no RELRO split (.cargo/config.toml);
//! `Program::check` checks the rest. A program may have one template of
//! thread-local storage (`PT_TLS`, spec 2, 3.5): its bytes, if any, lie in
//! the data segment, and the program's C library (relibc) builds each
//! thread's TLS from them, so the loader gives it no memory of its own.
//! xtask builds the boot image with it; a loader of programs from a disk
//! will read them with it too.

use crate::{Error, Part, Program, Segment, u32_at, u64_at};
use core::fmt;

const ET_EXEC: u16 = 2;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_TLS: u32 = 7;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const RX: u32 = PF_R | PF_X;
const RW: u32 = PF_R | PF_W;
const PHDR_SIZE: usize = 56;

/// Why an ELF file is no program of the boot image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// The file is shorter than the ELF header or has no ELF signature.
    NotElf,
    /// It is not a 64-bit little-endian file.
    NotElf64,
    /// It is no executable, or it asks for dynamic linking.
    NotStatic,
    /// It is for another machine.
    NotAarch64,
    /// Its program headers are not 56 bytes long.
    HeaderSize,
    /// Its program headers run past the end of the file.
    HeadersPastEnd,
    /// It has two templates of thread-local storage.
    TlsTwice,
    /// Its template of thread-local storage is not in the data segment's
    /// bytes.
    TlsOutside,
    /// The loadable segment at `vaddr` has the protection `flags`, not r-x,
    /// r-- or rw-.
    Protection { vaddr: u64, flags: u32 },
    /// Two loadable segments have the protection of this part.
    Twice(Part),
    /// The bytes of the segment of this part run past the end of the file.
    BytesPastEnd(Part),
    /// The program breaks a rule of the simple format (`Program::check`).
    Program(Error),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ElfError::NotElf => f.write_str("not an ELF file"),
            ElfError::NotElf64 => f.write_str("not a 64-bit little-endian ELF file"),
            ElfError::NotStatic => f.write_str("not a static executable"),
            ElfError::NotAarch64 => f.write_str("not an AArch64 program"),
            ElfError::HeaderSize => f.write_str("program headers are not 56 bytes long"),
            ElfError::HeadersPastEnd => {
                f.write_str("the program headers run past the end of the file")
            }
            ElfError::TlsTwice => f.write_str("two thread-local storage templates"),
            ElfError::TlsOutside => {
                f.write_str("the thread-local storage template is not in the data segment")
            }
            ElfError::Protection { vaddr, flags } => {
                let bit = |b, c| if flags & b != 0 { c } else { '-' };
                write!(
                    f,
                    "the segment at {vaddr:#x} is {}{}{}, not r-x, r-- or rw-",
                    bit(PF_R, 'r'),
                    bit(PF_W, 'w'),
                    bit(PF_X, 'x')
                )
            }
            ElfError::Twice(part) => write!(f, "two {part} segments"),
            ElfError::BytesPastEnd(part) => {
                write!(f, "the {part} segment's bytes run past the end of the file")
            }
            ElfError::Program(e) => write!(f, "the program: {e}"),
        }
    }
}

/// The program in `elf`, with a stack of `stack_size` bytes, checked
/// (`Program::check`); its segments borrow the file's bytes.
pub fn program(elf: &[u8], stack_size: u32) -> Result<Program<'_>, ElfError> {
    let read = headers(elf, elf.len() as u64)?;
    let mut segments = [Segment::EMPTY; 3];
    for part in Part::ALL {
        let load = &read.segments[part as usize];
        if load.mem_size == 0 && load.file_size == 0 && load.vaddr == 0 {
            continue;
        }
        // `headers` checked that the bytes lie in the file.
        let (offset, file_size) = (load.offset as usize, load.file_size as usize);
        segments[part as usize] = Segment {
            vaddr: load.vaddr,
            mem_size: load.mem_size,
            bytes: &elf[offset..offset + file_size],
        };
    }
    let program = Program {
        entry: read.entry,
        stack_size,
        segments,
    };
    program.check().map_err(ElfError::Program)?;
    Ok(program)
}

/// A loadable segment as the file lays it out (`layout`): its address and
/// size in memory, and where its bytes lie in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Load {
    pub vaddr: u64,
    pub mem_size: u64,
    pub offset: u64,
    pub file_size: u64,
}

impl Load {
    pub const EMPTY: Load = Load {
        vaddr: 0,
        mem_size: 0,
        offset: 0,
        file_size: 0,
    };

    /// The whole pages the segment takes.
    pub fn pages(&self) -> core::ops::Range<u64> {
        self.vaddr..(self.vaddr + self.mem_size).next_multiple_of(crate::PAGE_SIZE)
    }

    pub fn is_empty(&self) -> bool {
        self.mem_size == 0 && self.file_size == 0
    }
}

/// A program read from the head of its ELF file (`layout`): the entry
/// point and the code, read-only data and data segments, in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub entry: u64,
    pub segments: [Load; 3],
}

/// The program whose ELF file is `file_len` bytes long and starts with
/// `head`, which holds the ELF header and every program header (a loader
/// that reads a file in pieces gives its first page): the rules of
/// `program`, and each segment within `room`, a range of whole pages, so
/// that a loader keeps a program's segments off the addresses it and the
/// layer reserve. Nothing past `head` is read: the bytes of each segment
/// lie at `offset` in the file, and the loader copies them itself.
pub fn layout(head: &[u8], file_len: u64, room: core::ops::Range<u64>) -> Result<Layout, ElfError> {
    let read = headers(head, file_len)?;
    for part in Part::ALL {
        let s = &read.segments[part as usize];
        if s.is_empty() {
            if s.vaddr != 0 {
                return Err(ElfError::Program(Error::EmptyNotZero(part)));
            }
            continue;
        }
        if !s.vaddr.is_multiple_of(crate::PAGE_SIZE) {
            return Err(ElfError::Program(Error::Misaligned(part)));
        }
        if s.file_size > s.mem_size {
            return Err(ElfError::Program(Error::FileOverMemory(part)));
        }
        let fits = s.vaddr >= room.start
            && s.vaddr
                .checked_add(s.mem_size)
                .is_some_and(|e| e <= room.end);
        if !fits {
            return Err(ElfError::Program(Error::Outside(part)));
        }
    }
    for (i, &a) in Part::ALL.iter().enumerate() {
        for &b in &Part::ALL[i + 1..] {
            let (pa, pb) = (
                read.segments[a as usize].pages(),
                read.segments[b as usize].pages(),
            );
            if !pa.is_empty() && !pb.is_empty() && pa.start < pb.end && pb.start < pa.end {
                return Err(ElfError::Program(Error::Overlap(a, b)));
            }
        }
    }
    let code = &read.segments[Part::Code as usize];
    let entry = read.entry;
    if code.is_empty()
        || !entry.is_multiple_of(4)
        || !(code.vaddr..code.vaddr + code.mem_size).contains(&entry)
    {
        return Err(ElfError::Program(Error::BadEntry(entry)));
    }
    Ok(read)
}

/// The entry point and the loadable segments of the ELF file whose first
/// bytes are `head` and whose length is `file_len`: the checks of the ELF
/// header, one segment of each protection, the bytes of each within the
/// file, and one template of TLS within the data segment's bytes.
fn headers(head: &[u8], file_len: u64) -> Result<Layout, ElfError> {
    let elf = head;
    if elf.len() < 64 || elf[..4] != *b"\x7fELF" {
        return Err(ElfError::NotElf);
    }
    if elf[4] != 2 || elf[5] != 1 {
        return Err(ElfError::NotElf64);
    }
    if u16_at(elf, 16) != ET_EXEC {
        return Err(ElfError::NotStatic);
    }
    if u16_at(elf, 18) != EM_AARCH64 {
        return Err(ElfError::NotAarch64);
    }
    if usize::from(u16_at(elf, 54)) != PHDR_SIZE {
        return Err(ElfError::HeaderSize);
    }
    let entry = u64_at(elf, 24);
    let headers = u64_at(elf, 32);
    let mut segments = [Load::EMPTY; 3];
    let mut seen = [false; 3];
    let mut tls = None;
    for i in 0..u64::from(u16_at(elf, 56)) {
        let h = usize::try_from(headers.saturating_add(i * PHDR_SIZE as u64))
            .ok()
            .and_then(|at| elf.get(at..at.checked_add(PHDR_SIZE)?))
            .ok_or(ElfError::HeadersPastEnd)?;
        match u32_at(h, 0) {
            PT_LOAD => {}
            PT_DYNAMIC | PT_INTERP => return Err(ElfError::NotStatic),
            PT_TLS => {
                if tls.replace((u64_at(h, 16), u64_at(h, 32))).is_some() {
                    return Err(ElfError::TlsTwice);
                }
                continue;
            }
            _ => continue,
        }
        let (flags, offset, vaddr) = (u32_at(h, 4), u64_at(h, 8), u64_at(h, 16));
        let (file_size, mem_size) = (u64_at(h, 32), u64_at(h, 40));
        let part = match flags & (PF_R | PF_W | PF_X) {
            RX => Part::Code,
            PF_R => Part::Rodata,
            RW => Part::Data,
            flags => return Err(ElfError::Protection { vaddr, flags }),
        };
        if core::mem::replace(&mut seen[part as usize], true) {
            return Err(ElfError::Twice(part));
        }
        if offset
            .checked_add(file_size)
            .is_none_or(|end| end > file_len)
        {
            return Err(ElfError::BytesPastEnd(part));
        }
        segments[part as usize] = Load {
            vaddr,
            mem_size,
            offset,
            file_size,
        };
    }
    if let Some((vaddr, size @ 1..)) = tls {
        let data = &segments[Part::Data as usize];
        let end = data.vaddr.saturating_add(data.file_size);
        if !seen[Part::Data as usize] || vaddr < data.vaddr || vaddr.saturating_add(size) > end {
            return Err(ElfError::TlsOutside);
        }
    }
    Ok(Layout { entry, segments })
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A loadable segment of a test file: protection, address, file
    /// offset, bytes, size in memory.
    type Load<'a> = (u32, u64, u64, &'a [u8], u64);

    fn put(f: &mut [u8], at: usize, bytes: &[u8]) {
        f[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// An AArch64 executable with entry point 0x201010, these loadable
    /// segments and, after them, a stack header the reader passes over.
    fn elf(loads: &[Load]) -> Vec<u8> {
        let count = loads.len() + 1;
        let mut f = vec![0; 64 + PHDR_SIZE * count];
        put(&mut f, 0, b"\x7fELF\x02\x01\x01");
        put(&mut f, 16, &ET_EXEC.to_le_bytes());
        put(&mut f, 18, &EM_AARCH64.to_le_bytes());
        put(&mut f, 24, &0x20_1010u64.to_le_bytes());
        put(&mut f, 32, &64u64.to_le_bytes());
        put(&mut f, 54, &(PHDR_SIZE as u16).to_le_bytes());
        put(&mut f, 56, &(count as u16).to_le_bytes());
        for (i, &(flags, vaddr, offset, bytes, mem_size)) in loads.iter().enumerate() {
            let h = 64 + PHDR_SIZE * i;
            put(&mut f, h, &PT_LOAD.to_le_bytes());
            put(&mut f, h + 4, &flags.to_le_bytes());
            put(&mut f, h + 8, &offset.to_le_bytes());
            put(&mut f, h + 16, &vaddr.to_le_bytes());
            put(&mut f, h + 32, &(bytes.len() as u64).to_le_bytes());
            put(&mut f, h + 40, &mem_size.to_le_bytes());
            let end = offset as usize + bytes.len();
            if f.len() < end {
                f.resize(end, 0);
            }
            put(&mut f, offset as usize, bytes);
        }
        let stack = 64 + PHDR_SIZE * loads.len();
        put(&mut f, stack, &0x6474_e551u32.to_le_bytes()); // PT_GNU_STACK
        put(&mut f, stack + 4, &RW.to_le_bytes());
        f
    }

    /// Read-only data, code and data, as lld lays them out.
    fn layout() -> Vec<u8> {
        elf(&[
            (PF_R, 0x20_0000, 0x1000, b"rodata", 0x474),
            (RX, 0x20_1000, 0x2000, &[0xAA; 0x20], 0xA80),
            (RW, 0x20_2000, 0x3000, b"data", 0x1F48),
        ])
    }

    #[test]
    fn loadable_segments_become_code_rodata_and_data() {
        let f = layout();
        let p = program(&f, 0x1_0000).unwrap();
        assert_eq!((p.entry, p.stack_size), (0x20_1010, 0x1_0000));
        let segment = |vaddr, mem_size, bytes| Segment {
            vaddr,
            mem_size,
            bytes,
        };
        assert_eq!(
            p.segments,
            [
                segment(0x20_1000, 0xA80, &[0xAA; 0x20]),
                segment(0x20_0000, 0x474, b"rodata"),
                segment(0x20_2000, 0x1F48, b"data"),
            ]
        );
        // The boot image writer takes it as it is.
        assert!(crate::write::program(&p).is_ok());
    }

    /// Each field of the ELF header the reader checks gives its own error,
    /// and so do the headers of dynamic linking and thread-local storage
    /// after the loadable segments; each error says what it is.
    #[test]
    fn elf_errors_name_their_cause() {
        let good = layout();
        for (at, value, why) in [
            (0, 0x7e, ElfError::NotElf),
            (4, 1, ElfError::NotElf64),
            (5, 2, ElfError::NotElf64),
            (16, 3, ElfError::NotStatic),
            (18, 62, ElfError::NotAarch64),
            (54, 32, ElfError::HeaderSize),
        ] {
            let mut f = good.clone();
            f[at] = value;
            assert_eq!(program(&f, 0x1000), Err(why), "{why}");
        }
        assert_eq!(program(&good[..63], 0x1000), Err(ElfError::NotElf));
        for (kind, why) in [
            (PT_DYNAMIC, ElfError::NotStatic),
            (PT_INTERP, ElfError::NotStatic),
        ] {
            let mut f = good.clone();
            put(&mut f, 64 + PHDR_SIZE * 3, &kind.to_le_bytes());
            assert_eq!(program(&f, 0x1000), Err(why), "{why}");
        }
        for (e, text) in [
            (ElfError::NotElf, "not an ELF file"),
            (ElfError::NotElf64, "not a 64-bit little-endian ELF file"),
            (ElfError::NotStatic, "not a static executable"),
            (ElfError::NotAarch64, "not an AArch64 program"),
            (
                ElfError::HeaderSize,
                "program headers are not 56 bytes long",
            ),
            (
                ElfError::HeadersPastEnd,
                "the program headers run past the end of the file",
            ),
            (ElfError::TlsTwice, "two thread-local storage templates"),
            (
                ElfError::TlsOutside,
                "the thread-local storage template is not in the data segment",
            ),
            (
                ElfError::Protection {
                    vaddr: 0x20_1000,
                    flags: PF_W,
                },
                "the segment at 0x201000 is -w-, not r-x, r-- or rw-",
            ),
            (ElfError::Twice(Part::Code), "two code segments"),
            (
                ElfError::BytesPastEnd(Part::Data),
                "the data segment's bytes run past the end of the file",
            ),
        ] {
            assert_eq!(e.to_string(), text);
        }
    }

    /// `layout()` with its stack header turned into templates of TLS:
    /// address and bytes of each.
    fn with_tls(templates: &[(u64, u64)]) -> Vec<u8> {
        let mut f = layout();
        // The stack header's place and room for more headers after it.
        let first = 64 + PHDR_SIZE * 3;
        let count = 3 + templates.len();
        let mut headers = vec![0; PHDR_SIZE * templates.len()];
        for (i, &(vaddr, size)) in templates.iter().enumerate() {
            let h = PHDR_SIZE * i;
            put(&mut headers, h, &PT_TLS.to_le_bytes());
            put(&mut headers, h + 4, &PF_R.to_le_bytes());
            put(&mut headers, h + 16, &vaddr.to_le_bytes());
            put(&mut headers, h + 32, &size.to_le_bytes());
            put(&mut headers, h + 40, &(size + 16).to_le_bytes());
        }
        // The headers end before the first segment's bytes at 0x1000.
        put(&mut f, first, &headers);
        put(&mut f, 56, &(count as u16).to_le_bytes());
        f
    }

    /// One template of thread-local storage whose bytes are in the data
    /// segment's, or that has no bytes (lld puts a `.tbss` alone after the
    /// code), passes and changes nothing of the program; a template with
    /// bytes elsewhere, or a second one, is refused.
    #[test]
    fn one_tls_template_in_the_data_is_taken() {
        let plain = layout();
        let plain = program(&plain, 0x1000).unwrap();
        // The data segment's four bytes are at 0x202000.
        for template in [
            (0x20_2000, 4),
            (0x20_2001, 2),
            (0x20_2004, 0),
            (0x20_1a80, 0),
        ] {
            let f = with_tls(&[template]);
            assert_eq!(program(&f, 0x1000), Ok(plain), "{template:x?}");
        }
        for template in [(0x20_1ff0, 4), (0x20_2002, 4), (0x20_0000, 2)] {
            let f = with_tls(&[template]);
            assert_eq!(
                program(&f, 0x1000),
                Err(ElfError::TlsOutside),
                "{template:x?}"
            );
        }
        let f = with_tls(&[(0x20_2000, 4), (0x20_2000, 4)]);
        assert_eq!(program(&f, 0x1000), Err(ElfError::TlsTwice));
    }

    #[test]
    fn each_protection_comes_once() {
        let two = elf(&[
            (RX, 0x20_1000, 0x1000, b"a", 1),
            (RX, 0x20_2000, 0x2000, b"b", 1),
        ]);
        assert_eq!(program(&two, 0x1000), Err(ElfError::Twice(Part::Code)));
        for flags in [PF_R | PF_W | PF_X, PF_W, PF_X] {
            let f = elf(&[(flags, 0x20_1000, 0x1000, b"a", 1)]);
            let why = ElfError::Protection {
                vaddr: 0x20_1000,
                flags,
            };
            assert_eq!(program(&f, 0x1000), Err(why));
        }
    }

    /// The program of an ELF file keeps the rules of the simple format:
    /// each fault of Program::check comes back as it is.
    #[test]
    fn the_program_is_checked() {
        let at = |i: usize, field: usize| 64 + PHDR_SIZE * i + field;
        let fault = |f: &[u8], stack, why| {
            assert_eq!(program(f, stack), Err(ElfError::Program(why)), "{why}");
        };
        fault(&layout(), 0x1001, Error::BadStack(0x1001));
        let mut f = layout();
        put(&mut f, at(1, 16), &0x20_1008u64.to_le_bytes());
        fault(&f, 0x1000, Error::Misaligned(Part::Code));
        let mut f = layout();
        put(&mut f, at(2, 40), &2u64.to_le_bytes());
        fault(&f, 0x1000, Error::FileOverMemory(Part::Data));
        let mut f = layout();
        put(&mut f, at(0, 16), &0u64.to_le_bytes());
        fault(&f, 0x1000, Error::Outside(Part::Rodata));
        let mut f = layout();
        put(&mut f, at(2, 16), &0x20_1000u64.to_le_bytes());
        fault(&f, 0x1000, Error::Overlap(Part::Code, Part::Data));
        let mut f = layout();
        put(&mut f, 24, &0x20_2000u64.to_le_bytes());
        fault(&f, 0x1000, Error::BadEntry(0x20_2000));
        assert_eq!(
            ElfError::Program(Error::BadEntry(0x20_2000)).to_string(),
            format!("the program: {}", Error::BadEntry(0x20_2000))
        );
    }

    #[test]
    fn segments_and_headers_must_be_in_the_file() {
        let mut f = layout();
        // The data's four bytes at 0x3000 end the file; ask for five.
        put(&mut f, 64 + PHDR_SIZE * 2 + 32, &5u64.to_le_bytes());
        assert_eq!(program(&f, 0x1000), Err(ElfError::BytesPastEnd(Part::Data)));
        let mut f = layout();
        let len = f.len() as u64;
        put(&mut f, 32, &len.to_le_bytes());
        assert_eq!(program(&f, 0x1000), Err(ElfError::HeadersPastEnd));
    }

    /// The head of a file, its first page, gives the segments by their
    /// place in the file, as `program` reads them from the whole file; a
    /// head without every program header, bytes past the file's length, a
    /// segment outside the room and no code are refused.
    #[test]
    fn a_layout_comes_from_the_head_of_the_file() {
        let f = layout();
        let room = 0x1000..0x100_0000;
        let read = super::layout(&f[..0x1000], f.len() as u64, room.clone()).unwrap();
        let whole = program(&f, 0x1000).unwrap();
        assert_eq!(read.entry, whole.entry);
        for part in Part::ALL {
            let (load, segment) = (read.segments[part as usize], whole.segments[part as usize]);
            assert_eq!(
                (load.vaddr, load.mem_size),
                (segment.vaddr, segment.mem_size)
            );
            let bytes = &f[load.offset as usize..(load.offset + load.file_size) as usize];
            assert_eq!(bytes, segment.bytes, "{part}");
        }
        assert_eq!(
            super::layout(&f[..64 + PHDR_SIZE * 2], f.len() as u64, room.clone()),
            Err(ElfError::HeadersPastEnd)
        );
        assert_eq!(
            super::layout(&f[..0x1000], f.len() as u64 - 1, room.clone()),
            Err(ElfError::BytesPastEnd(Part::Data))
        );
        // A segment on the reserved pages above the room, or below it.
        for room in [0x1000..0x20_2000, 0x20_1000..0x100_0000] {
            assert!(matches!(
                super::layout(&f[..0x1000], f.len() as u64, room),
                Err(ElfError::Program(Error::Outside(_)))
            ));
        }
        let no_code = elf(&[(PF_R, 0x20_0000, 0x1000, b"rodata", 0x474)]);
        assert_eq!(
            super::layout(&no_code, no_code.len() as u64, room.clone()),
            Err(ElfError::Program(Error::BadEntry(0x20_1010)))
        );
        let mut f = layout();
        put(&mut f, 64 + PHDR_SIZE * 2 + 16, &0x20_1000u64.to_le_bytes());
        assert_eq!(
            super::layout(&f, f.len() as u64, room),
            Err(ElfError::Program(Error::Overlap(Part::Code, Part::Data)))
        );
    }
}
