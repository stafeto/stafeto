// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A program's ELF file as the simple program format wants it (spec 3.3,
//! 13.2): the entry point and one loadable segment per protection.
//! Programs are static AArch64 executables, linked with 4 KiB pages, each
//! segment on pages of its own and no RELRO split (.cargo/config.toml);
//! `Program::check` checks the rest. A program of the process service may
//! also be dynamic (spec 2, 3.12.4): an executable with `PT_INTERP`
//! `/lib/ld.so` and `PT_DYNAMIC`, whose C library is the shared libc.so
//! (`library` reads that file); `layout` tells the two kinds apart. A program may have one template of
//! thread-local storage (`PT_TLS`, spec 2, 3.5): its bytes, if any, lie in
//! the data segment, and the program's C library (relibc) builds each
//! thread's TLS from them, so the loader gives it no memory of its own.
//! xtask builds the boot image with it; a loader of programs from a disk
//! will read them with it too.

use crate::{Error, Part, Program, Segment, u32_at, u64_at};
use core::fmt;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const RX: u32 = PF_R | PF_X;
const RW: u32 = PF_R | PF_W;
const PHDR_SIZE: usize = 56;

/// The only interpreter a dynamic program names, with its NUL: the loader
/// of the process service plays it (proto_loader::INTERP is the same path).
pub const INTERP_PATH: &[u8; 11] = b"/lib/ld.so\0";

/// Why an ELF file is no program of the boot image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// The file is shorter than the ELF header or has no ELF signature.
    NotElf,
    /// It is not a 64-bit little-endian file.
    NotElf64,
    /// It is no executable, or it asks for dynamic linking where only a
    /// static program is read (`program`).
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
    /// The loadable segment at `vaddr` has the protection `flags`, which is none of
    /// r-x, r-- and rw-.
    Protection { vaddr: u64, flags: u32 },
    /// Two loadable segments have the protection of this part.
    Twice(Part),
    /// The bytes of the segment of this part run past the end of the file.
    BytesPastEnd(Part),
    /// The program breaks a rule of the simple format (`Program::check`).
    Program(Error),
    /// A program with `PT_INTERP` and no `PT_DYNAMIC`.
    InterpWithoutDynamic,
    /// A program with `PT_DYNAMIC` and no `PT_INTERP`.
    DynamicWithoutInterp,
    /// A header of this type twice (`PT_INTERP`, `PT_DYNAMIC`, `PT_PHDR`).
    HeaderTwice(u32),
    /// `PT_INTERP` is not `/lib/ld.so` with its NUL, or its bytes are not in
    /// the head of the file.
    BadInterp,
    /// `PT_INTERP` is not inside the bytes of the read-only segment.
    InterpOutside,
    /// `PT_DYNAMIC` is empty or not inside the bytes of the data segment.
    DynamicOutside,
    /// A dynamic program with a template of thread-local storage: its TLS
    /// has no place in the single module of libc.so.
    DynamicTls,
    /// The program headers are not inside the bytes of the read-only
    /// segment, where the C library reads them.
    PhdrOutside,
    /// A library that is no `ET_DYN` file.
    NotLibrary,
    /// A library with `PT_INTERP`.
    LibraryInterp,
    /// A library with no `PT_DYNAMIC`.
    NoDynamic,
    /// A library without a loadable segment of this part.
    Missing(Part),
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
                    "the segment at {vaddr:#x} is {}{}{}, which is none of r-x, r-- and rw-",
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
            ElfError::InterpWithoutDynamic => f.write_str("an interpreter and no dynamic section"),
            ElfError::DynamicWithoutInterp => f.write_str("a dynamic section and no interpreter"),
            ElfError::HeaderTwice(kind) => write!(f, "two program headers of type {kind:#x}"),
            ElfError::BadInterp => f.write_str("the interpreter is not /lib/ld.so"),
            ElfError::InterpOutside => {
                f.write_str("the interpreter is not in the read-only segment")
            }
            ElfError::DynamicOutside => {
                f.write_str("the dynamic section is not in the data segment")
            }
            ElfError::DynamicTls => f.write_str("a dynamic program with thread-local storage"),
            ElfError::PhdrOutside => {
                f.write_str("the program headers are not in the read-only segment")
            }
            ElfError::NotLibrary => f.write_str("not a shared object"),
            ElfError::LibraryInterp => f.write_str("a shared object with an interpreter"),
            ElfError::NoDynamic => f.write_str("no dynamic section"),
            ElfError::Missing(part) => write!(f, "no {part} segment"),
        }
    }
}

/// The program in `elf`, with a stack of `stack_size` bytes, checked
/// (`Program::check`); its segments borrow the file's bytes. Only a static
/// program is one: the boot image holds no dynamic file.
pub fn program(elf: &[u8], stack_size: u32) -> Result<Program<'_>, ElfError> {
    let read = scan(elf, elf.len() as u64, Expect::Executable)?;
    if read.interp.is_some() || read.dynamic.is_some() {
        return Err(ElfError::NotStatic);
    }
    let mut segments = [Segment::EMPTY; 3];
    for part in Part::ALL {
        let load = &read.segments[part as usize];
        if load.mem_size == 0 && load.file_size == 0 && load.vaddr == 0 {
            continue;
        }
        // `scan` checked that the bytes lie in the file.
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

    /// Whether `size` bytes from `vaddr` lie in the bytes the file gives
    /// the segment.
    fn holds(&self, vaddr: u64, size: u64) -> bool {
        vaddr >= self.vaddr
            && vaddr
                .checked_add(size)
                .zip(self.vaddr.checked_add(self.file_size))
                .is_some_and(|(end, top)| end <= top)
    }
}

/// Bytes at an address of the program's memory, as a header gives them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub vaddr: u64,
    pub size: u64,
}

/// A template of thread-local storage (`PT_TLS`): `file_size` bytes of
/// initial data at `vaddr`, `mem_size` in all, aligned to `align`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tls {
    pub vaddr: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub align: u64,
}

/// What kind of program an executable is (`layout`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// No `PT_INTERP` and no `PT_DYNAMIC`: everything is in the file.
    Static,
    /// `PT_INTERP` `/lib/ld.so` and `PT_DYNAMIC`: the loader relocates the
    /// program and libc.so before the jump (spec 2, 3.12.4).
    Dynamic,
}

/// A program read from the head of its ELF file (`layout`): the entry
/// point and the code, read-only data and data segments, in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub entry: u64,
    pub segments: [Load; 3],
    /// The size of the main stack the file asks for (`PT_GNU_STACK`, which
    /// `-z stack-size` sets), 0 when it asks for none.
    pub stack: u64,
    pub kind: Kind,
    /// `PT_DYNAMIC`, inside the bytes of the data segment: empty for a
    /// static program.
    pub dynamic: Extent,
    /// The address of `PT_INTERP` (the path `INTERP_PATH`, checked), inside
    /// the bytes of the read-only segment: 0 for a static program.
    pub interp: u64,
    /// Where the program headers lie in memory (`PT_PHDR`, or the offset of
    /// the table in the file from the start of the read-only segment), and
    /// how many there are; 0 for a static program, which has no use for them.
    pub phdr: u64,
    pub phnum: u16,
}

/// A shared object read from the head of its ELF file (`library`): the
/// three segments (code, read-only data, data) to map at their own
/// addresses, with `PT_DYNAMIC` and the single template of thread-local
/// storage, if it has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Library {
    pub segments: [Load; 3],
    pub dynamic: Extent,
    pub tls: Option<Tls>,
    /// The address of the `PT_TLS` program header in memory (inside the
    /// read-only segment), which the C library reads; 0 without `tls`.
    pub tls_header: u64,
}

/// The program whose ELF file is `file_len` bytes long and starts with
/// `head`, which holds the ELF header and every program header (a loader
/// that reads a file in pieces gives its first page): the rules of
/// `program` for a static one, those of spec 2, 3.12.4 for a dynamic one,
/// and each segment within `room`, a range of whole pages, so
/// that a loader keeps a program's segments off the addresses it and the
/// layer reserve. Nothing past `head` is read: the bytes of each segment
/// lie at `offset` in the file, and the loader copies them itself.
pub fn layout(head: &[u8], file_len: u64, room: core::ops::Range<u64>) -> Result<Layout, ElfError> {
    let read = scan(head, file_len, Expect::Executable)?;
    check_segments(&read.segments, &room)?;
    let [code, rodata, data] = read.segments;
    let entry = read.entry;
    if code.is_empty()
        || !entry.is_multiple_of(4)
        || !(code.vaddr..code.vaddr + code.mem_size).contains(&entry)
    {
        return Err(ElfError::Program(Error::BadEntry(entry)));
    }
    let mut layout = Layout {
        entry,
        segments: read.segments,
        stack: read.stack,
        kind: Kind::Static,
        dynamic: Extent { vaddr: 0, size: 0 },
        interp: 0,
        phdr: 0,
        phnum: 0,
    };
    let (interp, dynamic) = match (read.interp, read.dynamic) {
        (None, None) => return Ok(layout),
        (Some(_), None) => return Err(ElfError::InterpWithoutDynamic),
        (None, Some(_)) => return Err(ElfError::DynamicWithoutInterp),
        (Some(i), Some(d)) => (i, d),
    };
    if read.tls.is_some() {
        return Err(ElfError::DynamicTls);
    }
    // The interpreter: its path, in the head, inside the bytes of the
    // read-only segment at the place its address says.
    let (offset, ivaddr, isize) = interp;
    if isize != INTERP_PATH.len() as u64 {
        return Err(ElfError::BadInterp);
    }
    let path = usize::try_from(offset)
        .ok()
        .and_then(|at| head.get(at..at.checked_add(INTERP_PATH.len())?))
        .ok_or(ElfError::BadInterp)?;
    if path != INTERP_PATH {
        return Err(ElfError::BadInterp);
    }
    let in_rodata = !rodata.is_empty()
        && offset >= rodata.offset
        && offset - rodata.offset + isize <= rodata.file_size
        && ivaddr == rodata.vaddr + (offset - rodata.offset);
    if !in_rodata {
        return Err(ElfError::InterpOutside);
    }
    let (dvaddr, dsize) = dynamic;
    if dsize == 0 || data.is_empty() || !data.holds(dvaddr, dsize) {
        return Err(ElfError::DynamicOutside);
    }
    layout.phdr = headers_in_memory(&read, &rodata)?;
    layout.phnum = read.phnum;
    layout.kind = Kind::Dynamic;
    layout.dynamic = Extent {
        vaddr: dvaddr,
        size: dsize,
    };
    layout.interp = ivaddr;
    Ok(layout)
}

/// The shared object whose ELF file is `file_len` bytes long and starts
/// with `head` (the same rules of reading as `layout`): `ET_DYN`, one
/// segment of each protection, each inside `room` on pages of its own, no
/// interpreter, `PT_DYNAMIC` inside the data segment's bytes and at most
/// one template of thread-local storage there.
pub fn library(
    head: &[u8],
    file_len: u64,
    room: core::ops::Range<u64>,
) -> Result<Library, ElfError> {
    let read = scan(head, file_len, Expect::Library)?;
    if read.interp.is_some() {
        return Err(ElfError::LibraryInterp);
    }
    for part in Part::ALL {
        if read.segments[part as usize].is_empty() {
            return Err(ElfError::Missing(part));
        }
    }
    check_segments(&read.segments, &room)?;
    let (dvaddr, dsize) = read.dynamic.ok_or(ElfError::NoDynamic)?;
    let data = &read.segments[Part::Data as usize];
    if dsize == 0 || !data.holds(dvaddr, dsize) {
        return Err(ElfError::DynamicOutside);
    }
    let (tls, tls_header) = match read.tls {
        None => (None, 0),
        Some((index, tls)) => {
            let rodata = &read.segments[Part::Rodata as usize];
            (
                Some(tls),
                headers_in_memory(&read, rodata)? + PHDR_SIZE as u64 * index,
            )
        }
    };
    Ok(Library {
        segments: read.segments,
        dynamic: Extent {
            vaddr: dvaddr,
            size: dsize,
        },
        tls,
        tls_header,
    })
}

/// The address of the program header table in memory: `PT_PHDR` when the
/// file has it, else the table's place in the file counted from the start
/// of the read-only segment; the whole table inside the segment's bytes.
fn headers_in_memory(read: &Scan, rodata: &Load) -> Result<u64, ElfError> {
    let size = PHDR_SIZE as u64 * u64::from(read.phnum);
    let vaddr = match read.phdr {
        Some((vaddr, _)) => vaddr,
        None => {
            if rodata.is_empty() || read.phoff < rodata.offset {
                return Err(ElfError::PhdrOutside);
            }
            rodata.vaddr + (read.phoff - rodata.offset)
        }
    };
    if rodata.is_empty() || !rodata.holds(vaddr, size) {
        return Err(ElfError::PhdrOutside);
    }
    Ok(vaddr)
}

/// The rules of the segments `layout` and `library` share: whole pages,
/// bytes within memory, inside the room, no two on one page.
fn check_segments(segments: &[Load; 3], room: &core::ops::Range<u64>) -> Result<(), ElfError> {
    for part in Part::ALL {
        let s = &segments[part as usize];
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
            let (pa, pb) = (segments[a as usize].pages(), segments[b as usize].pages());
            if !pa.is_empty() && !pb.is_empty() && pa.start < pb.end && pb.start < pa.end {
                return Err(ElfError::Program(Error::Overlap(a, b)));
            }
        }
    }
    Ok(())
}

/// What `scan` expects of the file's type.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    Executable,
    Library,
}

/// What the headers of a file say, before the rules of `layout` and
/// `library` are applied.
struct Scan {
    entry: u64,
    segments: [Load; 3],
    stack: u64,
    phoff: u64,
    phnum: u16,
    /// The offset in the file, address and size of `PT_INTERP`.
    interp: Option<(u64, u64, u64)>,
    /// The address and size of `PT_DYNAMIC`.
    dynamic: Option<(u64, u64)>,
    /// The address and size of `PT_PHDR`.
    phdr: Option<(u64, u64)>,
    /// The template of TLS and the index of its header in the table.
    tls: Option<(u64, Tls)>,
}

/// The entry point and the loadable segments of the ELF file whose first
/// bytes are `head` and whose length is `file_len`: the checks of the ELF
/// header, one segment of each protection, the bytes of each within the
/// file, and one template of TLS within the data segment's bytes.
fn scan(head: &[u8], file_len: u64, expect: Expect) -> Result<Scan, ElfError> {
    let elf = head;
    if elf.len() < 64 || elf[..4] != *b"\x7fELF" {
        return Err(ElfError::NotElf);
    }
    if elf[4] != 2 || elf[5] != 1 {
        return Err(ElfError::NotElf64);
    }
    match (expect, u16_at(elf, 16)) {
        (Expect::Executable, ET_EXEC) | (Expect::Library, ET_DYN) => {}
        (Expect::Executable, _) => return Err(ElfError::NotStatic),
        (Expect::Library, _) => return Err(ElfError::NotLibrary),
    }
    if u16_at(elf, 18) != EM_AARCH64 {
        return Err(ElfError::NotAarch64);
    }
    if usize::from(u16_at(elf, 54)) != PHDR_SIZE {
        return Err(ElfError::HeaderSize);
    }
    let entry = u64_at(elf, 24);
    let headers = u64_at(elf, 32);
    let phnum = u16_at(elf, 56);
    let mut segments = [Load::EMPTY; 3];
    let mut seen = [false; 3];
    let mut tls = None;
    let (mut interp, mut dynamic, mut phdr) = (None, None, None);
    let mut stack = 0;
    for i in 0..u64::from(phnum) {
        let h = usize::try_from(headers.saturating_add(i * PHDR_SIZE as u64))
            .ok()
            .and_then(|at| elf.get(at..at.checked_add(PHDR_SIZE)?))
            .ok_or(ElfError::HeadersPastEnd)?;
        let kind = u32_at(h, 0);
        match kind {
            PT_LOAD => {}
            PT_DYNAMIC | PT_INTERP | PT_PHDR => {
                let found = (u64_at(h, 8), u64_at(h, 16), u64_at(h, 32));
                let twice = match kind {
                    PT_DYNAMIC => dynamic.replace((found.1, found.2)).is_some(),
                    PT_INTERP => interp.replace(found).is_some(),
                    _ => phdr.replace((found.1, found.2)).is_some(),
                };
                if twice {
                    return Err(ElfError::HeaderTwice(kind));
                }
                continue;
            }
            PT_GNU_STACK => {
                stack = u64_at(h, 40);
                continue;
            }
            PT_TLS => {
                let found = Tls {
                    vaddr: u64_at(h, 16),
                    file_size: u64_at(h, 32),
                    mem_size: u64_at(h, 40),
                    align: u64_at(h, 48),
                };
                if tls.replace((i, found)).is_some() {
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
    if let Some((_, tls)) = tls
        && tls.file_size > 0
    {
        let data = &segments[Part::Data as usize];
        let end = data.vaddr.saturating_add(data.file_size);
        if !seen[Part::Data as usize]
            || tls.vaddr < data.vaddr
            || tls.vaddr.saturating_add(tls.file_size) > end
        {
            return Err(ElfError::TlsOutside);
        }
    }
    Ok(Scan {
        entry,
        segments,
        stack,
        phoff: headers,
        phnum,
        interp,
        dynamic,
        phdr,
        tls,
    })
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
    fn the_stack_a_file_asks_for_is_pt_gnu_stack() {
        let mut f = layout();
        let room = 0x20_0000..0x40_0000;
        let read = super::layout(&f, f.len() as u64, room.clone()).unwrap();
        assert_eq!(read.stack, 0, "no size asked");
        let header = 64 + PHDR_SIZE * 3;
        put(&mut f, header + 40, &(1u64 << 20).to_le_bytes());
        let read = super::layout(&f, f.len() as u64, room).unwrap();
        assert_eq!(read.stack, 1 << 20);
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
                "the segment at 0x201000 is -w-, which is none of r-x, r-- and rw-",
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

    // ---- Dynamic programs and shared objects (spec 2, 3.12.4).

    /// A program header of a test file.
    #[derive(Clone, Copy)]
    struct Ph {
        kind: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
        align: u64,
    }

    /// The headers a test file has; index them with the constants.
    const R: usize = 0;
    const D: usize = 2;
    const DYN: usize = 3;
    const INT: usize = 4;
    const PHDR: usize = 5;

    fn ph(kind: u32, flags: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64) -> Ph {
        Ph {
            kind,
            flags,
            offset,
            vaddr,
            filesz,
            memsz,
            align: 0x1000,
        }
    }

    /// The file for `phs`: ELF header with the type and entry, the headers
    /// at 64, the interpreter's path at 0x200, `size` bytes in all.
    fn file(etype: u16, entry: u64, phs: &[Ph], size: usize) -> Vec<u8> {
        let mut f = vec![0; size];
        put(&mut f, 0, b"\x7fELF\x02\x01\x01");
        put(&mut f, 16, &etype.to_le_bytes());
        put(&mut f, 18, &EM_AARCH64.to_le_bytes());
        put(&mut f, 24, &entry.to_le_bytes());
        put(&mut f, 32, &64u64.to_le_bytes());
        put(&mut f, 54, &(PHDR_SIZE as u16).to_le_bytes());
        put(&mut f, 56, &(phs.len() as u16).to_le_bytes());
        for (i, p) in phs.iter().enumerate() {
            let h = 64 + PHDR_SIZE * i;
            put(&mut f, h, &p.kind.to_le_bytes());
            put(&mut f, h + 4, &p.flags.to_le_bytes());
            put(&mut f, h + 8, &p.offset.to_le_bytes());
            put(&mut f, h + 16, &p.vaddr.to_le_bytes());
            put(&mut f, h + 32, &p.filesz.to_le_bytes());
            put(&mut f, h + 40, &p.memsz.to_le_bytes());
            put(&mut f, h + 48, &p.align.to_le_bytes());
        }
        put(&mut f, 0x200, INTERP_PATH);
        f
    }

    /// A dynamic program as lld lays it out: the headers and the path in
    /// the read-only segment at 0x200000, code, data with the dynamic
    /// section at 0x202010, a stack header.
    fn dynamic_headers() -> Vec<Ph> {
        vec![
            ph(PT_LOAD, PF_R, 0, 0x20_0000, 0x400, 0x400),
            ph(PT_LOAD, RX, 0x1000, 0x20_1000, 0x20, 0x20),
            ph(PT_LOAD, RW, 0x2000, 0x20_2000, 0x100, 0x200),
            ph(PT_DYNAMIC, RW, 0x2010, 0x20_2010, 0x60, 0x60),
            ph(PT_INTERP, PF_R, 0x200, 0x20_0200, 11, 11),
            ph(PT_PHDR, PF_R, 64, 0x20_0040, 56 * 7, 56 * 7),
            ph(PT_GNU_STACK, RW, 0, 0, 0, 0),
        ]
    }

    const PROGRAM_ROOM: core::ops::Range<u64> = 0x1000..0x0200_0000;
    const LIBRARY_ROOM: core::ops::Range<u64> = 0x0400_0000..0x0800_0000;

    fn dynamic_file(phs: &[Ph]) -> Vec<u8> {
        file(ET_EXEC, 0x20_1000, phs, 0x2200)
    }

    fn dyn_layout(phs: &[Ph]) -> Result<Layout, ElfError> {
        let f = dynamic_file(phs);
        super::layout(&f[..0x1000], f.len() as u64, PROGRAM_ROOM)
    }

    #[test]
    fn a_static_program_stays_static() {
        let f = layout();
        let read = super::layout(&f, f.len() as u64, 0x1000..0x100_0000).unwrap();
        assert_eq!(read.kind, Kind::Static);
        let none = Extent { vaddr: 0, size: 0 };
        assert_eq!(
            (read.dynamic, read.interp, read.phdr, read.phnum),
            (none, 0, 0, 0)
        );
    }

    #[test]
    fn a_dynamic_program_is_told_by_its_two_headers() {
        let read = dyn_layout(&dynamic_headers()).unwrap();
        assert_eq!(read.kind, Kind::Dynamic);
        assert_eq!(read.entry, 0x20_1000);
        assert_eq!(
            read.dynamic,
            Extent {
                vaddr: 0x20_2010,
                size: 0x60
            }
        );
        assert_eq!(read.interp, 0x20_0200);
        assert_eq!((read.phdr, read.phnum), (0x20_0040, 7));
        assert_eq!(read.segments[Part::Rodata as usize].vaddr, 0x20_0000);
        // `program` is for the boot image: static files only.
        let f = dynamic_file(&dynamic_headers());
        assert_eq!(program(&f, 0x1000), Err(ElfError::NotStatic));
    }

    /// Without PT_PHDR the table is found by e_phoff from the start of the
    /// segment, which holds the file from offset 0 as lld does.
    #[test]
    fn the_headers_in_memory_come_from_phdr_or_from_the_offset() {
        let mut phs = dynamic_headers();
        phs.remove(PHDR);
        assert_eq!(dyn_layout(&phs).unwrap().phdr, 0x20_0040);
        // The segment starts later in the file than the table: the table is outside.
        let mut late = phs.clone();
        late[R] = ph(PT_LOAD, PF_R, 0x100, 0x20_0000, 0x300, 0x300);
        late[INT] = ph(PT_INTERP, PF_R, 0x200, 0x20_0100, 11, 11);
        assert_eq!(dyn_layout(&late), Err(ElfError::PhdrOutside));
        // A table that ends past the segment's bytes.
        let mut short = phs.clone();
        short[R].filesz = 0x230;
        short[R].memsz = 0x230;
        assert_eq!(dyn_layout(&short).unwrap().phdr, 0x20_0040);
        short[R].filesz = 0x1f0;
        assert_eq!(dyn_layout(&short), Err(ElfError::InterpOutside));
        // PT_PHDR outside the segment, or past its bytes.
        for (vaddr, size) in [
            (0x20_1000, 56 * 7),
            (0x20_0300, 56 * 7),
            (0x1f_ffc0, 56 * 7),
            (0x20_0040, 56 * 7),
        ] {
            let mut p = dynamic_headers();
            p[PHDR] = ph(PT_PHDR, PF_R, 64, vaddr, size, size);
            let r = dyn_layout(&p);
            if vaddr == 0x20_0040 {
                assert!(r.is_ok());
            } else {
                assert_eq!(r, Err(ElfError::PhdrOutside), "{vaddr:#x}");
            }
        }
    }

    #[test]
    fn the_two_dynamic_headers_come_together() {
        let mut p = dynamic_headers();
        p.remove(DYN);
        assert_eq!(dyn_layout(&p), Err(ElfError::InterpWithoutDynamic));
        let mut p = dynamic_headers();
        p.remove(INT);
        assert_eq!(dyn_layout(&p), Err(ElfError::DynamicWithoutInterp));
        for (index, kind) in [(DYN, PT_DYNAMIC), (INT, PT_INTERP), (PHDR, PT_PHDR)] {
            let mut p = dynamic_headers();
            p.push(p[index]);
            assert_eq!(dyn_layout(&p), Err(ElfError::HeaderTwice(kind)));
        }
    }

    #[test]
    fn the_interpreter_is_one_path() {
        for (path, ok) in [
            (&b"/lib/ld.so\0"[..], true),
            (b"/lib/other.so\0", false),
            (b"/lib/ld.so.1\0", false),
            (b"/lib/ld.so\x01", false),
            (b"/LIB/ld.so\0", false),
            (b"lib/ld.so\0\0", false),
            (b"\0\0\0\0\0\0\0\0\0\0\0", false),
        ] {
            let phs = dynamic_headers();
            let mut f = dynamic_file(&phs);
            put(&mut f, 0x200, &[0; 16]);
            put(&mut f, 0x200, path);
            let r = super::layout(&f[..0x1000], f.len() as u64, PROGRAM_ROOM);
            if ok {
                assert!(r.is_ok());
            } else {
                assert_eq!(r, Err(ElfError::BadInterp), "{path:?}");
            }
        }
        // Another size: the path with no NUL, or longer.
        for size in [10, 12, 0, 255] {
            let mut p = dynamic_headers();
            p[INT].filesz = size;
            p[INT].memsz = size;
            assert_eq!(dyn_layout(&p), Err(ElfError::BadInterp), "{size}");
        }
        // The path is not in the head the loader read.
        let f = dynamic_file(&dynamic_headers());
        assert_eq!(
            super::layout(&f[..0x205], f.len() as u64, PROGRAM_ROOM),
            Err(ElfError::BadInterp)
        );
        let mut p = dynamic_headers();
        p[INT].offset = u64::MAX - 3;
        assert_eq!(dyn_layout(&p), Err(ElfError::BadInterp));
    }

    #[test]
    fn the_interpreter_lies_in_the_read_only_segment() {
        // Its address is not where the segment shows its bytes.
        for vaddr in [0x20_0201, 0x20_0000, 0x20_1000, 0x21_0200, 0] {
            let mut p = dynamic_headers();
            p[INT].vaddr = vaddr;
            assert_eq!(dyn_layout(&p), Err(ElfError::InterpOutside), "{vaddr:#x}");
        }
        // Its bytes in the file are not the segment's (it ends before 0x200).
        let mut p = dynamic_headers();
        p[R].filesz = 0x205;
        p[R].memsz = 0x205;
        assert_eq!(dyn_layout(&p), Err(ElfError::InterpOutside));
        // The segment has no bytes in the file for it.
        let mut p = dynamic_headers();
        p[R] = ph(PT_LOAD, PF_R, 0x400, 0x20_0000, 0x100, 0x100);
        assert_eq!(dyn_layout(&p), Err(ElfError::InterpOutside));
    }

    #[test]
    fn the_dynamic_section_lies_in_the_bytes_of_the_data() {
        for (vaddr, size) in [
            (0x20_2000u64, 0x100u64),
            (0x20_20a0, 0x60), // the end of the bytes
            (0x20_2010, 0x60),
        ] {
            let mut p = dynamic_headers();
            p[DYN].vaddr = vaddr;
            p[DYN].filesz = size;
            assert!(dyn_layout(&p).is_ok(), "{vaddr:#x} {size:#x}");
        }
        for (vaddr, size) in [
            (0x20_2010u64, 0u64), // empty
            (0x20_2100, 0x10),    // in the memory but past the bytes
            (0x20_20f8, 0x10),    // across the end of the bytes
            (0x20_1ff0, 0x20),    // before the segment
            (0x20_0100, 0x20),    // in the read-only segment
            (0x20_1000, 0x10),    // in the code
            (u64::MAX - 7, 0x10), // wraps
        ] {
            let mut p = dynamic_headers();
            p[DYN].vaddr = vaddr;
            p[DYN].filesz = size;
            assert_eq!(
                dyn_layout(&p),
                Err(ElfError::DynamicOutside),
                "{vaddr:#x} {size:#x}"
            );
        }
        // No data segment at all.
        let mut p = dynamic_headers();
        p.remove(D);
        let r = dyn_layout(&p);
        assert_eq!(r, Err(ElfError::DynamicOutside));
    }

    #[test]
    fn a_dynamic_program_has_no_tls() {
        for (filesz, memsz) in [(4, 20), (0, 16), (0, 0)] {
            let mut p = dynamic_headers();
            p.push(ph(PT_TLS, PF_R, 0x2020, 0x20_2020, filesz, memsz));
            assert_eq!(
                dyn_layout(&p),
                Err(ElfError::DynamicTls),
                "{filesz} {memsz}"
            );
        }
    }

    #[test]
    fn a_dynamic_program_keeps_the_rules_of_a_program() {
        // Not in the room, the code, the segments on one page, the entry.
        let f = dynamic_file(&dynamic_headers());
        for room in [0x1000..0x20_2000, 0x20_1000..0x100_0000] {
            assert!(matches!(
                super::layout(&f[..0x1000], f.len() as u64, room),
                Err(ElfError::Program(Error::Outside(_)))
            ));
        }
        let mut p = dynamic_headers();
        p[D].vaddr = 0x20_1000;
        assert!(matches!(
            dyn_layout(&p),
            Err(ElfError::Program(Error::Overlap(..)))
        ));
        let f = file(ET_EXEC, 0x20_2000, &dynamic_headers(), 0x2200);
        assert_eq!(
            super::layout(&f[..0x1000], f.len() as u64, PROGRAM_ROOM),
            Err(ElfError::Program(Error::BadEntry(0x20_2000)))
        );
        // A PIE is no program.
        let f = file(ET_DYN, 0x1000, &dynamic_headers(), 0x2200);
        assert_eq!(
            super::layout(&f[..0x1000], f.len() as u64, PROGRAM_ROOM),
            Err(ElfError::NotStatic)
        );
        // Bytes past the end of the file.
        let f = dynamic_file(&dynamic_headers());
        assert_eq!(
            super::layout(&f[..0x1000], 0x2050, PROGRAM_ROOM),
            Err(ElfError::BytesPastEnd(Part::Data))
        );
    }

    /// A shared object: the three segments in the library's room, the
    /// dynamic section and a template of TLS in the data bytes, the
    /// headers in the read-only segment.
    fn library_headers() -> Vec<Ph> {
        vec![
            ph(PT_LOAD, PF_R, 0, 0x0400_0000, 0x500, 0x500),
            ph(PT_LOAD, RX, 0x1000, 0x0400_1000, 0x40, 0x40),
            ph(PT_LOAD, RW, 0x2000, 0x0400_2000, 0x200, 0x400),
            ph(PT_DYNAMIC, RW, 0x2010, 0x0400_2010, 0x60, 0x60),
            Ph {
                align: 64,
                ..ph(PT_TLS, PF_R, 0x2100, 0x0400_2100, 0x20, 0x280)
            },
            ph(PT_GNU_STACK, RW, 0, 0, 0, 0),
        ]
    }

    fn lib_file(phs: &[Ph]) -> Vec<u8> {
        file(ET_DYN, 0, phs, 0x2300)
    }

    fn lib(phs: &[Ph]) -> Result<Library, ElfError> {
        let f = lib_file(phs);
        library(&f[..0x1000], f.len() as u64, LIBRARY_ROOM)
    }

    #[test]
    fn a_shared_object_is_three_segments_a_dynamic_section_and_a_block_of_tls() {
        let l = lib(&library_headers()).unwrap();
        assert_eq!(l.segments[Part::Rodata as usize].vaddr, 0x0400_0000);
        assert_eq!(
            l.segments[Part::Code as usize],
            super::Load {
                vaddr: 0x0400_1000,
                mem_size: 0x40,
                offset: 0x1000,
                file_size: 0x40
            }
        );
        assert_eq!(l.segments[Part::Data as usize].mem_size, 0x400);
        assert_eq!(
            l.dynamic,
            Extent {
                vaddr: 0x0400_2010,
                size: 0x60
            }
        );
        assert_eq!(
            l.tls,
            Some(Tls {
                vaddr: 0x0400_2100,
                file_size: 0x20,
                mem_size: 0x280,
                align: 64
            })
        );
        // The TLS header is the fifth: the table at 64 and 4 headers before it.
        assert_eq!(l.tls_header, 0x0400_0000 + 64 + 56 * 4);
        // Without a template: none, and no address.
        let mut p = library_headers();
        p.remove(4);
        let l = lib(&p).unwrap();
        assert_eq!((l.tls, l.tls_header), (None, 0));
        // A template with no bytes (only .tbss) may lie anywhere.
        let mut p = library_headers();
        p[4].vaddr = 0x0400_2300;
        p[4].filesz = 0;
        assert!(lib(&p).is_ok());
    }

    #[test]
    fn a_shared_object_is_refused_when_it_breaks_a_rule() {
        let good = library_headers();
        // The type, the interpreter, the dynamic section.
        let f = file(ET_EXEC, 0, &good, 0x2300);
        assert_eq!(
            library(&f[..0x1000], f.len() as u64, LIBRARY_ROOM),
            Err(ElfError::NotLibrary)
        );
        let mut p = good.clone();
        p.push(ph(PT_INTERP, PF_R, 0x200, 0x0400_0200, 11, 11));
        assert_eq!(lib(&p), Err(ElfError::LibraryInterp));
        let mut p = good.clone();
        p.remove(3);
        assert_eq!(lib(&p), Err(ElfError::NoDynamic));
        // One segment of each protection.
        for (index, part) in [(0, Part::Rodata), (1, Part::Code), (2, Part::Data)] {
            let mut p = good.clone();
            p.remove(index);
            if part == Part::Data {
                // The dynamic section and the template lie in the data.
                p.drain(2..4);
            }
            assert_eq!(lib(&p), Err(ElfError::Missing(part)), "{part}");
        }
        let mut p = good.clone();
        p.push(ph(PT_LOAD, RX, 0x1000, 0x0400_5000, 0x10, 0x10));
        assert_eq!(lib(&p), Err(ElfError::Twice(Part::Code)));
        let mut p = good.clone();
        p[1].flags = PF_W;
        assert_eq!(
            lib(&p),
            Err(ElfError::Protection {
                vaddr: 0x0400_1000,
                flags: PF_W
            })
        );
        // The room: below, above, across.
        for (index, vaddr) in [(0, 0x03ff_f000u64), (1, 0x0800_0000), (0, 0x2000_0000)] {
            let mut p = good.clone();
            p[index].vaddr = vaddr;
            assert!(
                matches!(lib(&p), Err(ElfError::Program(Error::Outside(_)))),
                "{vaddr:#x}"
            );
        }
        let mut p = good.clone();
        p[2].memsz = 0x0400_0000; // runs past the end of the room
        assert!(matches!(lib(&p), Err(ElfError::Program(Error::Outside(_)))));
        // Pages: not aligned, two segments on one page, bytes over memory.
        let mut p = good.clone();
        p[1].vaddr = 0x0400_1010;
        assert_eq!(
            lib(&p),
            Err(ElfError::Program(Error::Misaligned(Part::Code)))
        );
        let mut p = good.clone();
        p[1].vaddr = 0x0400_0000 + 0x500 - 0x500; // the read-only page again
        assert!(matches!(
            lib(&p),
            Err(ElfError::Program(Error::Overlap(..)))
        ));
        let mut p = good.clone();
        p[2].memsz = 0x100;
        assert_eq!(
            lib(&p),
            Err(ElfError::Program(Error::FileOverMemory(Part::Data)))
        );
        // The bytes in the file.
        let f = lib_file(&good);
        assert_eq!(
            library(&f[..0x1000], 0x2100, LIBRARY_ROOM),
            Err(ElfError::BytesPastEnd(Part::Data))
        );
        assert_eq!(
            library(&f[..64 + 56 * 2], f.len() as u64, LIBRARY_ROOM),
            Err(ElfError::HeadersPastEnd)
        );
    }

    #[test]
    fn the_dynamic_section_and_the_tls_of_a_shared_object_lie_in_the_data_bytes() {
        for (vaddr, size) in [
            (0x0400_2200u64, 0x10u64),
            (0x0400_21f8, 0x10),
            (0x0400_1000, 0x10),
            (0x0400_0100, 0x10),
            (0x0400_2010, 0),
        ] {
            let mut p = library_headers();
            p[3].vaddr = vaddr;
            p[3].filesz = size;
            assert_eq!(lib(&p), Err(ElfError::DynamicOutside), "{vaddr:#x} {size}");
        }
        let mut p = library_headers();
        p.push(p[4]);
        assert_eq!(lib(&p), Err(ElfError::TlsTwice));
        for (vaddr, size) in [
            (0x0400_21f8u64, 0x20u64),
            (0x0400_1000, 0x10),
            (0x0400_1ff0, 0x20),
            (0x0400_0100, 8),
        ] {
            let mut p = library_headers();
            p[4].vaddr = vaddr;
            p[4].filesz = size;
            assert_eq!(lib(&p), Err(ElfError::TlsOutside), "{vaddr:#x} {size}");
        }
        // The headers the C library reads must be in the read-only bytes.
        let mut p = library_headers();
        p[0].filesz = 64 + 56 * 4 + 20;
        p[0].memsz = 64 + 56 * 4 + 20;
        assert_eq!(lib(&p), Err(ElfError::PhdrOutside));
        let mut p = library_headers();
        p[0] = ph(PT_LOAD, PF_R, 0x80, 0x0400_0000, 0x400, 0x400);
        assert_eq!(lib(&p), Err(ElfError::PhdrOutside));
    }

    #[test]
    fn the_new_errors_say_what_they_are() {
        for (e, text) in [
            (
                ElfError::InterpWithoutDynamic,
                "an interpreter and no dynamic section",
            ),
            (
                ElfError::DynamicWithoutInterp,
                "a dynamic section and no interpreter",
            ),
            (ElfError::HeaderTwice(3), "two program headers of type 0x3"),
            (ElfError::BadInterp, "the interpreter is not /lib/ld.so"),
            (
                ElfError::InterpOutside,
                "the interpreter is not in the read-only segment",
            ),
            (
                ElfError::DynamicOutside,
                "the dynamic section is not in the data segment",
            ),
            (
                ElfError::DynamicTls,
                "a dynamic program with thread-local storage",
            ),
            (
                ElfError::PhdrOutside,
                "the program headers are not in the read-only segment",
            ),
            (ElfError::NotLibrary, "not a shared object"),
            (
                ElfError::LibraryInterp,
                "a shared object with an interpreter",
            ),
            (ElfError::NoDynamic, "no dynamic section"),
            (ElfError::Missing(Part::Code), "no code segment"),
        ] {
            assert_eq!(e.to_string(), text);
        }
    }

    // ---- The real files of target/libc-so (cargo xtask libc-so).

    fn real(name: &str) -> Option<Vec<u8>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/libc-so")
            .join(name);
        match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                // The build that fills target/libc-so requires the files.
                assert!(
                    std::env::var_os("STAFETO_REQUIRE_LIBC_SO").is_none(),
                    "no {}",
                    path.display()
                );
                eprintln!("skipped: no {}", path.display());
                None
            }
        }
    }

    #[test]
    fn the_real_libc_so_is_a_shared_object() {
        let Some(f) = real("libc.so") else { return };
        let l = library(&f[..0x1000], f.len() as u64, LIBRARY_ROOM).unwrap();
        assert_eq!(l.segments[Part::Rodata as usize].vaddr, 0x0400_0000);
        let data = &l.segments[Part::Data as usize];
        assert!(data.mem_size > data.file_size, "the bss");
        assert!(data.holds(l.dynamic.vaddr, l.dynamic.size));
        let tls = l.tls.expect("libc.so has a block of TLS");
        assert!(tls.mem_size > tls.file_size && tls.align.is_power_of_two());
        let rodata = &l.segments[Part::Rodata as usize];
        assert!(rodata.holds(l.tls_header, PHDR_SIZE as u64));
        // The header in memory is the PT_TLS of the file.
        let at = (l.tls_header - rodata.vaddr + rodata.offset) as usize;
        assert_eq!(u32_at(&f, at), PT_TLS);
        assert_eq!(u64_at(&f, at + 16), tls.vaddr);
        // A shared object is no program.
        assert_eq!(program(&f, 0x1000), Err(ElfError::NotStatic));
        assert_eq!(
            super::layout(&f[..0x1000], f.len() as u64, LIBRARY_ROOM),
            Err(ElfError::NotStatic)
        );
    }

    #[test]
    fn the_real_dynamic_programs_are_dynamic() {
        for name in ["probes/so-hello", "probes/so-image"] {
            let Some(f) = real(name) else { return };
            let l = super::layout(&f[..0x1000], f.len() as u64, PROGRAM_ROOM).unwrap();
            assert_eq!(l.kind, Kind::Dynamic, "{name}");
            assert_ne!(l.interp, 0);
            let rodata = &l.segments[Part::Rodata as usize];
            assert!(rodata.holds(l.phdr, 56 * u64::from(l.phnum)));
            assert!(l.segments[Part::Data as usize].holds(l.dynamic.vaddr, l.dynamic.size));
            let at = (l.phdr - rodata.vaddr + rodata.offset) as usize;
            assert_eq!(u32_at(&f, at), PT_PHDR, "the first header is PT_PHDR");
            assert_eq!(program(&f, 0x1000), Err(ElfError::NotStatic));
            assert_eq!(
                library(&f[..0x1000], f.len() as u64, LIBRARY_ROOM),
                Err(ElfError::NotLibrary)
            );
        }
    }
}
