// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A program's ELF file as the simple program format wants it (spec 3.3,
//! 13.2): the entry point and one loadable segment per protection.
//! Programs are static AArch64 executables without thread-local storage,
//! linked with 4 KiB pages, each segment on pages of its own and no RELRO
//! split (.cargo/config.toml); `Program::parse` of the written program
//! checks the rest. xtask builds the boot image with it; a loader of
//! programs from a disk will read them with it too.

use crate::{Part, Program, Segment, u32_at, u64_at};
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
    /// It has thread-local storage.
    Tls,
    /// The loadable segment at `vaddr` has the protection `flags`, not r-x,
    /// r-- or rw-.
    Protection { vaddr: u64, flags: u32 },
    /// Two loadable segments have the protection of this part.
    Twice(Part),
    /// The bytes of the segment of this part run past the end of the file.
    BytesPastEnd(Part),
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
            ElfError::Tls => f.write_str("thread-local storage is not supported"),
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
        }
    }
}

/// The program in `elf`, with a stack of `stack_size` bytes; its segments
/// borrow the file's bytes.
pub fn program(elf: &[u8], stack_size: u32) -> Result<Program<'_>, ElfError> {
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
    let headers = u64_at(elf, 32) as usize;
    let mut segments = [Segment::EMPTY; 3];
    let mut seen = [false; 3];
    for i in 0..usize::from(u16_at(elf, 56)) {
        let at = headers.saturating_add(i * PHDR_SIZE);
        let h = elf
            .get(at..at.saturating_add(PHDR_SIZE))
            .ok_or(ElfError::HeadersPastEnd)?;
        match u32_at(h, 0) {
            PT_LOAD => {}
            PT_DYNAMIC | PT_INTERP => return Err(ElfError::NotStatic),
            PT_TLS => return Err(ElfError::Tls),
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
        let (offset, file_size) = (offset as usize, file_size as usize);
        let bytes = elf
            .get(offset..offset.saturating_add(file_size))
            .ok_or(ElfError::BytesPastEnd(part))?;
        segments[part as usize] = Segment {
            vaddr,
            mem_size,
            bytes,
        };
    }
    Ok(Program {
        entry,
        stack_size,
        segments,
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
            (PT_TLS, ElfError::Tls),
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
            (ElfError::Tls, "thread-local storage is not supported"),
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
}
