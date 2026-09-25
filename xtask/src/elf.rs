// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A program's ELF file as the simple program format of the boot image
//! wants it (spec 3.3): the entry point and one loadable segment per
//! protection. Programs are static AArch64 executables without
//! thread-local storage, linked with 4 KiB pages, each segment on pages of
//! its own and no RELRO split (.cargo/config.toml); the boot image writer
//! checks the rest.

use bootimg::{Part, Program, Segment};

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

/// The program in `elf`, with a stack of `stack_size` bytes.
pub fn program(elf: &[u8], stack_size: u32) -> Result<Program<'_>, String> {
    if elf.len() < 64 || elf[..4] != *b"\x7fELF" {
        return Err("not an ELF file".into());
    }
    if elf[4] != 2 || elf[5] != 1 {
        return Err("not a 64-bit little-endian ELF file".into());
    }
    if u16_at(elf, 16) != ET_EXEC {
        return Err("not a static executable".into());
    }
    if u16_at(elf, 18) != EM_AARCH64 {
        return Err("not an AArch64 program".into());
    }
    if usize::from(u16_at(elf, 54)) != PHDR_SIZE {
        return Err("program headers are not 56 bytes long".into());
    }
    let entry = u64_at(elf, 24);
    let headers = u64_at(elf, 32) as usize;
    let mut segments = [Segment::EMPTY; 3];
    let mut seen = [false; 3];
    for i in 0..usize::from(u16_at(elf, 56)) {
        let at = headers.saturating_add(i * PHDR_SIZE);
        let h = elf
            .get(at..at.saturating_add(PHDR_SIZE))
            .ok_or("the program headers run past the end of the file")?;
        match u32_at(h, 0) {
            PT_LOAD => {}
            PT_DYNAMIC | PT_INTERP => return Err("not a static executable".into()),
            PT_TLS => return Err("thread-local storage is not supported".into()),
            _ => continue,
        }
        let (flags, offset, vaddr) = (u32_at(h, 4), u64_at(h, 8), u64_at(h, 16));
        let (file_size, mem_size) = (u64_at(h, 32), u64_at(h, 40));
        let part = match flags & (PF_R | PF_W | PF_X) {
            RX => Part::Code,
            PF_R => Part::Rodata,
            RW => Part::Data,
            f => {
                return Err(format!(
                    "the segment at {vaddr:#x} is {}, not r-x, r-- or rw-",
                    protection(f)
                ));
            }
        };
        if std::mem::replace(&mut seen[part as usize], true) {
            return Err(format!("two {part} segments"));
        }
        let (offset, file_size) = (offset as usize, file_size as usize);
        let bytes = elf
            .get(offset..offset.saturating_add(file_size))
            .ok_or_else(|| format!("the {part} segment's bytes run past the end of the file"))?;
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

fn protection(flags: u32) -> String {
    [(PF_R, 'r'), (PF_W, 'w'), (PF_X, 'x')]
        .iter()
        .map(|&(bit, c)| if flags & bit != 0 { c } else { '-' })
        .collect()
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
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
        assert!(bootimg::write::program(&p).is_ok());
    }

    #[test]
    fn only_static_aarch64_executables_are_read() {
        let good = layout();
        for (at, value, why) in [
            (0, 0x7e, "not an ELF file"),
            (4, 1, "not a 64-bit little-endian ELF file"),
            (5, 2, "not a 64-bit little-endian ELF file"),
            (16, 3, "not a static executable"),
            (18, 62, "not an AArch64 program"),
            (54, 32, "program headers are not 56 bytes long"),
        ] {
            let mut f = good.clone();
            f[at] = value;
            assert_eq!(program(&f, 0x1000).err().as_deref(), Some(why), "{why}");
        }
        assert_eq!(
            program(&good[..63], 0x1000).err().as_deref(),
            Some("not an ELF file")
        );
        // The header after the loadable segments, as dynamic linking or
        // thread-local storage would have it.
        for (kind, why) in [
            (PT_DYNAMIC, "not a static executable"),
            (PT_INTERP, "not a static executable"),
            (PT_TLS, "thread-local storage is not supported"),
        ] {
            let mut f = good.clone();
            put(&mut f, 64 + PHDR_SIZE * 3, &kind.to_le_bytes());
            assert_eq!(program(&f, 0x1000).err().as_deref(), Some(why), "{why}");
        }
    }

    #[test]
    fn each_protection_comes_once() {
        let two = elf(&[
            (RX, 0x20_1000, 0x1000, b"a", 1),
            (RX, 0x20_2000, 0x2000, b"b", 1),
        ]);
        assert_eq!(
            program(&two, 0x1000).err().as_deref(),
            Some("two code segments")
        );
        for (flags, name) in [(PF_R | PF_W | PF_X, "rwx"), (PF_W, "-w-"), (PF_X, "--x")] {
            let f = elf(&[(flags, 0x20_1000, 0x1000, b"a", 1)]);
            let why = format!("the segment at 0x201000 is {name}, not r-x, r-- or rw-");
            assert_eq!(program(&f, 0x1000).err(), Some(why));
        }
    }

    #[test]
    fn segments_and_headers_must_be_in_the_file() {
        let mut f = layout();
        // The data's four bytes at 0x3000 end the file; ask for five.
        put(&mut f, 64 + PHDR_SIZE * 2 + 32, &5u64.to_le_bytes());
        assert_eq!(
            program(&f, 0x1000).err().as_deref(),
            Some("the data segment's bytes run past the end of the file")
        );
        let mut f = layout();
        let len = f.len() as u64;
        put(&mut f, 32, &len.to_le_bytes());
        assert_eq!(
            program(&f, 0x1000).err().as_deref(),
            Some("the program headers run past the end of the file")
        );
    }
}
