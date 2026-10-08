// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Checks on the disassembly of built ELF files: direct memory-helper
//! calls in the shipping kernel's hot paths, the instruction pairs of
//! Cortex-A53 erratum 835769, and the instruction sequences of erratum
//! 843419.

use std::path::Path;
use std::process::Command;

fn memory_call(line: &str) -> bool {
    line.contains("\tbl\t") && (line.contains("<memcpy>") || line.contains("<memset>"))
}

fn check(text: &str) -> Result<(), String> {
    let mut symbol = String::new();
    let mut seen_dispatch = false;
    let mut seen_zeroed = false;
    let mut seen_deliver = false;
    let mut seen_deliver_boundary = false;
    let mut register_part = true;
    for line in text.lines() {
        if let Some((_, name)) = line.split_once(" <")
            && let Some(name) = name.strip_suffix(">:")
        {
            symbol = name.to_owned();
            register_part = true;
            seen_dispatch |= name == "kernel::syscall::dispatch";
            seen_zeroed |= name == "kernel::mm::phys::alloc_zeroed";
            seen_deliver |= name == "kernel::channel::message::deliver";
            continue;
        }
        // The register-only prefix ends at the length > 64 branch. The
        // remainder may copy the message buffer or handle records.
        if symbol == "kernel::channel::message::deliver"
            && line.contains("\tsubs\t")
            && line.contains("#0x40")
        {
            register_part = false;
            seen_deliver_boundary = true;
        }
        let guarded = symbol == "kernel::syscall::dispatch"
            || symbol == "kernel::syscall::dispatch_inner"
            || symbol == "kernel::syscall::set_result"
            || symbol == "kernel::mm::phys::alloc_zeroed"
            || symbol.contains("::alloc_table")
            || symbol == "kernel::mm::kmap::map"
            || (symbol.starts_with("kernel::mm::aspace::") && symbol != "kernel::mm::aspace::init")
            || (symbol == "kernel::channel::message::deliver" && register_part);
        if guarded && memory_call(line) {
            return Err(format!("{symbol} calls a memory helper: {line}"));
        }
    }
    if !seen_dispatch || !seen_zeroed || !seen_deliver || !seen_deliver_boundary {
        return Err("a hot-path symbol is missing from the shipping ELF".into());
    }
    Ok(())
}

pub fn shipping(elf: &Path, objdump: &Path) -> Result<(), String> {
    check(&disassemble(elf, objdump)?)?;
    println!("shipping hot paths call no memcpy or memset");
    Ok(())
}

fn disassemble(elf: &Path, objdump: &Path) -> Result<String, String> {
    let output = Command::new(objdump)
        .args(["--disassemble", "--demangle", "--no-show-raw-insn"])
        .arg(elf)
        .output()
        .map_err(|e| format!("{}: {e}", objdump.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} failed on {}: {}",
            objdump.display(),
            elf.display(),
            output.status
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| e.to_string())
}

/// The mnemonic and the operands of an instruction line of
/// `llvm-objdump --no-show-raw-insn` ("addr:  \tmnemonic\toperands").
fn instruction(line: &str) -> Option<(&str, &str)> {
    let (address, rest) = line.split_once('\t')?;
    if !address.trim_end().ends_with(':') {
        return None;
    }
    Some(rest.split_once('\t').unwrap_or((rest, "")))
}

/// A load, a store or a prefetch: the first instruction of an erratum
/// 835769 pair (LLVM AArch64A53Fix835769, `mayLoadOrStore` and PRFM).
fn memory_access(mnemonic: &str) -> bool {
    ["ld", "st", "prfm", "prfum", "cas", "swp"]
        .iter()
        .any(|p| mnemonic.starts_with(p))
}

/// A 64-bit integer multiply-accumulate: the second instruction of an
/// erratum 835769 pair. The plain multiplies (Ra = XZR) disassemble as
/// their aliases mul, mneg, smull, smnegl, umull and umnegl, which the
/// erratum spares.
fn multiply_accumulate(mnemonic: &str, operands: &str) -> bool {
    match mnemonic {
        "madd" | "msub" => operands.starts_with('x'),
        "smaddl" | "smsubl" | "umaddl" | "umsubl" => true,
        _ => false,
    }
}

/// The erratum 835769 pairs of the disassembly `text`: a memory access
/// followed at once by a 64-bit multiply-accumulate, which a Cortex-A53
/// (the PinePhone's A64) may compute wrongly. Each pair as "symbol: line".
fn pairs_835769(text: &str) -> Vec<String> {
    let mut symbol = "";
    let mut after_access = false;
    let mut pairs = Vec::new();
    for line in text.lines() {
        if let Some((_, name)) = line.split_once(" <")
            && let Some(name) = name.strip_suffix(">:")
        {
            symbol = name;
            continue;
        }
        let Some((mnemonic, operands)) = instruction(line) else {
            continue;
        };
        if after_access && multiply_accumulate(mnemonic, operands) {
            pairs.push(format!("{symbol}: {}", line.trim()));
        }
        after_access = memory_access(mnemonic);
    }
    pairs
}

/// Fails when `elf` holds an erratum 835769 pair: the builds pass
/// `+fix-cortex-a53-835769` (Rust) and `-mfix-cortex-a53-835769` (C), and
/// this catches a toolchain or a build that drops it. Every kernel build
/// and every program of a boot image goes through it, whichever command
/// made them.
pub fn erratum_835769(elf: &Path, objdump: &Path) -> Result<(), String> {
    let found = pairs_835769(&disassemble(elf, objdump)?);
    if !found.is_empty() {
        return Err(format!(
            "{}: {} erratum 835769 pairs (memory access, then a 64-bit multiply-accumulate):\n{}",
            elf.display(),
            found.len(),
            found.join("\n")
        ));
    }
    Ok(())
}

/// The loadable, executable segments of the ELF64 little-endian file
/// `bytes`: (virtual address, contents).
fn executable_segments(bytes: &[u8]) -> Result<Vec<(u64, &[u8])>, String> {
    let field = |at: usize, len: usize| -> Result<&[u8], String> {
        bytes
            .get(at..at + len)
            .ok_or_else(|| "a truncated ELF file".to_owned())
    };
    let u16_at = |at| field(at, 2).map(|b| u64::from(u16::from_le_bytes([b[0], b[1]])));
    let u32_at = |at| field(at, 4).map(|b| u64::from(u32::from_le_bytes(b.try_into().unwrap())));
    let u64_at = |at| field(at, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    if field(0, 5)? != b"\x7fELF\x02" {
        return Err("not an ELF64 file".into());
    }
    let (table, size, count) = (u64_at(0x20)?, u16_at(0x36)?, u16_at(0x38)?);
    let mut segments = Vec::new();
    for index in 0..count {
        let at = usize::try_from(table + index * size).map_err(|e| e.to_string())?;
        // PT_LOAD with PF_X.
        if u32_at(at)? != 1 || u32_at(at + 4)? & 1 == 0 {
            continue;
        }
        let (offset, address, length) = (u64_at(at + 8)?, u64_at(at + 16)?, u64_at(at + 32)?);
        let offset = usize::try_from(offset).map_err(|e| e.to_string())?;
        let length = usize::try_from(length).map_err(|e| e.to_string())?;
        segments.push((address, field(offset, length)?));
    }
    Ok(segments)
}

/// A load or store, literal loads excluded (A64 encoding group
/// `x1x0` of bits 28..25; the literal form has no base register).
fn load_store(word: u32) -> bool {
    word & 0x0a00_0000 == 0x0800_0000 && word & 0x3b00_0000 != 0x1800_0000
}

/// The addresses of the erratum 843419 sequences in `code`, which starts
/// at the address `base` of a 4 KiB page: an ADRP at offset 0xff8 or 0xffc
/// of a page, then a load or store, then a load or store whose base is
/// the register of the ADRP. A Cortex-A53 (the PinePhone's A64) may then
/// read the third instruction's address wrongly. Each is the address of
/// the ADRP.
fn sequences_843419(base: u64, code: &[u8]) -> Vec<u64> {
    let words: Vec<u32> = code
        .as_chunks::<4>()
        .0
        .iter()
        .map(|w| u32::from_le_bytes(*w))
        .collect();
    let mut found = Vec::new();
    for (index, &adrp) in words.iter().enumerate() {
        let address = base + 4 * index as u64;
        if address & 0xfff < 0xff8 || adrp & 0x9f00_0000 != 0x9000_0000 {
            continue;
        }
        let (Some(&second), Some(&third)) = (words.get(index + 1), words.get(index + 2)) else {
            continue;
        };
        let register = adrp & 0x1f;
        if register != 31
            && load_store(second)
            && load_store(third)
            && (third >> 5) & 0x1f == register
        {
            found.push(address);
        }
    }
    found
}

/// Fails when `elf` holds an erratum 843419 sequence in an executable
/// segment: the linker rewrites them (`--fix-cortex-a53-843419`, which the
/// kernel's rustflags pass and the hard-float program target passes by
/// default), and this catches a build that loses it. The segments are
/// loaded on 4 KiB pages, so the offset in the page is the offset of the
/// address. Every kernel build and every program of a boot image goes
/// through it, with the 835769 check.
pub fn erratum_843419(elf: &Path) -> Result<(), String> {
    let bytes = std::fs::read(elf).map_err(|e| format!("{}: {e}", elf.display()))?;
    let mut found = Vec::new();
    for (base, code) in
        executable_segments(&bytes).map_err(|e| format!("{}: {e}", elf.display()))?
    {
        found.extend(sequences_843419(base, code));
    }
    if !found.is_empty() {
        let list: Vec<_> = found.iter().map(|a| format!("{a:#x}")).collect();
        return Err(format!(
            "{}: {} erratum 843419 sequences (ADRP at the end of a page, two loads or stores): {}",
            elf.display(),
            found.len(),
            list.join(" ")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_an_access_followed_by_a_64_bit_multiply_accumulate() {
        let text = "0 <f>:\n4:      \tldr\tx1, [x0]\n8:      \tmadd\tx2, x3, x4, x5\n\
            c:      \tstp\tx1, x2, [sp]\n10:     \tumaddl\tx9, w11, w12, x9\n\
            14:     \tprfm\tpldl1keep, [x0]\n18:     \tmsub\tx1, x2, x3, x4\n";
        assert_eq!(pairs_835769(text).len(), 3);
        assert!(pairs_835769(text)[0].starts_with("f: 8:"));
    }

    #[test]
    fn spares_32_bit_plain_multiplies_and_separated_pairs() {
        let text = "0 <f>:\n4:      \tldr\tw1, [x0]\n8:      \tmadd\tw2, w3, w4, w5\n\
            c:      \tldr\tx1, [x0]\n10:     \tmul\tx2, x3, x4\n\
            14:     \tldr\tx1, [x0]\n18:     \tnop\n1c:     \tmadd\tx2, x3, x4, x5\n\
            20:     \tadd\tx1, x1, #1\n24:     \tsmaddl\tx2, w3, w4, x5\n";
        assert!(pairs_835769(text).is_empty());
    }

    #[test]
    fn catches_a_call_in_the_register_delivery_prefix() {
        let text = "1 <kernel::syscall::dispatch>:\n2 <kernel::mm::phys::alloc_zeroed>:\n3 <kernel::channel::message::deliver>:\n4:\tbl\t<memcpy>\n";
        assert!(check(text).is_err());
    }

    #[test]
    fn catches_a_call_in_the_inlined_result_path() {
        let text = "1 <kernel::syscall::dispatch>:\n2 <kernel::syscall::dispatch_inner>:\n3:\tbl\t<memset>\n";
        assert!(check(text).is_err());
    }

    /// The words as little-endian bytes.
    fn bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    const ADRP_X8: u32 = 0x9000_0008;
    const LDR_X1_X0: u32 = 0xf940_0001;
    const STR_X2_X8_8: u32 = 0xf900_0502;
    const LDR_LITERAL_X3: u32 = 0x5800_0103;
    const NOP: u32 = 0xd503_201f;

    #[test]
    fn finds_an_adrp_at_the_end_of_a_page_before_two_accesses() {
        // adrp x8 at 0xff8, ldr x1, [x0], str x2, [x8, #8].
        let code = bytes(&[ADRP_X8, LDR_X1_X0, STR_X2_X8_8]);
        assert_eq!(sequences_843419(0x4000_0ff8, &code), [0x4000_0ff8]);
        // The adrp at 0xffc, the two accesses on the next page.
        let code = bytes(&[NOP, ADRP_X8, LDR_X1_X0, STR_X2_X8_8]);
        assert_eq!(sequences_843419(0x4000_0ff8, &code), [0x4000_0ffc]);
    }

    #[test]
    fn spares_other_offsets_other_bases_and_other_instructions() {
        let at = |code: &[u32]| sequences_843419(0x4000_0ff8, &bytes(code));
        // The same words at 0xff4 and at 0x1000 are clean.
        assert!(
            sequences_843419(0x4000_0ff4, &bytes(&[ADRP_X8, LDR_X1_X0, STR_X2_X8_8])).is_empty()
        );
        assert!(
            sequences_843419(0x4000_1000, &bytes(&[ADRP_X8, LDR_X1_X0, STR_X2_X8_8])).is_empty()
        );
        // The third access has a base other than x8.
        assert!(at(&[ADRP_X8, LDR_X1_X0, 0xf900_0422]).is_empty());
        // A nop in place of the second or of the third instruction.
        assert!(at(&[ADRP_X8, NOP, STR_X2_X8_8]).is_empty());
        assert!(at(&[ADRP_X8, LDR_X1_X0, NOP]).is_empty());
        // A literal load has no base register (its offset field reads as x8).
        assert!(at(&[ADRP_X8, LDR_X1_X0, LDR_LITERAL_X3]).is_empty());
        // Too short for a third instruction.
        assert!(at(&[ADRP_X8, LDR_X1_X0]).is_empty());
    }

    #[test]
    fn reads_the_executable_segments_of_an_elf() {
        // One PT_LOAD with PF_X at 0x4000_0ff8 of three words.
        let mut elf = vec![0u8; 0x40 + 0x38];
        elf[..5].copy_from_slice(b"\x7fELF\x02");
        elf[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        elf[0x36..0x38].copy_from_slice(&0x38u16.to_le_bytes());
        elf[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        let header = 0x40;
        elf[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
        elf[header + 4..header + 8].copy_from_slice(&5u32.to_le_bytes());
        elf[header + 8..header + 16].copy_from_slice(&0x78u64.to_le_bytes());
        elf[header + 16..header + 24].copy_from_slice(&0x4000_0ff8u64.to_le_bytes());
        elf[header + 32..header + 40].copy_from_slice(&12u64.to_le_bytes());
        elf.extend(bytes(&[ADRP_X8, LDR_X1_X0, STR_X2_X8_8]));
        let segments = executable_segments(&elf).unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].0, 0x4000_0ff8);
        assert_eq!(
            sequences_843419(segments[0].0, segments[0].1),
            [0x4000_0ff8]
        );
        assert!(executable_segments(&elf[..0x50]).is_err());
    }
}
