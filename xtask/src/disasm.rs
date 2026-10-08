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

/// ST1 (store of vector registers) in the groups of the structure
/// accesses, the opcodes of LLD's `isST1MultipleOpcode` and
/// `isST1SingleOpcode`; ST2 to ST4 are no part of the sequence.
fn st1(word: u32) -> bool {
    let (opcode, size, store) = ((word >> 12) & 0xf, (word >> 10) & 3, word & (1 << 22) == 0);
    if !store {
        return false;
    }
    if word & 0xbf20_0000 == 0x0c00_0000 {
        return matches!(opcode, 0b0111 | 0b1010 | 0b0110 | 0b0010);
    }
    if word & 0xbf20_0000 == 0x0d00_0000 {
        let (opcode, s) = (opcode >> 1, opcode & 1);
        return opcode == 0
            || (opcode == 2 && size & 1 == 0)
            || (opcode == 4 && (size == 0 || (size == 1 && s == 0)));
    }
    false
}

/// Whether `word` is a load or store that may stand second in an erratum
/// 843419 sequence (the classes of the LLD test `is843419ErratumSequence`):
/// a single register access of any addressing form, an exclusive access, a
/// literal load, STP or STNP, ST1.
fn second_access(word: u32) -> bool {
    let store = word & (1 << 22) == 0;
    word & 0x3a00_0000 == 0x3800_0000
        || word & 0x3f00_0000 == 0x0800_0000
        || word & 0x3b00_0000 == 0x1800_0000
        || (word & 0x3a00_0000 == 0x2800_0000 && store)
        || st1(word)
}

/// Whether the single register access `word` loads a general or vector
/// register (LLD's `isV8NonStructureLoad`: opc not 0, but the 128-bit
/// vector store and PRFM, whose opc is 2, are no loads; LDRSB, LDRSH and
/// LDRSW into X have a clear bit 22 and are loads).
fn single_load(word: u32) -> bool {
    let (size, vector, opc) = (word >> 30, word & (1 << 26) != 0, (word >> 22) & 3);
    opc != 0 && !(opc == 2 && ((size == 0 && vector) || (size == 3 && !vector)))
}

/// Whether the second instruction `word` of a sequence writes the
/// register `register`: a load into it, a status register of a store
/// exclusive, or a base register written back. A load of a vector
/// register of the same number does not count (LLD counts it, so the
/// check is stricter there: it finds a sequence that the linker leaves,
/// and the code has to change when it does).
fn writes_register(word: u32, register: u32) -> bool {
    let (rt, base) = (word & 0x1f, (word >> 5) & 0x1f);
    let load = word & (1 << 22) != 0;
    let vector = word & (1 << 26) != 0;
    if word & 0x3b00_0000 == 0x1800_0000 {
        // Literal: PRFM (opc 3) writes nothing.
        return !vector && word >> 30 != 3 && rt == register;
    }
    if word & 0x3f00_0000 == 0x0800_0000 {
        return if load {
            rt == register
        } else {
            (word >> 16) & 0x1f == register
        };
    }
    if word & 0x3a00_0000 == 0x3800_0000 {
        let written_back = word & (1 << 24) == 0 && word & (1 << 21) == 0 && (word >> 10) & 1 == 1;
        return (single_load(word) && !vector && rt == register)
            || (written_back && base == register);
    }
    if word & 0x3a00_0000 == 0x2800_0000 {
        let written_back = matches!((word >> 23) & 3, 1 | 3);
        return written_back && base == register;
    }
    // ST1: a post-indexed form writes its base back.
    word & 0xbe00_0000 == 0x0c00_0000 && word & (1 << 23) != 0 && base == register
}

/// A branch, a call or a return.
fn branch(word: u32) -> bool {
    word & 0x7c00_0000 == 0x1400_0000
        || word & 0xfe00_0000 == 0x5400_0000
        || word & 0x7e00_0000 == 0x3400_0000
        || word & 0x7e00_0000 == 0x3600_0000
        || word & 0xfe00_0000 == 0xd600_0000
}

/// The addresses of the erratum 843419 sequences in `code`, which starts
/// at the address `base` of a 4 KiB page: an ADRP at offset 0xff8 or 0xffc
/// of a page, then a load or store (second_access) that does not write the
/// register of the ADRP, then either directly or after one instruction
/// that is no branch a load or store of the unsigned immediate class with
/// that register as its base. A Cortex-A53 (the PinePhone's A64) may then
/// read the last instruction's address wrongly. Each is the address of
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
        let register = adrp & 0x1f;
        let Some(&second) = words.get(index + 1) else {
            continue;
        };
        if register == 31 || !second_access(second) || writes_register(second, register) {
            continue;
        }
        let last = |word: u32| word & 0x3b00_0000 == 0x3900_0000 && (word >> 5) & 0x1f == register;
        let three = words.get(index + 2).is_some_and(|&w| last(w));
        let four = words
            .get(index + 2)
            .is_some_and(|&w| !branch(w) && words.get(index + 3).is_some_and(|&w| last(w)));
        if three || four {
            found.push(address);
        }
    }
    found
}

/// Fails when `elf` holds an erratum 843419 sequence in an executable
/// segment: the linker rewrites them (`--fix-cortex-a53-843419`, which the
/// kernel's rustflags pass and the hard-float program target passes by
/// default), and this finds a sequence that the linker left, which a
/// build that loses the flag shows only when an ADRP lands at the end of
/// a page. Only the link line of the os-test programs is checked for the
/// flag itself (ostest.rs). The segments are
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
            "{}: {} erratum 843419 sequences (ADRP at the end of a page, then loads or stores): {}",
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
        // The last access has a base other than x8.
        assert!(at(&[ADRP_X8, LDR_X1_X0, 0xf900_0422]).is_empty());
        // A nop in place of the second or of the last instruction.
        assert!(at(&[ADRP_X8, NOP, STR_X2_X8_8]).is_empty());
        assert!(at(&[ADRP_X8, LDR_X1_X0, NOP]).is_empty());
        // A literal load as the last instruction has no base register
        // (its offset field reads as x8).
        assert!(at(&[ADRP_X8, LDR_X1_X0, LDR_LITERAL_X3]).is_empty());
        // Too short for a last instruction.
        assert!(at(&[ADRP_X8, LDR_X1_X0]).is_empty());
    }

    const ADD_X2: u32 = 0x9100_0442;
    const LDR_X8_X8: u32 = 0xf940_0108;
    const LDR_X0_X8: u32 = 0xf940_0100;
    const LDP_X2_X3_X8: u32 = 0xa940_0d02 & !0x3e0 | (8 << 5);
    const LDR_X1_X8_POST: u32 = 0xf840_8501 & !0x3e0 | (8 << 5);
    const CBZ: u32 = 0xb400_0040;
    const ADRP_X8_AGAIN: u32 = ADRP_X8;

    #[test]
    fn finds_the_form_of_four_instructions() {
        let at = |code: &[u32]| sequences_843419(0x4000_0ff8, &bytes(code));
        // One instruction that is no branch between the two accesses,
        // an adrp of the same register among them.
        assert_eq!(
            at(&[ADRP_X8, LDR_X1_X0, ADD_X2, STR_X2_X8_8]),
            [0x4000_0ff8]
        );
        assert_eq!(
            at(&[ADRP_X8, LDR_X1_X0, ADRP_X8_AGAIN, STR_X2_X8_8]),
            [0x4000_0ff8]
        );
        // A branch between them, or two instructions, is clean.
        assert!(at(&[ADRP_X8, LDR_X1_X0, CBZ, STR_X2_X8_8]).is_empty());
        assert!(at(&[ADRP_X8, LDR_X1_X0, ADD_X2, ADD_X2, STR_X2_X8_8]).is_empty());
    }

    #[test]
    fn finds_a_literal_load_in_the_second_place() {
        let code = bytes(&[ADRP_X8, LDR_LITERAL_X3, STR_X2_X8_8]);
        assert_eq!(sequences_843419(0x4000_0ff8, &code), [0x4000_0ff8]);
    }

    #[test]
    fn spares_a_second_instruction_that_writes_the_register() {
        let at = |code: &[u32]| sequences_843419(0x4000_0ff8, &bytes(code));
        // adrp x8; ldr x8, [x8]; ldr x0, [x8]: the pointer is loaded.
        assert!(at(&[ADRP_X8, LDR_X8_X8, LDR_X0_X8]).is_empty());
        // A post-indexed access that writes its base x8 back.
        assert!(at(&[ADRP_X8, LDR_X1_X8_POST, STR_X2_X8_8]).is_empty());
        // The same access to another base is a sequence.
        assert_eq!(at(&[ADRP_X8, LDR_X1_X0, STR_X2_X8_8]), [0x4000_0ff8]);
    }

    #[test]
    fn spares_a_signed_load_into_the_register_and_st2() {
        let at = |code: &[u32]| sequences_843419(0x4000_0ff8, &bytes(code));
        // adrp x8; ldrsw x8, [x8]; ldr x0, [x8]: the pointer is loaded.
        assert!(at(&[ADRP_X8, 0xb980_0108, LDR_X0_X8]).is_empty());
        // st1 {v0.16b}, [x0] is a sequence, st2 {v0.4s, v1.4s}, [x0] is not.
        assert_eq!(at(&[ADRP_X8, 0x4c00_7000, STR_X2_X8_8]), [0x4000_0ff8]);
        assert!(at(&[ADRP_X8, 0x4c00_8800, STR_X2_X8_8]).is_empty());
    }

    #[test]
    fn finds_a_vector_load_of_the_number_of_the_register() {
        // ldr d8, [x0] writes v8; LLD leaves it, this check refuses it.
        let code = bytes(&[ADRP_X8, 0xfd40_0008, STR_X2_X8_8]);
        assert_eq!(sequences_843419(0x4000_0ff8, &code), [0x4000_0ff8]);
    }

    #[test]
    fn spares_a_last_instruction_outside_the_unsigned_immediate_class() {
        let at = |code: &[u32]| sequences_843419(0x4000_0ff8, &bytes(code));
        // ldp x2, x3, [x8] is no unsigned immediate access.
        assert!(at(&[ADRP_X8, LDR_X1_X0, LDP_X2_X3_X8]).is_empty());
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
