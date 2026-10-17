// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Checks on the disassembly of built ELF files: direct memory-helper
//! calls in the shipping kernel's hot paths, the instruction pairs of
//! Cortex-A53 erratum 835769, and the instruction sequences of erratum
//! 843419. Also the places that read the virtual counter, which the
//! PinePhone's A64 needs a workaround at (`counter_read_sites`).

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

/// RAM's service loop leaves room for its nested request and formatter paths.
/// The permanent descriptor tables must stay outside this persistent frame.
pub fn ram_main_frame(elf: &Path, objdump: &Path) -> Result<(), String> {
    let frame = check_ram_main_frame(&disassemble(elf, objdump)?)?;
    println!("RAM persistent main frame: {frame} bytes (limit 8192)");
    Ok(())
}

fn immediate(text: &str) -> Result<usize, String> {
    let text = text.trim().strip_prefix('#').unwrap_or(text.trim());
    let (digits, base) = text
        .strip_prefix("0x")
        .map_or((text, 10), |digits| (digits, 16));
    usize::from_str_radix(digits, base).map_err(|_| format!("unknown RAM frame immediate: {text}"))
}

fn check_ram_main_frame(text: &str) -> Result<usize, String> {
    let (mut active, mut found, mut frame) = (false, false, 0);
    let mut probe = None;
    for line in text.lines() {
        if let Some((_, name)) = line.split_once(" <")
            && let Some(name) = name.strip_suffix(">:")
        {
            active = name == "__rt_main";
            found |= active;
            continue;
        }
        if !active {
            continue;
        }
        let Some((mnemonic, operands)) = instruction(line) else {
            continue;
        };
        let operands = operands
            .split_once("//")
            .map_or(operands, |(code, _)| code)
            .trim();
        let parts: Vec<_> = operands.split(',').map(str::trim).collect();
        if mnemonic == "sub" && parts.len() >= 3 && parts[1] == "sp" {
            let value = immediate(parts[2])?;
            let shift = match parts.get(3).copied() {
                None => 1,
                Some("lsl #12") => 4096,
                Some(other) => return Err(format!("unknown RAM frame shift: {other}")),
            };
            if parts[0] == "sp" {
                frame += value * shift;
            } else if parts[0].starts_with('x')
                && shift == 4096
                && (probe.replace(value).is_some() || value == 0)
            {
                return Err("unknown RAM main stack probe".into());
            }
        }
        if matches!(mnemonic, "stp" | "str")
            && let Some((_, suffix)) = operands.split_once("[sp, #-")
            && let Some((amount, _)) = suffix.split_once("]!")
        {
            frame += immediate(amount)?;
        }
        if matches!(mnemonic, "add" | "mov" | "and")
            && parts.first().copied() == Some("sp")
            && (mnemonic != "add" || parts.get(2).is_none_or(|part| !part.starts_with('#')))
        {
            return Err("dynamic RAM main stack adjustment".into());
        }
    }
    if !found {
        return Err("RAM main symbol missing".into());
    }
    if let Some(pages) = probe {
        frame += (pages - 1) * 4096;
    }
    if frame > 8192 {
        return Err(format!("RAM main frame {frame} exceeds 8192 bytes"));
    }
    Ok(frame)
}

/// The instruction lines of the function `symbol` in the disassembly
/// `text`; None when it is not there.
fn body<'a>(text: &'a str, symbol: &str) -> Option<Vec<&'a str>> {
    let mut lines = text.lines();
    let header = format!(" <{symbol}>:");
    lines.find(|l| l.ends_with(&header))?;
    Some(
        lines
            .take_while(|l| !l.is_empty())
            .filter(|l| instruction(l).is_some())
            .collect(),
    )
}

/// The position of the first instruction of `lines` whose mnemonic is
/// `mnemonic` and whose operands contain `operands`.
fn position(lines: &[&str], mnemonic: &str, operands: &str) -> Option<usize> {
    lines
        .iter()
        .position(|l| instruction(l).is_some_and(|(m, o)| m == mnemonic && o.contains(operands)))
}

/// The orders that starting a CPU and sending an SGI need, which no
/// QEMU machine can show (TCG has no cache and no weak order that
/// reaches the GIC model): the start block is cleaned to memory with
/// `dc cvac` and `dsb ish` before the PSCI call that starts the CPU, and
/// each SGI's register write follows its barrier (GICv2 `dmb ishst`
/// before GICD_SGIR; GICv3 `dsb ishst`, ICC_SGI1R_EL1, `isb`).
fn check_smp_order(text: &str) -> Result<(), String> {
    let need = |symbol: &str| {
        body(text, symbol).ok_or_else(|| format!("{symbol} is missing from the kernel"))
    };
    let clean = need("kernel::arch::aarch64::cache::clean_to_memory")?;
    let last_dc = clean
        .iter()
        .rposition(|l| instruction(l).is_some_and(|(m, o)| m == "dc" && o.starts_with("cvac")))
        .ok_or("clean_to_memory has no dc cvac")?;
    let dsb = clean
        .iter()
        .rposition(|l| instruction(l).is_some_and(|(m, o)| m == "dsb" && o == "ish"))
        .ok_or("clean_to_memory has no dsb ish")?;
    if dsb < last_dc {
        return Err("clean_to_memory: the dsb ish does not follow the dc cvac".into());
    }
    let start = need("kernel::smp::start_one")?;
    let cleaned = start
        .iter()
        .position(|l| l.contains("clean_to_memory"))
        .ok_or("start_one does not clean the start block with clean_to_memory")?;
    let call = start
        .iter()
        .position(|l| {
            instruction(l).is_some_and(|(m, o)| {
                m == "hvc" || m == "smc" || (m == "bl" && o.contains("psci::cpu_on"))
            })
        })
        .ok_or("start_one makes no PSCI call")?;
    if cleaned > call {
        return Err("start_one calls PSCI CPU_ON before it cleans the start block".into());
    }
    let v2 = need("kernel::arch::aarch64::gic::send_sgi_v2")?;
    let barrier = position(&v2, "dmb", "ishst").ok_or("send_sgi_v2 has no dmb ishst")?;
    let write = v2
        .iter()
        .position(|l| instruction(l).is_some_and(|(m, _)| m.starts_with("str")))
        .ok_or("send_sgi_v2 never writes GICD_SGIR")?;
    if barrier > write {
        return Err("send_sgi_v2 writes GICD_SGIR before its dmb ishst".into());
    }
    let v3 = need("kernel::arch::aarch64::gic::send_sgi_v3")?;
    let dsb = position(&v3, "dsb", "ishst").ok_or("send_sgi_v3 has no dsb ishst")?;
    let msr = v3
        .iter()
        .position(|l| {
            instruction(l).is_some_and(|(m, o)| {
                let o = o.to_ascii_lowercase();
                m == "msr" && (o.contains("icc_sgi1r_el1") || o.contains("s3_0_c12_c11_5"))
            })
        })
        .ok_or("send_sgi_v3 never writes ICC_SGI1R_EL1")?;
    let isb = v3
        .iter()
        .rposition(|l| instruction(l).is_some_and(|(m, _)| m == "isb"))
        .ok_or("send_sgi_v3 has no isb")?;
    if !(dsb < msr && msr < isb) {
        return Err("send_sgi_v3 does not run dsb ishst, the write, isb in that order".into());
    }
    Ok(())
}

/// `check_smp_order` on the kernel at `elf`.
pub fn smp_order(elf: &Path, objdump: &Path) -> Result<(), String> {
    check_smp_order(&disassemble(elf, objdump)?)?;
    println!("SMP start and SGI order: dc cvac before CPU_ON, barriers before the SGI registers");
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
    let text = disassemble(elf, objdump)?;
    if text.contains("OUTLINED_FUNCTION_") {
        return Err(format!(
            "{}: machine-outlined functions in native ELF",
            elf.display()
        ));
    }
    let found = pairs_835769(&text);
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

/// The number of lines of `text` that read the virtual counter
/// (`mrs <register>, cntvct_el0`, in Rust, C or assembly), comments left out.
fn counter_reads(text: &str) -> usize {
    text.lines()
        .filter(|line| {
            let line = line.trim_start().to_ascii_lowercase();
            !(line.starts_with("//") || line.starts_with('*') || line.starts_with("/*"))
                && line.contains("mrs")
                && line.contains("cntvct_el0")
        })
        .count()
}

/// The source files under `dir` with reads of the virtual counter, and the
/// number of reads in each, as paths relative to `root`.
fn counter_read_sites_in(
    root: &Path,
    dir: &Path,
    found: &mut Vec<(String, usize)>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            counter_read_sites_in(root, &path, found)?;
        } else if path
            .extension()
            .is_some_and(|ext| ["rs", "S", "c", "h"].iter().any(|e| ext == *e))
        {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let reads = counter_reads(&text);
            if reads > 0 {
                let relative = path.strip_prefix(root).unwrap_or(&path);
                found.push((relative.display().to_string(), reads));
            }
        }
    }
    Ok(())
}

/// Every source file of the repository with `mrs ..., cntvct_el0`, sorted,
/// with its number of reads. On the PinePhone's A64 a read of the counter
/// may return a wrong value (erratum Allwinner "unknown1", [G30]), and the
/// workaround has to stand at each place that reads it: one place in the
/// kernel (`timer::now`) and the user-space reads of `rt` and `posix-abi`.
/// A new place is a new place to patch, so it is listed by hand in
/// `COUNTER_READ_SITES` or the check fails.
pub fn counter_read_sites(root: &Path) -> Result<Vec<(String, usize)>, String> {
    let mut found = Vec::new();
    for top in [
        "kernel", "kcore", "lib", "services", "apps", "proto", "tests",
    ] {
        let dir = root.join(top);
        if dir.is_dir() {
            counter_read_sites_in(root, &dir, &mut found)?;
        }
    }
    found.sort();
    Ok(found)
}

/// The places allowed to read the counter, with the number of reads in each.
/// The shipping code: the kernel's `timer::now` and the three reads of
/// user space. The rest are tests and benchmarks that time themselves.
pub const COUNTER_READ_SITES: [(&str, usize); 8] = [
    ("kernel/src/arch/aarch64/timer.rs", 1),
    ("kernel/src/ktest.rs", 2),
    ("kernel/src/ktest/el0.S", 8),
    ("lib/posix-abi/src/signals.rs", 1),
    ("lib/rt/src/sys.rs", 1),
    ("lib/rt/src/time.rs", 1),
    ("tests/init/src/main.rs", 2),
    ("tests/rtbench-posix/rtbench.c", 2),
];

/// Fails when a source file outside `COUNTER_READ_SITES` reads the counter,
/// or one of them reads it a different number of times.
pub fn check_counter_read_sites(root: &Path) -> Result<(), String> {
    let found = counter_read_sites(root)?;
    let allowed: Vec<(String, usize)> = COUNTER_READ_SITES
        .iter()
        .map(|(path, n)| ((*path).to_owned(), *n))
        .collect();
    if found == allowed {
        return Ok(());
    }
    let describe = |sites: &[(String, usize)]| {
        sites
            .iter()
            .map(|(path, n)| format!("{path} ({n})"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    Err(format!(
        "reads of cntvct_el0 are at:\n  {}\nthe allowed places are:\n  {}\nA new read of the counter needs the A64 workaround; add the place to COUNTER_READ_SITES in xtask/src/disasm.rs with it",
        describe(&found),
        describe(&allowed)
    ))
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
    #[test]
    fn ram_main_frame_guard_counts_every_stack_probe_iteration() {
        let small = "0000000000200000 <__rt_main>:\n200000: \tstp\tx29, x30, [sp, #-0x10]!\n200004: \tsub\tsp, sp, #0x200\n";
        assert_eq!(super::check_ram_main_frame(small), Ok(528));
        let large = "0000000000200000 <__rt_main>:\n200000: \tsub\tx9, sp, #0x5, lsl #12\n200004: \tsub\tsp, sp, #0x1, lsl #12\n200008: \tstr\txzr, [sp]\n20000c: \tcmp\tsp, x9\n200010: \tb.ne\t0x200004 <__rt_main+0x4>\n200014: \tsub\tsp, sp, #0x880\n";
        assert_eq!(
            super::check_ram_main_frame(large),
            Err("RAM main frame 22656 exceeds 8192 bytes".into())
        );
        assert!(super::check_ram_main_frame("0000000000200000 <other>:\n").is_err());
        assert!(
            super::check_ram_main_frame(
                "0000000000200000 <__rt_main>:\n200000: \tsub\tsp, sp, x9\n"
            )
            .is_err()
        );
    }
    use super::*;

    /// A disassembly of the four functions `check_smp_order` reads, with
    /// the lines of `broken` replaced by the text given for them.
    fn smp_text(replace: &[(&str, &str)]) -> String {
        let mut text = String::from(
            "0 <kernel::arch::aarch64::cache::clean_to_memory>:\n\
             0: \tdc\tcvac, x8\n4: \tdsb\tish\n8: \tret\n\n\
             10 <kernel::smp::start_one>:\n\
             10: \tbl\t0x0 <kernel::arch::aarch64::cache::clean_to_memory>\n\
             14: \tsmc\t#0x0\n\n\
             20 <kernel::arch::aarch64::gic::send_sgi_v2>:\n\
             20: \tdmb\tishst\n24: \tstr\tw1, [x8, #0xf00]\n28: \tret\n\n\
             30 <kernel::arch::aarch64::gic::send_sgi_v3>:\n\
             30: \tdsb\tishst\n34: \tmsr\tICC_SGI1R_EL1, x8\n38: \tisb\n3c: \tret\n\n",
        );
        for (from, to) in replace {
            text = text.replace(from, to);
        }
        text
    }

    #[test]
    fn the_order_of_the_start_and_the_sgi_barriers_is_checked() {
        assert_eq!(check_smp_order(&smp_text(&[])), Ok(()));
        let broken = |replace: &[(&str, &str)]| check_smp_order(&smp_text(replace)).unwrap_err();
        // The clean of the start block gone, or after the PSCI call.
        assert!(
            broken(&[(
                "10: \tbl\t0x0 <kernel::arch::aarch64::cache::clean_to_memory>",
                "10: \tnop"
            )])
            .contains("does not clean the start block")
        );
        assert!(
            broken(&[(
                "10: \tbl\t0x0 <kernel::arch::aarch64::cache::clean_to_memory>\n14: \tsmc\t#0x0",
                "10: \tsmc\t#0x0\n14: \tbl\t0x0 <kernel::arch::aarch64::cache::clean_to_memory>"
            )])
            .contains("before it cleans")
        );
        // The clean without its dc cvac or its dsb.
        assert!(broken(&[("dc\tcvac, x8", "nop")]).contains("no dc cvac"));
        assert!(broken(&[("4: \tdsb\tish", "4: \tnop")]).contains("no dsb ish"));
        // A write before the barrier, or no barrier.
        assert!(broken(&[("dmb\tishst", "nop")]).contains("no dmb ishst"));
        assert!(
            broken(&[(
                "20: \tdmb\tishst\n24: \tstr\tw1, [x8, #0xf00]",
                "20: \tstr\tw1, [x8, #0xf00]\n24: \tdmb\tishst"
            )])
            .contains("before its dmb")
        );
        assert!(broken(&[("30: \tdsb\tishst", "30: \tnop")]).contains("no dsb ishst"));
        assert!(broken(&[("38: \tisb", "38: \tnop")]).contains("no isb"));
    }

    #[test]
    fn counts_the_reads_of_the_counter_and_not_comments() {
        let text = "// mrs x0, cntvct_el0\n    mrs     x0, CNTVCT_EL0\n\"isb\", \"mrs {}, cntvct_el0\"\n/// the CNTVCT_EL0 counter\n    mrs x1, cntfrq_el0\n";
        assert_eq!(super::counter_reads(text), 2);
    }

    #[test]
    fn the_reads_of_the_counter_are_at_the_listed_places() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        super::check_counter_read_sites(&root).unwrap();
    }

    #[test]
    fn a_read_of_the_counter_at_a_new_place_is_found() {
        let dir = std::env::temp_dir().join(format!("counter-sites-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("kernel/src")).unwrap();
        std::fs::write(
            dir.join("kernel/src/sched.rs"),
            "fn f() { asm!(\"mrs {}, cntvct_el0\") }\n",
        )
        .unwrap();
        let error = super::check_counter_read_sites(&dir).unwrap_err();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(error.contains("kernel/src/sched.rs (1)"), "{error}");
    }

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
