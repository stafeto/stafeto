// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Checks on the disassembly of built ELF files: direct memory-helper
//! calls in the shipping kernel's hot paths, and the instruction pairs of
//! Cortex-A53 erratum 835769.

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
}
