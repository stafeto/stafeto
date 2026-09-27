// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Direct memory-helper calls in the shipping kernel's hot paths.

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
            seen_deliver |= name == "kernel::channel::deliver";
            continue;
        }
        // The register-only prefix ends at the length > 64 branch. The
        // remainder may copy the message buffer or handle records.
        if symbol == "kernel::channel::deliver"
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
            || (symbol == "kernel::channel::deliver" && register_part);
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
    let output = Command::new(objdump)
        .args(["--disassemble", "--demangle", "--no-show-raw-insn"])
        .arg(elf)
        .output()
        .map_err(|e| format!("{}: {e}", objdump.display()))?;
    if !output.status.success() {
        return Err(format!("{} failed: {}", objdump.display(), output.status));
    }
    check(&String::from_utf8(output.stdout).map_err(|e| e.to_string())?)?;
    println!("shipping hot paths call no memcpy or memset");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_a_call_in_the_register_delivery_prefix() {
        let text = "1 <kernel::syscall::dispatch>:\n2 <kernel::mm::phys::alloc_zeroed>:\n3 <kernel::channel::deliver>:\n4:\tbl\t<memcpy>\n";
        assert!(check(text).is_err());
    }

    #[test]
    fn catches_a_call_in_the_inlined_result_path() {
        let text = "1 <kernel::syscall::dispatch>:\n2 <kernel::syscall::dispatch_inner>:\n3:\tbl\t<memset>\n";
        assert!(check(text).is_err());
    }
}
