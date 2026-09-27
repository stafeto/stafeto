// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Resolve a kernel backtrace with the ELF used for that QEMU run.

use std::path::Path;
use std::process::Command;

fn frames(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let frame = words.next()?;
            let address = words.next()?;
            (frame.starts_with('#') && address.starts_with("0x")).then_some(address)
        })
        .collect()
}

/// The original addresses have already been printed by QEMU. A missing
/// symbolizer leaves them intact and gives one actionable diagnostic.
pub fn backtrace(lines: &[String], elf: &Path) {
    let addresses = frames(lines);
    if addresses.is_empty() {
        return;
    }
    let program = crate::llvm_tool("llvm-symbolizer").unwrap_or_else(|_| "llvm-symbolizer".into());
    for address in addresses {
        let result = Command::new(&program)
            .arg(format!("--obj={}", elf.display()))
            .args(["--functions", "--demangle", address])
            .output();
        match result {
            Ok(output) if output.status.success() => {
                let resolved = String::from_utf8_lossy(&output.stdout);
                let mut lines = resolved.lines().filter(|line| !line.is_empty());
                println!(
                    "  {address}  {} at {}",
                    lines.next().unwrap_or("??"),
                    lines.next().unwrap_or("??:0")
                );
            }
            Ok(output) => {
                eprintln!(
                    "llvm-symbolizer failed with {}; addresses remain above",
                    output.status
                );
                return;
            }
            Err(error) => {
                eprintln!(
                    "llvm-symbolizer unavailable ({error}); install LLVM to resolve the addresses above"
                );
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_backtrace_frames() {
        let lines = [
            "backtrace:",
            "  #0  0xffffffffc0001000",
            "ELR 0x1000",
            "  #1  0x10",
        ]
        .map(str::to_owned);
        assert_eq!(frames(&lines), ["0xffffffffc0001000", "0x10"]);
    }
}
