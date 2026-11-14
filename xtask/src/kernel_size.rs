// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask kernel-size`: builds the shipping kernel and prints the bytes
//! of its `.text` per source file, the share of each, and how many of them
//! are code that runs once at boot. The size is a report; no build or ci step
//! fails on it.
//!
//! The method is the line table of the debug info. `llvm-objdump -d -l`
//! names the source line of every instruction and an instruction takes 4
//! bytes. With full LTO most code is inlined, so the symbol sizes
//! (`llvm-nm --size-sort`) would credit an inlined callee to its caller's
//! symbol (`kernel::syscall` gets the channel, memory and ITS code that was
//! inlined into the system call handlers). The line table credits the file
//! the instruction was written in. Instructions of the library (`core`,
//! `alloc`) that were inlined into a function are credited to the last file
//! of the workspace seen in that function; a function with no workspace
//! line at all (`fmt`, `memcpy`) is the row `library`. Assembly has no
//! line table and forms the row `assembly (no line info)`.
//!
//! The boot-only column counts the instructions of functions that run once
//! at boot (see `BOOT_ONLY`). It is a lower bound: boot code inlined into a
//! function that also runs later is not counted.

use crate::*;
use std::collections::BTreeMap;

/// Symbols (demangled, by prefix) of code that runs once while the kernel
/// starts: the boot parameters, the initialization of the memory, the
/// interrupt controller, the timer, the scheduler, the ITS and the other
/// CPUs, and the boot report.
const BOOT_ONLY: &[&str] = &[
    "kernel::boot::",
    "kernel::init::",
    "kernel::report",
    "kboot::bootinfo::",
    "kboot::fdt::",
    "bootimg::",
    "kernel::mm::kmap::switch_to_kernel_tables",
    "kernel::mm::phys::init",
    "kernel::mm::aspace::init",
    "kernel::smp::start",
    "kernel::sched::init",
    "karch::gic::init",
    "kernel::arch::gic::init",
    "kernel::arch::its::init",
    "karch::timer::init",
    "kernel::arch::cpu::init_boot",
    "karch::user::init",
];

const ASSEMBLY: &str = "assembly (no line info)";
const LIBRARY: &str = "library";
const EXTERNAL: &str = "external crates";

/// Bytes of one row.
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
pub struct Bytes {
    pub total: u64,
    pub boot: u64,
}

fn boot_only(symbol: &str) -> bool {
    BOOT_ONLY.iter().any(|p| symbol.starts_with(p))
}

/// The row of a source path: the path inside the workspace, or the library.
/// `None` for a path that is neither (a crate from the registry).
fn row_of(path: &str, root: &str) -> Option<String> {
    if let Some(rest) = path.strip_prefix(root) {
        return Some(rest.trim_start_matches('/').to_owned());
    }
    if path.contains("/library/") || path.starts_with("/rustc/") {
        return None;
    }
    Some(EXTERNAL.to_owned())
}

fn is_library(path: &str, root: &str) -> bool {
    !path.starts_with(root) && (path.contains("/library/") || path.starts_with("/rustc/"))
}

/// A marker line `; /path/file.rs:123` (the objdump line shows no column
/// when there is none). The function marker `; name():` is not one.
fn marker(line: &str) -> Option<&str> {
    let body = line.strip_prefix("; ")?;
    let (path, number) = body.rsplit_once(':')?;
    (path.starts_with('/') && !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
        .then_some(path)
}

/// `address <symbol>:` of a function label.
fn label(line: &str) -> Option<&str> {
    let (address, rest) = line.split_once(" <")?;
    if address.is_empty() || !address.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    rest.strip_suffix(">:")
}

/// An instruction line starts with its address and a colon.
fn instruction(line: &str) -> bool {
    line.split_once(':').is_some_and(|(address, rest)| {
        !address.is_empty()
            && address.bytes().all(|b| b.is_ascii_hexdigit())
            && rest.starts_with(|c: char| c.is_whitespace())
    })
}

/// The table of a disassembly made with `-d -l -C`: the bytes of each row.
pub fn parse(listing: &str, root: &str) -> BTreeMap<String, Bytes> {
    let mut rows: BTreeMap<String, Bytes> = BTreeMap::new();
    let mut boot = false;
    let mut row = ASSEMBLY.to_owned();
    let mut last_workspace: Option<String> = None;
    for line in listing.lines() {
        if let Some(symbol) = label(line) {
            boot = boot_only(symbol);
            row = ASSEMBLY.to_owned();
            last_workspace = None;
        } else if let Some(path) = marker(line) {
            row = if is_library(path, root) {
                last_workspace.clone().unwrap_or_else(|| LIBRARY.to_owned())
            } else {
                let name = row_of(path, root).unwrap_or_else(|| LIBRARY.to_owned());
                last_workspace = Some(name.clone());
                name
            };
        } else if instruction(line) {
            let entry = rows.entry(row.clone()).or_default();
            entry.total += 4;
            if boot {
                entry.boot += 4;
            }
        }
    }
    rows
}

/// The sizes of the sections `.text`, `.rodata`, `.data` from `llvm-size -A`.
pub fn sections(output: &str) -> BTreeMap<String, u64> {
    output
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let name = words.next()?;
            let size = words.next()?.parse().ok()?;
            matches!(name, ".text" | ".rodata" | ".data").then(|| (name.to_owned(), size))
        })
        .collect()
}

fn commas(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The report: rows by size, the unattributed part of `.text`, and the
/// total against the image.
pub fn render(
    rows: &BTreeMap<String, Bytes>,
    sections: &BTreeMap<String, u64>,
    image: Option<u64>,
) -> String {
    let text = sections.get(".text").copied().unwrap_or(0);
    let rodata = sections.get(".rodata").copied().unwrap_or(0);
    let data = sections.get(".data").copied().unwrap_or(0);
    let mut list: Vec<(&String, &Bytes)> = rows.iter().collect();
    list.sort_by(|a, b| b.1.total.cmp(&a.1.total).then(a.0.cmp(b.0)));
    let attributed: u64 = rows.values().map(|b| b.total).sum();
    let boot: u64 = rows.values().map(|b| b.boot).sum();
    let share = |n: u64| {
        if text == 0 {
            0.0
        } else {
            n as f64 * 100.0 / text as f64
        }
    };
    let width = list
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or(0)
        .max(24);
    let mut out = String::new();
    out.push_str(&format!(
        "{:<width$} {:>9} {:>7} {:>9}\n",
        "file", ".text", "share", "boot-only"
    ));
    for (name, b) in &list {
        out.push_str(&format!(
            "{:<width$} {:>9} {:>6.1}% {:>9}\n",
            name,
            commas(b.total),
            share(b.total),
            if b.boot == 0 {
                "-".to_owned()
            } else {
                commas(b.boot)
            }
        ));
    }
    let gap = text.saturating_sub(attributed);
    out.push_str(&format!(
        "{:<width$} {:>9} {:>6.1}% {:>9}\n",
        "(alignment and literal pools)",
        commas(gap),
        share(gap),
        "-"
    ));
    out.push_str(&format!(
        "{:<width$} {:>9} {:>6.1}% {:>9}\n",
        ".text total",
        commas(text),
        share(text),
        commas(boot)
    ));
    out.push('\n');
    out.push_str(&format!("{:<width$} {:>9}\n", ".rodata", commas(rodata)));
    out.push_str(&format!("{:<width$} {:>9}\n", ".data", commas(data)));
    if let Some(image) = image {
        let padding = image.saturating_sub(text + rodata + data);
        out.push_str(&format!(
            "{:<width$} {:>9}\n",
            "padding (4 KiB pages)",
            commas(padding)
        ));
        out.push_str(&format!("{:<width$} {:>9}\n", "image", commas(image)));
    }
    out
}

pub fn command(args: &[String]) -> Result<(), String> {
    if let Some(arg) = args.first() {
        return Err(format!("kernel-size takes no argument, got {arg:?}"));
    }
    let built = build(Variant::Normal)?;
    let image = std::fs::metadata(&built.image)
        .map_err(|e| format!("{}: {e}", built.image.display()))?
        .len();
    let listing = stdout_of(
        Command::new(llvm_tool("llvm-objdump")?)
            .args(["-d", "-l", "-C", "--no-show-raw-insn"])
            .arg(&built.elf),
    )?;
    let size = stdout_of(
        Command::new(llvm_tool("llvm-size")?)
            .arg("-A")
            .arg(&built.elf),
    )?;
    let root = root();
    let rows = parse(&listing, &root.display().to_string());
    if rows.is_empty() {
        return Err("the disassembly has no instructions".into());
    }
    print!("{}", render(&rows, &sections(&size), Some(image)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "\
Disassembly of section .text:

ffffffffc0000000 <_head>:
; __image_start():
ffffffffc0000000:      \tb\t0xffffffffc0000040 <primary_entry>
ffffffffc0000004:      \tnop

ffffffffc0001000 <kernel::syscall::dispatch>:
; kernel::syscall::dispatch():
; /w/kernel/src/syscall/mod.rs:10
ffffffffc0001000:      \tsub\tsp, sp, #0x50
ffffffffc0001004:      \tstp\tx29, x30, [sp]
; /rustc/abc/library/core/src/option.rs:5
ffffffffc0001008:      \tldr\tx0, [x1]
; /w/kcore/src/handles.rs:7
ffffffffc000100c:      \tret

ffffffffc0002000 <kernel::boot::collect>:
; kernel::boot::collect():
; /w/kernel/src/boot.rs:33
ffffffffc0002000:      \tnop
ffffffffc0002004:      \tnop

ffffffffc0003000 <core::fmt::write>:
; core::fmt::write():
; /rustc/abc/library/core/src/fmt/mod.rs:1
ffffffffc0003000:      \tnop
\t\t...
";

    #[test]
    fn rows_follow_the_line_table() {
        let rows = parse(LISTING, "/w");
        let get = |n: &str| rows.get(n).copied().unwrap_or_default();
        assert_eq!(
            get("kernel/src/syscall/mod.rs"),
            Bytes { total: 12, boot: 0 }
        );
        assert_eq!(get("kcore/src/handles.rs"), Bytes { total: 4, boot: 0 });
        assert_eq!(get("kernel/src/boot.rs"), Bytes { total: 8, boot: 8 });
        assert_eq!(get(ASSEMBLY), Bytes { total: 8, boot: 0 });
        assert_eq!(get(LIBRARY), Bytes { total: 4, boot: 0 });
        assert_eq!(rows.values().map(|b| b.total).sum::<u64>(), 36);
    }

    #[test]
    fn section_sizes_are_read() {
        let text = "k  :\nsection  size  addr\n.text  171500  1\n.rodata  20432  2\n.data  5  3\n.bss  9  4\nTotal 1\n";
        let s = sections(text);
        assert_eq!(s[".text"], 171500);
        assert_eq!(s[".rodata"], 20432);
        assert_eq!(s[".data"], 5);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn report_totals_and_gap() {
        let rows = parse(LISTING, "/w");
        let mut s = BTreeMap::new();
        s.insert(".text".to_owned(), 40);
        s.insert(".rodata".to_owned(), 8);
        s.insert(".data".to_owned(), 4);
        let out = render(&rows, &s, Some(8192));
        assert!(out.contains("kernel/src/syscall/mod.rs"));
        let gap = out
            .lines()
            .find(|l| l.starts_with("(alignment"))
            .expect("gap row");
        assert!(gap.split_whitespace().nth_back(2) == Some("4"), "{gap}");
        let image = out.lines().last().expect("last line");
        assert!(image.ends_with("8,192"), "{image}");
        assert_eq!(commas(1234567), "1,234,567");
    }
}
