// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Inputs of the worst-case execution time analysis of the kernel
//! (docs/wcet.md): `wcet coverage`, the basic blocks of the kernel's entry
//! paths that no probe ever ran, and `wcet stack`, the deepest kernel stack
//! any entry path can need. Both read the disassembly of the kernel's ELF
//! file (`Image`): its functions, their basic blocks and the call graph.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{KERNEL_TARGET, cargo, jobs, llvm_tool, root, run_cmd, target_dir};

/// The entry paths of the kernel, by the symbol each one starts at: the
/// system calls, every entry from EL0 (which ends in the scheduler's
/// `resume` and so handles the interrupts), the exceptions of the kernel
/// itself and the vector table.
const ENTRIES: [(&str, &str); 4] = [
    ("system calls", "kernel::syscall::dispatch"),
    ("entries from EL0 and interrupts", "handle_user_exception"),
    ("exceptions at EL1", "handle_exception"),
    ("vector table", "exception_vectors"),
];

/// The probes of `wcet coverage` that the kernel group of `ci` does not
/// run already: the steps of the process service and the two that run
/// under `-icount` with a service.
const EXTRA_PROBES: [&str; 3] = ["process-steps", "entropy", "rtbench-short"];

// ---- the disassembly ----

struct Insn {
    addr: u64,
    mnemonic: String,
    operands: String,
    /// The address a direct branch or call goes to.
    target: Option<u64>,
}

struct Function {
    name: String,
    start: u64,
    /// One past the last instruction.
    end: u64,
    insns: Vec<Insn>,
}

/// How an instruction takes the flow of control.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Flow {
    Plain,
    /// `bl`: returns to the next instruction.
    Call,
    /// `blr`: a call through a register.
    IndirectCall,
    /// `b`.
    Jump,
    /// `b.cond`, `cbz`, `tbz` and the like: continues or jumps.
    Branch,
    /// `br`: a jump through a register (a table of a `match`, or a call
    /// that does not return).
    IndirectJump,
    /// `ret`, `eret`.
    Return,
}

impl Insn {
    fn flow(&self) -> Flow {
        let m = self.mnemonic.as_str();
        match m {
            "bl" => Flow::Call,
            "b" => Flow::Jump,
            "cbz" | "cbnz" | "tbz" | "tbnz" => Flow::Branch,
            "eret" | "ret" | "retaa" | "retab" | "eretaa" | "eretab" => Flow::Return,
            "blr" | "blraa" | "blraaz" | "blrab" | "blrabz" => Flow::IndirectCall,
            "br" | "braa" | "braaz" | "brab" | "brabz" => Flow::IndirectJump,
            _ if m.starts_with("b.") || m.starts_with("bc.") => Flow::Branch,
            _ => Flow::Plain,
        }
    }

    /// Whether the next instruction begins a block.
    fn ends_block(&self) -> bool {
        matches!(
            self.flow(),
            Flow::Jump | Flow::Branch | Flow::IndirectJump | Flow::Return
        )
    }
}

/// The callees of a function.
#[derive(Default)]
struct Callees {
    /// Indices of the functions that a call or a tail call names.
    direct: BTreeSet<usize>,
    /// The instructions that call or jump through a register: the callee
    /// is not known.
    indirect: Vec<(u64, String)>,
    /// A call whose target is in no function.
    stray: Vec<u64>,
}

struct Image {
    functions: Vec<Function>,
    /// By function: the addresses inside it that a jump of another
    /// function lands at, as a veneer of an erratum workaround does when
    /// it jumps back; each begins a block.
    landings: Vec<BTreeSet<u64>>,
}

fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16).ok()
}

/// The address of the direct branch in `operands`: the last operand that
/// starts with `0x` (the others are registers and `#` immediates).
fn branch_target(operands: &str) -> Option<u64> {
    operands
        .split(|c: char| c.is_whitespace() || c == ',')
        .rfind(|t| t.starts_with("0x"))
        .and_then(parse_hex)
}

impl Image {
    /// The functions of `llvm-objdump --disassemble --demangle
    /// --no-show-raw-insn`: a header `address <name>:` and the lines
    /// `address:  \tmnemonic\toperands`.
    fn parse(text: &str) -> Result<Image, String> {
        let mut functions: Vec<Function> = Vec::new();
        for line in text.lines() {
            if let Some((addr, rest)) = line.split_once(" <")
                && let Some(name) = rest.strip_suffix(">:")
                && let Some(start) = parse_hex(addr)
            {
                functions.push(Function {
                    name: name.to_owned(),
                    start,
                    end: start,
                    insns: Vec::new(),
                });
                continue;
            }
            let Some(function) = functions.last_mut() else {
                continue;
            };
            let Some((addr, rest)) = line.trim_start().split_once(':') else {
                continue;
            };
            let Some(addr) = parse_hex(addr) else {
                continue;
            };
            let rest = rest.trim_start();
            let (mnemonic, operands) = rest.split_once('\t').unwrap_or((rest, ""));
            let mnemonic = mnemonic.trim();
            if mnemonic.is_empty() {
                continue;
            }
            let mut insn = Insn {
                addr,
                mnemonic: mnemonic.to_owned(),
                operands: operands.trim().to_owned(),
                target: None,
            };
            if matches!(insn.flow(), Flow::Call | Flow::Jump | Flow::Branch) {
                insn.target = branch_target(operands);
            }
            function.end = addr + 4;
            function.insns.push(insn);
        }
        functions.retain(|f| !f.insns.is_empty());
        if functions.is_empty() {
            return Err("the disassembly has no function".to_owned());
        }
        functions.sort_by_key(|f| f.start);
        let mut image = Image {
            landings: vec![BTreeSet::new(); functions.len()],
            functions,
        };
        for (f, function) in image.functions.iter().enumerate() {
            for insn in &function.insns {
                let Some(t) = insn.target else { continue };
                if let Some(g) = image.containing(t)
                    && g != f
                    && insn.flow() != Flow::Call
                    && t != image.functions[g].start
                {
                    image.landings[g].insert(t);
                }
            }
        }
        Ok(image)
    }

    fn load(elf: &Path) -> Result<Image, String> {
        let out = Command::new(llvm_tool("llvm-objdump")?)
            .args(["--disassemble", "--demangle", "--no-show-raw-insn"])
            .arg(elf)
            .output()
            .map_err(|e| format!("llvm-objdump {}: {e}", elf.display()))?;
        if !out.status.success() {
            return Err(format!("llvm-objdump {} failed", elf.display()));
        }
        Image::parse(&String::from_utf8_lossy(&out.stdout))
    }

    fn by_name(&self, name: &str) -> Option<usize> {
        self.functions.iter().position(|f| f.name == name)
    }

    fn containing(&self, addr: u64) -> Option<usize> {
        let at = self.functions.partition_point(|f| f.start <= addr);
        let i = at.checked_sub(1)?;
        (addr < self.functions[i].end).then_some(i)
    }

    /// The addresses of the basic blocks of function `f`: its entry, the
    /// targets of its branches and the instruction after each instruction
    /// that ends a block.
    fn blocks(&self, f: usize) -> Vec<u64> {
        let function = &self.functions[f];
        let mut leaders = self.landings[f].clone();
        leaders.insert(function.start);
        for (i, insn) in function.insns.iter().enumerate() {
            if let Some(t) = insn.target
                && matches!(insn.flow(), Flow::Jump | Flow::Branch)
                && (function.start..function.end).contains(&t)
            {
                leaders.insert(t);
            }
            if insn.ends_block()
                && let Some(next) = function.insns.get(i + 1)
            {
                leaders.insert(next.addr);
            }
        }
        leaders.into_iter().collect()
    }

    fn callees(&self, f: usize) -> Callees {
        let function = &self.functions[f];
        let mut c = Callees::default();
        for insn in &function.insns {
            match insn.flow() {
                Flow::IndirectCall | Flow::IndirectJump => {
                    c.indirect.push((insn.addr, insn.mnemonic.clone()));
                }
                Flow::Call | Flow::Jump | Flow::Branch => {
                    let Some(t) = insn.target else { continue };
                    if insn.flow() != Flow::Call && (function.start..function.end).contains(&t) {
                        continue;
                    }
                    match self.containing(t) {
                        // A jump back into the middle of another function
                        // is no call.
                        Some(g) if insn.flow() != Flow::Call && t != self.functions[g].start => {}
                        Some(g) if g != f => {
                            c.direct.insert(g);
                        }
                        Some(_) => {}
                        None => c.stray.push(insn.addr),
                    }
                }
                _ => {}
            }
        }
        c
    }

    /// The functions that can run from `entry`, `entry` included.
    fn reachable(&self, entry: usize) -> BTreeSet<usize> {
        let mut seen = BTreeSet::from([entry]);
        let mut work = vec![entry];
        while let Some(f) = work.pop() {
            for g in self.callees(f).direct {
                if seen.insert(g) {
                    work.push(g);
                }
            }
        }
        seen
    }

    fn label(&self, f: usize) -> String {
        short(&self.functions[f].name)
    }
}

/// `name` at most 110 characters, cut in the middle.
fn short(name: &str) -> String {
    const LIMIT: usize = 110;
    if name.chars().count() <= LIMIT {
        return name.to_owned();
    }
    let head: String = name.chars().take(LIMIT / 2).collect();
    let tail: Vec<char> = name.chars().rev().take(LIMIT / 2 - 3).collect();
    format!("{head}...{}", tail.into_iter().rev().collect::<String>())
}

// ---- the traces of the probes ----

// Where the traces go while a probe runs: this thread's directory and the
// probe's name.
thread_local! {
    static TRACING: RefCell<Option<(PathBuf, String)>> = const { RefCell::new(None) };
}

static PLUGIN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

fn sanitize(label: &str) -> String {
    label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// The arguments that load the trace plugin into a QEMU of `accel` that
/// boots `kernel`, when a probe runs under `wcet coverage`; none otherwise.
pub fn plugin_args(accel: &str, kernel: &Path) -> Vec<String> {
    let Some(so) = PLUGIN.get() else {
        return Vec::new();
    };
    if accel != "tcg" {
        return Vec::new();
    }
    let Some((dir, label)) = TRACING.with(|t| t.borrow().clone()) else {
        return Vec::new();
    };
    let stem = kernel
        .file_stem()
        .map_or_else(|| "kernel".into(), |s| s.to_string_lossy().into_owned());
    let dir = dir.join(sanitize(&label));
    if std::fs::create_dir_all(&dir).is_err() {
        return Vec::new();
    }
    vec![
        "-plugin".to_owned(),
        format!("{},prefix={}", so.display(), dir.join(stem).display()),
    ]
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(program))
        .find(|p| p.is_file())
}

/// The directory that has QEMU's `qemu-plugin.h`: STAFETO_QEMU_INCLUDE,
/// or `include` next to the `bin` of the QEMU on PATH.
fn plugin_header_dir() -> Result<PathBuf, String> {
    if let Some(dir) = std::env::var_os("STAFETO_QEMU_INCLUDE") {
        return Ok(dir.into());
    }
    let qemu = find_in_path("qemu-system-aarch64").ok_or("qemu-system-aarch64 is not on PATH")?;
    let qemu = qemu.canonicalize().map_err(|e| e.to_string())?;
    let prefix = qemu.parent().and_then(Path::parent).ok_or("QEMU's path")?;
    let dir = prefix.join("include");
    if dir.join("qemu-plugin.h").is_file() {
        Ok(dir)
    } else {
        Err(format!(
            "{} has no qemu-plugin.h: build QEMU with --enable-plugins (the setup action of ci does), or set STAFETO_QEMU_INCLUDE",
            dir.display()
        ))
    }
}

/// Compiles tools/wcet/trace.c against QEMU's plugin header.
fn build_plugin() -> Result<PathBuf, String> {
    let dir = target_dir().join("wcet");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let so = dir.join("trace.so");
    let glib = crate::stdout_of(Command::new("pkg-config").args(["--cflags", "glib-2.0"]))
        .map_err(|e| format!("pkg-config glib-2.0 (QEMU's plugin header needs it): {e}"))?;
    let mut cc = Command::new("cc");
    cc.args(["-shared", "-fPIC", "-O2", "-Wall", "-Werror"]);
    if cfg!(target_os = "macos") {
        cc.args(["-undefined", "dynamic_lookup"]);
    }
    cc.args(glib.split_whitespace());
    cc.arg(format!("-I{}", plugin_header_dir()?.display()));
    cc.arg("-o").arg(&so);
    cc.arg(root().join("tools/wcet/trace.c"));
    run_cmd(&mut cc)?;
    Ok(so)
}

/// The traces of one run of a probe: the blocks that ran, each once.
fn read_trace(text: &str, covered: &mut HashSet<u64>) {
    for line in text.lines() {
        let Some((start, n)) = line.split_once(' ') else {
            continue;
        };
        let (Some(start), Ok(n)) = (parse_hex(start), n.trim().parse::<u64>()) else {
            continue;
        };
        covered.extend((0..n).map(|i| start + 4 * i));
    }
}

/// What the traces of a kernel hold: the addresses of the instructions
/// that ran and the probes that ran it.
type Traced = (HashSet<u64>, BTreeSet<String>);

/// The executed instruction addresses of every kernel under `dir`: the
/// traces of the probes not in `skip`, by the stem of the kernel's file,
/// and the number of probes that ran each kernel.
fn read_traces(dir: &Path, skip: &[String]) -> Result<BTreeMap<String, Traced>, String> {
    let mut kernels: BTreeMap<String, Traced> = BTreeMap::new();
    let skip: Vec<String> = skip.iter().map(|s| sanitize(s)).collect();
    let probes = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for probe in probes.flatten() {
        let label = probe.file_name().to_string_lossy().into_owned();
        if !probe.path().is_dir() || skip.contains(&label) {
            continue;
        }
        for file in std::fs::read_dir(probe.path())
            .map_err(|e| e.to_string())?
            .flatten()
        {
            let name = file.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".trace") else {
                continue;
            };
            // `<kernel stem>.<pid>`
            let kernel = stem.rsplit_once('.').map_or(stem, |(k, _)| k).to_owned();
            let text = std::fs::read_to_string(file.path())
                .map_err(|e| format!("{}: {e}", file.path().display()))?;
            let entry = kernels.entry(kernel).or_default();
            read_trace(&text, &mut entry.0);
            entry.1.insert(label.clone());
        }
    }
    Ok(kernels)
}

// ---- wcet coverage ----

struct Cover {
    name: String,
    blocks: usize,
    missed: Vec<u64>,
    start: u64,
}

fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        100.0
    } else {
        100.0 * part as f64 / whole as f64
    }
}

/// The blocks of the functions in `entry`'s reach that no trace ran.
fn cover(image: &Image, entry: usize, covered: &HashSet<u64>) -> Vec<Cover> {
    image
        .reachable(entry)
        .into_iter()
        .map(|f| {
            let blocks = image.blocks(f);
            Cover {
                name: image.functions[f].name.clone(),
                blocks: blocks.len(),
                missed: blocks
                    .into_iter()
                    .filter(|b| !covered.contains(b))
                    .collect(),
                start: image.functions[f].start,
            }
        })
        .collect()
}

/// The summary and the full list for one kernel.
fn coverage_report(
    kernel: &str,
    probes: &BTreeSet<String>,
    image: &Image,
    covered: &HashSet<u64>,
) -> (String, String) {
    let mut summary = String::new();
    let mut full = String::new();
    let _ = writeln!(
        summary,
        "kernel {kernel}: {} probes traced, {} instructions ran",
        probes.len(),
        covered.len()
    );
    let _ = writeln!(full, "kernel {kernel}\nprobes: {}", join(probes));
    for (what, symbol) in ENTRIES {
        let Some(entry) = image.by_name(symbol) else {
            let _ = writeln!(summary, "  {what} ({symbol}): not in this kernel");
            continue;
        };
        let mut rows = cover(image, entry, covered);
        let blocks: usize = rows.iter().map(|r| r.blocks).sum();
        let missed: usize = rows.iter().map(|r| r.missed.len()).sum();
        let _ = writeln!(
            summary,
            "  {what} ({symbol}): {} functions, {blocks} blocks, {missed} not run, {:.1} % covered",
            rows.len(),
            percent(blocks - missed, blocks)
        );
        rows.sort_by_key(|r| (std::cmp::Reverse(r.missed.len()), r.start));
        for r in rows.iter().filter(|r| !r.missed.is_empty()).take(8) {
            let _ = writeln!(
                summary,
                "      {:>4} of {:>4}  {}",
                r.missed.len(),
                r.blocks,
                short(&r.name)
            );
        }
        let _ = writeln!(
            full,
            "\n== {what} ({symbol}): {} functions, {blocks} blocks, {missed} not run",
            rows.len()
        );
        for r in rows.iter().filter(|r| !r.missed.is_empty()) {
            let _ = writeln!(
                full,
                "{}  {} of {} blocks not run",
                r.name,
                r.missed.len(),
                r.blocks
            );
            for b in &r.missed {
                let _ = writeln!(full, "    {b:#x}  +{:#x}", b - r.start);
            }
        }
    }
    (summary, full)
}

fn join(set: &BTreeSet<String>) -> String {
    set.iter().cloned().collect::<Vec<_>>().join(", ")
}

/// The probes of `wcet coverage`: the boots of the kernel group of `ci`,
/// with `EXTRA_PROBES`, less those in `skip`.
fn probes(skip: &[String], all: bool, traces: &Path) -> Vec<jobs::Job> {
    let mut wanted = crate::ci::kernel_boot_names();
    wanted.extend(EXTRA_PROBES.map(str::to_owned));
    let mut list = crate::boot_jobs(Vec::new());
    list.push(jobs::job("process-steps", || {
        crate::process_steps(&crate::qemu::VIRT_2G, 7)
    }));
    list.into_iter()
        .filter(|j| {
            (all || wanted.iter().any(|w| w == j.name())) && !skip.iter().any(|s| s == j.name())
        })
        .map(|job| {
            let (name, run) = job.into_parts();
            let dir = traces.to_owned();
            let label = name.clone();
            jobs::job(&name, move || {
                TRACING.with(|t| *t.borrow_mut() = Some((dir, label)));
                let result = run();
                TRACING.with(|t| *t.borrow_mut() = None);
                result
            })
        })
        .collect()
}

struct CoverageOptions {
    jobs: usize,
    skip: Vec<String>,
    from: Option<PathBuf>,
    all: bool,
    /// Where the traces and the report go, under the target directory.
    out: String,
}

fn parse_coverage(args: &[String]) -> Result<CoverageOptions, String> {
    let usage = "usage: cargo xtask wcet coverage [--jobs N] [--all] [--skip PROBE]... [--from TRACE-DIR] [--out DIR]";
    let mut o = CoverageOptions {
        jobs: jobs::default_jobs(),
        skip: Vec::new(),
        from: None,
        all: false,
        out: "wcet".to_owned(),
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if flag == "--all" {
            o.all = true;
            continue;
        }
        let value = it.next().ok_or(usage)?;
        match flag.as_str() {
            "--jobs" => {
                o.jobs = value
                    .parse()
                    .ok()
                    .filter(|&n| n >= 1)
                    .ok_or("--jobs expects a number from 1")?;
            }
            "--skip" => o.skip.push(value.clone()),
            "--from" => o.from = Some(value.into()),
            "--out" => o.out = value.clone(),
            _ => return Err(usage.to_owned()),
        }
    }
    Ok(o)
}

fn coverage(args: &[String]) -> Result<(), String> {
    let o = parse_coverage(args)?;
    let traces = match &o.from {
        Some(dir) => dir.clone(),
        None => {
            let traces = target_dir().join(&o.out).join("traces");
            if traces.exists() {
                std::fs::remove_dir_all(&traces).map_err(|e| e.to_string())?;
            }
            let so = build_plugin()?;
            let _ = PLUGIN.set(so);
            let list = probes(&o.skip, o.all, &traces);
            if list.is_empty() {
                return Err("no probe to run".to_owned());
            }
            // A failed probe leaves its trace and does not stop the others.
            let ran = jobs::run_all(list, o.jobs);
            if let Err(e) = &ran {
                println!("== a probe failed, its trace is kept: {e}");
            }
            traces
        }
    };
    report_coverage(&traces, &o.skip, &target_dir().join(&o.out))
}

fn report_coverage(traces: &Path, skip: &[String], out: &Path) -> Result<(), String> {
    let kernels = read_traces(traces, skip)?;
    if kernels.is_empty() {
        return Err(format!("no trace under {}", traces.display()));
    }
    let mut summary = String::new();
    let mut full = String::new();
    for (kernel, (covered, probes)) in &kernels {
        let elf = target_dir().join(format!("{kernel}.elf"));
        if !elf.is_file() {
            println!("no {}: the traces of {kernel} are not used", elf.display());
            continue;
        }
        let image = Image::load(&elf)?;
        let (s, f) = coverage_report(kernel, probes, &image, covered);
        summary += &s;
        full += &f;
        full.push('\n');
    }
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let file = out.join("coverage.txt");
    std::fs::write(&file, &full).map_err(|e| format!("{}: {e}", file.display()))?;
    print!("{summary}");
    println!(
        "the full list of blocks that no probe ran: {}",
        file.display()
    );
    Ok(())
}

/// A run of the first boot probe under the trace plugin: the plugin loads
/// into the QEMU of this machine and the kernel's entry shows in its
/// trace (a step of `ci`).
pub fn smoke() -> Result<(), String> {
    let so = build_plugin()?;
    let _ = PLUGIN.set(so);
    let dir = target_dir().join("wcet/smoke");
    let _ = std::fs::remove_dir_all(&dir);
    let job = crate::boot_jobs(Vec::new())
        .into_iter()
        .find(|j| j.name() == "boot 512M GICv2")
        .ok_or("no boot probe")?;
    let (_, run) = job.into_parts();
    TRACING.with(|t| *t.borrow_mut() = Some((dir.clone(), "smoke".to_owned())));
    let result = run();
    TRACING.with(|t| *t.borrow_mut() = None);
    result?;
    let kernels = read_traces(&dir, &[])?;
    let (covered, _) = kernels.get("stafeto").ok_or("the plugin wrote no trace")?;
    let image = Image::load(&target_dir().join("stafeto.elf"))?;
    let main = image.by_name("kernel_main").ok_or("no kernel_main")?;
    if !covered.contains(&image.functions[main].start) {
        return Err("kernel_main is not in the trace".to_owned());
    }
    println!(
        "trace plugin: {} instructions of the shipping kernel ran, kernel_main among them",
        covered.len()
    );
    Ok(())
}

// ---- wcet stack ----

/// The stack of one CPU, in bytes: every kernel stack has this size
/// (kcore::layout).
const STACK_SIZE: usize = kcore::layout::KERNEL_STACK_SIZE;

/// The kernel for the stack sums: the shipping build with
/// `-Z emit-stack-sizes`, in a target directory of its own so that no
/// image of a run changes. The flag is unstable; RUSTC_BOOTSTRAP lets the
/// pinned toolchain take it for this build only.
fn build_stack_elf() -> Result<PathBuf, String> {
    let target = target_dir().join("wcet-stack");
    let mut cmd = cargo();
    cmd.env("RUSTC_BOOTSTRAP", "1");
    cmd.args(["build", "--package", "kernel", "--release", "--target"]);
    cmd.arg(KERNEL_TARGET);
    cmd.arg("--target-dir").arg(&target);
    cmd.args([
        "--config",
        &format!("target.{KERNEL_TARGET}.rustflags=[\"-Z\", \"emit-stack-sizes\"]"),
    ]);
    run_cmd(&mut cmd)?;
    Ok(target.join(KERNEL_TARGET).join("release/kernel"))
}

fn uleb(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let (mut value, mut shift) = (0u64, 0);
    loop {
        let byte = *bytes.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
}

/// The entries of a `.stack_sizes` section: the address of a function and
/// its frame, in bytes.
fn parse_stack_sizes(bytes: &[u8]) -> Result<BTreeMap<u64, u64>, String> {
    let mut sizes = BTreeMap::new();
    let mut at = 0;
    while at < bytes.len() {
        let addr = bytes
            .get(at..at + 8)
            .ok_or("a cut entry in .stack_sizes")?
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| "a cut entry in .stack_sizes")?;
        at += 8;
        let size = uleb(bytes, &mut at).ok_or("a bad size in .stack_sizes")?;
        sizes.insert(addr, size);
    }
    Ok(sizes)
}

fn stack_sizes(elf: &Path) -> Result<BTreeMap<u64, u64>, String> {
    let dump = target_dir().join("wcet/stack_sizes.bin");
    let tmp = target_dir().join("wcet/stack_sizes.elf");
    run_cmd(
        Command::new(llvm_tool("llvm-objcopy")?)
            .arg(format!("--dump-section=.stack_sizes={}", dump.display()))
            .arg(elf)
            .arg(&tmp),
    )?;
    let bytes = std::fs::read(&dump).map_err(|e| format!("{}: {e}", dump.display()))?;
    parse_stack_sizes(&bytes)
}

/// The immediate `#N` that starts `text`, decimal or hexadecimal.
fn immediate(text: &str) -> Option<u64> {
    let digits = text.strip_prefix('#')?;
    let digits = digits
        .split(|c: char| c == ',' || c == ']' || c.is_whitespace())
        .next()?;
    match digits.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => digits.parse().ok(),
    }
}

/// The frame of an assembly function, which has no entry in
/// `.stack_sizes`: its largest `sub sp, sp, #N` and its largest push
/// `[sp, #-N]!` (a symbol may hold many entries, each with a frame of its own).
fn asm_frame(function: &Function) -> u64 {
    let mut largest = 0;
    let mut pushed = 0;
    for insn in &function.insns {
        if insn.mnemonic == "sub"
            && let Some(n) = insn.operands.strip_prefix("sp, sp, ").and_then(immediate)
        {
            largest = largest.max(n);
        }
        if let Some((_, rest)) = insn.operands.split_once("[sp, #-")
            && rest.ends_with("]!")
            && let Some(n) = immediate(&format!("#{rest}"))
        {
            pushed = pushed.max(n);
        }
    }
    largest + pushed
}

struct Frames {
    sizes: BTreeMap<u64, u64>,
}

impl Frames {
    fn of(&self, function: &Function) -> (u64, bool) {
        match self.sizes.get(&function.start) {
            Some(&size) => (size, false),
            None => (asm_frame(function), true),
        }
    }
}

/// The deepest path from a function: the sum of the frames and the
/// functions on it.
struct Deepest {
    depth: u64,
    path: Vec<usize>,
}

struct Walk<'a> {
    image: &'a Image,
    frames: &'a Frames,
    memo: BTreeMap<usize, Deepest>,
    on_path: Vec<usize>,
    recursion: BTreeSet<Vec<usize>>,
}

impl Walk<'_> {
    fn deepest(&mut self, f: usize) -> (u64, Vec<usize>) {
        if let Some(d) = self.memo.get(&f) {
            return (d.depth, d.path.clone());
        }
        self.on_path.push(f);
        let mut best = (0u64, Vec::new());
        for g in self.image.callees(f).direct {
            if let Some(at) = self.on_path.iter().position(|&p| p == g) {
                self.recursion.insert(self.on_path[at..].to_vec());
                continue;
            }
            let (depth, path) = self.deepest(g);
            if depth > best.0 {
                best = (depth, path);
            }
        }
        self.on_path.pop();
        let own = self.frames.of(&self.image.functions[f]).0;
        let mut path = vec![f];
        path.extend(best.1);
        let result = (own + best.0, path);
        self.memo.insert(
            f,
            Deepest {
                depth: result.0,
                path: result.1.clone(),
            },
        );
        result
    }
}

/// The starts of the paths whose stacks the CPU holds: the vector table
/// and the handlers that run on its frame, and the boot path that runs on
/// the boot stack.
const STACK_ENTRIES: [&str; 4] = [
    "exception_vectors",
    "handle_user_exception",
    "handle_exception",
    "kernel_main",
];

struct StackOptions {
    limit: usize,
    elf: Option<PathBuf>,
}

fn parse_stack(args: &[String]) -> Result<StackOptions, String> {
    let usage = "usage: cargo xtask wcet stack [--limit BYTES] [--elf FILE]";
    let mut o = StackOptions {
        limit: STACK_SIZE,
        elf: None,
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next().ok_or(usage)?;
        match flag.as_str() {
            "--limit" => o.limit = value.parse().map_err(|_| usage)?,
            "--elf" => o.elf = Some(value.into()),
            _ => return Err(usage.to_owned()),
        }
    }
    Ok(o)
}

fn path_text(image: &Image, frames: &Frames, path: &[usize]) -> String {
    let mut text = String::new();
    for &f in path {
        let (size, asm) = frames.of(&image.functions[f]);
        let _ = writeln!(
            text,
            "      {size:>6}  {}{}",
            image.label(f),
            if asm {
                "  (assembly: from its prologue)"
            } else {
                ""
            }
        );
    }
    text
}

fn stack(args: &[String]) -> Result<(), String> {
    let o = parse_stack(args)?;
    let dir = target_dir().join("wcet");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let elf = match o.elf {
        Some(elf) => elf,
        None => build_stack_elf()?,
    };
    let image = Image::load(&elf)?;
    let frames = Frames {
        sizes: stack_sizes(&elf)?,
    };
    let mut walk = Walk {
        image: &image,
        frames: &frames,
        memo: BTreeMap::new(),
        on_path: Vec::new(),
        recursion: BTreeSet::new(),
    };
    let mut report = String::new();
    let mut worst: Option<(u64, &str, Vec<usize>)> = None;
    let mut reached = BTreeSet::new();
    for symbol in STACK_ENTRIES {
        let entry = image
            .by_name(symbol)
            .ok_or_else(|| format!("{symbol} is not in {}", elf.display()))?;
        let (depth, path) = walk.deepest(entry);
        reached.extend(image.reachable(entry));
        let _ = writeln!(
            report,
            "{symbol}: deepest path {depth} bytes\n{}",
            path_text(&image, &frames, &path)
        );
        if worst.as_ref().is_none_or(|w| depth > w.0) {
            worst = Some((depth, symbol, path));
        }
    }
    let _ = writeln!(report, "recursion (the depth counts each function once):");
    for cycle in &walk.recursion {
        let names: Vec<String> = cycle.iter().map(|&f| image.label(f)).collect();
        let _ = writeln!(report, "  {}", names.join(" > "));
    }
    if walk.recursion.is_empty() {
        report.push_str("  none\n");
    }
    let _ = writeln!(
        report,
        "calls and jumps through a register, whose callee the graph does not know:"
    );
    let mut unknown = 0;
    for &f in &reached {
        let c = image.callees(f);
        for (addr, mnemonic) in &c.indirect {
            unknown += 1;
            let _ = writeln!(report, "  {addr:#x} {mnemonic}  in {}", image.label(f));
        }
        for addr in &c.stray {
            unknown += 1;
            let _ = writeln!(
                report,
                "  {addr:#x} a call to no function  in {}",
                image.label(f)
            );
        }
    }
    if unknown == 0 {
        report.push_str("  none\n");
    }
    let file = dir.join("stack.txt");
    std::fs::write(&file, &report).map_err(|e| format!("{}: {e}", file.display()))?;
    let (depth, symbol, path) = worst.ok_or("no entry")?;
    let depth = depth as usize;
    let needed = depth + depth / 10;
    println!(
        "deepest kernel stack: {depth} bytes from {symbol}; with 10 % room {needed} of {} bytes ({} functions reached, {} recursions, {unknown} calls through a register)",
        o.limit,
        reached.len(),
        walk.recursion.len(),
    );
    println!("full report: {}", file.display());
    if needed > o.limit {
        return Err(format!(
            "the kernel stack needs {needed} bytes with 10 % room, the stack has {}; the deepest path from {symbol}:\n{}",
            o.limit,
            path_text(&image, &frames, &path)
        ));
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<(), String> {
    match args {
        [cmd, rest @ ..] if cmd == "coverage" => coverage(rest),
        [cmd, rest @ ..] if cmd == "stack" => stack(rest),
        _ => Err("usage: cargo xtask wcet coverage|stack".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "\
ffffffffc0000000 <first>:
ffffffffc0000000:      \tcbz\tx0, 0xffffffffc000000c <first+0xc>
ffffffffc0000004:      \tbl\t0xffffffffc0000020 <second>
ffffffffc0000008:      \tb\t0xffffffffc0000030 <third>
ffffffffc000000c:      \tret
\t\t...
ffffffffc0000020 <second>:
ffffffffc0000020:      \tsub\tsp, sp, #0x40
ffffffffc0000024:      \tblr\tx8
ffffffffc0000028:      \ttbz\tw0, #0x3, 0xffffffffc0000020 <second>
ffffffffc000002c:      \tret
ffffffffc0000030 <third>:
ffffffffc0000030:      \tret
";

    #[test]
    fn blocks_split_at_branches_and_their_targets() {
        let image = Image::parse(LISTING).unwrap();
        assert_eq!(image.functions.len(), 3);
        assert_eq!(
            image.blocks(0),
            vec![0xffffffffc0000000, 0xffffffffc0000004, 0xffffffffc000000c]
        );
        assert_eq!(
            image.blocks(1),
            vec![0xffffffffc0000020, 0xffffffffc000002c]
        );
    }

    #[test]
    fn calls_and_tail_calls_are_edges_and_register_calls_are_unknown() {
        let image = Image::parse(LISTING).unwrap();
        assert_eq!(image.callees(0).direct, BTreeSet::from([1, 2]));
        let second = image.callees(1);
        assert!(second.direct.is_empty());
        assert_eq!(
            second.indirect,
            vec![(0xffffffffc0000024, "blr".to_owned())]
        );
        assert_eq!(image.reachable(0), BTreeSet::from([0, 1, 2]));
    }

    #[test]
    fn the_trace_of_a_run_covers_the_instructions_of_its_blocks() {
        let mut covered = HashSet::new();
        read_trace("ffffffffc0000000 1\nffffffffc000000c 1\n", &mut covered);
        assert!(covered.contains(&0xffffffffc000000c));
        assert!(!covered.contains(&0xffffffffc0000004));
        let image = Image::parse(LISTING).unwrap();
        let rows = cover(&image, 0, &covered);
        let first = rows.iter().find(|r| r.name == "first").unwrap();
        assert_eq!(first.missed, vec![0xffffffffc0000004]);
    }

    #[test]
    fn stack_sizes_are_address_and_uleb_pairs() {
        let mut bytes = Vec::new();
        bytes.extend(0xffffffffc0001000u64.to_le_bytes());
        bytes.push(0x10);
        bytes.extend(0xffffffffc0002000u64.to_le_bytes());
        bytes.extend([0x80, 0x02]);
        let sizes = parse_stack_sizes(&bytes).unwrap();
        assert_eq!(sizes[&0xffffffffc0001000], 16);
        assert_eq!(sizes[&0xffffffffc0002000], 256);
    }

    #[test]
    fn the_deepest_path_sums_the_frames() {
        let image = Image::parse(LISTING).unwrap();
        let frames = Frames {
            sizes: BTreeMap::from([
                (0xffffffffc0000000, 16),
                (0xffffffffc0000020, 64),
                (0xffffffffc0000030, 8),
            ]),
        };
        let mut walk = Walk {
            image: &image,
            frames: &frames,
            memo: BTreeMap::new(),
            on_path: Vec::new(),
            recursion: BTreeSet::new(),
        };
        assert_eq!(walk.deepest(0), (80, vec![0, 1]));
    }

    #[test]
    fn an_assembly_frame_is_its_largest_stack_subtraction() {
        let image = Image::parse(LISTING).unwrap();
        assert_eq!(asm_frame(&image.functions[1]), 0x40);
        assert_eq!(asm_frame(&image.functions[0]), 0);
    }
}
