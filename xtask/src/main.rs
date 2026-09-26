// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Build, run and test stafeto. Usage: `cargo xtask <command>`.

mod elf;
mod image;
mod qemu;

use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use std::time::Duration;

const KERNEL_TARGET: &str = "aarch64-unknown-none-softfloat";
/// Spec 14: programs, which run at EL0, are built for this target.
const PROGRAM_TARGET: &str = "aarch64-unknown-none";
/// The stack of init's first thread, in bytes, which init's program asks
/// the kernel for (lib/bootimg); the size is ours.
const INIT_STACK_SIZE: u32 = 64 * 1024;
/// Spec 3.4: the kernel image file stays under 200 KB: the build that
/// ships and the probes built from it.
const KERNEL_LIMIT: u64 = 200 * 1024;
/// The builds with the kernel tests carry the tests' programs, fixtures
/// and judges besides the kernel, and spec 3.4 does not bound them; a
/// limit of their own still catches a runaway growth.
const TEST_KERNEL_LIMIT: u64 = 512 * 1024;
const BOOT_TIMEOUT: Duration = Duration::from_secs(30);
const TEST_TIMEOUT: Duration = Duration::from_secs(60);
/// The overflow probe's recursive function, as `llvm-nm -C` names it.
const OVERFLOW_PROBE_FN: &str = "kernel::arch::aarch64::probe::recurse";
/// Lines the kernel tests write through `debug_write`, each whole: from
/// the kernel, all of x2-x9 (ktest::calls::LINE) and the bytes of a
/// length with other bytes past it (ktest::calls::STOPS), and from EL0
/// (ktest::el0::EL0_LINE).
const DEBUG_WRITE_LINES: [&str; 3] = [
    "kernel test: debug_write prints all 64 bytes of x2-x9 in order.",
    "debug_write stops at its length",
    "debug_write from EL0 reaches the console",
];
/// Tests only the `icount` build has: the first checks that the run is
/// under -icount; the next two depend on how much of a quantum is left,
/// which only -icount makes repeatable; the fourth takes a big process
/// apart in hundreds of portions with interrupts between them, where
/// virtual time counts instructions and a stall of the host changes
/// nothing; the last measures the round trip of a request, which only
/// -icount counts in instructions (spec 15.3).
const ICOUNT_TESTS: [&str; 5] = [
    "virtual_time_counts_instructions",
    "lone_round_robin_thread_is_not_switched",
    "preempted_rr_thread_resumes_before_its_peer",
    "teardown_yields_to_a_pending_interrupt",
    "ipc_round_trip_is_measured",
];
/// The rows of the line of `ipc_round_trip_is_measured`, in its order
/// (spec 15.3).
const ROUND_TRIP_ROWS: [&str; 6] = ["null", "switch", "fast", "slow", "buffer", "handles"];
/// What init prints on the normal build (services/init), each line whole;
/// the order of the threads' lines depends on the timer and is not
/// checked.
const INIT_LINES: [&str; 9] = [
    "init: hello from EL0",
    "init: threads 1 and 2 take turns at priority 10, round robin",
    "thread 1: turn 1",
    "thread 2: turn 1",
    "thread 1: turn 2",
    "thread 2: turn 2",
    "thread 1: turn 3",
    "thread 2: turn 3",
    "init: both threads are done",
];
/// The kernel's last line when init exits with 0 (spec 7.9).
const INIT_EXIT: &str = "init exited with code 0";
/// Lines of a run of the test init (tests/init) besides its TEST lines,
/// each whole: a formatted line longer than one debug_write, the bytes of
/// a debug_write's length and no more, and the kernel's line for the
/// fault of a child (spec 7.9, 15.2).
const TEST_INIT_LINES: [&str; 3] = [
    "init prints from EL0 in pieces of at most 64 bytes: this line takes 2 of them",
    "debug_write stops at its length",
    "process fault: instruction abort from EL0 (EC 0x20) ESR=0x82000007 FAR=0x1000 ELR=0x1000",
];
/// Where xtask's own programs (`raw_init`) start: lld's first address.
const RAW_INIT_ENTRY: u64 = 0x20_0000;
/// `ldr x0, [x0]`: init starts with x0 = 0, so this loads from page 0,
/// which nothing maps.
const LDR_X0_X0: u32 = 0xF940_0000;
/// `adr x1, .+0x1000`: x1 = the page after the code, raw_init's
/// read-only page.
const ADR_X1_NEXT_PAGE: u32 = 0x1000_8001;
/// `str x0, [x1]`.
const STR_X0_X1: u32 = 0xF900_0020;
/// `b .+0x1000`: a branch to the page after the code.
const B_NEXT_PAGE: u32 = 0x1400_0400;
/// init kills its own process: x0 = abi::INIT_PROCESS, then process_kill,
/// which does not return; if it did, the load through x0 would fault.
const KILL_ITSELF: [u32; 4] = [
    movz_x0(abi::INIT_PROCESS.0 as u16),
    movk_x0_lsl16((abi::INIT_PROCESS.0 >> 16) as u16),
    svc(abi::Call::ProcessKill.number()),
    LDR_X0_X0,
];
const _: () = assert!(
    abi::INIT_PROCESS.0 >> 32 == 0,
    "INIT_PROCESS takes two moves"
);
/// Tests the test init has (tests/init): its own count in `TESTS DONE`
/// could drop a test with the line.
const INIT_TESTS: u32 = 106;
/// A data segment bigger than the 4 MiB one block of frames holds.
const BIG_DATA: u64 = 8 << 20;

/// Kernel builds xtask makes; each keeps its own ELF and image under target/.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    Normal,
    Test,
    /// The kernel tests with those that need QEMU's `-icount` (qemu::ICOUNT).
    TestIcount,
    FaultProbe,
    OverflowProbe,
}

impl Variant {
    const ALL: [Variant; 5] = [
        Variant::Normal,
        Variant::Test,
        Variant::TestIcount,
        Variant::FaultProbe,
        Variant::OverflowProbe,
    ];

    fn feature(self) -> Option<&'static str> {
        match self {
            Variant::Normal => None,
            Variant::Test => Some("ktest"),
            Variant::TestIcount => Some("icount"),
            Variant::FaultProbe => Some("fault-probe"),
            Variant::OverflowProbe => Some("overflow-probe"),
        }
    }

    /// The limit of its image file, and where the limit comes from.
    fn limit(self) -> (u64, &'static str) {
        match self {
            Variant::Normal | Variant::FaultProbe | Variant::OverflowProbe => {
                (KERNEL_LIMIT, "spec 3.4")
            }
            Variant::Test | Variant::TestIcount => (TEST_KERNEL_LIMIT, "test builds"),
        }
    }

    fn stem(self) -> &'static str {
        match self {
            Variant::Normal => "stafeto",
            Variant::Test => "stafeto-ktest",
            Variant::TestIcount => "stafeto-ktest-icount",
            Variant::FaultProbe => "stafeto-probe",
            Variant::OverflowProbe => "stafeto-overflow",
        }
    }
}

const USAGE: &str = "usage: cargo xtask <command>

commands:
  build     build the kernel image and the boot image
  run       build and boot in QEMU (Ctrl-A X quits)
  test      host tests, then boot checks, init tests and kernel tests in QEMU
  gdb       boot in QEMU halted at the first instruction, debugger on :1234
  ci        formatting, clippy, then everything `test` does
  help      this text";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("build") => build(Variant::Normal).map(|_| ()),
        Some("run") => run(),
        Some("test") => test(),
        Some("gdb") => gdb(),
        Some("ci") => ci(),
        Some("help") | None => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    };
    if let Err(e) = result {
        eprintln!("xtask: {e}");
        exit(1);
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in the workspace")
        .to_path_buf()
}

fn cargo() -> Command {
    let mut c = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(root());
    c
}

fn run_cmd(cmd: &mut Command) -> Result<(), String> {
    let status = cmd.status().map_err(|e| format!("{cmd:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?} failed: {status}"))
    }
}

fn stdout_of(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("{cmd:?}: {e}"))?;
    String::from_utf8(out.stdout).map_err(|e| e.to_string())
}

/// Path of an LLVM tool from the `llvm-tools` rustup component.
fn llvm_tool(name: &str) -> Result<PathBuf, String> {
    let sysroot = stdout_of(
        Command::new("rustc")
            .current_dir(root())
            .args(["--print", "sysroot"]),
    )?;
    let version = stdout_of(Command::new("rustc").current_dir(root()).arg("-vV"))?;
    let host = version
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .ok_or("`rustc -vV` has no host line")?;
    let path = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin")
        .join(name);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!(
            "{} not found: run `rustup component add llvm-tools`",
            path.display()
        ))
    }
}

struct Artifacts {
    elf: PathBuf,
    image: PathBuf,
    boot_image: PathBuf,
}

fn build(variant: Variant) -> Result<Artifacts, String> {
    let mut cmd = cargo();
    cmd.args([
        "build",
        "--package",
        "kernel",
        "--release",
        "--target",
        KERNEL_TARGET,
    ]);
    if let Some(feature) = variant.feature() {
        cmd.args(["--features", feature]);
    }
    run_cmd(&mut cmd)?;
    let target = root().join("target");
    // Every variant writes the same cargo output path; a copy next to each image
    // keeps the symbols that match it.
    let elf = target.join(format!("{}.elf", variant.stem()));
    let image = target.join(format!("{}.img", variant.stem()));
    let built = target.join(KERNEL_TARGET).join("release").join("kernel");
    std::fs::copy(&built, &elf)
        .map_err(|e| format!("{} -> {}: {e}", built.display(), elf.display()))?;
    run_cmd(
        Command::new(llvm_tool("llvm-objcopy")?)
            .args(["-O", "binary"])
            .arg(&elf)
            .arg(&image),
    )?;
    let bytes = std::fs::read(&image).map_err(|e| format!("{}: {e}", image.display()))?;
    image::check_header(&bytes)?;
    let (limit, source) = variant.limit();
    image::check_size(bytes.len() as u64, limit)?;
    let boot_image = build_boot_image("init", "boot.img")?;
    println!(
        "kernel image {} ({} bytes, limit {limit} of {source})",
        image.display(),
        bytes.len()
    );
    Ok(Artifacts {
        elf,
        image,
        boot_image,
    })
}

/// Builds program `package` for EL0 and, under target/, a boot image
/// `name` whose only file is that program as init (spec 3.3, 13.1).
fn build_boot_image(package: &str, name: &str) -> Result<PathBuf, String> {
    run_cmd(cargo().args([
        "build",
        "--package",
        package,
        "--release",
        "--target",
        PROGRAM_TARGET,
    ]))?;
    let target = root().join("target");
    let elf = target.join(PROGRAM_TARGET).join("release").join(package);
    let why = |e: String| format!("{}: {e}", elf.display());
    let bytes = std::fs::read(&elf).map_err(|e| why(e.to_string()))?;
    let program = elf::program(&bytes, INIT_STACK_SIZE).map_err(why)?;
    let init = bootimg::write::program(&program).map_err(|e| why(e.to_string()))?;
    let image = bootimg::write::image(&[("init", &init)]).map_err(|e| why(e.to_string()))?;
    let path = target.join(name);
    std::fs::write(&path, &image).map_err(|e| format!("{}: {e}", path.display()))?;
    println!(
        "boot image {} ({} bytes): init from {}",
        path.display(),
        image.len(),
        elf.display()
    );
    Ok(path)
}

/// Init's entry point in the boot image at `path`, read as the kernel
/// reads it.
fn init_entry(path: &Path) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let init = bootimg::BootImage::parse(&bytes)
        .and_then(bootimg::BootImage::init)
        .and_then(bootimg::Program::parse)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(init.entry)
}

/// `movz x0, #imm`.
const fn movz_x0(imm: u16) -> u32 {
    0xD280_0000 | (imm as u32) << 5
}

/// `movk x0, #imm, lsl #16`.
const fn movk_x0_lsl16(imm: u16) -> u32 {
    0xF2A0_0000 | (imm as u32) << 5
}

/// `svc #n`.
const fn svc(n: u16) -> u32 {
    0xD400_0001 | (n as u32) << 5
}

/// A boot image whose init xtask writes itself, with no ELF: `code` at
/// RAW_INIT_ENTRY, which is its entry; with `rodata`, a read-only page of
/// zeros on the next page; unless `data_size` is 0, a data segment of
/// that many zero bytes on the page after those.
fn raw_init(code: &[u32], rodata: bool, data_size: u64) -> Result<Vec<u8>, String> {
    let code: Vec<u8> = code.iter().flat_map(|i| i.to_le_bytes()).collect();
    let read_only = if rodata {
        bootimg::Segment {
            vaddr: RAW_INIT_ENTRY + bootimg::PAGE_SIZE,
            mem_size: bootimg::PAGE_SIZE,
            bytes: &[],
        }
    } else {
        bootimg::Segment::EMPTY
    };
    let data = match data_size {
        0 => bootimg::Segment::EMPTY,
        size => bootimg::Segment {
            vaddr: RAW_INIT_ENTRY + bootimg::PAGE_SIZE * (1 + u64::from(rodata)),
            mem_size: size,
            bytes: &[],
        },
    };
    let program = bootimg::Program {
        entry: RAW_INIT_ENTRY,
        stack_size: INIT_STACK_SIZE,
        segments: [
            bootimg::Segment {
                vaddr: RAW_INIT_ENTRY,
                mem_size: bootimg::PAGE_SIZE,
                bytes: &code,
            },
            read_only,
            data,
        ],
    };
    let init = bootimg::write::program(&program).map_err(|e| e.to_string())?;
    bootimg::write::image(&[("init", &init)]).map_err(|e| e.to_string())
}

fn run() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    run_cmd(qemu::command(&qemu::VIRT, &a.image, Some(&a.boot_image)).arg("-nographic"))
}

fn test() -> Result<(), String> {
    host_tests()?;
    boot_smoke()?;
    el2_boot_smoke()?;
    two_gib_boot()?;
    elf_boot_reports_missing_device_tree()?;
    bad_boot_images_stop_the_boot()?;
    init_fault_stops_the_machine()?;
    fault_report()?;
    stack_overflow_report()?;
    test_build_carries_test_symbols()?;
    init_tests(&qemu::VIRT, false)?;
    init_tests(&qemu::VIRT_2G, false)?;
    init_tests(&qemu::VIRT, true)?;
    init_tests(&qemu::VIRT_2G, true)?;
    kernel_tests(&qemu::VIRT, Variant::Test)?;
    kernel_tests(&qemu::VIRT_2G, Variant::Test)?;
    kernel_tests(&qemu::VIRT, Variant::TestIcount)?;
    kernel_tests(&qemu::VIRT_2G, Variant::TestIcount)?;
    println!("all checks passed");
    Ok(())
}

fn host_tests() -> Result<(), String> {
    run_cmd(cargo().args([
        "test",
        "--package",
        "abi",
        "--package",
        "bootimg",
        "--package",
        "kcore",
        "--package",
        "xtask",
    ]))
}

/// Init on the normal build prints its lines and exits, and the kernel
/// turns the machine off (spec 7.9).
fn expect_init_run(o: &qemu::Outcome) -> Result<(), String> {
    for line in INIT_LINES {
        qemu::expect_line(o, line)?;
    }
    qemu::expect_clean_exit_with(o, INIT_EXIT)
}

/// A normal build boots, prints its report with the timer frequency and
/// init's entry point from the boot image, starts init, and powers the
/// machine off when init exits. The image also carries none of the
/// kernel's own tests (spec 3.4): `no_test_symbols` checks it here so
/// every normal build, not just the one that ships, is covered.
fn boot_smoke() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    no_test_symbols(&a.elf)?;
    let mut cmd = qemu::command(&qemu::VIRT, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let o = qemu::run_until(cmd, BOOT_TIMEOUT, None)?;
    qemu::expect_clean_exit_with(&o, "boot complete")?;
    expect_init_run(&o)?;
    let entry = init_entry(&a.boot_image)?;
    qemu::expect_marker(&o, &format!("init       entry {entry:#x},"))?;
    match qemu::number_after(&o.lines, "timer ") {
        Some(hz) if hz > 0 => Ok(()),
        _ => Err("the kernel printed no `timer N Hz` line".into()),
    }
}

/// The same build entered at EL2, as the PinePhone's loader does: head.S
/// must drop to EL1, and power-off goes through SMC. Not the ktest build: its
/// device tree test expects HVC.
fn el2_boot_smoke() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let mut cmd = qemu::command(&qemu::VIRT_EL2, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let o = qemu::run_until(cmd, BOOT_TIMEOUT, None)?;
    qemu::expect_clean_exit_with(&o, "boot complete")?;
    expect_init_run(&o)
}

/// With 2 GiB of RAM the second GiB is not mapped at boot: the allocator
/// must receive it after the kernel page tables map all RAM.
fn two_gib_boot() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let mut cmd = qemu::command(&qemu::VIRT_2G, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let o = qemu::run_until(cmd, BOOT_TIMEOUT, None)?;
    qemu::expect_clean_exit_with(&o, "boot complete")?;
    expect_init_run(&o)?;
    let free =
        qemu::number_after(&o.lines, "frames ").ok_or("the kernel printed no frames line")?;
    if free < 1900 {
        return Err(format!("only {free} MiB of frames free with 2 GiB of RAM"));
    }
    Ok(())
}

/// Booting the ELF leaves x0 = 0; the kernel must say why it stops.
fn elf_boot_reports_missing_device_tree() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let mut cmd = qemu::command(&qemu::VIRT, &a.elf, None);
    cmd.args(qemu::HEADLESS);
    let o = qemu::run_until(cmd, BOOT_TIMEOUT, Some("no device tree in x0"))?;
    qemu::expect_marker(&o, "no device tree in x0")?;
    if !o.stopped_on_marker {
        return Err("QEMU was not stopped on the marker line".into());
    }
    Ok(())
}

/// A boot image that is missing, cut short or damaged stops the boot with
/// a panic that says what is wrong (spec 3.3, 13.1). The cases: no boot
/// image; the image without its last byte; the image's signature spoiled;
/// init's signature spoiled; an init whose data segment is bigger than
/// one block of frames, which the kernel cannot load.
fn bad_boot_images_stop_the_boot() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let good =
        std::fs::read(&a.boot_image).map_err(|e| format!("{}: {e}", a.boot_image.display()))?;
    let init_at = bootimg::BootImage::parse(&good)
        .map_err(|e| e.to_string())?
        .files()
        .next()
        .ok_or("the boot image has no files")?
        .offset as usize;
    let mut unsigned = good.clone();
    unsigned[0] = b's';
    let mut bad_init = good.clone();
    bad_init[init_at] = b's';
    let big = raw_init(&[LDR_X0_X0], false, BIG_DATA)?;
    let cases = [
        (None, "no boot image"),
        (Some(&good[..good.len() - 1]), "boot image: cut short"),
        (Some(&unsigned[..]), "boot image: no STAFBOOT signature"),
        (
            Some(&bad_init[..]),
            "boot image: init: no STAFPROG signature",
        ),
        (
            Some(&big[..]),
            "init: no frames for its data segment of 0x800000 bytes",
        ),
    ];
    let path = root().join("target").join("bad-boot.img");
    for (bytes, marker) in cases {
        if let Some(b) = bytes {
            std::fs::write(&path, b).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        let image = bytes.map(|_| path.as_path());
        let mut cmd = qemu::command(&qemu::VIRT, &a.image, image);
        cmd.args(qemu::HEADLESS);
        let o = qemu::run_until(cmd, BOOT_TIMEOUT, None)?;
        qemu::expect_powered_off(&o)?;
        qemu::expect_marker(&o, "KERNEL PANIC")?;
        qemu::expect_marker(&o, marker)?;
    }
    Ok(())
}

/// An init that faults or is killed stops the machine (spec 7.9). At a
/// fault the kernel prints the fault and init's registers, panics with
/// the fault, and the machine powers off. The cases: a load through a
/// null pointer; a store to init's read-only data and a branch into it,
/// which its protection forbids (spec 3.3). An init that kills its own
/// process makes the kernel panic with «killed», and no fault is printed.
fn init_fault_stops_the_machine() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let path = root().join("target").join("fault-init.img");
    let run = |image: Vec<u8>| {
        std::fs::write(&path, image).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut cmd = qemu::command(&qemu::VIRT, &a.image, Some(&path));
        cmd.args(qemu::HEADLESS);
        let o = qemu::run_until(cmd, BOOT_TIMEOUT, None)?;
        qemu::expect_powered_off(&o)?;
        qemu::expect_marker(&o, "KERNEL PANIC")?;
        Ok::<_, String>(o)
    };
    let cases: [(&[u32], bool, &str, &str, u64); 3] = [
        (
            &[LDR_X0_X0],
            false,
            "data abort from EL0 (EC 0x24)",
            "ESR=0x92000006 FAR=0x0 ELR=0x200000",
            0x20_0000,
        ),
        (
            &[ADR_X1_NEXT_PAGE, STR_X0_X1],
            true,
            "data abort from EL0 (EC 0x24)",
            "ESR=0x9200004f FAR=0x201000 ELR=0x200004",
            0x20_0004,
        ),
        (
            &[B_NEXT_PAGE],
            true,
            "instruction abort from EL0 (EC 0x20)",
            "ESR=0x8200000f FAR=0x201000 ELR=0x201000",
            0x20_1000,
        ),
    ];
    for (code, rodata, class, fault, elr) in cases {
        let o = run(raw_init(code, rodata, 0)?)?;
        qemu::expect_line(&o, &format!("process fault: {class} {fault}"))?;
        qemu::expect_line(&o, &init_registers(elr))?;
        qemu::expect_line(&o, &format!("init terminated by a fault: {fault}"))?;
    }
    let o = run(raw_init(&KILL_ITSELF, false, 0)?)?;
    qemu::expect_line(&o, "init terminated: Killed")?;
    if let Some(l) = o.lines.iter().find(|l| l.starts_with("process fault")) {
        return Err(format!("an init that killed itself faulted: {l}"));
    }
    Ok(())
}

/// The line of init's registers the kernel prints at its fault
/// (exceptions::user_fault) for an init of raw_init faulting at `elr`: SP
/// at abi::INIT_STACK_TOP, 0 in SPSR and TPIDR_EL0.
fn init_registers(elr: u64) -> String {
    format!(
        "sp_el0 0x0000000100000000  elr {elr:#018x}  spsr 0x0000000000000000  tpidr_el0 0x0000000000000000"
    )
}

/// A kernel that executes an undefined instruction must name the exception
/// class, print the registers, and its backtrace must name the interrupted
/// instruction: proof that exception entry recorded a frame, not just that
/// the panic handler's own frames print (they would with no record at all).
fn fault_report() -> Result<(), String> {
    let a = build(Variant::FaultProbe)?;
    let mut cmd = qemu::command(&qemu::VIRT, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let o = qemu::run_until(cmd, BOOT_TIMEOUT, None)?;
    qemu::expect_not_timed_out(&o)?;
    for marker in ["unknown or undefined instruction", "x0  0x", "backtrace ("] {
        qemu::expect_marker(&o, marker)?;
    }
    qemu::backtrace_names_the_fault(&o.lines)
}

/// `llvm-nm -C`, defined symbols only, on `elf`.
fn nm_defined(elf: &Path) -> Result<String, String> {
    stdout_of(
        Command::new(llvm_tool("llvm-nm")?)
            .args(["-C", "--defined-only"])
            .arg(elf),
    )
}

/// The image that ships carries none of the kernel's own tests (spec 3.4):
/// no symbol of `elf` lies in `kernel::ktest` or `kernel::testpoint`
/// (qemu::test_symbols).
fn no_test_symbols(elf: &Path) -> Result<(), String> {
    let nm = nm_defined(elf)?;
    let found = qemu::test_symbols(&nm);
    if found.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} carries test symbols it must not ship:\n{}",
            elf.display(),
            found.join("\n")
        ))
    }
}

/// `no_test_symbols` is not a check on an image that never carries test
/// symbols at all: the ktest build's own ELF does.
fn test_build_carries_test_symbols() -> Result<(), String> {
    let a = build(Variant::Test)?;
    let nm = nm_defined(&a.elf)?;
    if qemu::test_symbols(&nm).is_empty() {
        Err(format!(
            "{} has no test symbols; no_test_symbols would pass on anything",
            a.elf.display()
        ))
    } else {
        Ok(())
    }
}

/// A kernel that recurses without end must report the overflow from the
/// emergency stack and power off: the report names the real ELR inside the
/// recursive function, and its backtrace goes on into the recursion on the
/// kernel stack. The function's address range comes from the ELF's symbols.
fn stack_overflow_report() -> Result<(), String> {
    let a = build(Variant::OverflowProbe)?;
    let mut cmd = qemu::command(&qemu::VIRT, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let o = qemu::run_until(cmd, BOOT_TIMEOUT, None)?;
    qemu::expect_powered_off(&o)?;
    for marker in ["kernel stack overflow", "backtrace ("] {
        qemu::expect_marker(&o, marker)?;
    }
    let nm = stdout_of(
        Command::new(llvm_tool("llvm-nm")?)
            .args(["-C", "--print-size", "--defined-only"])
            .arg(&a.elf),
    )?;
    let f = qemu::symbol_range(&nm, OVERFLOW_PROBE_FN)
        .ok_or_else(|| format!("{OVERFLOW_PROBE_FN} is not in {}", a.elf.display()))?;
    qemu::overflow_report_names(&o.lines, f)
}

/// Kernel built with `ktest` on machine `m`: runs its tests and exits QEMU
/// through semihosting. On 2 GiB the tests also cover RAM the boot page
/// tables did not map. Every test the kernel counts passes once, and what
/// the tests wrote through `debug_write` reaches the console whole. The
/// `icount` build runs under qemu::ICOUNT, where virtual time counts
/// instructions: the tests that depend on how much of a quantum is left
/// run only there. A hang, such as a quantum that never ends, fails at
/// TEST_TIMEOUT.
fn kernel_tests(m: &qemu::Machine, variant: Variant) -> Result<(), String> {
    let a = build(variant)?;
    let mut cmd = qemu::command(m, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS).arg("-semihosting");
    let icount = variant == Variant::TestIcount;
    if icount {
        cmd.args(qemu::ICOUNT);
    }
    let o = qemu::run_until(cmd, TEST_TIMEOUT, None)?;
    let r = qemu::parse_report(&o.lines);
    qemu::counted_verdict(&o, &r)?;
    for line in DEBUG_WRITE_LINES {
        qemu::expect_line(&o, line)?;
    }
    for name in ICOUNT_TESTS {
        if r.passed.iter().any(|p| p == name) != icount {
            return Err(format!(
                "{name} must pass in the icount build and only there"
            ));
        }
    }
    let under = if icount { " under icount" } else { "" };
    println!(
        "kernel tests{under} on {}: {} passed",
        m.memory,
        r.passed.len()
    );
    if icount {
        let ticks = round_trip_ticks(&o.lines)?;
        let rows: Vec<_> = ROUND_TRIP_ROWS
            .iter()
            .zip(ticks)
            .map(|(row, n)| format!("{row}={n}"))
            .collect();
        println!("ipc round trip ticks on {}: {}", m.memory, rows.join(" "));
    }
    Ok(())
}

/// The numbers of the line `ipc round trip ticks: null=... handles=...`
/// that `ipc_round_trip_is_measured` prints, one for each of
/// ROUND_TRIP_ROWS in that order: an error when no line has them all.
fn round_trip_ticks(lines: &[String]) -> Result<[u64; 6], String> {
    let line = lines
        .iter()
        .find_map(|l| l.strip_prefix("ipc round trip ticks: "))
        .ok_or("the kernel printed no round trip")?;
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != ROUND_TRIP_ROWS.len() {
        return Err(format!("the round trip has other rows: {line:?}"));
    }
    let mut ticks = [0; 6];
    for ((t, row), field) in ticks.iter_mut().zip(ROUND_TRIP_ROWS).zip(fields) {
        *t = field
            .strip_prefix(row)
            .and_then(|f| f.strip_prefix('='))
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| format!("{field:?} is no {row} row of the round trip"))?;
    }
    Ok(ticks)
}

/// The test init (tests/init) as init of the normal build, the kernel that
/// ships, on machine `m`, under qemu::ICOUNT when `icount`: each of its
/// INIT_TESTS tests passes once, the lines it and the kernel print for the
/// tests come whole, one child faults, and it exits with 0, which turns
/// the machine off. Its first line says how long a counted loop took,
/// which under -icount must be the loop's instructions.
fn init_tests(m: &qemu::Machine, icount: bool) -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let image = build_boot_image("test-init", "boot-test.img")?;
    let mut cmd = qemu::command(m, &a.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    if icount {
        cmd.args(qemu::ICOUNT);
    }
    let o = qemu::run_until(cmd, TEST_TIMEOUT, None)?;
    let r = qemu::parse_report(&o.lines);
    qemu::counted_verdict(&o, &r)?;
    if r.total != Some(INIT_TESTS) {
        return Err(format!(
            "the test init has {:?} tests, {INIT_TESTS} expected",
            r.total
        ));
    }
    for line in TEST_INIT_LINES.into_iter().chain([INIT_EXIT]) {
        qemu::expect_line(&o, line)?;
    }
    let faults = o
        .lines
        .iter()
        .filter(|l| l.starts_with("process fault: "))
        .count();
    if faults != 1 {
        return Err(format!(
            "{faults} process fault lines; the test init makes one"
        ));
    }
    let ticks = qemu::number_after(&o.lines, "counter ticks of 10000 turns: ")
        .ok_or("the test init printed no loop time")?;
    if icount && !(20_000..=20_100).contains(&ticks) {
        return Err(format!(
            "{ticks} ticks for 10000 turns: the run is not under -icount"
        ));
    }
    let under = if icount { " under icount" } else { "" };
    println!(
        "init tests{under} on {}: {} passed",
        m.memory,
        r.passed.len()
    );
    Ok(())
}

fn gdb() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    println!(
        "QEMU is halted before the kernel starts (kernel entry: PA 0x40200000). In another terminal:\n  lldb {} -o 'gdb-remote 1234'\nCode before the MMU runs at physical addresses; see docs/debugging.md.",
        a.elf.display()
    );
    run_cmd(
        qemu::command(&qemu::VIRT, &a.image, Some(&a.boot_image)).args(["-nographic", "-s", "-S"]),
    )
}

fn ci() -> Result<(), String> {
    run_cmd(cargo().args(["fmt", "--all", "--check"]))?;
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "abi",
        "--package",
        "bootimg",
        "--package",
        "kcore",
        "--package",
        "xtask",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]))?;
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "abi",
        "--package",
        "bootimg",
        "--package",
        "kcore",
        "--target",
        KERNEL_TARGET,
        "--",
        "-D",
        "warnings",
    ]))?;
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "rt",
        "--package",
        "init",
        "--package",
        "test-init",
        "--target",
        PROGRAM_TARGET,
        "--",
        "-D",
        "warnings",
    ]))?;
    for variant in Variant::ALL {
        let mut cmd = cargo();
        cmd.args([
            "clippy",
            "--package",
            "kernel",
            "--release",
            "--target",
            KERNEL_TARGET,
        ]);
        if let Some(feature) = variant.feature() {
            cmd.args(["--features", feature]);
        }
        run_cmd(cmd.args(["--", "-D", "warnings"]))?;
    }
    test()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_itself_is_what_an_assembler_makes() {
        // movz x0, #0x1; movk x0, #0x1, lsl #16; svc #13; ldr x0, [x0]
        assert_eq!(
            KILL_ITSELF,
            [0xD280_0020, 0xF2A0_0020, 0xD400_01A1, 0xF940_0000]
        );
    }

    #[test]
    fn variants_have_their_own_artifacts_and_features() {
        let all = Variant::ALL;
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.stem(), b.stem());
                assert_ne!(a.feature(), b.feature());
            }
        }
        assert_eq!(Variant::Normal.feature(), None);
    }

    /// The build that ships and its probes keep the limit of spec 3.4; the
    /// builds with the kernel tests have one of their own.
    #[test]
    fn test_builds_have_a_limit_of_their_own() {
        for variant in [Variant::Normal, Variant::FaultProbe, Variant::OverflowProbe] {
            assert_eq!(variant.limit(), (204_800, "spec 3.4"));
        }
        for variant in [Variant::Test, Variant::TestIcount] {
            assert_eq!(variant.limit(), (524_288, "test builds"));
        }
    }

    /// The text of every file under `dirs` of the workspace that reads as
    /// UTF-8, with its path from the workspace's root.
    fn texts(dirs: &[&str]) -> Vec<(String, String)> {
        let mut found = Vec::new();
        let mut paths: Vec<_> = dirs.iter().map(|dir| root().join(dir)).collect();
        while let Some(path) = paths.pop() {
            if path.is_dir() {
                let entries = std::fs::read_dir(&path).expect("a readable directory");
                paths.extend(entries.map(|e| e.expect("a directory entry").path()));
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let name = path.strip_prefix(root()).expect("a path in the workspace");
            found.push((name.to_string_lossy().into_owned(), text));
        }
        found
    }

    /// The kernel keeps the FP and SIMD registers for programs and saves
    /// them only when threads switch (spec 8), so FP or SIMD anywhere else
    /// in the kernel would change a program's registers without a word.
    /// Only the thread switch and the EL0 test programs may assemble them.
    /// Every crate linked into the kernel is searched: the kernel itself,
    /// kcore, abi and bootimg.
    #[test]
    fn only_the_thread_switch_uses_fp() {
        let mut found: Vec<_> = texts(&["kernel", "kcore", "lib/abi", "lib/bootimg"])
            .into_iter()
            .filter(|(_, text)| {
                text.lines().any(|l| {
                    (l.contains(".arch_extension") && (l.contains("fp") || l.contains("simd")))
                        || ((l.contains("target_feature") || l.contains("target-feature"))
                            && (l.contains("neon") || l.contains("fp-armv8")))
                })
            })
            .map(|(name, _)| name)
            .collect();
        found.sort();
        assert_eq!(
            found,
            ["kernel/src/arch/aarch64/fpsimd.S", "kernel/src/ktest/el0.S"]
        );
    }

    /// The round trip's line gives its six rows in order, and nothing else
    /// passes for it.
    #[test]
    fn round_trip_line_gives_six_rows() {
        let line = "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 buffer=5 handles=6";
        let lines = ["TEST fast_path_is_taken ok", line].map(String::from);
        assert_eq!(round_trip_ticks(&lines), Ok([1, 2, 3, 4, 5, 6]));
        for bad in [
            "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 buffer=5",
            "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 handles=5 buffer=6",
            "ipc round trip ticks: null=x switch=2 fast=3 slow=4 buffer=5 handles=6",
            "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 buffer=5 handles=6 more=7",
        ] {
            assert!(round_trip_ticks(&[bad.to_string()]).is_err(), "{bad}");
        }
        assert!(round_trip_ticks(&[]).is_err());
    }

    /// The kernel tests wake their threads through timers of programs
    /// (spec 10): the test builds keep no deadline of their own for the
    /// kernel's timer to serve besides the programs' timers.
    #[test]
    fn kernel_tests_keep_no_deadline_of_their_own() {
        let found: Vec<_> = texts(&["kernel/src"])
            .into_iter()
            .filter(|(name, text)| {
                text.contains("el0::deadline")
                    || (name.starts_with("kernel/src/ktest") && text.contains("fn deadline("))
            })
            .map(|(name, _)| name)
            .collect();
        assert!(found.is_empty(), "a test deadline in {found:?}");
    }
}
