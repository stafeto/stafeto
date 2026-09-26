// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Build, run and test stafeto. Usage: `cargo xtask <command>`.

mod elf;
mod image;
mod qemu;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

const KERNEL_TARGET: &str = "aarch64-unknown-none-softfloat";
/// Spec 14: programs, which run at EL0, are built for this target.
const PROGRAM_TARGET: &str = "aarch64-unknown-none";
/// The stack of init's first thread, in bytes, which init's program asks
/// the kernel for (lib/bootimg); the size is ours.
const INIT_STACK_SIZE: u32 = 64 * 1024;
/// The stack of a child of the test init (tests/child), which its loader
/// maps (rt::loader).
const CHILD_STACK_SIZE: u32 = 16 * 1024;
/// The programs of the boot image of the normal build and of the test
/// init's runs: each file's name in the image, the package that builds it
/// for EL0 and the size of its stack. Init comes first (spec 13.1).
const BOOT_PROGRAMS: [(&str, &str, u32); 1] = [("init", "init", INIT_STACK_SIZE)];
const TEST_PROGRAMS: [(&str, &str, u32); 2] = [
    ("init", "test-init", INIT_STACK_SIZE),
    ("child", "test-child", CHILD_STACK_SIZE),
];
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
/// Tests only the `icount` build has: the first checks that the run is
/// under -icount; the second and the third measure the portions of the
/// long calls of memory objects and of the timers of programs, which only
/// -icount counts in instructions (spec 15.3); the next two depend on how
/// much of a quantum is left, which only -icount makes repeatable; the
/// sixth takes a big process apart in hundreds of portions with interrupts
/// between them, where virtual time counts instructions and a stall of the
/// host changes nothing; the seventh measures the round trip of a request;
/// in the eighth a timer fires in the middle of each long call of memory
/// objects at the same place on every run; the ninth measures the path of
/// an interrupt of a bound line to its driver, and the last the calls and
/// portions of device windows.
const ICOUNT_TESTS: [&str; 10] = [
    "virtual_time_counts_instructions",
    "memory_portions_are_measured",
    "timer_firing_is_measured",
    "lone_round_robin_thread_is_not_switched",
    "preempted_rr_thread_resumes_before_its_peer",
    "teardown_yields_to_a_pending_interrupt",
    "ipc_round_trip_is_measured",
    "long_call_yields_to_a_pending_interrupt",
    "interrupt_path_is_measured",
    "device_windows_are_measured",
];
/// The rows of the line of `ipc_round_trip_is_measured`, in its order
/// (spec 15.3).
const ROUND_TRIP_ROWS: [&str; 6] = ["null", "switch", "fast", "slow", "buffer", "handles"];
/// The rows of the line of `memory_portions_are_measured`, in its order
/// (spec 15.3).
const MEMORY_PORTION_ROWS: [&str; 8] = [
    "create",
    "map",
    "map_exec",
    "unmap",
    "protect",
    "protect_exec",
    "release",
    "first_map",
];
/// The rows of the line of `timer_firing_is_measured`, in its order (spec
/// 15.3).
const TIMER_PORTION_ROWS: [&str; 3] = ["interrupt", "fire", "set"];
/// The rows of the line of `interrupt_path_is_measured`, in its order
/// (spec 15.3).
const INTERRUPT_PATH_ROWS: [&str; 4] = ["driver", "bind", "ack", "portion"];
/// The rows of the line of `device_windows_are_measured`, in its order
/// (spec 15.3).
const WINDOW_ROWS: [&str; 3] = ["create", "map", "release"];
/// The rows of the line of the test init's `normal_build_costs`, in its
/// order: the costs of the build that ships (spec 15.3).
const NORMAL_BUILD_ROWS: [&str; 5] = ["null", "clock", "yield", "notify", "round_trip"];
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
/// Where RAM starts on QEMU's `virt`.
const VIRT_RAM: u64 = 0x4000_0000;
/// The kernel's lines of the GIC on QEMU's GICv2 and GICv3 (spec 9).
const GIC_V2_LINE: &str = "gic        v2 distributor 0x8000000, cpu interface 0x8010000";
const GIC_V3_LINE: &str = "gic        v3 distributor 0x8000000, redistributor 0x80a0000";
/// The kernel's last line when init exits with 0 (spec 7.9).
const INIT_EXIT: &str = "init exited with code 0";
/// The test init's exit under HVF, where one of its tests fails
/// (qemu::hvf_verdict): its code is its count of failures.
const INIT_EXIT_HOLE: &str = "init exited with code 1";
/// The frequency of the counter of Apple's processors (CNTFRQ_EL0), which
/// HVF passes on.
const HVF_HZ: u64 = 24_000_000;
/// Lines of a run of the test init (tests/init) besides its TEST lines,
/// each whole: a formatted line longer than one debug_write, all 64 bytes
/// of x2-x9 in one debug_write, the bytes of a debug_write's length and no
/// more, and the kernel's line for the fault of a child with no code (spec
/// 7.9, 15.2).
const TEST_INIT_LINES: [&str; 4] = [
    "init prints from EL0 in pieces of at most 64 bytes: this line takes 2 of them",
    "test init: debug_write prints all 64 bytes of x2 to x9 in order",
    "debug_write stops at its length",
    "process fault: instruction abort from EL0 (EC 0x20) ESR=0x82000007 FAR=0x1000 ELR=0x1000",
];
/// The children of the test init that fault, each with a line of the
/// kernel (spec 7.9): the child with no code of
/// `child_fault_reason_reaches_the_parent` and the children with code of
/// the tests of faults, of `wfi` with the fault before it, of an orphan
/// that faults and of a load through a device window on a hole.
const CHILD_FAULTS: usize = 13;
/// The panic of a child (tests/child, Role::Panic): rt prints where it
/// panicked, then this message on a line of its own (spec 13.2).
const CHILD_PANIC_AT: &str = "panic: panicked at tests/child/src/main.rs:";
const CHILD_PANIC: &str = "the child panics on purpose";
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
const INIT_TESTS: u32 = 179;
/// A data segment bigger than the biggest memory object (abi::MAX_MEMORY)
/// by a page.
const HUGE_DATA: u64 = abi::MAX_MEMORY + bootimg::PAGE_SIZE;

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
  hvf       boot checks, init tests and kernel tests under HVF on a Mac with
            Apple silicon, on Apple's GICv3 and QEMU's GICv2; skips elsewhere
  help      this text";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("build") => build(Variant::Normal).map(|_| ()),
        Some("run") => run(),
        Some("test") => test(),
        Some("gdb") => gdb(),
        Some("ci") => ci(),
        Some("hvf") => hvf(),
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

/// Where cargo writes its builds: CARGO_TARGET_DIR when it is set, else
/// target/ of the workspace.
fn target_dir() -> PathBuf {
    target_dir_of(std::env::var_os("CARGO_TARGET_DIR"), &root())
}

/// target_dir with CARGO_TARGET_DIR as `var`: a relative directory is
/// taken from `root`, where xtask runs cargo.
fn target_dir_of(var: Option<OsString>, root: &Path) -> PathBuf {
    root.join(var.unwrap_or_else(|| "target".into()))
}

/// The file cargo builds for `package` on `triple` with `--release`
/// under the directory `target`.
fn cargo_output(target: &Path, triple: &str, package: &str) -> PathBuf {
    target.join(triple).join("release").join(package)
}

/// What `make` gives for `key`: made at the first call for `key` in this
/// run of xtask and kept in `made` for the calls after it.
fn once<K: PartialEq, T: Clone>(
    made: &Mutex<Vec<(K, T)>>,
    key: K,
    make: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let mut made = made.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, t)) = made.iter().find(|(k, _)| *k == key) {
        return Ok(t.clone());
    }
    let t = make()?;
    made.push((key, t.clone()));
    Ok(t)
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

#[derive(Clone)]
struct Artifacts {
    elf: PathBuf,
    image: PathBuf,
    boot_image: PathBuf,
}

/// The kernel builds of this run of xtask, one per variant.
static BUILDS: Mutex<Vec<(Variant, Artifacts)>> = Mutex::new(Vec::new());
/// The boot images of this run of xtask, one per name.
static BOOT_IMAGES: Mutex<Vec<(&str, PathBuf)>> = Mutex::new(Vec::new());

/// The kernel image of `variant` and the boot image of the normal build,
/// each built once in a run of xtask, whatever number of checks takes
/// them.
fn build(variant: Variant) -> Result<Artifacts, String> {
    once(&BUILDS, variant, || build_kernel(variant))
}

fn build_kernel(variant: Variant) -> Result<Artifacts, String> {
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
    let target = target_dir();
    // Every variant writes the same cargo output path; a copy next to each image
    // keeps the symbols that match it.
    let elf = target.join(format!("{}.elf", variant.stem()));
    let image = target.join(format!("{}.img", variant.stem()));
    let built = cargo_output(&target, KERNEL_TARGET, "kernel");
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
    let boot_image = build_boot_image("boot.img", &BOOT_PROGRAMS)?;
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

/// Builds `programs` for EL0 and, under target_dir, a boot image `name`
/// whose files they are, in their order, each with its name and the stack
/// size its header asks for (spec 3.3, 13.1); once in a run of xtask.
fn build_boot_image(name: &'static str, programs: &[(&str, &str, u32)]) -> Result<PathBuf, String> {
    once(&BOOT_IMAGES, name, || write_boot_image(name, programs))
}

fn write_boot_image(name: &str, programs: &[(&str, &str, u32)]) -> Result<PathBuf, String> {
    let mut cmd = cargo();
    cmd.args(["build", "--release", "--target", PROGRAM_TARGET]);
    for (_, package, _) in programs {
        cmd.args(["--package", package]);
    }
    run_cmd(&mut cmd)?;
    let target = target_dir();
    let mut files = Vec::new();
    for &(file, package, stack) in programs {
        let elf = cargo_output(&target, PROGRAM_TARGET, package);
        let why = |e: String| format!("{}: {e}", elf.display());
        let bytes = std::fs::read(&elf).map_err(|e| why(e.to_string()))?;
        let program = elf::program(&bytes, stack).map_err(why)?;
        let written = bootimg::write::program(&program).map_err(|e| why(e.to_string()))?;
        files.push((file, written, elf));
    }
    let list: Vec<_> = files.iter().map(|(f, b, _)| (*f, b.as_slice())).collect();
    let image = bootimg::write::image(&list).map_err(|e| format!("{name}: {e}"))?;
    let path = target.join(name);
    std::fs::write(&path, &image).map_err(|e| format!("{}: {e}", path.display()))?;
    let from: Vec<_> = files
        .iter()
        .map(|(f, _, elf)| format!("{f} from {}", elf.display()))
        .collect();
    println!(
        "boot image {} ({} bytes): {}",
        path.display(),
        image.len(),
        from.join(", ")
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
    boot_smoke(&qemu::VIRT, GIC_V2_LINE)?;
    boot_smoke(&qemu::VIRT_V3, GIC_V3_LINE)?;
    boot_smoke(&qemu::VIRT_EL2, GIC_V2_LINE)?;
    boot_smoke(&qemu::VIRT_EL2_V3, GIC_V3_LINE)?;
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
    init_tests(&qemu::VIRT_V3, false)?;
    kernel_tests(&qemu::VIRT, Variant::Test)?;
    kernel_tests(&qemu::VIRT_2G, Variant::Test)?;
    kernel_tests(&qemu::VIRT_V3, Variant::Test)?;
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

/// A normal build boots on machine `m`, prints its report (boot_report)
/// with the line of the GIC, `gic`, and init's entry point from the boot
/// image, starts init, and powers the machine off when init exits. Gives
/// the timer's frequency. On VIRT_EL2 and VIRT_EL2_V3 the kernel is
/// entered at EL2, as the PinePhone's loader does: head.S must drop to
/// EL1, with a GICv3 open its system registers to EL1 first, and power-off
/// goes through SMC. The image also carries none of the kernel's own
/// tests (spec 3.4): `no_test_symbols` checks it here so every normal
/// build, not just the one that ships, is covered.
fn boot_smoke(m: &qemu::Machine, gic: &str) -> Result<u64, String> {
    let a = build(Variant::Normal)?;
    no_test_symbols(&a.elf)?;
    let mut cmd = qemu::command(m, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let o = qemu::run_until(cmd, BOOT_TIMEOUT, None)?;
    qemu::expect_clean_exit_with(&o, "boot complete")?;
    expect_init_run(&o)?;
    let entry = init_entry(&a.boot_image)?;
    qemu::expect_marker(&o, &format!("init       entry {entry:#x},"))?;
    let size = std::fs::metadata(&a.boot_image)
        .map_err(|e| format!("{}: {e}", a.boot_image.display()))?
        .len();
    boot_report(&o.lines, m, size, gic)
}

/// The kernel's boot report (spec 3.3) on machine `m` with a boot image of
/// `boot_image` bytes and the line of the GIC `gic`: the lines of `m`'s
/// RAM at VIRT_RAM, the boot image, the GIC, `m`'s PSCI conduit, the timer
/// and `boot complete`, each whole. Gives the timer's frequency, which
/// depends on the host.
fn boot_report(
    lines: &[String],
    m: &qemu::Machine,
    boot_image: u64,
    gic: &str,
) -> Result<u64, String> {
    let memory = format!("memory     {VIRT_RAM:#x}..{:#x}", VIRT_RAM + m.ram());
    let psci = format!("psci       {}", m.psci());
    for line in [memory.as_str(), gic, psci.as_str(), "boot complete"] {
        if !lines.iter().any(|l| l == line) {
            return Err(format!("the boot report has no line {line:?}"));
        }
    }
    let hex = |s: &str| u64::from_str_radix(s.strip_prefix("0x")?, 16).ok();
    let image = lines.iter().find_map(|l| {
        let (start, end) = l.strip_prefix("boot image ")?.split_once("..")?;
        hex(end)?.checked_sub(hex(start)?)
    });
    if image != Some(boot_image) {
        return Err(format!(
            "the boot report has no line of a boot image of {boot_image} bytes"
        ));
    }
    lines
        .iter()
        .find_map(|l| {
            l.strip_prefix("timer      ")?
                .strip_suffix(" Hz")?
                .parse()
                .ok()
        })
        .filter(|&hz| hz > 0)
        .ok_or_else(|| "the boot report has no line `timer N Hz`".into())
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

/// A boot image that is missing, cut short, damaged or not whole pages
/// stops the boot with a panic that says what is wrong (spec 3.3, 13.1).
/// The cases: no boot image; the image without the last byte of init; the
/// image's signature spoiled; init's signature spoiled; the image with a
/// byte past its whole pages; an init whose data segment is
/// bigger than a memory object can be, which the kernel cannot load.
fn bad_boot_images_stop_the_boot() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let good =
        std::fs::read(&a.boot_image).map_err(|e| format!("{}: {e}", a.boot_image.display()))?;
    let init = bootimg::BootImage::parse(&good)
        .map_err(|e| e.to_string())?
        .files()
        .next()
        .ok_or("the boot image has no files")?;
    let (init_at, init_end) = (init.offset as usize, init.offset as usize + init.data.len());
    let mut odd = good.clone();
    odd.push(0);
    let mut unsigned = good.clone();
    unsigned[0] = b's';
    let mut bad_init = good.clone();
    bad_init[init_at] = b's';
    let huge = raw_init(&[LDR_X0_X0], false, HUGE_DATA)?;
    let cases = [
        (None, "no boot image"),
        (Some(&good[..init_end - 1]), "boot image: cut short"),
        (Some(&unsigned[..]), "boot image: no STAFBOOT signature"),
        (
            Some(&bad_init[..]),
            "boot image: init: no STAFPROG signature",
        ),
        (Some(&odd[..]), "boot image: not whole pages"),
        (
            Some(&huge[..]),
            "init: no memory object for its data segment",
        ),
    ];
    let path = target_dir().join("bad-boot.img");
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
    let path = target_dir().join("fault-init.img");
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

/// Kernel built with `ktest` on machine `m`: runs its tests, prints
/// `TESTS DONE` and powers the machine off through PSCI (spec 14). On 2
/// GiB the tests also cover RAM the boot page tables did not map. Every
/// test the kernel counts passes once. The `icount` build runs under
/// qemu::ICOUNT, where virtual time counts instructions: the tests that
/// depend on how much of a quantum is left run only there. A hang, such
/// as a quantum that never ends, fails at TEST_TIMEOUT. Gives the number
/// of tests that passed.
fn kernel_tests(m: &qemu::Machine, variant: Variant) -> Result<usize, String> {
    let a = build(variant)?;
    let mut cmd = qemu::command(m, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let icount = variant == Variant::TestIcount;
    if icount {
        cmd.args(qemu::ICOUNT);
    }
    let o = qemu::run_until(cmd, TEST_TIMEOUT, None)?;
    let r = qemu::parse_report(&o.lines);
    qemu::counted_verdict(&o, &r)?;
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
        m.name,
        r.passed.len()
    );
    if icount {
        for (what, rows) in [
            ("ipc round trip", &ROUND_TRIP_ROWS[..]),
            ("memory portions", &MEMORY_PORTION_ROWS[..]),
            ("timer portions", &TIMER_PORTION_ROWS[..]),
            ("interrupt path", &INTERRUPT_PATH_ROWS[..]),
            ("device window", &WINDOW_ROWS[..]),
        ] {
            let ticks = ticks_of(&o.lines, what, rows)?;
            println!("{what} ticks on {}: {}", m.name, rows_of(rows, &ticks));
        }
    }
    Ok(r.passed.len())
}

/// `rows` with their `ticks`, as `<row>=<n> ...`.
fn rows_of(rows: &[&str], ticks: &[u64]) -> String {
    let rows: Vec<_> = rows
        .iter()
        .zip(ticks)
        .map(|(row, n)| format!("{row}={n}"))
        .collect();
    rows.join(" ")
}

/// The numbers of the line `<what> ticks: <row>=<n> ...` that a measuring
/// test prints (`ipc round trip`, `memory portions`), one for each of
/// `rows` in that order: an error when no line has them all.
fn ticks_of(lines: &[String], what: &str, rows: &[&str]) -> Result<Vec<u64>, String> {
    let prefix = format!("{what} ticks: ");
    let line = lines
        .iter()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .ok_or_else(|| format!("the kernel printed no {what} ticks"))?;
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != rows.len() {
        return Err(format!("the {what} line has other rows: {line:?}"));
    }
    rows.iter()
        .zip(fields)
        .map(|(row, field)| {
            field
                .strip_prefix(row)
                .and_then(|f| f.strip_prefix('='))
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| format!("{field:?} is no {row} row of the {what} line"))
        })
        .collect()
}

/// The test init (tests/init) as init of the normal build, the kernel that
/// ships, on machine `m`, under qemu::ICOUNT when `icount`, with its child
/// program (tests/child) as the second file of the boot image: each of its
/// INIT_TESTS tests passes once, the lines it, its children and the kernel
/// print for the tests come whole, CHILD_FAULTS children fault, and it
/// exits with 0, which turns the machine off. Its first line says how long
/// a counted loop took, which under -icount must be the loop's
/// instructions; there it also prints the costs of the build that ships
/// (NORMAL_BUILD_ROWS), which fail nothing by their numbers (spec 15.3).
/// Under HVF qemu::hvf_verdict judges the run: the test of a window on a
/// hole fails, one child fewer faults, and init exits with 1. Gives the
/// number of tests that passed.
fn init_tests(m: &qemu::Machine, icount: bool) -> Result<usize, String> {
    let a = build(Variant::Normal)?;
    let image = build_boot_image("boot-test.img", &TEST_PROGRAMS)?;
    let mut cmd = qemu::command(m, &a.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    if icount {
        cmd.args(qemu::ICOUNT);
    }
    let o = qemu::run_until(cmd, TEST_TIMEOUT, None)?;
    let r = qemu::parse_report(&o.lines);
    let hvf = m.is_hvf();
    if hvf {
        qemu::hvf_verdict(&o, &r)?;
    } else {
        qemu::counted_verdict(&o, &r)?;
    }
    if r.total != Some(INIT_TESTS) {
        return Err(format!(
            "the test init has {:?} tests, {INIT_TESTS} expected",
            r.total
        ));
    }
    let exit = if hvf { INIT_EXIT_HOLE } else { INIT_EXIT };
    for line in TEST_INIT_LINES.into_iter().chain([exit]) {
        qemu::expect_line(&o, line)?;
    }
    child_panic_comes_whole(&o.lines)?;
    let faults = o
        .lines
        .iter()
        .filter(|l| l.starts_with("process fault: "))
        .count();
    let made = CHILD_FAULTS - usize::from(hvf);
    if faults != made {
        return Err(format!(
            "{faults} process fault lines; the test init makes {made}"
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
    println!("init tests{under} on {}: {} passed", m.name, r.passed.len());
    if icount {
        let ticks = ticks_of(&o.lines, "normal build", &NORMAL_BUILD_ROWS)?;
        println!(
            "normal build ticks on {}: {}",
            m.name,
            rows_of(&NORMAL_BUILD_ROWS, &ticks)
        );
    }
    Ok(r.passed.len())
}

/// The panic of a child comes whole (spec 13.2): a line with where it
/// panicked, CHILD_PANIC_AT and the line and column, then CHILD_PANIC on
/// the next line.
fn child_panic_comes_whole(lines: &[String]) -> Result<(), String> {
    let whole = lines.windows(2).any(|pair| {
        let place = pair[0].strip_prefix(CHILD_PANIC_AT).and_then(|p| {
            let (line, column) = p.strip_suffix(':')?.split_once(':')?;
            line.parse::<u32>().ok().zip(column.parse::<u32>().ok())
        });
        place.is_some() && pair[1] == CHILD_PANIC
    });
    if whole {
        Ok(())
    } else {
        Err("the child's panic did not come whole".into())
    }
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

/// `cargo xtask hvf` (spec 14, 15.2): on a Mac with Apple silicon, for
/// HVF_V3 and then HVF_V2, the boot of the normal build with the counter
/// at HVF_HZ, the test init under qemu::hvf_verdict and the kernel tests,
/// with a line of results for each machine. Elsewhere it prints why it
/// skips and succeeds: `ci` does not run it.
fn hvf() -> Result<(), String> {
    if let Err(why) = hvf_host() {
        println!(
            "hvf: skipped: needs macOS on Apple Silicon with the Hypervisor framework ({why})"
        );
        return Ok(());
    }
    for (m, gic) in [(&qemu::HVF_V3, GIC_V3_LINE), (&qemu::HVF_V2, GIC_V2_LINE)] {
        let hz = boot_smoke(m, gic)?;
        if hz != HVF_HZ {
            return Err(format!("the counter runs at {hz} Hz on {}", m.name));
        }
        let init = init_tests(m, false)?;
        let kernel = kernel_tests(m, Variant::Test)?;
        println!(
            "hvf on {}: boot ok, init tests {init} passed (hole reads zero), kernel tests {kernel} passed",
            m.name
        );
    }
    Ok(())
}

/// qemu::hvf_host on this host: its OS and processor, `sysctl -n
/// kern.hv_support` and `qemu-system-aarch64 -accel help`; a command that
/// does not run gives no output.
fn hvf_host() -> Result<(), String> {
    let output = |cmd: &mut Command| {
        cmd.output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };
    qemu::hvf_host(
        std::env::consts::OS,
        std::env::consts::ARCH,
        &output(Command::new("sysctl").args(["-n", "kern.hv_support"])),
        &output(Command::new("qemu-system-aarch64").args(["-accel", "help"])),
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
        "--package",
        "test-child",
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

    /// Cargo writes under CARGO_TARGET_DIR when it is set, which cargo
    /// takes from the directory it runs in, the workspace's root for
    /// xtask's builds, and under target/ of the workspace otherwise; the
    /// kernel's ELF and the programs are taken from there.
    #[test]
    fn artifacts_come_from_cargo_target_dir() {
        let root = Path::new("/w");
        assert_eq!(target_dir_of(None, root), Path::new("/w/target"));
        assert_eq!(target_dir_of(Some("/t".into()), root), Path::new("/t"));
        assert_eq!(target_dir_of(Some("out".into()), root), Path::new("/w/out"));
        assert_eq!(
            cargo_output(
                &target_dir_of(Some("/t".into()), root),
                KERNEL_TARGET,
                "kernel"
            ),
            Path::new("/t/aarch64-unknown-none-softfloat/release/kernel")
        );
    }

    /// The boot report passes with each of its lines whole, and fails
    /// without any one of them or with one that tells of another machine;
    /// the RAM and the PSCI conduit come from the machine.
    #[test]
    fn boot_smoke_needs_every_report_line() {
        assert_eq!(
            (qemu::VIRT.ram(), qemu::VIRT_2G.ram()),
            (512 << 20, 2 << 30)
        );
        assert_eq!(
            (qemu::VIRT.psci(), qemu::VIRT_EL2_V3.psci()),
            ("Hvc", "Smc")
        );
        let report = [
            "memory     0x40000000..0x60000000",
            "boot image 0x48000000..0x48005000",
            GIC_V2_LINE,
            "psci       Hvc",
            "timer      62500000 Hz",
            "boot complete",
        ]
        .map(String::from);
        let check = |lines: &[String], m, gic| boot_report(lines, m, 0x5000, gic);
        assert_eq!(check(&report, &qemu::VIRT, GIC_V2_LINE), Ok(62_500_000));
        for i in 0..report.len() {
            let mut cut = report.to_vec();
            cut.remove(i);
            let cut = check(&cut, &qemu::VIRT, GIC_V2_LINE);
            assert!(cut.is_err(), "without {:?}", report[i]);
        }
        assert!(check(&report, &qemu::VIRT, GIC_V3_LINE).is_err());
        assert!(check(&report, &qemu::VIRT_2G, GIC_V2_LINE).is_err());
        assert!(check(&report, &qemu::VIRT_EL2, GIC_V2_LINE).is_err());
        for (i, other) in [
            (1, "boot image 0x48000000..0x48006000"),
            (4, "timer      0 Hz"),
        ] {
            let mut changed = report.clone();
            changed[i] = other.to_string();
            let changed = check(&changed, &qemu::VIRT, GIC_V2_LINE);
            assert!(changed.is_err(), "with {other:?}");
        }
        let mut el2 = report.clone();
        el2[3] = "psci       Smc".to_string();
        el2[4] = "timer      24000000 Hz".to_string();
        assert_eq!(check(&el2, &qemu::VIRT_EL2, GIC_V2_LINE), Ok(24_000_000));
    }

    /// The drivers of the kernel's devices and the test init's driver of
    /// the PL031 reach registers through arch::mmio and rt::mmio only (spec
    /// 9): one `ldr` or `str` with the address in a register, which a
    /// hypervisor emulates from the syndrome [G34]. `read_volatile` and
    /// `write_volatile` may compile to a pair or a writeback, which stops
    /// QEMU under HVF.
    #[test]
    fn device_registers_go_through_mmio() {
        // Every file that reaches device registers is listed here.
        let files = [
            "kernel/src/arch/aarch64/gic.rs",
            "kernel/src/console.rs",
            "tests/init/src/devices.rs",
        ];
        for file in files {
            let text = std::fs::read_to_string(root().join(file)).expect("a device file");
            assert!(
                !text.contains("read_volatile") && !text.contains("write_volatile"),
                "{file} reaches a register without mmio"
            );
        }
    }

    /// Each access of arch::mmio and rt::mmio is one plain `ldr` or `str`
    /// (or a byte of it) with the address in a register, with no writeback
    /// and no pair, or the `dmb oshst` of `wmb` [G34]: a hypervisor
    /// emulates only such an access from the syndrome.
    #[test]
    fn mmio_is_one_plain_load_or_store() {
        let allowed = [
            "ldr {v:w}, [{a}]",
            "str {v:w}, [{a}]",
            "ldrb {v:w}, [{a}]",
            "strb {v:w}, [{a}]",
            "ldr {v}, [{a}]",
            "str {v}, [{a}]",
            "dmb oshst",
        ];
        for file in ["kernel/src/arch/aarch64/mmio.rs", "lib/rt/src/mmio.rs"] {
            let text = std::fs::read_to_string(root().join(file)).expect("an mmio file");
            let mut accesses = 0;
            for line in text.lines().filter(|line| line.contains("asm!(")) {
                // The template, and no second template after it.
                let template = line
                    .split_once("asm!(\"")
                    .and_then(|(_, rest)| rest.split_once('"'))
                    .filter(|(_, rest)| !rest.starts_with(", \""))
                    .map(|(template, _)| template);
                assert!(
                    template.is_some_and(|t| allowed.contains(&t)),
                    "{file}: {line}"
                );
                accesses += 1;
            }
            assert!(accesses > 0, "{file} has no access");
        }
    }

    /// The round trip's line gives its six rows in order, and nothing else
    /// passes for it.
    #[test]
    fn round_trip_line_gives_six_rows() {
        let what = "ipc round trip";
        let line = "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 buffer=5 handles=6";
        let lines = ["TEST fast_path_is_taken ok", line].map(String::from);
        let ticks = ticks_of(&lines, what, &ROUND_TRIP_ROWS);
        assert_eq!(ticks, Ok(vec![1, 2, 3, 4, 5, 6]));
        for bad in [
            "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 buffer=5",
            "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 handles=5 buffer=6",
            "ipc round trip ticks: null=x switch=2 fast=3 slow=4 buffer=5 handles=6",
            "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 buffer=5 handles=6 more=7",
        ] {
            let lines = [bad.to_string()];
            assert!(ticks_of(&lines, what, &ROUND_TRIP_ROWS).is_err(), "{bad}");
        }
        assert!(ticks_of(&[], what, &ROUND_TRIP_ROWS).is_err());
    }

    /// The line of the portions of memory objects gives its eight rows in
    /// order, and the round trip's does not pass for it.
    #[test]
    fn memory_portions_line_gives_eight_rows() {
        let what = "memory portions";
        let line = "memory portions ticks: create=1 map=2 map_exec=3 unmap=4 protect=5 \
                    protect_exec=6 release=7 first_map=8";
        let lines = [line.to_string()];
        let ticks = ticks_of(&lines, what, &MEMORY_PORTION_ROWS);
        assert_eq!(ticks, Ok((1..=8).collect()));
        for bad in [
            "memory portions ticks: create=1 map=2 map_exec=3 unmap=4 protect=5 protect_exec=6 release=7",
            "memory portions ticks: map=2 create=1 map_exec=3 unmap=4 protect=5 protect_exec=6 release=7 first_map=8",
            "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 buffer=5 handles=6",
        ] {
            let lines = [bad.to_string()];
            assert!(
                ticks_of(&lines, what, &MEMORY_PORTION_ROWS).is_err(),
                "{bad}"
            );
        }
    }

    /// A child's panic is its place and its message on two whole lines, and
    /// nothing else passes for it.
    #[test]
    fn child_panic_is_two_whole_lines() {
        let place = format!("{CHILD_PANIC_AT}42:5:");
        let good = [place.clone(), CHILD_PANIC.to_string()];
        assert_eq!(child_panic_comes_whole(&good), Ok(()));
        for bad in [
            [place.clone(), format!("{CHILD_PANIC} more")],
            [format!("{CHILD_PANIC_AT}42:"), CHILD_PANIC.to_string()],
            [format!("{CHILD_PANIC_AT}42:5"), CHILD_PANIC.to_string()],
            [CHILD_PANIC.to_string(), place.clone()],
        ] {
            assert!(child_panic_comes_whole(&bad).is_err(), "{bad:?}");
        }
    }

    /// Runs end with PSCI SYSTEM_OFF on every machine (spec 14): the exit
    /// through `hlt #0xf000`, an undefined instruction under HVF, is gone
    /// from the kernel, the programs, xtask and the documents. The word is
    /// built here so that this test finds neither its text nor its name.
    #[test]
    fn no_semihosting_left() {
        let word = ["semi", "hosting"].concat();
        let own_name = format!("fn no_{word}_left() {{");
        let mut found: Vec<_> = texts(&[
            "kernel",
            "kcore",
            "lib",
            "services",
            "tests",
            "xtask",
            "docs",
            "README.md",
        ])
        .into_iter()
        .filter(|(_, text)| {
            text.lines()
                .any(|l| l.to_lowercase().contains(&word) && l.trim() != own_name)
        })
        .map(|(name, _)| name)
        .collect();
        found.sort();
        assert!(found.is_empty(), "{word} in {found:?}");
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
