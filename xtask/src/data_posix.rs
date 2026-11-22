// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask data-posix`: the reading paths of `/data` in the POSIX layer (tests/posix-data) on
//! QEMU's `virt` with a virtio disk that holds a data volume made offline
//! (`data_image::make_posix_volume`: known files, owners, modes, times and numbers, the mark 4, so the
//! service converts nothing). The image has the RAM files, the process, clock and pipe services, the
//! disk service of the volume, the data file service and the probe, a POSIX process of the root that
//! waits for the data service and takes its session from the process service at its first call
//! under `/data`. The probe prints a line for each check (`posix-data: <name> ok`), runs the next
//! check after a failed one, and ends with `posix-data: read checks passed`.
//!
//! The probe's processes run at the level of the tables' POSIX records, 30, on one CPU: the same
//! level as the worker of the data service, so a caller that retries with a yield lets the worker run.
//! A caller at 31 on one CPU is not staged here.

use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, Variant, build, qemu, run_until,
    write_boot_image_files,
};
use std::path::PathBuf;

/// The probe's image; the service is built to stop at a sector of the volume for the crash runs
/// (`datafs/crash`: the point comes from `STAFETO_DATAFS_CRASH_AT`).
const fn programs(datafs: &'static [&'static str]) -> [ImageProgram; 11] {
    [
        ("init", "init", INIT_STACK_SIZE, &["table-data-posix"]),
        ("ramfs", "ramfs", crate::RAMFS_STACK_SIZE, &[]),
        (
            "posix-process-service",
            "posix-process-service",
            64 * 1024,
            &[],
        ),
        ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
        ("pipe", "pipe", crate::PIPE_STACK_SIZE, &[]),
        ("loader", "loader", 0, &[]),
        (
            "virtio-blk",
            "virtio-blk",
            crate::blk_probe::BLK_STACK_SIZE,
            &[],
        ),
        ("datafsd", "datafsd", 32 * 1024, datafs),
        (
            "posix-data",
            "posix-data-probe",
            crate::POSIX_STACK_SIZE,
            &[],
        ),
        (
            "virtio-rng",
            "virtio-rng",
            crate::entropy::RNG_STACK_SIZE,
            &[],
        ),
        (
            "entropy",
            "entropy",
            crate::entropy::ENTROPY_STACK_SIZE,
            &[],
        ),
    ]
}

pub const PROGRAMS: [ImageProgram; 11] = programs(&[]);
/// The service that counts the reads of the disk (`data-fast`).
const PROGRAMS_FAST: [ImageProgram; 11] = programs(&["count"]);
/// The service that ends on a request, for the restart of `data-atomic`.
const PROGRAMS_ATOMIC: [ImageProgram; 11] = programs(&["probe-restart"]);
/// The service with the steps and the counts (`data-steps`).
const PROGRAMS_STEPS: [ImageProgram; 11] = programs(&["steps"]);
const PROGRAMS_CRASH: [ImageProgram; 11] = programs(&["crash"]);
/// The service that ends when it is asked to open `.die` (the restart probe).
const PROGRAMS_RESTART: [ImageProgram; 11] = programs(&["probe-restart"]);

/// The modes of `cargo xtask data-posix`: each is an image of its own, with the role the C program
/// runs (`STAFETO_DATA_POSIX_MODE`), its volume and its checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// The reading paths of a volume made offline.
    Read,
    /// The writing paths: creation, write, truncation, rename, removal, permissions, limits.
    Write,
    /// The cap of 1,024 directories (about 3 million reads of the volume).
    Cap,
    /// The volume filled to its reserve and emptied again (31,000 writes).
    Full,
    /// A restart of the data service in the middle: the service built to end on a request, init
    /// starting it again.
    Restart,
    /// 64 MiB written onto /data and read back, with the throughput printed (no bound): a volume
    /// of 127 MiB.
    Throughput,
    /// `data-fast`: 64 MiB written and read back through the window of the large calls, judged
    /// against the bounds of the plan (`fast_verdict`), with the controls of 4,096 and 1,000 bytes.
    Fast,
    /// `data-atomic`: the atomicity of the large calls, the lease, the signals in the middle of a
    /// call, `fork`, SCM_RIGHTS, the pages of the window, and a restart of the service mid-call.
    Atomic,
    /// `data-steps`: the service built with the steps and the counts, under `-icount`: the 64 MiB
    /// of `Fast` with a stat of another file beside it, and the checks of `Atomic` with shorter loops.
    Steps,
}

impl Mode {
    /// The role of the C program and the name of the mode.
    pub fn role(self) -> &'static str {
        match self {
            Mode::Read => "run",
            Mode::Write => "write-run",
            Mode::Cap => "cap-run",
            Mode::Full => "full-run",
            Mode::Restart => "restart-run",
            Mode::Throughput => "throughput-run",
            Mode::Fast => "fast-run",
            Mode::Atomic => "atomic-run",
            Mode::Steps => "steps-run",
        }
    }

    fn image(self) -> &'static str {
        match self {
            Mode::Read => "boot-data-posix.img",
            Mode::Write => "boot-data-posix-write.img",
            Mode::Cap => "boot-data-posix-cap.img",
            Mode::Full => "boot-data-posix-full.img",
            Mode::Restart => "boot-data-posix-restart.img",
            Mode::Throughput => "boot-data-posix-throughput.img",
            Mode::Fast => "boot-data-posix-fast.img",
            Mode::Atomic => "boot-data-posix-atomic.img",
            Mode::Steps => "boot-data-posix-steps.img",
        }
    }

    /// The checks of the mode, in the order the probe runs them: the line of each is `posix-data:
    /// <name> ok`.
    pub fn checks(self) -> &'static [&'static str] {
        match self {
            Mode::Read => &READ_CHECKS,
            Mode::Write => &WRITE_CHECKS,
            Mode::Cap => &["directory cap"],
            Mode::Full => &["enospc at the reserve then unlink"],
            Mode::Restart => &[
                "stale descriptor EIO",
                "close of a stale descriptor",
                "open after restart",
                "current directory reopened",
            ],
            Mode::Throughput => &["dd 64 MiB there and back"],
            Mode::Fast => &[
                "dd 64 MiB through the window",
                "dd bs 4096 control",
                "dd bs 1000 control",
            ],
            Mode::Atomic => &ATOMIC_CHECKS,
            Mode::Steps => &STEPS_CHECKS,
        }
    }

    fn passed(self) -> &'static str {
        match self {
            Mode::Read => "posix-data: read checks passed",
            Mode::Write => "posix-data: write checks passed",
            Mode::Cap => "posix-data: cap checks passed",
            Mode::Full => "posix-data: full checks passed",
            Mode::Restart => "posix-data: restart checks passed",
            Mode::Throughput => "posix-data: throughput checks passed",
            Mode::Fast => "posix-data: fast checks passed",
            Mode::Atomic => "posix-data: atomic checks passed",
            Mode::Steps => "posix-data: steps checks passed",
        }
    }

    /// The seconds the boot may take: the reads of the volume dominate the long modes (the cap: about
    /// 3 million reads, the reserve: 31,000 messages of 1,012 bytes at about 1.4 ms each).
    fn limit(self) -> std::time::Duration {
        std::time::Duration::from_secs(match self {
            Mode::Read => 180,
            Mode::Write => 20 * 60,
            Mode::Cap => 40 * 60,
            Mode::Full => 20 * 60,
            Mode::Restart => 10 * 60,
            Mode::Throughput => 30 * 60,
            Mode::Fast => 30 * 60,
            Mode::Atomic => 15 * 60,
            Mode::Steps => 60 * 60,
        })
    }
}

/// The checks of the atomic role, in the order the probe runs them.
pub const ATOMIC_CHECKS: [&str; 12] = [
    "1 MiB writes and reads never mix",
    "the service keeps no cell mapped",
    "O_APPEND 200 KiB records whole",
    "inline parts atomic",
    "lease lapses after 1 s",
    "siglongjmp out of a handler returns the cell",
    "thread exit mid-call returns the cell",
    "handler write during a long write",
    "fork in a handler whose child returns",
    "fork and scm_rights with windows",
    "window pages come back",
    "restart during a long write",
];

/// The checks of the steps role: the large write with a stat beside it, then the atomic checks that
/// do not depend on the time (a lease lasts a second, an instruction costs 16 ns under `-icount`).
pub const STEPS_CHECKS: [&str; 6] = [
    "dd 64 MiB with a stat of another file",
    "1 MiB writes and reads never mix",
    "the service keeps no cell mapped",
    "O_APPEND 200 KiB records whole",
    "fork and scm_rights with windows",
    "window pages come back",
];

/// The checks of the read role.
pub const READ_CHECKS: [&str; 28] = [
    "read pub whole",
    "pread",
    "lseek",
    "stat pub",
    "fstat equals stat",
    "lstat equals stat",
    "stat directories",
    "stat owners and modes",
    "readdir d_ino equals st_ino",
    "readdir 300 entries once",
    "rewinddir telldir seekdir",
    "access as root",
    "description survives setuid",
    "modes decide for user 1000",
    "closed directory hides file",
    "chdir fchdir relative",
    "openat fstatat faccessat",
    "fork shares the position",
    "spawn keeps the descriptor",
    "exec keeps the descriptor",
    "cloexec closed",
    "clofork stays with the parent",
    "set-ID program reads the descriptor",
    "real and effective access",
    "datax is the RAM service",
    "errno for bad paths",
    "statvfs",
    "realpath",
];

/// The checks of the write role.
pub const WRITE_CHECKS: [&str; 21] = [
    "create with umask 027",
    "create owner is the effective uid",
    "write pwrite and read back",
    "O_APPEND from two processes 2000 lines",
    "fork shares the write position",
    "ftruncate grows with zeros",
    "fsync returns",
    "unlink while open reads on",
    "rename over an open file",
    "rename of directories and across",
    "rmdir non-empty and cwd",
    "times and chmod of an open file",
    "chown by 1000",
    "sticky directory",
    "a non-owner cannot write",
    "setuid then write",
    "set-ID program writes through the descriptor",
    "fsize EFBIG and SIGXFSZ",
    "link symlink lock and exec refused",
    "scm_rights passes a data descriptor",
    "access W_OK utimensat and O_EXCL",
];

const PREFIX: &str = "posix-data: ";

/// Reads the lines of the probe. Each check has exactly one line `ok`, in the order of `CHECKS`
/// (the lines of the children, which print nothing but a failure, may stand between them); no line
/// says a check failed; the line of the end comes once, after every check. The lines come glued to
/// the kernel's and the services' lines, so the text is looked for inside the line.
pub fn read_lines(lines: &[String], mode: Mode) -> Result<(), String> {
    registered(lines)?;
    let (checks, passed) = (mode.checks(), mode.passed());
    let mine: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.find(PREFIX).map(|at| &l[at..]))
        .collect();
    if let Some(bad) = mine.iter().find(|l| {
        l.contains("check failed") || l.ends_with(" FAILED") || l.contains(" checks failed")
    }) {
        let shown: Vec<&&str> = mine.iter().filter(|l| !l.ends_with(" ok")).collect();
        return Err(format!("posix-data: {bad}; the failures: {shown:?}"));
    }
    let mut next = 0;
    for line in &mine {
        if *line == passed {
            if next != checks.len() {
                return Err(format!(
                    "the end came after {next} of {} checks",
                    checks.len()
                ));
            }
            next = usize::MAX;
            continue;
        }
        let Some(name) = line
            .strip_prefix(PREFIX)
            .and_then(|rest| rest.strip_suffix(" ok"))
        else {
            continue;
        };
        if next == usize::MAX {
            return Err(format!("a line after the end: {line:?}"));
        }
        match checks.get(next) {
            Some(expected) if *expected == name => next += 1,
            Some(expected) => {
                return Err(format!(
                    "check {:?} came where {expected:?} was due (a repeat, a gap or a probe that started again)",
                    name
                ));
            }
            None => return Err(format!("an extra check line {line:?}")),
        }
    }
    match next {
        usize::MAX => Ok(()),
        n if n < checks.len() => Err(format!(
            "the probe stopped after {n} of {} checks: the next is {:?}",
            checks.len(),
            checks[n]
        )),
        _ => Err(format!("no line {passed:?}")),
    }
}

/// The data service says its root is registered with the process service (`rt::roots`: `datafs: root
/// registered with the process service`, or after some failed attempts). Without it no process gets a
/// session and every call under `/data` answers EIO, so the run fails here, early, with what the
/// service said about it.
fn registered(lines: &[String]) -> Result<(), String> {
    if lines.iter().any(|l| {
        l.contains("datafs: root registered with the process service")
            || l.contains("datafs: root registered after ")
    }) {
        return Ok(());
    }
    let said: Vec<&str> = lines
        .iter()
        .filter(|l| {
            l.contains("datafs: no notary session")
                || l.contains("datafs: registering the root failed")
                || l.contains("datafs: no thread to register the root")
        })
        .map(String::as_str)
        .collect();
    Err(format!(
        "the data service's root was not registered with the process service, so no process has a session and every call under /data answers EIO: {}",
        if said.is_empty() {
            "the service printed no line about its root".to_owned()
        } else {
            format!("it said {said:?}")
        }
    ))
}

/// The service ended on the request of the probe and was started again: its line of the end, and its
/// root registered twice (the old instance's and the new one's).
pub fn restarted(lines: &[String]) -> Result<(), String> {
    if !lines
        .iter()
        .any(|l| l.contains("datafs: probe-restart: the service ends"))
    {
        return Err("the service never said it ended on the request of the probe".into());
    }
    let registrations = lines
        .iter()
        .filter(|l| l.contains("datafs: root registered"))
        .count();
    if registrations < 2 {
        return Err(format!(
            "the new instance of the service registered its root {} times in all, two expected (one for each instance)",
            registrations
        ));
    }
    Ok(())
}

/// The disk of the run: a file of the process's name, removed at the end.
struct Disk(PathBuf);

impl Drop for Disk {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The size of the disk file: the layout takes 1 MiB for the table, `store` the half, and the data
/// partition of 31 MiB holds the volume of the probe (about 1 MiB of files).
const DISK_BYTES: u64 = 64 << 20;
/// The throughput mode writes 64 MiB: a disk of 256 MiB has a data partition of 127 MiB.
const THROUGHPUT_DISK_BYTES: u64 = 256 << 20;
const ENDS: &str = "init: posix-data ended: ";
const ENDED: &str = "init: posix-data ended: exit code 0, not restarted";

/// `cargo xtask data-posix [write|cap|full|restart|throughput|fast|atomic|steps|crash [N]]`, and
/// `atomic-break FEATURE`.
pub fn command(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => probe(Mode::Read, machine),
        Some("write") if args.len() == 1 => probe(Mode::Write, machine),
        Some("cap") if args.len() == 1 => probe(Mode::Cap, machine),
        Some("full") if args.len() == 1 => probe(Mode::Full, machine),
        Some("restart") if args.len() == 1 => probe(Mode::Restart, machine),
        Some("throughput") if args.len() == 1 => probe(Mode::Throughput, machine),
        Some("fast") if args.len() == 1 => probe(Mode::Fast, machine),
        Some("atomic") if args.len() == 1 => probe(Mode::Atomic, machine),
        Some("steps") if args.len() == 1 => steps(machine),
        Some("steps-icount") if args.len() == 1 => steps_icount(machine),
        Some("steps-budget") if args.len() == 1 => steps_budget(machine),
        Some("atomic-break") if args.len() == 2 => atomic_break(&args[1], machine),
        Some("crash") => crash(&args[1..], machine),
        Some(other) => Err(format!(
            "data-posix [write|cap|full]: unknown argument {other}"
        )),
    }
}

/// How a boot differs from the plain one: the CPUs (0 for the machine's own), the clock that follows
/// the instructions, and a deliberate break of the service (a feature of `datafsd`).
#[derive(Clone, Copy, Default)]
pub struct Boot {
    pub cpus: usize,
    pub icount: bool,
}

/// The programs of the image of `mode`, with the break `brk` in the service when there is one.
fn programs_of(mode: Mode, breaks: &[&'static str]) -> Vec<ImageProgram> {
    let base: &[ImageProgram] = match mode {
        Mode::Restart => &PROGRAMS_RESTART,
        Mode::Fast => &PROGRAMS_FAST,
        Mode::Atomic => &PROGRAMS_ATOMIC,
        Mode::Steps => &PROGRAMS_STEPS,
        _ => &PROGRAMS,
    };
    let mut programs = base.to_vec();
    if !breaks.is_empty() {
        let at = programs
            .iter()
            .position(|p| p.0 == "datafsd")
            .expect("the image has the data service");
        let mut features: Vec<&'static str> = programs[at].3.to_vec();
        features.extend_from_slice(breaks);
        programs[at].3 = Box::leak(features.into_boxed_slice());
    }
    programs
}

/// The boot of one mode: the image with the role of the mode, a volume made offline, QEMU until the
/// probe ends; the lines and the seconds it took.
fn boot(mode: Mode, machine: &qemu::Machine, how: Boot) -> Result<(qemu::Outcome, u64), String> {
    boot_with(mode, machine, how, &[])
}

/// `boot` with deliberate breaks (features of `datafsd`) in the service.
fn boot_with(
    mode: Mode,
    machine: &qemu::Machine,
    how: Boot,
    breaks: &[&'static str],
) -> Result<(qemu::Outcome, u64), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let programs = programs_of(mode, breaks);
    let image = write_boot_image_files(
        mode.image(),
        &programs,
        BOOT_PROFILE,
        &[("STAFETO_DATA_POSIX_MODE", mode.role())],
        Vec::new(),
    )?;
    let disk = Disk(std::env::temp_dir().join(format!(
        "stafeto-data-posix-{}-{}.img",
        std::process::id(),
        mode.role()
    )));
    let big = matches!(
        mode,
        Mode::Throughput | Mode::Fast | Mode::Atomic | Mode::Steps
    );
    crate::data_image::make_posix_volume(
        &disk.0,
        if big {
            THROUGHPUT_DISK_BYTES
        } else {
            DISK_BYTES
        },
    )?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&disk.0, None));
    if how.cpus > 0 {
        cmd.args(["-smp", &how.cpus.to_string()]);
    }
    if how.icount {
        cmd.args(["-icount", "shift=4,sleep=on"]);
    }
    let started = std::time::Instant::now();
    let output = run_until(cmd, mode.limit(), Some(ENDS), &kernel.elf)?;
    Ok((output, started.elapsed().as_secs()))
}

/// One mode: the image with the role of the mode, a volume made offline, QEMU until the probe ends,
/// and the lines read.
pub fn probe(mode: Mode, machine: &qemu::Machine) -> Result<(), String> {
    run(mode, machine, Boot::default())
}

fn run(mode: Mode, machine: &qemu::Machine, how: Boot) -> Result<(), String> {
    let (output, seconds) = boot(mode, machine, how)?;
    read_lines(&output.lines, mode)?;
    if matches!(mode, Mode::Restart | Mode::Atomic) {
        restarted(&output.lines)?;
    }
    let report = match mode {
        Mode::Fast => Some(fast_verdict(&output.lines)?),
        Mode::Steps => Some(steps_verdict(&output.lines, how.cpus)?),
        _ => None,
    };
    qemu::expect_stopped_on(&output, ENDED)?;
    if let Some(report) = report {
        println!("{report}");
    }
    println!(
        "data-posix {:?} on {}: {} checks of /data in the POSIX layer over the data file service in {} s: ok",
        mode,
        machine.name,
        mode.checks().len(),
        seconds
    );
    Ok(())
}

/// `data-steps`: the steps of the service under `-icount` on one CPU (`steps_icount`), then the CPU
/// time of the worker's parts in real time on two CPUs, where the table gives the worker the budget
/// `work` (`steps_budget`).
pub fn steps(machine: &qemu::Machine) -> Result<(), String> {
    steps_icount(machine)?;
    steps_budget(machine)
}

/// The steps of the loop, the map and unmap of a cell, and the stat of another file, under `-icount`
/// on one CPU: the instruction count is the clock, so the figures repeat.
pub fn steps_icount(machine: &qemu::Machine) -> Result<(), String> {
    run(
        Mode::Steps,
        machine,
        Boot {
            cpus: 1,
            icount: true,
        },
    )
}

/// The CPU time of the parts by the budget `work`, in real time on two CPUs.
pub fn steps_budget(machine: &qemu::Machine) -> Result<(), String> {
    run(
        Mode::Steps,
        machine,
        Boot {
            cpus: 2,
            icount: false,
        },
    )
}

/// The deliberate breaks of the service that `data-atomic` must catch, and the check each fails.
pub const BREAKS: [(&str, &str); 3] = [
    (
        "break-datafs-lease-hold",
        "1 MiB writes and reads never mix",
    ),
    ("break-datafs-append-end", "O_APPEND 200 KiB records whole"),
    ("break-datafs-cell-kept", "the service keeps no cell mapped"),
];

/// `cargo xtask data-posix atomic-break FEATURE[,FEATURE]`: the atomic probe on a service with the
/// breaks (the features that do not spoil each other's check go in one boot); it passes when the check
/// of each break FAILED.
pub fn atomic_break(features: &str, machine: &qemu::Machine) -> Result<(), String> {
    let mut chosen: Vec<(&'static str, &'static str)> = Vec::new();
    for name in features.split(',') {
        let Some(&entry) = BREAKS.iter().find(|b| b.0 == name) else {
            return Err(format!(
                "data-posix atomic-break: {name} is not one of {:?}",
                BREAKS.map(|b| b.0)
            ));
        };
        chosen.push(entry);
    }
    let (output, seconds) = boot_with(
        Mode::Atomic,
        machine,
        Boot::default(),
        &chosen.iter().map(|b| b.0).collect::<Vec<_>>(),
    )?;
    let failed: Vec<&str> = output
        .lines
        .iter()
        .filter_map(|l| l.find(PREFIX).map(|at| &l[at..]))
        .filter(|l| l.ends_with(" FAILED"))
        .collect();
    for (feature, check) in &chosen {
        let want = format!("{PREFIX}{check} FAILED");
        if !failed.iter().any(|l| **l == *want) {
            return Err(format!(
                "data-posix atomic-break: {feature} did not fail {check:?}; the checks that failed: {failed:?}"
            ));
        }
        println!("data-posix atomic-break: {feature} is caught by {check:?}");
    }
    println!("data-posix atomic-break: all that failed: {failed:?} (in {seconds} s)");
    Ok(())
}

// ---------------------------------------------------------------- the verdicts

/// The write of 64 MiB takes at most this many milliseconds under QEMU (twice the model of the plan,
/// 2 to 2.5 s), and the read of 64 MiB at most this many (the model: 4 to 5 s).
pub const FAST_WRITE_MS_MAX: u64 = 6_000;
pub const FAST_READ_MS_MAX: u64 = 8_000;
/// The reads of the disk for each block of 4 KiB of the file in the read, at most.
pub const FAST_READS_PER_BLOCK_MAX: f64 = 3.0;
/// The blocks of the 64 MiB file.
const FAST_BLOCKS: u64 = 64 * 1024 * 1024 / 4096;
/// The controls of 1,000 bytes (the old path) run at least this fast, in KiB/s: the speed of 0.6.0
/// was 2,106 (write) and 1,352 (read) on 64 MiB.
const FAST_CONTROL_KIB_MIN: u64 = 500;

/// The digits that follow the first `key` in `line`.
fn number_after(line: &str, key: &str) -> Option<u64> {
    let rest = &line[line.find(key)? + key.len()..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// The digits that end the text before the first `key` in `line`.
fn number_before(line: &str, key: &str) -> Option<u64> {
    let head = &line[..line.find(key)?];
    let digits: String = head
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits.parse().ok()
}

/// What a line `posix-data: fast TAG write|read ...` tells.
#[derive(Debug, PartialEq, Eq)]
struct Phase {
    ms: u64,
    kib_s: u64,
    cell: u64,
    inline: u64,
    /// The calls of a write, the mismatches of a read.
    last: u64,
}

fn phase(lines: &[String], tag: &str, what: &str) -> Result<Phase, String> {
    let key = format!("posix-data: fast {tag} {what} ");
    let line = lines
        .iter()
        .find(|l| l.contains(&key))
        .ok_or_else(|| format!("data-fast: no line {key:?}"))?;
    let read = || -> Option<Phase> {
        Some(Phase {
            ms: number_after(line, " in ")?,
            kib_s: number_after(line, " ms: ")?,
            cell: number_before(line, " cell parts")?,
            inline: number_before(line, " inline parts")?,
            last: if what == "write" {
                number_before(line, " calls")?
            } else {
                number_before(line, " mismatches")?
            },
        })
    };
    read().ok_or_else(|| format!("data-fast: the line is not read: {line:?}"))
}

/// The reads of the disk the service counted in the read of the big file: the counter before the
/// mark `begin` and the first one after the mark `end` (the service says its counters after 100 ms of
/// quiet, and the probe waits 300 ms at each mark).
fn reads_of_the_read(lines: &[String]) -> Result<u64, String> {
    let (mut last, mut begin, mut ended) = (None, None, false);
    for l in lines {
        if l.contains("posix-data: fast mark begin read") {
            begin = last;
        } else if l.contains("posix-data: fast mark end read") {
            ended = true;
        } else if let Some(reads) = number_after(l, "datafs: disk reads ") {
            if ended {
                let before = begin.ok_or("data-fast: no counter of the disk before the read")?;
                return reads
                    .checked_sub(before)
                    .ok_or_else(|| "data-fast: the counter of the disk went back".to_owned());
            }
            last = Some(reads);
        }
    }
    Err("data-fast: the service said no counter of the disk after the read (is it built with `count`?)".into())
}

/// The verdict of `data-fast` on the lines: the bounds of the plan (section 7.1) and the controls.
/// The report: the times, the parts and the reads of the disk for each block.
pub fn fast_verdict(lines: &[String]) -> Result<String, String> {
    let write = phase(lines, "big", "write")?;
    let read = phase(lines, "big", "read")?;
    let parts = 64 * 1024 * 1024 / (64 * 1024);
    if write.cell < parts || write.inline != 0 || read.cell < parts || read.inline != 0 {
        return Err(format!(
            "data-fast: 64 MiB went in {} cell parts and {} inline parts (write), {} and {} (read), {parts} cell parts of 64 KiB expected",
            write.cell, write.inline, read.cell, read.inline
        ));
    }
    if read.last != 0 {
        return Err(format!(
            "data-fast: {} blocks of 1 MiB read back differ from what was written",
            read.last
        ));
    }
    if write.ms > FAST_WRITE_MS_MAX {
        return Err(format!(
            "data-fast: the write of 64 MiB took {} ms, over {FAST_WRITE_MS_MAX} ms",
            write.ms
        ));
    }
    if read.ms > FAST_READ_MS_MAX {
        return Err(format!(
            "data-fast: the read of 64 MiB took {} ms, over {FAST_READ_MS_MAX} ms",
            read.ms
        ));
    }
    let reads = reads_of_the_read(lines)?;
    let per_block = reads as f64 / FAST_BLOCKS as f64;
    if per_block > FAST_READS_PER_BLOCK_MAX {
        return Err(format!(
            "data-fast: {reads} reads of the disk for {FAST_BLOCKS} blocks, {per_block:.2} for each, over {FAST_READS_PER_BLOCK_MAX}"
        ));
    }
    // The control of 4,096 bytes: a call of one part through a cell; of 1,000: the old path, by
    // messages, at the speed of the release before.
    let (w4, r4) = (
        phase(lines, "bs4096", "write")?,
        phase(lines, "bs4096", "read")?,
    );
    let (w1, r1) = (
        phase(lines, "bs1000", "write")?,
        phase(lines, "bs1000", "read")?,
    );
    let calls4 = 4 * 1024 * 1024 / 4096;
    if w4.cell != calls4 || w4.inline != 0 || r4.cell != calls4 || r4.inline != 0 {
        return Err(format!(
            "data-fast: bs 4096 went in {}+{} parts (write cell+inline) and {}+{} (read), {calls4} cell parts expected",
            w4.cell, w4.inline, r4.cell, r4.inline
        ));
    }
    if w1.cell + w1.inline + r1.cell + r1.inline != 0 {
        return Err(format!(
            "data-fast: bs 1000 is one message a call and made {} parts",
            w1.cell + w1.inline + r1.cell + r1.inline
        ));
    }
    if r4.last != 0 || r1.last != 0 {
        return Err("data-fast: a control read back other bytes than it wrote".into());
    }
    for (what, kib) in [("write", w1.kib_s), ("read", r1.kib_s)] {
        if kib < FAST_CONTROL_KIB_MIN {
            return Err(format!(
                "data-fast: the control of 1,000 bytes {what} ran at {kib} KiB/s, under {FAST_CONTROL_KIB_MIN}"
            ));
        }
    }
    Ok(format!(
        "data-fast: write 64 MiB {} ms ({} KiB/s, bound {FAST_WRITE_MS_MAX}), read {} ms ({} KiB/s, bound {FAST_READ_MS_MAX}), {reads} disk reads in the read = {per_block:.2} for each of {FAST_BLOCKS} blocks (bound {FAST_READS_PER_BLOCK_MAX}); controls 4 MiB: bs 4096 write {} read {} KiB/s, bs 1000 write {} read {} KiB/s",
        write.ms, write.kib_s, read.ms, read.kib_s, w4.kib_s, r4.kib_s, w1.kib_s, r1.kib_s
    ))
}

/// The model of the worker's CPU time for a part of 64 KiB (plan section 5: 0.7 ms), and the most
/// the mean of the parts may be: twice it.
pub const PART_CPU_MODEL_US: u64 = 700;
pub const PART_CPU_MEAN_MAX_US: u64 = 2 * PART_CPU_MODEL_US;
/// The service's step of a part, in ticks, the most (the goal of READ and WRITE).
const PART_STEP_MAX: u64 = 6_000;

/// What a line `datafs: parts write|read n N cpu mean M us max X us total T us own mean M us max X us
/// span S us` tells (all in microseconds).
#[derive(Debug, PartialEq, Eq)]
pub struct Parts {
    pub n: u64,
    pub cpu_mean: u64,
    pub cpu_max: u64,
    pub cpu_total: u64,
    pub own_mean: u64,
    pub own_max: u64,
    pub span: u64,
}

/// The parts of a 64 MiB pass (`PASS_PARTS` of 64 KiB).
const PASS_PARTS: u64 = 1024;

/// The first line of the service about the parts of the direction `what` (`write` or `read`) that
/// counts a whole pass of 64 MiB: the totals are cumulative, and the pass of `data-fast` is the first
/// work of the run, so this line is its own (the figures of the later checks are not in it).
pub fn parts_line(lines: &[String], what: &str) -> Option<Parts> {
    let key = format!("datafs: parts {what} ");
    lines.iter().filter(|l| l.contains(&key)).find_map(|line| {
        let words: Vec<&str> = line[line.find(&key)? + key.len()..]
            .split_whitespace()
            .collect();
        let at = |i: usize| -> Option<u64> { words.get(i)?.parse().ok() };
        // n N cpu mean M us max X us total T us own mean M us max X us span S us
        let parts = Parts {
            n: at(1)?,
            cpu_mean: at(4)?,
            cpu_max: at(7)?,
            cpu_total: at(10)?,
            own_mean: at(14)?,
            own_max: at(17)?,
            span: at(20)?,
        };
        (parts.n >= PASS_PARTS).then_some(parts)
    })
}

/// The longest job of any method the service told (`datafs: job <method> longest N us`), in us.
fn longest_job_us(lines: &[String]) -> u64 {
    lines
        .iter()
        .filter_map(|l| {
            let at = l.find("datafs: job ")?;
            number_after(&l[at..], " longest ")
        })
        .max()
        .unwrap_or(0)
}

/// The verdict of `data-steps` on the lines of a run on `cpus` CPUs: one CPU is the run under `-icount`,
/// two CPUs the run in real time. On one CPU under `-icount` the steps count: the loop's steps (0.9 B, a
/// method of the parts 6,000 ticks) and the map and unmap of a cell (B) are judged, and the worker's own
/// time for a part is told (an instruction is 16 ns there). On two CPUs the figures of the steps are told
/// and judged by nothing (the instruction count of two CPUs is not one clock: the unmap of a cell waits
/// for the other CPU); there the worker has the budget `work`, and the CPU time of a part of 64 KiB (the
/// mean at most twice the model) comes from it. A stat of another file during the write is judged
/// against four jobs on both. The report: the figures.
pub fn steps_verdict(lines: &[String], cpus: usize) -> Result<String, String> {
    let rows = crate::step_line::longest(lines, crate::data_probe::DATAFS_TAG);
    for kind in [37, 39] {
        if !rows.iter().any(|r| r.0 == kind) {
            return Err(format!(
                "data-steps: no step of the method {kind}: {rows:?}"
            ));
        }
    }
    let (map, unmap) = if cpus == 1 {
        crate::step_line::within_b(
            lines,
            crate::data_probe::DATAFS_TAG,
            crate::step_line::Kinds::All,
        )?;
        if let Some(row) = rows.iter().find(|r| r.1 > crate::blk_probe::STEP_MAX) {
            return Err(format!(
                "data-steps: a step past 0.9 of term B ({}): {row:?}",
                crate::blk_probe::STEP_MAX
            ));
        }
        if let Some(row) = rows
            .iter()
            .find(|r| (36..=42).contains(&r.0) && r.1 > PART_STEP_MAX)
        {
            return Err(format!(
                "data-steps: a step of a method of the parts past {PART_STEP_MAX} ticks: {row:?}"
            ));
        }
        crate::data_probe::cell_verdict(lines)?
    } else {
        crate::data_probe::cell_longest(lines)?
    };
    let stretches = crate::data_probe::worker_verdict(lines)?;
    let histogram = |what: &str| {
        let key = format!("datafs: cell {what} ticks ");
        lines
            .iter()
            .rev()
            .find_map(|l| l.find(&key).map(|at| l[at + key.len()..].to_owned()))
            .unwrap_or_default()
    };
    let mut report = format!(
        "data-steps on {cpus} CPUs{}: steps of the loop (kind, judged ticks, detail) {rows:?}; the longest map of a cell {map} ticks, unmap {unmap} (B {}); calls of a cell map by length [{}], unmap [{}]; worker wall stretches {stretches:?}",
        if cpus == 1 {
            " under -icount"
        } else {
            " in real time (the steps are only told)"
        },
        crate::TERM_B,
        histogram("map"),
        histogram("unmap")
    );
    for what in ["write", "read"] {
        let parts = parts_line(lines, what)
            .ok_or_else(|| format!("data-steps: no line of the parts {what} of the worker"))?;
        report.push_str(&format!(
            "; parts {what}: {} of 64 KiB, own mean {} us max {} us (wall less the disk, preemptions included{})",
            parts.n,
            parts.own_mean,
            parts.own_max,
            if cpus == 1 {
                format!(
                    "; at 16 ns an instruction that is about {} instructions on average",
                    parts.own_mean * 1000 / 16
                )
            } else {
                String::new()
            }
        ));
        if cpus >= 2 {
            if parts.cpu_total == 0 {
                return Err(format!(
                    "data-steps: the budget of the worker counted no CPU time for the parts {what}"
                ));
            }
            if parts.cpu_mean > PART_CPU_MEAN_MAX_US {
                return Err(format!(
                    "data-steps: a part of 64 KiB ({what}) took {} us of CPU on average by the budget `work`, over twice the model ({PART_CPU_MEAN_MAX_US} us); the longest {} us",
                    parts.cpu_mean, parts.cpu_max
                ));
            }
            report.push_str(&format!(
                ", CPU by the budget mean {} us (model {PART_CPU_MODEL_US}) max {} us, the worker's share while the parts ran {}.{} % ({} us of {} us)",
                parts.cpu_mean,
                parts.cpu_max,
                parts.cpu_total * 100 / parts.span.max(1),
                parts.cpu_total * 1000 / parts.span.max(1) % 10,
                parts.cpu_total,
                parts.span
            ));
        }
    }
    let stat_line = lines
        .iter()
        .find(|l| l.contains("posix-data: stat of another file during the write: "))
        .ok_or("data-steps: no line of the stat beside the write")?;
    let (calls, longest) = (
        number_after(stat_line, "write: ").unwrap_or(0),
        number_after(stat_line, "longest ").unwrap_or(u64::MAX),
    );
    let job = longest_job_us(lines);
    let bound = 4 * job + 5_000;
    if calls == 0 || longest > bound {
        return Err(format!(
            "data-steps: a stat of another file during the write took {longest} us over {calls} calls, over four jobs ({job} us the longest) and 5 ms = {bound} us"
        ));
    }
    report.push_str(&format!(
        "; stat of another file during the write: {calls} calls, longest {longest} us (four jobs of {job} us and 5 ms: {bound} us)"
    ));
    Ok(report)
}

/// The machine is cut after the sector the point names was written (the service built for the crash
/// runs stops there and the host kills the machine on its line), and a second boot on the same disk
/// verifies: every file whose line `posix-data: synced N` came out is whole, an unsynced file is
/// absent or a prefix of what was written, the file renamed over another is one whole generation and
/// not older than the last rename the host saw, and the volume takes a write.
const POINTS: u64 = 12;

/// The disk, the image and the boot of one crash run: the lines up to the cut or to the end.
fn crash_boot(
    kernel: &crate::Artifacts,
    machine: &qemu::Machine,
    disk: &std::path::Path,
    name: &str,
    env: &[(&str, &str)],
    marker: &str,
) -> Result<Vec<String>, String> {
    let programs: &[ImageProgram] = if env.iter().any(|(k, _)| *k == "STAFETO_DATAFS_CRASH_AT") {
        &PROGRAMS_CRASH
    } else {
        &PROGRAMS
    };
    let image = write_boot_image_files(name, programs, BOOT_PROFILE, env, Vec::new())?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(disk, None));
    let output = run_until(
        cmd,
        std::time::Duration::from_secs(10 * 60),
        Some(marker),
        &kernel.elf,
    )?;
    Ok(output.lines)
}

/// The sectors the sequence writes, from a run of the service built for the crash tests that does
/// not stop (its STATFS at the end prints the count).
fn sectors_of_the_sequence(
    kernel: &crate::Artifacts,
    machine: &qemu::Machine,
) -> Result<u64, String> {
    let disk = Disk(std::env::temp_dir().join(format!(
        "stafeto-data-posix-{}-count.img",
        std::process::id()
    )));
    crate::data_image::make_posix_volume(&disk.0, DISK_BYTES)?;
    let lines = crash_boot(
        kernel,
        machine,
        &disk.0,
        "boot-data-posix-crash.img",
        &[
            ("STAFETO_DATA_POSIX_MODE", "crash-run"),
            ("STAFETO_DATAFS_CRASH_AT", "0"),
        ],
        ENDS,
    )?;
    if !lines
        .iter()
        .any(|l| l.contains("posix-data: crash run finished"))
    {
        return Err(format!(
            "data-posix crash: the counting run did not finish: {:?}",
            tail(&lines)
        ));
    }
    qemu::number_after(&lines, "datafs: written ").ok_or_else(|| {
        "data-posix crash: the service did not say how many sectors the sequence wrote".into()
    })
}

fn tail(lines: &[String]) -> Vec<&String> {
    lines
        .iter()
        .rev()
        .take(12)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

/// The last synced file and the last rename the lines tell.
pub fn seen_before_the_cut(lines: &[String]) -> (u32, u32) {
    let last = |prefix: &str| {
        lines
            .iter()
            .filter_map(|l| {
                let at = l.find(prefix)?;
                l[at + prefix.len()..]
                    .split(|c: char| !c.is_ascii_digit())
                    .next()?
                    .parse()
                    .ok()
            })
            .max()
            .unwrap_or(0)
    };
    (last("posix-data: synced "), last("posix-data: renamed "))
}

/// The lines of the verifying boot: the three checks with the numbers the host saw, the end.
pub fn read_verify_lines(lines: &[String], synced: u32) -> Result<(), String> {
    registered(lines)?;
    if let Some(bad) = lines
        .iter()
        .find(|l| l.contains("posix-data: check failed") || l.contains("posix-data: verify failed"))
    {
        return Err(format!("the verifying boot: {bad}"));
    }
    for want in [
        format!("posix-data: after cut synced files whole 1..{synced} ok"),
        "posix-data: after cut the renamed file is one whole generation ok".to_owned(),
        "posix-data: after cut the volume takes a write ok".to_owned(),
        "posix-data: verify checks passed".to_owned(),
    ] {
        if !lines.iter().any(|l| l.contains(&want)) {
            return Err(format!("the verifying boot has no line {want:?}"));
        }
    }
    Ok(())
}

fn crash_point(
    kernel: &crate::Artifacts,
    machine: &qemu::Machine,
    point: u64,
) -> Result<(), String> {
    let disk = Disk(std::env::temp_dir().join(format!(
        "stafeto-data-posix-{}-crash-{point}.img",
        std::process::id()
    )));
    crate::data_image::make_posix_volume(&disk.0, DISK_BYTES)?;
    let marker = format!("datafs: crash point {point}");
    let cut = crash_boot(
        kernel,
        machine,
        &disk.0,
        "boot-data-posix-crash.img",
        &[
            ("STAFETO_DATA_POSIX_MODE", "crash-run"),
            ("STAFETO_DATAFS_CRASH_AT", &point.to_string()),
        ],
        &marker,
    )?;
    if !cut.iter().any(|l| l.contains(&marker)) {
        return Err(format!(
            "data-posix crash {point}: the service never said {marker:?}: {:?}",
            tail(&cut)
        ));
    }
    let (synced, renamed) = seen_before_the_cut(&cut);
    let lines = crash_boot(
        kernel,
        machine,
        &disk.0,
        "boot-data-posix-verify.img",
        &[
            ("STAFETO_DATA_POSIX_MODE", "verify-run"),
            ("STAFETO_DATA_POSIX_MIN", &synced.to_string()),
            ("STAFETO_DATA_POSIX_RENAMED", &renamed.to_string()),
        ],
        ENDS,
    )?;
    read_verify_lines(&lines, synced).map_err(|e| format!("data-posix crash {point}: {e}"))?;
    println!(
        "data-posix crash {point}: cut after sector {point} ({synced} files synced, {renamed} renames seen), the next boot found every synced file whole and the renamed file one whole generation: ok"
    );
    Ok(())
}

/// `cargo xtask data-posix crash [N]`: 12 points spread over the sectors of the sequence, or the one
/// the argument names.
pub fn crash(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let points: Vec<u64> = match args.first() {
        Some(n) => vec![
            n.parse()
                .map_err(|_| format!("data-posix crash: {n} is not a number of sectors"))?,
        ],
        None => {
            let total = sectors_of_the_sequence(&kernel, machine)?;
            println!("data-posix crash: the sequence writes {total} sectors");
            let mut points: Vec<u64> = (1..=POINTS)
                .map(|k| (total * k / (POINTS + 1)).max(1))
                .collect();
            points.dedup();
            points
        }
    };
    for point in points {
        crash_point(&kernel, machine, point)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Vec<String> {
        good_of(Mode::Read)
    }

    fn good_of(mode: Mode) -> Vec<String> {
        let mut lines = vec![
            "init: starting".to_owned(),
            "datafs: root registered with the process service".to_owned(),
            "posix-abi: data: open /data/pub: step take_session status 0".to_owned(),
        ];
        lines.extend(mode.checks().iter().map(|c| format!("posix-data: {c} ok")));
        lines.push(mode.passed().to_owned());
        lines.push(ENDED.to_owned());
        lines
    }

    #[test]
    fn a_run_with_every_check_and_the_end_passes() {
        assert_eq!(read_lines(&good(), Mode::Read), Ok(()));
        // The lines come glued to another line's tail.
        let glued: Vec<String> = good().iter().map(|l| format!("[ 1.234] {l}")).collect();
        assert_eq!(read_lines(&glued, Mode::Read), Ok(()));
    }

    #[test]
    fn a_run_whose_root_was_not_registered_fails_early_and_says_what_the_service_said() {
        let mut none = good();
        none.retain(|l| !l.contains("root registered"));
        let error = read_lines(&none, Mode::Read).unwrap_err();
        assert!(error.contains("root was not registered") && error.contains("printed no line"));
        let mut refused = none.clone();
        refused.insert(
            1,
            "datafs: no notary session with the process service (ACCESS_DENIED): the root is not registered"
                .to_owned(),
        );
        assert!(
            read_lines(&refused, Mode::Read)
                .unwrap_err()
                .contains("no notary session")
        );
        let mut late = good();
        late[1] = "datafs: root registered after 3 failed attempts".to_owned();
        assert_eq!(read_lines(&late, Mode::Read), Ok(()));
    }

    #[test]
    fn a_failed_check_a_missing_check_and_a_missing_end_are_refused() {
        let mut failed = good();
        failed[5] = "posix-data: stat pub FAILED".to_owned();
        assert!(
            read_lines(&failed, Mode::Read)
                .unwrap_err()
                .contains("stat pub FAILED")
        );
        let mut line = good();
        line.insert(
            6,
            "posix-data: check failed at line 99: st.st_size == 5000 (errno 0)".to_owned(),
        );
        assert!(
            read_lines(&line, Mode::Read)
                .unwrap_err()
                .contains("check failed")
        );
        let mut summary = good();
        summary.insert(2, "posix-data: 2 checks failed".to_owned());
        assert!(read_lines(&summary, Mode::Read).is_err());
        let mut missing = good();
        missing.remove(7);
        assert!(read_lines(&missing, Mode::Read).is_err());
        let mut no_end = good();
        no_end.retain(|l| l != Mode::Read.passed());
        assert!(
            read_lines(&no_end, Mode::Read)
                .unwrap_err()
                .contains("no line")
        );
        let mut cut = good();
        cut.truncate(12);
        assert!(
            read_lines(&cut, Mode::Read)
                .unwrap_err()
                .contains("stopped after")
        );
    }

    #[test]
    fn a_repeat_a_swap_an_extra_line_and_an_early_end_are_refused() {
        let mut repeat = good();
        repeat.insert(5, "posix-data: read pub whole ok".to_owned());
        assert!(read_lines(&repeat, Mode::Read).is_err());
        let mut swapped = good();
        swapped.swap(4, 5);
        assert!(read_lines(&swapped, Mode::Read).is_err());
        let mut extra = good();
        let end = extra.iter().position(|l| l == Mode::Read.passed()).unwrap();
        extra.insert(end, "posix-data: something else ok".to_owned());
        assert!(read_lines(&extra, Mode::Read).is_err());
        let mut early = good();
        let end = early.iter().position(|l| l == Mode::Read.passed()).unwrap();
        let last = early.remove(end - 1);
        early.insert(end, last);
        assert!(read_lines(&early, Mode::Read).is_err());
        let mut after = good();
        after.insert(after.len() - 1, "posix-data: stat pub ok".to_owned());
        assert!(read_lines(&after, Mode::Read).is_err());
    }

    #[test]
    fn every_mode_passes_and_each_has_its_own_end() {
        for mode in [
            Mode::Read,
            Mode::Write,
            Mode::Cap,
            Mode::Full,
            Mode::Restart,
            Mode::Fast,
            Mode::Atomic,
            Mode::Steps,
        ] {
            assert_eq!(read_lines(&good_of(mode), mode), Ok(()), "{mode:?}");
            // The end of another mode is not the end of this one.
            let mut other = good_of(mode);
            let end = other.iter().position(|l| l == mode.passed()).unwrap();
            other[end] = Mode::Read.passed().replace("read", "wrong");
            assert!(read_lines(&other, mode).is_err(), "{mode:?}");
        }
        // A write run read as a read run has the wrong first check.
        assert!(read_lines(&good_of(Mode::Write), Mode::Read).is_err());
    }

    /// The names the function `role` of data.c passes to `run_check`.
    fn checks_of_function(source: &str, role: &str) -> Vec<String> {
        let at = source
            .find(&format!("static int {role}(void) {{"))
            .unwrap_or_else(|| panic!("data.c has no {role}"));
        let body = &source[at..];
        let end = body.find("\n}\n").unwrap();
        body[..end]
            .lines()
            .filter_map(|l| l.trim().strip_prefix("run_check(\""))
            .map(|rest| rest.split('"').next().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn the_lists_of_checks_are_the_ones_of_the_c_probe() {
        let source = include_str!("../../tests/posix-data/data.c");
        for (role, mode) in [
            ("first", Mode::Read),
            ("write_run", Mode::Write),
            ("cap_run", Mode::Cap),
            ("full_run", Mode::Full),
            ("restart_run", Mode::Restart),
            ("throughput_run", Mode::Throughput),
            ("fast_run", Mode::Fast),
            ("atomic_run", Mode::Atomic),
            ("steps_run", Mode::Steps),
        ] {
            let in_c = checks_of_function(source, role);
            assert_eq!(
                in_c,
                mode.checks(),
                "{role} of data.c and the list of {mode:?}"
            );
        }
    }

    fn verify_good(synced: u32) -> Vec<String> {
        vec![
            "datafs: root registered with the process service".to_owned(),
            format!("posix-data: after cut synced files whole 1..{synced} ok"),
            "posix-data: after cut the renamed file is one whole generation ok".to_owned(),
            "posix-data: after cut the volume takes a write ok".to_owned(),
            "posix-data: verify checks passed".to_owned(),
        ]
    }

    #[test]
    fn the_verifying_boot_must_find_what_the_host_saw_synced() {
        assert_eq!(read_verify_lines(&verify_good(3), 3), Ok(()));
        // The boot says 1..2 where the host saw 3 files synced: it checked too little.
        assert!(read_verify_lines(&verify_good(2), 3).is_err());
        for gone in 1..5 {
            let mut lines = verify_good(3);
            lines.remove(gone);
            assert!(read_verify_lines(&lines, 3).is_err(), "line {gone}");
        }
        let mut failed = verify_good(3);
        failed.insert(
            2,
            "posix-data: check failed at line 90: g >= 1 (errno 0)".to_owned(),
        );
        assert!(
            read_verify_lines(&failed, 3)
                .unwrap_err()
                .contains("check failed")
        );
        let mut early = verify_good(3);
        early.remove(0);
        assert!(
            read_verify_lines(&early, 3)
                .unwrap_err()
                .contains("not registered")
        );
    }

    #[test]
    fn the_host_reads_what_was_synced_and_renamed_before_the_cut() {
        let lines: Vec<String> = [
            "posix-data: synced 1",
            "[ 2.1] posix-data: synced 2",
            "posix-data: synced 3",
            "posix-data: renamed 1",
            "datafs: crash point 700",
        ]
        .iter()
        .map(|l| (*l).to_owned())
        .collect();
        assert_eq!(seen_before_the_cut(&lines), (3, 1));
        assert_eq!(seen_before_the_cut(&lines[..0]), (0, 0));
    }

    #[test]
    fn a_restart_needs_the_end_of_the_old_service_and_a_second_registration() {
        let mut lines = good_of(Mode::Restart);
        assert!(restarted(&lines).is_err());
        lines.insert(
            1,
            "datafs: probe-restart: the service ends with the exit code 1".to_owned(),
        );
        assert!(restarted(&lines).unwrap_err().contains("1 times"));
        lines.push("datafs: root registered with the process service".to_owned());
        assert_eq!(restarted(&lines), Ok(()));
    }

    fn lines(texts: &[&str]) -> Vec<String> {
        texts.iter().map(|t| (*t).to_owned()).collect()
    }

    /// The lines a good run of `data-fast` prints (the service's counters between the marks).
    fn fast_lines(write_ms: u64, read_ms: u64, reads: u64) -> Vec<String> {
        lines(&[
            "datafs: disk reads 100 writes 50 flushes 3",
            &format!(
                "posix-data: fast big write 64 MiB bs 1048576 in {write_ms} ms: 30000 KiB/s, 1024 cell parts, 0 inline parts, 64 calls"
            ),
            "datafs: disk reads 20000 writes 17000 flushes 9",
            "posix-data: fast mark begin read",
            &format!(
                "posix-data: fast big read 64 MiB bs 1048576 in {read_ms} ms: 20000 KiB/s, 1024 cell parts, 0 inline parts, 0 mismatches"
            ),
            "posix-data: fast mark end read",
            &format!(
                "datafs: disk reads {} writes 17000 flushes 9",
                20000 + reads
            ),
            "posix-data: fast bs4096 write 4 MiB bs 4096 in 900 ms: 4500 KiB/s, 1024 cell parts, 0 inline parts, 1024 calls",
            "posix-data: fast bs4096 read 4 MiB bs 4096 in 500 ms: 8000 KiB/s, 1024 cell parts, 0 inline parts, 0 mismatches",
            "posix-data: fast bs1000 write 4 MiB bs 1000 in 2000 ms: 2000 KiB/s, 0 cell parts, 0 inline parts, 4194 calls",
            "posix-data: fast bs1000 read 4 MiB bs 1000 in 2500 ms: 1600 KiB/s, 0 cell parts, 0 inline parts, 0 mismatches",
        ])
    }

    #[test]
    fn data_fast_passes_a_run_inside_the_bounds_and_says_the_numbers() {
        let report = fast_verdict(&fast_lines(2400, 4300, 20000)).unwrap();
        assert!(
            report.contains("2400 ms") && report.contains("1.22 for each"),
            "{report}"
        );
        // The edges: at the bound passes, one past fails.
        assert!(fast_verdict(&fast_lines(FAST_WRITE_MS_MAX, FAST_READ_MS_MAX, 16384 * 3)).is_ok());
        for (w, r, reads, what) in [
            (FAST_WRITE_MS_MAX + 1, 4300, 20000, "the write of 64 MiB"),
            (2400, FAST_READ_MS_MAX + 1, 20000, "the read of 64 MiB"),
            (2400, 4300, 16384 * 3 + 1, "reads of the disk"),
        ] {
            let error = fast_verdict(&fast_lines(w, r, reads)).unwrap_err();
            assert!(error.contains(what), "{error}");
        }
    }

    #[test]
    fn data_fast_refuses_a_run_that_lacks_a_line_a_counter_or_the_parts() {
        let good = fast_lines(2400, 4300, 20000);
        // No line of the controls, no counter after the read, no counter before it.
        for gone in [7, 6] {
            let mut lines = good.clone();
            lines.remove(gone);
            assert!(fast_verdict(&lines).is_err(), "line {gone}");
        }
        let mut before = good.clone();
        before.retain(|l| !l.contains("disk reads 100 ") && !l.contains("disk reads 20000 "));
        assert!(
            fast_verdict(&before)
                .unwrap_err()
                .contains("before the read")
        );
        // The big write through messages (a refused window) is not the large path.
        let mut inline = good.clone();
        inline[1] = "posix-data: fast big write 64 MiB bs 1048576 in 2400 ms: 30000 KiB/s, 0 cell parts, 65536 inline parts, 64 calls".into();
        assert!(fast_verdict(&inline).unwrap_err().contains("cell parts"));
        // A read that came back wrong.
        let mut wrong = good.clone();
        wrong[4] = wrong[4].replace("0 mismatches", "3 mismatches");
        assert!(fast_verdict(&wrong).unwrap_err().contains("differ"));
        // The control of 1,000 bytes made parts: it is not the old path.
        let mut parts = good.clone();
        parts[9] = parts[9].replace("0 cell parts", "5 cell parts");
        assert!(fast_verdict(&parts).is_err());
        // The control of 4,096 bytes that did not go through the window.
        let mut small = good;
        small[7] = small[7].replace(
            "1024 cell parts, 0 inline parts",
            "0 cell parts, 1024 inline parts",
        );
        assert!(fast_verdict(&small).is_err());
    }

    #[test]
    fn the_parts_line_of_the_service_is_read_and_the_numbers_of_the_helpers_are_the_digits_next_to_their_text()
     {
        let line = lines(&[
            "datafs: parts write n 1024 cpu mean 700 us max 900 us total 716800 us own mean 800 us max 1000 us span 2000000 us",
        ]);
        assert_eq!(
            parts_line(&line, "write"),
            Some(Parts {
                n: 1024,
                cpu_mean: 700,
                cpu_max: 900,
                cpu_total: 716_800,
                own_mean: 800,
                own_max: 1000,
                span: 2_000_000
            })
        );
        assert_eq!(parts_line(&line, "read"), None);
        // A line of a shorter pass is not the pass of 64 MiB.
        let short = lines(&[
            "datafs: parts write n 5 cpu mean 700 us max 900 us total 3500 us own mean 800 us max 1000 us span 20000 us",
        ]);
        assert_eq!(parts_line(&short, "write"), None);
        assert_eq!(number_after("a in 12 ms", " in "), Some(12));
        assert_eq!(number_before("x 7 cell parts", " cell parts"), Some(7));
        assert_eq!(number_before("cell parts", " cell parts"), None);
    }

    /// The lines of a good run of the steps on `cpus` CPUs: the figures of the service and the probe.
    fn steps_lines(cpu_mean: u64, stat_us: u64) -> Vec<String> {
        lines(&[
            "service step: 17 kind 37 4000 ticks detail 65536",
            "service step: 17 kind 39 4500 ticks detail 65536",
            "service step: 17 kind 64 1000 ticks detail 0",
            "datafs: cell map longest 4115 ticks (pages 16, call 1, access rw)",
            "datafs: cell unmap longest 3000 ticks (pages 16, call 2, access -)",
            "datafs: worker wall stretch WriteFrom 9000 ticks",
            "datafs: worker wall stretch ReadInto 9000 ticks",
            "datafs: worker wall stretch PreadInto 9000 ticks",
            "datafs: job WriteFrom longest 2500 us",
            &format!(
                "datafs: parts write n 1024 cpu mean {cpu_mean} us max 1000 us total 700000 us own mean 900 us max 1200 us span 2000000 us"
            ),
            &format!(
                "datafs: parts read n 1024 cpu mean {cpu_mean} us max 1000 us total 700000 us own mean 900 us max 1200 us span 2000000 us"
            ),
            &format!(
                "posix-data: stat of another file during the write: 300 calls, longest {stat_us} us"
            ),
        ])
    }

    #[test]
    fn data_steps_judges_the_cpu_of_a_part_by_the_budget_and_the_stat_by_four_jobs() {
        let report = steps_verdict(&steps_lines(700, 9000), 2).unwrap();
        assert!(
            report.contains("share while the parts ran 35.0 %"),
            "{report}"
        );
        assert!(steps_verdict(&steps_lines(PART_CPU_MEAN_MAX_US, 15_000), 2).is_ok());
        let slow = steps_verdict(&steps_lines(PART_CPU_MEAN_MAX_US + 1, 9000), 2).unwrap_err();
        assert!(slow.contains("twice the model"), "{slow}");
        // Four jobs of 2,500 us and 5 ms: 15,000 us.
        let late = steps_verdict(&steps_lines(700, 15_001), 2).unwrap_err();
        assert!(late.contains("four jobs"), "{late}");
        // On one CPU there is no budget: the CPU time is not judged (the service says 0).
        let mut one = steps_lines(0, 9000);
        for l in &mut one {
            *l = l.replace("total 700000 us", "total 0 us");
        }
        assert!(steps_verdict(&one, 1).unwrap().contains("own mean 900"));
        let mut none = steps_lines(0, 9000);
        for l in &mut none {
            *l = l.replace("total 700000 us", "total 0 us");
        }
        assert!(steps_verdict(&none, 2).unwrap_err().contains("no CPU time"));
        // On one CPU the steps are judged: a step past 0.9 B, a method of the parts past 6,000 ticks,
        // a cell map past B; on two CPUs they are told.
        let mut over = steps_lines(700, 9000);
        over[0] = "service step: 17 kind 37 19000 ticks detail 65536".into();
        assert!(steps_verdict(&over, 1).is_err());
        assert!(steps_verdict(&over, 2).is_ok());
        let mut part = steps_lines(700, 9000);
        part[1] = "service step: 17 kind 39 6500 ticks detail 65536".into();
        assert!(steps_verdict(&part, 1).unwrap_err().contains("6000"));
        let mut missing = steps_lines(700, 9000);
        missing.remove(1);
        assert!(
            steps_verdict(&missing, 1)
                .unwrap_err()
                .contains("method 39")
        );
        let mut map = steps_lines(700, 9000);
        map[3] = "datafs: cell map longest 25000 ticks (pages 16, call 1, access rw)".into();
        assert!(steps_verdict(&map, 1).is_err());
        assert!(steps_verdict(&map, 2).is_ok());
    }

    #[test]
    fn the_breaks_of_the_atomic_probe_name_a_check_of_the_probe_and_a_feature_of_the_service() {
        let manifest = include_str!("../../services/datafs/Cargo.toml");
        for (feature, check) in BREAKS {
            assert!(ATOMIC_CHECKS.contains(&check), "{check}");
            assert!(manifest.contains(&format!("{feature} = [")), "{feature}");
        }
    }
}
