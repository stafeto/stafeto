// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask data-posix`: the reading paths of `/data` in the POSIX layer (tests/posix-data) on
//! QEMU's `virt` with a virtio disk that holds a data volume made offline
//! (`data_image::make_posix_volume`: known files, owners, modes, times and numbers, version 3, so the
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
        })
    }
}

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
pub const WRITE_CHECKS: [&str; 20] = [
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

/// `cargo xtask data-posix [write|cap|full|restart|throughput|crash [N]]`.
pub fn command(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => probe(Mode::Read, machine),
        Some("write") if args.len() == 1 => probe(Mode::Write, machine),
        Some("cap") if args.len() == 1 => probe(Mode::Cap, machine),
        Some("full") if args.len() == 1 => probe(Mode::Full, machine),
        Some("restart") if args.len() == 1 => probe(Mode::Restart, machine),
        Some("throughput") if args.len() == 1 => probe(Mode::Throughput, machine),
        Some("crash") => crash(&args[1..], machine),
        Some(other) => Err(format!(
            "data-posix [write|cap|full]: unknown argument {other}"
        )),
    }
}

/// One mode: the image with the role of the mode, a volume made offline, QEMU until the probe ends,
/// and the lines read.
pub fn probe(mode: Mode, machine: &qemu::Machine) -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let programs: &[ImageProgram] = if mode == Mode::Restart {
        &PROGRAMS_RESTART
    } else {
        &PROGRAMS
    };
    let image = write_boot_image_files(
        mode.image(),
        programs,
        BOOT_PROFILE,
        &[("STAFETO_DATA_POSIX_MODE", mode.role())],
        Vec::new(),
    )?;
    let disk = Disk(std::env::temp_dir().join(format!(
        "stafeto-data-posix-{}-{}.img",
        std::process::id(),
        mode.role()
    )));
    crate::data_image::make_posix_volume(
        &disk.0,
        if mode == Mode::Throughput {
            THROUGHPUT_DISK_BYTES
        } else {
            DISK_BYTES
        },
    )?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&disk.0, None));
    let started = std::time::Instant::now();
    let output = run_until(cmd, mode.limit(), Some(ENDS), &kernel.elf)?;
    read_lines(&output.lines, mode)?;
    if mode == Mode::Restart {
        restarted(&output.lines)?;
    }
    qemu::expect_stopped_on(&output, ENDED)?;
    println!(
        "data-posix {:?} on {}: {} checks of /data in the POSIX layer over the data file service in {} s: ok",
        mode,
        machine.name,
        mode.checks().len(),
        started.elapsed().as_secs()
    );
    Ok(())
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
}
