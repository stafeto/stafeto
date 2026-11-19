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
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, Variant, build, build_boot_image, qemu, run_until,
};
use std::path::PathBuf;

/// The probe's image.
pub const PROGRAMS: [ImageProgram; 11] = [
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
    ("datafsd", "datafsd", 32 * 1024, &[]),
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
];

/// The checks of the probe, in the order it runs them: the line of each is `posix-data: <name> ok`.
pub const CHECKS: [&str; 29] = [
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
    "writes refused",
    "datax is the RAM service",
    "errno for bad paths",
    "statvfs",
    "realpath",
];

const PREFIX: &str = "posix-data: ";
const PASSED: &str = "posix-data: read checks passed";

/// Reads the lines of the probe. Each check has exactly one line `ok`, in the order of `CHECKS`
/// (the lines of the children, which print nothing but a failure, may stand between them); no line
/// says a check failed; the line of the end comes once, after every check. The lines come glued to
/// the kernel's and the services' lines, so the text is looked for inside the line.
pub fn read_lines(lines: &[String]) -> Result<(), String> {
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
        if *line == PASSED {
            if next != CHECKS.len() {
                return Err(format!(
                    "the end came after {next} of {} checks",
                    CHECKS.len()
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
        match CHECKS.get(next) {
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
        n if n < CHECKS.len() => Err(format!(
            "the probe stopped after {n} of {} checks: the next is {:?}",
            CHECKS.len(),
            CHECKS[n]
        )),
        _ => Err(format!("no line {PASSED:?}")),
    }
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
const ENDS: &str = "init: posix-data ended: ";
const ENDED: &str = "init: posix-data ended: exit code 0, not restarted";

/// `cargo xtask data-posix`.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-data-posix.img", &PROGRAMS, BOOT_PROFILE)?;
    let disk =
        Disk(std::env::temp_dir().join(format!("stafeto-data-posix-{}.img", std::process::id())));
    crate::data_image::make_posix_volume(&disk.0, DISK_BYTES)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&disk.0, None));
    let output = run_until(cmd, crate::BOOT_TIMEOUT * 6, Some(ENDS), &kernel.elf)?;
    read_lines(&output.lines)?;
    qemu::expect_stopped_on(&output, ENDED)?;
    println!(
        "data-posix on {}: {} reading checks of /data in the POSIX layer over the data file service: ok",
        machine.name,
        CHECKS.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Vec<String> {
        let mut lines = vec!["init: starting".to_owned()];
        lines.extend(CHECKS.iter().map(|c| format!("posix-data: {c} ok")));
        lines.push(PASSED.to_owned());
        lines.push(ENDED.to_owned());
        lines
    }

    #[test]
    fn a_run_with_every_check_and_the_end_passes() {
        assert_eq!(read_lines(&good()), Ok(()));
        // The lines come glued to another line's tail.
        let glued: Vec<String> = good().iter().map(|l| format!("[ 1.234] {l}")).collect();
        assert_eq!(read_lines(&glued), Ok(()));
    }

    #[test]
    fn a_failed_check_a_missing_check_and_a_missing_end_are_refused() {
        let mut failed = good();
        failed[3] = "posix-data: stat pub FAILED".to_owned();
        assert!(read_lines(&failed).unwrap_err().contains("stat pub FAILED"));
        let mut line = good();
        line.insert(
            4,
            "posix-data: check failed at line 99: st.st_size == 5000 (errno 0)".to_owned(),
        );
        assert!(read_lines(&line).unwrap_err().contains("check failed"));
        let mut summary = good();
        summary.insert(2, "posix-data: 2 checks failed".to_owned());
        assert!(read_lines(&summary).is_err());
        let mut missing = good();
        missing.remove(5);
        assert!(read_lines(&missing).is_err());
        let mut no_end = good();
        no_end.retain(|l| l != PASSED);
        assert!(read_lines(&no_end).unwrap_err().contains("no line"));
        let mut cut = good();
        cut.truncate(10);
        assert!(read_lines(&cut).unwrap_err().contains("stopped after"));
    }

    #[test]
    fn a_repeat_a_swap_an_extra_line_and_an_early_end_are_refused() {
        let mut repeat = good();
        repeat.insert(3, "posix-data: read pub whole ok".to_owned());
        assert!(read_lines(&repeat).is_err());
        let mut swapped = good();
        swapped.swap(2, 3);
        assert!(read_lines(&swapped).is_err());
        let mut extra = good();
        let end = extra.iter().position(|l| l == PASSED).unwrap();
        extra.insert(end, "posix-data: something else ok".to_owned());
        assert!(read_lines(&extra).is_err());
        let mut early = good();
        let end = early.iter().position(|l| l == PASSED).unwrap();
        let last = early.remove(end - 1);
        early.insert(end, last);
        assert!(read_lines(&early).is_err());
        let mut after = good();
        after.insert(after.len() - 1, "posix-data: stat pub ok".to_owned());
        assert!(read_lines(&after).is_err());
    }

    #[test]
    fn the_list_of_checks_is_the_one_of_the_c_probe() {
        let source = include_str!("../../tests/posix-data/data.c");
        for check in CHECKS {
            assert!(
                source.contains(&format!("run_check(\"{check}\"")),
                "{check} is not run by data.c"
            );
        }
        assert_eq!(source.matches("run_check(\"").count(), CHECKS.len());
    }
}
