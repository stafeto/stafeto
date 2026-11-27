// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask layer-names-probe [breaks]`: the names of the layered root (tests/layer-names) on QEMU's
//! `virt` with a virtio disk that holds a data volume made offline
//! (`data_image::make_layer_volume`: the live layer 00 with a mark of deletion, a name that
//! shadows a lower one, an opaque directory, a file of another owner with a number of the layer
//! and a directory closed to other users). The image has the RAM files (the lower set of the probe:
//! `boot-layer-names.img`), the process, clock and pipe services, the disk service of the volume, the
//! data file service, the layer service and the probe, a POSIX process of the root that speaks to
//! the layer service directly. The probe prints a line for each check
//! (`layer-names: <check> ok`) and ends with `layer-names: read checks passed`.
//!
//! `breaks` builds the layer service with each deliberate break and runs the probe against it: the
//! probe must fail, and the check each break is meant for must be one of the failures.

use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, Variant, build, qemu, run_until,
    write_boot_image_files,
};
use std::path::PathBuf;

const PREFIX: &str = "layer-names: ";
const ENDS: &str = "init: layer-names ended: ";
const PASSED: &str = "layer-names: read checks passed";
const IMAGE: &str = "boot-layer-names.img";

/// The size of the disk file: the layout takes 1 MiB for the table, `store` half of the rest, and the
/// data partition of 31 MiB holds the volume of the probe.
const DISK_BYTES: u64 = 64 << 20;

/// The longest a boot may take: the start of the volume, the index of 11 names and 22 checks.
const LIMIT: std::time::Duration = std::time::Duration::from_secs(180);

/// The checks of the probe, in the order it runs them: the line of each is `layer-names: <check> ok`.
pub const CHECKS: [&str; 23] = [
    "sessions",
    "status",
    "a lower file is a redirect",
    "a lower directory is a redirect",
    "the pass of a file of the layer",
    "a file of the layer shadows the lower one",
    "stat numbers",
    "a stat of a lower name is a redirect",
    "merged listing of a directory",
    "a name of the layer is listed once over the lower one",
    "the names a layer deleted are gone",
    "a dot dot in the index and after a lower name",
    "an opaque directory lists only its own names",
    "rewind fstat and close",
    "the lower set is not written",
    "the superuser searches a closed directory",
    "the superuser reads a closed file",
    "search denied for user 1000 on the session of before",
    "search denied for user 1000 on a new session",
    "a file whose own mode denies the read is denied",
    "a closed lower directory is left to the RAM file service",
    "the owner reads the file of the layer",
    "a lower file stays reachable",
];

/// The checks that make a line `ok`.
fn ok_checks() -> &'static [&'static str] {
    &CHECKS
}

/// The deliberate breaks of the layer service and the check each one fails.
pub const BREAKS: [(&str, &str); 2] = [
    ("break-layerd-whiteout", "merged listing of a directory"),
    (
        "break-layerd-search",
        "search denied for user 1000 on a new session",
    ),
];

/// The image's programs; the layer service is built with `layerd` features.
pub(crate) fn programs(
    layerd: &'static [&'static str],
    datafs: &'static [&'static str],
) -> Vec<ImageProgram> {
    vec![
        ("init", "init", INIT_STACK_SIZE, &["table-layer-names"][..]),
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
        ("layerd", "layerd", crate::LAYERD_STACK_SIZE, layerd),
        ("layer-names", "layer-names", crate::POSIX_STACK_SIZE, &[]),
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

/// The programs of the plain image, for the check of the stacks of every list of programs.
#[cfg(test)]
pub fn plain_programs() -> Vec<ImageProgram> {
    programs(&[], &[])
}

/// The disk of the run: a file of the process's name, removed at the end.
pub(crate) struct Disk(pub PathBuf);

impl Drop for Disk {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn command(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => probe(machine),
        Some("breaks") if args.len() == 1 => breaks(machine),
        Some("steps") if args.len() == 1 => steps(machine),
        Some(other) => Err(format!(
            "layer-names-probe [breaks]: unknown argument {other}"
        )),
    }
}

/// One boot with the layer service built with `features`; the lines of the console.
fn boot(
    machine: &qemu::Machine,
    features: &'static [&'static str],
) -> Result<(qemu::Outcome, u64), String> {
    boot_with(machine, features, false)
}

/// `boot`, under `-icount` on one CPU when `icount` (the figures of the steps repeat).
fn boot_with(
    machine: &qemu::Machine,
    features: &'static [&'static str],
    icount: bool,
) -> Result<(qemu::Outcome, u64), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = write_boot_image_files(
        IMAGE,
        &programs(features, &[]),
        BOOT_PROFILE,
        &[],
        Vec::new(),
    )?;
    let disk =
        Disk(std::env::temp_dir().join(format!("stafeto-layer-names-{}.img", std::process::id())));
    crate::data_image::make_layer_volume(&disk.0, DISK_BYTES)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&disk.0, None));
    if icount {
        cmd.args(["-smp", "1", "-icount", "shift=4,sleep=on"]);
    }
    let started = std::time::Instant::now();
    let output = run_until(cmd, LIMIT, Some(ENDS), &kernel.elf)?;
    Ok((output, started.elapsed().as_secs()))
}

/// The lines of the probe, text after the prefix.
pub(crate) fn mine(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .filter_map(|l| l.find(PREFIX).map(|at| &l[at + PREFIX.len()..]))
        .collect()
}

/// The root of the layer service is registered, or the probe could not have taken it.
pub(crate) fn registered(lines: &[String]) -> Result<(), String> {
    if lines.iter().any(|l| {
        l.contains("layerd: root registered with the process service")
            || l.contains("layerd: root registered after ")
    }) {
        return Ok(());
    }
    Err(format!(
        "the layer service did not say its root is registered: {:?}",
        lines
            .iter()
            .filter(|l| l.contains("layerd:"))
            .collect::<Vec<_>>()
    ))
}

/// Each check has exactly one line `ok`, in the order of `CHECKS`; no line says a check failed; the
/// line of the end comes once, after every check.
pub fn read_lines(lines: &[String]) -> Result<(), String> {
    registered(lines)?;
    let mine = mine(lines);
    if let Some(bad) = mine
        .iter()
        .find(|l| l.contains("FAILED") || l.contains("checks failed"))
    {
        return Err(format!("layer-names: {bad}"));
    }
    let want = ok_checks();
    let mut next = 0;
    let mut ended = false;
    for line in &mine {
        if *line == &PASSED[PREFIX.len()..] {
            if next != want.len() {
                return Err(format!("the end after {next} of {} checks", want.len()));
            }
            ended = true;
            continue;
        }
        let Some(name) = line.strip_suffix(" ok") else {
            continue;
        };
        if ended {
            return Err(format!("a line after the end: {line:?}"));
        }
        match want.get(next) {
            Some(expected) if *expected == name => next += 1,
            Some(expected) => {
                return Err(format!(
                    "the check {name:?} came where {expected:?} was due"
                ));
            }
            None => return Err(format!("an extra check line {line:?}")),
        }
    }
    if !ended {
        return Err(format!(
            "the probe said {next} of {} checks and no end",
            want.len()
        ));
    }
    Ok(())
}

pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    let (output, seconds) = boot(machine, &[])?;
    read_lines(&output.lines)?;
    qemu::expect_stopped_on(
        &output,
        "init: layer-names ended: exit code 0, not restarted",
    )?;
    println!(
        "layer-names on {}: {} checks of the names of the layered root in {} s: ok",
        machine.name,
        ok_checks().len(),
        seconds
    );
    Ok(())
}

/// The steps of the service under `-icount` on one CPU: the probe passes and the longest step of
/// each kind goes to the console; none may be over 0.9 B (`layer_steps::gate`). The kinds 64 and up
/// of the loop's table are one kind (63) for the methods of the names, since their numbers are 70 and
/// over. The scale of the limits is `cargo xtask layer-steps`.
pub fn steps(machine: &qemu::Machine) -> Result<(), String> {
    let (output, seconds) = boot_with(machine, &["steps"], true)?;
    read_lines(&output.lines)?;
    qemu::expect_stopped_on(
        &output,
        "init: layer-names ended: exit code 0, not restarted",
    )?;
    let rows = crate::layer_steps::gate(&output.lines)?;
    println!(
        "layer-names-probe steps on {} under -icount: steps of the layer service (kind, ticks, detail) {rows:?}, none over 0.9 B ({}) in {seconds} s: ok",
        machine.name,
        crate::TERM_B * 9 / 10
    );
    Ok(())
}

/// Each break, one boot each: the probe must fail and name the check the break is for.
pub fn breaks(machine: &qemu::Machine) -> Result<(), String> {
    for (feature, check) in BREAKS {
        let features: &'static [&'static str] = Box::leak(vec![feature].into_boxed_slice());
        let (output, seconds) = boot(machine, features)?;
        let mine = mine(&output.lines);
        if mine.iter().any(|l| *l == &PASSED[PREFIX.len()..]) {
            return Err(format!(
                "layer-names-probe breaks: {feature} did not fail the probe"
            ));
        }
        let failed: Vec<&&str> = mine.iter().filter(|l| l.contains(" FAILED")).collect();
        let wanted = format!("{check} FAILED");
        if !failed.iter().any(|l| l.starts_with(&wanted)) {
            return Err(format!(
                "layer-names-probe breaks: {feature} did not fail {check:?}; the checks that failed: {failed:?}"
            ));
        }
        println!("layer-names-probe breaks: {feature} is caught by {check:?} (in {seconds} s)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(names: &[&str]) -> Vec<String> {
        let mut v = vec!["layerd: root registered with the process service".to_owned()];
        v.extend(names.iter().map(|n| format!("{PREFIX}{n}")));
        v
    }

    fn all_ok() -> Vec<String> {
        let mut names: Vec<String> = ok_checks().iter().map(|c| format!("{c} ok")).collect();
        names.push(PASSED[PREFIX.len()..].to_owned());
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        lines(&refs)
    }

    #[test]
    fn a_run_with_every_check_in_order_and_the_end_passes() {
        assert_eq!(read_lines(&all_ok()), Ok(()));
    }

    #[test]
    fn a_failed_check_a_missing_check_or_a_missing_end_fails() {
        let mut v = all_ok();
        v.insert(3, format!("{PREFIX}status FAILED: why"));
        assert!(read_lines(&v).is_err());
        let mut v = all_ok();
        v.remove(4);
        assert!(read_lines(&v).is_err());
        let mut v = all_ok();
        v.pop();
        assert!(read_lines(&v).is_err());
        let mut v = all_ok();
        v.swap(2, 3);
        assert!(read_lines(&v).is_err());
        let mut v = all_ok();
        v.remove(0);
        assert!(read_lines(&v).is_err(), "no root registered");
    }

    #[test]
    fn every_break_names_a_check_of_the_probe() {
        for (feature, check) in BREAKS {
            assert!(CHECKS.contains(&check), "{feature}");
            assert!(feature.starts_with("break-layerd-"));
        }
    }

    #[test]
    fn the_image_has_the_layer_service_after_the_data_service() {
        let p = plain_programs();
        let at = |name: &str| p.iter().position(|x| x.0 == name).unwrap();
        assert!(at("datafsd") < at("layerd") && at("layerd") < at("layer-names"));
    }
}
