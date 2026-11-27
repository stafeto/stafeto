// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask layer-posix [breaks]`: the POSIX layer on the layered root (tests/layer-posix) on
//! QEMU's `virt` with a virtio disk that holds a data volume made offline
//! (`data_image::make_layer_posix_volume`: the live layer 00 with marks of deletion, names that
//! shadow lower ones, an opaque directory, files of another owner and closed directories, a
//! directory whose first sixteen lower names the layer hides). The image has the RAM files (the
//! lower set of the probe: `boot-layer-posix.img`, with the programs the probe starts), the process,
//! clock and pipe services, the disk service of the volume, the data file service, the layer service
//! and the probe, a POSIX process of the root whose layer sends every path of the root but the
//! pass-through names to the layer service (the feature `layer`). The probe prints a line for each
//! check (`layer-posix: <check> ok`) and ends with `layer-posix: checks passed`.
//!
//! `breaks` builds the probe's layer with each deliberate break (no path routed to the layer
//! service, no session for a child) and runs the probe against it: the probe must fail, and the
//! check each break is meant for must be one of the failures.

use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, Variant, build, qemu, run_until,
    write_boot_image_files,
};
use std::path::PathBuf;

const PREFIX: &str = "layer-posix: ";
const ENDS: &str = "init: layer-posix ended: ";
const PASSED: &str = "layer-posix: checks passed";
const IMAGE: &str = "boot-layer-posix.img";

/// The size of the disk file: the layout takes 1 MiB for the table, `store` half of the rest, and the
/// data partition of 31 MiB holds the volume of the probe.
const DISK_BYTES: u64 = 64 << 20;

/// The longest a boot may take: the start of the volume, the index and 24 checks with their forks.
const LIMIT: std::time::Duration = std::time::Duration::from_secs(300);

/// The checks of the probe, in the order it runs them: the line of each is `layer-posix: <check> ok`.
pub const CHECKS: [&str; 24] = [
    "a file of the layer of the user is read",
    "a lower file is read",
    "a name of the layer shadows the lower one",
    "the names the layer deletes are gone",
    "stat of paths and the layered device",
    "access and readlink",
    "a merged directory is listed once",
    "a lower directory is listed",
    "a listing goes on over empty replies",
    "an opaque directory lists its own names",
    "paths against a merged directory",
    "paths against a lower directory",
    "the pass-through names are the services' own",
    "chdir and fchdir",
    "realpath",
    "a forked child shares the directory description",
    "a spawned program keeps the directory description",
    "an exec keeps the directory description",
    "programs of the layers",
    "a forked child binds its own identity",
    "rights of another user",
    "writes are refused",
    "a set-ID program is given the service's session",
    "a set-ID program keeps the genuine session and binds it",
];

/// The deliberate breaks, the program each is a feature of and the check each one fails.
pub const BREAKS: [(&str, &str, &str); 3] = [
    (
        "break-layer-route",
        "layer-posix",
        "a file of the layer of the user is read",
    ),
    (
        "break-layer-clone",
        "layer-posix",
        "a forked child shares the directory description",
    ),
    ("break-layered-guard", "ramfs", "writes are refused"),
];

/// The image's programs; the probe is built with `probe` features and the RAM file service with
/// `ramfs` features.
fn programs(probe: &'static [&'static str], ramfs: &'static [&'static str]) -> Vec<ImageProgram> {
    vec![
        ("init", "init", INIT_STACK_SIZE, &["table-layer-posix"][..]),
        ("ramfs", "ramfs", crate::RAMFS_STACK_SIZE, ramfs),
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
        ("layerd", "layerd", 128 * 1024, &[]),
        (
            "layer-posix",
            "layer-posix-probe",
            crate::POSIX_STACK_SIZE,
            probe,
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

/// The programs of the plain image, for the check of the stacks of every list of programs.
#[cfg(test)]
pub fn plain_programs() -> Vec<ImageProgram> {
    programs(&[], &[])
}

/// The disk of the run: a file of the process's name, removed at the end.
struct Disk(PathBuf);

impl Drop for Disk {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn command(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => probe(machine),
        Some("breaks") if args.len() == 1 => breaks(machine),
        Some(other) => Err(format!("layer-posix [breaks]: unknown argument {other}")),
    }
}

/// One boot with the probe built with `probe` features and the RAM file service with `ramfs`
/// features; the lines of the console.
fn boot(
    machine: &qemu::Machine,
    probe: &'static [&'static str],
    ramfs: &'static [&'static str],
) -> Result<(qemu::Outcome, u64), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = write_boot_image_files(
        IMAGE,
        &programs(probe, ramfs),
        BOOT_PROFILE,
        &[],
        Vec::new(),
    )?;
    let disk =
        Disk(std::env::temp_dir().join(format!("stafeto-layer-posix-{}.img", std::process::id())));
    crate::data_image::make_layer_posix_volume(&disk.0, DISK_BYTES)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&disk.0, None));
    let started = std::time::Instant::now();
    let output = run_until(cmd, LIMIT, Some(ENDS), &kernel.elf)?;
    Ok((output, started.elapsed().as_secs()))
}

/// The lines of the probe, text after the prefix.
fn mine(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .filter_map(|l| l.find(PREFIX).map(|at| &l[at + PREFIX.len()..]))
        .collect()
}

/// The root of the layer service is registered, or the probe could not have taken it.
fn registered(lines: &[String]) -> Result<(), String> {
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
        .find(|l| l.contains("FAILED") || l.contains("checks failed") || l.contains("check failed"))
    {
        return Err(format!("layer-posix: {bad}"));
    }
    let mut next = 0;
    let mut ended = false;
    for line in &mine {
        if *line == &PASSED[PREFIX.len()..] {
            if next != CHECKS.len() {
                return Err(format!("the end after {next} of {} checks", CHECKS.len()));
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
        match CHECKS.get(next) {
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
            CHECKS.len()
        ));
    }
    Ok(())
}

pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    let (output, seconds) = boot(machine, &[], &[])?;
    read_lines(&output.lines)?;
    qemu::expect_stopped_on(
        &output,
        "init: layer-posix ended: exit code 0, not restarted",
    )?;
    println!(
        "layer-posix on {}: {} checks of the POSIX layer on the layered root in {} s: ok",
        machine.name,
        CHECKS.len(),
        seconds
    );
    Ok(())
}

/// Each break, one boot each: the probe must fail and name the check the break is for.
pub fn breaks(machine: &qemu::Machine) -> Result<(), String> {
    for (feature, program, check) in BREAKS {
        let features: &'static [&'static str] = Box::leak(vec![feature].into_boxed_slice());
        let (output, seconds) = match program {
            "ramfs" => boot(machine, &[], features)?,
            _ => boot(machine, features, &[])?,
        };
        let mine = mine(&output.lines);
        if mine.iter().any(|l| *l == &PASSED[PREFIX.len()..]) {
            return Err(format!(
                "layer-posix breaks: {feature} did not fail the probe"
            ));
        }
        let failed: Vec<&&str> = mine.iter().filter(|l| l.contains(" FAILED")).collect();
        let wanted = format!("{check} FAILED");
        if !failed.iter().any(|l| l.starts_with(&wanted)) {
            return Err(format!(
                "layer-posix breaks: {feature} did not fail {check:?}; the checks that failed: {failed:?}"
            ));
        }
        println!("layer-posix breaks: {feature} is caught by {check:?} (in {seconds} s)");
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
        let mut names: Vec<String> = CHECKS.iter().map(|c| format!("{c} ok")).collect();
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
        v.insert(3, format!("{PREFIX}a lower file is read FAILED"));
        assert!(read_lines(&v).is_err());
        let mut v = all_ok();
        v.insert(3, format!("{PREFIX}check failed at line 9: x (errno 2)"));
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
        for (feature, program, check) in BREAKS {
            assert!(CHECKS.contains(&check), "{feature}");
            assert!(feature.starts_with("break-layer"));
            assert!(["layer-posix", "ramfs"].contains(&program), "{feature}");
        }
        // The checks of the file are the checks of the C program, each once.
        let source = include_str!("../../tests/layer-posix/layer.c");
        for check in CHECKS {
            let quoted = format!("run_check(\"{check}\"");
            assert_eq!(source.matches(&quoted).count(), 1, "{check}");
        }
        assert_eq!(source.matches("run_check(\"").count(), CHECKS.len());
    }

    #[test]
    fn the_image_has_the_layer_service_after_the_data_service_and_before_the_probe() {
        let p = plain_programs();
        let at = |name: &str| p.iter().position(|x| x.0 == name).unwrap();
        assert!(at("datafsd") < at("layerd") && at("layerd") < at("layer-posix"));
    }
}
