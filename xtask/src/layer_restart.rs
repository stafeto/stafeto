// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask layer-restart [breaks]`: the layer service and the data file service restart under a
//! program that keeps working. The probe (tests/layer-names, built with
//! `STAFETO_LAYER_NAMES_MODE=restart`) holds a directory description and a file of the layer, ends the
//! layer service with an OPEN of `/.die` (the feature `probe-restart` of `layerd`), and checks that the
//! old session is dead, that the description of the old instance answers STALE on a session of the
//! new one, that the file the data file service holds is read on, and that a new listing carries
//! the epoch of the new instance. It then ends the data file service on the same name (its feature
//! `probe-restart`); the layer service meets the end at its next call, ends too (exit code 6),
//! and both come back: the same bytes through new sessions.
//!
//! `breaks` builds the layer service with `break-layerd-epoch`, whose instances all carry one epoch,
//! so the description of the old instance is not told STALE: the probe must fail on it.

use crate::{BOOT_PROFILE, Variant, build, layer_names, qemu, run_until, write_boot_image_files};

const PREFIX: &str = "layer-names: ";
const ENDS: &str = "init: layer-names ended: ";
const PASSED: &str = "restart checks passed";
const IMAGE: &str = "boot-layer-restart.img";
const DISK_BYTES: u64 = 64 << 20;
/// Two restarts of the layer service and one of the data file service, each with the mount of the
/// volume and the build of the index, and the probe's waits.
const LIMIT: std::time::Duration = std::time::Duration::from_secs(420);

/// The checks of the probe in restart mode, in the order it runs them.
pub const CHECKS: [&str; 14] = [
    "sessions",
    "descriptions of the first instance",
    "the service ends on the request",
    "a session of the new instance",
    "the session of the old instance is dead",
    "a description of the old instance answers STALE",
    "a file of the old instance is read on",
    "a new description lists and carries the epoch of the new instance",
    "a stat on the new session",
    "the data file service ends on the request",
    "the layer service ends when the data file service has ended",
    "both services are back",
    "the same bytes through the new instances",
    "a listing of the third instance",
];

/// The deliberate break of the layer service and the check it fails.
pub const BREAKS: [(&str, &str); 1] = [(
    "break-layerd-epoch",
    "a description of the old instance answers STALE",
)];

fn programs(layerd: &'static [&'static str]) -> Vec<crate::ImageProgram> {
    layer_names::programs(layerd, &["probe-restart"])
}

/// The programs of the image, for the check of the stacks of every list of programs.
#[cfg(test)]
pub fn plain_programs() -> Vec<crate::ImageProgram> {
    programs(&["probe-restart"])
}

fn boot(
    machine: &qemu::Machine,
    layerd: &'static [&'static str],
) -> Result<(qemu::Outcome, u64), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = write_boot_image_files(
        IMAGE,
        &programs(layerd),
        BOOT_PROFILE,
        &[("STAFETO_LAYER_NAMES_MODE", "restart")],
        Vec::new(),
    )?;
    let disk = layer_names::Disk(
        std::env::temp_dir().join(format!("stafeto-layer-restart-{}.img", std::process::id())),
    );
    crate::data_image::make_layer_volume(&disk.0, DISK_BYTES)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&disk.0, None));
    let started = std::time::Instant::now();
    let output = run_until(cmd, LIMIT, Some(ENDS), &kernel.elf)?;
    Ok((output, started.elapsed().as_secs()))
}

fn count(lines: &[String], text: &str) -> usize {
    lines.iter().filter(|l| l.contains(text)).count()
}

/// The checks said ok in order, the end once, and the console tells of the restarts: the layer
/// service ended on the request (code 1) and after the data file service (code 6), the data file
/// service ended once, three instances of the layer service registered their root, and init never
/// marked a service broken.
pub fn read_lines(lines: &[String]) -> Result<(), String> {
    let mine = layer_names::mine(lines);
    if let Some(bad) = mine
        .iter()
        .find(|l| l.contains("FAILED") || l.contains("checks failed"))
    {
        return Err(format!("layer-restart: {bad}"));
    }
    let oks: Vec<&str> = mine.iter().filter_map(|l| l.strip_suffix(" ok")).collect();
    if oks != CHECKS {
        return Err(format!(
            "the checks that said ok are {oks:?}, {CHECKS:?} were due"
        ));
    }
    if !mine.contains(&PASSED) {
        return Err(format!("no line {PREFIX}{PASSED}"));
    }
    let want = [
        (
            "layerd: probe-restart: the service ends with the exit code 1",
            1,
        ),
        ("init: layerd ended: exit code 1; restarts in", 1),
        (
            "datafs: probe-restart: the service ends with the exit code 1",
            1,
        ),
        (
            "layerd: the data file service went, ending for a new instance",
            1,
        ),
        ("init: layerd ended: exit code 6; restarts in", 1),
        ("layerd: root registered", 3),
        ("datafs: root registered", 2),
    ];
    for (text, least) in want {
        let found = count(lines, text);
        if found < least {
            return Err(format!(
                "the console has {found} lines with {text:?}, at least {least} were due"
            ));
        }
    }
    if let Some(broken) = lines
        .iter()
        .find(|l| l.contains("marked broken") || l.contains("; broken:"))
    {
        return Err(format!("init marked a service broken: {broken}"));
    }
    Ok(())
}

pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    let (output, seconds) = boot(machine, &["probe-restart"])?;
    read_lines(&output.lines)?;
    qemu::expect_stopped_on(
        &output,
        "init: layer-names ended: exit code 0, not restarted",
    )?;
    println!(
        "layer-restart on {}: the layer service ended twice (on a request, and after the data file service ended) and came back, STALE for the description of the old instance, the file read on, the same bytes through the new instances, in {seconds} s: ok",
        machine.name
    );
    Ok(())
}

/// Each break, one boot each: the probe must fail and name the check the break is for.
pub fn breaks(machine: &qemu::Machine) -> Result<(), String> {
    for (feature, check) in BREAKS {
        let features: &'static [&'static str] =
            Box::leak(vec!["probe-restart", feature].into_boxed_slice());
        let (output, seconds) = boot(machine, features)?;
        let mine = layer_names::mine(&output.lines);
        if mine.contains(&PASSED) {
            return Err(format!(
                "layer-restart breaks: {feature} did not fail the probe"
            ));
        }
        let wanted = format!("{check} FAILED");
        if !mine.iter().any(|l| l.starts_with(&wanted)) {
            return Err(format!(
                "layer-restart breaks: {feature} did not fail {check:?}; the lines: {mine:?}"
            ));
        }
        println!("layer-restart breaks: {feature} is caught by {check:?} (in {seconds} s)");
    }
    Ok(())
}

pub fn command(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => probe(machine),
        Some("breaks") if args.len() == 1 => breaks(machine),
        Some(other) => Err(format!("layer-restart [breaks]: unknown argument {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Vec<String> {
        let mut lines = vec![
            "layerd: probe-restart: the service ends with the exit code 1".to_owned(),
            "init: layerd ended: exit code 1; restarts in 100 ms".to_owned(),
            "datafs: probe-restart: the service ends with the exit code 1".to_owned(),
            "layerd: the data file service went, ending for a new instance".to_owned(),
            "init: layerd ended: exit code 6; restarts in 100 ms".to_owned(),
        ];
        lines.extend((0..3).map(|_| "layerd: root registered with the process service".to_owned()));
        lines.extend((0..2).map(|_| "datafs: root registered with the process service".to_owned()));
        lines.extend(CHECKS.iter().map(|c| format!("{PREFIX}{c} ok")));
        lines.push(format!("{PREFIX}{PASSED}"));
        lines
    }

    #[test]
    fn a_run_with_the_checks_and_the_restarts_passes_and_a_missing_part_fails() {
        assert_eq!(read_lines(&good()), Ok(()));
        let mut v = good();
        v.retain(|l| !l.contains("exit code 6"));
        assert!(
            read_lines(&v).is_err(),
            "the layer service did not follow the data service"
        );
        let mut v = good();
        v.push("init: layerd ended: fault; broken: 5 failures in 60 s".to_owned());
        assert!(read_lines(&v).is_err());
        let mut v = good();
        v.retain(|l| !l.contains("a stat on the new session"));
        assert!(read_lines(&v).is_err());
    }

    #[test]
    fn every_break_names_a_check_of_the_probe() {
        for (feature, check) in BREAKS {
            assert!(CHECKS.contains(&check), "{feature}");
        }
    }
}
