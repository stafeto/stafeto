// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask layer-steps [breaks]`: the steps of the layer service at the scale of its limits,
//! under `-icount` on one CPU. The volume (`data_image::layer_steps_entries`) holds 8,192 names in
//! the live layer: a chain of 246 directories with a file at its end, a directory of 1,024 files
//! that lists beside the lower `/etc`, and files in the directories `d00` and on. The probe
//! (tests/layer-names, built with `STAFETO_LAYER_NAMES_MODE=scale`) counts the names, opens the file
//! at the end of the chain (a path of 247 components), asks for a path of 253 components and lists
//! the merged directory; the service is built with `steps` and tells the longest step of each kind.
//! The run passes when the checks pass and no step is over 0.9 B (the 18,369 ticks that
//! `step_line::longest` judges against) and none over B.
//!
//! The copy up is measured too (step C4 part A): the probe writes a lower file of 64 MiB
//! (`/lowbig/big`, pattern bytes) before its first read and waits for the copy after its last, so
//! the worker thread of the service copies it while the loop serves the checks. The RAM file service
//! is built with `steps` as well: its steps, the reads of 12 KiB into the window among them (the
//! kind 63), must stay under B and under `RAM_STEP_MAX`, and the loop of the layer service under
//! 0.9 B. The disk is large enough for the copy.
//!
//! `breaks` builds the service with `break-layerd-one-step`, which walks the whole layer in one step
//! of the loop, and the gate must fail on it; with `break-layerd-copy-in-loop`, which moves the bytes
//! of the copy in the loop's own step, the same gate.

use crate::{
    BOOT_PROFILE, ImageProgram, Variant, build, layer_names, qemu, run_until,
    write_boot_image_files,
};

const PREFIX: &str = "layer-names: ";
const ENDS: &str = "init: layer-names ended: ";
const PASSED: &str = "scale checks passed";
const IMAGE: &str = "boot-layer-steps.img";
/// The disk of the run: the volume of 8,192 names takes a few MiB of the data partition, and the
/// copy of the lower file of 64 MiB the rest of it.
const DISK_BYTES: u64 = 384 << 20;
/// The longest a boot may take under `-icount`: the volume, the build of the index in about 150
/// steps, the listing and the checks.
const LIMIT: std::time::Duration = std::time::Duration::from_secs(900);
/// The tag of the step lines of the layer service, and of the RAM file service.
const STEP_TAG: &str = "18";
const RAM_TAG: &str = "2";
/// The kind of the RAM file service that counts READ_AT_FD_INTO (the statistics count every method
/// from 64 on in the kind 63): the reads of the copy up of 12 KiB each.
const RAM_READ_KIND: usize = 63;

/// The checks of the probe in scale mode, in the order it runs them.
pub const CHECKS: [&str; 16] = [
    "sessions",
    "status counts the names of the layer",
    "a file at the end of a chain of 247 components",
    "a file with a name of 200 bytes",
    "a path of 253 components is the lower set's after the chain",
    "a name of the last directory of the layer",
    "a merged listing of 1,024 names of the layer",
    "a lower file of 64 MiB is copied up while the checks run",
    "a file made, written and removed at the depth of 240",
    "a directory made and removed at the depth of 240",
    "a directory below a chain of 32 lower directories",
    "a directory of 1,024 names renamed and back",
    "a directory renamed into the opaque directory and back",
    "a directory of 2,000 marks removed and made again",
    "a rename onto a directory of marks alone",
    "status counts the names after the changes",
];

/// The deliberate breaks, and whether the step gate must catch the break itself (the walk of the
/// whole layer in one step is also caught by the watch of init, which kills the silent service).
pub const BREAKS: [(&str, bool); 4] = [
    ("break-layerd-one-step", false),
    ("break-layerd-slots", true),
    ("break-layerd-change-one-step", true),
    // The copy of 64 MiB in the step of the loop: the step gate, or the watch of init when the
    // service is silent for the time of the copy.
    ("break-layerd-copy-in-loop", false),
];

/// The bytes of the lower file the probe writes: the byte at i is (i % 251) | 1 (`scale.rs`).
const BIG_BYTES: usize = 64 << 20;

/// What the lower set of the run holds besides the system: a chain of directories with no
/// counterpart in the layer (`/lowdeep/l1/.../l32`, below which the probe makes a directory, which
/// copies them up; the service resolves a lower path one step of the RAM file service at a time,
/// about 1,400 ticks each, so the chain of 33 components stays under the gate), and a file in
/// `/opq`, the directory of the layer that is opaque.
fn lower_files() -> Vec<crate::rootfs::RootFile> {
    let leak = |text: String| -> &'static str { Box::leak(text.into_boxed_str()) };
    let dir = |path: &'static str| crate::rootfs::RootFile {
        path,
        mode: 0o755,
        uid: 0,
        gid: 0,
        source: None,
    };
    let mut files = vec![dir("/lowdeep")];
    let mut path = String::from("/lowdeep");
    for k in 1..=32 {
        path.push_str(&format!("/l{k}"));
        files.push(dir(leak(path.clone())));
    }
    files.push(dir("/lowbig"));
    files.push(crate::rootfs::RootFile {
        path: "/lowbig/big",
        mode: 0o644,
        uid: 0,
        gid: 0,
        source: Some(crate::rootfs::Source::Bytes(
            "layer-steps-lowbig",
            Box::leak(
                (0..BIG_BYTES)
                    .map(|i| (i % 251) as u8 | 1)
                    .collect::<Vec<u8>>()
                    .into_boxed_slice(),
            ),
        )),
    });
    files.push(dir("/opq"));
    files.push(crate::rootfs::RootFile {
        path: "/opq/lowfile",
        mode: 0o644,
        uid: 0,
        gid: 0,
        source: Some(crate::rootfs::Source::Bytes(
            "layer-steps-opq-lowfile",
            b"hidden by the opaque directory\n",
        )),
    });
    files
}

fn programs(layerd: &'static [&'static str]) -> Vec<ImageProgram> {
    let mut list = layer_names::programs(layerd, &[]);
    // The RAM file service tells its steps too: the reads of the copy are among them.
    let at = list
        .iter()
        .position(|p| p.0 == "ramfs")
        .expect("the image has the RAM file service");
    list[at].3 = &["steps"];
    list
}

/// The programs of the image, for the check of the stacks of every list of programs.
#[cfg(test)]
pub fn plain_programs() -> Vec<ImageProgram> {
    programs(&[])
}

fn boot(
    machine: &qemu::Machine,
    features: &'static [&'static str],
) -> Result<(qemu::Outcome, u64), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = write_boot_image_files(
        IMAGE,
        &programs(features),
        BOOT_PROFILE,
        &[("STAFETO_LAYER_NAMES_MODE", "scale")],
        lower_files(),
    )?;
    let disk = layer_names::Disk(
        std::env::temp_dir().join(format!("stafeto-layer-steps-{}.img", std::process::id())),
    );
    crate::data_image::make_layer_steps_volume(&disk.0, DISK_BYTES)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&disk.0, None));
    cmd.args(["-smp", "1", "-icount", "shift=4,sleep=on"]);
    let started = std::time::Instant::now();
    let output = run_until(cmd, LIMIT, Some(ENDS), &kernel.elf)?;
    Ok((output, started.elapsed().as_secs()))
}

/// Each check has one line `ok`, in the order of `CHECKS`, and the end comes once, after them all.
pub fn read_lines(lines: &[String]) -> Result<(), String> {
    layer_names::registered(lines)?;
    let mine = layer_names::mine(lines);
    if let Some(bad) = mine
        .iter()
        .find(|l| l.contains("FAILED") || l.contains("checks failed"))
    {
        return Err(format!("layer-steps: {bad}"));
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
    Ok(())
}

/// The gate: every step of the service of every kind is at most 0.9 B judged, and none over B.
pub fn gate(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = crate::step_line::longest(lines, STEP_TAG);
    if rows.is_empty() {
        return Err("layer-steps: the service printed no step".into());
    }
    crate::step_line::within_b(lines, STEP_TAG, crate::step_line::Kinds::All)?;
    let bound = crate::TERM_B * 9 / 10;
    if let Some(row) = rows.iter().find(|r| r.1 > bound) {
        return Err(format!(
            "layer-steps: a step of kind {} took {} ticks, over 0.9 B ({bound}); all rows {rows:?}",
            row.0, row.1
        ));
    }
    Ok(rows)
}

/// The steps of the RAM file service: none over B, and the reads of the copy among them (kind 63, the
/// step of READ_AT_FD_INTO of 12 KiB) at most 0.9 B and seen at all, so that the copy of the lower
/// file of 64 MiB was made through them. The longest of the kind, in ticks.
pub fn ram_gate(lines: &[String]) -> Result<u64, String> {
    crate::step_line::within_b(lines, RAM_TAG, crate::step_line::Kinds::All)?;
    let rows = crate::step_line::longest(lines, RAM_TAG);
    let reads = rows
        .iter()
        .find(|r| r.0 == RAM_READ_KIND && r.1 != 0)
        .ok_or_else(|| {
            format!("layer-steps: the RAM file service printed no read of the copy: {rows:?}")
        })?;
    let bound = crate::TERM_B * 9 / 10;
    if reads.1 > bound {
        return Err(format!(
            "layer-steps: a read of the copy took {} ticks in the RAM file service, over 0.9 B ({bound}); all rows {rows:?}",
            reads.1
        ));
    }
    Ok(reads.1)
}

/// The line the service says when its index is built: the names, the marks and the steps it took.
fn index_line(lines: &[String]) -> Result<(u32, u32, u32), String> {
    let line = lines
        .iter()
        .find_map(|l| l.split_once("layerd: index built: ").map(|(_, rest)| rest))
        .ok_or("the service did not say its index is built")?;
    let number = |at: usize| -> Result<u32, String> {
        line.split_whitespace()
            .nth(at)
            .and_then(|w| w.parse().ok())
            .ok_or_else(|| format!("the line {line:?} has no number at {at}"))
    };
    Ok((number(0)?, number(3)?, number(6)?))
}

pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    let (output, seconds) = boot(machine, &["steps"])?;
    read_lines(&output.lines)?;
    qemu::expect_stopped_on(
        &output,
        "init: layer-names ended: exit code 0, not restarted",
    )?;
    let (names, deleted, steps) = index_line(&output.lines)?;
    let marks = (crate::data_image::STEPS_MARKS + crate::data_image::STEPS_MK2_MARKS) as u32;
    if names != crate::data_image::STEPS_NAMES as u32 || deleted != marks {
        return Err(format!(
            "the index holds {names} names and {deleted} marks, {} names and {marks} marks were due",
            crate::data_image::STEPS_NAMES
        ));
    }
    let rows = gate(&output.lines)?;
    let read = ram_gate(&output.lines)?;
    println!(
        "layer-steps on {}: {names} names built in {steps} steps, a file at 247 components, a path of 253, a merged listing of {} names, a lower file of 64 MiB copied up meanwhile (a read of the copy in the RAM file service {read} ticks); steps of the layer service (kind, ticks, detail) {rows:?}, none over 0.9 B ({}) in {seconds} s: ok",
        machine.name,
        crate::data_image::STEPS_LISTED,
        crate::TERM_B * 9 / 10
    );
    Ok(())
}

/// The break: the service that walks the whole layer in one step must fail the gate.
pub fn breaks(machine: &qemu::Machine) -> Result<(), String> {
    for (feature, gate_only) in BREAKS {
        let features: &'static [&'static str] =
            Box::leak(vec!["steps", feature].into_boxed_slice());
        let (output, seconds) = boot(machine, features)?;
        // A step the watch of init finds too long kills the service (`went silent`).
        let silent = output
            .lines
            .iter()
            .find(|l| l.contains("layerd went silent"));
        match gate(&output.lines) {
            Err(why) if why.contains("kind 6") || why.contains("over 0.9 B") => {
                println!(
                    "layer-steps breaks: {feature} is caught by the step gate ({why}) in {seconds} s"
                );
            }
            _ if silent.is_some() && !gate_only => {
                println!(
                    "layer-steps breaks: {feature} is caught by the watch of init ({}) in {seconds} s",
                    silent.map_or("", String::as_str)
                );
            }
            Err(why) => {
                return Err(format!(
                    "layer-steps breaks: {feature} failed for another reason: {why}"
                ));
            }
            Ok(rows) => {
                return Err(format!(
                    "layer-steps breaks: {feature} passed the gate: {rows:?}"
                ));
            }
        }
    }
    Ok(())
}

pub fn command(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => probe(machine),
        Some("breaks") if args.len() == 1 => breaks(machine),
        Some(other) => Err(format!("layer-steps [breaks]: unknown argument {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(kind: usize, ticks: u64) -> String {
        format!("service step: {STEP_TAG} kind {kind} {ticks} ticks")
    }

    #[test]
    fn a_step_over_the_target_fails_the_gate_and_one_under_it_passes() {
        let ok = vec![step(63, 17_000), step(64, 8_743)];
        assert_eq!(gate(&ok).unwrap().len(), 2);
        let over = vec![step(63, 17_000), step(64, 18_400)];
        assert!(gate(&over).unwrap_err().contains("over 0.9 B"));
        let long = vec![step(64, 250_000)];
        assert!(gate(&long).is_err());
        assert!(gate(&[]).is_err());
    }

    #[test]
    fn the_reads_of_the_copy_are_judged_in_the_ram_file_service() {
        let step =
            |kind: usize, ticks: u64| format!("service step: {RAM_TAG} kind {kind} {ticks} ticks");
        let ok = vec![step(63, 14_002), step(64, 5_043)];
        assert_eq!(ram_gate(&ok), Ok(14_002));
        // A read over 0.9 B, a step over B, and a run with no read of the copy fail.
        assert!(ram_gate(&[step(63, 18_400)]).unwrap_err().contains("0.9 B"));
        assert!(ram_gate(&[step(63, 14_000), step(64, 21_000)]).is_err());
        assert!(
            ram_gate(&[step(64, 5_000)])
                .unwrap_err()
                .contains("no read")
        );
        assert!(ram_gate(&[]).is_err());
    }

    #[test]
    fn the_index_line_is_read() {
        let lines = vec!["layerd: index built: 8192 names and 0 deletions in 120 steps".to_owned()];
        assert_eq!(index_line(&lines), Ok((8192, 0, 120)));
        assert!(index_line(&[]).is_err());
    }

    #[test]
    fn the_checks_are_the_ones_the_probe_prints() {
        let mut lines = vec!["layerd: root registered with the process service".to_owned()];
        lines.extend(CHECKS.iter().map(|c| format!("{PREFIX}{c} ok")));
        lines.push(format!("{PREFIX}{PASSED}"));
        assert!(read_lines(&lines).is_ok());
        lines.remove(3);
        assert!(read_lines(&lines).is_err());
    }
}
