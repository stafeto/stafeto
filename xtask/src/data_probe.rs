// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask data-probe` and `cargo xtask data-crash [N]`: the data file service
//! (services/datafs, littlefs on the data partition of the disk service) on QEMU's `virt` with a disk
//! file (`qemu::store`) and the probe tests/data-probe.
//!
//! `data-probe`: the first run starts on a disk of zeros. The service writes a table with the
//! partitions `store` and `data` and formats `data`, the probe writes the series of 12 steps (files
//! made, written, synced, renamed, removed), and the machine ends. The second run starts on the same file:
//! the service only mounts, and the probe finds every step there, every file whole.
//!
//! `data-crash`: the service is built to stop after the sector of the volume that the point names
//! was written (`datafs/crash`), the write that holds it torn at the sector. The host reads the count
//! of sectors the series writes from a run that does not stop, spreads 12 points over it, and for
//! each one kills the machine on the service's line `datafs: crash point N` and starts it again on
//! the same file. The verifying probe finds a tree that is whole: the steps whose line `data-probe:
//! synced J` came out before the cut are all there, no file is torn, the next write goes through, and
//! the service mounted what was there and did not format it again.

use super::*;
use std::path::{Path, PathBuf};

const DATAFS_STACK_SIZE: u32 = 32 * 1024;
const DISK_BYTES: u64 = 64 << 20;
const STEPS: u32 = 12;
/// The files of the tree after the 12 steps: f2 to f4, f6 to f8 and f10 to f12.
const FILES: u32 = 9;
const ENDS: &str = "init: data-probe ended: ";
const ENDED: &str = "init: data-probe ended: exit code 0, not restarted";
const POINTS: u64 = 12;
/// The tag of the service's lines of steps (rt::service::report_steps).
const DATAFS_TAG: &str = "17";
/// The kinds of the loop that the probe's two runs use: the methods of proto_data that the series
/// and the check send (the worker thread does the disk's work, so these steps are the queue's), the notices
/// with the heartbeat (64) and the notification the service marks as its own (65, the worker's DONE).
const STEP_KINDS: [(usize, &str); 11] = [
    (1, "Open"),
    (2, "Close"),
    (3, "Read"),
    (4, "Write"),
    (6, "Fsync"),
    (10, "Mkdir"),
    (11, "Unlink"),
    (13, "Rename"),
    (14, "Readdir"),
    (64, "the notices and the heartbeat"),
    (65, "the service's own step"),
];

/// The steps of the loop in the lines of the two runs: every kind the probe used came, and no step
/// is past 0.9 of term B (spec 3, section 6), the bound the other services' probes use.
fn steps_verdict(
    writing: &[String],
    verifying: &[String],
) -> Result<Vec<(usize, u64, u64)>, String> {
    let mut rows = longest_steps(writing, DATAFS_TAG);
    for row in longest_steps(verifying, DATAFS_TAG) {
        match rows.iter_mut().find(|r| r.0 == row.0) {
            Some(known) if known.1 < row.1 => *known = row,
            Some(_) => {}
            None => rows.push(row),
        }
    }
    for (kind, name) in STEP_KINDS {
        if !rows.iter().any(|(k, ..)| *k == kind) {
            return Err(format!("the data service: no step {name}: {rows:?}"));
        }
    }
    if let Some(row) = rows.iter().find(|r| r.1 > blk_probe::STEP_MAX) {
        return Err(format!(
            "the data service: a step past 0.9 of term B ({}): {row:?}",
            blk_probe::STEP_MAX
        ));
    }
    Ok(rows)
}

const fn programs(crash: bool) -> [ImageProgram; 5] {
    // The crash runs stop the machine at a sector and count nothing else; the others print the
    // longest step of each kind of the request loop (rt's step-stats).
    let datafs: &'static [&'static str] = if crash { &["crash"] } else { &["steps"] };
    [
        ("init", "init", INIT_STACK_SIZE, &["table-data-probe"]),
        ("uart", "uart", UART_STACK_SIZE, &[]),
        ("virtio-blk", "virtio-blk", blk_probe::BLK_STACK_SIZE, &[]),
        ("datafsd", "datafsd", DATAFS_STACK_SIZE, datafs),
        ("data-probe", "data-probe", CHILD_STACK_SIZE, &[]),
    ]
}
pub const PROGRAMS: [ImageProgram; 5] = programs(false);
const PROGRAMS_CRASH: [ImageProgram; 5] = programs(true);

/// The disk of a run: named by the process and the variant, removed at the end.
struct Disk(PathBuf);

impl Disk {
    fn new(what: &str) -> Disk {
        Disk(std::env::temp_dir().join(format!("stafeto-data-{}-{what}.img", std::process::id())))
    }
}

impl Drop for Disk {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct Built {
    kernel: Artifacts,
}

/// The image of a run: the probe in `mode` (`write` or `verify`, with the last step the host saw the
/// line of) and the service with or without the crash point.
fn image(
    name: &'static str,
    crash_at: Option<u64>,
    mode: &str,
    min: u32,
) -> Result<PathBuf, String> {
    let (point, min) = (crash_at.unwrap_or(0).to_string(), min.to_string());
    let env = [
        ("STAFETO_DATA_PROBE_MODE", mode),
        ("STAFETO_DATA_PROBE_MIN", min.as_str()),
        ("STAFETO_DATAFS_CRASH_AT", point.as_str()),
    ];
    let programs: &'static [ImageProgram] = if crash_at.is_some() {
        &PROGRAMS_CRASH
    } else {
        &PROGRAMS
    };
    write_boot_image_files(name, programs, BOOT_PROFILE, &env, Vec::new())
}

/// The machine of a run. With `icount` the clock follows the instructions, so the steps of the
/// request loop are the same in every run (the probe's two runs). The clock is the one of
/// `sleep=on` (the network probes' choice): while the guest waits for the disk in `wfi`, time
/// follows the host's, and does not jump to the guest's own deadline (the 10 s wait of datafs for
/// the disk service) before the completion of the host's file I/O comes (stafeto/stafeto#459).
fn machine(built: &Built, image: &Path, disk: &Path, icount: bool) -> Command {
    let mut cmd = qemu::command(&qemu::VIRT, &built.kernel.image, Some(image));
    cmd.args(qemu::HEADLESS).args(qemu::store(disk, None));
    if icount {
        cmd.args(["-icount", "shift=4,sleep=on"]);
    }
    cmd
}

/// A run until the probe ends well.
fn run_to_end(built: &Built, cmd: Command, what: &str) -> Result<Vec<String>, String> {
    let output = run_until(cmd, BOOT_TIMEOUT * 6, Some(ENDS), &built.kernel.elf)
        .map_err(|e| format!("data-probe ({what}): {e}"))?;
    if let Some(failed) = output
        .lines
        .iter()
        .find(|l| l.starts_with("data-probe: failed"))
    {
        return Err(format!("data-probe ({what}): {failed}"));
    }
    qemu::expect_stopped_on(&output, ENDED).map_err(|e| format!("data-probe ({what}): {e}"))?;
    Ok(output.lines)
}

fn has(lines: &[String], text: &str) -> bool {
    lines.iter().any(|l| l == text)
}

fn need(lines: &[String], wanted: &[String], what: &str) -> Result<(), String> {
    for text in wanted {
        if !has(lines, text) {
            let said: Vec<_> = lines
                .iter()
                .filter(|l| l.starts_with("datafs") || l.starts_with("data-probe"))
                .collect();
            return Err(format!(
                "data-probe ({what}): no line {text:?}; seen {said:?}"
            ));
        }
    }
    Ok(())
}

fn datafs_line(lines: &[String], prefix: &str) -> Option<String> {
    lines
        .iter()
        .find_map(|l| l.strip_prefix("datafs: ").filter(|r| r.starts_with(prefix)))
        .map(str::to_owned)
}

/// The line of the first walk of the volume (`datafs: first walk N blocks used, M reads, T ms`, or
/// that a request or the mount work made it), which the worker prints once after READY, when its queue
/// is empty (a walk that a request stopped is tried again and prints its line when it ends). The
/// lines of the services come glued to the lines of a step under -icount, so the text is looked for
/// inside the line. Returns the text from `first walk` on.
pub(crate) fn first_walk(lines: &[String], what: &str) -> Result<String, String> {
    let said: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.find("datafs: first walk ").map(|at| &l[at..]))
        .collect();
    match said.as_slice() {
        [one] => Ok((*one).to_owned()),
        other => Err(format!(
            "data-probe ({what}): {} lines of the first walk, one expected: {other:?}",
            other.len()
        )),
    }
}

fn synced(lines: &[String]) -> u32 {
    lines
        .iter()
        .filter_map(|l| l.strip_prefix("data-probe: synced ")?.parse().ok())
        .max()
        .unwrap_or(0)
}

/// The run on a disk of zeros and the run on the same file after the machine ended.
pub fn probe() -> Result<(), String> {
    let built = Built {
        kernel: build(Variant::Normal)?,
    };
    let disk = Disk::new("probe");
    qemu::store_file(&disk.0, DISK_BYTES, true)?;
    let writer = image("boot-data-probe-write.img", None, "write", 0)?;
    let lines = run_to_end(&built, machine(&built, &writer, &disk.0, true), "writing")?;
    let written = lines.clone();
    let mut wanted: Vec<String> = (1..=STEPS)
        .map(|j| format!("data-probe: synced {j}"))
        .collect();
    wanted.push("data-probe: written".into());
    wanted.push("data-probe: finished".into());
    need(&lines, &wanted, "writing")?;
    if datafs_line(&lines, "partition table written, data volume formatted").is_none() {
        return Err("data-probe (writing): the volume was not partitioned and formatted".into());
    }
    let walk_writing = first_walk(&lines, "writing")?;
    let verifier = image("boot-data-probe-verify.img", None, "verify", STEPS)?;
    let lines = run_to_end(
        &built,
        machine(&built, &verifier, &disk.0, true),
        "verifying",
    )?;
    need(
        &lines,
        &[format!(
            "data-probe: verify ok progress={STEPS} files={FILES}"
        )],
        "verifying",
    )?;
    if datafs_line(&lines, "data volume mounted").is_none() {
        return Err("data-probe (verifying): the service did not only mount the volume".into());
    }
    let walk_verifying = first_walk(&lines, "verifying")?;
    println!("data-probe: {walk_writing} (writing), {walk_verifying} (verifying)");
    let rows = steps_verdict(&written, &lines)?;
    println!("data-probe: steps of the request loop (kind, ticks, whole step): {rows:?}");
    println!(
        "data-probe: a table with store and data, littlefs formatted, 12 steps of files made, synced, renamed and removed, the same tree after a new start of QEMU: ok"
    );
    Ok(())
}

/// The sectors the series writes, from a run of the service built for the crash tests that does not
/// stop (its STATFS at the end prints the count).
fn series_sectors(built: &Built) -> Result<u64, String> {
    let disk = Disk::new("crash-count");
    qemu::store_file(&disk.0, DISK_BYTES, true)?;
    let image = image("boot-data-crash-count.img", Some(0), "write", 0)?;
    let lines = run_to_end(built, machine(built, &image, &disk.0, false), "counting")?;
    datafs_line(&lines, "written ")
        .and_then(|l| l.strip_prefix("written ")?.trim().parse().ok())
        .ok_or_else(|| {
            "data-crash: the service did not say how many sectors the series wrote".into()
        })
}

/// One point: the machine killed after sector `point` of the series, started again.
fn crash_point(built: &Built, point: u64) -> Result<(), String> {
    let disk = Disk::new(&format!("crash-{point}"));
    qemu::store_file(&disk.0, DISK_BYTES, true)?;
    let crashed = image("boot-data-crash.img", Some(point), "write", 0)?;
    let marker = format!("datafs: crash point {point}");
    let output = run_until(
        machine(built, &crashed, &disk.0, false),
        BOOT_TIMEOUT * 6,
        Some(&marker),
        &built.kernel.elf,
    )
    .map_err(|e| format!("data-crash {point}: {e}"))?;
    if !output.stopped_on_marker {
        let said: Vec<_> = output
            .lines
            .iter()
            .filter(|l| l.starts_with("datafs") || l.starts_with("data-probe"))
            .collect();
        return Err(format!(
            "data-crash {point}: the service never said {marker:?}: {said:?}"
        ));
    }
    let last = synced(&output.lines);
    let verifier = image("boot-data-crash-verify.img", None, "verify", last)?;
    let lines = run_to_end(
        built,
        machine(built, &verifier, &disk.0, false),
        &format!("point {point}"),
    )?;
    let ok = lines
        .iter()
        .find_map(|l| l.strip_prefix("data-probe: verify ok progress="))
        .ok_or_else(|| format!("data-crash {point}: the probe did not verify the tree"))?;
    if datafs_line(&lines, "data volume mounted").is_none() {
        return Err(format!(
            "data-crash {point}: the service did not mount the volume it found: {:?}",
            lines
                .iter()
                .filter(|l| l.starts_with("datafs"))
                .collect::<Vec<_>>()
        ));
    }
    println!(
        "data-crash {point}: killed after sector {point} of the series (step {last} synced), found progress={ok}: ok"
    );
    Ok(())
}

pub fn crash(args: &[String]) -> Result<(), String> {
    let built = Built {
        kernel: build(Variant::Normal)?,
    };
    let points: Vec<u64> = match args.first() {
        Some(n) => vec![
            n.parse()
                .map_err(|_| format!("data-crash: {n} is not a number of sectors"))?,
        ],
        None => {
            let total = series_sectors(&built)?;
            println!("data-crash: the series writes {total} sectors");
            let mut points: Vec<u64> = (1..=POINTS)
                .map(|k| (total * k / (POINTS + 1)).max(1))
                .collect();
            points.dedup();
            points
        }
    };
    for point in points {
        crash_point(&built, point)?;
    }
    Ok(())
}

pub fn command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => probe(),
        Some(other) => Err(format!("data-probe: unknown argument {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_stands_for_the_lines_lost_in_the_burst() {
        let lines: Vec<String> = STEP_KINDS
            .iter()
            .map(|(k, _)| format!("service step: {DATAFS_TAG} kind {k} 5000 ticks detail 0"))
            .collect();
        let lost = crate::step_line::tabled(&lines);
        assert_eq!(
            steps_verdict(&lost, &[]).map(|r| r.len()),
            Ok(STEP_KINDS.len())
        );
        // The first run lost a line, the second run's table has the kind.
        let (first, second) = lost.split_at(5);
        assert!(steps_verdict(first, second).is_ok());
        assert!(steps_verdict(first, &[]).is_err());
    }
}
