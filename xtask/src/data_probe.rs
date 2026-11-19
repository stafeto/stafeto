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
/// The stack of the probe. Its calls are nested: `verify` holds a reply of 1 KiB (`MESSAGE_MAX`) and
/// the checks of the version 3 series add `stat_of`, `Client::call` with its own reply and request
/// and the copies the `Result`s make, each of a kilobyte or more; 16 KiB (`CHILD_STACK_SIZE`) was
/// overrun by a write fault below the stack in the verifying boot. 32 KiB leaves the room of the
/// deepest chain (about 8 frames of 2 KiB) twice over.
const DATA_PROBE_STACK_SIZE: u32 = 32 * 1024;
const DISK_BYTES: u64 = 64 << 20;
const STEPS: u32 = 12;
/// The files of the tree after the 12 steps: f2 to f4, f6 to f8 and f10 to f12.
const FILES: u32 = 9;
/// The seconds the verifying boot of `probe` sleeps before its first request. The service walks the
/// volume once its queue has been quiet for 2 s (`datafs::idle::QUIET_NS`) from the end of its mount
/// work; 4 s leaves the mount work and the walk of this small volume (milliseconds) well inside it,
/// so the walk ends before the probe's first request and nothing waits behind it.
const VERIFY_WAIT_S: u32 = 4;
/// The longest the walk of the probe's volume may take, in milliseconds: the volume is a few MiB.
const WALK_MS_MAX: u64 = 1000;
const ENDS: &str = "init: data-probe ended: ";
const ENDED: &str = "init: data-probe ended: exit code 0, not restarted";
const POINTS: u64 = 12;
/// The tag of the service's lines of steps (rt::service::report_steps).
const DATAFS_TAG: &str = "17";
/// The kinds of the loop that the probe's two runs use: the methods of proto_data that the series
/// and the check send (the worker thread does the disk's work, so these steps are the queue's), the notices
/// with the heartbeat (64) and the notification the service marks as its own (65, the worker's DONE).
const STEP_KINDS: [(usize, &str); 15] = [
    (1, "Open"),
    (2, "Close"),
    (3, "Read"),
    (4, "Write"),
    (6, "Fsync"),
    (8, "Stat"),
    (10, "Mkdir"),
    (11, "Unlink"),
    (13, "Rename"),
    (14, "Readdir"),
    (19, "Clone"),
    (25, "Bind"),
    (26, "Chmod"),
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
        ("data-probe", "data-probe", DATA_PROBE_STACK_SIZE, &[]),
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
    wait_s: u32,
) -> Result<PathBuf, String> {
    let (point, min) = (crash_at.unwrap_or(0).to_string(), min.to_string());
    let wait = wait_s.to_string();
    let env = [
        ("STAFETO_DATA_PROBE_MODE", mode),
        ("STAFETO_DATA_PROBE_MIN", min.as_str()),
        ("STAFETO_DATA_PROBE_WAIT_S", wait.as_str()),
        ("STAFETO_DATAFS_CRASH_AT", point.as_str()),
        // The version 3 series runs in the two boots of `probe` and not in the crash runs, whose
        // count of the sectors it would move.
        (
            "STAFETO_DATA_PROBE_V3",
            if crash_at.is_none()
                && !name.contains("crash")
                && !name.contains("fill")
                && !name.contains("settle")
            {
                "1"
            } else {
                "0"
            },
        ),
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

/// The line of the first walk of the volume, if the run has it (`datafs: first walk N blocks used,
/// M reads, T ms`, or that a request or the mount work made it). The worker walks after the queue
/// has been empty for 2 s (`datafs::idle::QUIET_NS`), and the probes end within seconds of READY, so
/// a run may end before the walk starts: no probe requires the line, and each checks what a run
/// does show. At most one line of the first walk, none that says it failed, and no more than
/// `MAX_YIELDS` lines of a walk stopped for a request. The lines of the services come glued to the
/// lines of a step under -icount, so the text is looked for inside the line. Returns the text from
/// `first walk` on when it is there.
pub(crate) fn first_walk(lines: &[String], what: &str) -> Result<Option<String>, String> {
    let said: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.find("datafs: first walk ").map(|at| &l[at..]))
        .collect();
    let stopped = lines
        .iter()
        .filter(|l| l.contains("datafs: walk stopped for a request"))
        .count();
    if stopped > 3 {
        return Err(format!(
            "data-probe ({what}): {stopped} walks stopped for a request, three tries at most"
        ));
    }
    match said.as_slice() {
        [] => Ok(None),
        [one] if one.contains("failed") => Err(format!("data-probe ({what}): {one}")),
        [one] => Ok(Some((*one).to_owned())),
        other => Err(format!(
            "data-probe ({what}): {} lines of the first walk, one at most: {other:?}",
            other.len()
        )),
    }
}

/// The numbers of a line of a walk that ran to its end: `first walk N blocks used, M reads, T ms`
/// (the line a real walk prints; the lines that say a request or the mount work made the walk, that
/// say it failed, or that say a request stopped tries of it, have other tails).
fn parse_walk(text: &str) -> Option<(u64, u64, u64)> {
    let rest = text.strip_prefix("first walk ")?;
    let (blocks, rest) = rest.split_once(" blocks used, ")?;
    let (reads, rest) = rest.split_once(" reads, ")?;
    let ms = rest.strip_suffix(" ms")?;
    Some((blocks.parse().ok()?, reads.parse().ok()?, ms.parse().ok()?))
}

/// The proof that a walk started after the quiet time (the timer of the worker works on the guest):
/// the verifying boot sleeps before its first request, so the volume, which the mount work left
/// with an empty window, is walked in the quiet; the run has exactly one line of the walk in the
/// form of a real walk, before the probe woke, with the reads and the time of it, no failed walk and
/// no walk stopped for a request. Returns the numbers.
fn real_walk(lines: &[String], what: &str) -> Result<(u64, u64, u64), String> {
    let mut found = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if let Some(at) = l.find("datafs: first walk ") {
            found.push((i, &l[at + "datafs: ".len()..]));
        }
    }
    let [(at, text)] = found.as_slice() else {
        return Err(format!(
            "data-probe ({what}): {} lines of the first walk, exactly one expected: {found:?}",
            found.len()
        ));
    };
    let Some((blocks, reads, ms)) = parse_walk(text) else {
        return Err(format!(
            "data-probe ({what}): the line of the walk is not the form of a walk that ran to its end (N blocks used, M reads, T ms): {text:?}"
        ));
    };
    let woke = lines.iter().position(|l| l.contains("data-probe: waited "));
    if woke.is_none_or(|w| *at > w) {
        return Err(format!(
            "data-probe ({what}): the walk's line is not before the probe's first request (the probe woke at line {woke:?}, the walk's line is line {at})"
        ));
    }
    if reads == 0 || blocks == 0 || ms > WALK_MS_MAX {
        return Err(format!(
            "data-probe ({what}): a walk of {blocks} blocks, {reads} reads, {ms} ms is not one of this volume (at most {WALK_MS_MAX} ms)"
        ));
    }
    if lines.iter().any(|l| {
        l.contains("datafs: walk stopped for a request") || l.contains("first walk failed")
    }) {
        return Err(format!("data-probe ({what}): a walk was stopped or failed"));
    }
    Ok((blocks, reads, ms))
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
    let writer = image("boot-data-probe-write.img", None, "write", 0, 0)?;
    let lines = run_to_end(&built, machine(&built, &writer, &disk.0, true), "writing")?;
    let written = lines.clone();
    let mut wanted: Vec<String> = (1..=STEPS)
        .map(|j| format!("data-probe: synced {j}"))
        .collect();
    wanted.push("data-probe: written".into());
    // The version 3 series: the record of a native client's files, and the refusals of a session
    // with no mark and no BIND (NOT_BOUND) and of a BIND with a copy that is no identity session.
    wanted.push("data-probe: v3 stat 0644 0:0 ino ok".into());
    wanted.push("data-probe: unbound session refused ok".into());
    wanted.push("data-probe: finished".into());
    need(&lines, &wanted, "writing")?;
    if datafs_line(&lines, "partition table written, data volume formatted").is_none() {
        return Err("data-probe (writing): the volume was not partitioned and formatted".into());
    }
    let walk_writing = first_walk(&lines, "writing")?;
    let verifier = image(
        "boot-data-probe-verify.img",
        None,
        "verify",
        STEPS,
        VERIFY_WAIT_S,
    )?;
    let lines = run_to_end(
        &built,
        machine(&built, &verifier, &disk.0, true),
        "verifying",
    )?;
    need(
        &lines,
        &[
            format!("data-probe: verify ok progress={STEPS} files={FILES}"),
            "data-probe: chmod survives a remount ok".to_string(),
        ],
        "verifying",
    )?;
    if datafs_line(&lines, "data volume mounted").is_none() {
        return Err("data-probe (verifying): the service did not only mount the volume".into());
    }
    first_walk(&lines, "verifying")?;
    let (blocks, reads, ms) = real_walk(&lines, "verifying")?;
    let said = |w: Option<String>| w.unwrap_or_else(|| "no line of the first walk".into());
    println!(
        "data-probe: {} (writing); the verifying boot slept {VERIFY_WAIT_S} s before its first request and the service walked the volume in the quiet, {blocks} blocks used, {reads} reads, {ms} ms: ok",
        said(walk_writing)
    );
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
    let image = image("boot-data-crash-count.img", Some(0), "write", 0, 0)?;
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
    let crashed = image("boot-data-crash.img", Some(point), "write", 0, 0)?;
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
    let verifier = image("boot-data-crash-verify.img", None, "verify", last, 0)?;
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

/// The lines of the service and of the probe that a measurement run reports, in the order they came.
fn report(lines: &[String], what: &str) {
    const WANTED: [&str; 10] = [
        "datafs: ready after",
        "datafs: first walk",
        "datafs: refresh walk",
        "datafs: walk cpu",
        "datafs: job ",
        "entries got attributes",
        "datafs: data volume mounted",
        "data-probe: fill",
        "datafs: the budget of the worker",
        "datafs: serve ran",
    ];
    println!("data-probe fill ({what}):");
    for l in lines {
        let start = l.find("datafs: ").or_else(|| l.find("data-probe: fill"));
        if let Some(at) = start.filter(|_| WANTED.iter().any(|w| l.contains(w))) {
            println!("  {}", &l[at..]);
        }
    }
}

/// `cargo xtask data-probe fill`: the measurements of the plan's step on a volume of 1 GiB with
/// small and large files (`data_image::make_filled`, the layout an older release leaves, no
/// attribute anywhere). The first boot converts the volume (the lines `entries got attributes` and
/// `ready after`) and walks it in the quiet; the second boot, on the converted volume, reports the
/// mount time, the first call, the listing of 1,000 entries, RMDIR, the longest WRITE, the removal of
/// large files with the refresh walk after it, the longest job of each method (the service is built
/// with `steps`) and the CPU the worker took in each walk. QEMU runs with real time (no `-icount`):
/// the figures are those of the host's disk and CPU, for the table of the limit of the volume (the
/// reads a second and the time of a walk).
pub fn fill() -> Result<(), String> {
    let built = Built {
        kernel: build(Variant::Normal)?,
    };
    let disk = Disk::new("fill");
    let started = std::time::Instant::now();
    super::data_image::make_filled(
        &disk.0,
        super::data_image::FILL_DISK,
        super::data_image::FILL_1G,
    )?;
    println!(
        "data-probe fill: the disk of 2 GiB with a data partition of 1,023 MiB made in {} s",
        started.elapsed().as_secs()
    );
    let settle = image("boot-data-probe-settle.img", None, "settle", 0, 10)?;
    let lines = run_to_end(
        &built,
        machine(&built, &settle, &disk.0, false),
        "converting boot",
    )?;
    need_ready(&lines, "converting boot")?;
    report(&lines, "the boot that converts the volume");
    let measure = image("boot-data-probe-fill.img", None, "fill", 0, 0)?;
    let lines = run_to_end(
        &built,
        machine(&built, &measure, &disk.0, false),
        "measuring boot",
    )?;
    need_ready(&lines, "measuring boot")?;
    need(
        &lines,
        &["data-probe: fill done".to_string()],
        "measuring boot",
    )?;
    for tag in [
        "data-probe: fill first call",
        "data-probe: fill readdir 1002 entries",
        "data-probe: fill rmdir",
        "data-probe: fill write",
        "data-probe: fill unlink 24 files",
        "data-probe: fill free blocks",
    ] {
        if !lines.iter().any(|l| l.contains(tag)) {
            return Err(format!("data-probe fill: no line {tag:?}"));
        }
    }
    report(&lines, "the boot that measures");
    Ok(())
}

/// The service said it was ready, after how long.
fn need_ready(lines: &[String], what: &str) -> Result<(), String> {
    if lines.iter().any(|l| l.contains("datafs: ready after ")) {
        Ok(())
    } else {
        Err(format!(
            "data-probe fill ({what}): no line `datafs: ready after`"
        ))
    }
}

pub fn command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => probe(),
        Some("fill") if args.len() == 1 => fill(),
        Some(other) => Err(format!("data-probe: unknown argument {other}")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_probe_has_the_stack_its_nested_calls_need() {
        // The verifying boot overran 16 KiB: the stack is not lowered again without a measurement.
        assert!(super::DATA_PROBE_STACK_SIZE >= 32 * 1024);
        assert!(
            super::PROGRAMS
                .iter()
                .any(|p| p.0 == "data-probe" && p.2 == super::DATA_PROBE_STACK_SIZE)
        );
    }

    #[test]
    fn a_walk_line_is_read_only_in_the_form_of_a_walk_that_ran_to_its_end() {
        use super::parse_walk;
        assert_eq!(
            parse_walk("first walk 6 blocks used, 16 reads, 35 ms"),
            Some((6, 16, 35))
        );
        for text in [
            "first walk made at mount, 6 blocks used",
            "first walk made by a request, 6 blocks used",
            "first walk failed after 4 reads, 3 ms",
            "first walk 6 blocks used, 16 reads, 35 ms, after 3 tries a request stopped",
            "refresh walk 6 blocks used, about 3 given back, 16 reads, 35 ms",
        ] {
            assert_eq!(parse_walk(text), None, "{text}");
        }
    }

    #[test]
    fn the_proof_of_a_walk_wants_one_line_before_the_probe_woke() {
        use super::real_walk;
        let lines = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let good = lines(&[
            "datafs: data volume mounted, 800 blocks, partition at sector 2048",
            "datafs: first walk 6 blocks used, 16 reads, 35 ms",
            "data-probe: waited 4 s",
            "data-probe: verify ok progress=12 files=9",
        ]);
        assert_eq!(real_walk(&good, "t"), Ok((6, 16, 35)));
        // No line, a line of the other forms, a walk after the probe woke, a walk that was stopped.
        for bad in [
            lines(&["data-probe: waited 4 s"]),
            lines(&[
                "datafs: first walk made at mount, 6 blocks used",
                "data-probe: waited 4 s",
            ]),
            lines(&[
                "data-probe: waited 4 s",
                "datafs: first walk 6 blocks used, 16 reads, 35 ms",
            ]),
            lines(&[
                "datafs: walk stopped for a request after 1 reads, try 1",
                "datafs: first walk 6 blocks used, 16 reads, 35 ms",
                "data-probe: waited 4 s",
            ]),
            lines(&[
                "datafs: first walk 6 blocks used, 16 reads, 5000 ms",
                "data-probe: waited 4 s",
            ]),
        ] {
            assert!(real_walk(&bad, "t").is_err(), "{bad:?}");
        }
    }

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
