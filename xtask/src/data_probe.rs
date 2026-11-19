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
    run_to_end_within(built, cmd, what, BOOT_TIMEOUT * 6)
}

/// The same with a limit of its own, and the time the boot took told: the boots of `fill` last
/// minutes (the conversion of a full volume holds READY for as long as it takes), and the whole
/// command has the 60 minutes of the probe workflow.
fn run_to_end_within(
    built: &Built,
    cmd: Command,
    what: &str,
    limit: std::time::Duration,
) -> Result<Vec<String>, String> {
    let started = std::time::Instant::now();
    let output = run_until(cmd, limit, Some(ENDS), &built.kernel.elf).map_err(|e| {
        format!(
            "data-probe ({what}): {e} (after {} s)",
            started.elapsed().as_secs()
        )
    })?;
    if limit > BOOT_TIMEOUT * 6 {
        println!(
            "data-probe fill: the {what} took {} s of {} s allowed",
            started.elapsed().as_secs(),
            limit.as_secs()
        );
    }
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
    const WANTED: [&str; 12] = [
        "datafs: pairs ",
        "datafs: walk own work",
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
    // One CPU first: no budget `work`, no cross-CPU hand-off, the device rate to put in the table of
    // the limit of the volume; then two, where the worker has its budget on CPU 1 and the line `walk
    // cpu` tells its share, and where each read costs two crossings between the CPUs.
    let one = qemu::on_cpus(1, || fill_on(&built, 1))?;
    let two = qemu::on_cpus(2, || fill_on(&built, 2))?;
    println!(
        "data-probe fill: the first walk read {} blocks a second on one CPU and {} on two (the cost of the hand-off between the CPUs of the worker and the disk service is {}%)",
        one.rate,
        two.rate,
        (one.rate.saturating_sub(two.rate) * 100)
            .checked_div(one.rate)
            .unwrap_or(0)
    );
    Ok(())
}

/// What a run on `cpus` CPUs found.
struct Filled {
    /// The reads a second of the first walk.
    rate: u64,
}

/// The two boots of `fill` on a machine of `cpus` CPUs, on a volume of their own: the lines, and the
/// check of every figure against its bound.
fn fill_on(built: &Built, cpus: usize) -> Result<Filled, String> {
    let disk = Disk::new(&format!("fill{cpus}"));
    let started = std::time::Instant::now();
    super::data_image::make_filled(
        &disk.0,
        super::data_image::FILL_DISK,
        super::data_image::FILL_1G,
    )?;
    println!(
        "data-probe fill ({cpus} CPUs): the disk of 2 GiB with a data partition of 1,023 MiB made in {} s",
        started.elapsed().as_secs()
    );
    // The first boot converts the volume (the mount work holds READY for the conversion, and the
    // walk it needs fills the window then: the line says the first walk was `made at mount`, a walk
    // with no rate). The second boot finds nothing to convert and walks in the quiet, after READY:
    // its line has the reads and the time, which give the device rate.
    // The probe's mode `convert` sends one request, which is answered when the mount work is over
    // (READY comes after the conversion: 142 s for 3,258 entries in the first run), and ends.
    let convert = image("boot-data-probe-convert.img", None, "convert", 0, 0)?;
    let converted = run_to_end_within(
        built,
        machine(built, &convert, &disk.0, false),
        "converting boot",
        CONVERT_LIMIT,
    )?;
    need_ready(&converted, "converting boot")?;
    report(
        &converted,
        &format!("{cpus} CPUs, the boot that converts the volume"),
    );
    let settle = image(
        "boot-data-probe-settle.img",
        None,
        "settle",
        0,
        SETTLE_WAIT_S,
    )?;
    let settled = run_to_end_within(
        built,
        machine(built, &settle, &disk.0, false),
        "quiet boot",
        QUIET_LIMIT,
    )?;
    need_ready(&settled, "quiet boot")?;
    report(
        &settled,
        &format!("{cpus} CPUs, the boot that walks in the quiet"),
    );
    let measure = image("boot-data-probe-fill.img", None, "fill", 0, 0)?;
    let measured = run_to_end_within(
        built,
        machine(built, &measure, &disk.0, false),
        "measuring boot",
        MEASURE_LIMIT,
    )?;
    need_ready(&measured, "measuring boot")?;
    need(
        &measured,
        &["data-probe: fill done".to_string()],
        "measuring boot",
    )?;
    report(&measured, &format!("{cpus} CPUs, the boot that measures"));
    let checked = fill_checks(&settled, &measured, cpus)?;
    for line in &checked.lines {
        println!("data-probe fill ({cpus} CPUs): {line}");
    }
    Ok(Filled { rate: checked.rate })
}

/// The seconds the converting boot sleeps: the conversion of 3,260 entries, the quiet of 2 s and the
/// first walk of 1 GiB at 78 % (at most 60 s by the limit 4.3) fit with room over.
const SETTLE_WAIT_S: u32 = 120;

/// The limits of the three boots of `fill` (the whole command has 60 minutes, and the boots of one
/// machine took about 12 minutes together in the first run): the conversion holds READY for the
/// conversion of every entry and the move-out of every inline file (about 110 reads an entry), the
/// quiet boot sleeps `SETTLE_WAIT_S` s after a walk of up to 60 s, and the measuring boot walks the
/// volume itself, waits 65 s and removes files.
const CONVERT_LIMIT: std::time::Duration = std::time::Duration::from_secs(20 * 60);
const QUIET_LIMIT: std::time::Duration = std::time::Duration::from_secs(8 * 60);
const MEASURE_LIMIT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// The figures of a pair of boots and the bounds they were checked against.
struct Checked {
    /// The reads a second of the first walk.
    rate: u64,
    /// One line for each figure: the figure, its bound and the source of the bound.
    lines: Vec<String>,
}

/// The reads a call needs by table 4.2 of the plan as amended by the review of step 5: RMDIR of the
/// oldest directory costs 3.2 reads for each pair of the volume (the pairs are read from the line
/// `datafs: pairs N of 2048, directories M of 1024`), a `rm -rf` of D directories 1.6 reads for each
/// pair for each directory (measured 1.53 on the host at 1,010 directories in 2,148 pairs), the
/// listing of 1,000 entries, and a write (the 393 reads of the creation and write of 1 MiB, rounded
/// up).
const READDIR_READS: u64 = 197;
/// The caps of the volume (`proto_data::PAIRS_MAX` and `DIRS_MAX`).
const PAIRS_CAP: u64 = 2048;
const DIRS_CAP: u64 = 1024;
const WRITE_READS: u64 = 400;
/// The first walk of a full volume takes at most this long (limit 4.3).
const WALK_MS_LIMIT: u64 = 60_000;
/// A measured time may be this much over the time its reads take at the measured rate (3 over 2).
const MARGIN_NUM: u64 = 3;
const MARGIN_DEN: u64 = 2;
/// The overruns of `work` a period of its budget (10 ms) may have in a walk before the share the
/// line `walk cpu` tells is too low to trust.
const OVERRUNS_PER_PERIOD: u64 = 4;
/// The blocks the probe gives back with its 24 removals of 16 MiB, and the part of them the refresh
/// walk must show in the free count.
const GIVEN_BACK_BLOCKS: u64 = 24 * (16 << 20) / 4096;

/// Checks every figure of the two boots against its bound: the first walk (a time, from the line of
/// the converting boot), the device rate it gives, and the bounds of table 4.2 and the limit 4.3 for
/// the calls of the measuring boot at that rate with a margin of 1.5. On two CPUs also the share the
/// worker took in a walk and the overruns of its budget.
fn fill_checks(settled: &[String], measured: &[String], cpus: usize) -> Result<Checked, String> {
    let walk = first_walk(settled, "converting boot")?.ok_or("no line of the first walk")?;
    let walk = walk.strip_prefix("datafs: ").unwrap_or(&walk);
    let (blocks, reads, ms) = parse_walk(walk)
        .ok_or_else(|| format!("the first walk is not one that ran to its end: {walk:?}"))?;
    let rate = (reads * 1000)
        .checked_div(ms)
        .unwrap_or(reads * 1000)
        .max(1);
    let mut lines = vec![format!(
        "first walk {blocks} blocks used, {reads} reads in {ms} ms: {rate} reads a second"
    )];
    if ms > WALK_MS_LIMIT {
        return Err(format!(
            "the first walk took {ms} ms, over the 60 s of the limit 4.3 (limit of the volume)"
        ));
    }
    lines.push(format!(
        "first walk {ms} ms <= {WALK_MS_LIMIT} ms (limit 4.3, a full volume): ok"
    ));
    // The time of `reads` reads at the measured rate with the margin, in microseconds.
    let allowed = |reads: u64| reads * 1_000_000 * MARGIN_NUM / MARGIN_DEN / rate;
    let number = |prefix: &str| {
        qemu::number_after(measured, prefix)
            .ok_or_else(|| format!("no number after {prefix:?} in the measuring boot"))
    };
    // The pairs and the directories of the volume, from the count at the mount of the measuring boot.
    let counts: Vec<(u64, u64)> = measured
        .iter()
        .filter_map(|l| {
            let one = [l.clone()];
            l.contains("datafs: pairs ")
                .then(|| {
                    Some((
                        qemu::number_after(&one, "datafs: pairs ")?,
                        qemu::number_after(&one, ", directories ")?,
                    ))
                })
                .flatten()
        })
        .collect();
    let &(pairs, dirs) = counts
        .first()
        .ok_or("no line `datafs: pairs N of 2048, directories M of 1024` in the measuring boot")?;
    if pairs == 0 || pairs > PAIRS_CAP || dirs > DIRS_CAP {
        return Err(format!(
            "the volume has {pairs} pairs and {dirs} directories, over the caps of {PAIRS_CAP} and {DIRS_CAP}"
        ));
    }
    lines.push(format!(
        "the volume has {pairs} pairs of {PAIRS_CAP} and {dirs} directories of {DIRS_CAP}: ok"
    ));
    // The first call after the mount comes before the walk in the quiet starts and walks the volume
    // itself: it takes the time of the first walk (the same reads) with a margin of 1.5 and a second.
    let first_call = number("data-probe: fill first call ")?;
    let bound = ms * 1000 * MARGIN_NUM / MARGIN_DEN + 1_000_000;
    if first_call > bound {
        return Err(format!(
            "the first call took {first_call} us, over {bound} us (the first walk took {ms} ms, margin 1.5 and 1 s)"
        ));
    }
    lines.push(format!(
        "first call {first_call} us <= {bound} us (a first walk of {ms} ms, margin 1.5): ok"
    ));
    let rmdir = number("data-probe: fill rmdir ")?;
    let rmdir_reads = pairs * 32 / 10;
    let bound = allowed(rmdir_reads);
    if rmdir > bound {
        return Err(format!(
            "RMDIR of the oldest directory took {rmdir} us, over {bound} us (3.2 x {pairs} pairs = {rmdir_reads} reads of table 4.2 at {rate} a second, margin 1.5)"
        ));
    }
    lines.push(format!(
        "RMDIR {rmdir} us <= {bound} us (3.2 reads for each of {pairs} pairs, table 4.2): ok"
    ));
    let tree = number("data-probe: fill rm -rf 199 directories ")?;
    let tree_reads = 199 * pairs * 16 / 10;
    let bound = allowed(tree_reads);
    if tree > bound {
        return Err(format!(
            "rm -rf of 199 directories took {tree} us, over {bound} us (1.6 x 199 x {pairs} = {tree_reads} reads at {rate} a second, margin 1.5)"
        ));
    }
    lines.push(format!(
        "rm -rf of 199 directories {tree} us <= {bound} us (1.6 reads for each pair for each directory): ok"
    ));
    let calls = number("data-probe: fill readdir 1002 entries in ")?;
    let total = number(&format!("{calls} calls, total "))?;
    let bound = allowed(READDIR_READS) + 2_000 * calls;
    if total > bound {
        return Err(format!(
            "the listing of 1,002 entries took {total} us in {calls} calls, over {bound} us ({READDIR_READS} reads of table 4.2 at {rate} a second, margin 1.5, 2 ms a call)"
        ));
    }
    lines.push(format!(
        "READDIR of 1,002 entries {total} us in {calls} calls <= {bound} us ({READDIR_READS} reads, table 4.2, and 2 ms a call): ok"
    ));
    let write = number("longest call ")?;
    let bound = allowed(WRITE_READS) + 50_000;
    if write > bound {
        return Err(format!(
            "the longest WRITE took {write} us, over {bound} us ({WRITE_READS} reads of table 4.2 at {rate} a second, margin 1.5, 50 ms)"
        ));
    }
    lines.push(format!(
        "longest WRITE {write} us <= {bound} us ({WRITE_READS} reads, table 4.2, and 50 ms): ok"
    ));
    // The refresh walk: the free count caught up with the removals.
    let free = measured
        .iter()
        .find_map(|l| {
            l.split_once("data-probe: fill free blocks ")
                .map(|(_, t)| t.to_owned())
        })
        .ok_or("no line of the free blocks")?;
    let words: Vec<u64> = free.split(' ').filter_map(|w| w.parse().ok()).collect();
    let &[_, low, after] = words.get(..3).unwrap_or_default() else {
        return Err(format!("the line of the free blocks is not read: {free:?}"));
    };
    if after < low + GIVEN_BACK_BLOCKS * 9 / 10 {
        return Err(format!(
            "after the removals the free count went from {low} to {after}, short of 90% of the {GIVEN_BACK_BLOCKS} blocks given back: no refresh walk (limit 4.3, the refresh rule)"
        ));
    }
    if !measured.iter().any(|l| l.contains("datafs: refresh walk ")) {
        return Err(
            "the free count caught up but the service printed no line of a refresh walk".into(),
        );
    }
    lines.push(format!(
        "free blocks {low} -> {after} after the removals (at least 90% of {GIVEN_BACK_BLOCKS} given back) with a refresh walk: ok"
    ));
    // The share of the walk that was the worker's own work, on any number of CPUs: the time of the
    // walk less the time in the disk reads. On a table of one CPU the worker has no budget; when
    // this share is over 30% there, the review's rule puts its thread at level 1 (below every
    // program). No bound: the figure is for that decision.
    let own = settled
        .iter()
        .find(|l| l.contains("datafs: walk own work "))
        .ok_or("no line `walk own work` (the service is built with `steps`)")?;
    let one = [own.to_string()];
    let (work, wall) = (
        qemu::number_after(&one, "walk own work ").unwrap_or(0),
        qemu::number_after(&one, " us of ").unwrap_or(1).max(1),
    );
    lines.push(format!(
        "the walk's own work {work} us of {wall} us ({}%){}",
        work * 100 / wall,
        if work * 100 > wall * 30 {
            ": over 30%, so on a table of one CPU the worker goes to level 1 (the rule of the review of step 5)"
        } else {
            ": at most 30%, the budget of 30% would not bind it"
        }
    ));
    // The budget of the worker: on two CPUs it is there and tells its share; on one it is not.
    let cpu_lines: Vec<&String> = measured
        .iter()
        .chain(settled)
        .filter(|l| l.contains("datafs: walk cpu "))
        .collect();
    if cpus >= 2 {
        if cpu_lines.is_empty() {
            return Err("two CPUs and no line `walk cpu`: the worker has no budget".into());
        }
        for l in cpu_lines {
            let one = [l.to_string()];
            let cpu = qemu::number_after(&one, "walk cpu ").unwrap_or(0);
            let wall = qemu::number_after(&one, " us of ").unwrap_or(1).max(1);
            let overruns = qemu::number_after(&one, ", ").unwrap_or(0);
            let periods = wall / 10_000 + 1;
            if overruns > OVERRUNS_PER_PERIOD * periods {
                return Err(format!(
                    "a walk had {overruns} overruns of `work` in {periods} periods, over {OVERRUNS_PER_PERIOD} a period: the share it tells is too low to trust: {l}"
                ));
            }
            if cpu * 100 > wall * 35 {
                return Err(format!(
                    "the worker took {cpu} us of {wall} us in a walk, over the 30% of its budget (and 5% of slack): {l}"
                ));
            }
            lines.push(format!(
                "walk cpu {cpu} us of {wall} us ({}%), {overruns} overruns in {periods} periods (at most {OVERRUNS_PER_PERIOD} a period): ok",
                cpu * 100 / wall
            ));
        }
    } else if !cpu_lines.is_empty() {
        return Err(
            "one CPU and a line `walk cpu`: a budget on CPU 1 was given to a machine without it"
                .into(),
        );
    } else {
        lines.push("one CPU: no budget `work`, no line `walk cpu`: ok (the share of the worker on one CPU is read from the time of its walk against the reads it did)".into());
    }
    Ok(Checked { rate, lines })
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
    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|l| (*l).to_owned()).collect()
    }

    /// The lines of a pair of boots that pass: a walk of 150,000 reads in 15 s (10,000 reads a second).
    fn fixture(cpus: usize) -> (Vec<String>, Vec<String>) {
        let settled = lines(&[
            "datafs: first walk 200000 blocks used, 150000 reads, 15000 ms",
            "datafs: walk own work 3000000 us of 15000000 us, 12000000 us in disk reads",
            "datafs: ready after 900 ms, 700 reads",
        ]);
        let mut measured = lines(&[
            "data-probe: fill first call 15000000 us, 261888 blocks, 60000 free",
            "data-probe: fill readdir 1002 entries in 3 calls, total 30000 us, longest 20000 us",
            "data-probe: fill rmdir 150000 us",
            "data-probe: fill rm -rf 199 directories 15000000 us",
            "datafs: pairs 400 of 2048, directories 230 of 1024",
            "data-probe: fill write 8388608 bytes in 9000 calls, total 900000 us, longest call 90000 us",
            "data-probe: fill free blocks 60000 before the removals, 60040 right after, 158000 after 4 s of quiet",
            "datafs: refresh walk 100000 blocks used, about 98304 given back, 100000 reads, 10000 ms",
        ]);
        if cpus >= 2 {
            measured.push("datafs: walk cpu 800000 us of 10000000 us, 3 overruns".into());
        }
        (settled, measured)
    }

    #[test]
    fn the_fill_figures_are_checked_against_the_bounds_of_the_plan() {
        for cpus in [1, 2] {
            let (settled, measured) = fixture(cpus);
            let checked = super::fill_checks(&settled, &measured, cpus).unwrap();
            assert_eq!(checked.rate, 10_000);
            assert!(checked.lines.len() >= 5);
        }
        let slow = |from: &str, to: &str, cpus: usize| {
            let (settled, measured) = fixture(cpus);
            let measured: Vec<String> = measured.iter().map(|l| l.replace(from, to)).collect();
            super::fill_checks(&settled, &measured, cpus)
        };
        // The first call over 1.5 times the first walk (15 s) and a second.
        assert!(slow("first call 15000000 us", "first call 23500000 us", 2).is_ok());
        assert!(slow("first call 15000000 us", "first call 23500001 us", 2).is_err());
        // RMDIR over 1.5 times 3.2 x 400 pairs = 1,280 reads at 10,000 a second (192 ms).
        assert!(slow("rmdir 150000 us", "rmdir 192001 us", 2).is_err());
        assert!(slow("rmdir 150000 us", "rmdir 192000 us", 2).is_ok());
        // rm -rf of 199 directories: 1.5 times 1.6 x 199 x 400 = 127,360 reads (19.104 s).
        assert!(slow("directories 15000000 us", "directories 19104001 us", 2).is_err());
        assert!(slow("directories 15000000 us", "directories 19104000 us", 2).is_ok());
        // Pairs over the cap, or no line of the count.
        assert!(slow("pairs 400 of", "pairs 2049 of", 2).is_err());
        // The listing over 1.5 times 197 reads and 2 ms for each of 3 calls.
        assert!(slow("total 30000 us", "total 35550 us", 2).is_ok());
        assert!(slow("total 30000 us", "total 35551 us", 2).is_err());
        // The longest write over 1.5 times 400 reads and 50 ms.
        assert!(slow("longest call 90000 us", "longest call 111000 us", 2).is_err());
        // A free count that did not catch up: no refresh.
        assert!(slow("158000 after", "60100 after", 2).is_err());
        // Overruns of `work` over 4 a period make the share untrustworthy; a share over the budget fails.
        assert!(slow("3 overruns", "4005 overruns", 2).is_err());
        assert!(slow("800000 us of", "4000000 us of", 2).is_err());
        // Two CPUs need the line of the share; one CPU must not have it.
        let (settled, mut measured) = fixture(2);
        measured.pop();
        assert!(super::fill_checks(&settled, &measured, 2).is_err());
        let (settled, measured) = fixture(2);
        assert!(super::fill_checks(&settled, &measured, 1).is_err());
        // A first walk over 60 s.
        let (mut settled, measured) = fixture(1);
        settled[0] = "datafs: first walk 200000 blocks used, 150000 reads, 60001 ms".into();
        assert!(super::fill_checks(&settled, &measured, 1).is_err());
    }

    #[test]
    fn the_probe_has_the_stack_its_nested_calls_need() {
        // The verifying boot overran 16 KiB: the stack is not lowered again without a measurement.
        const { assert!(super::DATA_PROBE_STACK_SIZE >= 32 * 1024) };
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
