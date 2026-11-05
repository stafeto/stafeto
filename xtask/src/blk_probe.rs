// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask blk-probe [--hvf]`: the probe of the disk service
//! (services/virtio-blk) on QEMU's `virt` with a disk file (`qemu::store`),
//! in three runs of the machine (tests/blk-probe):
//!
//! 1. A new file of 64 MiB, zeros. The probe writes a pattern, flushes, and
//!    marks sector 0; the refusals and a CANCEL are checked on the way. On
//!    QEMU's own emulation the run is under -icount and the service's
//!    steps are read from its lines: every kind came and every one stays
//!    under 0.9 of term B.
//! 2. The same file, a new run of QEMU: the pattern read and compared, a
//!    CRASH of the service, and the restarted service read again. The line
//!    of the driver shows the device's status 0 at the second start, so
//!    init reset it before it let the old DMA object go.
//! 3. A file marked for faults, behind QEMU's `blkdebug`: the host fails
//!    the first flush and the first read of sector 4096 with EIO, and the
//!    client sees IO for each and READY for the second try. A flush that
//!    never reached the device (or `cache=unsafe`, which swallows it) shows
//!    here. The drive also holds every write after the first for half a
//!    second (`throttling`), so that the rule of the flush is seen with a
//!    write at the device, whatever the speed of the host.
//!
//! The jobs of `ci` are `blk-probe` (runs 1 and 2 under -icount), `blk-probe
//! GICv3` (runs 1 and 2 on the GICv3 machine) and `blk-faults` (run 3). With
//! `--hvf` all three runs go on both HVF machines. The files lie in the
//! temporary directory under the name of the process and go at the end of
//! the command, whatever its outcome.

use super::*;
use std::path::{Path, PathBuf};

/// The stack of the disk service: its loop's table of sessions and the
/// queue's chains.
pub const BLK_STACK_SIZE: u32 = 32 * 1024;

/// The probe's image: the PL011's driver, the service with CRASH and the
/// count of its steps (it prints only under the tag it asks for), the probe.
pub const PROGRAMS: [ImageProgram; 4] = [
    ("init", "init", INIT_STACK_SIZE, &["table-blk-probe"]),
    ("uart", "uart", UART_STACK_SIZE, &[]),
    (
        "virtio-blk",
        "virtio-blk",
        BLK_STACK_SIZE,
        &["crash", "steps"],
    ),
    ("blk-probe", "blk-probe", CHILD_STACK_SIZE, &[]),
];

/// The bytes of the files of the runs: 131,072 sectors.
const DISK_BYTES: u64 = 64 << 20;
/// The marks of sector 0 (tests/blk-probe).
const FAULTS_MARK: &[u8; 8] = b"STAFFLT1";
/// The rules of the host's `blkdebug` for run 3: the first flush and the
/// first read that covers sector 4096 fail with EIO.
const FAULT_RULES: &str = "\
[inject-error]
event = \"flush_to_disk\"
errno = \"5\"
once = \"on\"

[inject-error]
event = \"read_aio\"
errno = \"5\"
sector = \"4096\"
once = \"on\"
";

/// The driver's lines at a start: the function, its line, and the device's
/// status as the driver found it (0 at the machine's start and after init
/// stopped the device); the device's ID and the flush it offers.
const SERVICE_LINE: &str = "virtio-blk: 1af4:1042 at 0x3f008000, line 36, status 0x0, ";
const ID_LINE: &str = "virtio-blk: id stafeto-store, flush";
const ENDED: &str = "init: blk-probe ended: exit code 0, not restarted";
const ENDS: &str = "init: blk-probe ended: ";

/// The lines of the probe, once each, per mode.
const NO_BUFFER: &str = "blk-probe: READ before BUFFER is NO_BUFFER";
const INFO: &str = "blk-probe: 131072 sectors, block 512, flush";
const WRITE_LINES: [&str; 7] = [
    "blk-probe: bad requests are refused: counts, cell, range, keys",
    "blk-probe: a cell in flight is BUSY, a second BUFFER is EXISTS",
    "blk-probe: 8224 sectors of the pattern written, four cells in flight",
    "blk-probe: FLUSH after the writes is READY",
    "blk-probe: CANCEL ended a read in flight, the cell came free",
    "blk-probe: 8224 sectors read back and equal",
    "blk-probe: written 8224 sectors",
];
const CHECK_LINES: [&str; 3] = [
    "blk-probe: verified 8224 sectors",
    "blk-probe: crashing blk",
    "blk-probe: restarted",
];
const FAULT_LINES: [&str; 6] = [
    "blk-probe: FLUSH with a write at the device is BUSY",
    "blk-probe: a failed FLUSH is IO",
    "blk-probe: the second FLUSH is READY",
    "blk-probe: a failed READ is IO",
    "blk-probe: the second READ is READY",
    "blk-probe: faults seen",
];

/// The tag of the service's lines of steps (rt::service::report_steps).
const BLK_TAG: &str = "15";
/// The kinds of the service's steps that must come in run 1: the methods
/// INFO to CANCEL of proto_blk, the interrupt (rt::service::step_own, 65)
/// and the departure of a session (66).
const BLK_STEP_KINDS: [(usize, &str); 9] = [
    (1, "Info"),
    (2, "Read"),
    (3, "Write"),
    (4, "Flush"),
    (5, "Buffer"),
    (6, "Take"),
    (7, "Cancel"),
    (65, "the interrupt"),
    (66, "the departure of a session"),
];
/// The most one step of the service may take (spec 3, section 6): 0.9 of
/// term B, 18,369 ticks.
pub const STEP_MAX: u64 = TERM_B * 9 / 10;

/// The files of a run, named by the process, the machine and the kind of
/// run, so that jobs of one process (the threads of `ci`) and processes side
/// by side share none; `Drop` removes these and no others.
struct Files {
    disk: PathBuf,
    faults: PathBuf,
    rules: PathBuf,
}

impl Files {
    fn new(machine: &qemu::Machine, run: &str) -> Files {
        let machine: String = machine
            .name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        let name = |what: &str| {
            std::env::temp_dir().join(format!(
                "stafeto-blk-{}-{machine}-{run}-{what}",
                std::process::id()
            ))
        };
        Files {
            disk: name("disk.img"),
            faults: name("faults.img"),
            rules: name("faults.conf"),
        }
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        for file in [&self.disk, &self.faults, &self.rules] {
            let _ = std::fs::remove_file(file);
        }
    }
}

/// The boot image of a run: a path of its own for each machine and kind of
/// run, since the jobs of `ci` build and read their images at the same time.
fn image_name(machine: &qemu::Machine, run: &str) -> &'static str {
    match (machine.name, run) {
        ("512M", "probe") => "boot-blk-probe.img",
        ("512M", _) => "boot-blk-faults.img",
        ("GICv3", "probe") => "boot-blk-probe-v3.img",
        ("GICv3", _) => "boot-blk-faults-v3.img",
        (_, "probe") => "boot-blk-probe-hvf.img",
        (_, _) => "boot-blk-faults-hvf.img",
    }
}

/// A line that starts the driver, `n` times, and its ID: `starts` of them.
fn driver_lines(lines: &[String], starts: usize) -> Result<(), String> {
    let seen = lines.iter().filter(|l| l.starts_with(SERVICE_LINE)).count();
    let ids = lines.iter().filter(|l| l.as_str() == ID_LINE).count();
    if seen != starts || ids != starts {
        let found: Vec<_> = lines
            .iter()
            .filter(|l| l.starts_with("virtio-blk: "))
            .collect();
        return Err(format!(
            "{seen} starts and {ids} IDs of the driver, {starts} of each expected: {found:?}"
        ));
    }
    Ok(())
}

/// Judges the lines of a run: no failure of the probe, the driver started
/// `starts` times and answered GET_ID each time, and every line of `wanted`
/// came once, then the probe ended well.
fn verdict(lines: &[String], starts: usize, wanted: &[&str]) -> Result<(), String> {
    if let Some(failed) = lines.iter().find(|l| l.starts_with("blk-probe: failed")) {
        return Err(failed.clone());
    }
    driver_lines(lines, starts)?;
    for marker in [NO_BUFFER, INFO].iter().chain(wanted) {
        let n = lines.iter().filter(|l| l.as_str() == *marker).count();
        if n != 1 {
            let said: Vec<_> = lines
                .iter()
                .filter(|l| l.starts_with("blk-probe: "))
                .collect();
            return Err(format!(
                "{n} lines {marker:?}, one expected; the probe said {said:?}"
            ));
        }
    }
    Ok(())
}

/// The steps of the service in the lines of run 1: every kind came, and
/// every row, the heartbeat's too, stays under STEP_MAX.
pub fn steps_verdict(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = longest_steps(lines, BLK_TAG);
    for (kind, name) in BLK_STEP_KINDS {
        if !rows.iter().any(|(k, ..)| *k == kind) {
            return Err(format!("the disk service: no step {name}: {rows:?}"));
        }
    }
    if let Some(row) = rows.iter().find(|r| r.1 > STEP_MAX) {
        return Err(format!(
            "the disk service: a step past 0.9 of term B ({STEP_MAX}): {row:?}"
        ));
    }
    Ok(rows)
}

/// The machine with the image, the disk `file` (through `faults` rules when
/// given) and, with `icount`, the clock of instructions.
fn machine_command(
    machine: &qemu::Machine,
    kernel: &Artifacts,
    image: &Path,
    file: &Path,
    faults: Option<&Path>,
    icount: bool,
) -> Command {
    let mut cmd = qemu::command(machine, &kernel.image, Some(image));
    cmd.args(qemu::HEADLESS).args(qemu::store(file, faults));
    if icount {
        cmd.args(qemu::ICOUNT);
    }
    cmd
}

/// Runs the machine until the probe ends, whatever its code, and checks
/// that it ended well.
fn run_probe(
    machine: &qemu::Machine,
    kernel: &Artifacts,
    cmd: Command,
    what: &str,
) -> Result<qemu::Outcome, String> {
    let output = run_until(cmd, BOOT_TIMEOUT * 4, Some(ENDS), &kernel.elf)
        .map_err(|e| format!("blk-probe on {} ({what}): {e}", machine.name))?;
    if let Some(failed) = output
        .lines
        .iter()
        .find(|l| l.starts_with("blk-probe: failed"))
    {
        return Err(format!("blk-probe on {} ({what}): {failed}", machine.name));
    }
    qemu::expect_stopped_on(&output, ENDED)
        .map_err(|e| format!("blk-probe on {} ({what}): {e}", machine.name))?;
    Ok(output)
}

/// Runs 1 and 2 on `machine`: a pattern, a flush, and the same file after
/// a new start of QEMU and a restart of the service. With `steps` (QEMU's
/// own emulation) run 1 is under -icount and the service's steps are
/// judged.
pub fn probe(machine: &qemu::Machine, steps: bool) -> Result<(), String> {
    let files = Files::new(machine, "probe");
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(image_name(machine, "probe"), &PROGRAMS, BOOT_PROFILE)?;
    qemu::store_file(&files.disk, DISK_BYTES, true)?;
    let icount = steps && !machine.is_hvf();
    let cmd = machine_command(machine, &kernel, &image, &files.disk, None, icount);
    let output = run_probe(machine, &kernel, cmd, "writing")?;
    let wrote = verdict(&output.lines, 1, &WRITE_LINES)
        .map_err(|e| format!("blk-probe on {} (writing): {e}", machine.name));
    wrote?;
    if icount {
        let rows = steps_verdict(&output.lines)?;
        crate::check_waits(&output.lines, &[BLK_TAG], "blk-probe")?;
        let text: Vec<_> = rows
            .iter()
            .map(|(kind, ticks, _)| format!("kind {kind} {ticks}"))
            .collect();
        println!(
            "blk-probe on {}: the longest steps under -icount, ticks (0.9 of term B {STEP_MAX}): {}",
            machine.name,
            text.join(", ")
        );
    }
    let cmd = machine_command(machine, &kernel, &image, &files.disk, None, false);
    let output = run_probe(machine, &kernel, cmd, "checking")?;
    verdict(&output.lines, 2, &CHECK_LINES)
        .map_err(|e| format!("blk-probe on {} (checking): {e}", machine.name))?;
    println!(
        "blk-probe on {}: refusals, a pattern of 4 MiB and the disk's tail written and flushed, CANCEL, the same read after a new start of QEMU, a restart of the service: ok",
        machine.name
    );
    Ok(())
}

/// Run 3 on `machine`: the host's errors reach the client.
pub fn faults(machine: &qemu::Machine) -> Result<(), String> {
    let files = Files::new(machine, "faults");
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(image_name(machine, "faults"), &PROGRAMS, BOOT_PROFILE)?;
    qemu::store_file(&files.faults, DISK_BYTES, true)?;
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&files.faults)
            .map_err(|e| format!("{}: {e}", files.faults.display()))?;
        file.write_all(FAULTS_MARK)
            .map_err(|e| format!("{}: {e}", files.faults.display()))?;
    }
    std::fs::write(&files.rules, FAULT_RULES)
        .map_err(|e| format!("{}: {e}", files.rules.display()))?;
    let cmd = machine_command(
        machine,
        &kernel,
        &image,
        &files.faults,
        Some(&files.rules),
        false,
    );
    let output = run_probe(machine, &kernel, cmd, "faults")?;
    verdict(&output.lines, 1, &FAULT_LINES)
        .map_err(|e| format!("blk-probe on {} (faults): {e}", machine.name))?;
    println!(
        "blk-faults on {}: the host's error of a flush and of a read reach the client as IO, the second try is READY: ok",
        machine.name
    );
    Ok(())
}

/// `cargo xtask blk-probe [--hvf]`.
pub fn command(args: &[String]) -> Result<(), String> {
    match args {
        [] => {
            probe(&qemu::VIRT, true)?;
            faults(&qemu::VIRT)
        }
        // TCG without -icount, where the speed pass of the probe means something.
        [flag] if flag == "--plain" => probe(&qemu::VIRT, false),
        [flag] if flag == "--hvf" => {
            hvf_host()?;
            for machine in [&qemu::HVF_V3, &qemu::HVF_V2] {
                probe(machine, false)?;
                faults(machine)?;
            }
            Ok(())
        }
        _ => Err("usage: cargo xtask blk-probe [--hvf | --plain]".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(extra: &[&str], starts: usize) -> Vec<String> {
        let mut l: Vec<String> = Vec::new();
        for _ in 0..starts {
            l.push(format!("{SERVICE_LINE}131072 sectors"));
            l.push(ID_LINE.to_owned());
        }
        l.push(NO_BUFFER.to_owned());
        l.push(INFO.to_owned());
        l.extend(extra.iter().map(|s| (*s).to_owned()));
        l.push(ENDED.to_owned());
        l
    }

    #[test]
    fn a_run_with_every_line_passes() {
        assert_eq!(verdict(&lines(&WRITE_LINES, 1), 1, &WRITE_LINES), Ok(()));
        assert_eq!(verdict(&lines(&CHECK_LINES, 2), 2, &CHECK_LINES), Ok(()));
        assert_eq!(verdict(&lines(&FAULT_LINES, 1), 1, &FAULT_LINES), Ok(()));
    }

    #[test]
    fn a_missing_line_a_failure_or_a_missing_start_fails() {
        let l = lines(&WRITE_LINES[1..], 1);
        assert!(
            verdict(&l, 1, &WRITE_LINES)
                .unwrap_err()
                .contains("bad requests")
        );
        let mut l = lines(&WRITE_LINES, 1);
        l.push("blk-probe: failed: FLUSH failed".into());
        assert!(
            verdict(&l, 1, &WRITE_LINES)
                .unwrap_err()
                .contains("FLUSH failed")
        );
        // Run 2 starts the driver twice; once means the restart never came.
        assert!(
            verdict(&lines(&CHECK_LINES, 1), 2, &CHECK_LINES)
                .unwrap_err()
                .contains("1 starts")
        );
        // A device that answers GET_ID otherwise.
        let mut l = lines(&WRITE_LINES, 1);
        l.retain(|x| x != ID_LINE);
        assert!(verdict(&l, 1, &WRITE_LINES).unwrap_err().contains("0 IDs"));
    }

    fn steps(rows: &[(usize, u64)]) -> Vec<String> {
        rows.iter()
            .map(|(kind, ticks)| format!("service step: 15 kind {kind} {ticks} ticks detail 0"))
            .collect()
    }

    #[test]
    fn every_kind_must_come_and_stay_under_the_bound() {
        let all: Vec<(usize, u64)> = BLK_STEP_KINDS.iter().map(|(k, _)| (*k, 9_000)).collect();
        assert!(steps_verdict(&steps(&all)).is_ok());
        assert!(
            steps_verdict(&steps(&all[..8]))
                .unwrap_err()
                .contains("departure")
        );
        let mut over = all.clone();
        over[2].1 = STEP_MAX + 1;
        assert!(
            steps_verdict(&steps(&over))
                .unwrap_err()
                .contains("a step past")
        );
        // The last line of a kind is its longest.
        let mut grown = steps(&all);
        grown.extend(steps(&[(3, STEP_MAX)]));
        assert!(steps_verdict(&grown).is_ok());
        assert_eq!(STEP_MAX, 18_369);
    }

    #[test]
    fn the_rules_name_the_flush_and_sector_4096_once_each() {
        assert_eq!(FAULT_RULES.matches("once = \"on\"").count(), 2);
        assert!(FAULT_RULES.contains("flush_to_disk") && FAULT_RULES.contains("sector = \"4096\""));
    }

    #[test]
    fn the_files_of_the_jobs_share_none_and_go_with_their_run() {
        let sets: Vec<Files> = vec![
            Files::new(&qemu::VIRT, "probe"),
            Files::new(&qemu::VIRT_V3, "probe"),
            Files::new(&qemu::VIRT, "faults"),
        ];
        let mut all: Vec<&PathBuf> = sets
            .iter()
            .flat_map(|f| [&f.disk, &f.faults, &f.rules])
            .collect();
        let n = all.len();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), n, "two runs name one file");
        let name = sets[0]
            .disk
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(name.contains(&std::process::id().to_string()));
        let (kept, gone) = (sets[1].disk.clone(), sets[0].disk.clone());
        std::fs::write(&kept, b"x").unwrap();
        std::fs::write(&gone, b"x").unwrap();
        let mut sets = sets;
        drop(sets.remove(0));
        assert!(!gone.exists(), "a run removes its files");
        assert!(kept.exists(), "a run removes only its own files");
        drop(sets);
        assert!(!kept.exists());
        let images = [
            image_name(&qemu::VIRT, "probe"),
            image_name(&qemu::VIRT_V3, "probe"),
            image_name(&qemu::VIRT, "faults"),
        ];
        assert!(images[0] != images[1] && images[1] != images[2] && images[0] != images[2]);
    }
}
