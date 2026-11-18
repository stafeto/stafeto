// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of focus and composition of two clients (stage G2 of the
//! graphics design): the compositor with a virtio-tablet for its pointer, two
//! clients whose windows overlap (the second has an alpha), a manager and a
//! program that injects the keys and the pointer (tests/focus-probe,
//! services/init `table::focus`).
//!
//! xtask asks the monitor of QEMU for a `screendump` after each step the
//! guest announces and compares the CRC-32 of the colours with the one the
//! guest computed for the screen it should show: the overlap with its
//! transparency, a click that gives a window the focus and the top place,
//! the manager's switch on Alt and Tab, and the screen after the second
//! client ended. The guest checks that each client saw the focus and the keys
//! of its time and no others, and that the manager heard the Alt keys alone.
//! Then xtask moves QEMU's tablet and presses its button through QMP
//! (`input-send-event`: the monitor's `mouse_move` is relative, and a tablet
//! has no relative axes): the surviving window must see the click, in its own
//! coordinates, from the device, which is another path than INJECT's.
//!
//! A second run, under -icount, measures the steps of the compositor, of the
//! display driver and of the tablet's driver: every step stays under 0.9 of
//! term B, and a band of a frame and a step of the drivers' own under
//! PORTION_MAX.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::gpu_probe::{self, Scratch};
use crate::monitor::Monitor;
use crate::qemu::{Input, Run};
use crate::{
    BOOT_PROFILE, CHILD_STACK_SIZE, INIT_STACK_SIZE, ImageProgram, PORTION_MAX, Variant, build,
    build_boot_image, comp_probe, input_probe, longest_steps, qemu, run_until,
};

/// The probe's image: the display driver, the tablet's driver (the input
/// service's program on its own transport), the compositor and the clients.
pub const PROGRAMS: [ImageProgram; 5] = [
    ("init", "init", INIT_STACK_SIZE, &["table-focus"]),
    (
        "virtio-gpu",
        "virtio-gpu",
        crate::gpu_probe::GPU_STACK_SIZE,
        &[],
    ),
    (
        "virtio-input",
        "virtio-input",
        input_probe::INPUT_STACK_SIZE,
        &[],
    ),
    ("compositor", "compositor", comp_probe::COMP_STACK_SIZE, &[]),
    ("focus-probe", "focus-probe", CHILD_STACK_SIZE, &[]),
];

/// The image of the run under -icount: the services count their steps, the
/// clients do not wait for the monitor.
pub const STEPS_PROGRAMS: [ImageProgram; 5] = [
    ("init", "init", INIT_STACK_SIZE, &["table-focus"]),
    (
        "virtio-gpu",
        "virtio-gpu",
        crate::gpu_probe::GPU_STACK_SIZE,
        &["steps"],
    ),
    (
        "virtio-input",
        "virtio-input",
        input_probe::INPUT_STACK_SIZE,
        &["steps"],
    ),
    (
        "compositor",
        "compositor",
        comp_probe::COMP_STACK_SIZE,
        &["steps"],
    ),
    ("focus-probe", "focus-probe", CHILD_STACK_SIZE, &["quick"]),
];

const OVERLAP: &str = "focus-probe: overlap crc ";
const CLICK: &str = "focus-probe: click crc ";
const SWITCH: &str = "focus-probe: switch crc ";
const SURVIVOR: &str = "focus-probe: survivor crc ";
const INJECTED: &str = "focus-probe: the keys are injected";
/// The line of the tablet's driver about its device.
const TABLET_LINE: &str = "virtio-input: virtio-mmio at 0xa001a00, line 61, status 0x0";
const ENDED: [&str; 5] = [
    "init: focus-a ended: exit code 0, not restarted",
    "init: focus-b ended: exit code 0, not restarted",
    "init: focus-wm ended: exit code 0, not restarted",
    "init: focus-inject ended: exit code 0, not restarted",
    "init: focus-many ended: exit code 0, not restarted",
];
/// The line the run under -icount has of the many windows, and the bound on
/// their bands is the compositor's steps.
const MANY: &str = "focus-probe: eight windows are shown and none of the seven took the focus";

/// The lines the clients print once per check that passed, and how many
/// times a run has each.
const CHECKS: [(&str, usize); 11] = [
    ("focus-probe: a window is up", 1),
    ("focus-probe: b window is up", 1),
    (
        "focus-probe: a events are exactly the focus and the keys it had",
        1,
    ),
    (
        "focus-probe: b events are exactly the focus and the keys it had",
        1,
    ),
    ("focus-probe: the manager has subscribed", 1),
    (
        "focus-probe: the manager heard the Alt keys and the windows did not",
        1,
    ),
    (INJECTED, 1),
    ("focus-probe: ok", 5),
    (comp_probe::READY, 1),
    (gpu_probe::SERVICE_LINE, 1),
    (gpu_probe::READY, 1),
];
/// The lines only the run with a monitor has: the tablet's click.
const TABLET_CHECKS: [(&str, usize); 1] = [(
    "focus-probe: a the tablet's click reached the window under it",
    1,
)];

/// Judges the lines of a run: the services started and were ready once, every
/// check of the clients passed once, none failed, the manager switched the
/// windows once, and the tablet's driver found its device.
pub fn verdict(lines: &[String], tablet: bool) -> Result<(), String> {
    let count = |marker: &str| lines.iter().filter(|l| l.as_str() == marker).count();
    if let Some(failed) = lines.iter().find(|l| l.starts_with("focus-probe: failed")) {
        return Err(failed.clone());
    }
    let tablet_checks: &[(&str, usize)] = if tablet { &TABLET_CHECKS } else { &[] };
    for (marker, wanted) in CHECKS.iter().chain(tablet_checks) {
        if count(marker) != *wanted {
            let found: Vec<_> = lines
                .iter()
                .filter(|l| {
                    l.starts_with("virtio-gpu: ")
                        || l.starts_with("virtio-input: ")
                        || l.starts_with("compositor: ")
                        || l.starts_with("focus-probe: ")
                })
                .collect();
            return Err(format!(
                "{} lines {marker:?}, {wanted} expected; the programs said {found:?}",
                count(marker)
            ));
        }
    }
    let switched = lines
        .iter()
        .filter(|l| l.starts_with("focus-probe: the manager gave the focus to window "))
        .count();
    if switched != 1 {
        return Err(format!("the manager switched the windows {switched} times"));
    }
    if !lines.iter().any(|l| l.starts_with(TABLET_LINE)) {
        return Err(format!(
            "the tablet's driver never said {TABLET_LINE:?}; lines: {:?}",
            lines
                .iter()
                .filter(|l| l.starts_with("virtio-input: "))
                .collect::<Vec<_>>()
        ));
    }
    Ok(())
}

/// The kinds of the compositor's steps that must come: DESCRIBE,
/// WINDOW_CREATE, ATTACH, POST, EVENTS, MANAGE and INJECT, and its own (a
/// band of a frame, the end of a frame, a read of the tablet).
const COMP_KINDS: [(usize, &str); 8] = [
    (17, "Describe"),
    (18, "WindowCreate"),
    (19, "Attach"),
    (20, "Post"),
    (21, "Events"),
    (22, "Manage"),
    (23, "Inject"),
    (65, "a band of a frame and the end of a frame"),
];
/// The tablet driver's: GRANT, and its own (the interrupt).
const INPUT_KINDS: [(usize, &str); 2] = [(1, "Grant"), (65, "the interrupt")];
const INPUT_TAG: &str = "13";

/// Every kind came, every row is under STEP_MAX and the rows of the
/// service's own kind under PORTION_MAX.
fn rows_of(
    lines: &[String],
    tag: &str,
    name: &str,
    kinds: &[(usize, &str)],
) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = longest_steps(lines, tag);
    for (kind, what) in kinds {
        if !rows.iter().any(|(k, ..)| k == kind) {
            return Err(format!("the {name}: no step {what}: {rows:?}"));
        }
    }
    if let Some(row) = rows.iter().find(|r| r.1 > gpu_probe::STEP_MAX) {
        return Err(format!(
            "the {name}: a step past 0.9 of term B ({}): {row:?}",
            gpu_probe::STEP_MAX
        ));
    }
    if let Some(row) = rows.iter().find(|r| r.0 == 65 && r.1 > PORTION_MAX) {
        return Err(format!(
            "the {name}: a portion or an interrupt past {PORTION_MAX}: {row:?}"
        ));
    }
    Ok(rows)
}

/// The steps of the compositor and of the tablet's driver.
pub fn steps_verdict(lines: &[String]) -> Result<(comp_probe::Rows, comp_probe::Rows), String> {
    Ok((
        rows_of(lines, comp_probe::COMP_TAG, "compositor", &COMP_KINDS)?,
        rows_of(lines, INPUT_TAG, "tablet's driver", &INPUT_KINDS)?,
    ))
}

/// A connection to QEMU's QMP socket: the events of the input devices, which
/// the monitor of HMP cannot make for a tablet.
struct Qmp {
    reader: BufReader<UnixStream>,
}

impl Qmp {
    /// Connects to `path` (it appears when QEMU starts), reads the greeting
    /// and negotiates the capabilities.
    fn connect(path: &Path, timeout: Duration) -> Result<Qmp, String> {
        let deadline = Instant::now() + timeout;
        let stream = loop {
            match UnixStream::connect(path) {
                Ok(stream) => break stream,
                Err(e) if Instant::now() >= deadline => {
                    return Err(format!("QMP at {}: {e}", path.display()));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        let mut qmp = Qmp {
            reader: BufReader::new(stream),
        };
        qmp.line()?;
        qmp.execute(r#"{"execute":"qmp_capabilities"}"#)?;
        Ok(qmp)
    }

    fn line(&mut self) -> Result<String, String> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Err("QMP closed".to_owned()),
            Ok(_) => Ok(line),
            Err(e) => Err(format!("QMP: {e}")),
        }
    }

    /// Sends `request` and reads until its reply (events are skipped): an
    /// error is the reply's `error`.
    fn execute(&mut self, request: &str) -> Result<(), String> {
        self.reader
            .get_mut()
            .write_all(format!("{request}\n").as_bytes())
            .map_err(|e| format!("QMP: {e}"))?;
        loop {
            let line = self.line()?;
            if line.contains("\"error\"") {
                return Err(format!("QMP {request}: {}", line.trim()));
            }
            if line.contains("\"return\"") {
                return Ok(());
            }
        }
    }

    /// The tablet to (`x`, `y`) of a screen of `width` by `height` points.
    fn move_to(&mut self, x: u32, y: u32, width: u32, height: u32) -> Result<(), String> {
        let (ax, ay) = (x * 0x8000 / width, y * 0x8000 / height);
        self.execute(&format!(
            r#"{{"execute":"input-send-event","arguments":{{"events":[{{"type":"abs","data":{{"axis":"x","value":{ax}}}}},{{"type":"abs","data":{{"axis":"y","value":{ay}}}}}]}}}}"#
        ))
    }

    fn left_button(&mut self, down: bool) -> Result<(), String> {
        self.execute(&format!(
            r#"{{"execute":"input-send-event","arguments":{{"events":[{{"type":"btn","data":{{"down":{down},"button":"left"}}}}]}}}}"#
        ))
    }
}

/// Follows the run: the screenshots against the guest's CRC-lines, then the
/// tablet's click, then the end of the four programs.
fn drive(run: &mut Run, scratch: &Scratch) -> Result<(), String> {
    const WITHIN: Duration = Duration::from_secs(120);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    for prefix in [OVERLAP, CLICK, SWITCH, SURVIVOR] {
        let line = run.expect_line(prefix, |l| l.contains(prefix), WITHIN)?;
        let first = gpu_probe::compare(&mut monitor, &scratch.picture(), &line, prefix);
        // A runner under load has dropped the monitor's connection once with
        // QEMU still up (the guest was waiting 2.5 s for this photograph). The
        // monitor takes a new client when the old one is gone, so a reset or a
        // closed connection is tried once more on a new one; a QEMU that is
        // gone refuses the new connection and the first error is the failure,
        // and a CRC that differs is never tried again.
        if let Err(e) = &first
            && (e.contains("Connection reset") || e.contains("monitor closed"))
        {
            println!("focus-probe: {e}; connecting to the monitor again");
            monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(5))
                .map_err(|again| format!("{e}; and the monitor does not answer again: {again}"))?;
            gpu_probe::compare(&mut monitor, &scratch.picture(), &line, prefix)?;
        } else {
            first?;
        }
    }
    // The keys are injected; then the device moves, to a place of the
    // surviving window, and its button goes down and up there.
    run.expect_line(INJECTED, |l| l == INJECTED, WITHIN)?;
    let mut qmp = Qmp::connect(
        &scratch.socket().with_file_name("qmp.sock"),
        Duration::from_secs(20),
    )?;
    qmp.move_to(200, 120, 640, 400)?;
    std::thread::sleep(Duration::from_millis(300));
    qmp.left_button(true)?;
    std::thread::sleep(Duration::from_millis(300));
    qmp.left_button(false)?;
    // The four end in the order the scene takes, which the lines of one
    // run already passed: each is looked for anywhere in the output.
    for ended in ENDED {
        run.expect_seen(ended, WITHIN)?;
    }
    Ok(())
}

/// `cargo xtask focus-probe`: the probe on `machine`, the screenshots of the
/// monitor against the guest's CRC and the tablet's click, and, on QEMU's own
/// emulation, the steps of the services under -icount.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-focus.img", &PROGRAMS, BOOT_PROFILE)?;
    let scratch = Scratch::new()?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    cmd.arg(format!(
        "unix:{},server=on,wait=off",
        scratch.socket().display()
    ));
    cmd.args(["-qmp"]);
    cmd.arg(format!(
        "unix:{},server=on,wait=off",
        scratch.socket().with_file_name("qmp.sock").display()
    ));
    cmd.args(qemu::GPU);
    cmd.args(qemu::TABLET);
    let mut run = Run::start(cmd, Input::Null)?;
    let driven = drive(&mut run, &scratch);
    let outcome = run.stop();
    driven.map_err(|e| format!("focus-probe on {}: {e}", machine.name))?;
    verdict(&outcome.lines, true).map_err(|e| format!("focus-probe on {}: {e}", machine.name))?;
    println!(
        "focus-probe on {}: the screen matched the guest's frames for two windows with an alpha, a click that raised one, the manager's switch and the screen after the second client ended; the keys went to the window with the focus only; the tablet's click reached the window under it",
        machine.name
    );
    if !machine.is_hvf() {
        steps(machine)?;
    }
    Ok(())
}

/// The run under -icount: the clients do not wait for the monitor, and the
/// services' steps are read from their lines.
fn steps(machine: &qemu::Machine) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-focus-steps.img", &STEPS_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::GPU);
    cmd.args(qemu::TABLET);
    cmd.args(qemu::ICOUNT);
    // The first client ends last: it waits for the many windows to go, and
    // then a moment more.
    let output = run_until(
        cmd,
        crate::BOOT_TIMEOUT * 4,
        Some("init: focus-a ended: "),
        &kernel.elf,
    )?;
    qemu::expect_stopped_on(&output, ENDED[0])?;
    for ended in &ENDED[1..] {
        qemu::expect_marker(&output, ended)?;
    }
    qemu::expect_marker(&output, MANY)?;
    if let Some(failed) = output
        .lines
        .iter()
        .find(|l| l.starts_with("focus-probe: failed"))
    {
        return Err(format!("focus-probe under -icount: {failed}"));
    }
    let (comp, input) = steps_verdict(&output.lines)?;
    crate::check_waits(
        &output.lines,
        &[comp_probe::COMP_TAG, INPUT_TAG],
        "focus-probe",
    )?;
    let text = |rows: &[(usize, u64, u64)]| -> String {
        rows.iter()
            .map(|(kind, ticks, _)| format!("kind {kind} {ticks}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "focus-probe on {}: the longest steps under -icount, ticks (0.9 of term B {}, portions {PORTION_MAX}): compositor {}; tablet's driver {}",
        machine.name,
        gpu_probe::STEP_MAX,
        text(&comp),
        text(&input)
    );
    println!(
        "focus-probe on {}: the cost of the layers inside the bands, ticks (CALL_TICKS {}, BAND_TICKS {}): {}",
        machine.name,
        compositor::CALL_TICKS,
        compositor::BAND_TICKS,
        comp_probe::raster_text(&comp_probe::raster_costs(
            &output.lines,
            comp_probe::COMP_TAG
        ))
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_run() -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        for (marker, n) in CHECKS.iter().chain(&TABLET_CHECKS) {
            for _ in 0..*n {
                lines.push((*marker).to_owned());
            }
        }
        lines.push("focus-probe: the manager gave the focus to window 0".to_owned());
        lines.push(format!("{TABLET_LINE}0"));
        lines
    }

    #[test]
    fn a_run_with_every_check_passes() {
        assert_eq!(verdict(&good_run(), true), Ok(()));
    }

    #[test]
    fn a_missing_or_a_failed_check_is_named() {
        let mut lines = good_run();
        lines.retain(|l| !l.contains("a events are exactly"));
        assert!(
            verdict(&lines, true)
                .unwrap_err()
                .contains("a events are exactly")
        );
        let mut lines = good_run();
        lines.push("focus-probe: failed: EVENTS".to_owned());
        assert_eq!(
            verdict(&lines, true),
            Err("focus-probe: failed: EVENTS".to_owned())
        );
    }

    #[test]
    fn the_run_without_a_monitor_has_no_tablet_check_and_two_switches_fail() {
        let mut lines = good_run();
        lines.retain(|l| !l.contains("the tablet's click"));
        assert!(verdict(&lines, true).is_err());
        assert_eq!(verdict(&lines, false), Ok(()));
        let mut twice = good_run();
        twice.push("focus-probe: the manager gave the focus to window 1".to_owned());
        assert!(verdict(&twice, true).unwrap_err().contains("2 times"));
    }

    #[test]
    fn a_tablet_driver_that_never_found_its_device_fails() {
        let mut lines = good_run();
        lines.retain(|l| !l.starts_with(TABLET_LINE));
        assert!(
            verdict(&lines, true)
                .unwrap_err()
                .contains("tablet's driver")
        );
    }

    #[test]
    fn a_step_past_the_bound_fails() {
        let row = |kind: usize, ticks: u64| {
            format!("service step: 17 kind {kind} {ticks} ticks detail 0")
        };
        let mut lines: Vec<String> = COMP_KINDS.iter().map(|&(k, _)| row(k, 100)).collect();
        lines.extend(
            INPUT_KINDS
                .iter()
                .map(|&(k, _)| format!("service step: {INPUT_TAG} kind {k} 100 ticks detail 0")),
        );
        assert!(steps_verdict(&lines).is_ok());
        lines.push(row(65, PORTION_MAX + 1));
        assert!(steps_verdict(&lines).unwrap_err().contains("portion"));
    }

    #[test]
    fn the_table_stands_for_the_lines_lost_in_the_burst() {
        let row = |kind: usize, ticks: u64| {
            format!("service step: 17 kind {kind} {ticks} ticks detail 0")
        };
        let mut lines: Vec<String> = COMP_KINDS.iter().map(|&(k, _)| row(k, 100)).collect();
        lines.extend(
            INPUT_KINDS
                .iter()
                .map(|&(k, _)| format!("service step: {INPUT_TAG} kind {k} 100 ticks detail 0")),
        );
        let lost = crate::step_line::tabled(&lines);
        assert!(steps_verdict(&lost).is_ok());
        let mut over = lost.clone();
        over.push(format!(
            "service table: 17 kind 65 {} ticks detail 0 preempts 0",
            PORTION_MAX + 1
        ));
        assert!(steps_verdict(&over).unwrap_err().contains("portion"));
    }
}
