// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the composition service (services/compositor) on QEMU's
//! virtio-gpu-device, which also runs under HVF: the display driver with
//! the compositor as its one client, and two clients of the compositor
//! (tests/comp-probe). The first makes windows of its own (two buffers, a
//! rectangle posted alone, a second window over the first) and ends holding
//! them; the second waits for them to go, finds the black screen they left,
//! and asks for the screen as a program of proto_gpu's first revision does
//! (OPEN, a pattern, FLUSH).
//!
//! While each client waits after a frame, xtask asks the monitor of QEMU
//! for a `screendump` and takes the CRC-32 of the colours: it equals the
//! CRC the guest computed for the screen it should show, so the compositor
//! put the windows where, in what order and in what colours they are, the
//! driver showed the frame, and the end of a process freed its windows (the
//! black screen).
//!
//! A second run, under -icount, measures the steps of the compositor and
//! of the driver: the probe in its `quick` build does not wait for the
//! monitor. Every step stays under 0.9 of term B, and a step of the
//! compositor's own (a band of the frame, the end of a frame) and of the
//! driver's under PORTION_MAX.

use std::time::Duration;

use crate::gpu_probe::{self, Scratch};
use crate::monitor::Monitor;
use crate::qemu::{Input, Run};
use crate::{
    BOOT_PROFILE, CHILD_STACK_SIZE, INIT_STACK_SIZE, ImageProgram, PORTION_MAX, Variant, build,
    build_boot_image, longest_steps, qemu, run_until,
};

/// The stack of the compositor: its loop's table of 96 sessions, the clones
/// it gave, the rings of events of its windows, and the frames of pixman's
/// general path, which keeps scanline buffers of 24 KiB on the stack.
pub const COMP_STACK_SIZE: u32 = 64 * 1024;

/// The probe's image: the driver, the compositor, the two clients.
pub const PROGRAMS: [ImageProgram; 4] = [
    ("init", "init", INIT_STACK_SIZE, &["table-comp"]),
    ("virtio-gpu", "virtio-gpu", gpu_probe::GPU_STACK_SIZE, &[]),
    ("compositor", "compositor", COMP_STACK_SIZE, &[]),
    ("comp-probe", "comp-probe", CHILD_STACK_SIZE, &[]),
];

/// The image of the run under -icount: the driver and the compositor count
/// their steps, the clients do not wait for the monitor.
pub const STEPS_PROGRAMS: [ImageProgram; 4] = [
    ("init", "init", INIT_STACK_SIZE, &["table-comp"]),
    (
        "virtio-gpu",
        "virtio-gpu",
        gpu_probe::GPU_STACK_SIZE,
        &["steps"],
    ),
    ("compositor", "compositor", COMP_STACK_SIZE, &["steps"]),
    ("comp-probe", "comp-probe", CHILD_STACK_SIZE, &["quick"]),
];

pub const DRIVER_LINE: &str = gpu_probe::SERVICE_LINE;
pub const DRIVER_READY: &str = gpu_probe::READY;
pub const READY: &str = "compositor: screen ready, 640x400, stride 2560";
/// The line of the compositor when a window of the first revision went and
/// its place was shown again (the line of the driver when the screen came
/// back, which the games probe counts).
pub const RELEASED: &str = gpu_probe::RELEASED;

const WINDOW: &str = "comp-probe: window crc ";
const PARTIAL: &str = "comp-probe: partial crc ";
const OVERLAP: &str = "comp-probe: overlap crc ";
const BLACK: &str = "comp-probe: black crc ";
const LEGACY: &str = "comp-probe: legacy crc ";
const LEGACY_PARTIAL: &str = "comp-probe: legacy partial crc ";
const ENDED: &str = "init: comp-probe ended: exit code 0, not restarted";
const ENDED_B: &str = "init: comp-probe-b ended: exit code 0, not restarted";
const B_ENDS: &str = "init: comp-probe-b ended: ";

/// The lines each client prints once per check that passed, and how many
/// times a run has each.
const CHECKS: [(&str, usize); 20] = [
    ("comp-probe: the screen is 640x400, no window yet", 1),
    (
        "comp-probe: windows outside the screen or of another format are refused",
        1,
    ),
    (
        "comp-probe: ATTACH takes the buffers once and checks them",
        1,
    ),
    (
        "comp-probe: a POST with a wrong buffer or rectangle is INVALID",
        1,
    ),
    ("comp-probe: the buffer the frame replaced came free", 1),
    ("comp-probe: a session calls its own methods only", 1),
    (
        "comp-probe: a window that went gives its place to a window with buffers",
        1,
    ),
    ("comp-probe: a context has four windows at most", 1),
    ("comp-probe: the client ends with its windows", 1),
    (
        "comp-probe: the windows of the client that ended are gone",
        1,
    ),
    (
        "comp-probe: OPEN gives a window of the whole screen, a cleared buffer",
        1,
    ),
    ("comp-probe: a second OPEN is BUSY", 1),
    (
        "comp-probe: OPEN is BUSY while a closed window's mapping is kept",
        1,
    ),
    (
        "comp-probe: OPEN is BUSY while a closed window's handle is kept",
        1,
    ),
    ("comp-probe: after the unmap OPEN gives a cleared buffer", 1),
    (
        "comp-probe: FLUSH of a rectangle outside the screen is INVALID",
        1,
    ),
    ("comp-probe: the program ends with its window", 1),
    ("comp-probe: ok", 2),
    (DRIVER_LINE, 1),
    (DRIVER_READY, 1),
];

/// The tags of the lines of steps (rt::service::report_steps): the driver's
/// and the compositor's.
const DRIVER_TAG: &str = "12";
pub const COMP_TAG: &str = "17";
/// The kinds of the compositor's steps that must come: OPEN and FLUSH of
/// proto_gpu, DESCRIBE, WINDOW_CREATE, ATTACH and POST of proto_comp, and
/// its own (a band, the end of a frame).
const COMP_KINDS: [(usize, &str); 7] = [
    (1, "Open"),
    (2, "Flush"),
    (17, "Describe"),
    (18, "WindowCreate"),
    (19, "Attach"),
    (20, "Post"),
    (65, "a band of a frame and the end of a frame"),
];
/// The driver's: SUBSCRIBE, COMMIT, and its own (the interrupt).
const DRIVER_KINDS: [(usize, &str); 3] = [(5, "Subscribe"), (6, "Commit"), (65, "the interrupt")];

/// Judges the lines of a run: the compositor and the driver started and
/// were ready once, every check of the clients passed once, none failed,
/// and the window of the first revision came back once.
pub fn verdict(lines: &[String]) -> Result<(), String> {
    let lines = &crate::qemu::unglued(lines, RELEASED);
    let count = |marker: &str| lines.iter().filter(|l| l.as_str() == marker).count();
    if let Some(failed) = lines.iter().find(|l| l.starts_with("comp-probe: failed")) {
        return Err(failed.clone());
    }
    for (marker, wanted) in CHECKS.iter().chain(&[(READY, 1), (RELEASED, 2)]) {
        if count(marker) != *wanted {
            let found: Vec<_> = lines
                .iter()
                .filter(|l| {
                    l.starts_with("virtio-gpu: ")
                        || l.starts_with("gpu: ")
                        || l.starts_with("compositor: ")
                })
                .collect();
            return Err(format!(
                "{} lines {marker:?}, {wanted} expected; the services said {found:?}",
                count(marker)
            ));
        }
    }
    Ok(())
}

/// The steps of one service: every kind came, every row is under STEP_MAX
/// and the rows of its own kind under PORTION_MAX.
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

/// The steps of the compositor and of the driver.
pub fn steps_verdict(lines: &[String]) -> Result<(Rows, Rows), String> {
    Ok((
        rows_of(lines, COMP_TAG, "compositor", &COMP_KINDS)?,
        rows_of(lines, DRIVER_TAG, "display driver", &DRIVER_KINDS)?,
    ))
}

/// The longest step of each kind: kind, ticks, detail.
pub type Rows = Vec<(usize, u64, u64)>;

/// Follows the run: the screenshots against the guest's CRC-lines, then
/// the end of both clients.
fn drive(run: &mut Run, scratch: &Scratch) -> Result<(), String> {
    const WITHIN: Duration = Duration::from_secs(120);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    let compare = |run: &mut Run, monitor: &mut Monitor, prefix: &str| -> Result<(), String> {
        let line = run.expect_line(prefix, |l| l.contains(prefix), WITHIN)?;
        gpu_probe::compare(monitor, &scratch.picture(), &line, prefix)
    };
    for prefix in [WINDOW, PARTIAL, OVERLAP] {
        compare(run, &mut monitor, prefix)?;
    }
    // The first client ends, and the second finds the black screen it left.
    run.expect_line(ENDED, |l| l == ENDED, WITHIN)?;
    for prefix in [BLACK, LEGACY, LEGACY_PARTIAL] {
        compare(run, &mut monitor, prefix)?;
    }
    run.expect_line(ENDED_B, |l| l == ENDED_B, WITHIN)?;
    // The compositor paints the legacy window's place black and says so
    // once that frame is shown, which can come after the launcher's line.
    run.expect_times(RELEASED, 2, WITHIN)?;
    Ok(())
}

/// `cargo xtask comp-probe` and its run in `test` under HVF: the probe on
/// `machine`, the screenshots of the monitor against the guest's CRC, and,
/// on QEMU's own emulation, the steps of the services under -icount.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-comp.img", &PROGRAMS, BOOT_PROFILE)?;
    let scratch = Scratch::new()?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    cmd.arg(format!(
        "unix:{},server=on,wait=off",
        scratch.socket().display()
    ));
    cmd.args(qemu::GPU);
    let mut run = Run::start(cmd, Input::Null)?;
    let driven = drive(&mut run, &scratch);
    let outcome = run.stop();
    driven.map_err(|e| format!("comp-probe on {}: {e}", machine.name))?;
    verdict(&outcome.lines).map_err(|e| format!("comp-probe on {}: {e}", machine.name))?;
    println!(
        "comp-probe on {}: the screen matched the guest's frames for a window, a rectangle of it, two windows, the black screen after a process ended and a window of the first revision",
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
    let image = build_boot_image("boot-comp-steps.img", &STEPS_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::GPU);
    cmd.args(qemu::ICOUNT);
    let output = run_until(cmd, crate::BOOT_TIMEOUT * 4, Some(B_ENDS), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED_B)?;
    qemu::expect_marker(&output, ENDED)?;
    if let Some(failed) = output
        .lines
        .iter()
        .find(|l| l.starts_with("comp-probe: failed"))
    {
        return Err(format!("comp-probe under -icount: {failed}"));
    }
    let (comp, driver) = steps_verdict(&output.lines)?;
    crate::check_waits(&output.lines, &[COMP_TAG, DRIVER_TAG], "comp-probe")?;
    let text = |rows: &[(usize, u64, u64)]| -> String {
        rows.iter()
            .map(|(kind, ticks, _)| format!("kind {kind} {ticks}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "comp-probe on {}: the longest steps under -icount, ticks (0.9 of term B {}, portions {PORTION_MAX}): compositor {}; driver {}",
        machine.name,
        gpu_probe::STEP_MAX,
        text(&comp),
        text(&driver)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_run() -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        for (marker, n) in CHECKS.iter().chain(&[(READY, 1), (RELEASED, 2)]) {
            for _ in 0..*n {
                lines.push((*marker).to_owned());
            }
        }
        lines
    }

    #[test]
    fn a_run_with_every_check_passes() {
        assert_eq!(verdict(&good_run()), Ok(()));
    }

    #[test]
    fn a_missing_or_a_failed_check_is_named() {
        let mut lines = good_run();
        lines.retain(|l| l != "comp-probe: a second OPEN is BUSY");
        assert!(
            verdict(&lines)
                .unwrap_err()
                .contains("a second OPEN is BUSY")
        );
        let mut lines = good_run();
        lines.push("comp-probe: failed: POST".to_owned());
        assert_eq!(verdict(&lines), Err("comp-probe: failed: POST".to_owned()));
    }

    #[test]
    fn a_compositor_that_never_had_its_screen_or_a_window_that_never_went_fails() {
        let mut lines = good_run();
        lines.retain(|l| l != READY);
        assert!(verdict(&lines).is_err());
        let mut lines = good_run();
        lines.retain(|l| l != RELEASED);
        assert!(verdict(&lines).unwrap_err().contains("screen released"));
    }

    #[test]
    fn a_release_that_came_inside_the_line_of_a_client_still_counts() {
        // Run 44364602842: the line of the compositor came in the middle of a client's line.
        let mut lines = good_run();
        let busy = "comp-probe: OPEN is BUSY while a closed window's mapping is kept";
        assert!(
            lines.iter().any(|l| l == busy),
            "the check is in the good run"
        );
        lines.retain(|l| l != busy && l != RELEASED);
        lines.push(RELEASED.to_owned());
        lines.push(format!(
            "comp-probe: OPEN is BUSY while a closed window's mapping is{RELEASED}"
        ));
        lines.push(" kept".to_owned());
        assert_eq!(verdict(&lines), Ok(()));
    }

    fn step(tag: &str, kind: usize, ticks: u64) -> String {
        format!("service step: {tag} kind {kind} {ticks} ticks detail 0")
    }

    fn rows(over: Option<(&str, usize, u64)>, skip: Option<(&str, usize)>) -> Vec<String> {
        let mut out = Vec::new();
        for (tag, kinds) in [(COMP_TAG, &COMP_KINDS[..]), (DRIVER_TAG, &DRIVER_KINDS[..])] {
            for (kind, _) in kinds {
                if skip == Some((tag, *kind)) {
                    continue;
                }
                let ticks = match over {
                    Some((t, k, n)) if t == tag && k == *kind => n,
                    _ => 3000,
                };
                out.push(step(tag, *kind, ticks));
            }
        }
        out
    }

    #[test]
    fn steps_under_the_bounds_pass() {
        let (comp, driver) = steps_verdict(&rows(None, None)).unwrap();
        assert_eq!(comp.len(), COMP_KINDS.len());
        assert_eq!(driver.len(), DRIVER_KINDS.len());
    }

    #[test]
    fn a_step_past_the_bound_or_a_missing_kind_fails() {
        assert!(steps_verdict(&rows(Some((COMP_TAG, 20, gpu_probe::STEP_MAX + 1)), None)).is_err());
        // A band past the portion bound fails for the own kind alone.
        assert!(steps_verdict(&rows(Some((COMP_TAG, 65, PORTION_MAX + 1)), None)).is_err());
        assert!(steps_verdict(&rows(Some((COMP_TAG, 20, PORTION_MAX + 1)), None)).is_ok());
        assert!(
            steps_verdict(&rows(None, Some((COMP_TAG, 19))))
                .unwrap_err()
                .contains("Attach")
        );
        assert!(
            steps_verdict(&rows(None, Some((DRIVER_TAG, 6))))
                .unwrap_err()
                .contains("Commit")
        );
    }

    #[test]
    fn the_table_stands_for_the_lines_lost_in_the_burst() {
        let lost = crate::step_line::tabled(&rows(None, None));
        assert!(lost.iter().all(|l| l.starts_with("service table:")));
        let (comp, driver) = steps_verdict(&lost).unwrap();
        assert_eq!(
            (comp.len(), driver.len()),
            (COMP_KINDS.len(), DRIVER_KINDS.len())
        );
        let over =
            crate::step_line::tabled(&rows(Some((COMP_TAG, 20, gpu_probe::STEP_MAX + 1)), None));
        assert!(steps_verdict(&over).is_err());
    }
}
