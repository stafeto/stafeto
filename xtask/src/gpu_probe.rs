// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the display service (services/virtio-gpu) on QEMU's
//! virtio-gpu-device, which also runs under HVF. Two clients of the
//! service (tests/gpu-probe): the first opens the screen, shows a pattern
//! and then a rectangle of another colour, tries the refusals and ends
//! holding the screen; the second takes the screen once the first ended,
//! finds the buffer cleared, closes the screen and finds the buffer cleared
//! again, kills the service and opens the screen of the new instance.
//!
//! While the first client waits after each frame, xtask asks the monitor of
//! QEMU for a `screendump` and takes the CRC-32 of the colours: it equals
//! the CRC the guest printed for the buffer it drew, so the device showed
//! what the guest wrote (the pattern, then the rectangle at the offset
//! `y * stride + x * 4`). On HVF the same holds without any clean of the
//! cache, which is what spec 3, 3.4 expects of a cached buffer.
//!
//! A second run, under -icount (QEMU's own emulation), measures the steps
//! of the service: the probe in its `quick` build does not wait for the
//! monitor. Every step stays under 0.9 of term B, and a step of the
//! interrupt or of the clearing (one portion of 16 KiB) under PORTION_MAX.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::monitor::Monitor;
use crate::qemu::{Input, Run};
use crate::{
    BOOT_PROFILE, CHILD_STACK_SIZE, INIT_STACK_SIZE, ImageProgram, PORTION_MAX, TERM_B, Variant,
    build, build_boot_image, longest_steps, qemu, run_until,
};

/// The stack of the display service: its loop's table of 96 sessions and
/// the clones it gave.
pub const GPU_STACK_SIZE: u32 = 32 * 1024;

/// The probe's image: the service with CRASH, the two clients.
pub const PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["table-gpu"]),
    ("virtio-gpu", "virtio-gpu", GPU_STACK_SIZE, &["crash"]),
    ("gpu-probe", "gpu-probe", CHILD_STACK_SIZE, &[]),
];

/// The image of the run under -icount: the service counts its steps, the
/// clients do not wait for the monitor.
pub const STEPS_PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["table-gpu"]),
    (
        "virtio-gpu",
        "virtio-gpu",
        GPU_STACK_SIZE,
        &["crash", "steps"],
    ),
    ("gpu-probe", "gpu-probe", CHILD_STACK_SIZE, &["quick"]),
];

/// The service's line at each start: the transport, its line and the
/// device's status as the driver found it, before its own reset: 0 at the
/// machine's start and after init stopped the device.
pub const SERVICE_LINE: &str = "virtio-gpu: virtio-mmio at 0xa002e00, line 71, status 0x0";
pub const READY: &str = "virtio-gpu: screen ready, 640x400, stride 2560";
pub const RELEASED: &str = "gpu: screen released";
const PATTERN: &str = "gpu-probe: pattern crc ";
const PARTIAL: &str = "gpu-probe: partial crc ";
const ENDED: &str = "init: gpu-probe ended: exit code 0, not restarted";
const ENDED_B: &str = "init: gpu-probe-b ended: exit code 0, not restarted";
const B_ENDS: &str = "init: gpu-probe-b ended: ";

/// The lines each client prints once per check that passed, and how many
/// times a run has each.
const CHECKS: [(&str, usize); 11] = [
    ("gpu-probe: the owner's handles cannot be duplicated", 1),
    (
        "gpu-probe: screen 640x400, stride 2560, a cleared buffer",
        1,
    ),
    ("gpu-probe: rectangles outside the screen are INVALID", 1),
    ("gpu-probe: a second OPEN is BUSY", 1),
    ("gpu-probe: a session calls its own methods only", 1),
    (
        "gpu-probe: the screen came back cleared when its owner ended",
        1,
    ),
    (
        "gpu-probe: CLOSE returned the screen, a cleared buffer, FLUSH REVOKED",
        1,
    ),
    ("gpu-probe: FLUSH after the service ended is PEER_CLOSED", 1),
    (
        "gpu-probe: a new session after the restart opened the screen",
        1,
    ),
    ("gpu-probe: ok", 2),
    (SERVICE_LINE, 2),
];

/// The tag of the service's lines of steps (rt::service::report_steps).
const GPU_TAG: &str = "12";
/// The kinds of the service's steps that must come: OPEN, FLUSH, CLOSE,
/// CLONE (the methods of proto_gpu), and its own steps: the interrupt and
/// the portions of clearing (rt::service::step_own).
const STEP_KINDS: [(usize, &str); 5] = [
    (1, "Open"),
    (2, "Flush"),
    (3, "Close"),
    (8, "Clone"),
    (65, "the interrupt and a portion of clearing"),
];
/// The most one step of the service may take (spec 3, section 6): 0.9 of
/// term B, 18,369 ticks.
pub const STEP_MAX: u64 = TERM_B * 9 / 10;

/// The CRC after `prefix` in the line of the guest, eight hex digits.
pub fn crc_of(line: &str, prefix: &str) -> Result<u32, String> {
    let digits = line
        .split_once(prefix)
        .map(|(_, rest)| rest.trim())
        .ok_or_else(|| format!("no {prefix:?} in {line:?}"))?;
    u32::from_str_radix(digits, 16).map_err(|e| format!("the CRC in {line:?}: {e}"))
}

/// Judges the lines of a run: the service started twice, ready each time,
/// every check of the clients passed once, none failed, and the screen
/// went back at least three times (the first client's end, a CLOSE, the
/// second client's end under the new instance).
pub fn verdict(lines: &[String]) -> Result<(), String> {
    let count = |marker: &str| lines.iter().filter(|l| l.as_str() == marker).count();
    if let Some(failed) = lines.iter().find(|l| l.starts_with("gpu-probe: failed")) {
        return Err(failed.clone());
    }
    for (marker, wanted) in CHECKS.iter().chain(&[(READY, 2)]) {
        if count(marker) != *wanted {
            let found: Vec<_> = lines
                .iter()
                .filter(|l| l.starts_with("virtio-gpu: ") || l.starts_with("gpu: "))
                .collect();
            return Err(format!(
                "{} lines {marker:?}, {wanted} expected; the service said {found:?}",
                count(marker)
            ));
        }
    }
    let released = count(RELEASED);
    if released < 3 {
        return Err(format!("the screen went back {released} times, 3 expected"));
    }
    Ok(())
}

/// The steps of the service (loop_steps of entropy.rs, with its own
/// bounds): every kind came, every row stays under STEP_MAX, and the rows
/// of the interrupt and of the portions under PORTION_MAX.
pub fn steps_verdict(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = longest_steps(lines, GPU_TAG);
    for (kind, name) in STEP_KINDS {
        if !rows.iter().any(|(k, ..)| *k == kind) {
            return Err(format!("the display service: no step {name}: {rows:?}"));
        }
    }
    if let Some(row) = rows.iter().find(|r| r.1 > STEP_MAX) {
        return Err(format!(
            "the display service: a step past 0.9 of term B ({STEP_MAX}): {row:?}"
        ));
    }
    if let Some(row) = rows.iter().find(|r| r.0 == 65 && r.1 > PORTION_MAX) {
        return Err(format!(
            "the display service: a portion or an interrupt past {PORTION_MAX}: {row:?}"
        ));
    }
    Ok(rows)
}

/// Where the run keeps its monitor's socket and the screenshots.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new() -> Result<Scratch, String> {
        let dir = std::env::temp_dir().join(format!("stafeto-gpu-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        Ok(Scratch(dir))
    }

    pub fn socket(&self) -> PathBuf {
        self.0.join("monitor.sock")
    }

    pub fn picture(&self) -> PathBuf {
        self.0.join("screen.ppm")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A screenshot of the monitor, 640 by 400, whose CRC is the guest's.
pub fn compare(
    monitor: &mut Monitor,
    picture: &Path,
    line: &str,
    prefix: &str,
) -> Result<(), String> {
    let wanted = crc_of(line, prefix)?;
    let shot = monitor.screendump(picture)?;
    if (shot.width, shot.height) != (640, 400) {
        return Err(format!(
            "the screenshot is {}x{}, 640x400 expected",
            shot.width, shot.height
        ));
    }
    if shot.crc32() != wanted {
        return Err(format!(
            "the screenshot's CRC-32 is {:08x}, the guest drew {wanted:08x} ({prefix:?}), {} colours",
            shot.crc32(),
            shot.colours()
        ));
    }
    println!(
        "gpu-probe: the screenshot after {:?} has the guest's CRC-32 {wanted:08x}, {} colours",
        prefix.trim(),
        shot.colours()
    );
    Ok(())
}

/// Follows the run: the screenshots against the guest's CRC-lines, then
/// the end of both clients.
fn drive(run: &mut Run, scratch: &Scratch) -> Result<(), String> {
    const WITHIN: Duration = Duration::from_secs(120);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    for prefix in [PATTERN, PARTIAL] {
        let line = run.expect_line(prefix, |l| l.contains(prefix), WITHIN)?;
        compare(&mut monitor, &scratch.picture(), &line, prefix)?;
    }
    run.expect_line(ENDED, |l| l == ENDED, WITHIN)?;
    run.expect_line(ENDED_B, |l| l == ENDED_B, WITHIN)?;
    // The service clears the screen of the second client in portions after
    // the client ended, so its line can come after the launcher's: the run
    // is not stopped before the third return of the screen.
    run.expect_times(RELEASED, 3, WITHIN)?;
    Ok(())
}

/// `cargo xtask gpu-probe` and its run in `test` under HVF: the probe on
/// `machine`, the screenshots of the monitor against the guest's CRC, and,
/// on QEMU's own emulation, the steps of the service under -icount.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-gpu.img", &PROGRAMS, BOOT_PROFILE)?;
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
    driven.map_err(|e| format!("gpu-probe on {}: {e}", machine.name))?;
    verdict(&outcome.lines).map_err(|e| format!("gpu-probe on {}: {e}", machine.name))?;
    println!(
        "gpu-probe on {}: the screen matched the guest's frames, one owner, the screen back three times, a restart",
        machine.name
    );
    if !machine.is_hvf() {
        steps(machine)?;
    }
    Ok(())
}

/// The run under -icount: the clients do not wait for the monitor, and the
/// service's steps are read from its lines.
fn steps(machine: &qemu::Machine) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-gpu-steps.img", &STEPS_PROGRAMS, BOOT_PROFILE)?;
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
        .find(|l| l.starts_with("gpu-probe: failed"))
    {
        return Err(format!("gpu-probe under -icount: {failed}"));
    }
    let rows = steps_verdict(&output.lines)?;
    crate::check_waits(&output.lines, &[GPU_TAG], "gpu-probe")?;
    let text: Vec<_> = rows
        .iter()
        .map(|(kind, ticks, _)| format!("kind {kind} {ticks}"))
        .collect();
    println!(
        "gpu-probe on {}: the longest steps under -icount, ticks (0.9 of term B {STEP_MAX}, portions {PORTION_MAX}): {}",
        machine.name,
        text.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_run() -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        for _ in 0..2 {
            lines.push(SERVICE_LINE.to_owned());
            lines.push(READY.to_owned());
        }
        for (marker, n) in CHECKS.iter().filter(|(m, _)| *m != SERVICE_LINE) {
            for _ in 0..*n {
                lines.push((*marker).to_owned());
            }
        }
        for _ in 0..3 {
            lines.push(RELEASED.to_owned());
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
        lines.retain(|l| l != "gpu-probe: a second OPEN is BUSY");
        assert!(
            verdict(&lines)
                .unwrap_err()
                .contains("a second OPEN is BUSY")
        );
        let mut lines = good_run();
        lines.push("gpu-probe: failed: OPEN".to_owned());
        assert_eq!(verdict(&lines), Err("gpu-probe: failed: OPEN".to_owned()));
    }

    #[test]
    fn a_service_that_started_once_or_returned_the_screen_twice_fails() {
        let mut lines = good_run();
        let at = lines
            .iter()
            .rposition(|l| l == SERVICE_LINE)
            .expect("a start");
        lines.remove(at);
        assert!(verdict(&lines).is_err());
        let mut lines = good_run();
        let at = lines.iter().rposition(|l| l == RELEASED).expect("a return");
        lines.remove(at);
        assert!(verdict(&lines).unwrap_err().contains("2 times"));
    }

    #[test]
    fn the_crc_is_read_after_its_prefix() {
        assert_eq!(
            crc_of("gpu-probe: pattern crc 1a2b3c4d", PATTERN),
            Ok(0x1a2b_3c4d)
        );
        assert!(crc_of("gpu-probe: pattern crc zz", PATTERN).is_err());
        assert!(crc_of("gpu-probe: partial crc 12", PATTERN).is_err());
    }

    fn step(kind: usize, ticks: u64) -> String {
        format!("service step: {GPU_TAG} kind {kind} {ticks} ticks detail 0")
    }

    #[test]
    fn steps_under_the_bounds_pass() {
        let lines: Vec<String> = [
            (1, 3000),
            (2, 2500),
            (3, 900),
            (8, 2000),
            (65, 5000),
            (64, 4000),
        ]
        .iter()
        .map(|&(k, t)| step(k, t))
        .collect();
        assert_eq!(steps_verdict(&lines).map(|r| r.len()), Ok(6));
    }

    #[test]
    fn a_step_past_the_bound_or_a_missing_kind_fails() {
        let base = [(1, 3000), (2, 2500), (3, 900), (8, 2000), (65, 5000)];
        let make = |over: Option<(usize, u64)>, skip: Option<usize>| -> Vec<String> {
            base.iter()
                .filter(|(k, _)| Some(*k) != skip)
                .map(|&(k, t)| match over {
                    Some((ok, ot)) if ok == k => step(k, ot),
                    _ => step(k, t),
                })
                .collect()
        };
        assert!(steps_verdict(&make(Some((2, STEP_MAX + 1)), None)).is_err());
        // A portion past 0.8 of term B but under 0.9 fails for the own kind
        // alone.
        assert!(steps_verdict(&make(Some((65, PORTION_MAX + 1)), None)).is_err());
        assert!(steps_verdict(&make(Some((2, PORTION_MAX + 1)), None)).is_ok());
        assert!(
            steps_verdict(&make(None, Some(8)))
                .unwrap_err()
                .contains("Clone")
        );
    }

    #[test]
    fn the_bounds_are_the_specs() {
        assert_eq!(STEP_MAX, 18_369);
        assert_eq!(PORTION_MAX, 16_328);
    }
}
