// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the screen and the keys of libc.so (sub-project 3, part
//! 3b; spec 3, 3.7 and 9.3) on QEMU's virtio-gpu-device and
//! virtio-keyboard-device, which also run under HVF. A C program on libc.so
//! (tests/posix-so/dyn/display-probe.c), started by tests/display-run,
//! calls `stafeto_display_open`, `stafeto_display_flush`,
//! `stafeto_input_read` and `stafeto_display_close`: the description, a
//! pattern and a rectangle shown, the keys, the refusals, a forked child,
//! `exec`, the end of a process that owns the screen, a restart of the
//! display service.
//!
//! Every screen the guest shows is photographed through the monitor of
//! QEMU (`screendump`) and the CRC-32 of its colours must equal the one the
//! guest printed. The keys `a` and `b` are the guest's cue to go on: the
//! guest prints the CRC of a frame it has shown, xtask photographs the
//! screen and sends the key (`sendkey`, a Linux event the guest checks by
//! code), and the guest reads it.
//!
//! A second launcher of the image has no session with the display service
//! and runs the role of an image without one (ENODEV from open, EBADF from
//! the rest).

use std::time::Duration;

use crate::gpu_probe::{self, Scratch};
use crate::monitor::Monitor;
use crate::qemu::{Input, Run};
use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, POSIX_STACK_SIZE, Variant, build,
    build_boot_image, libc_so, qemu,
};

/// The probe's image: the services of the POSIX probes, the input and the
/// display service (with the method that ends it), and the launcher.
pub const PROGRAMS: [ImageProgram; 11] = [
    ("init", "init", INIT_STACK_SIZE, &["table-display"]),
    ("ramfs", "ramfs", crate::RAMFS_STACK_SIZE, &[]),
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
        "virtio-input",
        "virtio-input",
        crate::input_probe::INPUT_STACK_SIZE,
        &[],
    ),
    (
        "virtio-gpu",
        "virtio-gpu",
        gpu_probe::GPU_STACK_SIZE,
        &["crash"],
    ),
    ("display-run", "display-run", POSIX_STACK_SIZE, &[]),
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
];

const PATTERN: &str = "display-probe: pattern crc ";
const PARTIAL: &str = "display-probe: partial crc ";
const ENDED: &str = "init: display-run ended: exit code 0, not restarted";
const ENDED_B: &str = "init: display-run-b ended: exit code 0, not restarted";

/// The lines the probe prints once per check that passed.
const CHECKS: [&str; 15] = [
    "display-probe: before the open the calls are EBADF, a null description EINVAL",
    "display-probe: the screen is 640x400, XRGB8888, a cleared buffer; a second open gives the same",
    "display-probe: with no key pressed a read gives 0",
    "display-probe: the keys a down and a up came",
    "display-probe: the keys b down and b up came one by one",
    "display-probe: rectangles outside the screen are EINVAL",
    "display-probe: a forked child gets EBUSY at once and SIGSEGV at the parent's buffer",
    "display-probe: after exec the screen opens at once and its buffer is cleared",
    "display-probe: after the exit of its owner the screen opens, a cleared buffer",
    "display-probe: close takes the buffer away and the screen opens again",
    "display-probe: after the display service ended flush and the keys are ENODEV",
    "display-probe: close still works and a new open is ENODEV",
    "display-probe: without a display service open is ENODEV and the rest EBADF",
    "display-probe: ok",
    "display-probe: nogpu ok",
];

/// Judges the lines of a run: every check of the probe once, none failed,
/// the display service started twice (the probe ended it once) and the
/// screen went back at least three times (the exec, the end of the second
/// role, the close of the third).
pub fn verdict(lines: &[String]) -> Result<(), String> {
    let count = |marker: &str| lines.iter().filter(|l| l.as_str() == marker).count();
    if let Some(failed) = lines.iter().find(|l| {
        l.starts_with("display-probe: check failed") || l.starts_with("display-probe: failed")
    }) {
        return Err(failed.clone());
    }
    for marker in CHECKS.into_iter().chain([ENDED, ENDED_B]) {
        if count(marker) != 1 {
            return Err(format!("{} lines {marker:?}, 1 expected", count(marker)));
        }
    }
    for (marker, wanted) in [(gpu_probe::SERVICE_LINE, 2), (gpu_probe::READY, 2)] {
        if count(marker) != wanted {
            return Err(format!(
                "{} lines {marker:?}, {wanted} expected",
                count(marker)
            ));
        }
    }
    let released = count(gpu_probe::RELEASED);
    if released < 3 {
        return Err(format!("the screen went back {released} times, 3 expected"));
    }
    Ok(())
}

/// Follows the run: the screenshots against the guest's CRC, a key after
/// each, then the end of both launchers.
fn drive(run: &mut Run, scratch: &Scratch) -> Result<(), String> {
    const WITHIN: Duration = Duration::from_secs(180);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    for (prefix, key) in [(PATTERN, "a"), (PARTIAL, "b")] {
        let line = run.expect_line(prefix, |l| l.contains(prefix), WITHIN)?;
        gpu_probe::compare(&mut monitor, &scratch.picture(), &line, prefix)?;
        monitor.sendkey(key, Some(50))?;
    }
    // The launcher of the image without a display service ended long
    // before: `verdict` looks for its line. A probe that failed ends the
    // launcher with another code.
    run.expect_line(
        ENDED,
        |l| l.starts_with("init: display-run ended: "),
        WITHIN,
    )?;
    // The service the probe ended starts again, ready for the next OPEN.
    run.expect_line(
        "the display service again",
        |l| l == gpu_probe::READY,
        WITHIN,
    )?;
    Ok(())
}

/// `cargo xtask display-probe` and its run in `test` under HVF.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    libc_so()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-display.img", &PROGRAMS, BOOT_PROFILE)?;
    let scratch = Scratch::new()?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    cmd.arg(format!(
        "unix:{},server=on,wait=off",
        scratch.socket().display()
    ));
    cmd.args(qemu::GPU);
    cmd.args(qemu::KEYBOARD);
    let mut run = Run::start(cmd, Input::Null)?;
    let driven = drive(&mut run, &scratch);
    let outcome = run.stop();
    if let Err(e) = driven {
        // A probe that failed says so before the run times out.
        let said = outcome.lines.iter().find(|l| {
            l.starts_with("display-probe: check failed") || l.starts_with("display-probe: failed")
        });
        return Err(format!(
            "display-probe on {}: {}",
            machine.name,
            said.map_or(e, Clone::clone)
        ));
    }
    verdict(&outcome.lines).map_err(|e| format!("display-probe on {}: {e}", machine.name))?;
    println!(
        "display-probe on {}: the screen and the keys of libc.so: the description, two frames that matched QEMU's screenshots, the keys, the refusals, fork, exec, the end of the owner, a restart of the display service, an image without one",
        machine.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_run() -> Vec<String> {
        let mut lines: Vec<String> = CHECKS.iter().map(|c| (*c).to_owned()).collect();
        lines.push(ENDED.to_owned());
        lines.push(ENDED_B.to_owned());
        for _ in 0..2 {
            lines.push(gpu_probe::SERVICE_LINE.to_owned());
            lines.push(gpu_probe::READY.to_owned());
        }
        for _ in 0..3 {
            lines.push(gpu_probe::RELEASED.to_owned());
        }
        lines
    }

    #[test]
    fn a_run_with_every_check_passes() {
        assert_eq!(verdict(&good_run()), Ok(()));
    }

    #[test]
    fn a_missing_check_a_failure_or_a_missed_return_is_named() {
        let mut lines = good_run();
        lines.retain(|l| !l.contains("forked child"));
        assert!(verdict(&lines).unwrap_err().contains("forked child"));
        let mut lines = good_run();
        lines.push("display-probe: check failed at line 9: x (errno 1)".to_owned());
        assert!(verdict(&lines).unwrap_err().contains("check failed"));
        let mut lines = good_run();
        let at = lines
            .iter()
            .rposition(|l| l == gpu_probe::RELEASED)
            .expect("a return");
        lines.remove(at);
        assert!(verdict(&lines).unwrap_err().contains("2 times"));
        let mut lines = good_run();
        let at = lines
            .iter()
            .rposition(|l| l == gpu_probe::SERVICE_LINE)
            .expect("a start");
        lines.remove(at);
        assert!(verdict(&lines).is_err());
    }
}
