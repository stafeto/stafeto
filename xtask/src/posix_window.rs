// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C probe of the window library (tests/posix-window, the functions of
//! `<stafeto/window.h>` in a static program) on QEMU's virtio-gpu-device:
//! the services of the POSIX probes, the display driver, the compositor and
//! the probe, which starts its own file once. The copy that can fork makes a
//! window of 200 by 100 points with two buffers, posts a pattern, a second
//! buffer with one rectangle changed and the first again with five
//! rectangles that merge into their bounding box, and prints the CRC-32 of
//! the screen it should show after each frame. While the probe waits after a
//! line, xtask asks the monitor of QEMU for a `screendump` and takes the
//! CRC-32 of the colours (`comp-probe`'s way): the two are equal, so the
//! window library's buffers, the compositor's frame and the driver's show
//! agree. The other checks (the bits that free the buffers, the events, the
//! child that has no window, the signal that ends a wait, the close) are the
//! probe's lines.

use std::time::Duration;

use crate::gpu_probe::{self, Scratch};
use crate::monitor::Monitor;
use crate::qemu::{Input, Run};
use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, POSIX_STACK_SIZE, Variant, build,
    build_boot_image, qemu,
};

/// The probe's image: the services of the POSIX probes, the driver, the
/// compositor and the probe.
pub const PROGRAMS: [ImageProgram; 11] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-window"]),
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
    ("virtio-gpu", "virtio-gpu", gpu_probe::GPU_STACK_SIZE, &[]),
    (
        "compositor",
        "compositor",
        crate::comp_probe::COMP_STACK_SIZE,
        &[],
    ),
    ("posix-window", "posix-window-probe", POSIX_STACK_SIZE, &[]),
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

/// The lines with a CRC the screenshots are compared with, in order.
const SHOTS: [&str; 3] = [
    "posix-window: window crc ",
    "posix-window: partial crc ",
    "posix-window: merged crc ",
];

/// The lines of the probe, each a check that passed.
const LINES: [&str; 8] = [
    "posix-window: the screen is described, no window yet, and bad arguments leave nothing",
    "posix-window: a window of 200 by 100 with two zeroed buffers, a second open is EBUSY",
    "posix-window: post refuses a wrong buffer, window or rectangle, and a buffer that is out",
    "posix-window: the frame is shown and its bit frees the replaced buffer",
    "posix-window: five rectangles merge into their bounding box",
    "posix-window: the events are the focus events only and the ring is empty after",
    "posix-window: a forked child has no window, and a signal ends a wait with EINTR",
    "posix-window: close ends the window, and a new one opens",
];

const ENDED: &str = "init: posix-window ended: exit code 0, not restarted";

/// Follows the run: the three screenshots against the guest's CRC lines,
/// then the end of the probe.
fn drive(run: &mut Run, scratch: &Scratch) -> Result<(), String> {
    const WITHIN: Duration = Duration::from_secs(120);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    for prefix in SHOTS {
        let line = run.expect_line(prefix, |l| l.contains(prefix), WITHIN)?;
        gpu_probe::compare(&mut monitor, &scratch.picture(), &line, prefix)?;
    }
    run.expect_line(ENDED, |l| l == ENDED, WITHIN)?;
    Ok(())
}

/// Judges the lines of a run: no check failed, each line of the probe came
/// once, and the screen was the same after the first frame and after the
/// merged one.
fn verdict(lines: &[String]) -> Result<(), String> {
    if let Some(failed) = lines
        .iter()
        .find(|l| l.starts_with("posix-window: check failed"))
    {
        return Err(failed.clone());
    }
    for marker in LINES.iter().chain(&["posix-window: ok"]) {
        let found = lines.iter().filter(|l| l.as_str() == *marker).count();
        if found != 1 {
            return Err(format!("{found} lines {marker:?}, 1 expected"));
        }
    }
    let crc = |prefix: &str| -> Result<u32, String> {
        let line = lines
            .iter()
            .find(|l| l.starts_with(prefix))
            .ok_or_else(|| format!("no line {prefix:?}"))?;
        gpu_probe::crc_of(line, prefix)
    };
    if crc(SHOTS[0])? != crc(SHOTS[2])? {
        return Err("the merged post did not bring the first picture back".into());
    }
    if crc(SHOTS[0])? == crc(SHOTS[1])? {
        return Err("the screen did not change with the second buffer".into());
    }
    Ok(())
}

/// `cargo xtask posix-window` and its boot in `test`.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-posix-window.img", &PROGRAMS, BOOT_PROFILE)?;
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
    driven.map_err(|e| format!("posix-window on {}: {e}", machine.name))?;
    verdict(&outcome.lines).map_err(|e| format!("posix-window on {}: {e}", machine.name))?;
    println!(
        "posix-window on {}: a window of the C library with two buffers matched QEMU's screenshot for the first frame, a rectangle of the second buffer and the merge of five rectangles; the bits freed the buffers, the child had no window, a signal ended the wait, close and a new window: ok",
        machine.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(crcs: [&str; 3]) -> Vec<String> {
        let mut lines: Vec<String> = LINES.iter().map(|l| (*l).to_owned()).collect();
        for (prefix, crc) in SHOTS.iter().zip(crcs) {
            lines.push(format!("{prefix}{crc}"));
        }
        lines.push("posix-window: ok".to_owned());
        lines
    }

    #[test]
    fn a_run_whose_merge_restores_the_first_picture_passes() {
        assert_eq!(verdict(&run(["0a0b0c0d", "11223344", "0a0b0c0d"])), Ok(()));
    }

    #[test]
    fn the_verdict_names_what_is_wrong() {
        let err = verdict(&run(["0a0b0c0d", "11223344", "55555555"])).unwrap_err();
        assert!(err.contains("merged"), "{err}");
        let err = verdict(&run(["0a0b0c0d", "0a0b0c0d", "0a0b0c0d"])).unwrap_err();
        assert!(err.contains("did not change"), "{err}");
        let mut lines = run(["1", "2", "1"]);
        lines.remove(0);
        assert!(verdict(&lines).unwrap_err().contains("expected"));
        let mut lines = run(["1", "2", "1"]);
        lines.push("posix-window: check failed at line 9: x (errno 1)".to_owned());
        assert!(verdict(&lines).unwrap_err().contains("check failed"));
    }
}
