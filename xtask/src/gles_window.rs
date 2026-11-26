// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The cube in a window (apps/gles-cube, `--window`): a static C program on
//! relibc with the Mesa of tools/build-mesa.py, on QEMU's virtio-gpu-device
//! with the composition service. The program starts its own file once (a
//! program init starts cannot fork); the copy that draws opens a window with
//! three buffers (its side, 160 points, comes from the arguments of the
//! program's record in the table `table::gles::WINDOW_TABLE`, as does the
//! number of frames), checks the API of the platform of
//! EGL (a display not initialized, the format of the window against the
//! configuration, the handles 0 and 6, a second surface over one window, the
//! swap behaviour and interval, a swap with no current context, a swap in a
//! forked child, two threads with two contexts, a surface current in one
//! thread and moved to another, a thread asleep in `stafeto_window_wait` while
//! the main thread swaps), draws six frames of the cube
//! with softpipe, reads each back and swaps it into the window (the swap
//! interval alternates 1 and 0). At the third frame the window must hold the
//! rows of the frame read back, mirrored, and four swaps with damage over a
//! scissored clear leave the window equal to the frame; the end is
//! `eglTerminate` with the surface current. At the third frame and at the last it prints
//! the CRC-32 of the screen it should show and sleeps; while it sleeps, xtask
//! asks the monitor of QEMU for a `screendump` and takes the CRC-32 of the
//! colours (`posix-window`'s way): the two are equal, so the copy of the frame
//! into the buffer of the window, the post, the compositor's frame and the
//! driver's show agree. The two screenshots differ (the cube turned).

use std::time::Duration;

use crate::gles_pbuffer::{CUBE_STACK_SIZE, frame_line};
use crate::gpu_probe::{self, Scratch};
use crate::monitor::Monitor;
use crate::qemu::{self, Input, Run};
use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, PIPE_STACK_SIZE, RAMFS_STACK_SIZE, Variant, build,
    build_boot_image,
};

/// The probe's image: the services of the POSIX probes, the driver, the
/// compositor and the cube (started by init, which starts its own copy).
pub const PROGRAMS: [ImageProgram; 11] = [
    ("init", "init", INIT_STACK_SIZE, &["table-gles-window"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("virtio-gpu", "virtio-gpu", gpu_probe::GPU_STACK_SIZE, &[]),
    (
        "compositor",
        "compositor",
        crate::comp_probe::COMP_STACK_SIZE,
        &[],
    ),
    ("gles-cube", "gles-cube", CUBE_STACK_SIZE, &[]),
    ("loader", "loader", 0, &[]),
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

/// The frames the program draws, and the side of its window.
pub const FRAMES: usize = 6;
pub const SIZE: usize = 160;

/// The prefix of the program's lines, and of the lines with the CRC the
/// screenshots are compared with.
pub(crate) const PREFIX: &str = "gles-cube: ";
pub(crate) const SHOTS: [&str; 2] = ["gles-cube: window crc ", "gles-cube: last crc "];
const ENDED: &str = "init: gles-cube ended: exit code 0, not restarted";

/// The checks of the API, each a line the program prints once it passed
/// (`starts_with` and `ends_with` of the line after the prefix).
const API: [(&str, &str); 13] = [
    (
        "api a display not initialized",
        "answers EGL_NOT_INITIALIZED",
    ),
    (
        "api ",
        " configurations name the format of a window, the one chosen is XRGB8888",
    ),
    (
        "api a window of another format",
        "the handles 0 and 6 and a pixmap are refused",
    ),
    (
        "api the surface is 160 by 160",
        "a second one over the window is EGL_BAD_ALLOC",
    ),
    (
        "api swap behaviour preserved or destroyed",
        "swap interval 0, 1 and 2 (held to 1)",
    ),
    (
        "api a swap of a surface that is not current",
        "is EGL_BAD_SURFACE",
    ),
    ("api a swap in a forked child", "is EGL_BAD_SURFACE"),
    (
        "api a second thread made its own pbuffer",
        "and context and drew",
    ),
    (
        "api a surface current in one thread is EGL_BAD_ACCESS in another",
        "and moves between threads",
    ),
    (
        "api a thread asleep in stafeto_window_wait got the bits of the swaps",
        "the events bit stayed for it",
    ),
    (
        "api the window shows the rows of the frame read back from the bottom up",
        "the frame is no mirror of itself",
    ),
    (
        "api four swaps with damage over a cleared rectangle",
        "left the window equal to the frame",
    ),
    (
        "api eglTerminate with the surface current",
        "eglReleaseThread lets go",
    ),
];

/// A line that ends the probe in failure: a check of the program that failed,
/// a shader that did not compile, the drawing copy ending in another way, or
/// the program ending with a code other than 0.
pub(crate) fn failure(line: &str) -> Option<String> {
    let failed = line.starts_with("gles-cube: check failed")
        || line.starts_with("gles-cube: shader")
        || line.starts_with("gles-cube: the drawing copy")
        || (line.starts_with("init: gles-cube ended: ") && line != ENDED);
    failed.then(|| line.to_owned())
}

/// Follows the run: the two screenshots against the guest's CRC lines, then
/// the end of the program. The CRC-32 of each screenshot.
fn drive(run: &mut Run, scratch: &Scratch) -> Result<[u32; 2], String> {
    // softpipe draws a frame in seconds under TCG, and the compiler of GLSL
    // runs first.
    const WITHIN: Duration = Duration::from_secs(900);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    let mut shots = [0; 2];
    for (shot, prefix) in shots.iter_mut().zip(SHOTS) {
        // A check that failed or an end with another code ends the probe: no
        // CRC line will come, and the wait for it would run to the end of the
        // time.
        let line = run.expect_line(
            prefix,
            |l| l.contains(prefix) || failure(l).is_some(),
            WITHIN,
        )?;
        if let Some(failed) = failure(&line) {
            return Err(failed);
        }
        *shot = gpu_probe::compare_shot(&mut monitor, &scratch.picture(), &line, prefix)?;
    }
    let line = run.expect_line(ENDED, |l| l == ENDED || failure(l).is_some(), WITHIN)?;
    if let Some(failed) = failure(&line) {
        return Err(failed);
    }
    Ok(shots)
}

/// Judges the lines of a run and the CRC-32 of the two screenshots: no check
/// failed, the API lines came once each, the library is Mesa's softpipe, the
/// six frames came in order with different CRCs and sums above 0, each swap
/// took a time, and the two screenshots differ.
pub fn verdict(lines: &[String], shots: [u32; 2]) -> Result<(), String> {
    verdict_of(lines, shots, End::Exit)
}

/// How the program ends: with the code 0 after "ok" (init's line follows), or
/// holding the window for a scene's holder (`--hold`), the CRC of the screen it
/// holds being its last line.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum End {
    Exit,
    Held,
}

/// `verdict` for either end.
pub fn verdict_of(lines: &[String], shots: [u32; 2], end: End) -> Result<(), String> {
    if let Some(failed) = lines.iter().find_map(|l| failure(l)) {
        return Err(failed);
    }
    let seen: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.strip_prefix(PREFIX))
        .collect();
    for (start, end) in API {
        let found = seen
            .iter()
            .filter(|l| l.starts_with(start) && l.ends_with(end))
            .count();
        if found != 1 {
            return Err(format!(
                "{found} lines of the API check {start:?} ... {end:?}, 1 expected"
            ));
        }
    }
    let find = |prefix: &str| {
        seen.iter()
            .find_map(|l| l.strip_prefix(prefix))
            .ok_or_else(|| format!("the program printed no line {prefix:?}"))
    };
    if !find("EGL ")?.starts_with("1.5 ") {
        return Err(format!("EGL is {:?}, 1.5 expected", find("EGL ")?));
    }
    let renderer = find("GL_RENDERER ")?;
    if !renderer.contains("softpipe") {
        return Err(format!("the renderer is {renderer:?}, softpipe expected"));
    }
    let frames: Vec<(usize, u32, u64)> = seen.iter().filter_map(|l| frame_line(l)).collect();
    if frames.len() != FRAMES {
        return Err(format!(
            "the program printed {} frame lines, {FRAMES} expected",
            frames.len()
        ));
    }
    for (at, (number, _, sum)) in frames.iter().enumerate() {
        if *number != at {
            return Err(format!("frame line {at} is the one of frame {number}"));
        }
        if *sum == 0 {
            return Err(format!("frame {at} is all zeros"));
        }
    }
    let mut crcs: Vec<u32> = frames.iter().map(|f| f.1).collect();
    crcs.sort_unstable();
    crcs.dedup();
    if crcs.len() != FRAMES {
        return Err("two frames of the turning cube have the same CRC".to_owned());
    }
    // The same Mesa draws the same frames into a window and into a pbuffer.
    if let Some(expected) = crate::gles_pbuffer::EXPECTED_CRCS {
        for (at, (_, crc, _)) in frames.iter().enumerate() {
            if *crc != expected[at] {
                return Err(format!(
                    "frame {at} has the CRC {crc:08x}, {:08x} of the pbuffer probe expected",
                    expected[at]
                ));
            }
        }
    }
    for k in 0..FRAMES {
        let interval = if k % 2 == 1 { 0 } else { 1 };
        let prefix = format!("time swap {k} (interval {interval}) ");
        if !seen.iter().any(|l| l.starts_with(&prefix)) {
            return Err(format!("the program printed no line {prefix:?}"));
        }
    }
    if shots[0] == shots[1] {
        return Err("the screen did not change between the two screenshots".to_owned());
    }
    match end {
        End::Exit => {
            if seen.last() != Some(&"ok") {
                return Err(format!(
                    "the program ended with {:?}, \"ok\" expected",
                    seen.last()
                ));
            }
            if !lines.iter().any(|l| l == ENDED) {
                return Err(format!("init never printed {ENDED:?}"));
            }
        }
        End::Held => {
            let held = seen.iter().filter(|l| l.starts_with("held crc ")).count();
            if held != 1 || !seen.last().is_some_and(|l| l.starts_with("held crc ")) {
                return Err(format!(
                    "the program held {held} times and its last line is {:?}, one \"held crc\" line as the last expected",
                    seen.last()
                ));
            }
        }
    }
    Ok(())
}

/// `cargo xtask gles-window`.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    crate::mesa()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-gles-window.img", &PROGRAMS, BOOT_PROFILE)?;
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
    let shots = driven.map_err(|e| format!("gles-window on {}: {e}", machine.name))?;
    verdict(&outcome.lines, shots).map_err(|e| format!("gles-window on {}: {e}", machine.name))?;
    println!(
        "gles-window on {}: the cube of Mesa's softpipe in a window of {SIZE} by {SIZE} points matched QEMU's screenshot at two frames; the platform of EGL refused what it must and a forked child could not swap: ok",
        machine.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> Vec<String> {
        let mut lines = vec![
            "gles-cube: EGL 1.5 Mesa Project".to_owned(),
            "gles-cube: GL_RENDERER softpipe (LLVM none)".to_owned(),
            "gles-cube: api a display not initialized answers EGL_NOT_INITIALIZED".to_owned(),
            "gles-cube: api 12 configurations name the format of a window, the one chosen is XRGB8888"
                .to_owned(),
            "gles-cube: api a window of another format, the handles 0 and 6 and a pixmap are refused"
                .to_owned(),
            "gles-cube: api the surface is 160 by 160, a second one over the window is EGL_BAD_ALLOC"
                .to_owned(),
            "gles-cube: api swap behaviour preserved or destroyed, swap interval 0, 1 and 2 (held to 1)"
                .to_owned(),
            "gles-cube: api a swap of a surface that is not current is EGL_BAD_SURFACE".to_owned(),
            "gles-cube: api a swap in a forked child is EGL_BAD_SURFACE".to_owned(),
            "gles-cube: api a second thread made its own pbuffer and context and drew".to_owned(),
            "gles-cube: api a surface current in one thread is EGL_BAD_ACCESS in another and moves between threads"
                .to_owned(),
            "gles-cube: api a thread asleep in stafeto_window_wait got the bits of the swaps and the events bit stayed for it"
                .to_owned(),
            "gles-cube: api the window shows the rows of the frame read back from the bottom up, and the frame is no mirror of itself"
                .to_owned(),
            "gles-cube: api four swaps with damage over a cleared rectangle left the window equal to the frame"
                .to_owned(),
            "gles-cube: api eglTerminate with the surface current, a swap after it is EGL_NOT_INITIALIZED and eglReleaseThread lets go"
                .to_owned(),
        ];
        for k in 0..FRAMES {
            lines.push(format!(
                "gles-cube: frame {k} crc {:08x} sum {}",
                crate::gles_pbuffer::EXPECTED_CRCS
                    .map_or(0x1000_0000 + k as u32 * 0x1111, |c| c[k]),
                900_000 + k
            ));
            lines.push(format!(
                "gles-cube: time swap {k} (interval {}) 7 ms",
                if k % 2 == 1 { 0 } else { 1 }
            ));
        }
        lines.insert(3, "unrelated line of the console".to_owned());
        lines.push("gles-cube: ok".to_owned());
        lines.push(ENDED.to_owned());
        lines
    }

    #[test]
    fn the_expected_run_passes() {
        assert_eq!(verdict(&run(), [1, 2]), Ok(()));
    }

    #[test]
    fn a_failed_check_or_an_end_with_another_code_is_a_failure() {
        assert!(failure("gles-cube: check failed at line 9: x (egl 0x3000 gl 0x0)").is_some());
        assert!(failure("gles-cube: shader did not compile: x").is_some());
        assert!(failure("gles-cube: the drawing copy ended with status 0x100").is_some());
        assert!(failure("init: gles-cube ended: exit code 1, not restarted").is_some());
        assert!(failure(ENDED).is_none());
        assert!(failure("gles-cube: window crc 79c130d2").is_none());
        let mut lines = run();
        lines.insert(
            5,
            "gles-cube: check failed at line 9: x (egl 0x3000 gl 0x0)".to_owned(),
        );
        assert!(
            verdict(&lines, [1, 2])
                .unwrap_err()
                .contains("check failed")
        );
    }

    #[test]
    fn a_missing_or_doubled_api_line_is_refused() {
        let mut lines = run();
        let at = lines
            .iter()
            .position(|l| l.contains("forked child"))
            .unwrap();
        lines.remove(at);
        assert!(
            verdict(&lines, [1, 2])
                .unwrap_err()
                .contains("forked child")
        );
        let mut lines = run();
        let at = lines
            .iter()
            .position(|l| l.contains("second thread"))
            .unwrap();
        let again = lines[at].clone();
        lines.insert(at, again);
        assert!(
            verdict(&lines, [1, 2])
                .unwrap_err()
                .contains("second thread")
        );
    }

    #[test]
    fn frames_out_of_order_or_alike_or_empty_or_missing_are_refused() {
        let mut lines = run();
        let first = lines.iter().position(|l| l.contains("frame 2 ")).unwrap();
        lines.swap(first, first + 2);
        assert!(verdict(&lines, [1, 2]).unwrap_err().contains("frame line"));
        let mut lines = run();
        let at = lines.iter().position(|l| l.contains("frame 4 ")).unwrap();
        let again = lines
            .iter()
            .find(|l| l.contains("frame 3 "))
            .unwrap()
            .clone();
        lines[at] = again.replace("frame 3 ", "frame 4 ");
        assert!(verdict(&lines, [1, 2]).is_err());
        let mut lines = run();
        let at = lines.iter().position(|l| l.contains("frame 1 ")).unwrap();
        lines[at] = "gles-cube: frame 1 crc 10001111 sum 0".to_owned();
        assert!(verdict(&lines, [1, 2]).unwrap_err().contains("all zeros"));
        let mut lines = run();
        let at = lines.iter().position(|l| l.contains("frame 5 ")).unwrap();
        lines.remove(at);
        assert!(verdict(&lines, [1, 2]).unwrap_err().contains("frame lines"));
    }

    #[test]
    fn a_swap_with_no_time_line_is_refused() {
        let mut lines = run();
        let at = lines
            .iter()
            .position(|l| l.contains("time swap 3 (interval 0)"))
            .unwrap();
        lines.remove(at);
        assert!(verdict(&lines, [1, 2]).unwrap_err().contains("time swap 3"));
    }

    #[test]
    fn a_frame_that_differs_from_the_pbuffer_probes_is_refused() {
        let mut lines = run();
        let at = lines.iter().position(|l| l.contains("frame 2 ")).unwrap();
        lines[at] = "gles-cube: frame 2 crc 00000001 sum 900002".to_owned();
        if crate::gles_pbuffer::EXPECTED_CRCS.is_some() {
            assert!(
                verdict(&lines, [1, 2])
                    .unwrap_err()
                    .contains("pbuffer probe")
            );
        }
    }

    /// A cube that holds its window ends with the line of its held CRC and no "ok".
    #[test]
    fn a_held_window_ends_with_its_held_crc() {
        let mut lines = run();
        lines.retain(|l| l != "gles-cube: ok" && l != ENDED);
        assert!(verdict_of(&lines, [1, 2], End::Held).is_err());
        lines.push("gles-cube: held crc 99e46166".to_owned());
        assert_eq!(verdict_of(&lines, [1, 2], End::Held), Ok(()));
        // Twice, or followed by another line of the cube, is refused.
        let mut twice = lines.clone();
        twice.push("gles-cube: held crc 99e46166".to_owned());
        assert!(verdict_of(&twice, [1, 2], End::Held).is_err());
        lines.push("gles-cube: ok".to_owned());
        assert!(verdict_of(&lines, [1, 2], End::Held).is_err());
    }

    #[test]
    fn two_equal_screenshots_are_refused() {
        assert!(
            verdict(&run(), [7, 7])
                .unwrap_err()
                .contains("did not change")
        );
    }

    #[test]
    fn a_run_without_the_last_line_or_the_end_of_init_is_refused() {
        let mut lines = run();
        lines.pop();
        assert!(verdict(&lines, [1, 2]).unwrap_err().contains("init never"));
        let mut lines = run();
        let at = lines.iter().position(|l| l == "gles-cube: ok").unwrap();
        lines.remove(at);
        assert!(verdict(&lines, [1, 2]).unwrap_err().contains("ok"));
    }

    #[test]
    fn the_library_is_mesa_softpipe() {
        let mut lines = run();
        let at = lines
            .iter()
            .position(|l| l.contains("GL_RENDERER"))
            .unwrap();
        lines[at] = "gles-cube: GL_RENDERER llvmpipe".to_owned();
        assert!(verdict(&lines, [1, 2]).unwrap_err().contains("softpipe"));
    }

    /// The program asks for the stack it needs in its own file (a copy a spawn
    /// starts gets 64 KiB otherwise, and the compiler of GLSL recurses deeper):
    /// `PT_GNU_STACK` of the built `gles-cube` is the size the image gives the
    /// program that init starts. Skipped when the program is not built.
    #[test]
    fn the_file_of_the_cube_asks_for_the_stack_of_the_image() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let Ok(elf) = std::fs::read(root.join("target/aarch64-unknown-none/release/gles-cube"))
        else {
            eprintln!("gles-cube is not built: the stack of its file is not read");
            return;
        };
        let u16_at = |at: usize| u16::from_le_bytes(elf[at..at + 2].try_into().unwrap()) as usize;
        let u32_at = |at: usize| u32::from_le_bytes(elf[at..at + 4].try_into().unwrap());
        let u64_at = |at: usize| u64::from_le_bytes(elf[at..at + 8].try_into().unwrap()) as usize;
        let (offset, size, count) = (u64_at(0x20), u16_at(0x36), u16_at(0x38));
        let stack = (0..count)
            .map(|k| offset + k * size)
            .find(|&at| u32_at(at) == 0x6474_e551)
            .map(|at| u64_at(at + 0x28))
            .expect("the file has a PT_GNU_STACK");
        assert!(stack >= 1024 * 1024, "{stack}");
        assert_eq!(stack, crate::gles_pbuffer::CUBE_STACK_SIZE as usize);
    }
}
