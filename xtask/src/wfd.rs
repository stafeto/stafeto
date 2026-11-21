// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the display library of OpenWF Display (apps/wfd-demo, the C
//! functions of `<WF/wfd.h>` in a static program) on QEMU's virtio-gpu-device
//! with no composition service: the services of the POSIX probes, the display
//! driver and the demo, which starts its own file once. The copy that can
//! fork takes the screen through `wfdCreateDevice`, checks the calls the
//! specification gives errors for, binds the compositing target and the pool
//! buffer to the primary pipeline in turn (100 frames, each drawn in the one
//! the screen does not show), waits for the bind event of each, prints the
//! CRC-32 of the frame it drew, and moves a cursor picture 100 times on the
//! cursor pipeline.
//!
//! While the demo pauses after a line, xtask asks the monitor of QEMU for a
//! `screendump` and takes the CRC-32 of the colours. Three numbers are equal
//! for every frame: the guest's, QEMU's screenshot and the host's own
//! (`pattern_crc`, the demo's pattern computed here), so a frame the guest
//! draws wrong, binds wrong or the driver shows wrong fails the probe. The
//! trace of the device (QEMU's `virtio_gpu_cmd_set_scanout` and
//! `virtio_gpu_update_cursor`) shows the scanout moving between resources 1
//! and 2 in turn and the cursor updated from resource 3 and moved through its
//! places, never with resource 0 (QEMU takes the resource of a cursor command
//! as the pointer's on flag). The picture of the cursor is in no screenshot,
//! so the trace is what shows it.
//!
//! A second run under -icount (QEMU's own emulation) measures the steps of the
//! driver: the demo leaves out its pauses, and every step stays under 0.9 of
//! term B.

use std::time::Duration;

use crate::gpu_probe::{self, GPU_STACK_SIZE, Scratch};
use crate::monitor::{self, Monitor};
use crate::qemu::{self, GpuTrace, Input, Run};
use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, POSIX_STACK_SIZE, Variant, build,
    build_boot_image, run_until,
};

/// The probe's image: the services of the POSIX probes, the display driver
/// and the demo. No composition service: the process's `Display` session
/// leads to the driver.
pub const PROGRAMS: [ImageProgram; 10] = [
    ("init", "init", INIT_STACK_SIZE, &["table-wfd"]),
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
    ("virtio-gpu", "virtio-gpu", GPU_STACK_SIZE, &[]),
    ("wfd-demo", "wfd-demo", POSIX_STACK_SIZE, &[]),
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

/// The image of the run under -icount: the driver counts its steps and the
/// demo does not pause for the monitor.
pub const STEPS_PROGRAMS: [ImageProgram; 10] = [
    ("init", "init", INIT_STACK_SIZE, &["table-wfd-steps"]),
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
    ("virtio-gpu", "virtio-gpu", GPU_STACK_SIZE, &["steps"]),
    ("wfd-demo", "wfd-demo", POSIX_STACK_SIZE, &[]),
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

const WIDTH: usize = 640;
const HEIGHT: usize = 400;
const FRAMES: usize = 100;
const MOVES: usize = 100;

/// The place the cursor's picture is first bound at.
const FIRST_PLACE: (u32, u32) = (10, 10);

/// The pattern of frame `k` as the demo draws it (`pattern` of wfd-demo.c):
/// a gradient that moves with `k` and a white bar of `6 * (k + 1)` points.
fn pattern(k: usize, x: usize, y: usize) -> [u8; 3] {
    if (8..24).contains(&y) && x < (k + 1) * 6 {
        return [0xFF; 3];
    }
    [
        (x * 255 / (WIDTH - 1) + 3 * k) as u8,
        (y * 255 / (HEIGHT - 1) + 5 * k) as u8,
        ((x ^ y) + k) as u8,
    ]
}

/// The CRC-32 of the red, green and blue bytes of frame `k`, row after row.
pub fn pattern_crc(k: usize) -> u32 {
    let mut bytes = Vec::with_capacity(WIDTH * HEIGHT * 3);
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            bytes.extend(pattern(k, x, y));
        }
    }
    monitor::crc32(&bytes)
}

/// The place of the cursor for move `j` (`place` of wfd-demo.c).
pub fn place(j: usize) -> (u32, u32) {
    (20 + (j as u32 * 5) % 560, 20 + (j as u32 * 3) % 310)
}

const FRAME: &str = "wfd-demo: frame ";
const ENDED: &str = concat!("init: wfd-demo ended: exit code 0,", " not restarted");
const ENDS: &str = "init: wfd-demo ended: ";

/// The lines of the demo, each a check that passed.
const LINES: [&str; 11] = [
    "wfd-demo: no device while the screen of the first revision is open, and its buffer is untouched",
    "wfd-demo: exec gave the screen back to the driver, a new device is made",
    "wfd-demo: the device is made once, described, and its calls are checked",
    "wfd-demo: the port has one mode of 640 by 400 at 60 hertz and its power is on",
    "wfd-demo: the pipelines are the primary one and the cursor, with their layers and limits",
    "wfd-demo: the streams of the driver are described and the sources made of them",
    "wfd-demo: a forked child has no device",
    "wfd-demo: the cursor picture is bound and its event completes",
    "wfd-demo: 100 frames, each completed its bind event with the source before it",
    "wfd-demo: the cursor moved 100 times",
    "wfd-demo: the device is destroyed and its handles are gone",
];

/// The lines that end the run in failure: a check that failed, and the
/// demo's process ending with a code other than 0.
fn failure(line: &str) -> Option<String> {
    let failed =
        line.starts_with("wfd-demo: check failed") || (line.starts_with(ENDS) && line != ENDED);
    failed.then(|| line.to_owned())
}

/// The CRC in a frame's line, the frame's number being `k`: eight hex digits
/// after the exact words.
fn frame_crc(line: &str, k: usize) -> Result<u32, String> {
    let prefix = format!("{FRAME}{k} crc ");
    let digits = line
        .strip_prefix(&prefix)
        .filter(|d| d.len() == 8)
        .ok_or_else(|| format!("{line:?} is not the line of frame {k}"))?;
    u32::from_str_radix(digits, 16).map_err(|e| format!("the CRC in {line:?}: {e}"))
}

/// What the three sources say about a frame.
#[derive(Debug, PartialEq, Eq)]
pub struct Shot {
    pub guest: u32,
    pub screen: u32,
    pub host: u32,
}

/// Follows the run: the screenshot after each frame's line against the
/// guest's CRC and the host's own, then the end of the demo.
fn drive(run: &mut Run, scratch: &Scratch) -> Result<Vec<Shot>, String> {
    const WITHIN: Duration = Duration::from_secs(180);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    let mut shots = Vec::with_capacity(FRAMES);
    for k in 0..FRAMES {
        let prefix = format!("{FRAME}{k} crc ");
        let line = run.expect_line(
            &prefix,
            |l| l.starts_with(&prefix) || failure(l).is_some(),
            WITHIN,
        )?;
        if let Some(failed) = failure(&line) {
            return Err(failed);
        }
        let guest = frame_crc(&line, k)?;
        let picture = monitor.screendump(&scratch.picture())?;
        if (picture.width, picture.height) != (WIDTH, HEIGHT) {
            return Err(format!(
                "the screenshot is {}x{}, 640x400 expected",
                picture.width, picture.height
            ));
        }
        shots.push(Shot {
            guest,
            screen: picture.crc32(),
            host: pattern_crc(k),
        });
    }
    let line = run.expect_line(ENDED, |l| l == ENDED || failure(l).is_some(), WITHIN)?;
    if let Some(failed) = failure(&line) {
        return Err(failed);
    }
    Ok(shots)
}

/// Judges the lines of a run and the frames: no check failed, each line of
/// the demo came once, and for every frame the guest's CRC, QEMU's
/// screenshot's and the host's are the same, and no two frames are.
fn verdict(lines: &[String], shots: &[Shot]) -> Result<(), String> {
    if let Some(failed) = lines
        .iter()
        .find(|l| l.starts_with("wfd-demo: check failed"))
    {
        return Err(failed.clone());
    }
    for marker in LINES.iter().chain(&["wfd-demo: ok"]) {
        let found = lines.iter().filter(|l| l.as_str() == *marker).count();
        if found != 1 {
            return Err(format!("{found} lines {marker:?}, 1 expected"));
        }
    }
    if shots.len() != FRAMES {
        return Err(format!("{} frames, {FRAMES} expected", shots.len()));
    }
    for (k, s) in shots.iter().enumerate() {
        if s.guest != s.host {
            return Err(format!(
                "frame {k}: the guest drew {:08x}, the host's pattern is {:08x}",
                s.guest, s.host
            ));
        }
        if s.screen != s.guest {
            return Err(format!(
                "frame {k}: QEMU's screenshot is {:08x}, the guest drew {:08x}",
                s.screen, s.guest
            ));
        }
    }
    let mut seen = std::collections::HashSet::new();
    if let Some(k) = shots.iter().position(|s| !seen.insert(s.guest)) {
        return Err(format!("frame {k} is a picture an earlier frame had"));
    }
    Ok(())
}

/// The device's trace against what the demo did: the scanout went to the pool
/// (resource 2) and the target (resource 1) in turn for the 100 frames, and
/// the cursor got an update from resource 3 at its first place and then moves,
/// every command with resource 3 (a command with resource 0 would hide the
/// cursor), through the places of the demo in order and ending at the last.
/// A move that the device had not yet returned the one before may be left
/// out (the driver merges them), so the places are a subsequence.
pub fn trace_verdict(events: &[GpuTrace]) -> Result<(), String> {
    use GpuTrace::{Cursor, Scanout};
    let mut scanouts: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            Scanout {
                id: 0,
                res,
                w: 640,
                h: 400,
                x: 0,
                y: 0,
            } => Some(*res),
            _ => None,
        })
        .collect();
    scanouts.dedup();
    let mut wanted = vec![1];
    for _ in 0..FRAMES / 2 {
        wanted.extend([2, 1]);
    }
    if !scanouts.windows(wanted.len()).any(|w| w == wanted) {
        return Err(format!(
            "the trace of SET_SCANOUT shows resources {scanouts:?}, 1 and then 2, 1 fifty times in turn expected"
        ));
    }
    let mut cursor: Vec<(bool, u32, u32, u32)> = events
        .iter()
        .filter_map(|e| match e {
            Cursor { update, x, y, res } => Some((*update, *x, *y, *res)),
            _ => None,
        })
        .collect();
    // The driver hides the cursor when the screen goes back (the demo's
    // destroy): commands with resource 0 at the end are that.
    while cursor.last().is_some_and(|(.., res)| *res == 0) {
        cursor.pop();
    }
    let named = format!(
        "the trace of the cursor is {:?}, an update from resource 3 at {FIRST_PLACE:?}, then moves with resource 3 through the places of the demo ending at {:?} expected",
        &cursor[..cursor.len().min(6)],
        place(MOVES - 1)
    );
    if cursor.iter().any(|(.., res)| *res != 3) {
        return Err(named);
    }
    let Some(first) = cursor.first() else {
        return Err(named);
    };
    if *first != (true, FIRST_PLACE.0, FIRST_PLACE.1, 3) {
        return Err(named);
    }
    let places: Vec<(u32, u32)> = (0..MOVES).map(place).collect();
    let mut from = 0;
    for (i, (update, x, y, _)) in cursor.iter().enumerate().skip(1) {
        if *update {
            return Err(format!("{named}; event {i} is another update"));
        }
        match places[from..].iter().position(|p| *p == (*x, *y)) {
            Some(at) => from += at + 1,
            None => {
                return Err(format!(
                    "{named}; event {i} of {} is at {:?}, no place of the demo after place {from}",
                    cursor.len(),
                    (*x, *y)
                ));
            }
        }
    }
    if from != places.len() {
        return Err(format!(
            "{named}; the last move is place {from} of {} ({} events)",
            places.len(),
            cursor.len()
        ));
    }
    Ok(())
}

/// `cargo xtask wfd-probe` and its boot in `test`.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-wfd.img", &PROGRAMS, BOOT_PROFILE)?;
    let scratch = Scratch::new()?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    cmd.arg(format!(
        "unix:{},server=on,wait=off",
        scratch.socket().display()
    ));
    cmd.args(qemu::GPU);
    cmd.args(qemu::gpu_trace(&scratch.trace()));
    let mut run = Run::start(cmd, Input::Null)?;
    let driven = drive(&mut run, &scratch);
    let outcome = run.stop();
    let who = |e: String| format!("wfd-probe on {}: {e}", machine.name);
    let shots = driven.map_err(who)?;
    verdict(&outcome.lines, &shots).map_err(who)?;
    let text = std::fs::read_to_string(scratch.trace())
        .map_err(|e| who(format!("the trace file: {e}")))?;
    let events = qemu::parse_gpu_trace(&text).map_err(who)?;
    trace_verdict(&events).map_err(who)?;
    println!(
        "wfd-probe on {}: 100 frames of OpenWF Display bound to the primary pipeline in turn matched, each, the guest's CRC, the host's own and QEMU's screenshot (first {:08x}, last {:08x}); the scanout went between resources 1 and 2, the cursor was updated from resource 3 and moved through 100 places; the calls, the errors, the events, the fork and the destroy: ok",
        machine.name,
        shots[0].guest,
        shots[FRAMES - 1].guest
    );
    if !machine.is_hvf() {
        steps(machine)?;
    }
    Ok(())
}

/// The driver's tag of the lines of steps and the kinds the run must have: OPEN,
/// CLOSE, SUBSCRIBE, CLONE, PIPELINES, SOURCE, LAYERS, and the interrupt.
const KINDS: [(usize, &str); 8] = [
    (1, "Open"),
    (3, "Close"),
    (5, "Subscribe"),
    (8, "Clone"),
    (9, "Pipelines"),
    (10, "Source"),
    (11, "Layers"),
    (65, "the interrupt and a portion of clearing"),
];

/// The steps of the driver (the lines of `loop_steps`): every kind came, every
/// row stays under 0.9 of term B, and the rows of the interrupt and of the
/// portions under PORTION_MAX.
pub fn steps_verdict(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = crate::longest_steps(lines, gpu_probe::GPU_TAG);
    crate::step_line::within_b(lines, gpu_probe::GPU_TAG, crate::step_line::Kinds::All)?;
    for (kind, name) in KINDS {
        if !rows.iter().any(|(k, ..)| *k == kind) {
            return Err(format!("the display service: no step {name}: {rows:?}"));
        }
    }
    if let Some(row) = rows.iter().find(|r| r.1 > gpu_probe::STEP_MAX) {
        return Err(format!(
            "the display service: a step past 0.9 of term B ({}): {row:?}",
            gpu_probe::STEP_MAX
        ));
    }
    if let Some(row) = rows.iter().find(|r| r.0 == 65 && r.1 > crate::PORTION_MAX) {
        return Err(format!(
            "the display service: a portion or an interrupt past {}: {row:?}",
            crate::PORTION_MAX
        ));
    }
    Ok(rows)
}

/// The run under -icount: the demo does not pause for the monitor, and the
/// driver's steps are read from its lines.
fn steps(machine: &qemu::Machine) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-wfd-steps.img", &STEPS_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::GPU);
    cmd.args(qemu::ICOUNT);
    let output = run_until(cmd, crate::BOOT_TIMEOUT * 6, Some(ENDS), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED)?;
    if let Some(failed) = output
        .lines
        .iter()
        .find(|l| l.starts_with("wfd-demo: check failed"))
    {
        return Err(format!("wfd-probe under -icount: {failed}"));
    }
    qemu::expect_marker(&output, "wfd-demo: ok")?;
    let rows = steps_verdict(&output.lines)?;
    crate::check_waits(&output.lines, &[gpu_probe::GPU_TAG], "wfd-probe")?;
    let text: Vec<_> = rows
        .iter()
        .map(|(kind, ticks, _)| format!("kind {kind} {ticks}"))
        .collect();
    println!(
        "wfd-probe on {}: the longest steps of the display driver under -icount, ticks (0.9 of term B {}, portions {}): {}",
        machine.name,
        gpu_probe::STEP_MAX,
        crate::PORTION_MAX,
        text.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use GpuTrace::{Cursor, Scanout};

    fn good_lines() -> Vec<String> {
        let mut lines: Vec<String> = LINES.iter().map(|l| (*l).to_owned()).collect();
        lines.push("wfd-demo: ok".to_owned());
        lines
    }

    fn good_shots() -> Vec<Shot> {
        (0..FRAMES)
            .map(|k| {
                let c = pattern_crc(k);
                Shot {
                    guest: c,
                    screen: c,
                    host: c,
                }
            })
            .collect()
    }

    fn scanout(res: u32) -> GpuTrace {
        Scanout {
            id: 0,
            res,
            w: 640,
            h: 400,
            x: 0,
            y: 0,
        }
    }

    fn good_trace() -> Vec<GpuTrace> {
        let mut events = vec![scanout(1)];
        for _ in 0..FRAMES / 2 {
            events.extend([scanout(2), scanout(1)]);
        }
        events.insert(
            3,
            Cursor {
                update: true,
                x: 10,
                y: 10,
                res: 3,
            },
        );
        for j in 0..MOVES {
            let (x, y) = place(j);
            events.push(Cursor {
                update: false,
                x,
                y,
                res: 3,
            });
        }
        events
    }

    #[test]
    fn the_host_pattern_has_the_demos_numbers() {
        // The first points of frame 0 and of frame 7, by hand from
        // wfd-demo.c's pattern.
        assert_eq!(pattern(0, 0, 0), [0, 0, 0]);
        assert_eq!(pattern(0, 639, 399), [255, 255, ((639 ^ 399) & 0xFF) as u8]);
        assert_eq!(pattern(7, 0, 0), [21, 35, 7]);
        // The bar: 6 points for each frame, between rows 8 and 23.
        assert_eq!(pattern(0, 5, 8), [0xFF; 3]);
        assert_ne!(pattern(0, 6, 8), [0xFF; 3]);
        assert_eq!(pattern(99, 599, 23), [0xFF; 3]);
        assert_ne!(pattern(99, 599, 24), [0xFF; 3]);
        // No two frames are alike.
        let crcs: std::collections::HashSet<u32> = (0..FRAMES).map(pattern_crc).collect();
        assert_eq!(crcs.len(), FRAMES);
    }

    #[test]
    fn the_places_of_the_cursor_are_all_different_and_on_the_screen() {
        let places: std::collections::HashSet<(u32, u32)> = (0..MOVES).map(place).collect();
        assert_eq!(places.len(), MOVES);
        assert!(places.iter().all(|(x, y)| *x + 64 <= 640 && *y + 64 <= 400));
        assert_eq!(place(0), (20, 20));
    }

    #[test]
    fn a_run_whose_frames_agree_passes() {
        assert_eq!(verdict(&good_lines(), &good_shots()), Ok(()));
    }

    #[test]
    fn a_doubled_frame_line_with_another_crc_fails_the_parse() {
        // The demo's line of frame k with another number in it is not the
        // line the host waits for.
        let line = "wfd-demo: frame 3 crc 0badf00d";
        assert_eq!(frame_crc(line, 3), Ok(0x0bad_f00d));
        assert!(frame_crc(line, 4).is_err());
        assert!(frame_crc("wfd-demo: frame 3 crc 0bad", 3).is_err());
    }

    #[test]
    fn a_frame_that_differs_from_the_host_or_the_screen_is_named() {
        let mut shots = good_shots();
        shots[41].screen ^= 1;
        let err = verdict(&good_lines(), &shots).unwrap_err();
        assert!(
            err.contains("frame 41") && err.contains("screenshot"),
            "{err}"
        );
        let mut shots = good_shots();
        shots[7].guest ^= 1;
        shots[7].screen = shots[7].guest;
        let err = verdict(&good_lines(), &shots).unwrap_err();
        assert!(err.contains("frame 7") && err.contains("host"), "{err}");
        let mut shots = good_shots();
        shots.pop();
        assert!(
            verdict(&good_lines(), &shots)
                .unwrap_err()
                .contains("99 frames")
        );
    }

    #[test]
    fn a_missing_or_a_failed_line_is_named() {
        let mut lines = good_lines();
        lines.remove(2);
        assert!(
            verdict(&lines, &good_shots())
                .unwrap_err()
                .contains("expected")
        );
        let mut lines = good_lines();
        lines.push("wfd-demo: check failed at line 9: x (errno 1, error 0)".to_owned());
        assert!(
            verdict(&lines, &good_shots())
                .unwrap_err()
                .contains("check failed")
        );
    }

    #[test]
    fn a_failed_check_or_an_end_with_another_code_stops_the_wait() {
        assert!(failure("wfd-demo: check failed at line 355: x (errno 4, error 0)").is_some());
        assert!(
            failure(concat!(
                "init: wfd-demo ended: exit code 20,",
                " not restarted"
            ))
            .is_some()
        );
        assert!(failure(ENDED).is_none());
        assert!(failure("wfd-demo: frame 3 crc 79c130d2").is_none());
    }

    #[test]
    fn a_trace_of_alternating_scanouts_and_a_cursor_that_moves_passes() {
        assert_eq!(trace_verdict(&good_trace()), Ok(()));
    }

    #[test]
    fn merged_moves_still_pass_and_a_lost_last_place_does_not() {
        let mut events = good_trace();
        // Drop a few moves in the middle, as the driver's merging does.
        let at = events.len() - 50;
        events.drain(at..at + 3);
        assert_eq!(trace_verdict(&events), Ok(()));
        let mut events = good_trace();
        events.pop();
        assert!(trace_verdict(&events).is_err());
    }

    #[test]
    fn the_hide_when_the_screen_goes_back_is_no_failure() {
        let mut events = good_trace();
        events.push(Cursor {
            update: true,
            x: 0,
            y: 0,
            res: 0,
        });
        assert_eq!(trace_verdict(&events), Ok(()));
    }

    #[test]
    fn a_cursor_command_with_resource_0_fails() {
        let mut events = good_trace();
        let at = events.len() - 5;
        events[at] = Cursor {
            update: false,
            x: place(MOVES - 5).0,
            y: place(MOVES - 5).1,
            res: 0,
        };
        let err = trace_verdict(&events).unwrap_err();
        assert!(err.contains("resource 3"), "{err}");
    }

    #[test]
    fn moves_out_of_order_or_before_the_update_fail() {
        let mut events = good_trace();
        let n = events.len();
        events.swap(n - 1, n - 2);
        assert!(trace_verdict(&events).is_err());
        let mut events = good_trace();
        let first = events.remove(3);
        events.push(first);
        assert!(trace_verdict(&events).is_err());
    }

    #[test]
    fn scanouts_that_do_not_alternate_fail() {
        let mut events = good_trace();
        let at = events
            .iter()
            .position(|e| matches!(e, Scanout { res: 2, .. }))
            .unwrap();
        events[at] = scanout(1);
        assert!(trace_verdict(&events).unwrap_err().contains("SET_SCANOUT"));
    }
}
