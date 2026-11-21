// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the scene library of OpenWF Composition (apps/wfc-demo, the C
//! functions of `<WF/wfc.h>` in a static program) on QEMU's virtio-gpu-device
//! with the composition service: the services of the POSIX probes, the display
//! driver, the compositor and the demo, the holder of the scene. The demo starts
//! two producers (tests/wfc-producer: a window of 100 by 200 points and one of
//! 160 by 100, each a fixed pattern), draws a mask of A8 of its own, finds the
//! windows by `wfcNextStreamSTAFETO`, and shows two scenes of three elements,
//! A and B (a stretch, turns, a flip, the three filters, a global alpha and a
//! mask).
//!
//! The expected frames are the host's (`tools/wfc-ref`): the scenes built
//! through the crate `wfc` with the demo's calls and drawn point by point from
//! `proto_comp::meaning`. In the first part the demo commits A and B in turn 100
//! times, each composed on request (`wfcCompose` with wait), and prints the
//! number and the scene of each commit; while it pauses after a line, xtask asks
//! the monitor of QEMU for a `screendump` and takes the CRC-32 of the colours,
//! which must be the host's for that scene. A frame with elements of both scenes
//! is a third CRC and fails the probe. In the second part the context is active
//! and the demo changes the scene 100 times without waiting; xtask takes
//! screenshots one after another meanwhile, and each is the CRC of A or of B.
//!
//! A second run under -icount (QEMU's own emulation) measures the steps of the
//! compositor and the driver: the demo leaves out its pauses, and every step
//! stays under 0.9 of term B, the bands and the portions under PORTION_MAX.

use std::time::Duration;

use crate::gpu_probe::{self, Scratch};
use crate::monitor::Monitor;
use crate::qemu::{self, Input, Run};
use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, POSIX_STACK_SIZE, Variant, build,
    build_boot_image, longest_steps, run_until,
};

/// The probe's image: the services of the POSIX probes, the driver, the
/// compositor, the demo (started by init) and the producer (a file the demo
/// spawns).
pub const PROGRAMS: [ImageProgram; 12] = [
    ("init", "init", INIT_STACK_SIZE, &["table-wfc"]),
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
    ("wfc-demo", "wfc-demo", POSIX_STACK_SIZE, &[]),
    ("wfc-producer", "wfc-producer", 0, &[]),
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

/// The image of the run under -icount: the driver and the compositor count their
/// steps, and the demo does not pause for the monitor.
pub const STEPS_PROGRAMS: [ImageProgram; 12] = [
    ("init", "init", INIT_STACK_SIZE, &["table-wfc-steps"]),
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
        "virtio-gpu",
        "virtio-gpu",
        gpu_probe::GPU_STACK_SIZE,
        &["steps"],
    ),
    (
        "compositor",
        "compositor",
        crate::comp_probe::COMP_STACK_SIZE,
        &["steps"],
    ),
    ("wfc-demo", "wfc-demo", POSIX_STACK_SIZE, &[]),
    ("wfc-producer", "wfc-producer", 0, &[]),
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
const COMMITS: usize = 100;
const COMMIT: &str = "wfc-demo: commit ";
const AUTO_BEGIN: &str = "wfc-demo: auto begin";
const AUTO_END: &str = "wfc-demo: auto end";
const SCENE_C: &str = "wfc-demo: scene C committed";
const ENDED: &str = concat!("init: wfc-demo ended: exit code 0,", " not restarted");
const ENDS: &str = "init: wfc-demo ended: ";

/// The lines of the demo, each a check that passed.
const LINES: [&str; 12] = [
    "wfc-demo: the calls before a device are refused as the specification says",
    "wfc-demo: the device is made, described, and a second one has its own state",
    "wfc-demo: the context is made, a second one is in use, its attributes are as the specification says",
    "wfc-demo: the windows of the producers and of the mask are found by wfcNextStreamSTAFETO, the sources and the mask are made",
    "wfc-demo: the elements are made, ordered and refused as the specification says",
    "wfc-demo: a spawned child has no device",
    "wfc-demo: 100 commits of scenes A and B, each composed on request",
    "wfc-demo: 100 scene changes of the active context",
    "wfc-demo: the device is destroyed and its handles are gone",
    AUTO_BEGIN,
    AUTO_END,
    SCENE_C,
];

/// The lines that end the run in failure: a check that failed (of the demo or of
/// a producer), and the demo's process ending with a code other than 0.
fn failure(line: &str) -> Option<String> {
    let failed = line.starts_with("wfc-demo: check failed")
        || line.starts_with("wfc-producer: check failed")
        || (line.starts_with(ENDS) && line != ENDED);
    failed.then(|| line.to_owned())
}

/// The scene in the line of commit `k` ("wfc-demo: commit 7 scene B"): `A` for
/// an even `k` and `B` for an odd one, as the demo alternates them.
fn commit_scene(line: &str, k: usize) -> Result<usize, String> {
    let prefix = format!("{COMMIT}{k} scene ");
    let rest = line
        .strip_prefix(&prefix)
        .ok_or_else(|| format!("{line:?} is not the line of commit {k}"))?;
    let scene = match rest {
        "A" => 0,
        "B" => 1,
        _ => return Err(format!("{line:?}: scene {rest:?}, A or B expected")),
    };
    if scene != k % 2 {
        return Err(format!(
            "{line:?}: commit {k} shows scene {}",
            b"AB"[k % 2] as char
        ));
    }
    Ok(scene)
}

/// What the host and the screen say about a commit.
#[derive(Debug, PartialEq, Eq)]
pub struct Shot {
    pub scene: usize,
    pub screen: u32,
    pub host: u32,
}

/// What a run gave: the screenshots after the commits and those of the active
/// context.
pub struct Seen {
    pub shots: Vec<Shot>,
    pub auto: Vec<u32>,
    /// The screenshot of scene C (the window of the first revision, shown
    /// straight from its buffer).
    pub direct: u32,
}

/// The CRC of the picture the third producer draws on the screen of the first
/// revision: the gradient of frame 0 of the display demo (`wfd::pattern_crc`).
fn direct_crc() -> u32 {
    crate::wfd::pattern_crc(0)
}

fn take(monitor: &mut Monitor, scratch: &Scratch) -> Result<u32, String> {
    let picture = monitor.screendump(&scratch.picture())?;
    if (picture.width, picture.height) != (WIDTH, HEIGHT) {
        return Err(format!(
            "the screenshot is {}x{}, 640x400 expected",
            picture.width, picture.height
        ));
    }
    Ok(picture.crc32())
}

/// Follows the run: the screenshot after each commit's line against the host's
/// CRC for its scene, the shots of the active context, then the end of the demo.
fn drive(run: &mut Run, scratch: &Scratch, host: [u32; 2]) -> Result<Seen, String> {
    const WITHIN: Duration = Duration::from_secs(240);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    let mut shots = Vec::with_capacity(COMMITS);
    for k in 0..COMMITS {
        let prefix = format!("{COMMIT}{k} scene ");
        let line = run.expect_line(
            &prefix,
            |l| l.starts_with(&prefix) || failure(l).is_some(),
            WITHIN,
        )?;
        if let Some(failed) = failure(&line) {
            return Err(failed);
        }
        let scene = commit_scene(&line, k)?;
        shots.push(Shot {
            scene,
            screen: take(&mut monitor, scratch)?,
            host: host[scene],
        });
    }
    let line = run.expect_line(
        AUTO_BEGIN,
        |l| l == AUTO_BEGIN || failure(l).is_some(),
        WITHIN,
    )?;
    if let Some(failed) = failure(&line) {
        return Err(failed);
    }
    let mut auto = Vec::new();
    loop {
        auto.push(take(&mut monitor, scratch)?);
        match run.expect_line(
            AUTO_END,
            |l| l == AUTO_END || failure(l).is_some(),
            Duration::from_millis(5),
        ) {
            Ok(line) => {
                if let Some(failed) = failure(&line) {
                    return Err(failed);
                }
                break;
            }
            Err(e) if e.starts_with("timed out") => {}
            Err(e) => return Err(e),
        }
    }
    let line = run.expect_line(SCENE_C, |l| l == SCENE_C || failure(l).is_some(), WITHIN)?;
    if let Some(failed) = failure(&line) {
        return Err(failed);
    }
    let direct = take(&mut monitor, scratch)?;
    let line = run.expect_line(ENDED, |l| l == ENDED || failure(l).is_some(), WITHIN)?;
    if let Some(failed) = failure(&line) {
        return Err(failed);
    }
    Ok(Seen {
        shots,
        auto,
        direct,
    })
}

/// The lines of commits in a run's output: each number once, in order, with
/// the scene of its parity. A doubled line (even with another scene) fails.
fn commit_lines(lines: &[String]) -> Result<(), String> {
    let commits: Vec<&String> = lines.iter().filter(|l| l.starts_with(COMMIT)).collect();
    if commits.len() != COMMITS {
        return Err(format!(
            "{} lines of commits, {COMMITS} expected",
            commits.len()
        ));
    }
    for (k, line) in commits.iter().enumerate() {
        commit_scene(line, k)?;
    }
    Ok(())
}

/// Judges the lines of a run and the frames: no check failed, each line of the
/// demo came once, the commit lines are 0 to 99 each once, and every screenshot
/// after a commit is the host's CRC for its scene (a frame of elements of both
/// scenes is neither), and each screenshot of the active context is the CRC of A
/// or of B.
pub fn verdict(lines: &[String], seen: &Seen, host: [u32; 2]) -> Result<(), String> {
    if let Some(failed) = lines.iter().find_map(|l| failure(l)) {
        return Err(failed);
    }
    for marker in LINES.iter().chain(&["wfc-demo: ok"]) {
        let found = lines.iter().filter(|l| l.as_str() == *marker).count();
        if found != 1 {
            return Err(format!("{found} lines {marker:?}, 1 expected"));
        }
    }
    commit_lines(lines)?;
    if host[0] == host[1] {
        return Err(format!(
            "the host's frames of scenes A and B are the same ({:08x})",
            host[0]
        ));
    }
    if seen.shots.len() != COMMITS {
        return Err(format!(
            "{} screenshots, {COMMITS} expected",
            seen.shots.len()
        ));
    }
    for (k, s) in seen.shots.iter().enumerate() {
        if s.screen != s.host {
            let other = if s.screen == host[1 - s.scene] {
                "the other scene's"
            } else {
                "a third picture"
            };
            return Err(format!(
                "commit {k} (scene {}): QEMU's screenshot is {:08x}, the host's frame is {:08x} ({other})",
                b"AB"[s.scene] as char, s.screen, s.host
            ));
        }
    }
    if seen.auto.len() < 3 {
        return Err(format!(
            "{} screenshots of the active context, 3 at least expected",
            seen.auto.len()
        ));
    }
    if let Some((i, c)) = seen
        .auto
        .iter()
        .enumerate()
        .find(|(_, c)| !host.contains(c))
    {
        return Err(format!(
            "screenshot {i} of the active context is {c:08x}, neither scene A's {:08x} nor B's {:08x}",
            host[0], host[1]
        ));
    }
    if seen.direct != direct_crc() {
        return Err(format!(
            "scene C (the window of the first revision shown directly): QEMU's screenshot is {:08x}, the producer's gradient is {:08x}",
            seen.direct,
            direct_crc()
        ));
    }
    Ok(())
}

/// The trace of the device against what the demo did: the screen went to the pool
/// (resource 2) after the target (resource 1), which is the window of the first
/// revision shown straight from its buffer, with no band put together.
pub fn trace_verdict(events: &[qemu::GpuTrace]) -> Result<(), String> {
    let scanouts: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            qemu::GpuTrace::Scanout {
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
    if gpu_probe::contains_in_order(&scanouts, &[1, 2]) {
        Ok(())
    } else {
        Err(format!(
            "the trace of SET_SCANOUT shows resources {scanouts:?}, 1 and then 2 (scene C shown directly) expected"
        ))
    }
}

/// `cargo xtask wfc-probe [screen|steps]`: the probe, the screenshots alone, or the run
/// under -icount alone.
pub fn command(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => probe(machine, true),
        Some("screen") => probe(machine, false),
        Some("steps") => steps(machine),
        Some(other) => Err(format!(
            "wfc-probe: unknown argument {other:?}; screen, steps or none"
        )),
    }
}

/// `cargo xtask wfc-probe` and its boot in `test`.
pub fn probe(machine: &qemu::Machine, with_steps: bool) -> Result<(), String> {
    crate::relibc()?;
    let host = wfc_ref::crcs();
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-wfc.img", &PROGRAMS, BOOT_PROFILE)?;
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
    let driven = drive(&mut run, &scratch, host);
    let outcome = run.stop();
    let who = |e: String| format!("wfc-probe on {}: {e}", machine.name);
    let seen = driven.map_err(who)?;
    verdict(&outcome.lines, &seen, host).map_err(who)?;
    let text = std::fs::read_to_string(scratch.trace())
        .map_err(|e| who(format!("the trace file: {e}")))?;
    trace_verdict(&qemu::parse_gpu_trace(&text).map_err(who)?).map_err(who)?;
    println!(
        "wfc-probe on {}: scene A is {:08x} and scene B {:08x} (the host's frames from the same calls, drawn point by point); {COMMITS} commits in turn, each composed on request, matched QEMU's screenshot; {} screenshots of the active context while the scene changed {COMMITS} times were each A or B; scene C, the window of the first revision, matched the producer's gradient and the scanout went to the pool (resource 2); the calls, the errors, the streams, the sources, the mask, the child and the destroy: ok",
        machine.name,
        host[0],
        host[1],
        seen.auto.len()
    );
    if with_steps && !machine.is_hvf() {
        steps(machine)?;
    }
    Ok(())
}

/// The compositor's kinds that must come: DESCRIBE, WINDOW_CREATE, ATTACH, POST,
/// SCENE_COMMIT, SCENE_COMPOSE, and its own (a band, the end of a frame).
const COMP_KINDS: [(usize, &str); 7] = [
    (17, "Describe"),
    (18, "WindowCreate"),
    (19, "Attach"),
    (20, "Post"),
    (26, "SceneCommit"),
    (27, "SceneCompose"),
    (65, "a band of a frame and the end of a frame"),
];
/// The driver's: SUBSCRIBE, COMMIT, PIPELINES and SOURCE (the compositor asks them
/// when it opens the screen), and its own (the interrupt).
const DRIVER_KINDS: [(usize, &str); 5] = [
    (5, "Subscribe"),
    (6, "Commit"),
    (9, "Pipelines"),
    (10, "Source"),
    (65, "the interrupt"),
];

type Rows = Vec<(usize, u64, u64)>;

/// The steps of one service: every kind came, every row is under STEP_MAX and the
/// rows of its own kind under PORTION_MAX.
fn rows_of(
    lines: &[String],
    tag: &str,
    name: &str,
    kinds: &[(usize, &str)],
) -> Result<Rows, String> {
    let rows = longest_steps(lines, tag);
    crate::step_line::within_b(lines, tag, crate::step_line::Kinds::All)?;
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
    if let Some(row) = rows.iter().find(|r| r.0 == 65 && r.1 > crate::PORTION_MAX) {
        return Err(format!(
            "the {name}: a portion or an interrupt past {}: {row:?}",
            crate::PORTION_MAX
        ));
    }
    Ok(rows)
}

/// The steps of the compositor and of the driver.
pub fn steps_verdict(lines: &[String]) -> Result<(Rows, Rows), String> {
    use crate::comp_probe::{COMP_TAG, DRIVER_TAG};
    Ok((
        rows_of(lines, COMP_TAG, "compositor", &COMP_KINDS)?,
        rows_of(lines, DRIVER_TAG, "display driver", &DRIVER_KINDS)?,
    ))
}

/// The run under -icount: the demo does not pause for the monitor, and the steps
/// of the compositor and the driver are read from their lines.
fn steps(machine: &qemu::Machine) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-wfc-steps.img", &STEPS_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::GPU);
    cmd.args(qemu::ICOUNT);
    let output = run_until(cmd, crate::BOOT_TIMEOUT * 8, Some(ENDS), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED)?;
    if let Some(failed) = output.lines.iter().find_map(|l| failure(l)) {
        return Err(format!("wfc-probe under -icount: {failed}"));
    }
    qemu::expect_marker(&output, "wfc-demo: ok")?;
    commit_lines(&output.lines).map_err(|e| format!("wfc-probe under -icount: {e}"))?;
    let (comp, driver) = steps_verdict(&output.lines)?;
    println!(
        "{}",
        crate::frame_probe::check_waits(&output.lines, init::table::wfc::STEPS_TABLE, "wfc-probe")?
    );
    let text = |rows: &Rows| -> String {
        rows.iter()
            .map(|(kind, ticks, _)| format!("kind {kind} {ticks}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "wfc-probe on {}: {COMMITS} commits and {COMMITS} changes under -icount; the longest steps, ticks (0.9 of term B {}, portions {}): compositor {}; driver {}; {}",
        machine.name,
        gpu_probe::STEP_MAX,
        crate::PORTION_MAX,
        text(&comp),
        text(&driver),
        crate::comp_probe::band_report(&output.lines, crate::comp_probe::COMP_TAG)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> [u32; 2] {
        [0x1111_1111, 0x2222_2222]
    }

    fn good_lines() -> Vec<String> {
        let mut lines: Vec<String> = LINES.iter().map(|l| (*l).to_owned()).collect();
        for k in 0..COMMITS {
            lines.push(format!("{COMMIT}{k} scene {}", b"AB"[k % 2] as char));
        }
        lines.push("wfc-demo: ok".to_owned());
        lines
    }

    fn good_seen() -> Seen {
        let h = host();
        Seen {
            shots: (0..COMMITS)
                .map(|k| Shot {
                    scene: k % 2,
                    screen: h[k % 2],
                    host: h[k % 2],
                })
                .collect(),
            auto: vec![h[1], h[0], h[1], h[1], h[0]],
            direct: direct_crc(),
        }
    }

    #[test]
    fn a_good_run_passes() {
        verdict(&good_lines(), &good_seen(), host()).unwrap();
    }

    #[test]
    fn the_commit_line_names_its_number_and_the_scene_of_its_parity() {
        assert_eq!(commit_scene("wfc-demo: commit 4 scene A", 4), Ok(0));
        assert_eq!(commit_scene("wfc-demo: commit 5 scene B", 5), Ok(1));
        assert!(commit_scene("wfc-demo: commit 5 scene A", 5).is_err());
        assert!(commit_scene("wfc-demo: commit 5 scene B", 6).is_err());
        assert!(commit_scene("wfc-demo: commit 5 scene C", 5).is_err());
        assert!(commit_scene("wfc-demo: commit 5 scene", 5).is_err());
    }

    /// A doubled line with another scene fails the parse.
    #[test]
    fn a_doubled_commit_line_with_another_scene_fails() {
        let mut lines = good_lines();
        let at = lines
            .iter()
            .position(|l| l == "wfc-demo: commit 7 scene B")
            .unwrap();
        lines.insert(at + 1, "wfc-demo: commit 7 scene A".to_owned());
        let e = verdict(&lines, &good_seen(), host()).unwrap_err();
        assert!(e.contains("101 lines of commits"), "{e}");
        let mut lines = good_lines();
        lines.remove(
            lines
                .iter()
                .position(|l| l == "wfc-demo: commit 7 scene B")
                .unwrap(),
        );
        assert!(verdict(&lines, &good_seen(), host()).is_err());
    }

    /// A scene B with one element of A is a third picture.
    #[test]
    fn a_third_picture_fails() {
        let mut seen = good_seen();
        seen.shots[10].screen = 0x3333_3333;
        let e = verdict(&good_lines(), &seen, host()).unwrap_err();
        assert!(
            e.contains("commit 10") && e.contains("third picture"),
            "{e}"
        );
        let mut seen = good_seen();
        seen.shots[11].screen = host()[0];
        let e = verdict(&good_lines(), &seen, host()).unwrap_err();
        assert!(e.contains("the other scene's"), "{e}");
    }

    #[test]
    fn a_screenshot_of_the_active_context_must_be_one_of_the_two() {
        let mut seen = good_seen();
        seen.auto.push(0x4444_4444);
        let e = verdict(&good_lines(), &seen, host()).unwrap_err();
        assert!(e.contains("neither scene A's"), "{e}");
        let mut seen = good_seen();
        seen.auto.truncate(2);
        assert!(verdict(&good_lines(), &seen, host()).is_err());
    }

    #[test]
    fn a_failed_check_or_a_missing_line_fails() {
        let mut lines = good_lines();
        lines.push("wfc-demo: check failed at line 9: x (errno 1, error 0)".to_owned());
        assert!(verdict(&lines, &good_seen(), host()).is_err());
        let mut lines = good_lines();
        lines.remove(0);
        assert!(verdict(&lines, &good_seen(), host()).is_err());
        assert!(failure("wfc-demo: check failed at line 1: x").is_some());
        assert!(failure("wfc-producer: check failed at line 1: x").is_some());
        assert!(
            failure(concat!(
                "init: wfc-demo ended: exit code 20,",
                " not restarted"
            ))
            .is_some()
        );
        assert!(failure(ENDED).is_none());
    }

    #[test]
    fn scene_c_must_be_the_producers_gradient() {
        let mut seen = good_seen();
        seen.direct ^= 1;
        let e = verdict(&good_lines(), &seen, host()).unwrap_err();
        assert!(e.contains("scene C"), "{e}");
    }

    #[test]
    fn the_trace_must_show_the_scanout_going_to_the_pool() {
        use qemu::GpuTrace::Scanout;
        let at = |res| Scanout {
            id: 0,
            res,
            w: 640,
            h: 400,
            x: 0,
            y: 0,
        };
        assert!(trace_verdict(&[at(1), at(2)]).is_ok());
        assert!(trace_verdict(&[at(1), at(1)]).is_err());
        assert!(trace_verdict(&[at(2), at(1)]).is_err());
    }

    #[test]
    fn equal_host_frames_fail() {
        assert!(verdict(&good_lines(), &good_seen(), [5, 5]).is_err());
    }

    #[test]
    fn the_hosts_two_frames_differ() {
        let [a, b] = wfc_ref::crcs();
        assert_ne!(a, b);
    }
}
