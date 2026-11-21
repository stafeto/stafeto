// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the scene library of OpenWF Composition (apps/wfc-demo, the C
//! functions of `<WF/wfc.h>` in a static program) on QEMU's virtio-gpu-device
//! with the composition service: the services of the POSIX probes, the display
//! driver, the compositor and the demo, the holder of the scene. The demo starts
//! two producers (tests/wfc-producer: a window of 100 by 200 points and one of
//! 160 by 100, each a fixed pattern), draws a mask of A8 of its own, finds the
//! windows by `wfcNextStreamSTAFETO`, and shows two scenes of three elements,
//! A and B: elements of one to one scale, quarter turns, the filters none and
//! faster, a global alpha and a mask. A stretch, a flip and the bilinear filter
//! are left out while the service's price model makes a frame of them take
//! seconds; they come back with the change of that model.
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
//! screenshots one after another meanwhile, and each is the CRC of A or of B,
//! both of them come up, and the picture changes between them at least twice (the
//! first change of the phase sets the scene the last commit left, so a service that
//! composed nothing would show one picture only). A last scene C shows the window of
//! the first revision straight from its buffer. The demo prints the service's counters
//! at five points (DESCRIBE and STATS); no frame failed, the frames of the first part
//! are 100 or more, the bands grow under A and B and the frames shown straight do not,
//! and scene C adds a frame shown straight.
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
    /// The scanouts the device's trace had when the active phase ended, a lower
    /// bound (the file may lag): the one to the pool must come after them.
    pub scanouts_before_c: usize,
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
    let scanouts_before_c = loop {
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
                break scanouts_now(scratch);
            }
            Err(e) if e.starts_with("timed out") => {}
            Err(e) => return Err(e),
        }
    };
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
        scanouts_before_c,
    })
}

/// The scanouts of the whole screen the device's trace has so far (0 when the file is
/// not there yet or has nothing).
fn scanouts_now(scratch: &Scratch) -> usize {
    std::fs::read_to_string(scratch.trace())
        .ok()
        .and_then(|text| qemu::parse_gpu_trace(&text).ok())
        .map_or(0, |events| scanouts(&events).len())
}

/// The resources the screen was set to, in order.
fn scanouts(events: &[qemu::GpuTrace]) -> Vec<u32> {
    events
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
        .collect()
}

/// The service's counters the demo printed at a point (`counters` of wfc-demo.c).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counters {
    pub frames: u64,
    pub direct: u64,
    pub late: u64,
    pub skipped: u64,
    pub failed: u64,
    pub capped: u64,
    pub bypassed: u64,
    pub bands: u64,
}

/// The five lines `wfc-demo: counters P frames F direct D late L skipped S failed X
/// capped C bypassed Y bands B`, in order of P.
pub fn counters_of(lines: &[String]) -> Result<[Counters; 5], String> {
    let mut found = Vec::new();
    for point in 0..5 {
        let prefix = format!("wfc-demo: counters {point} ");
        let mut mine = lines.iter().filter(|l| l.starts_with(&prefix));
        let line = mine.next().ok_or_else(|| format!("no line {prefix:?}"))?;
        if mine.next().is_some() {
            return Err(format!("two lines {prefix:?}"));
        }
        let words: Vec<&str> = line[prefix.len()..].split_whitespace().collect();
        let names = [
            "frames", "direct", "late", "skipped", "failed", "capped", "bypassed", "bands",
        ];
        let mut numbers = [0u64; 8];
        if words.len() != 16 {
            return Err(format!("{line:?}: eight counters expected"));
        }
        for (k, name) in names.iter().enumerate() {
            if words[2 * k] != *name {
                return Err(format!("{line:?}: {name} expected"));
            }
            numbers[k] = words[2 * k + 1]
                .parse()
                .map_err(|e| format!("{line:?}: {name}: {e}"))?;
        }
        found.push(Counters {
            frames: numbers[0],
            direct: numbers[1],
            late: numbers[2],
            skipped: numbers[3],
            failed: numbers[4],
            capped: numbers[5],
            bypassed: numbers[6],
            bands: numbers[7],
        });
    }
    Ok(found.try_into().expect("five points"))
}

/// What the counters say (plan 8.2.4 and 7.4): no frame failed, the 100 composes of the
/// first part are 100 frames or more, bands grew under the scenes A and B in both
/// parts and no frame of them was shown straight, and scene C added a frame shown
/// straight from a window's buffer. The bands of scene C are told and left unjudged: the run
/// showed 3 285 bands in the two frames of that step (one shown straight, one put
/// together), so "no band in frame C" is not a property of this scene.
pub fn counters_verdict(c: &[Counters; 5]) -> Result<(), String> {
    if let Some(k) = c.iter().position(|c| c.failed != 0) {
        return Err(format!("counters {k}: {} frames failed", c[k].failed));
    }
    if c[1].frames < c[0].frames + COMMITS as u64 {
        return Err(format!(
            "frames {} then {}: {COMMITS} or more expected for the commits",
            c[0].frames, c[1].frames
        ));
    }
    if c[1].bands <= c[0].bands || c[2].bands <= c[1].bands {
        return Err(format!(
            "bands {}, {}, {}: they grow under scenes A and B",
            c[0].bands, c[1].bands, c[2].bands
        ));
    }
    if c[0].bypassed != c[1].bypassed || c[1].bypassed != c[2].bypassed {
        return Err(format!(
            "frames shown straight {}, {}, {}: none under scenes A and B",
            c[0].bypassed, c[1].bypassed, c[2].bypassed
        ));
    }
    if c[4].bypassed <= c[3].bypassed {
        return Err(format!(
            "scene C: frames shown straight {} then {}, more expected",
            c[3].bypassed, c[4].bypassed
        ));
    }
    Ok(())
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
    let changes = seen.auto.windows(2).filter(|w| w[0] != w[1]).count();
    if !seen.auto.contains(&host[0]) || !seen.auto.contains(&host[1]) || changes < 2 {
        return Err(format!(
            "the {} screenshots of the active context show {} change(s) between the scenes and A {} and B {} among them: both scenes and two changes at least expected (the active context took no frame by itself)",
            seen.auto.len(),
            changes,
            if seen.auto.contains(&host[0]) {
                "is"
            } else {
                "is not"
            },
            if seen.auto.contains(&host[1]) {
                "is"
            } else {
                "is not"
            },
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
    counters_verdict(&counters_of(lines)?)?;
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
pub fn trace_verdict(events: &[qemu::GpuTrace], before_c: usize) -> Result<(), String> {
    let scanouts = scanouts(events);
    let first = scanouts.iter().position(|&r| r == 2);
    if gpu_probe::contains_in_order(&scanouts, &[1, 2]) && first.is_some_and(|k| k >= before_c) {
        Ok(())
    } else {
        Err(format!(
            "the trace of SET_SCANOUT shows resources {scanouts:?}: 1 and then 2 (scene C shown directly), the first 2 after the first {before_c} entries (the end of the active phase), expected"
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
    trace_verdict(
        &qemu::parse_gpu_trace(&text).map_err(who)?,
        seen.scanouts_before_c,
    )
    .map_err(who)?;
    let c = counters_of(&outcome.lines).map_err(who)?;
    println!(
        "wfc-probe on {}: scene A is {:08x} and scene B {:08x} (the host's frames from the same calls, drawn point by point); {COMMITS} commits in turn, each composed on request, matched QEMU's screenshot; {} screenshots of the active context while the scene changed {COMMITS} times were each A or B (both came up, {} changes between them); scene C, the window of the first revision, matched the producer's gradient and the scanout went to the pool (resource 2) after the active phase; the service's counters: frames {} then {} then {} (commits, active phase), bands {} then {} then {}, frames shown straight {} under A and B and {} after C with {} bands in it, failed {}, late {} and capped {} (of the frames and periods since the start); the calls, the errors, the streams, the sources, the mask, the child and the destroy: ok",
        machine.name,
        host[0],
        host[1],
        seen.auto.len(),
        seen.auto.windows(2).filter(|w| w[0] != w[1]).count(),
        c[0].frames,
        c[1].frames,
        c[2].frames,
        c[0].bands,
        c[1].bands,
        c[2].bands,
        c[2].bypassed,
        c[4].bypassed,
        c[4].bands - c[3].bands,
        c[4].failed,
        c[4].late,
        c[4].capped
    );
    if with_steps && !machine.is_hvf() {
        steps(machine)?;
    }
    Ok(())
}

/// The compositor's kinds that must come: OPEN and FLUSH of the producer of the first
/// revision (scene C), DESCRIBE, WINDOW_CREATE, ATTACH, POST, SCENE_COMMIT,
/// SCENE_COMPOSE, and its own (a band, the end of a frame). The step of the taking of a
/// frame is no kind of its own: the lines tell the longest step of a kind, and the
/// details seen were the band's and the work's, so it is not asked for by itself.
const COMP_KINDS: [(usize, &str); 9] = [
    (1, "Open"),
    (2, "Flush"),
    (17, "Describe"),
    (18, "WindowCreate"),
    (19, "Attach"),
    (20, "Post"),
    (26, "SceneCommit"),
    (27, "SceneCompose"),
    (65, "a band of a frame and the end of a frame"),
];
/// The driver's: SUBSCRIBE, COMMIT, PIPELINES and SOURCE (the compositor asks them
/// when it opens the screen), LAYERS (scene C shown straight), and its own (the
/// interrupt).
const DRIVER_KINDS: [(usize, &str); 6] = [
    (5, "Subscribe"),
    (6, "Commit"),
    (11, "Layers"),
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
        for (point, c) in good_counters().iter().enumerate() {
            lines.push(format!(
                "wfc-demo: counters {point} frames {} direct {} late {} skipped {} failed {} capped {} bypassed {} bands {}",
                c.frames, c.direct, c.late, c.skipped, c.failed, c.capped, c.bypassed, c.bands
            ));
        }
        lines.push("wfc-demo: ok".to_owned());
        lines
    }

    fn counters_at(frames: u64, bypassed: u64, bands: u64) -> Counters {
        Counters {
            frames,
            direct: bypassed,
            late: 0,
            skipped: 0,
            failed: 0,
            capped: 1,
            bypassed,
            bands,
        }
    }

    fn good_counters() -> [Counters; 5] {
        [
            counters_at(3, 0, 100),
            counters_at(110, 0, 90_000),
            counters_at(150, 0, 190_000),
            counters_at(151, 0, 190_000),
            counters_at(152, 1, 190_000),
        ]
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
            scanouts_before_c: 2,
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
        assert!(trace_verdict(&[at(1), at(2)], 1).is_ok());
        assert!(trace_verdict(&[at(1), at(1)], 1).is_err());
        assert!(trace_verdict(&[at(2), at(1)], 0).is_err());
        // The scanout to the pool must come after the end of the active phase.
        assert!(trace_verdict(&[at(1), at(2), at(1)], 2).is_err());
        assert!(trace_verdict(&[at(1), at(1), at(2)], 2).is_ok());
    }

    /// The active context composed nothing: every screenshot is the scene the last
    /// commit of the first part left (B).
    #[test]
    fn an_active_context_that_shows_one_picture_fails() {
        let h = host();
        let mut seen = good_seen();
        seen.auto = vec![h[1]; 20];
        let e = verdict(&good_lines(), &seen, h).unwrap_err();
        assert!(e.contains("took no frame by itself"), "{e}");
        // Both pictures but a single change is too few.
        seen.auto = vec![h[1], h[1], h[0], h[0]];
        assert!(verdict(&good_lines(), &seen, h).is_err());
        seen.auto = vec![h[1], h[0], h[1]];
        verdict(&good_lines(), &seen, h).unwrap();
    }

    #[test]
    fn the_counters_are_read_and_judged() {
        let lines = good_lines();
        assert_eq!(counters_of(&lines).unwrap(), good_counters());
        counters_verdict(&good_counters()).unwrap();
        let mut c = good_counters();
        c[2].failed = 1;
        assert!(counters_verdict(&c).unwrap_err().contains("failed"));
        let mut c = good_counters();
        c[1].frames = c[0].frames + 99;
        assert!(counters_verdict(&c).is_err());
        let mut c = good_counters();
        c[2].bands = c[1].bands;
        assert!(counters_verdict(&c).is_err());
        let mut c = good_counters();
        c[2].bypassed = 1;
        assert!(counters_verdict(&c).is_err());
        let mut c = good_counters();
        c[4].bands += 3285;
        counters_verdict(&c).unwrap();
        let mut c = good_counters();
        c[4].bypassed = c[3].bypassed;
        assert!(counters_verdict(&c).is_err());
        let mut lines = good_lines();
        lines.retain(|l| !l.starts_with("wfc-demo: counters 3 "));
        assert!(counters_of(&lines).is_err());
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
