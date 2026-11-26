// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the graphics of Mesa (`cargo xtask gles-probe`): EGL 1.5 and
//! OpenGL ES 3 on Mesa's softpipe driver, drawn by C programs on relibc and shown
//! by the composition service on QEMU's virtio-gpu-device. Three boots:
//!
//! 1. the cube into a pbuffer (`gles_pbuffer`): ten frames read back, each CRC-32
//!    the one pinned in `gles_pbuffer::EXPECTED_CRCS`, which the same Mesa built for
//!    Linux gives (tools/mesa-reference);
//! 2. the scene (`boot-gles.img`, apps/wfc-demo `--gles`): the demo holds the scene
//!    and starts `gles-cube --window-run --hold` and `gles3-demo --probe --hold`,
//!    and shows their windows. The cube checks the platform of EGL (the checks of
//!    `gles_window`), draws six frames into its window, and while it pauses at
//!    the third frame and at the last the host's screenshot has the CRC-32 of the
//!    screen the cube printed: the window, shown by the scene, holds what the
//!    platform copied into it. The cube then holds its window and the screenshot has
//!    its CRC-32 once more. `gles3-demo` (a vertex array object, a uniform block,
//!    an instanced draw of 64 cubes) draws three frames into a pbuffer and the same
//!    three into a window, each with the CRC-32 of the pbuffer's frame and the rows
//!    of the window the mirror of the readback; the screenshot of its window has the
//!    CRC-32 it printed. Last the demo turns the cube's window by 90 degrees and
//!    scales it by one half with an element of libWFC (the stream of
//!    `eglSwapBuffers` as a source of OpenWF Composition), and the host draws that
//!    scene point by point (`tools/wfc-ref`, `gles_frame`) from the two windows as
//!    its own screenshot of them shows them: the screenshot of the scene has that
//!    frame's CRC-32;
//! 3. the same scene under -icount (`boot-gles-steps.img`): the demo leaves out its
//!    pauses, and the steps of the compositor and the driver, with the cube and the
//!    field drawing, stay under 0.9 of term B and the portions under `PORTION_MAX`.

use std::time::{Duration, Instant};

use crate::gles_pbuffer::frame_line;
use crate::gles_window::{End, SHOTS};
use crate::gpu_probe::{self, Scratch};
use crate::monitor::{Monitor, Ppm};
use crate::qemu::{self, Input, Run};
use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, POSIX_STACK_SIZE, Variant, build,
    build_boot_image, run_until,
};

/// The image of the scene: the services of the POSIX probes, the driver, the
/// compositor, the demo (started by init) and the two programs it starts (files).
pub const PROGRAMS: [ImageProgram; 13] = [
    ("init", "init", INIT_STACK_SIZE, &["table-gles"]),
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
    // Files the demo spawns: the stack is the PT_GNU_STACK of their own build.
    ("gles-cube", "gles-cube", 0, &[]),
    ("gles3-demo", "gles3-demo", 0, &[]),
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
pub const STEPS_PROGRAMS: [ImageProgram; 13] = [
    ("init", "init", INIT_STACK_SIZE, &["table-gles-steps"]),
    ("ramfs", "ramfs", crate::RAMFS_STACK_SIZE, &["steps"]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &["steps"],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("pipe", "pipe", crate::PIPE_STACK_SIZE, &["steps"]),
    ("loader", "loader", 0, &["steps"]),
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
    ("gles-cube", "gles-cube", 0, &[]),
    ("gles3-demo", "gles3-demo", 0, &[]),
    (
        "virtio-rng",
        "virtio-rng",
        crate::entropy::RNG_STACK_SIZE,
        &["steps"],
    ),
    (
        "entropy",
        "entropy",
        crate::entropy::ENTROPY_STACK_SIZE,
        &["steps"],
    ),
];

const WIDTH: usize = 640;
const HEIGHT: usize = 400;
/// The side of the two windows, and where the demo shows them (`GLES_*` of
/// wfc-demo.c, `wfc_ref::GLES_*`).
const SIZE: usize = wfc_ref::GLES_SIZE as usize;
const CUBE_AT: (usize, usize) = (
    wfc_ref::GLES_CUBE_AT.0 as usize,
    wfc_ref::GLES_CUBE_AT.1 as usize,
);
const FIELD_AT: (usize, usize) = (
    wfc_ref::GLES_FIELD_AT.0 as usize,
    wfc_ref::GLES_FIELD_AT.1 as usize,
);

/// The lines of the field of cubes start with this.
const FIELD: &str = "gles3-demo: ";
/// The frames the field draws, and their CRC-32 as the program prints them once
/// pinned: the frames are the same on every run of the same build; the value is
/// pinned after agreeing runs (the three runs of the local machine agree; the
/// repeats of probe.yml on the machines of GitHub are the second witness).
pub const FIELD_FRAMES: usize = 3;
pub const EXPECTED_FIELD_CRCS: Option<[u32; FIELD_FRAMES]> =
    Some([0xbb63_7c2c, 0x463e_8d75, 0x1b38_eaa0]);

const CUBE_HELD: &str = "gles-cube: held crc ";
const FIELD_HELD: &str = "gles3-demo: held crc ";
const LINE_ALONE: &str =
    "wfc-demo: gles the window of the cube is an element of the active context";
const LINE_CUBE: &str = "wfc-demo: gles the cube holds its last frame";
const LINE_BOTH: &str = "wfc-demo: gles both windows are shown as they are";
const LINE_G: &str = "wfc-demo: gles scene G committed";
const LINE_GONE: &str = "wfc-demo: the programs are gone and the device is destroyed";
const LINE_OK: &str = "wfc-demo: ok";
const ENDED: &str = concat!("init: wfc-demo ended: exit code 0,", " not restarted");
const ENDS: &str = "init: wfc-demo ended: ";

/// The lines of the demo that come once each (besides the checks of the device).
const DEMO_LINES: [&str; 6] = [LINE_ALONE, LINE_CUBE, LINE_BOTH, LINE_G, LINE_GONE, LINE_OK];

/// The lines of the field's program that come once each, as the text after its
/// prefix (`starts_with`, `ends_with`).
const FIELD_ONCE: [(&str, &str); 1] = [("uniform block Scene of ", " bytes")];

/// A line that ends the probe in failure: a check of a program that failed, a
/// shader that did not compile, or the demo ending with a code other than 0.
fn failure(line: &str) -> Option<String> {
    let failed = crate::gles_window::failure(line).is_some()
        || line.starts_with("gles3-demo: check failed")
        || line.starts_with("gles3-demo: shader")
        || line.starts_with("wfc-demo: check failed")
        || (line.starts_with(ENDS) && line != ENDED);
    failed.then(|| line.to_owned())
}

/// What the screenshots showed.
#[derive(Debug, PartialEq, Eq)]
pub struct Seen {
    /// The CRC-32 of the two screenshots the cube's `window crc` and `last crc`
    /// lines asked for.
    pub shots: [u32; 2],
    /// The CRC-32 of the screen with the cube's window alone, its own `held crc`.
    pub cube_held: u32,
    /// The CRC-32 of the field's window in the screenshot with both windows, its own
    /// `held crc`.
    pub field_held: u32,
    /// The CRC-32 of the screenshot with both windows as they are, and of the
    /// scene G (the cube turned and halved).
    pub both: u32,
    pub scene_g: u32,
}

/// The points of a part of a screenshot, 0x00RRGGBB, rows from the top.
fn crop(picture: &Ppm, at: (usize, usize)) -> Vec<u32> {
    let mut points = Vec::with_capacity(SIZE * SIZE);
    for y in at.1..at.1 + SIZE {
        for x in at.0..at.0 + SIZE {
            let p = &picture.rgb[3 * (y * WIDTH + x)..3 * (y * WIDTH + x) + 3];
            points.push(u32::from(p[0]) << 16 | u32::from(p[1]) << 8 | u32::from(p[2]));
        }
    }
    points
}

/// Where a screenshot differs from the host's frame: the number of points, the
/// box around them and the first of them with both colours (0xRRGGBB).
fn where_it_differs(picture: &Ppm, frame: &[u32]) -> String {
    let mut count = 0usize;
    let mut bounds = (usize::MAX, usize::MAX, 0usize, 0usize);
    let mut first = None;
    for (i, want) in frame.iter().enumerate() {
        let got = &picture.rgb[3 * i..3 * i + 3];
        let got = u32::from(got[0]) << 16 | u32::from(got[1]) << 8 | u32::from(got[2]);
        if got != *want {
            let (x, y) = (i % WIDTH, i / WIDTH);
            count += 1;
            bounds = (
                bounds.0.min(x),
                bounds.1.min(y),
                bounds.2.max(x),
                bounds.3.max(y),
            );
            first.get_or_insert((x, y, got, *want));
        }
    }
    match first {
        None => "no point differs".to_owned(),
        Some((x, y, got, want)) => format!(
            "{count} points differ, in the box x {}..{} y {}..{}; the first at ({x}, {y}): screen {got:06x}, host {want:06x}",
            bounds.0, bounds.2, bounds.1, bounds.3
        ),
    }
}

fn take_picture(monitor: &mut Monitor, scratch: &Scratch) -> Result<Ppm, String> {
    let picture = monitor.screendump(&scratch.picture())?;
    if (picture.width, picture.height) != (WIDTH, HEIGHT) {
        return Err(format!(
            "the screenshot is {}x{}, 640x400 expected",
            picture.width, picture.height
        ));
    }
    Ok(picture)
}

/// The CRC-32 a program printed after `prefix`, eight hex digits.
fn crc_after(line: &str, prefix: &str) -> Result<u32, String> {
    gpu_probe::crc_of(line, prefix)
}

/// Waits for the first line that is `marker`, or a failure.
fn wait_for(run: &mut Run, marker: &str, within: Duration) -> Result<String, String> {
    let line = run.expect_line(
        marker,
        |l| l.starts_with(marker) || failure(l).is_some(),
        within,
    )?;
    match failure(&line) {
        Some(failed) => Err(failed),
        None => Ok(line),
    }
}

/// Follows the run: the screenshots at the cube's two pauses, the cube held, both
/// windows as they are, and the scene G.
fn drive(run: &mut Run, scratch: &Scratch) -> Result<Seen, String> {
    // softpipe draws a frame in tens of milliseconds under TCG, and the compiler of
    // GLSL runs first.
    const WITHIN: Duration = Duration::from_secs(900);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    let mut shots = [0; 2];
    for (shot, prefix) in shots.iter_mut().zip(SHOTS) {
        let line = wait_for(run, prefix, WITHIN)?;
        *shot = gpu_probe::compare_shot(&mut monitor, &scratch.picture(), &line, prefix)?;
    }
    let cube_line = wait_for(run, CUBE_HELD, WITHIN)?;
    let cube_held = crc_after(&cube_line, CUBE_HELD)?;
    wait_for(run, LINE_CUBE, WITHIN)?;
    let alone = take_picture(&mut monitor, scratch)?;
    if alone.crc32() != cube_held {
        return Err(format!(
            "the screenshot of the cube's window held by the scene is {:08x}, the cube printed {cube_held:08x}",
            alone.crc32()
        ));
    }
    let cube = crop(&alone, CUBE_AT);
    let field_line = wait_for(run, FIELD_HELD, WITHIN)?;
    let field_printed = crc_after(&field_line, FIELD_HELD)?;
    wait_for(run, LINE_BOTH, WITHIN)?;
    let both = take_picture(&mut monitor, scratch)?;
    let field = crop(&both, FIELD_AT);
    let field_held = wfc_ref::crc(&field);
    if field_held != field_printed {
        return Err(format!(
            "the screenshot of the field's window is {field_held:08x}, the program printed {field_printed:08x}"
        ));
    }
    if crop(&both, CUBE_AT) != cube {
        return Err("the cube's window changed between the two screenshots".to_owned());
    }
    let wanted = wfc_ref::gles_frame(false, &cube, &field);
    if both.crc32() != wfc_ref::crc(&wanted) {
        return Err(format!(
            "both windows as they are: QEMU's screenshot is {:08x}, the host's frame is {:08x}: {}",
            both.crc32(),
            wfc_ref::crc(&wanted),
            where_it_differs(&both, &wanted)
        ));
    }
    wait_for(run, LINE_G, WITHIN)?;
    let turned = take_picture(&mut monitor, scratch)?;
    let wanted = wfc_ref::gles_frame(true, &cube, &field);
    if turned.crc32() != wfc_ref::crc(&wanted) {
        return Err(format!(
            "scene G (the cube's window turned by 90 degrees and scaled by one half): QEMU's screenshot is {:08x}, the host's frame is {:08x}: {}",
            turned.crc32(),
            wfc_ref::crc(&wanted),
            where_it_differs(&turned, &wanted)
        ));
    }
    if crop(&turned, FIELD_AT) != field {
        return Err("the field's window changed in the scene G".to_owned());
    }
    let line = run.expect_line(ENDED, |l| l == ENDED || failure(l).is_some(), WITHIN)?;
    if let Some(failed) = failure(&line) {
        return Err(failed);
    }
    Ok(Seen {
        shots,
        cube_held,
        field_held,
        both: both.crc32(),
        scene_g: turned.crc32(),
    })
}

/// The lines of the field's program: the library is Mesa's softpipe with OpenGL ES 3,
/// the uniform block is there, the three frames came once each in order with
/// different CRC-32 and sums above 0, each frame of the window had the CRC-32 of the
/// pbuffer's (the program checks it, and the lines say it), and the held CRC-32 is
/// the last line. Returns the CRC-32 of the frames.
pub fn field_verdict(lines: &[String]) -> Result<[u32; FIELD_FRAMES], String> {
    let seen: Vec<&str> = lines.iter().filter_map(|l| l.strip_prefix(FIELD)).collect();
    let find = |prefix: &str| {
        seen.iter()
            .find_map(|l| l.strip_prefix(prefix))
            .ok_or_else(|| format!("the field's program printed no line {prefix:?}"))
    };
    if !find("EGL ")?.starts_with("1.5 ") {
        return Err(format!("EGL is {:?}, 1.5 expected", find("EGL ")?));
    }
    let renderer = find("GL_RENDERER ")?;
    if !renderer.contains("softpipe") {
        return Err(format!("the renderer is {renderer:?}, softpipe expected"));
    }
    let version = find("GL_VERSION ")?;
    if !version.contains("OpenGL ES 3.") || !version.contains("Mesa 26.3.1") {
        return Err(format!(
            "the version is {version:?}, OpenGL ES 3.x of Mesa 26.3.1 expected"
        ));
    }
    for (start, end) in FIELD_ONCE {
        let found = seen
            .iter()
            .filter(|l| l.starts_with(start) && l.ends_with(end))
            .count();
        if found != 1 {
            return Err(format!(
                "{found} lines {start:?} ... {end:?} of the field's program, 1 expected"
            ));
        }
    }
    if find("uniform block Scene of ")? != "208 bytes" {
        return Err(format!(
            "the uniform block is {:?}, 208 bytes expected",
            find("uniform block Scene of ")?
        ));
    }
    let frames: Vec<(usize, u32, u64)> = seen.iter().filter_map(|l| frame_line(l)).collect();
    if frames.len() != FIELD_FRAMES {
        return Err(format!(
            "the field's program printed {} frame lines, {FIELD_FRAMES} expected",
            frames.len()
        ));
    }
    let mut crcs = [0u32; FIELD_FRAMES];
    for (at, (number, crc, sum)) in frames.iter().enumerate() {
        if *number != at {
            return Err(format!("frame line {at} is the one of frame {number}"));
        }
        if *sum == 0 {
            return Err(format!("frame {at} of the field is all zeros"));
        }
        crcs[at] = *crc;
    }
    let mut sorted = crcs;
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err("two frames of the turning field have the same CRC".to_owned());
    }
    if let Some(expected) = EXPECTED_FIELD_CRCS {
        for (at, crc) in crcs.iter().enumerate() {
            if *crc != expected[at] {
                return Err(format!(
                    "frame {at} of the field has the CRC {crc:08x}, {:08x} pinned",
                    expected[at]
                ));
            }
        }
    }
    for (at, crc) in crcs.iter().enumerate() {
        let prefix = format!("window frame {at} crc ");
        let mut mine = seen.iter().filter(|l| l.starts_with(&prefix));
        let line = mine
            .next()
            .ok_or_else(|| format!("the field's program printed no line {prefix:?}"))?;
        if mine.next().is_some() {
            return Err(format!("two lines {prefix:?} of the field's program"));
        }
        let text = &line[prefix.len()..];
        let wanted =
            format!("{crc:08x} matches the pbuffer, and the window holds its rows mirrored");
        if text != wanted {
            return Err(format!(
                "the window's frame {at}: {text:?}, {wanted:?} expected"
            ));
        }
    }
    let held: Vec<&&str> = seen.iter().filter(|l| l.starts_with("held crc ")).collect();
    if held.len() != 1 || !seen.last().is_some_and(|l| l.starts_with("held crc ")) {
        return Err(format!(
            "the field's program held {} times and its last line is {:?}, one \"held crc\" line as the last expected",
            held.len(),
            seen.last()
        ));
    }
    Ok(crcs)
}

/// Judges the lines of a run that need no screenshot: no check failed, the cube's
/// lines are those of `gles_window` (ending in its held CRC-32; `shots` is what the
/// screenshots at its two pauses had), the field's lines, each line of the demo came
/// once, and the demo ended with the code 0.
pub fn lines_verdict(lines: &[String], shots: [u32; 2]) -> Result<(), String> {
    if let Some(failed) = lines.iter().find_map(|l| failure(l)) {
        return Err(failed);
    }
    crate::gles_window::verdict_of(lines, shots, End::Held)?;
    field_verdict(lines)?;
    for marker in DEMO_LINES {
        let found = lines.iter().filter(|l| l.as_str() == marker).count();
        if found != 1 {
            return Err(format!("{found} lines {marker:?}, 1 expected"));
        }
    }
    if !lines.iter().any(|l| l == ENDED) {
        return Err(format!("init never printed {ENDED:?}"));
    }
    Ok(())
}

/// `lines_verdict` and the screenshots: the CRC-32 the programs held are the ones
/// the screenshots had, and the scene G is no picture of the windows as they are.
pub fn verdict(lines: &[String], seen: &Seen) -> Result<(), String> {
    lines_verdict(lines, seen.shots)?;
    let held = |prefix: &str| {
        lines
            .iter()
            .find_map(|l| l.strip_prefix(prefix))
            .and_then(|crc| u32::from_str_radix(crc, 16).ok())
            .ok_or_else(|| format!("no line {prefix:?}"))
    };
    if held(CUBE_HELD)? != seen.cube_held {
        return Err(format!(
            "the cube held {:08x}, the screenshot had {:08x}",
            held(CUBE_HELD)?,
            seen.cube_held
        ));
    }
    if held(FIELD_HELD)? != seen.field_held {
        return Err(format!(
            "the field held {:08x}, the screenshot had {:08x}",
            held(FIELD_HELD)?,
            seen.field_held
        ));
    }
    if seen.both == seen.scene_g {
        return Err("the scene G looks like the windows as they are".to_owned());
    }
    Ok(())
}

/// The compositor's kinds that must come in the run: DESCRIBE, WINDOW_CREATE,
/// ATTACH, POST, SCENE_COMMIT, and its own (a band, the end of a frame).
const COMP_KINDS: [(usize, &str); 6] = [
    (17, "Describe"),
    (18, "WindowCreate"),
    (19, "Attach"),
    (20, "Post"),
    (26, "SceneCommit"),
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

/// The steps of the compositor and of the driver while the cube and the field draw.
pub fn steps_verdict(lines: &[String]) -> Result<(crate::wfc::Rows, crate::wfc::Rows), String> {
    use crate::comp_probe::{COMP_TAG, DRIVER_TAG};
    Ok((
        crate::wfc::rows_of(lines, COMP_TAG, "compositor", &COMP_KINDS)?,
        crate::wfc::rows_of(lines, DRIVER_TAG, "display driver", &DRIVER_KINDS)?,
    ))
}

/// The services the client of Mesa calls besides the compositor and the driver, by the
/// tag init gives them in the image of the scene: the process service (`fork`, `exec`,
/// the pool of the quotas), the RAM file service (the files of the programs, the
/// sockets of the cube's child), the pipe service, the two services of the random
/// numbers (Mesa and the libc seed from them).
const CLIENT_SERVICES: [(&str, &str); 5] = [
    ("1", "process service"),
    ("2", "RAM file service"),
    ("4", "pipe service"),
    ("10", "random device driver"),
    ("11", "entropy service"),
];

/// The longest step of each service the GLES client calls (`CLIENT_SERVICES`): every
/// kind under the hard check against B, 0.9 of B and, for the own steps, the portion
/// bound. Returns the text of the report: the service and its longest kind.
pub fn client_services_verdict(lines: &[String]) -> Result<String, String> {
    let mut said = Vec::new();
    for (tag, name) in CLIENT_SERVICES {
        let rows = crate::wfc::rows_of(lines, tag, name, &[])?;
        let Some((kind, ticks, detail)) = rows.iter().max_by_key(|r| r.1) else {
            return Err(format!("the {name}: no step line (tag {tag})"));
        };
        said.push(format!("{name} kind {kind} {ticks} detail {detail}"));
    }
    Ok(said.join(", "))
}

/// The process service's gaps and the reaper (the steps image): every gap of a step of the
/// service (`service gap: 1 kind K G ticks of A`, the time the step's own thread did not run
/// and did not wait) is at most 0.9 of term B, every close of the reaper (`posix-process:
/// reaper level L N ticks`) ran at a level of at most 31, and the report names the longest
/// close and the longest notice step of each detail (0x1000 the first part of an exit, 0x8000
/// its second part, 0x2000 and up the portions of a load).
pub fn process_service_verdict(lines: &[String]) -> Result<String, String> {
    let mut gap = 0;
    let mut closed = (0u64, 0u64);
    let mut waited = (0u64, 0u64);
    let mut details: Vec<(u64, u64)> = Vec::new();
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["service", "gap:", "1", "kind", _, g, "ticks", "of", _] => {
                gap = gap.max(g.parse::<u64>().unwrap_or(0));
            }
            ["posix-process:", "reaper", "highest", "level", level] => {
                let level = level.parse::<u64>().map_err(|e| format!("{line:?}: {e}"))?;
                if level > 31 {
                    return Err(format!(
                        "the reaper closed an image object at level {level}, 31 at most"
                    ));
                }
            }
            [
                "posix-process:",
                "reaper",
                "waited",
                pauses,
                "pauses,",
                ns,
                "ns,",
                "the",
                "child",
                "uses",
                used,
                "ended",
                "by",
                why,
            ] => {
                let (pauses, ns, used) = (
                    pauses
                        .parse::<u64>()
                        .map_err(|e| format!("{line:?}: {e}"))?,
                    ns.parse::<u64>().map_err(|e| format!("{line:?}: {e}"))?,
                    used.parse::<u64>().map_err(|e| format!("{line:?}: {e}"))?,
                );
                if *why == "deadline" && used > 64 * 1024 {
                    return Err(format!(
                        "the reaper gave up after {pauses} pauses ({ns} ns): the process still used {used} bytes"
                    ));
                }
                waited = waited.max((pauses, ns));
            }
            ["posix-process:", "reaper", "level", level, ticks, "ticks"] => {
                let (level, ticks) = (
                    level.parse::<u64>().map_err(|e| format!("{line:?}: {e}"))?,
                    ticks.parse::<u64>().map_err(|e| format!("{line:?}: {e}"))?,
                );
                if level > 31 {
                    return Err(format!(
                        "the reaper closed an image object at level {level}, 31 at most"
                    ));
                }
                if ticks > closed.1 {
                    closed = (level, ticks);
                }
            }
            [
                "service",
                "step:",
                "1",
                "kind",
                "64",
                ticks,
                "ticks",
                "detail",
                detail,
                ..,
            ] => {
                if let (Ok(t), Ok(d)) = (ticks.parse::<u64>(), detail.parse::<u64>()) {
                    match details.iter_mut().find(|(k, _)| *k == d) {
                        Some(row) => row.1 = row.1.max(t),
                        None => details.push((d, t)),
                    }
                }
            }
            _ => {}
        }
    }
    if gap > gpu_probe::STEP_MAX {
        return Err(format!(
            "the process service: a gap of {gap} ticks in a step, over 0.9 of term B ({})",
            gpu_probe::STEP_MAX
        ));
    }
    details.sort_unstable();
    let rows: Vec<String> = details
        .iter()
        .map(|(d, t)| format!("detail {d:#x} {t}"))
        .collect();
    Ok(format!(
        "the process service: the widest gap {gap} ticks; the reaper's longest close {} ticks at level {}, longest wait {} pauses ({} ns); notice steps: {}",
        closed.1,
        closed.0,
        waited.0,
        waited.1,
        rows.join(", ")
    ))
}

/// The copies of the loader (feature `steps`), each kernel call of a copy with its
/// ticks: printed, and the whole copy beside them. The kernel's B bounds the portions
/// of a call, so no limit is put on them here (the process-steps probe's rule).
fn loader_text(lines: &[String]) -> String {
    let mut most = [0u64; 10];
    for line in lines {
        let Some(rest) = line.strip_prefix("loader step: kind ") else {
            continue;
        };
        let words: Vec<&str> = rest.split_whitespace().collect();
        if let [kind, ticks, "ticks", ..] = words.as_slice()
            && let (Ok(k), Ok(t)) = (kind.parse::<usize>(), ticks.parse::<u64>())
            && k < most.len()
        {
            most[k] = most[k].max(t);
        }
    }
    format!(
        "loader: a kernel call of a copy {} ticks at most (kinds 1 to 7), the whole copy {}",
        most[1..8].iter().max().copied().unwrap_or(0),
        most[9]
    )
}

/// The run under -icount: the demo does not pause for the monitor, and the steps
/// of the compositor and the driver are read from their lines.
pub fn steps(machine: &qemu::Machine) -> Result<(), String> {
    let output = run_steps_image(machine)?;
    // The numbers of the load and of the stamps are told before the verdicts of the steps.
    println!("{}", load_report(&output.lines)?);
    judge_steps(machine, &output)?;
    load_verdict(&output.lines)
}

/// `gles-probe load`: the run of the same image, with the numbers of the load beside a
/// window with no GLES and of the clock stamps, and the verdict on the load alone (the
/// verdicts of the steps are `steps`').
pub fn load(machine: &qemu::Machine) -> Result<(), String> {
    let output = run_steps_image(machine)?;
    println!("{}", load_report(&output.lines)?);
    if machine.is_hvf() {
        // The host's clock and the host's processor: the numbers are the report, and the
        // verdict of the late frames is the run under -icount's.
        println!(
            "gles-probe on {}: the load and the stamps of the cube under HVF (the release of the buffers against their due times is judged)",
            machine.name
        );
        return load_verdict_hvf(&output.lines);
    }
    load_verdict(&output.lines)
}

/// The lines of the scene proper: the demo's first part is the load (`run_load` of
/// wfc-demo), which ends with the line `LOAD_END`.
fn scene_lines(lines: &[String]) -> &[String] {
    match lines.iter().position(|l| l == LOAD_END) {
        Some(at) => &lines[at + 1..],
        None => lines,
    }
}

/// The run of the image under -icount, up to the demo's end and its marker.
fn run_steps_image(machine: &qemu::Machine) -> Result<qemu::Outcome, String> {
    run_image(machine, "boot-gles-steps.img", &STEPS_PROGRAMS)
}

fn run_image(
    machine: &qemu::Machine,
    name: &'static str,
    programs: &'static [ImageProgram],
) -> Result<qemu::Outcome, String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::GPU);
    // -icount and HVF exclude each other: the hypervisor's run keeps the host's clock.
    if !machine.is_hvf() {
        cmd.args(qemu::ICOUNT);
    }
    let output = run_until(cmd, crate::BOOT_TIMEOUT * 8, Some(ENDS), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED)?;
    if let Some(failed) = output.lines.iter().find_map(|l| failure(l)) {
        return Err(format!("gles-probe under -icount: {failed}"));
    }
    qemu::expect_marker(&output, LINE_OK)?;
    Ok(output)
}

/// The verdicts of the steps of the run.
fn judge_steps(machine: &qemu::Machine, output: &qemu::Outcome) -> Result<(), String> {
    // The screenshots are not taken here: the programs' own lines are judged.
    lines_verdict(scene_lines(&output.lines), [1, 2])
        .map_err(|e| format!("gles-probe under -icount: {e}"))?;
    let (comp, driver) = steps_verdict(&output.lines)?;
    println!(
        "{}",
        crate::frame_probe::check_waits(
            &output.lines,
            init::table::gles::STEPS_TABLE,
            "gles-probe"
        )?
    );
    let clients = client_services_verdict(&output.lines).map_err(|e| format!("gles-probe: {e}"))?;
    println!(
        "gles-probe: {}",
        process_service_verdict(&output.lines).map_err(|e| format!("gles-probe: {e}"))?
    );
    println!(
        "gles-probe: the services of the client, the longest step, ticks (0.9 of term B {}): {clients}; {}",
        gpu_probe::STEP_MAX,
        loader_text(&output.lines)
    );
    let text = |rows: &crate::wfc::Rows| -> String {
        rows.iter()
            .map(|(kind, ticks, _)| format!("kind {kind} {ticks}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "gles-probe on {}: the cube and the field of cubes under -icount; the longest steps, ticks (0.9 of term B {}, portions {}): compositor {}; driver {}; {}",
        machine.name,
        gpu_probe::STEP_MAX,
        crate::PORTION_MAX,
        text(&comp),
        text(&driver),
        crate::comp_probe::band_report(&output.lines, crate::comp_probe::COMP_TAG)
    );
    Ok(())
}

const LOAD_END: &str = "wfc-demo: load ok";
const LOAD_START: &str = "wfc-demo: load starts";
const LOAD_PREFIX: &str = "wfc-demo: load ";

/// What the paced client of the demo told of a phase: `wfc-demo: load PHASE posts P late L
/// late2 L2 take max T us mean M us wake max W us unfreed U`.
#[derive(Debug, PartialEq, Eq)]
pub struct Phase {
    pub posts: u64,
    pub late: u64,
    pub late2: u64,
    pub take_max_us: u64,
    pub take_mean_us: u64,
    pub wake_max_us: u64,
    pub unfreed: u64,
    /// The most the release of a buffer came after the time its post was due.
    pub lag_max_us: u64,
    /// The posts that were already due when the client got to them (no wake-up measured).
    pub overruns: u64,
}

fn phase_of(lines: &[String], name: &str) -> Result<Phase, String> {
    let prefix = format!("{LOAD_PREFIX}{name} posts ");
    let line = lines
        .iter()
        .find(|l| l.starts_with(&prefix))
        .ok_or_else(|| format!("no line {prefix:?} of the load"))?;
    let words: Vec<&str> = line[LOAD_PREFIX.len()..].split_whitespace().collect();
    let get = |key: &str, skip: usize| -> Result<u64, String> {
        let at = words
            .iter()
            .position(|w| *w == key)
            .ok_or_else(|| format!("{line:?}: no {key}"))?;
        words
            .get(at + skip)
            .and_then(|w| w.parse().ok())
            .ok_or_else(|| format!("{line:?}: no number after {key}"))
    };
    Ok(Phase {
        posts: get("posts", 1)?,
        late: get("late", 1)?,
        late2: get("late2", 1)?,
        take_max_us: get("take", 2)?,
        take_mean_us: get("mean", 1)?,
        wake_max_us: get("wake", 2)?,
        unfreed: get("unfreed", 1)?,
        lag_max_us: get("lag", 2)?,
        overruns: get("overrun", 1).unwrap_or(0),
    })
}

/// The longest wait of `eglSwapInterval(1)` the verdict allows, microseconds: two periods of 60 Hz.
const IFWAIT_MAX_US: u64 = 2 * 16_667;
/// The limit of the platform's wait of the swap interval (`WAIT_NS`), microseconds.
const WAIT_LIMIT_US: u64 = 1_000_000;
/// What the wake-up of the paced client may be above the longest frame of the compositor: two
/// service steps at 0.9 of B (588 us) and about 100 us of the kernel.
const WAKE_SLACK_US: u64 = 700;

/// The swaps of the cube beside the window: how many interval waits ran out (`timeout N` of
/// the line of the platform) and the longest interval wait, microseconds.
fn swap_waits(lines: &[String]) -> (u64, u64) {
    let (mut timeouts, mut longest) = (0, 0);
    for line in lines.iter().filter(|l| l.starts_with("egl-stamp: swap ")) {
        let words: Vec<&str> = line.split_whitespace().collect();
        let after = |key: &str| {
            let at = words.iter().position(|w| *w == key)?;
            words.get(at + 1)?.parse::<u64>().ok()
        };
        let ifwait = after("ifwait").unwrap_or(0);
        longest = longest.max(ifwait);
        // A platform that does not count says nothing: a wait of the whole limit is a timeout.
        timeouts += after("timeout").unwrap_or(u64::from(ifwait >= WAIT_LIMIT_US));
    }
    (timeouts, longest)
}

/// The longest frame of the compositor between the line `LOAD_START` and `LOAD_END` (`service
/// frame: T n N bands B us U`), microseconds.
fn longest_frame_us(lines: &[String]) -> u64 {
    let end = lines
        .iter()
        .position(|l| l == LOAD_END)
        .unwrap_or(lines.len());
    let start = lines[..end]
        .iter()
        .position(|l| l == LOAD_START)
        .unwrap_or(0);
    lines[start..end]
        .iter()
        .filter_map(|l| {
            let words: Vec<&str> = l.split_whitespace().collect();
            let at = words.iter().position(|w| *w == "us")?;
            if words.first() != Some(&"service") || words.get(1) != Some(&"frame:") {
                return None;
            }
            words.get(at + 1)?.parse::<u64>().ok()
        })
        .max()
        .unwrap_or(0)
}

/// The release of a buffer with the cube drawing, against the time its post was due.
fn lag_verdict(cube: &Phase) -> Result<(), String> {
    if cube.lag_max_us > IFWAIT_MAX_US {
        return Err(format!(
            "load: a buffer of the client with no GLES was released {} us after its post was due with the cube, {IFWAIT_MAX_US} at most",
            cube.lag_max_us
        ));
    }
    Ok(())
}

/// The load beside a window of a client with no GLES, the cube at level 28 below every
/// interactive level (-icount, the verdict). The client posted at least 60 times in each phase,
/// and in each phase its wake-up after a real sleep is at most the longest frame of the
/// compositor and `WAKE_SLACK_US` (the compositor prepares the image of a posted window at its
/// own level, two service steps and the kernel). The other numbers (the takes, the late
/// frames, the release lag, the waits of the swap interval and its timeouts, the cube's
/// stamps) depend on the host's clock and are in the report.
pub fn load_verdict(lines: &[String]) -> Result<(), String> {
    let quiet = phase_of(lines, "quiet")?;
    let cube = phase_of(lines, "cube")?;
    if quiet.posts < 60 || cube.posts < 60 {
        return Err(format!(
            "load: the client posted {} and {} times, 60 at least expected",
            quiet.posts, cube.posts
        ));
    }
    let frame = longest_frame_us(lines);
    for (name, phase) in [("quiet", &quiet), ("cube", &cube)] {
        if phase.wake_max_us > frame + WAKE_SLACK_US {
            return Err(format!(
                "load: the wake-up of the client reached {} us in the {name} phase, the longest frame of the compositor is {frame} us (slack {WAKE_SLACK_US})",
                phase.wake_max_us
            ));
        }
    }
    Ok(())
}

/// The verdict under HVF, on the host's clock: the release of the buffers against the time
/// their posts were due, which does not depend on the phase of the frame, and no wait of the
/// swap interval that ran out; the rest is the report.
pub fn load_verdict_hvf(lines: &[String]) -> Result<(), String> {
    lag_verdict(&phase_of(lines, "cube")?)?;
    let (timeouts, _) = swap_waits(lines);
    if timeouts != 0 {
        return Err(format!(
            "load: {timeouts} waits of the swap interval ran out"
        ));
    }
    Ok(())
}

/// The numbers of a run of stamps, in microseconds: the count, the most and the mean.
fn stat(values: &[u64]) -> String {
    match values.iter().max() {
        None => "none".to_owned(),
        Some(max) => format!(
            "{} max {max} mean {}",
            values.len(),
            values.iter().sum::<u64>() / values.len() as u64
        ),
    }
}

/// The numbers after `key` in the stamp lines that start with `prefix`.
fn stamps_of(lines: &[String], prefix: &str, key: &str) -> Vec<u64> {
    lines
        .iter()
        .filter(|l| l.starts_with(prefix))
        .filter_map(|l| {
            let words: Vec<&str> = l.split_whitespace().collect();
            if key == "us" {
                // The number before the last word: `... (interval 1) 9500 us`.
                return words.get(words.len().checked_sub(2)?)?.parse().ok();
            }
            let at = words.iter().position(|w| *w == key)?;
            words.get(at + 1)?.parse().ok()
        })
        .collect()
}

/// The report of the load and of the clock stamps (the cube's frames, the swap and the
/// copy of the frame into the window, microseconds of the clock under -icount): the
/// per-frame lines and the summary of each of the two runs of the cube, the one beside the
/// window of the client (the load) and the one of the scene.
pub fn load_report(lines: &[String]) -> Result<String, String> {
    let at = lines.iter().position(|l| l == LOAD_END);
    let (beside, alone): (&[String], &[String]) = match at {
        Some(at) => (&lines[..at], &lines[at + 1..]),
        None => (&[], lines),
    };
    let mut out = String::new();
    for (name, part) in [("beside a window with no GLES", beside), ("scene", alone)] {
        out += &format!("gles-probe: the cube, {name}:\n");
        let mut swaps: Vec<String> = Vec::new();
        for k in 0..6 {
            let draw = stamps_of(part, &format!("gles-cube: stamp frame {k} "), "draw");
            let swap = stamps_of(part, &format!("gles-cube: stamp swap {k} "), "us");
            // The platform prints its line of a swap just before the cube's.
            let egl = part
                .iter()
                .position(|l| l.starts_with(&format!("gles-cube: stamp swap {k} ")))
                .and_then(|at| at.checked_sub(1))
                .map(|at| &part[at])
                .filter(|l| l.starts_with("egl-stamp: "));
            out += &format!(
                "  frame {k}: draw {} us, swap {} us, {}\n",
                draw.first().map_or("none".to_owned(), u64::to_string),
                swap.first().map_or("none".to_owned(), u64::to_string),
                egl.map_or("no stamp of the platform", |l| l.as_str())
            );
            swaps.extend(egl.cloned());
        }
        let draw = stamps_of(part, "gles-cube: stamp frame ", "draw");
        let swap = stamps_of(&swaps, "egl-stamp: swap ", "draw");
        let copy = stamps_of(&swaps, "egl-stamp: swap ", "copy");
        let ifwait = stamps_of(&swaps, "egl-stamp: swap ", "ifwait");
        out += &format!(
            "  draw of a frame (us): {}; swap of the driver: {}; copy into the window (putImage): {}; wait of the interval: {}\n",
            stat(&draw),
            stat(&swap),
            stat(&copy),
            stat(&ifwait)
        );
    }
    for name in ["quiet", "cube"] {
        let p = phase_of(lines, name)?;
        out += &format!(
            "gles-probe: the client with no GLES, {name}: {} posts ({} overruns), wake-up late max {} us; host-dependent under -icount: late {}, over two periods {}, post to free bit max {} us mean {} us, buffers not freed {}, release after due max {} us\n",
            p.posts,
            p.overruns,
            p.wake_max_us,
            p.late,
            p.late2,
            p.take_max_us,
            p.take_mean_us,
            p.unfreed,
            p.lag_max_us
        );
    }
    let (timeouts, ifwait) = swap_waits(lines);
    out += &format!(
        "gles-probe: the cube's swaps (host-dependent under -icount, with its stamps above): {timeouts} waits of the swap interval ran out, the longest wait {ifwait} us\n"
    );
    Ok(out.trim_end().to_owned())
}

/// `cargo xtask gles-probe [pbuffer|scene|steps|load [--hvf]]`: the three boots, or one.
pub fn command(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => probe(machine, true),
        Some("pbuffer") => crate::gles_pbuffer::probe(machine),
        Some("scene") => scene(machine),
        Some("steps") => steps(machine),
        Some("load") if args.get(1).map(String::as_str) == Some("--hvf") => load(&qemu::HVF_V2_1G),
        Some("load") => load(machine),
        Some(other) => Err(format!(
            "gles-probe: unknown argument {other:?}; pbuffer, scene, steps, load or none"
        )),
    }
}

/// `cargo xtask gles-probe` and its boots in `test`.
pub fn probe(machine: &qemu::Machine, with_steps: bool) -> Result<(), String> {
    let started = Instant::now();
    crate::gles_pbuffer::probe(machine)?;
    scene(machine)?;
    if with_steps && !machine.is_hvf() {
        steps(machine)?;
    }
    println!(
        "gles-probe on {}: ok in {} s",
        machine.name,
        started.elapsed().as_secs()
    );
    Ok(())
}

/// The scene boot: the screenshots against the guests' CRC lines and the host's
/// frames.
fn scene(machine: &qemu::Machine) -> Result<(), String> {
    crate::mesa()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-gles.img", &PROGRAMS, BOOT_PROFILE)?;
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
    let who = |e: String| format!("gles-probe on {}: {e}", machine.name);
    let seen = driven.map_err(who)?;
    verdict(&outcome.lines, &seen).map_err(who)?;
    let field = field_verdict(&outcome.lines).map_err(who)?;
    println!(
        "gles-probe on {}: the cube of EGL in a window matched QEMU's screenshot at two frames and held ({:08x}); the field of 64 instanced cubes of OpenGL ES 3 drew frames {:08x}, {:08x}, {:08x} into a pbuffer and the same into a window, and its window matched the screenshot ({:08x}); scene G (the cube's window turned by 90 degrees and scaled by one half by an element of libWFC beside the field) matched the host's frame ({:08x}), the windows as they are ({:08x}); the platform of EGL refused what it must and a forked child could not swap: ok",
        machine.name,
        seen.cube_held,
        field[0],
        field[1],
        field[2],
        seen.field_held,
        seen.scene_g,
        seen.both
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CRC-32 the test's lines give frame `k`.
    fn crc_of(k: usize) -> u32 {
        EXPECTED_FIELD_CRCS.map_or(0x2000_0000 + k as u32 * 0x1111, |c| c[k])
    }

    fn field_lines() -> Vec<String> {
        let mut lines = vec![
            "gles3-demo: EGL 1.5 Mesa Project".to_owned(),
            "gles3-demo: GL_RENDERER softpipe (LLVM none)".to_owned(),
            "gles3-demo: GL_VERSION OpenGL ES 3.0 Mesa 26.3.1".to_owned(),
            "gles3-demo: uniform block Scene of 208 bytes".to_owned(),
        ];
        for k in 0..FIELD_FRAMES {
            lines.push(format!(
                "gles3-demo: frame {k} crc {:08x} sum {}",
                crc_of(k),
                700_000 + k
            ));
        }
        for k in 0..FIELD_FRAMES {
            lines.push(format!(
                "gles3-demo: window frame {k} crc {:08x} matches the pbuffer, and the window holds its rows mirrored",
                crc_of(k),
            ));
        }
        lines.push("gles3-demo: held crc 0badf00d".to_owned());
        lines
    }

    #[test]
    fn the_expected_field_passes() {
        let crcs = field_verdict(&field_lines()).unwrap();
        assert_eq!(crcs.len(), FIELD_FRAMES);
    }

    #[test]
    fn a_doubled_frame_line_with_another_crc_is_refused() {
        let mut lines = field_lines();
        let at = lines
            .iter()
            .position(|l| l.contains("frame 1 crc") && l.contains(" sum "))
            .unwrap();
        lines.insert(
            at + 1,
            "gles3-demo: frame 1 crc deadbeef sum 700001".to_owned(),
        );
        assert!(field_verdict(&lines).unwrap_err().contains("frame lines"));
        // A CRC line that does not parse is no frame line, and the count falls short.
        let mut lines = field_lines();
        let at = lines
            .iter()
            .position(|l| l.contains("frame 1 crc"))
            .unwrap();
        lines[at] = "gles3-demo: frame 1 crc zzzzzzzz sum 700001".to_owned();
        assert!(field_verdict(&lines).unwrap_err().contains("frame lines"));
    }

    #[test]
    fn a_window_frame_that_differs_from_the_pbuffers_is_refused() {
        let mut lines = field_lines();
        let at = lines
            .iter()
            .position(|l| l.contains("window frame 2 crc"))
            .unwrap();
        lines[at] = lines[at].replace(&format!("{:08x}", crc_of(2)), "00000001");
        assert!(
            field_verdict(&lines)
                .unwrap_err()
                .contains("the window's frame 2")
        );
        let mut lines = field_lines();
        let at = lines
            .iter()
            .position(|l| l.contains("window frame 0 crc"))
            .unwrap();
        lines.remove(at);
        assert!(
            field_verdict(&lines)
                .unwrap_err()
                .contains("no line \"window frame 0 crc \"")
        );
    }

    #[test]
    fn frames_alike_empty_or_out_of_order_are_refused() {
        let mut lines = field_lines();
        let at = lines
            .iter()
            .position(|l| l.contains("frame 2 crc"))
            .unwrap();
        lines[at] = format!("gles3-demo: frame 2 crc {:08x} sum 700002", crc_of(0));
        assert!(field_verdict(&lines).unwrap_err().contains("same CRC"));
        let mut lines = field_lines();
        let at = lines
            .iter()
            .position(|l| l.contains("frame 1 crc"))
            .unwrap();
        lines[at] = format!("gles3-demo: frame 1 crc {:08x} sum 0", crc_of(1));
        assert!(field_verdict(&lines).unwrap_err().contains("all zeros"));
        let mut lines = field_lines();
        let a = lines
            .iter()
            .position(|l| l.contains("frame 0 crc"))
            .unwrap();
        lines.swap(a, a + 1);
        assert!(field_verdict(&lines).unwrap_err().contains("frame line"));
    }

    #[test]
    fn the_library_the_block_and_the_end_of_the_field_are_checked() {
        let mut lines = field_lines();
        lines[1] = "gles3-demo: GL_RENDERER llvmpipe".to_owned();
        assert!(field_verdict(&lines).unwrap_err().contains("softpipe"));
        let mut lines = field_lines();
        lines[2] = "gles3-demo: GL_VERSION OpenGL ES 2.0 Mesa 26.3.1".to_owned();
        assert!(field_verdict(&lines).unwrap_err().contains("OpenGL ES 3"));
        let mut lines = field_lines();
        lines[3] = "gles3-demo: uniform block Scene of 192 bytes".to_owned();
        assert!(field_verdict(&lines).unwrap_err().contains("208 bytes"));
        let mut lines = field_lines();
        lines.pop();
        assert!(field_verdict(&lines).unwrap_err().contains("held"));
    }

    #[test]
    fn a_check_of_any_program_or_a_bad_end_is_a_failure() {
        assert!(failure("gles3-demo: check failed at line 9: x (egl 0x3000 gl 0x0)").is_some());
        assert!(failure("gles3-demo: shader did not compile: x").is_some());
        assert!(failure("wfc-demo: check failed at line 9: x (errno 0, error 0)").is_some());
        assert!(failure("gles-cube: check failed at line 9: x (egl 0x3000 gl 0x0)").is_some());
        assert!(failure("init: wfc-demo ended: exit code 20, not restarted").is_some());
        assert!(failure(ENDED).is_none());
        assert!(failure("gles3-demo: held crc 0badf00d").is_none());
    }

    /// A copy of the platform that flips the rows fails the program's own check
    /// (the window is not the mirror of the readback), and the run fails with it.
    #[test]
    fn a_window_that_does_not_mirror_the_readback_fails_the_run() {
        let line = "gles-cube: check failed at line 478: swap_window_matches_readback(shown, size) (egl 0x3000 gl 0x0)";
        assert!(failure(line).is_some());
        let mut lines = vec![line.to_owned()];
        lines.extend(field_lines());
        assert!(
            lines_verdict(&lines, [1, 2])
                .unwrap_err()
                .contains("check failed")
        );
    }

    #[test]
    fn the_images_name_the_programs_the_demo_starts() {
        for table in [&PROGRAMS, &STEPS_PROGRAMS] {
            for name in ["wfc-demo", "gles-cube", "gles3-demo", "compositor"] {
                assert!(table.iter().any(|p| p.0 == name), "{name}");
            }
        }
        assert!(PROGRAMS[0].3.contains(&"table-gles"));
        assert!(STEPS_PROGRAMS[0].3.contains(&"table-gles-steps"));
    }

    fn service_lines(ticks: u64) -> Vec<String> {
        let mut lines = Vec::new();
        for (tag, _) in CLIENT_SERVICES {
            lines.push(format!("service step: {tag} kind 3 1200 ticks"));
        }
        lines.push(format!("service step: 2 kind 10 {ticks} ticks"));
        lines
    }

    #[test]
    fn the_services_of_the_client_pass_under_the_gate_and_fail_over_it() {
        let said = client_services_verdict(&service_lines(5000)).unwrap();
        assert!(said.contains("RAM file service kind 10 5000"), "{said}");
        let err = client_services_verdict(&service_lines(gpu_probe::STEP_MAX + 1)).unwrap_err();
        assert!(err.contains("RAM file service"), "{err}");
    }

    #[test]
    fn a_service_without_step_lines_is_refused() {
        assert!(client_services_verdict(&[]).is_err());
    }

    #[test]
    fn the_loader_text_names_the_calls_and_the_whole_copy() {
        let lines = vec![
            "loader step: kind 2 900 ticks detail 4096".to_owned(),
            "loader step: kind 4 5000 ticks detail 4096".to_owned(),
            "loader step: kind 9 70000 ticks detail 7".to_owned(),
        ];
        let text = loader_text(&lines);
        assert!(
            text.contains("5000 ticks at most") && text.ends_with("copy 70000"),
            "{text}"
        );
    }

    #[test]
    fn the_gap_of_the_process_service_and_the_level_of_the_reaper_are_judged() {
        let ok = vec![
            "service gap: 1 kind 64 2113 ticks of 9641".to_owned(),
            "service gap: 2 kind 64 900000 ticks of 900100".to_owned(),
            "posix-process: reaper level 28 1200000 ticks".to_owned(),
            "posix-process: reaper highest level 28".to_owned(),
            "posix-process: reaper waited 29 pauses, 1886650 ns, the child uses 28672 ended by drained".to_owned(),
            "service step: 1 kind 64 6500 ticks detail 4096".to_owned(),
            "service step: 1 kind 64 9900 ticks detail 32768".to_owned(),
        ];
        let said = process_service_verdict(&ok).unwrap();
        assert!(
            said.contains("gap 2113")
                && said.contains("1200000 ticks at level 28")
                && said.contains("longest wait 29 pauses (1886650 ns)"),
            "{said}"
        );
        assert!(
            said.contains("detail 0x1000 6500, detail 0x8000 9900"),
            "{said}"
        );
        let mut wide = ok.clone();
        wide.push("service gap: 1 kind 64 1218768 ticks of 1230164".to_owned());
        assert!(process_service_verdict(&wide).is_err());
        let mut high = ok.clone();
        high.push("posix-process: reaper level 52 10 ticks".to_owned());
        assert!(process_service_verdict(&high).is_err());
        let mut highest = ok.clone();
        highest.push("posix-process: reaper highest level 52".to_owned());
        assert!(process_service_verdict(&highest).is_err());
        let mut gave_up = ok.clone();
        gave_up.push(
            "posix-process: reaper waited 100 pauses, 100000000 ns, the child uses 9932800 ended by deadline"
                .to_owned(),
        );
        assert!(process_service_verdict(&gave_up).is_err());
        // A wait that a higher place ended leaves the pages to the queue: not judged.
        let mut yielded = ok;
        yielded.push(
            "posix-process: reaper waited 3 pauses, 3000000 ns, the child uses 9932800 ended by higher"
                .to_owned(),
        );
        assert!(process_service_verdict(&yielded).is_ok());
    }

    fn load_lines(cube_lag_us: u64, cube_wake_us: u64) -> Vec<String> {
        let mut lines = Vec::new();
        // A long frame before the load starts is not the load's.
        lines.push("service frame: 17 n 3 bands 4 us 151703".to_owned());
        lines.push(LOAD_START.to_owned());
        for k in 0..6 {
            lines.push(format!(
                "gles-cube: stamp frame {k} draw {} us",
                650_000 + k
            ));
            lines.push(format!(
                "egl-stamp: swap wait 3 draw {} copy 200 post 40 ifwait 9000 us timeout 0",
                400 + k
            ));
            lines.push(format!("gles-cube: stamp swap {k} (interval 1) 9500 us"));
        }
        lines.push("service frame: 17 n 24 bands 4 us 3000".to_owned());
        lines.push(format!(
            "wfc-demo: load cube posts 600 late 4 late2 0 take max 18000 us mean 8100 us wake max {cube_wake_us} us unfreed 0 lag max {cube_lag_us} us overrun 0"
        ));
        lines.push(
            "wfc-demo: load quiet posts 600 late 0 late2 0 take max 17000 us mean 8000 us wake max 120 us unfreed 0 lag max 9000 us overrun 0"
                .to_owned(),
        );
        lines.push(LOAD_END.to_owned());
        lines
    }

    #[test]
    fn the_load_with_the_wake_ups_in_time_passes_and_is_reported() {
        let lines = load_lines(20_000, 3_000);
        load_verdict(&lines).unwrap();
        load_verdict_hvf(&lines).unwrap();
        let report = load_report(&lines).unwrap();
        assert!(
            report.contains("copy into the window (putImage): 6 max 200 mean 200"),
            "{report}"
        );
        assert!(
            report.contains("frame 3: draw 650003 us, swap 9500 us, egl-stamp: swap wait 3"),
            "{report}"
        );
        assert!(
            report.contains("release after due max 20000 us"),
            "{report}"
        );
        assert!(report.contains("(0 overruns)"), "{report}");
        assert!(report.contains("host-dependent under -icount"), "{report}");
        assert!(
            report.contains("0 waits of the swap interval ran out"),
            "{report}"
        );
    }

    #[test]
    fn a_wake_up_after_a_real_sleep_is_judged_against_the_longest_frame_of_the_load() {
        // The longest frame between the start and the end is 3000 us.
        assert!(load_verdict(&load_lines(0, 3000 + 700)).is_ok());
        assert!(
            load_verdict(&load_lines(0, 3000 + 701))
                .unwrap_err()
                .contains("cube phase")
        );
        // The quiet phase is judged the same way.
        let mut lines = load_lines(0, 300);
        let at = lines.iter().position(|l| l.contains("load quiet")).unwrap();
        lines[at] = lines[at].replace("wake max 120", "wake max 4000");
        assert!(load_verdict(&lines).unwrap_err().contains("quiet phase"));
    }

    #[test]
    fn overruns_with_a_late_release_a_timeout_and_a_long_wait_do_not_fail_under_icount() {
        // A client that overran its posts (busy or starved) has no wake-up to judge; the
        // lag, the late frames, the timeouts and the waits are the report's.
        let mut lines = load_lines(63_000, 300);
        let at = lines.iter().position(|l| l.contains("load quiet")).unwrap();
        lines[at] = lines[at].replace("overrun 0", "overrun 590");
        let swap = lines
            .iter()
            .position(|l| l.starts_with("egl-stamp"))
            .unwrap();
        lines[swap] =
            lines[swap].replace("ifwait 9000 us timeout 0", "ifwait 1000047 us timeout 1");
        load_verdict(&lines).unwrap();
        let report = load_report(&lines).unwrap();
        assert!(report.contains("(590 overruns)"), "{report}");
        assert!(
            report.contains("1 waits of the swap interval ran out"),
            "{report}"
        );
    }

    #[test]
    fn under_hvf_a_late_release_and_a_timeout_fail() {
        assert!(load_verdict_hvf(&load_lines(40_000, 300)).is_err());
        let mut lines = load_lines(0, 300);
        let swap = lines
            .iter()
            .position(|l| l.starts_with("egl-stamp"))
            .unwrap();
        lines[swap] = lines[swap].replace("timeout 0", "timeout 1");
        assert!(load_verdict_hvf(&lines).unwrap_err().contains("ran out"));
        // A platform that does not count says nothing: a wait of the whole limit is a timeout.
        let mut lines = load_lines(0, 300);
        lines[3] = lines[3].replace("ifwait 9000 us timeout 0", "ifwait 1000942 us");
        assert!(load_verdict_hvf(&lines).is_err());
    }

    #[test]
    fn a_missing_overrun_is_zero() {
        let lines = vec![
            "wfc-demo: load cube posts 600 late 4 late2 0 take max 18000 us mean 8100 us wake max 300 us unfreed 0 lag max 100 us"
                .to_owned(),
        ];
        assert_eq!(phase_of(&lines, "cube").unwrap().overruns, 0);
    }

    #[test]
    fn a_load_that_did_not_post_or_is_missing_fails() {
        assert!(load_verdict(&[]).is_err());
        let mut lines = load_lines(0, 300);
        let at = lines.iter().position(|l| l.contains("load quiet")).unwrap();
        lines[at] = lines[at].replace("posts 600", "posts 5");
        assert!(load_verdict(&lines).unwrap_err().contains("60 at least"));
    }
}
