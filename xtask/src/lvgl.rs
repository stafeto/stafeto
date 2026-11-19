// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the LVGL demo (stage G4, `cargo xtask lvgl-probe`) and the run
//! by hand (`cargo xtask lvgl`).
//!
//! The image `boot-lvgl.img` (lvgl_image.rs, table `table::lvgl`) has the
//! shell, the compositor with the tablet's driver and the injector
//! `lvgl-inject`. The probe types `lvgl-demo --probe --evidence` into the
//! shell. The demo makes its window, settles its first frame, prints the
//! CRC-32 of it (`lvgl-demo: first crc`), and waits two seconds for the
//! screenshot; xtask takes it from the monitor of QEMU. The injector sees the
//! window and injects the 22 events of the scenario; the demo collects all of
//! them with no turn of its clock, runs the scenario one change at a time and
//! prints `lvgl-demo: after crc`, which gets a screenshot too.
//!
//! Three numbers say whether a frame is right: the guest's CRC, the CRC of
//! QEMU's screenshot (the path from the demo's buffer to the screen of the
//! service and the driver) and the CRC the reference program on the host
//! (`target/lvgl-host/lvgl-ref`, tools/lvgl-ref) draws from the same sources
//! and the same font (the arithmetic of LVGL and FreeType). Besides the frames
//! the probe compares exactly what both print: the state line, the turns and
//! the frames of the loop, the glyph evidence lines (the hinted outline and
//! the bitmap of `a g W 0`, the multiple-masters flag, the kerning of `AV`),
//! the CRC of each band of 16 rows of both frames, and the largest use of
//! LVGL's pool. The guest prints no `interpreter-version` line (it has no
//! property call, and FreeType's configuration forbids one), so that one line
//! of the reference is left out of the comparison. The events the demo took
//! are counted by kind (4 keys, 6 moves, 12 buttons) with no `LOST`.
//!
//! A second run, under -icount on `boot-lvgl-steps.img`, repeats the same
//! lines and holds the steps of the compositor, of the display driver and of
//! the tablet's driver to the bounds (STEP_MAX per step, PORTION_MAX per
//! portion), as focus-probe does.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use super::*;
use crate::gpu_probe::{self, Scratch};
use crate::monitor::Monitor;
use crate::{comp_probe, focus_probe, lvgl_image, qemu};

/// What the shell is told in the probe, and with `--quick` in the run under
/// -icount (no seconds for a screenshot).
const LAUNCH: &str = "lvgl-demo --probe --evidence";
const LAUNCH_QUICK: &str = "lvgl-demo --probe --evidence --quick";
/// The prefixes of the lines of the demo and of the reference program.
const GUEST: &str = "lvgl-demo: ";
const HOST: &str = "lvgl-ref: ";
const FIRST: &str = "lvgl-demo: first crc ";
const AFTER: &str = "lvgl-demo: after crc ";
/// The last line the demo prints.
const LAST: &str = "lvgl-demo: frames ";
/// The line of the reference that the guest has no counterpart of.
const HOST_ONLY: &str = "evidence truetype interpreter-version";
/// How long the first frame and the scenario may take on QEMU's emulation,
/// and under -icount.
const WITHIN: Duration = Duration::from_secs(180);
const SLOW: Duration = Duration::from_secs(1800);
/// The whole probe may take this long.
const PROBE_WITHIN: Duration = Duration::from_secs(600);
/// The rows of a band of the frame CRCs the evidence prints.
const BAND_ROWS: usize = 16;

/// The scene header, the one source of the scenario's events.
const SCENE: &str = include_str!("../../ports/lvgl/scene.h");

/// How many events of each kind the scenario has: keys, moves, buttons,
/// counted in the rows of `SCENE_EVENT_ROWS`.
fn scene_kinds() -> (u32, u32, u32) {
    let start = SCENE
        .find("#define SCENE_EVENT_ROWS")
        .expect("scene.h has SCENE_EVENT_ROWS");
    let end = SCENE[start..]
        .find("#define SCENE_STATE_FORMAT")
        .map_or(SCENE.len(), |n| start + n);
    let (mut keys, mut moves, mut buttons) = (0, 0, 0);
    for group in SCENE[start..end].split('{').skip(1) {
        match group.split(',').next().map(str::trim) {
            Some("1") => keys += 1,
            Some("2") => moves += 1,
            Some("3") => buttons += 1,
            _ => {}
        }
    }
    (keys, moves, buttons)
}

/// The events the demo took, by kind, as its `events` line says.
#[derive(Debug, PartialEq, Eq)]
pub struct Events {
    pub key: u32,
    pub moved: u32,
    pub button: u32,
    pub focus_in: u32,
    pub focus_out: u32,
    pub lost: u32,
}

/// What a run printed, as far as the probe judges it: the bodies of the lines
/// of the demo (or of the reference), prefix off.
#[derive(Debug, Default)]
pub struct Report {
    pub first_crc: u32,
    pub after_crc: u32,
    pub state: String,
    pub turns: u32,
    pub frames: u32,
    pub mem_max_used: u64,
    /// The evidence lines, in order, but the bands.
    pub evidence: Vec<String>,
    pub bands_first: Vec<u32>,
    pub bands_after: Vec<u32>,
    /// The guest alone: the events, the process's memory and the frame times.
    pub events: Option<Events>,
    pub memory: Option<String>,
    pub timing: Option<String>,
}

/// The lines of `lines` that start with `prefix`, prefix off.
fn bodies<'a>(lines: &'a [String], prefix: &str) -> Vec<&'a str> {
    lines
        .iter()
        .filter_map(|l| l.strip_prefix(prefix))
        .map(str::trim_end)
        .collect()
}

fn hex(text: &str) -> Result<u32, String> {
    u32::from_str_radix(text.trim(), 16).map_err(|e| format!("{text:?} is no CRC: {e}"))
}

/// The one line that starts with `start` among `body`: none or several is an
/// error that names them.
fn one<'a>(who: &str, body: &[&'a str], start: &str) -> Result<&'a str, String> {
    let found: Vec<&&str> = body.iter().filter(|l| l.starts_with(start)).collect();
    match found.as_slice() {
        [line] => Ok(line[start.len()..].trim()),
        _ => Err(format!(
            "{} lines {start:?} of {who}, 1 expected: {found:?}",
            found.len()
        )),
    }
}

/// The CRCs of a bands line (`evidence bands first C0 C1 ...`).
fn bands(body: &[&str], which: &str) -> Result<Vec<u32>, String> {
    let start = format!("evidence bands {which} ");
    let line = one("the bands", body, &start)?;
    line.split_whitespace().map(hex).collect()
}

/// A number after `word` in `text` (`events key 4 move 6 ...`).
fn after(text: &str, word: &str) -> Result<u32, String> {
    let mut words = text.split_whitespace();
    while let Some(w) = words.next() {
        if w == word {
            return words
                .next()
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| format!("no number after {word:?} in {text:?}"));
        }
    }
    Err(format!("no {word:?} in {text:?}"))
}

/// The lines of the demo that are faults whatever their place: the demo
/// says so itself, or LVGL logged a warning, an error or an assertion.
const FAULTS: [&str; 14] = [
    "LOST",
    "lvgl: [",
    "cannot open the window",
    "cannot post",
    "cannot take events",
    "the display is gone",
    "the display ended",
    "the display service ended",
    "did not settle",
    "did not finish",
    "input events came",
    "did not reach the screen",
    "evidence failed",
    "cannot open the font",
];

/// Parses the lines of a run of the demo (`GUEST` prefix) or of the reference
/// program (`HOST` prefix). A fault line, a line the report does not know and
/// a line that comes twice or not at all are errors.
pub fn parse(lines: &[String], prefix: &str) -> Result<Report, String> {
    let who = prefix.trim_end_matches(": ");
    let body = bodies(lines, prefix);
    if let Some(fault) = body
        .iter()
        .find(|l| FAULTS.iter().any(|f| l.contains(f)) || l.starts_with("still waiting"))
    {
        return Err(format!("{who}: {fault}"));
    }
    let first_crc = hex(one(who, &body, "first crc ")?)?;
    let after_crc = hex(one(who, &body, "after crc ")?)?;
    let state = one(who, &body, "state ")?.to_owned();
    let turns_line = one(who, &body, "turns ")?;
    let turns = turns_line
        .split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("{who}: the turns line {turns_line:?}"))?;
    let frames = after(turns_line, "frames")?;
    let mem_max_used = one(who, &body, "mem max-used ")?
        .parse()
        .map_err(|e| format!("{who}: mem max-used: {e}"))?;
    let evidence: Vec<String> = body
        .iter()
        .filter(|l| l.starts_with("evidence ") && !l.starts_with("evidence bands "))
        .map(|l| (*l).to_owned())
        .collect();
    let mut report = Report {
        first_crc,
        after_crc,
        state,
        turns,
        frames,
        mem_max_used,
        evidence,
        bands_first: bands(&body, "first").map_err(|e| format!("{who}: {e}"))?,
        bands_after: bands(&body, "after").map_err(|e| format!("{who}: {e}"))?,
        ..Report::default()
    };
    if prefix == GUEST {
        let events = one(who, &body, "events ")?;
        report.events = Some(Events {
            key: after(events, "key")?,
            moved: after(events, "move")?,
            button: after(events, "button")?,
            focus_in: after(events, "focus-in")?,
            focus_out: after(events, "focus-out")?,
            lost: after(events, "lost")?,
        });
        report.memory = Some(one(who, &body, "memory ")?.to_owned());
        report.timing = Some(one(who, &body, "frames ")?.to_owned());
    }
    // Every other line of the demo is a line the probe does not know.
    let known = [
        "first crc ",
        "after crc ",
        "state ",
        "turns ",
        "mem max-used ",
        "evidence ",
        "events ",
        "memory ",
        "frames ",
    ];
    if let Some(odd) = body
        .iter()
        .find(|l| !known.iter().any(|k| l.starts_with(k)))
    {
        return Err(format!("{who}: a line the probe does not know: {odd:?}"));
    }
    Ok(report)
}

/// The bands (16 rows each) in which two lists of band CRCs differ, with
/// their rows.
fn differing_bands(guest: &[u32], host: &[u32]) -> String {
    let mut named = Vec::new();
    for (i, (g, h)) in guest.iter().zip(host).enumerate() {
        if g != h {
            named.push(format!(
                "band {i} (rows {}..{}) guest {g:08X} host {h:08X}",
                i * BAND_ROWS,
                (i + 1) * BAND_ROWS - 1
            ));
        }
    }
    if guest.len() != host.len() {
        named.push(format!(
            "the guest has {} bands and the host {}",
            guest.len(),
            host.len()
        ));
    }
    if named.is_empty() {
        "no band differs (the frames agree row by row)".to_owned()
    } else {
        named.join("; ")
    }
}

/// The evidence lines of the guest against the host's, but the one the guest
/// does not print: `None` when they agree, else the first difference.
fn evidence_difference(guest: &Report, host: &Report) -> Option<String> {
    let host_lines: Vec<&String> = host
        .evidence
        .iter()
        .filter(|l| !l.starts_with(HOST_ONLY))
        .collect();
    let guest_lines: Vec<&String> = guest.evidence.iter().collect();
    for i in 0..guest_lines.len().max(host_lines.len()) {
        let (g, h) = (guest_lines.get(i), host_lines.get(i));
        if g != h {
            return Some(format!("line {i}: guest {g:?}, host {h:?}"));
        }
    }
    None
}

/// Judges the guest's report against the reference's: the events, then the two
/// frames' CRCs (with the evidence and the differing bands in the message),
/// the evidence, the state, the turns, the frames and the use of the pool. The
/// text is what the verdict printed on success.
pub fn verdict(guest: &Report, host: &Report) -> Result<String, String> {
    let (keys, moves, buttons) = scene_kinds();
    let events = guest
        .events
        .as_ref()
        .ok_or("the guest's report has no events line")?;
    if events.lost != 0 {
        return Err(format!(
            "the ring of the window dropped events (lost {}): {events:?}",
            events.lost
        ));
    }
    if (events.key, events.moved, events.button) != (keys, moves, buttons) {
        return Err(format!(
            "the demo took {} keys, {} moves and {} buttons, {keys}, {moves} and {buttons} expected: {events:?}",
            events.key, events.moved, events.button
        ));
    }
    let evidence = evidence_difference(guest, host);
    let evidence_note = match &evidence {
        None => "the glyph evidence lines agree".to_owned(),
        Some(d) => format!("the glyph evidence lines differ ({d})"),
    };
    for (frame, g, h, gb, hb) in [
        (
            "first",
            guest.first_crc,
            host.first_crc,
            &guest.bands_first,
            &host.bands_first,
        ),
        (
            "after",
            guest.after_crc,
            host.after_crc,
            &guest.bands_after,
            &host.bands_after,
        ),
    ] {
        if g != h {
            return Err(format!(
                "the {frame} frame: the guest's CRC-32 is {g:08X}, the host reference's {h:08X}; {evidence_note}; bands that differ: {}",
                differing_bands(gb, hb)
            ));
        }
    }
    if let Some(d) = evidence {
        return Err(format!(
            "the glyph evidence lines differ while the CRCs agree: {d}"
        ));
    }
    for (what, g, h) in [
        ("state", guest.state.clone(), host.state.clone()),
        ("turns", guest.turns.to_string(), host.turns.to_string()),
        ("frames", guest.frames.to_string(), host.frames.to_string()),
        (
            "mem max-used",
            guest.mem_max_used.to_string(),
            host.mem_max_used.to_string(),
        ),
    ] {
        if g != h {
            return Err(format!(
                "the {what} of the guest is {g:?}, the host's {h:?}"
            ));
        }
    }
    if guest.bands_first != host.bands_first || guest.bands_after != host.bands_after {
        return Err(format!(
            "the bands differ while the CRCs agree: first {}; after {}",
            differing_bands(&guest.bands_first, &host.bands_first),
            differing_bands(&guest.bands_after, &host.bands_after)
        ));
    }
    Ok(format!(
        "first crc {:08X}, after crc {:08X}, state {:?}, {} turns, {} frames, pool max {} bytes, {} evidence lines and {} + {} band CRCs equal to the host's ({HOST_ONLY} is the reference's alone); the demo took {} keys, {} moves, {} buttons, {} focus-in and {} focus-out events, lost {}",
        guest.first_crc,
        guest.after_crc,
        guest.state,
        guest.turns,
        guest.frames,
        guest.mem_max_used,
        guest.evidence.len(),
        guest.bands_first.len(),
        guest.bands_after.len(),
        events.key,
        events.moved,
        events.button,
        events.focus_in,
        events.focus_out,
        events.lost
    ))
}

/// The CRCs of one frame: the guest's line, QEMU's screenshot, the host's
/// reference. All three equal, or the message says which path changed the
/// pixels.
pub fn three_way(frame: &str, guest: u32, shot: u32, host: u32) -> Result<(), String> {
    if shot != guest {
        return Err(format!(
            "the {frame} frame: the screenshot's CRC-32 is {shot:08X}, the demo's own {guest:08X} (the host reference {host:08X}): the pixels changed between the demo's buffer and QEMU's screen (the service, the driver or the device)"
        ));
    }
    if guest != host {
        return Err(format!(
            "the {frame} frame: the screenshot agrees with the demo's CRC-32 {guest:08X}, the host reference has {host:08X}: the demo draws other pixels in the guest than on the host (see the evidence lines and the bands)"
        ));
    }
    Ok(())
}

/// The message of a screenshot anchor that never came: which line the probe
/// waited for and the lines of the demo it did see.
pub fn missing_anchor(anchor: &str, lines: &[String], why: &str) -> String {
    let seen: Vec<&String> = lines.iter().filter(|l| l.starts_with(GUEST)).collect();
    format!(
        "no line {anchor:?} to anchor a screenshot on ({why}); the lines of the demo so far: {seen:?}"
    )
}

/// The reference program's report: runs `target/lvgl-host/lvgl-ref` with the
/// evidence (building it with `tools/build-lvgl.py --host` when missing).
pub fn reference() -> Result<Report, String> {
    let root = root();
    let program = root.join("target/lvgl-host/lvgl-ref");
    if !program.exists() {
        run_cmd(
            Command::new("python3")
                .arg(root.join("tools/build-lvgl.py"))
                .arg("--host"),
        )?;
    }
    let font =
        root.join("target/lvgl-host/lvgl-9.6.0/src/libs/freetype/LiberationSans-Regular.ttf");
    let out = Command::new(&program)
        .arg("--evidence")
        .arg(&font)
        .output()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    if !out.status.success() {
        return Err(format!(
            "{} ended with {}: {}",
            program.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    parse(&lines, HOST)
}

/// The lines of the demo in a transcript, for a failure message.
fn demo_lines(lines: &[String]) -> Vec<&String> {
    lines.iter().filter(|l| l.starts_with(GUEST)).collect()
}

/// The scripts the image needs: relibc, BusyBox, the add-ons of the shell
/// image and the package `lvgl` with FreeType.
fn build_lvgl() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    nano_build()?;
    packages_built_where(|p| p.name == "lvgl")
}

/// The command line of a run with a screen nobody looks at, a serial line on
/// stdio and the monitor on the socket of `scratch`; the tablet is the
/// pointer's device.
fn probe_command(
    machine: &qemu::Machine,
    kernel: &Path,
    image: &Path,
    scratch: &Scratch,
) -> Command {
    let mut cmd = qemu::command(machine, kernel, Some(image));
    cmd.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    cmd.arg(format!(
        "unix:{},server=on,wait=off",
        scratch.socket().display()
    ));
    cmd.args(qemu::GPU);
    cmd.args(qemu::TABLET);
    cmd
}

/// Waits for the line `prefix` of the demo, with the anchor's message when it
/// does not come.
fn anchor(run: &mut qemu::Run, prefix: &str, within: Duration) -> Result<String, String> {
    run.expect_line(prefix, |l| l.starts_with(prefix), within)
        .map_err(|e| missing_anchor(prefix, &run.text(), &e))
}

/// Follows the run: the screenshots after the two CRC lines against the
/// guest's and the host's, then the end of the demo.
fn drive(run: &mut qemu::Run, scratch: &Scratch, host: &Report) -> Result<(), String> {
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
    run.expect("# ", DIALOG_STEP)?;
    run.send(LAUNCH)?;
    for (prefix, frame, wanted) in [
        (FIRST, "first", host.first_crc),
        (AFTER, "after", host.after_crc),
    ] {
        let line = anchor(run, prefix, WITHIN)?;
        let guest = gpu_probe::crc_of(&line, prefix)?;
        let shot = monitor.screendump(&scratch.picture())?;
        if (shot.width, shot.height) != (640, 400) {
            return Err(format!(
                "the screenshot after {prefix:?} is {}x{}, 640x400 expected",
                shot.width, shot.height
            ));
        }
        let shot = shot.crc32();
        three_way(frame, guest, shot, wanted)?;
    }
    anchor(run, LAST, WITHIN)?;
    run.expect("# ", DIALOG_STEP)?;
    run.send("echo rc=$?")?;
    run.expect_line("the exit code of the demo", |l| l == "rc=0", DIALOG_STEP)?;
    Ok(())
}

/// What the probe tells of the demo's memory: its line, as the guest printed it.
fn memory_note(report: &Report) -> String {
    format!(
        "{} (the plan estimates about 1650 pages; the quota of a shell child in the games table is 3072)",
        report.memory.as_deref().unwrap_or("no memory line")
    )
}

/// `cargo xtask lvgl-probe [--hvf]`: the probe on `machine`; on QEMU's own
/// emulation the run under -icount after it.
pub fn probe(machine: &'static qemu::Machine) -> Result<(), String> {
    build_lvgl()?;
    let host = reference()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(lvgl_image::IMAGE, lvgl_image::programs(), BOOT_PROFILE)?;
    packages::check()?;
    let scratch = Scratch::new()?;
    let cmd = probe_command(machine, &kernel.image, &image, &scratch);
    let began = Instant::now();
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let driven = drive(&mut run, &scratch, &host);
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    driven.map_err(|e| format!("lvgl-probe on {}: {e}", machine.name))?;
    if began.elapsed() > PROBE_WITHIN {
        return Err(format!(
            "lvgl-probe on {}: {:.0} s, {} s at most",
            machine.name,
            began.elapsed().as_secs_f64(),
            PROBE_WITHIN.as_secs()
        ));
    }
    if let Some(line) = faulted(&output.lines) {
        return Err(format!(
            "lvgl-probe on {}: the image faulted: {line}",
            machine.name
        ));
    }
    let guest = parse(&output.lines, GUEST).map_err(|e| {
        format!(
            "lvgl-probe on {}: {e}; lines of the demo: {:?}",
            machine.name,
            demo_lines(&output.lines)
        )
    })?;
    let said =
        verdict(&guest, &host).map_err(|e| format!("lvgl-probe on {}: {e}", machine.name))?;
    println!(
        "lvgl-probe on {}: the screenshots of QEMU, the demo's CRCs and the host reference's agree for the first frame and for the frame after the scenario; {said}; memory of the demo: {}; {} s in all",
        machine.name,
        memory_note(&guest),
        began.elapsed().as_secs()
    );
    if !machine.is_hvf() {
        steps(machine, &host)?;
    }
    Ok(())
}

/// The lines that say a process or the kernel faulted.
fn faulted(lines: &[String]) -> Option<&String> {
    lines.iter().find(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("I/O error")
    })
}

/// The kinds of the compositor's steps the demo and the injector make:
/// DESCRIBE, WINDOW_CREATE, ATTACH, POST, EVENTS, INJECT and its own (a band
/// of a frame and the end of a frame). No manager, so no MANAGE.
const COMP_KINDS: [(usize, &str); 7] = [
    (17, "Describe"),
    (18, "WindowCreate"),
    (19, "Attach"),
    (20, "Post"),
    (21, "Events"),
    (23, "Inject"),
    (65, "a band of a frame and the end of a frame"),
];
/// The display driver's: the compositor opens the screen (PIPELINES,
/// SOURCE), and its own (the interrupt).
const DRIVER_KINDS: [(usize, &str); 3] = [(9, "Pipelines"), (10, "Source"), (65, "the interrupt")];
/// The tablet driver's: GRANT (no event comes from the device: the keys and
/// the pointer are injected).
const INPUT_KINDS: [(usize, &str); 1] = [(1, "Grant")];
const INPUT_TAG: &str = "13";

/// The run under -icount on `boot-lvgl-steps.img`: the same lines against the
/// host's, no screenshots, and the longest steps of the three services under
/// the bounds.
fn steps(machine: &'static qemu::Machine, host: &Report) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        lvgl_image::STEPS_IMAGE,
        lvgl_image::steps_programs(),
        BOOT_PROFILE,
    )?;
    let scratch = Scratch::new()?;
    let mut cmd = probe_command(machine, &kernel.image, &image, &scratch);
    cmd.args(qemu::ICOUNT);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let driven = (|| {
        run.expect(SERVICES_STARTED, SLOW)?;
        run.expect("# ", SLOW)?;
        run.send(LAUNCH_QUICK)?;
        anchor(&mut run, LAST, SLOW)?;
        run.expect("# ", SLOW)?;
        run.send("echo rc=$?")?;
        run.expect_line("the exit code of the demo", |l| l == "rc=0", SLOW)?;
        Ok::<(), String>(())
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    driven.map_err(|e| format!("lvgl-probe under -icount: {e}"))?;
    if let Some(line) = faulted(&output.lines) {
        return Err(format!(
            "lvgl-probe under -icount: the image faulted: {line}"
        ));
    }
    let guest = parse(&output.lines, GUEST).map_err(|e| {
        format!(
            "lvgl-probe under -icount: {e}; lines of the demo: {:?}",
            demo_lines(&output.lines)
        )
    })?;
    let said = verdict(&guest, host).map_err(|e| format!("lvgl-probe under -icount: {e}"))?;
    let comp = focus_probe::rows_of(
        &output.lines,
        comp_probe::COMP_TAG,
        "compositor",
        &COMP_KINDS,
    )?;
    let input = focus_probe::rows_of(&output.lines, INPUT_TAG, "tablet's driver", &INPUT_KINDS)?;
    let driver = focus_probe::rows_of(
        &output.lines,
        comp_probe::DRIVER_TAG,
        "display driver",
        &DRIVER_KINDS,
    )?;
    check_waits(
        &output.lines,
        &[comp_probe::COMP_TAG, INPUT_TAG, comp_probe::DRIVER_TAG],
        "lvgl-probe",
    )?;
    let text = |rows: &[(usize, u64, u64)]| -> String {
        rows.iter()
            .map(|(kind, ticks, _)| format!("kind {kind} {ticks}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "lvgl-probe on {} under -icount: the same lines as the host's ({said}); the longest steps, ticks (0.9 of term B {}, portions {PORTION_MAX}): compositor {}; tablet's driver {}; display driver {}; the demo's frame times under -icount (virtual): {}",
        machine.name,
        gpu_probe::STEP_MAX,
        text(&comp),
        text(&input),
        text(&driver),
        guest.timing.as_deref().unwrap_or("none")
    );
    Ok(())
}

/// `cargo xtask lvgl [--machine hvf]`: QEMU with the window of the screen
/// (cocoa on a Mac) and the console on the terminal, to try the demo by hand.
/// At the prompt of ash type `lvgl-demo`. The pointer is the window's tablet:
/// click the button, the check box, the switch and the slider. The keys of the
/// window's keyboard do not reach the demo (the image has no keyboard's
/// driver: the keyboard and the tablet share a page of transports), and the
/// injector of the probe plays the scenario once when the window opens.
/// Ctrl-A X in the terminal quits QEMU.
pub fn window(args: &[String]) -> Result<(), String> {
    let machine = player_machine(args)?;
    if machine.is_hvf() {
        hvf_host().map_err(|why| {
            format!(
                "--machine hvf needs macOS on Apple Silicon with the Hypervisor framework: {why}"
            )
        })?;
    }
    build_lvgl()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(lvgl_image::IMAGE, lvgl_image::programs(), BOOT_PROFILE)?;
    packages::check()?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    if cfg!(target_os = "macos") {
        cmd.args(["-display", "cocoa"]);
    }
    cmd.args([
        "-chardev",
        "stdio,id=console,mux=on,signal=off",
        "-serial",
        "chardev:console",
        "-mon",
        "chardev=console,mode=readline",
    ]);
    cmd.args(qemu::GPU);
    cmd.args(qemu::TABLET);
    println!(
        "lvgl on {}: at the prompt of ash type `lvgl-demo`; the window shows the widgets of the demo (the injector plays the scenario of the probe once when it opens); click the button, the check box, the switch and the slider with the mouse; Ctrl-C in the terminal ends the demo; Ctrl-A X quits QEMU",
        machine.name
    );
    let status = cmd
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .status()
        .map_err(|e| format!("{cmd:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("QEMU exited with {status}"))
    }
}

/// The machine the probe or the window runs on: the default is QEMU's own
/// emulation; `--machine hvf` and `--hvf` pick Apple's Hypervisor.
fn player_machine(args: &[String]) -> Result<&'static qemu::Machine, String> {
    match args {
        [] => Ok(&qemu::VIRT),
        [flag, name] if flag == "--machine" => match name.as_str() {
            "hvf" => Ok(&qemu::HVF_V3),
            "tcg" => Ok(&qemu::VIRT),
            other => qemu::machine(Some(&other.to_owned())),
        },
        _ => Err(format!("unknown arguments of lvgl: {args:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference's own lines for a good run, as `lvgl-ref` prints them.
    fn host_lines() -> Vec<String> {
        let mut lines = Vec::new();
        for l in [
            "evidence glyph a outline points 49 contours 2 crc EFEA584D",
            "evidence glyph a bitmap width 9 rows 9 pitch 9 left 0 top 9 advance 576 crc DEA4419D",
            "evidence multiple-masters 0",
            "evidence kerning AV x -64 y 0",
            "evidence truetype interpreter-version 40",
            "first crc 450D7460",
            "after crc DDBD81B9",
            "state presses 2 option 1 switch 1 slider 75 text hi",
            "turns 111 frames 64",
            "mem max-used 70152",
        ] {
            lines.push(format!("{HOST}{l}"));
        }
        let bands = |frame: &str, odd: Option<usize>| {
            let list: Vec<String> = (0..25)
                .map(|i| {
                    if Some(i) == odd {
                        "DEADBEEF".to_owned()
                    } else {
                        format!("{:08X}", 0x1000 + i)
                    }
                })
                .collect();
            format!("evidence bands {frame} {}", list.join(" "))
        };
        lines.push(format!("{HOST}{}", bands("first", None)));
        lines.push(format!("{HOST}{}", bands("after", None)));
        lines
    }

    /// The guest's lines: the reference's but the interpreter's line, with the
    /// guest's own.
    fn guest_lines() -> Vec<String> {
        let mut lines: Vec<String> = host_lines()
            .into_iter()
            .filter(|l| !l.contains("interpreter-version"))
            .map(|l| l.replacen(HOST, GUEST, 1))
            .collect();
        lines.push(format!(
            "{GUEST}events key 4 move 6 button 12 focus-in 1 focus-out 0 lost 0"
        ));
        lines.push(format!("{GUEST}memory heap-bytes 1000000 own-pages 520"));
        lines.push(format!("{GUEST}frames 63 longest-us 90000 mean-us 40000"));
        lines
    }

    fn judged(guest: &[String]) -> Result<String, String> {
        verdict(&parse(guest, GUEST)?, &parse(&host_lines(), HOST)?)
    }

    #[test]
    fn the_scenario_has_four_keys_six_moves_and_twelve_buttons() {
        assert_eq!(scene_kinds(), (4, 6, 12));
    }

    #[test]
    fn a_good_run_passes_and_says_what_it_compared() {
        let said = judged(&guest_lines()).unwrap();
        assert!(said.contains("first crc 450D7460"), "{said}");
        assert!(said.contains("lost 0"), "{said}");
        assert!(said.contains("pool max 70152"), "{said}");
    }

    /// The first planted fault of the plan: a doubled `after crc` line with
    /// another CRC fails the parse, naming both.
    #[test]
    fn a_doubled_after_crc_line_with_another_crc_fails_the_parse() {
        let mut lines = guest_lines();
        lines.push(format!("{AFTER}00000000"));
        let error = parse(&lines, GUEST).unwrap_err();
        assert!(error.contains("2 lines \"after crc \""), "{error}");
        assert!(
            error.contains("00000000") && error.contains("DDBD81B9"),
            "{error}"
        );
    }

    /// The second: LOST in the log fails, whether the demo's line or the
    /// ring's own.
    #[test]
    fn lost_in_the_log_fails() {
        let mut lines = guest_lines();
        lines.push(format!("{GUEST}LOST: the ring of events dropped some"));
        let error = parse(&lines, GUEST).unwrap_err();
        assert!(error.contains("LOST"), "{error}");
        let mut lines = guest_lines();
        for l in lines.iter_mut() {
            *l = l.replace("lost 0", "lost 3");
        }
        let guest = parse(&lines, GUEST).unwrap();
        let error = verdict(&guest, &parse(&host_lines(), HOST).unwrap()).unwrap_err();
        assert!(error.contains("dropped events"), "{error}");
    }

    #[test]
    fn fewer_than_the_scenario_events_fail() {
        let mut lines = guest_lines();
        for l in lines.iter_mut() {
            *l = l.replace("button 12", "button 11");
        }
        let error = judged(&lines).unwrap_err();
        assert!(
            error.contains("11 buttons, 4, 6 and 12 expected"),
            "{error}"
        );
    }

    #[test]
    fn a_log_line_of_lvgl_or_a_stall_fails() {
        for odd in [
            "lvgl: [Warn] lv_obj_remove_flag: Deprecated lv_obj.c:447",
            "still waiting for a free buffer",
            "only 17 of 22 input events came",
            "cannot open the window: errno 16",
        ] {
            let mut lines = guest_lines();
            lines.push(format!("{GUEST}{odd}"));
            assert!(parse(&lines, GUEST).is_err(), "{odd}");
        }
    }

    #[test]
    fn a_line_the_report_does_not_know_fails() {
        let mut lines = guest_lines();
        lines.push(format!("{GUEST}hello"));
        let error = parse(&lines, GUEST).unwrap_err();
        assert!(error.contains("does not know"), "{error}");
    }

    /// A guest CRC that differs from the host's names the differing bands.
    #[test]
    fn a_guest_crc_that_differs_names_the_bands() {
        let mut lines = guest_lines();
        for l in lines.iter_mut() {
            if l.starts_with(FIRST) {
                *l = format!("{FIRST}11111111");
            }
            if l.starts_with("lvgl-demo: evidence bands first") {
                let mut parts: Vec<String> = l.split(' ').map(str::to_owned).collect();
                // The words are "lvgl-demo:", "evidence", "bands", "first" and the CRCs.
                parts[4 + 3] = "DEADBEEF".to_owned();
                parts[4 + 9] = "CAFEF00D".to_owned();
                *l = parts.join(" ");
            }
        }
        let error = judged(&lines).unwrap_err();
        assert!(error.contains("the first frame"), "{error}");
        assert!(
            error.contains("11111111") && error.contains("450D7460"),
            "{error}"
        );
        assert!(error.contains("band 3 (rows 48..63)"), "{error}");
        assert!(error.contains("band 9 (rows 144..159)"), "{error}");
        assert!(error.contains("the glyph evidence lines agree"), "{error}");
    }

    #[test]
    fn a_difference_of_the_glyph_evidence_is_named_with_the_crcs() {
        let mut lines = guest_lines();
        for l in lines.iter_mut() {
            if l.contains("glyph a outline") {
                *l = l.replace("EFEA584D", "00000000");
            }
            if l.starts_with(AFTER) {
                *l = format!("{AFTER}22222222");
            }
        }
        let error = judged(&lines).unwrap_err();
        assert!(error.contains("the glyph evidence lines differ"), "{error}");
        assert!(error.contains("00000000"), "{error}");
        // Evidence alone, with equal CRCs, fails too.
        let mut lines = guest_lines();
        for l in lines.iter_mut() {
            if l.contains("kerning AV") {
                *l = l.replace("x -64", "x -63");
            }
        }
        let error = judged(&lines).unwrap_err();
        assert!(
            error.contains("evidence lines differ while the CRCs agree"),
            "{error}"
        );
    }

    #[test]
    fn the_state_turns_frames_and_pool_are_compared_exactly() {
        for (from, to, what) in [
            ("text hi", "text hhii", "state"),
            ("turns 111", "turns 112", "turns"),
            ("frames 64", "frames 66", "frames"),
            ("max-used 70152", "max-used 70240", "mem max-used"),
        ] {
            let mut lines = guest_lines();
            for l in lines.iter_mut() {
                *l = l.replace(from, to);
            }
            let error = judged(&lines).unwrap_err();
            assert!(
                error.contains(&format!("the {what} of the guest")),
                "{what}: {error}"
            );
        }
    }

    #[test]
    fn the_guest_needs_no_interpreter_line_and_the_host_may_have_it() {
        let guest = parse(&guest_lines(), GUEST).unwrap();
        assert!(guest.evidence.iter().all(|l| !l.contains("interpreter")));
        let host = parse(&host_lines(), HOST).unwrap();
        assert!(host.evidence.iter().any(|l| l.starts_with(HOST_ONLY)));
    }

    #[test]
    fn three_crcs_name_the_path_that_changed_the_pixels() {
        assert!(three_way("first", 1, 1, 1).is_ok());
        let error = three_way("first", 1, 2, 1).unwrap_err();
        assert!(
            error.contains("between the demo's buffer and QEMU's screen"),
            "{error}"
        );
        let error = three_way("after", 1, 1, 3).unwrap_err();
        assert!(
            error.contains("draws other pixels in the guest than on the host"),
            "{error}"
        );
    }

    /// A screenshot anchor that never came: the message names the line and
    /// shows what the demo did say.
    #[test]
    fn a_missing_anchor_says_which_line_and_what_the_demo_said() {
        let lines = vec![
            "init: services started".to_owned(),
            format!("{GUEST}cannot open the window: errno 16"),
        ];
        let message = missing_anchor(FIRST, &lines, "timed out");
        assert!(
            message.contains("no line \"lvgl-demo: first crc \""),
            "{message}"
        );
        assert!(
            message.contains("cannot open the window: errno 16"),
            "{message}"
        );
        assert!(!message.contains("services started"), "{message}");
    }

    #[test]
    fn the_player_machine_takes_tcg_and_hvf() {
        assert!(player_machine(&[]).is_ok());
        let tcg = ["--machine".to_owned(), "tcg".to_owned()];
        assert!(!player_machine(&tcg).unwrap().is_hvf());
        let hvf = ["--machine".to_owned(), "hvf".to_owned()];
        assert!(player_machine(&hvf).unwrap().is_hvf());
        assert!(player_machine(&["--nonsense".to_owned()]).is_err());
    }
}
