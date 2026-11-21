// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the composition service (services/compositor) on QEMU's
//! virtio-gpu-device, which also runs under HVF: the display driver with
//! the compositor as its one client, and two clients of the compositor
//! (tests/comp-probe). The first makes windows of its own (two buffers, a
//! rectangle posted alone, a second window over the first) and ends holding
//! them; the second waits for them to go, finds the black screen they left,
//! and asks for the screen as a program of proto_gpu's first revision does
//! (OPEN, a pattern, FLUSH). Its window covers the screen with nothing above
//! it, so the display shows the window's buffer (the driver's pool) as it
//! is: the service's `bands` stay as they were over three FLUSHes while
//! `bypassed` grows by three. A third client then puts a window over it
//! (the frame is put together, and the screenshot has the CRC of that
//! screen) and ends (the pool is shown again). QEMU's trace of the display
//! must show the scanout on resources 1, 2, 1, 2 and 1 in this order: the
//! target, the pool, the target, the pool, the target.
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
/// general path, which keeps scanline buffers of 24 KiB on the stack (a turned
/// element in a scene runs it under the general path, and 64 KiB did not hold it).
pub const COMP_STACK_SIZE: u32 = 128 * 1024;

/// The stack of the probe: the scene holder keeps the scenes of its elements and
/// the messages of its calls on it.
pub const PROBE_STACK_SIZE: u32 = 2 * CHILD_STACK_SIZE;

/// The probe's image: the driver, the compositor, the two clients.
pub const PROGRAMS: [ImageProgram; 4] = [
    ("init", "init", INIT_STACK_SIZE, &["table-comp"]),
    ("virtio-gpu", "virtio-gpu", gpu_probe::GPU_STACK_SIZE, &[]),
    ("compositor", "compositor", COMP_STACK_SIZE, &[]),
    ("comp-probe", "comp-probe", PROBE_STACK_SIZE, &[]),
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
    ("compositor", "compositor", COMP_STACK_SIZE, &["calibrate"]),
    ("comp-probe", "comp-probe", PROBE_STACK_SIZE, &["quick"]),
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
const ABOVE: &str = "comp-probe: above crc ";
const SCENE: &str = "comp-probe: scene crc ";
const SCENE_LEGACY: &str = "comp-probe: scene legacy crc ";
const SCENE_STATIC: &str = "comp-probe: scene static crc ";
const SCENE_COMPOSED: &str = "comp-probe: scene composed crc ";
const LEGACY_BACK: &str = "comp-probe: legacy back crc ";
/// The scenes of the elements, in the order the holder shows them.
const ELEMENT_STRETCH: &str = "comp-probe: element stretch crc ";
const ELEMENT_ORIENT: &str = "comp-probe: element orient crc ";
const ELEMENT_BILINEAR: &str = "comp-probe: element bilinear crc ";
const ELEMENT_ALPHA: &str = "comp-probe: element alpha crc ";
const ELEMENT_MASK: &str = "comp-probe: element mask crc ";
const ELEMENT_MASK_CUT: &str = "comp-probe: element maskcut crc ";
const ENDED: &str = "init: comp-probe ended: exit code 0, not restarted";
const ENDED_C: &str = "init: comp-probe-c ended: exit code 0, not restarted";
const ENDED_B: &str = "init: comp-probe-b ended: exit code 0, not restarted";
const ENDED_S: &str = concat!("init: comp-probe-s ended: exit code 0,", " not restarted");
const B_ENDS: &str = "init: comp-probe-b ended: ";
const S_ENDS: &str = "init: comp-probe-s ended: ";

/// The lines each client prints once per check that passed, and how many
/// times a run has each.
const CHECKS: [(&str, usize); 34] = [
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
    (
        "comp-probe: the pool is cleared and written again through the kept mapping",
        1,
    ),
    ("comp-probe: after the unmap OPEN gives a cleared buffer", 1),
    (
        "comp-probe: FLUSH of a rectangle outside the screen is INVALID",
        1,
    ),
    (
        "comp-probe: three FLUSHes were shown from the pool, no band was put together",
        1,
    ),
    ("comp-probe: the window below is shown from its pool", 1),
    (
        "comp-probe: a window above the pool made the service put the frame together",
        1,
    ),
    (
        "comp-probe: the window above went and the pool was shown again with no band",
        1,
    ),
    (
        "comp-probe: the client over the pool ends with its window",
        1,
    ),
    ("comp-probe: the program ends with its window", 1),
    (
        "comp-probe: a scene is committed by its session and refused past its limits",
        1,
    ),
    ("comp-probe: the scene is taken whole, COMMITTED comes", 1),
    (
        "comp-probe: a FLUSH of a window no element shows is answered",
        1,
    ),
    (
        "comp-probe: a scene composed on request is made by SCENE_COMPOSE, COMPOSED comes",
        1,
    ),
    (
        "comp-probe: elements are drawn: a stretch, the turns and the reflection, the bilinear mean, a global alpha, a mask",
        1,
    ),
    ("comp-probe: the scene holder ends with its windows", 1),
    ("comp-probe: ok", 4),
    (ENDED_C, 1),
    (ENDED_S, 1),
    (DRIVER_LINE, 1),
    (DRIVER_READY, 1),
];

/// The tags of the lines of steps (rt::service::report_steps): the driver's
/// and the compositor's.
pub const DRIVER_TAG: &str = "12";
pub const COMP_TAG: &str = "17";
/// The kinds of the compositor's steps that must come: OPEN and FLUSH of
/// proto_gpu, DESCRIBE, WINDOW_CREATE, ATTACH and POST of proto_comp, and
/// its own (a band, the end of a frame), and SCENE_COMMIT and SCENE_COMPOSE of
/// the scene's holder.
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
/// The driver's: SUBSCRIBE, COMMIT, PIPELINES and SOURCE (the compositor
/// asks them when it opens the screen: the cursor pipeline and the pool),
/// LAYERS (the frames shown directly from the pool and the frame that
/// takes the screen back), and its own (the interrupt).
const DRIVER_KINDS: [(usize, &str); 6] = [
    (5, "Subscribe"),
    (6, "Commit"),
    (9, "Pipelines"),
    (10, "Source"),
    (11, "Layers"),
    (65, "the interrupt"),
];

/// Judges the lines of a run: the compositor and the driver started and
/// were ready once, every check of the clients passed once, none failed,
/// and the window of the first revision came back once.
pub fn verdict(lines: &[String]) -> Result<(), String> {
    let lines = &crate::qemu::unglued(lines, RELEASED);
    let count = |marker: &str| lines.iter().filter(|l| l.as_str() == marker).count();
    if let Some(failed) = lines.iter().find(|l| l.starts_with("comp-probe: failed")) {
        return Err(failed.clone());
    }
    for (marker, wanted) in CHECKS.iter().chain(&[(READY, 1), (RELEASED, 3)]) {
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
    // A portion is a target of the kind of 0.9 B and is judged the same way: the greatest by
    // kind of N - P * PREEMPT_CHARGE. The work no preemption touched is told beside it.
    if let Some(row) = rows.iter().find(|r| r.0 == 65 && r.1 > PORTION_MAX) {
        return Err(format!(
            "the {name}: a portion or an interrupt past {PORTION_MAX}: {row:?}"
        ));
    }
    crate::step_line::say_clean(lines, tag, name, 65);
    Ok(rows)
}

/// The steps of the compositor and of the driver.
pub fn steps_verdict(lines: &[String]) -> Result<(Rows, Rows), String> {
    Ok((
        rows_of(lines, COMP_TAG, "compositor", &COMP_KINDS)?,
        rows_of(lines, DRIVER_TAG, "display driver", &DRIVER_KINDS)?,
    ))
}

/// The most steps a frame of the probe's scenes may take (the lines `service frame: T n N
/// bands B us U` of the service): the greatest of the scenes took 17,675 before the edge of the fast class was priced, and a band of one
/// point over the whole rectangle of an element would make up to 256,000 steps of a group.
pub const FRAME_STEPS_MAX: u64 = 60_000;

/// The frames the service told: (frame, steps, microseconds).
pub fn frame_steps(lines: &[String], tag: &str) -> Vec<(u64, u64, u64)> {
    lines
        .iter()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            let ["service", "frame:", t, "n", n, "bands", b, "us", u] = w.as_slice() else {
                return None;
            };
            (*t == tag).then(|| Some((n.parse().ok()?, b.parse().ok()?, u.parse().ok()?)))?
        })
        .collect()
}

/// No frame takes more than FRAME_STEPS_MAX steps: the greatest, or the frame that did.
pub fn frames_verdict(lines: &[String]) -> Result<u64, String> {
    let frames = frame_steps(lines, COMP_TAG);
    if let Some((n, bands, _)) = frames.iter().find(|f| f.1 > FRAME_STEPS_MAX) {
        return Err(format!(
            "the compositor: frame {n} took {bands} steps, over {FRAME_STEPS_MAX}"
        ));
    }
    Ok(frames.iter().map(|f| f.1).max().unwrap_or(0))
}

/// The longest step of each kind: kind, ticks, detail.
pub type Rows = Vec<(usize, u64, u64)>;

/// What the compositor measured inside its bands for one kind of layer
/// (the line `service raster: T KIND calls C points P ticks N big B W small
/// S L` of services/compositor's `px::cost`, told after the 1st, 2nd, 4th...
/// frame): the totals up to that frame, the least and the greatest ticks a
/// hundred points of an operation of 64 points or more, and the least and the
/// greatest ticks of an operation of 8 points or fewer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RasterCost {
    pub kind: String,
    pub calls: u64,
    pub points: u64,
    pub ticks: u64,
    pub big_best: u64,
    pub big_worst: u64,
    pub small_best: u64,
    pub small_worst: u64,
    /// The operations of 256 points or more, when the line has them: their
    /// number, the least ticks a hundred points, the points of that operation
    /// and the greatest.
    pub large: Option<Large>,
    /// The three prices of the model `call + rows * row + points * point`, when
    /// the line has them.
    pub model: Option<Model>,
}

/// The measured prices of a kind (`px::cost`): each the greatest over its class
/// of operations, with how many there were. The call is ticks, the row and the
/// point hundredths of a tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Model {
    pub call: u64,
    pub row: u64,
    pub point: u64,
    pub calls: u64,
    pub rows: u64,
    pub points: u64,
}

/// The large operations of a kind (`px::cost`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Large {
    pub calls: u64,
    pub best: u64,
    pub best_points: u64,
    pub worst: u64,
}

impl RasterCost {
    /// The price of a point net of the call, in hundredths of a tick: the least
    /// of the large operations, less the least call of the small ones, over the
    /// points of the operation that made the least. None without large
    /// operations; the whole least (call included) when no small operation came.
    pub fn net_price(&self) -> Option<u64> {
        let large = self.large?;
        if large.calls == 0 || large.best_points == 0 {
            return None;
        }
        let ticks = large.best * large.best_points / 100;
        Some(ticks.saturating_sub(self.small_best) * 100 / large.best_points)
    }
}

impl RasterCost {
    fn parse(line: &str, tag: &str) -> Option<RasterCost> {
        let w: Vec<&str> = line.split_whitespace().collect();
        let [
            "service",
            "raster:",
            t,
            kind,
            "calls",
            calls,
            "points",
            points,
            "ticks",
            ticks,
            "big",
            bb,
            bw,
            "small",
            sb,
            sw,
            rest @ ..,
        ] = w.as_slice()
        else {
            return None;
        };
        if *t != tag {
            return None;
        }
        let (large, model) = match rest {
            [] => (None, None),
            ["large", n, lb, lp, lw, tail @ ..] => {
                let large = Large {
                    calls: n.parse().ok()?,
                    best: lb.parse().ok()?,
                    best_points: lp.parse().ok()?,
                    worst: lw.parse().ok()?,
                };
                let model = match tail {
                    [] => None,
                    ["price", c, r, p, nc, nr, np] => Some(Model {
                        call: c.parse().ok()?,
                        row: r.parse().ok()?,
                        point: p.parse().ok()?,
                        calls: nc.parse().ok()?,
                        rows: nr.parse().ok()?,
                        points: np.parse().ok()?,
                    }),
                    _ => return None,
                };
                (Some(large), model)
            }
            _ => return None,
        };
        Some(RasterCost {
            kind: (*kind).to_owned(),
            calls: calls.parse().ok()?,
            points: points.parse().ok()?,
            ticks: ticks.parse().ok()?,
            big_best: bb.parse().ok()?,
            big_worst: bw.parse().ok()?,
            small_best: sb.parse().ok()?,
            small_worst: sw.parse().ok()?,
            large,
            model,
        })
    }

    /// The mean ticks a point over the whole run, a hundred times.
    fn mean_per_hundred(&self) -> u64 {
        (self.ticks * 100).checked_div(self.points).unwrap_or(0)
    }
}

/// The last line of each kind of layer of the service `tag` (the totals of
/// the latest frame told), in the order the kinds first came.
pub fn raster_costs(lines: &[String], tag: &str) -> Vec<RasterCost> {
    let mut out: Vec<RasterCost> = Vec::new();
    for cost in lines.iter().filter_map(|l| RasterCost::parse(l, tag)) {
        match out.iter_mut().find(|c| c.kind == cost.kind) {
            Some(old) => *old = cost,
            None => out.push(cost),
        }
    }
    out
}

/// The row of the compositor's table of prices of a kind of layer.
fn price(kind: &str) -> compositor::Price {
    compositor::PRICES
        .iter()
        .copied()
        .find(|p| p.kind == kind)
        .unwrap_or(compositor::PRICES[2])
}

/// The costs for the report of a probe, per kind of layer: the three prices of
/// the model of `Scene::tile` (`compositor::PRICES`: the call in ticks, the row
/// and the point in hundredths of a tick; the measure and the constant of each,
/// "(estimate)" where no probe measured it) against what the run measured: each
/// the greatest over its class of operations (the call over operations of one row
/// and 8 points or fewer, the row over those at most 16 points wide and at least 8
/// rows with the call taken off, the point over those of 1 024 points or more with
/// the call and the rows taken off) with the number of operations of the class.
/// The measured figure goes into the table as the measure of its price, and the
/// constant follows with the margin. The price of a point net of the call from
/// the large operations (256 points or more) is printed beside them.
pub fn raster_text(costs: &[RasterCost]) -> String {
    if costs.is_empty() {
        return "no cost lines (the log lost them, or the frames came too few)".to_owned();
    }
    costs
        .iter()
        .map(|c| {
            let hundredths = |v: u64| format!("{}.{:02}", v / 100, v % 100);
            let p = price(&c.kind);
            let est = |e: bool| if e { " (estimate)" } else { "" };
            let table = format!(
                "table: call {} constant {}, row {} constant {}{}, point {} constant {}{}",
                p.call_measured,
                p.call,
                hundredths(u64::from(p.row_measured)),
                hundredths(u64::from(p.row)),
                est(p.row_estimate),
                hundredths(u64::from(p.point_measured)),
                hundredths(u64::from(p.point)),
                est(p.point_estimate),
            );
            let measured = match c.model {
                Some(m) => format!(
                    "measured: call {} ({} operations), row {} ({}), point {} ({})",
                    m.call,
                    m.calls,
                    hundredths(m.row),
                    m.rows,
                    hundredths(m.point),
                    m.points
                ),
                None => "measured: no classes in this line".to_owned(),
            };
            let large = match c.large {
                Some(l) if l.calls > 0 => format!(
                    "{} large operations: least {} at {} points, net of the call {}, greatest {}",
                    l.calls,
                    hundredths(l.best),
                    l.best_points,
                    c.net_price().map_or("none".to_owned(), hundredths),
                    hundredths(l.worst)
                ),
                _ => "no large operation".to_owned(),
            };
            format!(
                "{} ({table}; {measured}): {} calls, {} points, {large}; call of an operation of 8 points or fewer least {} greatest {}; over 64 points or more a point mean {} least {} greatest {}",
                c.kind,
                c.calls,
                c.points,
                c.small_best,
                c.small_worst,
                hundredths(c.mean_per_hundred()),
                hundredths(c.big_best),
                hundredths(c.big_worst),
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The most bands of a full frame the period of 60 Hz holds without load.
pub const FULL_FRAME_BANDS_MAX: u32 = 45;

/// One class of the calibration: the least and the greatest figure, the
/// operations that counted and the shape of the greatest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Class {
    pub least: u64,
    pub greatest: u64,
    pub n: u64,
    pub w: u64,
    pub h: u64,
}

/// The line `service calibration: T KIND call L G N W H row L G N W H point L G
/// N W H preempted K` of the service under its steps feature (`px::calibration`):
/// the prices of a kind measured on shapes chosen for each class, with the
/// operations a higher level preempted left out. The call is ticks, the row and
/// the point hundredths of a tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Calibration {
    pub kind: String,
    pub call: Class,
    pub row: Class,
    pub point: Class,
    pub preempted: u64,
}

impl Calibration {
    fn parse(line: &str, tag: &str) -> Option<Calibration> {
        let w: Vec<&str> = line.split_whitespace().collect();
        let ["service", "calibration:", t, kind, "call", c @ ..] = w.as_slice() else {
            return None;
        };
        if *t != tag || c.len() != 5 + 1 + 5 + 1 + 5 + 2 {
            return None;
        }
        let class = |s: &[&str]| -> Option<Class> {
            Some(Class {
                least: s[0].parse().ok()?,
                greatest: s[1].parse().ok()?,
                n: s[2].parse().ok()?,
                w: s[3].parse().ok()?,
                h: s[4].parse().ok()?,
            })
        };
        if c[5] != "row" || c[11] != "point" || c[17] != "preempted" {
            return None;
        }
        Some(Calibration {
            kind: (*kind).to_owned(),
            call: class(&c[0..5])?,
            row: class(&c[6..11])?,
            point: class(&c[12..17])?,
            preempted: c[18].parse().ok()?,
        })
    }
}

/// The last calibration line of each kind of the service `tag`.
pub fn calibrations(lines: &[String], tag: &str) -> Vec<Calibration> {
    let mut out: Vec<Calibration> = Vec::new();
    for c in lines.iter().filter_map(|l| Calibration::parse(l, tag)) {
        match out.iter_mut().find(|o| o.kind == c.kind) {
            Some(old) => *old = c,
            None => out.push(c),
        }
    }
    out
}

/// The line `service shape: T KIND W H least L greatest G n N`: the ticks of an
/// operation of one shape over its offsets and repeats (those a preemption
/// landed in left out).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShapeCost {
    pub kind: String,
    pub w: u32,
    pub h: u32,
    pub least: u64,
    pub greatest: u64,
    pub n: u64,
}

impl ShapeCost {
    fn parse(line: &str, tag: &str) -> Option<ShapeCost> {
        let w: Vec<&str> = line.split_whitespace().collect();
        let [
            "service",
            "shape:",
            t,
            kind,
            ww,
            hh,
            "least",
            l,
            "greatest",
            g,
            "n",
            n,
        ] = w.as_slice()
        else {
            return None;
        };
        if *t != tag {
            return None;
        }
        Some(ShapeCost {
            kind: (*kind).to_owned(),
            w: ww.parse().ok()?,
            h: hh.parse().ok()?,
            least: l.parse().ok()?,
            greatest: g.parse().ok()?,
            n: n.parse().ok()?,
        })
    }
}

/// The last line of each shape of each kind of the service `tag`.
pub fn shape_costs(lines: &[String], tag: &str) -> Vec<ShapeCost> {
    let mut out: Vec<ShapeCost> = Vec::new();
    for c in lines.iter().filter_map(|l| ShapeCost::parse(l, tag)) {
        match out
            .iter_mut()
            .find(|o| (&o.kind, o.w, o.h) == (&c.kind, c.w, c.h))
        {
            Some(old) => *old = c,
            None => out.push(c),
        }
    }
    out
}

/// The upper fit of a kind over the greatest ticks of its shapes
/// (`compositor::fit`): the call in ticks, the row and the point in hundredths
/// of a tick, with the greatest overstatement of a shape.
pub fn fit_of(costs: &[ShapeCost], kind: &str) -> Option<(compositor::fit::Fit, u64)> {
    let shapes: Vec<compositor::fit::Shape> = costs
        .iter()
        .filter(|c| c.kind == kind)
        .map(|c| compositor::fit::Shape {
            w: c.w,
            h: c.h,
            ticks: c.greatest,
        })
        .collect();
    let fit = compositor::fit::envelope(&shapes)?;
    let slack = shapes.iter().map(|s| fit.slack(*s)).max().unwrap_or(0);
    Some((fit, slack))
}

/// The cost of a row at each width that has two heights, in ticks: the
/// greatest, and the least, ticks of the taller operation less the shorter,
/// over the rows between them. It is the row price plus the width's points, so
/// a line of these over the widths is straight when the model of three terms
/// holds, and bends up at the narrow widths when a narrow row costs more a point.
pub fn row_costs(costs: &[ShapeCost], kind: &str) -> Vec<(u32, u64, u64)> {
    let mut out: Vec<(u32, u64, u64)> = Vec::new();
    let of_kind: Vec<&ShapeCost> = costs.iter().filter(|c| c.kind == kind).collect();
    for a in &of_kind {
        for b in &of_kind {
            if a.w == b.w && a.h < b.h && !out.iter().any(|(w, ..)| *w == a.w) {
                let rows = u64::from(b.h - a.h);
                out.push((
                    a.w,
                    b.greatest.saturating_sub(a.greatest) / rows,
                    b.least.saturating_sub(a.least) / rows,
                ));
            }
        }
    }
    out.sort();
    out
}

/// The cost of the layers of a band beyond their operations, from the bands of
/// one, two, four and eight layers on the same rows (the shapes of the kinds
/// `layers1` to `layers8`): each count's greatest excess of the band's ticks over
/// the black and the layers by the fits of the operations, the excess of one
/// layer taken off, for each layer added, and the greatest of those (the term of
/// a layer, `compositor::LAYER_MEASURED`). The first of the pair is the excess of
/// a band of one layer, which the model of the operations has no term for.
pub struct LayerTerm {
    /// The greatest excess of a band of one layer, in ticks (0 when none).
    pub one: i64,
    /// For each count above 1: the count and the greatest excess of a layer added.
    pub by_count: Vec<(u64, i64)>,
    /// The greatest of those.
    pub term: i64,
}

pub fn layer_term(costs: &[ShapeCost]) -> Option<LayerTerm> {
    let (black, _) = fit_of(costs, "black")?;
    let (over, _) = fit_of(costs, "over")?;
    let ticks = |f: compositor::fit::Fit, w: u32, h: u32| -> i64 {
        let (w, h) = (i64::from(w), i64::from(h));
        f.call as i64 + (f.row as i64 * h + f.point as i64 * w * h + 99) / 100
    };
    let band = |count: u64, w: u32, h: u32| {
        costs
            .iter()
            .find(|c| c.kind == format!("layers{count}") && c.w == w && c.h == h)
    };
    let excess = |count: u64, c: &ShapeCost| {
        c.greatest as i64 - ticks(black, c.w, c.h) - count as i64 * ticks(over, c.w, c.h)
    };
    let mut one = i64::MIN;
    let mut by_count = Vec::new();
    for c in costs.iter().filter(|c| c.kind == "layers1") {
        one = one.max(excess(1, c));
    }
    if one == i64::MIN {
        return None;
    }
    for count in [2u64, 4, 8, 9] {
        let mut greatest = i64::MIN;
        for c in costs.iter().filter(|c| c.kind == format!("layers{count}")) {
            if let Some(single) = band(1, c.w, c.h) {
                greatest =
                    greatest.max((excess(count, c) - excess(1, single)) / (count as i64 - 1));
            }
        }
        if greatest != i64::MIN {
            by_count.push((count, greatest));
        }
    }
    let term = by_count.iter().map(|(_, g)| *g).max().unwrap_or(0);
    Some(LayerTerm {
        one: one.max(0),
        by_count,
        term: term.max(0),
    })
}

/// The line `service band: T layers L n N outside least A greatest B total
/// greatest G compose C ops O`: for the bands of L layers the service made, the
/// least and the greatest ticks of `compose` less its operations (what the band
/// spends around the calls), and, of the band whose own code took longest (G), the
/// ticks of its `compose` and of its operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BandSplit {
    pub layers: u64,
    pub n: u64,
    pub outside_least: u64,
    pub outside_greatest: u64,
    pub total: u64,
    pub compose: u64,
    pub ops: u64,
}

impl BandSplit {
    fn parse(line: &str, tag: &str) -> Option<BandSplit> {
        let w: Vec<&str> = line.split_whitespace().collect();
        let [
            "service",
            "band:",
            t,
            "layers",
            layers,
            "n",
            n,
            "outside",
            "least",
            a,
            "greatest",
            b,
            "total",
            "greatest",
            g,
            "compose",
            c,
            "ops",
            o,
        ] = w.as_slice()
        else {
            return None;
        };
        if *t != tag {
            return None;
        }
        Some(BandSplit {
            layers: layers.parse().ok()?,
            n: n.parse().ok()?,
            outside_least: a.parse().ok()?,
            outside_greatest: b.parse().ok()?,
            total: g.parse().ok()?,
            compose: c.parse().ok()?,
            ops: o.parse().ok()?,
        })
    }
}

/// The last line of each count of layers of the service `tag`.
pub fn band_splits(lines: &[String], tag: &str) -> Vec<BandSplit> {
    let mut out: Vec<BandSplit> = Vec::new();
    for c in lines.iter().filter_map(|l| BandSplit::parse(l, tag)) {
        match out.iter_mut().find(|o| o.layers == c.layers) {
            Some(old) => *old = c,
            None => out.push(c),
        }
    }
    out.sort_by_key(|b| b.layers);
    out
}

/// The line `service band floor: T layers L n N total least A compose C ops O
/// above-gate G`: for the bands of L layers, the band whose own code took least (the
/// floor: what a band costs when nothing else happened in it), the ticks of its
/// `compose` and of its operations, and how many bands passed the gate of a band
/// (a preempted band does too).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BandFloor {
    pub layers: u64,
    pub n: u64,
    pub least: u64,
    pub compose: u64,
    pub ops: u64,
    pub above_gate: u64,
}

impl BandFloor {
    fn parse(line: &str, tag: &str) -> Option<BandFloor> {
        let w: Vec<&str> = line.split_whitespace().collect();
        let [
            "service",
            "band",
            "floor:",
            t,
            "layers",
            layers,
            "n",
            n,
            "total",
            "least",
            a,
            "compose",
            c,
            "ops",
            o,
            "above-gate",
            g,
        ] = w.as_slice()
        else {
            return None;
        };
        if *t != tag {
            return None;
        }
        Some(BandFloor {
            layers: layers.parse().ok()?,
            n: n.parse().ok()?,
            least: a.parse().ok()?,
            compose: c.parse().ok()?,
            ops: o.parse().ok()?,
            above_gate: g.parse().ok()?,
        })
    }
}

/// The last floor line of each count of layers of the service `tag`.
pub fn band_floors(lines: &[String], tag: &str) -> Vec<BandFloor> {
    let mut out: Vec<BandFloor> = Vec::new();
    for c in lines.iter().filter_map(|l| BandFloor::parse(l, tag)) {
        match out.iter_mut().find(|o| o.layers == c.layers) {
            Some(old) => *old = c,
            None => out.push(c),
        }
    }
    out.sort_by_key(|b| b.layers);
    out
}

/// The last line of each of the kinds `service band place: T NAME ...`, `service band
/// histogram: T ...` and `service band trace: T ...` of the service `tag`, told as they
/// stand (the places of the bands of two layers or more in the work of the service, their
/// ticks in bins, and what the bands past the gate spent in the kernel and in the table of
/// images).
pub fn band_places(lines: &[String], tag: &str) -> Vec<String> {
    let mut out: Vec<(String, String)> = Vec::new();
    for l in lines {
        let w: Vec<&str> = l.split_whitespace().collect();
        let key = match w.as_slice() {
            ["service", "band", "place:", t, name, ..] if *t == tag => format!("place {name}"),
            ["service", "band", "histogram:", t, ..] if *t == tag => "histogram".to_owned(),
            ["service", "band", "trace:", t, ..] if *t == tag => "trace".to_owned(),
            _ => continue,
        };
        let text = l.trim_start_matches("service band ").trim_end().to_owned();
        match out.iter_mut().find(|(k, _)| *k == key) {
            Some(old) => old.1 = text,
            None => out.push((key, text)),
        }
    }
    out.into_iter().map(|(_, t)| t).collect()
}

/// The bands by layers and their floors, told together: the split of each count
/// and the least band of it, which tells whether a band over the gate is the
/// band of its scene or an excess that came to it.
pub fn band_report(lines: &[String], tag: &str) -> String {
    let floors = band_floors(lines, tag);
    let mut text = band_split_text(&band_splits(lines, tag));
    let places = band_places(lines, tag);
    if !places.is_empty() {
        text = format!("{text}; places of the bands: {}", places.join("; "));
    }
    if floors.is_empty() {
        return text;
    }
    let parts: Vec<String> = floors
        .iter()
        .map(|f| {
            format!(
                "{} layers ({} bands): the least band {} ticks of which compose {} and the operations {}, {} past the gate {}",
                f.layers,
                f.n,
                f.least,
                f.compose,
                f.ops,
                f.above_gate,
                compositor::BAND_GATE
            )
        })
        .collect();
    format!("{text}; floors of the bands: {}", parts.join("; "))
}

/// The bands the service made, by layers: what a band spends around its
/// operations (`compose` less the calls, least and greatest, the greatest includes a
/// preemption in the middle), and the band whose own code took longest: its ticks,
/// of which the operations and what is around them, each by the layers it laid.
pub fn band_split_text(splits: &[BandSplit]) -> String {
    if splits.is_empty() {
        return "bands by layers: no lines (a run without the steps feature)".to_owned();
    }
    let parts: Vec<String> = splits
        .iter()
        .map(|b| {
            let layers = b.layers.max(1);
            format!(
                "{} layers ({} bands): around the operations {}..{} ticks, the model's {} ({}..{} a layer), longest band {} ticks of which the operations {} and around them {} ({} a layer)",
                b.layers,
                b.n,
                b.outside_least,
                b.outside_greatest,
                compositor::BAND_FIXED + compositor::LAYER * b.layers as u32,
                b.outside_least / layers,
                b.outside_greatest / layers,
                b.total,
                b.ops,
                b.total.saturating_sub(b.ops),
                b.total.saturating_sub(b.ops) / layers
            )
        })
        .collect();
    format!("bands by layers: {}", parts.join("; "))
}

/// The term of a layer told against the table.
pub fn layer_text(costs: &[ShapeCost]) -> String {
    let Some(t) = layer_term(costs) else {
        return "layers: no lines of bands of layers (a run without the steps feature)".to_owned();
    };
    let counts: Vec<String> = t
        .by_count
        .iter()
        .map(|(n, g)| format!("{n} layers {g}"))
        .collect();
    format!(
        "layers: the greatest excess of a band of one layer over its operations is {} ticks, and of each layer added {} ticks (by count: {}; a term that is the same at 2, 4 and 8 is a constant a layer, one that grows with the count is not); the table follows the real bands (`service band`), whose terms are the fixed term of a band {} measured ({} with the margin) and the term of every layer {} measured ({} with the margin), and the calibration's term is the check on shapes of its own",
        t.one,
        t.term,
        counts.join(", "),
        compositor::BAND_FIXED_MEASURED,
        compositor::BAND_FIXED,
        compositor::LAYER_MEASURED,
        compositor::LAYER
    )
}

/// The fit of each kind and what it means for the bands that matter, told
/// against the table: the fitted prices (hundredths of a tick for a row and a
/// point) and their constants with the margin, the greatest overstatement of a
/// shape, the row cost by width, and the band of a copy over the whole width
/// (a frame of the whole screen in bands), of a damage the size of the cursor
/// and of a line of text, and the worst band of eight windows with an alpha,
/// each by the fitted constants.
pub fn fit_text(costs: &[ShapeCost]) -> String {
    use compositor::{BAND_TICKS, band_size, with_margin};
    let hundredths = |v: u64| format!("{}.{:02}", v / 100, v % 100);
    let mut fits = Vec::new();
    let mut parts = Vec::new();
    for kind in compositor::PRICES.iter().map(|p| p.kind) {
        let Some((fit, slack)) = fit_of(costs, kind) else {
            parts.push(format!("{kind}: no fit (shapes missing)"));
            continue;
        };
        let widths: Vec<String> = row_costs(costs, kind)
            .iter()
            .map(|(w, g, l)| format!("{w} wide {l}..{g}"))
            .collect();
        parts.push(format!(
            "{kind}: call {} (constant {}), row {} (constant {}), point {} (constant {}), the model overstates a shape by {slack} ticks at most; ticks a row by width, least..greatest: {}",
            fit.call,
            with_margin(fit.call as u32),
            hundredths(fit.row),
            hundredths(u64::from(with_margin(fit.row as u32))),
            hundredths(fit.point),
            hundredths(u64::from(with_margin(fit.point as u32))),
            widths.join(", ")
        ));
        fits.push((kind, fit));
    }
    let get = |kind: &str| fits.iter().find(|(k, _)| *k == kind).map(|(_, f)| *f);
    if let (Some(copy), Some(over), Some(black)) = (get("copy"), get("over"), get("black")) {
        let c = |f: compositor::fit::Fit| {
            (
                with_margin(f.call as u32),
                with_margin(f.row as u32),
                with_margin(f.point as u32),
            )
        };
        let (cc, cr, cp) = c(copy);
        let (oc, or, op) = c(over);
        let (bc, br, bp) = c(black);
        // A copy over the whole width: the lines of a band, the bands of the
        // screen.
        let (w, rows) = band_size(cc, cr, cp, 640);
        let full = 400u32.div_ceil(rows);
        // A damage the size of the cursor (12 by 19) and of a line of text
        // (200 by 16) over a copy.
        let (cw, ch) = band_size(cc, cr, cp, 12);
        let (tw, th) = band_size(cc, cr, cp, 200);
        // Eight windows with an alpha over the whole screen, and the black.
        let term = compositor::LAYER * 8;
        let (ew, er) = band_size(8 * oc + bc + term, 8 * or + br, 8 * op + bp, 640);
        let worst = |calls: u32, row: u32, point: u32, w: u32, h: u32| {
            u64::from(calls)
                + (u64::from(row) * u64::from(h) + u64::from(point) * u64::from(w) * u64::from(h))
                    .div_ceil(100)
        };
        parts.push(format!(
            "by the fitted constants: a copy over the whole width is a band of {w} by {rows} and a frame of the whole screen {full} bands (the table gives {}); a damage of the cursor's size a band of {cw} by {ch}, of a line of text {tw} by {th}; eight windows with an alpha a band of {ew} by {er} costing {} ticks by the model (BAND_TICKS, the work of a band by the model, is {BAND_TICKS}; the step around it costs up to about 2 400 ticks more, and the gate of a band is 16 328)",
            compositor::full_screen_bands(),
            worst(8 * oc + bc + term + compositor::BAND_FIXED, 8 * or + br, 8 * op + bp, ew, er)
        ));
    }
    parts.push(layer_text(costs));
    parts.join("; ")
}

/// The calibration against the table, per kind: each price as the least and the
/// greatest over its class (the greatest goes into the table as the measure, and
/// the spread between them tells a cost of a shape from a stray), the shape of the
/// greatest, and the operations a preemption left out.
pub fn calibration_text(costs: &[Calibration]) -> String {
    if costs.is_empty() {
        return "no calibration lines (a run without the steps feature)".to_owned();
    }
    let hundredths = |v: u64| format!("{}.{:02}", v / 100, v % 100);
    costs
        .iter()
        .map(|c| {
            let p = price(&c.kind);
            format!(
                "{}: call least {} greatest {} ({} operations, at {}x{}; table {}), row least {} greatest {} ({}, at {}x{}; table {}), point least {} greatest {} ({}, at {}x{}; table {}), {} preempted and left out",
                c.kind,
                c.call.least,
                c.call.greatest,
                c.call.n,
                c.call.w,
                c.call.h,
                p.call_measured,
                hundredths(c.row.least),
                hundredths(c.row.greatest),
                c.row.n,
                c.row.w,
                c.row.h,
                hundredths(u64::from(p.row_measured)),
                hundredths(c.point.least),
                hundredths(c.point.greatest),
                c.point.n,
                c.point.w,
                c.point.h,
                hundredths(u64::from(p.point_measured)),
                c.preempted
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The bands of a frame of one copy over the whole screen by the table, and
/// the words that say whether the period holds them.
pub fn full_frame_text() -> String {
    let bands = compositor::full_screen_bands();
    let verdict = if bands <= FULL_FRAME_BANDS_MAX {
        format!("within the {FULL_FRAME_BANDS_MAX} the period holds")
    } else {
        format!(
            "MORE THAN {FULL_FRAME_BANDS_MAX}: the full frame is no promise at 60 Hz under -icount"
        )
    };
    format!(
        "a frame of one copy over the whole screen takes {bands} bands by the table ({verdict})"
    )
}

/// The device's trace against what the probe did: the scanout was set to
/// the target (OPEN), the pool (the window of the first revision shown
/// directly), the target (a window came over it), the pool again (it went)
/// and the target at last (the window closed), all on the whole screen, in
/// this order.
pub fn bypass_trace_verdict(events: &[qemu::GpuTrace]) -> Result<(), String> {
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
    if gpu_probe::contains_in_order(&scanouts, &[1, 2, 1, 2, 1]) {
        Ok(())
    } else {
        Err(format!(
            "the trace of SET_SCANOUT shows resources {scanouts:?}, 1, 2, 1, 2, 1 in order expected"
        ))
    }
}

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
    // The third client's window over the window of the first revision (the
    // frame is put together), and the pool shown again once it has gone.
    for prefix in [ABOVE, LEGACY_BACK] {
        compare(run, &mut monitor, prefix)?;
    }
    run.expect_line(ENDED_B, |l| l == ENDED_B, WITHIN)?;
    // The holder of a scene: the two windows of the first client through
    // their elements, the window of the first revision shown directly under a
    // scene, and a scene composed on request.
    for prefix in [
        SCENE,
        SCENE_LEGACY,
        SCENE_STATIC,
        SCENE_COMPOSED,
        ELEMENT_STRETCH,
        ELEMENT_ORIENT,
        ELEMENT_BILINEAR,
        ELEMENT_ALPHA,
        ELEMENT_MASK,
        ELEMENT_MASK_CUT,
    ] {
        compare(run, &mut monitor, prefix)?;
    }
    run.expect_line(ENDED_S, |l| l == ENDED_S, WITHIN)?;
    // The compositor paints the legacy window's place black and says so
    // once that frame is shown, which can come after the launcher's line.
    run.expect_times(RELEASED, 3, WITHIN)?;
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
    cmd.args(qemu::gpu_trace(&scratch.trace()));
    let mut run = Run::start(cmd, Input::Null)?;
    let driven = drive(&mut run, &scratch);
    let outcome = run.stop();
    driven.map_err(|e| format!("comp-probe on {}: {e}", machine.name))?;
    verdict(&outcome.lines).map_err(|e| format!("comp-probe on {}: {e}", machine.name))?;
    let text = std::fs::read_to_string(scratch.trace())
        .map_err(|e| format!("comp-probe on {}: the trace file: {e}", machine.name))?;
    let events =
        qemu::parse_gpu_trace(&text).map_err(|e| format!("comp-probe on {}: {e}", machine.name))?;
    bypass_trace_verdict(&events).map_err(|e| format!("comp-probe on {}: {e}", machine.name))?;
    println!(
        "comp-probe on {}: the screen matched the guest's frames for a window, a rectangle of it, two windows, the black screen after a process ended, a window of the first revision shown from the pool (the trace shows the scanout on resource 2, no band put together over three FLUSHes), a window over it (resource 1) and the pool again (resource 2), then the two windows through the elements of a scene, a window of the first revision shown directly under a scene, a scene composed on request, and the scenes of the elements a stretch, the eight orientations, the bilinear mean, a global alpha and a mask, each the CRC the reference works out point by point",
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
    let output = run_until(cmd, crate::BOOT_TIMEOUT * 4, Some(S_ENDS), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED_S)?;
    qemu::expect_marker(&output, ENDED_B)?;
    qemu::expect_marker(&output, ENDED)?;
    if let Some(failed) = output
        .lines
        .iter()
        .find(|l| l.starts_with("comp-probe: failed"))
    {
        return Err(format!("comp-probe under -icount: {failed}"));
    }
    let (comp, driver) = steps_verdict(&output.lines)?;
    let most = frames_verdict(&output.lines)?;
    println!(
        "comp-probe on {}: the frames of the scenes took {most} steps at most (limit {FRAME_STEPS_MAX}): {}",
        machine.name,
        frame_steps(&output.lines, COMP_TAG)
            .iter()
            .map(|(n, b, u)| format!("frame {n} {b} steps {u} us"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "{}",
        crate::frame_probe::check_waits(&output.lines, init::table::comp::TABLE, "comp-probe")?
    );
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
    println!(
        "comp-probe on {}: {}; the cost of the layers inside the bands, ticks (BAND_TICKS {}): {}; the calibration of the prices on shapes of their own: {}; the upper fit over the shapes: {}; {}",
        machine.name,
        full_frame_text(),
        compositor::BAND_TICKS,
        raster_text(&raster_costs(&output.lines, COMP_TAG)),
        calibration_text(&calibrations(&output.lines, COMP_TAG)),
        fit_text(&shape_costs(&output.lines, COMP_TAG)),
        band_report(&output.lines, COMP_TAG)
    );
    Ok(())
}

/// The image of the probe of the late opening: the compositor leaves the tries of its start out
/// (the feature `late-open`), so the first DESCRIBE of the client opens the screen from a request.
pub const LATE_PROGRAMS: [ImageProgram; 4] = [
    ("init", "init", INIT_STACK_SIZE, &["table-comp"]),
    (
        "virtio-gpu",
        "virtio-gpu",
        gpu_probe::GPU_STACK_SIZE,
        &["steps"],
    ),
    ("compositor", "compositor", COMP_STACK_SIZE, &["late-open"]),
    ("comp-probe", "comp-probe", PROBE_STACK_SIZE, &["quick"]),
];

/// The details the compositor gives the steps of the opening from a request: a portion of the
/// frame buffer mapped, and the four steps of the finishing (SUBSCRIBE, the pipelines, the
/// cursor, the pool's source).
const STEP_SCREEN: u64 = 5001;
const STEP_SCREEN_FINISH: [u64; 4] = [5002, 5003, 5004, 5005];

/// The longest step of the opening of the screen, by the details of its steps: (mapping portion,
/// finishing), judged ticks. None for a part that no line shows.
pub fn late_steps(lines: &[String]) -> (Option<u64>, Option<u64>) {
    let longest = |wanted: fn(u64) -> bool| {
        lines
            .iter()
            .filter_map(|l| crate::step_line::parse(l).or_else(|| crate::step_line::parse_table(l)))
            .filter(|s| s.tag == COMP_TAG && wanted(s.detail))
            .map(|s| s.judged())
            .max()
    };
    (
        longest(|d| d == STEP_SCREEN),
        longest(|d| STEP_SCREEN_FINISH.contains(&d)),
    )
}

/// The verdict of the probe of the late opening: the screen opened once, no check of the client
/// failed, and the steps of the opening are under the gate.
pub fn late_verdict(lines: &[String]) -> Result<(u64, u64), String> {
    if let Some(failed) = lines.iter().find(|l| l.starts_with("comp-probe: failed")) {
        return Err(failed.clone());
    }
    let ready = lines.iter().filter(|l| l.as_str() == READY).count();
    if ready != 1 {
        return Err(format!("{ready} lines {READY:?}, 1 expected"));
    }
    crate::step_line::within_b(lines, COMP_TAG, crate::step_line::Kinds::All)?;
    let (Some(mapping), Some(finishing)) = late_steps(lines) else {
        return Err(
            "no step of the opening in the lines (a mapping portion and a finishing step)"
                .to_owned(),
        );
    };
    for (what, ticks) in [
        ("a mapping portion", mapping),
        ("a finishing step", finishing),
    ] {
        if ticks > PORTION_MAX {
            return Err(format!(
                "{what} of the opening took {ticks} ticks, over {PORTION_MAX}"
            ));
        }
    }
    Ok((mapping, finishing))
}

/// The run under -icount with the screen opened late.
pub fn late(machine: &qemu::Machine) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-comp-late.img", &LATE_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::GPU);
    cmd.args(qemu::ICOUNT);
    let output = run_until(cmd, crate::BOOT_TIMEOUT * 4, Some(B_ENDS), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED_B)?;
    qemu::expect_marker(&output, ENDED)?;
    let (mapping, finishing) = late_verdict(&output.lines)?;
    println!(
        "comp-late-probe on {}: the screen opened from a request; the longest step of the mapping work {mapping} ticks (portions of 32 pages), the longest finishing step {finishing} ticks (judged, gate {PORTION_MAX}, B {})",
        machine.name,
        crate::TERM_B
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_frames_the_service_told_are_counted_and_a_frame_over_the_limit_is_refused() {
        let line = |n: u64, b: u64| format!("service frame: 17 n {n} bands {b} us 100");
        let lines = vec![
            line(1, 13),
            "service frame: 12 n 2 bands 999999 us 5".to_owned(),
            line(3, 17_675),
        ];
        assert_eq!(super::frames_verdict(&lines), Ok(17_675));
        let lines = vec![line(1, 13), line(2, super::FRAME_STEPS_MAX + 1)];
        assert!(
            super::frames_verdict(&lines)
                .unwrap_err()
                .contains("frame 2")
        );
    }

    use super::*;

    fn good_run() -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        for (marker, n) in CHECKS.iter().chain(&[(READY, 1), (RELEASED, 3)]) {
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
        for _ in 0..2 {
            lines.push(RELEASED.to_owned());
        }
        lines.push(format!(
            "comp-probe: OPEN is BUSY while a closed window's mapping is{RELEASED}"
        ));
        lines.push(" kept".to_owned());
        assert_eq!(verdict(&lines), Ok(()));
    }

    fn scanout(res: u32) -> qemu::GpuTrace {
        qemu::GpuTrace::Scanout {
            id: 0,
            res,
            w: 640,
            h: 400,
            x: 0,
            y: 0,
        }
    }

    #[test]
    fn the_trace_of_the_direct_frames_needs_the_pool_twice_with_the_target_between() {
        let good: Vec<_> = [1, 2, 1, 2, 1].map(scanout).to_vec();
        assert_eq!(bypass_trace_verdict(&good), Ok(()));
        // A pointer's move and the like in between do not matter.
        let mut noisy = good.clone();
        noisy.insert(
            2,
            qemu::GpuTrace::Cursor {
                update: false,
                x: 1,
                y: 1,
                res: 3,
            },
        );
        assert_eq!(bypass_trace_verdict(&noisy), Ok(()));
        // The pool never shown, shown once only, or never given back.
        for bad in [
            [1, 1, 1].as_slice(),
            &[1, 2, 1],
            &[1, 2, 1, 2],
            &[2, 1, 2, 1],
        ] {
            let events: Vec<_> = bad.iter().map(|r| scanout(*r)).collect();
            assert!(bypass_trace_verdict(&events).is_err(), "{bad:?}");
        }
        // A scanout of another size is not the screen's.
        let mut small = good.clone();
        small[1] = qemu::GpuTrace::Scanout {
            id: 0,
            res: 2,
            w: 320,
            h: 200,
            x: 0,
            y: 0,
        };
        assert!(bypass_trace_verdict(&small).is_err());
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
    fn the_cost_lines_of_a_run_are_read_and_the_last_of_a_kind_counts() {
        let lines: Vec<String> = [
            "service raster: 17 copy calls 3 points 900 ticks 2700 big 280 330 small 40 50",
            "service raster: 17 over calls 2 points 400 ticks 9000 big 2000 2500 small 0 0",
            "service raster: 17 copy calls 6 points 1800 ticks 5000 big 270 330 small 40 60",
            "service raster: 12 copy calls 1 points 1 ticks 1 big 1 1 small 1 1",
            "service raster: 17 copy calls x",
        ]
        .iter()
        .map(|l| (*l).to_owned())
        .collect();
        let costs = raster_costs(&lines, COMP_TAG);
        assert_eq!(costs.len(), 2);
        assert_eq!((costs[0].kind.as_str(), costs[0].calls), ("copy", 6));
        assert_eq!(costs[1].big_worst, 2500);
        let text = raster_text(&costs);
        assert!(text.contains(
            "copy (table: call 780 constant 897, row 54.80 constant 63.02, point 1.38 constant 1.59; measured: no classes in this line): 6 calls, 1800 points, no large operation; call of an operation of 8 points or fewer least 40 greatest 60; over 64 points or more a point mean 2.77 least 2.70 greatest 3.30"
        ));
        assert!(raster_text(&[]).contains("no cost lines"));
    }

    /// The line with the large operations: the price of a point net of the
    /// call is the least of them less the least call, over its points; a line
    /// without them (an older build) is read as before.
    #[test]
    fn the_large_operations_give_the_price_of_a_point_net_of_the_call() {
        let lines: Vec<String> = [
            "service raster: 17 copy calls 31 points 90000 ticks 159000 big 156 352 small 765 851 large 20 160 6144 352",
            "service raster: 17 black calls 16 points 64000 ticks 28800 big 45 53 small 212 212 large 12 46 6400 53",
            "service raster: 17 over calls 5 points 900 ticks 9000 big 700 1300 small 0 0 large 0 0 0 0",
            "service raster: 17 copy calls 2 points 3 ticks 4 big 1 1 small 1 1 large 1 2",
        ]
        .iter()
        .map(|l| (*l).to_owned())
        .collect();
        let costs = raster_costs(&lines, COMP_TAG);
        assert_eq!(costs.len(), 3, "the line with a short tail is not read");
        let copy = &costs[0];
        assert_eq!(copy.large.unwrap().calls, 20);
        // 160 a hundred over 6144 points is 9830 ticks; less the call 765, over
        // the points: 147 a hundred.
        assert_eq!(copy.net_price(), Some(147));
        assert_eq!(costs[1].net_price(), Some(42));
        assert_eq!(costs[2].net_price(), None);
        let text = raster_text(&costs);
        assert!(text.contains(
            "20 large operations: least 1.60 at 6144 points, net of the call 1.47, greatest 3.52"
        ));
        assert!(text.contains(
            "black (table: call 209 constant 241, row 24.00 constant 27.60, point 0.38 constant 0.44;"
        ));
    }

    /// The three prices of the model come in the tail of the line.
    #[test]
    fn the_three_prices_are_read_from_the_tail_of_the_line() {
        let lines: Vec<String> = [
            "service raster: 17 copy calls 31 points 90000 ticks 159000 big 156 352 small 765 851 large 20 160 6144 352 price 851 1800 205 12 5 20",
            "service raster: 17 black calls 16 points 64000 ticks 28800 big 45 53 small 212 212 large 12 46 6400 53 price 212 900 49 4 2 12",
            "service raster: 17 over calls 5 points 900 ticks 9000 big 700 1300 small 0 0 large 0 0 0 0 price 0 0 0 0 0 0 7",
        ]
        .iter()
        .map(|l| (*l).to_owned())
        .collect();
        let costs = raster_costs(&lines, COMP_TAG);
        assert_eq!(costs.len(), 2, "a line with a long tail is not read");
        let m = costs[0].model.unwrap();
        assert_eq!((m.call, m.row, m.point), (851, 1800, 205));
        assert_eq!((m.calls, m.rows, m.points), (12, 5, 20));
        let text = raster_text(&costs);
        assert!(
            text.contains("measured: call 851 (12 operations), row 18.00 (5), point 2.05 (20)")
        );
        assert!(text.contains("measured: call 212 (4 operations), row 9.00 (2), point 0.49 (12)"));
    }

    /// The line of the full frame says its bands and whether the period holds
    /// them.
    #[test]
    fn the_full_frame_line_says_the_bands_and_the_verdict() {
        let text = full_frame_text();
        assert!(text.contains(&format!("takes {} bands", compositor::full_screen_bands())));
        assert!(
            compositor::full_screen_bands() <= FULL_FRAME_BANDS_MAX,
            "{text}"
        );
        assert!(text.contains("within the 45"));
    }

    #[test]
    fn the_calibration_lines_are_read_and_told_against_the_table() {
        let lines: Vec<String> = [
            "service calibration: 17 copy call 700 780 48 8 1 row 1500 2100 72 16 8 point 150 170 120 64 32 preempted 3",
            "service calibration: 17 black call 200 212 48 8 1 row 800 900 72 4 32 point 40 49 120 152 8 preempted 0",
            "service calibration: 12 copy call 1 1 1 1 1 row 1 1 1 1 1 point 1 1 1 1 1 preempted 0",
            "service calibration: 17 over call 1 2 3",
        ]
        .iter()
        .map(|l| (*l).to_owned())
        .collect();
        let costs = calibrations(&lines, COMP_TAG);
        assert_eq!(costs.len(), 2);
        assert_eq!(costs[0].kind, "copy");
        assert_eq!(
            costs[0].call,
            Class {
                least: 700,
                greatest: 780,
                n: 48,
                w: 8,
                h: 1
            }
        );
        assert_eq!(costs[0].point.greatest, 170);
        assert_eq!(costs[0].preempted, 3);
        let text = calibration_text(&costs);
        assert!(
            text.contains("copy: call least 700 greatest 780 (48 operations, at 8x1; table 780)")
        );
        assert!(text.contains("point least 1.50 greatest 1.70 (120, at 64x32; table 1.38)"));
        assert!(text.contains("3 preempted and left out"));
        assert!(calibration_text(&[]).contains("no calibration lines"));
    }

    /// Shapes made from a known model are fitted back to it, the cost of a row
    /// by width comes out as the row plus the width's points, and the bands by
    /// the fit are those of the model.
    #[test]
    fn the_shapes_are_fitted_and_the_bands_told() {
        let mut lines = Vec::new();
        for (kind, call, row, point) in [
            ("black", 220, 2_000, 50),
            ("copy", 760, 2_000, 150),
            ("over", 800, 2_000, 400),
        ] {
            for (w, h) in [
                (1u32, 1u32),
                (8, 1),
                (64, 1),
                (8, 8),
                (8, 16),
                (16, 8),
                (16, 16),
                (4, 16),
                (4, 32),
                (152, 8),
                (152, 16),
                (76, 16),
                (76, 32),
                (640, 1),
                (640, 8),
                (640, 13),
            ] {
                let ticks =
                    call + (row * u64::from(h) + point * u64::from(w) * u64::from(h)).div_ceil(100);
                lines.push(format!(
                    "service shape: 17 {kind} {w} {h} least {} greatest {ticks} n 12",
                    ticks - 1
                ));
            }
        }
        let shapes = shape_costs(&lines, COMP_TAG);
        assert_eq!(shapes.len(), 48);
        let (fit, slack) = fit_of(&shapes, "copy").unwrap();
        assert!(fit.call >= 760 && fit.call <= 761, "{fit:?}");
        assert!(slack <= 2, "{slack}");
        // A row at width 8 costs the row plus eight points: 20 + 12 ticks.
        let rows = row_costs(&shapes, "copy");
        assert_eq!(rows.iter().find(|r| r.0 == 8).map(|r| r.1), Some(32));
        assert_eq!(
            rows.iter().find(|r| r.0 == 152).map(|r| r.1),
            Some(20 + 228)
        );
        let text = fit_text(&shapes);
        assert!(text.contains("copy: call 76"));
        assert!(text.contains("a frame of the whole screen"));
        assert!(text.contains("eight windows with an alpha"));
        // Shapes that are missing are said so, and no price is made up.
        assert!(fit_text(&shapes[..2]).contains("no fit"));
    }

    #[test]
    fn the_bands_by_layers_are_read_from_their_lines() {
        let lines = vec![
            "service band: 17 layers 8 n 100 outside least 3000 greatest 3400 total greatest 17000 compose 14500 ops 10000".to_owned(),
            "service band: 17 layers 8 n 200 outside least 3000 greatest 3500 total greatest 17100 compose 14600 ops 10100".to_owned(),
            "service band: 17 layers 1 n 5 outside least 400 greatest 500 total greatest 4000 compose 1500 ops 1000".to_owned(),
            "service band: 12 layers 8 n 1 outside least 1 greatest 1 total greatest 1 compose 1 ops 1".to_owned(),
        ];
        let splits = band_splits(&lines, COMP_TAG);
        assert_eq!(splits.len(), 2);
        assert_eq!((splits[0].layers, splits[0].n), (1, 5));
        assert_eq!(
            (splits[1].layers, splits[1].n, splits[1].total),
            (8, 200, 17_100)
        );
        let text = band_split_text(&splits);
        assert!(text.contains(
            "8 layers (200 bands): around the operations 3000..3500 ticks, the model's 2948 (375..437 a layer)"
        ));
        assert!(band_split_text(&[]).contains("no lines"));
    }

    #[test]
    fn the_floor_of_the_bands_is_read_and_told_with_the_split() {
        let lines: Vec<String> = [
            "service band floor: 17 layers 8 n 1 total least 15900 compose 14800 ops 12000 above-gate 1",
            "service band floor: 17 layers 8 n 4 total least 15400 compose 14300 ops 11800 above-gate 3",
            "service band floor: 12 layers 8 n 1 total least 1 compose 1 ops 1 above-gate 0",
            "service band floor: 17 layers 8 n 4 total least 15400",
        ]
        .map(str::to_owned)
        .to_vec();
        let floors = band_floors(&lines, COMP_TAG);
        assert_eq!(floors.len(), 1);
        assert_eq!(
            (floors[0].n, floors[0].least, floors[0].above_gate),
            (4, 15_400, 3)
        );
        let text = band_report(&lines, COMP_TAG);
        assert!(text.contains(
            "8 layers (4 bands): the least band 15400 ticks of which compose 14300 and the operations 11800, 3 past the gate 16328"
        ));
        // A run without the feature tells no floor, place or histogram line: the report is
        // the split alone.
        let plain: Vec<String> =
            ["service band: 17 layers 8 n 1 outside least 1 greatest 1 total greatest 1 compose 1 ops 1"]
                .map(str::to_owned)
                .to_vec();
        assert!(band_floors(&plain, COMP_TAG).is_empty());
        assert!(band_places(&plain, COMP_TAG).is_empty());
        let report = band_report(&plain, COMP_TAG);
        assert!(report.contains("8 layers (1 bands)"));
        assert!(!report.contains("floors of the bands") && !report.contains("places of the bands"));
        let more: Vec<String> = [
            "service band place: 17 rest n 5 greatest 14000 past-gate 0",
            "service band place: 17 rest n 9 greatest 15000 past-gate 1",
            "service band place: 17 before-cap n 2 greatest 15500 past-gate 2",
            "service band histogram: 17 layers 2+ from 11000 step 500: [0, 1]",
            "service band trace: 12 system least 1",
        ]
        .map(str::to_owned)
        .to_vec();
        let places = band_places(&more, COMP_TAG);
        assert_eq!(places.len(), 3);
        assert!(places[0].starts_with("place: 17 rest n 9"));
        assert!(band_report(&more, COMP_TAG).contains("places of the bands: place: 17 rest n 9"));
        // The line of the split keeps its own fields.
        assert!(band_splits(&lines, COMP_TAG).is_empty());
    }

    #[test]
    fn the_term_of_a_layer_is_the_excess_of_each_layer_added() {
        let mut lines = Vec::new();
        let mut shape = |kind: &str, w: u32, h: u32, ticks: u64| {
            lines.push(format!(
                "service shape: 17 {kind} {w} {h} least {} greatest {ticks} n 12",
                ticks - 1
            ));
        };
        // Operations on a plane: black 200 + 1 a point, over 800 + 4 a point.
        for (w, h) in [
            (8u32, 1u32),
            (64, 1),
            (150, 1),
            (64, 16),
            (150, 8),
            (16, 8),
            (4, 32),
        ] {
            let p = u64::from(w) * u64::from(h);
            shape("black", w, h, 200 + p);
            shape("over", w, h, 800 + 4 * p);
        }
        // Bands of layers: each layer after the first costs 300 more.
        for (w, h) in [(64u32, 1u32), (150, 1)] {
            let p = u64::from(w) * u64::from(h);
            for n in [1u64, 2, 4, 8] {
                shape(
                    &format!("layers{n}"),
                    w,
                    h,
                    200 + p + n * (800 + 4 * p) + 300 * (n - 1),
                );
            }
        }
        let t = layer_term(&shape_costs(&lines, COMP_TAG)).unwrap();
        assert_eq!(t.one, 0);
        assert_eq!(t.term, 300);
        assert_eq!(t.by_count, vec![(2, 300), (4, 300), (8, 300)]);
        assert!(layer_text(&shape_costs(&lines, COMP_TAG)).contains("each layer added 300"));
        assert!(layer_text(&[]).contains("no lines"));
    }

    #[test]
    fn steps_under_the_bounds_pass() {
        let (comp, driver) = steps_verdict(&rows(None, None)).unwrap();
        assert_eq!(comp.len(), COMP_KINDS.len());
        assert_eq!(driver.len(), DRIVER_KINDS.len());
    }

    /// The gate of a band that the cap of a period divides by is the portion
    /// gate of the probes, 0.8 of term B.
    #[test]
    fn the_gate_of_a_band_is_the_portion_gate() {
        assert_eq!(u64::from(compositor::BAND_GATE), PORTION_MAX);
        assert_eq!(compositor::frame::band_cap(16_666_667, 750_000), 47);
    }

    #[test]
    fn a_step_past_the_bound_or_a_missing_kind_fails() {
        assert!(steps_verdict(&rows(Some((COMP_TAG, 20, gpu_probe::STEP_MAX + 1)), None)).is_err());
        // A band past the portion bound fails for the own kind alone.
        assert!(steps_verdict(&rows(Some((COMP_TAG, 65, PORTION_MAX + 1)), None)).is_err());
        assert!(steps_verdict(&rows(Some((COMP_TAG, 20, PORTION_MAX + 1)), None)).is_ok());
        // A portion is judged like 0.9 B, by N - P * 1 300: 18 807 with three preemptions passes
        // (14 907), 17 000 with none and 18 000 with one (16 700) fail, and a kind with lines that
        // all have preemptions is judged.
        let with = |text: &str| {
            let mut lines = rows(Some((COMP_TAG, 65, 100)), None);
            lines.push(format!("service step: {COMP_TAG} kind 65 {text}"));
            lines
        };
        assert!(steps_verdict(&with("18807 ticks detail 0 preempts 3")).is_ok());
        assert!(steps_verdict(&with("17000 ticks detail 0")).is_err());
        let error = steps_verdict(&with("18000 ticks detail 0 preempts 1")).unwrap_err();
        assert!(error.contains("16700"), "{error}");
        let only_preempted: Vec<String> = rows(None, None)
            .into_iter()
            .filter(|l| !l.contains(&format!("{COMP_TAG} kind 65 ")))
            .chain([format!(
                "service step: {COMP_TAG} kind 65 18000 ticks detail 0 preempts 1"
            )])
            .collect();
        assert!(steps_verdict(&only_preempted).is_err());
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

    fn late_lines(mapping: u64, finishing: u64) -> Vec<String> {
        vec![
            READY.to_owned(),
            format!("service step: {COMP_TAG} kind 65 {mapping} ticks detail 5001"),
            format!("service step: {COMP_TAG} kind 65 {finishing} ticks detail 5002"),
        ]
    }

    #[test]
    fn the_stack_of_the_images_is_the_one_the_service_paints_in_its_steps_build() {
        assert_eq!(COMP_STACK_SIZE as usize, compositor::STACK_BYTES);
    }

    #[test]
    fn the_late_opening_is_judged_by_its_longest_steps() {
        assert_eq!(late_verdict(&late_lines(7_000, 9_000)), Ok((7_000, 9_000)));
        assert!(late_verdict(&late_lines(PORTION_MAX + 1, 9_000)).is_err());
        assert!(late_verdict(&late_lines(7_000, PORTION_MAX + 1)).is_err());
        let mut lines = late_lines(7_000, 9_000);
        lines.remove(2);
        assert!(late_verdict(&lines).is_err());
        let mut lines = late_lines(7_000, 9_000);
        lines.remove(0);
        assert!(late_verdict(&lines).is_err());
        let mut lines = late_lines(7_000, 9_000);
        lines.push("comp-probe: failed: DESCRIBE".to_owned());
        assert!(late_verdict(&lines).is_err());
    }
}
