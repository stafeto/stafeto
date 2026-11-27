// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask frame-probe [counters]`: the frame time under the loads.
//!
//! One boot of the image of the measures (`boot-frame-steps.img`, init's table
//! `table::frame`) runs the ten phases of `tests/frame-load` (quiet, idle,
//! full, cpu, files, net, full-loaded, direct, hog-ref, overload) under -icount
//! on one CPU. The
//! conductor reads the service's statistics (STATS) at the end of each phase
//! and prints them; this module reads the lines and judges each phase against
//! the bound of the analysis of the frame time:
//!
//! - `quiet` and `hog-ref`: no frame and no wake-up of the frame's timer (in
//!   `hog-ref` the CPU load runs alone and its loops a second are the reference);
//! - `idle`, `cpu`, `files`, `net` (the scene P): no late frame, no skip, the
//!   window of the client neither late nor missed, the time to compose under
//!   the bound of its row; the report says how many times the budgets of the
//!   network service were spent in the run, and says so when none was;
//! - `full` (the scene F): the same, with the bound computed from the bands of
//!   the frame as measured, when the frame has no more than 45 bands; with more
//!   the phase is a load phase and says so;
//! - `full-loaded` (F with all the loads): at least half of the periods make a frame,
//!   late and skipped frames are printed, and the loop of the CPU load turned;
//! - `direct` (a window of the first revision shown from the pool): no late
//!   frame, no skip, every frame direct, the time to compose under the bound;
//! - `overload` (eight windows of 320 by 200 with an alpha, each posted whole
//!   every period, the CPU load alone): `capped` at least `releases` and at least
//!   half the periods, `skipped` above 0, `late` equal to the frames, frames at
//!   least a period count over (the bands of the frame over the cap, rounded up,
//!   and one), and the loops of the CPU load at least 0.08 of the reference;
//! - every step of the services under the gates of the steps (18 369 ticks, a
//!   band or a portion 16 328), the kinds of SET and STATS and the timer's step
//!   among them.
//!
//! `counters` runs the image on QEMU's own clock (no -icount) and asks for
//! the shape of the lines and the counts alone, with no requirement of time.

use crate::frame_image;
use compositor::frame::{Source, bound};
use frame_load::phases::{ORDER, PERIODS, Phase};
use init::table::Kind;
use init::table::frame::TABLE;

/// The tick of the counter under -icount: 62.5 MHz.
const TICK_NS: u64 = 16;
/// The terms of the bound (the design of the frame time): the taking at the start of a period,
/// a band, the commit and the end of a frame (two steps), the longest kernel path with a step,
/// the display driver, the disk (two steps), the requests of the clients and the events of a
/// budget.
const TAKING: u64 = 3_000;
/// The gate of a band or a portion and the gate of any step of a service (the
/// probes' own constants).
const BAND: u64 = crate::PORTION_MAX;
const STEP: u64 = crate::gpu_probe::STEP_MAX;
const KERNEL: u64 = 38_779;
const DRIVER: u64 = 13_596;
/// The round trip of a call (C_ipc of the analysis of the waits, `CALL_WAIT_MAX`) with the step of the request.
const C_IPC: u64 = 2_034;
const REQUESTS: u64 = 10_000;
const EVENTS: u64 = 1_875;
const LIMIT: u64 = 10_000_000;
/// The period of the clock in microseconds (60 Hz, as the service's default).
const PERIOD_US: u64 = 16_667;
/// The time from the show to the client's post (about 1,240 us): the compositor's end step
/// returning the buffer, the longest kernel path, and the round trip of the POST with its
/// step. A margin built from the probe's constants.
const POST_US: u64 = us(2 * STEP + KERNEL + C_IPC);
/// The acceptance limit of the whole screen with no load: a frame with more bands than this
/// does not fit a period (a decision of the design, which a test holds against the bound of the
/// row and the service's own count of the bands of the screen).
const FULL_BANDS_MAX: u64 = 45;
/// The frames of a phase of 240 periods: the counters start 50 ms after the
/// phase starts and are read 5 ms before it ends, which leaves about 237.
const FRAMES_MIN: u64 = 230;
const FRAMES_MAX: u64 = 242;
/// The frames the whole screen under all the loads must still make: half of the
/// periods.
const STRESS_FRAMES_MIN: u64 = PERIODS / 2;
/// The share of its loop alone the CPU load must keep under the overload: the
/// cap and three steps leave the service most of a period and the console and
/// the signs of life take a few percent, so about a tenth is left.
const HOG_FLOOR_PPM: u64 = 80_000;
/// The share of a period the service may use at most, in parts per million:
/// the bands the cap lets it make in a period, each at the gate of a band, and
/// the three steps of a frame beside them (the take, the commit and the end, each at
/// the gate of a step), over the ticks of a period. The CPU the levels below it can count on is what
/// the budgets above leave of the rest.
fn service_share_ppm() -> u64 {
    use compositor::frame::DEFAULT_PERIOD_NS;
    (u64::from(frame_cap_bands()) * BAND + 3 * STEP) * 1_000_000 / (DEFAULT_PERIOD_NS / TICK_NS)
}

/// The share of the processor the service takes in a phase of the scene P or D, in parts per
/// million: the greatest time to compose of a frame over the period, taking one frame in each
/// period (the worst the phase shows).
fn compose_share_ppm(compose_max_us: u64) -> u64 {
    compose_max_us * 1_000_000 / (compositor::frame::DEFAULT_PERIOD_NS / 1_000)
}

/// The share of its loop alone the CPU load is promised in a phase that has the file load:
/// the processor less the compositor (`service_ppm`), less the budgets of the services above
/// the compositor, less the budget the file load keeps itself to (`FILE_SHARE_PPM`). Nothing
/// when they take it all.
fn files_floor_ppm(service_ppm: u64) -> u64 {
    1_000_000u64
        .saturating_sub(service_ppm)
        .saturating_sub(budgets_share_ppm())
        .saturating_sub(frame_load::loads::FILE_SHARE_PPM)
}

/// The share of its loop alone the CPU load made in `phase` against the floor `files_floor_ppm`
/// gives for the compositor's share `service_ppm`: `(share, floor)`, or what the phase got
/// when it fell short. A share of nothing fails whatever the floor.
fn hog_share(lines: &[String], phase: Phase, service_ppm: u64) -> Result<(u64, u64), String> {
    let alone = loops(lines, Phase::Quiet).unwrap_or(0);
    let share = loops(lines, phase)
        .map(|n| n * 1_000_000 / alone.max(1))
        .unwrap_or(0);
    let floor = files_floor_ppm(service_ppm);
    if share == 0 || share < floor {
        return Err(format!(
            "the CPU load got {} of the loop alone (floor {}) under the file load",
            frac(share),
            frac(floor)
        ));
    }
    Ok((share, floor))
}

/// A tick count in microseconds.
const fn us(ticks: u64) -> u64 {
    ticks * TICK_NS / 1_000
}

/// The term of the signs of life of the image: each service above the compositor
/// with no budget puts a sign of life and a step of init in a period (8 000
/// ticks), each with a budget only the step of init (2 400), and the service itself one
/// sign (8 000).
pub fn heartbeat_ticks() -> u64 {
    let above = |r: &&init::table::Record| matches!(r.kind, Kind::Service(_)) && r.priority > 32;
    let without = TABLE
        .iter()
        .filter(above)
        .filter(|r| r.budgets.is_empty())
        .count() as u64;
    let with = TABLE
        .iter()
        .filter(above)
        .filter(|r| !r.budgets.is_empty())
        .count() as u64;
    without * 8_000 + with * 2_400 + 8_000
}

/// The wakes of a budget of the record `r` in its period: the console's driver
/// takes the kernel log on the kernel's notification, at most once in the pace
/// of its takes (`uart::log::DRAIN_NS`), so up to its period over the pace; any
/// other source wakes once.
fn wakes(r: &init::table::Record, b: &init::table::Budget) -> u64 {
    if r.program == "uart" {
        b.t_ns.div_ceil(uart::log::DRAIN_NS)
    } else {
        1
    }
}

fn ticks_of(ns: u64) -> u64 {
    ns.div_ceil(TICK_NS)
}

/// The budgets on CPU 0 of the services above the compositor, as the sources
/// of interference of the bound; with `only_console` the console's alone.
pub fn sources(only_console: bool) -> Vec<Source> {
    TABLE
        .iter()
        .filter(|r| matches!(r.kind, Kind::Service(_)) && r.priority > 32)
        .filter(|r| !only_console || r.name == "uart")
        .flat_map(|r| r.budgets.iter().map(move |b| (r, b)))
        .filter(|(_, b)| b.cpu == 0)
        .map(|(r, b)| Source {
            budget: ticks_of(b.c_ns),
            period: ticks_of(b.t_ns),
            step: STEP,
            wakes: wakes(r, b),
        })
        .collect()
}

/// The level of the record `name` of `table`.
fn level_of(table: &[init::table::Record], name: &str) -> Result<u8, String> {
    table
        .iter()
        .find(|r| r.name == name)
        .map(|r| r.priority)
        .ok_or_else(|| format!("the table has no record {name}"))
}

/// The bound of the wait of a call of the service `caller` to the service
/// `callee` in the image whose records are `table`, in ticks: the response time
/// of the call by the formula of the frame (`bound`). The call returns when the
/// callee has run its step of the request, and the callee runs when no service
/// above it does; so the work of the call is the round trip of the request, the
/// step of the request and one step of the callee that was running (two steps of
/// the driver), the longest path of the kernel that is not preempted, the signs of life
/// of the services above the callee and the two steps of the disk. The sources are the budgets on CPU 0 of the
/// services above the callee, each at most ceil(w / T) times in the wait w (the
/// budget is a corrected sporadic server). A source adds its longest step only when
/// its level after the budget (`low`) is not under the caller's: it then stands
/// level with the caller and may run a step before the call returns.
/// An error when the table lacks a record or the iteration does not settle.
pub fn call_wait_bound(
    table: &[init::table::Record],
    caller: &str,
    callee: &str,
) -> Result<u64, String> {
    let from = level_of(table, caller)?;
    let to = level_of(table, callee)?;
    let above = |r: &&init::table::Record| matches!(r.kind, Kind::Service(_)) && r.priority > to;
    let signs: u64 = table
        .iter()
        .filter(above)
        .map(|r| if r.budgets.is_empty() { 8_000 } else { 2_400 })
        .sum();
    let sources: Vec<Source> = table
        .iter()
        .filter(above)
        .flat_map(|r| r.budgets.iter().map(move |b| (r, b)))
        .filter(|(_, b)| b.cpu == 0)
        .map(|(r, b)| Source {
            budget: ticks_of(b.c_ns),
            period: ticks_of(b.t_ns),
            step: if b.low >= from { STEP } else { 0 },
            wakes: wakes(r, b),
        })
        .collect();
    let own = C_IPC + 2 * DRIVER + KERNEL + signs + 2 * STEP;
    bound(own, &sources, EVENTS, LIMIT)
        .ok_or_else(|| format!("the wait of {caller} for {callee} has no bound under {LIMIT}"))
}

/// Fails when a wait in the lines of the compositor (tag 17) passes `call_wait_bound` of its
/// call to the display driver in the image `table`, or a wait of the driver (tag 12) passes
/// `call_wait_max` (`check_waits`). Returns the line that tells the greatest wait of the
/// compositor and its share of the bound.
pub fn check_waits(
    lines: &[String],
    table: &[init::table::Record],
    who: &str,
) -> Result<String, String> {
    use crate::comp_probe::{COMP_TAG, DRIVER_TAG};
    let limit = call_wait_bound(table, "gpu", "display")?;
    crate::check_waits_by(lines, &[COMP_TAG, DRIVER_TAG], who, &|tag, kind| {
        if tag == COMP_TAG {
            limit
        } else {
            crate::call_wait_max(tag, kind)
        }
    })?;
    let greatest = crate::longest_waits(lines, COMP_TAG)
        .iter()
        .map(|r| r.1)
        .max()
        .unwrap_or(0);
    Ok(format!(
        "{who}: the greatest wait of the compositor {greatest} ticks, {} per cent of the bound {limit}",
        greatest * 100 / limit
    ))
}

/// The share of CPU 0 the budgets above the compositor take, in parts per
/// million.
pub fn budgets_share_ppm() -> u64 {
    TABLE
        .iter()
        .filter(|r| matches!(r.kind, Kind::Service(_)) && r.priority > 32)
        .flat_map(|r| r.budgets.iter())
        .filter(|b| b.cpu == 0)
        .map(|b| b.share_ppm())
        .sum()
}

/// The bands a layer-by-layer frame of `w` by `h` points takes, by the model of
/// the service's `Scene::tile`: `opaque` windows of XRGB8888, `over` of ARGB8888
/// and `fill` black layers all touching the damage, no pointer. A band is as
/// many whole lines as the ticks allow (at most BAND_ROWS) or, when not even
/// one line fits, a run of one line, the lines cut in as many runs as it takes.
pub fn bands_of(w: u32, h: u32, opaque: u32, over: u32, fill: u32) -> u64 {
    use compositor::{FILL, LAYER, OPAQUE, OVER, band_size};
    // The calls of the layers, every layer costing `LAYER` more, the first too, as
    // `Scene::tile` charges them; the size of the band is the service's own.
    let calls =
        OPAQUE.call * opaque + OVER.call * over + FILL.call * fill + LAYER * (opaque + over);
    let per_row = OPAQUE.row * opaque + OVER.row * over + FILL.row * fill;
    let per_point = OPAQUE.point * opaque + OVER.point * over + FILL.point * fill;
    let (run, rows) = band_size(calls, per_row, per_point, w);
    if run >= w {
        return u64::from(h).div_ceil(u64::from(rows));
    }
    // A band is a run within one line and the next band starts the next piece
    // of the same line or the next line: every line is cut in `ceil(w / run)`
    // bands.
    u64::from(h) * u64::from(w).div_ceil(u64::from(run))
}

/// The bands of a window of 160 by 100 by the model (the scene of the rows P).
pub fn p_bands() -> u64 {
    bands_of(160, 100, 1, 0, 0)
}

/// The bands of a frame of the overload: eight windows of 320 by 200 points
/// with an alpha over one another, no opaque one under them (the black
/// layer is made as well).
pub fn overload_frame_bands() -> u64 {
    bands_of(320, 200, 0, 8, 1)
}

/// The frames the overload must still show: the periods over the periods a
/// frame of the scene takes at the cap, and one for the take at the start of a
/// period after the frame is shown.
pub fn overload_floor_frames() -> u64 {
    PERIODS / (overload_frame_bands().div_ceil(u64::from(frame_cap_bands())) + 1)
}

/// The bands the service makes in a period at most.
pub fn frame_cap_bands() -> u32 {
    use compositor::frame::{DEFAULT_CAP_PPM, DEFAULT_PERIOD_NS, band_cap};
    band_cap(DEFAULT_PERIOD_NS, DEFAULT_CAP_PPM)
}

/// The bound of the latency from a post to its prepared image ready (`compositor::prep`), in
/// ticks, for a transform of kind `kind` (a row of `compositor::PRICES`) into an image of `w`
/// by `h` points, made by the worker at `level`. It is a model bound (the response time by the
/// formula of the frame over the prices of the model), not a measure. The terms:
///
/// - the worker's own work: its pieces of `compositor::prep::PIECE_POINTS` points (whole lines),
///   a call of pixman each at the model's price, with the loss of the cache of paths once;
/// - `B_worker`, the blocking by a pass of a lower level that is in its piece when the post comes:
///   the longest piece of the dearest kind (the nearest point or the bilinear mean, copied);
/// - the passes of the other slots at or above `level` that come first (`others`: kind and size
///   of each), each its whole work;
/// - the wake path of the post (the round trip of the request and the longest path of the kernel
///   that is not preempted) and the step of the service that was running when it came;
/// - the sources above the worker: the compositor itself, which makes `bands` bands of at most their
///   gate in every period (the bands of the scene's frame, or at most the cap's `frame_cap_bands`),
///   and, with `loaded`, the budgets on CPU 0 of the services of the table above `level` with
///   their signs of life. The worker's own time is outside the budgets of the clients: it runs at
///   the poster's level on the service's own account, not on the poster's budget.
///
/// None when a kind has no price or the shares leave the worker no CPU (the iteration does not
/// settle).
pub fn image_latency_bound(
    level: u8,
    kind: &str,
    (w, h): (u32, u32),
    others: &[(&str, u32, u32)],
    bands: u64,
    loaded: bool,
) -> Option<u64> {
    use compositor::frame::DEFAULT_PERIOD_NS;
    use compositor::prep::piece_rows;
    let work = |kind: &str, w: u32, h: u32| -> Option<u64> {
        let mut own = u64::from(compositor::kind_miss_ticks(kind)?);
        let mut y = 0;
        while y < h {
            let rows = piece_rows(w).min(h - y);
            own += compositor::kind_model_ticks(kind, w, rows)?;
            y += rows;
        }
        Some(own)
    };
    let mut own = work(kind, w, h)?;
    for (k, ow, oh) in others {
        own += work(k, *ow, *oh)?;
    }
    let piece = |kind: &str| compositor::kind_model_ticks(kind, w, piece_rows(w)).unwrap_or(0);
    own += piece("scale-nearest-copy").max(piece("scale-bilinear-copy"));
    let above = |r: &&init::table::Record| {
        loaded && matches!(r.kind, Kind::Service(_)) && r.priority > level
    };
    let signs: u64 = TABLE
        .iter()
        .filter(above)
        .map(|r| if r.budgets.is_empty() { 8_000 } else { 2_400 })
        .sum();
    own += C_IPC + KERNEL + STEP + signs;
    let period = ticks_of(DEFAULT_PERIOD_NS);
    let mut sources = vec![Source {
        budget: bands * BAND,
        period,
        step: BAND,
        wakes: 1,
    }];
    sources.extend(
        TABLE
            .iter()
            .filter(above)
            .filter(|r| r.program != "compositor")
            .flat_map(|r| r.budgets.iter().map(move |b| (r, b)))
            .filter(|(_, b)| b.cpu == 0)
            .map(|(r, b)| Source {
                budget: ticks_of(b.c_ns),
                period: ticks_of(b.t_ns),
                step: if b.low >= level { STEP } else { 0 },
                wakes: wakes(r, b),
            }),
    );
    bound(own, &sources, EVENTS, LIMIT)
}

/// The service's own steps that prepared images add to the work of a frame's period, ticks: each
/// image the worker publishes is one step of the service (PREP: the raster wraps the image and
/// the screen is damaged), and the end of the frame that frees buffers and lets go of the images
/// is another (`Scene::end`, counted in the `2 * STEP` of the frame already). The terms of a row
/// that has `images` published in the period are `own(row) + prep_steps(images)`; the rows P, D
/// and F, which have none, are as they were.
pub fn prep_steps(images: u64) -> u64 {
    images * STEP
}

/// The model bounds of the prepared images, as the report tells them (a model, not a measure): the
/// latency from a post to the image of the cube's element ready at level 28, with the bands of the
/// scene P in each period and no load, with another slot ahead, at the cap of the frame and with
/// the loads; and the step a published image adds to the work of a period.
pub fn image_model_report() -> String {
    let kind = "scale-nearest-copy";
    let p = p_bands();
    let cap = u64::from(frame_cap_bands());
    let ticks = |bound: Option<u64>| bound.map_or("none".to_owned(), |t| t.to_string());
    format!(
        "frame-probe: prepared images, model bounds (not measures), ticks of 16 ns: post to image at level 28 (80 by 80, scene P bands {p}): {}, behind another slot {}, at the cap of {cap} bands {}, with the loads {}; a published image adds {} ticks to the work of a period",
        ticks(image_latency_bound(28, kind, (80, 80), &[], p, false)),
        ticks(image_latency_bound(
            28,
            kind,
            (80, 80),
            &[(kind, 80, 80)],
            p,
            false
        )),
        ticks(image_latency_bound(28, kind, (80, 80), &[], cap, false)),
        ticks(image_latency_bound(28, kind, (80, 80), &[], p, true)),
        prep_steps(1),
    )
}

/// The rows of the table of bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Row {
    /// A window of 160 by 100 under all the loads.
    P,
    /// A frame shown directly from the pool under all the loads.
    D,
    /// The whole screen of this many bands with no load.
    F(u64),
    /// The whole screen of this many bands under all the loads: the sources of
    /// the image all stand above the service, and the disk and the requests of
    /// the clients are in the frame.
    FullLoaded(u64),
}

/// The own work of a frame of a row, in ticks.
pub fn own(row: Row) -> u64 {
    let (bands, disk, requests) = match row {
        Row::P => (p_bands(), true, true),
        Row::D => (0, true, true),
        Row::F(bands) => (bands, false, false),
        Row::FullLoaded(bands) => (bands, true, true),
    };
    let mut w = TAKING + bands * BAND + 2 * STEP + KERNEL + DRIVER + heartbeat_ticks();
    if disk {
        w += 2 * STEP;
    }
    if requests {
        w += REQUESTS;
    }
    // A direct frame has no taking by bands (the taking is the commit's).
    if row == Row::D {
        w -= TAKING;
    }
    w
}

/// The bound of the frame time of a row, in ticks.
pub fn bound_ticks(row: Row) -> Option<u64> {
    let sources = sources(matches!(row, Row::F(_)));
    bound(own(row), &sources, EVENTS, LIMIT)
}

/// The words of a line as numbers by name: `late 0 skipped 3`.
fn field(line: &str, name: &str) -> Option<u64> {
    // The first three words are the program's, the kind of the line and the phase.
    let mut words = line.split_whitespace().skip(3);
    while let Some(w) = words.next() {
        if w == name {
            return words.next()?.parse().ok();
        }
    }
    None
}

fn line_of<'a>(lines: &'a [String], prefix: &str) -> Option<&'a String> {
    lines.iter().find(|l| l.starts_with(prefix))
}

/// What a phase's lines say.
#[derive(Debug, Clone, Copy)]
struct Phased {
    frames: u64,
    late: u64,
    skipped: u64,
    failed: u64,
    wakeups: u64,
    compose_max_us: u64,
    direct: u64,
    capped: u64,
    releases: u64,
    bands: u64,
}

fn read_phase(lines: &[String], phase: Phase) -> Result<Phased, String> {
    let name = phase.name();
    let line = line_of(lines, &format!("frame-load: phase {name} "))
        .ok_or_else(|| format!("no line of the phase {name}"))?;
    let get = |word: &str| {
        field(line, word).ok_or_else(|| format!("the line of the phase {name} has no {word}"))
    };
    let bands = line_of(lines, &format!("frame-load: bands {name} "))
        .and_then(|l| l.split_whitespace().nth(3))
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("no line of the bands of the phase {name}"))?;
    if !lines
        .iter()
        .any(|l| l.starts_with(&format!("frame-load: hist {name} ")))
    {
        return Err(format!("no histogram of the phase {name}"));
    }
    Ok(Phased {
        frames: get("frames")?,
        late: get("late")?,
        skipped: get("skipped")?,
        failed: get("failed")?,
        wakeups: get("wakeups")?,
        compose_max_us: get("compose-max-us")?,
        direct: get("direct")?,
        capped: get("capped")?,
        releases: get("releases")?,
        bands,
    })
}

/// The window of a phase: the counts of the window that posted most.
fn window_of(lines: &[String], phase: Phase) -> Option<(u64, u64, u64, u64)> {
    let prefix = format!("frame-load: window {} ", phase.name());
    lines
        .iter()
        .filter(|l| l.starts_with(&prefix))
        .filter_map(|l| {
            Some((
                field(l, "posts")?,
                field(l, "taken")?,
                field(l, "late")?,
                field(l, "missed")?,
            ))
        })
        .max_by_key(|w| w.0)
}

/// The loops a second the CPU load made in a phase.
fn loops(lines: &[String], phase: Phase) -> Option<u64> {
    field(
        line_of(lines, &format!("frame-load: cpu {} ", phase.name()))?,
        "loops-per-s",
    )
}

/// A line the compositor told for a late frame: the phases in microseconds and the
/// longest of them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LateLine {
    take_us: u64,
    compose_us: u64,
    device_us: u64,
    frame_us: u64,
    cause: String,
}

/// The late-frame lines the compositor printed for `phase`: the ones between the line of the
/// phase before it and the line of this phase (STATS prints them just before the conductor
/// prints the phase's counters).
fn late_lines(lines: &[String], phase: Phase) -> Vec<LateLine> {
    let prefix = format!("frame-load: phase {} ", phase.name());
    let Some(end) = lines.iter().position(|l| l.starts_with(&prefix)) else {
        return Vec::new();
    };
    let start = lines[..end]
        .iter()
        .rposition(|l| l.starts_with("frame-load: phase "))
        .map_or(0, |i| i + 1);
    lines[start..end]
        .iter()
        .filter(|l| l.starts_with("compositor: late frame"))
        .filter_map(|l| {
            Some(LateLine {
                take_us: field(l, "take")?,
                compose_us: field(l, "compose")?,
                device_us: field(l, "device")?,
                frame_us: field(l, "frame")?,
                cause: l
                    .split("(the longest: ")
                    .nth(1)?
                    .strip_suffix(')')?
                    .to_owned(),
            })
        })
        .collect()
}

/// Whether the late frames of a phase (one or two) are excused: the wait for the emulated device is the
/// host's (QEMU serves the display device on its main loop thread, so on a loaded host the
/// wait counts the instructions that pass until that thread has run), and the rest of the
/// frame is inside the analysis. Ok(false) is no late frame. Ok(true) holds only when the
/// phase has the CPU load, every late frame is told as the device's, take and compose are
/// under the bound less the kernel path, the driver and a step, the periods skipped are the
/// ones those frames cover, the window was late or missed once for each at most, as the frames'
/// lengths explain (a frame that shows by 2T may make it late, a longer one may make it miss),
/// and no step of
/// the display driver was longer than its term.
fn host_late(
    lines: &[String],
    phase: Phase,
    p: &Phased,
    (wtaken, wlate, wmissed): (u64, u64, u64),
    bound: u64,
) -> Result<bool, String> {
    if p.late == 0 {
        return Ok(false);
    }
    let no = |why: String| Err(format!("late {} skipped {} ({why})", p.late, p.skipped));
    if !phase.loads().cpu {
        return no("no excuse in a phase with no load".to_owned());
    }
    let told = late_lines(lines, phase);
    if told.len() as u64 != p.late {
        return no(format!(
            "{} late frames and {} told: only the told frames are excused",
            p.late,
            told.len()
        ));
    }
    if p.late > 2 {
        return no(format!("{} late frames: at most 2 are excused", p.late));
    }
    let limit = us(bound.saturating_sub(KERNEL + DRIVER + STEP));
    let mut periods = 0;
    let (mut a, mut b) = (0, 0);
    for late in &told {
        if late.cause != "device" {
            return no(format!("the longest phase is the {}'s", late.cause));
        }
        if late.take_us + late.compose_us > limit {
            return no(format!(
                "take {} us and compose {} us over {limit} us of the bound",
                late.take_us, late.compose_us
            ));
        }
        periods += (late.frame_us / PERIOD_US).saturating_sub(1);
        if late.frame_us + POST_US <= 2 * PERIOD_US {
            a += 1;
        } else {
            b += 1;
        }
    }
    if p.skipped > periods {
        return no(format!(
            "skipped {} over the {periods} the frames of {} us cover",
            p.skipped,
            told.iter()
                .map(|l| l.frame_us.to_string())
                .collect::<Vec<_>>()
                .join(" and ")
        ));
    }
    if wlate + wmissed > p.late {
        return no(format!("the window late {wlate} missed {wmissed}"));
    }
    if wtaken != p.frames {
        return no(format!(
            "the window took {wtaken} buffers for {} frames",
            p.frames
        ));
    }
    if wlate > a {
        return no(format!(
            "the window late {wlate} with {a} frames that can explain it: the lateness is the window's own"
        ));
    }
    if wmissed > b {
        return no(format!(
            "the window missed {wmissed} with {b} frames long enough: the buffer came back in time for the post"
        ));
    }
    let driver = crate::longest_steps(lines, crate::comp_probe::DRIVER_TAG);
    if let Some(row) = driver
        .iter()
        .find(|r| (r.0 == 6 || r.0 == 65) && r.1 > DRIVER)
    {
        return no(format!(
            "a step of the display driver past {DRIVER} ticks: {row:?}"
        ));
    }
    Ok(true)
}

/// The words of a phase's report for its late frame, when one is excused.
fn excused_report(lines: &[String], phase: Phase) -> String {
    let frames: Vec<String> = late_lines(lines, phase)
        .iter()
        .map(|l| ms(l.frame_us))
        .collect();
    format!(
        "late {} (the device's, {} ms: emulator main loop, excused)",
        frames.len(),
        frames.join(" and ")
    )
}

fn ms(us: u64) -> String {
    format!("{}.{:02}", us / 1_000, us % 1_000 / 10)
}

/// Judges the lines of a run. `timed` is a run under -icount, where time is
/// judged; without it only the shape and the counts are. The text is the report of the
/// phases, one line each.
pub fn verdict(lines: &[String], timed: bool) -> Result<Vec<String>, String> {
    if let Some(failed) = lines.iter().find(|l| {
        l.starts_with("frame-load: failed")
            || l.starts_with("net-probe: failed")
            || l.starts_with("data-probe: failed")
    }) {
        return Err(failed.clone());
    }
    // The loads did their work: the same check the loads' command makes.
    frame_image::loads_verdict(lines)?;
    let mut said = Vec::new();
    let mut full_judged_as_load = false;
    for phase in ORDER {
        let name = phase.name();
        let p = read_phase(lines, phase)?;
        let fail = |what: String| Err(format!("{name}: {what}"));
        if p.failed != 0 {
            return fail(format!("{} frames failed", p.failed));
        }
        match phase {
            Phase::Quiet | Phase::HogRef => {
                if p.frames != 0 || (timed && p.wakeups != 0) {
                    return fail(format!(
                        "frames {} wakeups {} with nothing drawn",
                        p.frames, p.wakeups
                    ));
                }
                if phase == Phase::HogRef && loops(lines, phase).is_none_or(|n| n == 0) {
                    return fail("the CPU load made no loop alone".to_owned());
                }
                said.push(format!(
                    "frame-probe: {name}: no frame, wakeups {}",
                    p.wakeups
                ));
            }
            Phase::Idle | Phase::Cpu | Phase::Files | Phase::Net | Phase::Full => {
                let (window, row) = if phase == Phase::Full {
                    let per = p.bands.div_ceil(p.frames.max(1));
                    (window_of(lines, phase), Row::F(per.min(FULL_BANDS_MAX + 1)))
                } else {
                    (window_of(lines, phase), Row::P)
                };
                if !(FRAMES_MIN..=FRAMES_MAX).contains(&p.frames) {
                    return fail(format!(
                        "{} frames of 240 periods ({FRAMES_MIN} to {FRAMES_MAX} expected)",
                        p.frames
                    ));
                }
                let Some((_, wtaken, wlate, wmissed)) = window else {
                    return fail("no line of the window".to_owned());
                };
                if let Row::F(bands) = row
                    && bands > FULL_BANDS_MAX
                {
                    // The whole screen does not fit a period: a load phase.
                    full_judged_as_load = true;
                    said.push(format!(
                        "frame-probe: full: {} frames of {} bands a frame (more than {FULL_BANDS_MAX}): judged as a load phase, late {} skipped {}",
                        p.frames, bands, p.late, p.skipped
                    ));
                    continue;
                }
                let bound = bound_ticks(row).ok_or_else(|| {
                    format!("{name}: the bound of the row {row:?} does not settle")
                })?;
                let mut late_said = format!("late {}", p.late);
                if timed {
                    if host_late(lines, phase, &p, (wtaken, wlate, wmissed), bound)
                        .map_err(|e| format!("{name}: {e}"))?
                    {
                        late_said = excused_report(lines, phase);
                    } else {
                        if p.skipped != 0 {
                            return fail(format!("late {} skipped {}", p.late, p.skipped));
                        }
                        if wlate != 0 || wmissed != 0 {
                            return fail(format!("the window late {wlate} missed {wmissed}"));
                        }
                    }
                    if p.compose_max_us > us(bound) {
                        return fail(format!(
                            "compose max {} us over the bound {} us (the bound is wrong or the frame too long)",
                            p.compose_max_us,
                            us(bound)
                        ));
                    }
                }
                // A phase with the file load also keeps the CPU load its share.
                let hog = if timed && phase.loads().files {
                    let (share, floor) =
                        hog_share(lines, phase, compose_share_ppm(p.compose_max_us))
                            .map_err(|e| format!("{name}: {e}"))?;
                    format!(", cpu share {} (floor {})", frac(share), frac(floor))
                } else {
                    String::new()
                };
                said.push(format!(
                    "frame-probe: {name}: {} frames, {late_said}, skipped {}, compose max {} ms (bound {} ms){hog}",
                    p.frames,
                    p.skipped,
                    ms(p.compose_max_us),
                    ms(us(bound))
                ));
            }
            Phase::FullLoaded => {
                // The whole screen under every load at once: the service keeps
                // delivering frames. Skips and lateness are the report's; the
                // frame of this scene fits a period, so none is required.
                let per = p.bands.div_ceil(p.frames.max(1));
                let row = Row::FullLoaded(per);
                let bound = bound_ticks(row).ok_or_else(|| {
                    format!("{name}: the bound of the row {row:?} does not settle")
                })?;
                if timed && p.compose_max_us > us(bound) {
                    return fail(format!(
                        "compose max {} us over the bound {} us of the whole screen of {per} bands under all the loads: the analysis does not cover the frame (a finding for the design)",
                        p.compose_max_us,
                        us(bound)
                    ));
                }
                if timed && p.frames < STRESS_FRAMES_MIN {
                    return fail(format!(
                        "{} frames of 240 periods under all the loads ({STRESS_FRAMES_MIN} at least)",
                        p.frames
                    ));
                }
                // What the levels below the service are promised: the period less the
                // service, the budgets above it and the file load's share, none when they
                // take it all.
                let (share, floor) = hog_share(lines, phase, service_share_ppm())
                    .map_err(|e| format!("{name}: {e}"))?;
                said.push(format!(
                    "frame-probe: full-loaded: 240 periods, frames {}, late {}, skipped {}, compose max {} ms (bound {} ms, {per} bands under all the loads), cpu share {} (floor {})",
                    p.frames,
                    p.late,
                    p.skipped,
                    ms(p.compose_max_us),
                    ms(us(bound)),
                    frac(share),
                    frac(floor)
                ));
            }
            Phase::Overload => {
                if timed {
                    let bands = overload_frame_bands();
                    let cap = u64::from(frame_cap_bands());
                    let floor = overload_floor_frames();
                    if p.capped < PERIODS / 2 {
                        return fail(format!(
                            "capped {} of {} periods (the cap does not hold the bands back)",
                            p.capped, PERIODS
                        ));
                    }
                    if p.capped + 1 < p.releases {
                        return fail(format!(
                            "capped {} periods, fewer than the {} frames released (one taking allowed)",
                            p.capped, p.releases
                        ));
                    }
                    // Skips are printed only: with the client unable to post while
                    // its frame is in work almost no change waits at a period start.
                    //
                    // `late` counts the frames that released a buffer of the windows,
                    // the ones of the scene, and each is late. A frame shown in the phase that
                    // released none (at most one) is the frame the end of the earlier
                    // phase made, black or tiny, which falls on either side of the
                    // boundary of the two readings of STATS by a few thousand ticks
                    // of difference in the cost of a band: it is made in its period.
                    if p.late != p.frames && !(p.late + 1 == p.frames && p.releases == p.late) {
                        return fail(format!(
                            "late {} of {} frames (a frame of {bands} bands over a cap of {cap} is late every time)",
                            p.late, p.frames
                        ));
                    }
                    if p.frames < floor {
                        return fail(format!(
                            "{} frames of {PERIODS} periods ({floor} at least for {bands} bands at {cap} a period)",
                            p.frames
                        ));
                    }
                    let alone = loops(lines, Phase::HogRef).unwrap_or(0);
                    let share = loops(lines, phase)
                        .map(|n| n * 1_000_000 / alone.max(1))
                        .unwrap_or(0);
                    if share < HOG_FLOOR_PPM {
                        return fail(format!(
                            "the CPU load kept {} of its loop alone (floor {}): the cap does not keep the promise",
                            frac(share),
                            frac(HOG_FLOOR_PPM)
                        ));
                    }
                    said.push(format!(
                        "frame-probe: overload: {} frames of {bands} bands, capped {}, skipped {}, late {}, cpu share {} (floor {}), longest band step {} (gates {} and {})",
                        p.frames,
                        p.capped,
                        p.skipped,
                        p.late,
                        frac(share),
                        frac(HOG_FLOOR_PPM),
                        match band_step_in(lines, Phase::HogRef, Phase::Overload) {
                            (Some((t, d)), _) =>
                                format!("{t} ticks in the phase, {}", own_step_kind(d)),
                            (None, before) =>
                                format!("none above the earlier greatest {before} ticks"),
                        },
                        crate::PORTION_MAX,
                        crate::gpu_probe::STEP_MAX
                    ));
                } else {
                    said.push(format!("frame-probe: overload: {} frames", p.frames));
                }
            }
            Phase::Direct => {
                if !(FRAMES_MIN..=FRAMES_MAX).contains(&p.frames) && timed {
                    return fail(format!("{} frames of 240 periods", p.frames));
                }
                if p.frames == 0 || p.direct != p.frames {
                    return fail(format!("{} frames of which {} direct", p.frames, p.direct));
                }
                let bound = bound_ticks(Row::D)
                    .ok_or_else(|| "direct: the bound does not settle".to_owned())?;
                let mut late_said = format!("late {}", p.late);
                if timed {
                    // The window of the first revision has no record of its own.
                    if host_late(lines, phase, &p, (p.frames, 0, 0), bound)
                        .map_err(|e| format!("{name}: {e}"))?
                    {
                        late_said = excused_report(lines, phase);
                    } else if p.skipped != 0 {
                        return fail(format!("late {} skipped {}", p.late, p.skipped));
                    }
                    if p.compose_max_us > us(bound) {
                        return fail(format!(
                            "compose max {} us over the bound {} us",
                            p.compose_max_us,
                            us(bound)
                        ));
                    }
                }
                let hog = if timed {
                    let (share, floor) =
                        hog_share(lines, phase, compose_share_ppm(p.compose_max_us))
                            .map_err(|e| format!("{name}: {e}"))?;
                    format!(", cpu share {} (floor {})", frac(share), frac(floor))
                } else {
                    String::new()
                };
                said.push(format!(
                    "frame-probe: direct: {} frames, all direct, {late_said}, skipped {}, compose max {} ms (bound {} ms){hog}",
                    p.frames,
                    p.skipped,
                    ms(p.compose_max_us),
                    ms(us(bound))
                ));
            }
        }
    }
    // How loaded the network service was: the journal of init counts, over the
    // whole run, the times the kernel found each of its budgets spent. A run
    // with none says so, and the bound's term for the service has been
    // exercised in part only.
    let overruns = netd_overruns(lines);
    let spent = overruns.iter().map(|(_, n)| *n).sum::<u64>();
    said.push(if spent == 0 {
        "frame-probe: netd: the budgets were not spent in the run, so the bound's term for the service is exercised in part"
            .to_owned()
    } else {
        format!(
            "frame-probe: netd: budgets spent in the run (the kernel's count of overruns){}",
            overruns
                .iter()
                .map(|(name, n)| format!(", {name} {n}"))
                .collect::<String>()
        )
    });
    // The loopback load: how much it did and where it waited (the `net` phase loads
    // the network only in part under -icount).
    if let Some(l) = line_of(lines, "net-probe: load rounds") {
        let n = |w: &str| {
            l.split_whitespace()
                .skip_while(|x| *x != w)
                .nth(1)
                .unwrap_or("?")
        };
        said.push(format!(
            "frame-probe: net load: rounds {}, longest round {} ms, send-again {}, recv-again {}",
            n("rounds"),
            n("longest-round-ms"),
            n("send-again"),
            n("recv-again")
        ));
    }
    if full_judged_as_load {
        said.push(
            "frame-probe: the whole-screen frame has more bands than the design allows: raise it in the report"
                .to_owned(),
        );
    }
    Ok(said)
}

/// What the detail of the compositor's longest own step (kind 65) says it was:
/// 1000 and the images made for a band, 2000 a take, 3000 the commit after the
/// last band, 4000 the end of a frame, 5000 housekeeping, 6000 the arming of
/// the timer after the cap of a period.
pub fn own_step_kind(detail: u64) -> String {
    match detail {
        1000..=1999 => format!("a band that made {} images", detail - 1000),
        2000..=2999 => "a take".to_owned(),
        3000..=3999 => "the commit after the last band".to_owned(),
        4000..=4999 => "the end of a frame".to_owned(),
        5000..=5999 => "housekeeping".to_owned(),
        6000..=6999 => "the arming of the timer after the cap".to_owned(),
        _ => format!("a step of detail {detail}"),
    }
}

/// The longest step of the compositor's own kind (65: a band and the end of a
/// frame) that the lines of the steps show between the end of the phase
/// `from` and the end of the phase `to`, and the longest before them. The
/// lines of a step come when a kind's greatest grows, so a phase with no line
/// had no step above the earlier greatest.
pub fn band_step_in(lines: &[String], from: Phase, to: Phase) -> (Option<(u64, u64)>, u64) {
    let at = |phase: Phase| {
        lines
            .iter()
            .position(|l| l.starts_with(&format!("frame-load: phase {} ", phase.name())))
    };
    let (Some(a), Some(b)) = (at(from), at(to)) else {
        return (None, 0);
    };
    let tag = crate::comp_probe::COMP_TAG;
    let kind65 = |part: &[String]| {
        crate::longest_steps(part, tag)
            .into_iter()
            .find(|r| r.0 == 65)
            .map(|r| (r.1, r.2))
    };
    (
        kind65(&lines[a..b]),
        kind65(&lines[..a]).map_or(0, |(t, _)| t),
    )
}

/// The overruns of the budgets of the network service by the lines of init's
/// journal (`init: netd budget NAME: ... kernel counts N`): the greatest count
/// of each budget.
pub fn netd_overruns(lines: &[String]) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = Vec::new();
    for l in lines {
        let Some(rest) = l.strip_prefix("init: netd budget ") else {
            continue;
        };
        let name = rest.split(':').next().unwrap_or("").to_owned();
        let Some(n) = rest
            .split_once("kernel counts ")
            .and_then(|(_, n)| n.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok())
        else {
            continue;
        };
        match out.iter_mut().find(|(k, _)| *k == name) {
            Some(e) => e.1 = e.1.max(n),
            None => out.push((name, n)),
        }
    }
    out
}

/// A share in parts per million as a decimal.
fn frac(ppm: u64) -> String {
    format!("{}.{:02}", ppm / 1_000_000, ppm % 1_000_000 / 10_000)
}

/// The steps of the services under the gates (the run under -icount): the
/// kinds that must come are the window methods, SET and STATS, the notice
/// (the frame's timer) and the service's own steps.
pub fn steps_verdict(lines: &[String]) -> Result<String, String> {
    const COMP: [(usize, &str); 7] = [
        (18, "WindowCreate"),
        (19, "Attach"),
        (20, "Post"),
        (24, "Set"),
        (25, "Stats"),
        (64, "the timer of the frame"),
        (65, "a band and the end of a frame"),
    ];
    const DRIVER: [(usize, &str); 5] = [
        (5, "Subscribe"),
        (6, "Commit"),
        (9, "Pipelines"),
        (10, "Source"),
        (65, "the interrupt"),
    ];
    let mut said = Vec::new();
    for (tag, name, kinds) in [
        (crate::comp_probe::COMP_TAG, "compositor", &COMP[..]),
        (crate::comp_probe::DRIVER_TAG, "display driver", &DRIVER[..]),
    ] {
        let rows = crate::longest_steps(lines, tag);
        for (kind, what) in kinds {
            if !rows.iter().any(|(k, ..)| k == kind) {
                return Err(format!("the {name}: no step {what}: {rows:?}"));
            }
        }
        let kind = |row: &(usize, u64, u64)| {
            if row.0 == 65 && tag == crate::comp_probe::COMP_TAG {
                format!(", {}", own_step_kind(row.2))
            } else {
                String::new()
            }
        };
        if let Some(row) = rows.iter().find(|r| r.1 > crate::gpu_probe::STEP_MAX) {
            return Err(format!(
                "the {name}: a step past the gate ({}): {row:?}{}",
                crate::gpu_probe::STEP_MAX,
                kind(row)
            ));
        }
        if let Some(row) = rows.iter().find(|r| r.0 == 65 && r.1 > crate::PORTION_MAX) {
            return Err(format!(
                "the {name}: a portion past {}: {row:?}{}",
                crate::PORTION_MAX,
                kind(row)
            ));
        }
        // After the gates the hard check against B covers every kind of both services: the probe judges all of
        // them against the gates below, and no kind is exempt (neither service has a start-up
        // step in this image).
        crate::step_line::within_b(lines, tag, crate::step_line::Kinds::All)
            .map_err(|e| format!("the {name}: {e}"))?;
        said.push(format!(
            "{name} {}",
            rows.iter()
                .map(|(k, t, _)| format!("kind {k} {t}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(said.join("; "))
}

/// `cargo xtask frame-probe [counters]`.
pub fn probe(args: &[String]) -> Result<(), String> {
    let (timed, trace) = match args {
        [] => (true, false),
        [word] if word == "counters" => (false, false),
        [word] if word == "trace" => (true, true),
        _ => return Err("frame-probe [counters|trace]".to_owned()),
    };
    let lines = frame_image::run_traced(timed, trace)?;
    // Told before the verdicts, so that a probe that fails still tells what the bands
    // of the overload (the only bands of eight layers of this run) cost.
    if timed {
        println!(
            "frame-probe: {}",
            crate::comp_probe::band_report(&lines, crate::comp_probe::COMP_TAG)
        );
    }
    let said = verdict(&lines, timed).map_err(|e| format!("frame-probe: {e}"))?;
    for line in &said {
        println!("{line}");
    }
    if timed {
        let waits = check_waits(&lines, TABLE, "frame-probe")?;
        println!("{waits}");
        let steps = steps_verdict(&lines).map_err(|e| format!("frame-probe: {e}"))?;
        println!("frame-probe: the longest steps, ticks: {steps}");
    }
    if timed {
        println!("{}", image_model_report());
    }
    println!(
        "frame-probe on {}: {} phases judged{}",
        crate::qemu::VIRT.name,
        ORDER.len(),
        if timed {
            " under -icount"
        } else {
            " by their counts (no time)"
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_load::phases::Scene;

    /// The bound of the wait of the compositor's call to the display driver in the image of the
    /// frame: the work of the call (the round trip, two steps of the driver, the kernel's longest
    /// path, the signs of life above the driver, two steps of the disk) with the budgets of CPU 0
    /// above the driver, and the iteration settles at a bound below the limit.
    #[test]
    fn the_wait_of_the_call_to_the_driver_is_the_response_time_of_the_image() {
        let w = call_wait_bound(TABLE, "gpu", "display").unwrap();
        assert_eq!(w, 527_932);
        // It is a fixed point of the formula: the work and the interference of the sources
        // over the wait give the wait again, and one tick less does not.
        let level = level_of(TABLE, "display").unwrap();
        let signs: u64 = TABLE
            .iter()
            .filter(|r| matches!(r.kind, Kind::Service(_)) && r.priority > level)
            .map(|r| if r.budgets.is_empty() { 8_000 } else { 2_400 })
            .sum();
        assert_eq!(signs, 6 * 2_400 + 2 * 8_000);
        let own = C_IPC + 2 * DRIVER + KERNEL + signs + 2 * STEP;
        let again = |w: u64, sources: &[Source]| {
            own + sources
                .iter()
                .map(|s| {
                    (w / s.period) * s.budget
                        + (w % s.period).min(s.budget)
                        + s.step
                        + 2 * EVENTS * s.wakes * w.div_ceil(s.period)
                })
                .sum::<u64>()
        };
        let sources: Vec<Source> = TABLE
            .iter()
            .filter(|r| matches!(r.kind, Kind::Service(_)) && r.priority > level)
            .flat_map(|r| r.budgets.iter().map(move |b| (r, b)))
            .filter(|(_, b)| b.cpu == 0)
            .map(|(r, b)| Source {
                budget: ticks_of(b.c_ns),
                period: ticks_of(b.t_ns),
                step: if b.low >= 32 { STEP } else { 0 },
                wakes: wakes(r, b),
            })
            .collect();
        assert_eq!(again(w, &sources), w);
        assert!(again(w - 1, &sources) > w - 1);
        // The console wakes four times in its period and the others once; the network's step
        // is no term (its `low` is 1).
        assert_eq!(
            sources
                .iter()
                .map(|s| s.wakes)
                .collect::<Vec<_>>()
                .iter()
                .filter(|&&k| k == 4)
                .count(),
            1
        );
        assert!(sources.iter().any(|s| s.step == 0));
        // The old bound of the calls held no interference at all.
        assert!(w > crate::call_wait_max("17", 65) * 10);
        // A table with no budgets above the driver has the work alone.
        assert_eq!(
            call_wait_bound(init::table::comp::TABLE, "gpu", "display"),
            Ok(C_IPC + 2 * DRIVER + KERNEL + 2 * STEP)
        );
        assert!(call_wait_bound(TABLE, "gpu", "nowhere").is_err());
    }

    /// The greatest wait of the compositor is told with its share of the bound, and a wait past
    /// the bound fails.
    #[test]
    fn a_wait_of_the_compositor_is_judged_by_the_bound_of_the_image() {
        let w = call_wait_bound(TABLE, "gpu", "display").unwrap();
        let at = |ticks: u64| {
            vec![format!(
                "service wait: 17 kind 65 {ticks} ticks of {}",
                ticks + 2_055
            )]
        };
        let said = check_waits(&at(62_481), TABLE, "t").unwrap();
        assert_eq!(
            said,
            format!(
                "t: the greatest wait of the compositor 62481 ticks, {} per cent of the bound {w}",
                62_481 * 100 / w
            )
        );
        assert!(check_waits(&at(w), TABLE, "t").is_ok());
        assert!(check_waits(&at(w + 1), TABLE, "t").is_err());
        // The driver stays on the bound of the calls.
        let driver = vec!["service wait: 12 kind 6 48001 ticks of 50000".to_owned()];
        assert!(check_waits(&driver, TABLE, "t").is_err());
    }

    /// The latency from a post to the prepared image of the cube's element (a turn by a quarter
    /// and a stretch to half, 80 by 80 points, the nearest point) at the level of the holders
    /// of the probes (28), by the model: with the bands of the scene P (a window of 160 by 100)
    /// in every period and no load the bound is within a period; with the pass of another slot
    /// ahead of it it is longer; at the cap of the frame (47 bands a period, which leaves the
    /// worker a quarter of the CPU) it is not within a period; with the budgets of the services
    /// above the worker the bound is longer than with none.
    #[test]
    fn the_image_of_a_post_is_ready_within_a_period_by_the_bound() {
        let period = ticks_of(compositor::frame::DEFAULT_PERIOD_NS);
        let kind = "scale-nearest-copy";
        let p = p_bands();
        let idle = image_latency_bound(28, kind, (80, 80), &[], p, false).expect("a bound");
        assert!(idle < period, "{idle} ticks over {period}");
        // A bigger target takes longer, and so does a pass of another slot ahead of it.
        let big = image_latency_bound(28, kind, (160, 160), &[], p, false).expect("a bound");
        assert!(big > idle);
        let behind =
            image_latency_bound(28, kind, (80, 80), &[(kind, 80, 80)], p, false).expect("a bound");
        assert!(behind > idle);
        // The budgets of the services above the worker add to the wait; a lower level has
        // more of them above it.
        let high = image_latency_bound(28, kind, (80, 80), &[], p, true);
        let low = image_latency_bound(10, kind, (80, 80), &[], p, true);
        assert!(high.is_none_or(|h| h >= idle));
        assert!(low.is_none_or(|l| high.is_none_or(|h| l >= h)));
        let capped =
            image_latency_bound(28, kind, (80, 80), &[], u64::from(frame_cap_bands()), false)
                .expect("a bound");
        assert!(capped > period, "{capped} ticks at the cap");
        println!(
            "image latency bound at 28 (model, ticks of 16 ns, period {period}): scene P {idle}, 160 by 160 {big}, behind another slot {behind}, at the cap {capped}, with the loads {high:?}"
        );
    }

    /// The report tells the bounds and none of them is missing.
    #[test]
    fn the_report_tells_the_model_bounds_of_the_images() {
        let line = image_model_report();
        assert!(
            line.starts_with("frame-probe: prepared images, model bounds"),
            "{line}"
        );
        assert!(!line.contains("none"), "{line}");
        assert!(line.contains(&format!("adds {} ticks", prep_steps(1))));
    }

    /// An image the worker publishes in a period is a step of the service: the frame's own work
    /// grows by `STEP` for each, and the rows with none are unchanged.
    #[test]
    fn a_published_image_adds_a_step_to_the_work_of_the_period() {
        assert_eq!(prep_steps(0), 0);
        assert_eq!(prep_steps(3), 3 * STEP);
        assert_eq!(own(Row::P) + prep_steps(1), own(Row::P) + STEP);
    }

    /// The numbers of the analysis for the image of the frame (the heartbeat 46 400).
    #[test]
    fn the_bounds_of_the_image_are_the_numbers_of_the_analysis() {
        assert_eq!(heartbeat_ticks(), 46_400);
        assert_eq!(bound_ticks(Row::P), Some(929_078));
        assert_eq!(bound_ticks(Row::D), Some(747_093));
        // The whole screen by the service's own count of the bands of the frame: the
        // row follows it, and the rows of the analysis for the counts it has had.
        let n = u64::from(compositor::full_screen_bands());
        assert!(bound_ticks(Row::F(n)).is_some());
        for (bands, own_ticks, bound) in [
            (31, 644_681, 711_800),
            (33, 677_337, 744_456),
            (34, 693_665, 760_784),
            (37, 742_649, 809_768),
        ] {
            assert_eq!(own(Row::F(bands)), own_ticks);
            assert_eq!(bound_ticks(Row::F(bands)), Some(bound));
        }
        // Under all the loads the whole screen has a bound past a period (1 041 667
        // ticks): the analysis does not promise this frame on time.
        assert_eq!(bound_ticks(Row::FullLoaded(31)), Some(1_744_397));
    }

    /// The limit of the whole screen holds the service's count of the bands and a bound inside
    /// a period, so a change of the terms of a band moves this test and not a literal.
    #[test]
    fn the_whole_screen_limit_follows_the_terms_of_a_band() {
        let period = compositor::frame::DEFAULT_PERIOD_NS / TICK_NS;
        assert!(u64::from(compositor::full_screen_bands()) <= FULL_BANDS_MAX);
        assert!(bound_ticks(Row::F(FULL_BANDS_MAX)).is_some_and(|b| b <= period));
        // The rows of the image are made of the model of the bands of the service.
        assert_eq!(p_bands(), 7);
    }

    /// The overload scene as the service lays it (eight windows with an alpha over one place):
    /// the model of the probe counts the bands the way `Scene::tile` does.
    #[test]
    fn the_band_model_agrees_with_the_service_for_the_overload() {
        use frame_load::paint::{O_RECT, O_WINDOWS};
        let mut s = compositor::Scene::new();
        let rect = proto_comp::Rect {
            x: O_RECT.x,
            y: O_RECT.y,
            w: O_RECT.w,
            h: O_RECT.h,
        };
        let own = proto_comp::Rect {
            x: 0,
            y: 0,
            w: O_RECT.w,
            h: O_RECT.h,
        };
        for i in 0..O_WINDOWS {
            let w = s
                .create(i as u64, 1 + (i / 4) as u64, rect, true, 0)
                .unwrap();
            s.set_format(w, compositor::Format::Argb);
            s.flush(w, own).unwrap();
        }
        let d = s.begin().unwrap();
        s.end(true);
        let (run, rows) = s.tile(d);
        let bands =
            u64::from(d.h).div_ceil(u64::from(rows)) * u64::from(d.w).div_ceil(u64::from(run));
        assert_eq!(bands, overload_frame_bands());
    }

    /// The floor of the overload is a function of the bands and the cap, and the gate of the
    /// share of the hog stays under what the cap leaves of a period.
    #[test]
    fn the_gates_of_the_overload_follow_the_service() {
        let periods = overload_frame_bands().div_ceil(u64::from(frame_cap_bands()));
        assert_eq!(overload_floor_frames(), PERIODS / (periods + 1));
        assert!(HOG_FLOOR_PPM < 1_000_000 - service_share_ppm());
        // The gate of a band the probe holds is the one the cap divides by.
        assert_eq!(BAND, u64::from(compositor::BAND_GATE));
        // The cap is the service's own function of the period and the cap in parts a million.
        let period = compositor::frame::DEFAULT_PERIOD_NS;
        let cap = compositor::frame::DEFAULT_CAP_PPM;
        assert_eq!(frame_cap_bands(), compositor::frame::band_cap(period, cap));
        // The service's share counts the bands and the three steps of a frame: 47 bands at
        // 16 328 and 3 steps at 18 369 over a period of 1 041 666 ticks.
        let ticks = u64::from(frame_cap_bands()) * BAND + 3 * STEP;
        assert_eq!(service_share_ppm(), ticks * 1_000_000 / (period / TICK_NS));
    }

    /// The floor of the CPU load under the file load is the processor less the compositor, the
    /// budgets above it and the file load's share, and nothing when they take it all.
    #[test]
    fn the_floor_of_the_cpu_load_counts_the_file_loads_share() {
        let budgets = budgets_share_ppm();
        assert_eq!(
            files_floor_ppm(0),
            1_000_000 - budgets - frame_load::loads::FILE_SHARE_PPM
        );
        assert!(
            files_floor_ppm(0) > 0,
            "the budgets and the file load leave room"
        );
        assert_eq!(files_floor_ppm(compose_share_ppm(1_000_000)), 0);
        // One millisecond of composing in a period of 16.67 ms is 6 %.
        assert_eq!(compose_share_ppm(1_000), 60_002);
        assert_eq!(
            files_floor_ppm(compose_share_ppm(1_000)),
            files_floor_ppm(0) - 60_002
        );
        // The whole screen at the cap leaves nothing: the share only has to be above 0.
        assert_eq!(files_floor_ppm(service_share_ppm()), 0);
    }

    #[test]
    fn the_cpu_load_under_the_file_load_must_reach_the_floor() {
        let lines = |files: u64| {
            vec![
                "frame-load: cpu quiet loops-per-s 1000000".to_owned(),
                format!("frame-load: cpu files loops-per-s {files}"),
            ]
        };
        let compose = compose_share_ppm(1_000);
        let floor = files_floor_ppm(compose);
        let at = floor; // the quiet loop is 1 000 000, so loops and parts per million agree
        assert_eq!(
            hog_share(&lines(at), Phase::Files, compose),
            Ok((at, floor))
        );
        assert!(hog_share(&lines(at - 1), Phase::Files, compose).is_err());
        // Starved: nothing, and with a floor of 0 as well.
        assert!(hog_share(&lines(0), Phase::Files, compose).is_err());
        assert!(hog_share(&lines(0), Phase::Files, 1_000_000).is_err());
        assert!(hog_share(&lines(1), Phase::Files, 1_000_000).is_ok());
        // No line of the phase is a share of nothing.
        assert!(hog_share(&lines(5)[..1], Phase::Files, 1_000_000).is_err());
    }

    /// The image the probe boots has its compositor on the frame clock at the defaults the cap is
    /// derived from (no arguments: 60 Hz and 750 000 parts a million).
    #[test]
    fn the_image_of_the_probe_runs_the_compositor_on_the_clock() {
        let record = TABLE.iter().find(|r| r.name == "gpu").unwrap();
        assert!(record.args.is_empty());
    }

    /// The counts the heartbeat is made of: three services above the
    /// compositor with no budget and six with one.
    #[test]
    fn the_heartbeat_counts_the_services_of_the_table() {
        let above: Vec<_> = TABLE
            .iter()
            .filter(|r| matches!(r.kind, Kind::Service(_)) && r.priority > 32)
            .collect();
        assert_eq!(above.iter().filter(|r| r.budgets.is_empty()).count(), 3);
        assert_eq!(above.iter().filter(|r| !r.budgets.is_empty()).count(), 6);
    }

    /// The budgets above the service take a third of CPU 0.
    #[test]
    fn the_budgets_above_the_service_are_a_third_of_the_cpu() {
        assert_eq!(budgets_share_ppm(), 330_000);
    }

    /// The lines of a good run.
    fn good() -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        for phase in ORDER {
            let name = phase.name();
            let (frames, direct, skipped, wakeups, bands, compose) = match phase {
                Phase::Quiet => (0, 0, 0, 0, 0, 0),
                Phase::Full => (240, 0, 0, 240, 240 * 40, 9_000),
                Phase::FullLoaded => (200, 0, 0, 240, 200 * 40, 10_000),
                Phase::HogRef => (0, 0, 0, 0, 0, 0),
                Phase::Overload => (
                    overload_floor_frames(),
                    0,
                    PERIODS - overload_floor_frames(),
                    PERIODS,
                    overload_floor_frames() * overload_frame_bands(),
                    12_000,
                ),
                Phase::Direct => (240, 240, 0, 240, 0, 1_000),
                _ => (240, 0, 0, 240, 240 * 4, 2_950),
            };
            let (late, capped) = if phase == Phase::Overload {
                (frames, 240)
            } else {
                (0, 0)
            };
            lines.push(format!(
                "frame-load: phase {name} frames {frames} late {late} skipped {skipped} failed 0 capped {capped} wakeups {wakeups} take-max-us 410 compose-max-us {compose} device-max-us 120 frame-max-us 3070 band-max-us 260 releases {frames} direct {direct}"
            ));
            lines.push(format!("frame-load: hist {name} 0 212 26 2 0"));
            lines.push(format!("frame-load: bands {name} {bands}"));
            if matches!(phase.scene(), Scene::P | Scene::F | Scene::O) {
                lines.push(format!(
                    "frame-load: window {name} id 1 interval 1 posts {frames} taken {frames} replaced 0 late 0 missed 0 late-max-us 0"
                ));
                lines.push(format!(
                    "frame-load: draw {name} posts {frames} no-free-buffer 0"
                ));
            }
            if phase == Phase::Direct {
                lines.push("frame-load: legacy direct flushes 77".to_owned());
            }
            if phase.loads().cpu || phase == Phase::Quiet {
                let n = match phase {
                    Phase::FullLoaded => 200_000,
                    Phase::Overload => 100_000,
                    _ => 812_345,
                };
                lines.push(format!("frame-load: cpu {name} loops-per-s {n}"));
            }
        }
        lines.push(
            "init: netd budget switch: at least 5 overruns, at least 5 in all, kernel counts 5"
                .to_owned(),
        );
        lines.push("net-probe: load rounds 31 bytes 8126464".to_owned());
        lines.push("data-probe: load ops 120 bytes 2031616".to_owned());
        lines.push("frame-load: done".to_owned());
        lines
    }

    fn change(lines: &mut [String], from: &str, to: &str) {
        for l in lines.iter_mut() {
            *l = l.replace(from, to);
        }
    }

    fn replace_line(lines: &mut [String], prefix: &str, with: &str) {
        let l = lines.iter_mut().find(|l| l.starts_with(prefix)).unwrap();
        *l = with.to_owned();
    }

    #[test]
    fn a_good_run_passes_and_reports_each_phase() {
        let said = verdict(&good(), true).unwrap();
        assert!(
            said.iter()
                .any(|l| l.starts_with("frame-probe: net: 240 frames, late 0, skipped 0"))
        );
        assert!(said.iter().any(|l| {
            l.starts_with("frame-probe: full-loaded: 240 periods, frames 200, late 0, skipped 0")
        }));
        assert!(
            said.iter()
                .any(|l| l.contains("direct: 240 frames, all direct"))
        );
    }

    #[test]
    fn a_late_frame_in_a_loaded_phase_fails() {
        let mut lines = good();
        let l = lines
            .iter_mut()
            .find(|l| l.starts_with("frame-load: phase net "))
            .unwrap();
        *l = l.replace("late 0", "late 1");
        assert!(
            verdict(&lines, true)
                .unwrap_err()
                .starts_with("net: late 1")
        );
        // Without the clock of the guest the count is not judged.
        assert!(verdict(&lines, false).is_ok());
    }

    const LATE_DEVICE: &str = "compositor: late frame period 7 take 38 us compose 413 us device 19000 us frame 19451 us (the longest: device)";

    /// The lines of a good run with one late frame told in `phase`: the late line before the
    /// phase's line, the count of late frames and of skipped periods in it.
    fn with_late(phase: &str, told: &[&str], late: u32, skipped: u32) -> Vec<String> {
        let mut lines = good();
        let at = lines
            .iter()
            .position(|l| l.starts_with(&format!("frame-load: phase {phase} ")))
            .unwrap();
        lines[at] = lines[at]
            .replace("late 0", &format!("late {late}"))
            .replace("skipped 0", &format!("skipped {skipped}"));
        for (i, l) in told.iter().enumerate() {
            lines.insert(at + i, (*l).to_owned());
        }
        lines
    }

    #[test]
    fn one_late_frame_that_waited_for_the_device_is_excused_in_a_loaded_phase() {
        for phase in ["cpu", "files", "net", "direct"] {
            let said = verdict(&with_late(phase, &[LATE_DEVICE], 1, 0), true).unwrap();
            let line = said
                .iter()
                .find(|l| l.starts_with(&format!("frame-probe: {phase}: ")))
                .unwrap();
            assert!(
                line.contains("late 1 (the device's, 19.45 ms: emulator main loop, excused)"),
                "{line}"
            );
        }
        // The window missed once, with a frame long enough to explain it.
        let cases = [
            (
                "cpu",
                "compositor: late frame period 7 take 38 us compose 413 us device 32640 us frame 33092 us (the longest: device)",
                "frame-load: window cpu id 1 interval 1 posts 235 taken 235 replaced 0 late 0 missed 1 late-max-us 0",
            ),
            (
                "files",
                "compositor: late frame period 7 take 38 us compose 414 us device 33586 us frame 34039 us (the longest: device)",
                "frame-load: window files id 1 interval 1 posts 236 taken 235 replaced 0 late 0 missed 1 late-max-us 0",
            ),
        ];
        for (phase, told, window) in cases {
            let mut lines = with_late(phase, &[told], 1, 0);
            replace_line(&mut lines, &format!("frame-load: window {phase} "), window);
            let at = lines
                .iter()
                .position(|l| l.starts_with(&format!("frame-load: phase {phase} ")))
                .unwrap();
            lines[at] = lines[at].replace("frames 240", "frames 235");
            let said = verdict(&lines, true).unwrap();
            let line = said
                .iter()
                .find(|l| l.starts_with(&format!("frame-probe: {phase}: ")))
                .unwrap();
            assert!(line.contains("excused"), "{line}");
        }
        // The window late once is allowed.
        let mut lines = with_late("cpu", &[LATE_DEVICE], 1, 0);
        replace_line(
            &mut lines,
            "frame-load: window cpu ",
            "frame-load: window cpu id 1 interval 1 posts 240 taken 240 replaced 0 late 1 missed 0 late-max-us 2165",
        );
        assert!(verdict(&lines, true).is_ok());
    }

    #[test]
    fn the_excuse_is_refused_when_one_of_its_conditions_fails() {
        // The same frame in a phase with no load.
        for phase in ["idle", "full"] {
            let e = verdict(&with_late(phase, &[LATE_DEVICE], 1, 0), true).unwrap_err();
            assert!(e.starts_with(&format!("{phase}: late 1")), "{e}");
        }
        let cases: [(Vec<String>, &str); 8] = [
            // The cause is the compose.
            (
                with_late(
                    "cpu",
                    &[
                        "compositor: late frame period 7 take 38 us compose 19000 us device 413 us frame 19451 us (the longest: compose)",
                    ],
                    1,
                    0,
                ),
                "the longest phase is the compose's",
            ),
            // Three late frames.
            (
                with_late("cpu", &[LATE_DEVICE, LATE_DEVICE, LATE_DEVICE], 3, 0),
                "at most 2 are excused",
            ),
            // Two late frames with one line told.
            (
                with_late("cpu", &[LATE_DEVICE], 2, 0),
                "2 late frames and 1 told",
            ),
            // Two late frames, one of them the compose's.
            (
                with_late(
                    "cpu",
                    &[
                        LATE_DEVICE,
                        "compositor: late frame period 7 take 38 us compose 19000 us device 413 us frame 19451 us (the longest: compose)",
                    ],
                    2,
                    0,
                ),
                "the longest phase is the compose's",
            ),
            // One late frame with no line.
            (with_late("cpu", &[], 1, 0), "0 told"),
            // Take and compose over the bound less the kernel path, the driver and a step.
            (
                with_late(
                    "cpu",
                    &[
                        "compositor: late frame period 7 take 38 us compose 14000 us device 19000 us frame 33038 us (the longest: device)",
                    ],
                    1,
                    0,
                ),
                "over 13733 us of the bound",
            ),
            // More periods skipped than the frame covers (19 451 us is one period, so none).
            (
                with_late("cpu", &[LATE_DEVICE], 1, 1),
                "skipped 1 over the 0",
            ),
            // A step of the driver past its term.
            (
                {
                    let mut l = with_late("cpu", &[LATE_DEVICE], 1, 0);
                    l.insert(
                        0,
                        format!(
                            "service step: {} kind 65 14000 ticks detail 0",
                            crate::comp_probe::DRIVER_TAG
                        ),
                    );
                    l
                },
                "a step of the display driver past 13596 ticks",
            ),
        ];
        for (lines, why) in cases {
            let e = verdict(&lines, true).unwrap_err();
            assert!(e.starts_with("cpu: late "), "{e}");
            assert!(e.contains(why), "{e}: wanted {why}");
        }
        let long = "compositor: late frame period 7 take 38 us compose 414 us device 33586 us frame 34039 us (the longest: device)";
        let window = |late: u32, missed: u32, taken: u32| {
            format!(
                "frame-load: window cpu id 1 interval 1 posts 240 taken {taken} replaced 0 late {late} missed {missed} late-max-us 2165"
            )
        };
        let refused = |phase: &str, told: &str, w: String, why: &str| {
            let mut lines = with_late(phase, &[told], 1, 0);
            replace_line(&mut lines, &format!("frame-load: window {phase} "), &w);
            let e = verdict(&lines, true).unwrap_err();
            assert!(e.contains(why), "{e}: wanted {why}");
        };
        // The window late once and missed once.
        refused("cpu", long, window(1, 1, 240), "the window late 1 missed 1");
        // The window late with a frame the window cannot explain.
        refused(
            "cpu",
            long,
            window(1, 0, 240),
            "the lateness is the window's own",
        );
        // The window missed with taken one less than frames.
        refused(
            "cpu",
            long,
            window(0, 1, 239),
            "took 239 buffers for 240 frames",
        );
        // The window missed once with a frame that shows in time for the post.
        refused(
            "cpu",
            LATE_DEVICE,
            window(0, 1, 240),
            "came back in time for the post",
        );
        // Two device frames in the phases with no load.
        for phase in ["idle", "full"] {
            let e = verdict(&with_late(phase, &[D23, D28], 2, 0), true).unwrap_err();
            assert!(e.starts_with(&format!("{phase}: late 2")), "{e}");
        }
        // Two told frames with the window late twice and one of them too long for it.
        let mut lines = with_late("cpu", &[D23, D34], 2, 0);
        replace_line(&mut lines, "frame-load: window cpu ", &window(2, 0, 240));
        let e = verdict(&lines, true).unwrap_err();
        assert!(e.contains("the lateness is the window's own"), "{e}");
        // Missed once in the phases with no load.
        for phase in ["idle", "full"] {
            let mut lines = with_late(phase, &[long], 1, 0);
            replace_line(
                &mut lines,
                &format!("frame-load: window {phase} "),
                &window(0, 1, 240).replace("window cpu", &format!("window {phase}")),
            );
            let e = verdict(&lines, true).unwrap_err();
            assert!(e.starts_with(&format!("{phase}: ")), "{e}");
        }
    }

    const D23: &str = "compositor: late frame period 7 take 38 us compose 413 us device 22571 us frame 23022 us (the longest: device)";
    const D28: &str = "compositor: late frame period 9 take 38 us compose 414 us device 27761 us frame 28213 us (the longest: device)";
    const D34: &str = "compositor: late frame period 9 take 38 us compose 414 us device 33586 us frame 34039 us (the longest: device)";

    #[test]
    fn two_late_device_frames_are_excused_in_a_loaded_phase() {
        let run = |told: &[&str], late: u32, missed: u32| {
            let mut lines = with_late("files", told, 2, 0);
            replace_line(
                &mut lines,
                "frame-load: window files ",
                &format!(
                    "frame-load: window files id 1 interval 1 posts 234 taken 234 replaced 0 late {late} missed {missed} late-max-us 11985"
                ),
            );
            let at = lines
                .iter()
                .position(|l| l.starts_with("frame-load: phase files "))
                .unwrap();
            lines[at] = lines[at].replace("frames 240", "frames 234");
            verdict(&lines, true)
        };
        let said = run(&[D23, D28], 2, 0).unwrap();
        let line = said
            .iter()
            .find(|l| l.starts_with("frame-probe: files: "))
            .unwrap();
        assert!(
            line.contains("late 2 (the device's, 23.02 and 28.21 ms: emulator main loop, excused)"),
            "{line}"
        );
        assert!(run(&[D23, D34], 1, 1).is_ok());
        // One of the two lines is missing.
        let e = run(&[D23], 2, 0).unwrap_err();
        assert!(e.contains("2 late frames and 1 told"), "{e}");
        // Two told device frames and the window late twice with one too long for it.
        let e = run(&[D23, D34], 2, 0).unwrap_err();
        assert!(e.contains("the lateness is the window's own"), "{e}");
    }

    #[test]
    fn the_late_lines_are_those_between_the_phase_before_and_the_phase() {
        let mut lines = with_late("net", &[LATE_DEVICE], 1, 0);
        let cpu = lines
            .iter()
            .position(|l| l.starts_with("frame-load: phase cpu "))
            .unwrap();
        lines.insert(cpu, LATE_DEVICE.replace("period 7", "period 9"));
        assert_eq!(late_lines(&lines, Phase::Net).len(), 1);
        assert_eq!(late_lines(&lines, Phase::Cpu).len(), 1);
        assert_eq!(late_lines(&lines, Phase::Files).len(), 0);
        let mut two = with_late("files", &[D23, D28], 2, 0);
        let net = two
            .iter()
            .position(|l| l.starts_with("frame-load: phase net "))
            .unwrap();
        two.insert(net, LATE_DEVICE.to_owned());
        assert_eq!(late_lines(&two, Phase::Files).len(), 2);
        let one = &late_lines(&lines, Phase::Net)[0];
        assert_eq!(
            (
                one.take_us,
                one.compose_us,
                one.device_us,
                one.frame_us,
                one.cause.as_str()
            ),
            (38, 413, 19000, 19451, "device")
        );
    }

    #[test]
    fn wakeups_in_the_quiet_phase_fail() {
        let mut lines = good();
        let l = lines
            .iter_mut()
            .find(|l| l.starts_with("frame-load: phase quiet "))
            .unwrap();
        *l = l.replace("wakeups 0", "wakeups 3");
        assert!(verdict(&lines, true).unwrap_err().starts_with("quiet:"));
    }

    #[test]
    fn a_compose_time_over_the_bound_fails() {
        let mut lines = good();
        let l = lines
            .iter_mut()
            .find(|l| l.starts_with("frame-load: phase cpu "))
            .unwrap();
        // The bound of P is 14 865 us.
        *l = l.replace("compose-max-us 2950", "compose-max-us 14900");
        let e = verdict(&lines, true).unwrap_err();
        assert!(
            e.starts_with("cpu: compose max 14900 us over the bound 14865 us"),
            "{e}"
        );
    }

    #[test]
    fn a_missing_phase_or_histogram_fails() {
        let mut lines = good();
        lines.retain(|l| !l.starts_with("frame-load: phase files "));
        assert!(
            verdict(&lines, true)
                .unwrap_err()
                .contains("no line of the phase files")
        );
        let mut lines = good();
        lines.retain(|l| !l.starts_with("frame-load: hist idle "));
        assert!(
            verdict(&lines, true)
                .unwrap_err()
                .contains("no histogram of the phase idle")
        );
    }

    #[test]
    fn too_few_frames_in_full_loaded_fail_and_so_does_a_loop_that_did_not_turn() {
        let mut lines = good();
        let l = lines
            .iter_mut()
            .find(|l| l.starts_with("frame-load: phase full-loaded "))
            .unwrap();
        *l = l.replace("frames 200", "frames 59");
        assert!(
            verdict(&lines, true)
                .unwrap_err()
                .starts_with("full-loaded: 59 frames")
        );
        let mut lines = good();
        replace_line(
            &mut lines,
            "frame-load: cpu full-loaded ",
            "frame-load: cpu full-loaded loops-per-s 0",
        );
        assert!(verdict(&lines, true).is_err());
    }

    /// The model of the bands here is the service's: a frame of one opaque window
    /// over the whole screen has the bands `full_screen_bands` counts.
    #[test]
    fn the_band_model_agrees_with_the_service_for_the_whole_screen() {
        assert_eq!(
            bands_of(640, 400, 1, 0, 0),
            u64::from(compositor::full_screen_bands())
        );
    }

    /// Eight windows with an alpha over one place take far more bands than the
    /// cap lets the service make in a period.
    #[test]
    fn a_frame_of_the_overload_is_many_periods_of_the_cap() {
        let bands = overload_frame_bands();
        let cap = u64::from(frame_cap_bands());
        // The scene is made of many bands of a few points each, so the frame takes
        // more than eight periods at the cap, and the floor is derived from the
        // model: never a literal.
        let periods = bands.div_ceil(cap);
        assert!(periods > 8, "{bands} bands, {periods} periods");
        assert_eq!(overload_floor_frames(), PERIODS / (periods + 1));
        assert!(overload_floor_frames() >= 1);
    }

    fn overload_line(lines: &mut [String], from: &str, to: &str) {
        let l = lines
            .iter_mut()
            .find(|l| l.starts_with("frame-load: phase overload "))
            .unwrap();
        *l = l.replace(from, to);
    }

    #[test]
    fn the_longest_band_step_of_the_overload_is_read_from_the_lines() {
        let tag = crate::comp_probe::COMP_TAG;
        let mut lines = good();
        // A step before the phase and a longer one inside it.
        let hog = lines
            .iter()
            .position(|l| l.starts_with("frame-load: phase hog-ref "))
            .unwrap();
        lines.insert(
            hog,
            format!("service step: {tag} kind 65 9000 ticks detail 0"),
        );
        let over = lines
            .iter()
            .position(|l| l.starts_with("frame-load: phase overload "))
            .unwrap();
        lines.insert(
            over,
            format!("service step: {tag} kind 65 10100 ticks detail 0"),
        );
        assert_eq!(
            band_step_in(&lines, Phase::HogRef, Phase::Overload),
            (Some((10_100, 0)), 9_000)
        );
        let said = verdict(&lines, true).unwrap();
        assert!(
            said.iter()
                .any(|l| l
                    .contains("longest band step 10100 ticks in the phase, a step of detail 0"))
        );
        // No line in the phase: nothing above the earlier greatest.
        lines.remove(over);
        let said = verdict(&lines, true).unwrap();
        assert!(
            said.iter()
                .any(|l| l.contains("none above the earlier greatest 9000 ticks"))
        );
    }

    #[test]
    fn the_kind_of_a_long_step_is_named() {
        let tag = crate::comp_probe::COMP_TAG;
        assert_eq!(own_step_kind(1008), "a band that made 8 images");
        assert_eq!(own_step_kind(1000), "a band that made 0 images");
        assert_eq!(own_step_kind(6000), "the arming of the timer after the cap");
        assert_eq!(own_step_kind(2000), "a take");
        assert_eq!(own_step_kind(3000), "the commit after the last band");
        assert_eq!(own_step_kind(4000), "the end of a frame");
        assert_eq!(own_step_kind(5000), "housekeeping");
        // The phase's line carries it, and a gate message names it.
        let mut lines = good();
        let over = lines
            .iter()
            .position(|l| l.starts_with("frame-load: phase overload "))
            .unwrap();
        lines.insert(
            over,
            format!("service step: {tag} kind 65 21333 ticks detail 1008"),
        );
        let said = verdict(&lines, true).unwrap();
        assert!(said.iter().any(|l| {
            l.contains("longest band step 21333 ticks in the phase, a band that made 8 images")
        }));
        let mut steps = steps(&[]);
        steps.push(format!(
            "service step: {tag} kind 65 21333 ticks detail 1008"
        ));
        let e = steps_verdict(&steps).unwrap_err();
        assert!(e.contains("a band that made 8 images"), "{e}");
    }

    #[test]
    fn the_loopback_load_is_reported_with_its_longest_round() {
        let mut lines = good();
        replace_line(
            &mut lines,
            "net-probe: load rounds",
            "net-probe: load rounds 8 bytes 1048576 send-again 17 recv-again 79 longest-round-ms 2385",
        );
        let said = verdict(&lines, true).unwrap();
        assert!(said.iter().any(|l| l
            == "frame-probe: net load: rounds 8, longest round 2385 ms, send-again 17, recv-again 79"));
    }

    #[test]
    fn a_good_overload_passes_and_is_reported() {
        let said = verdict(&good(), true).unwrap();
        assert!(said.iter().any(|l| {
            let f = overload_floor_frames();
            l.starts_with(&format!(
                "frame-probe: overload: {f} frames of {} bands",
                overload_frame_bands()
            )) && l.contains(&format!(
                "capped 240, skipped {}, late {f}, cpu share 0.12 (floor 0.08)",
                PERIODS - f
            ))
        }));
    }

    /// The faults the verdict of the overload exists for.
    #[test]
    fn a_hog_under_the_floor_no_cap_or_a_frame_on_time_fails() {
        // The CPU load kept under 0.08 of its loop alone.
        let mut lines = good();
        replace_line(
            &mut lines,
            "frame-load: cpu overload ",
            "frame-load: cpu overload loops-per-s 50000",
        );
        let e = verdict(&lines, true).unwrap_err();
        assert!(e.starts_with("overload: the CPU load kept 0.06"), "{e}");
        // The cap never put a band off.
        let mut lines = good();
        overload_line(&mut lines, "capped 240", "capped 0");
        let e = verdict(&lines, true).unwrap_err();
        assert!(e.starts_with("overload: capped 0 of 240 periods"), "{e}");
        // Fewer capped periods than frames released.
        let mut lines = good();
        let f = overload_floor_frames();
        overload_line(&mut lines, "capped 240", "capped 120");
        overload_line(&mut lines, &format!("releases {f}"), "releases 200");
        let e = verdict(&lines, true).unwrap_err();
        assert!(e.contains("fewer than the"), "{e}");
        // One taking short is a read of STATS between a taking and the last band of a period.
        let mut lines = good();
        overload_line(&mut lines, "capped 240", "capped 120");
        overload_line(&mut lines, &format!("releases {f}"), "releases 121");
        assert!(verdict(&lines, true).is_ok());
        // A frame shown in its period though the scene cannot make one.
        let mut lines = good();
        let f = overload_floor_frames();
        overload_line(&mut lines, &format!("late {f}"), &format!("late {}", f - 1));
        let e = verdict(&lines, true).unwrap_err();
        assert!(
            e.starts_with(&format!("overload: late {} of {f} frames", f - 1)),
            "{e}"
        );
        // One frame shown in the phase that released no buffer, in its period (the
        // frame of the end of the earlier phase read on this side of the boundary):
        // the frames of the scene are all late, and it passes. Two do not.
        let mut lines = good();
        let f = overload_floor_frames();
        overload_line(
            &mut lines,
            &format!("frames {f}"),
            &format!("frames {}", f + 1),
        );
        assert!(verdict(&lines, true).is_ok());
        let mut lines = good();
        overload_line(
            &mut lines,
            &format!("frames {f}"),
            &format!("frames {}", f + 2),
        );
        assert!(verdict(&lines, true).is_err());
        // A frame of the scene on time with a frame that released nothing: one
        // more frame and one more release than late frames. `late` counts the
        // released frames alone, so these counts pass no longer.
        let mut lines = good();
        overload_line(
            &mut lines,
            &format!("frames {f}"),
            &format!("frames {}", f + 1),
        );
        overload_line(
            &mut lines,
            &format!("releases {f}"),
            &format!("releases {}", f + 1),
        );
        let e = verdict(&lines, true).unwrap_err();
        assert!(e.starts_with("overload: late"), "{e}");
        // Skips are printed and judge nothing.
        let mut lines = good();
        overload_line(
            &mut lines,
            &format!("skipped {}", PERIODS - overload_floor_frames()),
            "skipped 0",
        );
        assert!(verdict(&lines, true).is_ok());
        // Fewer frames than a frame a period count would give.
        let mut lines = good();
        let f = overload_floor_frames();
        overload_line(&mut lines, &format!("frames {f}"), "frames 0");
        overload_line(&mut lines, &format!("late {f}"), "late 0");
        overload_line(&mut lines, &format!("releases {f}"), "releases 0");
        let e = verdict(&lines, true).unwrap_err();
        assert!(e.contains("0 frames of 240 periods"), "{e}");
        // A reference with no loops makes no share to judge.
        let mut lines = good();
        replace_line(
            &mut lines,
            "frame-load: cpu hog-ref ",
            "frame-load: cpu hog-ref loops-per-s 0",
        );
        assert!(verdict(&lines, true).is_err());
        // The counts alone judge no time.
        let mut lines = good();
        overload_line(&mut lines, "capped 240", "capped 0");
        assert!(verdict(&lines, false).is_ok());
    }

    #[test]
    fn direct_frames_that_were_composed_fail() {
        let mut lines = good();
        change(
            &mut lines,
            "releases 240 direct 240",
            "releases 240 direct 3",
        );
        assert!(
            verdict(&lines, true)
                .unwrap_err()
                .starts_with("direct: 240 frames of which 3 direct")
        );
    }

    /// A whole-screen frame of more than 45 bands makes the phase a load
    /// phase, which the report says.
    #[test]
    fn a_full_frame_of_58_bands_is_judged_as_a_load_phase() {
        let mut lines = good();
        replace_line(
            &mut lines,
            "frame-load: bands full ",
            "frame-load: bands full 13920",
        );
        let l = lines
            .iter_mut()
            .find(|l| l.starts_with("frame-load: phase full "))
            .unwrap();
        *l = l
            .replace("late 0", "late 5")
            .replace("skipped 0", "skipped 7");
        let said = verdict(&lines, true).unwrap();
        assert!(said.iter().any(|l| l.contains("judged as a load phase")));
    }

    #[test]
    fn a_whole_screen_over_its_bound_under_all_the_loads_is_a_finding() {
        let mut lines = good();
        let l = lines
            .iter_mut()
            .find(|l| l.starts_with("frame-load: phase full-loaded "))
            .unwrap();
        // The bound of 40 bands is about 33 400 us.
        *l = l.replace("compose-max-us 10000", "compose-max-us 34000");
        let e = verdict(&lines, true).unwrap_err();
        assert!(
            e.starts_with("full-loaded: compose max 34000 us over the bound 33"),
            "{e}"
        );
        assert!(e.contains("a finding for the design"));
    }

    #[test]
    fn the_report_says_how_far_netd_was_loaded() {
        let mut lines = good();
        lines.push(
            "init: netd budget stack0: at least 40 overruns, at least 90 in all, kernel counts 91"
                .to_owned(),
        );
        assert_eq!(
            netd_overruns(&lines),
            [("switch".to_owned(), 5), ("stack0".to_owned(), 91)]
        );
        let said = verdict(&lines, true).unwrap();
        assert!(said.iter().any(|l| l.ends_with(", switch 5, stack0 91")));
    }

    /// A run whose budgets were not spent still passes and says plainly that the
    /// term for the service was exercised in part.
    #[test]
    fn a_run_with_no_overrun_of_netd_says_so() {
        let mut lines = good();
        lines.retain(|l| !l.starts_with("init: netd budget"));
        let said = verdict(&lines, true).unwrap();
        assert!(
            said.iter()
                .any(|l| l.contains("budgets were not spent") && l.contains("exercised in part"))
        );
        lines.push(
            "init: netd budget switch: at least 0 overruns, at least 0 in all, kernel counts 0"
                .to_owned(),
        );
        assert!(
            verdict(&lines, true)
                .unwrap()
                .iter()
                .any(|l| l.contains("not spent"))
        );
    }

    #[test]
    fn a_failed_frame_or_a_failed_program_fails() {
        let mut lines = good();
        change(
            &mut lines,
            "failed 0 capped 0 wakeups 240 take-max-us 410 compose-max-us 9000",
            "failed 2 capped 0 wakeups 240 take-max-us 410 compose-max-us 9000",
        );
        assert!(
            verdict(&lines, true)
                .unwrap_err()
                .contains("2 frames failed")
        );
        let mut lines = good();
        lines.insert(2, "frame-load: failed: woke late for a phase".to_owned());
        assert_eq!(
            verdict(&lines, true).unwrap_err(),
            "frame-load: failed: woke late for a phase"
        );
    }

    fn steps(extra: &[(&str, usize, u64)]) -> Vec<String> {
        let mut lines = Vec::new();
        let tag = crate::comp_probe::COMP_TAG;
        for kind in [18, 19, 20, 24, 25, 64, 65] {
            lines.push(format!(
                "service step: {tag} kind {kind} 4000 ticks detail 0"
            ));
        }
        let tag = crate::comp_probe::DRIVER_TAG;
        for kind in [5, 6, 9, 10, 65] {
            lines.push(format!(
                "service step: {tag} kind {kind} 4000 ticks detail 0"
            ));
        }
        for (tag, kind, ticks) in extra {
            lines.push(format!(
                "service step: {tag} kind {kind} {ticks} ticks detail 0"
            ));
        }
        lines
    }

    /// The hard check against B: the compositor and the display driver are judged in every
    /// kind (none is exempt), by the time less the least charge of the preemptions; the steps of
    /// a service the probe does not judge are the business of its own probe.
    #[test]
    fn a_step_past_b_by_the_least_charge_fails_in_any_kind_of_both_services() {
        // Eight preemptions at the measured charge leave 16 800 ticks (under 0.9 B), and at the
        // least charge 23 240, past B.
        for (tag, kind) in [
            (crate::comp_probe::COMP_TAG, 20usize),
            (crate::comp_probe::DRIVER_TAG, 6),
        ] {
            let mut lines = steps(&[]);
            lines.push(format!(
                "service step: {tag} kind {kind} 24000 ticks detail 0 preempts 8"
            ));
            let e = steps_verdict(&lines).unwrap_err();
            assert!(
                e.contains(&format!("kind {kind}"))
                    && e.contains(&format!("against B {}", crate::TERM_B)),
                "{e}"
            );
        }
        // The same step of a service this probe does not judge passes.
        let mut lines = steps(&[]);
        lines.push("service step: 99 kind 20 24000 ticks detail 0 preempts 8".to_owned());
        assert!(steps_verdict(&lines).is_ok());
        // A step of 20 000 ticks with two preemptions is within B by the least charge.
        let mut lines = steps(&[]);
        lines.push(format!(
            "service step: {} kind 20 20000 ticks detail 0 preempts 2",
            crate::comp_probe::COMP_TAG
        ));
        assert!(steps_verdict(&lines).is_ok());
    }

    #[test]
    fn the_steps_are_under_the_gates_and_the_kinds_came() {
        assert!(steps_verdict(&steps(&[])).is_ok());
        let tag = crate::comp_probe::COMP_TAG;
        let e = steps_verdict(&steps(&[(tag, 20, crate::gpu_probe::STEP_MAX + 100)])).unwrap_err();
        assert!(e.contains("past the gate"), "{e}");
        let e = steps_verdict(&steps(&[(tag, 65, crate::PORTION_MAX + 100)])).unwrap_err();
        assert!(e.contains(&format!("past {}", crate::PORTION_MAX)), "{e}");
        // Stats and the timer's step are required.
        for kind in [25usize, 64] {
            let mut lines = steps(&[]);
            lines.retain(|l| !l.starts_with(&format!("service step: {tag} kind {kind} ")));
            assert!(steps_verdict(&lines).unwrap_err().contains("no step"));
        }
    }
}
