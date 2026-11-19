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
const REQUESTS: u64 = 10_000;
const EVENTS: u64 = 1_875;
const LIMIT: u64 = 10_000_000;
/// A frame with more bands than this does not fit a period without a load.
const FULL_BANDS_MAX: u64 = 45;
/// The bands of a window of 160 by 100 at 16 rows a band.
const P_BANDS: u64 = 7;
/// The frames of a phase of 240 periods: the counters start 50 ms after the
/// phase starts and are read 5 ms before it ends, which leaves about 237.
const FRAMES_MIN: u64 = 230;
const FRAMES_MAX: u64 = 242;
/// The frames the whole screen under all the loads must still make: half of the
/// periods.
const STRESS_FRAMES_MIN: u64 = 120;
/// The share of its loop alone the CPU load must keep under the overload: the
/// cap and three steps leave the service most of a period and the console and
/// the signs of life take a few percent, so about a tenth is left.
const HOG_FLOOR_PPM: u64 = 80_000;
/// The share of a period the service may use at most, in parts per million:
/// the bands the cap lets it make in a period, each at the gate of a band,
/// over the ticks of a period. The CPU the levels below it can count on is what
/// the budgets above leave of the rest.
fn service_share_ppm() -> u64 {
    use compositor::frame::DEFAULT_PERIOD_NS;
    u64::from(frame_cap_bands()) * BAND * 1_000_000 / (DEFAULT_PERIOD_NS / TICK_NS)
}

/// A tick count in microseconds.
fn us(ticks: u64) -> u64 {
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

/// The budgets on CPU 0 of the services above the compositor, as the sources
/// of interference of the bound; with `only_console` the console's alone.
pub fn sources(only_console: bool) -> Vec<Source> {
    let ticks = |ns: u64| (ns).div_ceil(TICK_NS);
    TABLE
        .iter()
        .filter(|r| matches!(r.kind, Kind::Service(_)) && r.priority > 32)
        .filter(|r| !only_console || r.name == "uart")
        .flat_map(|r| r.budgets.iter())
        .filter(|b| b.cpu == 0)
        .map(|b| Source {
            budget: ticks(b.c_ns),
            period: ticks(b.t_ns),
            step: STEP,
        })
        .collect()
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
    // The calls of the layers, a layer after the first costing `LAYER` more, as
    // `Scene::tile` charges them; the size of the band is the service's own.
    let calls = OPAQUE.call * opaque
        + OVER.call * over
        + FILL.call * fill
        + LAYER * (opaque + over).saturating_sub(1);
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
    band_cap(DEFAULT_PERIOD_NS, DEFAULT_CAP_PPM, compositor::BAND_TICKS)
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
        Row::P => (P_BANDS, true, true),
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
fn window_of(lines: &[String], phase: Phase) -> Option<(u64, u64, u64)> {
    let prefix = format!("frame-load: window {} ", phase.name());
    lines
        .iter()
        .filter(|l| l.starts_with(&prefix))
        .filter_map(|l| Some((field(l, "posts")?, field(l, "late")?, field(l, "missed")?)))
        .max_by_key(|w| w.0)
}

/// The loops a second the CPU load made in a phase.
fn loops(lines: &[String], phase: Phase) -> Option<u64> {
    field(
        line_of(lines, &format!("frame-load: cpu {} ", phase.name()))?,
        "loops-per-s",
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
                let Some((_, wlate, wmissed)) = window else {
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
                if timed {
                    if p.late != 0 || p.skipped != 0 {
                        return fail(format!("late {} skipped {}", p.late, p.skipped));
                    }
                    if wlate != 0 || wmissed != 0 {
                        return fail(format!("the window late {wlate} missed {wmissed}"));
                    }
                    if p.compose_max_us > us(bound) {
                        return fail(format!(
                            "compose max {} us over the bound {} us (the bound is wrong or the frame too long)",
                            p.compose_max_us,
                            us(bound)
                        ));
                    }
                }
                said.push(format!(
                    "frame-probe: {name}: {} frames, late {}, skipped {}, compose max {} ms (bound {} ms)",
                    p.frames,
                    p.late,
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
                let alone = loops(lines, Phase::Quiet).unwrap_or(0);
                let share = loops(lines, phase)
                    .map(|n| n * 1_000_000 / alone.max(1))
                    .unwrap_or(0);
                // What the levels below the service are promised: the period less the
                // service and the budgets above it, none when they take it all.
                let floor = 1_000_000u64
                    .saturating_sub(service_share_ppm())
                    .saturating_sub(budgets_share_ppm());
                if share == 0 || share < floor {
                    return fail(format!(
                        "the CPU load got {} of the loop alone (floor {})",
                        frac(share),
                        frac(floor)
                    ));
                }
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
                    // Skips are printed only: with the client unable to post while
                    // its frame is in work almost no change waits at a period start.
                    if p.late != p.frames {
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
                if timed {
                    if p.late != 0 || p.skipped != 0 {
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
                said.push(format!(
                    "frame-probe: direct: {} frames, all direct, late {}, skipped {}, compose max {} ms (bound {} ms)",
                    p.frames,
                    p.late,
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
/// last band, 4000 the end of a frame, 5000 housekeeping.
pub fn own_step_kind(detail: u64) -> String {
    match detail {
        1000..=1999 => format!("a band that made {} images", detail - 1000),
        2000..=2999 => "a take".to_owned(),
        3000..=3999 => "the commit after the last band".to_owned(),
        4000..=4999 => "the end of a frame".to_owned(),
        5000..=5999 => "housekeeping".to_owned(),
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
    let timed = match args {
        [] => true,
        [word] if word == "counters" => false,
        _ => return Err("frame-probe [counters]".to_owned()),
    };
    let lines = frame_image::run(timed)?;
    let said = verdict(&lines, timed).map_err(|e| format!("frame-probe: {e}"))?;
    for line in &said {
        println!("{line}");
    }
    if timed {
        crate::check_waits(
            &lines,
            &[crate::comp_probe::COMP_TAG, crate::comp_probe::DRIVER_TAG],
            "frame-probe",
        )?;
        let steps = steps_verdict(&lines).map_err(|e| format!("frame-probe: {e}"))?;
        println!("frame-probe: the longest steps, ticks: {steps}");
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

    /// The numbers of the analysis for the image of the frame (the heartbeat 46 400).
    #[test]
    fn the_bounds_of_the_image_are_the_numbers_of_the_analysis() {
        assert_eq!(heartbeat_ticks(), 46_400);
        assert_eq!(bound_ticks(Row::P), Some(906_578));
        assert_eq!(bound_ticks(Row::D), Some(622_091));
        // The whole screen by the service's own count of the bands of the frame: the
        // row follows it, and the rows of the analysis for the counts it has had.
        let n = u64::from(compositor::full_screen_bands());
        assert!(bound_ticks(Row::F(n)).is_some());
        for (bands, own_ticks, bound) in [
            (31, 644_681, 689_300),
            (33, 677_337, 721_956),
            (34, 693_665, 738_284),
        ] {
            assert_eq!(own(Row::F(bands)), own_ticks);
            assert_eq!(bound_ticks(Row::F(bands)), Some(bound));
        }
        // Under all the loads the whole screen has a bound past a period (1 041 667
        // ticks): the analysis does not promise this frame on time.
        assert_eq!(bound_ticks(Row::FullLoaded(31)), Some(1_710_647));
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
                Phase::Overload => (30, 0, 210, 240, 30 * 424, 12_000),
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
        // The bound of P is 14 505 us.
        *l = l.replace("compose-max-us 2950", "compose-max-us 14600");
        let e = verdict(&lines, true).unwrap_err();
        assert!(
            e.starts_with("cpu: compose max 14600 us over the bound 14505 us"),
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
            l.starts_with("frame-probe: overload: 30 frames of ")
                && l.contains("capped 240, skipped 210, late 30, cpu share 0.12 (floor 0.08)")
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
        // A frame shown in its period though the scene cannot make one.
        let mut lines = good();
        overload_line(&mut lines, "late 30", "late 29");
        let e = verdict(&lines, true).unwrap_err();
        assert!(e.starts_with("overload: late 29 of 30 frames"), "{e}");
        // Skips are printed and judge nothing.
        let mut lines = good();
        overload_line(&mut lines, "skipped 210", "skipped 0");
        assert!(verdict(&lines, true).is_ok());
        // Fewer frames than a frame a period count would give.
        let mut lines = good();
        overload_line(&mut lines, "frames 30", "frames 0");
        overload_line(&mut lines, "late 30", "late 0");
        overload_line(&mut lines, "releases 30", "releases 0");
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
        // The bound of 40 bands is about 32 400 us.
        *l = l.replace("compose-max-us 10000", "compose-max-us 33000");
        let e = verdict(&lines, true).unwrap_err();
        assert!(
            e.starts_with("full-loaded: compose max 33000 us over the bound 32"),
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
