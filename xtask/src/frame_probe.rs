// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask frame-probe [counters]`: the frame time under the loads.
//!
//! One boot of the image of the measures (`boot-frame-steps.img`, init's table
//! `table::frame`) runs the eight phases of `tests/frame-load` (quiet, idle,
//! full, cpu, files, net, stress, direct) under -icount on one CPU. The
//! conductor reads the service's statistics (STATS) at the end of each phase
//! and prints them; this module reads the lines and judges each phase against
//! the bound of the analysis of the frame time:
//!
//! - `quiet`: no frame and no wake-up of the frame's timer;
//! - `idle`, `cpu`, `files`, `net` (the scene P): no late frame, no skip, the
//!   window of the client neither late nor missed, the time to compose under
//!   the bound of its row, and in `net` the budgets of the network service
//!   overrun (the load is real);
//! - `full` (the scene F): the same, with the bound computed from the bands of
//!   the frame as measured, when the frame has no more than 45 bands; with more
//!   the phase is a load phase and says so;
//! - `stress` (F with all the loads): skips are printed and expected, and the
//!   loop of the CPU load turned;
//! - `direct` (a window of the first revision shown from the pool): no late
//!   frame, no skip, every frame direct, the time to compose under the bound;
//! - every step of the services under the gates of the steps (18 369 ticks, a
//!   band or a portion 16 328), the kinds of SET and STATS and the timer's step
//!   among them.
//!
//! `counters` runs the image on QEMU's own clock (no -icount) and asks for
//! the shape of the lines and the counts alone, with no requirement of time.

use crate::frame_image;
use compositor::frame::{Source, bound};
use frame_load::phases::{ORDER, Phase};
use init::table::Kind;
use init::table::frame::TABLE;

/// The tick of the counter under -icount: 62.5 MHz.
const TICK_NS: u64 = 16;
/// The terms of the bound (the design of the frame time): the taking at the start of a period,
/// a band, the commit and the end of a frame (two steps), the longest kernel path with a step,
/// the display driver, the disk (two steps), the requests of the clients and the events of a
/// budget.
const TAKING: u64 = 3_000;
const BAND: u64 = 16_328;
const STEP: u64 = 18_369;
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
/// The share of a period the service may use at most (52 bands under the
/// cap, 849 056 ticks of 1 041 667): the CPU the levels below it can count on
/// is what the budgets above leave of the rest.
const SERVICE_SHARE_PPM: u64 = 815_000;

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

/// The rows of the table of bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Row {
    /// A window of 160 by 100 under all the loads.
    P,
    /// A frame shown directly from the pool under all the loads.
    D,
    /// The whole screen of this many bands with no load.
    F(u64),
}

/// The own work of a frame of a row, in ticks.
pub fn own(row: Row) -> u64 {
    let (bands, disk, requests) = match row {
        Row::P => (P_BANDS, true, true),
        Row::D => (0, true, true),
        Row::F(bands) => (bands, false, false),
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
            Phase::Quiet => {
                if p.frames != 0 || (timed && p.wakeups != 0) {
                    return fail(format!(
                        "frames {} wakeups {} with nothing drawn",
                        p.frames, p.wakeups
                    ));
                }
                said.push(format!(
                    "frame-probe: quiet: no frame, wakeups {}",
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
            Phase::Stress => {
                if timed && p.skipped == 0 {
                    return fail(
                        "no skip under all the loads (the loads are not heavy)".to_owned(),
                    );
                }
                let alone = loops(lines, Phase::Quiet).unwrap_or(0);
                let share = loops(lines, phase)
                    .map(|n| n * 1_000_000 / alone.max(1))
                    .unwrap_or(0);
                // What the levels below the service are promised: the period less the
                // service and the budgets above it, none when they take it all.
                let floor = 1_000_000u64
                    .saturating_sub(SERVICE_SHARE_PPM)
                    .saturating_sub(budgets_share_ppm());
                if share == 0 || share < floor {
                    return fail(format!(
                        "the CPU load got {} of the loop alone (floor {})",
                        frac(share),
                        frac(floor)
                    ));
                }
                said.push(format!(
                    "frame-probe: stress: 240 periods, frames {}, skipped {}, cpu share {} (floor {})",
                    p.frames,
                    p.skipped,
                    frac(share),
                    frac(floor)
                ));
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
    // The network load is real in the phase `net`: the budgets of the network service ran out.
    if timed
        && !lines
            .iter()
            .any(|l| l.starts_with("init: netd budget ") && l.contains(" overruns"))
    {
        return Err("net: no line of init about an overrun of the budgets of netd".to_owned());
    }
    if full_judged_as_load {
        said.push(
            "frame-probe: the whole-screen frame has more bands than the design allows: raise it in the report"
                .to_owned(),
        );
    }
    Ok(said)
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
        if let Some(row) = rows.iter().find(|r| r.1 > crate::gpu_probe::STEP_MAX) {
            return Err(format!(
                "the {name}: a step past the gate ({}): {row:?}",
                crate::gpu_probe::STEP_MAX
            ));
        }
        if let Some(row) = rows.iter().find(|r| r.0 == 65 && r.1 > crate::PORTION_MAX) {
            return Err(format!(
                "the {name}: a portion past {}: {row:?}",
                crate::PORTION_MAX
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
        assert_eq!(bound_ticks(Row::F(42)), Some(868_908));
        assert_eq!(bound_ticks(Row::F(45)), Some(917_892));
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
                Phase::Stress => (97, 0, 143, 240, 97 * 58, 14_000),
                Phase::Direct => (240, 240, 0, 240, 0, 1_000),
                _ => (240, 0, 0, 240, 240 * 4, 2_950),
            };
            lines.push(format!(
                "frame-load: phase {name} frames {frames} late 0 skipped {skipped} failed 0 capped 0 wakeups {wakeups} take-max-us 410 compose-max-us {compose} device-max-us 120 frame-max-us 3070 band-max-us 260 releases {frames} direct {direct}"
            ));
            lines.push(format!("frame-load: hist {name} 0 212 26 2 0"));
            lines.push(format!("frame-load: bands {name} {bands}"));
            if matches!(phase.scene(), Scene::P | Scene::F) {
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
                let n = if phase == Phase::Stress {
                    200_000
                } else {
                    812_345
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
        assert!(
            said.iter()
                .any(|l| l.starts_with("frame-probe: stress: 240 periods, frames 97, skipped 143"))
        );
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
    fn no_skip_in_stress_fails_and_so_does_a_loop_that_did_not_turn() {
        let mut lines = good();
        let l = lines
            .iter_mut()
            .find(|l| l.starts_with("frame-load: phase stress "))
            .unwrap();
        *l = l.replace("skipped 143", "skipped 0");
        assert!(
            verdict(&lines, true)
                .unwrap_err()
                .starts_with("stress: no skip")
        );
        let mut lines = good();
        replace_line(
            &mut lines,
            "frame-load: cpu stress ",
            "frame-load: cpu stress loops-per-s 0",
        );
        assert!(verdict(&lines, true).is_err());
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
    fn a_net_phase_without_an_overrun_of_netd_fails() {
        let mut lines = good();
        lines.retain(|l| !l.starts_with("init: netd budget"));
        assert!(
            verdict(&lines, true)
                .unwrap_err()
                .starts_with("net: no line of init")
        );
        assert!(verdict(&lines, false).is_ok());
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
        let e = steps_verdict(&steps(&[(tag, 20, 18_500)])).unwrap_err();
        assert!(e.contains("past the gate"), "{e}");
        let e = steps_verdict(&steps(&[(tag, 65, 16_400)])).unwrap_err();
        assert!(e.contains("past 16328"), "{e}");
        // Stats and the timer's step are required.
        for kind in [25usize, 64] {
            let mut lines = steps(&[]);
            lines.retain(|l| !l.starts_with(&format!("service step: {tag} kind {kind} ")));
            assert!(steps_verdict(&lines).unwrap_err().contains("no step"));
        }
    }
}
