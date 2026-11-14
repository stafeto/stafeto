// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the time budgets of threads (`tests/budget-hog`, spec 8)
//! under QEMU's -icount, on one CPU and on four: a hog at a high level with
//! a budget of C for each period T must not take more than C of a window of
//! T from a task of a lower level on the same CPU, and without the budget
//! the hog starves it. The lines the probe prints are checked against
//! their bounds here; `breaks` runs the same probe on the kernels with a
//! deliberate break, each of which must fail it.

use std::time::Duration;

use crate::{BOOT_PROFILE, BUDGET_HOG_PROGRAMS, Variant, build, build_boot_image, qemu};

const TIMEOUT: Duration = Duration::from_secs(180);

/// The numbers of the probe's lines: `budget window=10 min_share=873 ...`.
fn number(line: &str, key: &str) -> Result<u64, String> {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(key))
        .ok_or_else(|| format!("missing {key} in {line:?}"))?
        .parse()
        .map_err(|e| format!("bad {key} in {line:?}: {e}"))
}

/// What the probe measured: the least share (per mille) of the victim and the
/// most time of the hog in microseconds for each window, the round trip of
/// the service's request and the victim's numbers with the notification's
/// boost.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Numbers {
    /// (window in ms, least victim share in per mille, most hog time in us,
    /// least hog time in us, times the budget ran out)
    pub windows: Vec<(u64, u64, u64, u64, u64)>,
    pub boost_n: u64,
    pub boost_max_us: u64,
    pub slot_share: u64,
    pub slot_gap_us: u64,
    pub victim_gap_us: u64,
    /// The same windows on CPU 1, when the machine has one.
    pub cpu1: Vec<(u64, u64, u64, u64, u64)>,
    pub cpu1_gap_us: u64,
}

/// The budget of the hog, 300 us for each 1 ms, and the longest stretch the
/// kernel runs with interrupts masked (B), in microseconds under -icount: the
/// 8 865 instructions measured (kernel-test icount) of 16 ns each, with a
/// little room.
const HOG_US: u64 = 300;
const B_US: u64 = 150;

pub fn parse(lines: &[String]) -> Result<Numbers, String> {
    if !lines.iter().any(|l| l.starts_with("budget START "))
        || !lines.iter().any(|l| l == "budget DONE")
    {
        return Err(format!("the probe did not finish: {:?}", lines.last()));
    }
    let mut n = Numbers::default();
    for line in lines {
        let (rest, on_cpu1) = match line.strip_prefix("budget cpu1 ") {
            Some(rest) => (rest, true),
            None => (line.strip_prefix("budget ").unwrap_or(""), false),
        };
        if let Some(rest) = rest.strip_prefix("window=") {
            let w: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|w| w.parse().ok())
                .ok_or_else(|| format!("bad window in {line:?}"))?;
            let row = (
                w,
                number(line, "min_share=")?,
                number(line, "max_hog=")?,
                number(line, "hog_min=")?,
                number(line, "overruns=")?,
            );
            if on_cpu1 {
                n.cpu1.push(row);
            } else {
                n.windows.push(row);
            }
        } else if rest.starts_with("gaps ") {
            let gap = number(line, "victim_us=")?;
            if on_cpu1 {
                n.cpu1_gap_us = gap;
            } else {
                n.victim_gap_us = gap;
            }
        } else if line.starts_with("budget boost ") {
            n.boost_n = number(line, "n=")?;
            n.boost_max_us = number(line, "max_round_trip_us=")?;
        } else if line.starts_with("budget slot ") {
            n.slot_share = number(line, "min_share=")?;
            n.slot_gap_us = number(line, "max_gap_us=")?;
        }
    }
    if n.windows.len() != 3 || n.boost_n == 0 || n.slot_share == 0 && n.slot_gap_us == 0 {
        return Err(format!("the probe's lines are incomplete: {n:?}"));
    }
    Ok(n)
}

/// The bounds of the probe against what it measured.
pub fn verdict(n: &Numbers, cpus: usize) -> Result<(), String> {
    if cpus >= 2 && n.cpu1.len() != 3 {
        return Err("the probe did not run its hog on CPU 1".into());
    }
    for &(window, share, hog_most, hog_least, overruns) in n.windows.iter().chain(&n.cpu1) {
        // The hog takes the budget for each period the window touches, and
        // one longest call of the kernel (B) more.
        let most = window * HOG_US + B_US;
        if hog_most > most {
            return Err(format!(
                "the hog took {hog_most} us in a window of {window} ms: over {most}"
            ));
        }
        // The victim keeps what the hog and the trusted work leave: 70 % less
        // a tenth for the work of the kernel and the probe's own threads.
        if share < 600 {
            return Err(format!(
                "the victim got {share} per mille in a window of {window} ms: under 600"
            ));
        }
        // The budget comes back: the hog runs its budget in every window of
        // 5 ms and more.
        if window >= 5 && hog_least < window * HOG_US * 3 / 4 {
            return Err(format!(
                "the hog took {hog_least} us in a window of {window} ms: its budget did not come back"
            ));
        }
        if overruns == 0 {
            return Err("the budget of the hog never ran out".into());
        }
    }
    // The victim waits for the hog's budget and the worker's, and the
    // work of the kernel between them; a gap longer than a period is the
    // hog without a budget.
    if n.victim_gap_us.max(n.cpu1_gap_us) > 1000 - HOG_US + B_US {
        return Err(format!(
            "the victim waited {} us: over {}",
            n.victim_gap_us,
            1000 - HOG_US + B_US
        ));
    }
    // The service's request takes its 500 us of work and no more: the boost
    // of its client stays when the budget of 200 us is gone.
    if n.boost_max_us > 700 {
        return Err(format!(
            "a request took {} us: the boost of its client did not stay with the budget gone",
            n.boost_max_us
        ));
    }
    // The worker at 55 for each notification gets its 200 us of each
    // period and the boost of the slot goes with the budget: the victim
    // keeps 750 per mille at least, and no gap of its own passes 400 us.
    if n.slot_share < 750 || n.slot_gap_us > 400 {
        return Err(format!(
            "the boost of a notification outlived the budget: the victim got {} per mille with a gap of {} us",
            n.slot_share, n.slot_gap_us
        ));
    }
    Ok(())
}

/// One run of the probe on `cpus` CPUs with the kernel of `variant`.
pub fn probe(variant: Variant, cpus: usize) -> Result<Numbers, String> {
    let image = build_boot_image("budget-hog.img", &BUDGET_HOG_PROGRAMS, BOOT_PROFILE)?;
    let kernel = build(variant)?;
    let outcome = qemu::on_cpus(cpus, || {
        let mut cmd = qemu::command(&qemu::VIRT_V3, &kernel.image, Some(&image));
        cmd.args(qemu::HEADLESS);
        cmd.args(qemu::ICOUNT);
        qemu::run_until(cmd, TIMEOUT, Some("budget DONE"))
    })?;
    if outcome.timed_out || !outcome.stopped_on_marker {
        return Err(format!(
            "the probe on {cpus} CPUs did not finish: {:?}",
            outcome.lines.last()
        ));
    }
    for line in outcome.lines.iter().filter(|l| l.starts_with("budget ")) {
        println!("  [{cpus} CPUs] {line}");
    }
    parse(&outcome.lines)
}

pub fn run(args: &[String]) -> Result<(), String> {
    let cpus: Vec<usize> = match args {
        [] => vec![1, 4],
        [flag, n] if flag == "--cpus" => vec![
            n.parse()
                .ok()
                .filter(|n| (1..=8).contains(n))
                .ok_or("budget-hog --cpus expects 1..=8")?,
        ],
        _ => return Err("usage: cargo xtask budget-hog [--cpus N]".into()),
    };
    for n in cpus {
        let numbers = probe(Variant::Normal, n)?;
        verdict(&numbers, n).map_err(|e| format!("budget-hog on {n} CPUs: {e}"))?;
        println!("budget-hog: {n} CPUs pass");
    }
    Ok(())
}

/// `cargo xtask budget-breaks`: the probe fails on each kernel with a
/// break, the kernel tests fail the test of the level of a process on the
/// kernel that ignores it, and the host tests of kcore fail on each break
/// of the rules.
pub fn breaks() -> Result<(), String> {
    for (variant, what) in [
        (Variant::BudgetOff, "a bind that binds nothing"),
        (
            Variant::BudgetSlotKeeps,
            "a boost of a notification that outlives the budget",
        ),
        (Variant::BudgetRefill, "a replenishment that never applies"),
        (
            Variant::BudgetKeepLevel,
            "a thread that keeps its level when its budget is gone",
        ),
    ] {
        match probe(variant, 1).and_then(|n| verdict(&n, 1)) {
            Err(e) => println!("budget-breaks: {what} is caught ({e})"),
            Ok(()) => return Err(format!("the break ({what}) passed the probe")),
        }
    }
    for (variant, test, what) in [
        (
            Variant::BudgetNoFree,
            "a_thread_with_no_budget_works_at_the_free_level",
            "a thread with no budget above the level of its process",
        ),
        (
            Variant::BudgetChildFree,
            "a_thread_with_no_budget_works_at_the_free_level",
            "a child with more free level than its creator",
        ),
    ] {
        let a = build(variant)?;
        let mut cmd = qemu::command(&qemu::VIRT, &a.image, Some(&a.boot_image));
        cmd.args(qemu::HEADLESS);
        let o = qemu::run_until(cmd, Duration::from_secs(300), None)?;
        let report = qemu::parse_report(&o.lines);
        if !report.failed.iter().any(|(name, _)| name == test) {
            return Err(format!("the kernel with {what} passed its test"));
        }
        println!("budget-breaks: {what} is caught");
    }
    for feature in [
        "break-budget-refill",
        "break-budget-short-period",
        "break-budget-merge-always",
        "break-budget-no-overrun",
        "break-budget-keep-level",
        "break-budget-keep-slot",
        "break-budget-no-free",
        "break-budget-child-free",
        "break-budget-forgive-overrun",
        "break-budget-skip-boosted",
    ] {
        let out =
            std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
                .current_dir(crate::root())
                .args(["test", "-p", "kcore", "--features", feature])
                .output()
                .map_err(|e| format!("cargo test: {e}"))?;
        if out.status.success() {
            return Err(format!("the host tests of kcore passed with {feature}"));
        }
        println!("budget-breaks: {feature} fails the host tests");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(share: u64, hog: u64, boost: u64, slot: (u64, u64)) -> Vec<String> {
        vec![
            "budget START hz=62500000".into(),
            format!("budget window=1 min_share={share} max_hog={hog} hog_min=0 overruns=3"),
            format!(
                "budget window=5 min_share={share} max_hog={} hog_min=1400 overruns=3",
                hog * 5
            ),
            format!(
                "budget window=10 min_share={share} max_hog={} hog_min=2900 overruns=3",
                hog * 10
            ),
            "budget gaps victim_us=500 hog_us=100".into(),
            format!("budget boost n=40 max_round_trip_us={boost}"),
            format!("budget slot min_share={} max_gap_us={}", slot.0, slot.1),
            "budget DONE".into(),
        ]
    }

    #[test]
    fn a_probe_run_within_its_bounds_passes() {
        let n = parse(&lines(700, 300, 600, (800, 250))).unwrap();
        assert_eq!(n.windows.len(), 3);
        verdict(&n, 1).unwrap();
    }

    #[test]
    fn each_bound_fails_its_own_number() {
        for (case, text) in [
            (lines(50, 300, 600, (800, 250)), "victim got"),
            (lines(700, 600, 600, (800, 250)), "the hog took"),
            (lines(700, 300, 1500, (800, 250)), "request took"),
            (lines(700, 300, 600, (400, 900)), "outlived"),
        ] {
            let e = verdict(&parse(&case).unwrap(), 1).unwrap_err();
            assert!(e.contains(text), "{e}");
        }
    }

    #[test]
    fn a_run_that_did_not_finish_is_refused() {
        let mut l = lines(700, 300, 600, (800, 250));
        l.pop();
        assert!(parse(&l).is_err());
    }
}
