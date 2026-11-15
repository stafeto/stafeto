// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the overruns in init's journal (`cargo xtask budget-journal`,
//! spec 8, stage 5) under QEMU's -icount on one CPU. Init's table
//! (`table-budget-journal`) has one client, `burner` (tests/svc, role `b`),
//! with two budgets of 1 ms for each 10 ms: its thread under `hog` works
//! without a pause and overruns in every period until second 13, its thread
//! under `quiet` stays within its budget. The service prints a line each
//! second of the clock with the overruns the kernel counts for each budget.
//! The verdict:
//!
//! 1. `hog` has exactly one line of init's journal in each window of 10 s: one
//!    by the first second, a second between the 10th and the 20th, and a third
//!    after the 20th, which is the tail of the overruns of the 10th to the
//!    13th second, written at the heartbeat after the window passed; no line
//!    after it.
//! 2. The total of each line stands between what the kernel counted at the
//!    seconds on either side of the line, is not above the kernel's own count
//!    the line prints, and the overruns since the last line add up to the
//!    totals.
//! 3. `quiet` has no line, and the kernel counts no overrun for it.
//!
//! `breaks` runs the probe on init built with each deliberate break; each must
//! fail it, and the host tests of init with it.

use std::time::Duration;

use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, SVC_STACK_SIZE, Variant, build, build_boot_image,
    qemu,
};

const TIMEOUT: Duration = Duration::from_secs(900);
const DONE: &str = "burner: done";
/// The seconds of the client's lines: 0 to this.
const SECONDS: usize = 30;
/// The kernel's count may run ahead of the line's total by this much at most
/// at the second before the line (a notification in flight).
const SLACK: u64 = 2;

const NORMAL: [ImageProgram; 2] = [
    ("init", "init", INIT_STACK_SIZE, &["table-budget-journal"]),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
];
const IGNORE: [ImageProgram; 2] = [
    (
        "init",
        "init",
        INIT_STACK_SIZE,
        &["table-budget-journal", "break-overrun-ignore"],
    ),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
];
const EACH: [ImageProgram; 2] = [
    (
        "init",
        "init",
        INIT_STACK_SIZE,
        &["table-budget-journal", "break-overrun-log-each"],
    ),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
];

/// A line of init's journal: the overruns since the last line, the total.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Entry {
    pub since: u64,
    pub total: u64,
    /// What the kernel counts for the budget, when the line says.
    pub kernel: Option<u64>,
}

/// What the lines of the run say, in the order they came: the lines of init
/// for each budget, each with the number of the client's lines before it, and
/// the kernel's counts at each second.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Journal {
    pub hog: Vec<(usize, Entry)>,
    pub quiet: Vec<(usize, Entry)>,
    /// (hog, quiet) overruns the kernel counted, at second 0, 1, ...
    pub kernel: Vec<(u64, u64)>,
}

fn number(text: &str) -> Result<u64, String> {
    text.trim().parse().map_err(|e| format!("{text:?}: {e}"))
}

/// `init: burner budget hog: at least 1000 overruns, at least 3000 in all, kernel counts 3004`.
fn entry(rest: &str) -> Result<Entry, String> {
    let bad = || format!("the line of a budget: {rest:?}");
    let rest = rest.strip_prefix("at least ").ok_or_else(bad)?;
    let (since, rest) = rest.split_once(" overruns, at least ").ok_or_else(bad)?;
    let (total, kernel) = match rest.split_once(" in all, kernel counts ") {
        Some((total, kernel)) => (total, Some(number(kernel)?)),
        None => (rest.strip_suffix(" in all").ok_or_else(bad)?, None),
    };
    Ok(Entry {
        since: number(since)?,
        total: number(total)?,
        kernel,
    })
}

pub fn parse(lines: &[String]) -> Result<Journal, String> {
    let mut j = Journal::default();
    for l in lines {
        if let Some(rest) = l.strip_prefix("init: burner budget hog: ") {
            j.hog.push((j.kernel.len(), entry(rest)?));
        } else if let Some(rest) = l.strip_prefix("init: burner budget quiet: ") {
            j.quiet.push((j.kernel.len(), entry(rest)?));
        } else if let Some(rest) = l.strip_prefix("burner: t=") {
            let (t, rest) = rest.split_once(" hog=").ok_or("a line of a second")?;
            let (hog, quiet) = rest.split_once(" quiet=").ok_or("a line of a second")?;
            if number(t)? as usize != j.kernel.len() {
                return Err(format!("the second {t} came out of order"));
            }
            j.kernel.push((number(hog)?, number(quiet)?));
        }
    }
    Ok(j)
}

/// The lines due at second `k` of the ticker's: those before its line of
/// second `k` count for it. Seconds 0, 10 and 20 are left out of the count:
/// the second line comes 10 s after the first, which the budget wrote a few
/// milliseconds before the ticker's clock began. The hog stops at second 13;
/// the third line is the tail of its overruns, written at the heartbeat that
/// follows the end of the second window.
fn expected_at(k: usize) -> Option<usize> {
    match k {
        1..=9 => Some(1),
        11..=19 => Some(2),
        21..=30 => Some(3),
        _ => None,
    }
}

pub fn verdict(j: &Journal) -> Result<(), String> {
    if j.kernel.len() != SECONDS + 1 {
        return Err(format!(
            "the client printed {} seconds, {} expected",
            j.kernel.len(),
            SECONDS + 1
        ));
    }
    if !j.quiet.is_empty() || j.kernel.iter().any(|&(_, quiet)| quiet != 0) {
        return Err(format!(
            "a budget that never runs out has {} lines, and the kernel counts {:?} overruns for it",
            j.quiet.len(),
            j.kernel.last().map(|k| k.1)
        ));
    }
    // One line for each window of 10 s.
    for k in 0..=SECONDS {
        let Some(want) = expected_at(k) else { continue };
        let got = j.hog.iter().filter(|(at, _)| *at <= k).count();
        if got != want {
            return Err(format!(
                "{got} lines of the hog's budget by the second {k}, {want} expected (one in each 10 s)"
            ));
        }
    }
    if j.hog.len() != 3 {
        return Err(format!(
            "{} lines of the hog's budget, 3 expected",
            j.hog.len()
        ));
    }
    // The counts: since and total agree, and the total is what the kernel
    // counted around the line.
    let mut before = 0;
    for (n, (at, e)) in j.hog.iter().enumerate() {
        if e.total != before + e.since || e.since == 0 {
            return Err(format!("line {n}: {e:?} after a total of {before}"));
        }
        before = e.total;
        let ahead = j.kernel.get(*at).map_or(u64::MAX, |k| k.0);
        let behind = at.checked_sub(1).map_or(0, |a| j.kernel[a].0);
        if e.total > ahead || e.total + SLACK < behind {
            return Err(format!(
                "line {n}: a total of {} where the kernel counted {behind} before it and {ahead} after",
                e.total
            ));
        }
        // 100 overruns a second: 1000 in the window of 10 s, and about 300
        // in the tail (the hog stops at second 13).
        let (least, most) = match n {
            0 => (1, 1),
            1 => (900, 1100),
            _ => (200, 400),
        };
        if !(least..=most).contains(&e.since) {
            return Err(format!(
                "line {n}: {} overruns, {least} to {most} expected",
                e.since
            ));
        }
        // The notifications count a lower bound of the kernel's overruns.
        if e.kernel.is_some_and(|k| e.total > k || k > ahead) {
            return Err(format!(
                "line {n}: a total of {} where the kernel counts {:?} (at most {ahead} at the next second)",
                e.total, e.kernel
            ));
        }
    }
    // The tail is the whole: nothing is left untold at the end.
    let last = j.kernel.last().map_or(0, |k| k.0);
    if j.hog
        .last()
        .is_none_or(|(_, e)| e.total > last || e.total + SLACK < last)
    {
        return Err(format!("the last total is not the kernel's {last}"));
    }
    Ok(())
}

/// One run of the probe on the programs `programs`.
fn probe(name: &'static str, programs: &'static [ImageProgram]) -> Result<Journal, String> {
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let kernel = build(Variant::Normal)?;
    let outcome = qemu::on_cpus(1, || {
        let mut cmd = qemu::command(&qemu::VIRT_V3, &kernel.image, Some(&image));
        cmd.args(qemu::HEADLESS);
        cmd.args(qemu::ICOUNT);
        qemu::run_until(cmd, TIMEOUT, Some(DONE))
    })?;
    if outcome.timed_out || !outcome.stopped_on_marker {
        return Err(format!(
            "the probe did not finish: {:?}",
            outcome.lines.last()
        ));
    }
    for l in outcome
        .lines
        .iter()
        .filter(|l| l.starts_with("init: burner") || l.starts_with("burner: "))
    {
        println!("  {l}");
    }
    parse(&outcome.lines)
}

/// `cargo xtask budget-journal`.
pub fn run(_: &[String]) -> Result<(), String> {
    let journal = probe("budget-journal.img", &NORMAL)?;
    verdict(&journal).map_err(|e| format!("budget-journal: {e}"))?;
    println!(
        "budget-journal: one line in each 10 s for the budget that overruns, none for the other: ok"
    );
    Ok(())
}

/// The deliberate breaks of init that the probe and the host tests of init
/// must catch (`cargo xtask budget-breaks`).
pub fn breaks() -> Result<(), String> {
    for (name, programs, feature) in [
        (
            "budget-journal-ignore.img",
            &IGNORE[..],
            "break-overrun-ignore",
        ),
        (
            "budget-journal-each.img",
            &EACH[..],
            "break-overrun-log-each",
        ),
    ] {
        match probe(name, programs).and_then(|j| verdict(&j)) {
            Err(e) => println!("budget-breaks: {feature} is caught by the probe ({e})"),
            Ok(()) => return Err(format!("the break {feature} passed the journal probe")),
        }
        let out =
            std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
                .current_dir(crate::root())
                .args(["test", "-p", "init", "--lib", "--features", feature])
                .output()
                .map_err(|e| format!("cargo test: {e}"))?;
        if out.status.success() {
            return Err(format!("the host tests of init passed with {feature}"));
        }
        println!("budget-breaks: {feature} fails the host tests of init");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lines of a good run: the hog's budget overruns 100 times a second
    /// until second 13, and init writes the lines at 0, 10 and 20 s.
    fn good() -> Vec<String> {
        let mut lines = vec![
            "init: burner budget hog: at least 1 overruns, at least 1 in all, kernel counts 1"
                .to_string(),
        ];
        let count = |k: usize| 100 * k.min(13) as u64 + 1;
        for k in 0..=SECONDS {
            lines.push(format!("burner: t={k} hog={} quiet=0", count(k)));
            if k == 10 {
                lines.push("init: burner budget hog: at least 1000 overruns, at least 1001 in all, kernel counts 1001".into());
            }
            if k == 20 {
                lines.push(
                    "init: burner budget hog: at least 300 overruns, at least 1301 in all".into(),
                );
            }
        }
        lines.push(DONE.into());
        lines
    }

    #[test]
    fn a_good_run_passes() {
        assert_eq!(verdict(&parse(&good()).unwrap()), Ok(()));
    }

    #[test]
    fn a_line_for_each_notification_fails() {
        let mut lines = good();
        lines.insert(
            1,
            "init: burner budget hog: at least 1 overruns, at least 2 in all".to_string(),
        );
        assert!(verdict(&parse(&lines).unwrap()).is_err());
    }

    #[test]
    fn no_line_at_all_fails() {
        let lines: Vec<String> = good()
            .into_iter()
            .filter(|l| !l.starts_with("init:"))
            .collect();
        assert!(verdict(&parse(&lines).unwrap()).is_err());
    }

    #[test]
    fn a_line_for_the_budget_that_never_overruns_fails() {
        let mut lines = good();
        lines.insert(
            1,
            "init: burner budget quiet: at least 1 overruns, at least 1 in all".to_string(),
        );
        assert!(verdict(&parse(&lines).unwrap()).is_err());
    }

    #[test]
    fn a_count_that_the_kernel_does_not_back_fails() {
        let mut lines = good();
        for l in &mut lines {
            if l.ends_with("1301 in all") {
                *l = "init: burner budget hog: at least 300 overruns, at least 1301 in all, kernel counts 900".into();
            }
        }
        assert!(verdict(&parse(&lines).unwrap()).is_err());
    }

    #[test]
    fn a_tail_that_never_comes_fails() {
        let lines: Vec<String> = good()
            .into_iter()
            .filter(|l| !l.ends_with("1301 in all"))
            .collect();
        assert!(verdict(&parse(&lines).unwrap()).is_err());
    }
}
