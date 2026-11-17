// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The line `service step: T kind K N ticks detail D preempts P` of `rt::service` (`preempts P`
//! is left out when P is 0) and the judgement of a step against the bound B.
//!
//! The line carries the raw time N of the step, the CPU ticks of the thread in it, and is
//! printed when the raw time of a kind grows (a step with a shorter raw time and more work does
//! not print: the reader may take at most the charge of the preemptions of the longest raw step
//! too little, and the warning names a raw time above the bound). A step that a
//! higher level preempted P times holds P charges of the switch that are no work of the step, so
//! the probes judge `N - P * PREEMPT_CHARGE` (`judged`) and keep printing the raw N. A warning
//! names the raw time when it is above the bound.

/// The ticks one preemption adds to the time of the preempted thread, at the least: the lower
/// bound the kernel test measures for a switch inside one process (the `preempt charge ticks`
/// row). A lower bound cannot hide step work: a step that took N with P preemptions did at least
/// `N - P * c` ticks of its own for any true charge c at or above the bound, so judging by that
/// value never passes a step that a true charge would fail.
pub const PREEMPT_CHARGE: u64 = 487;

/// A line of a step, read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepLine<'a> {
    pub tag: &'a str,
    pub kind: usize,
    /// The raw time of the step, in ticks.
    pub ticks: u64,
    pub detail: u64,
    /// The preemptions in the step (0 for a line that has no count).
    pub preempts: u64,
}

impl StepLine<'_> {
    /// The time the step is judged by: the raw time less the charge of its preemptions.
    pub fn judged(&self) -> u64 {
        judged(self.ticks, self.preempts)
    }
}

/// The time less the charge of `preempts` preemptions.
pub fn judged(ticks: u64, preempts: u64) -> u64 {
    ticks.saturating_sub(preempts.saturating_mul(PREEMPT_CHARGE))
}

/// The line, when it is a line of a step (with or without the count of preemptions).
pub fn parse(line: &str) -> Option<StepLine<'_>> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let (tag, kind, ticks, detail, preempts) = match words.as_slice() {
        [
            "service",
            "step:",
            tag,
            "kind",
            kind,
            ticks,
            "ticks",
            "detail",
            detail,
        ] => (tag, kind, ticks, detail, "0"),
        [
            "service",
            "step:",
            tag,
            "kind",
            kind,
            ticks,
            "ticks",
            "detail",
            detail,
            "preempts",
            preempts,
        ] => (tag, kind, ticks, detail, *preempts),
        _ => return None,
    };
    Some(StepLine {
        tag,
        kind: kind.parse().ok()?,
        ticks: ticks.parse().ok()?,
        detail: detail.parse().ok()?,
        preempts: preempts.parse().ok()?,
    })
}

/// The longest step of each kind of the service `tag` in `lines`, by the judged time:
/// (kind, judged ticks, detail), in the order the kinds came.
pub fn longest(lines: &[String], tag: &str) -> Vec<(usize, u64, u64)> {
    let mut out: Vec<(usize, u64, u64)> = Vec::new();
    for step in lines
        .iter()
        .filter_map(|l| parse(l))
        .filter(|s| s.tag == tag)
    {
        let row = (step.kind, step.judged(), step.detail);
        match out.iter_mut().find(|(k, ..)| *k == step.kind) {
            Some(old) if old.1 > row.1 => {}
            Some(old) => *old = row,
            None => out.push(row),
        }
    }
    out
}

/// The warnings for the steps of the service `tag` whose raw time is above `bound`, once for
/// each kind: the judged time may pass them, and the raw time is what the reader should see.
pub fn raw_warnings(lines: &[String], tag: &str, bound: u64) -> Vec<String> {
    let mut seen: Vec<(usize, u64, u64)> = Vec::new();
    for step in lines
        .iter()
        .filter_map(|l| parse(l))
        .filter(|s| s.tag == tag)
    {
        if step.ticks <= bound {
            continue;
        }
        match seen.iter_mut().find(|(k, ..)| *k == step.kind) {
            Some(old) if old.1 >= step.ticks => {}
            Some(old) => *old = (step.kind, step.ticks, step.preempts),
            None => seen.push((step.kind, step.ticks, step.preempts)),
        }
    }
    seen.into_iter()
        .map(|(kind, ticks, preempts)| {
            format!(
                "warning: service {tag} kind {kind}: the raw step took {ticks} ticks with {preempts} preemptions, above the bound {bound}"
            )
        })
        .collect()
}

/// Prints `raw_warnings`, each warning once in the run of `xtask` (the verdicts read the same
/// lines more than once).
pub fn warn_raw(lines: &[String], tag: &str, bound: u64) {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SAID: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let said = SAID.get_or_init(Default::default);
    for warning in raw_warnings(lines, tag, bound) {
        let fresh = said
            .lock()
            .is_ok_and(|mut said| said.insert(warning.clone()));
        if fresh {
            println!("{warning}");
        }
    }
}

/// `longest`, with the warnings of the raw times above `bound`.
pub fn longest_warned(lines: &[String], tag: &str, bound: u64) -> Vec<(usize, u64, u64)> {
    warn_raw(lines, tag, bound);
    longest(lines, tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|l| (*l).to_owned()).collect()
    }

    #[test]
    fn a_line_is_read_with_and_without_the_count() {
        let old = parse("service step: 14 kind 33 16000 ticks detail 64").unwrap();
        assert_eq!(
            (old.tag, old.kind, old.ticks, old.detail, old.preempts),
            ("14", 33, 16_000, 64, 0)
        );
        let new = parse("service step: 14 kind 33 16000 ticks detail 64 preempts 3").unwrap();
        assert_eq!((new.ticks, new.preempts), (16_000, 3));
        assert_eq!(new.judged(), 16_000 - 3 * PREEMPT_CHARGE);
        assert!(parse("service step: 14 kind 33 16000 ticks detail 64 preempts").is_none());
        assert!(parse("service wait: 14 kind 33 16000 ticks of 5").is_none());
        assert!(parse("service step: 14 kind x 16000 ticks detail 64").is_none());
    }

    #[test]
    fn a_step_is_judged_less_the_charge_of_its_preemptions() {
        let bound = 18_369;
        // 19 000 raw with 2 preemptions is 18 026 of work: it passes the judgement, and the raw
        // time is named by a warning.
        let rows = lines(&["service step: 14 kind 33 19000 ticks detail 64 preempts 2"]);
        assert_eq!(longest(&rows, "14"), vec![(33, 18_026, 64)]);
        assert!(longest(&rows, "14")[0].1 <= bound);
        let warnings = raw_warnings(&rows, "14", bound);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("19000") && warnings[0].contains("2 preemptions"));
        // The charge is a lower bound: 19 000 with one preemption is 18 513, past the bound.
        let rows = lines(&["service step: 14 kind 33 19000 ticks detail 64 preempts 1"]);
        assert!(longest(&rows, "14")[0].1 > bound);
        // A raw time within the bound has no warning.
        assert!(
            raw_warnings(
                &lines(&["service step: 14 kind 1 100 ticks detail 0 preempts 0"]),
                "14",
                bound
            )
            .is_empty()
        );
    }

    #[test]
    fn the_longest_is_by_the_judged_time_not_by_the_last_line() {
        let rows = lines(&[
            "service step: 14 kind 7 17000 ticks detail 1 preempts 0",
            // A later line with a longer raw time and more preemptions is shorter as work.
            "service step: 14 kind 7 18000 ticks detail 2 preempts 4",
            "service step: 14 kind 8 500 ticks detail 0",
            "service step: 4 kind 7 99999 ticks detail 0 preempts 0",
        ]);
        assert_eq!(longest(&rows, "14"), vec![(7, 17_000, 1), (8, 500, 0)]);
    }
}
