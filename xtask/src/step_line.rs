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
//! a step is judged by two checks and the raw N keeps printing:
//!
//! - B, hard: `N - P * PREEMPT_CHARGE_MIN` at most B (`over_bound`), the provable bound of the
//!   step's own work;
//! - 0.9 B: the greatest by kind of `N - P * PREEMPT_CHARGE` (`judged`, `longest`) at most 0.9 B,
//!   which the callers check. A warning names the raw time when it is above the bound.

/// The ticks one preemption adds to the time of the preempted thread, at the least: the lower
/// bound the kernel test measures for a switch inside one process (the `preempt charge ticks`
/// row). A lower bound cannot hide step work: a step that took N with P preemptions did at least
/// `N - P * c` ticks of its own for any true charge c at or above the bound, so judging by that
/// value never passes a step that a true charge would fail. It judges the bound B.
pub const PREEMPT_CHARGE_MIN: u64 = 487;

/// The measured cost of a preemption of the worst kind seen (a preemptor of another process, SIMD
/// state live, a budget event), for the target 0.9 B. A probe is to measure it (the `preempt
/// charge ticks` rows); until then it is the largest seen, 1 261 ticks in a step of the RAM file
/// service on 19 November, with a margin. A c that is too small can only eat the margin between
/// 0.9 B and B, since `over_bound` holds B by the lower bound.
pub const PREEMPT_CHARGE: u64 = 1_300;

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
    /// The time the step is judged by against 0.9 B: the raw time less the measured charge of
    /// its preemptions.
    pub fn judged(&self) -> u64 {
        judged(self.ticks, self.preempts)
    }

    /// The least the step's own work took: the raw time less the least charge of its
    /// preemptions. The bound B is judged by it.
    pub fn least(&self) -> u64 {
        least(self.ticks, self.preempts)
    }
}

/// The services keep the longest raw time of each pair (kind, preemptions) for 0 to 7
/// preemptions and one pair for 8 and more (`rt::service`'s step statistics). In one pair the
/// greatest raw time is the greatest judged time at any charge, and the pair of 8 and more is
/// judged with 8 preemptions: stricter than the true count of the line, which is the safe side.
pub const PAIR_TOP: u64 = 8;

/// The time less the measured charge of `preempts` preemptions (against 0.9 B).
pub fn judged(ticks: u64, preempts: u64) -> u64 {
    ticks.saturating_sub(preempts.min(PAIR_TOP).saturating_mul(PREEMPT_CHARGE))
}

/// The time less the least charge of `preempts` preemptions (against B).
pub fn least(ticks: u64, preempts: u64) -> u64 {
    ticks.saturating_sub(preempts.min(PAIR_TOP).saturating_mul(PREEMPT_CHARGE_MIN))
}

/// The kinds a probe judges: the hard check against B applies to exactly those, with the
/// exemptions the probe always had (a start-up step, a run on two CPUs, the kinds it does not
/// bound).
#[derive(Clone, Copy, Debug)]
pub enum Kinds<'a> {
    /// Every kind of the service.
    All,
    /// These kinds only.
    Only(&'a [usize]),
    /// Every kind but these.
    Except(&'a [usize]),
}

impl Kinds<'_> {
    pub fn has(&self, kind: usize) -> bool {
        match self {
            Kinds::All => true,
            Kinds::Only(kinds) => kinds.contains(&kind),
            Kinds::Except(kinds) => !kinds.contains(&kind),
        }
    }
}

/// The hard check against B (`crate::TERM_B`) of the steps of the service `tag` of the kinds a
/// probe judges (`over_bound`): an error that names the step, for the probes to return.
pub fn within_b(lines: &[String], tag: &str, kinds: Kinds) -> Result<(), String> {
    match over_bound(lines, tag, crate::TERM_B, kinds) {
        Some(over) => Err(over),
        None => Ok(()),
    }
}

/// The first step of the service `tag` in `lines` (a line of a new longest or of the table) whose
/// least own work, `N - P * PREEMPT_CHARGE_MIN`, is above `bound` (B), told with the raw N, P and
/// both judged figures. The bound stays hard for every step line.
pub fn over_bound(lines: &[String], tag: &str, bound: u64, kinds: Kinds) -> Option<String> {
    lines
        .iter()
        .filter_map(|l| parse_any(l))
        .filter(|s| s.tag == tag && kinds.has(s.kind))
        .find(|s| s.least() > bound)
        .map(|s| {
            format!(
                "service {tag} kind {}: raw {} ticks, preempts {}, judged {} - {} * {PREEMPT_CHARGE} = {} against 0.9 B {}, at least {} - {} * {PREEMPT_CHARGE_MIN} = {} against B {bound}",
                s.kind,
                s.ticks,
                s.preempts,
                s.ticks,
                s.preempts,
                s.judged(),
                bound * 9 / 10,
                s.ticks,
                s.preempts,
                s.least()
            )
        })
}

/// Tells the observed own work of a kind (`clean_longest`) beside the judged maximum: a report
/// line, no verdict.
pub fn say_clean(lines: &[String], tag: &str, name: &str, kind: usize) {
    if let Some(clean) = clean_longest(lines, tag, kind) {
        println!("{name}: the longest kind {kind} step with no preemption took {clean} ticks");
    }
}

/// The greatest raw time of a step of kind `kind` of the service `tag` that no preemption
/// touched (`preempts 0`), the figure of the work of the step itself. None when every line of the
/// kind has a preemption.
pub fn clean_longest(lines: &[String], tag: &str, kind: usize) -> Option<u64> {
    lines
        .iter()
        .filter_map(|l| parse_any(l))
        .filter(|s| s.tag == tag && s.kind == kind && s.preempts == 0)
        .map(|s| s.ticks)
        .max()
}

/// The line, when it is a line of a step (with or without the count of preemptions).
pub fn parse(line: &str) -> Option<StepLine<'_>> {
    parse_word(line, "step:")
}

/// The line `service table: T kind K N ticks detail D preempts P` of the table that a service
/// tells after the burst at the start of a run (`rt::service::table_steps`).
pub fn parse_table(line: &str) -> Option<StepLine<'_>> {
    parse_word(line, "table:")
}

/// A line of a new longest or a line of the table, read: the table lines hold the longest step
/// of each kind after the burst at the start of a run, where the lines of a new longest may have
/// been lost, and a reader that takes the longer of the two for each kind gets every kind the
/// run did.
fn parse_any(line: &str) -> Option<StepLine<'_>> {
    parse(line).or_else(|| parse_table(line))
}

fn parse_word<'a>(line: &'a str, word: &str) -> Option<StepLine<'a>> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let (tag, kind, ticks, detail, preempts) = match words.as_slice() {
        [
            "service",
            w,
            tag,
            "kind",
            kind,
            ticks,
            "ticks",
            "detail",
            detail,
        ] if *w == word => (tag, kind, ticks, detail, "0"),
        [
            "service",
            w,
            tag,
            "kind",
            kind,
            ticks,
            "ticks",
            "detail",
            detail,
            "preempts",
            preempts,
        ] if *w == word => (tag, kind, ticks, detail, *preempts),
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

/// The longest step of each kind of the service `tag` in `lines`, by the time judged against 0.9 B:
/// (kind, judged ticks, detail), in the order the kinds came. The lines of a new longest and the
/// lines of the table (`parse_table`) are both read.
pub fn longest(lines: &[String], tag: &str) -> Vec<(usize, u64, u64)> {
    let mut out: Vec<(usize, u64, u64)> = Vec::new();
    for step in lines
        .iter()
        .filter_map(|l| parse_any(l))
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
        .filter_map(|l| parse_any(l))
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

/// `longest`, with the warnings of the raw times above `bound`. The hard check against B is
/// `within_b`, which each probe calls for the kinds it judges.
pub fn longest_warned(lines: &[String], tag: &str, bound: u64) -> Vec<(usize, u64, u64)> {
    warn_raw(lines, tag, bound);
    longest(lines, tag)
}

/// The lines of a run whose lines of a new longest were all lost in the burst at the start and
/// that kept the table of the service (for the tests of the probes that read it).
#[cfg(test)]
pub fn tabled(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|l| match parse(l) {
            Some(s) => format!(
                "service table: {} kind {} {} ticks detail {} preempts {}",
                s.tag, s.kind, s.ticks, s.detail, s.preempts
            ),
            None => l.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|l| (*l).to_owned()).collect()
    }

    #[test]
    fn the_table_lines_are_read_apart_from_the_lines_of_a_new_longest() {
        let l = "service table: 15 kind 5 8058 ticks detail 0 preempts 0";
        assert!(parse(l).is_none());
        let t = parse_table(l).unwrap();
        assert_eq!((t.tag, t.kind, t.ticks), ("15", 5, 8058));
        assert!(parse_table("service step: 15 kind 5 8058 ticks detail 0").is_none());
    }

    #[test]
    fn a_kind_whose_line_was_lost_comes_from_the_table_and_the_longer_one_wins() {
        let got = longest(
            &lines(&[
                "service step: 15 kind 1 100 ticks detail 0",
                "service table: 15 kind 5 8058 ticks detail 0 preempts 0",
                "service table: 14 kind 5 9999 ticks detail 0 preempts 0",
                "service table: 15 kind 1 2192 ticks detail 0 preempts 0",
                "service table: 15 kind 6 5000 ticks detail 3 preempts 2",
                "service step: 15 kind 6 5100 ticks detail 4",
            ]),
            "15",
        );
        assert_eq!(got, [(1, 2192, 0), (5, 8058, 0), (6, 5100, 4)]);
        // A raw time above the bound is warned of when only the table has it.
        let warned = raw_warnings(
            &lines(&["service table: 15 kind 5 8058 ticks detail 0 preempts 1"]),
            "15",
            8000,
        );
        assert_eq!(warned.len(), 1);
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
        assert_eq!(new.least(), 16_000 - 3 * PREEMPT_CHARGE_MIN);
        assert!(parse("service step: 14 kind 33 16000 ticks detail 64 preempts").is_none());
        assert!(parse("service wait: 14 kind 33 16000 ticks of 5").is_none());
        assert!(parse("service step: 14 kind x 16000 ticks detail 64").is_none());
    }

    #[test]
    fn a_step_is_judged_less_the_charge_of_its_preemptions() {
        let bound = 18_369;
        // 19 000 raw with 2 preemptions is 16 400 of work at the measured charge: it passes the
        // judgement, and the raw time is named by a warning.
        let rows = lines(&["service step: 14 kind 33 19000 ticks detail 64 preempts 2"]);
        assert_eq!(longest(&rows, "14"), vec![(33, 16_400, 64)]);
        assert!(longest(&rows, "14")[0].1 <= bound);
        let warnings = raw_warnings(&rows, "14", bound);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("19000") && warnings[0].contains("2 preemptions"));
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

    /// The verdict of a step by the two checks: B (20 410) by the least charge, 0.9 B (18 369) by
    /// the measured one.
    fn verdict(n: u64, p: u64) -> (bool, bool) {
        let rows = vec![format!(
            "service step: 14 kind 33 {n} ticks detail 0 preempts {p}"
        )];
        let b = over_bound(&rows, "14", 20_410, Kinds::All).is_none();
        let target = longest(&rows, "14")[0].1 <= 18_369;
        (b, target)
    }

    #[test]
    fn a_step_passes_b_by_the_least_charge_and_the_target_by_the_measured_one() {
        // The band of 18 807 with three preemptions passes both.
        assert_eq!(verdict(18_807, 3), (true, true));
        // No preemption: 19 000 fails 0.9 B.
        assert_eq!(verdict(19_000, 0), (true, false));
        // 21 000 with one preemption is 20 513 of work at least: fails B.
        assert_eq!(verdict(21_000, 1), (false, false));
        // 20 800 with one preemption passes B (20 313) and fails 0.9 B (19 500).
        assert_eq!(verdict(20_800, 1), (true, false));
    }

    #[test]
    fn the_line_of_the_verdict_has_the_raw_figures_and_both_judged_ones() {
        let rows = lines(&["service step: 14 kind 33 21000 ticks detail 0 preempts 1"]);
        let said = over_bound(&rows, "14", 20_410, Kinds::All).unwrap();
        assert!(
            said.contains("kind 33") && said.contains("raw 21000") && said.contains("preempts 1")
        );
        assert!(said.contains("= 19700 against 0.9 B 18369"), "{said}");
        assert!(said.contains("= 20513 against B 20410"), "{said}");
        // Another service's lines are not read.
        assert!(over_bound(&rows, "4", 20_410, Kinds::All).is_none());
        // The probes call it for the kinds they judge: an exempt kind is not checked.
        assert!(within_b(&rows, "14", Kinds::All).is_err());
        assert!(within_b(&rows, "14", Kinds::Only(&[33])).is_err());
        assert!(within_b(&rows, "14", Kinds::Only(&[1, 2])).is_ok());
        assert!(within_b(&rows, "14", Kinds::Except(&[33])).is_ok());
        assert!(within_b(&rows, "14", Kinds::Except(&[1])).is_err());
    }

    #[test]
    fn the_lines_of_the_pairs_of_a_kind_give_the_greatest_judged_one() {
        // The services tell the pairs (kind, preemptions) no other pair beats in the table at the
        // end of a run (`service table:`), and the line of a new longest as the run goes on: the
        // three steps give three lines of the table, and the judged maximum is the second,
        // 16 700 (the raw maximum alone gave 14 907).
        let rows = lines(&[
            "service step: 17 kind 65 18807 ticks detail 0 preempts 3",
            "service table: 17 kind 65 18000 ticks detail 1 preempts 1",
            "service table: 17 kind 65 16400 ticks detail 2 preempts 0",
        ]);
        assert_eq!(longest(&rows, "17"), vec![(65, 16_700, 1)]);
        assert!(longest(&rows[..1], "17")[0].1 == 14_907);
        // The pair of 8 and more is judged with 8 preemptions, whatever the count of the line.
        let many = lines(&["service step: 17 kind 65 20000 ticks detail 0 preempts 12"]);
        assert_eq!(longest(&many, "17"), vec![(65, 20_000 - 8 * 1_300, 0)]);
        assert_eq!(parse(&many[0]).unwrap().least(), 20_000 - 8 * 487);
    }

    #[test]
    fn the_work_a_preemption_never_touched_is_the_clean_longest() {
        let rows = lines(&[
            "service step: 17 kind 65 17000 ticks detail 0 preempts 2",
            "service step: 17 kind 65 15000 ticks detail 0",
            "service table: 17 kind 65 15500 ticks detail 0 preempts 0",
            "service step: 16 kind 65 99999 ticks detail 0",
        ]);
        assert_eq!(clean_longest(&rows, "17", 65), Some(15_500));
        assert_eq!(clean_longest(&rows, "17", 64), None);
        assert_eq!(clean_longest(&rows[..1], "17", 65), None);
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
