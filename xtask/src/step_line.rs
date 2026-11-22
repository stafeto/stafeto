// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The line `service step: T kind K N ticks detail D preempts P wall W` of `rt::service` (`preempts P`
//! is left out when P is 0 and no wall is told; `wall W` is told when the clock's part of the
//! step, W, is longer than N) and the judgement of a step against the bound B.
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

/// The ticks one preemption adds to the time of the preempted thread, at the least. A preemption
/// decided inside the thread's own call (the call wakes a thread of a higher level, or the cleanup
/// queue is at or above its level, and `pick` takes the thread off the CPU) closes the stint at
/// the top of `exit_loop` and reopens it at the `now` of `thread::run`, so it costs the thread
/// about nothing: the bound is 0. The 95 ticks that the `preempt charge ticks` row of the kernel
/// test measures are the cost of an EL0 timer preemption alone (the registers' save and restore).
/// A lower bound cannot hide step work: a step that took N with P preemptions did at least
/// `N - P * c` ticks of its own for any true charge c at or above the bound, so judging by that
/// value never passes a step that a true charge would fail. It judges the bound B. The residual
/// of the bound 0 is at most P times the path from the top of `exit_loop` to the `now` of
/// `thread::run`, a fraction of `NULL_MAX`.
pub const PREEMPT_CHARGE_MIN: u64 = 0;

/// The cost of a preemption of the worst kind seen (a preemptor of another process), for the
/// target 0.9 B. The stint of a thread begins at its return to EL0, so the entries for interrupts,
/// the budget events and the SIMD switches are outside the time a step is measured by. In
/// `thread::run` the save and load of the FP state (thread.rs) and the switch of TTBR0 and the
/// setup of the upcall happen before `now` is read, and the budget event runs between the entry
/// and the reopening of the stint, so an EL0 preemption costs about 95 ticks under -icount
/// whatever the preemptor is: the registers' save and restore. The `preempt charge ticks` row of
/// the kernel test fell from 487 to 95 with that change, a drop of 392 ticks in every preemption,
/// and the worst step seen before it left 1 261 ticks in a step of the RAM file service on 19
/// November: 869 ticks now, with the margin of that figure (3 per cent, rounded up to the
/// hundred) 900. The 900 stays for now; a follow-up lowers it after a probe run. A c that is too
/// small can only eat the margin between 0.9 B and B, since `over_bound` holds B by the lower
/// bound.
pub const PREEMPT_CHARGE: u64 = 900;

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
    /// The step's whole time less its waits, when the line carries it (`wall W`): the figure
    /// the raw time would have had without the thread's own CPU time. None for a line without it.
    pub wall: Option<u64>,
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
///
/// The pairs reach xtask in the tables, at powers of two of the steps done and once at an ordered
/// stop, and a run that ends otherwise may hold a pair that beat its maximum after the last
/// table. That understatement is accepted: a hidden step is no longer than the raw maximum printed
/// for its kind, so it cannot pass the check against B (`over_bound`); against 0.9 B the figure
/// is understated by at most `P * PREEMPT_CHARGE` from the printed maximum, P being the
/// preemptions of the hidden step.
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
///
/// A kind is exempt from B only together with its exemption from 0.9 B in the same probe, and
/// with a stated reason (a start-up step, a run whose ticks are the timer's). A new kind of a
/// service falls under the check by default: `Kinds::All` and `Kinds::Except` take it in, and
/// `Kinds::Only` takes it in when its list is extended with the bound the probe puts on it.
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

/// The longest raw line of each kind of the service `tag`, with the wall time the line carries
/// when the thread's CPU time was the shorter figure (None: the two were equal): (kind, ticks,
/// wall, preempts), in the order the kinds came.
pub fn ran_and_wall(lines: &[String], tag: &str) -> Vec<(usize, u64, Option<u64>, u64)> {
    let mut out: Vec<(usize, u64, Option<u64>, u64)> = Vec::new();
    for step in lines
        .iter()
        .filter_map(|l| parse_any(l))
        .filter(|s| s.tag == tag)
    {
        let row = (step.kind, step.ticks, step.wall, step.preempts);
        match out.iter_mut().find(|(k, ..)| *k == step.kind) {
            Some(old) if old.1 > row.1 => {}
            Some(old) => *old = row,
            None => out.push(row),
        }
    }
    out
}

/// Tells `ran_and_wall` of the service `tag`: for each kind the ticks by the thread's CPU time
/// beside the wall ticks (the step's whole less its waits), a report line, no verdict.
pub fn say_ran_and_wall(lines: &[String], tag: &str) {
    for (kind, ticks, wall, preempts) in ran_and_wall(lines, tag) {
        match wall {
            Some(w) => println!(
                "step cpu and wall: service {tag} kind {kind}: ran {ticks} ticks, wall {w} ticks, preempts {preempts}"
            ),
            None => println!(
                "step cpu and wall: service {tag} kind {kind}: ran {ticks} ticks, wall the same, preempts {preempts}"
            ),
        }
    }
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
    let (tag, kind, ticks, detail, preempts, wall) = match words.as_slice() {
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
        ] if *w == word => (tag, kind, ticks, detail, "0", None),
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
        ] if *w == word => (tag, kind, ticks, detail, *preempts, None),
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
            "wall",
            wall,
        ] if *w == word => (tag, kind, ticks, detail, *preempts, Some(*wall)),
        _ => return None,
    };
    Some(StepLine {
        tag,
        kind: kind.parse().ok()?,
        ticks: ticks.parse().ok()?,
        detail: detail.parse().ok()?,
        preempts: preempts.parse().ok()?,
        wall: match wall {
            Some(w) => Some(w.parse().ok()?),
            None => None,
        },
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

/// The longest step of kind `kind` of the service `tag` among the lines (new longest or table)
/// between the first line that contains `from` and the first line after it that contains `to`,
/// whose detail `detail_ok` accepts: how a probe reads the steps of one of its cases, which it
/// brackets with two marker lines. None when a marker is missing or no such line came: the
/// console tells a step only when it passes the longest of its kind so far.
pub fn longest_between<'a>(
    lines: &'a [String],
    from: &str,
    to: &str,
    tag: &str,
    kind: usize,
    detail_ok: impl Fn(u64) -> bool,
) -> Option<StepLine<'a>> {
    let begin = lines.iter().position(|l| l.contains(from))?;
    let end = begin + lines[begin..].iter().position(|l| l.contains(to))?;
    lines[begin..end]
        .iter()
        .filter_map(|l| parse_any(l))
        .filter(|s| s.tag == tag && s.kind == kind && detail_ok(s.detail))
        .max_by_key(|s| s.ticks)
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
    fn the_steps_of_a_case_are_read_between_its_markers_by_detail() {
        let l = lines(&[
            "service step: 2 kind 50 9000 ticks detail 7",
            "case a: begin",
            "service step: 2 kind 50 12000 ticks detail 5",
            "service step: 2 kind 50 13000 ticks detail 7 preempts 1",
            "service table: 2 kind 50 14000 ticks detail 7 preempts 0",
            "service step: 2 kind 49 15000 ticks detail 7",
            "case a: end",
            "service step: 2 kind 50 19000 ticks detail 7",
        ]);
        let got = longest_between(&l, "case a: begin", "case a: end", "2", 50, |d| d == 7).unwrap();
        assert_eq!((got.ticks, got.preempts), (14000, 0));
        assert!(longest_between(&l, "case a: begin", "case a: end", "3", 50, |_| true).is_none());
        assert!(longest_between(&l, "case a: begin", "case b: end", "2", 50, |_| true).is_none());
        assert!(longest_between(&l, "case a: end", "case a: begin", "2", 50, |_| true).is_none());
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
    fn ran_and_wall_keep_the_longest_line_of_each_kind() {
        let got = ran_and_wall(
            &lines(&[
                "service step: 4 kind 14 9000 ticks detail 0",
                "service step: 4 kind 14 15000 ticks detail 0 preempts 0 wall 19800",
                "service step: 5 kind 14 99999 ticks detail 0",
                "service table: 4 kind 15 7000 ticks detail 0 preempts 1",
            ]),
            "4",
        );
        assert_eq!(got, [(14, 15_000, Some(19_800), 0), (15, 7_000, None, 1)]);
    }

    #[test]
    fn the_wall_field_is_optional() {
        let w =
            parse("service step: 4 kind 14 15000 ticks detail 0 preempts 0 wall 19800").unwrap();
        assert_eq!(
            (w.kind, w.ticks, w.preempts, w.wall),
            (14, 15_000, 0, Some(19_800))
        );
        assert_eq!(
            parse("service step: 4 kind 14 15000 ticks detail 0")
                .unwrap()
                .wall,
            None
        );
        assert_eq!(
            parse("service step: 4 kind 14 15000 ticks detail 0 preempts 2")
                .unwrap()
                .wall,
            None
        );
        assert!(parse("service step: 4 kind 14 15000 ticks detail 0 preempts 0 wall x").is_none());
        let t =
            parse_table("service table: 4 kind 14 15000 ticks detail 0 preempts 1 wall 9").unwrap();
        assert_eq!(t.wall, Some(9));
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
        // 19 000 raw with 2 preemptions is 17 200 of work at the measured charge: it passes the
        // judgement, and the raw time is named by a warning.
        let rows = lines(&["service step: 14 kind 33 19000 ticks detail 64 preempts 2"]);
        assert_eq!(longest(&rows, "14"), vec![(33, 17_200, 64)]);
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
        // 21 000 with one preemption is 21 000 of work at least (the least charge is 0): fails B.
        assert_eq!(verdict(21_000, 1), (false, false));
        // 20 400 with one preemption passes B (20 400 of work at least) and fails 0.9 B (19 500).
        assert_eq!(verdict(20_400, 1), (true, false));
    }

    #[test]
    fn the_line_of_the_verdict_has_the_raw_figures_and_both_judged_ones() {
        let rows = lines(&["service step: 14 kind 33 21000 ticks detail 0 preempts 1"]);
        let said = over_bound(&rows, "14", 20_410, Kinds::All).unwrap();
        assert!(
            said.contains("kind 33") && said.contains("raw 21000") && said.contains("preempts 1")
        );
        assert!(said.contains("= 20100 against 0.9 B 18369"), "{said}");
        assert!(said.contains("= 21000 against B 20410"), "{said}");
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
        // 17 100 (the raw maximum alone gave 16 107).
        let rows = lines(&[
            "service step: 17 kind 65 18807 ticks detail 0 preempts 3",
            "service table: 17 kind 65 18000 ticks detail 1 preempts 1",
            "service table: 17 kind 65 16400 ticks detail 2 preempts 0",
        ]);
        assert_eq!(longest(&rows, "17"), vec![(65, 17_100, 1)]);
        assert!(longest(&rows[..1], "17")[0].1 == 16_107);
        // The pair of 8 and more is judged with 8 preemptions, whatever the count of the line.
        let many = lines(&["service step: 17 kind 65 20000 ticks detail 0 preempts 12"]);
        assert_eq!(longest(&many, "17"), vec![(65, 20_000 - 8 * 900, 0)]);
        assert_eq!(
            parse(&many[0]).unwrap().least(),
            20_000 - 8 * PREEMPT_CHARGE_MIN
        );
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
