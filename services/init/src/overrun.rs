// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The overruns of the time budgets in init's journal (spec 8, stage 5).
//!
//! Init makes each budget of its table with a place for the notifications of
//! its overruns (`budget_create` x5): a copy of init's channel with NOTIFY
//! whose label names the record and the budget (`label`). The kernel posts
//! one notification for each firing of the budget's event that finds overruns
//! it has not told, and merges the posts that come between two receives (at
//! most `abi::SS_REPL_MAX` of them a period); the count of a notification is
//! the number of posts merged. A thread that blocks can regain capacity
//! before the firing and overrun twice in the one post, so the sum of the
//! counts is a lower bound of the kernel's own counter of overruns, and the
//! journal says "at least". `Overruns` adds the counts up for each budget and
//! says when a line is due: the first at once, then at most one line per
//! budget in each `WINDOW_NS`, with the notifications since the last line and
//! the total; `flush` gives the line of a budget that overran and then
//! stopped, once its window has passed. The totals run across the instances
//! of a record: a restart makes new budgets under the same labels.
//!
//! The lines of the journal go through the console driver, so each one costs
//! the driver's own budget a few overruns, and a line about that budget would
//! cause the next one, window after window, in an idle system. A window of the
//! console record's budgets (`set_console`) is therefore written only when its
//! overruns exceed `CONSOLE_SHARE_PERCENT` of the periods the window holds; a
//! smaller window closes without a line, and its overruns stay in the sum the
//! next written line tells (the totals count every overrun).
//!
//! The kernel counts an overrun for each exhausted piece of the budget. The
//! queue of a budget holds up to `abi::SS_REPL_MAX` pieces, and each block of
//! its thread splits the capacity, so a service that blocks often can exhaust
//! up to four pieces in one period: a count above the number of periods is
//! normal, and it does not measure the size of the excess. The share of the
//! periods in which the budget ran out is the figure that compares services.
//!
//! The work for a flood of overruns is bounded: a notification costs one
//! lookup in a table of `SLOTS` places and two additions, whatever its count
//! is (init never loops over the overruns), the kernel posts at most
//! `abi::SS_REPL_MAX` notifications for each budget in each of its periods,
//! and a budget writes one line in `WINDOW_NS`. A heartbeat of a record looks
//! at its budgets (`START_DATA_MAX` at most) once.

use crate::table::{MAX_RECORDS, START_DATA_MAX};

/// The least time between two lines of one budget, in nanoseconds.
pub const WINDOW_NS: u64 = 10_000_000_000;

/// The mark of the labels of the budgets' places. The labels init gives
/// otherwise count up from 1 (`labels::Labels`), so no other label has this bit
/// before 2^63 labels were given.
const MARK: u64 = 1 << 63;

/// The places of the counts: each budget of each record of the table.
pub const SLOTS: usize = MAX_RECORDS * START_DATA_MAX;

/// The label of the place of the budget `index` of the record at `place` of
/// the table.
pub const fn label(place: usize, index: usize) -> u64 {
    MARK | ((place as u64) << 8) | index as u64
}

/// The record's place and the budget's index of a label that `label` made;
/// None for any other.
pub fn decode(label: u64) -> Option<(usize, usize)> {
    if label & MARK == 0 || label & !(MARK | 0xFFFF) != 0 {
        return None;
    }
    let (place, index) = (((label >> 8) & 0xFF) as usize, (label & 0xFF) as usize);
    (place < MAX_RECORDS && index < START_DATA_MAX).then_some((place, index))
}

/// Whether the budgets of the record `name` report their overruns. The
/// network service's do not: a budget that runs out under the load of the
/// wire is the normal case there, and the budget keeps the work in order. The
/// image of the frame-time measures reports them as well: the probe reads from
/// the journal how loaded the service was.
pub fn reports(name: &str) -> bool {
    cfg!(feature = "table-frame") || name != crate::table::NET_SERVICE
}

/// The share of the periods of a window, in percent, that the overruns of a
/// console budget have to exceed for the window to be written. The share of
/// the periods in which a budget ran out is the figure that compares services
/// (see above), and a line's own echo is a few overruns. With a period of
/// 10 ms and a window of 10 s this is 50 overruns. Not measured on real
/// hardware.
pub const CONSOLE_SHARE_PERCENT: u64 = 5;

/// A line of the journal that is due: the budget `index` of the record at
/// `place`, the overruns since the last line and the total.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    pub place: usize,
    pub index: usize,
    pub since: u64,
    pub total: u64,
}

#[derive(Clone, Copy)]
struct Slot {
    total: u64,
    /// The overruns that no written line has told.
    unwritten: u64,
    /// The overruns of the window that is open.
    window: u64,
    /// When the last line was due, in nanoseconds on init's clock.
    last: Option<u64>,
}

/// The counts of the overruns of every budget of the table.
pub struct Overruns {
    slots: [Slot; SLOTS],
    /// The place of the console record and the overruns a window of each of
    /// its budgets has to exceed to be written.
    console: Option<(usize, [u64; START_DATA_MAX])>,
}

impl Overruns {
    pub const fn new() -> Overruns {
        Overruns {
            slots: [Slot {
                total: 0,
                unwritten: 0,
                window: 0,
                last: None,
            }; SLOTS],
            console: None,
        }
    }

    /// Names the record at `place` as the console driver, whose budgets have
    /// the periods `periods_ns`: the windows of them get the threshold of
    /// `CONSOLE_SHARE_PERCENT` of their periods.
    pub fn set_console(&mut self, place: usize, periods_ns: &[u64]) {
        let mut floor = [0; START_DATA_MAX];
        for (f, &t) in floor.iter_mut().zip(periods_ns) {
            *f = (WINDOW_NS / t.max(1)) * CONSOLE_SHARE_PERCENT / 100;
        }
        self.console = Some((place, floor));
    }

    /// A notification of the place `label` of count `count` at time `now`:
    /// adds it, and gives the line that is due, if one is. A label that is
    /// not a budget's, or names a place the table has no room for, counts
    /// nothing.
    pub fn note(&mut self, label: u64, count: u32, now: u64) -> Option<Line> {
        // The break: init takes no notice of the overruns.
        if cfg!(feature = "break-overrun-ignore") {
            return None;
        }
        let (place, index) = decode(label)?;
        let slot = &mut self.slots[place * START_DATA_MAX + index];
        // A notification stands for one overrun at least.
        let count = u64::from(count).max(1);
        slot.total = slot.total.saturating_add(count);
        slot.unwritten = slot.unwritten.saturating_add(count);
        slot.window = slot.window.saturating_add(count);
        let due = slot
            .last
            .is_none_or(|last| now.saturating_sub(last) >= WINDOW_NS);
        // The break: a line for every notification.
        if !due && cfg!(not(feature = "break-overrun-log-each")) {
            return None;
        }
        self.write(place, index, now)
    }

    /// The window of the budget `index` of the record at `place` is over: its
    /// line, or None for a window of a console budget below the threshold.
    fn write(&mut self, place: usize, index: usize, now: u64) -> Option<Line> {
        let floor = match self.console {
            Some((p, floor)) if p == place => floor[index],
            _ => 0,
        };
        let slot = &mut self.slots[place * START_DATA_MAX + index];
        let window = core::mem::take(&mut slot.window);
        slot.last = Some(now);
        // The break (a line for every notification) writes whatever the size.
        if window <= floor && cfg!(not(feature = "break-overrun-log-each")) {
            return None;
        }
        let since = core::mem::take(&mut slot.unwritten);
        Some(Line {
            place,
            index,
            since,
            total: slot.total,
        })
    }

    /// The line of the budget `index` of the record at `place` for the
    /// overruns that no line has told, once the window of its last line has
    /// passed: the tail of a budget that stopped overrunning. None when all
    /// are told, or the window is still open.
    pub fn flush(&mut self, place: usize, index: usize, now: u64) -> Option<Line> {
        let slot = self.slots.get_mut(place * START_DATA_MAX + index)?;
        let open = slot
            .last
            .is_some_and(|last| now.saturating_sub(last) < WINDOW_NS);
        if slot.window == 0 || open {
            return None;
        }
        self.write(place, index, now)
    }

    /// The overruns counted for the budget `index` of the record at `place`.
    pub fn total(&self, place: usize, index: usize) -> u64 {
        self.slots
            .get(place * START_DATA_MAX + index)
            .map_or(0, |s| s.total)
    }
}

impl Default for Overruns {
    fn default() -> Overruns {
        Overruns::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    #[test]
    fn labels_name_the_record_and_the_budget_and_nothing_else_decodes() {
        for (place, index) in [(0, 0), (3, 2), (MAX_RECORDS - 1, START_DATA_MAX - 1)] {
            assert_eq!(decode(label(place, index)), Some((place, index)));
        }
        assert_eq!(decode(1), None, "a label of init's count");
        assert_eq!(decode(0), None);
        assert_eq!(decode(label(MAX_RECORDS, 0)), None);
        assert_eq!(decode(label(0, START_DATA_MAX)), None);
        assert_eq!(decode(label(1, 1) | 1 << 20), None);
        let a = label(2, 5);
        let b = label(5, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn the_first_overrun_writes_a_line_at_once() {
        let mut o = Overruns::new();
        let line = o.note(label(1, 0), 1, 5 * S).unwrap();
        assert_eq!(
            line,
            Line {
                place: 1,
                index: 0,
                since: 1,
                total: 1
            }
        );
    }

    #[test]
    fn a_flood_writes_one_line_in_each_window_with_the_counts_that_came() {
        let mut o = Overruns::new();
        let id = label(0, 1);
        let mut lines = Vec::new();
        // 100 notifications a second of count 2 (merged) for 25 s.
        for k in 0..2500u64 {
            if let Some(l) = o.note(id, 2, k * S / 100) {
                lines.push((k * S / 100, l));
            }
        }
        let times: Vec<u64> = lines.iter().map(|(t, _)| *t).collect();
        assert_eq!(times, [0, 10 * S, 20 * S], "one line in each 10 s");
        assert_eq!(lines[0].1.since, 2);
        assert_eq!(lines[1].1.since, 2000, "1000 notifications of 2 in 10 s");
        assert_eq!(lines[2].1.since, 2000);
        assert_eq!(lines[2].1.total, 4002);
        assert_eq!(o.total(0, 1), 5000);
    }

    #[test]
    fn the_window_is_exact_and_each_budget_has_its_own() {
        let mut o = Overruns::new();
        let (a, b) = (label(0, 0), label(0, 1));
        assert!(o.note(a, 1, 0).is_some());
        assert!(
            o.note(b, 1, 3 * S).is_some(),
            "the other budget writes its own first line"
        );
        assert!(o.note(a, 1, 10 * S - 1).is_none());
        let l = o.note(a, 1, 10 * S).unwrap();
        assert_eq!((l.since, l.total), (2, 3));
        assert!(o.note(b, 1, 10 * S).is_none(), "b wrote at 3 s");
        let l = o.note(b, 3, 13 * S).unwrap();
        assert_eq!((l.since, l.total), (4, 5));
    }

    #[test]
    fn a_count_is_added_in_one_step_whatever_its_size() {
        let mut o = Overruns::new();
        let id = label(4, 3);
        o.note(id, 1, 0);
        assert!(o.note(id, u32::MAX, S).is_none());
        assert_eq!(o.total(4, 3), 1 + u64::from(u32::MAX));
        let l = o.note(id, 0, 11 * S).unwrap();
        assert_eq!(
            l.since,
            u64::from(u32::MAX) + 1,
            "a count of 0 stands for one"
        );
    }

    #[test]
    fn the_tail_of_a_budget_that_stopped_is_flushed_once_its_window_has_passed() {
        let mut o = Overruns::new();
        let id = label(2, 0);
        assert!(o.note(id, 1, 0).is_some());
        assert!(o.note(id, 3, 4 * S).is_none());
        assert_eq!(o.flush(2, 0, 9 * S), None, "the window is open");
        let l = o.flush(2, 0, 10 * S).unwrap();
        assert_eq!((l.since, l.total), (3, 4));
        assert_eq!(o.flush(2, 0, 30 * S), None, "told once");
        assert_eq!(o.flush(2, 1, 30 * S), None, "a budget with no overruns");
        assert_eq!(o.flush(MAX_RECORDS, 0, 30 * S), None);
    }

    #[test]
    fn totals_run_across_the_instances_of_a_record() {
        // A restart makes new budgets under the same labels.
        let mut o = Overruns::new();
        let id = label(1, 1);
        assert_eq!(o.note(id, 5, 0).unwrap().total, 5);
        let l = o.note(id, 2, 10 * S).unwrap();
        assert_eq!((l.since, l.total), (2, 7));
        let l = o.flush(1, 1, 30 * S);
        assert_eq!(l, None);
        o.note(id, 1, 31 * S);
        assert_eq!(
            o.flush(1, 1, 45 * S).map(|l| l.total),
            None,
            "written at 31 s"
        );
    }

    #[test]
    fn a_label_that_is_not_a_budgets_counts_nothing() {
        let mut o = Overruns::new();
        assert_eq!(o.note(7, 1, 0), None);
        assert_eq!(o.note(label(MAX_RECORDS, 0), 1, 0), None);
        assert_eq!(o.total(0, 0), 0);
    }

    #[test]
    fn the_network_service_does_not_report() {
        assert_eq!(
            reports(crate::table::NET_SERVICE),
            cfg!(feature = "table-frame")
        );
        assert!(reports("ramfs"));
    }

    const T10MS: u64 = 10_000_000;

    /// The console record at place 0 with one budget of period 10 ms: a window
    /// of 10 s holds 1000 periods, and 5 % of them are 50.
    fn console() -> (Overruns, u64) {
        let mut o = Overruns::new();
        o.set_console(0, &[T10MS]);
        (o, label(0, 0))
    }

    #[test]
    fn a_console_window_at_the_threshold_is_silent_and_one_over_it_is_written() {
        let (mut o, id) = console();
        assert_eq!(o.note(id, 50, 0), None, "50 of 1000 periods");
        let l = o.note(id, 51, 10 * S).expect("51 of 1000 periods");
        assert_eq!((l.since, l.total), (101, 101));
        // The threshold is the share of the budget's own period.
        let mut o = Overruns::new();
        o.set_console(0, &[T10MS * 5]);
        assert_eq!(o.note(id, 10, 0), None, "10 of 200 periods");
        assert!(o.note(id, 11, 10 * S).is_some());
    }

    #[test]
    fn the_silent_windows_are_in_the_sum_of_the_next_line() {
        let (mut o, id) = console();
        for w in 0..5 {
            assert_eq!(o.note(id, 40, w * 10 * S), None);
        }
        let l = o.note(id, 60, 50 * S).unwrap();
        assert_eq!((l.since, l.total), (260, 260));
        // After a written line the count starts again, the total goes on.
        assert_eq!(o.note(id, 1, 60 * S), None);
        let l = o.note(id, 70, 70 * S).unwrap();
        assert_eq!((l.since, l.total), (71, 331));
        assert_eq!(o.total(0, 0), 331);
    }

    #[test]
    fn the_tail_of_a_console_budget_below_the_threshold_is_not_flushed() {
        let (mut o, id) = console();
        assert!(o.note(id, 100, 0).is_some());
        assert_eq!(o.note(id, 3, 4 * S), None);
        assert_eq!(o.flush(0, 0, 20 * S), None, "3 of 1000 periods");
        let l = o.note(id, 100, 30 * S).unwrap();
        assert_eq!((l.since, l.total), (103, 203));
    }

    #[test]
    fn the_other_budgets_keep_the_rule_whatever_the_console_does() {
        let (mut o, _) = console();
        let other = label(1, 0);
        assert!(
            o.note(other, 1, 0).is_some(),
            "one overrun, written at once"
        );
        assert!(o.note(other, 1, 10 * S).is_some());
        // A second budget of the console record, with no period given, has
        // no threshold either way: a window of 1 is silent only when it is
        // at or under 0 periods' share, so it is written.
        assert!(o.note(label(0, 1), 1, 0).is_some());
    }
}
