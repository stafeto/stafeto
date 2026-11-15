// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The overruns of the time budgets in init's journal (spec 8, stage 5).
//!
//! Init makes each budget of its table with a place for the notifications of
//! its overruns (`budget_create` x5): a copy of init's channel with NOTIFY
//! whose label names the record and the budget (`label`). The kernel posts
//! one notification for each overrun and merges the overruns that come
//! between two firings of the budget's event (at most `abi::SS_REPL_MAX` of
//! them a period), so the count of a notification says how many overruns it
//! stands for. `Overruns` adds the counts up for each budget and says when a
//! line of the journal is due: the first at once, then at most one line a
//! budget in each `WINDOW_NS`, with the overruns since the last line and the
//! total.
//!
//! The work for a flood of overruns is bounded: a notification costs one
//! lookup in a table of `SLOTS` places and two additions, whatever its count
//! is (init never loops over the overruns), the kernel posts at most
//! `abi::SS_REPL_MAX` notifications for each budget in each of its periods,
//! and a budget writes one line in `WINDOW_NS`. Overruns that come between
//! two lines are in the count of the next line; a budget that overruns
//! and then never again is counted but writes no line after its last.

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
/// wire is the normal case there, and the budget keeps the work in order.
pub fn reports(name: &str) -> bool {
    name != crate::table::NET_SERVICE
}

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
    unwritten: u64,
    /// When the last line was due, in nanoseconds on init's clock.
    last: Option<u64>,
}

/// The counts of the overruns of every budget of the table.
pub struct Overruns {
    slots: [Slot; SLOTS],
}

impl Overruns {
    pub const fn new() -> Overruns {
        Overruns {
            slots: [Slot {
                total: 0,
                unwritten: 0,
                last: None,
            }; SLOTS],
        }
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
        let due = slot
            .last
            .is_none_or(|last| now.saturating_sub(last) >= WINDOW_NS);
        // The break: a line for every notification.
        if !due && cfg!(not(feature = "break-overrun-log-each")) {
            return None;
        }
        slot.last = Some(now);
        let since = core::mem::take(&mut slot.unwritten);
        Some(Line {
            place,
            index,
            since,
            total: slot.total,
        })
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
    fn a_label_that_is_not_a_budgets_counts_nothing() {
        let mut o = Overruns::new();
        assert_eq!(o.note(7, 1, 0), None);
        assert_eq!(o.note(label(MAX_RECORDS, 0), 1, 0), None);
        assert_eq!(o.total(0, 0), 0);
    }

    #[test]
    fn the_network_service_does_not_report() {
        assert!(!reports(crate::table::NET_SERVICE));
        assert!(reports("ramfs"));
    }
}
