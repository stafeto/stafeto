// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The restart of a service that failed (spec 13.4): the pause before it,
//! which doubles with each failure in a row, and the mark of a service
//! that fails too often. A failure is the end of the current instance, by
//! an exit, a fault or a kill, or the watchdog's word that it went silent.

/// The pause before a restart after the first failure in a row.
pub const PAUSE_FIRST_NS: u64 = 100_000_000;
/// The longest pause.
pub const PAUSE_MAX_NS: u64 = 5_000_000_000;
/// The failures that fall within WINDOW_NS mark a service broken when
/// there are BREAK_AFTER of them; an instance that lived WINDOW_NS or
/// longer starts the count in a row again.
pub const WINDOW_NS: u64 = 60_000_000_000;
pub const BREAK_AFTER: usize = 5;

/// What init does after a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Start a new instance after this pause.
    Restart { pause_ns: u64 },
    /// BREAK_AFTER failures within WINDOW_NS: never start it again.
    Broken,
}

/// The pause before a restart after `k` failures in a row, k from 1:
/// PAUSE_FIRST_NS · 2^(k-1), at most PAUSE_MAX_NS.
pub const fn pause(k: u32) -> u64 {
    let doubled = match 1u64.checked_shl(k.saturating_sub(1)) {
        Some(factor) => PAUSE_FIRST_NS.saturating_mul(factor),
        None => u64::MAX,
    };
    if doubled < PAUSE_MAX_NS {
        doubled
    } else {
        PAUSE_MAX_NS
    }
}

/// The failures of one record: the times of the last BREAK_AFTER, and how
/// many came in a row.
#[derive(Debug)]
pub struct Failures {
    times: [Option<u64>; BREAK_AFTER],
    next: usize,
    in_a_row: u32,
    /// The failures in a row that were exits with the code the record names in `broken_after`.
    same_code: u32,
}

impl Failures {
    pub const fn new() -> Failures {
        Failures {
            times: [None; BREAK_AFTER],
            next: 0,
            in_a_row: 0,
            same_code: 0,
        }
    }

    /// A failure at `now` of an instance that lived `lived` ns, both on
    /// the one scale of the system: Broken when it is the BREAK_AFTER-th
    /// within WINDOW_NS, otherwise a restart after `pause(k)`, where k
    /// counts the failures in a row and an instance that lived WINDOW_NS
    /// or longer starts k at 1 again.
    pub fn failed(&mut self, now: u64, lived: u64) -> Verdict {
        self.failed_with(now, lived, None, None)
    }

    /// `failed`, for a record that names an exit code in `broken_after` (`code`, `times`): the
    /// failure ended with exit code `ended_with` (None for a fault, a kill, the watchdog's word or
    /// a start that did not load). `times` failures in a row that all ended with `code` make the
    /// record broken at once; a failure that ended in another way starts the count again, so a stuck
    /// exit followed by an ordinary one is no streak. The record's failures also count toward
    /// BREAK_AFTER in WINDOW_NS as for any record.
    pub fn failed_with(
        &mut self,
        now: u64,
        lived: u64,
        ended_with: Option<u64>,
        broken_after: Option<(u64, u32)>,
    ) -> Verdict {
        let streak = match (broken_after, ended_with) {
            (Some((code, _)), Some(got)) if got == code => self.same_code.saturating_add(1),
            _ => 0,
        };
        self.same_code = streak;
        if let Some((_, times)) = broken_after
            && streak >= times
        {
            self.in_a_row = self.in_a_row.saturating_add(1);
            self.times[self.next] = Some(now);
            self.next = (self.next + 1) % BREAK_AFTER;
            return Verdict::Broken;
        }
        if lived >= WINDOW_NS {
            self.in_a_row = 0;
        }
        self.in_a_row = self.in_a_row.saturating_add(1);
        self.times[self.next] = Some(now);
        self.next = (self.next + 1) % BREAK_AFTER;
        if usize::from(self.recent(now)) >= BREAK_AFTER {
            Verdict::Broken
        } else {
            Verdict::Restart {
                pause_ns: pause(self.in_a_row),
            }
        }
    }

    /// The failures in a row that ended with the exit code of the record's `broken_after` rule.
    pub fn same_code(&self) -> u32 {
        self.same_code
    }

    /// The failures within WINDOW_NS up to `now` (LIST).
    pub fn recent(&self, now: u64) -> u8 {
        let within = |t: &&u64| now.saturating_sub(**t) < WINDOW_NS;
        self.times.iter().flatten().filter(within).count() as u8
    }
}

impl Default for Failures {
    fn default() -> Failures {
        Failures::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;
    const S: u64 = 1_000 * MS;

    /// The pauses of `failures`, each at its time with its life.
    fn pauses(failures: &mut Failures, times: &[(u64, u64)]) -> Vec<Verdict> {
        times
            .iter()
            .map(|&(now, lived)| failures.failed(now, lived))
            .collect()
    }

    #[test]
    fn pause_doubles_from_100_ms_to_5_s() {
        let expected = [100, 200, 400, 800, 1600, 3200, 5000, 5000].map(|ms| ms * MS);
        assert_eq!((1..=8).map(pause).collect::<Vec<_>>(), expected);
        assert_eq!(pause(64), PAUSE_MAX_NS);
        assert_eq!(pause(u32::MAX), PAUSE_MAX_NS);
        // A failure every 20 s after a life of 19 s: never five within
        // 60 s, so the pause goes all the way up.
        let mut f = Failures::new();
        let times: Vec<(u64, u64)> = (0..8).map(|i| (i * 20 * S, 19 * S)).collect();
        let restarts = expected.map(|pause_ns| Verdict::Restart { pause_ns });
        assert_eq!(pauses(&mut f, &times), restarts);
    }

    #[test]
    fn five_failures_in_60_s_break_the_service() {
        let mut f = Failures::new();
        let times: Vec<(u64, u64)> = (0..5).map(|i| (i * S, MS)).collect();
        let verdicts = pauses(&mut f, &times);
        let restarts = [100, 200, 400, 800].map(|ms| Verdict::Restart { pause_ns: ms * MS });
        assert_eq!(verdicts[..4], restarts);
        assert_eq!(verdicts[4], Verdict::Broken);
        assert_eq!(f.recent(4 * S), 5);
        // Within 60 s of the first, to the last nanosecond.
        let mut f = Failures::new();
        let mut times: Vec<(u64, u64)> = (0..4).map(|i| (i * S, MS)).collect();
        times.push((WINDOW_NS - 1, 50 * S));
        assert_eq!(pauses(&mut f, &times)[4], Verdict::Broken);
    }

    #[test]
    fn failures_older_than_60_s_do_not_count() {
        let mut f = Failures::new();
        let mut times: Vec<(u64, u64)> = (0..4).map(|i| (i * S, MS)).collect();
        // The fifth after a life of 57 s, 60.5 s after the first.
        let fifth = WINDOW_NS + 500 * MS;
        times.push((fifth, 57 * S));
        let verdicts = pauses(&mut f, &times);
        assert_eq!(verdicts[4], Verdict::Restart { pause_ns: pause(5) });
        assert_eq!(f.recent(fifth), 4);
        assert_eq!(f.recent(200 * S), 0);
        // A failure exactly 60 s old is out of the window.
        let mut f = Failures::new();
        pauses(&mut f, &times[..4]);
        assert_eq!(f.recent(WINDOW_NS - 1), 4);
        assert_eq!(f.recent(WINDOW_NS), 3);
    }

    const STUCK: u64 = 6;

    #[test]
    fn two_stuck_exits_in_a_row_break_a_record_that_names_them() {
        let rule = Some((STUCK, 2));
        let mut f = Failures::new();
        assert_eq!(
            f.failed_with(0, 25 * S, Some(STUCK), rule),
            Verdict::Restart { pause_ns: 100 * MS }
        );
        assert_eq!(
            f.failed_with(30 * S, 25 * S, Some(STUCK), rule),
            Verdict::Broken
        );
    }

    #[test]
    fn a_stuck_exit_then_an_ordinary_one_is_no_streak() {
        let rule = Some((STUCK, 2));
        let mut f = Failures::new();
        let verdicts = [
            f.failed_with(0, 25 * S, Some(STUCK), rule),
            f.failed_with(30 * S, 25 * S, Some(1), rule),
            f.failed_with(60 * S, 25 * S, Some(STUCK), rule),
            // A fault, a kill and the watchdog's word end the streak as well.
            f.failed_with(90 * S, 25 * S, None, rule),
            f.failed_with(120 * S, 25 * S, Some(STUCK), rule),
        ];
        assert!(
            verdicts
                .iter()
                .all(|v| matches!(v, Verdict::Restart { .. })),
            "{verdicts:?}"
        );
        // The next stuck exit after a stuck one breaks it.
        assert_eq!(
            f.failed_with(150 * S, 25 * S, Some(STUCK), rule),
            Verdict::Broken
        );
    }

    #[test]
    fn a_record_without_the_rule_restarts_on_any_exit_code() {
        let mut f = Failures::new();
        for i in 0..4 {
            let v = f.failed_with(i * 30 * S, 25 * S, Some(STUCK), None);
            assert!(matches!(v, Verdict::Restart { .. }), "{v:?}");
        }
    }

    #[test]
    fn a_long_life_resets_the_pause() {
        let mut f = Failures::new();
        let times = [(0, MS), (S, MS), (2 * S, MS), (70 * S, WINDOW_NS)];
        let verdicts = pauses(&mut f, &times);
        assert_eq!(verdicts[2], Verdict::Restart { pause_ns: 400 * MS });
        assert_eq!(verdicts[3], Verdict::Restart { pause_ns: 100 * MS });
        // One nanosecond less is no long life.
        let mut f = Failures::new();
        let times = [(0, MS), (S, MS), (2 * S, MS), (70 * S, WINDOW_NS - 1)];
        assert_eq!(
            pauses(&mut f, &times)[3],
            Verdict::Restart { pause_ns: 800 * MS }
        );
    }
}
