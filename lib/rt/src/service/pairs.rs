// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The longest raw time of the steps of a loop for each pair (kind, preemptions P): P from 0 to 7
//! each its own pair, and one pair for P of 8 and more (feature `step-stats`).
//!
//! Within one pair the greatest raw time is also the greatest time less the charge of the
//! preemptions, at any charge, so a reader that has the pairs knows the exact greatest
//! `N - P * c` of a kind without the service knowing c. The line of a kind alone, which grows
//! with the raw time only, hid a step that was shorter raw and longer once the charge of its
//! preemptions was taken off. The pairs go out in the table at the end of a run
//! (`service table:`), and only those no other pair beats (`next`): the console is slow, and a
//! pair that has a pair of fewer preemptions and at least as much raw time can never be the
//! greatest at any charge.

use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

/// The pairs of a kind: P of 0 to 7, and the pair of 8 and more.
pub const PAIRS: usize = 9;

/// The pair a step with `preempts` preemptions is in.
pub fn pair_of(preempts: u64) -> usize {
    preempts.min(PAIRS as u64 - 1) as usize
}

/// The longest step of each pair of each of `KINDS` kinds: its raw time, its detail and, for the
/// last pair, its count of preemptions (the other pairs have theirs in the pair's number).
/// 9 x 8 bytes of time and 9 x 8 of detail for a kind, and 8 for the count: 152 bytes a kind, in
/// the `.bss` of the images that turn the feature on and nowhere else.
pub struct Pairs<const KINDS: usize> {
    longest: [[AtomicU64; PAIRS]; KINDS],
    detail: [[AtomicU64; PAIRS]; KINDS],
    top_preempts: [AtomicU64; KINDS],
    /// The pairs of each kind that grew since they were last told, a bit for each (the heartbeat
    /// tells these between two tables).
    changed: [AtomicU16; KINDS],
}

/// The least time between two tellings of the changed pairs at a heartbeat, in nanoseconds.
pub const FLUSH_GAP_NS: u64 = 250_000_000;

/// Whether the changed pairs are due: `gap` has passed since the last telling.
pub fn due(now: u64, last: u64, gap: u64) -> bool {
    now.saturating_sub(last) >= gap
}

/// A pair's longest step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Longest {
    pub ticks: u64,
    pub detail: u64,
    pub preempts: u64,
}

impl<const KINDS: usize> Pairs<KINDS> {
    pub const fn new() -> Pairs<KINDS> {
        Pairs {
            longest: [const { [const { AtomicU64::new(0) }; PAIRS] }; KINDS],
            detail: [const { [const { AtomicU64::new(0) }; PAIRS] }; KINDS],
            top_preempts: [const { AtomicU64::new(0) }; KINDS],
            changed: [const { AtomicU16::new(0) }; KINDS],
        }
    }

    /// Takes a step: true when its raw time is the greatest of its pair so far.
    pub fn record(&self, kind: usize, ticks: u64, detail: u64, preempts: u64) -> bool {
        let pair = pair_of(preempts);
        if ticks <= self.longest[kind][pair].fetch_max(ticks, Ordering::Relaxed) {
            return false;
        }
        self.detail[kind][pair].store(detail, Ordering::Relaxed);
        if pair == PAIRS - 1 {
            self.top_preempts[kind].store(preempts, Ordering::Relaxed);
        }
        self.changed[kind].fetch_or(1 << pair, Ordering::Relaxed);
        true
    }

    /// The longest step of `pair` of `kind`, None while the pair is empty.
    pub fn get(&self, kind: usize, pair: usize) -> Option<Longest> {
        let ticks = self.longest.get(kind)?.get(pair)?.load(Ordering::Relaxed);
        if ticks == 0 {
            return None;
        }
        let preempts = if pair == PAIRS - 1 {
            self.top_preempts[kind].load(Ordering::Relaxed)
        } else {
            pair as u64
        };
        Some(Longest {
            ticks,
            detail: self.detail[kind][pair].load(Ordering::Relaxed),
            preempts,
        })
    }

    /// Whether a pair of fewer preemptions has at least this pair's raw time: then
    /// `N - P * c` of this pair is never the greatest of its kind, at any charge c.
    fn dominated(&self, kind: usize, pair: usize, ticks: u64) -> bool {
        (0..pair).any(|q| self.longest[kind][q].load(Ordering::Relaxed) >= ticks)
    }

    /// The next non-empty pair that no other pair beats, at or after the place `from` of the walk
    /// over all pairs (kind by kind, P up by P), with the place after it.
    pub fn next(&self, from: usize) -> Option<(usize, Longest, usize)> {
        (from..KINDS * PAIRS).find_map(|at| {
            let (kind, pair) = (at / PAIRS, at % PAIRS);
            self.get(kind, pair)
                .filter(|l| !self.dominated(kind, pair, l.ticks))
                .map(|l| (kind, l, at + 1))
        })
    }

    /// The next pair that grew since it was last told and that no other pair beats, at or after
    /// the place `from`, with the place after it. The pairs it passes, told or beaten, count as
    /// told: a walk from 0 to the end tells each changed pair once.
    pub fn next_changed(&self, from: usize) -> Option<(usize, Longest, usize)> {
        (from..KINDS * PAIRS).find_map(|at| {
            let (kind, pair) = (at / PAIRS, at % PAIRS);
            let bit = 1u16 << pair;
            if self.changed[kind].fetch_and(!bit, Ordering::Relaxed) & bit == 0 {
                return None;
            }
            self.get(kind, pair)
                .filter(|l| !self.dominated(kind, pair, l.ticks))
                .map(|l| (kind, l, at + 1))
        })
    }

    /// Marks every pair as told (a whole table is going out).
    pub fn clear_changed(&self) {
        for kind in &self.changed {
            kind.store(0, Ordering::Relaxed);
        }
    }

    /// The greatest raw time of a kind over its pairs, with the detail of that step.
    pub fn maximum(&self, kind: usize) -> Option<(u64, u64)> {
        let mut best: Option<Longest> = None;
        for pair in 0..PAIRS {
            if let Some(l) = self.get(kind, pair)
                && best.is_none_or(|b| l.ticks > b.ticks)
            {
                best = Some(l);
            }
        }
        match best {
            Some(l) => Some((l.ticks, l.detail)),
            None if kind < KINDS => Some((0, 0)),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a kind prints: the lines of the pairs that grew, in the order the steps came (at
    /// most eight of them in these tests).
    fn told(steps: &[(u64, u64)]) -> Told {
        let pairs = Pairs::<3>::new();
        let mut out = Told([(0, 0); 8], 0);
        for &(ticks, p) in steps {
            if pairs.record(1, ticks, 0, p) {
                out.0[out.1] = (ticks, p);
                out.1 += 1;
            }
        }
        out
    }

    struct Told([(u64, u64); 8], usize);

    impl Told {
        fn lines(&self) -> &[(u64, u64)] {
            &self.0[..self.1]
        }
    }

    #[test]
    fn a_step_shorter_raw_and_longer_after_the_charge_is_told() {
        // One maximum per kind printed the first only; a maximum per pair prints all three.
        let steps = [(18_807, 3), (18_000, 1), (16_400, 0)];
        assert_eq!(told(&steps).lines(), steps);
        // Judged at a charge of 1 300 the second is 16 700, the greatest of the three.
        let judged = |&(n, p): &(u64, u64)| n - p * 1_300;
        assert_eq!(told(&steps).lines().iter().map(judged).max(), Some(16_700));
    }

    #[test]
    fn the_table_of_the_three_steps_keeps_all_three_and_drops_a_beaten_pair() {
        let pairs = Pairs::<2>::new();
        for (ticks, p) in [(18_807, 3), (18_000, 1), (16_400, 0), (15_000, 2)] {
            pairs.record(1, ticks, 0, p);
        }
        let mut at = 0;
        let mut seen = [(0, 0); 4];
        let mut count = 0;
        while let Some((_, l, next)) = pairs.next(at) {
            seen[count] = (l.ticks, l.preempts);
            count += 1;
            at = next;
        }
        // (15 000, P 2) has (16 400, P 0) above it with fewer preemptions: it is left out.
        assert_eq!(seen[..count], [(16_400, 0), (18_000, 1), (18_807, 3)]);
    }

    #[test]
    fn a_pair_tells_again_only_when_its_own_maximum_grows() {
        let steps = [
            (100, 0),
            (90, 0),
            (100, 0),
            (101, 0),
            (50, 1),
            (60, 1),
            (55, 1),
        ];
        assert_eq!(told(&steps).lines(), [(100, 0), (101, 0), (50, 1), (60, 1)]);
    }

    #[test]
    fn eight_and_more_share_a_pair_and_keep_their_count() {
        let pairs = Pairs::<2>::new();
        assert!(pairs.record(0, 500, 7, 8));
        assert!(!pairs.record(0, 400, 7, 12));
        assert!(pairs.record(0, 600, 9, 12));
        let top = pairs.get(0, PAIRS - 1).unwrap();
        assert_eq!(
            top,
            Longest {
                ticks: 600,
                detail: 9,
                preempts: 12
            }
        );
        assert_eq!(pair_of(7), 7);
        assert_eq!(pair_of(8), 8);
        assert_eq!(pair_of(70_000), 8);
        assert!(pairs.get(0, 3).is_none());
    }

    #[test]
    fn the_table_walks_the_pairs_no_other_pair_beats_in_the_order_of_kind_and_count() {
        let pairs = Pairs::<4>::new();
        pairs.record(2, 300, 0, 1);
        pairs.record(1, 200, 5, 0);
        pairs.record(2, 350, 0, 0);
        pairs.record(2, 900, 0, 20);
        // (2, P 1, 300) has the pair of no preemption with 350: never the greatest at any charge.
        let mut at = 0;
        let mut seen = [(0, 0, 0); 8];
        let mut count = 0;
        while let Some((kind, l, next)) = pairs.next(at) {
            seen[count] = (kind, l.ticks, l.preempts);
            count += 1;
            at = next;
        }
        assert_eq!(seen[..count], [(1, 200, 0), (2, 350, 0), (2, 900, 20)]);
    }

    /// What a heartbeat tells: the changed pairs, each once.
    fn flushed<const K: usize>(pairs: &Pairs<K>) -> ([(usize, u64, u64); 8], usize) {
        let mut out = [(0, 0, 0); 8];
        let (mut at, mut count) = (0, 0);
        while let Some((kind, l, next)) = pairs.next_changed(at) {
            out[count] = (kind, l.ticks, l.preempts);
            count += 1;
            at = next;
        }
        (out, count)
    }

    #[test]
    fn a_heartbeat_tells_the_changed_pairs_once_and_nothing_when_none_changed() {
        let pairs = Pairs::<3>::new();
        pairs.record(1, 18_807, 0, 3);
        pairs.record(1, 16_400, 0, 0);
        let (lines, count) = flushed(&pairs);
        assert_eq!(lines[..count], [(1, 16_400, 0), (1, 18_807, 3)]);
        // The next heartbeat has nothing to tell.
        assert_eq!(flushed(&pairs).1, 0);
        // A pair that grows is told again, alone.
        pairs.record(1, 17_000, 0, 0);
        let (lines, count) = flushed(&pairs);
        assert_eq!(lines[..count], [(1, 17_000, 0)]);
        // A pair beaten by one of fewer preemptions counts as told and is not printed.
        pairs.record(1, 9_000, 0, 2);
        assert_eq!(flushed(&pairs).1, 0);
        // A whole table marks everything told.
        pairs.record(0, 500, 0, 0);
        pairs.clear_changed();
        assert_eq!(flushed(&pairs).1, 0);
    }

    #[test]
    fn the_changed_pairs_are_due_every_quarter_of_a_second_at_most() {
        assert!(!due(100_000_000, 0, FLUSH_GAP_NS));
        assert!(due(250_000_000, 0, FLUSH_GAP_NS));
        assert!(!due(400_000_000, 300_000_000, FLUSH_GAP_NS));
        assert!(due(550_000_000, 300_000_000, FLUSH_GAP_NS));
    }

    #[test]
    fn the_maximum_of_a_kind_is_the_greatest_raw_time_of_its_pairs() {
        let pairs = Pairs::<2>::new();
        assert_eq!(pairs.maximum(0), Some((0, 0)));
        assert_eq!(pairs.maximum(5), None);
        pairs.record(0, 300, 4, 2);
        pairs.record(0, 200, 8, 0);
        assert_eq!(pairs.maximum(0), Some((300, 4)));
    }
}
