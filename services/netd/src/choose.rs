// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The choice of the frames of one step and of the groups the pass of sending
//! visits from the parts of the step the probe measured (spec 6, 6;
//! reports/2026-11-04-net-p1a). A step of the stack costs
//!
//! `fixed + k * (frame_rx + frame_tx) + e * group`
//!
//! for k frames received and sent and e groups passed; no term has the number
//! of sockets in it. The step may take 0.85 of the bound of 0.9 of term B
//! (18 369 ticks under -icount): the 15 percent cover the worst parts meeting
//! in one step and the spread between builds.
//!
//! The batch k is the largest of 16, 8, 4 and 2 for which some e fits, and e
//! is then the largest of 4, 2 and 1 that fits with it. When k = 2 with e = 1
//! does not fit, the choice stops and nothing is adjusted.

/// The longest step the service may take, in ticks.
pub const BOUND: u64 = 18_369;
/// What the sum of the parts may come to: 0.85 of the bound.
pub const BUDGET: u64 = BOUND * 85 / 100;
/// The batches to try, the largest first, and the groups per step.
pub const BATCHES: [usize; 4] = [16, 8, 4, 2];
pub const GROUPS_PER_STEP: [usize; 3] = [4, 2, 1];
/// The most the longest step at 256 places may differ from that at 8 places.
pub const FLATNESS: u64 = 1_500;

/// The 90th percentiles of the parts of the step, in ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parts {
    pub fixed: u64,
    pub frame_rx: u64,
    pub frame_tx: u64,
    pub group: u64,
}

impl Parts {
    /// The estimate of a step of k frames and e groups.
    pub fn cost(&self, batch: usize, groups: usize) -> u64 {
        self.fixed + batch as u64 * (self.frame_rx + self.frame_tx) + groups as u64 * self.group
    }
}

/// Why the choice stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stop;

/// The batch and the groups per step for `parts`.
pub fn choose(parts: &Parts) -> Result<(usize, usize), Stop> {
    for batch in BATCHES {
        let fits = |groups: usize| parts.cost(batch, groups) <= BUDGET;
        if let Some(groups) = GROUPS_PER_STEP.into_iter().find(|&e| fits(e)) {
            return Ok((batch, groups));
        }
    }
    Err(Stop)
}

/// Whether the longest step at 256 places stays within FLATNESS of that at 8
/// (the same batch and groups per step).
pub fn flat(at_8: u64, at_256: u64) -> bool {
    at_256.saturating_sub(at_8) <= FLATNESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(fixed: u64, rx: u64, tx: u64, group: u64) -> Parts {
        Parts {
            fixed,
            frame_rx: rx,
            frame_tx: tx,
            group,
        }
    }

    #[test]
    fn the_largest_batch_that_fits_with_the_largest_groups_is_chosen() {
        assert_eq!(BUDGET, 15_613);
        // Cheap parts: 16 frames and 4 groups.
        assert_eq!(choose(&parts(1_000, 300, 300, 200)), Ok((16, 4)));
        // The estimate of the decision: 5 000, 1 800, 1 500, 1 300.
        let expected = parts(5_000, 1_800, 1_500, 1_300);
        assert_eq!(expected.cost(2, 2), 14_200);
        assert_eq!(choose(&expected), Ok((2, 2)));
        assert_eq!(expected.cost(4, 2), 20_800);
    }

    #[test]
    fn a_batch_that_fits_only_with_fewer_groups_takes_them() {
        // 8 frames of 600 and one group of 3 000 around 4 000.
        let p = parts(4_000, 300, 300, 3_000);
        assert_eq!(p.cost(8, 1), 11_800);
        assert_eq!(p.cost(8, 2), 14_800);
        assert_eq!(p.cost(8, 4), 20_800);
        assert_eq!(choose(&p), Ok((8, 2)));
    }

    #[test]
    fn the_largest_batch_wins_over_more_groups() {
        // 16 frames fit with one group only; 8 would fit with four.
        let p = parts(2_000, 400, 400, 3_500);
        assert_eq!(p.cost(16, 1), 18_300);
        assert_eq!(choose(&p), Ok((8, 2)));
        let q = parts(2_000, 300, 300, 3_000);
        assert_eq!(q.cost(16, 1), 14_600);
        assert_eq!(choose(&q), Ok((16, 1)));
    }

    #[test]
    fn nothing_that_fits_stops_the_choice() {
        assert_eq!(choose(&parts(12_000, 1_000, 1_000, 2_000)), Err(Stop));
        assert_eq!(choose(&parts(15_700, 1, 1, 1)), Err(Stop));
    }

    #[test]
    fn the_steps_are_flat_within_the_spread() {
        assert!(flat(14_000, 14_000));
        assert!(flat(14_000, 15_500));
        assert!(!flat(14_000, 15_501));
        assert!(flat(15_000, 14_000), "a smaller step at 256 is flat");
    }
}
