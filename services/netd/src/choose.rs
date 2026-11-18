// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The choice of the frames of the steps and of the groups the pass of sending
//! visits from the parts of the steps the probe measured (spec 6, 6;
//! reports/2026-11-04-net-p1a). The service has a step of receiving and a step
//! of sending. They cost
//!
//! receiving: `fixed_rx + k * frame_rx` for k frames (the answers of the
//! stack to them are in `frame_rx`);
//! sending: `fixed_tx + e * group + k * frame_tx` for e groups and k frames;
//!
//! where the price of a frame is the larger of the price of a frame of the
//! loopback and that of a frame of the wire (stage P4a-1: a frame of the wire
//! has its sums checked or made over up to 1 514 bytes);
//!
//! and no term has the number of sockets in it. A step may take 0.85 of the
//! bound of 0.9 of term B (18 369 ticks under -icount): the 15 percent cover
//! the worst parts meeting in one step and the spread between builds.
//!
//! The images that count steps (`ring::RX_SOFT`) take a frame of the wire after
//! the first only while the step has used no more than the soft share
//! (`ring::RX_SOFT_MEASURED`). A wire frame costs more than the share, so two of
//! them never make one step, and a step with a second frame costs at most the
//! share, the frame and the tail of the step (`ring::STEP_TAIL_TICKS`),
//! whatever the frames before it cost. The rule takes the batch of two when that
//! sum is within the margin (`ring::STEP_MARGIN`) and the estimate above does
//! not give more.
//!
//! The same holds for sending (`ring::TX_SOFT_MEASURED`): a second group is visited only while
//! the step is within the share, so the step costs at most the share, a group, a sent frame
//! and the tail. The rule takes two groups with a single frame when that sum is within the
//! margin, whatever the estimate of two groups gives.
//!
//! The gate: a step of receiving with one frame, and a step of sending with
//! one group and one frame, each within the budget. Past the gate, the batch of
//! receiving is the largest of 16, 8, 4, 2 and 1 that fits, then the groups
//! per step the largest of 4, 2 and 1, then the frames of sending the largest
//! of 16, 8, 4, 2 and 1 that fit with them. When the gate is not passed the
//! choice stops and nothing is adjusted.

/// The longest step the service may take, in ticks.
pub const BOUND: u64 = 18_369;
/// What the sum of the parts may come to: 0.85 of the bound.
pub const BUDGET: u64 = BOUND * 85 / 100;
/// The frames of a step of receiving the soft share lets through: the first
/// and one more.
pub const SOFT_FRAMES: usize = 2;
/// The groups of a step of sending the soft share lets through: the first and one more.
pub const SOFT_GROUPS: usize = 2;
/// The batches to try, the largest first, and the groups per step.
pub const BATCHES: [usize; 5] = [16, 8, 4, 2, 1];
pub const GROUPS_PER_STEP: [usize; 3] = [4, 2, 1];
/// The most the longest step at 256 places may differ from that at 8 places.
pub const FLATNESS: u64 = 1_500;

/// The 90th percentiles of the parts of the steps, in ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parts {
    pub fixed_rx: u64,
    pub fixed_tx: u64,
    pub frame_rx: u64,
    pub frame_tx: u64,
    pub frame_rx_wire: u64,
    pub frame_tx_wire: u64,
    pub group: u64,
}

impl Parts {
    /// The price of a received frame: the larger of the loopback's and the
    /// wire's.
    pub fn rx_price(&self) -> u64 {
        self.frame_rx.max(self.frame_rx_wire)
    }

    /// The price of a sent frame.
    pub fn tx_price(&self) -> u64 {
        self.frame_tx.max(self.frame_tx_wire)
    }

    /// The estimate of a step of receiving of k frames.
    pub fn receiving(&self, frames: usize) -> u64 {
        self.fixed_rx + frames as u64 * self.rx_price()
    }

    /// The longest step of receiving with a second frame under the soft share:
    /// the share, a frame of the price and the tail.
    pub fn receiving_soft(&self) -> u64 {
        crate::ring::RX_SOFT_MEASURED + self.rx_price() + crate::ring::STEP_TAIL_TICKS as u64
    }

    /// The longest step of sending with a second group under the soft share
    /// (`ring::TX_SOFT_MEASURED`): the share, a group, a frame of the price and the tail.
    pub fn sending_soft(&self) -> u64 {
        crate::ring::TX_SOFT_MEASURED
            + self.group
            + self.tx_price()
            + crate::ring::STEP_TAIL_TICKS as u64
    }

    /// The room the margin leaves for the share of sending after a group, a frame of the price
    /// and the tail: the largest `TX_SOFT_MEASURED` these parts allow.
    pub fn tx_soft_room(&self) -> u64 {
        (crate::ring::STEP_MARGIN as u64)
            .saturating_sub(self.group + self.tx_price() + crate::ring::STEP_TAIL_TICKS as u64)
    }

    /// The parts the code stands on: the constants of `netd::ring`, which the step rule reads
    /// as they are. The rule on them must give `STEP_RX`, `EGRESS_GROUPS` and `STEP_TX`.
    pub fn of_ring() -> Parts {
        use crate::ring::*;
        Parts {
            fixed_rx: STEP_TAIL_TICKS as u64,
            fixed_tx: TX_FIXED_TICKS as u64,
            frame_rx: LOOP_RX_FRAME_TICKS as u64,
            frame_tx: LOOP_TX_FRAME_TICKS as u64,
            frame_rx_wire: WIRE_FRAME_TICKS as u64,
            frame_tx_wire: WIRE_TX_FRAME_TICKS as u64,
            group: TX_GROUP_TICKS as u64,
        }
    }

    /// The estimate of a step of sending of e groups and k frames.
    pub fn sending(&self, groups: usize, frames: usize) -> u64 {
        self.fixed_tx + groups as u64 * self.group + frames as u64 * self.tx_price()
    }
}

/// What the choice made of the parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Choice {
    pub receive: usize,
    pub groups: usize,
    pub send: usize,
}

/// Why the choice stops: the gate is not passed (the step of receiving or the
/// step of sending of one frame is past the budget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stop {
    pub receiving: u64,
    pub sending: u64,
}

/// The gate and the choice for `parts`.
pub fn choose(parts: &Parts) -> Result<Choice, Stop> {
    let (receiving, sending) = (parts.receiving(1), parts.sending(1, 1));
    if receiving > BUDGET || sending > BUDGET {
        return Err(Stop { receiving, sending });
    }
    let by_estimate = BATCHES
        .into_iter()
        .find(|&k| parts.receiving(k) <= BUDGET)
        .expect("the gate passed with one frame");
    let receive = if parts.receiving_soft() <= crate::ring::STEP_MARGIN as u64 {
        by_estimate.max(SOFT_FRAMES)
    } else {
        by_estimate
    };
    let by_estimate = GROUPS_PER_STEP
        .into_iter()
        .find(|&e| parts.sending(e, 1) <= BUDGET)
        .expect("the gate passed with one group");
    let send = BATCHES
        .into_iter()
        .find(|&k| parts.sending(by_estimate, k) <= BUDGET)
        .expect("the gate passed with one frame");
    // The soft share lets a second group in with a single frame of sending, the one the sum
    // counts.
    let groups = if send == 1 && parts.sending_soft() <= crate::ring::STEP_MARGIN as u64 {
        by_estimate.max(SOFT_GROUPS)
    } else {
        by_estimate
    };
    Ok(Choice {
        receive,
        groups,
        send,
    })
}

/// The portions of a copy of the shared buffer to try, the largest first.
pub const PORTIONS: [usize; 3] = [16 * 1024, 8 * 1024, 4 * 1024];

/// The portion of a copy of the shared buffer (`ring::BUFFER_PORTION`): the
/// largest of PORTIONS whose steps of SEND and of RECV with a cell, measured
/// at that portion (`rows`: the portion, the step of SEND, the step of RECV,
/// in ticks), stay within the budget. The longest step of a kind stands for
/// its 90th percentile: it is never below it. None when no portion fits or
/// none was measured.
pub fn portion(rows: &[(usize, u64, u64)]) -> Option<usize> {
    PORTIONS.into_iter().find(|&p| {
        rows.iter()
            .any(|&(q, send, recv)| q == p && send <= BUDGET && recv <= BUDGET)
    })
}

/// Whether the longest step at 256 places stays within FLATNESS of that at 8
/// (the same choice).
pub fn flat(at_8: u64, at_256: u64) -> bool {
    at_256.saturating_sub(at_8) <= FLATNESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(fixed_rx: u64, fixed_tx: u64, rx: u64, tx: u64, group: u64) -> Parts {
        Parts {
            fixed_rx,
            fixed_tx,
            frame_rx: rx,
            frame_tx: tx,
            frame_rx_wire: 0,
            frame_tx_wire: 0,
            group,
        }
    }

    #[test]
    fn cheap_parts_take_the_largest_everything() {
        assert_eq!(BUDGET, 15_613);
        assert_eq!(
            choose(&parts(1_000, 1_000, 300, 300, 200)),
            Ok(Choice {
                receive: 16,
                groups: 4,
                send: 16
            })
        );
    }

    #[test]
    fn the_expected_parts_of_the_decision_pass_with_small_batches() {
        // fixed 7 500, frames 3 000, group 2 500 (the worst corner).
        let p = parts(7_500, 7_500, 3_000, 3_000, 2_500);
        assert_eq!(p.sending(1, 1), 13_000);
        assert_eq!(p.receiving(1), 10_500);
        // Two groups still fit with one frame (15 500), a second frame does not.
        assert_eq!(p.sending(2, 1), 15_500);
        assert_eq!(
            choose(&p),
            Ok(Choice {
                receive: 2,
                groups: 2,
                send: 1
            })
        );
    }

    #[test]
    fn the_groups_and_the_frames_of_sending_are_chosen_apart() {
        let p = parts(2_000, 4_000, 500, 400, 1_000);
        // 4 groups and 16 frames: 4 000 + 4 000 + 6 400 = 14 400.
        assert_eq!(p.sending(4, 16), 14_400);
        assert_eq!(
            choose(&p),
            Ok(Choice {
                receive: 16,
                groups: 4,
                send: 16
            })
        );
        let q = parts(2_000, 4_000, 500, 800, 2_500);
        // 4 groups do not fit with one frame (4 000 + 10 000 + 800); two do.
        assert_eq!(q.sending(4, 1), 14_800);
        assert_eq!(q.sending(4, 2), 15_600);
        let c = choose(&q).unwrap();
        assert_eq!((c.groups, c.send), (4, 2));
    }

    #[test]
    fn the_gate_stops_a_step_of_one_frame_that_is_past_the_budget() {
        // The receiving step is past it.
        let r = parts(14_000, 1_000, 2_000, 500, 500);
        assert_eq!(
            choose(&r),
            Err(Stop {
                receiving: 16_000,
                sending: 2_000
            })
        );
        // The sending step is past it.
        let s = parts(1_000, 13_000, 500, 1_500, 1_500);
        assert_eq!(choose(&s).unwrap_err().sending, 16_000);
    }

    #[test]
    fn a_dearer_frame_of_the_wire_sets_the_price() {
        let mut p = parts(2_000, 4_000, 500, 400, 1_000);
        assert_eq!(choose(&p).unwrap().receive, 16);
        p.frame_rx_wire = 3_000;
        p.frame_tx_wire = 2_500;
        assert_eq!(p.rx_price(), 3_000);
        assert_eq!(p.tx_price(), 2_500);
        assert_eq!(p.receiving(4), 14_000);
        let c = choose(&p).unwrap();
        assert_eq!(c.receive, 4);
        assert_eq!(c.send, 2);
        // The cheaper wire frame leaves the loopback's price in force.
        p.frame_rx_wire = 100;
        assert_eq!(p.rx_price(), 500);
    }

    #[test]
    fn the_soft_share_lets_a_second_frame_in_when_the_sum_fits_the_margin() {
        use crate::ring::{RX_SOFT_MEASURED, STEP_MARGIN, STEP_TAIL_TICKS};
        // The dearest frame the margin allows after the share and the tail:
        // two of them cost more than the budget, one does not, and the share
        // holds the second one back, so the batch is two.
        let fit = STEP_MARGIN as u64 - RX_SOFT_MEASURED - STEP_TAIL_TICKS as u64;
        let mut p = parts(1_000, 4_000, 500, 400, 1_000);
        p.frame_rx_wire = fit;
        assert!(p.receiving(2) > BUDGET && p.receiving(1) <= BUDGET);
        assert_eq!(p.receiving_soft(), STEP_MARGIN as u64);
        assert_eq!(choose(&p).unwrap().receive, SOFT_FRAMES);
        // A frame so dear that the share, the frame and the tail pass the
        // margin leaves the batch of one.
        p.frame_rx_wire = fit + 1;
        assert!(p.receiving_soft() > STEP_MARGIN as u64);
        assert_eq!(choose(&p).unwrap().receive, 1);
    }

    #[test]
    fn the_soft_share_lets_a_second_group_in_when_the_sum_fits_the_margin() {
        use crate::ring::{STEP_MARGIN, STEP_TAIL_TICKS, TX_SOFT_MEASURED};
        // The dearest frame the margin allows after the share, a group and the tail.
        let mut p = parts(1_000, 5_800, 500, 400, 2_500);
        let fit = STEP_MARGIN as u64 - TX_SOFT_MEASURED - 2_500 - STEP_TAIL_TICKS as u64;
        p.frame_tx_wire = fit;
        // Two groups pass the budget, one fits, so the estimate alone gives one.
        assert!(p.sending(2, 1) > BUDGET && p.sending(1, 1) <= BUDGET);
        assert_eq!(p.sending_soft(), STEP_MARGIN as u64);
        let c = choose(&p).unwrap();
        assert_eq!((c.groups, c.send), (SOFT_GROUPS, 1));
        // One unit more leaves the group at one.
        p.frame_tx_wire = fit + 1;
        assert!(p.sending_soft() > STEP_MARGIN as u64);
        assert_eq!(choose(&p).unwrap().groups, 1);
        // The room for the share is what the sum has left.
        assert_eq!(p.tx_soft_room(), TX_SOFT_MEASURED - 1);
    }

    #[test]
    fn the_constants_of_the_code_give_the_numbers_of_the_code() {
        use crate::ring::{EGRESS_GROUPS, STEP_RX, STEP_TX};
        let p = Parts::of_ring();
        // Two groups pass the budget by the estimate and the soft share lets them in.
        assert!(p.sending(2, 1) > BUDGET);
        assert_eq!(
            choose(&p),
            Ok(Choice {
                receive: STEP_RX,
                groups: EGRESS_GROUPS,
                send: STEP_TX
            })
        );
    }

    #[test]
    fn the_portion_is_the_largest_whose_steps_fit() {
        let rows = [
            (16_384, 16_000, 9_000),
            (8_192, 11_000, 15_613),
            (4_096, 8_000, 7_000),
        ];
        assert_eq!(portion(&rows), Some(8_192));
        assert_eq!(portion(&rows[..1]), None);
        assert_eq!(portion(&[(16_384, 15_613, 15_000)]), Some(16_384));
        assert_eq!(portion(&[(4_096, 15_614, 1)]), None);
        assert_eq!(portion(&[]), None);
    }

    #[test]
    fn the_steps_are_flat_within_the_spread() {
        assert!(flat(14_000, 14_000));
        assert!(flat(14_000, 15_500));
        assert!(!flat(14_000, 15_501));
        assert!(flat(15_000, 14_000), "a smaller step at 256 is flat");
    }
}
