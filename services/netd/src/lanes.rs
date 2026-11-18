// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! How a step of the switch shares its work among the lanes of the stack instances
//! (`switch::Lane`): one budget for all of them, so that the longest step does not grow with
//! the number of instances, a first lane that turns, so that none waits behind the others for
//! ever, the room each lane has for frames of the wire, so that a lane that does not take
//! its frames costs its own and no other's, and the lanes that hold the doorbell.

/// The lane whose rings come first in a step: it moves on by one each step.
#[derive(Clone, Copy, Debug, Default)]
pub struct Turn {
    next: usize,
}

impl Turn {
    pub const fn new() -> Turn {
        Turn { next: 0 }
    }

    /// The first lane of this step, among `lanes`, and the turn moves on.
    pub fn first(&mut self, lanes: usize) -> usize {
        let first = self.next % lanes;
        self.next = (first + 1) % lanes;
        first
    }
}

/// The lanes of a step in order, from `first`.
pub fn order(first: usize, lanes: usize) -> impl Iterator<Item = usize> {
    (0..lanes).map(move |i| (first + i) % lanes)
}

/// What each lane can still take of the frames of the wire.
pub fn take_room<const N: usize>(room: &mut [usize; N], k: usize) -> bool {
    if room[k] == 0 {
        return false;
    }
    room[k] -= 1;
    true
}

/// The most any lane can still take: the frames of the wire are taken off the queue while some
/// lane has room for them.
pub fn widest(room: &[usize]) -> usize {
    room.iter().copied().max().unwrap_or(0)
}

/// Whether lane `k` has frames waiting for the doorbell (`submitted`, a bit each): only such a
/// lane delays or holds the bell for the end of its run.
pub fn waiting(submitted: u8, k: usize) -> bool {
    submitted & (1 << k) != 0
}

/// Whether the end of a step of the stack wakes the switch (`switch::Lane::kick`): `more` says
/// another step follows at once. Inside a run the switch is woken when the stack's frames to send
/// are half a step of the switch or the buffers given back reach `RX_BACK_LAZY`; at the end of
/// the run also when the switch holds the doorbell (`held`), a frame waits to be sent, the
/// switch is `starved` or waits for the end of the run (`cut_wait`).
///
/// The buffers given back wake the switch from `RX_BACK_LAZY`, which is at most the room of a
/// lane: a switch that stopped with the lane full leaves frames in the used ring of the device,
/// and a device that has no buffer left raises no interrupt, so the stack that drained the lane
/// is the only one that can wake the switch, whatever it sent.
pub fn switch_due(
    more: bool,
    held: bool,
    tx_sub: usize,
    rx_back: usize,
    starved: bool,
    cut_wait: bool,
) -> bool {
    switch_due_at(
        crate::ring::RX_BACK_LAZY,
        more,
        held,
        tx_sub,
        rx_back,
        starved,
        cut_wait,
    )
}

/// `switch_due` with the threshold of the buffers given back as a parameter.
pub fn switch_due_at(
    lazy: usize,
    more: bool,
    held: bool,
    tx_sub: usize,
    rx_back: usize,
    starved: bool,
    cut_wait: bool,
) -> bool {
    if more {
        tx_sub >= crate::ring::SWITCH_TX / 2 || rx_back >= lazy || starved
    } else {
        held || tx_sub > 0 || rx_back >= lazy || starved || cut_wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A step that takes `budget` words from lanes holding `held[k]`, from `first` on; the
    /// words each lane gave.
    fn step(held: &mut [usize], first: usize, mut budget: usize) -> Vec<usize> {
        let lanes = held.len();
        let mut gave = vec![0; lanes];
        for k in order(first, lanes) {
            while budget > 0 && held[k] > 0 {
                held[k] -= 1;
                gave[k] += 1;
                budget -= 1;
            }
        }
        gave
    }

    #[test]
    fn the_budget_of_a_step_is_one_whatever_the_number_of_lanes() {
        for lanes in 1..=4 {
            let mut held = vec![100; lanes];
            let mut turn = Turn::new();
            let gave = step(&mut held, turn.first(lanes), 16);
            assert_eq!(gave.iter().sum::<usize>(), 16, "{lanes} lanes");
        }
    }

    #[test]
    fn the_first_lane_turns_so_that_every_lane_is_served() {
        let mut held = vec![1000; 4];
        let mut turn = Turn::new();
        let mut served = vec![0usize; 4];
        for _ in 0..100 {
            let first = turn.first(4);
            for (k, g) in step(&mut held, first, 6).iter().enumerate() {
                served[k] += g;
            }
        }
        // 600 words over 4 lanes: no lane is starved (a fixed first lane would give one all 600).
        assert!(served.iter().all(|&s| s >= 100), "{served:?}");
        assert_eq!(served.iter().sum::<usize>(), 600);
    }

    #[test]
    fn a_lane_with_no_room_costs_its_own_frames_and_never_stops_the_others() {
        let mut room = [0, 5, 5, 5];
        assert!(!take_room(&mut room, 0), "the stalled lane takes nothing");
        assert_eq!(widest(&room), 5, "the others still have room");
        for _ in 0..5 {
            assert!(take_room(&mut room, 2));
        }
        assert!(!take_room(&mut room, 2));
        assert_eq!(widest(&room), 5);
        assert_eq!(
            widest(&[0, 0, 0, 0]),
            0,
            "no room anywhere: the frames stay queued"
        );
    }

    #[test]
    fn only_a_lane_with_frames_waiting_counts_for_the_bell() {
        assert!(waiting(0b0100, 2));
        assert!(
            !waiting(0b0100, 1),
            "a lane in a run that put nothing in the queue"
        );
        assert!(!waiting(0, 0));
    }

    /// The device of the model: 256 buffers, a used ring, and a queue of parked frames that a
    /// doorbell flushes (the queue of the emulated device).
    struct Wire {
        avail: usize,
        used: usize,
        parked: usize,
        wanted: bool,
    }

    impl Wire {
        fn arrive(&mut self, n: usize) -> bool {
            let mut irq = false;
            for _ in 0..n {
                if self.avail > 0 {
                    self.avail -= 1;
                    self.used += 1;
                    irq = true;
                } else {
                    self.parked += 1;
                    self.wanted = true;
                }
            }
            irq
        }

        fn doorbell(&mut self) -> bool {
            if !self.wanted {
                return false;
            }
            self.wanted = false;
            let parked = self.parked;
            self.parked = 0;
            self.arrive(parked)
        }
    }

    /// A burst of `burst` frames on the model: the switch passes at most `RX_AHEAD` to the lane
    /// and sleeps when it is full, the stack takes the lane, replies to nothing and wakes the
    /// switch by `switch_due_at(lazy, ..)`; no event comes from outside. The frames that reached
    /// the stack.
    fn burst(lazy: usize, burst: usize) -> usize {
        use crate::ring::{RX_AHEAD, RX_BUFFERS, SWITCH_BACK, SWITCH_RX};
        let mut wire = Wire {
            avail: RX_BUFFERS,
            used: 0,
            parked: 0,
            wanted: false,
        };
        let (mut lane, mut back, mut got) = (0usize, 0usize, 0usize);
        let (mut switch_awake, mut stack_awake) = (wire.arrive(burst), false);
        for _ in 0..100_000 {
            if switch_awake {
                // A run of steps: buffers back first, then the frames while the lane has room.
                loop {
                    let give = back.min(SWITCH_BACK);
                    back -= give;
                    wire.avail += give;
                    if give > 0 {
                        wire.doorbell();
                    }
                    let take = (RX_AHEAD - lane).min(SWITCH_RX).min(wire.used);
                    lane += take;
                    wire.used -= take;
                    stack_awake |= take > 0;
                    if take == 0 && back == 0 {
                        break;
                    }
                }
                switch_awake = false;
            } else if stack_awake {
                stack_awake = false;
                got += lane;
                back += lane;
                lane = 0;
                switch_awake = switch_due_at(lazy, false, false, 0, back, false, false);
            } else {
                break;
            }
        }
        got
    }

    #[test]
    fn a_burst_of_frames_without_replies_reaches_the_stack_with_no_outside_event() {
        assert_eq!(burst(crate::ring::RX_BACK_LAZY, 600), 600);
        assert_eq!(burst(crate::ring::RX_BACK_LAZY, 5_000), 5_000);
    }

    #[test]
    fn a_threshold_over_the_room_of_the_lane_leaves_the_burst_in_the_device() {
        let ahead = crate::ring::RX_AHEAD;
        assert_eq!(burst(ahead, 600), 600);
        // 64 is the old threshold: one batch of 32 never reaches it, the switch sleeps with the
        // device out of buffers, and the stack has seen 32 frames.
        assert_eq!(burst(2 * ahead, 600), ahead);
    }

    #[test]
    fn the_wake_rule_reads_what_the_end_of_a_run_holds() {
        let lazy = crate::ring::RX_BACK_LAZY;
        assert!(switch_due(false, false, 0, lazy, false, false));
        assert!(!switch_due(false, false, 0, lazy - 1, false, false));
        assert!(switch_due(false, true, 0, 0, false, false));
        assert!(switch_due(false, false, 1, 0, false, false));
        assert!(switch_due(false, false, 0, 0, false, true));
        // Inside a run a lone frame to send waits, half a step of them does not.
        assert!(!switch_due(true, true, 1, 0, false, true));
        assert!(switch_due(
            true,
            false,
            crate::ring::SWITCH_TX / 2,
            0,
            false,
            false
        ));
        assert!(switch_due(true, false, 0, lazy, false, false));
    }
}
