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
}
