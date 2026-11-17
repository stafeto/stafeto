// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Waits that cannot block, parked while steps of the wire stand ahead of them.
//!
//! No step of the wire runs inside a request. A wait of a set with the steps of sending,
//! receiving or waking told ahead of it (or owed) is parked. The step of waking only counts: a
//! parked wait becomes due at the first step of waking after which neither sending nor receiving
//! is told, and at the latest at its third step (`WAKES`). The step `ZERO`, which follows the
//! step of waking, answers one due wait for a step, with whatever is ready then, which may be
//! nothing, and tells itself again while due waits remain. A flood that keeps the wire's steps
//! told cannot keep a request waiting for more than three steps of waking and the steps `ZERO`
//! of the waits due before it.

/// The waits that may be parked at once; a request that finds no place is answered BUSY.
pub const PARKED_MAX: usize = 16;
/// The steps of waking a parked wait stands.
pub const WAKES: u8 = 3;

/// A parked wait, the steps of waking it has left, and whether it is due: its steps are
/// counted out, or the wire was quiet, and the step `ZERO` answers it.
pub struct Slot<T> {
    pub item: T,
    pub wakes: u8,
    pub due: bool,
}

impl<T> Slot<T> {
    pub fn new(item: T) -> Slot<T> {
        Slot {
            item,
            wakes: WAKES,
            due: false,
        }
    }
}

/// Whether a wait can be parked.
pub fn room<T>(slots: &[Option<Slot<T>>]) -> bool {
    slots.iter().any(Option::is_none)
}

/// Parks `item`; it comes back when there is no room.
pub fn park<T>(slots: &mut [Option<Slot<T>>], item: T) -> Result<(), T> {
    match slots.iter_mut().find(|s| s.is_none()) {
        Some(slot) => {
            *slot = Some(Slot::new(item));
            Ok(())
        }
        None => Err(item),
    }
}

/// Whether some wait stands and is not due: the step of waking has more to count.
pub fn waiting<T>(slots: &[Option<Slot<T>>]) -> bool {
    slots.iter().flatten().any(|s| !s.due)
}

/// Whether some wait is due.
pub fn due<T>(slots: &[Option<Slot<T>>]) -> bool {
    slots.iter().flatten().any(|s| s.due)
}

/// A step of waking ran. `quiet` says that neither sending nor receiving is told. Each wait that
/// is not due counts the step; those that stand no more, or find the wire quiet, become due. No
/// wait is answered here: the step `ZERO` answers one at a time (`take_due`).
pub fn after_wake<T>(slots: &mut [Option<Slot<T>>], quiet: bool) {
    for parked in slots.iter_mut().flatten() {
        if parked.due {
            continue;
        }
        parked.wakes -= 1;
        if quiet || parked.wakes == 0 {
            parked.due = true;
        }
    }
}

/// The first wait that is due, taken off the table: one answer for a step.
pub fn take_due<T>(slots: &mut [Option<Slot<T>>]) -> Option<T> {
    let slot = slots
        .iter_mut()
        .find(|s| s.as_ref().is_some_and(|p| p.due))?;
    slot.take().map(|p| p.item)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> [Option<Slot<u32>>; 4] {
        [const { None }; 4]
    }

    /// The step ZERO until nothing is due: each step answers one wait.
    fn zero_steps(slots: &mut [Option<Slot<u32>>]) -> Vec<u32> {
        let mut answered = Vec::new();
        while let Some(item) = take_due(slots) {
            answered.push(item);
        }
        answered
    }

    #[test]
    fn a_wait_is_due_at_the_first_step_of_waking_after_which_the_wire_is_quiet() {
        let mut slots = table();
        park(&mut slots, 7).unwrap();
        after_wake(&mut slots, false);
        assert!(waiting(&slots) && !due(&slots));
        after_wake(&mut slots, true);
        assert!(!waiting(&slots) && due(&slots));
        assert_eq!(take_due(&mut slots), Some(7));
        assert_eq!(take_due(&mut slots), None);
    }

    #[test]
    fn a_wait_under_a_flood_is_due_at_its_third_step_of_waking() {
        // The wire's steps are told again at every step: the wire is never quiet.
        let mut slots = table();
        park(&mut slots, 1).unwrap();
        let mut wakes = 0;
        while !due(&slots) {
            wakes += 1;
            after_wake(&mut slots, false);
            assert!(wakes <= 3);
        }
        assert_eq!(wakes, 3);
        assert_eq!(take_due(&mut slots), Some(1));
    }

    #[test]
    fn the_step_of_waking_answers_nothing_and_each_zero_step_answers_one() {
        let mut slots = table();
        for i in 0..4 {
            park(&mut slots, i).unwrap();
        }
        after_wake(&mut slots, true);
        // Four are due; one answer for a step, and the step tells itself again while due
        // waits remain.
        let mut steps = 0;
        let mut answered = Vec::new();
        while due(&slots) {
            steps += 1;
            answered.push(take_due(&mut slots).unwrap());
        }
        assert_eq!((steps, answered), (4, vec![0, 1, 2, 3]));
        assert!(!due(&slots) && !waiting(&slots));
    }

    #[test]
    fn a_wait_parked_later_counts_its_own_steps() {
        let mut slots = table();
        park(&mut slots, 1).unwrap();
        after_wake(&mut slots, false);
        park(&mut slots, 2).unwrap();
        after_wake(&mut slots, false);
        after_wake(&mut slots, false);
        assert_eq!(zero_steps(&mut slots), [1]);
        after_wake(&mut slots, false);
        assert_eq!(zero_steps(&mut slots), [2]);
    }

    #[test]
    fn a_wait_that_is_due_does_not_count_again() {
        let mut slots = table();
        park(&mut slots, 1).unwrap();
        after_wake(&mut slots, true);
        for _ in 0..5 {
            after_wake(&mut slots, false);
        }
        assert_eq!(zero_steps(&mut slots), [1]);
    }

    #[test]
    fn a_full_table_gives_the_wait_back() {
        let mut slots = table();
        for i in 0..4 {
            assert!(room(&slots));
            park(&mut slots, i).unwrap();
        }
        assert!(!room(&slots));
        assert_eq!(park(&mut slots, 9), Err(9));
        after_wake(&mut slots, true);
        assert_eq!(zero_steps(&mut slots), [0, 1, 2, 3]);
        assert!(room(&slots));
    }

    #[test]
    fn the_seventeenth_caller_finds_no_place_and_gets_one_after_three_steps_of_waking() {
        let mut slots: [Option<Slot<usize>>; PARKED_MAX] = [const { None }; PARKED_MAX];
        for i in 0..PARKED_MAX {
            assert!(room(&slots));
            park(&mut slots, i).unwrap();
        }
        // The 17th is answered BUSY (no place) and asks again.
        assert!(!room(&slots));
        for _ in 0..WAKES {
            after_wake(&mut slots, false);
        }
        // Three steps of waking made every wait due, and each step ZERO frees one place.
        assert!(due(&slots) && !waiting(&slots));
        assert_eq!(take_due(&mut slots), Some(0));
        assert!(room(&slots));
    }
}
