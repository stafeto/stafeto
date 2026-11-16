// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Waits that cannot block, parked while steps of the wire stand ahead of them.
//!
//! No step of the wire runs inside a request. A wait of a set with the steps of sending,
//! receiving or waking told ahead of it (or owed) is parked, and the step of waking answers it:
//! at the first step of waking after which neither sending nor receiving is told, and at the
//! latest at its third step of waking (`WAKES`), with whatever is ready then, which may be
//! nothing. A flood that keeps the wire's steps told cannot keep a request waiting for more than
//! three steps of waking.

/// The waits that may be parked at once (the other requests take the records as they stand).
pub const PARKED_MAX: usize = 16;
/// The steps of waking a parked wait stands.
pub const WAKES: u8 = 3;

/// A parked wait and the steps of waking it has left.
pub struct Slot<T> {
    pub item: T,
    pub wakes: u8,
}

impl<T> Slot<T> {
    pub fn new(item: T) -> Slot<T> {
        Slot { item, wakes: WAKES }
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

/// Whether some wait is parked.
pub fn parked<T>(slots: &[Option<Slot<T>>]) -> bool {
    slots.iter().any(Option::is_some)
}

/// A step of waking ran. `quiet` says that neither sending nor receiving is told. Each parked
/// wait counts the step; those that stand no more, or find the wire quiet, go to `answer`.
pub fn after_wake<T>(slots: &mut [Option<Slot<T>>], quiet: bool, mut answer: impl FnMut(T)) {
    for slot in slots.iter_mut() {
        let Some(parked) = slot.as_mut() else {
            continue;
        };
        parked.wakes -= 1;
        let last = quiet || parked.wakes == 0;
        if last && let Some(done) = slot.take() {
            answer(done.item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> [Option<Slot<u32>>; 4] {
        [const { None }; 4]
    }

    #[test]
    fn a_wait_is_answered_at_the_first_step_of_waking_after_which_the_wire_is_quiet() {
        let mut slots = table();
        park(&mut slots, 7).unwrap();
        let mut answered = Vec::new();
        after_wake(&mut slots, false, |i| answered.push(i));
        assert!(answered.is_empty() && parked(&slots));
        after_wake(&mut slots, true, |i| answered.push(i));
        assert_eq!(answered, [7]);
        assert!(!parked(&slots));
    }

    #[test]
    fn a_wait_under_a_flood_is_answered_at_its_third_step_of_waking() {
        // The wire's steps are told again at every step: the wire is never quiet.
        let mut slots = table();
        park(&mut slots, 1).unwrap();
        let mut answered = Vec::new();
        let mut wakes = 0;
        while parked(&slots) {
            wakes += 1;
            after_wake(&mut slots, false, |i| answered.push((i, wakes)));
            assert!(wakes <= 3);
        }
        assert_eq!(answered, [(1, 3)]);
    }

    #[test]
    fn a_wait_parked_later_counts_its_own_steps() {
        let mut slots = table();
        park(&mut slots, 1).unwrap();
        let mut answered = Vec::new();
        after_wake(&mut slots, false, |i| answered.push(i));
        park(&mut slots, 2).unwrap();
        after_wake(&mut slots, false, |i| answered.push(i));
        after_wake(&mut slots, false, |i| answered.push(i));
        assert_eq!(answered, [1]);
        after_wake(&mut slots, false, |i| answered.push(i));
        assert_eq!(answered, [1, 2]);
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
        let mut answered = Vec::new();
        after_wake(&mut slots, true, |i| answered.push(i));
        assert_eq!(answered, [0, 1, 2, 3]);
        assert!(room(&slots));
    }
}
