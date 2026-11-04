// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The passes of a send (sockets of the network service in an SCM_RIGHTS
//! message) apart from the handles themselves: the numbers a request lists
//! (`PASS + k`, k the number of a handle among the handles of the request),
//! their translation into the places the service keeps the handles in, and the
//! places a send that waits holds by its operation. Everything here is plain
//! data, so the host tests it.

use proto_pipe::sock::{PASS, PASSES_PER_MESSAGE};

/// What a request that lists passes may be refused for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refuse {
    /// The numbers do not name each handle once, or their count is not the
    /// handles'.
    Size,
}

/// The places a send that waits holds: its session's label (a session that
/// goes lets go of them) and the place of each handle by its number in the
/// request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Carry {
    pub n: u8,
    pub label: u64,
    pub slots: [u8; PASSES_PER_MESSAGE],
}

impl Carry {
    pub const EMPTY: Self = Self {
        n: 0,
        label: 0,
        slots: [0; PASSES_PER_MESSAGE],
    };

    /// The places in use.
    pub fn places(&self) -> &[u8] {
        &self.slots[..usize::from(self.n)]
    }
}

/// Whether a handle with these rights is a pass of the network service: it
/// may be handed on and nothing else (a session of this service may send, a
/// copy may be copied).
pub fn is_pass_rights(rights: abi::Rights) -> bool {
    rights == abi::Rights::TRANSFER
}

/// How many of `fds` are passes.
pub fn listed(fds: &[u32]) -> usize {
    fds.iter().filter(|&&id| id >= PASS).count()
}

/// Whether the passes among `fds` name each number 0..`n` once and are `n`.
pub fn names_each_once(fds: &[u32], n: usize) -> bool {
    if n > PASSES_PER_MESSAGE || listed(fds) != n {
        return false;
    }
    let mut named = 0u32;
    for &id in fds.iter().filter(|&&id| id >= PASS) {
        let k = id - PASS;
        if k as usize >= n || named >> k & 1 != 0 {
            return false;
        }
        named |= 1 << k;
    }
    true
}

/// `fds` with each pass `PASS + k` made `PASS + slots[k]`: for a start, the
/// places it was given; for a take, those of the operation. The passes must
/// name each handle once.
pub fn translate(fds: &mut [u32], slots: &[u8]) -> Result<(), Refuse> {
    if !names_each_once(fds, slots.len()) {
        return Err(Refuse::Size);
    }
    for id in fds.iter_mut().filter(|id| **id >= PASS) {
        // `PASS + slot` is a number of `u32`: the base leaves room for every
        // place (`proto_pipe::sock`).
        *id = PASS + u32::from(slots[(*id - PASS) as usize]);
    }
    Ok(())
}

/// The sends that wait, by operation.
pub struct Carries<const N: usize> {
    table: [Carry; N],
}

impl<const N: usize> Default for Carries<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Carries<N> {
    pub const fn new() -> Self {
        Self {
            table: [Carry::EMPTY; N],
        }
    }

    /// What operation `idx` holds.
    pub fn get(&self, idx: usize) -> Carry {
        self.table[idx]
    }

    /// Operation `idx` holds `carry` for the session `label`.
    pub fn file(&mut self, idx: usize, label: u64, carry: Carry) {
        self.table[idx] = Carry { label, ..carry };
    }

    /// What operation `idx` held, which it holds no more.
    pub fn take(&mut self, idx: usize) -> Carry {
        core::mem::replace(&mut self.table[idx], Carry::EMPTY)
    }

    /// The operations of the session `label` that hold places.
    pub fn of(&self, label: u64) -> impl Iterator<Item = usize> + '_ {
        (0..N).filter(move |&i| self.table[i].n != 0 && self.table[i].label == label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_handle_with_the_right_to_be_handed_on_alone_is_a_pass() {
        use abi::Rights;
        assert!(is_pass_rights(Rights::TRANSFER));
        assert!(!is_pass_rights(Rights::SEND | Rights::TRANSFER));
        assert!(!is_pass_rights(Rights::TRANSFER | Rights::DUPLICATE));
        assert!(!is_pass_rights(Rights::NONE));
        assert!(!is_pass_rights(Rights::SEND));
    }

    #[test]
    fn every_place_has_a_number_of_u32() {
        // The highest place gives the highest number, and nothing wraps.
        let mut fds = [PASS];
        translate(&mut fds, &[31]).unwrap();
        assert_eq!(fds, [PASS + 31]);
        assert!(fds[0] > PASS);
    }

    #[test]
    fn the_order_of_the_numbers_among_other_descriptions_is_kept() {
        let mut fds = [PASS + 1, 5, PASS, 9];
        translate(&mut fds, &[17, 30]).unwrap();
        assert_eq!(fds, [PASS + 30, 5, PASS + 17, 9]);
    }

    #[test]
    fn a_number_named_twice_or_a_handle_not_named_is_refused() {
        let mut twice = [PASS, PASS];
        assert_eq!(translate(&mut twice, &[3, 4]), Err(Refuse::Size));
        let mut missing = [PASS];
        assert_eq!(translate(&mut missing, &[3, 4]), Err(Refuse::Size));
        let mut past = [PASS + 2, PASS];
        assert_eq!(translate(&mut past, &[3, 4]), Err(Refuse::Size));
        let mut none = [5];
        assert_eq!(translate(&mut none, &[3]), Err(Refuse::Size));
        assert_eq!(translate(&mut none, &[]), Ok(()));
        // A refusal changes nothing.
        assert_eq!(twice, [PASS, PASS]);
    }

    #[test]
    fn a_message_holds_four_passes_at_most() {
        let fds = [PASS, PASS + 1, PASS + 2, PASS + 3, PASS + 4];
        assert!(!names_each_once(&fds, 5));
        assert!(names_each_once(&fds[..4], 4));
    }

    #[test]
    fn the_places_of_a_send_that_waits_go_with_its_session() {
        let mut c: Carries<8> = Carries::new();
        let carry = Carry {
            n: 2,
            label: 0,
            slots: [20, 21, 0, 0],
        };
        c.file(3, 77, carry);
        c.file(5, 88, carry);
        c.file(6, 77, Carry { n: 1, ..carry });
        assert_eq!(c.of(77).collect::<Vec<_>>(), [3, 6]);
        assert_eq!(c.get(3).places(), [20, 21]);
        // A take moves the places out: the operation holds none.
        let taken = c.take(3);
        assert_eq!(taken.places(), [20, 21]);
        assert_eq!(c.get(3).n, 0);
        assert_eq!(c.of(77).collect::<Vec<_>>(), [6]);
        assert_eq!(c.of(99).count(), 0);
    }
}
