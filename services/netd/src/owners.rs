// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The owners of the sets of places. The stack hands a SYN to the first
//! socket in LISTEN, by place, of the set of four places the service names.
//! The queue sockets of the members of a SO_REUSEPORT group therefore must not
//! share a set with the queue sockets of another member: then the socket that
//! takes the SYN is the chosen member's own. A set has an owner (the listening
//! description whose queue sockets stand in it) and the count of those
//! sockets; the owner goes with the last one. Other sockets (connections,
//! clients, datagrams, queues of descriptions with no group) stand anywhere.

/// The places of a set.
pub const SET: usize = 4;

/// No owner.
const NONE: u16 = u16::MAX;

/// The owners of `SETS` sets, over `WORDS` words of 64 places.
pub struct Owners<const SETS: usize, const WORDS: usize> {
    owner: [u16; SETS],
    owned: [u8; SETS],
    /// The places of the sets that have an owner, a bit each.
    barred: [u64; WORDS],
}

impl<const SETS: usize, const WORDS: usize> Owners<SETS, WORDS> {
    pub const fn new() -> Self {
        assert!(SETS * SET <= WORDS * 64);
        // The places past the last set are barred for good: the table
        // (the sets of the stack) ends there.
        let mut barred = [0u64; WORDS];
        let mut i = SETS * SET;
        while i < WORDS * 64 {
            barred[i / 64] |= 1 << (i % 64);
            i += 1;
        }
        Owners {
            owner: [NONE; SETS],
            owned: [0; SETS],
            barred,
        }
    }

    /// Whether a queue socket of `listener` may stand in `set`.
    pub fn allowed(&self, set: usize, listener: usize) -> bool {
        let owner = self.owner[set];
        owner == NONE || usize::from(owner) == listener
    }

    /// A queue socket of `listener` stands in `set`.
    pub fn claim(&mut self, set: usize, listener: usize) {
        debug_assert!(self.allowed(set, listener));
        if self.owned[set] == 0 {
            self.owner[set] = listener as u16;
            self.barred[set * SET / 64] |= Self::mask(set);
        }
        self.owned[set] += 1;
    }

    /// A queue socket in `set` is one no longer.
    pub fn release(&mut self, set: usize) {
        debug_assert!(self.owned[set] > 0);
        self.owned[set] -= 1;
        if self.owned[set] == 0 {
            self.owner[set] = NONE;
            self.barred[set * SET / 64] &= !Self::mask(set);
        }
    }

    /// The places of the sets that have an owner, and those past the sets,
    /// per word.
    pub fn barred(&self) -> &[u64; WORDS] {
        &self.barred
    }

    /// The owner of `set`, if it has one.
    pub fn owner(&self, set: usize) -> Option<usize> {
        (self.owner[set] != NONE).then_some(usize::from(self.owner[set]))
    }

    fn mask(set: usize) -> u64 {
        ((1u64 << SET) - 1) << (set * SET % 64)
    }
}

impl<const SETS: usize, const WORDS: usize> Default for Owners<SETS, WORDS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_listeners_do_not_share_a_set() {
        let mut o = Owners::<32, 2>::new();
        assert!(o.allowed(3, 100));
        o.claim(3, 100);
        assert!(o.allowed(3, 100));
        assert!(!o.allowed(3, 101));
        assert!(o.allowed(4, 101));
        assert_eq!(o.owner(3), Some(100));
    }

    #[test]
    fn a_set_is_free_with_its_last_queue_socket() {
        let mut o = Owners::<32, 2>::new();
        o.claim(3, 100);
        o.claim(3, 100);
        o.release(3);
        assert!(!o.allowed(3, 101));
        assert_eq!(o.barred()[0], 0xF << 12);
        o.release(3);
        assert!(o.allowed(3, 101));
        assert_eq!(o.barred()[0], 0);
        assert_eq!(o.owner(3), None);
    }

    #[test]
    fn the_places_past_the_sets_are_barred() {
        let o = Owners::<2, 1>::new();
        assert_eq!(o.barred()[0], !0xFF);
    }

    #[test]
    fn the_barred_bits_follow_the_sets_across_words() {
        let mut o = Owners::<32, 2>::new();
        o.claim(15, 1);
        o.claim(16, 2);
        assert_eq!(o.barred()[0], 0xF << 60);
        assert_eq!(o.barred()[1], 0xF);
        o.release(15);
        o.release(16);
        assert_eq!(*o.barred(), [0; 2]);
    }
}
