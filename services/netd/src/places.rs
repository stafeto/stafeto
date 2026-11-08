// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The places of the descriptions: a fixed table whose place keeps the
//! generation of its description (a description of an old generation names
//! nothing), the count of the sessions that hold it, and its state. A
//! description on the wire is a place and a generation
//! (`proto_net::sockets`).
//!
//! The queue sockets of the members of a SO_REUSEPORT group are placed apart
//! (`owners`, `Places::allocate_in`): in the sets of their own member, else in
//! the lowest set no other member's queue stands in. With many groups some
//! queue sockets are therefore placed above the first 256 places and have the
//! small buffers; with none the lowest places are used first as before.

use crate::owners::SET;
use proto_net::sockets::{description, generation, slot};

/// The places of the table, and so the most descriptions (every member of a
/// queue of `listen` takes one).
pub const SOCKETS_MAX: usize = 1280;

/// The sockets the service serves at once: all the places of the table. The
/// step of the loop does not grow with the number of sockets (the sockets are
/// in sets of a few, and a frame goes to the set of its socket), so the limit
/// is the room of the table (reports/2026-11-04-net-p1a). The features
/// `limit-8`, `limit-64`, `limit-256` (and `limit-1280`, the default) build the
/// service with a smaller or the full
/// table of sets for the measurement of that evenness.
#[cfg(feature = "limit-8")]
pub const SOCKETS_LIMIT: usize = 8;
#[cfg(all(feature = "limit-64", not(feature = "limit-8")))]
pub const SOCKETS_LIMIT: usize = 64;
#[cfg(all(
    feature = "limit-256",
    not(any(feature = "limit-8", feature = "limit-64"))
))]
pub const SOCKETS_LIMIT: usize = 256;
#[cfg(not(any(feature = "limit-8", feature = "limit-64", feature = "limit-256")))]
pub const SOCKETS_LIMIT: usize = SOCKETS_MAX;

/// The generations have 20 bits.
const GENERATION_MASK: u32 = (1 << (32 - proto_net::sockets::SLOT_BITS)) - 1;

/// What a place holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Free,
    /// A description some session holds.
    Live,
    /// A stream that no session holds and that is still closing.
    Orphan,
    /// A socket of the queue of a listening description.
    Member,
}

/// The places of N descriptions.
pub struct Places<const N: usize> {
    generation: [u32; N],
    state: [State; N],
    refs: [u16; N],
    /// The free places, a bit each: a place is given from the lowest, so that
    /// the places with the full buffers (the lowest) are used first.
    free: [u64; FREE_WORDS],
    free_len: usize,
}

/// The words of the bitmap of the free places: 4 096 places at most.
const FREE_WORDS: usize = 64;

impl<const N: usize> Places<N> {
    pub const fn new() -> Self {
        assert!(N <= FREE_WORDS * 64);
        let mut free = [0u64; FREE_WORDS];
        let mut i = 0;
        while i < N {
            free[i / 64] |= 1 << (i % 64);
            i += 1;
        }
        Places {
            generation: [0; N],
            state: [State::Free; N],
            refs: [0; N],
            free,
            free_len: N,
        }
    }

    /// A place for a description in `state`, with a new generation and no
    /// holder; None when the table is full.
    pub fn allocate(&mut self, state: State) -> Option<usize> {
        debug_assert!(state != State::Free);
        let word = self.free.iter().position(|&w| w != 0)?;
        let i = word * 64 + self.free[word].trailing_zeros() as usize;
        Some(self.take(i, state))
    }

    /// A place for a queue socket of a SO_REUSEPORT member: a free place of
    /// one of `own_sets` (the sets whose owner is the member already), else
    /// the lowest free place that is not in a set with an owner (`barred`, a
    /// bit per place, a word per 64 places; the places past the words are
    /// barred). None when there is none, though free places may be left in
    /// the sets of other owners.
    pub fn allocate_in(
        &mut self,
        state: State,
        own_sets: impl IntoIterator<Item = usize>,
        barred: &[u64],
    ) -> Option<usize> {
        debug_assert!(state != State::Free);
        for set in own_sets {
            let (word, shift) = (set * SET / 64, set * SET % 64);
            let free = self.free[word] >> shift & ((1 << SET) - 1);
            if free != 0 {
                return Some(self.take(set * SET + free.trailing_zeros() as usize, state));
            }
        }
        // The places past the words of `barred` are barred.
        for (word, &closed) in barred.iter().enumerate().take(self.free.len()) {
            let open = self.free[word] & !closed;
            if open != 0 {
                return Some(self.take(word * 64 + open.trailing_zeros() as usize, state));
            }
        }
        None
    }

    /// Takes the free place `i`.
    fn take(&mut self, i: usize, state: State) -> usize {
        let word = i / 64;
        self.free[word] &= !(1 << (i % 64));
        self.free_len -= 1;
        self.generation[i] = match (self.generation[i] + 1) & GENERATION_MASK {
            0 => 1,
            g => g,
        };
        self.state[i] = state;
        self.refs[i] = 0;
        i
    }

    /// The place goes back to the free ones.
    pub fn free(&mut self, i: usize) {
        if self.state[i] != State::Free {
            self.state[i] = State::Free;
            self.refs[i] = 0;
            self.free[i / 64] |= 1 << (i % 64);
            self.free_len += 1;
        }
    }

    pub fn state(&self, i: usize) -> State {
        self.state[i]
    }

    pub fn set_state(&mut self, i: usize, state: State) {
        debug_assert!(self.state[i] != State::Free && state != State::Free);
        self.state[i] = state;
    }

    /// The place of a description a session may use: live, of the
    /// generation the description names.
    pub fn find(&self, d: u32) -> Option<usize> {
        let i = slot(d);
        (i < N && self.state[i] == State::Live && self.generation[i] == generation(d)).then_some(i)
    }

    /// The description of the place.
    pub fn name(&self, i: usize) -> u32 {
        description(i, self.generation[i])
    }

    /// One more session holds the place; false at the limit of the count.
    pub fn hold(&mut self, i: usize) -> bool {
        match self.refs[i].checked_add(1) {
            Some(n) => {
                self.refs[i] = n;
                true
            }
            None => false,
        }
    }

    /// A session lets go of the place: the holders left.
    pub fn release(&mut self, i: usize) -> u16 {
        self.refs[i] = self.refs[i].saturating_sub(1);
        self.refs[i]
    }

    pub fn holders(&self, i: usize) -> u16 {
        self.refs[i]
    }

    /// How many places are not free.
    pub fn used(&self) -> usize {
        N - self.free_len
    }
}

impl<const N: usize> Default for Places<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// The places a session holds, one bit each: SOCKETS_MAX bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Held {
    bits: [u64; SOCKETS_MAX / 64],
    count: u16,
}

impl Held {
    pub const EMPTY: Held = Held {
        bits: [0; SOCKETS_MAX / 64],
        count: 0,
    };

    pub fn has(&self, i: usize) -> bool {
        self.bits[i / 64] >> (i % 64) & 1 != 0
    }

    /// Adds the place; false when it is held already.
    pub fn add(&mut self, i: usize) -> bool {
        if self.has(i) {
            return false;
        }
        self.bits[i / 64] |= 1 << (i % 64);
        self.count += 1;
        true
    }

    pub fn remove(&mut self, i: usize) -> bool {
        if !self.has(i) {
            return false;
        }
        self.bits[i / 64] &= !(1 << (i % 64));
        self.count -= 1;
        true
    }

    pub fn count(&self) -> usize {
        usize::from(self.count)
    }

    /// The lowest held place at or after `from`.
    pub fn next(&self, from: usize) -> Option<usize> {
        if from >= SOCKETS_MAX {
            return None;
        }
        // A word at a time: the lowest bit at or after `from`.
        let mut word = from / 64;
        let mut bits = self.bits[word] & (!0u64 << (from % 64));
        loop {
            if bits != 0 {
                return Some(word * 64 + bits.trailing_zeros() as usize);
            }
            word += 1;
            if word == self.bits.len() {
                return None;
            }
            bits = self.bits[word];
        }
    }
}

/// Whether a stream no session holds is over, so that a new SYN on its four starts a new stream:
/// it waits out TIME-WAIT, or it has closed with no RST of ours still on the way and only waits
/// for the sweep to free its place.
pub fn orphan_is_over(time_wait: bool, closed: bool, rst_pending: bool) -> bool {
    time_wait || (closed && !rst_pending)
}

#[cfg(test)]
mod tests {
    /// A closed stream waiting for the sweep gives its four to a new SYN as one in TIME-WAIT does;
    /// one whose RST is still on the way, and a stream that is still open, does not.
    #[test]
    fn a_closed_orphan_is_over_unless_its_reset_is_on_the_way() {
        assert!(orphan_is_over(false, true, false));
        assert!(orphan_is_over(true, false, false));
        assert!(!orphan_is_over(false, true, true));
        assert!(!orphan_is_over(false, false, false));
    }

    use super::*;

    #[test]
    fn a_place_gets_a_new_generation_each_time() {
        let mut p = Places::<4>::new();
        let i = p.allocate(State::Live).unwrap();
        let first = p.name(i);
        assert_eq!(p.find(first), Some(i));
        p.free(i);
        assert_eq!(p.find(first), None);
        // The place comes again with another generation: the old name stays dead.
        let again = p.allocate(State::Live).unwrap();
        assert_eq!(again, i);
        assert_ne!(p.name(again), first);
        assert_eq!(p.find(first), None);
        assert_eq!(p.find(p.name(again)), Some(i));
    }

    #[test]
    fn the_lowest_free_place_is_given_first() {
        let mut p = Places::<300>::new();
        let places: Vec<_> = (0..300).map(|_| p.allocate(State::Live).unwrap()).collect();
        assert_eq!(places, (0..300).collect::<Vec<_>>());
        p.free(290);
        p.free(70);
        p.free(5);
        assert_eq!(p.allocate(State::Live), Some(5));
        assert_eq!(p.allocate(State::Live), Some(70));
        assert_eq!(p.allocate(State::Live), Some(290));
        assert_eq!(p.allocate(State::Live), None);
    }

    #[test]
    fn a_queue_socket_stays_out_of_the_sets_of_other_owners() {
        let mut p = Places::<64>::new();
        // Sets 0 and 1 (places 0..8) belong to others.
        let barred = [0xFFu64];
        assert_eq!(p.allocate_in(State::Member, [], &barred), Some(8));
        // The own set comes first, even above the lowest free place.
        assert_eq!(p.allocate_in(State::Member, [5], &barred), Some(20));
        assert_eq!(p.allocate_in(State::Member, [5], &barred), Some(21));
        // An own set that is full gives way to the lowest open place.
        for _ in 0..2 {
            p.allocate_in(State::Member, [5], &barred).unwrap();
        }
        assert_eq!(p.allocate_in(State::Member, [5], &barred), Some(9));
        // Plain allocation takes the barred places.
        assert_eq!(p.allocate(State::Live), Some(0));
    }

    #[test]
    fn two_listeners_that_place_in_turn_never_share_a_set() {
        use crate::owners::Owners;
        let mut p = Places::<256>::new();
        let mut o = Owners::<64, 4>::new();
        let mut queue: [Vec<usize>; 2] = [Vec::new(), Vec::new()];
        // Other sockets stand between them, as connections do.
        for round in 0..16 {
            for (l, q) in queue.iter_mut().enumerate() {
                let own: Vec<usize> = q.iter().map(|&m| m / SET).collect();
                let own = own.into_iter().filter(|&s| o.allowed(s, l));
                let m = p.allocate_in(State::Member, own, o.barred()).unwrap();
                o.claim(m / SET, l);
                q.push(m);
            }
            if round % 3 == 0 {
                p.allocate(State::Live).unwrap();
            }
        }
        for a in &queue[0] {
            for b in &queue[1] {
                assert_ne!(a / SET, b / SET, "{a} and {b} share a set");
            }
        }
        // Each queue is dense: 16 sockets in 4 sets.
        for q in &queue {
            let mut sets: Vec<_> = q.iter().map(|m| m / SET).collect();
            sets.dedup();
            assert!(sets.len() <= 5, "{sets:?}");
        }
    }

    #[test]
    fn no_open_place_is_none_though_places_are_free() {
        let mut p = Places::<8>::new();
        assert_eq!(p.allocate_in(State::Member, [], &[0xFF]), None);
        assert_eq!(p.used(), 0);
        assert_eq!(p.allocate_in(State::Member, [1], &[0xFF]), Some(4));
        assert!(p.allocate(State::Live).is_some());
    }

    #[test]
    fn the_generation_is_never_zero() {
        let mut p = Places::<1>::new();
        p.generation[0] = GENERATION_MASK;
        let i = p.allocate(State::Live).unwrap();
        assert_eq!(proto_net::sockets::generation(p.name(i)), 1);
    }

    #[test]
    fn only_live_places_are_found() {
        let mut p = Places::<4>::new();
        let i = p.allocate(State::Member).unwrap();
        assert_eq!(p.find(p.name(i)), None);
        p.set_state(i, State::Live);
        assert_eq!(p.find(p.name(i)), Some(i));
        p.set_state(i, State::Orphan);
        assert_eq!(p.find(p.name(i)), None);
        assert_eq!(p.find(u32::MAX), None, "a place past the table");
    }

    #[test]
    fn the_table_fills_and_empties() {
        let mut p = Places::<3>::new();
        let places: Vec<_> = (0..3).map(|_| p.allocate(State::Live).unwrap()).collect();
        assert_eq!(p.used(), 3);
        assert_eq!(p.allocate(State::Live), None);
        for i in places {
            p.free(i);
            p.free(i);
        }
        assert_eq!(p.used(), 0);
        assert!(p.allocate(State::Live).is_some());
    }

    #[test]
    fn holders_are_counted() {
        let mut p = Places::<2>::new();
        let i = p.allocate(State::Live).unwrap();
        assert!(p.hold(i));
        assert!(p.hold(i));
        assert_eq!(p.release(i), 1);
        assert_eq!(p.release(i), 0);
        assert_eq!(p.release(i), 0);
        p.refs[i] = u16::MAX;
        assert!(!p.hold(i));
    }

    #[test]
    fn a_session_holds_a_place_once() {
        let mut h = Held::EMPTY;
        assert!(h.add(3));
        assert!(!h.add(3));
        assert!(h.add(255));
        assert_eq!(h.count(), 2);
        assert_eq!(h.next(0), Some(3));
        assert_eq!(h.next(4), Some(255));
        assert!(h.remove(3));
        assert!(!h.remove(3));
        assert_eq!(h.count(), 1);
        assert_eq!(h.next(0), Some(255));
        assert_eq!(h.next(256), None);
        // The word borders.
        let mut h = Held::EMPTY;
        for i in [63, 64, 127, 128, 200] {
            h.add(i);
        }
        assert_eq!(h.next(0), Some(63));
        assert_eq!(h.next(63), Some(63));
        assert_eq!(h.next(64), Some(64));
        assert_eq!(h.next(65), Some(127));
        assert_eq!(h.next(129), Some(200));
        assert_eq!(h.next(201), None);
        assert_eq!(h.next(255), None);
    }
}
