// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The sets of endpoint holds of the sessions, found in a bounded number
//! of steps.
//!
//! A session holds a set from its first request (or from its Clone) until
//! the queue of retired sets has closed what it holds. A set of a clone is
//! found by the place of the clone's label in the table of `Clones`; a
//! session that is no clone of the service (a root: one that init or the
//! service gave out itself) has its set in a small table of roots,
//! whose labels trusted parties choose and which is walked whole. A free
//! list gives the next free set. No operation walks the sets.
//!
//! A set goes back to the free list (`release`) only after `unbind` took
//! it out of the tables, and `unbind` comes with the end of the session's
//! last handle (`closed`), which follows `gone` in the same notice. A
//! service that hears `gone` alone (a session moved off its place) must
//! unbind the set there before it can release it.

use crate::endpoints::Holds;
use proto_wire::clones::{Clones, ROOTS};

/// No set: the end of the free list, and an empty entry of a table.
const NONE: u16 = u16::MAX;

/// What a session holds, and whose it is.
pub struct HoldSet {
    pub label: u64,
    pub root: u64,
    pub holds: Holds,
    pub retired: bool,
}

impl HoldSet {
    pub const fn new() -> Self {
        Self {
            label: 0,
            root: 0,
            holds: Holds::new(),
            retired: false,
        }
    }
}

impl Default for HoldSet {
    fn default() -> Self {
        Self::new()
    }
}

/// `N` sets for `C` places of clones and `ROOTS` roots.
pub struct HoldSets<const C: usize, const N: usize> {
    sets: [HoldSet; N],
    /// For each set: the next free one while it is free.
    next: [u16; N],
    free: u16,
    /// For each place of the table of clones: the set of the clone there.
    by_place: [u16; C],
    /// For each root: its label and its set (NONE for a free entry).
    roots: [(u64, u16); ROOTS],
    /// The entries of the tables a test counted.
    #[cfg(test)]
    probes: core::cell::Cell<usize>,
}

impl<const C: usize, const N: usize> Default for HoldSets<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const C: usize, const N: usize> HoldSets<C, N> {
    pub const fn new() -> Self {
        assert!(N == C + ROOTS, "a set for each clone and each root");
        assert!(N < NONE as usize, "sets are 16 bits");
        let mut next = [NONE; N];
        let mut i = 0;
        while i + 1 < N {
            next[i] = (i + 1) as u16;
            i += 1;
        }
        Self {
            sets: [const { HoldSet::new() }; N],
            next,
            free: 0,
            by_place: [NONE; C],
            roots: [(0, NONE); ROOTS],
            #[cfg(test)]
            probes: core::cell::Cell::new(0),
        }
    }

    #[cfg(test)]
    fn probe(&self) {
        self.probes.set(self.probes.get() + 1);
    }

    /// The first free set, off the free list, empty.
    pub fn take(&mut self) -> Option<usize> {
        #[cfg(test)]
        self.probe();
        let set = self.free;
        if set == NONE {
            return None;
        }
        self.free = self.next[usize::from(set)];
        self.next[usize::from(set)] = NONE;
        Some(usize::from(set))
    }

    /// The set back on the free list, emptied.
    pub fn release(&mut self, set: usize) {
        #[cfg(test)]
        self.probe();
        // Still bound: the session's end was not heard (see the module).
        debug_assert!(!self.by_place.contains(&(set as u16)));
        debug_assert!(!self.roots.iter().any(|&(_, bound)| bound == set as u16));
        self.sets[set] = HoldSet::new();
        self.next[set] = self.free;
        self.free = set as u16;
    }

    /// The set of the clone at `place` of the table of clones.
    pub fn for_clone(&self, place: usize) -> Option<usize> {
        #[cfg(test)]
        self.probe();
        let set = self.by_place[place];
        (set != NONE).then_some(usize::from(set))
    }

    /// The set of the root `label`, in one walk of the table of roots.
    pub fn for_root(&self, label: u64) -> Option<usize> {
        self.root_entry(label).map(|i| usize::from(self.roots[i].1))
    }

    fn root_entry(&self, label: u64) -> Option<usize> {
        (0..ROOTS).find(|&i| {
            #[cfg(test)]
            self.probe();
            self.roots[i].1 != NONE && self.roots[i].0 == label
        })
    }

    /// The set of the session `label`: its clone's, or its root's.
    pub fn find<const B: u32>(&self, label: u64, clones: &Clones<C, B>) -> Option<usize> {
        match clones.place_of(label) {
            Some(place) => self.for_clone(place),
            None => self.for_root(label),
        }
    }

    pub fn bind_clone(&mut self, place: usize, set: usize) {
        #[cfg(test)]
        self.probe();
        debug_assert!(self.by_place[place] == NONE);
        self.by_place[place] = set as u16;
    }

    /// False when the table of roots is full.
    pub fn bind_root(&mut self, label: u64, set: usize) -> bool {
        match (0..ROOTS).find(|&i| {
            #[cfg(test)]
            self.probe();
            self.roots[i].1 == NONE
        }) {
            Some(i) => {
                self.roots[i] = (label, set as u16);
                true
            }
            None => false,
        }
    }

    /// The set of the session `label`, no longer found by it. The caller
    /// frees the clone's place after this (`Clones::gone`), as the place
    /// is how a clone's set is found.
    pub fn unbind<const B: u32>(&mut self, label: u64, clones: &Clones<C, B>) -> Option<usize> {
        match clones.place_of(label) {
            Some(place) => {
                #[cfg(test)]
                self.probe();
                let set = core::mem::replace(&mut self.by_place[place], NONE);
                (set != NONE).then_some(usize::from(set))
            }
            None => {
                let i = self.root_entry(label)?;
                let set = self.roots[i].1;
                self.roots[i] = (0, NONE);
                Some(usize::from(set))
            }
        }
    }
}

impl<const C: usize, const N: usize> core::ops::Index<usize> for HoldSets<C, N> {
    type Output = HoldSet;
    fn index(&self, set: usize) -> &HoldSet {
        &self.sets[set]
    }
}

impl<const C: usize, const N: usize> core::ops::IndexMut<usize> for HoldSets<C, N> {
    fn index_mut(&mut self, set: usize) -> &mut HoldSet {
        &mut self.sets[set]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: usize = 320;
    const N: usize = C + ROOTS;
    const TAG: u64 = 1 << 62;

    /// The tables as a service fills them: `live` clones of one root and
    /// `roots` roots, each with a set.
    fn filled(clones: &mut Clones<C>, live: usize, roots: usize) -> HoldSets<C, N> {
        let mut sets = HoldSets::<C, N>::new();
        for i in 0..roots {
            let set = sets.take().unwrap();
            let label = TAG | (i as u64 + 1) << 20;
            sets[set].label = label;
            assert!(sets.bind_root(label, set));
        }
        for _ in 0..live {
            let label = clones.give_within(TAG, TAG | 1 << 20, C).unwrap();
            let set = sets.take().unwrap();
            sets[set].label = label;
            sets.bind_clone(clones.place_of(label).unwrap(), set);
        }
        sets
    }

    /// The steps of `take`, a clone's set, a root's set that is missing
    /// and `release` are the same with one set busy and with all but one,
    /// and the walk of the roots is ROOTS entries at most.
    #[test]
    fn steps_do_not_grow_with_the_sets_in_use() {
        let mut seen = [[0; 4]; 2];
        for (row, live) in [1, C - 1].into_iter().enumerate() {
            let mut clones = Clones::<C>::new();
            let mut sets = filled(&mut clones, live, 1);
            let at = |sets: &HoldSets<C, N>| sets.probes.get();
            let before = at(&sets);
            let taken = sets.take().unwrap();
            let takes = at(&sets) - before;
            let before = at(&sets);
            assert!(sets.for_clone(0).is_some());
            let finds = at(&sets) - before;
            let before = at(&sets);
            assert_eq!(sets.for_root(TAG | 99 << 20), None);
            let roots = at(&sets) - before;
            let before = at(&sets);
            sets.release(taken);
            let releases = at(&sets) - before;
            seen[row] = [takes, finds, roots, releases];
        }
        assert_eq!(seen[0], seen[1]);
        assert!(seen[0][2] <= ROOTS);
        assert!(seen[0].iter().all(|&n| n <= ROOTS + 2));
    }

    /// A walk of the free sets would count the sets in use: the free list
    /// answers `take` at once, whatever the sets hold.
    #[test]
    fn all_the_sets_can_be_taken_once() {
        let mut sets = HoldSets::<C, N>::new();
        let mut seen = std::collections::HashSet::new();
        while let Some(set) = sets.take() {
            assert!(seen.insert(set));
        }
        assert_eq!(seen.len(), N);
        sets.release(7);
        assert_eq!(sets.take(), Some(7));
        assert_eq!(sets.take(), None);
    }

    /// The place of a closed clone goes to a new clone while the set of
    /// the old one waits in the queue of retired sets: the new clone finds
    /// no set until it has made its own, and the old set keeps what it
    /// held.
    #[test]
    fn a_place_given_again_leaves_the_retired_set_alone() {
        let mut clones = Clones::<C>::new();
        let mut sets = HoldSets::<C, N>::new();
        let root = TAG | 1 << 20;
        let old = clones.give_within(TAG, root, C).unwrap();
        let held = sets.take().unwrap();
        sets[held].label = old;
        sets[held].retired = true;
        sets.bind_clone(clones.place_of(old).unwrap(), held);
        // The end of the clone: its set is unbound first, then its place
        // is freed, and the set stays out of the free list.
        assert_eq!(sets.unbind(old, &clones), Some(held));
        clones.gone(old);
        assert_eq!(sets.find(old, &clones), None);
        // The place comes again for another clone (the free list gives
        // the last freed place first).
        let new = clones.give_within(TAG, root, C).unwrap();
        assert_eq!(new & 0xffff, old & 0xffff, "the same place");
        assert_eq!(sets.find(new, &clones), None);
        let fresh = sets.take().unwrap();
        assert_ne!(fresh, held, "the set in the queue is not free");
        sets.bind_clone(clones.place_of(new).unwrap(), fresh);
        assert_eq!(sets.find(new, &clones), Some(fresh));
        assert_eq!(sets[held].label, old);
        assert!(sets[held].retired);
        // Only the queue's release frees it.
        sets.release(held);
        assert_eq!(sets.find(new, &clones), Some(fresh));
    }

    /// A root finds its set; the ROOTS+1st gets a refusal; a root's end
    /// frees its entry.
    #[test]
    fn roots_are_found_and_are_at_most_roots() {
        let mut clones = Clones::<C>::new();
        let mut sets = filled(&mut clones, 0, ROOTS);
        let label = |i: u64| TAG | (i + 1) << 20;
        for i in 0..ROOTS as u64 {
            assert!(sets.for_root(label(i)).is_some());
        }
        let extra = sets.take().unwrap();
        assert!(!sets.bind_root(label(ROOTS as u64), extra));
        let first = sets.unbind(label(0), &clones).unwrap();
        assert_eq!(sets.for_root(label(0)), None);
        assert!(sets.bind_root(label(ROOTS as u64), extra));
        assert_eq!(sets.for_root(label(ROOTS as u64)), Some(extra));
        sets.release(first);
    }

    /// A set that is still bound to a clone is not given back.
    #[test]
    #[should_panic]
    fn a_bound_set_is_not_released() {
        let mut clones = Clones::<C>::new();
        let mut sets = filled(&mut clones, 1, 0);
        let set = sets.for_clone(0).unwrap();
        sets.release(set);
    }
}
