// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the images the service keeps: a ring of `N` slots in which the
//! oldest entry goes when a new one comes, and for the surfaces a caller names by a
//! number of its own (a hint) the slot each was last found in, so that a lookup on
//! the path of a band is one comparison whatever the table holds. A hint is only a
//! guess: the slot it names is used when its key is the key looked for, and
//! otherwise (the slot was taken by another surface, or the hint is new) the table
//! is looked through and the hint is set again, so that a stale hint never gives the
//! image of another surface.

/// A ring of `N` entries of a key and a value, with `H` hints.
pub struct Kept<K, V, const N: usize, const H: usize> {
    slots: [Option<(K, V)>; N],
    next: usize,
    /// For each hint, the slot it was last found in, plus one (0 is none).
    hints: [u8; H],
    /// The entries compared in all (host tests and the feature `scan-count`).
    #[cfg(any(test, feature = "scan-count"))]
    scanned: u32,
}

impl<K: Copy + PartialEq, V, const N: usize, const H: usize> Kept<K, V, N, H> {
    const FITS: () = assert!(N >= 1 && N < 256);

    pub const fn new() -> Self {
        let () = Self::FITS;
        Kept {
            slots: [const { None }; N],
            next: 0,
            hints: [0; H],
            #[cfg(any(test, feature = "scan-count"))]
            scanned: 0,
        }
    }

    #[inline]
    fn count(&mut self, _entries: u32) {
        #[cfg(any(test, feature = "scan-count"))]
        {
            self.scanned = self.scanned.wrapping_add(_entries);
        }
    }

    /// The entries compared in all (0 without the host tests or the feature
    /// `scan-count`).
    pub fn scanned(&self) -> u32 {
        #[cfg(any(test, feature = "scan-count"))]
        {
            self.scanned
        }
        #[cfg(not(any(test, feature = "scan-count")))]
        {
            0
        }
    }

    /// The slot of `key`: the one `hint` names when it holds the key (one
    /// comparison), else the first in the ring that does, which the hint then
    /// names. A `hint` of `H` or more names none.
    pub fn find(&mut self, key: &K, hint: usize) -> Option<usize> {
        if hint < H {
            let at = usize::from(self.hints[hint]);
            if at != 0 {
                self.count(1);
                if let Some((k, _)) = &self.slots[at - 1]
                    && k == key
                {
                    return Some(at - 1);
                }
            }
        }
        let mut seen = 0;
        let mut found = None;
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some((k, _)) = slot {
                seen += 1;
                if k == key {
                    found = Some(i);
                    break;
                }
            }
        }
        self.count(seen);
        if let Some(i) = found
            && hint < H
        {
            self.hints[hint] = (i + 1) as u8;
        }
        found
    }

    /// `value` joins the ring under `key`, in the place of the oldest entry (which
    /// is dropped), and `hint` names its slot: the slot.
    pub fn insert(&mut self, key: K, value: V, hint: usize) -> usize {
        let at = self.next;
        self.next = (self.next + 1) % N;
        self.slots[at] = Some((key, value));
        if hint < H {
            self.hints[hint] = (at + 1) as u8;
        }
        at
    }

    /// The value in `slot` (a slot `find` or `insert` gave).
    pub fn value(&self, slot: usize) -> Option<&V> {
        self.slots[slot].as_ref().map(|(_, v)| v)
    }
}

impl<K: Copy + PartialEq, V, const N: usize, const H: usize> Default for Kept<K, V, N, H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Table = Kept<u32, u32, 4, 8>;

    /// What a lookup does with the image of a key: found by hint, found by
    /// looking through the ring, or made.
    fn get(t: &mut Table, key: u32, hint: usize, made: &mut u32) -> u32 {
        match t.find(&key, hint) {
            Some(slot) => *t.value(slot).unwrap(),
            None => {
                *made += 1;
                let slot = t.insert(key, key * 10, hint);
                *t.value(slot).unwrap()
            }
        }
    }

    #[test]
    fn a_hint_finds_its_slot_with_one_comparison() {
        let mut t = Table::new();
        let mut made = 0;
        for k in 1..=3 {
            assert_eq!(get(&mut t, k, k as usize, &mut made), k * 10);
        }
        assert_eq!(made, 3);
        let before = t.scanned();
        // The third is the last in the ring: the hint goes straight to it.
        assert_eq!(get(&mut t, 3, 3, &mut made), 30);
        assert_eq!(t.scanned() - before, 1);
        assert_eq!(made, 3);
        // With no hint the ring is looked through.
        let before = t.scanned();
        assert_eq!(get(&mut t, 3, 99, &mut made), 30);
        assert_eq!(t.scanned() - before, 3);
    }

    #[test]
    fn a_hint_gone_stale_after_an_eviction_falls_back_and_never_gives_another_image() {
        let mut t = Table::new();
        let mut made = 0;
        for k in 1..=4 {
            get(&mut t, k, k as usize, &mut made);
        }
        // Key 5 takes the slot of key 1 (the oldest).
        get(&mut t, 5, 5, &mut made);
        assert_eq!(made, 5);
        // Hint 1 still names that slot: it holds key 5, so key 1 is not found there
        // and is made again (it never gets the image of key 5), and then the hint is
        // right.
        assert_eq!(get(&mut t, 1, 1, &mut made), 10);
        assert_eq!(made, 6);
        let before = t.scanned();
        assert_eq!(get(&mut t, 1, 1, &mut made), 10);
        assert_eq!(t.scanned() - before, 1);
        // The making of key 1 took the slot of the next oldest key: whatever is
        // looked for is found or made, never mixed up with another.
        for k in 1..=5 {
            assert_eq!(get(&mut t, k, k as usize, &mut made), k * 10);
        }
    }

    #[test]
    fn a_slot_reused_by_another_buffer_is_told_by_its_key() {
        let mut t = Table::new();
        let mut made = 0;
        get(&mut t, 7, 0, &mut made);
        // Two hints for one surface, and the slot is taken by another key.
        assert_eq!(get(&mut t, 7, 1, &mut made), 70);
        for k in 20..24 {
            get(&mut t, k, 2, &mut made);
        }
        assert!(t.find(&7, 0).is_none());
        assert!(t.find(&7, 1).is_none());
        for k in 20..24 {
            let slot = t.find(&k, 5).unwrap();
            assert_eq!(*t.value(slot).unwrap(), k * 10);
        }
    }

    /// A band of eight layers (eight sources and the target) looks at the same number
    /// of entries whatever else the table holds: the linear find that this replaces
    /// looks at more with every entry before the ones wanted.
    #[test]
    fn a_band_of_eight_layers_looks_at_no_more_entries_with_other_sources_in_the_table() {
        type Big = Kept<u32, u32, 32, 32>;
        let band = |others: u32| {
            let mut t = Big::new();
            let mut made = 0u32;
            let mut look = |t: &mut Big, key: u32, hint: usize| match t.find(&key, hint) {
                Some(_) => {}
                None => {
                    made += 1;
                    t.insert(key, key, hint);
                }
            };
            // The others first (older), then the target and the eight sources.
            for o in 0..others {
                look(&mut t, 1000 + o, 31 - (o as usize % 20));
            }
            look(&mut t, 1, 0);
            for s in 0..8u32 {
                look(&mut t, 100 + s, 1 + s as usize);
            }
            // The first band made them; the next ones are measured.
            let before = t.scanned();
            for _ in 0..4 {
                look(&mut t, 1, 0);
                for s in 0..8u32 {
                    look(&mut t, 100 + s, 1 + s as usize);
                }
            }
            t.scanned() - before
        };
        let none = band(0);
        let sixteen = band(16);
        assert_eq!(none, 4 * 9);
        assert!(sixteen <= none, "{sixteen} > {none}");
    }
}
