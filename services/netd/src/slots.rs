// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The store of the buffers of the sockets, one for the whole service: the stack instances
//! take its slots in chunks of 64 and give them back with the last slot of a chunk. A chunk
//! has one owner at a time (a byte in `Owners`, taken with one compare-and-swap), so the
//! slots of a chunk are handed out and taken back with no atomic operation at all, and the
//! instances share the memory of the old single pool (decision of the instances, 3.6).

use core::sync::atomic::{AtomicU8, Ordering};

/// The slots in a chunk.
pub const CHUNK: usize = 64;

/// Who holds each chunk of a class of slots: 0 for nobody, the instance's number plus one.
pub struct Owners<const CHUNKS: usize>([AtomicU8; CHUNKS]);

impl<const CHUNKS: usize> Owners<CHUNKS> {
    pub const fn new() -> Self {
        Owners([const { AtomicU8::new(0) }; CHUNKS])
    }

    fn take(&self, who: u8) -> Option<usize> {
        (0..CHUNKS).find(|&c| {
            self.0[c]
                .compare_exchange(0, who + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        })
    }

    fn give(&self, chunk: usize, who: u8) {
        let _ = self.0[chunk].compare_exchange(who + 1, 0, Ordering::AcqRel, Ordering::Relaxed);
    }

    /// The chunks `who` holds.
    pub fn held_by(&self, who: u8) -> usize {
        self.0
            .iter()
            .filter(|c| c.load(Ordering::Acquire) == who + 1)
            .count()
    }
}

impl<const CHUNKS: usize> Default for Owners<CHUNKS> {
    fn default() -> Self {
        Self::new()
    }
}

/// An instance's view of a class of slots: for each chunk it holds, a bit for each free slot.
pub struct Local<const CHUNKS: usize> {
    free: [u64; CHUNKS],
    mine: [bool; CHUNKS],
}

impl<const CHUNKS: usize> Local<CHUNKS> {
    pub const fn new() -> Self {
        Local {
            free: [0; CHUNKS],
            mine: [false; CHUNKS],
        }
    }

    /// A free slot: from a chunk the instance holds, else from a chunk it takes from the
    /// store. None when every chunk is held and full.
    pub fn take(&mut self, shared: &Owners<CHUNKS>, who: u8) -> Option<usize> {
        let c = match (0..CHUNKS).find(|&c| self.mine[c] && self.free[c] != 0) {
            Some(c) => c,
            None => {
                let c = shared.take(who)?;
                self.mine[c] = true;
                self.free[c] = !0;
                c
            }
        };
        let bit = self.free[c].trailing_zeros() as usize;
        self.free[c] &= !(1 << bit);
        Some(c * CHUNK + bit)
    }

    /// Gives `slot` back; the chunk goes back to the store when all its slots are free and the
    /// instance holds another chunk with room (one chunk is kept, so a socket that opens and
    /// closes in turn does not take and give a chunk each time).
    pub fn give(&mut self, shared: &Owners<CHUNKS>, who: u8, slot: usize) {
        let (c, bit) = (slot / CHUNK, slot % CHUNK);
        debug_assert!(
            self.mine[c] && self.free[c] >> bit & 1 == 0,
            "a slot of ours"
        );
        self.free[c] |= 1 << bit;
        if self.free[c] == !0 {
            let spare = (0..CHUNKS).any(|o| o != c && self.mine[o] && self.free[o] != 0);
            if spare {
                self.mine[c] = false;
                self.free[c] = 0;
                shared.give(c, who);
            }
        }
    }

    /// The slots in use.
    pub fn used(&self) -> usize {
        (0..CHUNKS)
            .filter(|&c| self.mine[c])
            .map(|c| CHUNK - self.free[c].count_ones() as usize)
            .sum()
    }
}

impl<const CHUNKS: usize> Default for Local<CHUNKS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_instances_never_get_the_same_slot_and_together_take_them_all() {
        let shared = Owners::<4>::new();
        let (mut a, mut b) = (Local::<4>::new(), Local::<4>::new());
        let mut seen = [false; 256];
        for i in 0..256 {
            let (who, local) = if i % 2 == 0 { (1, &mut b) } else { (0, &mut a) };
            let s = local.take(&shared, who).expect("a slot is left");
            assert!(!seen[s], "slot {s} given twice");
            seen[s] = true;
        }
        assert!(a.take(&shared, 0).is_none() && b.take(&shared, 1).is_none());
        assert_eq!(shared.held_by(0) + shared.held_by(1), 4);
    }

    #[test]
    fn a_chunk_goes_back_for_another_instance_when_it_is_free_and_another_has_room() {
        let shared = Owners::<2>::new();
        let (mut a, mut b) = (Local::<2>::new(), Local::<2>::new());
        let first: Vec<usize> = (0..CHUNK + 1)
            .map(|_| a.take(&shared, 0).unwrap())
            .collect();
        assert_eq!(shared.held_by(0), 2);
        assert!(b.take(&shared, 1).is_none(), "both chunks are a's");
        for s in &first[..CHUNK] {
            a.give(&shared, 0, *s);
        }
        assert_eq!(shared.held_by(0), 1, "the free chunk went back");
        assert!(b.take(&shared, 1).is_some());
        assert_eq!(a.used(), 1);
    }

    #[test]
    fn the_last_chunk_is_kept_so_a_socket_that_comes_and_goes_takes_none() {
        let shared = Owners::<2>::new();
        let mut a = Local::<2>::new();
        let s = a.take(&shared, 0).unwrap();
        a.give(&shared, 0, s);
        assert_eq!(shared.held_by(0), 1);
        assert_eq!(a.take(&shared, 0), Some(s));
    }
}
