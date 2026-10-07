// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Genuine session labels retain an exact place until their final CLIENT_GONE.
//! Interior cells are accessed only by the single RAM service thread.

use core::cell::Cell;
use proto_fs::{IMAGE_SESSION, OWN};

pub const COUNT: usize = 320;
const NONE: u16 = u16::MAX;
pub struct Places {
    labels: [Cell<u64>; COUNT],
    next: [Cell<u16>; COUNT],
    head: Cell<u16>,
}
impl Places {
    pub const fn new() -> Self {
        let mut next = [const { Cell::new(NONE) }; COUNT];
        let mut i = 1;
        while i + 1 < COUNT {
            next[i] = Cell::new((i + 1) as u16);
            i += 1;
        }
        Self {
            labels: [const { Cell::new(0) }; COUNT],
            next,
            head: Cell::new(1),
        }
    }
    fn allocate(&self, label: impl FnOnce(u16) -> u64) -> Option<u64> {
        let slot = self.head.get();
        if slot == NONE {
            return None;
        }
        self.head.set(self.next[slot as usize].get());
        let label = label(slot);
        self.labels[slot as usize].set(label);
        Some(label)
    }
    pub fn issue(&self, generation: u64) -> Option<u64> {
        if generation >= 1 << 53 {
            return None;
        }
        self.allocate(|slot| OWN | generation << 9 | u64::from(slot))
    }
    pub fn place(&self, label: u64) -> usize {
        if label & (OWN | IMAGE_SESSION) == OWN | IMAGE_SESSION {
            return 0;
        }
        if label & OWN != 0 {
            let slot = (label & 511) as usize;
            return if slot != 0 && slot < COUNT && self.labels[slot].get() == label {
                slot
            } else {
                COUNT
            };
        }
        // Named init principals are admitted once; ordinary issued clients use
        // the exact slot above, including while their descriptors are births.
        if let Some(slot) = self
            .labels
            .iter()
            .position(|s| s.get() == label && label != 0)
        {
            return slot;
        }
        let slot = self.head.get();
        if label == 0 || self.allocate(|_| label).is_none() {
            COUNT
        } else {
            slot as usize
        }
    }
    pub fn release(&self, label: u64) {
        if label & (OWN | IMAGE_SESSION) == OWN | IMAGE_SESSION {
            return;
        }
        let slot = if label & OWN != 0 {
            (label & 511) as usize
        } else {
            self.labels
                .iter()
                .position(|s| s.get() == label && label != 0)
                .unwrap_or(COUNT)
        };
        if slot == 0 || slot >= COUNT || self.labels[slot].get() != label {
            return;
        }
        self.labels[slot].set(0);
        self.next[slot].set(self.head.get());
        self.head.set(slot as u16);
    }
}
impl Default for Places {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_admitted_session_has_a_distinct_place_and_exhaustion_does_not_evict() {
        let places = Places::new();
        let named = places.place(17);
        let mut labels = [0; COUNT - 2];
        for (generation, label) in labels.iter_mut().enumerate() {
            *label = places.issue(generation as u64).unwrap();
            assert_ne!(places.place(*label), named);
            assert_eq!(places.place(*label), (*label & 511) as usize);
        }
        assert_eq!(places.issue(319), None);
        assert_eq!(places.place(18), COUNT);
        assert_eq!(places.place(17), named);
        for label in labels {
            assert!(places.place(label) < COUNT);
        }
    }
    #[test]
    fn reused_place_requires_its_full_generation_and_old_cleanup_cannot_free_it() {
        let places = Places::new();
        let old = places.issue(0).unwrap();
        places.release(old);
        let new = places.issue(1).unwrap();
        assert_eq!(old & 511, new & 511);
        assert_eq!(places.place(old), COUNT);
        assert!(places.place(new) < COUNT);
        places.release(old);
        assert!(places.place(new) < COUNT);
        assert_eq!(places.issue(1 << 53), None);
        places.release(new);
        assert_eq!(places.place(new), COUNT);
        assert_eq!(places.place(proto_fs::image_label(10, 12)), 0);
    }
}
