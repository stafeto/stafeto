// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Slots whose real descriptions are released one per service step.

pub struct Retired<const N: usize> {
    slots: [usize; N],
    head: usize,
    len: usize,
}

impl<const N: usize> Default for Retired<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Retired<N> {
    pub const fn new() -> Self {
        Self {
            slots: [0; N],
            head: 0,
            len: 0,
        }
    }

    /// Each live slot enters once and leaves before it can be reused.
    pub fn push(&mut self, slot: usize) -> bool {
        if self.len == N {
            return false;
        }
        self.slots[(self.head + self.len) % N] = slot;
        self.len += 1;
        true
    }

    pub fn first(&self) -> Option<usize> {
        (self.len != 0).then(|| self.slots[self.head])
    }

    pub fn pop(&mut self) -> Option<usize> {
        let slot = self.first()?;
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_queue_preserves_order_and_reused_slots_across_wrap() {
        let mut q = Retired::<3>::new();
        for slot in [7, 8, 9] {
            assert!(q.push(slot));
        }
        assert!(!q.push(10));
        assert_eq!(q.pop(), Some(7));
        assert!(q.push(7));
        for slot in [8, 9, 7] {
            assert_eq!(q.pop(), Some(slot));
        }
        assert_eq!(q.pop(), None);
        assert!(q.push(8));
        assert_eq!(q.pop(), Some(8));
    }
}
