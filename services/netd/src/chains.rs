// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The places that are bound, in a chain for each port: the check of a new
//! bind (`ports::conflicts`) looks at the places of that port alone, not at
//! every place of the table, so BIND costs the same at 8 places and at 1 280.
//! The head of the chain of a port is in a table of 65 536 entries; each
//! place has its next and its previous in the chain, so a place goes out in
//! O(1) (the accepted sockets of a server all share its port, and 500 of them
//! made a walk of the chain cost 3 000 ticks). A place is 1 more than its
//! index in the tables (0 means none), so that the table is all zeros at the
//! start.

/// The ports.
const PORTS: usize = 65_536;
/// The words of the bitmap of the places in a chain: 4 096 places at most.
const WORDS: usize = 64;

/// The chains of the places of `N`.
pub struct PortChains<const N: usize> {
    heads: [u16; PORTS],
    next: [u16; N],
    previous: [u16; N],
    port: [u16; N],
    linked: [u64; WORDS],
}

impl<const N: usize> PortChains<N> {
    pub const fn new() -> Self {
        assert!(N < u16::MAX as usize && N <= WORDS * 64);
        PortChains {
            heads: [0; PORTS],
            next: [0; N],
            previous: [0; N],
            port: [0; N],
            linked: [0; WORDS],
        }
    }

    /// Whether place `i` is in a chain.
    pub fn is_linked(&self, i: usize) -> bool {
        self.linked[i / 64] >> (i % 64) & 1 != 0
    }

    /// Puts place `i` at the head of the chain of `port`; nothing when it is in
    /// a chain already.
    pub fn link(&mut self, i: usize, port: u16) {
        if self.is_linked(i) {
            return;
        }
        self.linked[i / 64] |= 1 << (i % 64);
        self.port[i] = port;
        let head = self.heads[usize::from(port)];
        self.next[i] = head;
        self.previous[i] = 0;
        if head != 0 {
            self.previous[usize::from(head) - 1] = i as u16 + 1;
        }
        self.heads[usize::from(port)] = i as u16 + 1;
    }

    /// Takes place `i` out of its chain in O(1); nothing when it is in none.
    pub fn unlink(&mut self, i: usize) {
        if !self.is_linked(i) {
            return;
        }
        self.linked[i / 64] &= !(1 << (i % 64));
        let (before, after) = (self.previous[i], self.next[i]);
        if before == 0 {
            self.heads[usize::from(self.port[i])] = after;
        } else {
            self.next[usize::from(before) - 1] = after;
        }
        if after != 0 {
            self.previous[usize::from(after) - 1] = before;
        }
        self.next[i] = 0;
        self.previous[i] = 0;
    }

    /// The places in the chain of `port`.
    pub fn chain(&self, port: u16) -> impl Iterator<Item = usize> + '_ {
        core::iter::successors(
            (self.heads[usize::from(port)] != 0)
                .then(|| usize::from(self.heads[usize::from(port)]) - 1),
            |&i| (self.next[i] != 0).then(|| usize::from(self.next[i]) - 1),
        )
    }
}

impl<const N: usize> Default for PortChains<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain_of(c: &PortChains<64>, port: u16) -> Vec<usize> {
        c.chain(port).collect()
    }

    #[test]
    fn a_place_is_in_the_chain_of_its_port_alone() {
        let mut c = PortChains::<64>::new();
        c.link(3, 80);
        c.link(5, 80);
        c.link(7, 443);
        assert_eq!(chain_of(&c, 80), vec![5, 3]);
        assert_eq!(chain_of(&c, 443), vec![7]);
        assert_eq!(chain_of(&c, 81), Vec::<usize>::new());
        // Linked again, a place stays where it is.
        c.link(3, 443);
        assert_eq!(chain_of(&c, 80), vec![5, 3]);
        assert_eq!(chain_of(&c, 443), vec![7]);
    }

    #[test]
    fn the_head_the_middle_and_the_tail_go_out_of_a_chain() {
        let mut c = PortChains::<64>::new();
        for i in [1, 2, 3, 4] {
            c.link(i, 9);
        }
        assert_eq!(chain_of(&c, 9), vec![4, 3, 2, 1]);
        c.unlink(3);
        assert_eq!(chain_of(&c, 9), vec![4, 2, 1]);
        c.unlink(4);
        assert_eq!(chain_of(&c, 9), vec![2, 1]);
        c.unlink(1);
        assert_eq!(chain_of(&c, 9), vec![2]);
        c.unlink(2);
        assert_eq!(chain_of(&c, 9), Vec::<usize>::new());
        c.unlink(2);
        assert!(!c.is_linked(2));
        c.link(2, 10);
        assert_eq!(chain_of(&c, 10), vec![2]);
    }

    #[test]
    fn a_thousand_places_on_one_port_are_all_in_the_chain() {
        let mut c = PortChains::<1280>::new();
        for i in 0..1280 {
            c.link(i, 8080);
        }
        assert_eq!(c.chain(8080).count(), 1280);
        for i in (0..1280).step_by(2) {
            c.unlink(i);
        }
        assert_eq!(c.chain(8080).count(), 640);
        assert!(c.chain(8080).all(|i| i % 2 == 1));
    }
}
