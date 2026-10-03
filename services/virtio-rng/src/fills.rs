// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The fills the clients wait for (proto_entropy): FILLS at most, each the
//! `n` bytes a client asked for under the key of its long operation. The
//! device serves them in the order they came, one request at a time
//! (`wanted`); its bytes go into the fill (`put`) until it has `n`, and
//! the client takes them once (`take`); the fill's bytes are erased with
//! volatile stores as it goes (taken, cancelled, or its client gone). A
//! fill whose client cancelled or went leaves at once; bytes the device
//! still brings for it find no fill and go nowhere. Each step is O(FILLS).

use proto_entropy::FILL_MAX;

/// The fills the driver holds at once.
pub const FILLS: usize = 4;

const MAX: usize = FILL_MAX as usize;

/// One fill: its client and key, the bytes asked for and those that came.
/// Not Copy: a copy of its bytes left on the stack would outlive the fill.
#[derive(Debug, PartialEq, Eq)]
struct Fill {
    label: u64,
    key: u64,
    /// Its place in the order the fills came.
    order: u64,
    n: usize,
    got: usize,
    bytes: [u8; MAX],
}

/// What `take` found for a fill.
#[derive(Debug, PartialEq, Eq)]
pub enum Taken {
    /// Its bytes, all `n` of them; the fill went.
    Ready(usize),
    /// It still waits for the device.
    Waits,
    /// No such fill.
    Unknown,
}

#[derive(Debug)]
pub struct Fills {
    fills: [Option<Fill>; FILLS],
    next_order: u64,
}

impl Default for Fills {
    fn default() -> Self {
        Self::new()
    }
}

impl Fills {
    pub const fn new() -> Fills {
        Fills {
            fills: [const { None }; FILLS],
            next_order: 0,
        }
    }

    fn place(&self, label: u64, key: u64) -> Option<usize> {
        self.fills
            .iter()
            .position(|f| f.as_ref().is_some_and(|f| f.label == label && f.key == key))
    }

    /// A fill of `n` bytes, 1 to FILL_MAX, for the key `key` of the client
    /// `label`; false when FILLS wait already.
    pub fn add(&mut self, label: u64, key: u64, n: usize) -> bool {
        let Some(free) = self.fills.iter().position(Option::is_none) else {
            return false;
        };
        self.fills[free] = Some(Fill {
            label,
            key,
            order: self.next_order,
            n: n.clamp(1, MAX),
            got: 0,
            bytes: [0; MAX],
        });
        self.next_order += 1;
        true
    }

    /// The fill the device serves next, the oldest that still waits for
    /// bytes: its client, key and the bytes it lacks.
    pub fn wanted(&self) -> Option<(u64, u64, usize)> {
        self.fills
            .iter()
            .flatten()
            .filter(|f| f.got < f.n)
            .min_by_key(|f| f.order)
            .map(|f| (f.label, f.key, f.n - f.got))
    }

    /// Bytes the device brought for the fill of `label` and `key`, as many
    /// as it lacks; true when it now has all it asked for. Bytes for a
    /// fill that went are dropped.
    pub fn put(&mut self, label: u64, key: u64, bytes: &[u8]) -> bool {
        let Some(i) = self.place(label, key) else {
            return false;
        };
        let f = self.fills[i].as_mut().expect("a placed fill");
        let n = bytes.len().min(f.n - f.got);
        f.bytes[f.got..f.got + n].copy_from_slice(&bytes[..n]);
        f.got += n;
        f.got == f.n
    }

    /// The bytes of the fill of `label` and `key` into `out` once it has
    /// them all: the fill goes, and its bytes with it.
    pub fn take(&mut self, label: u64, key: u64, out: &mut [u8]) -> Taken {
        let Some(i) = self.place(label, key) else {
            return Taken::Unknown;
        };
        let f = self.fills[i].as_mut().expect("a placed fill");
        if f.got < f.n {
            return Taken::Waits;
        }
        let n = f.n.min(out.len());
        out[..n].copy_from_slice(&f.bytes[..n]);
        self.drop_fill(i);
        Taken::Ready(n)
    }

    /// The fill of `label` and `key` goes, whatever it holds; false for
    /// none.
    pub fn cancel(&mut self, label: u64, key: u64) -> bool {
        match self.place(label, key) {
            Some(i) => {
                self.drop_fill(i);
                true
            }
            None => false,
        }
    }

    /// The client `label` went: its fills go.
    pub fn gone(&mut self, label: u64) {
        for i in 0..FILLS {
            if self.fills[i].as_ref().is_some_and(|f| f.label == label) {
                self.drop_fill(i);
            }
        }
    }

    /// The fill at `i` goes, its bytes erased first (`wipe`).
    fn drop_fill(&mut self, i: usize) {
        self.wipe(i);
        self.fills[i] = None;
    }

    /// Erases the bytes of the fill at `i` in place, with volatile stores,
    /// which no compiler drops as dead.
    fn wipe(&mut self, i: usize) {
        if let Some(f) = self.fills[i].as_mut() {
            posix_random::erase(&mut f.bytes);
        }
    }

    /// The fills held.
    pub fn len(&self) -> usize {
        self.fills.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_are_served_in_their_order_and_taken_once() {
        let mut f = Fills::new();
        assert!(f.add(7, 1, 64));
        assert!(f.add(8, 1, 32));
        assert_eq!(f.wanted(), Some((7, 1, 64)));
        // The device may bring fewer bytes than asked: the fill waits on.
        assert!(!f.put(7, 1, &[1; 40]));
        assert_eq!(f.wanted(), Some((7, 1, 24)));
        let mut out = [0; 256];
        assert_eq!(f.take(7, 1, &mut out), Taken::Waits);
        assert!(f.put(7, 1, &[2; 40]));
        assert_eq!(f.wanted(), Some((8, 1, 32)));
        assert_eq!(f.take(7, 1, &mut out), Taken::Ready(64));
        assert_eq!(&out[..40], &[1; 40]);
        assert_eq!(&out[40..64], &[2; 24]);
        // Taken once: the driver keeps no copy.
        assert_eq!(f.take(7, 1, &mut out), Taken::Unknown);
        assert_eq!(f.len(), 1);
    }

    /// The bytes of a fill are erased in its place before it goes, however
    /// it goes (taken, cancelled, its client gone: each through
    /// `drop_fill`, which wipes first).
    #[test]
    fn the_bytes_of_a_fill_are_erased_before_it_goes() {
        let mut f = Fills::new();
        assert!(f.add(1, 1, 32));
        assert!(f.put(1, 1, &[0xee; 32]));
        f.wipe(0);
        let kept = f.fills[0].as_ref().map(|fill| fill.bytes[..32].to_vec());
        assert_eq!(kept, Some(vec![0; 32]));
        assert!(f.add(1, 2, 32) && f.add(2, 3, 32));
        let mut out = [0; MAX];
        assert!(f.put(1, 2, &[0xee; 32]));
        assert_eq!(f.take(1, 2, &mut out), Taken::Ready(32));
        assert_eq!(out[..32], [0xee; 32]);
        assert!(f.cancel(1, 1));
        f.gone(2);
        assert!(f.is_empty());
    }

    #[test]
    fn a_fill_of_another_client_is_not_found() {
        let mut f = Fills::new();
        assert!(f.add(7, 1, 32));
        assert!(f.put(7, 1, &[3; 32]));
        let mut out = [0; 256];
        assert_eq!(f.take(8, 1, &mut out), Taken::Unknown);
        assert_eq!(f.take(7, 2, &mut out), Taken::Unknown);
        assert!(!f.cancel(8, 1));
        assert_eq!(f.take(7, 1, &mut out), Taken::Ready(32));
    }

    #[test]
    fn at_most_fills_wait_and_those_of_a_client_that_went_go() {
        let mut f = Fills::new();
        for key in 1..=FILLS as u64 {
            assert!(f.add(key % 2, key, 32));
        }
        assert!(!f.add(9, 9, 32));
        f.gone(1);
        assert_eq!(f.len(), FILLS / 2);
        assert!(f.cancel(0, 2));
        // Bytes the device brings for a fill that went go nowhere.
        assert!(!f.put(0, 2, &[1; 32]));
        assert!(!f.put(1, 1, &[1; 32]));
        assert_eq!(f.wanted(), Some((0, 4, 32)));
        assert!(f.add(9, 9, 32));
        assert_eq!(f.wanted(), Some((0, 4, 32)));
    }
}
