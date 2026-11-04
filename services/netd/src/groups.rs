// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A set of the groups of sockets, one bit each, in as many words as the
//! groups need: the service has 320 groups at 1 280 places, more than the
//! 64 a word holds. Every walk goes a word at a time.

/// The groups of `W` words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupMask<const W: usize>([u64; W]);

impl<const W: usize> GroupMask<W> {
    pub const EMPTY: Self = Self([0; W]);

    pub fn set(&mut self, g: usize) {
        self.0[g / 64] |= 1 << (g % 64);
    }

    pub fn clear(&mut self, g: usize) {
        self.0[g / 64] &= !(1 << (g % 64));
    }

    pub fn has(&self, g: usize) -> bool {
        self.0[g / 64] >> (g % 64) & 1 != 0
    }

    pub fn any(&self) -> bool {
        self.0.iter().any(|&w| w != 0)
    }

    /// The groups 0 to `count`, all of them.
    pub fn set_below(&mut self, count: usize) {
        for (i, word) in self.0.iter_mut().enumerate() {
            let low = i * 64;
            if count >= low + 64 {
                *word = u64::MAX;
            } else if count > low {
                *word |= (1u64 << (count - low)) - 1;
            }
        }
    }

    /// The lowest group at or after `from`.
    pub fn next(&self, from: usize) -> Option<usize> {
        let mut word = from / 64;
        if word >= W {
            return None;
        }
        let mut bits = self.0[word] & (!0u64 << (from % 64));
        loop {
            if bits != 0 {
                return Some(word * 64 + bits.trailing_zeros() as usize);
            }
            word += 1;
            bits = *self.0.get(word)?;
        }
    }

    /// The set, which is empty afterwards.
    pub fn take(&mut self) -> Self {
        core::mem::replace(self, Self::EMPTY)
    }
}

impl<const W: usize> Default for GroupMask<W> {
    fn default() -> Self {
        Self::EMPTY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_past_the_first_word_are_kept() {
        let mut m = GroupMask::<5>::EMPTY;
        assert!(!m.any());
        for g in [0, 63, 64, 130, 319] {
            m.set(g);
        }
        assert!(m.any() && m.has(319) && m.has(64) && !m.has(65));
        assert_eq!(m.next(0), Some(0));
        assert_eq!(m.next(1), Some(63));
        assert_eq!(m.next(64), Some(64));
        assert_eq!(m.next(65), Some(130));
        assert_eq!(m.next(131), Some(319));
        assert_eq!(m.next(320), None);
        m.clear(130);
        assert_eq!(m.next(65), Some(319));
        let taken = m.take();
        assert!(!m.any() && taken.has(0));
    }

    #[test]
    fn set_below_names_the_first_groups() {
        let mut m = GroupMask::<5>::EMPTY;
        m.set_below(320);
        assert!(m.has(0) && m.has(319));
        let mut n = GroupMask::<5>::EMPTY;
        n.set_below(70);
        assert!(n.has(69) && !n.has(70) && n.has(0) && !n.has(128));
        let mut e = GroupMask::<1>::EMPTY;
        e.set_below(64);
        assert!(e.has(63));
        e.set_below(0);
    }
}
