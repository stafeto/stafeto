// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The bit maps of a session's numbers. A session has `PLACES` places, which
//! seventeen words of 64 bits cover; every search for a free place or a set bit
//! reads at most those seventeen words, whatever the session holds.

/// The places of one session (`proto_fs::SESSION_PLACES`).
pub const PLACES: usize = proto_fs::SESSION_PLACES;
/// The words of a map.
pub const WORDS: usize = PLACES.div_ceil(64);

/// One bit for each place of a session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bits([u64; WORDS]);

impl Bits {
    pub const EMPTY: Self = Self([0; WORDS]);

    pub fn get(&self, place: usize) -> bool {
        self.0
            .get(place / 64)
            .is_some_and(|w| w & (1 << (place % 64)) != 0)
    }
    pub fn set(&mut self, place: usize) {
        debug_assert!(place < PLACES);
        self.0[place / 64] |= 1 << (place % 64);
    }
    pub fn clear(&mut self, place: usize) {
        self.0[place / 64] &= !(1 << (place % 64));
    }
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&w| w == 0)
    }
    pub fn count(&self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }
    /// The first place that is not set, below `PLACES`.
    pub fn first_clear(&self) -> Option<usize> {
        self.0.iter().enumerate().find_map(|(i, &w)| {
            let bit = w.trailing_ones() as usize;
            let place = i * 64 + bit;
            (bit < 64 && place < PLACES).then_some(place)
        })
    }
    /// The first place that is set.
    pub fn first_set(&self) -> Option<usize> {
        self.first_set_of(self, false)
    }
    /// The first place that is set here and not set in `other`.
    pub fn first_set_without(&self, other: &Self) -> Option<usize> {
        self.first_set_of(other, true)
    }
    fn first_set_of(&self, other: &Self, without: bool) -> Option<usize> {
        self.0
            .iter()
            .zip(&other.0)
            .enumerate()
            .find_map(|(i, (&a, &b))| {
                let w = if without { a & !b } else { a };
                (w != 0).then(|| i * 64 + w.trailing_zeros() as usize)
            })
    }
    /// The places that are set here and not set in `other`, in order.
    pub fn iter_without<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = usize> + 'a {
        self.0
            .iter()
            .zip(&other.0)
            .enumerate()
            .flat_map(|(i, (&a, &b))| {
                let mut w = a & !b;
                core::iter::from_fn(move || {
                    (w != 0).then(|| {
                        let bit = w.trailing_zeros() as usize;
                        w &= w - 1;
                        i * 64 + bit
                    })
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_clear_place_spans_every_word_and_stops_at_the_places() {
        let mut taken = Bits::EMPTY;
        for place in 0..PLACES {
            assert_eq!(taken.first_clear(), Some(place));
            taken.set(place);
        }
        assert_eq!(taken.first_clear(), None);
        taken.clear(1000);
        assert_eq!(taken.first_clear(), Some(1000));
        assert_eq!(taken.count(), PLACES - 1);
    }

    #[test]
    fn set_places_are_found_in_order_and_without_the_others() {
        let mut a = Bits::EMPTY;
        let mut b = Bits::EMPTY;
        for place in [3, 64, 65, 700, 1055] {
            a.set(place);
        }
        b.set(3);
        b.set(700);
        assert_eq!(a.first_set(), Some(3));
        assert_eq!(a.first_set_without(&b), Some(64));
        assert!(a.iter_without(&b).eq([64, 65, 1055]));
        assert!(a.get(1055) && !a.get(1072) && !a.get(5000));
    }
}
