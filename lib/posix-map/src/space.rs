// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What each page of the layer's room is for (spec 2, 3.4): two bits a page.
//! The room holds the chunks of the layer's heap and the objects of the
//! program's own mappings. A page of the room is not backed by any
//! object, backed and free, taken from a chunk of the heap (by `mmap` or by
//! the layer), or in an object made for one mapping.

use crate::PAGE;

/// The pages of the room: 256 MiB.
pub const ROOM_PAGES: usize = 65536;

/// What a page is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    /// No object shows the page.
    Unbacked = 0,
    /// A chunk of the heap shows it and nobody uses it.
    Free = 1,
    /// Taken from a chunk of the heap: it goes back to Free (and loses its
    /// access) when its owner gives it up.
    User = 2,
    /// In an object made for the mapping (large, shared or from a file):
    /// it goes back to Unbacked when unmapped.
    Own = 3,
}

impl State {
    fn from_bits(bits: u8) -> State {
        match bits & 3 {
            0 => State::Unbacked,
            1 => State::Free,
            2 => State::User,
            _ => State::Own,
        }
    }
}

/// The states of the pages of a room that starts at `base`.
pub struct Space {
    bits: [u8; ROOM_PAGES / 4],
    base: usize,
}

impl Space {
    /// A room of ROOM_PAGES pages from `base`, all unbacked: all zeros, so
    /// that it lies in the program's zeroed data.
    pub const fn new(base: usize) -> Space {
        Space {
            bits: [0; ROOM_PAGES / 4],
            base,
        }
    }

    pub const fn base(&self) -> usize {
        self.base
    }

    pub const fn limit(&self) -> usize {
        self.base + ROOM_PAGES * PAGE
    }

    fn index(&self, address: usize) -> Option<usize> {
        let page = address.checked_sub(self.base)? / PAGE;
        (page < ROOM_PAGES).then_some(page)
    }

    /// The state of the page at `address`; None outside the room.
    pub fn get(&self, address: usize) -> Option<State> {
        let page = self.index(address)?;
        Some(State::from_bits(self.bits[page / 4] >> (2 * (page % 4))))
    }

    fn put(&mut self, page: usize, state: State) {
        let shift = 2 * (page % 4);
        let byte = &mut self.bits[page / 4];
        *byte = (*byte & !(3 << shift)) | ((state as u8) << shift);
    }

    /// Sets `pages` pages from `address`; false (nothing set) when the range
    /// leaves the room.
    pub fn set(&mut self, address: usize, pages: usize, state: State) -> bool {
        let Some(first) = self.index(address) else {
            return false;
        };
        if first + pages > ROOM_PAGES || !address.is_multiple_of(PAGE) {
            return false;
        }
        for page in first..first + pages {
            self.put(page, state);
        }
        true
    }

    /// Whether all `pages` pages from `address` are in `state`.
    pub fn all(&self, address: usize, pages: usize, state: State) -> bool {
        let Some(first) = self.index(address) else {
            return false;
        };
        first + pages <= ROOM_PAGES
            && (first..first + pages)
                .all(|page| State::from_bits(self.bits[page / 4] >> (2 * (page % 4))) == state)
    }

    /// How many pages are in `state`.
    pub fn count(&self, state: State) -> usize {
        (0..ROOM_PAGES)
            .filter(|page| State::from_bits(self.bits[page / 4] >> (2 * (page % 4))) == state)
            .count()
    }

    /// The address of the first run of `pages` pages in `state`, from the
    /// bottom of the room, or from the top when `from_top`.
    pub fn find(&self, pages: usize, state: State, from_top: bool) -> Option<usize> {
        if pages == 0 || pages > ROOM_PAGES {
            return None;
        }
        let state_at =
            |page: usize| State::from_bits(self.bits[page / 4] >> (2 * (page % 4))) == state;
        let mut run = 0;
        if from_top {
            for page in (0..ROOM_PAGES).rev() {
                if state_at(page) {
                    run += 1;
                    if run == pages {
                        return Some(self.base + page * PAGE);
                    }
                } else {
                    run = 0;
                }
            }
        } else {
            for page in 0..ROOM_PAGES {
                if state_at(page) {
                    run += 1;
                    if run == pages {
                        return Some(self.base + (page + 1 - pages) * PAGE);
                    }
                } else {
                    run = 0;
                }
            }
        }
        None
    }

    /// The length in pages of the longest run in `state`.
    pub fn longest(&self, state: State) -> usize {
        let mut best = 0;
        let mut run = 0;
        for page in 0..ROOM_PAGES {
            if State::from_bits(self.bits[page / 4] >> (2 * (page % 4))) == state {
                run += 1;
                best = best.max(run);
            } else {
                run = 0;
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: usize = 0x1000_0000;

    #[test]
    fn a_new_room_is_unbacked_and_a_run_is_found_from_either_end() {
        let mut space = Space::new(BASE);
        assert_eq!(space.limit(), 0x2000_0000);
        assert_eq!(space.find(16, State::Unbacked, false), Some(BASE));
        assert_eq!(
            space.find(16, State::Unbacked, true),
            Some(0x2000_0000 - 16 * PAGE)
        );
        assert!(space.set(BASE, 16, State::Free));
        assert_eq!(space.get(BASE + 15 * PAGE), Some(State::Free));
        assert_eq!(space.get(BASE + 16 * PAGE), Some(State::Unbacked));
        assert_eq!(
            space.find(4, State::Unbacked, false),
            Some(BASE + 16 * PAGE)
        );
        assert_eq!(space.find(16, State::Free, true), Some(BASE));
        assert_eq!(space.find(17, State::Free, false), None);
    }

    #[test]
    fn runs_are_cut_by_other_states_and_ranges_outside_the_room_are_refused() {
        let mut space = Space::new(BASE);
        space.set(BASE, 8, State::Free);
        space.set(BASE + 3 * PAGE, 1, State::User);
        assert_eq!(space.find(4, State::Free, false), Some(BASE + 4 * PAGE));
        assert_eq!(space.find(3, State::Free, false), Some(BASE));
        assert_eq!(space.longest(State::Free), 4);
        assert!(!space.set(BASE - PAGE, 1, State::User));
        assert!(!space.set(0x2000_0000 - PAGE, 2, State::User));
        assert_eq!(space.get(0x2000_0000), None);
        assert!(space.all(BASE + 4 * PAGE, 4, State::Free));
        assert!(!space.all(BASE, 8, State::Free));
        assert_eq!(space.count(State::User), 1);
    }
}
