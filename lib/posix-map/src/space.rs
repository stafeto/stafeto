// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What each page of the layer's room is for (spec 2, 3.4): two bits a page.
//! The room holds the chunks of the layer's heap and the objects of the
//! program's own mappings. A page of the room is not backed by any
//! object, backed and free, taken from a chunk of the heap (by `mmap` or by
//! the layer), or in an object made for one mapping.

use crate::PAGE;

/// The pages of the room at the start: 32 MiB, the first of the 1 GiB
/// the loader admits for the layer's heap. A process pays for what it maps
/// from its quota (2 MiB by default), and the bitmap lies in the program's
/// data, which the quota pays for.
pub const ROOM_PAGES: usize = 8192;

/// The pages of a room that grew (`Space::extend`): 1 GiB, all the
/// loader admits. Only a process with a quota above 64 MiB asks for it.
pub const ROOM_MAX: usize = 262_144;

/// The bytes of the bitmap of `ROOM_MAX` pages (two bits a page): 16 pages
/// of an object of their own, which a room that grew keeps in itself.
pub const MAX_BITS_BYTES: usize = ROOM_MAX / 4;

/// The pages in a word of the bitmap.
const PER_WORD: usize = 32;
/// The low bit of each two-bit field of a word.
const LOW: u64 = 0x5555_5555_5555_5555;

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

/// The states of the pages of a room that starts at `base`. The bitmap
/// lies inside, for the first ROOM_PAGES pages; a room that grew keeps it in
/// memory `extend` was given.
pub struct Space {
    bits: [u8; ROOM_PAGES / 4],
    base: usize,
    /// The bitmap of a room that grew, null for the one inside.
    grown: *mut u8,
    pages: usize,
}

// SAFETY: the pointer names memory the room owns; the users of a room
// (the heap under its lock) take care of the access.
unsafe impl Send for Space {}

impl Space {
    /// A room of ROOM_PAGES pages from `base`, all unbacked: all zeros, so
    /// that it lies in the program's zeroed data.
    pub const fn new(base: usize) -> Space {
        Space {
            bits: [0; ROOM_PAGES / 4],
            base,
            grown: core::ptr::null_mut(),
            pages: ROOM_PAGES,
        }
    }

    pub const fn base(&self) -> usize {
        self.base
    }

    /// How many pages the room has now.
    pub const fn pages(&self) -> usize {
        self.pages
    }

    pub const fn limit(&self) -> usize {
        self.base + self.pages * PAGE
    }

    /// Whether the room has grown to ROOM_MAX pages.
    pub const fn grown(&self) -> bool {
        !self.grown.is_null()
    }

    /// The room grows to ROOM_MAX pages, with `bits` as its bitmap: the
    /// states of the pages so far are copied into it, the rest are
    /// unbacked (`bits` is zeros).
    ///
    /// # Safety
    /// `bits` names MAX_BITS_BYTES bytes of zeros that no one else uses and
    /// that stay for as long as the room.
    pub unsafe fn extend(&mut self, bits: *mut u8) {
        // SAFETY: the caller's promise gives the bytes.
        unsafe { core::ptr::copy_nonoverlapping(self.bits.as_ptr(), bits, self.bits.len()) };
        self.grown = bits;
        self.pages = ROOM_MAX;
    }

    fn bytes(&self) -> &[u8] {
        if self.grown.is_null() {
            &self.bits
        } else {
            // SAFETY: `extend` was promised MAX_BITS_BYTES bytes.
            unsafe { core::slice::from_raw_parts(self.grown, MAX_BITS_BYTES) }
        }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        if self.grown.is_null() {
            &mut self.bits
        } else {
            // SAFETY: as in `bytes`, and `&mut self` is the only borrow.
            unsafe { core::slice::from_raw_parts_mut(self.grown, MAX_BITS_BYTES) }
        }
    }

    /// The words that hold the pages of the room: 32 pages each.
    fn words(&self) -> usize {
        self.pages / PER_WORD
    }

    /// The low bit of each field of word `word` (the first page in the low
    /// bits) that is in `state`.
    fn matches(&self, word: usize, state: State) -> u64 {
        let mut eight = [0u8; 8];
        eight.copy_from_slice(&self.bytes()[word * 8..word * 8 + 8]);
        let x = u64::from_le_bytes(eight) ^ (LOW * state as u64);
        !(x | x >> 1) & LOW
    }

    fn index(&self, address: usize) -> Option<usize> {
        let page = address.checked_sub(self.base)? / PAGE;
        (page < self.pages).then_some(page)
    }

    fn state_of(&self, page: usize) -> State {
        State::from_bits(self.bytes()[page / 4] >> (2 * (page % 4)))
    }

    /// The state of the page at `address`; None outside the room.
    pub fn get(&self, address: usize) -> Option<State> {
        Some(self.state_of(self.index(address)?))
    }

    fn put(&mut self, page: usize, state: State) {
        let shift = 2 * (page % 4);
        let byte = &mut self.bytes_mut()[page / 4];
        *byte = (*byte & !(3 << shift)) | ((state as u8) << shift);
    }

    /// Sets `pages` pages from `address`; false (nothing set) when the range
    /// leaves the room.
    pub fn set(&mut self, address: usize, pages: usize, state: State) -> bool {
        let Some(first) = self.index(address) else {
            return false;
        };
        if first + pages > self.pages || !address.is_multiple_of(PAGE) {
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
        first + pages <= self.pages
            && (first..first + pages).all(|page| self.state_of(page) == state)
    }

    /// How many pages are in `state`.
    pub fn count(&self, state: State) -> usize {
        (0..self.words())
            .map(|word| self.matches(word, state).count_ones() as usize)
            .sum()
    }

    /// The address of the first run of `pages` pages in `state`, from the
    /// bottom of the room, or from the top when `from_top` (the run's
    /// highest pages are the ones taken). A word of 32 pages with none or
    /// all of them in `state` is passed with one comparison.
    pub fn find(&self, pages: usize, state: State, from_top: bool) -> Option<usize> {
        if pages == 0 || pages > self.pages {
            return None;
        }
        let words = self.words();
        let mut run = 0;
        // From the top: the highest page of the run being counted.
        let mut top = 0;
        for step in 0..words {
            let word = if from_top { words - 1 - step } else { step };
            let hits = self.matches(word, state);
            let first = word * PER_WORD;
            if hits == 0 {
                run = 0;
            } else if hits == LOW {
                if run == 0 {
                    top = first + PER_WORD - 1;
                }
                run += PER_WORD;
                if run >= pages {
                    let start = if from_top {
                        top + 1 - pages
                    } else {
                        first + PER_WORD - run
                    };
                    return Some(self.base + start * PAGE);
                }
            } else {
                for k in 0..PER_WORD {
                    let bit = if from_top { PER_WORD - 1 - k } else { k };
                    if hits >> (2 * bit) & 1 == 0 {
                        run = 0;
                        continue;
                    }
                    if run == 0 {
                        top = first + bit;
                    }
                    run += 1;
                    if run == pages {
                        let start = if from_top {
                            first + bit
                        } else {
                            first + bit + 1 - pages
                        };
                        return Some(self.base + start * PAGE);
                    }
                }
            }
        }
        None
    }

    /// The length in pages of the longest run in `state`.
    pub fn longest(&self, state: State) -> usize {
        let mut best = 0;
        let mut run = 0;
        for word in 0..self.words() {
            let hits = self.matches(word, state);
            if hits == 0 {
                run = 0;
            } else if hits == LOW {
                run += PER_WORD;
                best = best.max(run);
            } else {
                for bit in 0..PER_WORD {
                    if hits >> (2 * bit) & 1 == 1 {
                        run += 1;
                        best = best.max(run);
                    } else {
                        run = 0;
                    }
                }
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
        assert_eq!(space.limit(), BASE + ROOM_PAGES * PAGE);
        assert_eq!(space.find(16, State::Unbacked, false), Some(BASE));
        assert_eq!(
            space.find(16, State::Unbacked, true),
            Some(space.limit() - 16 * PAGE)
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
        assert!(!space.set(space.limit() - PAGE, 2, State::User));
        assert_eq!(space.get(space.limit()), None);
        assert!(space.all(BASE + 4 * PAGE, 4, State::Free));
        assert!(!space.all(BASE, 8, State::Free));
        assert_eq!(space.count(State::User), 1);
    }

    /// The search of the page-by-page loop, the one the words replaced.
    fn slow_find(space: &Space, pages: usize, state: State, from_top: bool) -> Option<usize> {
        let at = |page: usize| space.get(space.base() + page * PAGE) == Some(state);
        let total = space.pages();
        let mut run = 0;
        if from_top {
            for page in (0..total).rev() {
                run = if at(page) { run + 1 } else { 0 };
                if run == pages {
                    return Some(space.base() + page * PAGE);
                }
            }
        } else {
            for page in 0..total {
                run = if at(page) { run + 1 } else { 0 };
                if run == pages {
                    return Some(space.base() + (page + 1 - pages) * PAGE);
                }
            }
        }
        None
    }

    fn random_room(space: &mut Space, seed: &mut u64, runs: usize, longest: usize) {
        let mut next = || {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed
        };
        for _ in 0..runs {
            let page = next() as usize % space.pages();
            let length = 1 + next() as usize % longest;
            let state = State::from_bits(next() as u8);
            let length = length.min(space.pages() - page);
            space.set(space.base() + page * PAGE, length, state);
        }
    }

    #[test]
    fn the_search_by_words_finds_what_the_search_by_pages_finds() {
        let mut seed = 0x9E37_79B9_7F4A_7C15;
        for round in 0..200 {
            let mut space = Space::new(BASE);
            let (runs, longest) = [(40, 70), (300, 20), (12, 400), (2000, 3)][round % 4];
            random_room(&mut space, &mut seed, runs, longest);
            for state in [State::Unbacked, State::Free, State::User, State::Own] {
                for pages in [1, 2, 31, 32, 33, 63, 64, 65, 100, 300, 5000] {
                    for from_top in [false, true] {
                        assert_eq!(
                            space.find(pages, state, from_top),
                            slow_find(&space, pages, state, from_top),
                            "round {round} {state:?} {pages} top {from_top}"
                        );
                    }
                }
                let counted = (0..ROOM_PAGES)
                    .filter(|&page| space.get(BASE + page * PAGE) == Some(state))
                    .count();
                assert_eq!(space.count(state), counted);
                let mut longest = 0;
                while space.find(longest + 1, state, false).is_some() {
                    longest += 1;
                }
                assert_eq!(space.longest(state), longest, "round {round} {state:?}");
            }
        }
    }

    #[test]
    fn a_room_that_grew_keeps_the_states_and_adds_unbacked_pages() {
        let mut seed = 0x1234_5678_9ABC_DEF1;
        let mut space = Space::new(BASE);
        random_room(&mut space, &mut seed, 100, 50);
        let before: Vec<_> = (0..ROOM_PAGES)
            .map(|page| space.get(BASE + page * PAGE))
            .collect();
        let mut bits = vec![0u8; MAX_BITS_BYTES];
        assert!(!space.grown());
        assert_eq!(space.get(BASE + ROOM_PAGES * PAGE), None);
        // SAFETY: `bits` is zeros, lives as long as the room and is used by no one else.
        unsafe { space.extend(bits.as_mut_ptr()) };
        assert!(space.grown());
        assert_eq!(space.limit(), BASE + ROOM_MAX * PAGE);
        for (page, state) in before.iter().enumerate() {
            assert_eq!(space.get(BASE + page * PAGE), *state);
        }
        assert_eq!(
            space.get(BASE + ROOM_MAX * PAGE - PAGE),
            Some(State::Unbacked)
        );
        assert!(space.set(BASE + ROOM_MAX * PAGE - 16 * PAGE, 16, State::Own));
        assert_eq!(
            space.find(16, State::Own, true),
            Some(BASE + (ROOM_MAX - 16) * PAGE)
        );
        assert_eq!(space.find(ROOM_MAX, State::Unbacked, false), None);
        assert_eq!(
            space.find(ROOM_MAX - ROOM_PAGES - 16, State::Unbacked, true),
            slow_find(&space, ROOM_MAX - ROOM_PAGES - 16, State::Unbacked, true)
        );
        random_room(&mut space, &mut seed, 3000, 90);
        for pages in [1, 40, 64, 1000, 20_000] {
            for from_top in [false, true] {
                assert_eq!(
                    space.find(pages, State::Unbacked, from_top),
                    slow_find(&space, pages, State::Unbacked, from_top)
                );
            }
        }
    }
}
