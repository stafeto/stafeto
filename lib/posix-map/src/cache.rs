// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The state of the process's copies of immutable files (`posix-abi` `filecache` holds the
//! lock, the memory objects and the calls to the file service): descriptions, entries, the
//! pages of the arena's pieces and the clock that evicts. No operation here calls the system, so
//! the host tests run them whole.

use crate::PAGE;
use core::sync::atomic::{AtomicU16, Ordering};

/// The pages of a piece: a word of `u64` says which are taken.
pub const PIECE_PAGES: usize = 64;
pub const PIECE_BYTES: usize = PIECE_PAGES * PAGE;
pub const PIECES_MAX: usize = 8;
/// The largest file the cache takes.
pub const FILE_MAX: usize = PIECE_BYTES;
/// The default budget in pages (2 MiB).
pub const BUDGET_PAGES: usize = PIECES_MAX * PIECE_PAGES;
/// The descriptions the cache knows at once: a description goes to the place of its slot modulo
/// this, and the one that was there goes out (it asks the service once more when read again).
pub const DESCS: usize = 1024;
/// More than the pages of the default budget, which is what bounds the entries with pages.
pub const ENTRIES: usize = BUDGET_PAGES + 8;
pub const NONE: u16 = u16::MAX;

const _: () = assert!(ENTRIES < NONE as usize);

/// What the cache knows of a description.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Know {
    /// The file can change, is too large, or the service has no copy to give: the old path.
    Direct,
    /// The file is immutable; `key` and `len` are the service's.
    Immutable,
}

#[derive(Clone, Copy)]
pub struct Desc {
    /// The generation of the description; zero is a free place.
    pub generation: u64,
    pub key: u64,
    pub slot: u32,
    pub len: u32,
    /// The entry the description names, valid while its `egen` is that of the entry.
    pub egen: u32,
    pub entry: u16,
    pub know: Know,
}

impl Desc {
    pub const FREE: Self = Self {
        generation: 0,
        key: 0,
        slot: 0,
        len: 0,
        egen: 0,
        entry: NONE,
        know: Know::Direct,
    };
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Free,
    /// The pages are taken and being filled; one reader (the filler) holds it.
    Filling,
    Ready,
}

#[derive(Clone, Copy)]
pub struct Entry {
    pub key: u64,
    /// Bumped each time the entry is freed, so a description's reference to it goes stale.
    pub egen: u32,
    pub len: u32,
    pub refs: u16,
    pub piece: u8,
    pub first: u8,
    pub pages: u8,
    pub phase: Phase,
    pub recent: bool,
}

impl Entry {
    pub const FREE: Self = Self {
        key: 0,
        egen: 1,
        len: 0,
        refs: 0,
        piece: 0,
        first: 0,
        pages: 0,
        phase: Phase::Free,
        recent: false,
    };
}

#[derive(Clone, Copy)]
pub struct Piece {
    pub base: usize,
    pub handle: u64,
    pub taken: u64,
}

/// What a look at a description found.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// The old path.
    Direct,
    /// The service has not been asked about the description.
    Ask,
    /// The copy is here, pinned: its address and the length of the file.
    Hit { at: usize, len: usize, entry: u16 },
    /// No copy yet: the pages are taken (the entry is pinned for the filler) and wait for bytes.
    Fill { entry: u16, piece: usize },
}

/// All the cache's state; its operations do no call of the system, so the host tests run them.
pub struct Cache {
    pub descs: [Desc; DESCS],
    pub entries: [Entry; ENTRIES],
    pub pieces: [Piece; PIECES_MAX],
    pub pieces_made: usize,
    /// The system refused a piece: no more are asked for.
    pub refused: bool,
    pub used_pages: usize,
    pub budget_pages: usize,
    pub hand: usize,
}

impl Cache {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            descs: [Desc::FREE; DESCS],
            entries: [Entry::FREE; ENTRIES],
            pieces: [Piece {
                base: 0,
                handle: 0,
                taken: 0,
            }; PIECES_MAX],
            pieces_made: 0,
            refused: false,
            used_pages: 0,
            budget_pages: BUDGET_PAGES,
            hand: 0,
        }
    }

    pub fn index(slot: u32) -> usize {
        slot as usize % DESCS
    }

    /// The place of the description `target` names, when it is the one the cache knows.
    pub fn desc_of(&self, slot: u32, generation: u64) -> Option<usize> {
        let at = Self::index(slot);
        let d = &self.descs[at];
        (d.generation == generation && d.slot == slot).then_some(at)
    }

    /// The entry a description names, if it still is that entry and holds a ready copy.
    pub fn entry_of(&self, d: &Desc) -> Option<u16> {
        let e = self.entries.get(usize::from(d.entry))?;
        (e.phase == Phase::Ready && e.egen == d.egen && e.key == d.key).then_some(d.entry)
    }

    pub fn find_key(&self, key: u64) -> Option<u16> {
        self.entries
            .iter()
            .position(|e| e.phase != Phase::Free && e.key == key)
            .map(|i| i as u16)
    }

    /// The description `slot`/`generation` goes into its place, as `know` says; whatever the place
    /// held lets go of its entry.
    pub fn put(&mut self, slot: u32, generation: u64, know: Know, key: u64, len: u32) -> usize {
        let at = Self::index(slot);
        self.forget(at);
        self.descs[at] = Desc {
            generation,
            key,
            slot,
            len,
            egen: 0,
            entry: NONE,
            know,
        };
        at
    }

    /// The description at `at` goes, and its entry loses a reference.
    pub fn forget(&mut self, at: usize) {
        let d = self.descs[at];
        if d.generation != 0
            && let Some(entry) = self.entry_of(&d)
        {
            let e = &mut self.entries[usize::from(entry)];
            e.refs = e.refs.saturating_sub(1);
        }
        self.descs[at] = Desc::FREE;
    }

    pub fn attach(&mut self, at: usize, entry: u16) {
        let e = &mut self.entries[usize::from(entry)];
        e.refs = e.refs.saturating_add(1);
        e.recent = true;
        let (egen, key) = (e.egen, e.key);
        let d = &mut self.descs[at];
        d.entry = entry;
        d.egen = egen;
        debug_assert_eq!(d.key, key);
    }

    /// What to do for a read of the description. `create` lets the answer be Ask or Fill.
    /// `readers` counts the reads copying from an entry.
    pub fn plan(
        &mut self,
        slot: u32,
        generation: u64,
        create: bool,
        readers: &[AtomicU16],
        make: &mut dyn FnMut() -> Option<(usize, u64)>,
    ) -> Plan {
        let Some(at) = self.desc_of(slot, generation) else {
            return if create { Plan::Ask } else { Plan::Direct };
        };
        let d = self.descs[at];
        if d.know == Know::Direct {
            return Plan::Direct;
        }
        if d.len == 0 {
            return Plan::Hit {
                at: 0,
                len: 0,
                entry: NONE,
            };
        }
        let entry = match self.entry_of(&d) {
            Some(entry) => entry,
            None => match self.find_key(d.key) {
                Some(entry) if self.entries[usize::from(entry)].phase == Phase::Ready => {
                    self.attach(at, entry);
                    entry
                }
                // Another read is filling it: the old path this once.
                Some(_) => return Plan::Direct,
                None if create => return self.start_fill(at, readers, make),
                None => return Plan::Direct,
            },
        };
        let e = &mut self.entries[usize::from(entry)];
        e.recent = true;
        readers[usize::from(entry)].fetch_add(1, Ordering::AcqRel);
        let at = self.pieces[usize::from(e.piece)].base + usize::from(e.first) * PAGE;
        Plan::Hit {
            at,
            len: d.len as usize,
            entry,
        }
    }

    /// The pages for the copy of the file the description at `at` names, taken and marked as
    /// being filled; Direct when none can be had.
    pub fn start_fill(
        &mut self,
        at: usize,
        readers: &[AtomicU16],
        make: &mut dyn FnMut() -> Option<(usize, u64)>,
    ) -> Plan {
        let d = self.descs[at];
        let pages = (d.len as usize).div_ceil(PAGE);
        let Some(free) = self.entries.iter().position(|e| e.phase == Phase::Free) else {
            if !self.evict_one(readers) {
                return Plan::Direct;
            }
            return self.start_fill(at, readers, make);
        };
        let Some((piece, first)) = self.allocate(pages, readers, make) else {
            return Plan::Direct;
        };
        // Eviction may have taken the free entry's neighbours but never this one.
        let e = &mut self.entries[free];
        *e = Entry {
            key: d.key,
            egen: e.egen,
            len: d.len,
            refs: 0,
            piece: piece as u8,
            first: first as u8,
            pages: pages as u8,
            phase: Phase::Filling,
            recent: true,
        };
        readers[free].store(1, Ordering::Release);
        Plan::Fill {
            entry: free as u16,
            piece,
        }
    }

    /// A run of `pages` pages: its piece and first page. Pieces are made as they are needed
    /// (`make` gives the base and the handle of a new one) while the budget allows; otherwise
    /// entries go by the clock until a run is free.
    pub fn allocate(
        &mut self,
        pages: usize,
        readers: &[AtomicU16],
        make: &mut dyn FnMut() -> Option<(usize, u64)>,
    ) -> Option<(usize, usize)> {
        loop {
            if self.used_pages + pages <= self.budget_pages {
                if let Some(found) = self.find_run(pages) {
                    self.pieces[found.0].taken |= run_mask(found.1, pages);
                    self.used_pages += pages;
                    return Some(found);
                }
                if self.pieces_made < PIECES_MAX && !self.refused {
                    match make() {
                        Some((base, handle)) => {
                            self.pieces[self.pieces_made] = Piece {
                                base,
                                handle,
                                taken: 0,
                            };
                            self.pieces_made += 1;
                            continue;
                        }
                        None => self.refused = true,
                    }
                }
            }
            if !self.evict_one(readers) {
                return None;
            }
        }
    }

    pub fn find_run(&self, pages: usize) -> Option<(usize, usize)> {
        for piece in 0..self.pieces_made {
            let taken = self.pieces[piece].taken;
            for first in 0..=(PIECE_PAGES - pages) {
                if taken & run_mask(first, pages) == 0 {
                    return Some((piece, first));
                }
            }
        }
        None
    }

    /// One ready entry no read is copying from goes: first one no description names, then by the
    /// clock (a recent entry gets one more turn). False when none can.
    pub fn evict_one(&mut self, readers: &[AtomicU16]) -> bool {
        let idle = |c: &Self, i: usize| {
            c.entries[i].phase == Phase::Ready && readers[i].load(Ordering::Acquire) == 0
        };
        if let Some(i) = (0..ENTRIES).find(|&i| idle(self, i) && self.entries[i].refs == 0) {
            self.free_entry(i);
            return true;
        }
        for _ in 0..2 * ENTRIES {
            let i = self.hand;
            self.hand = (self.hand + 1) % ENTRIES;
            if !idle(self, i) {
                continue;
            }
            if self.entries[i].recent {
                self.entries[i].recent = false;
                continue;
            }
            self.free_entry(i);
            return true;
        }
        false
    }

    pub fn free_entry(&mut self, i: usize) {
        let e = self.entries[i];
        self.pieces[usize::from(e.piece)].taken &=
            !run_mask(usize::from(e.first), usize::from(e.pages));
        self.used_pages -= usize::from(e.pages);
        self.entries[i] = Entry {
            egen: e.egen.wrapping_add(1).max(1),
            ..Entry::FREE
        };
    }

    /// The bytes of the entry are in place: it is ready and the description names it.
    pub fn filled(&mut self, entry: u16, at: usize) {
        self.entries[usize::from(entry)].phase = Phase::Ready;
        self.attach(at, entry);
    }

    /// The fill failed: the pages go back.
    pub fn failed(&mut self, entry: u16, readers: &[AtomicU16]) {
        readers[usize::from(entry)].store(0, Ordering::Release);
        self.entries[usize::from(entry)].phase = Phase::Ready;
        self.free_entry(usize::from(entry));
    }

    /// Every description and every copy no read holds goes, as after a closed session (a read
    /// that holds a copy finishes with it; the copy goes with the next eviction).
    pub fn clear(&mut self, readers: &[AtomicU16]) {
        self.descs = [Desc::FREE; DESCS];
        for (i, count) in readers.iter().enumerate().take(ENTRIES) {
            if self.entries[i].phase == Phase::Ready && count.load(Ordering::Acquire) == 0 {
                self.free_entry(i);
            }
        }
    }
}

/// The budget in pages from `STAFETO_FILE_CACHE` (the text of the variable): None for off.
pub fn budget_from(text: Option<&[u8]>) -> Option<usize> {
    let Some(text) = text else {
        return Some(BUDGET_PAGES);
    };
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return Some(BUDGET_PAGES);
    }
    let kib = text.iter().fold(0usize, |n, d| {
        n.saturating_mul(10).saturating_add(usize::from(d - b'0'))
    });
    if kib == 0 {
        return None;
    }
    Some(kib.div_ceil(PAGE / 1024).clamp(1, BUDGET_PAGES))
}

pub const fn run_mask(first: usize, pages: usize) -> u64 {
    if pages >= 64 {
        u64::MAX
    } else {
        ((1u64 << pages) - 1) << first
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn no_piece() -> Option<(usize, u64)> {
        None
    }

    fn readers() -> Vec<AtomicU16> {
        (0..ENTRIES).map(|_| AtomicU16::new(0)).collect()
    }

    /// A cache with `pieces` pieces already made (the host has no memory objects).
    fn cache(pieces: usize, budget_pages: usize) -> Cache {
        let mut c = Cache::new();
        for i in 0..pieces {
            c.pieces[i] = Piece {
                base: 0x1000_0000 + i * PIECE_BYTES,
                handle: i as u64 + 1,
                taken: 0,
            };
        }
        c.pieces_made = pieces;
        c.budget_pages = budget_pages;
        c.refused = true;
        c
    }

    fn immutable(c: &mut Cache, slot: u32, key: u64, len: u32) {
        c.put(slot, 1, Know::Immutable, key, len);
    }

    /// Takes the plan of a description, fills it when asked and gives back the pin.
    fn read(c: &mut Cache, r: &[AtomicU16], slot: u32) -> Plan {
        let plan = c.plan(slot, 1, true, r, &mut no_piece);
        match plan {
            Plan::Fill { entry, .. } => {
                c.filled(entry, Cache::index(slot));
                r[usize::from(entry)].store(0, Ordering::Release);
            }
            Plan::Hit { entry, .. } if entry != NONE => {
                r[usize::from(entry)].fetch_sub(1, Ordering::Release);
            }
            _ => {}
        }
        plan
    }

    #[test]
    fn a_file_takes_a_run_of_pages_of_one_piece_and_the_next_follows() {
        let r = readers();
        let mut c = cache(2, BUDGET_PAGES);
        immutable(&mut c, 3, 100, 1024);
        immutable(&mut c, 4, 200, 3 * PAGE as u32);
        assert!(matches!(read(&mut c, &r, 3), Plan::Fill { piece: 0, .. }));
        assert!(matches!(read(&mut c, &r, 4), Plan::Fill { piece: 0, .. }));
        assert_eq!(c.used_pages, 4);
        assert_eq!(c.pieces[0].taken, 0b1111_u64);
        // The entry of the first sits at page 0, the second at page 1.
        let a = c.find_key(100).unwrap();
        let b = c.find_key(200).unwrap();
        assert_eq!(
            (c.entries[a as usize].first, c.entries[b as usize].first),
            (0, 1)
        );
        // A second read is a hit at the first address of the copy.
        let hit = c.plan(3, 1, true, &r, &mut no_piece);
        assert_eq!(
            hit,
            Plan::Hit {
                at: 0x1000_0000,
                len: 1024,
                entry: a
            }
        );
        r[usize::from(a)].fetch_sub(1, Ordering::Release);
        // A file of a whole piece takes the whole of the other.
        immutable(&mut c, 5, 300, PIECE_BYTES as u32);
        assert!(matches!(read(&mut c, &r, 5), Plan::Fill { piece: 1, .. }));
        assert_eq!(c.pieces[1].taken, u64::MAX);
    }

    #[test]
    fn two_descriptions_of_one_file_share_the_copy_and_a_new_key_does_not() {
        let r = readers();
        let mut c = cache(1, BUDGET_PAGES);
        immutable(&mut c, 3, 100, 10);
        c.put(4, 1, Know::Immutable, 100, 10);
        c.put(5, 1, Know::Immutable, 101, 10);
        assert!(matches!(read(&mut c, &r, 3), Plan::Fill { .. }));
        // The second description of the key attaches to the copy: a hit with no fill.
        assert!(matches!(read(&mut c, &r, 4), Plan::Hit { .. }));
        assert!(matches!(read(&mut c, &r, 5), Plan::Fill { .. }));
        assert_eq!(c.used_pages, 2);
        let a = c.find_key(100).unwrap();
        assert_eq!(c.entries[a as usize].refs, 2);
        // A close lets go of one reference; the copy stays for the next.
        let at = c.desc_of(3, 1).unwrap();
        c.forget(at);
        assert_eq!(c.entries[a as usize].refs, 1);
        assert_eq!(c.desc_of(3, 1), None);
        // The number reopened is another description: unknown until asked.
        assert_eq!(c.plan(3, 2, true, &r, &mut no_piece), Plan::Ask);
        assert_eq!(c.plan(3, 2, false, &r, &mut no_piece), Plan::Direct);
    }

    #[test]
    fn the_budget_evicts_by_the_clock_and_never_an_entry_a_read_holds() {
        let r = readers();
        // 4 pages of budget, files of one page each.
        let mut c = cache(1, 4);
        for slot in 0..4 {
            immutable(&mut c, slot, 1000 + u64::from(slot), 100);
            assert!(matches!(read(&mut c, &r, slot), Plan::Fill { .. }));
        }
        assert_eq!(c.used_pages, 4);
        // A fifth file evicts one entry; the one a read holds stays.
        let held = c.find_key(1000).unwrap();
        r[usize::from(held)].store(1, Ordering::Release);
        immutable(&mut c, 9, 2000, 100);
        assert!(matches!(read(&mut c, &r, 9), Plan::Fill { .. }));
        assert_eq!(c.used_pages, 4);
        assert!(c.find_key(1000).is_some(), "a held entry is never evicted");
        assert!(c.find_key(2000).is_some());
        // With all four held there is nothing to evict: the old path, no change.
        for count in r.iter() {
            count.store(1, Ordering::Release);
        }
        immutable(&mut c, 10, 3000, 100);
        assert_eq!(c.plan(10, 1, true, &r, &mut no_piece), Plan::Direct);
        assert_eq!(c.used_pages, 4);
        // The evicted description knows its key and fills again on its next read.
        for count in r.iter() {
            count.store(0, Ordering::Release);
        }
        let gone = (0..4u32)
            .find(|s| {
                let d = c.descs[Cache::index(*s)];
                c.entry_of(&d).is_none()
            })
            .expect("one description lost its entry");
        assert!(matches!(read(&mut c, &r, gone), Plan::Fill { .. }));
    }

    #[test]
    fn entries_no_description_names_go_before_the_clock_takes_a_named_one() {
        let r = readers();
        let mut c = cache(1, 3);
        for slot in 0..3 {
            immutable(&mut c, slot, 10 + u64::from(slot), 100);
            assert!(matches!(read(&mut c, &r, slot), Plan::Fill { .. }));
        }
        // Slot 1's description closes: its entry has no reference left.
        let at = c.desc_of(1, 1).unwrap();
        c.forget(at);
        immutable(&mut c, 7, 99, 100);
        assert!(matches!(read(&mut c, &r, 7), Plan::Fill { .. }));
        assert!(c.find_key(11).is_none(), "the unnamed copy went");
        assert!(c.find_key(10).is_some() && c.find_key(12).is_some());
    }

    #[test]
    fn a_gap_too_small_is_filled_by_eviction_and_the_arena_never_exceeds_its_pieces() {
        let r = readers();
        let mut c = cache(1, BUDGET_PAGES);
        // 64 one-page files fill the piece.
        for slot in 0..64 {
            immutable(&mut c, slot, 10 + u64::from(slot), 100);
            assert!(matches!(read(&mut c, &r, slot), Plan::Fill { .. }));
        }
        // A file of 8 pages needs a run: eviction frees pages until 8 in a row are free.
        immutable(&mut c, 100, 5000, 8 * PAGE as u32);
        assert!(matches!(read(&mut c, &r, 100), Plan::Fill { .. }));
        assert!(c.used_pages <= PIECE_PAGES);
        assert_eq!(c.pieces_made, 1);
    }

    #[test]
    fn many_small_descriptions_under_a_small_budget_stay_within_it() {
        let r = readers();
        let mut c = cache(1, 16);
        for slot in 0..600u32 {
            immutable(&mut c, slot, 5000 + u64::from(slot), 1024);
            assert!(!matches!(read(&mut c, &r, slot), Plan::Direct));
            assert!(c.used_pages <= 16, "{}", c.used_pages);
        }
        assert_eq!(c.pieces_made, 1);
    }

    #[test]
    fn an_empty_file_is_a_hit_with_no_pages_and_the_clear_goes_whole() {
        let r = readers();
        let mut c = cache(1, BUDGET_PAGES);
        immutable(&mut c, 3, 7, 0);
        assert_eq!(
            c.plan(3, 1, true, &r, &mut no_piece),
            Plan::Hit {
                at: 0,
                len: 0,
                entry: NONE
            }
        );
        immutable(&mut c, 4, 8, 50);
        assert!(matches!(read(&mut c, &r, 4), Plan::Fill { .. }));
        c.clear(&r);
        assert_eq!(c.used_pages, 0);
        assert_eq!(c.plan(4, 1, true, &r, &mut no_piece), Plan::Ask);
        assert_eq!(c.pieces[0].taken, 0);
    }

    #[test]
    fn a_description_that_cannot_change_keeps_the_old_path_and_the_lookup_never_fills() {
        let r = readers();
        let mut c = cache(1, BUDGET_PAGES);
        c.put(3, 1, Know::Direct, 0, 0);
        assert_eq!(c.plan(3, 1, true, &r, &mut no_piece), Plan::Direct);
        // The fill of a mapping (create false) takes no copy that is not there.
        immutable(&mut c, 4, 8, 50);
        assert_eq!(c.plan(4, 1, false, &r, &mut no_piece), Plan::Direct);
        assert_eq!(c.used_pages, 0);
    }

    #[test]
    fn the_budget_text_is_off_default_or_kib() {
        assert_eq!(budget_from(None), Some(BUDGET_PAGES));
        assert_eq!(budget_from(Some(b"0")), None);
        assert_eq!(budget_from(Some(b"64")), Some(16));
        assert_eq!(budget_from(Some(b"1")), Some(1));
        assert_eq!(budget_from(Some(b"99999")), Some(BUDGET_PAGES));
        assert_eq!(budget_from(Some(b"x")), Some(BUDGET_PAGES));
    }
}
