// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The state of the process's copies of immutable files (`posix-abi` `filecache` holds the
//! lock, the memory objects and the calls to the file service): descriptions, entries, the
//! pages of the arena's pieces and the clock that evicts. No operation here calls the system, so
//! the host tests run them whole.

use crate::PAGE;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, AtomicUsize, Ordering};

/// The pages of a piece: a word of `u64` says which are taken.
pub const PIECE_PAGES: usize = 64;
pub const PIECE_BYTES: usize = PIECE_PAGES * PAGE;
pub const PIECES_MAX: usize = 8;
/// The pages of the pieces in the order they are made: the first is the size of its file (a
/// file that fits one page costs one page), the second has 16, the others are `PIECE_PAGES`. A
/// process that reads one small file once pays for that file alone. Each piece takes a place of
/// the table of mappings, so the pieces stay few. A file that needs more pages than the next
/// size asks for a piece of its own size. The pieces hold 465 of the 512 pages of the default
/// budget, so the arena holds at most 1.8 MiB until the budget is lowered.
pub const PIECE_SIZES: [usize; PIECES_MAX] = [1, 16, 64, 64, 64, 64, 64, 64];
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
    /// The pages of the piece (at most `PIECE_PAGES`).
    pub pages: usize,
}

/// The words the readers and the filler share with the lock's holders without the lock: the
/// readers each entry has, the verdict of a fill whose filler found the lock taken (the next
/// holder applies it), the piece made outside the lock, and the system's refusal of a piece.
pub struct Shared {
    /// The reads copying from each entry.
    pub readers: [AtomicU16; ENTRIES],
    /// 1: the fill of the entry is done, 2: it failed; applied by the next holder of the lock.
    pub pending: [AtomicU8; ENTRIES],
    pub due: AtomicBool,
    /// The system refused a piece: no more are asked for.
    pub refused: AtomicBool,
    /// A thread is making a piece.
    pub making: AtomicBool,
    /// A piece made outside the lock that no holder has taken yet: base (0 for none), handle,
    /// pages. The base is stored last.
    pub spare_handle: AtomicU64,
    pub spare_pages: AtomicUsize,
    pub spare_base: AtomicUsize,
}

impl Shared {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            readers: [const { AtomicU16::new(0) }; ENTRIES],
            pending: [const { AtomicU8::new(0) }; ENTRIES],
            due: AtomicBool::new(false),
            refused: AtomicBool::new(false),
            making: AtomicBool::new(false),
            spare_handle: AtomicU64::new(0),
            spare_pages: AtomicUsize::new(0),
            spare_base: AtomicUsize::new(0),
        }
    }

    /// A thread asks to make a piece: true for one thread at a time, and not while a made piece
    /// waits. `making` stays set until `take_spare` has read the piece (or `refuse` is called),
    /// so only one spare exists at a time and no maker overwrites it.
    pub fn begin_make(&self) -> bool {
        self.spare_base.load(Ordering::Acquire) == 0 && !self.making.swap(true, Ordering::AcqRel)
    }

    /// The system refused the piece: no more are asked for.
    pub fn refuse(&self) {
        self.refused.store(true, Ordering::Release);
        self.making.store(false, Ordering::Release);
    }

    /// A piece made outside the lock waits for the next holder. The maker keeps `making` set.
    pub fn offer(&self, base: usize, handle: u64, pages: usize) {
        self.spare_handle.store(handle, Ordering::Relaxed);
        self.spare_pages.store(pages, Ordering::Relaxed);
        self.spare_base.store(base, Ordering::Release);
    }

    fn take_spare(&self) -> Option<(usize, u64, usize)> {
        let base = self.spare_base.swap(0, Ordering::Acquire);
        (base != 0).then(|| {
            let taken = (
                base,
                self.spare_handle.load(Ordering::Relaxed),
                self.spare_pages.load(Ordering::Relaxed),
            );
            // The three words are read: the next piece may be made.
            self.making.store(false, Ordering::Release);
            taken
        })
    }

    /// A forked child's words: nothing is shared with the parent's readers.
    pub fn reset(&self) {
        for i in 0..ENTRIES {
            self.readers[i].store(0, Ordering::Release);
            self.pending[i].store(0, Ordering::Release);
        }
        self.due.store(false, Ordering::Release);
        self.refused.store(false, Ordering::Release);
        self.making.store(false, Ordering::Release);
        self.spare_base.store(0, Ordering::Release);
    }
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
    /// The arena needs a piece of `pages` pages: the caller makes it outside the lock, offers it
    /// (`Shared::offer`) and looks again.
    NeedPiece { pages: usize },
}

/// What `allocate` found.
enum Alloc {
    Run(usize, usize),
    NeedPiece(usize),
    None,
}

/// All the cache's state; its operations do no call of the system, so the host tests run them.
pub struct Cache {
    pub descs: [Desc; DESCS],
    pub entries: [Entry; ENTRIES],
    pub pieces: [Piece; PIECES_MAX],
    pub pieces_made: usize,
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
                pages: 0,
            }; PIECES_MAX],
            pieces_made: 0,
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
    pub fn plan(&mut self, slot: u32, generation: u64, create: bool, sh: &Shared) -> Plan {
        self.reconcile(sh);
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
                None if create => return self.start_fill(at, sh),
                None => return Plan::Direct,
            },
        };
        let e = &mut self.entries[usize::from(entry)];
        e.recent = true;
        sh.readers[usize::from(entry)].fetch_add(1, Ordering::AcqRel);
        let at = self.pieces[usize::from(e.piece)].base + usize::from(e.first) * PAGE;
        Plan::Hit {
            at,
            len: d.len as usize,
            entry,
        }
    }

    /// The pages for the copy of the file the description at `at` names, taken and marked as
    /// being filled; Direct when none can be had.
    pub fn start_fill(&mut self, at: usize, sh: &Shared) -> Plan {
        let d = self.descs[at];
        let pages = (d.len as usize).div_ceil(PAGE);
        let Some(free) = self.entries.iter().position(|e| e.phase == Phase::Free) else {
            if !self.evict_one(sh) {
                return Plan::Direct;
            }
            return self.start_fill(at, sh);
        };
        let (piece, first) = match self.allocate(pages, sh) {
            Alloc::Run(piece, first) => (piece, first),
            Alloc::NeedPiece(pages) => return Plan::NeedPiece { pages },
            Alloc::None => return Plan::Direct,
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
        sh.readers[free].store(1, Ordering::Release);
        Plan::Fill {
            entry: free as u16,
            piece,
        }
    }

    /// A run of `pages` pages. A piece a thread made outside the lock is taken when the arena has
    /// no run and room for one more; the caller is asked for a piece (`Alloc::NeedPiece`) when
    /// there is none; otherwise entries go by the clock until a run is free.
    fn allocate(&mut self, pages: usize, sh: &Shared) -> Alloc {
        loop {
            if self.used_pages + pages <= self.budget_pages {
                if let Some(found) = self.find_run(pages) {
                    self.pieces[found.0].taken |= run_mask(found.1, pages);
                    self.used_pages += pages;
                    return Alloc::Run(found.0, found.1);
                }
                if self.pieces_made < PIECES_MAX && !sh.refused.load(Ordering::Acquire) {
                    match sh.take_spare() {
                        Some((base, handle, size)) => {
                            self.pieces[self.pieces_made] = Piece {
                                base,
                                handle,
                                taken: 0,
                                pages: size,
                            };
                            self.pieces_made += 1;
                            continue;
                        }
                        None => {
                            let next = PIECE_SIZES[self.pieces_made];
                            return Alloc::NeedPiece(next.max(pages));
                        }
                    }
                }
            }
            if !self.evict_one(sh) {
                return Alloc::None;
            }
        }
    }

    /// The verdicts of fills whose fillers found the lock taken: a finished fill is ready, a
    /// failed one gives its pages back.
    pub fn reconcile(&mut self, sh: &Shared) {
        if !sh.due.swap(false, Ordering::Acquire) {
            return;
        }
        for i in 0..ENTRIES {
            let verdict = sh.pending[i].swap(0, Ordering::AcqRel);
            if verdict == 0 || self.entries[i].phase != Phase::Filling {
                continue;
            }
            if verdict == 1 {
                self.entries[i].phase = Phase::Ready;
            } else {
                self.entries[i].phase = Phase::Ready;
                self.free_entry(i);
            }
        }
    }

    pub fn find_run(&self, pages: usize) -> Option<(usize, usize)> {
        for piece in 0..self.pieces_made {
            let taken = self.pieces[piece].taken;
            let size = self.pieces[piece].pages;
            if pages > size {
                continue;
            }
            for first in 0..=(size - pages) {
                if taken & run_mask(first, pages) == 0 {
                    return Some((piece, first));
                }
            }
        }
        None
    }

    /// One ready entry no read is copying from goes: first one no description names, then by the
    /// clock (a recent entry gets one more turn). False when none can.
    pub fn evict_one(&mut self, sh: &Shared) -> bool {
        let idle = |c: &Self, i: usize| {
            c.entries[i].phase == Phase::Ready && sh.readers[i].load(Ordering::Acquire) == 0
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
    pub fn failed(&mut self, entry: u16, sh: &Shared) {
        sh.readers[usize::from(entry)].store(0, Ordering::Release);
        self.entries[usize::from(entry)].phase = Phase::Ready;
        self.free_entry(usize::from(entry));
    }

    /// Every description and every copy no read holds goes, as after a closed session (a read
    /// that holds a copy finishes with it; the copy goes with the next eviction). In place: no
    /// temporary of the size of the state is made.
    pub fn clear(&mut self, sh: &Shared) {
        self.descs.fill(Desc::FREE);
        for i in 0..ENTRIES {
            if self.entries[i].phase == Phase::Ready && sh.readers[i].load(Ordering::Acquire) == 0 {
                self.free_entry(i);
            }
        }
    }

    /// The state of a forked child: nothing, the pieces being the parent's. In place, with no
    /// temporary of the size of the state (the child runs on a copy of the caller's stack, which
    /// may be a handler's alternate stack of a few KiB); the budget stays.
    pub fn reset(&mut self) {
        self.descs.fill(Desc::FREE);
        for e in &mut self.entries {
            *e = Entry {
                egen: e.egen.wrapping_add(1).max(1),
                ..Entry::FREE
            };
        }
        for piece in &mut self.pieces {
            piece.base = 0;
            piece.handle = 0;
            piece.taken = 0;
            piece.pages = 0;
        }
        self.pieces_made = 0;
        self.used_pages = 0;
        self.hand = 0;
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
    use std::boxed::Box;

    /// The shared words; the system refuses pieces (the host has no memory objects).
    fn shared() -> Box<Shared> {
        let sh = Box::new(Shared::new());
        sh.refused.store(true, Ordering::Release);
        sh
    }

    /// A cache with `pieces` pieces already made (the host has no memory objects).
    fn cache(pieces: usize, budget_pages: usize) -> Cache {
        let mut c = Cache::new();
        for i in 0..pieces {
            c.pieces[i] = Piece {
                base: 0x1000_0000 + i * PIECE_BYTES,
                handle: i as u64 + 1,
                taken: 0,
                pages: PIECE_PAGES,
            };
        }
        c.pieces_made = pieces;
        c.budget_pages = budget_pages;
        c
    }

    fn immutable(c: &mut Cache, slot: u32, key: u64, len: u32) {
        c.put(slot, 1, Know::Immutable, key, len);
    }

    /// Takes the plan of a description, fills it when asked and gives back the pin.
    fn read(c: &mut Cache, r: &Shared, slot: u32) -> Plan {
        let plan = c.plan(slot, 1, true, r);
        match plan {
            Plan::Fill { entry, .. } => {
                c.filled(entry, Cache::index(slot));
                r.readers[usize::from(entry)].store(0, Ordering::Release);
            }
            Plan::Hit { entry, .. } if entry != NONE => {
                r.readers[usize::from(entry)].fetch_sub(1, Ordering::Release);
            }
            _ => {}
        }
        plan
    }

    #[test]
    fn a_file_takes_a_run_of_pages_of_one_piece_and_the_next_follows() {
        let r = shared();
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
        let hit = c.plan(3, 1, true, &r);
        assert_eq!(
            hit,
            Plan::Hit {
                at: 0x1000_0000,
                len: 1024,
                entry: a
            }
        );
        r.readers[usize::from(a)].fetch_sub(1, Ordering::Release);
        // A file of a whole piece takes the whole of the other.
        immutable(&mut c, 5, 300, PIECE_BYTES as u32);
        assert!(matches!(read(&mut c, &r, 5), Plan::Fill { piece: 1, .. }));
        assert_eq!(c.pieces[1].taken, u64::MAX);
    }

    #[test]
    fn two_descriptions_of_one_file_share_the_copy_and_a_new_key_does_not() {
        let r = shared();
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
        assert_eq!(c.plan(3, 2, true, &r), Plan::Ask);
        assert_eq!(c.plan(3, 2, false, &r), Plan::Direct);
    }

    #[test]
    fn the_budget_evicts_by_the_clock_and_never_an_entry_a_read_holds() {
        let r = shared();
        // 4 pages of budget, files of one page each.
        let mut c = cache(1, 4);
        for slot in 0..4 {
            immutable(&mut c, slot, 1000 + u64::from(slot), 100);
            assert!(matches!(read(&mut c, &r, slot), Plan::Fill { .. }));
        }
        assert_eq!(c.used_pages, 4);
        // A fifth file evicts one entry; the one a read holds stays.
        let held = c.find_key(1000).unwrap();
        r.readers[usize::from(held)].store(1, Ordering::Release);
        immutable(&mut c, 9, 2000, 100);
        assert!(matches!(read(&mut c, &r, 9), Plan::Fill { .. }));
        assert_eq!(c.used_pages, 4);
        assert!(c.find_key(1000).is_some(), "a held entry is never evicted");
        assert!(c.find_key(2000).is_some());
        // With all four held there is nothing to evict: the old path, no change.
        for count in r.readers.iter() {
            count.store(1, Ordering::Release);
        }
        immutable(&mut c, 10, 3000, 100);
        assert_eq!(c.plan(10, 1, true, &r), Plan::Direct);
        assert_eq!(c.used_pages, 4);
        // The evicted description knows its key and fills again on its next read.
        for count in r.readers.iter() {
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
        let r = shared();
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
        let r = shared();
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
        let r = shared();
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
        let r = shared();
        let mut c = cache(1, BUDGET_PAGES);
        immutable(&mut c, 3, 7, 0);
        assert_eq!(
            c.plan(3, 1, true, &r),
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
        assert_eq!(c.plan(4, 1, true, &r), Plan::Ask);
        assert_eq!(c.pieces[0].taken, 0);
    }

    #[test]
    fn a_description_that_cannot_change_keeps_the_old_path_and_the_lookup_never_fills() {
        let r = shared();
        let mut c = cache(1, BUDGET_PAGES);
        c.put(3, 1, Know::Direct, 0, 0);
        assert_eq!(c.plan(3, 1, true, &r), Plan::Direct);
        // The fill of a mapping (create false) takes no copy that is not there.
        immutable(&mut c, 4, 8, 50);
        assert_eq!(c.plan(4, 1, false, &r), Plan::Direct);
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

    #[test]
    fn a_second_maker_waits_until_the_spare_is_taken() {
        let r = Shared::new();
        let mut c = Cache::new();
        immutable(&mut c, 3, 1, 1024);
        // Thread A makes a piece of 16 pages and offers it.
        assert!(r.begin_make());
        r.offer(0x2000_0000, 7, 16);
        // Thread B, which looked before the offer, must not make another piece while the spare
        // waits (the old code cleared `making` at the offer, so B made one of 40 pages and the
        // holder read B's handle and pages for A's base).
        assert!(!r.begin_make());
        assert!(!r.begin_make());
        // The holder takes A's three words, and then the next maker may go.
        assert_eq!(c.plan(3, 1, true, &r), Plan::Fill { entry: 0, piece: 0 });
        assert_eq!(c.pieces[0].base, 0x2000_0000);
        assert_eq!(c.pieces[0].handle, 7);
        assert_eq!(c.pieces[0].pages, 16);
        assert!(r.begin_make());
        r.refuse();
        assert!(r.refused.load(Ordering::Acquire));
        assert!(!r.making.load(Ordering::Acquire));
    }

    #[test]
    fn the_first_piece_is_small_and_the_next_ones_have_the_piece_size() {
        let r = Box::new(Shared::new());
        let mut c = Cache::new();
        immutable(&mut c, 3, 1, 1024);
        // The first file asks for a piece of its own size, one page.
        assert_eq!(c.plan(3, 1, true, &r), Plan::NeedPiece { pages: 1 });
        r.offer(0x2000_0000, 7, 1);
        assert!(matches!(
            c.plan(3, 1, true, &r),
            Plan::Fill { piece: 0, .. }
        ));
        assert_eq!(c.pieces[0].pages, 1);
        // A file of 20 pages does not fit the next of 16: the piece has the size of the file.
        immutable(&mut c, 4, 2, 20 * PAGE as u32);
        assert_eq!(c.plan(4, 1, true, &r), Plan::NeedPiece { pages: 20 });
        r.offer(0x2100_0000, 8, 20);
        assert!(matches!(
            c.plan(4, 1, true, &r),
            Plan::Fill { piece: 1, .. }
        ));
        // The third piece has 64.
        immutable(&mut c, 6, 4, 30 * PAGE as u32);
        assert_eq!(c.plan(6, 1, true, &r), Plan::NeedPiece { pages: 64 });
        r.offer(0x2200_0000, 9, 64);
        assert!(matches!(
            c.plan(6, 1, true, &r),
            Plan::Fill { piece: 2, .. }
        ));
        // A refused piece is not asked for again.
        immutable(&mut c, 5, 3, 60 * PAGE as u32);
        r.refused.store(true, Ordering::Release);
        assert_eq!(c.plan(5, 1, true, &r), Plan::Direct);
    }

    #[test]
    fn the_verdict_of_a_filler_that_found_the_lock_taken_is_applied_by_the_next_holder() {
        let r = shared();
        let mut c = cache(1, BUDGET_PAGES);
        immutable(&mut c, 3, 100, 10);
        immutable(&mut c, 4, 200, 10);
        let Plan::Fill { entry: a, .. } = c.plan(3, 1, true, &r) else {
            panic!("fill")
        };
        let Plan::Fill { entry: b, .. } = c.plan(4, 1, true, &r) else {
            panic!("fill")
        };
        // Both fillers publish without the lock: the first is done, the second failed.
        r.pending[usize::from(a)].store(1, Ordering::Release);
        r.pending[usize::from(b)].store(2, Ordering::Release);
        r.readers[usize::from(b)].store(0, Ordering::Release);
        r.due.store(true, Ordering::Release);
        r.readers[usize::from(a)].store(0, Ordering::Release);
        // The next look reconciles: the copy of 100 is ready, that of 200 is gone with its pages.
        immutable(&mut c, 5, 100, 10);
        assert!(matches!(c.plan(5, 1, true, &r), Plan::Hit { .. }));
        assert!(c.find_key(200).is_none());
        assert_eq!(c.used_pages, 1);
    }

    #[test]
    fn the_reset_of_a_fork_and_the_clear_are_in_place_and_keep_the_budget() {
        let r = shared();
        let mut c = cache(1, 20);
        immutable(&mut c, 3, 100, 10);
        assert!(matches!(read(&mut c, &r, 3), Plan::Fill { .. }));
        c.reset();
        assert_eq!((c.used_pages, c.pieces_made, c.budget_pages), (0, 0, 20));
        assert!(c.find_key(100).is_none());
        assert_eq!(c.plan(3, 1, true, &r), Plan::Ask);
        // The state of the cache is far above what a stack of a handler holds, so no operation
        // may build it as a value.
        assert!(core::mem::size_of::<Cache>() > 32 * 1024);
    }
}
