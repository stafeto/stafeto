// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The mappings of a process (spec 7.4, 7.7): up to MAX_MAPPINGS ranges of
//! whole pages of its address space, each showing pages of one memory
//! object, in a table of 2 KiB. A mapping holds a counted reference to its
//! object, `T`, and the rights of the handle it was made through; a long
//! call that works on it marks it busy, and the other calls on it get
//! BAD_STATE until the mark goes. `mem_unmap` and `mem_protect` take
//! exactly one whole mapping. Every operation walks the table once: O(1)
//! with the constant MAX_MAPPINGS.

use crate::PAGE_SHIFT;
use abi::{Error, Rights};

/// Mappings of one process, at most.
pub const MAX_MAPPINGS: usize = abi::MAX_MAPPINGS as usize;

/// One mapping: `pages` pages from `start` show the pages of `object`
/// from page `offset` on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping<T> {
    /// The first address, a whole page in the lower half.
    pub start: u64,
    /// The memory object, whose reference the mapping holds.
    pub object: T,
    pub pages: u32,
    /// The first page of the object it shows.
    pub offset: u32,
    /// MAP_READ, MAP_WRITE and MAP_EXEC of the handle it was made through:
    /// how far `mem_protect` may take it (spec 5.2).
    pub rights: Rights,
    busy: bool,
}

impl<T> Mapping<T> {
    /// A mapping no call works on.
    pub fn new(start: u64, pages: u32, offset: u32, object: T, rights: Rights) -> Mapping<T> {
        Mapping {
            start,
            object,
            pages,
            offset,
            rights,
            busy: false,
        }
    }

    /// The first address past it.
    pub fn end(&self) -> u64 {
        self.start + (u64::from(self.pages) << PAGE_SHIFT)
    }

    /// Whether a long call works on it.
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Whether it shares a page with `pages` pages from `start`.
    fn overlaps(&self, start: u64, pages: u64) -> bool {
        start < self.end() && self.start < start + (pages << PAGE_SHIFT)
    }
}

/// The mapping table of a process: MAX_MAPPINGS entries, 2 KiB, one block
/// of the process's pool (spec 7.8).
#[derive(Debug)]
pub struct Maps<T> {
    entries: [Option<Mapping<T>>; MAX_MAPPINGS],
}

impl<T: Copy> Maps<T> {
    pub const fn new() -> Maps<T> {
        Maps {
            entries: [const { None }; MAX_MAPPINGS],
        }
    }

    /// Mappings in the table.
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(Option::is_none)
    }

    /// The mappings in the table, busy or not, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &Mapping<T>> {
        self.entries.iter().flatten()
    }

    /// INVALID_ARGS when `pages` pages from `start` share a page with a
    /// mapping, busy or not (spec 7.4, 11).
    pub fn check_free(&self, start: u64, pages: u64) -> Result<(), Error> {
        if self
            .entries
            .iter()
            .flatten()
            .any(|m| m.overlaps(start, pages))
        {
            Err(Error::InvalidArgs)
        } else {
            Ok(())
        }
    }

    /// Puts `mapping` in the table and returns its index; LIMIT_REACHED
    /// when MAX_MAPPINGS are there. The caller checked its range
    /// (`check_free`): a mapping over another stops the kernel.
    pub fn insert(&mut self, mapping: Mapping<T>) -> Result<usize, Error> {
        assert!(
            self.check_free(mapping.start, mapping.pages.into()).is_ok(),
            "a mapping over another"
        );
        let index = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(Error::LimitReached)?;
        self.entries[index] = Some(mapping);
        Ok(index)
    }

    /// The index of the mapping of exactly `pages` pages from `start`;
    /// INVALID_ARGS when no mapping is that range: a part of one, more than
    /// one, or none (spec 7.4).
    pub fn find(&self, start: u64, pages: u64) -> Result<usize, Error> {
        self.entries
            .iter()
            .position(|m| m.is_some_and(|m| m.start == start && u64::from(m.pages) == pages))
            .ok_or(Error::InvalidArgs)
    }

    /// As `find`, and BAD_STATE when a long call works on the mapping
    /// (spec 7.7).
    pub fn find_idle(&self, start: u64, pages: u64) -> Result<usize, Error> {
        let index = self.find(start, pages)?;
        if self.get(index).busy {
            return Err(Error::BadState);
        }
        Ok(index)
    }

    /// The mapping at `index`, which is in the table.
    pub fn get(&self, index: usize) -> &Mapping<T> {
        self.entries[index]
            .as_ref()
            .expect("a mapping at the index")
    }

    /// Marks the mapping at `index` busy while a long call works on it, or
    /// idle once the call ended.
    pub fn set_busy(&mut self, index: usize, busy: bool) {
        self.entries[index]
            .as_mut()
            .expect("a mapping at the index")
            .busy = busy;
    }

    /// A `mem_map` that stopped midway (spec 7.7): the mapping at `index`
    /// keeps its first `pages` pages, the ones mapped, and is idle; with
    /// none it leaves the table, and its object comes back for its
    /// reference to go.
    pub fn shrink_to(&mut self, index: usize, pages: u32) -> Option<T> {
        let m = self.entries[index]
            .as_mut()
            .expect("a mapping at the index");
        assert!(pages <= m.pages, "a mapping shrinks past its end");
        if pages == 0 {
            return Some(self.remove(index).object);
        }
        m.pages = pages;
        m.busy = false;
        None
    }

    /// A `mem_unmap` that stopped midway (spec 7.7): the mapping at `index`
    /// loses its first `pages` pages, the ones unmapped, and is idle; with
    /// none left it leaves the table, and its object comes back for its
    /// reference to go.
    pub fn drop_prefix(&mut self, index: usize, pages: u32) -> Option<T> {
        let m = self.entries[index]
            .as_mut()
            .expect("a mapping at the index");
        assert!(pages <= m.pages, "a mapping loses more than it has");
        if pages == m.pages {
            return Some(self.remove(index).object);
        }
        m.start += u64::from(pages) << PAGE_SHIFT;
        m.offset += pages;
        m.pages -= pages;
        m.busy = false;
        None
    }

    /// Takes the mapping at `index` out of the table.
    pub fn remove(&mut self, index: usize) -> Mapping<T> {
        self.entries[index].take().expect("a mapping at the index")
    }

    /// Takes every mapping out of the table, busy or not, in one pass, and
    /// hands each to `f`: the teardown of the process (spec 7.7). The table
    /// is empty afterwards.
    pub fn drain(&mut self, f: impl FnMut(Mapping<T>)) {
        self.entries.iter_mut().filter_map(Option::take).for_each(f);
    }
}

impl<T: Copy> Default for Maps<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::NonNull;

    const PAGE: u64 = 1 << PAGE_SHIFT;
    const RW: Rights = Rights(Rights::MAP_READ.0 | Rights::MAP_WRITE.0);

    fn mapping(start: u64, pages: u32, object: u32) -> Mapping<u32> {
        Mapping::new(start, pages, 0, object, RW)
    }

    #[test]
    fn mapping_table_fits_one_block() {
        assert_eq!(core::mem::size_of::<Mapping<NonNull<u8>>>(), 32);
        assert_eq!(core::mem::size_of::<Maps<NonNull<u8>>>(), 2048);
        assert_eq!(core::mem::size_of::<Maps<u32>>(), 2048);
    }

    #[test]
    fn overlap_is_refused() {
        let mut maps = Maps::new();
        maps.insert(mapping(0x10 * PAGE, 4, 1)).unwrap();
        // Pages 0x10-0x13 are taken: each range that shares one of them
        // fails, the last page included.
        for (start, pages) in [
            (0x10, 4),
            (0x13, 1),
            (0x0C, 5),
            (0x0F, 2),
            (0x12, 10),
            (0x00, 0x100),
            (0x11, 1),
        ] {
            assert_eq!(
                maps.check_free(start * PAGE, pages),
                Err(Error::InvalidArgs),
                "{start:#x}, {pages}"
            );
        }
        for (start, pages) in [(0x0C, 4), (0x14, 1), (0x00, 0x10), (0x14, 0x100)] {
            assert_eq!(maps.check_free(start * PAGE, pages), Ok(()), "{start:#x}");
        }
        maps.insert(mapping(0x14 * PAGE, 1, 2)).unwrap();
        assert_eq!(maps.len(), 2);
        // A busy mapping takes its range as well.
        let i = maps.find(0x14 * PAGE, 1).unwrap();
        maps.set_busy(i, true);
        assert_eq!(maps.check_free(0x14 * PAGE, 1), Err(Error::InvalidArgs));
    }

    #[test]
    #[should_panic(expected = "a mapping over another")]
    fn a_mapping_over_another_stops() {
        let mut maps = Maps::new();
        maps.insert(mapping(0x10 * PAGE, 4, 1)).unwrap();
        let _ = maps.insert(mapping(0x13 * PAGE, 4, 2));
    }

    #[test]
    fn lookup_takes_whole_mappings_only() {
        let mut maps = Maps::new();
        let a = maps.insert(mapping(0x10 * PAGE, 4, 1)).unwrap();
        let b = maps.insert(mapping(0x14 * PAGE, 2, 2)).unwrap();
        assert_eq!(maps.find(0x10 * PAGE, 4), Ok(a));
        assert_eq!(maps.find(0x14 * PAGE, 2), Ok(b));
        assert_eq!(maps.get(b).object, 2);
        // A part, more than one, two together, a neighbour, nothing.
        for (start, pages) in [
            (0x10, 3),
            (0x11, 3),
            (0x10, 5),
            (0x10, 6),
            (0x0F, 4),
            (0x14, 1),
            (0x20, 1),
        ] {
            assert_eq!(
                maps.find(start * PAGE, pages),
                Err(Error::InvalidArgs),
                "{start:#x}, {pages}"
            );
        }
        let removed = maps.remove(a);
        assert_eq!((removed.object, removed.pages), (1, 4));
        assert_eq!(maps.find(0x10 * PAGE, 4), Err(Error::InvalidArgs));
    }

    #[test]
    fn limit_is_64() {
        let mut maps = Maps::new();
        for i in 0..MAX_MAPPINGS as u64 {
            maps.insert(mapping(i * PAGE, 1, i as u32)).unwrap();
        }
        assert_eq!(maps.len(), 64);
        let next = mapping(64 * PAGE, 1, 64);
        assert_eq!(maps.check_free(64 * PAGE, 1), Ok(()));
        assert_eq!(maps.insert(next), Err(Error::LimitReached));
        let i = maps.find(7 * PAGE, 1).unwrap();
        maps.remove(i);
        assert_eq!(maps.iter().count(), 63);
        assert!(maps.iter().all(|m| m.object != 7));
        assert_eq!(maps.insert(next), Ok(i));
        let mut drained = 0;
        maps.drain(|_| drained += 1);
        assert_eq!((drained, maps.is_empty()), (64, true));
    }

    #[test]
    fn busy_mapping_refuses_other_calls() {
        let mut maps = Maps::new();
        let i = maps.insert(mapping(0x10 * PAGE, 4, 1)).unwrap();
        assert_eq!(maps.find_idle(0x10 * PAGE, 4), Ok(i));
        maps.set_busy(i, true);
        assert!(maps.get(i).is_busy());
        assert_eq!(maps.find_idle(0x10 * PAGE, 4), Err(Error::BadState));
        // A range that is no mapping stays INVALID_ARGS: the lookup first.
        assert_eq!(maps.find_idle(0x10 * PAGE, 3), Err(Error::InvalidArgs));
        assert_eq!(maps.find(0x10 * PAGE, 4), Ok(i));
        maps.set_busy(i, false);
        assert_eq!(maps.find_idle(0x10 * PAGE, 4), Ok(i));
    }

    #[test]
    fn shrinking_keeps_the_mapped_prefix() {
        let mut maps = Maps::new();
        let i = maps
            .insert(Mapping::new(0x10 * PAGE, 10, 3, 1, RW))
            .unwrap();
        maps.set_busy(i, true);
        assert_eq!(maps.shrink_to(i, 4), None);
        let m = *maps.get(i);
        assert_eq!(
            (m.start, m.pages, m.offset, m.busy),
            (0x10 * PAGE, 4, 3, false)
        );
        assert_eq!(maps.find_idle(0x10 * PAGE, 4), Ok(i));
        assert_eq!(maps.check_free(0x14 * PAGE, 6), Ok(()));
        maps.set_busy(i, true);
        assert_eq!(maps.shrink_to(i, 0), Some(1));
        assert!(maps.is_empty());
    }

    #[test]
    fn dropping_a_prefix_moves_the_start() {
        let mut maps = Maps::new();
        let i = maps
            .insert(Mapping::new(0x10 * PAGE, 10, 3, 1, RW))
            .unwrap();
        maps.set_busy(i, true);
        assert_eq!(maps.drop_prefix(i, 4), None);
        let m = *maps.get(i);
        assert_eq!(
            (m.start, m.pages, m.offset, m.busy),
            (0x14 * PAGE, 6, 7, false)
        );
        assert_eq!(maps.find_idle(0x14 * PAGE, 6), Ok(i));
        assert_eq!(maps.check_free(0x10 * PAGE, 4), Ok(()));
        maps.set_busy(i, true);
        assert_eq!(maps.drop_prefix(i, 6), Some(1));
        assert!(maps.is_empty());
    }
}
