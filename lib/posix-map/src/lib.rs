// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The memory map of the layer (spec 2, 3.2): the handle of each memory
//! object the process has mapped, with where it lies and with what access.
//! The loader hands over the segments, the stack and the start area, and
//! the layer's heap adds a chunk each time it grows, so that a later
//! `fork` can copy every byte of the process's memory. At most
//! `MAX_REGIONS` entries, the kernel's number of mappings of a process
//! (abi::MAX_MAPPINGS): the map holds no more regions than the kernel
//! lets the process map. No device window and no DMA object is ever in it:
//! a POSIX process has no device resource. The handle type is a parameter,
//! so that the host tests use plain numbers.

#![cfg_attr(not(test), no_std)]

use abi::{Access, MAX_MAPPINGS};
use core::mem::MaybeUninit;

/// The entries of a map at most.
pub const MAX_REGIONS: usize = MAX_MAPPINGS as usize;

/// One mapped memory object: `pages` whole pages from `address`, mapped
/// with `access`, and the handle of the object.
#[derive(Debug, PartialEq, Eq)]
pub struct Region<H> {
    pub address: usize,
    pub pages: usize,
    pub access: Access,
    pub handle: H,
}

impl<H> Region<H> {
    /// The first address past the region.
    pub const fn end(&self) -> usize {
        self.address + self.pages * PAGE
    }
}

const PAGE: usize = 4096;

/// Why a map took no region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The map holds MAX_REGIONS already.
    Full,
    /// An address off a page boundary, no pages, or a range that wraps.
    Malformed,
    /// The range meets a region the map holds.
    Overlap,
}

/// The regions of a process, in the order they were added. The first
/// `len` entries hold a region and the rest nothing, so that an empty map
/// is all zeros and lies in the program's zeroed data.
pub struct Map<H> {
    entries: [MaybeUninit<Region<H>>; MAX_REGIONS],
    len: usize,
}

impl<H> Map<H> {
    pub const fn new() -> Self {
        Map {
            entries: [const { MaybeUninit::uninit() }; MAX_REGIONS],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn is_full(&self) -> bool {
        self.len == MAX_REGIONS
    }

    /// Adds `region`; the handle of a refused one goes with it.
    pub fn push(&mut self, region: Region<H>) -> Result<(), Refused> {
        if self.is_full() {
            return Err(Refused::Full);
        }
        let end = region
            .pages
            .checked_mul(PAGE)
            .and_then(|bytes| region.address.checked_add(bytes));
        match end {
            Some(end) if region.pages > 0 && region.address.is_multiple_of(PAGE) => {
                if self
                    .iter()
                    .any(|held| held.address < end && region.address < held.end())
                {
                    return Err(Refused::Overlap);
                }
            }
            _ => return Err(Refused::Malformed),
        }
        self.entries[self.len].write(region);
        self.len += 1;
        Ok(())
    }

    /// The regions, in the order they were added.
    pub fn iter(&self) -> impl Iterator<Item = &Region<H>> {
        self.entries[..self.len].iter().map(|entry| {
            // SAFETY: the first `len` entries were written by `push`.
            unsafe { entry.assume_init_ref() }
        })
    }

    /// The pages of all the regions.
    pub fn pages(&self) -> usize {
        self.iter().map(|region| region.pages).sum()
    }
}

impl<H> Drop for Map<H> {
    fn drop(&mut self) {
        for entry in &mut self.entries[..self.len] {
            // SAFETY: the first `len` entries were written by `push`, and
            // none is read again.
            unsafe { entry.assume_init_drop() };
        }
    }
}

impl<H> Default for Map<H> {
    fn default() -> Self {
        Map::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(address: usize, pages: usize, handle: u32) -> Region<u32> {
        Region {
            address,
            pages,
            access: Access::ReadWrite,
            handle,
        }
    }

    /// The heap grows three times and each chunk lands after the last: the
    /// map holds the three, in order, and their pages add up.
    #[test]
    fn three_growths_of_the_heap_make_three_regions() {
        let mut map = Map::new();
        let mut at = 0x1000_0000;
        for (handle, pages) in [(1, 16), (2, 20), (3, 64)] {
            map.push(region(at, pages, handle)).unwrap();
            at += pages * PAGE;
        }
        let held: Vec<_> = map.iter().map(|r| (r.address, r.pages, r.handle)).collect();
        assert_eq!(
            held,
            [
                (0x1000_0000, 16, 1),
                (0x1001_0000, 20, 2),
                (0x1002_4000, 64, 3)
            ]
        );
        assert_eq!((map.len(), map.pages()), (3, 100));
        assert_eq!(map.iter().last().unwrap().end(), 0x1006_4000);
    }

    /// The 129th region is refused, and the map still holds the 128.
    #[test]
    fn a_map_holds_128_regions() {
        assert_eq!(MAX_REGIONS, 128);
        let mut map = Map::new();
        for i in 0..MAX_REGIONS {
            assert!(!map.is_full());
            map.push(region(0x1000_0000 + i * PAGE, 1, i as u32))
                .unwrap();
        }
        assert!(map.is_full());
        assert_eq!(map.push(region(0x2000_0000, 1, 999)), Err(Refused::Full));
        assert_eq!(map.len(), 128);
        assert_eq!(map.iter().last().unwrap().handle, 127);
    }

    /// A refused region and a dropped map give their handles back once each.
    #[test]
    fn handles_go_once() {
        use std::rc::Rc;
        let handle = Rc::new(());
        let mut map = Map::new();
        let at = |address| Region {
            address,
            pages: 1,
            access: Access::Read,
            handle: handle.clone(),
        };
        map.push(at(0x1000)).unwrap();
        assert_eq!(Rc::strong_count(&handle), 2);
        assert_eq!(map.push(at(0x1000)), Err(Refused::Overlap));
        assert_eq!(Rc::strong_count(&handle), 2);
        map.push(at(0x2000)).unwrap();
        assert_eq!(Rc::strong_count(&handle), 3);
        drop(map);
        assert_eq!(Rc::strong_count(&handle), 1);
    }

    #[test]
    fn a_malformed_or_overlapping_region_is_refused() {
        let mut map = Map::new();
        map.push(region(0x4000, 2, 1)).unwrap();
        assert_eq!(map.push(region(0x4001, 1, 2)), Err(Refused::Malformed));
        assert_eq!(map.push(region(0x9000, 0, 2)), Err(Refused::Malformed));
        assert_eq!(
            map.push(region(usize::MAX - 0xFFF, 2, 2)),
            Err(Refused::Malformed)
        );
        assert_eq!(map.push(region(0x5000, 1, 2)), Err(Refused::Overlap));
        assert_eq!(map.push(region(0x3000, 2, 2)), Err(Refused::Overlap));
        assert_eq!(map.push(region(0x3000, 1, 2)), Ok(()));
        assert_eq!(map.push(region(0x6000, 1, 3)), Ok(()));
        assert_eq!(map.len(), 3);
    }
}
