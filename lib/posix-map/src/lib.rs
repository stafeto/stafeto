// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The memory map of the layer (spec 2, 3.2): a mirror of the kernel's table
//! of mappings of the process. A *piece* is one entry of that table (the
//! pages from `address`, their access, the object they show and the first
//! page of it); an *object* is a memory object the process has mapped, with
//! its handle. Splitting a piece (`protect`, `unmap`) cuts it as the
//! kernel's `Maps::split` does, so the map holds exactly as many pieces as
//! the kernel has entries, at most `MAX_PIECES` (abi::MAX_MAPPINGS), and a
//! range across several pieces is walked one piece at a time, as the
//! kernel's calls take a range inside one entry. `Space` records what each
//! page of the layer's room is for. No device window and no DMA object is
//! ever in the map: a POSIX process has no device resource. The handle type
//! is a parameter, so that the host tests use plain numbers.

#![cfg_attr(not(test), no_std)]

pub mod space;

use abi::{Access, MAX_MAPPINGS};
use core::mem::MaybeUninit;

/// The pieces of a map at most: the kernel's number of mappings of a
/// process.
pub const MAX_PIECES: usize = MAX_MAPPINGS as usize;

/// The objects of a map at most. Few pieces show an object of their own: the
/// heap's chunks, the loader's segments and the large, shared and file
/// mappings.
pub const MAX_OBJECTS: usize = 32;

/// The page of the map.
pub const PAGE: usize = 4096;

/// One entry of the kernel's table: `pages` pages from `address` show the
/// pages of `object` from page `offset` on, with `access`. 24 bytes: the
/// map lies in the program's data, which the quota pays for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Piece {
    pub address: usize,
    pages: u32,
    offset: u32,
    access: u8,
    /// The index of the object in the map.
    object: u8,
}

impl Piece {
    pub fn new(
        address: usize,
        pages: usize,
        access: Access,
        offset: usize,
        object: usize,
    ) -> Piece {
        Piece {
            address,
            pages: u32::try_from(pages).expect("pages of a piece"),
            offset: u32::try_from(offset).expect("offset of a piece"),
            access: access.raw() as u8,
            object: u8::try_from(object).expect("object of a piece"),
        }
    }

    pub const fn pages(&self) -> usize {
        self.pages as usize
    }

    /// The first page of the object the piece shows.
    pub const fn offset(&self) -> usize {
        self.offset as usize
    }

    pub fn access(&self) -> Access {
        Access::from_raw(u64::from(self.access)).expect("an access of a piece")
    }

    pub fn with_access(self, access: Access) -> Piece {
        Piece {
            access: access.raw() as u8,
            ..self
        }
    }

    /// The object of the piece.
    pub const fn object(&self) -> usize {
        self.object as usize
    }

    /// The first address past the piece.
    pub const fn end(&self) -> usize {
        self.address + self.pages as usize * PAGE
    }
}

/// What the layer knows of the file behind a shared object, to write it
/// back (`msync`, unmapping).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Back {
    /// The descriptor the layer holds for it.
    pub fd: i32,
    page: u32,
    /// The key of the file at the process service's rendezvous of shared
    /// memory, 0 for an object that is not registered there.
    pub key: u64,
}

impl Back {
    /// `offset` is the byte of the file the object's first byte shows, a
    /// multiple of the page.
    pub fn new(fd: i32, offset: u64, key: u64) -> Back {
        Back {
            fd,
            page: u32::try_from(offset / PAGE as u64).expect("offset of a mapped file"),
            key,
        }
    }

    pub fn offset(&self) -> u64 {
        u64::from(self.page) * PAGE as u64
    }
}

/// One memory object the process has mapped.
#[derive(Debug, PartialEq, Eq)]
pub struct Object<H> {
    pub handle: H,
    /// Shared with other processes and with a forked child (MAP_SHARED).
    pub shared: bool,
    pub back: Option<Back>,
}

/// Why a map refused a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The change needs more pieces than the map can hold (the kernel's
    /// LIMIT_REACHED).
    Full,
    /// An address off a page boundary, no pages, or a range that wraps.
    Malformed,
    /// The range meets a piece the map holds.
    Overlap,
}

/// The pieces of a process, sorted by address, and its objects. An empty
/// map is all zeros and lies in the program's zeroed data.
pub struct Map<H> {
    pieces: [MaybeUninit<Piece>; MAX_PIECES],
    objects: [Option<Object<H>>; MAX_OBJECTS],
    len: usize,
}

impl<H> Map<H> {
    pub const fn new() -> Self {
        Map {
            pieces: [const { MaybeUninit::uninit() }; MAX_PIECES],
            objects: [const { None }; MAX_OBJECTS],
            len: 0,
        }
    }

    /// The pieces (the kernel's entries).
    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn is_full(&self) -> bool {
        self.len == MAX_PIECES
    }

    /// Whether the map has a place for one more object.
    pub fn has_room_for_object(&self) -> bool {
        self.objects.iter().any(Option::is_none)
    }

    /// The places left for pieces.
    pub const fn room(&self) -> usize {
        MAX_PIECES - self.len
    }

    /// The pieces, by address.
    pub fn iter(&self) -> impl Iterator<Item = &Piece> {
        self.pieces[..self.len].iter().map(|piece| {
            // SAFETY: the first `len` entries hold a piece.
            unsafe { piece.assume_init_ref() }
        })
    }

    pub fn piece(&self, index: usize) -> &Piece {
        assert!(index < self.len, "a piece of the map");
        // SAFETY: below `len`.
        unsafe { self.pieces[index].assume_init_ref() }
    }

    fn piece_mut(&mut self, index: usize) -> &mut Piece {
        assert!(index < self.len, "a piece of the map");
        // SAFETY: below `len`.
        unsafe { self.pieces[index].assume_init_mut() }
    }

    /// The object at `index`.
    pub fn object(&self, index: usize) -> &Object<H> {
        self.objects[index].as_ref().expect("an object of the map")
    }

    pub fn object_mut(&mut self, index: usize) -> &mut Object<H> {
        self.objects[index].as_mut().expect("an object of the map")
    }

    /// The objects, with their indices.
    pub fn objects(&self) -> impl Iterator<Item = (usize, &Object<H>)> {
        self.objects
            .iter()
            .enumerate()
            .filter_map(|(i, o)| o.as_ref().map(|o| (i, o)))
    }

    /// The pieces of all the objects, in pages.
    pub fn pages(&self) -> usize {
        self.iter().map(|piece| piece.pages()).sum()
    }

    /// The pieces of an object.
    pub fn pieces_of(&self, object: usize) -> impl Iterator<Item = &Piece> {
        self.iter().filter(move |piece| piece.object() == object)
    }

    /// The index of the piece that holds `address`.
    pub fn find(&self, address: usize) -> Option<usize> {
        self.iter()
            .position(|piece| piece.address <= address && address < piece.end())
    }

    fn checked_end(address: usize, pages: usize) -> Result<usize, Refused> {
        if pages == 0 || !address.is_multiple_of(PAGE) {
            return Err(Refused::Malformed);
        }
        pages
            .checked_mul(PAGE)
            .and_then(|bytes| address.checked_add(bytes))
            .ok_or(Refused::Malformed)
    }

    /// Adds `object` with one piece of all its `pages` (or `pages` of them
    /// from page `offset`) at `address`; the handle of a refused object
    /// goes with it. Returns the index of the object.
    pub fn push(
        &mut self,
        address: usize,
        pages: usize,
        access: Access,
        offset: usize,
        object: Object<H>,
    ) -> Result<usize, Refused> {
        let end = Self::checked_end(address, pages)?;
        if self.is_full() {
            return Err(Refused::Full);
        }
        if self
            .iter()
            .any(|held| held.address < end && address < held.end())
        {
            return Err(Refused::Overlap);
        }
        let index = self
            .objects
            .iter()
            .position(Option::is_none)
            .ok_or(Refused::Full)?;
        self.objects[index] = Some(object);
        let at = self
            .iter()
            .take_while(|held| held.address < address)
            .count();
        self.insert_piece(at, Piece::new(address, pages, access, offset, index));
        Ok(index)
    }

    /// Adds a piece of an object the map holds already (a child's piece of
    /// the object of the piece before it, or a second mapping of an
    /// object).
    pub fn push_piece(
        &mut self,
        address: usize,
        pages: usize,
        access: Access,
        offset: usize,
        object: usize,
    ) -> Result<(), Refused> {
        let end = Self::checked_end(address, pages)?;
        if self.is_full() {
            return Err(Refused::Full);
        }
        if self
            .iter()
            .any(|held| held.address < end && address < held.end())
        {
            return Err(Refused::Overlap);
        }
        assert!(self.objects[object].is_some(), "an object of the map");
        let at = self
            .iter()
            .take_while(|held| held.address < address)
            .count();
        self.insert_piece(at, Piece::new(address, pages, access, offset, object));
        Ok(())
    }

    fn insert_piece(&mut self, at: usize, piece: Piece) {
        let mut i = self.len;
        while i > at {
            let moved = *self.piece(i - 1);
            self.pieces[i].write(moved);
            i -= 1;
        }
        self.pieces[at].write(piece);
        self.len += 1;
    }

    fn remove_piece(&mut self, at: usize) {
        for i in at..self.len - 1 {
            let moved = *self.piece(i + 1);
            self.pieces[i].write(moved);
        }
        self.len -= 1;
    }

    /// The pieces the range `pages` pages from `address` meets, as the
    /// sub-ranges inside each: `(index, address, pages)`, by address. The
    /// range may reach past the pieces and across gaps.
    pub fn walk(
        &self,
        address: usize,
        pages: usize,
    ) -> impl Iterator<Item = (usize, usize, usize)> + '_ {
        let end = address.saturating_add(pages.saturating_mul(PAGE));
        self.iter().enumerate().filter_map(move |(i, piece)| {
            let from = piece.address.max(address);
            let to = piece.end().min(end);
            (from < to).then(|| (i, from, (to - from) / PAGE))
        })
    }

    /// The places a change of `pages` pages from `address` needs for the
    /// edges of the pieces it cuts: at most two for each end of the range.
    pub fn edges(&self, address: usize, pages: usize) -> usize {
        let mut needed = 0;
        for (i, from, count) in self.walk(address, pages) {
            let piece = self.piece(i);
            needed += usize::from(from > piece.address);
            needed += usize::from(from + count * PAGE < piece.end());
        }
        needed
    }

    /// Whether every page of the range lies in a piece.
    pub fn covers(&self, address: usize, pages: usize) -> bool {
        let mut at = address;
        for (_, from, count) in self.walk(address, pages) {
            if from != at {
                return false;
            }
            at = from + count * PAGE;
        }
        at == address.saturating_add(pages.saturating_mul(PAGE))
    }

    /// Cuts the piece at `index` so that exactly the `pages` pages from
    /// `address` are a piece of their own, as the kernel does (`split`);
    /// returns the index of that piece. The range must lie inside the
    /// piece; Full when the cut needs more places than are free (nothing
    /// changes then).
    fn cut(&mut self, index: usize, address: usize, pages: usize) -> Result<usize, Refused> {
        let piece = *self.piece(index);
        let end = address + pages * PAGE;
        assert!(piece.address <= address && end <= piece.end() && pages != 0);
        let before = (address - piece.address) / PAGE;
        let after = (piece.end() - end) / PAGE;
        if usize::from(before != 0) + usize::from(after != 0) > self.room() {
            return Err(Refused::Full);
        }
        let mut at = index;
        let object = piece.object();
        if before != 0 {
            self.insert_piece(
                at,
                Piece::new(
                    piece.address,
                    before,
                    piece.access(),
                    piece.offset(),
                    object,
                ),
            );
            at += 1;
        }
        *self.piece_mut(at) = Piece::new(
            address,
            pages,
            piece.access(),
            piece.offset() + before,
            object,
        );
        if after != 0 {
            self.insert_piece(
                at + 1,
                Piece::new(
                    end,
                    after,
                    piece.access(),
                    piece.offset() + before + pages,
                    object,
                ),
            );
        }
        Ok(at)
    }

    /// The pages of the range inside the piece at `index` get `access`
    /// (the kernel's `mem_protect` succeeded on them); the piece is cut as
    /// the kernel cut it. Full when the cut needs more places than are
    /// free.
    pub fn protect(
        &mut self,
        index: usize,
        address: usize,
        pages: usize,
        access: Access,
    ) -> Result<(), Refused> {
        let at = self.cut(index, address, pages)?;
        let cut = *self.piece(at);
        *self.piece_mut(at) = cut.with_access(access);
        Ok(())
    }

    /// The pages of the range inside the piece at `index` leave the map
    /// (the kernel's `mem_unmap` succeeded on them). Returns the object when
    /// it has no piece left; the caller closes its handle.
    pub fn unmap(
        &mut self,
        index: usize,
        address: usize,
        pages: usize,
    ) -> Result<Option<Object<H>>, Refused> {
        let at = self.cut(index, address, pages)?;
        let object = self.piece(at).object();
        self.remove_piece(at);
        if self.iter().any(|piece| piece.object() == object) {
            Ok(None)
        } else {
            Ok(self.objects[object].take())
        }
    }

    /// As `unmap`, and the object stays in the map when it has no piece
    /// left (the caller maps it again).
    pub fn unmap_keep(
        &mut self,
        index: usize,
        address: usize,
        pages: usize,
    ) -> Result<(), Refused> {
        let at = self.cut(index, address, pages)?;
        self.remove_piece(at);
        Ok(())
    }

    /// The map is empty again, and its handles go without a drop: in a
    /// forked child they are its parent's values, which name nothing of
    /// the child's (spec 2, 3.2).
    pub fn forget(&mut self) {
        self.len = 0;
        for object in &mut self.objects {
            if let Some(object) = object.take() {
                core::mem::forget(object);
            }
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

    fn object(handle: u32, _pages: usize) -> Object<u32> {
        Object {
            handle,
            shared: false,
            back: None,
        }
    }

    fn held(map: &Map<u32>) -> Vec<(usize, usize, Access, usize, u32)> {
        map.iter()
            .map(|p| {
                (
                    p.address,
                    p.pages(),
                    p.access(),
                    p.offset(),
                    map.object(p.object()).handle,
                )
            })
            .collect()
    }

    /// The heap grows three times and each chunk lands after the last: the
    /// map holds the three, by address, and their pages add up.
    #[test]
    fn three_growths_of_the_heap_make_three_pieces() {
        let mut map = Map::new();
        let mut at = 0x1000_0000;
        for (handle, pages) in [(1, 16), (2, 20), (3, 64)] {
            map.push(at, pages, Access::ReadWrite, 0, object(handle, pages))
                .unwrap();
            at += pages * PAGE;
        }
        assert_eq!(
            held(&map),
            [
                (0x1000_0000, 16, Access::ReadWrite, 0, 1),
                (0x1001_0000, 20, Access::ReadWrite, 0, 2),
                (0x1002_4000, 64, Access::ReadWrite, 0, 3)
            ]
        );
        assert_eq!((map.len(), map.pages()), (3, 100));
        assert_eq!(map.iter().last().unwrap().end(), 0x1006_4000);
    }

    /// The 129th piece is refused, and the map still holds the 128; the 33rd
    /// object is refused too.
    #[test]
    fn a_map_holds_128_pieces_and_32_objects() {
        assert_eq!((MAX_PIECES, MAX_OBJECTS), (128, 32));
        let mut map = Map::new();
        let one = map
            .push(0x1000_0000, 1, Access::ReadWrite, 0, object(0, 1))
            .unwrap();
        for i in 1..MAX_PIECES {
            assert!(!map.is_full());
            map.push_piece(0x1000_0000 + i * PAGE, 1, Access::ReadWrite, i, one)
                .unwrap();
        }
        assert!(map.is_full());
        assert_eq!(
            map.push(0x2000_0000, 1, Access::ReadWrite, 0, object(999, 1)),
            Err(Refused::Full)
        );
        assert_eq!(
            map.push_piece(0x2000_0000, 1, Access::ReadWrite, 0, one),
            Err(Refused::Full)
        );
        assert_eq!(map.len(), 128);
        let mut map = Map::new();
        for i in 0..MAX_OBJECTS {
            map.push(
                0x1000_0000 + i * PAGE,
                1,
                Access::Read,
                0,
                object(i as u32, 1),
            )
            .unwrap();
        }
        assert_eq!(
            map.push(0x3000_0000, 1, Access::Read, 0, object(99, 1)),
            Err(Refused::Full)
        );
    }

    /// A refused object and a dropped map give their handles back once
    /// each.
    #[test]
    fn handles_go_once() {
        use std::rc::Rc;
        let handle = Rc::new(());
        let mut map = Map::new();
        let make = || Object {
            handle: handle.clone(),
            shared: false,
            back: None,
        };
        map.push(0x1000, 1, Access::Read, 0, make()).unwrap();
        assert_eq!(Rc::strong_count(&handle), 2);
        assert_eq!(
            map.push(0x1000, 1, Access::Read, 0, make()),
            Err(Refused::Overlap)
        );
        assert_eq!(Rc::strong_count(&handle), 2);
        map.push(0x2000, 1, Access::Read, 0, make()).unwrap();
        assert_eq!(Rc::strong_count(&handle), 3);
        drop(map);
        assert_eq!(Rc::strong_count(&handle), 1);
    }

    /// A forgotten map is empty, drops none of its handles and takes new
    /// pieces where the old lay.
    #[test]
    fn a_forgotten_map_drops_nothing() {
        use std::rc::Rc;
        let handle = Rc::new(());
        let mut map = Map::new();
        for i in 0..3 {
            map.push(
                0x1000 * (i + 1),
                1,
                Access::Read,
                0,
                Object {
                    handle: handle.clone(),
                    shared: false,
                    back: None,
                },
            )
            .unwrap();
        }
        map.forget();
        assert_eq!((map.len(), map.pages()), (0, 0));
        assert_eq!(Rc::strong_count(&handle), 4);
        map.push(
            0x1000,
            1,
            Access::Read,
            0,
            Object {
                handle: Rc::new(()),
                shared: false,
                back: None,
            },
        )
        .unwrap();
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn a_malformed_or_overlapping_piece_is_refused() {
        let mut map = Map::new();
        map.push(0x4000, 2, Access::Read, 0, object(1, 2)).unwrap();
        let at = |m: &mut Map<u32>, a: usize, n: usize| m.push(a, n, Access::Read, 0, object(2, n));
        assert_eq!(at(&mut map, 0x4001, 1), Err(Refused::Malformed));
        assert_eq!(at(&mut map, 0x9000, 0), Err(Refused::Malformed));
        assert_eq!(at(&mut map, usize::MAX - 0xFFF, 2), Err(Refused::Malformed));
        assert_eq!(at(&mut map, 0x5000, 1), Err(Refused::Overlap));
        assert_eq!(at(&mut map, 0x3000, 2), Err(Refused::Overlap));
        assert!(at(&mut map, 0x3000, 1).is_ok());
        assert!(at(&mut map, 0x6000, 1).is_ok());
        assert_eq!(map.len(), 3);
    }

    /// A protect in the middle of a piece cuts it in three, with the right
    /// offsets, as the kernel does; the pieces keep their object.
    #[test]
    fn protect_in_the_middle_cuts_three_pieces_with_offsets() {
        let mut map = Map::new();
        map.push(0x10000, 8, Access::ReadWrite, 0, object(7, 8))
            .unwrap();
        map.protect(0, 0x12000, 2, Access::None).unwrap();
        assert_eq!(
            held(&map),
            [
                (0x10000, 2, Access::ReadWrite, 0, 7),
                (0x12000, 2, Access::None, 2, 7),
                (0x14000, 4, Access::ReadWrite, 4, 7)
            ]
        );
        // The same range again changes only its access.
        map.protect(1, 0x12000, 2, Access::ReadWrite).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map.piece(1).access(), Access::ReadWrite);
        // An edge cuts in two.
        map.protect(2, 0x14000, 1, Access::Read).unwrap();
        assert_eq!(map.len(), 4);
        assert_eq!(map.piece(2).offset(), 4);
        assert_eq!(map.piece(3).offset(), 5);
    }

    /// With 127 pieces a cut in the middle needs two places and finds one:
    /// Full, and the map is as it was.
    #[test]
    fn a_cut_without_places_changes_nothing() {
        let mut map = Map::new();
        map.push(0x10000, 8, Access::ReadWrite, 0, object(7, 8))
            .unwrap();
        for i in 0..126 {
            map.push_piece(0x100000 + i * 2 * PAGE, 1, Access::Read, i, 0)
                .unwrap();
        }
        assert_eq!(map.len(), 127);
        let before = held(&map);
        assert_eq!(map.protect(0, 0x12000, 2, Access::None), Err(Refused::Full));
        assert_eq!(held(&map), before);
        // An edge needs one place, and there is one.
        map.protect(0, 0x10000, 2, Access::None).unwrap();
        assert!(map.is_full());
    }

    /// Unmapping the middle leaves the edges; the object goes with its last
    /// piece and not before.
    #[test]
    fn unmapping_gives_the_object_back_with_its_last_piece() {
        let mut map = Map::new();
        map.push(0x10000, 4, Access::ReadWrite, 0, object(9, 4))
            .unwrap();
        assert_eq!(map.unmap(0, 0x11000, 2).unwrap(), None);
        assert_eq!(
            held(&map),
            [
                (0x10000, 1, Access::ReadWrite, 0, 9),
                (0x13000, 1, Access::ReadWrite, 3, 9)
            ]
        );
        assert_eq!(map.unmap(0, 0x10000, 1).unwrap(), None);
        let gone = map.unmap(0, 0x13000, 1).unwrap().unwrap();
        assert_eq!(gone.handle, 9);
        assert!(map.is_empty());
    }

    /// A kept object survives its last piece and takes a piece again.
    #[test]
    fn a_kept_object_takes_a_piece_again() {
        let mut map = Map::new();
        let o = map
            .push(0x10000, 4, Access::ReadWrite, 0, object(5, 4))
            .unwrap();
        map.unmap_keep(0, 0x10000, 4).unwrap();
        assert!(map.is_empty());
        assert_eq!(map.object(o).handle, 5);
        map.push_piece(0x10000, 4, Access::Read, 0, o).unwrap();
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn a_walk_visits_each_piece_of_a_range_and_sees_gaps() {
        let mut map = Map::new();
        map.push(0x10000, 2, Access::ReadWrite, 0, object(1, 2))
            .unwrap();
        map.push(0x12000, 2, Access::Read, 0, object(2, 2)).unwrap();
        map.push(0x15000, 1, Access::Read, 0, object(3, 1)).unwrap();
        let walked: Vec<_> = map.walk(0x11000, 4).collect();
        assert_eq!(walked, [(0, 0x11000, 1), (1, 0x12000, 2)]);
        assert!(map.covers(0x11000, 3));
        assert!(!map.covers(0x11000, 4));
        assert!(!map.covers(0xF000, 2));
        assert_eq!(map.edges(0x11000, 3), 1);
        assert_eq!(map.edges(0x11000, 1), 1);
        assert_eq!(map.edges(0x10000, 1), 1);
        assert_eq!(map.edges(0x10000, 4), 0);
    }
}
