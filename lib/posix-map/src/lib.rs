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
//! page of the layer's room is for. No device window is ever in the map: a
//! POSIX process has no device resource. Two pieces are the layer's own and
//! of a kind of their own (`Kind`): the buffer of the screen, the *display
//! piece* (spec 3, 7.3), a DMA object, and the process's shared buffer with
//! the network service, the *network buffer piece*. `fork` copies neither
//! into the child (`Map::inherited` leaves them out, so the child has a hole
//! there), `munmap` and `mprotect` refuse both (`Refused::Special`, EINVAL),
//! and only `unmap_kind` takes one out. The handle type is a parameter, so
//! that the host tests use plain numbers.

#![cfg_attr(not(test), no_std)]

pub mod space;

use abi::{Access, MAX_MAPPINGS};
use core::mem::MaybeUninit;

/// The pieces of a map at most: the kernel's number of mappings of a
/// process.
pub const MAX_PIECES: usize = MAX_MAPPINGS as usize;

/// The objects of a map at most. Few pieces show an object of their own: the
/// heap's chunks, the loader's segments, the large, shared and file
/// mappings, and the stack of each thread (64 threads at most). As many as
/// the pieces: a map of 128 pieces may hold an object in each.
pub const MAX_OBJECTS: usize = MAX_PIECES;

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
    /// The pages just below `address` that no object shows and that nothing
    /// else may take: the guard of a thread's stack. They are no entry of
    /// the kernel's table and cost no frame; a reference to one is a
    /// translation fault.
    guard: u16,
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
            guard: 0,
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

    /// The pages of the hole just below the piece.
    pub const fn guard(&self) -> usize {
        self.guard as usize
    }

    /// The first address of the hole below the piece (the piece's own when
    /// it has none).
    pub const fn hole(&self) -> usize {
        self.address - self.guard as usize * PAGE
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

    pub fn with_guard(self, pages: usize) -> Piece {
        Piece {
            guard: u16::try_from(pages).expect("guard of a piece"),
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
    /// The place of the pin the layer holds for the file's description: a
    /// place of the table of descriptors outside the numbers, which no
    /// descriptor of the program names or replaces.
    pub pin: i32,
    /// The generation of the place: the pin is the one the mapping took.
    pub pin_generation: u64,
    page: u32,
    /// The identity of the file (device and inode, never 0).
    pub key: u64,
    /// The object is registered at the process service's rendezvous of
    /// shared memory under `key`.
    pub registered: bool,
}

impl Back {
    /// `offset` is the byte of the file the object's first byte shows, a
    /// multiple of the page.
    pub fn new(pin: i32, pin_generation: u64, offset: u64, key: u64, registered: bool) -> Back {
        Back {
            pin,
            pin_generation,
            page: u32::try_from(offset / PAGE as u64).expect("offset of a mapped file"),
            key,
            registered,
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
    /// The program may map the object writable (the descriptor was open
    /// for writing); `mprotect` to write is EACCES otherwise.
    pub may_write: bool,
    /// A piece of the object was writable: only then are its pages written
    /// back to the file.
    pub dirty: bool,
    /// An object of the program's image (code or read-only data) the loader
    /// filled: immutable, without a file, and shared with a forked child
    /// without a copy.
    pub image: bool,
    /// What the object is to the layer: a plain mapping, or one of the two
    /// pieces that `fork` does not copy, `munmap` and `mprotect` do not
    /// change, and only `unmap_kind` takes out.
    pub kind: Kind,
    /// The key of an anonymous shared object for waits by address between
    /// processes (0: none). A forked child shows the same object with the
    /// same key.
    pub wait_key: u64,
}

impl<H> Object<H> {
    pub fn new(handle: H, shared: bool, back: Option<Back>) -> Self {
        Object {
            handle,
            shared,
            back,
            may_write: true,
            dirty: false,
            image: false,
            kind: Kind::Plain,
            wait_key: 0,
        }
    }

    /// The buffer of the screen: writable, never shared with a child.
    pub fn display(handle: H) -> Self {
        Object {
            kind: Kind::Display,
            ..Object::new(handle, false, None)
        }
    }

    /// The shared buffer with the network service: writable, never shared
    /// with a child.
    pub fn net_buffer(handle: H) -> Self {
        Object {
            kind: Kind::NetBuffer,
            ..Object::new(handle, false, None)
        }
    }

    /// Whether the object is one of the layer's own pieces.
    pub fn special(&self) -> bool {
        self.kind != Kind::Plain
    }
}

/// The kinds of the objects of a map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A mapping of the program or of the layer that `fork`, `munmap` and
    /// `mprotect` treat as POSIX says.
    Plain,
    /// The buffer of the screen (spec 3, 7.3).
    Display,
    /// The shared buffer of the process with the network service.
    NetBuffer,
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
    /// The range meets the display piece or the network buffer piece, which
    /// only `unmap_kind` changes.
    Special,
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

    /// Whether some page of the range lies in the display piece or in the
    /// network buffer piece.
    pub fn meets_special(&self, address: usize, pages: usize) -> bool {
        self.walk(address, pages)
            .any(|(i, ..)| self.object(self.piece(i).object()).special())
    }

    /// The pieces a forked child gets: all but the display piece and the
    /// network buffer piece.
    pub fn inherited(&self) -> impl Iterator<Item = &Piece> {
        self.iter()
            .filter(|piece| !self.object(piece.object()).special())
    }

    /// The first address and the pages of the piece of `kind` (Display or
    /// NetBuffer), when the map has one.
    pub fn kind_piece(&self, kind: Kind) -> Option<(usize, usize)> {
        self.iter()
            .find(|piece| self.object(piece.object()).kind == kind)
            .map(|piece| (piece.address, piece.pages()))
    }

    /// The display piece's first address and pages, when the map has one.
    pub fn display_piece(&self) -> Option<(usize, usize)> {
        self.kind_piece(Kind::Display)
    }

    /// The display piece leaves the map: `unmap_kind` of Display.
    pub fn unmap_display(&mut self) -> Option<(usize, usize, Object<H>)> {
        self.unmap_kind(Kind::Display)
    }

    /// The piece of `kind` leaves the map (the kernel's `mem_unmap` of it
    /// succeeded): its address, its pages and the object, which the caller
    /// closes. None without one.
    pub fn unmap_kind(&mut self, kind: Kind) -> Option<(usize, usize, Object<H>)> {
        let (address, pages) = self.kind_piece(kind)?;
        let at = self.find(address)?;
        let object = self.piece(at).object();
        self.remove_piece(at);
        let object = self.objects[object].take()?;
        Some((address, pages, object))
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
        // The hole below the piece stays with the piece's first part.
        if before != 0 {
            self.insert_piece(
                at,
                Piece::new(
                    piece.address,
                    before,
                    piece.access(),
                    piece.offset(),
                    object,
                )
                .with_guard(piece.guard()),
            );
            at += 1;
        }
        *self.piece_mut(at) = Piece::new(
            address,
            pages,
            piece.access(),
            piece.offset() + before,
            object,
        )
        .with_guard(if before == 0 { piece.guard() } else { 0 });
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

    /// The piece at `index` has `pages` pages of hole below it (0 for none).
    pub fn set_guard(&mut self, index: usize, pages: usize) {
        let piece = *self.piece(index);
        *self.piece_mut(index) = piece.with_guard(pages);
    }

    /// A range of `pages` pages from `address` is given up: every hole it
    /// touches is released as far as the range takes it, and what lies
    /// below the range goes with it (a hole is one run next to its piece).
    /// A range that reaches the piece takes the whole hole; one that ends
    /// inside the hole leaves the pages from its end on. `freed(address,
    /// pages)` gets each run of the hole given up.
    pub fn trim_holes(
        &mut self,
        address: usize,
        pages: usize,
        mut freed: impl FnMut(usize, usize),
    ) {
        let end = address.saturating_add(pages.saturating_mul(PAGE));
        for index in 0..self.len {
            let piece = *self.piece(index);
            if piece.guard == 0 || piece.address <= address || end <= piece.hole() {
                continue;
            }
            // The range starts below the piece and ends above the hole's
            // start: it touches the hole.
            let keep = if end >= piece.address {
                0
            } else {
                (piece.address - end) / PAGE
            };
            freed(piece.hole(), piece.guard() - keep);
            self.set_guard(index, keep);
        }
    }

    /// The pages of all the holes.
    pub fn guard_pages(&self) -> usize {
        self.iter().map(Piece::guard).sum()
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
        if self.object(self.piece(index).object()).special() {
            return Err(Refused::Special);
        }
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
        if self.object(self.piece(index).object()).special() {
            return Err(Refused::Special);
        }
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
        if self.object(self.piece(index).object()).special() {
            return Err(Refused::Special);
        }
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
        Object::new(handle, false, None)
    }

    fn object_plain(handle: u32) -> Object<u32> {
        Object::new(handle, false, None)
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

    /// The 129th piece is refused, and the map still holds the 128; the 97th
    /// object is refused too.
    #[test]
    fn a_map_holds_128_pieces_and_96_objects() {
        assert_eq!((MAX_PIECES, MAX_OBJECTS), (128, 128));
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
        let make = || Object::new(handle.clone(), false, None);
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
                Object::new(handle.clone(), false, None),
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
            Object::new(Rc::new(()), false, None),
        )
        .unwrap();
        assert_eq!(map.len(), 1);
    }

    /// The image mark belongs to the object: a new object has none, and the
    /// mark stays through a cut of the object's piece and through a forget
    /// and a rebuild of the map.
    #[test]
    fn the_image_mark_stays_with_the_object() {
        assert!(!object(1, 1).image);
        let mut map = Map::new();
        let mut code = object(1, 4);
        code.image = true;
        code.may_write = false;
        let index = map.push(0x20_0000, 4, Access::ReadExec, 0, code).unwrap();
        map.push(0x30_0000, 1, Access::ReadWrite, 0, object(2, 1))
            .unwrap();
        map.unmap_keep(index, 0x20_1000, 1).unwrap();
        assert!(map.object(index).image && !map.object(index).may_write);
        assert!(!map.iter().all(|p| map.object(p.object()).image));
        map.forget();
        let mut again = object(1, 4);
        again.image = true;
        let index = map.push(0x20_0000, 4, Access::ReadExec, 0, again).unwrap();
        assert!(map.object(index).image);
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

    /// A hole stays with the first part of a cut piece and goes with the
    /// pieces that lose their first page.
    #[test]
    fn a_hole_follows_the_first_part_of_its_piece() {
        let mut map = Map::new();
        map.push(0x20000, 8, Access::ReadWrite, 0, object(1, 8))
            .unwrap();
        map.set_guard(0, 2);
        assert_eq!((map.piece(0).guard(), map.piece(0).hole()), (2, 0x1E000));
        assert_eq!(map.guard_pages(), 2);
        map.protect(0, 0x23000, 2, Access::Read).unwrap();
        assert_eq!(map.iter().map(|p| p.guard()).collect::<Vec<_>>(), [2, 0, 0]);
        // The first page cut away: the second piece starts a new run.
        map.protect(0, 0x20000, 1, Access::Read).unwrap();
        assert_eq!(
            map.iter().map(|p| p.guard()).collect::<Vec<_>>(),
            [2, 0, 0, 0]
        );
        // Access changes keep the hole.
        map.protect(0, 0x20000, 1, Access::ReadWrite).unwrap();
        assert_eq!(map.piece(0).guard(), 2);
        assert_eq!(map.guard_pages(), 2);
    }

    /// Giving up a range frees the hole as far as the range takes it.
    #[test]
    fn a_range_frees_the_hole_it_touches() {
        let mut freed = Vec::new();
        let mut run = |map: &mut Map<u32>, address: usize, pages: usize| {
            freed.clear();
            map.trim_holes(address, pages, |a, n| freed.push((a, n)));
            (freed.clone(), map.piece(0).guard())
        };
        let make = || {
            let mut map = Map::new();
            map.push(0x20000, 4, Access::ReadWrite, 0, object(1, 4))
                .unwrap();
            map.set_guard(0, 3); // hole 0x1D000..0x20000
            map
        };
        // The stack alone, or a range above the hole: nothing.
        assert_eq!(run(&mut make(), 0x20000, 4), (vec![], 3));
        assert_eq!(run(&mut make(), 0x30000, 4), (vec![], 3));
        // A range below the hole: nothing.
        assert_eq!(run(&mut make(), 0x10000, 3), (vec![], 3));
        // The whole hole and the stack, or the hole and more.
        assert_eq!(run(&mut make(), 0x1D000, 7), (vec![(0x1D000, 3)], 0));
        assert_eq!(run(&mut make(), 0x10000, 0x20), (vec![(0x1D000, 3)], 0));
        // The top of the hole to the stack: all of it.
        assert_eq!(run(&mut make(), 0x1F000, 1), (vec![(0x1D000, 3)], 0));
        // The lowest page of the hole: the pages from its end on are kept.
        assert_eq!(run(&mut make(), 0x1D000, 1), (vec![(0x1D000, 1)], 2));
        // A range that ends inside the hole frees what lies below its end.
        assert_eq!(run(&mut make(), 0x1C000, 2), (vec![(0x1D000, 1)], 2));
        assert_eq!(run(&mut make(), 0x1E000, 1), (vec![(0x1D000, 2)], 1));
    }

    /// The network buffer piece is kept from a forked child, refused by
    /// `munmap` and `mprotect`, and taken out by `unmap_kind` alone, as the
    /// display piece is; the one does not stand for the other.
    #[test]
    fn the_network_buffer_piece_follows_the_rule_of_the_display_piece() {
        let mut map = with_screen();
        map.push(0x4000_0000, 64, Access::ReadWrite, 0, Object::net_buffer(8))
            .unwrap();
        let child: Vec<usize> = map.inherited().map(|p| p.address).collect();
        assert_eq!(child, [0x1000_0000, 0x3000_0000]);
        assert_eq!(map.kind_piece(Kind::NetBuffer), Some((0x4000_0000, 64)));
        assert_eq!(map.display_piece(), Some((0x2000_0000, 250)));
        let at = map.find(0x4000_0000).unwrap();
        assert!(map.meets_special(0x4000_0000 + PAGE, 1));
        assert_eq!(map.unmap(at, 0x4000_0000, 64), Err(Refused::Special));
        assert_eq!(map.unmap_keep(at, 0x4000_0000, 1), Err(Refused::Special));
        assert_eq!(
            map.protect(at, 0x4000_0000, 64, Access::Read),
            Err(Refused::Special)
        );
        let (address, pages, object) = map.unmap_kind(Kind::NetBuffer).unwrap();
        assert_eq!(
            (address, pages, object.handle, object.kind),
            (0x4000_0000, 64, 8, Kind::NetBuffer)
        );
        // The display piece stays.
        assert_eq!(map.display_piece(), Some((0x2000_0000, 250)));
        assert!(map.unmap_kind(Kind::NetBuffer).is_none());
        assert!(!map.meets_special(0x4000_0000, 64));
    }

    /// A map with the heap's chunk, the display piece (250 pages) and a
    /// file mapping, as a process that owns the screen has.
    fn with_screen() -> Map<u32> {
        let mut map = Map::new();
        map.push(0x1000_0000, 16, Access::ReadWrite, 0, object(1, 16))
            .unwrap();
        map.push(0x2000_0000, 250, Access::ReadWrite, 0, Object::display(7))
            .unwrap();
        map.push(0x3000_0000, 4, Access::Read, 0, object(3, 4))
            .unwrap();
        map
    }

    /// `fork` copies the pieces `inherited` names: the display piece is not
    /// among them, so the child has a hole there.
    #[test]
    fn fork_leaves_the_display_piece_out() {
        let map = with_screen();
        let child: Vec<usize> = map.inherited().map(|p| p.address).collect();
        assert_eq!(child, [0x1000_0000, 0x3000_0000]);
        assert_eq!(map.display_piece(), Some((0x2000_0000, 250)));
        assert_eq!(map.len(), 3);
        let plain = Map::<u32>::new();
        assert_eq!(
            (plain.display_piece(), plain.inherited().count()),
            (None, 0)
        );
    }

    /// `munmap` and `mprotect` on any part of the display piece are refused
    /// (EINVAL), whole or cut, and nothing changes.
    #[test]
    fn munmap_and_mprotect_refuse_the_display_piece() {
        let mut map = with_screen();
        let before = held(&map);
        let at = map.find(0x2000_0000).unwrap();
        for (address, pages) in [
            (0x2000_0000, 250),
            (0x2000_0000, 1),
            (0x2000_0000 + 100 * PAGE, 3),
        ] {
            assert!(map.meets_special(address, pages));
            assert_eq!(map.unmap(at, address, pages), Err(Refused::Special));
            assert_eq!(map.unmap_keep(at, address, pages), Err(Refused::Special));
            assert_eq!(
                map.protect(at, address, pages, Access::Read),
                Err(Refused::Special)
            );
        }
        // A range that reaches the piece from a neighbour meets it too.
        assert!(map.meets_special(0x2000_0000 - PAGE, 2));
        assert!(!map.meets_special(0x1000_0000, 16));
        assert!(!map.meets_special(0x3000_0000, 4));
        assert_eq!(held(&map), before);
        // The other pieces still change.
        let heap = map.find(0x1000_0000).unwrap();
        map.protect(heap, 0x1000_0000, 4, Access::Read).unwrap();
        assert_eq!(map.len(), 4);
    }

    /// The close, the exit and `exec` take the piece out whole and give the
    /// object back for its handle to close; a second call finds none.
    #[test]
    fn unmap_display_gives_the_object_back() {
        let mut map = with_screen();
        let (address, pages, object) = map.unmap_display().unwrap();
        assert_eq!(
            (address, pages, object.handle, object.kind),
            (0x2000_0000, 250, 7, Kind::Display)
        );
        assert_eq!(map.len(), 2);
        assert!(!map.meets_special(0x2000_0000, 250));
        assert!(map.unmap_display().is_none());
        // The pages are free for another mapping, which `munmap` may take.
        let again = map
            .push(0x2000_0000, 250, Access::ReadWrite, 0, object_plain(9))
            .unwrap();
        assert_eq!(
            map.unmap(map.find(0x2000_0000).unwrap(), 0x2000_0000, 250)
                .unwrap()
                .map(|o| o.handle),
            Some(9)
        );
        let _ = again;
    }
}
