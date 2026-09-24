// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Handle tables (spec 5.1, 5.2). Lookup is O(1); the generation in every
//! handle catches stale ones; rights only shrink when copied. A table grows
//! by chunks up to a limit fixed at creation.

use abi::{Handle, Rights};
use core::ptr::NonNull;

pub const CHUNK: usize = 64;
pub const MAX_CHUNKS: usize = 256;
/// The largest limit a table accepts. The handle format allows 2^24 entries;
/// subproject 1 needs far fewer.
pub const MAX_HANDLES: u32 = (CHUNK * MAX_CHUNKS) as u32;
const NO_ENTRY: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleError {
    BadHandle,
    AccessDenied,
    LimitReached,
    NoMemory,
}

struct Entry<T> {
    object: Option<T>,
    rights: Rights,
    generation: u8,
    next_free: u32,
}

/// Storage for CHUNK entries.
pub struct Chunk<T> {
    entries: [Entry<T>; CHUNK],
}

/// Memory for chunks.
pub trait ChunkSource<T> {
    /// Uninitialised memory for one chunk.
    fn alloc_chunk(&mut self) -> Option<NonNull<Chunk<T>>>;

    /// Takes back a chunk's memory.
    ///
    /// # Safety
    /// `chunk` came from `alloc_chunk` of this source and its entries were dropped.
    unsafe fn free_chunk(&mut self, chunk: NonNull<Chunk<T>>);
}

/// A process's handles. The owner calls `release` before dropping it;
/// otherwise the chunks leak.
pub struct HandleTable<T> {
    chunks: [Option<NonNull<Chunk<T>>>; MAX_CHUNKS],
    chunk_count: usize,
    /// Entries initialised so far; each index below this is valid.
    used: u32,
    limit: u32,
    free_head: u32,
    live: u32,
}

// SAFETY: the table owns its chunks and the objects in them.
unsafe impl<T: Send> Send for HandleTable<T> {}

impl<T> HandleTable<T> {
    pub fn new(limit: u32) -> Self {
        assert!(
            limit <= MAX_HANDLES,
            "handle limit {limit} above {MAX_HANDLES}"
        );
        Self {
            chunks: [None; MAX_CHUNKS],
            chunk_count: 0,
            used: 0,
            limit,
            free_head: NO_ENTRY,
            live: 0,
        }
    }

    pub fn len(&self) -> u32 {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    fn entry(&self, index: u32) -> &Entry<T> {
        let chunk = self.chunks[index as usize / CHUNK].expect("an initialised chunk");
        // SAFETY: every chunk below chunk_count is initialised and owned by the table.
        unsafe { &(*chunk.as_ptr()).entries[index as usize % CHUNK] }
    }

    fn entry_mut(&mut self, index: u32) -> &mut Entry<T> {
        let chunk = self.chunks[index as usize / CHUNK].expect("an initialised chunk");
        // SAFETY: as in `entry`, and `&mut self` makes the access exclusive.
        unsafe { &mut (*chunk.as_ptr()).entries[index as usize % CHUNK] }
    }

    pub fn insert(
        &mut self,
        src: &mut impl ChunkSource<T>,
        object: T,
        rights: Rights,
    ) -> Result<Handle, HandleError> {
        let index = if self.free_head != NO_ENTRY {
            let i = self.free_head;
            self.free_head = self.entry(i).next_free;
            i
        } else {
            if self.used >= self.limit {
                return Err(HandleError::LimitReached);
            }
            if self.used as usize == self.chunk_count * CHUNK {
                let chunk = src.alloc_chunk().ok_or(HandleError::NoMemory)?;
                // SAFETY: fresh memory for one chunk; every entry is written before use.
                unsafe {
                    let entries = (&raw mut (*chunk.as_ptr()).entries).cast::<Entry<T>>();
                    for i in 0..CHUNK {
                        entries.add(i).write(Entry {
                            object: None,
                            rights: Rights::NONE,
                            generation: 1,
                            next_free: NO_ENTRY,
                        });
                    }
                }
                self.chunks[self.chunk_count] = Some(chunk);
                self.chunk_count += 1;
            }
            self.used += 1;
            self.used - 1
        };
        let entry = self.entry_mut(index);
        entry.object = Some(object);
        entry.rights = rights;
        let generation = entry.generation;
        self.live += 1;
        Ok(Handle::new(index, generation))
    }

    fn slot(&self, h: Handle) -> Result<u32, HandleError> {
        let i = h.index();
        if i >= self.used {
            return Err(HandleError::BadHandle);
        }
        let e = self.entry(i);
        if e.object.is_none() || e.generation != h.generation() {
            return Err(HandleError::BadHandle);
        }
        Ok(i)
    }

    pub fn get(&self, h: Handle) -> Result<(&T, Rights), HandleError> {
        let e = self.entry(self.slot(h)?);
        Ok((e.object.as_ref().expect("a live entry"), e.rights))
    }

    /// The object, when the handle carries at least `required`.
    pub fn get_with(&self, h: Handle, required: Rights) -> Result<&T, HandleError> {
        let (object, rights) = self.get(h)?;
        if rights.contains(required) {
            Ok(object)
        } else {
            Err(HandleError::AccessDenied)
        }
    }

    pub fn remove(&mut self, h: Handle) -> Result<(T, Rights), HandleError> {
        let i = self.slot(h)?;
        let free_head = self.free_head;
        let e = self.entry_mut(i);
        let object = e.object.take().expect("a live entry");
        let rights = e.rights;
        e.generation = if e.generation == u8::MAX {
            1
        } else {
            e.generation + 1
        };
        e.next_free = free_head;
        self.free_head = i;
        self.live -= 1;
        Ok((object, rights))
    }

    /// A new handle to the same object with a subset of the rights; the
    /// original must carry DUPLICATE.
    pub fn duplicate(
        &mut self,
        src: &mut impl ChunkSource<T>,
        h: Handle,
        rights: Rights,
    ) -> Result<Handle, HandleError>
    where
        T: Clone,
    {
        let (object, have) = self.get(h)?;
        if !have.contains(Rights::DUPLICATE) || !have.contains(rights) {
            return Err(HandleError::AccessDenied);
        }
        let copy = object.clone();
        self.insert(src, copy, rights)
    }

    /// Drops every object and gives every chunk back; the table is empty afterwards.
    pub fn release(&mut self, src: &mut impl ChunkSource<T>) {
        for c in 0..self.chunk_count {
            let chunk = self.chunks[c].take().expect("an initialised chunk");
            // SAFETY: the chunk's entries are initialised; each is dropped once
            // before its memory goes back.
            unsafe {
                let entries = (&raw mut (*chunk.as_ptr()).entries).cast::<Entry<T>>();
                for i in 0..CHUNK {
                    entries.add(i).drop_in_place();
                }
                src.free_chunk(chunk);
            }
        }
        self.chunk_count = 0;
        self.used = 0;
        self.free_head = NO_ENTRY;
        self.live = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::mem::MaybeUninit;
    use std::rc::Rc;

    #[derive(Default)]
    struct Boxes {
        left: usize,
        freed: usize,
    }

    impl<T> ChunkSource<T> for Boxes {
        fn alloc_chunk(&mut self) -> Option<NonNull<Chunk<T>>> {
            if self.left == 0 {
                return None;
            }
            self.left -= 1;
            let b: Box<MaybeUninit<Chunk<T>>> = Box::new_uninit();
            NonNull::new(Box::into_raw(b)).map(NonNull::cast)
        }

        unsafe fn free_chunk(&mut self, chunk: NonNull<Chunk<T>>) {
            self.freed += 1;
            // SAFETY: the chunk came from alloc_chunk; its entries were dropped.
            drop(unsafe { Box::from_raw(chunk.as_ptr().cast::<MaybeUninit<Chunk<T>>>()) });
        }
    }

    fn boxes(n: usize) -> Boxes {
        Boxes { left: n, freed: 0 }
    }

    const RW: Rights = Rights(Rights::SEND.0 | Rights::RECEIVE.0 | Rights::DUPLICATE.0);

    #[test]
    fn inserted_object_is_found_with_its_rights() {
        let mut src = boxes(1);
        let mut t = HandleTable::new(100);
        let h = t.insert(&mut src, 42, RW).unwrap();
        assert_eq!(t.get(h), Ok((&42, RW)));
        assert_eq!(t.len(), 1);
        t.release(&mut src);
    }

    #[test]
    fn handles_are_never_zero() {
        let mut src = boxes(1);
        let mut t = HandleTable::new(10);
        for i in 0..10 {
            assert_ne!(t.insert(&mut src, i, RW).unwrap(), Handle::INVALID);
        }
        t.release(&mut src);
    }

    #[test]
    fn removed_handle_goes_stale() {
        let mut src = boxes(1);
        let mut t = HandleTable::new(10);
        let h = t.insert(&mut src, 1, RW).unwrap();
        assert_eq!(t.remove(h), Ok((1, RW)));
        assert_eq!(t.get(h), Err(HandleError::BadHandle));
        assert_eq!(t.remove(h), Err(HandleError::BadHandle));
        t.release(&mut src);
    }

    #[test]
    fn freed_index_is_reused_with_a_new_generation() {
        let mut src = boxes(1);
        let mut t = HandleTable::new(10);
        let a = t.insert(&mut src, 1, RW).unwrap();
        t.remove(a).unwrap();
        let b = t.insert(&mut src, 2, RW).unwrap();
        assert_eq!(a.index(), b.index());
        assert_ne!(a.generation(), b.generation());
        assert_eq!(t.get(a), Err(HandleError::BadHandle));
        t.release(&mut src);
    }

    #[test]
    fn generation_wraps_without_reaching_zero() {
        let mut src = boxes(1);
        let mut t = HandleTable::new(1);
        for _ in 0..600 {
            let h = t.insert(&mut src, 0, RW).unwrap();
            assert_ne!(h.generation(), 0);
            t.remove(h).unwrap();
        }
        t.release(&mut src);
    }

    #[test]
    fn limit_is_enforced() {
        let mut src = boxes(1);
        let mut t = HandleTable::new(2);
        t.insert(&mut src, 1, RW).unwrap();
        t.insert(&mut src, 2, RW).unwrap();
        assert_eq!(t.insert(&mut src, 3, RW), Err(HandleError::LimitReached));
        t.release(&mut src);
    }

    #[test]
    fn table_grows_by_chunks() {
        let mut src = boxes(4);
        let mut t = HandleTable::new(1000);
        let hs: Vec<Handle> = (0..200)
            .map(|i| t.insert(&mut src, i, RW).unwrap())
            .collect();
        for (i, h) in hs.iter().enumerate() {
            assert_eq!(t.get(*h).unwrap().0, &i);
        }
        assert_eq!(src.left, 0);
        t.release(&mut src);
        assert_eq!(src.freed, 4);
    }

    #[test]
    fn duplicate_keeps_a_subset_of_rights() {
        let mut src = boxes(1);
        let mut t = HandleTable::new(10);
        let h = t.insert(&mut src, 5, RW).unwrap();
        let d = t.duplicate(&mut src, h, Rights::SEND).unwrap();
        assert_eq!(t.get(d), Ok((&5, Rights::SEND)));
        t.release(&mut src);
    }

    #[test]
    fn duplicate_needs_the_duplicate_right_and_no_new_rights() {
        let mut src = boxes(1);
        let mut t = HandleTable::new(10);
        let h = t.insert(&mut src, 5, RW).unwrap();
        assert_eq!(
            t.duplicate(&mut src, h, RW | Rights::MANAGE),
            Err(HandleError::AccessDenied)
        );
        let no_dup = t.insert(&mut src, 6, Rights::SEND).unwrap();
        assert_eq!(
            t.duplicate(&mut src, no_dup, Rights::SEND),
            Err(HandleError::AccessDenied)
        );
        t.release(&mut src);
    }

    #[test]
    fn get_with_checks_rights() {
        let mut src = boxes(1);
        let mut t = HandleTable::new(10);
        let h = t.insert(&mut src, 5, Rights::SEND).unwrap();
        assert_eq!(t.get_with(h, Rights::SEND), Ok(&5));
        assert_eq!(
            t.get_with(h, Rights::RECEIVE),
            Err(HandleError::AccessDenied)
        );
        t.release(&mut src);
    }

    #[test]
    fn forged_or_out_of_range_handles_are_bad() {
        let mut src = boxes(1);
        let mut t = HandleTable::new(10);
        let h = t.insert(&mut src, 5, RW).unwrap();
        assert_eq!(t.get(Handle::INVALID), Err(HandleError::BadHandle));
        assert_eq!(
            t.get(Handle::new(h.index() + 1, 1)),
            Err(HandleError::BadHandle)
        );
        assert_eq!(
            t.get(Handle::new(9_000_000, 1)),
            Err(HandleError::BadHandle)
        );
        assert_eq!(
            t.get(Handle::new(h.index(), h.generation().wrapping_add(1))),
            Err(HandleError::BadHandle)
        );
        t.release(&mut src);
    }

    #[test]
    fn release_drops_objects_and_returns_chunks() {
        let count = Rc::new(Cell::new(0));
        struct Counted(Rc<Cell<usize>>);
        impl Drop for Counted {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let mut src = boxes(2);
        let mut t = HandleTable::new(100);
        for _ in 0..70 {
            t.insert(&mut src, Counted(count.clone()), RW)
                .unwrap_or_else(|_| panic!("insert"));
        }
        t.release(&mut src);
        assert_eq!(count.get(), 70);
        assert_eq!(src.freed, 2);
        assert!(t.is_empty());
    }

    #[test]
    fn running_out_of_chunk_memory_is_reported() {
        let mut src = boxes(0);
        let mut t: HandleTable<u32> = HandleTable::new(10);
        assert_eq!(t.insert(&mut src, 1, RW), Err(HandleError::NoMemory));
    }
}
