// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Handle tables (spec 5.1, 5.2). Lookup is O(1); the generation in every
//! handle catches stale ones, and an entry freed at the last generation is
//! retired, so a table never hands out the same value twice. Rights only
//! shrink when copied. A table grows by chunks up to a limit fixed at creation.

use abi::{Error, Handle, Rights};
use core::ptr::NonNull;

pub const CHUNK: usize = 64;
pub const MAX_CHUNKS: usize = 256;
/// The largest limit a table accepts. The handle format allows 2^16 entries;
/// subproject 1 needs far fewer.
pub const MAX_HANDLES: u32 = (CHUNK * MAX_CHUNKS) as u32;
const NO_ENTRY: u32 = u32::MAX;

const _: () = assert!(MAX_HANDLES <= 1 << Handle::INDEX_BITS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleError {
    BadHandle,
    WrongType,
    AccessDenied,
    InvalidArgs,
    LimitReached,
    NoMemory,
}

impl From<HandleError> for Error {
    fn from(e: HandleError) -> Error {
        match e {
            HandleError::BadHandle => Error::BadHandle,
            HandleError::WrongType => Error::WrongType,
            HandleError::AccessDenied => Error::AccessDenied,
            HandleError::InvalidArgs => Error::InvalidArgs,
            HandleError::LimitReached => Error::LimitReached,
            HandleError::NoMemory => Error::NoMemory,
        }
    }
}

struct Entry<T> {
    object: Option<T>,
    rights: Rights,
    generation: u64,
    next_free: u32,
}

/// Storage for CHUNK entries.
pub struct Chunk<T> {
    entries: [Entry<T>; CHUNK],
}

/// Memory for chunks.
///
/// # Safety
/// `alloc_chunk` returns memory valid for reads and writes of
/// `size_of::<Chunk<T>>()` bytes, aligned to `align_of::<Chunk<T>>()`, that
/// nothing else uses until the table hands it back through `free_chunk`.
pub unsafe trait ChunkSource<T> {
    /// Uninitialised memory for one chunk.
    fn alloc_chunk(&mut self) -> Option<NonNull<Chunk<T>>>;

    /// Takes back a chunk's memory.
    ///
    /// # Safety
    /// `chunk` came from `alloc_chunk` of this source and its entries were dropped.
    unsafe fn free_chunk(&mut self, chunk: NonNull<Chunk<T>>);
}

/// A process's handles. The owner calls `release` before dropping it.
///
/// Every entry below `used` is live, free (on the free list) or retired
/// (freed at the last generation and never handed out again); retired
/// entries still count toward the limit.
pub struct HandleTable<T> {
    chunks: [Option<NonNull<Chunk<T>>>; MAX_CHUNKS],
    chunk_count: usize,
    /// Entries initialised so far; each index below this is valid.
    used: u32,
    limit: u32,
    free_head: u32,
    live: u32,
    free_count: u32,
    retired: u32,
    /// Generation of fresh entries: 1, except in tests that start near the end.
    first_generation: u64,
}

// SAFETY: the table owns its chunks and the objects in them.
unsafe impl<T: Send> Send for HandleTable<T> {}

impl<T> HandleTable<T> {
    /// An empty table for at most `limit` entries; `InvalidArgs` above MAX_HANDLES.
    pub fn new(limit: u32) -> Result<Self, HandleError> {
        if limit > MAX_HANDLES {
            return Err(HandleError::InvalidArgs);
        }
        Ok(Self {
            chunks: [None; MAX_CHUNKS],
            chunk_count: 0,
            used: 0,
            limit,
            free_head: NO_ENTRY,
            live: 0,
            free_count: 0,
            retired: 0,
            first_generation: 1,
        })
    }

    /// A table whose fresh entries start at `generation`, so tests reach
    /// retirement in a few steps.
    #[cfg(test)]
    fn with_first_generation(limit: u32, generation: u64) -> Self {
        let mut t = Self::new(limit).expect("a valid limit");
        t.first_generation = generation;
        t
    }

    pub fn len(&self) -> u32 {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Entries retired at the last generation.
    pub fn retired(&self) -> u32 {
        self.retired
    }

    /// How many inserts succeed before `LimitReached`, whatever the chunk
    /// source can give; lets a transfer check the receiver first.
    pub fn room(&self) -> u32 {
        self.free_count + (self.limit - self.used)
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
            self.free_count -= 1;
            i
        } else {
            if self.used >= self.limit {
                return Err(HandleError::LimitReached);
            }
            if self.used as usize == self.chunk_count * CHUNK {
                let chunk = src.alloc_chunk().ok_or(HandleError::NoMemory)?;
                let generation = self.first_generation;
                // SAFETY: fresh memory for one chunk; every entry is written before use.
                unsafe {
                    let entries = (&raw mut (*chunk.as_ptr()).entries).cast::<Entry<T>>();
                    for i in 0..CHUNK {
                        entries.add(i).write(Entry {
                            object: None,
                            rights: Rights::NONE,
                            generation,
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

    /// What `kind` makes of the object, checked in the order of the system
    /// calls (spec 11): a live handle (else BadHandle), an object `kind`
    /// accepts (else WrongType), then at least `required` (else AccessDenied).
    pub fn get_as<U>(
        &self,
        h: Handle,
        required: Rights,
        kind: impl FnOnce(&T) -> Option<U>,
    ) -> Result<U, HandleError> {
        let (object, rights) = self.get(h)?;
        let typed = kind(object).ok_or(HandleError::WrongType)?;
        if rights.contains(required) {
            Ok(typed)
        } else {
            Err(HandleError::AccessDenied)
        }
    }

    /// Takes the object out. The entry moves to the next generation, or
    /// retires when this was its last one.
    pub fn remove(&mut self, h: Handle) -> Result<(T, Rights), HandleError> {
        let i = self.slot(h)?;
        let free_head = self.free_head;
        let e = self.entry_mut(i);
        let object = e.object.take().expect("a live entry");
        let rights = e.rights;
        let retire = e.generation == Handle::MAX_GENERATION;
        if !retire {
            e.generation += 1;
            e.next_free = free_head;
        }
        self.live -= 1;
        if retire {
            self.retired += 1;
        } else {
            self.free_head = i;
            self.free_count += 1;
        }
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
        self.release_with(src, drop);
    }

    /// Hands every object to `f`, once each, and gives every chunk back;
    /// the table is empty afterwards. Objects that need more than a drop
    /// when their handle goes, such as counted references, leave this way.
    pub fn release_with(&mut self, src: &mut impl ChunkSource<T>, mut f: impl FnMut(T)) {
        for c in 0..self.chunk_count {
            let chunk = self.chunks[c].take().expect("an initialised chunk");
            // SAFETY: the chunk's entries are initialised; each object is
            // taken out once, then each entry is dropped once before its
            // memory goes back.
            unsafe {
                let entries = (&raw mut (*chunk.as_ptr()).entries).cast::<Entry<T>>();
                for i in 0..CHUNK {
                    if let Some(object) = (*entries.add(i)).object.take() {
                        f(object);
                    }
                    entries.add(i).drop_in_place();
                }
                src.free_chunk(chunk);
            }
        }
        self.chunk_count = 0;
        self.used = 0;
        self.free_head = NO_ENTRY;
        self.live = 0;
        self.free_count = 0;
        self.retired = 0;
    }
}

impl<T> Drop for HandleTable<T> {
    fn drop(&mut self) {
        // A failed host test unwinds through its tables; a second panic here
        // would abort the whole test run.
        #[cfg(test)]
        if std::thread::panicking() {
            return;
        }
        // Only a check: the work is `release`'s, which needs the chunk
        // source. The kernel builds without debug assertions, so the check
        // is a plain assert.
        assert!(
            self.chunk_count == 0,
            "handle table dropped without release"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashSet;
    use std::mem::MaybeUninit;
    use std::rc::Rc;

    #[derive(Default)]
    struct Boxes {
        left: usize,
        freed: usize,
    }

    // SAFETY: each chunk is a fresh Box, freed only in `free_chunk`.
    unsafe impl<T> ChunkSource<T> for Boxes {
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

    fn table<T>(limit: u32) -> HandleTable<T> {
        HandleTable::new(limit).unwrap_or_else(|e| panic!("new({limit}): {e:?}"))
    }

    const RW: Rights = Rights(Rights::SEND.0 | Rights::RECEIVE.0 | Rights::DUPLICATE.0);
    const LAST: u64 = Handle::MAX_GENERATION;

    #[test]
    fn inserted_object_is_found_with_its_rights() {
        let mut src = boxes(1);
        let mut t = table(100);
        let h = t.insert(&mut src, 42, RW).unwrap();
        assert_eq!(t.get(h), Ok((&42, RW)));
        assert_eq!(t.len(), 1);
        t.release(&mut src);
    }

    #[test]
    #[should_panic(expected = "handle table dropped without release")]
    fn a_table_dropped_without_release_stops() {
        let mut src = boxes(1);
        let mut t = table(10);
        t.insert(&mut src, 1, RW).unwrap();
        drop(t);
    }

    #[test]
    fn handles_are_never_zero() {
        let mut src = boxes(1);
        let mut t = table(10);
        for i in 0..10 {
            assert_ne!(t.insert(&mut src, i, RW).unwrap(), Handle::INVALID);
        }
        t.release(&mut src);
    }

    #[test]
    fn limit_above_max_handles_is_rejected() {
        assert!(matches!(
            HandleTable::<u32>::new(MAX_HANDLES + 1),
            Err(HandleError::InvalidArgs)
        ));
        assert!(HandleTable::<u32>::new(MAX_HANDLES).is_ok());
    }

    #[test]
    fn removed_handle_goes_stale() {
        let mut src = boxes(1);
        let mut t = table(10);
        let h = t.insert(&mut src, 1, RW).unwrap();
        assert_eq!(t.remove(h), Ok((1, RW)));
        assert_eq!(t.get(h), Err(HandleError::BadHandle));
        assert_eq!(t.remove(h), Err(HandleError::BadHandle));
        t.release(&mut src);
    }

    #[test]
    fn stale_handle_is_bad_for_every_operation() {
        let mut src = boxes(1);
        let mut t = table(10);
        let h = t.insert(&mut src, 1, RW).unwrap();
        t.remove(h).unwrap();
        t.insert(&mut src, 2, RW).unwrap();
        assert_eq!(t.get(h), Err(HandleError::BadHandle));
        assert_eq!(t.get_with(h, Rights::NONE), Err(HandleError::BadHandle));
        assert_eq!(
            t.duplicate(&mut src, h, Rights::NONE),
            Err(HandleError::BadHandle)
        );
        assert_eq!(t.remove(h), Err(HandleError::BadHandle));
        assert_eq!(t.len(), 1);
        t.release(&mut src);
    }

    #[test]
    fn len_and_room_follow_insert_and_remove() {
        let mut src = boxes(1);
        let mut t = table(5);
        assert_eq!((t.len(), t.room()), (0, 5));
        let a = t.insert(&mut src, 1, RW).unwrap();
        let b = t.insert(&mut src, 2, RW).unwrap();
        t.insert(&mut src, 3, RW).unwrap();
        assert_eq!((t.len(), t.room()), (3, 2));
        t.remove(a).unwrap();
        t.remove(b).unwrap();
        assert_eq!((t.len(), t.room()), (1, 4));
        for i in 0..4 {
            t.insert(&mut src, i, RW).unwrap();
        }
        assert_eq!((t.len(), t.room()), (5, 0));
        assert_eq!(t.insert(&mut src, 9, RW), Err(HandleError::LimitReached));
        t.release(&mut src);
        assert_eq!((t.len(), t.room()), (0, 5));
    }

    #[test]
    fn freed_index_is_reused_with_a_new_generation() {
        let mut src = boxes(1);
        let mut t = table(10);
        let a = t.insert(&mut src, 1, RW).unwrap();
        t.remove(a).unwrap();
        let b = t.insert(&mut src, 2, RW).unwrap();
        assert_eq!(a.index(), b.index());
        assert_ne!(a.generation(), b.generation());
        assert_eq!(t.get(a), Err(HandleError::BadHandle));
        t.release(&mut src);
    }

    #[test]
    fn stale_handle_never_opens_a_new_object() {
        let mut src = boxes(1);
        let mut t = table(1);
        let first = t.insert(&mut src, 0, RW).unwrap();
        t.remove(first).unwrap();
        let mut seen = HashSet::from([first]);
        for i in 1..=100_000 {
            let h = t.insert(&mut src, i, RW).unwrap();
            assert_ne!(h, Handle::INVALID);
            assert!(seen.insert(h), "handle {h:?} issued twice");
            assert_eq!(t.get(first), Err(HandleError::BadHandle));
            t.remove(h).unwrap();
        }
        t.release(&mut src);
    }

    #[test]
    fn stale_handle_stays_bad_among_other_free_entries() {
        // A service holds 10 handles and has 20 free entries; it closes one
        // but keeps its value, and a client then hands it a handle 256 times.
        let mut src = boxes(1);
        let mut t = table(100);
        let all: Vec<Handle> = (0..30)
            .map(|i| t.insert(&mut src, i, RW).unwrap())
            .collect();
        for h in &all[10..] {
            t.remove(*h).unwrap();
        }
        let kept = all[9];
        t.remove(kept).unwrap();
        for i in 0..256 {
            let h = t.insert(&mut src, 1000 + i, RW).unwrap();
            assert_eq!(h.index(), kept.index());
            assert_eq!(t.get(kept), Err(HandleError::BadHandle));
            t.remove(h).unwrap();
        }
        t.release(&mut src);
    }

    #[test]
    fn generation_crosses_32_bits() {
        let mut src = boxes(1);
        let mut t = HandleTable::with_first_generation(1, u64::from(u32::MAX));
        let old = t.insert(&mut src, 1, RW).unwrap();
        assert_eq!(old.generation(), u64::from(u32::MAX));
        t.remove(old).unwrap();
        let new = t.insert(&mut src, 2, RW).unwrap();
        assert_eq!(new.generation(), 1 << 32);
        assert_eq!(t.get(old), Err(HandleError::BadHandle));
        assert_eq!(t.get(new), Ok((&2, RW)));
        t.release(&mut src);
    }

    #[test]
    fn entry_retires_after_its_last_generation() {
        let mut src = boxes(1);
        let mut t = HandleTable::with_first_generation(1, LAST - 2);
        let mut issued = Vec::new();
        for i in 0..3 {
            let h = t.insert(&mut src, i, RW).unwrap();
            issued.push(h);
            t.remove(h).unwrap();
        }
        let generations: Vec<u64> = issued.iter().map(|h| h.generation()).collect();
        assert_eq!(generations, [LAST - 2, LAST - 1, LAST]);
        assert_eq!(t.insert(&mut src, 9, RW), Err(HandleError::LimitReached));
        assert_eq!((t.len(), t.retired(), t.room()), (0, 1, 0));
        for h in issued {
            assert_eq!(t.get(h), Err(HandleError::BadHandle));
            assert_eq!(t.remove(h), Err(HandleError::BadHandle));
        }
        assert_eq!(t.get(Handle::new(0, 1)), Err(HandleError::BadHandle));
        assert_eq!(t.get(Handle::new(0, 0)), Err(HandleError::BadHandle));
        t.release(&mut src);
    }

    #[test]
    fn retired_entry_is_skipped_for_a_new_one() {
        let mut src = boxes(1);
        let mut t = HandleTable::with_first_generation(2, LAST);
        let old = t.insert(&mut src, 1, RW).unwrap();
        assert_eq!((old.index(), old.generation()), (0, LAST));
        t.remove(old).unwrap();
        let new = t.insert(&mut src, 2, RW).unwrap();
        assert_eq!(new.index(), 1);
        assert_eq!(t.get(old), Err(HandleError::BadHandle));
        assert_eq!(t.get(Handle::new(0, 1)), Err(HandleError::BadHandle));
        assert_eq!(t.remove(old), Err(HandleError::BadHandle));
        t.release(&mut src);
    }

    #[test]
    fn retired_entries_count_toward_the_limit() {
        let mut src = boxes(1);
        let mut t = HandleTable::with_first_generation(3, LAST);
        let a = t.insert(&mut src, 1, RW).unwrap();
        t.remove(a).unwrap();
        assert_eq!((t.retired(), t.room()), (1, 2));
        let b = t.insert(&mut src, 2, RW).unwrap();
        let c = t.insert(&mut src, 3, RW).unwrap();
        assert_eq!(t.insert(&mut src, 4, RW), Err(HandleError::LimitReached));
        assert_eq!(t.get(b), Ok((&2, RW)));
        assert_eq!(t.get(c), Ok((&3, RW)));
        assert_eq!(t.len(), 2);
        t.release(&mut src);
        assert_eq!((t.retired(), t.room()), (0, 3));
    }

    /// Random inserts, duplicates and removes against a model: every value
    /// the table hands out is new, every closed one stays bad, and the
    /// counters agree with the entries. Returns how many entries retired.
    fn check_against_the_model(first_generation: u64, steps: usize) -> u32 {
        const LIMIT: u32 = 4;
        let mut src = boxes(1);
        let mut t = HandleTable::with_first_generation(LIMIT, first_generation);
        let mut issued: HashSet<Handle> = HashSet::new();
        let mut live: Vec<(Handle, u32)> = Vec::new();
        let mut closed: Vec<Handle> = Vec::new();
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for step in 0..steps as u32 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let (room, retired) = (t.room(), t.retired());
            match x % 4 {
                0 | 1 => {
                    let got = t.insert(&mut src, step, RW);
                    if room == 0 {
                        assert_eq!(got, Err(HandleError::LimitReached));
                    } else {
                        let h = got.unwrap();
                        assert!(h != Handle::INVALID && issued.insert(h), "{h:?} reissued");
                        live.push((h, step));
                    }
                }
                2 if !live.is_empty() => {
                    let (h, v) = live.swap_remove((x >> 8) as usize % live.len());
                    assert_eq!(t.remove(h), Ok((v, RW)));
                    assert_eq!(t.get(h), Err(HandleError::BadHandle));
                    closed.push(h);
                    let retired_now = t.retired() - retired;
                    assert!(retired_now <= 1);
                    assert_eq!(t.room(), room + 1 - retired_now);
                }
                3 if !live.is_empty() => {
                    let (h, v) = live[(x >> 8) as usize % live.len()];
                    let got = t.duplicate(&mut src, h, RW);
                    if room == 0 {
                        assert_eq!(got, Err(HandleError::LimitReached));
                    } else {
                        let d = got.unwrap();
                        assert!(d != Handle::INVALID && issued.insert(d), "{d:?} reissued");
                        live.push((d, v));
                    }
                }
                _ => {}
            }
            if let Some(&old) = closed.get((x >> 16) as usize % closed.len().max(1)) {
                assert_eq!(t.get(old), Err(HandleError::BadHandle));
            }
            // Any value at all, and one with an index inside the table: an
            // entry the model holds, or BadHandle, never a panic.
            let near = Handle::new((x >> 40) as u32 % (LIMIT + 1), x & Handle::MAX_GENERATION);
            for probe in [Handle(x), near] {
                match t.get(probe) {
                    Ok((v, _)) => assert!(live.contains(&(probe, *v)), "{probe:?} opens {v}"),
                    Err(e) => assert_eq!(e, HandleError::BadHandle),
                }
            }
            assert_eq!(t.len() as usize, live.len());
            assert_eq!(t.len() + t.retired + t.free_count, t.used);
        }
        for h in closed {
            assert_eq!(t.get(h), Err(HandleError::BadHandle));
            assert_eq!(t.get_with(h, Rights::NONE), Err(HandleError::BadHandle));
            assert_eq!(
                t.duplicate(&mut src, h, Rights::NONE),
                Err(HandleError::BadHandle)
            );
            assert_eq!(t.remove(h), Err(HandleError::BadHandle));
        }
        for (h, v) in live {
            assert_eq!(t.get(h), Ok((&v, RW)));
        }
        let retired = t.retired();
        t.release(&mut src);
        retired
    }

    #[test]
    fn handle_values_are_never_repeated() {
        assert_eq!(check_against_the_model(1, 10_000), 0);
    }

    #[test]
    fn handle_values_are_never_repeated_near_the_last_generation() {
        // Each entry retires after 8 frees; 2000 steps retire all four.
        assert_eq!(check_against_the_model(LAST - 7, 2_000), 4);
    }

    /// Every sequence of 12 inserts, removes and duplicates on a table of 3
    /// entries that retire after 3 generations.
    #[test]
    fn every_short_sequence_keeps_the_invariants() {
        const STEPS: u32 = 12;
        for code in 0..3u32.pow(STEPS) {
            let mut src = boxes(1);
            let mut t = HandleTable::with_first_generation(3, LAST - 2);
            let mut issued: Vec<Handle> = Vec::new();
            let mut live: Vec<Handle> = Vec::new();
            let mut closed: Vec<Handle> = Vec::new();
            let mut c = code;
            for _ in 0..STEPS {
                let room = t.room();
                let op = c % 3;
                c /= 3;
                let got = match op {
                    0 => Some(t.insert(&mut src, 0, RW)),
                    1 if !live.is_empty() => {
                        let h = live.remove(0);
                        assert_eq!(t.remove(h), Ok((0, RW)));
                        closed.push(h);
                        None
                    }
                    2 if !live.is_empty() => Some(t.duplicate(&mut src, live[live.len() - 1], RW)),
                    _ => None,
                };
                if let Some(got) = got {
                    if room == 0 {
                        assert_eq!(got, Err(HandleError::LimitReached));
                    } else {
                        let h = got.unwrap();
                        assert!(h != Handle::INVALID && !issued.contains(&h));
                        issued.push(h);
                        live.push(h);
                    }
                }
                for h in &closed {
                    assert_eq!(t.get(*h), Err(HandleError::BadHandle));
                }
                assert_eq!(t.len() + t.retired + t.free_count, t.used);
            }
            t.release(&mut src);
        }
    }

    #[test]
    fn limit_is_enforced() {
        let mut src = boxes(1);
        let mut t = table(2);
        t.insert(&mut src, 1, RW).unwrap();
        t.insert(&mut src, 2, RW).unwrap();
        assert_eq!(t.insert(&mut src, 3, RW), Err(HandleError::LimitReached));
        t.release(&mut src);
    }

    #[test]
    fn table_grows_by_chunks() {
        let mut src = boxes(4);
        let mut t = table(1000);
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
        let mut t = table(10);
        let h = t.insert(&mut src, 5, RW).unwrap();
        let d = t.duplicate(&mut src, h, Rights::SEND).unwrap();
        assert_eq!(t.get(d), Ok((&5, Rights::SEND)));
        t.release(&mut src);
    }

    #[test]
    fn duplicate_needs_the_duplicate_right_and_no_new_rights() {
        let mut src = boxes(1);
        let mut t = table(10);
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
        let mut t = table(10);
        let h = t.insert(&mut src, 5, Rights::SEND).unwrap();
        assert_eq!(t.get_with(h, Rights::SEND), Ok(&5));
        assert_eq!(
            t.get_with(h, Rights::RECEIVE),
            Err(HandleError::AccessDenied)
        );
        t.release(&mut src);
    }

    #[test]
    fn get_as_checks_the_handle_then_the_type_then_the_rights() {
        let even = |v: &u32| v.is_multiple_of(2).then_some(*v);
        let mut src = boxes(1);
        let mut t = table(10);
        let h = t.insert(&mut src, 4, Rights::SEND).unwrap();
        let odd = t.insert(&mut src, 5, Rights::NONE).unwrap();
        assert_eq!(t.get_as(h, Rights::SEND, even), Ok(4));
        assert_eq!(
            t.get_as(h, Rights::RECEIVE, even),
            Err(HandleError::AccessDenied)
        );
        // A wrong type comes before missing rights, a bad handle before both.
        assert_eq!(
            t.get_as(odd, Rights::RECEIVE, even),
            Err(HandleError::WrongType)
        );
        t.remove(h).unwrap();
        assert_eq!(
            t.get_as(h, Rights::RECEIVE, even),
            Err(HandleError::BadHandle)
        );
        assert_eq!(
            t.get_as(Handle::INVALID, Rights::NONE, even),
            Err(HandleError::BadHandle)
        );
        t.release(&mut src);
    }

    #[test]
    fn release_with_hands_every_object_out_once() {
        let mut src = boxes(2);
        let mut t = table(100);
        let hs: Vec<Handle> = (0..70)
            .map(|i| t.insert(&mut src, i, RW).unwrap())
            .collect();
        for h in &hs[10..20] {
            t.remove(*h).unwrap();
        }
        let mut out = Vec::new();
        t.release_with(&mut src, |v| out.push(v));
        out.sort();
        let want: Vec<u32> = (0..10).chain(20..70).collect();
        assert_eq!(out, want);
        assert_eq!(src.freed, 2);
        assert_eq!((t.len(), t.room()), (0, 100));
        t.release_with(&mut src, |_| panic!("an empty table has no objects"));
    }

    #[test]
    fn handle_errors_are_the_abi_errors() {
        use abi::Error;
        let pairs = [
            (HandleError::BadHandle, Error::BadHandle),
            (HandleError::WrongType, Error::WrongType),
            (HandleError::AccessDenied, Error::AccessDenied),
            (HandleError::InvalidArgs, Error::InvalidArgs),
            (HandleError::LimitReached, Error::LimitReached),
            (HandleError::NoMemory, Error::NoMemory),
        ];
        for (from, to) in pairs {
            assert_eq!(Error::from(from), to);
        }
    }

    #[test]
    fn forged_or_out_of_range_handles_are_bad() {
        let mut src = boxes(1);
        let mut t = table(10);
        let h = t.insert(&mut src, 5, RW).unwrap();
        assert_eq!(t.get(Handle::INVALID), Err(HandleError::BadHandle));
        assert_eq!(
            t.get(Handle::new(h.index() + 1, 1)),
            Err(HandleError::BadHandle)
        );
        assert_eq!(
            t.get(Handle::new(Handle::MAX_INDEX, 1)),
            Err(HandleError::BadHandle)
        );
        assert_eq!(t.get(Handle(u64::MAX)), Err(HandleError::BadHandle));
        assert_eq!(
            t.get(Handle::new(h.index(), h.generation() + 1)),
            Err(HandleError::BadHandle)
        );
        t.release(&mut src);
    }

    #[test]
    fn forged_handle_to_a_free_entry_is_bad() {
        let mut src = boxes(1);
        let mut t = table(10);
        let a = t.insert(&mut src, 1, RW).unwrap();
        t.remove(a).unwrap();
        let forged = Handle::new(a.index(), a.generation() + 1);
        assert_eq!(t.get(forged), Err(HandleError::BadHandle));
        assert_eq!(t.remove(forged), Err(HandleError::BadHandle));
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
        let mut t = table(100);
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
        let mut t: HandleTable<u32> = table(10);
        assert_eq!(t.insert(&mut src, 1, RW), Err(HandleError::NoMemory));
    }

    #[test]
    fn insert_works_again_after_no_memory() {
        let mut src = boxes(1);
        let mut t = table(100);
        for i in 0..CHUNK as u32 {
            t.insert(&mut src, i, RW).unwrap();
        }
        assert_eq!(t.insert(&mut src, 64, RW), Err(HandleError::NoMemory));
        assert_eq!((t.len(), t.room()), (64, 36));
        src.left = 1;
        let h = t.insert(&mut src, 64, RW).unwrap();
        assert_eq!(h.index(), 64);
        assert_eq!(t.get(h), Ok((&64, RW)));
        t.release(&mut src);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "dropped without release")]
    fn table_dropped_without_release_panics() {
        let mut src = boxes(1);
        let mut t = table(10);
        t.insert(&mut src, 1, RW).unwrap();
        drop(t);
    }
}
