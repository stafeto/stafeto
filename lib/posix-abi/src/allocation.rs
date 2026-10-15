// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's pages under a lock of the layer (spec 2, 3.4): relibc's
//! anonymous mappings (its stacks, TCBs and the large blocks of its
//! dlmalloc) come from here, whole pages with no header. The calling
//! thread allocates itself, its holder at the ceiling of the process
//! (LayerLock::raising), and grows the heap (`mem_create`, `mem_map`)
//! under the same lock. No helper thread. An entry of signals inside the
//! section waits for its end. This does not establish a bounded real-time
//! allocator: a section that grows the heap or splits a long free list is
//! longer.
//!
//! The layer keeps the handle of every memory object of the process (spec
//! 2, 3.2): each chunk the heap takes goes into the memory map under the
//! same lock (`regions`), and startup adds what the loader mapped (`adopt`),
//! so that `fork` can copy all of the process's memory. A mapping made past
//! the layer by a direct call of the kernel is not in the map, and a
//! forked child does not get it (a known limit).

use crate::constants::*;
use core::{
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};
use posix_map::{
    Map, Object, Refused,
    space::{Space, State as Page},
};
use posix_sync::LayerLock;
use rt::{
    abi::{Access, Rights},
    handle::{Handle, Memory, Process},
    sys,
};

const BASE: usize = 0x1000_0000;
const PAGE: usize = 4096;
/// The pages of the first chunk of the heap (64 KiB); each chunk is twice
/// the one before, up to MAX_CHUNK (4 MiB).
const FIRST_CHUNK: usize = 16;
const MAX_CHUNK: usize = 1024;
/// The places of the table kept for objects of the program's own and the
/// heap's chunks when freed pages lose their access.
const RESERVE: usize = 16;

struct Config {
    process: Handle<Process>,
}
struct Once(UnsafeCell<Option<Config>>);
// SAFETY: startup writes once before any allocation; READY publishes it and
// it stays immutable thereafter.
unsafe impl Sync for Once {}
static CONFIG: Once = Once(UnsafeCell::new(None));
static READY: AtomicBool = AtomicBool::new(false);
/// The use of the room, the memory map and the size of the last chunk, all
/// under HEAP_LOCK.
pub(crate) struct State {
    pub(crate) space: Space,
    pub(crate) map: Map<Handle<Memory>>,
    /// The pages of the last chunk the heap took.
    chunk: usize,
    /// The entries of the kernel's table the map does not show: a program
    /// started by init maps its own segments, every program the clock's
    /// page and its record's. A guess that the kernel's refusals raise.
    hidden: usize,
    /// The descriptors of files whose last shared mapping went, until the
    /// caller closes them (`take_closed`).
    closed: [(i32, u64); 16],
    closed_len: usize,
}

/// RLIMIT_AS and RLIMIT_DATA, soft, in bytes (u64::MAX for none): the
/// layer reads them from the process service at its first mapping and
/// `setrlimit` keeps them (`resources::set`), so that the heap's lock never
/// waits for a message.
pub(crate) static LIMIT_AS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);
pub(crate) static LIMIT_DATA: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);

/// The entries of the kernel's table not in the map, until a refusal says
/// there are more.
const HIDDEN: usize = 8;
struct Heap(UnsafeCell<State>);
// SAFETY: only `heap` borrows it, under HEAP_LOCK (and `adopt`, at startup
// before any other thread).
unsafe impl Sync for Heap {}
static HEAP: Heap = Heap(UnsafeCell::new(State {
    space: Space::new(BASE),
    map: Map::new(),
    chunk: 0,
    hidden: HIDDEN,
    closed: [(0, 0); 16],
    closed_len: 0,
}));
static HEAP_LOCK: LayerLock = LayerLock::raising();
/// Set while a thread is inside the heap's section, for the probes.
#[cfg(feature = "thread-probe")]
static INSIDE: AtomicBool = AtomicBool::new(false);

/// Initialize once during single-threaded startup, before any allocation call.
/// The process heap and its mappings share the room from BASE.
///
/// # Safety
/// Called while startup has exclusive heap initialization access, before any
/// client thread uses allocation. The reserved heap range must be unused.
pub unsafe fn init(process: Handle<Process>) -> Result<(), rt::abi::Error> {
    if READY.load(Ordering::Acquire) {
        return Err(rt::abi::Error::BadState);
    }
    // SAFETY: startup has exclusive access; no client exists yet.
    unsafe { *CONFIG.0.get() = Some(Config { process }) };
    READY.store(true, Ordering::Release);
    Ok(())
}

/// What the map's handle of an object holds: MAP_READ, MAP_WRITE, and
/// DUPLICATE and TRANSFER for the copy a `fork` hands its loader. No
/// MANAGE or MAP_EXEC.
const KEPT: Rights = Rights::MAP_READ
    .union(Rights::MAP_WRITE)
    .union(Rights::DUPLICATE)
    .union(Rights::TRANSFER);

/// Runs `f` on the heap and the map under the heap's lock.
pub(crate) fn heap<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let _guard = HEAP_LOCK.lock();
    #[cfg(feature = "thread-probe")]
    INSIDE.store(true, Ordering::SeqCst);
    // SAFETY: the lock gives this borrow alone.
    let result = f(unsafe { &mut *HEAP.0.get() });
    #[cfg(feature = "thread-probe")]
    INSIDE.store(false, Ordering::SeqCst);
    result
}

/// Whether a thread is inside the heap's section now, for the probes.
#[cfg(feature = "thread-probe")]
pub fn probe_inside() -> bool {
    INSIDE.load(Ordering::SeqCst)
}

/// The bytes the heap took from the kernel so far, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_committed() -> usize {
    heap(|state| state.space.count(Page::Free) * PAGE + state.space.count(Page::User) * PAGE)
}

/// Runs `run` holding the heap's lock, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_hold(run: impl FnOnce()) {
    heap(|_| run());
}

/// Runs `run` holding the heap's lock, for the probes of a fork while
/// another thread holds it.
pub(crate) fn hold(run: impl FnOnce()) {
    heap(|_| run());
}

fn config() -> &'static Config {
    // SAFETY: called after successful startup, which wrote it once.
    unsafe { (*CONFIG.0.get()).as_ref().expect("heap initialized") }
}

/// Adds an object the loader mapped to the memory map: `pages` pages at
/// `address` with `access`, `handle` the layer's. The handle goes if the
/// map refuses it.
///
/// # Safety
/// Called while startup has exclusive access, after `init`: no other
/// thread of the process runs.
pub unsafe fn adopt(
    address: usize,
    pages: usize,
    access: Access,
    handle: Handle<Memory>,
) -> Result<(), Refused> {
    // SAFETY: the caller's promise gives this borrow alone.
    let state = unsafe { &mut *HEAP.0.get() };
    state
        .map
        .push(
            address,
            pages,
            access,
            0,
            Object {
                handle,
                shared: false,
                back: None,
            },
        )
        .map(drop)
}

/// Where a mapping of its own gets its object: a handle the process service
/// gave (`existing`) or a new object, covering `offset` pages before the
/// mapping's own, and the file a shared object writes back to.
#[derive(Default)]
pub(crate) struct Source {
    pub existing: Option<Handle<Memory>>,
    pub offset: usize,
    pub back: Option<posix_map::Back>,
}

/// One entry of a forked child's memory map (the loader's `ForkEntry`): the
/// handle is None for an entry that shows the object of the one before.
pub struct ChildEntry {
    pub address: usize,
    pub pages: usize,
    pub access: Access,
    pub offset: usize,
    pub handle: Option<Handle<Memory>>,
    pub shared: bool,
}

/// The heap of a forked child (spec 2, 3.2): its own process `process`,
/// and the entries of its map in `map`, which its loader made at the
/// parent's addresses; the parent's handles in the copy of the map and of
/// the configuration go without a close (they name nothing of the
/// child's). The use of the room is the parent's at the fork, so the heap
/// goes on where the parent's was.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(
    process: Handle<Process>,
    map: impl Iterator<Item = ChildEntry>,
) -> Result<(), Refused> {
    // SAFETY: the caller's promise gives these borrows alone.
    let (config, state) = unsafe { (&mut *CONFIG.0.get(), &mut *HEAP.0.get()) };
    if let Some(parent) = config.replace(Config { process }) {
        core::mem::forget(parent);
    }
    // The files the parent's shared mappings write to: the child's
    // descriptors are the parent's numbers.
    let mut backs = [(0usize, None::<posix_map::Back>); posix_map::MAX_PIECES];
    for (slot, piece) in backs.iter_mut().zip(state.map.iter()) {
        *slot = (piece.address, state.map.object(piece.object()).back);
    }
    state.map.forget();
    let mut last = None;
    for entry in map {
        let object = match (entry.handle, last) {
            (Some(handle), _) => {
                let object = state.map.push(
                    entry.address,
                    entry.pages,
                    entry.access,
                    entry.offset,
                    Object {
                        handle,
                        shared: entry.shared,
                        back: backs
                            .iter()
                            .find(|(address, _)| entry.shared && *address == entry.address)
                            .and_then(|(_, back)| *back),
                    },
                )?;
                last = Some(object);
                continue;
            }
            (None, Some(object)) => object,
            (None, None) => return Err(Refused::Malformed),
        };
        state.map.push_piece(
            entry.address,
            entry.pages,
            entry.access,
            entry.offset,
            object,
        )?;
    }
    Ok(())
}

/// Runs `f` on the pieces of the memory map, by address, under the heap's
/// lock.
pub fn regions<R>(f: impl FnOnce(&Map<Handle<Memory>>) -> R) -> R {
    heap(|state| f(&state.map))
}

/// The errno of a refused kernel call on a mapping.
fn kernel_errno(error: rt::abi::Error) -> i32 {
    match error {
        rt::abi::Error::AccessDenied => EACCES,
        rt::abi::Error::LimitReached | rt::abi::Error::NoMemory => ENOMEM,
        _ => EINVAL,
    }
}

impl State {
    /// The places left in the kernel's table, as far as the map knows.
    pub(crate) fn room(&self) -> usize {
        posix_map::MAX_PIECES.saturating_sub(self.hidden + self.map.len())
    }

    /// The errno of a refusal of the kernel on a mapping; a table the
    /// kernel found full when the map saw room raises the guess of the
    /// entries the map does not show.
    fn refused(&mut self, error: rt::abi::Error) -> i32 {
        if error == rt::abi::Error::LimitReached {
            self.hidden = self
                .hidden
                .max(posix_map::MAX_PIECES.saturating_sub(self.map.len() + 1));
        }
        kernel_errno(error)
    }

    /// `protect`, and when the table has no places the free runs are joined
    /// (`compact`) and the call is tried once more.
    fn protect_or_compact(
        &mut self,
        address: usize,
        pages: usize,
        access: Access,
    ) -> Result<(), i32> {
        match self.protect(address, pages, access) {
            Err(ENOMEM) if self.map.covers(address, pages) => {
                self.compact();
                self.protect(address, pages, access)
            }
            other => other,
        }
    }

    /// Makes the pieces the free range meets writable whole, with no cut: the
    /// last resort when the table has no place for the edges. A piece that
    /// holds a page in use is left alone (ENOMEM). The pages of the pieces
    /// outside the range, free ones, are writable then until they are
    /// given back again.
    fn restore_whole(&mut self, address: usize, pages: usize) -> Result<(), i32> {
        let mut at = address;
        let end = address + pages * PAGE;
        while at < end {
            let index = self.map.find(at).ok_or(ENOMEM)?;
            let piece = *self.map.piece(index);
            if piece.access() != Access::ReadWrite {
                if !self.space.all(piece.address, piece.pages(), Page::Free) {
                    return Err(ENOMEM);
                }
                // SAFETY: free pages, which nothing uses.
                unsafe {
                    sys::mem_protect(
                        &config().process,
                        piece.address,
                        (piece.pages() * PAGE) as u64,
                        Access::ReadWrite,
                    )
                }
                .map_err(|e| self.refused(e))?;
                self.map
                    .protect(index, piece.address, piece.pages(), Access::ReadWrite)
                    .map_err(|_| ENOMEM)?;
            }
            at = piece.end();
        }
        Ok(())
    }

    /// Gives the pages of the range `access` (`mem_protect`), one piece of
    /// the map at a time; pieces that have it already are left alone.
    /// ENOMEM when a page of the range is in no piece or the cuts need more
    /// places than the table has (nothing changes then), EACCES when the
    /// object's rights stop short of `access`.
    pub(crate) fn protect(
        &mut self,
        address: usize,
        pages: usize,
        access: Access,
    ) -> Result<(), i32> {
        if !self.map.covers(address, pages) {
            return Err(ENOMEM);
        }
        let mut needed = 0;
        for (index, from, count) in self.map.walk(address, pages) {
            let piece = self.map.piece(index);
            if piece.access() != access {
                needed += usize::from(from > piece.address)
                    + usize::from(from + count * PAGE < piece.end());
            }
        }
        if needed > self.room() {
            return Err(ENOMEM);
        }
        let end = address + pages * PAGE;
        let mut at = address;
        while at < end {
            let index = self.map.find(at).ok_or(ENOMEM)?;
            let piece = *self.map.piece(index);
            let to = end.min(piece.end());
            if piece.access() != access {
                // SAFETY: the callers give up what the new access takes away
                // (they hand out or take back whole pages of the program's own
                // mappings).
                unsafe { sys::mem_protect(&config().process, at, (to - at) as u64, access) }
                    .map_err(|e| self.refused(e))?;
                self.map
                    .protect(index, at, (to - at) / PAGE, access)
                    .map_err(|_| ENOMEM)?;
            }
            at = to;
        }
        Ok(())
    }

    /// Unmaps the pages of the range (`mem_unmap`), one piece at a time;
    /// ENOMEM when a page is in no piece or the cuts need more places
    /// than the table has. The objects left without a piece close.
    pub(crate) fn unmap(&mut self, address: usize, pages: usize) -> Result<(), i32> {
        if !self.map.covers(address, pages) {
            return Err(ENOMEM);
        }
        if self.map.edges(address, pages) > self.room() {
            return Err(ENOMEM);
        }
        let end = address + pages * PAGE;
        let mut at = address;
        while at < end {
            let index = self.map.find(at).ok_or(ENOMEM)?;
            let to = end.min(self.map.piece(index).end());
            // SAFETY: the caller gives up these pages.
            unsafe { sys::mem_unmap(&config().process, at, (to - at) as u64) }
                .map_err(|e| self.refused(e))?;
            let gone = self
                .map
                .unmap(index, at, (to - at) / PAGE)
                .map_err(|_| ENOMEM)?;
            if let Some(back) = gone.and_then(|object| object.back) {
                // The descriptor and the key go with the last object that
                // has them.
                let fd_used = self
                    .map
                    .objects()
                    .any(|(_, o)| o.back.is_some_and(|b| b.fd == back.fd));
                let key_used = back.key != 0
                    && self
                        .map
                        .objects()
                        .any(|(_, o)| o.back.is_some_and(|b| b.key == back.key));
                let entry = (
                    if fd_used { -1 } else { back.fd },
                    if key_used { 0 } else { back.key },
                );
                if entry != (-1, 0) && self.closed_len < self.closed.len() {
                    self.closed[self.closed_len] = entry;
                    self.closed_len += 1;
                }
            }
            at = to;
        }
        Ok(())
    }

    /// The descriptor the layer holds for the shared mapping of the file of
    /// `key`, if this process maps it.
    pub(crate) fn fd_of_key(&self, key: u64) -> Option<i32> {
        self.map
            .objects()
            .find_map(|(_, o)| o.back.filter(|b| b.key == key && key != 0).map(|b| b.fd))
    }

    /// The descriptors of `closed`, moved to `out`: how many.
    pub(crate) fn take_closed(&mut self, out: &mut [(i32, u64)]) -> usize {
        let n = self.closed_len.min(out.len());
        out[..n].copy_from_slice(&self.closed[..n]);
        self.closed.copy_within(n..self.closed_len, 0);
        self.closed_len -= n;
        n
    }

    /// A new chunk of the heap with room for `needed` pages: twice the last
    /// one, 64 KiB to 4 MiB, or less when the room has no run so long.
    /// ENOMEM when `pages` more pages would pass RLIMIT_AS.
    fn within_address_space(&self, pages: usize) -> Result<(), i32> {
        let limit = LIMIT_AS.load(Ordering::Relaxed);
        if limit != u64::MAX && ((self.map.pages() + pages) * PAGE) as u64 > limit {
            return Err(ENOMEM);
        }
        Ok(())
    }

    /// ENOMEM when `pages` more pages of the program's mappings would pass
    /// RLIMIT_DATA.
    pub(crate) fn within_data(&self, pages: usize) -> Result<(), i32> {
        let limit = LIMIT_DATA.load(Ordering::Relaxed);
        if limit != u64::MAX {
            let used = self.space.count(Page::User) + self.space.count(Page::Own);
            if ((used + pages) * PAGE) as u64 > limit {
                return Err(ENOMEM);
            }
        }
        Ok(())
    }

    fn grow(&mut self, needed: usize) -> Result<(), i32> {
        // Twice the last chunk, but no more than a sixteenth of what the
        // process's quota has left: a small process does not pay for a big
        // chunk it never fills (it keeps 64 KiB chunks), and a process with
        // megabytes grows by doubling.
        let spare = sys::process_memory(&config().process).map_or(MAX_CHUNK, |m| {
            (m.quota.saturating_sub(m.used) as usize / PAGE / 16).max(FIRST_CHUNK)
        });
        let wanted = (self.chunk * 2)
            .clamp(FIRST_CHUNK, MAX_CHUNK)
            .min(spare)
            .max(needed);
        let (pages, address) = [wanted, needed]
            .into_iter()
            .find_map(|pages| {
                self.space
                    .find(pages, Page::Unbacked, false)
                    .map(|at| (pages, at))
            })
            .ok_or(ENOMEM)?;
        // A chunk the map has no room for is not made: the kernel's limit
        // of mappings is the map's.
        if self.room() == 0 || !self.map.has_room_for_object() {
            return Err(ENOMEM);
        }
        self.within_address_space(pages)?;
        let length = pages * PAGE;
        let memory = sys::mem_create(length as u64).map_err(|_| ENOMEM)?;
        // The map keeps a narrowed copy, and the full handle goes.
        let kept = sys::handle_duplicate(&memory, KEPT).map_err(|_| ENOMEM)?;
        drop(memory);
        sys::mem_map(
            &config().process,
            &kept,
            0,
            length as u64,
            address,
            Access::ReadWrite,
        )
        .map_err(|_| ENOMEM)?;
        self.map
            .push(
                address,
                pages,
                Access::ReadWrite,
                0,
                Object {
                    handle: kept,
                    shared: false,
                    back: None,
                },
            )
            .map_err(|_| ENOMEM)?;
        self.space.set(address, pages, Page::Free);
        self.chunk = pages;
        Ok(())
    }

    /// `pages` pages of the heap, writable again if they had lost their
    /// access, in the use `use_` (User); the pages are not zeroed.
    pub(crate) fn take(&mut self, pages: usize) -> Result<usize, i32> {
        for attempt in 0..2 {
            if let Some(address) = self.space.find(pages, Page::Free, false) {
                if self
                    .protect_or_compact(address, pages, Access::ReadWrite)
                    .is_err()
                {
                    self.restore_whole(address, pages)?;
                }
                self.space.set(address, pages, Page::User);
                return Ok(address);
            }
            if attempt == 0 {
                self.grow(pages)?;
            }
        }
        Err(ENOMEM)
    }

    /// As `take` for the Free pages exactly at `address`; ENOMEM for any
    /// other state.
    pub(crate) fn take_at(&mut self, address: usize, pages: usize) -> Result<(), i32> {
        if !self.space.all(address, pages, Page::Free) {
            return Err(ENOMEM);
        }
        self.protect(address, pages, Access::ReadWrite)?;
        self.space.set(address, pages, Page::User);
        Ok(())
    }

    /// An object of its own for `pages` pages, mapped with `access` (any
    /// but ReadExec) at `at`, or at the top of the room's free address
    /// space; `shared` objects carry the flag for `fork`. The pages are
    /// zeros. The returned index is the object's in the map.
    pub(crate) fn make_own(
        &mut self,
        at: Option<usize>,
        pages: usize,
        access: Access,
        shared: bool,
        source: Source,
    ) -> Result<(usize, usize), i32> {
        let address = match at {
            Some(address) if self.space.all(address, pages, Page::Unbacked) => address,
            Some(_) => return Err(ENOMEM),
            None => self.space.find(pages, Page::Unbacked, true).ok_or(ENOMEM)?,
        };
        if self.room() == 0 || !self.map.has_room_for_object() {
            return Err(ENOMEM);
        }
        self.within_address_space(pages)?;
        let length = (pages * PAGE) as u64;
        let Source {
            existing,
            offset,
            back,
        } = source;
        let kept = match existing {
            Some(kept) => kept,
            None => {
                // An object for a file covers it from its first page.
                let memory =
                    sys::mem_create(((offset + pages) * PAGE) as u64).map_err(|_| ENOMEM)?;
                let kept = sys::handle_duplicate(&memory, KEPT).map_err(|_| ENOMEM)?;
                drop(memory);
                kept
            }
        };
        let first = if access == Access::None {
            Access::ReadWrite
        } else {
            access
        };
        sys::mem_map(
            &config().process,
            &kept,
            (offset * PAGE) as u64,
            length,
            address,
            first,
        )
        .map_err(|e| self.refused(e))?;
        let index = self
            .map
            .push(
                address,
                pages,
                first,
                offset,
                Object {
                    handle: kept,
                    shared,
                    back,
                },
            )
            .map_err(|_| ENOMEM)?;
        self.space.set(address, pages, Page::Own);
        if access == Access::None {
            // The object has one piece and the table has room for the
            // piece, so only the failure of the kernel can refuse this.
            if let Err(error) = self.protect(address, pages, Access::None) {
                let _ = self.unmap(address, pages);
                self.space.set(address, pages, Page::Unbacked);
                return Err(error);
            }
        }
        Ok((index, address))
    }

    /// The pages of a `take` go back to the heap and lose their access
    /// (#187): the next touch is a fault. The kernel never joins mappings,
    /// so each cut stays; when the table runs short of places, the free runs
    /// are joined first (`compact`), and when that does not help the pages
    /// go back with their access: unmapping never fails for want of a place.
    pub(crate) fn give(&mut self, address: usize, pages: usize) {
        self.space.set(address, pages, Page::Free);
        if self.room() < RESERVE + 2 {
            self.compact();
        }
        let _ = self.protect_or_compact(address, pages, Access::None);
    }

    /// Joins the pieces of each run of free pages into as few as the
    /// object's chunks allow, with no access: the pieces are unmapped and
    /// the object mapped again over the same pages, which keep their
    /// frames. Nothing in a free run is in use, and the heap's lock is held.
    fn compact(&mut self) {
        let mut at = self.space.base();
        let limit = self.space.limit();
        while at < limit {
            if self.space.get(at) != Some(Page::Free) {
                at += PAGE;
                continue;
            }
            let mut to = at + PAGE;
            while to < limit && self.space.get(to) == Some(Page::Free) {
                to += PAGE;
            }
            let pages = (to - at) / PAGE;
            let inside = self
                .map
                .walk(at, pages)
                .filter(|&(i, from, count)| {
                    let piece = self.map.piece(i);
                    piece.address == from && piece.pages() == count
                })
                .count();
            if inside >= 2 && self.map.edges(at, pages) <= self.room() {
                self.repaint(at, pages);
            }
            at = to;
        }
    }

    /// Makes the free pages of the range pieces of no access, as few as
    /// the objects allow. On a refusal of the kernel the pages that could
    /// not be mapped again are taken out of use (state User): nothing of
    /// the layer touches them.
    fn repaint(&mut self, address: usize, pages: usize) {
        // (address, pages, object, first page of the object)
        let mut seen = [(0usize, 0usize, 0usize, 0usize); posix_map::MAX_PIECES];
        let mut n = 0;
        let end = address + pages * PAGE;
        let mut at = address;
        while at < end {
            let Some(index) = self.map.find(at) else {
                return;
            };
            let piece = *self.map.piece(index);
            let to = end.min(piece.end());
            let count = (to - at) / PAGE;
            let first = piece.offset() + (at - piece.address) / PAGE;
            // SAFETY: free pages, which nothing uses.
            if unsafe { sys::mem_unmap(&config().process, at, (to - at) as u64) }.is_err() {
                // Nothing of this piece changed; what was unmapped before
                // is mapped again below.
                break;
            }
            if self.map.unmap_keep(index, at, count).is_err() {
                return;
            }
            seen[n] = (at, count, piece.object(), first);
            n += 1;
            at = to;
        }
        let mut i = 0;
        while i < n {
            let (start, mut count, object, first) = seen[i];
            let mut j = i + 1;
            while j < n
                && seen[j].2 == object
                && seen[j].0 == start + count * PAGE
                && seen[j].3 == first + count
            {
                count += seen[j].1;
                j += 1;
            }
            let handle = &self.map.object(object).handle;
            let mapped = sys::mem_map(
                &config().process,
                handle,
                (first * PAGE) as u64,
                (count * PAGE) as u64,
                start,
                Access::Read,
            );
            if mapped.is_err()
                || self
                    .map
                    .push_piece(start, count, Access::Read, first, object)
                    .is_err()
            {
                self.space.set(start, count, Page::User);
            } else if self.protect(start, count, Access::None).is_err() {
                // The pages stay readable: no harm.
            }
            i = j;
        }
    }
}

/// The nanoseconds the next `map_pages` sleeps before the heap's section,
/// 0 for none: for the probe of relibc's allocator across a fork (its
/// lock held by a thread that waits in the kernel outside the layer's
/// sections).
static PROBE_SLEEP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static PROBE_SLEEP_ENTERED: AtomicBool = AtomicBool::new(false);

/// The next `map_pages` sleeps `ns` nanoseconds first, for the probes.
pub fn probe_sleep_next(ns: u64) {
    PROBE_SLEEP_ENTERED.store(false, Ordering::Release);
    PROBE_SLEEP.store(ns, Ordering::Release);
}

/// Sleeps as long as the armed probe says, once, before a mapping.
pub(crate) fn probe_pause() {
    let ns = PROBE_SLEEP.swap(0, Ordering::AcqRel);
    if ns != 0 {
        PROBE_SLEEP_ENTERED.store(true, Ordering::Release);
        crate::threads::sleep::probe_pause(ns);
    }
}

/// Whether an actual mapping consumed the armed allocator sleep probe.
pub fn probe_sleep_entered() -> bool {
    PROBE_SLEEP_ENTERED.load(Ordering::Acquire)
}

/// Whether heap ownership was published by startup.
pub(crate) fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Bootstrap admission never registers a waiter with its temporary Block.
/// The pages keep their access: nothing here calls the kernel for a
/// mapping.
pub(crate) fn try_map_pages(size: usize) -> Result<NonNull<u8>, i32> {
    if !ready() {
        return Err(crate::constants::EAGAIN);
    }
    let _guard = HEAP_LOCK.try_lock().ok_or(crate::constants::EAGAIN)?;
    // SAFETY: this successful guard provides the only heap/map borrow.
    let state = unsafe { &mut *HEAP.0.get() };
    let pages = size / PAGE;
    let address = state.take(pages)?;
    // SAFETY: the room gave this exact mapping exclusively to admission.
    unsafe { core::ptr::write_bytes(address as *mut u8, 0, size) };
    NonNull::new(address as *mut u8).ok_or(ENOMEM)
}

/// Give an ended or unpublished native page back without blocking under TABLE.
/// # Safety
/// The caller owns these whole pages and has ended every reader and waiter.
pub(crate) unsafe fn try_unmap_pages(pointer: NonNull<u8>, size: usize) -> bool {
    let Some(_guard) = HEAP_LOCK.try_lock() else {
        return false;
    };
    // SAFETY: the guard gives the only borrow; the caller owns the pages.
    let state = unsafe { &mut *HEAP.0.get() };
    state
        .space
        .set(pointer.as_ptr() as usize, size / PAGE, Page::Free);
    true
}

/// Zeroed whole pages for an anonymous mapping (relibc's mmap): no header,
/// so any whole pages of them go back with `unmap_pages`.
pub fn map_pages(size: usize) -> Result<NonNull<u8>, i32> {
    probe_pause();
    if size == 0 || !size.is_multiple_of(PAGE) {
        return Err(EINVAL);
    }
    let address = heap(|state| state.take(size / PAGE))?;
    // SAFETY: the heap gave `size` bytes there to this caller alone.
    unsafe { core::ptr::write_bytes(address as *mut u8, 0, size) };
    NonNull::new(address as *mut u8).ok_or(ENOMEM)
}

/// Gives back whole pages of a mapping of `map_pages`: they lose their
/// access (#187).
///
/// # Safety
/// The pages came from `map_pages`, are not given back yet, and nothing
/// uses them any more.
pub unsafe fn unmap_pages(pointer: NonNull<u8>, size: usize) {
    heap(|state| state.give(pointer.as_ptr() as usize, size / PAGE));
}

/// Borrow the process handle kept alive by the initialized heap.
pub fn process() -> &'static Handle<Process> {
    assert!(READY.load(Ordering::Acquire), "published heap process");
    &config().process
}
