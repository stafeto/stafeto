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
use posix_heap::{Allocator, Error};
use posix_map::{Map, Refused, Region};
use posix_sync::LayerLock;
use rt::{
    abi::{Access, Rights},
    handle::{Handle, Memory, Process},
    sys,
};

const BASE: usize = 0x1000_0000;
const LIMIT: usize = 0x2000_0000;
const PAGE: usize = 4096;
const CHUNK: usize = 65536;

struct Config {
    process: Handle<Process>,
}
struct Once(UnsafeCell<Option<Config>>);
// SAFETY: startup writes once before any allocation; READY publishes it and
// it stays immutable thereafter.
unsafe impl Sync for Once {}
static CONFIG: Once = Once(UnsafeCell::new(None));
static READY: AtomicBool = AtomicBool::new(false);
/// The heap and the memory map, both under HEAP_LOCK.
struct State {
    allocator: Allocator,
    map: Map<Handle<Memory>>,
}
struct Heap(UnsafeCell<State>);
// SAFETY: only `heap` borrows it, under HEAP_LOCK (and `adopt`, at startup
// before any other thread).
unsafe impl Sync for Heap {}
static HEAP: Heap = Heap(UnsafeCell::new(State {
    allocator: Allocator::new(),
    map: Map::new(),
}));
static HEAP_LOCK: LayerLock = LayerLock::raising();
/// Set while a thread is inside the heap's section, for the probes.
#[cfg(feature = "thread-probe")]
static INSIDE: AtomicBool = AtomicBool::new(false);

/// Initialize once during single-threaded startup, before any allocation call.
/// The process heap reserves BASE..LIMIT.
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
fn heap<R>(f: impl FnOnce(&mut State) -> R) -> R {
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
    heap(|state| state.allocator.committed())
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
    state.map.push(Region {
        address,
        pages,
        access,
        handle,
    })
}

/// The heap of a forked child (spec 2, 3.2): its own process `process`,
/// and the objects of its map in `map`, which its loader made at the
/// parent's addresses; the parent's handles in the copy of the map and of
/// the configuration go without a close (they name nothing of the
/// child's). The allocator's state is the parent's at the fork, so the
/// heap goes on where the parent's was.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(
    process: Handle<Process>,
    map: impl Iterator<Item = (usize, usize, Access, Handle<Memory>)>,
) -> Result<(), Refused> {
    // SAFETY: the caller's promise gives these borrows alone.
    let (config, state) = unsafe { (&mut *CONFIG.0.get(), &mut *HEAP.0.get()) };
    if let Some(parent) = config.replace(Config { process }) {
        core::mem::forget(parent);
    }
    state.map.forget();
    for (address, pages, access, handle) in map {
        state.map.push(Region {
            address,
            pages,
            access,
            handle,
        })?;
    }
    Ok(())
}

/// Runs `f` on the regions of the memory map, in the order they were added
/// (the loader's, then the heap's chunks), under the heap's lock.
pub fn regions<R>(f: impl FnOnce(&Map<Handle<Memory>>) -> R) -> R {
    heap(|state| f(&state.map))
}

fn grow(state: &mut State, needed: usize, alignment: usize) -> Result<(), Error> {
    let heap = &mut state.allocator;
    let length = needed
        .checked_add(alignment)
        .ok_or(Error::NoMemory)?
        .max(CHUNK)
        .checked_add(PAGE - 1)
        .ok_or(Error::NoMemory)?
        & !(PAGE - 1);
    let address = BASE.checked_add(heap.committed()).ok_or(Error::NoMemory)?;
    if address.checked_add(length).is_none_or(|end| end > LIMIT) {
        return Err(Error::NoMemory);
    }
    // A chunk the map has no room for is not made: the kernel's limit of
    // mappings is the map's.
    if state.map.is_full() {
        return Err(Error::NoMemory);
    }
    let memory = sys::mem_create(length as u64).map_err(|_| Error::NoMemory)?;
    // The map keeps a narrowed copy, and the full handle goes.
    let kept = sys::handle_duplicate(&memory, KEPT).map_err(|_| Error::NoMemory)?;
    drop(memory);
    sys::mem_map(
        &config().process,
        &kept,
        0,
        length as u64,
        address,
        Access::ReadWrite,
    )
    .map_err(|_| Error::NoMemory)?;
    state
        .map
        .push(Region {
            address,
            pages: length / PAGE,
            access: Access::ReadWrite,
            handle: kept,
        })
        .map_err(|_| Error::NoMemory)?;
    // SAFETY: mapping committed a disjoint contiguous range exclusively to heap.
    unsafe {
        if heap.committed() == 0 {
            heap.init(address as *mut u8, length);
        } else {
            heap.extend(length);
        }
    }
    Ok(())
}

/// The nanoseconds the next `map_pages` sleeps before the heap's section,
/// 0 for none: for the probe of relibc's allocator across a fork (its
/// lock held by a thread that waits in the kernel outside the layer's
/// sections).
static PROBE_SLEEP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The next `map_pages` sleeps `ns` nanoseconds first, for the probes.
pub fn probe_sleep_next(ns: u64) {
    PROBE_SLEEP.store(ns, Ordering::Release);
}

/// Whether heap ownership was published by startup.
pub(crate) fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Bootstrap admission never registers a waiter with its temporary Block.
pub(crate) fn try_map_pages(size: usize) -> Result<NonNull<u8>, i32> {
    if !ready() {
        return Err(crate::constants::EAGAIN);
    }
    let _guard = HEAP_LOCK.try_lock().ok_or(crate::constants::EAGAIN)?;
    // SAFETY: this successful guard provides the only heap/map borrow.
    let state = unsafe { &mut *HEAP.0.get() };
    let pointer = match state.allocator.allocate_pages(size) {
        Ok(pointer) => pointer,
        Err(_) => {
            grow(state, size, PAGE).map_err(errno)?;
            state.allocator.allocate_pages(size).map_err(errno)?
        }
    };
    // SAFETY: the allocator gave this exact mapping exclusively to admission.
    unsafe { core::ptr::write_bytes(pointer.as_ptr(), 0, size) };
    Ok(pointer)
}

/// Give an ended or unpublished native page back without blocking under TABLE.
/// # Safety
/// The caller owns these whole pages and has ended every reader and waiter.
pub(crate) unsafe fn try_unmap_pages(pointer: NonNull<u8>, size: usize) -> bool {
    let Some(_guard) = HEAP_LOCK.try_lock() else {
        return false;
    };
    // SAFETY: the guard gives the only allocator borrow; the caller owns the pages.
    unsafe { (&mut *HEAP.0.get()).allocator.free_pages(pointer, size) };
    true
}

/// Zeroed whole pages for an anonymous mapping (relibc's mmap): no header,
/// so any whole pages of them go back with `unmap_pages`.
pub fn map_pages(size: usize) -> Result<NonNull<u8>, i32> {
    let ns = PROBE_SLEEP.swap(0, Ordering::AcqRel);
    if ns != 0 {
        crate::threads::sleep::probe_pause(ns);
    }
    let pointer = heap(|state| {
        if let Ok(pointer) = state.allocator.allocate_pages(size) {
            return Ok(pointer);
        }
        grow(state, size, PAGE)?;
        state.allocator.allocate_pages(size)
    })
    .map_err(errno)?;
    // SAFETY: the heap gave `size` bytes there to this caller alone.
    unsafe { core::ptr::write_bytes(pointer.as_ptr(), 0, size) };
    Ok(pointer)
}

/// Gives back whole pages of a mapping of `map_pages`.
///
/// # Safety
/// The pages came from `map_pages`, are not given back yet, and nothing
/// uses them any more.
pub unsafe fn unmap_pages(pointer: NonNull<u8>, size: usize) {
    // SAFETY: the caller's promise.
    heap(|state| unsafe { state.allocator.free_pages(pointer, size) });
}

fn errno(error: Error) -> i32 {
    match error {
        Error::NoMemory => ENOMEM,
        Error::InvalidAlignment => EINVAL,
    }
}

/// Borrow the process handle kept alive by the initialized heap.
pub fn process() -> &'static Handle<Process> {
    assert!(READY.load(Ordering::Acquire), "published heap process");
    &config().process
}
