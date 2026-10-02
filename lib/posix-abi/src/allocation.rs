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

use crate::constants::*;
use core::{
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};
use posix_heap::{Allocator, Error};
use posix_sync::LayerLock;
use rt::{
    handle::{Handle, Process},
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
struct Heap(UnsafeCell<Allocator>);
// SAFETY: only `heap` borrows it, under HEAP_LOCK.
unsafe impl Sync for Heap {}
static HEAP: Heap = Heap(UnsafeCell::new(Allocator::new()));
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

/// Runs `f` on the heap under its lock.
fn heap<R>(f: impl FnOnce(&mut Allocator) -> R) -> R {
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
    heap(|heap| heap.committed())
}

/// Runs `run` holding the heap's lock, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_hold(run: impl FnOnce()) {
    heap(|_| run());
}

fn config() -> &'static Config {
    // SAFETY: called after successful startup, which wrote it once.
    unsafe { (*CONFIG.0.get()).as_ref().expect("heap initialized") }
}

fn grow(heap: &mut Allocator, needed: usize, alignment: usize) -> Result<(), Error> {
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
    let memory = sys::mem_create(length as u64).map_err(|_| Error::NoMemory)?;
    sys::mem_map(
        &config().process,
        &memory,
        0,
        length as u64,
        address,
        rt::abi::Access::ReadWrite,
    )
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

/// Zeroed whole pages for an anonymous mapping (relibc's mmap): no header,
/// so any whole pages of them go back with `unmap_pages`.
pub fn map_pages(size: usize) -> Result<NonNull<u8>, i32> {
    let pointer = heap(|heap| {
        if let Ok(pointer) = heap.allocate_pages(size) {
            return Ok(pointer);
        }
        grow(heap, size, PAGE)?;
        heap.allocate_pages(size)
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
    heap(|heap| unsafe { heap.free_pages(pointer, size) });
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
