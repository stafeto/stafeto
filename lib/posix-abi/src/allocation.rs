// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process heap under a lock of the layer (spec 2, 3.4): the calling
//! thread allocates itself, its holder at the ceiling of the process
//! (LayerLock::raising), and grows the heap (`mem_create`, `mem_map`)
//! under the same lock. No helper thread. An entry of signals inside the
//! section waits for its end. This does not establish a bounded real-time
//! allocator: a section that grows the heap or splits a long free list is
//! longer.

use crate::{constants::*, fail};
use core::{
    cell::UnsafeCell,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, Ordering},
};
use posix_heap::{Allocator, Error, FUNDAMENTAL_ALIGNMENT};
use posix_sync::LayerLock;
use rt::{
    handle::{Handle, Process},
    sys,
};

const BASE: usize = 0x1000_0000;
const LIMIT: usize = 0x2000_0000;
const PAGE: usize = 4096;
const CHUNK: usize = 65536;
const ALLOC: u64 = 1;
const REALLOC: u64 = 2;
const FREE: u64 = 3;
const ZERO: u64 = 4;

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

fn allocate(heap: &mut Allocator, size: usize, alignment: usize) -> Result<NonNull<u8>, Error> {
    let needed = Allocator::required(size, alignment)?;
    if let Ok(pointer) = heap.allocate(size, alignment) {
        return Ok(pointer);
    }
    grow(heap, needed, alignment)?;
    heap.allocate(size, alignment)
}

fn errno(error: Error) -> i32 {
    match error {
        Error::NoMemory => ENOMEM,
        Error::InvalidAlignment => EINVAL,
    }
}

/// The work under the heap's lock is the list of the allocator alone: the
/// zeroing of `calloc` and the copy of a moving `realloc` run after the
/// section, on a block only the caller holds, so that a large one keeps
/// no other thread of the process off the heap or below the ceiling.
fn request(op: u64, size: usize, alignment: usize, pointer: *mut u8) -> Result<*mut u8, i32> {
    if !READY.load(Ordering::Acquire) {
        return Err(ENOMEM);
    }
    match op {
        ALLOC | ZERO => {
            let block = heap(|heap| allocate(heap, size, alignment)).map_err(errno)?;
            if op == ZERO {
                // SAFETY: the block owns at least size writable bytes and is
                // the caller's alone.
                unsafe { block.as_ptr().write_bytes(0, size) };
            }
            Ok(block.as_ptr())
        }
        REALLOC => {
            let Some(old) = NonNull::new(pointer) else {
                return heap(|heap| allocate(heap, size, FUNDAMENTAL_ALIGNMENT))
                    .map(|p| p.as_ptr())
                    .map_err(errno);
            };
            // SAFETY: realloc callers supply a live allocation from this heap.
            let (kept, alignment) =
                unsafe { (Allocator::requested(old), Allocator::alignment(old)) };
            if size <= kept {
                // In place, under the lock: no copy.
                // SAFETY: as above.
                return heap(|heap| unsafe { heap.reallocate(old, size) })
                    .map(|p| p.as_ptr())
                    .map_err(errno);
            }
            let new = heap(|heap| allocate(heap, size, alignment)).map_err(errno)?;
            // SAFETY: both blocks are live and the caller's alone; the new
            // one holds at least `size` > `kept` bytes.
            unsafe { core::ptr::copy_nonoverlapping(old.as_ptr(), new.as_ptr(), kept) };
            // SAFETY: the old block is live and goes once.
            heap(|heap| unsafe { heap.deallocate(old) });
            Ok(new.as_ptr())
        }
        FREE => {
            if let Some(pointer) = NonNull::new(pointer) {
                // SAFETY: free callers supply a uniquely live allocation from this heap.
                heap(|heap| unsafe { heap.deallocate(pointer) });
            }
            Ok(ptr::null_mut())
        }
        _ => Err(EINVAL),
    }
}

fn returned(result: Result<*mut u8, i32>) -> *mut u8 {
    result.unwrap_or_else(|code| {
        fail(code);
        ptr::null_mut()
    })
}

/// # Safety
/// This thread has an initialized errno scope and the process heap is initialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    returned(request(ALLOC, size, FUNDAMENTAL_ALIGNMENT, ptr::null_mut()))
}

/// # Safety
/// Same initialization contract as malloc.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn calloc(count: usize, size: usize) -> *mut u8 {
    let Some(size) = count.checked_mul(size) else {
        return returned(Err(ENOMEM));
    };
    returned(request(ZERO, size, FUNDAMENTAL_ALIGNMENT, ptr::null_mut()))
}

/// # Safety
/// pointer is null or a live allocation from this process heap, with no
/// overlapping accesses; the initialization contract of malloc also applies.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(pointer: *mut u8, size: usize) -> *mut u8 {
    returned(request(REALLOC, size, 0, pointer))
}

/// # Safety
/// Same contract as realloc. Multiplication failure preserves the allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reallocarray(pointer: *mut u8, count: usize, size: usize) -> *mut u8 {
    let Some(size) = count.checked_mul(size) else {
        return returned(Err(ENOMEM));
    };
    unsafe { realloc(pointer, size) }
}

/// # Safety
/// pointer is null or a uniquely live allocation from this process heap.
/// Free preserves errno, including for a null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(pointer: *mut u8) {
    if !pointer.is_null() {
        let _ = request(FREE, 0, 0, pointer);
    }
}

/// # Safety
/// Same initialization contract as malloc. alignment is a nonzero power of two
/// and size is a multiple of alignment; invalid values report EINVAL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut u8 {
    if !alignment.is_power_of_two() || !size.is_multiple_of(alignment) {
        return returned(Err(EINVAL));
    }
    returned(request(ALLOC, size, alignment, ptr::null_mut()))
}

/// # Safety
/// out is writable/aligned for one pointer, and malloc's initialization holds.
/// Failure preserves out and errno; the result is an error number directly.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_memalign(out: *mut *mut u8, alignment: usize, size: usize) -> i32 {
    if out.is_null() {
        return EFAULT;
    }
    if alignment < core::mem::size_of::<usize>() || !alignment.is_power_of_two() {
        return EINVAL;
    }
    match request(ALLOC, size, alignment, ptr::null_mut()) {
        Ok(pointer) => {
            unsafe { out.write(pointer) };
            0
        }
        Err(code) => code,
    }
}

/// Borrow the process handle kept alive by the initialized heap.
pub(crate) fn process() -> &'static Handle<Process> {
    assert!(READY.load(Ordering::Acquire), "published heap process");
    &config().process
}
