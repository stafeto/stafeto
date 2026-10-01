// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Retained allocation outcomes and prepaid release under actual resource pressure.
use super::*;
use abi::allocation as heap;
use core::cell::UnsafeCell;
rt::upcall_entry!(entry, dispatch);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static DEPTH: AtomicUsize = AtomicUsize::new(0);
static HANDLERS: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicUsize = AtomicUsize::new(0);
static HELD: AtomicUsize = AtomicUsize::new(0);
struct Blocks(UnsafeCell<[*mut u8; 4096]>);
// SAFETY: only main accesses this array after joining the worker and its handlers.
unsafe impl Sync for Blocks {}
static BLOCKS: Blocks = Blocks(UnsafeCell::new([ptr::null_mut(); 4096]));
unsafe fn allocation(size: usize) -> *mut u8 {
    // Keep calls opaque so optimization cannot remove/reorder allocations
    // around injected failures, metadata inspection or heap warm-up.
    let allocate = core::hint::black_box(heap::malloc as unsafe extern "C" fn(usize) -> *mut u8);
    unsafe { allocate(size) }
}
unsafe extern "C" fn dispatch() {
    let depth = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    HANDLERS.fetch_add(1, Ordering::SeqCst);
    let errno = unsafe { abi::__errno_location() };
    let saved = unsafe { *errno };
    let native = Handle::borrowed(rt::abi::Handle(NATIVE.load(Ordering::Acquire)));
    if depth == 1 {
        heap::probe_upcall(&native, 1);
        unsafe { rt::upcall::enable() }.unwrap();
    } else {
        heap::probe_ack_interrupt(&native);
    }
    let block = unsafe { allocation(37) };
    if block.is_null() {
        ERRORS.fetch_add(1, Ordering::Release);
    } else {
        unsafe { block.write_bytes(0xa5, 37) };
        if depth == 1 && MODE.load(Ordering::Acquire) == 3 {
            HELD.store(block as usize, Ordering::Release);
        } else {
            unsafe { heap::free(block) };
        }
    }
    if unsafe { *errno } != saved {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    rt::upcall::mask().unwrap();
    unsafe { *errno = saved };
    DEPTH.fetch_sub(1, Ordering::SeqCst);
}
unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    let native = unsafe { threads::probe_native(threads::pthread_self()) }.unwrap();
    NATIVE.store(native.raw().0, Ordering::Release);
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    let baseline = heap::probe_stats();
    unsafe { rt::upcall::bind(entry) }.unwrap();
    unsafe { rt::upcall::enable() }.unwrap();
    let ack_before = heap::probe_ack_interrupts();
    for (round, op) in [1u64, 4, 2, 3].into_iter().enumerate() {
        MODE.store(op as usize, Ordering::Release);
        let original = if op >= 2 && op != 4 {
            let block = unsafe { allocation(37) };
            if block.is_null() {
                return ptr::null_mut();
            }
            unsafe { block.write_bytes(0x5a, 37) };
            block
        } else {
            ptr::null_mut()
        };
        heap::probe_upcall(&native, op);
        let block = match op {
            1 => unsafe { allocation(37) },
            4 => unsafe { heap::calloc(37, 1) },
            2 => unsafe { heap::realloc(original, 4096) },
            3 => {
                unsafe { heap::free(original) };
                HELD.load(Ordering::Acquire) as *mut u8
            }
            _ => unreachable!(),
        };
        let state = heap::probe_stats();
        if block.is_null()
            || state.0 <= baseline.0
            || state.2 <= baseline.2
            || HANDLERS.load(Ordering::Acquire) != (round + 1) * 2
            || ERRORS.load(Ordering::Acquire) != 0
            || DEPTH.load(Ordering::Acquire) != 0
            || unsafe { *errno } != 777
            || heap::probe_ack_interrupts() != ack_before + round as u64 + 1
        {
            failed(320);
            return ptr::null_mut();
        }
        let expected = match op {
            4 => 0,
            2 => 0x5a,
            3 => 0xa5,
            _ => 0,
        };
        if (op != 1
            && unsafe { core::slice::from_raw_parts(block, 37) }
                .iter()
                .any(|b| *b != expected))
            || (op == 2 && block == original)
            || (op == 3 && block != original)
        {
            failed(321);
            return ptr::null_mut();
        }
        unsafe { heap::free(block) };
        let after = heap::probe_stats();
        if after != baseline {
            rt::println!(
                "heap round={} before={:?} after={:?}",
                round,
                baseline,
                after
            );
            failed(322);
            return ptr::null_mut();
        }
    }
    rt::upcall::mask().unwrap();
    rt::upcall::unbind().unwrap();
    rt::println!(
        "heap-reply-probe: nested malloc/calloc/realloc/free, reused address, bytes, errno and ACK interruption"
    );
    ptr::dangling_mut::<c_void>()
}
fn growth() -> bool {
    let before = heap::probe_stats();
    // SAFETY: main exclusively owns this array throughout the phase.
    let storage = unsafe { &mut *BLOCKS.0.get() };
    let blocks = &mut storage[..1000];
    for block in blocks.iter_mut() {
        *block = unsafe { allocation(1) };
        if block.is_null() {
            return failed(323);
        }
        unsafe { (*block).write(0x5a) };
    }
    let full = heap::probe_stats();
    if full.1 <= before.1 || full.0 <= before.0 || full.2 <= before.2 {
        return failed(324);
    }
    for block in blocks.iter_mut().rev() {
        if unsafe { **block } != 0x5a {
            return failed(325);
        }
        unsafe { heap::free(*block) };
        *block = ptr::null_mut();
    }
    let warmed = heap::probe_stats();
    if warmed.0 != before.0 || warmed.2 != before.2 {
        return failed(326);
    }
    for _ in 0..2000 {
        let block = unsafe { allocation(64) };
        if block.is_null() {
            return failed(327);
        }
        unsafe {
            block.write_volatile(0x5a);
            heap::free(block)
        };
    }
    if heap::probe_stats() != warmed {
        return failed(328);
    }
    rt::println!("heap-reply-probe: 1000 live blocks grow metadata, 2000 releases reuse storage");
    true
}
fn failure() -> bool {
    let before = heap::probe_stats();
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    let block = unsafe { allocation(64) };
    if block.is_null() {
        return failed(329);
    }
    unsafe { block.write_bytes(0x5a, 64) };
    let live = heap::probe_stats();
    heap::probe_reject_new(true);
    let denied = unsafe { allocation(64) };
    let correct_error = unsafe { *errno } == ENOMEM;
    let preserved = heap::probe_stats() == live;
    let mut out = ptr::dangling_mut::<u8>();
    unsafe { *errno = 888 };
    let aligned_error = unsafe { heap::posix_memalign(&mut out, 64, 64) };
    let aligned_preserved = out == ptr::dangling_mut::<u8>() && unsafe { *errno } == 888;
    let resized = unsafe { heap::realloc(block, 16) };
    let prepaid_realloc = resized == block;
    let rejected = unsafe { heap::realloc(block, usize::MAX) };
    let realloc_preserved = rejected.is_null()
        && unsafe { *errno } == ENOMEM
        && unsafe { core::slice::from_raw_parts(block, 16) }
            .iter()
            .all(|b| *b == 0x5a);
    unsafe {
        *errno = 999;
        heap::free(block)
    };
    let released = unsafe { *errno } == 999;
    heap::probe_reject_new(false);
    if !denied.is_null()
        || !correct_error
        || !preserved
        || aligned_error != ENOMEM
        || !aligned_preserved
        || !prepaid_realloc
        || !realloc_preserved
        || !released
        || heap::probe_stats() != before
    {
        rt::println!(
            "heap failure denied={} errno={} same={} aligned={} output={} resize={} failure={} release={} before={:?} after={:?}",
            denied.is_null(),
            correct_error,
            preserved,
            aligned_error,
            aligned_preserved,
            prepaid_realloc,
            realloc_preserved,
            released,
            before,
            heap::probe_stats()
        );
        return failed(330);
    }
    rt::println!(
        "heap-reply-probe: reservation failure before allocation, paid realloc/free and preserved failure bytes"
    );
    true
}
fn pressure() -> bool {
    let held = fill_handles();
    let before = heap::probe_stats();
    let block = unsafe { allocation(64) };
    if block.is_null() {
        return failed(331);
    }
    unsafe { block.write_volatile(0x5a) };
    heap::probe_reject_new(true);
    unsafe { heap::free(block) };
    heap::probe_reject_new(false);
    if heap::probe_stats() != before {
        return failed(332);
    }
    // Keep small live blocks until existing metadata/application chunks fill.
    // Neither allocator can obtain another kernel memory capability now.
    let blocks = unsafe { &mut *BLOCKS.0.get() };
    let mut count = 0;
    for slot in blocks.iter_mut() {
        let block = unsafe { allocation(1) };
        if block.is_null() {
            break;
        }
        *slot = block;
        count += 1;
    }
    if count == 0 || count == blocks.len() {
        return failed(333);
    }
    heap::probe_reject_new(true);
    for slot in blocks[..count].iter_mut() {
        unsafe { heap::free(*slot) };
        *slot = ptr::null_mut();
    }
    heap::probe_reject_new(false);
    let restored = heap::probe_stats() == before;
    drop(held);
    if !restored {
        return failed(334);
    }
    rt::println!(
        "heap-reply-probe: actual handle exhaustion and full storage still permit all frees"
    );
    true
}
fn replay() -> bool {
    let baseline = heap::probe_stats();
    let base = 1u64 << 63;
    let args = [1, 37, 16, 0];
    let original = heap::probe_call(args, base).unwrap();
    if original.0 != 0 || original.1 == 0 {
        return failed(337);
    }
    if heap::probe_call(args, base).unwrap() != original
        || heap::probe_call([1, 38, 16, 0], base).unwrap() != (EINVAL, 0)
    {
        return failed(338);
    }
    heap::probe_ack(base).unwrap();
    let free = [3, 0, 0, original.1 as u64];
    if heap::probe_call(free, base + 1).unwrap() != (0, 0) {
        return failed(339);
    }
    let replacement = heap::probe_call(args, base + 2).unwrap();
    if replacement != original {
        return failed(340);
    }
    // Confirm the old FREE while a different ready result remains retained.
    let both = heap::probe_stats();
    heap::probe_ack(base + 1).unwrap();
    heap::probe_ack(base + 1).unwrap();
    if heap::probe_call(args, base + 2).unwrap() != replacement || heap::probe_stats().0 >= both.0 {
        return failed(341);
    }
    heap::probe_ack(base + 2).unwrap();
    if heap::probe_call(free, base + 3).unwrap() != (0, 0) {
        return failed(342);
    }
    let newer = heap::probe_call(args, base + 4).unwrap();
    if newer != original {
        return failed(343);
    }
    heap::probe_ack(base + 4).unwrap();
    let live = heap::probe_stats();
    if heap::probe_call(free, base + 3).unwrap() != (0, 0) || heap::probe_stats() != live {
        return failed(344);
    }
    heap::probe_ack(base + 3).unwrap();
    // The reused block remains live despite replaying the previous object's FREE.
    let pointer = newer.1 as *mut u8;
    unsafe {
        pointer.write_volatile(0x5a);
        heap::free(pointer)
    };
    if heap::probe_stats() != baseline || heap::probe_ack(base + 3).unwrap() != (0, 0) {
        return failed(345);
    }
    rt::println!(
        "heap-reply-probe: changed-body rejection, independent ACK, old FREE replay preserves reused block"
    );
    true
}
pub(super) fn run() -> bool {
    let warm = unsafe { allocation(4096) };
    if warm.is_null() {
        return failed(335);
    }
    unsafe {
        warm.write_volatile(0x5a);
        heap::free(warm)
    };
    let baseline = heap::probe_stats();
    let mut child = 0;
    let mut value = ptr::null_mut();
    if unsafe { threads::pthread_create(&mut child, ptr::null(), Some(worker), ptr::null_mut()) }
        != 0
        || unsafe { threads::pthread_join(child, &mut value) } != 0
        || value.is_null()
    {
        return failed(336);
    }
    if heap::probe_stats() != baseline || !growth() || !failure() || !pressure() || !replay() {
        return false;
    }
    true
}
