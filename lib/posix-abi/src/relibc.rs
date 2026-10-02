// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The threads of a program on relibc (spec 2, 3.5; 5a′): relibc keeps
//! each thread's pthread state, its TLS and the layer's block in a TCB it
//! made, and the layer keeps a table of 64 places of 64 bytes, one a
//! thread: its handle, its block, the memory of its TCB and of its stack.
//! A thread's number is its place plus 1 (relibc's OsTid; the owner word
//! of a relibc mutex); the main thread is number 1.
//!
//! The layer makes a thread (`create`) with its channel, timer and handle
//! in its block before it runs, so a lack of them is EAGAIN from
//! pthread_create. The thread's end comes as the kernel's notification on
//! the table's exit channel; the layer frees its TCB and stack once the
//! kernel told of its end and relibc gave it up (`release`: joined, or
//! detached and ended), so neither its joiner nor a late entry of signals
//! touches freed memory. The next `create`, or an exit, collects them.

use crate::{allocation, constants::*};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use posix_thread::{Block, flag};
use rt::abi::{Error, Policy, Rights, ThreadState};
use rt::handle::{Channel, Handle, Thread};
use rt::sys;

/// Places, the main thread's among them.
pub const PLACES: usize = 64;
const PAGE: usize = 4096;
/// The IPC buffers of the threads: a page each from here (place 0 is the
/// main thread's own, given by the loader).
const BUFFERS: usize = 0x200_0000;

/// States of a place.
const FREE: u32 = 0;
const MAKING: u32 = 1;
const LIVE: u32 = 2;
/// Bits added to LIVE: the thread called exit_thread (its stack is known),
/// relibc released it.
const EXITED: u32 = 4;
const RELEASED: u32 = 8;

/// A place of the table: 64 bytes.
#[repr(C, align(64))]
struct Place {
    state: AtomicU32,
    /// The thread's handle (all rights): for its state, interrupts and
    /// entries. The main thread's is borrowed.
    native: AtomicU64,
    /// Its block, in the TCB relibc made.
    block: AtomicUsize,
    /// relibc's mapping of the TCB (ABI page, TLS, TCB page).
    tcb: AtomicUsize,
    tcb_len: AtomicUsize,
    /// relibc's mapping of the stack, from exit_thread.
    stack: AtomicUsize,
    stack_len: AtomicUsize,
    /// The creator's floating-point environment, FPCR low and FPSR high,
    /// which the thread takes on at its start (POSIX: inherited).
    floating: AtomicU64,
}
const _: () = assert!(core::mem::size_of::<Place>() == 64);

static TABLE: [Place; PLACES] = [const {
    Place {
        state: AtomicU32::new(FREE),
        native: AtomicU64::new(0),
        block: AtomicUsize::new(0),
        tcb: AtomicUsize::new(0),
        tcb_len: AtomicUsize::new(0),
        stack: AtomicUsize::new(0),
        stack_len: AtomicUsize::new(0),
        floating: AtomicU64::new(0),
    }
}; PLACES];

/// The channel every thread's end is told on (thread_create x7).
static EXITS: AtomicU64 = AtomicU64::new(0);

/// The function that takes back a mapping of relibc (posix-platform's
/// munmap).
static UNMAP: AtomicUsize = AtomicUsize::new(0);

/// Called once by posix-platform: how to free relibc's mappings.
pub fn configure(unmap: fn(usize, usize)) {
    UNMAP.store(unmap as usize, Ordering::Release);
}

fn unmap(address: usize, length: usize) {
    let function = UNMAP.load(Ordering::Acquire);
    if function != 0 && address != 0 && length != 0 {
        // SAFETY: `configure` stored a `fn(usize, usize)` there.
        let unmap: fn(usize, usize) = unsafe { core::mem::transmute(function) };
        unmap(address, length);
    }
}

fn borrowed<K>(raw: u64) -> core::mem::ManuallyDrop<Handle<K>> {
    Handle::borrowed(rt::abi::Handle(raw))
}

fn close_raw(raw: u64) {
    if raw != 0 {
        drop(Handle::<rt::handle::Any>::from_raw(rt::abi::Handle(raw)));
    }
}

/// The calling thread's number (relibc's OsTid): 0 for a thread the layer
/// did not attach.
pub fn current() -> u64 {
    // SAFETY: a block lives while its thread runs.
    unsafe { posix_thread::block().as_ref() }.map_or(0, |block| block.thread_id)
}

/// The number of the live thread whose relibc `pthread_t` is `pthread`,
/// 0 for none: relibc's thread record lies in its TCB, whose page begins
/// `BLOCK_OFFSET` before the block. For the guest probes.
#[cfg(feature = "thread-probe")]
pub fn number_of(pthread: u64) -> u64 {
    let pthread = pthread as usize;
    for (index, place) in TABLE.iter().enumerate() {
        if place.state.load(Ordering::Acquire) & LIVE == 0 {
            continue;
        }
        let tcb = place.block.load(Ordering::Relaxed) - posix_thread::BLOCK_OFFSET;
        if (tcb..tcb + PAGE).contains(&pthread) {
            return index as u64 + 1;
        }
    }
    0
}

/// The main thread's place, from stafeto_init once relibc built its TCB.
///
/// # Safety
/// `block` is the main thread's block, in its TCB for its life.
pub unsafe fn attach_main(block: *mut Block) {
    let place = &TABLE[0];
    place
        .native
        .store(crate::threads::main_handle().raw().0, Ordering::Relaxed);
    place.block.store(block as usize, Ordering::Relaxed);
    place.state.store(LIVE, Ordering::Release);
    // SAFETY: the caller's promise.
    unsafe { (*block).thread_id = 1 };
}

/// The block and the handle of live thread `id`, for a signal or a
/// request of cancellation; ESRCH for none. A thread stays in its place
/// until relibc released it, which relibc does after the last use of its
/// number.
/// The block is read without the lock of the table: `collect` frees only a
/// place relibc released, and after that the thread's `pthread_t` is no
/// longer valid (POSIX), so no caller asks for it.
pub fn target(id: u64) -> Result<(&'static Block, core::mem::ManuallyDrop<Handle<Thread>>), i32> {
    let place = usize::try_from(id)
        .ok()
        .and_then(|id| id.checked_sub(1))
        .and_then(|index| TABLE.get(index))
        .ok_or(ESRCH)?;
    if place.state.load(Ordering::Acquire) & LIVE == 0 {
        return Err(ESRCH);
    }
    let block = place.block.load(Ordering::Relaxed) as *const Block;
    // SAFETY: a live place names a block in a TCB that is not freed.
    Ok((
        unsafe { &*block },
        borrowed(place.native.load(Ordering::Relaxed)),
    ))
}

/// Held while a block of the table is read (`each_block`) and while
/// `collect` frees a place, so that no block is read after its TCB went.
static TABLE_LOCK: posix_sync::LayerLock = posix_sync::LayerLock::raising();

/// Runs `f` on the block of every live thread.
pub fn each_block(mut f: impl FnMut(&Block)) {
    let _guard = TABLE_LOCK.lock();
    for place in &TABLE {
        if place.state.load(Ordering::Acquire) & LIVE != 0 {
            // SAFETY: as in `target`.
            f(unsafe { &*(place.block.load(Ordering::Relaxed) as *const Block) });
        }
    }
}

/// How many places hold a thread, for the probes and their measurements.
pub fn occupied() -> usize {
    TABLE
        .iter()
        .filter(|place| place.state.load(Ordering::Acquire) != FREE)
        .count()
}

/// Frees what the threads that ended and were released held: their TCB,
/// stack and handles; drains the exit channel.
pub fn collect() {
    let exits = EXITS.load(Ordering::Acquire);
    if exits != 0 {
        let channel = borrowed::<Channel>(exits);
        while sys::try_receive(&channel).is_ok() {}
    }
    for place in &TABLE[1..] {
        let state = place.state.load(Ordering::Acquire);
        if state != LIVE | EXITED | RELEASED {
            continue;
        }
        let native = place.native.load(Ordering::Relaxed);
        let ended = sys::thread_info(&borrowed::<Thread>(native))
            .is_ok_and(|info| info.state == ThreadState::Ended);
        // One collector takes the place, under the lock of the table: no
        // `each_block` reads the block from here until the place is free.
        let _guard = TABLE_LOCK.lock();
        if !ended
            || place
                .state
                .compare_exchange(state, MAKING, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            continue;
        }
        // SAFETY: the TCB is mapped until the unmap below.
        let block = unsafe { &*(place.block.load(Ordering::Relaxed) as *const Block) };
        close_raw(block.timer.swap(0, Ordering::Relaxed));
        close_raw(block.channel.swap(0, Ordering::Relaxed));
        close_raw(block.thread.swap(0, Ordering::Relaxed));
        close_raw(native);
        unmap(
            place.stack.swap(0, Ordering::Relaxed),
            place.stack_len.swap(0, Ordering::Relaxed),
        );
        let (tcb, tcb_len) = (
            place.tcb.swap(0, Ordering::Relaxed),
            place.tcb_len.swap(0, Ordering::Relaxed),
        );
        // A use of the TCB after its end reads this pattern, not stale
        // values: a joiner's return value, a pthread_t's thread number.
        // SAFETY: the TCB is relibc's mapping of tcb_len bytes, which nobody
        // uses any more.
        unsafe { core::ptr::write_bytes(tcb as *mut u8, 0xA5, tcb_len) };
        unmap(tcb, tcb_len);
        place.state.store(FREE, Ordering::Release);
    }
}

/// Whether some place holds a thread relibc released (joined, or detached):
/// its end, which the exit channel tells, frees the place.
fn exiting() -> bool {
    TABLE[1..]
        .iter()
        .any(|place| place.state.load(Ordering::Acquire) & RELEASED != 0)
}

fn exits() -> Result<u64, i32> {
    let known = EXITS.load(Ordering::Acquire);
    if known != 0 {
        return Ok(known);
    }
    let ceiling = crate::ceiling().map_err(|_| EIO)?;
    let channel = sys::channel_create(ceiling).map_err(|_| EAGAIN)?;
    let raw = channel.raw().0;
    match EXITS.compare_exchange(0, raw, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {
            core::mem::forget(channel);
            Ok(raw)
        }
        Err(other) => Ok(other),
    }
}

/// A free place, reserved (MAKING): after collecting, and waiting for an
/// exiting thread's end when all are taken; EAGAIN when none will come.
fn reserve() -> Result<usize, i32> {
    loop {
        collect();
        for (index, place) in TABLE.iter().enumerate().skip(1) {
            if place
                .state
                .compare_exchange(FREE, MAKING, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(index);
            }
        }
        if !exiting() {
            return Err(EAGAIN);
        }
        let channel = borrowed::<Channel>(exits()?);
        match sys::receive(&channel) {
            Ok(_) | Err(Error::Interrupted) => {}
            Err(_) => return Err(EAGAIN),
        }
    }
}

/// Makes a thread that starts in `entry` on `stack` with argument
/// `argument`, its block `block` (zeroed, in the TCB relibc made, 32 bytes
/// in), with the caller's signal mask, level and files; returns its
/// number. The thread is started.
///
/// # Safety
/// `block` is the block of a TCB relibc mapped for the new thread alone;
/// `stack` is that thread's, set up for `entry`.
pub unsafe fn create(
    entry: extern "C" fn(u64) -> !,
    stack: usize,
    block: *mut Block,
) -> Result<u64, i32> {
    let me = crate::threads::own_block();
    let base = me.base_level.load(Ordering::Relaxed) as u8;
    // relibc maps the ABI page, the TLS and the TCB page in one piece
    // (`Tcb::os_new`) and gives it to the platform: the layer frees it
    // after the thread's end, or now if no thread comes of it.
    // SAFETY: relibc wrote the generic part of the TCB, 32 bytes before
    // the block.
    let (tcb, tcb_len) = unsafe {
        let generic = block
            .cast::<u8>()
            .sub(posix_thread::BLOCK_OFFSET)
            .cast::<posix_thread::GenericTcb>();
        let (end, tls, page) = (
            (*generic).tls_end as usize,
            (*generic).tls_len,
            (*generic).tcb_len,
        );
        (end - tls - PAGE, PAGE + tls + page)
    };
    let reserved = exits().and_then(|exits| reserve().map(|index| (exits, index)));
    let Ok((exits, index)) = reserved else {
        unmap(tcb, tcb_len);
        return Err(EAGAIN);
    };
    let place = &TABLE[index];
    let id = index as u64 + 1;
    let undo = |native: u64, channel: u64, timer: u64, own: u64| {
        close_raw(timer);
        close_raw(channel);
        close_raw(own);
        close_raw(native);
        unmap(tcb, tcb_len);
        place.state.store(FREE, Ordering::Release);
    };
    let ceiling = crate::ceiling().map_err(|_| EIO)?;
    // Its channel takes the wakes of its waits and its timer their
    // deadlines (posix-sync); made at its level.
    let Ok(channel) = sys::channel_create(base) else {
        undo(0, 0, 0, 0);
        return Err(EAGAIN);
    };
    let Ok(timer) = sys::timer_create(&channel, base) else {
        undo(0, channel.into_raw().0, 0, 0);
        return Err(EAGAIN);
    };
    // SAFETY: the caller's promise: the stack and entry are the thread's.
    let made = unsafe {
        sys::thread_create_with(
            allocation::process(),
            entry,
            stack,
            id,
            base,
            Policy::Fifo,
            BUFFERS + index * PAGE,
            Some((&borrowed::<Channel>(exits), ceiling)),
        )
    };
    let Ok(native) = made else {
        undo(0, channel.into_raw().0, timer.into_raw().0, 0);
        return Err(EAGAIN);
    };
    let Ok(own) = sys::handle_duplicate(&native, Rights::MANAGE) else {
        undo(
            native.into_raw().0,
            channel.into_raw().0,
            timer.into_raw().0,
            0,
        );
        return Err(EAGAIN);
    };
    // SAFETY: the caller's promise; the thread does not run yet.
    unsafe {
        let block = &mut *block;
        block
            .mask
            .store(me.mask.load(Ordering::SeqCst), Ordering::Relaxed);
        block.base_level.store(u32::from(base), Ordering::Relaxed);
        block.thread.store(own.into_raw().0, Ordering::Relaxed);
        block.timer.store(timer.into_raw().0, Ordering::Relaxed);
        block.channel.store(channel.into_raw().0, Ordering::Relaxed);
        block.thread_id = id;
        block.cancel_point.store(0, Ordering::Relaxed);
    }
    place.tcb.store(tcb, Ordering::Relaxed);
    place.tcb_len.store(tcb_len, Ordering::Relaxed);
    place.block.store(block as usize, Ordering::Relaxed);
    place.native.store(native.raw().0, Ordering::Relaxed);
    place.stack.store(0, Ordering::Relaxed);
    place.stack_len.store(0, Ordering::Relaxed);
    place.floating.store(floating(), Ordering::Relaxed);
    place.state.store(LIVE, Ordering::Release);
    if sys::thread_start(&native).is_err() {
        // SAFETY: the block is the new thread's, which never ran.
        let block = unsafe { &*block };
        place.state.store(MAKING, Ordering::Release);
        undo(
            native.into_raw().0,
            block.channel.swap(0, Ordering::Relaxed),
            block.timer.swap(0, Ordering::Relaxed),
            block.thread.swap(0, Ordering::Relaxed),
        );
        return Err(EAGAIN);
    }
    core::mem::forget(native);
    Ok(id)
}

/// The new thread's part of its start, once relibc installed its TCB: its
/// entry of signals.
pub fn started() -> Result<(), i32> {
    let id = crate::threads::own_block().thread_id;
    if let Some(place) = (id as usize).checked_sub(1).and_then(|i| TABLE.get(i)) {
        set_floating(place.floating.load(Ordering::Relaxed));
    }
    crate::signals::attach()
}

/// The calling thread's floating-point environment: FPCR, FPSR above.
fn floating() -> u64 {
    let (control, status): (u64, u64);
    // SAFETY: reading the floating-point control and status registers.
    unsafe {
        core::arch::asm!(
            "mrs {c}, fpcr",
            "mrs {s}, fpsr",
            c = out(reg) control,
            s = out(reg) status,
            options(nomem, nostack, preserves_flags)
        );
    }
    (control & 0xffff_ffff) | (status << 32)
}

/// Sets the calling thread's floating-point environment from `floating`.
fn set_floating(environment: u64) {
    // SAFETY: writing the floating-point control and status registers;
    // the values are another thread's, so valid.
    unsafe {
        core::arch::asm!(
            "msr fpcr, {c}",
            "msr fpsr, {s}",
            c = in(reg) environment & 0xffff_ffff,
            s = in(reg) environment >> 32,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// The calling thread leaves: every signal masked, cancellation disabled,
/// so no handler runs past its destructors.
pub fn leaving() {
    let block = crate::threads::own_block();
    block.mask.store(
        posix_signals::VALID & !posix_signals::UNBLOCKABLE,
        Ordering::SeqCst,
    );
    block
        .flags
        .fetch_or(flag::EXITING | flag::CANCEL_DISABLED, Ordering::SeqCst);
    // The process signals this thread took go back to the page; the router
    // of the process's signals, if it was this thread, is the next live
    // one; with none left the process ends as exit(0) ends it (POSIX: the
    // last thread's pthread_exit), atexit handlers and stdio included.
    let own = current();
    // A thread that left is LIVE until its place goes (the main thread's
    // never does); its block says EXITING from `leaving` on.
    let next = TABLE.iter().enumerate().find(|(index, place)| {
        index + 1 != own as usize
            && place.state.load(Ordering::Acquire) & (LIVE | EXITED) == LIVE
            // SAFETY: a LIVE place's block lives until the place goes, and
            // only `collect` frees a place, under the lock, after EXITED.
            && unsafe { (place.block.load(Ordering::Acquire) as *const Block).as_ref() }
                .is_some_and(|b| b.flags.load(Ordering::SeqCst) & flag::EXITING == 0)
    });
    let Some((index, place)) = next else {
        // SAFETY: relibc's exit, with its atexit handlers and stdio.
        unsafe { exit(0) }
    };
    if ROUTER.load(Ordering::Acquire) == own {
        ROUTER.store(index as u64 + 1, Ordering::Release);
        let native = borrowed::<Thread>(place.native.load(Ordering::Relaxed));
        let _ = crate::process::register_router(&native);
    }
    crate::signals::leaving();
}

/// The number of the thread that routes the process's signals: the main
/// thread first (`leaving`).
static ROUTER: AtomicU64 = AtomicU64::new(1);

unsafe extern "C" {
    /// relibc's exit.
    fn exit(status: core::ffi::c_int) -> !;
}

/// relibc gave thread `id` up.
pub fn release(id: u64) {
    if let Some(place) = usize::try_from(id)
        .ok()
        .and_then(|id| id.checked_sub(1))
        .filter(|&index| index != 0)
        .and_then(|index| TABLE.get(index))
    {
        place.state.fetch_or(RELEASED, Ordering::AcqRel);
    }
}

/// Ends the calling thread; its stack, `stack` and `length` bytes as relibc
/// mapped it, goes with its TCB after its end.
pub fn exit_thread(stack: usize, length: usize) -> ! {
    let id = current();
    if let Some(place) = usize::try_from(id)
        .ok()
        .and_then(|id| id.checked_sub(1))
        .filter(|&index| index != 0)
        .and_then(|index| TABLE.get(index))
    {
        place.stack.store(stack, Ordering::Relaxed);
        place.stack_len.store(length, Ordering::Relaxed);
        place.state.fetch_or(EXITED, Ordering::AcqRel);
    }
    collect();
    sys::thread_exit()
}

/// pthread_cancel of thread `id`: the request in its block; when its
/// cancellation is enabled, bit CANCEL in its channel (a wait by address or
/// a sleep returns to its point), and, inside a cancellation point of the
/// layer or with the asynchronous type, an entry and an interrupt of its IPC
/// wait. 0 or an error number.
pub fn cancel(id: u64) -> i32 {
    let (block, native) = match target(id) {
        Ok(target) => target,
        Err(code) => return code,
    };
    let flags = block.flags.fetch_or(flag::CANCEL_PENDING, Ordering::SeqCst);
    if flags & (flag::CANCEL_DISABLED | flag::EXITING) != 0 {
        return 0;
    }
    let channel = block.channel.load(Ordering::Relaxed);
    if channel != 0 {
        let _ = sys::notify(&borrowed::<Channel>(channel), posix_sync::bit::CANCEL);
    }
    let at_point = block.cancel_point.load(Ordering::SeqCst) != 0;
    if at_point || flags & flag::CANCEL_ASYNCHRONOUS != 0 {
        if flags & flag::SIGNALS_READY != 0 {
            let _ = sys::thread_upcall_request(&native);
        }
        let _ = sys::thread_interrupt(&native);
    }
    0
}

/// Whether the calling thread's cancellation point acts now.
pub fn testcancel() -> bool {
    crate::threads::cancel::requested()
}

/// pthread_setcancelstate: whether cancellation is enabled; the old state.
/// A request waits for the next cancellation point.
pub fn set_cancel_enabled(enabled: bool) -> Result<bool, i32> {
    let block = crate::threads::own_block();
    if enabled && block.flags.load(Ordering::SeqCst) & flag::EXITING != 0 {
        return Err(EINVAL);
    }
    let old = if enabled {
        block
            .flags
            .fetch_and(!flag::CANCEL_DISABLED, Ordering::SeqCst)
    } else {
        block
            .flags
            .fetch_or(flag::CANCEL_DISABLED, Ordering::SeqCst)
    };
    Ok(old & flag::CANCEL_DISABLED == 0)
}

/// pthread_setcanceltype: whether the type is asynchronous; the old type.
/// The asynchronous type acts at cancellation points too until the
/// layer's asynchronous cancellation (5h), and an entry interrupts the
/// thread's IPC wait then even outside a point.
pub fn set_cancel_asynchronous(asynchronous: bool) -> bool {
    let block = crate::threads::own_block();
    let old = if asynchronous {
        block
            .flags
            .fetch_or(flag::CANCEL_ASYNCHRONOUS, Ordering::SeqCst)
    } else {
        block
            .flags
            .fetch_and(!flag::CANCEL_ASYNCHRONOUS, Ordering::SeqCst)
    };
    old & flag::CANCEL_ASYNCHRONOUS != 0
}
