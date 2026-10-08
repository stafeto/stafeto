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

#[path = "relibc/exit_intent.rs"]
mod exit_intent;

use crate::{allocation, constants::*};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use posix_thread::{Block, flag};
use rt::abi::{Policy, Rights, ThreadState};
use rt::handle::{Channel, Handle, Thread};
use rt::sys;

/// Places, the main thread's among them.
pub const PLACES: usize = 64;
const PAGE: usize = 4096;
/// The IPC buffers of the threads: a page each from here (place 0 is the
/// main thread's own, given by the loader).
const BUFFERS: usize = 0x200_0000;

// Admission hint only: full lifetime state remains the authority for row reuse.
static FREE_EPOCH: AtomicU32 = AtomicU32::new(0);

/// The caller holds TABLE_LOCK after completing exact detach and resource cleanup.
fn publish_free(place: &Place) {
    place.state.free();
    FREE_EPOCH.fetch_add(1, Ordering::SeqCst);
    posix_sync::futex_wake(&FREE_EPOCH, u32::MAX);
}

mod lifetime;
pub(crate) mod native;
mod native_owner;
pub use lifetime::OwnerStatus;
use lifetime::{DETACHED, DETACHING, EXITED, FREE, LIVE, Lifetime, RELEASED};

/// A place of the table: 64 bytes.
#[repr(C, align(64))]
struct Place {
    state: Lifetime,
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
const _: () = assert!(core::mem::offset_of!(Place, native) == 8);
const _: () = assert!(core::mem::offset_of!(Place, block) == 16);
const _: () = assert!(core::mem::offset_of!(Place, floating) == 56);

static TABLE: [Place; PLACES] = [const {
    Place {
        state: Lifetime::new(),
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

/// Fixed callbacks installed by shared initialization before its Ready state.
static OPEN_DETACH: AtomicUsize = AtomicUsize::new(0);
static OPEN_HELP: AtomicUsize = AtomicUsize::new(0);

/// Register the file layer callbacks once, before any resident Open exists.
/// Fork preserves these code pointers; child initialization discards records.
pub fn configure_open_lifetime(detach: fn(u64) -> bool, help: fn()) {
    let known = OPEN_DETACH.load(Ordering::Acquire);
    assert!(known == 0 || known == detach as usize);
    let known_help = OPEN_HELP.load(Ordering::Acquire);
    assert!(known_help == 0 || known_help == help as usize);
    OPEN_HELP.store(help as usize, Ordering::Release);
    OPEN_DETACH.store(detach as usize, Ordering::Release);
}

pub(crate) fn owner_token(id: u64) -> Option<u64> {
    let index = usize::try_from(id).ok()?.checked_sub(1)?;
    TABLE.get(index)?.state.token(index)
}

/// The exact current lifetime, after the file layer registered its callbacks.
pub fn open_owner() -> Result<u64, i32> {
    if let Some(block) = unsafe { posix_thread::block().as_ref() }
        && let Some(error) = native::admission_error(block)
    {
        return Err(error);
    }
    if OPEN_DETACH.load(Ordering::Acquire) == 0 {
        return Err(EIO);
    }
    let index = usize::try_from(current())
        .ok()
        .and_then(|id| id.checked_sub(1))
        .ok_or(EIO)?;
    TABLE
        .get(index)
        .and_then(|place| place.state.owner(index))
        .ok_or(EIO)
}

fn detach_open_owner(owner: u64) -> bool {
    let place = &TABLE[(owner & 63) as usize];
    match place.state.begin_detach(owner) {
        OwnerStatus::Gone | OwnerStatus::Detached => return true,
        OwnerStatus::Alive => unreachable!(),
        OwnerStatus::Detaching => {}
    }
    let function = OPEN_DETACH.load(Ordering::Acquire);
    if function != 0 {
        // SAFETY: initialization stores this immutable fn(u64) code pointer.
        let detach: fn(u64) -> bool = unsafe { core::mem::transmute(function) };
        // The callback locally removes owner/helper references and preserves
        // pending cleanup in the prepaid resident records. It is idempotent.
        if !detach(owner) {
            return false;
        }
    }
    place.state.finish_detach(owner);
    true
}

/// Recover an ended owner before relibc join/release permits memory collection.
/// The syscall under TABLE_LOCK reads native state; callbacks run after unlock.
pub fn detach_ended_open_owner(owner: u64) -> OwnerStatus {
    if owner >> 6 == 0 {
        return OwnerStatus::Gone;
    }
    let place = &TABLE[(owner & 63) as usize];
    {
        let _guard = TABLE_LOCK.lock();
        match place.state.status(owner) {
            OwnerStatus::Gone => return OwnerStatus::Gone,
            OwnerStatus::Detached => return OwnerStatus::Detached,
            OwnerStatus::Detaching => {}
            OwnerStatus::Alive => {
                // A MAKING place has no published native handle yet.
                if place.state.flags() & LIVE == 0 {
                    return OwnerStatus::Alive;
                }
                let native = place.native.load(Ordering::Relaxed);
                if native == 0
                    || !sys::thread_info(&borrowed::<Thread>(native))
                        .is_ok_and(|info| info.state == ThreadState::Ended)
                {
                    return OwnerStatus::Alive;
                }
                place.state.begin_detach(owner);
            }
        }
    }
    detach_open_owner(owner);
    place.state.status(owner)
}

fn help_open_recovery() {
    let function = OPEN_HELP.load(Ordering::Acquire);
    if function != 0 {
        // SAFETY: initialization stores this immutable fn() code pointer.
        let help: fn() = unsafe { core::mem::transmute(function) };
        help();
    }
}

/// Old-image owners detach after exec quiesced their threads, before fd export.
pub(crate) fn detach_for_exec() -> bool {
    let mut complete = true;
    for (index, place) in TABLE.iter().enumerate() {
        if let Some(owner) = place.state.token(index) {
            complete &= detach_open_owner(owner);
        }
    }
    help_open_recovery();
    complete
}

/// The number of the live thread whose relibc `pthread_t` is `pthread`,
/// 0 for none: relibc's thread record lies in its TCB, whose page begins
/// `BLOCK_OFFSET` before the block. For the guest probes.
#[cfg(feature = "thread-probe")]
pub fn number_of(pthread: u64) -> u64 {
    let pthread = pthread as usize;
    for (index, place) in TABLE.iter().enumerate() {
        if place.state.flags() & LIVE == 0 {
            continue;
        }
        let (tcb, length) = if place.stack.load(Ordering::Acquire) == 1 {
            (
                place.tcb.load(Ordering::Acquire),
                place.tcb_len.load(Ordering::Acquire),
            )
        } else {
            (
                place.block.load(Ordering::Relaxed) - posix_thread::BLOCK_OFFSET,
                PAGE,
            )
        };
        if (tcb..tcb + length).contains(&pthread) {
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
    // SAFETY: the caller's promise.
    unsafe { (*block).thread_id = 1 };
    crate::signals::reset_taken_before_live(1);
    place.block.store(block as usize, Ordering::Relaxed);
    place.state.main();
}

/// The table of a forked child (spec 2, 3.2): its only thread, number
/// `id` with the native handle `native`, keeps its place; every other
/// place is free, its handles and memory the parent's (the copies of the
/// other threads' TCBs and stacks stay in the child's heap); the exit
/// channel comes anew when a thread is made, and the child's thread routes
/// the process's signals.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(id: u64, native: u64) {
    for (index, place) in TABLE.iter().enumerate() {
        if index as u64 + 1 == id {
            place.native.store(native, Ordering::Relaxed);
            let block = unsafe { &*(place.block.load(Ordering::Relaxed) as *const Block) };
            if native::is_resident(block) {
                place.stack.store(1, Ordering::Relaxed);
                place.stack_len.store(0, Ordering::Relaxed);
                place.floating.store(0, Ordering::Relaxed);
            } else {
                place.stack.store(0, Ordering::Relaxed);
                place.stack_len.store(0, Ordering::Relaxed);
            }
            place.state.after_fork(true);
            continue;
        }
        place.native.store(0, Ordering::Relaxed);
        place.block.store(0, Ordering::Relaxed);
        place.tcb.store(0, Ordering::Relaxed);
        place.tcb_len.store(0, Ordering::Relaxed);
        place.stack.store(0, Ordering::Relaxed);
        place.stack_len.store(0, Ordering::Relaxed);
        place.state.after_fork(false);
    }
    EXITS.store(0, Ordering::Release);
    ROUTER.store(id, Ordering::Release);
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
    if place.state.flags() & LIVE == 0 {
        return Err(ESRCH);
    }
    let block = place.block.load(Ordering::Relaxed) as *const Block;
    // SAFETY: a live place names a block in a TCB that is not freed.
    Ok((
        unsafe { &*block },
        borrowed(place.native.load(Ordering::Relaxed)),
    ))
}

/// A target's resident page and native capability stay held through this callback.
/// The higher-ranked borrow cannot escape into the callback result.
pub(crate) fn with_target<R>(
    id: u64,
    f: impl for<'a> FnOnce(&'a Block, &'a Handle<Thread>) -> R,
) -> Result<R, i32> {
    let _guard = TABLE_LOCK.lock();
    let index = usize::try_from(id)
        .ok()
        .and_then(|id| id.checked_sub(1))
        .ok_or(ESRCH)?;
    let place = TABLE.get(index).ok_or(ESRCH)?;
    if place.state.flags() & LIVE == 0 {
        return Err(ESRCH);
    }
    let native = borrowed::<Thread>(place.native.load(Ordering::Acquire));
    if place.stack.load(Ordering::Acquire) == 1
        && !sys::thread_info(&native).is_ok_and(|i| i.state != ThreadState::Ended)
    {
        return Err(ESRCH);
    }
    // SAFETY: LIVE publication and TABLE keep this exact resident page mapped.
    let block = unsafe { &*(place.block.load(Ordering::Acquire) as *const Block) };
    Ok(f(block, &native))
}

/// Held while a block of the table is read (`each_block`) and while
/// `collect` frees a place, so that no block is read after its TCB went.
static TABLE_LOCK: posix_sync::LayerLock = posix_sync::LayerLock::raising();

/// Runs `f` on the block of every live thread.
pub fn each_block(mut f: impl FnMut(&Block)) {
    let _guard = TABLE_LOCK.lock();
    for place in &TABLE {
        if place.state.flags() & LIVE != 0 {
            // SAFETY: as in `target`.
            f(unsafe { &*(place.block.load(Ordering::Relaxed) as *const Block) });
        }
    }
}

/// Runs `f` on the place, native handle and block of every live thread,
/// under the lock of the table, so that no block is freed meanwhile.
pub fn each_live(mut f: impl FnMut(usize, u64, &Block)) {
    let _guard = TABLE_LOCK.lock();
    for (index, place) in TABLE.iter().enumerate() {
        if place.state.flags() & LIVE != 0 {
            let native = place.native.load(Ordering::Relaxed);
            // SAFETY: as in `target`.
            f(index, native, unsafe {
                &*(place.block.load(Ordering::Relaxed) as *const Block)
            });
        }
    }
}

/// How many places hold a thread, for the probes and their measurements.
pub fn occupied() -> usize {
    TABLE
        .iter()
        .filter(|place| place.state.flags() != FREE)
        .count()
}

/// Frees what the threads that ended and were released held: their TCB,
/// stack and handles; drains the exit channel.
pub fn collect() -> bool {
    #[cfg(feature = "thread-probe")]
    probe_router_ended();
    let mut deferred = false;
    let exits = EXITS.load(Ordering::Acquire);
    if exits != 0 {
        let channel = borrowed::<Channel>(exits);
        while sys::try_receive(&channel).is_ok() {}
    }
    // Owner recovery precedes relibc release and stack/TCB reclamation.
    for (index, place) in TABLE.iter().enumerate() {
        if let Some(owner) = place.state.token(index) {
            deferred |= detach_ended_open_owner(owner) == OwnerStatus::Detaching;
        }
    }
    help_open_recovery();
    for (index, place) in TABLE.iter().enumerate().skip(1) {
        if place.stack.load(Ordering::Acquire) == 1 {
            let _guard = TABLE_LOCK.lock();
            native::collect_row(index, place);
            continue;
        }
        if place.state.flags() != LIVE | EXITED | RELEASED | DETACHED {
            continue;
        }
        let _guard = TABLE_LOCK.lock();
        if place.state.flags() != LIVE | EXITED | RELEASED | DETACHED {
            continue;
        }
        let native = place.native.load(Ordering::Relaxed);
        let ended = sys::thread_info(&borrowed::<Thread>(native))
            .is_ok_and(|info| info.state == ThreadState::Ended);
        if !ended || !place.state.claim_collect() {
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
        // SAFETY: relibc released the ended thread; no reader uses its TCB.
        unsafe { core::ptr::write_bytes(tcb as *mut u8, 0xA5, tcb_len) };
        unmap(tcb, tcb_len);
        publish_free(place);
    }
    deferred
}

/// Whether some place holds a thread relibc released (joined, or detached):
/// its end, which the exit channel tells, frees the place.
fn future_exit() -> bool {
    let _guard = TABLE_LOCK.lock();
    TABLE.iter().enumerate().skip(1).any(|(index, place)| {
        let state = place.state.load();
        if index as u64 + 1 == current()
            || state & (LIVE | RELEASED | EXITED | DETACHING) != LIVE | RELEASED | EXITED
        {
            return false;
        }
        let native = place.native.load(Ordering::Acquire);
        native != 0
            && sys::thread_info(&borrowed::<Thread>(native)).is_ok_and(|info| {
                matches!(info.state, ThreadState::Ready | ThreadState::Running)
                    && place.state.load() == state
            })
    })
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
        let snapshot = FREE_EPOCH.load(Ordering::SeqCst);
        let deferred = collect();
        for (index, place) in TABLE.iter().enumerate().skip(1) {
            if place.state.reserve() {
                return Ok(index);
            }
        }
        if deferred || posix_sync::critical() || !future_exit() {
            return Err(EAGAIN);
        }
        // Recheck admission and exact deferred debt before registering an Exit wait.
        for (index, place) in TABLE.iter().enumerate().skip(1) {
            if place.state.reserve() {
                return Ok(index);
            }
        }
        if TABLE
            .iter()
            .any(|place| place.state.flags() & DETACHING != 0)
            || posix_sync::critical()
            || !future_exit()
        {
            return Err(EAGAIN);
        }
        let deadline = rt::time::ticks_to_ns(rt::time::now())
            .checked_add(1_000_000)
            .ok_or(EAGAIN)?;
        match posix_sync::futex_wait(
            &FREE_EPOCH,
            snapshot,
            posix_sync::CLOCK_MONOTONIC,
            Some(deadline),
        ) {
            Ok(_) | Err(EAGAIN | ETIMEDOUT) => {}
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
        if let Some(owner) = place.state.token(index) {
            // This exact reserved target has never executed user code. START_WINDOW
            // executes in the creator and must not start the target independently.
            place.state.begin_detach(owner);
            assert!(
                place.state.finish_detach(owner)
                    || place.state.status(owner) == OwnerStatus::Detached
            );
        }
        close_raw(timer);
        close_raw(channel);
        close_raw(own);
        close_raw(native);
        unmap(tcb, tcb_len);
        let _guard = TABLE_LOCK.lock();
        publish_free(place);
    };
    let ceiling = match crate::ceiling() {
        Ok(ceiling) => ceiling,
        Err(_) => {
            undo(0, 0, 0, 0);
            return Err(EIO);
        }
    };
    // The creator's policy: round robin unless it asked for FIFO.
    let policy_raw = me.policy.load(Ordering::Relaxed);
    let policy = Policy::from_raw(policy_raw).unwrap_or(Policy::RoundRobin);
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
            policy,
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
        block.policy.store(policy_raw, Ordering::Relaxed);
        block.cancel_point.store(0, Ordering::Relaxed);
    }
    place.tcb.store(tcb, Ordering::Relaxed);
    place.tcb_len.store(tcb_len, Ordering::Relaxed);
    place.block.store(block as usize, Ordering::Relaxed);
    place.native.store(native.raw().0, Ordering::Relaxed);
    place.stack.store(0, Ordering::Relaxed);
    place.stack_len.store(0, Ordering::Relaxed);
    place.floating.store(floating(), Ordering::Relaxed);
    crate::signals::reset_taken_before_live(id);
    place.state.set_flags(LIVE);
    let hook = START_WINDOW.swap(0, Ordering::AcqRel);
    if hook != 0 {
        // SAFETY: only probe_start_window stores a C function with this signature.
        let hook = unsafe { core::mem::transmute::<usize, extern "C" fn(u64)>(hook) };
        let creator = current();
        hook(id);
        assert_eq!(current(), creator, "start hook preserves creator identity");
        assert!(
            sys::thread_info(&native).is_ok_and(|info| info.state == ThreadState::Stopped),
            "start hook leaves the target never started"
        );
    }
    if sys::thread_start(&native).is_err() {
        // A hook must not independently start this target. An unproved state
        // ends the process before relibc can reclaim a potentially live TCB.
        if !sys::thread_info(&native).is_ok_and(|info| info.state == ThreadState::Stopped) {
            sys::process_exit(127);
        }
        // SAFETY: the block is the new thread's, which never ran.
        let block = unsafe { &*block };
        place.state.rollback();
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

static START_WINDOW: AtomicUsize = AtomicUsize::new(0);
pub fn probe_start_window(hook: Option<extern "C" fn(u64)>) {
    START_WINDOW.store(hook.map_or(0, |f| f as usize), Ordering::Release);
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
/// so no handler runs past its destructors. Its place in the routing of the
/// process's signals goes in this order (spec 2, 3.3):
/// 1. every signal of the thread blocked;
/// 2. the process signals it took go back to the page;
/// 3. under TABLE_LOCK the thread marks itself as leaving (EXITING) and
///    learns whether it was the router and whether any thread remains;
/// 4. a router takes ROUTER_LOCK, chooses its successor under TABLE_LOCK
///    and tells the process service (Router) outside TABLE_LOCK;
/// 5. the thread ends (ThreadExit), or the process does with the last one.
pub fn leaving() {
    let block = crate::threads::own_block();
    // This path hands the role over itself: the exit hook of a native
    // thread has nothing left to do.
    rt::upcall::set_exit_hook(None);
    // Native deferral survives libc retval publication/release until ThreadExit.
    // Managed exit preserves its existing interruptible cleanup path.
    if !exit_intent::hold_native(
        native::is_resident(block),
        rt::upcall::defer_entries,
        || {
            let own = current();
            if let Some(place) = usize::try_from(own)
                .ok()
                .and_then(|id| id.checked_sub(1))
                .and_then(|index| TABLE.get(index))
            {
                place.state.add_flags(EXITED);
            }
        },
    ) {
        sys::process_exit(127);
    }
    block_signals(block);
    #[cfg(feature = "thread-probe")]
    crate::signals::probe_queue_native_primary_after_intent(block);
    let own = current();
    if let Some(owner) = owner_token(own) {
        detach_open_owner(owner);
    }
    crate::signals::leaving();
    if !leave_table(own) {
        // No other thread lives: the process ends as exit(0) ends it
        // (POSIX: the last thread's pthread_exit), atexit handlers and
        // stdio included.
        // SAFETY: relibc's exit, with its atexit handlers and stdio.
        unsafe { exit(0) }
    }
}

/// Step 1 of the way out: every signal that can be blocked, and
/// cancellation disabled; EXITING is the thread's mark as leaving.
fn block_signals(block: &Block) {
    block.mask.store(
        posix_signals::VALID & !posix_signals::UNBLOCKABLE,
        Ordering::SeqCst,
    );
    block
        .flags
        .fetch_or(flag::EXITING | flag::CANCEL_DISABLED, Ordering::SeqCst);
}

/// Steps 3 and 4 for thread `own`, past step 2; false when no other thread
/// lives (the caller ends the process).
fn leave_table(own: u64) -> bool {
    let (was_router, others) = {
        let _table = TABLE_LOCK.lock();
        #[cfg(feature = "thread-probe")]
        let _held = TableHeld::new(own);
        // A leaving thread is LIVE until its place goes (the main thread's
        // never does); its block says EXITING from here on and no choice of
        // a router takes it.
        if let Some(block) = usize::try_from(own)
            .ok()
            .and_then(|id| id.checked_sub(1))
            .and_then(|index| TABLE.get(index))
            .and_then(|place| {
                // SAFETY: a LIVE place's block lives until the place goes,
                // and only `collect` frees a place, under this lock.
                unsafe { (place.block.load(Ordering::Acquire) as *const Block).as_ref() }
            })
        {
            block.flags.fetch_or(flag::EXITING, Ordering::SeqCst);
        }
        (
            ROUTER.load(Ordering::Acquire) == own,
            successor(own).is_some(),
        )
    };
    #[cfg(feature = "thread-probe")]
    probe_marked(own);
    if !others {
        return false;
    }
    if was_router {
        hand_over(own, true);
    }
    true
}

/// The router `own` leaves: the next thread of the process routes its
/// signals. The handoffs of leaving routers go one at a time under
/// ROUTER_LOCK, each choosing its successor under it, so the last message
/// the service gets names a thread that does not leave. The service is
/// told outside TABLE_LOCK. `leaving` is true when the caller is the leaving
/// thread itself and false when another thread acts for a thread that ended.
fn hand_over(own: u64, leaving: bool) {
    let _order = ROUTER_LOCK.lock();
    let copy = {
        let _table = TABLE_LOCK.lock();
        #[cfg(feature = "thread-probe")]
        let _held = TableHeld::new(own);
        // Only a router passes the role on; this one still is, since the
        // role leaves a thread only through this function.
        if ROUTER.load(Ordering::Acquire) != own {
            return;
        }
        let Some(index) = successor(own) else {
            return;
        };
        ROUTER.store(index as u64 + 1, Ordering::Release);
        let native = borrowed::<Thread>(TABLE[index].native.load(Ordering::Acquire));
        crate::process::router_copy(&native)
    };
    if let Ok(copy) = copy {
        // The calling thread is the one that leaves: no entry has anything
        // to deliver to it. A request of its entry (the service asks for it
        // when a signal comes) would interrupt this exchange, also under a
        // deferral of entries, and the handoff would be lost; the mask of
        // the kernel keeps the exchange whole.
        if leaving {
            let _ = rt::upcall::mask();
        }
        let _ = crate::process::send_router(copy);
    }
}

/// The thread that takes the routing of the process's signals once `own`
/// leaves, as the index of its place: a thread of the layer (the main thread
/// or a pthread) of the highest base level, the first in the table among
/// equals; a native thread of a program only when no thread of the layer
/// lives. A thread that marked itself as leaving is no choice. The caller
/// holds TABLE_LOCK; the choice reads at most 64 places and calls no
/// kernel.
fn successor(own: u64) -> Option<usize> {
    let mut best: Option<(usize, (bool, u32))> = None;
    for (index, place) in TABLE.iter().enumerate() {
        if index as u64 + 1 == own || place.state.flags() & (LIVE | EXITED) != LIVE {
            continue;
        }
        // SAFETY: a LIVE place's block lives until the place goes, and only
        // `collect` frees a place, under TABLE_LOCK, after EXITED.
        let Some(block) =
            (unsafe { (place.block.load(Ordering::Acquire) as *const Block).as_ref() })
        else {
            continue;
        };
        if block.flags.load(Ordering::SeqCst) & flag::EXITING != 0 {
            continue;
        }
        let key = (
            place.stack.load(Ordering::Acquire) == 1,
            u32::MAX - block.base_level.load(Ordering::Relaxed),
        );
        if best.is_none_or(|(_, kept)| key < kept) {
            best = Some((index, key));
        }
    }
    best.map(|(index, _)| index)
}

/// The exit hook of a native thread (`rt::upcall::set_exit_hook`), run by
/// `rt::sys::thread_exit` before its call: the way out of `leaving`, steps
/// 1 to 4, for a thread that ends past the library. When no other thread
/// lives the kernel ends the process with the thread.
pub(crate) fn exit_hook() {
    crate::tls::with_process(|| {
        let block = crate::threads::own_block();
        let own = block.thread_id;
        if own == 0 || block.flags.load(Ordering::SeqCst) & flag::EXITING != 0 {
            return;
        }
        block_signals(block);
        crate::signals::leaving();
        leave_table(own);
    });
}

/// The number of the thread that routes the process's signals: the main
/// thread first (`leave_table`).
static ROUTER: AtomicU64 = AtomicU64::new(1);

/// Orders the handoffs of the router role (`hand_over`). It lifts no
/// holder: a leaving thread holds it across one exchange with the process
/// service, and the holders of the table never wait for it.
static ROUTER_LOCK: posix_sync::LayerLock = posix_sync::LayerLock::new();

/// The number of the thread that holds TABLE_LOCK on its way out, for the
/// probes: the process service is never asked under the lock.
#[cfg(feature = "thread-probe")]
static TABLE_HELD: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "thread-probe")]
struct TableHeld;

#[cfg(feature = "thread-probe")]
impl TableHeld {
    fn new(own: u64) -> Self {
        TABLE_HELD.store(own, Ordering::SeqCst);
        TableHeld
    }
}

#[cfg(feature = "thread-probe")]
impl Drop for TableHeld {
    fn drop(&mut self) {
        TABLE_HELD.store(0, Ordering::SeqCst);
    }
}

/// Whether the calling thread is on its way out and holds TABLE_LOCK.
#[cfg(feature = "thread-probe")]
pub(crate) fn probe_table_held_by_caller() -> bool {
    let held = TABLE_HELD.load(Ordering::SeqCst);
    held != 0 && held == current()
}

/// A router whose thread ended past `rt` without the exit hook never named
/// its successor to the process service: the signals of the process wait on
/// the page for a thread that looks at it. The probe build says so and
/// passes the role on in the name of the thread that ended.
#[cfg(feature = "thread-probe")]
fn probe_router_ended() {
    let router = ROUTER.load(Ordering::Acquire);
    let Some(place) = usize::try_from(router)
        .ok()
        .and_then(|id| id.checked_sub(1))
        .and_then(|index| TABLE.get(index))
    else {
        return;
    };
    {
        let _table = TABLE_LOCK.lock();
        // SAFETY: a LIVE place's block lives until the place goes, and only
        // `collect` frees a place, under this lock.
        let Some(block) =
            (unsafe { (place.block.load(Ordering::Acquire) as *const Block).as_ref() })
        else {
            return;
        };
        if place.state.flags() & LIVE == 0
            || block.flags.load(Ordering::SeqCst) & flag::EXITING != 0
            || !sys::thread_info(&borrowed::<Thread>(place.native.load(Ordering::Acquire)))
                .is_ok_and(|info| info.state == ThreadState::Ended)
        {
            return;
        }
        block.flags.fetch_or(flag::EXITING, Ordering::SeqCst);
    }
    rt::println!("router ended without handoff");
    hand_over(router, false);
}

/// A hook that runs in `leaving` once the thread marked itself as leaving,
/// before it passes the role on: the guest probes hold a thread there.
#[cfg(feature = "thread-probe")]
static PROBE_MARKED: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "thread-probe")]
pub fn probe_marked_hook(hook: Option<fn(u64)>) {
    PROBE_MARKED.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

#[cfg(feature = "thread-probe")]
fn probe_marked(own: u64) {
    let hook = PROBE_MARKED.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only `probe_marked_hook` stores a `fn(u64)`.
        let hook: fn(u64) = unsafe { core::mem::transmute(hook) };
        hook(own);
    }
}

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
        place.state.add_flags(RELEASED);
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
        if place.stack.load(Ordering::Acquire) != 1 {
            place.stack.store(stack, Ordering::Relaxed);
            place.stack_len.store(length, Ordering::Relaxed);
        }
        place.state.add_flags(EXITED);
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
    with_target(id, |block, native| {
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
                let _ = sys::thread_upcall_request(native);
            }
            let _ = sys::thread_interrupt(native);
        }
        0
    })
    .unwrap_or_else(|code| code)
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

/// Observe the exact paid native lifetime after collect, before libc join releases it.
#[cfg(feature = "thread-probe")]
pub fn probe_native_retained(saved: &crate::signals::NativeStopSnapshot) -> bool {
    let _guard = TABLE_LOCK.lock();
    let index = (saved.owner & 63) as usize;
    let place = &TABLE[index];
    if place.state.token(index) != Some(saved.owner)
        || place.state.flags() != LIVE | EXITED | DETACHED
        || place.stack.load(Ordering::Acquire) != 1
        || place.native.load(Ordering::Acquire) != saved.native
        || place.tcb.load(Ordering::Acquire) != saved.page
        || place.tcb_len.load(Ordering::Acquire) != PAGE
        || place.block.load(Ordering::Acquire) != saved.block
        || saved.block < saved.page
        || saved
            .block
            .checked_add(core::mem::size_of::<Block>())
            .is_none_or(|end| end > saved.page + PAGE)
    {
        return false;
    }
    // SAFETY: the exact LIVE page and Block were checked under TABLE before dereference.
    let block = unsafe { &*(saved.block as *const Block) };
    block.thread_id == index as u64 + 1
        && block.thread.load(Ordering::Acquire) == saved.native
        && block.channel.load(Ordering::Acquire) == saved.channel
        && block.timer.load(Ordering::Acquire) == saved.timer
        && saved.native != 0
        && saved.channel != 0
        && saved.timer != 0
}

/// The selected generation is fully reclaimed after the real join/release.
#[cfg(feature = "thread-probe")]
pub fn probe_native_freed(owner: u64) -> bool {
    let _guard = TABLE_LOCK.lock();
    let place = &TABLE[(owner & 63) as usize];
    place.state.flags() == FREE
        && place.state.load() >> 6 == owner >> 6
        && place.native.load(Ordering::Acquire) == 0
        && place.tcb.load(Ordering::Acquire) == 0
        && place.block.load(Ordering::Acquire) == 0
        && place.stack.load(Ordering::Acquire) == 0
        && place.stack_len.load(Ordering::Acquire) == 0
        && place.floating.load(Ordering::Acquire) == 0
}
