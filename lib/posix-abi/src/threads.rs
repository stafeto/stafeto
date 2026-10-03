// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The layer's part of a thread (spec 2, 3.4, 3.5): its block in the TCB
//! relibc made (posix-thread), its channel and timer for waits, its entry
//! of signals, the process's ceiling. relibc owns pthreads; the layer's
//! table of their kernel threads is `crate::relibc`.

pub mod cancel;
pub mod sleep;

use crate::constants::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use posix_thread::Block;
#[cfg(any(feature = "rtbench", feature = "thread-probe"))]
use rt::abi::Policy;
use rt::{
    abi::Error,
    handle::{Handle, Thread},
    sys,
};

static READY: AtomicBool = AtomicBool::new(false);
/// The main thread's handle for its block: the loader gives it no
/// DUPLICATE, so the block names this one.
static MAIN_SELF: AtomicU64 = AtomicU64::new(0);

/// The calling thread's block.
pub(crate) fn own_block() -> &'static Block {
    // SAFETY: an attached thread has its block for its life.
    unsafe { posix_thread::block().as_ref() }.expect("an attached thread")
}

/// The main thread's handle, as the loader gave it.
pub fn main_handle() -> core::mem::ManuallyDrop<Handle<Thread>> {
    Handle::borrowed(rt::abi::Handle(MAIN_SELF.load(Ordering::Acquire)))
}

/// Initialize once at startup, before relibc starts: the process's
/// ceiling, the layer's critical sections and the main thread's handle.
///
/// # Safety
/// Startup owns exclusive initialization. The supplied handle owns the
/// calling main thread.
pub unsafe fn init(main: Handle<Thread>) -> Result<(), Error> {
    if READY.load(Ordering::Acquire) {
        return Err(Error::BadState);
    }
    let base = sys::thread_info(&main)?.base;
    let ceiling = crate::set_ceiling(base);
    // A process whose ceiling is its main thread's level puts the holders
    // of the layer's locks level with the application (init's POSIX record
    // gives main + 1): say so, since nothing else would.
    if ceiling <= base {
        rt::println!(
            "posix-abi: the process ceiling {} is not above main; the holders of the layer's locks compete with main",
            ceiling
        );
    }
    posix_sync::configure(ceiling, crate::signals::deliver_deferred);
    MAIN_SELF.store(main.into_raw().0, Ordering::Release);
    READY.store(true, Ordering::Release);
    Ok(())
}

/// The thread of a forked child (spec 2, 3.2), which goes on in the copy
/// of the TCB of its parent's thread that called fork: its own handle
/// `own` (the loader's thread, MANAGE), a new channel and timer, its
/// signals' word in the block cleared but the mask, which the caller
/// gives back, and no wait by address; the parent's handles in the copy
/// go without a close. Its place in the table of threads stays
/// (crate::relibc::after_fork), so relibc's number of the thread holds.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(own: Handle<Thread>) -> Result<(), i32> {
    use posix_thread::flag;
    let block = own_block();
    let base = sys::thread_info(&own).map_err(|_| EIO)?.base;
    let channel = sys::channel_create(base).map_err(|_| EAGAIN)?;
    let timer = sys::timer_create(&channel, base).map_err(|_| EAGAIN)?;
    let id = block.thread_id;
    let native = own.into_raw().0;
    // The main thread's block names its native handle; another place's a
    // copy with MANAGE, which `collect` closes apart from the native one.
    let thread = if id == 1 {
        MAIN_SELF.store(native, Ordering::Release);
        native
    } else {
        let borrowed = Handle::<Thread>::borrowed(rt::abi::Handle(native));
        sys::handle_duplicate(&*borrowed, rt::abi::Rights::MANAGE)
            .map_err(|_| EAGAIN)?
            .into_raw()
            .0
    };
    block.thread.store(thread, Ordering::Relaxed);
    block.base_level.store(u32::from(base), Ordering::Relaxed);
    block.timer.store(timer.into_raw().0, Ordering::Relaxed);
    block.channel.store(channel.into_raw().0, Ordering::Relaxed);
    block.waker.store(0, Ordering::Relaxed);
    block.pending.store(0, Ordering::Relaxed);
    block.process.store(0, Ordering::Relaxed);
    block.wait_set.store(0, Ordering::Relaxed);
    block.previous.store(0, Ordering::Relaxed);
    block.next.store(0, Ordering::Relaxed);
    block.address.store(0, Ordering::Relaxed);
    block.cancel_point.store(0, Ordering::Relaxed);
    block.flags.fetch_and(
        !(flag::SIGNAL_WAIT
            | flag::BUCKET
            | flag::ENTRY_DEFERRED
            | flag::SIGNALS_READY
            | flag::NO_RESTART
            | flag::WAITING),
        Ordering::SeqCst,
    );
    // SAFETY: the caller's promise.
    unsafe { crate::relibc::after_fork(id, native) };
    Ok(())
}

/// The calling thread's channel, timer and own handle `own` (MANAGE) in its
/// block, and its entry of signals.
fn attach_resources(own: u64) -> Result<(), i32> {
    let block = own_block();
    let thread = Handle::<Thread>::borrowed(rt::abi::Handle(own));
    let base = sys::thread_info(&thread).map_err(|_| EIO)?.base;
    // Its channel takes the wakes of its waits and its timer their
    // deadlines (posix-sync).
    let channel = sys::channel_create(base).map_err(|_| EAGAIN)?;
    let timer = sys::timer_create(&channel, base).map_err(|_| EAGAIN)?;
    block.thread.store(own, Ordering::Relaxed);
    block.base_level.store(u32::from(base), Ordering::Relaxed);
    block.timer.store(timer.into_raw().0, Ordering::Relaxed);
    block.channel.store(channel.into_raw().0, Ordering::Release);
    crate::signals::attach()
}

/// Attaches the main thread to the TCB relibc built and installed: its
/// block in that TCB as thread `id` with the process's files, its channel,
/// timer and entry of signals (spec 2, 3.5). EINVAL when `TPIDR_EL0` does
/// not name `tcb`.
///
/// # Safety
/// `tcb` is the calling thread's for its life; the calling thread is the
/// main thread, after `init`.
pub unsafe fn attach_installed(tcb: *mut posix_thread::Tcb, id: u64) -> Result<(), i32> {
    if tcb.is_null() || posix_thread::tcb() != tcb {
        return Err(EINVAL);
    }
    // SAFETY: the caller's promise; the register names the TCB.
    unsafe { crate::tls::attach_installed(tcb, id) };
    attach_resources(MAIN_SELF.load(Ordering::Acquire))
}

/// Closes the handle `raw`, unless it is 0.
#[cfg(any(feature = "rtbench", feature = "thread-probe"))]
fn close_raw(raw: u64) {
    if raw != 0 {
        drop(Handle::<rt::handle::Any>::from_raw(rt::abi::Handle(raw)));
    }
}

/// Moves the calling thread to kernel level `level` under FIFO (1 to one
/// below the process's ceiling; EINVAL otherwise) through its own handle in
/// its block, and makes it the thread's base level, which the lock of a
/// bucket returns to. A Rust call for the measurements of rtbench 2
/// (feature `rtbench`) until the scheduling attributes of POSIX come (spec
/// 2, 3.5); the guest probes have it too. Not from a signal handler: a
/// wait it interrupted keeps the old channel, which this closes.
#[cfg(any(feature = "rtbench", feature = "thread-probe"))]
pub fn set_level(level: u8) -> Result<(), i32> {
    let block = own_block();
    let thread = Handle::<Thread>::borrowed(rt::abi::Handle(block.thread.load(Ordering::Relaxed)));
    // Strictly below the ceiling, where the holders of the layer's locks
    // run: no application thread ties with them.
    if level == 0 || level >= crate::ceiling().map_err(|_| EIO)? {
        return Err(EINVAL);
    }
    sys::thread_set_priority(&thread, level, Policy::Fifo).map_err(|_| EINVAL)?;
    block.base_level.store(u32::from(level), Ordering::Relaxed);
    // A wakeup through the channel or the timer works at their level until
    // the next receive: they follow the thread's. Cancellation reaches the
    // channel only through the block, which the swap keeps whole.
    let channel = sys::channel_create(level).map_err(|_| EAGAIN)?;
    let timer = sys::timer_create(&channel, level).map_err(|_| EAGAIN)?;
    let _guard = rt::upcall::defer_entries().map_err(|_| EIO)?;
    close_raw(block.timer.swap(timer.into_raw().0, Ordering::SeqCst));
    close_raw(block.channel.swap(channel.into_raw().0, Ordering::SeqCst));
    Ok(())
}

/// Runs `f` on the block of every thread (crate::relibc's table).
pub(crate) fn each_block(f: impl FnMut(&Block)) {
    crate::relibc::each_block(f);
}

/// The calling thread's number (relibc's OsTid): 1 for the main thread.
pub fn thread_number() -> u64 {
    crate::relibc::current()
}

/// The handle of the live thread whose relibc `pthread_t` is `pthread`,
/// for the guest probes.
///
/// # Safety
/// The thread stays in its place while the borrowed handle is used.
#[cfg(feature = "thread-probe")]
pub unsafe fn probe_native(pthread: u64) -> Result<core::mem::ManuallyDrop<Handle<Thread>>, i32> {
    crate::relibc::target(crate::relibc::number_of(pthread)).map(|(_, native)| native)
}

/// The block of thread `pthread` while it lives, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_block(pthread: u64) -> Option<&'static Block> {
    crate::relibc::target(crate::relibc::number_of(pthread))
        .ok()
        .map(|(block, _)| block)
}

/// Whether thread `pthread` waits by address now, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_futex_waiting(pthread: u64) -> bool {
    probe_block(pthread).is_some_and(posix_sync::waiting)
}

/// Test the real window before IPC entry; the closure's resources are dropped
/// before its cancellation boundary.
#[cfg(feature = "thread-probe")]
pub fn probe_cancel_window(run: impl FnOnce()) {
    let point = cancel::Point::begin();
    run();
    point.finish();
}

/// Observe the current window.
#[cfg(feature = "thread-probe")]
pub fn probe_cancel_active() -> u64 {
    cancel::window()
}

/// Mark the console phase for nested-window guest probes only.
#[cfg(feature = "thread-probe")]
pub fn probe_cancel_console() {
    cancel::console_wait();
}

/// Confirm a live thread (its `pthread_t`) is inside the console phase of
/// read.
#[cfg(feature = "thread-probe")]
pub fn probe_console_waiting(pthread: u64) -> bool {
    probe_block(pthread).is_some_and(|block| {
        block.probe.load(Ordering::Acquire) != 0 && block.cancel_point.load(Ordering::SeqCst) != 0
    })
}
