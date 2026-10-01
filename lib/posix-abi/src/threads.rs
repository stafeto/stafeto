// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! pthreads without a helper thread (spec 2, 3.4, 3.5). Every operation
//! runs in the calling thread: the table of threads (stacks, handles,
//! claims of joins) is under the layer's lock, a thread's signals, its
//! cancellation and its waits live in its block (posix-thread), and waits
//! use its own channel (posix-sync). A pthread's stack and the page of its
//! TCB above it are one memory object in its band; its end comes as the
//! kernel's notification on its own exit channel (thread_create x7, x8),
//! which its joiner, or the next create, join or detach for a detached one,
//! takes before the stack and the handles go. The main thread's TCB is in
//! `.bss`; its joiner waits on the end word of its block. The process ends
//! with its last application thread.

pub mod cancel;
pub mod mutex;
pub mod once;
pub mod sleep;
pub mod specific;

use crate::{allocation, constants::*, tls};
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use posix_sync::LayerLock;
use posix_thread::Block;
use rt::{
    abi::{Access, Error, Policy, Rights, Source},
    handle::{Channel, Handle, Thread},
    sys,
};

const CAPACITY: usize = PTHREAD_THREADS_MAX as usize;
const PAGE: usize = 4096;
const STACK_BASE: usize = 0x3000_0000;
const STRIDE: usize = 0x10_0000;
const DEFAULT_STACK: usize = 65536;
const ATTR_MAGIC: u64 = 0x5054_4852_4154_5431;
type Start = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Attributes {
    magic: u64,
    stack_size: usize,
    guard_size: usize,
    detached: i32,
    reserved: u32,
}

impl Attributes {
    fn defaults() -> Self {
        Self {
            magic: ATTR_MAGIC,
            stack_size: DEFAULT_STACK,
            guard_size: PAGE,
            detached: PTHREAD_CREATE_JOINABLE,
            reserved: 0,
        }
    }
    fn valid(&self) -> bool {
        self.magic == ATTR_MAGIC
            && self.reserved == 0
            && matches!(
                self.detached,
                PTHREAD_CREATE_JOINABLE | PTHREAD_CREATE_DETACHED
            )
            && self.stack_size >= PTHREAD_STACK_MIN as usize
            && rounded(self.stack_size)
                .zip(rounded(self.guard_size))
                .is_some_and(|(stack, guard)| {
                    // The stack, its guard and the page of the TCB above it.
                    stack
                        .checked_add(guard)
                        .and_then(|n| n.checked_add(PAGE))
                        .is_some_and(|n| n <= STRIDE)
                })
    }
}

const _: () = {
    assert!(core::mem::size_of::<Attributes>() == 32);
    assert!(core::mem::align_of::<Attributes>() == 8);
};

fn rounded(size: usize) -> Option<usize> {
    size.checked_add(PAGE - 1).map(|n| n & !(PAGE - 1))
}

static READY: AtomicBool = AtomicBool::new(false);
/// The main thread's handle for its block: the loader gives it no
/// DUPLICATE, so the block names the table's.
static MAIN_SELF: AtomicU64 = AtomicU64::new(0);
/// The application threads that have not ended: the last that ends ends
/// the process, whatever the layer's own threads do.
static LIVE: AtomicUsize = AtomicUsize::new(1);

struct Launch {
    id: AtomicU64,
    callback: AtomicU64,
    argument: AtomicU64,
    floating: AtomicU64,
    /// The page of the thread's TCB, above its stack.
    tcb: AtomicU64,
    /// The thread's own handle with MANAGE, for its block.
    thread: AtomicU64,
    completed: AtomicBool,
    cancel: cancel::State,
    specific: specific::Values,
}
static LAUNCH: [Launch; CAPACITY] = [const {
    Launch {
        id: AtomicU64::new(0),
        callback: AtomicU64::new(0),
        argument: AtomicU64::new(0),
        floating: AtomicU64::new(0),
        tcb: AtomicU64::new(0),
        thread: AtomicU64::new(0),
        completed: AtomicBool::new(false),
        cancel: cancel::State::new(),
        specific: specific::Values::new(),
    }
}; CAPACITY];

/// A thread of the table: its pthread number, its handle with MANAGE, the
/// channel of its end (none for the main thread), its stack and TCB, and
/// whether it is detached or a join claimed it.
struct Entry {
    id: u64,
    native: Handle<Thread>,
    exit: Option<Handle<Channel>>,
    mapping: Option<(usize, usize)>,
    detached: bool,
    claimed: bool,
}
struct Registry {
    entries: [Option<Entry>; CAPACITY],
    next_id: u64,
}
struct Table(UnsafeCell<Registry>);
// SAFETY: only `registry` borrows it, under TABLE_LOCK.
unsafe impl Sync for Table {}
static TABLE: Table = Table(UnsafeCell::new(Registry {
    entries: [const { None }; CAPACITY],
    next_id: 2,
}));
static TABLE_LOCK: LayerLock = LayerLock::new();

/// Runs `f` on the table under the layer's lock (a short critical section).
fn registry<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    let _guard = TABLE_LOCK.lock();
    // SAFETY: the lock gives this borrow alone.
    f(unsafe { &mut *TABLE.0.get() })
}

/// The block of the thread in `slot` of the table.
fn block_of(slot: usize) -> &'static Block {
    let page = if slot == 0 {
        tls::main_page() as usize
    } else {
        LAUNCH[slot].tcb.load(Ordering::Acquire) as usize
    };
    // SAFETY: the TCB of a thread in the table stays mapped until it is
    // taken back under the table's lock.
    unsafe { &*((page + posix_thread::TCB_OFFSET + posix_thread::BLOCK_OFFSET) as *const Block) }
}

/// The calling thread's block.
pub(crate) fn own_block() -> &'static Block {
    // SAFETY: a managed thread has its block for its life.
    unsafe { posix_thread::block().as_ref() }.expect("an attached thread")
}

impl Registry {
    fn find(&self, id: u64) -> Result<usize, i32> {
        self.entries
            .iter()
            .position(|e| e.as_ref().is_some_and(|e| e.id == id))
            .ok_or(ESRCH)
    }
    /// Takes back a thread that ended: its handles, its stack and TCB.
    fn take_back(&mut self, slot: usize) {
        let entry = self.entries[slot].take().expect("an entry to take back");
        if let Some((address, length)) = entry.mapping {
            let block = block_of(slot);
            close_raw(block.timer.swap(0, Ordering::Relaxed));
            close_raw(block.channel.swap(0, Ordering::Relaxed));
            close_raw(LAUNCH[slot].thread.swap(0, Ordering::Relaxed));
            // SAFETY: the kernel told of the thread's end: it never runs again.
            unsafe { sys::mem_unmap(allocation::process(), address, length as u64) }
                .expect("ended pthread stack removal");
        }
        LAUNCH[slot].id.store(0, Ordering::Release);
        drop(entry);
    }
    /// Whether the thread in `slot` ended: the kernel's notification on its
    /// exit channel, or the end word of the main thread.
    fn ended(&self, slot: usize) -> bool {
        match self.entries[slot].as_ref().and_then(|e| e.exit.as_ref()) {
            Some(exit) => matches!(
                sys::try_receive(exit),
                Ok(sys::Received::Notification {
                    source: Source::Exit,
                    ..
                })
            ),
            None => block_of(slot).end.load(Ordering::SeqCst) != 0,
        }
    }
    /// Takes back the detached threads that ended.
    fn take_back_detached(&mut self) {
        for slot in 0..CAPACITY {
            if self.entries[slot].as_ref().is_some_and(|e| e.detached) && self.ended(slot) {
                self.end_past_library(slot);
                self.take_back(slot);
            }
        }
    }
    /// A thread that ended through thread_exit, past pthread_exit, leaves
    /// the count of live threads here.
    fn end_past_library(&self, slot: usize) {
        if block_of(slot).end.load(Ordering::SeqCst) == 0 {
            LIVE.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Initialize once after the heap and file workers, before entering C main.
///
/// # Safety
/// Startup owns exclusive initialization. Stack reservations
/// 0x30000000..0x34000000 and message pages from 0x2000000 are unused. The
/// supplied handle owns the calling main thread.
pub unsafe fn init(main: Handle<Thread>) -> Result<(), Error> {
    if READY.load(Ordering::Acquire) {
        return Err(Error::BadState);
    }
    let ceiling = crate::ceiling()?;
    // A process whose ceiling is its main thread's level puts the locks of
    // the buckets and the layer's workers level with the application
    // (init's POSIX record gives main + 1): say so, since nothing else
    // would.
    if sys::thread_info(&main).is_ok_and(|info| info.base >= ceiling) {
        rt::println!(
            "posix-abi: the process ceiling {} is not above main; its helper threads compete with main",
            ceiling
        );
    }
    posix_sync::configure(ceiling, crate::signals::deliver_deferred);
    MAIN_SELF.store(main.raw().0, Ordering::Release);
    LAUNCH[0].id.store(1, Ordering::Release);
    // SAFETY: startup is single-threaded.
    unsafe { &mut *TABLE.0.get() }.entries[0] = Some(Entry {
        id: 1,
        native: main,
        exit: None,
        mapping: None,
        detached: false,
        claimed: false,
    });
    READY.store(true, Ordering::Release);
    Ok(())
}

extern "C" fn trampoline(slot: u64) -> ! {
    let launch = &LAUNCH[slot as usize];
    let id = launch.id.load(Ordering::Acquire);
    // SAFETY: pthread_create supplied a live C function pointer; this slot cannot
    // be reused until this native thread is confirmed ended.
    let callback: Start =
        unsafe { core::mem::transmute(launch.callback.load(Ordering::Relaxed) as usize) };
    let argument = launch.argument.load(Ordering::Relaxed) as *mut c_void;
    let floating = launch.floating.load(Ordering::Relaxed);
    let tcb = launch.tcb.load(Ordering::Relaxed) as *mut u8;
    // SAFETY: EL0 owns its FP environment. Restore the creator's control and
    // status registers before entering any user callback.
    unsafe {
        core::arch::asm!("msr fpcr, {control}", "msr fpsr, {status}",
            control = in(reg) floating & 0xffff_ffff,
            status = in(reg) floating >> 32,
            options(nomem, nostack, preserves_flags));
    }
    // SAFETY: the creator built the TCB in the page above the stack, the
    // thread's until it ended.
    unsafe { tls::attach_built(tcb, id) };
    attach_resources(launch.thread.load(Ordering::Relaxed)).expect("managed thread attach");
    let value = unsafe { callback(argument) };
    // SAFETY: the current thread is managed and attached.
    unsafe { pthread_exit(value) }
}

/// Attaches the main thread to the TCB built in `page`, `len` bytes, as
/// pthread `id` with the process's files, gives it its channel and timer,
/// and binds and enables its entry of signals: the second step of its
/// start (spec 2, 3.5), after the process's (posix-crt). The trampoline of
/// `pthread_create` does the same for another thread.
///
/// # Safety
/// As for `tls::attach`; the calling thread is the main thread, after
/// `init`.
pub unsafe fn attach(page: *mut u8, len: usize, id: u64) -> Result<(), i32> {
    // SAFETY: the caller's promise.
    unsafe { tls::attach(page, len, id) };
    attach_resources(MAIN_SELF.load(Ordering::Acquire))
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
    let channel = channel.into_raw().0;
    block.channel.store(channel, Ordering::Relaxed);
    block.waker.store(channel, Ordering::Release);
    crate::signals::attach()
}

/// Closes the handle `raw`, unless it is 0.
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
/// 2, 3.5); the guest probes have it too.
#[cfg(any(feature = "rtbench", feature = "thread-probe"))]
pub fn set_level(level: u8) -> Result<(), i32> {
    let block = own_block();
    let thread = Handle::<Thread>::borrowed(rt::abi::Handle(block.thread.load(Ordering::Relaxed)));
    // Strictly below the ceiling, where the lock of a bucket and the
    // helpers of the layer run: no application thread ties with them.
    if level == 0 || level >= crate::ceiling().map_err(|_| EIO)? {
        return Err(EINVAL);
    }
    sys::thread_set_priority(&thread, level, Policy::Fifo).map_err(|_| EINVAL)?;
    block.base_level.store(u32::from(level), Ordering::Relaxed);
    // A wakeup through the channel or the timer works at their level until
    // the next receive: they follow the thread's. Others reach the channel
    // under the table's lock (cancellation) or only while the thread waits.
    let channel = sys::channel_create(level).map_err(|_| EAGAIN)?;
    let timer = sys::timer_create(&channel, level).map_err(|_| EAGAIN)?;
    registry(|_| {
        let channel = channel.into_raw().0;
        close_raw(block.timer.swap(timer.into_raw().0, Ordering::SeqCst));
        close_raw(block.channel.swap(channel, Ordering::SeqCst));
        block.waker.store(channel, Ordering::SeqCst);
    });
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_self() -> u64 {
    tls::thread_id()
}
#[unsafe(no_mangle)]
pub extern "C" fn pthread_equal(first: u64, second: u64) -> i32 {
    i32::from(first == second)
}

/// # Safety
/// out is writable, attr is null or initialized, and callback/argument remain
/// valid for the child. The calling thread is managed by this process runtime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_create(
    out: *mut u64,
    attr: *const Attributes,
    callback: Option<Start>,
    argument: *mut c_void,
) -> i32 {
    if out.is_null() || callback.is_none() || !READY.load(Ordering::Acquire) {
        return EINVAL;
    }
    let attr = if attr.is_null() {
        Attributes::defaults()
    } else {
        unsafe { *attr }
    };
    if !attr.valid() {
        return EINVAL;
    }
    let control: u64;
    let status: u64;
    // SAFETY: read only the calling thread's current FP environment.
    unsafe {
        core::arch::asm!("mrs {control}, fpcr", "mrs {status}, fpsr",
            control = out(reg) control, status = out(reg) status,
            options(nomem, nostack, preserves_flags));
    }
    let me = own_block();
    let mask = me.mask.load(Ordering::SeqCst);
    let base = me.base_level.load(Ordering::Relaxed) as u8;
    let result = registry(|r| {
        r.take_back_detached();
        let slot = r.entries.iter().position(Option::is_none).ok_or(EAGAIN)?;
        let id = r.next_id;
        let next = id.checked_add(1).ok_or(EAGAIN)?;
        let length = rounded(attr.stack_size).ok_or(EINVAL)?;
        let address = STACK_BASE + slot * STRIDE + rounded(attr.guard_size).ok_or(EINVAL)?;
        let ceiling = crate::ceiling().map_err(|_| EIO)?;
        // The stack and, above it, the page of the thread's TCB.
        let mapped = length + PAGE;
        let memory = sys::mem_create(mapped as u64).map_err(|_| EAGAIN)?;
        sys::mem_map(
            allocation::process(),
            &memory,
            0,
            mapped as u64,
            address,
            Access::ReadWrite,
        )
        .map_err(|_| EAGAIN)?;
        let unmap = || {
            // SAFETY: nothing runs on the stack mapped above.
            unsafe { sys::mem_unmap(allocation::process(), address, mapped as u64) }
                .expect("failed-create stack removal");
        };
        let launch = &LAUNCH[slot];
        launch.callback.store(
            callback.expect("checked") as usize as u64,
            Ordering::Relaxed,
        );
        launch.argument.store(argument as u64, Ordering::Relaxed);
        launch
            .floating
            .store(control | (status << 32), Ordering::Relaxed);
        launch
            .tcb
            .store((address + length) as u64, Ordering::Relaxed);
        // The TCB is built now, so that a signal sent before the thread
        // runs waits in its block; it starts with its creator's mask.
        // SAFETY: the page above the stack is mapped and the new thread's.
        unsafe {
            let tcb = posix_thread::build((address + length) as *mut u8, PAGE);
            (*tcb).block.mask.store(mask, Ordering::SeqCst);
        }
        launch.completed.store(false, Ordering::Relaxed);
        launch.cancel.reset();
        launch.specific.reset();
        launch.id.store(id, Ordering::Release);
        let made = (|| {
            let exit = sys::channel_create(ceiling)?;
            // SAFETY: this slot owns the new stack until its thread ended.
            let native = unsafe {
                sys::thread_create_with(
                    allocation::process(),
                    trampoline,
                    address + length,
                    slot as u64,
                    base,
                    Policy::Fifo,
                    0x2000000 + slot * PAGE,
                    Some((&exit, ceiling)),
                )
            }?;
            let own = sys::handle_duplicate(&native, Rights::MANAGE)?;
            Ok::<_, Error>((native, exit, own))
        })();
        let (native, exit, own) = match made {
            Ok(made) => made,
            Err(_) => {
                launch.id.store(0, Ordering::Release);
                unmap();
                return Err(EAGAIN);
            }
        };
        launch.thread.store(own.into_raw().0, Ordering::Relaxed);
        if sys::thread_start(&native).is_err() {
            close_raw(launch.thread.swap(0, Ordering::Relaxed));
            launch.id.store(0, Ordering::Release);
            drop(native);
            unmap();
            return Err(EAGAIN);
        }
        r.entries[slot] = Some(Entry {
            id,
            native,
            exit: Some(exit),
            mapping: Some((address, mapped)),
            detached: attr.detached != 0,
            claimed: false,
        });
        r.next_id = next;
        LIVE.fetch_add(1, Ordering::SeqCst);
        Ok(id)
    });
    match result {
        Ok(id) => {
            unsafe { out.write(id) };
            0
        }
        Err(status) => status,
    }
}

/// # Safety
/// The caller is managed; out is null or writable for one returned pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_join(thread: u64, out: *mut *mut c_void) -> i32 {
    let point = cancel::Point::begin();
    let me = tls::thread_id();
    let claim = registry(|r| {
        r.take_back_detached();
        let slot = r.find(thread)?;
        let entry = r.entries[slot].as_mut().expect("found entry");
        if entry.id == me {
            return Err(EDEADLK);
        }
        if entry.detached || entry.claimed {
            return Err(EINVAL);
        }
        entry.claimed = true;
        Ok(slot)
    });
    let slot = match claim {
        Ok(slot) => slot,
        Err(status) => {
            point.end();
            return status;
        }
    };
    let release = |point: cancel::Point| {
        registry(|r| {
            if let Some(entry) = r.entries[slot].as_mut() {
                entry.claimed = false;
            }
        });
        point.finish();
        unreachable!("a cancelled join ends its thread");
    };
    let block = block_of(slot);
    let exit = registry(|r| {
        r.entries[slot]
            .as_ref()
            .and_then(|e| e.exit.as_ref())
            .map(|h| h.raw())
    });
    match exit {
        // The main thread has no exit channel: its end word says it ended.
        None => {
            while block.end.load(Ordering::SeqCst) == 0 {
                let woken =
                    posix_sync::futex_wait(&block.end, 0, posix_sync::CLOCK_MONOTONIC, None);
                if woken == Ok(posix_sync::Woken::Entry) && point.requested() {
                    release(point);
                }
            }
        }
        // The kernel's notification of the end: the stack may go then.
        // Entries wait while the thread checks for cancellation and enters
        // receive, so that a request of cancellation or a signal coming in
        // between makes receive return at once.
        Some(exit) => {
            let exit = Handle::<Channel>::borrowed(exit);
            loop {
                let guard = rt::upcall::defer_entries().expect("join entry deferral");
                if point.requested() {
                    drop(guard);
                    release(point);
                }
                let got = sys::receive(&exit);
                drop(guard);
                match got {
                    Ok(sys::Received::Notification {
                        source: Source::Exit,
                        ..
                    }) => break,
                    Ok(_) | Err(Error::Interrupted) => {}
                    Err(error) => panic!("join receive: {error:?}"),
                }
            }
        }
    }
    let value = if block.end.load(Ordering::SeqCst) != 0 {
        block.result.load(Ordering::SeqCst)
    } else {
        0
    };
    registry(|r| {
        if exit.is_some() {
            r.end_past_library(slot);
        }
        r.take_back(slot);
    });
    point.end();
    if !out.is_null() {
        unsafe { out.write(value as *mut c_void) };
    }
    0
}

/// Cancellation asked of a thread (spec 2, 3.5): the flag in its block;
/// when it is enabled, bit CANCEL in its channel for a wait there, an entry
/// for a wait with a service (entries pending under deferral make the wait
/// return), and an interrupt of an IPC wait it is in now.
#[unsafe(no_mangle)]
pub extern "C" fn pthread_cancel(thread: u64) -> i32 {
    registry(|r| {
        let slot = r.find(thread)?;
        let block = block_of(slot);
        let flags = block
            .flags
            .fetch_or(posix_thread::flag::CANCEL_PENDING, Ordering::SeqCst);
        if flags & posix_thread::flag::CANCEL_DISABLED == 0 {
            wake_for_cancel(slot);
        }
        Ok(())
    })
    .map_or_else(|e| e, |()| 0)
}

/// Wakes the thread in `slot` for its cancellation.
fn wake_for_cancel(slot: usize) {
    let block = block_of(slot);
    let channel = block.channel.load(Ordering::Relaxed);
    if channel != 0 {
        let _ = sys::notify(
            &Handle::<Channel>::borrowed(rt::abi::Handle(channel)),
            posix_sync::bit::CANCEL,
        );
    }
    // SAFETY: the table holds the entry of `slot` while the lock is held.
    let native = unsafe { &*TABLE.0.get() }.entries[slot]
        .as_ref()
        .map(|e| e.native.raw());
    if let Some(native) = native {
        let native = Handle::<Thread>::borrowed(native);
        if block.flags.load(Ordering::SeqCst) & posix_thread::flag::SIGNALS_READY != 0 {
            let _ = sys::thread_upcall_request(&native);
        }
        let _ = sys::thread_interrupt(&native);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_detach(thread: u64) -> i32 {
    registry(|r| {
        let slot = r.find(thread)?;
        let entry = r.entries[slot].as_mut().expect("found entry");
        if entry.detached || entry.claimed {
            return Err(EINVAL);
        }
        entry.detached = true;
        r.take_back_detached();
        Ok(())
    })
    .map_or_else(|e| e, |()| 0)
}

/// # Safety
/// The current thread is managed and attached. Registered cleanup nodes,
/// destructors and their arguments remain live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_exit(value: *mut c_void) -> ! {
    unsafe { cancel::exit_cleanup() };
    unsafe { specific::exit_destructors() };
    let block = own_block();
    block.result.store(value as usize, Ordering::SeqCst);
    block.end.store(1, Ordering::SeqCst);
    posix_sync::futex_wake(&block.end, u32::MAX);
    if let Some(launch) = current_launch() {
        launch.completed.store(true, Ordering::Release);
    }
    // Application threads determine the process's life; the layer's
    // workers do not keep it.
    if LIVE.fetch_sub(1, Ordering::SeqCst) == 1 {
        sys::process_exit(0);
    }
    sys::thread_exit()
}

/// # Safety
/// attr points to writable storage for a new attribute object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_init(attr: *mut Attributes) -> i32 {
    if attr.is_null() {
        return EINVAL;
    }
    unsafe { attr.write(Attributes::defaults()) };
    0
}
/// # Safety
/// attr is initialized writable attribute storage with no concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_destroy(attr: *mut Attributes) -> i32 {
    if attr.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    unsafe { (*attr).magic = 0 };
    0
}

/// # Safety
/// attr is initialized writable attribute storage with no concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setstacksize(attr: *mut Attributes, size: usize) -> i32 {
    if attr.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    let mut copy = unsafe { *attr };
    copy.stack_size = size;
    if !copy.valid() {
        return EINVAL;
    }
    unsafe { attr.write(copy) };
    0
}
/// # Safety
/// attr is initialized writable attribute storage with no concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setguardsize(attr: *mut Attributes, size: usize) -> i32 {
    if attr.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    let mut copy = unsafe { *attr };
    copy.guard_size = size;
    if !copy.valid() {
        return EINVAL;
    }
    unsafe { attr.write(copy) };
    0
}
/// # Safety
/// attr is initialized writable attribute storage with no concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setdetachstate(attr: *mut Attributes, state: i32) -> i32 {
    if attr.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    let mut copy = unsafe { *attr };
    copy.detached = state;
    if !copy.valid() {
        return EINVAL;
    }
    unsafe { attr.write(copy) };
    0
}
/// # Safety
/// attr is initialized readable storage, and out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getstacksize(
    attr: *const Attributes,
    out: *mut usize,
) -> i32 {
    if attr.is_null() || out.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    unsafe { out.write((*attr).stack_size) };
    0
}
/// # Safety
/// attr is initialized readable storage, and out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getguardsize(
    attr: *const Attributes,
    out: *mut usize,
) -> i32 {
    if attr.is_null() || out.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    unsafe { out.write((*attr).guard_size) };
    0
}
/// # Safety
/// attr is initialized readable storage, and out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getdetachstate(
    attr: *const Attributes,
    out: *mut i32,
) -> i32 {
    if attr.is_null() || out.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    unsafe { out.write((*attr).detached) };
    0
}

/// Runs `f` with the block and the handle of live pthread `id` under the
/// table's lock; ESRCH for none.
pub(crate) fn with_target(id: u64, f: impl FnOnce(&Block, &Handle<Thread>)) -> Result<(), i32> {
    registry(|r| {
        let slot = r.find(id)?;
        let native = &r.entries[slot].as_ref().expect("found entry").native;
        f(block_of(slot), native);
        Ok(())
    })
}

/// Runs `f` on the block of every thread of the table.
pub(crate) fn each_block(mut f: impl FnMut(&Block)) {
    registry(|r| {
        for slot in 0..CAPACITY {
            if r.entries[slot].is_some() {
                f(block_of(slot));
            }
        }
    });
}

fn current_launch() -> Option<&'static Launch> {
    let id = tls::thread_id();
    (id != 0)
        .then(|| {
            LAUNCH
                .iter()
                .find(|launch| launch.id.load(Ordering::Acquire) == id)
        })
        .flatten()
}

/// The handle with MANAGE of live pthread `thread`, for the guest probes.
///
/// # Safety
/// The thread stays in the table while the borrowed handle is used.
#[cfg(feature = "thread-probe")]
pub unsafe fn probe_native(thread: u64) -> Result<core::mem::ManuallyDrop<Handle<Thread>>, i32> {
    registry(|r| {
        let slot = r.find(thread)?;
        Ok(Handle::borrowed(
            r.entries[slot].as_ref().expect("found entry").native.raw(),
        ))
    })
}

/// The block of pthread `id` while it lives, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_block(id: u64) -> Option<&'static posix_thread::Block> {
    registry(|r| r.find(id).ok()).map(block_of)
}

/// Whether pthread `id` waits by address now, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_futex_waiting(id: u64) -> bool {
    probe_block(id).is_some_and(posix_sync::waiting)
}

/// Test the real window before IPC entry; the closure's resources are dropped
/// before its cancellation boundary. Excluded from the regular sysroot.
#[cfg(feature = "thread-probe")]
pub fn probe_cancel_window(run: impl FnOnce()) {
    let point = cancel::Point::begin();
    run();
    point.finish();
}

/// Observe the current window.
#[cfg(feature = "thread-probe")]
pub fn probe_cancel_active() -> u64 {
    current_launch().map_or(0, |launch| launch.cancel.active.load(Ordering::SeqCst))
}

/// Mark the console phase for nested-window guest probes only.
#[cfg(feature = "thread-probe")]
pub fn probe_cancel_console() {
    cancel::console_wait();
}

/// Confirm a live thread is inside the console phase of read.
#[cfg(feature = "thread-probe")]
pub fn probe_console_waiting(id: u64) -> bool {
    LAUNCH
        .iter()
        .find(|launch| launch.id.load(Ordering::Acquire) == id)
        .is_some_and(|launch| {
            launch.cancel.console.load(Ordering::Acquire)
                && launch.cancel.active.load(Ordering::SeqCst) != 0
        })
}
