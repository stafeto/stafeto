// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Signals of threads in their blocks (spec 2, 3.3, design of 5a, 1.9):
//! a thread's mask and pending set are atomic words of its block, the
//! process's actions a table under the layer's lock. pthread_kill sets the
//! bit in the target's block and asks its entry (one call), or wakes its
//! sigwait through its channel; a thread delivers to itself before it
//! returns, and so does pthread_sigmask that unblocks a pending signal,
//! with no call of the kernel. An entry inside a critical section of the
//! layer only marks itself deferred; the end of the section delivers it.
//! Real-time queues, process routing, stop/continue, alternate stacks and
//! automatic syscall restart still require implementation.
use crate::{constants::*, threads};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering, fence};
pub use posix_signals::{DEFAULT, IGNORE};
use posix_sync::LayerLock;
use posix_thread::{Block, flag};
pub use posix_types::{MachineContext, SigAction, SigInfo, SigSet, SignalStack, UserContext};
use rt::abi::{Error, Source};
use rt::handle::{Channel, Handle, Timer};
use rt::{sys, upcall};

fn fail(code: i32) -> i32 {
    crate::fail(code) as i32
}

struct Actions(UnsafeCell<posix_signals::Actions>);
// SAFETY: only `actions` borrows it, under ACTIONS_LOCK.
unsafe impl Sync for Actions {}
static ACTIONS: Actions = Actions(UnsafeCell::new(posix_signals::Actions::new()));
/// Its holder runs at the ceiling of the process (spec 2, 3.4): a thread
/// that changes an action is not delayed by application threads.
static ACTIONS_LOCK: LayerLock = LayerLock::raising();
/// The actions as a delivery reads them without the lock (`action`): a
/// generation, odd while a writer changes them, and for each signal its
/// handler, mask and flags. Writers change them under ACTIONS_LOCK.
static GENERATION: AtomicU64 = AtomicU64::new(0);
static PUBLISHED: [[AtomicU64; 3]; 31] = [const { [const { AtomicU64::new(0) }; 3] }; 31];
const _: () = assert!(posix_signals::INITIAL.handler == 0 && posix_signals::INITIAL.flags == 0);

/// Runs `f` on the process's actions under their lock, and publishes them
/// for the readers without it.
fn actions<R>(f: impl FnOnce(&mut posix_signals::Actions) -> R) -> R {
    let _guard = ACTIONS_LOCK.lock();
    // SAFETY: the lock gives this borrow alone.
    let table = unsafe { &mut *ACTIONS.0.get() };
    GENERATION.fetch_add(1, Ordering::SeqCst);
    let result = f(table);
    for (signal, words) in (1..).zip(&PUBLISHED) {
        let action = table.get(signal).expect("a signal of the table");
        words[0].store(action.handler, Ordering::Relaxed);
        words[1].store(action.mask, Ordering::Relaxed);
        words[2].store(u64::from(action.flags as u32), Ordering::Relaxed);
    }
    GENERATION.fetch_add(1, Ordering::SeqCst);
    result
}

/// The action of valid `signal` without the lock: a copy that no writer
/// changed while it was read (the generation before and after is the same
/// even number). On one processor a writer holds the lock at the ceiling,
/// above every reader, so the loop turns only for a reader preempted
/// inside it.
fn action(signal: i32) -> SigAction {
    let words = &PUBLISHED[signal as usize - 1];
    for _ in 0..16 {
        let before = GENERATION.load(Ordering::Acquire);
        if before & 1 == 0 {
            let action = SigAction {
                handler: words[0].load(Ordering::Relaxed),
                mask: words[1].load(Ordering::Relaxed),
                flags: words[2].load(Ordering::Relaxed) as u32 as i32,
            };
            fence(Ordering::Acquire);
            if GENERATION.load(Ordering::Relaxed) == before {
                return action;
            }
        }
        let _ = sys::yield_now();
    }
    // A writer below the reader (no ceiling yet, a thread without a block)
    // gets the processor only through the lock.
    actions(|table| table.get(signal).expect("a signal of the table"))
}

/// Whether `action` of `signal` ignores it.
fn ignored(signal: i32, action: &SigAction) -> bool {
    action.handler == IGNORE
        || (action.handler == DEFAULT
            && posix_signals::default_action(signal) == posix_signals::DefaultAction::Ignore)
}

/// # Safety
/// set is writable for one signal set. No managed thread is required.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn sigemptyset(set: *mut SigSet) -> i32 {
    if set.is_null() {
        return fail(EFAULT);
    }
    unsafe { set.write(0) };
    0
}
/// # Safety
/// set is writable for one signal set.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn sigfillset(set: *mut SigSet) -> i32 {
    if set.is_null() {
        return fail(EFAULT);
    }
    unsafe { set.write(posix_signals::VALID) };
    0
}
unsafe fn alter(set: *mut SigSet, signal: i32, add: bool) -> i32 {
    if set.is_null() {
        return fail(EFAULT);
    }
    let Ok(bit) = posix_signals::bit(signal) else {
        return fail(EINVAL);
    };
    let old = unsafe { set.read() };
    unsafe { set.write(if add { old | bit } else { old & !bit }) };
    0
}
/// # Safety
/// set is initialized and writable for one signal set.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn sigaddset(set: *mut SigSet, signal: i32) -> i32 {
    unsafe { alter(set, signal, true) }
}
/// # Safety
/// set is initialized and writable for one signal set.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn sigdelset(set: *mut SigSet, signal: i32) -> i32 {
    unsafe { alter(set, signal, false) }
}
/// # Safety
/// set is initialized and readable for one signal set.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn sigismember(set: *const SigSet, signal: i32) -> i32 {
    if set.is_null() {
        return fail(EFAULT);
    }
    let Ok(bit) = posix_signals::bit(signal) else {
        return fail(EINVAL);
    };
    i32::from(unsafe { set.read() } & bit != 0)
}
/// # Safety
/// act is null or readable; old is null or writable. Their storage does not
/// overlap. A catching handler uses the one-argument or SA_SIGINFO signature,
/// remains live, and obeys async-signal safety.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn sigaction(signal: i32, act: *const SigAction, old: *mut SigAction) -> i32 {
    let result = actions(|table| {
        if act.is_null() {
            return table.get(signal).map_err(|_| EINVAL);
        }
        let old = table
            .replace(signal, unsafe { act.read() })
            .map_err(|_| EINVAL)?;
        Ok((old, table.ignored(signal))).map(|(old, ignored)| {
            if ignored {
                // An ignored signal pending in any thread is discarded.
                let bit = posix_signals::bit(signal).expect("valid signal");
                threads::each_block(|block| {
                    block.pending.fetch_and(!bit, Ordering::SeqCst);
                });
            }
            old
        })
    });
    match result {
        Ok(previous) => {
            if !old.is_null() {
                unsafe { old.write(previous) };
            }
            0
        }
        Err(code) => fail(code),
    }
}
/// # Safety
/// A non-special handler is a live void(int) C function, safe during asynchronous
/// entry. Stable BSD semantics are used: no reset, signal deferred during handler.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn signal(signal: i32, handler: u64) -> u64 {
    let action = SigAction {
        handler,
        mask: 0,
        flags: 0,
    };
    let mut old = posix_signals::INITIAL;
    if unsafe { sigaction(signal, &action, &mut old) } == 0 {
        old.handler
    } else {
        u64::MAX
    }
}
/// The calling thread's block.
fn own() -> &'static Block {
    threads::own_block()
}
/// # Safety
/// set is null or readable, old is null or writable; storage does not overlap.
/// No call of the kernel: the mask is a word of the thread's block.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_sigmask(how: i32, set: *const SigSet, old: *mut SigSet) -> i32 {
    let block = own();
    let before = block.mask.load(Ordering::SeqCst);
    if !set.is_null() {
        let Ok(set) = posix_signals::mask(unsafe { set.read() }) else {
            return EINVAL;
        };
        let mask = match how {
            SIG_BLOCK => before | set,
            SIG_UNBLOCK => before & !set,
            SIG_SETMASK => set,
            _ => return EINVAL,
        };
        block.mask.store(mask, Ordering::SeqCst);
        if block.pending.load(Ordering::SeqCst) & !mask != 0 {
            deliver_now();
        }
    }
    if !old.is_null() {
        unsafe { old.write(before) };
    }
    0
}
/// # Safety
/// Same pointers as pthread_sigmask; this implementation also supports threads.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn sigprocmask(how: i32, set: *const SigSet, old: *mut SigSet) -> i32 {
    let code = unsafe { pthread_sigmask(how, set, old) };
    if code == 0 { 0 } else { fail(code) }
}
/// # Safety
/// set is writable for one signal set, in a managed thread.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn sigpending(set: *mut SigSet) -> i32 {
    if set.is_null() {
        return fail(EFAULT);
    }
    let block = own();
    let pending = block.pending.load(Ordering::SeqCst) & block.mask.load(Ordering::SeqCst);
    unsafe { set.write(pending) };
    0
}
/// Sends `signal` to pthread `thread`: the bit in its block, then a wake of
/// its sigwait through its channel or a request of its entry; to the
/// calling thread itself, delivery before the return.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn pthread_kill(thread: u64, signal: i32) -> i32 {
    let bit = if signal == 0 {
        0
    } else {
        match posix_signals::bit(signal) {
            Ok(bit) => bit,
            Err(_) => return EINVAL,
        }
    };
    let action = if signal == 0 {
        None
    } else {
        let action = action(signal);
        Some((action, ignored(signal, &action)))
    };
    if let Some((action, _)) = action
        && (signal == SIGCONT
            || (action.handler == DEFAULT
                && matches!(
                    posix_signals::default_action(signal),
                    posix_signals::DefaultAction::Stop
                )))
    {
        return ENOSYS;
    }
    let me = threads::pthread_self();
    if thread == me {
        // The calling thread's own block: no lock, no call of the kernel.
        if let Some((_, false)) = action {
            own().pending.fetch_or(bit, Ordering::SeqCst);
            deliver_now();
        }
        return 0;
    }
    let sent = threads::with_target(thread, |block, native| {
        let Some((_, ignored)) = action else {
            return;
        };
        // An ended thread that is not joined yet takes no signal.
        if ignored || block.end.load(Ordering::SeqCst) != 0 {
            return;
        }
        block.pending.fetch_or(bit, Ordering::SeqCst);
        let flags = block.flags.load(Ordering::SeqCst);
        if flags & flag::SIGNAL_WAIT != 0 && block.wait_set.load(Ordering::SeqCst) & bit != 0 {
            let channel =
                Handle::<Channel>::borrowed(rt::abi::Handle(block.channel.load(Ordering::Relaxed)));
            let _ = sys::notify(&channel, posix_sync::bit::WAKE);
        } else if flags & flag::SIGNALS_READY != 0 && bit & !block.mask.load(Ordering::SeqCst) != 0
        {
            let _ = sys::thread_upcall_request(native);
        }
    });
    match sent {
        Ok(()) => 0,
        Err(code) => code,
    }
}
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn raise(signal: i32) -> i32 {
    let status = pthread_kill(threads::pthread_self(), signal);
    if status == 0 { 0 } else { fail(status) }
}

/// Waits for a signal of `set`, which the caller blocked, until `deadline`
/// (monotonic ns, from `timeout` read after the pending check): the signal,
/// EAGAIN once the deadline passed, EINVAL for a bad set or timeout. A
/// caught signal or an interrupt resumes the wait; cancellation ends it at
/// the point (EINTR to the caller, which terminates).
fn wait(set: SigSet, timeout: Option<posix_types::Timespec>, start: u64) -> Result<i32, i32> {
    let block = own();
    let set = posix_signals::mask(set).map_err(|_| EINVAL)?;
    if set & !block.mask.load(Ordering::SeqCst) != 0 {
        return Err(EINVAL);
    }
    let take = || loop {
        let pending = block.pending.load(Ordering::SeqCst);
        let eligible = pending & set;
        if eligible == 0 {
            return None;
        }
        let bit = eligible.isolate_lowest_one();
        if block
            .pending
            .compare_exchange(pending, pending & !bit, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Some(bit.trailing_zeros() as i32 + 1);
        }
    };
    block.wait_set.store(set, Ordering::SeqCst);
    block.flags.fetch_or(flag::SIGNAL_WAIT, Ordering::SeqCst);
    let leave = || {
        block.flags.fetch_and(!flag::SIGNAL_WAIT, Ordering::SeqCst);
    };
    // POSIX accepts a ready signal before validating the timeout value.
    if let Some(signal) = take() {
        leave();
        return Ok(signal);
    }
    let deadline = match timeout {
        None => None,
        Some(timeout) => match posix_time::Sleep::new(
            proto_clock::MONOTONIC,
            false,
            timeout.tv_sec,
            timeout.tv_nsec,
            start,
        ) {
            Ok(posix_time::Sleep::Relative(end)) => Some(end.clamp(0, i128::from(u64::MAX)) as u64),
            _ => {
                leave();
                return Err(EINVAL);
            }
        },
    };
    let channel =
        Handle::<Channel>::borrowed(rt::abi::Handle(block.channel.load(Ordering::Relaxed)));
    let timer = Handle::<Timer>::borrowed(rt::abi::Handle(block.timer.load(Ordering::Relaxed)));
    let result = loop {
        if let Some(signal) = take() {
            break Ok(signal);
        }
        // As in a sleep: an entry between the timer and `receive` stays
        // pending and makes `receive` return at once.
        let guard = rt::upcall::defer_entries().expect("sigwait entry deferral");
        if let Some(deadline) = deadline {
            if rt::time::reached(deadline) {
                drop(guard);
                break Err(EAGAIN);
            }
            let _ = sys::timer_set(&timer, deadline);
        }
        let got = sys::receive(&channel);
        drop(guard);
        match got {
            Ok(sys::Received::Notification {
                source: Source::Unlabeled,
                bits,
                ..
            }) if bits & posix_sync::bit::CANCEL != 0 && threads::cancel::requested() => {
                break Err(EINTR);
            }
            Ok(_) => {}
            Err(Error::Interrupted) if threads::cancel::requested() => break Err(EINTR),
            Err(Error::Interrupted) => {}
            Err(error) => panic!("sigwait receive: {error:?}"),
        }
    };
    if deadline.is_some() {
        let _ = sys::timer_cancel(&timer);
    }
    leave();
    result
}

/// # Safety
/// The caller is managed. set is readable and sig is writable; their storage
/// does not overlap. All selected signals are blocked before this call.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn sigwait(set: *const SigSet, sig: *mut i32) -> i32 {
    let point = threads::cancel::Point::begin();
    let result = if set.is_null() || sig.is_null() {
        Err(EFAULT)
    } else {
        let set = unsafe { set.read() };
        wait(set, None, 0).map(|signal| {
            unsafe { sig.write(signal) };
        })
    };
    point.finish();
    result.map_or_else(|code| code, |()| 0)
}

/// # Safety
/// The caller is managed. set is readable, info is null or writable for one
/// SigInfo, and their storage does not overlap. All selected signals are blocked.
/// Caught signals resume this wait; EINTR is not returned. Current
/// pthread_kill/raise causes are reported as SI_THREAD.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn sigwaitinfo(set: *const SigSet, info: *mut SigInfo) -> i32 {
    unsafe { sigtimedwait(set, info, core::ptr::null()) }
}

/// # Safety
/// The caller is managed. set is readable, info is null or writable for one
/// SigInfo, timeout is null or readable for one Timespec. Storage does not
/// overlap. Selected signals are blocked. NULL timeout means indefinite wait;
/// unrelated caught signals resume the original monotonic interval without EINTR.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn sigtimedwait(
    set: *const SigSet,
    info: *mut SigInfo,
    timeout: *const posix_types::Timespec,
) -> i32 {
    let point = threads::cancel::Point::begin();
    let start = rt::time::ticks_to_ns(rt::time::now());
    let result = if set.is_null() {
        Err(EFAULT)
    } else {
        let set = unsafe { set.read() };
        // Copy once; the wait validates it after checking pending signals.
        let timeout = (!timeout.is_null()).then(|| unsafe { timeout.read() });
        wait(set, timeout, start).inspect(|&signal| {
            if !info.is_null() {
                unsafe { info.write(SigInfo::thread(signal)) };
            }
        })
    };
    point.finish();
    result.unwrap_or_else(fail)
}

rt::upcall_entry!(entry, dispatch, context);

/// Where the calling thread's errno lives: the layer's block until 5a′,
/// relibc's `__errno_location` after it. The entry saves and gives back
/// the value there; it never moves the thread pointer (spec 2, 3.5).
static ERRNO_LOCATION: unsafe extern "C" fn() -> *mut core::ffi::c_int = crate::__errno_location;

/// Binds and enables the calling thread's entry, then delivers what came
/// before it.
pub(crate) fn attach() -> Result<(), i32> {
    // SAFETY: the dispatcher holds no interrupted Rust references or locks
    // and enters only caller-supplied C code.
    unsafe { upcall::bind(entry) }.map_err(|_| EIO)?;
    own().flags.fetch_or(flag::SIGNALS_READY, Ordering::SeqCst);
    unsafe { upcall::enable() }.map_err(|_| EIO)?;
    let block = own();
    if block.pending.load(Ordering::SeqCst) & !block.mask.load(Ordering::SeqCst) != 0 {
        deliver_now();
    }
    Ok(())
}

/// Delivers the calling thread's pending unblocked signals now, with no call
/// of the kernel; inside a critical section, at its end.
pub(crate) fn deliver_now() {
    if posix_sync::defer_entry() {
        return;
    }
    // SAFETY: an attached thread outside every critical section.
    unsafe { deliver(core::ptr::null_mut(), false) };
}

/// Delivers an entry that came inside a critical section of the layer, at
/// the end of the section (posix_sync::leave), with no call of the kernel.
pub(crate) fn deliver_deferred() {
    // SAFETY: called outside every critical section, on an attached thread.
    unsafe { deliver(core::ptr::null_mut(), false) };
}

unsafe extern "C" fn dispatch(native: *mut upcall::Context) {
    // Inside a critical section of the layer the entry only marks itself
    // deferred; the end of the section delivers it.
    if posix_sync::defer_entry() {
        return;
    }
    // SAFETY: the entry's frame.
    unsafe { deliver(native, true) };
}

/// Whether the next signal `take` would give has a handler with SA_SIGINFO.
fn next_wants_context(block: &Block) -> bool {
    let eligible = block.pending.load(Ordering::SeqCst) & !block.mask.load(Ordering::SeqCst);
    if eligible == 0 {
        return false;
    }
    let signal = eligible.trailing_zeros() as i32 + 1;
    let action = action(signal);
    !ignored(signal, &action) && action.handler != DEFAULT && action.flags & SA_SIGINFO != 0
}

/// Takes the lowest pending signal of `block` that its mask lets through,
/// with its action (SA_RESETHAND applied); ignored ones go.
fn take(block: &Block) -> Option<(i32, SigAction)> {
    loop {
        let pending = block.pending.load(Ordering::SeqCst);
        let eligible = pending & !block.mask.load(Ordering::SeqCst);
        if eligible == 0 {
            return None;
        }
        let bit = eligible.isolate_lowest_one();
        if block
            .pending
            .compare_exchange(pending, pending & !bit, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            continue;
        }
        let signal = bit.trailing_zeros() as i32 + 1;
        // Read without the lock; SA_RESETHAND alone writes, under it.
        let read = action(signal);
        let action = if ignored(signal, &read) {
            None
        } else if read.flags & SA_RESETHAND != 0 && signal != SIGILL && signal != SIGTRAP {
            actions(|table| {
                if table.ignored(signal) {
                    return None;
                }
                let action = table.get(signal).expect("pending signal");
                if action.flags & SA_RESETHAND != 0 {
                    table
                        .replace(signal, posix_signals::INITIAL)
                        .expect("reset action");
                }
                Some(action)
            })
        } else {
            Some(read)
        };
        if let Some(action) = action {
            return Some((signal, action));
        }
    }
}

/// Runs the handlers of the calling thread's deliverable signals. Through
/// the entry (`entered`) the kernel masked further entries: they are let
/// in for the handler and masked again after it; a direct delivery makes
/// no call. `native` is the entry's frame, or null for a direct delivery,
/// which leaves a handler with SA_SIGINFO to the thread's entry.
unsafe fn deliver(native: *mut upcall::Context, entered: bool) {
    let block = own();
    // A wait by address of this thread ends before the first handler, and
    // before the lock of the actions, whose wait uses the same block
    // (posix_sync::abandon); it goes on as woken after the last one.
    let abandoned = block.pending.load(Ordering::SeqCst) & !block.mask.load(Ordering::SeqCst) != 0
        && posix_sync::abandon();
    // SAFETY: the thread has a block (attach).
    let errno = unsafe { ERRNO_LOCATION() };
    let saved_errno = unsafe { *errno };
    loop {
        let old_mask = block.mask.load(Ordering::SeqCst);
        if native.is_null() && next_wants_context(block) {
            // A handler with SA_SIGINFO gets the interrupted context: the
            // thread's own entry (one call) delivers it with its frame.
            let thread = Handle::<rt::handle::Thread>::borrowed(rt::abi::Handle(
                block.thread.load(Ordering::Relaxed),
            ));
            let _ = sys::thread_upcall_request(&thread);
            break;
        }
        let Some((signal, action)) = take(block) else {
            break;
        };
        let handler = action.handler;
        if action.flags & SA_RESTART == 0 {
            block.flags.fetch_or(flag::NO_RESTART, Ordering::SeqCst);
        }
        if handler == DEFAULT {
            // Process wait-status encoding and stop/continue need process routing.
            sys_exit_signal(signal);
        }
        let mut mask = old_mask | action.mask;
        if action.flags & SA_NODEFER == 0 {
            mask |= posix_signals::bit(signal).expect("valid signal");
        }
        block
            .mask
            .store(mask & !posix_signals::UNBLOCKABLE, Ordering::SeqCst);
        let mut restore_mask = old_mask;
        if action.flags & SA_SIGINFO != 0 {
            // SAFETY: the context-aware trampoline owns this unique live frame.
            let frame = unsafe { native.read() };
            let mut context = UserContext {
                uc_link: core::ptr::null_mut(),
                uc_sigmask: old_mask,
                uc_stack: SignalStack {
                    ss_sp: core::ptr::null_mut(),
                    ss_size: 0,
                    ss_flags: SS_DISABLE,
                },
                uc_mcontext: MachineContext {
                    registers: frame.registers,
                    sp: frame.sp,
                    pc: frame.pc,
                    pstate: frame.pstate,
                    vectors: frame.vectors,
                    fpcr: frame.fpcr,
                    fpsr: frame.fpsr,
                },
            };
            let mut info = SigInfo::thread(signal);
            // SAFETY: SA_SIGINFO registers this live three-argument C address.
            let callback: unsafe extern "C" fn(i32, *mut SigInfo, *mut core::ffi::c_void) =
                unsafe { core::mem::transmute(handler as usize) };
            if entered {
                unsafe { upcall::enable() }.expect("nested signal entry");
            }
            unsafe { callback(signal, &raw mut info, (&raw mut context).cast()) };
            if entered {
                upcall::mask().expect("signal handler mask restoration");
            }
            // The callback may edit the return context. Preserve private native
            // metadata and let the kernel validate machine state on return.
            let machine = context.uc_mcontext;
            unsafe {
                native.write(upcall::Context {
                    registers: machine.registers,
                    sp: machine.sp,
                    pc: machine.pc,
                    pstate: machine.pstate,
                    vectors: machine.vectors,
                    fpcr: machine.fpcr,
                    fpsr: machine.fpsr,
                    ..frame
                });
            }
            restore_mask =
                posix_signals::mask(context.uc_sigmask).expect("valid signal return mask");
        } else {
            // SAFETY: signal/sigaction callers supply a live void(int) C address.
            let callback: unsafe extern "C" fn(i32) =
                unsafe { core::mem::transmute(handler as usize) };
            if entered {
                unsafe { upcall::enable() }.expect("nested signal entry");
            }
            unsafe { callback(signal) };
            if entered {
                upcall::mask().expect("signal handler mask restoration");
            }
        }
        block.mask.store(restore_mask, Ordering::SeqCst);
    }
    unsafe { *errno = saved_errno };
    posix_sync::resume_wait(abandoned);
}
fn sys_exit_signal(signal: i32) -> ! {
    rt::sys::process_exit((128 + signal) as u64)
}

/// Runs `run` holding the lock of the actions, which a delivery takes to
/// apply SA_RESETHAND, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_hold_actions(run: impl FnOnce()) {
    let _guard = ACTIONS_LOCK.lock();
    run();
}
/// Whether pthread `thread` waits in sigwait now, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_waiting(thread: u64) -> Result<bool, i32> {
    threads::probe_block(thread)
        .map(|block| block.flags.load(Ordering::SeqCst) & flag::SIGNAL_WAIT != 0)
        .ok_or(ESRCH)
}
