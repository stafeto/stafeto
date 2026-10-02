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
pub use posix_types::{SigAction, SigInfo, SigSet};
use rt::abi::{Error, Source};
use rt::handle::{Channel, Handle, Timer};
use rt::{sys, upcall};

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

/// Sets the action of `signal` to `act` when given; the action before.
/// A catching handler uses the one-argument or SA_SIGINFO signature,
/// remains live, and obeys async-signal safety.
pub fn sigaction(signal: i32, act: Option<SigAction>) -> Result<SigAction, i32> {
    actions(|table| {
        let Some(act) = act else {
            return table.get(signal).map_err(|_| EINVAL);
        };
        let old = table.replace(signal, act).map_err(|_| EINVAL)?;
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
    })
}
/// The calling thread's block.
fn own() -> &'static Block {
    threads::own_block()
}
/// Changes the calling thread's mask by `how` with `set` when given; the
/// mask before. No call of the kernel: the mask is a word of the thread's
/// block.
pub fn pthread_sigmask(how: i32, set: Option<SigSet>) -> Result<SigSet, i32> {
    let block = own();
    let before = block.mask.load(Ordering::SeqCst);
    if let Some(set) = set {
        let set = posix_signals::mask(set).map_err(|_| EINVAL)?;
        let mask = match how {
            SIG_BLOCK => before | set,
            SIG_UNBLOCK => before & !set,
            SIG_SETMASK => set,
            _ => return Err(EINVAL),
        };
        block.mask.store(mask, Ordering::SeqCst);
        if block.pending.load(Ordering::SeqCst) & !mask != 0 {
            deliver_now();
        }
    }
    Ok(before)
}
/// The calling thread's pending signals that its mask holds back.
pub fn sigpending() -> SigSet {
    let block = own();
    block.pending.load(Ordering::SeqCst) & block.mask.load(Ordering::SeqCst)
}
/// Sends `bit` with its `action` (none for signal 0) to the thread of
/// `block` and `native`: the bit in its block, then a wake of its sigwait
/// through its channel or a request of its entry.
fn send(
    block: &Block,
    native: &Handle<rt::handle::Thread>,
    bit: u64,
    action: Option<(SigAction, bool)>,
) {
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
    } else if flags & flag::SIGNALS_READY != 0 && bit & !block.mask.load(Ordering::SeqCst) != 0 {
        let _ = sys::thread_upcall_request(native);
    }
}

/// Sends `signal` to the thread number `id` (relibc's OsTid): the bit in
/// its block, then a wake of its sigwait through its channel or a request
/// of its entry; to the calling thread itself, delivery before the
/// return. Stop and continue are ENOSYS until the process service routes
/// them. 0 or an error number.
pub fn kill_relibc_thread(id: u64, signal: i32) -> i32 {
    let bit = if signal == 0 {
        0
    } else {
        match posix_signals::bit(signal) {
            Ok(bit) => bit,
            Err(_) => return EINVAL,
        }
    };
    let action = (signal != 0).then(|| {
        let action = action(signal);
        (action, ignored(signal, &action))
    });
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
    let (block, native) = match crate::relibc::target(id) {
        Ok(target) => target,
        Err(code) => return code,
    };
    if core::ptr::eq(block, own()) {
        if let Some((_, false)) = action {
            own().pending.fetch_or(bit, Ordering::SeqCst);
            deliver_now();
        }
        return 0;
    }
    send(block, &native, bit, action);
    0
}

/// sigsuspend: the calling thread's mask becomes `mask` until a handler
/// ran, then the old one comes back. Always an error: EINTR after a
/// handler; a cancellation point.
pub fn suspend(mask: SigSet) -> i32 {
    let point = threads::cancel::Point::begin();
    let block = own();
    let Ok(mask) = posix_signals::mask(mask) else {
        point.end();
        return EINVAL;
    };
    let old = block.mask.swap(mask, Ordering::SeqCst);
    let channel =
        Handle::<Channel>::borrowed(rt::abi::Handle(block.channel.load(Ordering::Relaxed)));
    loop {
        if block.pending.load(Ordering::SeqCst) & !mask != 0 {
            deliver_now();
            break;
        }
        // An entry between the check and `receive` stays pending and makes
        // `receive` return at once; it runs when the guard goes.
        let guard = rt::upcall::defer_entries().expect("sigsuspend entry deferral");
        let got = sys::receive(&channel);
        drop(guard);
        match got {
            Err(Error::Interrupted) => break,
            Ok(sys::Received::Notification {
                source: Source::Unlabeled,
                bits,
                ..
            }) if bits & posix_sync::bit::CANCEL != 0 && threads::cancel::requested() => break,
            Ok(_) => {}
            Err(error) => panic!("sigsuspend receive: {error:?}"),
        }
    }
    block.mask.store(old, Ordering::SeqCst);
    if block.pending.load(Ordering::SeqCst) & !old != 0 {
        deliver_now();
    }
    point.finish();
    EINTR
}
/// Sends `signal` to the calling thread.
pub fn raise(signal: i32) -> Result<(), i32> {
    match kill_relibc_thread(threads::thread_number(), signal) {
        0 => Ok(()),
        status => Err(status),
    }
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

/// Waits for a signal of `set`, which the caller blocked, at most
/// `timeout` (none: no end): the signal, with its information in `info`;
/// EAGAIN when the time ran out. Caught signals resume the wait over the
/// original interval. A point of cancellation.
pub fn sigtimedwait(
    set: SigSet,
    info: Option<&mut SigInfo>,
    timeout: Option<posix_types::Timespec>,
) -> Result<i32, i32> {
    let point = threads::cancel::Point::begin();
    let start = rt::time::ticks_to_ns(rt::time::now());
    let result = wait(set, timeout, start).inspect(|&signal| {
        if let Some(info) = info {
            *info = SigInfo::thread(signal);
        }
    });
    point.finish();
    result
}

rt::upcall_entry!(entry, dispatch, context);

/// Where the calling thread's C errno lives: relibc's `__errno_location`. The entry saves and gives back
/// the value there; it never moves the thread pointer (spec 2, 3.5).
static ERRNO_LOCATION: unsafe extern "C" fn() -> *mut core::ffi::c_int = relibc_errno_location;
unsafe extern "C" {
    /// relibc's errno in its static TLS.
    #[link_name = "__errno_location"]
    fn relibc_errno_location() -> *mut core::ffi::c_int;
}

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
    // The handlers run outside the interrupted cancellation point and
    // sigwait: a request of cancellation that comes meanwhile waits for the
    // return to the point (POSIX), and a signal sent meanwhile enters as a
    // signal. A handler that leaves by siglongjmp leaves neither the window
    // nor SIGNAL_WAIT behind; one that returns gets both back.
    let window = block.cancel_point.swap(0, Ordering::SeqCst);
    let signal_wait =
        block.flags.fetch_and(!flag::SIGNAL_WAIT, Ordering::SeqCst) & flag::SIGNAL_WAIT;
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
            // Stop and continue need process routing (5e).
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
            let mut context = LinuxContext::new(&frame, old_mask);
            let mut info = LinuxSigInfo::thread(signal);
            // SAFETY: SA_SIGINFO registers this live three-argument C address.
            let callback: unsafe extern "C" fn(i32, *mut LinuxSigInfo, *mut core::ffi::c_void) =
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
            // SAFETY: the frame is the entry's.
            unsafe { native.write(context.frame(frame)) };
            restore_mask = posix_signals::mask(context.mask & posix_signals::VALID)
                .expect("valid signal return mask");
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
    block.flags.fetch_or(signal_wait, Ordering::SeqCst);
    block.cancel_point.store(window, Ordering::SeqCst);
    unsafe { *errno = saved_errno };
    posix_sync::resume_wait(abandoned);
}
/// The siginfo_t of relibc's headers (Linux AArch64): 128 bytes, the
/// signal, errno and code, then the sender's pid and uid and the value.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LinuxSigInfo {
    pub signo: i32,
    pub errno: i32,
    pub code: i32,
    pad: i32,
    pub pid: i32,
    pub uid: u32,
    pub value: u64,
    rest: [u8; 96],
}
const _: () = assert!(core::mem::size_of::<LinuxSigInfo>() == 128);

/// si_code of a signal sent by pthread_kill or raise (Linux SI_TKILL).
pub const SI_TKILL: i32 = -6;

impl LinuxSigInfo {
    /// The information of `signal` sent by pthread_kill or raise.
    pub const fn thread(signal: i32) -> Self {
        Self {
            signo: signal,
            errno: 0,
            code: SI_TKILL,
            pad: 0,
            pid: 0,
            uid: 0,
            value: 0,
            rest: [0; 96],
        }
    }
}

/// The ucontext_t of relibc's headers (Linux AArch64, asm/ucontext.h) with
/// its mcontext_t (struct sigcontext): x0 to x30, sp, pc, pstate, then
/// the record of the FP and SIMD registers (fpsimd_context) and an empty
/// record that ends the list.
#[repr(C, align(16))]
pub struct LinuxContext {
    flags: u64,
    pub link: *mut core::ffi::c_void,
    pub stack_pointer: *mut core::ffi::c_void,
    pub stack_flags: i32,
    pub stack_size: usize,
    pub mask: u64,
    unused: [u8; 120],
    /// uc_mcontext is 16-byte aligned.
    pad0: u64,
    fault_address: u64,
    pub registers: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    /// The records start 16-byte aligned.
    pad: u64,
    /// fpsimd_context: magic, size, fpsr, fpcr, the 32 vector registers.
    fp_magic: u32,
    fp_size: u32,
    pub fpsr: u32,
    pub fpcr: u32,
    pub vectors: [u128; 32],
    /// The empty record after it, then the rest of the 4096 bytes.
    reserved: [u8; 4096 - 528],
}
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<LinuxContext>() == 4560);
    assert!(offset_of!(LinuxContext, mask) == 40);
    assert!(offset_of!(LinuxContext, fault_address) == 176);
    assert!(offset_of!(LinuxContext, sp) == 432);
    assert!(offset_of!(LinuxContext, pc) == 440);
    assert!(offset_of!(LinuxContext, fp_magic) == 464);
    assert!(offset_of!(LinuxContext, vectors) == 480);
};
const FPSIMD_MAGIC: u32 = 0x4650_8001;

impl LinuxContext {
    fn new(frame: &upcall::Context, mask: u64) -> Self {
        Self {
            flags: 0,
            link: core::ptr::null_mut(),
            stack_pointer: core::ptr::null_mut(),
            stack_flags: SS_DISABLE,
            stack_size: 0,
            mask,
            unused: [0; 120],
            pad0: 0,
            fault_address: 0,
            registers: frame.registers,
            sp: frame.sp,
            pc: frame.pc,
            pstate: frame.pstate,
            pad: 0,
            fp_magic: FPSIMD_MAGIC,
            fp_size: 528,
            fpsr: frame.fpsr as u32,
            fpcr: frame.fpcr as u32,
            vectors: frame.vectors,
            reserved: [0; 4096 - 528],
        }
    }

    /// The entry's frame with the registers the handler left here.
    fn frame(&self, frame: upcall::Context) -> upcall::Context {
        upcall::Context {
            registers: self.registers,
            sp: self.sp,
            pc: self.pc,
            pstate: self.pstate,
            vectors: self.vectors,
            fpcr: u64::from(self.fpcr),
            fpsr: u64::from(self.fpsr),
            ..frame
        }
    }
}

/// The death of the process by `signal`: the code `0x100 | signal`, which
/// `_exit` never gives (it keeps 8 bits), so that the process service reads
/// WIFSIGNALED from the kernel's reason (proto_process::End).
fn sys_exit_signal(signal: i32) -> ! {
    rt::sys::process_exit(0x100 | signal as u64)
}

/// Runs `run` holding the lock of the actions, which a delivery takes to
/// apply SA_RESETHAND, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_hold_actions(run: impl FnOnce()) {
    let _guard = ACTIONS_LOCK.lock();
    run();
}
/// Whether thread `thread` (its relibc `pthread_t`) waits in sigwait now,
/// for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_waiting(thread: u64) -> Result<bool, i32> {
    threads::probe_block(thread)
        .map(|block| block.flags.load(Ordering::SeqCst) & flag::SIGNAL_WAIT != 0)
        .ok_or(ESRCH)
}
