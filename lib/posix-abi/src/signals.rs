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
//!
//! Signals sent to the process (kill) wait on the page of the process's
//! record, where the process service sets their bits and asks for the
//! entry of the router, the main thread (spec 2, 3.3). The thread that
//! takes one is chosen late, when a thread looks at the page (`route`):
//! one in sigwait for that signal, else the first in the table of threads
//! whose mask lets it through; with none the signal stays on the page, and
//! pthread_sigmask that unblocks it, sigsuspend and sigwait look again.
//! The page also says which signals the process ignores and catches and
//! the flags of SIGCHLD (`publish`). Real-time queues, stop/continue,
//! alternate stacks and automatic syscall restart still require
//! implementation.
use crate::{constants::*, threads};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};
pub use posix_signals::{DEFAULT, IGNORE};
use posix_sync::LayerLock;
use posix_thread::{Block, flag};
use posix_types::constants::{SA_NOCLDSTOP, SA_NOCLDWAIT};
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
    publish(table);
    result
}

/// Tells the process service through the record's page which signals the
/// actions of `table` ignore and catch, and SA_NOCLDWAIT, SA_NOCLDSTOP and
/// SIG_IGN of SIGCHLD. The service reads them as hints: it drops a signal
/// the process ignores, keeps no zombie for SA_NOCLDWAIT or SIG_IGN, and
/// refuses the stops nobody handles.
fn publish(table: &posix_signals::Actions) {
    let page = crate::process::page();
    let (mut ignored, mut caught) = (0, 0);
    // SIG_IGN alone: a signal ignored by default stays for sigwait while
    // it is blocked, and the entry drops it otherwise.
    for signal in 1..=31 {
        let action = table.get(signal).expect("a signal of the table");
        let bit = posix_signals::bit(signal).expect("a signal of the table");
        if action.handler == IGNORE {
            ignored |= bit;
        } else if action.handler != DEFAULT {
            caught |= bit;
        }
    }
    let child = table.get(SIGCHLD).expect("SIGCHLD");
    let mut flags = 0;
    if child.flags & SA_NOCLDWAIT != 0 {
        flags |= proto_process::PAGE_NOCLDWAIT;
    }
    if child.flags & SA_NOCLDSTOP != 0 {
        flags |= proto_process::PAGE_NOCLDSTOP;
    }
    if child.handler == IGNORE {
        flags |= proto_process::PAGE_CHLD_IGNORED;
    }
    page.ignored.store(ignored, Ordering::Release);
    page.caught.store(caught, Ordering::Release);
    page.flags.store(flags, Ordering::Release);
}

/// Publishes the initial actions on the page (`publish`), at the start
/// of the process.
pub(crate) fn publish_initial() {
    // The signals the parent ignored stay ignored in a spawned child
    // ([P24-SPAWN]): the service put them on the page.
    let inherited = crate::process::page().ignored.load(Ordering::Acquire);
    actions(|table| {
        for signal in 1..=31 {
            let bit = posix_signals::bit(signal).expect("a signal of the table");
            if inherited & bit != 0 && posix_signals::UNBLOCKABLE & bit == 0 {
                let ignore = SigAction {
                    handler: IGNORE,
                    mask: 0,
                    flags: 0,
                };
                let _ = table.replace(signal, ignore);
            }
        }
    });
}

/// The sender's information of each process signal a thread took from the
/// page and has pending (Block::process): the service keeps one sending of
/// a signal on the page, so one slot a signal serves the process.
struct Taken {
    code: AtomicU64,
    from: AtomicU64,
    status: AtomicU64,
}
static TAKEN: [Taken; 31] = [const {
    Taken {
        code: AtomicU64::new(0),
        from: AtomicU64::new(0),
        status: AtomicU64::new(0),
    }
}; 31];

/// The information of process signal `signal` on the page, read again
/// until the bit stayed while it was read (the service writes it before
/// the bit).
fn page_info(signal: i32) -> Option<SigInfo> {
    let page = crate::process::page();
    let bit = posix_signals::bit(signal).ok()?;
    let slot = &page.info[signal as usize - 1];
    loop {
        let before = page.pending.load(Ordering::Acquire);
        if before & bit == 0 {
            return None;
        }
        let info = SigInfo {
            si_signo: signal,
            si_errno: 0,
            si_code: slot.code.load(Ordering::Acquire),
            si_pid: slot.pid.load(Ordering::Acquire) as i32,
            si_uid: slot.uid.load(Ordering::Acquire),
            si_status: slot.status.load(Ordering::Acquire),
            si_addr: 0,
            si_value: 0,
        };
        if page.pending.load(Ordering::Acquire) == before {
            return Some(info);
        }
    }
}

/// Keeps `info` of a process signal a thread took (`TAKEN`).
fn keep_taken(signal: i32, info: &SigInfo) {
    let slot = &TAKEN[signal as usize - 1];
    slot.code
        .store(info.si_code as u32 as u64, Ordering::Relaxed);
    slot.from.store(
        u64::from(info.si_pid as u32) | u64::from(info.si_uid) << 32,
        Ordering::Relaxed,
    );
    slot.status
        .store(info.si_status as u32 as u64, Ordering::Release);
}

/// The information `keep_taken` kept for `signal`.
fn taken(signal: i32) -> SigInfo {
    let slot = &TAKEN[signal as usize - 1];
    let from = slot.from.load(Ordering::Acquire);
    SigInfo {
        si_signo: signal,
        si_errno: 0,
        si_code: slot.code.load(Ordering::Acquire) as u32 as i32,
        si_pid: from as u32 as i32,
        si_uid: (from >> 32) as u32,
        si_status: slot.status.load(Ordering::Acquire) as u32 as i32,
        si_addr: 0,
        si_value: 0,
    }
}

/// Puts the process signals of `bits` that `block` holds back on the page
/// with their information, and routes them anew: the thread blocked them
/// or leaves.
fn give_back(block: &Block, bits: u64) {
    let page = crate::process::page();
    let back = block.process.fetch_and(!bits, Ordering::SeqCst) & bits;
    let back = block.pending.fetch_and(!back, Ordering::SeqCst) & back;
    if back == 0 {
        return;
    }
    let mut rest = back;
    while rest != 0 {
        let bit = rest.isolate_lowest_one();
        rest &= !bit;
        let signal = bit.trailing_zeros() as i32 + 1;
        let info = taken(signal);
        let slot = &page.info[signal as usize - 1];
        if page.pending.load(Ordering::Acquire) & bit == 0 {
            slot.code.store(info.si_code, Ordering::Relaxed);
            slot.pid.store(info.si_pid as u32, Ordering::Relaxed);
            slot.uid.store(info.si_uid, Ordering::Relaxed);
            slot.status.store(info.si_status, Ordering::Relaxed);
        }
        page.pending.fetch_or(bit, Ordering::Release);
    }
    route();
}

/// Takes the signals that wait on the process's page to threads (spec 2,
/// 3.3), lowest first: a thread in sigwait for one is woken and takes it
/// from the page itself, with its information; else the first live thread
/// in the table whose mask lets it through gets it as its own pending
/// signal with its information (`TAKEN`), under the lock of the table, so
/// that the thread neither blocks it nor leaves meanwhile (each gives it
/// back then, `give_back`); its entry is asked for unless it is the
/// caller, which delivers after. A signal no thread takes stays on the
/// page.
pub(crate) fn route() {
    // While an exec stops the process, the signals of the process wait on
    // the page for the new image's router (spec 2, 3.2 step 1).
    if STOPPING.load(Ordering::Acquire) != 0 {
        return;
    }
    let page = crate::process::page();
    let mut pending = page.pending.load(Ordering::Acquire);
    let own = own() as *const Block;
    while pending != 0 {
        let bit = pending.isolate_lowest_one();
        pending &= !bit;
        let signal = bit.trailing_zeros() as i32 + 1;
        let mut waiter = None;
        threads::each_block(|block| {
            if waiter.is_none()
                && block.end.load(Ordering::SeqCst) == 0
                && block.flags.load(Ordering::SeqCst) & flag::SIGNAL_WAIT != 0
                && block.wait_set.load(Ordering::SeqCst) & bit != 0
            {
                waiter = Some(block.channel.load(Ordering::Relaxed));
            }
        });
        if let Some(channel) = waiter {
            let channel = Handle::<Channel>::borrowed(rt::abi::Handle(channel));
            let _ = sys::notify(&channel, posix_sync::bit::WAKE);
            continue;
        }
        let mut entry = None;
        threads::each_block(|block| {
            if entry.is_some()
                || block.end.load(Ordering::SeqCst) != 0
                || block.flags.load(Ordering::SeqCst) & flag::EXITING != 0
                || block.mask.load(Ordering::SeqCst) & bit != 0
            {
                return;
            }
            let Some(info) = page_info(signal) else {
                entry = Some(None);
                return;
            };
            if page.pending.fetch_and(!bit, Ordering::AcqRel) & bit == 0 {
                // Another thread took it meanwhile.
                entry = Some(None);
                return;
            }
            keep_taken(signal, &info);
            block.process.fetch_or(bit, Ordering::SeqCst);
            block.pending.fetch_or(bit, Ordering::SeqCst);
            entry =
                Some((!core::ptr::eq(block, own)).then(|| block.thread.load(Ordering::Relaxed)));
        });
        if let Some(Some(thread)) = entry {
            let native = Handle::<rt::handle::Thread>::borrowed(rt::abi::Handle(thread));
            let _ = sys::thread_upcall_request(&native);
        }
    }
}

/// Takes `signal` from the process's page for a thread in sigwait: its
/// information, or None when it no longer waits there.
fn take_from_page(signal: i32) -> Option<SigInfo> {
    let page = crate::process::page();
    let bit = posix_signals::bit(signal).ok()?;
    let info = page_info(signal)?;
    (page.pending.fetch_and(!bit, Ordering::AcqRel) & bit != 0).then_some(info)
}

/// The process signals that wait on the page come to the threads that let
/// them through, the caller first: once the main thread is attached, for
/// a signal that came before (its router's entry was not bound yet).
pub fn take_waiting() {
    // The main thread starts with the mask of the thread whose posix_spawn
    // made the process ([P24-SPAWN]).
    let mask = crate::process::page().start_mask.load(Ordering::Acquire);
    own().mask.store(
        mask & posix_signals::VALID & !posix_signals::UNBLOCKABLE,
        Ordering::SeqCst,
    );
    // The calling thread's pending signals an exec carried, under that
    // mask ([P24-EXEC]).
    own()
        .pending
        .fetch_or(CARRIED.swap(0, Ordering::AcqRel), Ordering::SeqCst);
    route();
    deliver_now();
}

/// The calling thread leaves: the process signals it holds go back to the
/// page for the other threads.
pub fn leaving() {
    give_back(own(), u64::MAX);
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
        // A process signal this thread holds and blocks now goes back to
        // the page for a thread that lets it through.
        if block.process.load(Ordering::SeqCst) & mask != 0 {
            give_back(block, mask);
        }
        // A process signal this thread lets through now comes to it.
        if crate::process::page().pending.load(Ordering::Acquire) & !mask != 0 {
            route();
        }
        if block.pending.load(Ordering::SeqCst) & !mask != 0 {
            deliver_now();
        }
    }
    Ok(before)
}
/// The calling thread's pending signals that its mask holds back, and the
/// process's.
pub fn sigpending() -> SigSet {
    let block = own();
    let pending = block.pending.load(Ordering::SeqCst)
        | crate::process::page().pending.load(Ordering::Acquire);
    pending & block.mask.load(Ordering::SeqCst)
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
        route();
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
fn wait(
    set: SigSet,
    timeout: Option<posix_types::Timespec>,
    start: u64,
) -> Result<(i32, SigInfo), i32> {
    let block = own();
    let set = posix_signals::mask(set).map_err(|_| EINVAL)?;
    if set & !block.mask.load(Ordering::SeqCst) != 0 {
        return Err(EINVAL);
    }
    // The thread's own signals first, then the process's on the page, with
    // their information.
    let take = || loop {
        let pending = block.pending.load(Ordering::SeqCst);
        let eligible = pending & set;
        if eligible == 0 {
            let process = crate::process::page().pending.load(Ordering::Acquire) & set;
            if process == 0 {
                return None;
            }
            let signal = process.trailing_zeros() as i32 + 1;
            match take_from_page(signal) {
                Some(info) => return Some((signal, info)),
                None => continue,
            }
        }
        let bit = eligible.isolate_lowest_one();
        if block
            .pending
            .compare_exchange(pending, pending & !bit, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let signal = bit.trailing_zeros() as i32 + 1;
            let from_process = block.process.fetch_and(!bit, Ordering::SeqCst) & bit != 0;
            let info = if from_process {
                taken(signal)
            } else {
                SigInfo::thread(signal)
            };
            return Some((signal, info));
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
    let result = wait(set, timeout, start).map(|(signal, taken)| {
        if let Some(info) = info {
            *info = taken;
        }
        signal
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

/// The calling thread's own signals an exec carried to this image
/// (proto_loader::Carried), which the main thread takes as pending once
/// its mask is set (`take_waiting`).
static CARRIED: AtomicU64 = AtomicU64::new(0);

/// Keeps the pending signals an exec carried for the main thread.
pub fn carry_pending(bits: u64) {
    CARRIED.store(bits, Ordering::Release);
}

/// The thread that stops the others for an exec or a fork (its block's
/// address), 0 for none; how many parked; the channel the stopper waits
/// on; and, by place of the table of threads, the channel each parked
/// thread waits on until it goes on (0 for a thread that is not parked).
static STOPPING: AtomicUsize = AtomicUsize::new(0);
static PARKED: AtomicUsize = AtomicUsize::new(0);
static STOPPER: AtomicU64 = AtomicU64::new(0);
static PARKING: [AtomicU64; crate::relibc::PLACES] =
    [const { AtomicU64::new(0) }; crate::relibc::PLACES];

/// How often the stopper looks at the table again while a thread it waits
/// for neither parked nor said so: a thread that ends, or one in a wait of
/// the kernel, tells it nothing.
const LOOK_AGAIN_NS: u64 = 1_000_000;

/// Stops every other thread of the process for an exec or a fork (spec 2,
/// 3.2 step 1, mya2.V6). A thread with its entry of signals is asked for
/// it and parks there, outside every critical section of the layer, so it
/// holds no lock of the layer; one that waits in the kernel outside a
/// critical section counts as stopped, since its entry, asked for, comes
/// before any code of its own runs again. A thread that has no entry yet
/// (made, its start not done) parks in `attach` once it has one; one made
/// and not started, and one that ended, count as stopped. The stopper
/// looks at the table under its lock, again whenever a thread parks and
/// every LOOK_AGAIN_NS, until all others are stopped. A thread that finds
/// another stopper at work parks first. The process's signals wait on its
/// page meanwhile. The caller has every signal blocked.
pub(crate) fn stop_others() -> Result<(), i32> {
    use rt::abi::ThreadState;
    let level = own().base_level.load(Ordering::Relaxed) as u8;
    let me = own() as *const Block as usize;
    let channel = sys::channel_create(level.max(1)).map_err(|_| EAGAIN)?;
    let timer = sys::timer_create(&channel, level.max(1)).map_err(|_| EAGAIN)?;
    while STOPPING
        .compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        park();
    }
    PARKED.store(0, Ordering::Release);
    STOPPER.store(channel.raw().0, Ordering::Release);
    let mut asked = 0u64;
    loop {
        let mut waiting = false;
        crate::relibc::each_live(|index, native, block| {
            if core::ptr::from_ref(block) as usize == me
                || PARKING[index].load(Ordering::Acquire) != 0
            {
                return;
            }
            let thread = Handle::<rt::handle::Thread>::borrowed(rt::abi::Handle(native));
            let state = sys::thread_info(&thread).map_or(ThreadState::Ended, |i| i.state);
            if matches!(state, ThreadState::Ended | ThreadState::Stopped) {
                return;
            }
            let flags = block.flags.load(Ordering::SeqCst);
            if flags & flag::SIGNALS_READY == 0 {
                waiting = true;
                return;
            }
            if asked & 1 << index == 0 {
                asked |= 1 << index;
                let _ = sys::thread_upcall_request(&thread);
            }
            let in_kernel = matches!(
                state,
                ThreadState::Receiving | ThreadState::Sending | ThreadState::AwaitingReply
            );
            if !(in_kernel && flags >> flag::DEPTH_SHIFT == 0) {
                waiting = true;
            }
        });
        if !waiting {
            break;
        }
        let deadline = rt::time::ticks_to_ns(rt::time::now()) + LOOK_AGAIN_NS;
        let _ = sys::timer_set(&timer, deadline);
        if sys::receive(&channel).is_err() {
            break;
        }
    }
    // The stopper's channel lives as long as the stop.
    core::mem::forget(channel);
    Ok(())
}

/// The signals of a forked child (spec 2, 3.2): no stop is on, no pending
/// signal an exec carried, and the child's only thread gets its entry of
/// signals (`attach`); the actions are the copy of the parent's, and the
/// classes on the page the service's from ForkStart. The parent's channels
/// of the stop in the copy go without a close.
///
/// # Safety
/// The child's only thread, once its block has its handles
/// (crate::threads::after_fork).
pub(crate) unsafe fn after_fork() -> Result<(), i32> {
    STOPPING.store(0, Ordering::Release);
    PARKED.store(0, Ordering::Release);
    STOPPER.store(0, Ordering::Release);
    for place in &PARKING {
        place.store(0, Ordering::Relaxed);
    }
    CARRIED.store(0, Ordering::Release);
    attach()
}

/// The other threads go on: the exec failed before its commit, or the
/// fork's copy is made.
pub(crate) fn resume_others() {
    // Only the stopper ends its stop: a caller whose stop never began
    // leaves another's as it is.
    let me = own() as *const Block as usize;
    if STOPPING
        .compare_exchange(me, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    for place in &PARKING {
        let raw = place.swap(0, Ordering::AcqRel);
        if raw != 0 {
            let _ = sys::notify(&Handle::<Channel>::borrowed(rt::abi::Handle(raw)), 1);
        }
    }
    let stopper = STOPPER.swap(0, Ordering::AcqRel);
    if stopper != 0 {
        drop(Handle::<Channel>::from_raw(rt::abi::Handle(stopper)));
    }
}

/// Parks the calling thread while another thread stops the process for
/// an exec or a fork: its process signals go back to the page, it puts a
/// channel of its own in its place of PARKING, says so to the stopper and
/// waits there until the stop ends; a successful exec ends the process
/// meanwhile.
fn park() {
    let block = own();
    give_back(block, block.process.load(Ordering::SeqCst));
    let level = block.base_level.load(Ordering::Relaxed) as u8;
    let Some(place) = (block.thread_id as usize)
        .checked_sub(1)
        .and_then(|i| PARKING.get(i))
    else {
        return;
    };
    let Ok(channel) = sys::channel_create(level.max(1)) else {
        return;
    };
    let raw = channel.raw().0;
    place.store(raw, Ordering::Release);
    PARKED.fetch_add(1, Ordering::AcqRel);
    let stopper = STOPPER.load(Ordering::Acquire);
    if stopper != 0 {
        let _ = sys::notify(&Handle::<Channel>::borrowed(rt::abi::Handle(stopper)), 1);
    }
    while STOPPING.load(Ordering::Acquire) != 0 {
        if sys::receive(&channel).is_err() {
            break;
        }
    }
    let _ = place.compare_exchange(raw, 0, Ordering::AcqRel, Ordering::Acquire);
}

/// Whether the calling thread is to park: another thread stops the
/// process for an exec.
fn stopped_by_other() -> bool {
    let stopping = STOPPING.load(Ordering::Acquire);
    stopping != 0 && stopping != own() as *const Block as usize
}

/// Binds and enables the calling thread's entry, then delivers what came
/// before it.
pub(crate) fn attach() -> Result<(), i32> {
    // SAFETY: the dispatcher holds no interrupted Rust references or locks
    // and enters only caller-supplied C code.
    unsafe { upcall::bind(entry) }.map_err(|_| EIO)?;
    own().flags.fetch_or(flag::SIGNALS_READY, Ordering::SeqCst);
    unsafe { upcall::enable() }.map_err(|_| EIO)?;
    // A thread whose start ends while another stops the process parks
    // now: the stopper waits for it (`stop_others`).
    if stopped_by_other() {
        park();
    }
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
fn take(block: &Block) -> Option<(i32, SigAction, Option<SigInfo>)> {
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
        let from_process =
            (block.process.fetch_and(!bit, Ordering::SeqCst) & bit != 0).then(|| taken(signal));
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
            return Some((signal, action, from_process));
        }
    }
}

/// Runs the handlers of the calling thread's deliverable signals. Through
/// the entry (`entered`) the kernel masked further entries: they are let
/// in for the handler and masked again after it; a direct delivery makes
/// no call. `native` is the entry's frame, or null for a direct delivery,
/// which leaves a handler with SA_SIGINFO to the thread's entry.
unsafe fn deliver(native: *mut upcall::Context, entered: bool) {
    if stopped_by_other() {
        park();
    }
    // The process's signals first: one of them may be this thread's.
    route();
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
        let Some((signal, action, from_process)) = take(block) else {
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
            // A signal of the process carries its sender's information
            // (XSH 2.4.3): SI_USER with the PID and UID, or SIGCHLD's code
            // and status.
            let mut info = match from_process {
                Some(taken) => LinuxSigInfo::process(&taken),
                None => LinuxSigInfo::thread(signal),
            };
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
    /// The information of a signal of the process (kill, SIGCHLD): the
    /// code, the sender's PID and UID, and the status after them, where
    /// Linux keeps SIGCHLD's.
    pub const fn process(info: &SigInfo) -> Self {
        Self {
            signo: info.si_signo,
            errno: 0,
            code: info.si_code,
            pad: 0,
            pid: info.si_pid,
            uid: info.si_uid,
            value: info.si_status as u32 as u64,
            rest: [0; 96],
        }
    }

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
