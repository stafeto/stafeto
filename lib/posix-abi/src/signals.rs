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
//! the flags of SIGCHLD (`publish`). Real-time queues and
//! alternate stacks still require
//! implementation.
use crate::{constants::*, threads};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering, fence};
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

/// Sender information belongs to one assignment in one thread place.
/// The short lock orders table -> INFO; INFO is released before actions,
/// routing, entry requests and RPC, so no opposite nesting is possible.
static INFO_LOCK: LayerLock = LayerLock::raising();
struct Taken {
    code_status: AtomicU64,
    from: AtomicU64,
}
static TAKEN: [[Taken; 31]; crate::relibc::PLACES + 1] = [const {
    [const {
        Taken {
            code_status: AtomicU64::new(0),
            from: AtomicU64::new(0),
        }
    }; 31]
}; crate::relibc::PLACES + 1];
const _: () = assert!(core::mem::size_of_val(&TAKEN) == 32_240);
// A local claim keeps routing away from this number until its origin snapshot
// and removal are complete. Router acquisition is a try-lock under TABLE.
static CLAIMING: [AtomicU32; crate::relibc::PLACES + 1] =
    [const { AtomicU32::new(0) }; crate::relibc::PLACES + 1];
const CLAIM_WAITING: u32 = 1 << 31;

struct AssignmentClaim {
    row: usize,
    bit: u32,
}
impl AssignmentClaim {
    fn try_new(block: &Block, bit: u64) -> Option<Self> {
        let row = block.thread_id as usize;
        let bit = bit as u32;
        let word = &CLAIMING[row];
        let mut before = word.load(Ordering::Acquire);
        loop {
            if before & bit != 0 {
                return None;
            }
            match word.compare_exchange_weak(
                before,
                before | bit,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self { row, bit }),
                Err(now) => before = now,
            }
        }
    }
}
impl Drop for AssignmentClaim {
    fn drop(&mut self) {
        let word = &CLAIMING[self.row];
        if word.fetch_and(!(self.bit | CLAIM_WAITING), Ordering::SeqCst) & CLAIM_WAITING != 0 {
            posix_sync::futex_wake(core::ptr::from_ref(word), u32::MAX);
        }
    }
}

fn taken_row(block: &Block) -> &[Taken; 31] {
    &TAKEN[usize::try_from(block.thread_id).expect("a bounded thread place")]
}
/// Clear a reused place while it is still MAKING, before route can see it.
pub(crate) fn reset_taken_before_live(id: u64) {
    let _guard = INFO_LOCK.lock();
    clear_taken(&TAKEN[id as usize]);
    CLAIMING[id as usize].store(0, Ordering::Relaxed);
}

fn clear_taken(row: &[Taken; 31]) {
    for slot in row {
        slot.code_status.store(0, Ordering::Relaxed);
        slot.from.store(0, Ordering::Relaxed);
    }
}

/// Process signals that still belong to the currently published epochs.
pub(crate) fn process_pending() -> u64 {
    let p = crate::process::page();
    (p.pending.load(Ordering::Acquire) & !proto_process::job::MASK)
        | proto_process::job::bits(
            p.stop_word.load(Ordering::Acquire),
            p.cont_word.load(Ordering::Acquire),
        )
}

/// Thread signals, with cancelled job assignments filtered out.
pub(crate) fn thread_pending(block: &Block) -> u64 {
    use proto_process::job::{bits, class, live};
    let p = crate::process::page();
    (block.pending.load(Ordering::SeqCst) & !proto_process::job::MASK)
        | bits(
            live(
                &block.stop_word,
                &p.stop_word,
                class(proto_process::SIGTSTP).unwrap(),
            ),
            live(
                &block.cont_word,
                &p.cont_word,
                class(proto_process::SIGCONT).unwrap(),
            ),
        )
}

pub fn pending_unblocked() -> bool {
    let mask = own().mask.load(Ordering::SeqCst);
    (thread_pending(own()) | process_pending()) & !mask != 0
}

fn job_word(block: &Block, signal: i32) -> &AtomicU64 {
    if signal == SIGCONT {
        &block.cont_word
    } else {
        &block.stop_word
    }
}
fn origin_word(block: &Block, signal: i32) -> &AtomicU64 {
    if signal == SIGCONT {
        &block.cont_origin
    } else {
        &block.stop_origin
    }
}
fn page_word(signal: i32) -> &'static AtomicU64 {
    let p = crate::process::page();
    if signal == SIGCONT {
        &p.cont_word
    } else if proto_process::job::class(signal as u8).is_some() {
        &p.stop_word
    } else {
        &p.pending
    }
}
fn claim_page(signal: i32, ticket: u64) -> Option<u64> {
    if proto_process::job::class(signal as u8).is_some() {
        proto_process::job::take_ticket(page_word(signal), page_word(signal), signal as u8, ticket)
    } else {
        let bit = posix_signals::bit(signal).ok()?;
        (page_word(signal).fetch_and(!bit, Ordering::AcqRel) & bit != 0).then_some(0)
    }
}
fn claim_thread(block: &Block, signal: i32) -> Option<u64> {
    if proto_process::job::class(signal as u8).is_some() {
        proto_process::job::take(job_word(block, signal), page_word(signal), signal as u8)
    } else {
        let bit = posix_signals::bit(signal).ok()?;
        (block.pending.fetch_and(!bit, Ordering::SeqCst) & bit != 0).then_some(0)
    }
}
fn assign(block: &Block, signal: i32, ticket: u64, process: bool) -> bool {
    let bit = posix_signals::bit(signal).expect("a valid signal");
    if proto_process::job::class(signal as u8).is_some() {
        if process {
            proto_process::job::insert(
                origin_word(block, signal),
                page_word(signal),
                signal as u8,
                ticket,
            );
        }
        proto_process::job::insert(
            job_word(block, signal),
            page_word(signal),
            signal as u8,
            ticket,
        )
    } else {
        if process {
            block.process.fetch_or(bit, Ordering::SeqCst);
        }
        block.pending.fetch_or(bit, Ordering::SeqCst);
        true
    }
}
fn process_origin(block: &Block, signal: i32, ticket: u64) -> bool {
    if proto_process::job::class(signal as u8).is_some() {
        proto_process::job::take(origin_word(block, signal), page_word(signal), signal as u8)
            == Some(ticket)
    } else {
        block.process.fetch_and(
            !posix_signals::bit(signal).expect("a signal"),
            Ordering::SeqCst,
        ) & posix_signals::bit(signal).expect("a signal")
            != 0
    }
}

/// The information of process signal `signal` on the page, read again
/// until the bit stayed while it was read (the service writes it before
/// the bit).
fn page_info(signal: i32) -> Option<(u64, SigInfo)> {
    let page = crate::process::page();
    let bit = posix_signals::bit(signal).ok()?;
    let slot = &page.info[signal as usize - 1];
    loop {
        let before = page_word(signal).load(Ordering::Acquire);
        if process_pending() & bit == 0 {
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
        if page_word(signal).load(Ordering::Acquire) == before {
            let ticket = proto_process::job::class(signal as u8).map_or(0, |c| before & !c.low);
            return Some((ticket, info));
        }
    }
}

/// Keep the claimed sender before publishing its thread bit, under INFO_LOCK.
fn keep_taken(block: &Block, signal: i32, info: &SigInfo) {
    let slot = &taken_row(block)[signal as usize - 1];
    slot.code_status.store(
        u64::from(info.si_code as u32) | u64::from(info.si_status as u32) << 32,
        Ordering::Relaxed,
    );
    slot.from.store(
        u64::from(info.si_pid as u32) | u64::from(info.si_uid) << 32,
        Ordering::Release,
    );
}

/// Copy one owned sender under INFO_LOCK before a new assignment can replace it.
fn taken(block: &Block, signal: i32) -> SigInfo {
    let slot = &taken_row(block)[signal as usize - 1];
    let from = slot.from.load(Ordering::Acquire);
    let code_status = slot.code_status.load(Ordering::Relaxed);
    SigInfo {
        si_signo: signal,
        si_errno: 0,
        si_code: code_status as u32 as i32,
        si_pid: from as u32 as i32,
        si_uid: (from >> 32) as u32,
        si_status: (code_status >> 32) as u32 as i32,
        si_addr: 0,
        si_value: 0,
    }
}

struct ClaimCritical;
impl Drop for ClaimCritical {
    fn drop(&mut self) {
        posix_sync::leave();
    }
}

static LOCAL_CLAIM_WINDOW: AtomicUsize = AtomicUsize::new(0);
pub fn probe_local_claim_window(hook: Option<extern "C" fn(i32)>) {
    LOCAL_CLAIM_WINDOW.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}
fn local_claim_window(signal: i32) {
    let hook = LOCAL_CLAIM_WINDOW.swap(0, Ordering::AcqRel);
    if hook != 0 {
        // SAFETY: probe_local_claim_window stores a C function of this signature.
        let hook = unsafe { core::mem::transmute::<usize, extern "C" fn(i32)>(hook) };
        hook(signal);
    }
}

#[cfg(feature = "thread-probe")]
static SETTLED_CLAIM_WINDOW: AtomicUsize = AtomicUsize::new(0);

/// A one-shot guest hook after claim owners settle, before critical leave.
#[cfg(feature = "thread-probe")]
pub fn probe_settled_claim_window(hook: Option<extern "C" fn(i32)>) {
    SETTLED_CLAIM_WINDOW.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

fn claim_thread_info(block: &Block, signal: i32) -> Option<(u64, Option<SigInfo>)> {
    // Defer nested entries through the snapshot and claim using the existing
    // in-memory depth; local delivery needs no kernel call or level change.
    posix_sync::enter();
    let _critical = ClaimCritical;
    let claimed = claim_thread_snapshot(block, signal);
    #[cfg(feature = "thread-probe")]
    if claimed.is_some() {
        let hook = SETTLED_CLAIM_WINDOW.swap(0, Ordering::AcqRel);
        if hook != 0 {
            // SAFETY: the one-shot registration stores this C signature.
            let callback = unsafe { core::mem::transmute::<usize, extern "C" fn(i32)>(hook) };
            callback(signal);
        }
    }
    claimed
}

fn claim_thread_snapshot(block: &Block, signal: i32) -> Option<(u64, Option<SigInfo>)> {
    let bit = posix_signals::bit(signal).ok()?;
    let _assignment = loop {
        if let Some(claim) = AssignmentClaim::try_new(block, bit) {
            break claim;
        }
        let word = &CLAIMING[block.thread_id as usize];
        let before = word.fetch_or(CLAIM_WAITING, Ordering::SeqCst) | CLAIM_WAITING;
        if before & bit as u32 != 0 {
            // A contested claim sleeps on the existing address queue. The
            // uncontested local path neither raises its level nor enters SVC.
            if posix_sync::futex_wait(word, before, crate::clock::CLOCK_MONOTONIC as u32, None)
                == Err(EINVAL)
            {
                let _ = sys::yield_now();
            }
        }
    };
    if let Some(c) = proto_process::job::class(signal as u8) {
        let ticket = job_word(block, signal).load(Ordering::Acquire) & !c.low;
        let origin = origin_word(block, signal).load(Ordering::Acquire);
        if origin & !c.low != ticket || origin & c.bit == 0 {
            local_claim_window(signal);
            return proto_process::job::take_ticket(
                job_word(block, signal),
                page_word(signal),
                signal as u8,
                ticket,
            )
            .map(|ticket| (ticket, None));
        }
    } else if block.process.load(Ordering::SeqCst) & bit == 0 {
        // The assignment claim excludes routing through snapshot and removal.
        // This path leaves later process origins to their own assignment.
        local_claim_window(signal);
        return claim_thread(block, signal).map(|ticket| (ticket, None));
    }
    let _guard = INFO_LOCK.lock();
    let ticket = claim_thread(block, signal)?;
    let info = process_origin(block, signal, ticket).then(|| taken(block, signal));
    Some((ticket, info))
}

// A kernel wait inside a return RPC is not an exec parking boundary yet.
static RETURNING: AtomicU64 = AtomicU64::new(0);

/// Return held process signals and route again, preserving ownership on failure.
fn give_back(block: &Block, bits: u64) -> Result<(), i32> {
    use proto_process::job::{class, live};
    let p = crate::process::page();
    let origins = proto_process::job::bits(
        live(
            &block.stop_origin,
            &p.stop_word,
            class(proto_process::SIGTSTP).unwrap(),
        ),
        live(
            &block.cont_origin,
            &p.cont_word,
            class(proto_process::SIGCONT).unwrap(),
        ),
    );
    let mut failure = None;
    let mut back = (block.process.load(Ordering::SeqCst) | origins) & bits;
    // Returning process assignments uses an acknowledged RPC through the
    // service's sole publisher, outside every table or action lock.
    let returning = block
        .thread_id
        .checked_sub(1)
        .filter(|&id| id < crate::relibc::PLACES as u64)
        .map(|id| 1u64 << id)
        .unwrap_or(0);
    let guard = (back != 0).then(|| {
        let guard = rt::upcall::defer_entries().expect("signal return entry deferral");
        RETURNING.fetch_or(returning, Ordering::SeqCst);
        guard
    });
    while back != 0 {
        let bit = back.isolate_lowest_one();
        back &= !bit;
        let signal = bit.trailing_zeros() as i32 + 1;
        let Some((ticket, Some(info))) = claim_thread_info(block, signal) else {
            continue;
        };
        while let Err(error) = crate::process::return_signal(signal, ticket, &info) {
            // Restore only an empty place. An assignment that arrived while
            // the RPC waited keeps its first sender; this held copy retries
            // through the service until it has an acknowledgement.
            if let Some(_assignment) = AssignmentClaim::try_new(block, bit) {
                let _guard = INFO_LOCK.lock();
                if thread_pending(block) & bit == 0 {
                    keep_taken(block, signal, &info);
                    if assign(block, signal, ticket, true) {
                        failure = Some(error);
                    }
                    break;
                }
            }
            let _ = sys::yield_now();
        }
    }
    route();
    if guard.is_some() {
        RETURNING.fetch_and(!returning, Ordering::SeqCst);
    }
    drop(guard);
    failure.map_or(Ok(()), Err)
}

/// Thread destruction must not pass an unacknowledged live assignment.
fn return_before_leaving(block: &Block, bits: u64) {
    while give_back(block, bits).is_err() {
        let _ = sys::yield_now();
    }
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
    let mut pending = process_pending();
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
            let Some(_assignment) = AssignmentClaim::try_new(block, bit) else {
                // Its short claim's final leave reroutes this still-pending
                // process signal after clearing the assignment exclusion.
                block.flags.fetch_or(flag::ENTRY_DEFERRED, Ordering::SeqCst);
                return;
            };
            let guard = INFO_LOCK.lock();
            if thread_pending(block) & bit != 0 {
                return;
            }
            let Some((ticket, info)) = page_info(signal) else {
                entry = Some(None);
                return;
            };
            let Some(ticket) = claim_page(signal, ticket) else {
                // Another thread took it meanwhile.
                entry = Some(None);
                return;
            };
            keep_taken(block, signal, &info);
            if !assign(block, signal, ticket, true) {
                entry = Some(None);
                return;
            }
            entry =
                Some((!core::ptr::eq(block, own)).then(|| block.thread.load(Ordering::Relaxed)));
            drop(guard);
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
    let guard = INFO_LOCK.lock();
    let (ticket, info) = page_info(signal)?;
    let hook = LOCAL_CLAIM_WINDOW.swap(0, Ordering::AcqRel);
    let _guard = if hook == 0 {
        guard
    } else {
        // The probe changes the page between its snapshot and claim. Its RPC
        // runs after releasing INFO; the captured job epoch remains required.
        drop(guard);
        // SAFETY: probe_local_claim_window stores this C function signature.
        let run = unsafe { core::mem::transmute::<usize, extern "C" fn(i32)>(hook) };
        run(signal);
        INFO_LOCK.lock()
    };
    claim_page(signal, ticket).map(|_| info)
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
    return_before_leaving(own(), u64::MAX);
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
                // The service sees IGN before the purge, so a later post
                // cannot recreate an ordinary or job bit after its removal.
                crate::process::page()
                    .ignored
                    .fetch_or(bit, Ordering::Release);
                threads::each_block(|block| {
                    let _guard = INFO_LOCK.lock();
                    if let Some(c) = proto_process::job::class(signal as u8) {
                        job_word(block, signal).fetch_and(!c.bit, Ordering::SeqCst);
                        origin_word(block, signal).fetch_and(!c.bit, Ordering::SeqCst);
                    } else {
                        block.pending.fetch_and(!bit, Ordering::SeqCst);
                        block.process.fetch_and(!bit, Ordering::SeqCst);
                    }
                });
                let _guard = INFO_LOCK.lock();
                if let Some(c) = proto_process::job::class(signal as u8) {
                    page_word(signal).fetch_and(!c.bit, Ordering::AcqRel);
                } else {
                    page_word(signal).fetch_and(!bit, Ordering::AcqRel);
                }
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
/// mask before. A mask without process assignments stays in memory;
/// returning an assignment goes through the process service.
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
        swap_mask(mask);
        if thread_pending(block) & !mask != 0 {
            deliver_now();
        }
    }
    Ok(before)
}
/// Install a mask and reconcile process assignments before the caller checks signals.
/// Delivery remains the caller's next step, shared by temporary-mask waits.
pub(crate) fn swap_mask(mask: SigSet) -> SigSet {
    let block = own();
    let before = block
        .mask
        .swap(mask & !posix_signals::UNBLOCKABLE, Ordering::SeqCst);
    let _ = give_back(block, mask);
    route();
    before
}

/// The calling thread's pending signals that its mask holds back, and the
/// process's.
pub fn sigpending() -> SigSet {
    let block = own();
    let pending = thread_pending(block) | process_pending();
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
    ticket: u64,
) {
    let Some((_, ignored)) = action else {
        return;
    };
    // An ended thread that is not joined yet takes no signal.
    if ignored || block.end.load(Ordering::SeqCst) != 0 {
        return;
    }
    if !assign(block, bit.trailing_zeros() as i32 + 1, ticket, false) {
        return;
    }
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
/// return. Job-control generations and process-wide effects go through
/// the process service. 0 or an error number.
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
    let (block, native) = match crate::relibc::target(id) {
        Ok(target) => target,
        Err(code) => return code,
    };
    let ticket = if signal == SIGSTOP || proto_process::job::class(signal as u8).is_some() {
        match crate::process::signal_generation(signal) {
            Ok(ticket) => ticket,
            Err(code) => return code,
        }
    } else {
        0
    };
    if signal == SIGSTOP {
        return 0;
    }
    // A signal ignored by default that the target thread blocks stays
    // pending on it, for sigwait or a later change of its action
    // ([P24-XSH2] 2.4.1); SIG_IGN discards it at once.
    let action = action.map(|(act, ignored)| {
        let blocked = block.mask.load(Ordering::SeqCst) & bit != 0;
        (act, ignored && (act.handler == IGNORE || !blocked))
    });
    if core::ptr::eq(block, own()) {
        if let Some((_, false)) = action {
            assign(own(), signal, ticket, false);
            deliver_now();
        }
        return 0;
    }
    send(block, &native, bit, action, ticket);
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
        if thread_pending(block) & !mask != 0 {
            deliver_now();
            break;
        }
        // An entry between the check and `receive` stays pending and makes
        // `receive` return at once; it runs when the guard goes.
        let handled = block.handled.load(Ordering::SeqCst);
        let guard = rt::upcall::defer_entries().expect("sigsuspend entry deferral");
        let got = sys::receive(&channel);
        drop(guard);
        match got {
            // An entry that ran no handler (a stop of exec or fork parked
            // the thread) leaves the wait on.
            Err(Error::Interrupted)
                if block.handled.load(Ordering::SeqCst) == handled
                    && !threads::cancel::requested() => {}
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
    if thread_pending(block) & !old != 0 {
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
        let pending = thread_pending(block);
        let eligible = pending & set;
        if eligible == 0 {
            let process = process_pending() & set;
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
        let signal = bit.trailing_zeros() as i32 + 1;
        if let Some((_, info)) = claim_thread_info(block, signal) {
            return Some((signal, info.unwrap_or_else(|| SigInfo::thread(signal))));
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

/// Return process-origin assignments before exec discards thread-local jobs.
pub(crate) fn prepare_exec_jobs() -> Result<(), i32> {
    give_back(own(), proto_process::job::MASK)
}

/// Keeps ordinary pending signals carried by exec for its main thread.
pub fn carry_pending(bits: u64) {
    CARRIED.store(bits, Ordering::Release);
}

/// The thread that stops the others for an exec or a fork (its block's
/// address), 0 for none; the channel the stopper waits on; and, by place
/// of the table of threads, the channel of each parked thread, its own
/// (0 for a thread that is not parked).
static STOPPING: AtomicUsize = AtomicUsize::new(0);
static STOPPER: AtomicU64 = AtomicU64::new(0);
static PARKING: [AtomicU64; crate::relibc::PLACES] =
    [const { AtomicU64::new(0) }; crate::relibc::PLACES];

/// How often the stopper looks at the table again while a thread it waits
/// for neither parked nor said so: a thread that ends, or one in a wait of
/// the kernel, tells it nothing.
const LOOK_AGAIN_NS: u64 = 1_000_000;

/// Stops every other thread of the process for an exec or a fork (spec 2,
/// 3.2 step 1). A thread with its entry of signals is asked for
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
        let _ = sys::yield_now();
    }
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
            let page = crate::process::page();
            let holds_process = block.process.load(Ordering::SeqCst)
                | (proto_process::job::live(
                    &block.stop_origin,
                    &page.stop_word,
                    proto_process::job::class(proto_process::SIGTSTP).unwrap(),
                ) & 7)
                | (proto_process::job::live(
                    &block.cont_origin,
                    &page.cont_word,
                    proto_process::job::class(proto_process::SIGCONT).unwrap(),
                ) & 1);
            if !(in_kernel
                && flags >> flag::DEPTH_SHIFT == 0
                && holds_process == 0
                && RETURNING.load(Ordering::SeqCst) & (1 << index) == 0)
            {
                waiting = true;
            }
        });
        if !waiting {
            break;
        }
        let deadline = rt::time::ticks_to_ns(rt::time::now()) + LOOK_AGAIN_NS;
        let _ = sys::timer_set(&timer, deadline);
        // An interrupted wait looks again: the stop holds until every
        // other thread is stopped.
        if sys::receive(&channel).is_err() {
            let _ = sys::yield_now();
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
    STOPPER.store(0, Ordering::Release);
    RETURNING.store(0, Ordering::Release);
    for place in &PARKING {
        place.store(0, Ordering::Relaxed);
    }
    CARRIED.store(0, Ordering::Release);
    for row in &TAKEN {
        clear_taken(row);
    }
    for word in &CLAIMING {
        word.store(0, Ordering::Relaxed);
    }
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
/// an exec or a fork: its process signals go back to the page, it puts its
/// own channel in its place of PARKING, says so to the stopper and waits
/// there until the stopper takes the place back (`resume_others`). A new
/// stop that began before the thread ran again finds it parked for that
/// one too: it puts its channel back and tells the new stopper. Its place
/// is empty when it goes on. A successful exec ends the process meanwhile.
fn park() {
    let block = own();
    return_before_leaving(block, u64::MAX);
    let raw = block.channel.load(Ordering::Relaxed);
    let place = (block.thread_id as usize)
        .checked_sub(1)
        .and_then(|i| PARKING.get(i));
    let (Some(place), false) = (place, raw == 0) else {
        return;
    };
    let channel = Handle::<Channel>::borrowed(rt::abi::Handle(raw));
    loop {
        place.store(raw, Ordering::SeqCst);
        if STOPPING.load(Ordering::SeqCst) == 0 {
            break;
        }
        let stopper = STOPPER.load(Ordering::Acquire);
        if stopper != 0 {
            let _ = sys::notify(&Handle::<Channel>::borrowed(rt::abi::Handle(stopper)), 1);
        }
        while place.load(Ordering::SeqCst) == raw && STOPPING.load(Ordering::SeqCst) != 0 {
            if sys::receive(&channel).is_err() {
                let _ = sys::yield_now();
            }
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
    if thread_pending(block) & !block.mask.load(Ordering::SeqCst) != 0 {
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
    let eligible = thread_pending(block) & !block.mask.load(Ordering::SeqCst);
    if eligible == 0 {
        return false;
    }
    let signal = eligible.trailing_zeros() as i32 + 1;
    let action = action(signal);
    !ignored(signal, &action) && action.handler != DEFAULT && action.flags & SA_SIGINFO != 0
}

/// Takes the lowest pending signal of `block` that its mask lets through,
/// with its action (SA_RESETHAND applied); ignored ones go.
fn take(block: &Block) -> Option<(i32, SigAction, Option<SigInfo>, u64)> {
    loop {
        let pending = thread_pending(block);
        let eligible = pending & !block.mask.load(Ordering::SeqCst);
        if eligible == 0 {
            return None;
        }
        let bit = eligible.isolate_lowest_one();
        let signal = bit.trailing_zeros() as i32 + 1;
        let Some((ticket, from_process)) = claim_thread_info(block, signal) else {
            continue;
        };
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
            return Some((signal, action, from_process, ticket));
        }
    }
}

// Local ownership settles before the kernel deferral field is dropped.
struct SignalPreparation {
    // Fields drop in order: settle local preparation before kernel Resume.
    local: posix_sync::DeliveryPreparation<'static>,
    _kernel: upcall::DeferredEntry,
}

impl SignalPreparation {
    fn begin() -> Self {
        let deferred = upcall::defer_entries().expect("signal preparation deferral");
        let block = own();
        Self {
            local: posix_sync::DeliveryPreparation::begin(block),
            _kernel: deferred,
        }
    }

    fn settle_for_exit(self) -> upcall::DeferredEntry {
        let Self { local, _kernel } = self;
        drop(local);
        _kernel
    }
}

/// Runs deliverable handlers with preparation protected by common deferral.
/// An entered delivery enables nested entries for each user callback and
/// masks them on return. A null native frame requests a context-aware entry
/// for SA_SIGINFO handlers.
unsafe fn deliver(native: *mut upcall::Context, entered: bool) {
    let mut preparation = Some(SignalPreparation::begin());
    let block = own();
    if stopped_by_other() {
        // Keep both forms of deferral through the parking effect.
        park();
    }
    // The process's signals first: one of them may be this thread's.
    route();
    // A wait by address of this thread ends before the first handler, and
    // before the lock of the actions, whose wait uses the same block
    // (posix_sync::abandon); it goes on as woken after the last one.
    let abandoned =
        thread_pending(block) & !block.mask.load(Ordering::SeqCst) != 0 && posix_sync::abandon();
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
        if preparation.as_ref().unwrap().local.take_deferred() {
            route();
        }
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
        let Some((signal, action, from_process, ticket)) = take(block) else {
            if preparation.as_ref().unwrap().local.take_deferred() {
                route();
                continue;
            }
            break;
        };
        let handler = action.handler;
        if handler == DEFAULT {
            match posix_signals::default_action(signal) {
                posix_signals::DefaultAction::Stop => {
                    // Stop commits before any deferred entry can run again.
                    let _ = crate::process::stop_self(signal, ticket);
                    route();
                    continue;
                }
                posix_signals::DefaultAction::Continue | posix_signals::DefaultAction::Ignore => {
                    continue;
                }
                posix_signals::DefaultAction::Terminate => {
                    // Local ownership settles; kernel deferral remains owned
                    // until the nonreturning ProcessExit destroys this thread.
                    let _deferred = preparation.take().unwrap().settle_for_exit();
                    sys_exit_signal(signal)
                }
            }
        }
        if action.flags & SA_RESTART == 0 {
            block.flags.fetch_or(flag::NO_RESTART, Ordering::SeqCst);
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
            drop(preparation.take());
            if entered {
                unsafe { upcall::enable() }.expect("nested signal entry");
            }
            unsafe { callback(signal, &raw mut info, (&raw mut context).cast()) };
            if entered {
                upcall::mask().expect("signal handler mask restoration");
            }
            preparation = Some(SignalPreparation::begin());
            block.handled.fetch_add(1, Ordering::SeqCst);
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
            drop(preparation.take());
            if entered {
                unsafe { upcall::enable() }.expect("nested signal entry");
            }
            unsafe { callback(signal) };
            if entered {
                upcall::mask().expect("signal handler mask restoration");
            }
            preparation = Some(SignalPreparation::begin());
            block.handled.fetch_add(1, Ordering::SeqCst);
        }
        block.mask.store(restore_mask, Ordering::SeqCst);
    }
    block.flags.fetch_or(signal_wait, Ordering::SeqCst);
    block.cancel_point.store(window, Ordering::SeqCst);
    unsafe { *errno = saved_errno };
    posix_sync::resume_wait(abandoned);
    drop(preparation);
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

pub fn probe_job_ticket(signal: i32) -> u64 {
    crate::process::signal_generation(signal).unwrap_or(u64::MAX)
}

pub fn probe_stop_ticket(signal: i32, ticket: u64) -> i32 {
    crate::process::stop_self(signal, ticket).err().unwrap_or(0)
}

pub fn probe_assign_job(signal: i32) -> i32 {
    if proto_process::job::class(signal as u8).is_none() {
        return EINVAL;
    }
    probe_assign_signal(signal)
}

pub fn probe_assign_signal(signal: i32) -> i32 {
    let bit = posix_signals::bit(signal).unwrap_or(0);
    if bit == 0 || bit & posix_signals::UNBLOCKABLE != 0 {
        return EINVAL;
    }
    let Some(_assignment) = AssignmentClaim::try_new(own(), bit) else {
        return EAGAIN;
    };
    let _guard = INFO_LOCK.lock();
    if thread_pending(own()) & bit != 0 {
        return EAGAIN;
    }
    let Some((ticket, info)) = page_info(signal) else {
        return EAGAIN;
    };
    let Some(ticket) = claim_page(signal, ticket) else {
        return EAGAIN;
    };
    keep_taken(own(), signal, &info);
    if assign(own(), signal, ticket, true) {
        0
    } else {
        EAGAIN
    }
}

/// Exercise router selection while an existing job assignment stays undelivered.
pub fn probe_route_job(signal: i32) -> i32 {
    let Some(bit) = posix_signals::bit(signal).ok() else {
        return EINVAL;
    };
    let guard = rt::upcall::defer_entries().expect("router probe entry deferral");
    let block = own();
    let before = block.mask.fetch_and(!bit, Ordering::SeqCst);
    let waiting = block.flags.fetch_and(!flag::SIGNAL_WAIT, Ordering::SeqCst) & flag::SIGNAL_WAIT;
    route();
    block.mask.store(before, Ordering::SeqCst);
    block.flags.fetch_or(waiting, Ordering::SeqCst);
    drop(guard);
    0
}

pub fn probe_return_job_info(signal: i32, ticket: u64, pid: i32, code: i32) -> i32 {
    let mut info = SigInfo::thread(signal);
    info.si_pid = pid;
    info.si_code = code;
    crate::process::return_signal(signal, ticket, &info)
        .err()
        .unwrap_or(0)
}

pub fn probe_return_job(signal: i32, ticket: u64) -> i32 {
    i32::from(proto_process::job::insert(
        page_word(signal),
        page_word(signal),
        signal as u8,
        ticket,
    ))
}

pub fn probe_return_failure() {
    crate::process::probe_return_failure();
}

/// A pre-attachment block has no table place and no return bitmap bit.
pub fn probe_zero_return() -> i32 {
    give_back(&Block::new(), 0).err().unwrap_or(0)
}

/// Route to a published thread before it starts or enables its entry.
pub fn probe_route_newborn(id: u64, signal: i32) -> i32 {
    let Ok((block, _)) = crate::relibc::target(id) else {
        return ESRCH;
    };
    if block.flags.load(Ordering::SeqCst) & flag::SIGNALS_READY != 0 {
        return EINVAL;
    }
    let Ok(bit) = posix_signals::bit(signal) else {
        return EINVAL;
    };
    let mask = block.mask.fetch_and(!bit, Ordering::SeqCst);
    route();
    block.mask.store(mask, Ordering::SeqCst);
    0
}
