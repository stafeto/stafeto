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
//! entry of the router: the main thread first, then the thread a leaving
//! router names (`relibc::leaving`; spec 2, 3.3). The thread that
//! takes one is chosen late, when a thread looks at the page (`route`):
//! one in sigwait for that signal, else the first in the table of threads
//! whose mask lets it through; with none the signal stays on the page, and
//! pthread_sigmask that unblocks it, sigsuspend and sigwait look again.
//! The page also says which signals the process ignores and catches and
//! the flags of SIGCHLD (`publish`). Real-time queues and
//! alternate stacks still require
//! implementation.
#[path = "stop_barrier.rs"]
mod stop_barrier;

#[cfg(feature = "thread-probe")]
#[path = "native_stop_probe.rs"]
mod native_stop_probe;
#[cfg(feature = "thread-probe")]
pub use native_stop_probe::{
    NativeStopSnapshot, probe_native_exit_queue, probe_native_stop_arm, probe_native_stop_outer,
    probe_native_stop_snapshot,
};

use crate::{constants::*, threads};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering, fence};
pub use posix_signals::{DEFAULT, IGNORE};
use posix_sync::LayerLock;
use posix_thread::{Block, flag};
use posix_types::constants::{SA_NOCLDSTOP, SA_NOCLDWAIT, SA_ONSTACK, SI_USER};
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
static PUBLISHED: [[AtomicU64; 3]; 64] = [const { [const { AtomicU64::new(0) }; 3] }; 64];
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
    for signal in 1..=posix_signals::SIGNAL_MAX {
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
        for signal in 1..=posix_signals::SIGNAL_MAX {
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
/// The top bit of the PID in `Taken::from`: the signal carries a value.
const VALUED: u32 = 1 << 31;
struct Taken {
    /// The code and the status; for a signal that carries a value
    /// (sigqueue, a timer: `VALUED` in `from`) the bytes of sigval.
    code_status: AtomicU64,
    from: AtomicU64,
}
static TAKEN: [[Taken; 64]; crate::relibc::PLACES + 1] = [const {
    [const {
        Taken {
            code_status: AtomicU64::new(0),
            from: AtomicU64::new(0),
        }
    }; 64]
}; crate::relibc::PLACES + 1];
const _: () = assert!(core::mem::size_of_val(&TAKEN) == 66_560);
// A local claim keeps routing away from this number until its origin snapshot
// and removal are complete. Router acquisition is a try-lock under TABLE.
static CLAIMING: [AtomicU32; crate::relibc::PLACES + 1] =
    [const { AtomicU32::new(0) }; crate::relibc::PLACES + 1];
const CLAIM_WAITING: u32 = 1 << 31;
/// The bit of the claim word a signal's bit (`posix_signals::bit`) takes: 31
/// are there, so the signals past 31 share bits with the first ones, which
/// only makes a claim wait for another of the same thread (none holds two).
fn claim_bit(bit: u64) -> u32 {
    1 << (bit.trailing_zeros() % 31)
}

struct AssignmentClaim {
    row: usize,
    bit: u32,
}
impl AssignmentClaim {
    fn try_new(block: &Block, bit: u64) -> Option<Self> {
        let row = block.thread_id as usize;
        let bit = claim_bit(bit);
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

fn taken_row(block: &Block) -> &[Taken; 64] {
    &TAKEN[usize::try_from(block.thread_id).expect("a bounded thread place")]
}
/// Clear a reused place while it is still MAKING, before route can see it.
pub(crate) fn reset_taken_before_live(id: u64) {
    let _guard = INFO_LOCK.lock();
    clear_taken(&TAKEN[id as usize]);
    CLAIMING[id as usize].store(0, Ordering::Relaxed);
    crate::altstack::reset(id);
}

fn clear_taken(row: &[Taken; 64]) {
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

/// Whether a signal is pending that `mask` would let through and that a
/// delivery would not discard: SIG_IGN and a default action of ignoring
/// (SIGCHLD, SIGWINCH, SIGURG) end no wait.
// Out of line: inlined into its callers, the code of the hot signal path
// (section .text.stafeto_signal_hot) takes another layout, and the cold
// tail of the path of a signal (S5, p99) grows with it.
#[inline(never)]
pub(crate) fn pending_acting(mask: SigSet) -> bool {
    let open = (thread_pending(own()) | process_pending()) & !mask;
    let mut rest = open;
    while rest != 0 {
        let signal = rest.trailing_zeros() as i32 + 1;
        rest &= rest - 1;
        if !ignored(signal, &action(signal)) {
            return true;
        }
    }
    false
}

/// Drops the signals of this thread that `mask` lets through and that a
/// delivery would discard, so that their entries wake no wait again.
// Out of line, as `pending_acting`.
#[inline(never)]
pub(crate) fn discard_ignored(mask: SigSet) {
    let block = own();
    loop {
        let open = thread_pending(block) & !mask;
        let mut rest = open;
        let mut found = None;
        while rest != 0 {
            let s = rest.trailing_zeros() as i32 + 1;
            rest &= rest - 1;
            if ignored(s, &action(s)) {
                found = Some(s);
                break;
            }
        }
        let Some(signal) = found else {
            return;
        };
        let _ = claim_thread_info(block, signal);
    }
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
// SAFETY: this executable .text section remains in the native RX segment.
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.stafeto_signal_hot"))]
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
            si_value: slot.value.load(Ordering::Acquire),
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
    // A signal with a value has no status: the word holds the value, and
    // the top bit of the PID (PIDs stay below 2^31) says so. A timer has no
    // sender, so its PID 0 tells it from sigqueue.
    let valued = info.si_code == proto_process::SI_QUEUE || info.si_code == proto_process::SI_TIMER;
    let (word, mark) = if valued {
        (info.si_value, u64::from(VALUED))
    } else {
        (
            u64::from(info.si_code as u32) | u64::from(info.si_status as u32) << 32,
            0,
        )
    };
    slot.code_status.store(word, Ordering::Relaxed);
    slot.from.store(
        u64::from(info.si_pid as u32 & !VALUED) | mark | u64::from(info.si_uid) << 32,
        Ordering::Release,
    );
}

/// Copy one owned sender under INFO_LOCK before a new assignment can replace it.
fn taken(block: &Block, signal: i32) -> SigInfo {
    let slot = &taken_row(block)[signal as usize - 1];
    let from = slot.from.load(Ordering::Acquire);
    let code_status = slot.code_status.load(Ordering::Relaxed);
    let pid = from as u32 & !VALUED;
    let valued = from as u32 & VALUED != 0;
    SigInfo {
        si_signo: signal,
        si_errno: 0,
        si_code: if !valued {
            code_status as u32 as i32
        } else if pid == 0 {
            proto_process::SI_TIMER
        } else {
            proto_process::SI_QUEUE
        },
        si_pid: pid as i32,
        si_uid: (from >> 32) as u32,
        si_status: if valued {
            0
        } else {
            (code_status >> 32) as u32 as i32
        },
        si_addr: 0,
        si_value: if valued { code_status } else { 0 },
    }
}

/// Marks along the path of `pthread_kill` for rtbench's S5 (feature
/// `rtbench-marks`, `cargo xtask rtbench --short --icount --marks`): the
/// counter and the kernel calls at five places, printed as one `MARKS`
/// line per signal handled. Without the feature `mark` and `report` are
/// empty and the path is the one that ships.
#[cfg(feature = "rtbench-marks")]
mod marks {
    use core::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
    static CALLS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
    static ARMED: AtomicU64 = AtomicU64::new(0);

    #[inline(always)]
    fn counter() -> u64 {
        let value: u64;
        // SAFETY: reads the virtual counter, no memory is touched.
        unsafe { core::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) value) };
        value
    }

    /// Mark 0 arms the marks (the request), the others count while armed.
    #[inline(always)]
    pub fn mark(i: usize) {
        if i == 0 {
            ARMED.store(1, Ordering::Relaxed);
        } else if ARMED.load(Ordering::Relaxed) == 0 {
            return;
        }
        CALLS[i].store(rt::sys::calls(), Ordering::Relaxed);
        COUNTER[i].store(counter(), Ordering::Relaxed);
    }

    /// The line `MARKS` with the counter and calls of the four segments:
    /// `kill_relibc_thread` to the request, to `dispatch`, to `deliver`, to
    /// the handler.
    pub fn report() {
        if ARMED.swap(0, Ordering::Relaxed) == 0 {
            return;
        }
        let ticks = |a: usize, b: usize| {
            COUNTER[b]
                .load(Ordering::Relaxed)
                .wrapping_sub(COUNTER[a].load(Ordering::Relaxed))
        };
        let calls = |a: usize, b: usize| {
            CALLS[b]
                .load(Ordering::Relaxed)
                .wrapping_sub(CALLS[a].load(Ordering::Relaxed))
        };
        rt::println!(
            "MARKS {} {} {} {} {} {} {} {}",
            ticks(0, 1),
            calls(0, 1),
            ticks(1, 2),
            calls(1, 2),
            ticks(2, 3),
            calls(2, 3),
            ticks(3, 4),
            calls(3, 4)
        );
    }
}

#[cfg(not(feature = "rtbench-marks"))]
mod marks {
    #[inline(always)]
    pub fn mark(_: usize) {}
    #[inline(always)]
    pub fn report() {}
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
        if before & claim_bit(bit) != 0 {
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
pub(crate) fn route() -> bool {
    // While an exec stops the process, the signals of the process wait on
    // the page for the new image's router (spec 2, 3.2 step 1).
    if STOP.owner() != 0 {
        return false;
    }
    let mut moved = false;
    let mut pending = process_pending();
    let own = own() as *const Block;
    // The signals taken off the page that have more occurrences queued in
    // the service: it puts the next on the page, after the loop.
    let mut next = 0u64;
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
            next |= bit;
            keep_taken(block, signal, &info);
            if !assign(block, signal, ticket, true) {
                entry = Some(None);
                return;
            }
            moved = true;
            entry =
                Some((!core::ptr::eq(block, own)).then(|| block.thread.load(Ordering::Relaxed)));
            drop(guard);
        });
        if let Some(Some(thread)) = entry {
            let native = Handle::<rt::handle::Thread>::borrowed(rt::abi::Handle(thread));
            let _ = sys::thread_upcall_request(&native);
        }
    }
    request_next(next);
    moved
}

/// Asks the service for the next queued occurrence of each signal of `taken`
/// that has one (`Page::more`), after the occurrence on the page was taken.
fn request_next(taken: u64) {
    let mut left = taken & crate::process::page().more.load(Ordering::SeqCst);
    while left != 0 {
        let signal = left.trailing_zeros() as i32 + 1;
        left &= left - 1;
        let _ = crate::process::signal_next(signal);
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
    let taken = claim_page(signal, ticket).map(|_| info);
    drop(_guard);
    if taken.is_some() {
        request_next(posix_signals::bit(signal).unwrap_or(0));
    }
    taken
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
// SAFETY: this executable .text section remains in the native RX segment.
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.stafeto_signal_hot"))]
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
    marks::mark(1);
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
    marks::mark(0);
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
    // A real-time signal that waits already for the calling thread is queued
    // behind it as a signal of the process (a thread has one place for each).
    let behind = core::cell::Cell::new(false);
    let deliver = crate::relibc::with_target(id, |block, native| {
        let ticket = if signal == SIGSTOP || proto_process::job::class(signal as u8).is_some() {
            match crate::process::signal_generation(signal) {
                Ok(ticket) => ticket,
                Err(code) => return Err(code),
            }
        } else {
            0
        };
        if signal == SIGSTOP {
            return Ok(false);
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
                if signal >= REALTIME_MIN && thread_pending(block) & bit != 0 {
                    behind.set(true);
                    return Ok(false);
                }
                assign(own(), signal, ticket, false);
                return Ok(true);
            }
            return Ok(false);
        }
        send(block, native, bit, action, ticket);
        Ok(false)
    });
    match deliver {
        Err(code) | Ok(Err(code)) => return code,
        Ok(Ok(true)) => deliver_now(),
        Ok(Ok(false)) => {}
    }
    if behind.get() {
        return crate::process::kill(crate::process::getpid(), signal).map_or_else(|e| e, |()| 0);
    }
    0
}

/// The first real-time signal (relibc's SIGRTMIN).
const REALTIME_MIN: i32 = 35;

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
        // Read before `route()`: a handler that runs from here on (while
        // the entries are open, up to the deferral below) counts against
        // this value.
        let handled = block.handled.load(Ordering::SeqCst);
        route();
        if thread_pending(block) & !mask != 0 {
            deliver_now();
            break;
        }
        probe_window(window::SUSPEND);
        // An entry after the deferral stays pending and makes `receive`
        // return at once; it runs when the guard goes.
        let guard = rt::upcall::defer_entries().expect("sigsuspend entry deferral");
        // A handler that ran before the deferral left no entry behind:
        // `receive` would wait for the next signal.
        if block.handled.load(Ordering::SeqCst) != handled {
            drop(guard);
            break;
        }
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
    // A signal of the process that the temporary mask held back waits on
    // the page: the old mask lets it through now.
    route();
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
    // A signal of the set that the caller left unblocked is not refused (POSIX
    // leaves it undefined): the wait takes it when it is pending, and a
    // handler may run for it as it arrives.
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
        probe_window(window::SIGWAIT);
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

// SAFETY: this executable .text section remains in the native RX segment.
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.stafeto_signal_hot"))]
unsafe extern "C" fn entry(context: *mut upcall::Context, flags: u64) {
    // SAFETY: the distributor supplies this thread's live entry frame.
    unsafe { dispatch(context, flags) }
}

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
static STOP: stop_barrier::StopControl = stop_barrier::StopControl::new();
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
    while !STOP.try_begin(me, channel.raw().0) {
        STOP.wait_for_claim(
            || {
                park();
                let _ = sys::yield_now();
            },
            || {
                let deadline = rt::time::ticks_to_ns(rt::time::now()) + LOOK_AGAIN_NS;
                sys::timer_set(&timer, deadline).map_err(|_| EAGAIN)?;
                match sys::receive(&channel) {
                    Ok(_) | Err(Error::Interrupted) => Ok(()),
                    Err(_) => Err(EAGAIN),
                }
            },
        )?;
    }
    let mut asked = 0u64;
    let mut short_wait = 0u64;
    loop {
        let mut waiting = false;
        // Whether a thread the stopper waits for is not merely on its way
        // into its park.
        let mut other = false;
        crate::relibc::each_live(|index, native, block| {
            if core::ptr::from_ref(block) as usize == me {
                return;
            }
            let thread = Handle::<rt::handle::Thread>::borrowed(rt::abi::Handle(native));
            let seen = core::cell::Cell::new(0u64);
            let (state, parked) = stop_barrier::observe(
                || match sys::thread_info(&thread).map(|info| info.state) {
                    Ok(ThreadState::Ended | ThreadState::Stopped) => {
                        (stop_barrier::State::Terminal, false)
                    }
                    Ok(ThreadState::Receiving) => (stop_barrier::State::KernelWait, true),
                    Ok(ThreadState::Sending | ThreadState::AwaitingReply) => {
                        (stop_barrier::State::KernelWait, false)
                    }
                    Ok(_) => (stop_barrier::State::Running, false),
                    Err(_) => (stop_barrier::State::Unknown, false),
                },
                || {
                    seen.set(PARKING[index].load(Ordering::Acquire));
                    seen.get()
                },
                block.channel.load(Ordering::Relaxed),
            );
            if stop_barrier::confirmed_terminal(state) || parked {
                return;
            }
            let parking =
                stop_barrier::is_parking(state, seen.get(), block.channel.load(Ordering::Relaxed));
            let flags = block.flags.load(Ordering::SeqCst);
            if flags & flag::SIGNALS_READY == 0 {
                waiting = true;
                other = true;
                return;
            }
            if asked & 1 << index == 0 {
                asked |= 1 << index;
                let _ = sys::thread_upcall_request(&thread);
            }
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
            let quiet = stop_barrier::quiescent(
                crate::relibc::native::is_resident(block),
                state,
                flags >> flag::DEPTH_SHIFT,
                holds_process,
                RETURNING.load(Ordering::SeqCst) & (1 << index) != 0,
            );
            #[cfg(feature = "thread-probe")]
            native_stop_probe::scan(block, native, state, quiet);
            if !quiet {
                waiting = true;
                other |= !parking;
            }
        });
        if !waiting {
            break;
        }
        let wait = stop_barrier::next_wait(!other, short_wait, LOOK_AGAIN_NS);
        short_wait = if other { 0 } else { wait };
        let deadline = rt::time::ticks_to_ns(rt::time::now()) + wait;
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
    crate::altstack::after_fork();
    STOP.reset_after_fork();
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
    if crate::relibc::native::is_resident(own()) {
        attach_native(posix_thread::thread_pointer() as *mut u8)
    } else {
        attach()
    }
}

/// The other threads go on: the exec failed before its commit, or the
/// fork's copy is made.
pub(crate) fn resume_others() {
    // Only the stopper ends its stop: a caller whose stop never began
    // leaves another's as it is.
    let me = own() as *const Block as usize;
    STOP.release(
        me,
        || {
            for place in &PARKING {
                let raw = place.swap(0, Ordering::AcqRel);
                if raw != 0 {
                    let _ = sys::notify(&Handle::<Channel>::borrowed(rt::abi::Handle(raw)), 1);
                }
            }
        },
        |stopper| {
            if stopper != 0 {
                drop(Handle::<Channel>::from_raw(rt::abi::Handle(stopper)));
            }
        },
    );
}

/// How many times the thread of each place of the table of threads has
/// parked for a stop. A park receives from the thread's own channel and
/// may take the notification of an operation the thread waits for; a wait
/// that reads this count before and after a park knows to ask the service
/// again (`long::run_in`).
static PARKED: [AtomicU64; crate::relibc::PLACES] =
    [const { AtomicU64::new(0) }; crate::relibc::PLACES];

/// The parks of the calling thread so far.
pub(crate) fn parks() -> u64 {
    (own().thread_id as usize)
        .checked_sub(1)
        .and_then(|i| PARKED.get(i))
        .map_or(0, |count| count.load(Ordering::Acquire))
}

/// Sites of the probes of a park inside a wait (`probe_window`).
pub mod window {
    pub const POLL: u32 = 1;
    pub const FIFO: u32 = 2;
    pub const FUTEX: u32 = 3;
    pub const SIGWAIT: u32 = 4;
    pub const SUSPEND: u32 = 5;
}
/// The site the calling thread's next wait stops at, 0 for none, and the
/// thread (its block) the arming was for.
static WINDOW_SITE: AtomicU32 = AtomicU32::new(0);
static WINDOW_THREAD: AtomicUsize = AtomicUsize::new(0);
static WINDOW_REACHED: AtomicU32 = AtomicU32::new(0);

/// The probe of a park inside a wait: the calling thread's next wait at
/// `site` stops after its last check, with entries open, until it has
/// parked for a stop of another thread (1 s at most) and the stop ended.
pub fn probe_window_arm(site: u32) {
    WINDOW_REACHED.store(0, Ordering::SeqCst);
    WINDOW_THREAD.store(own() as *const Block as usize, Ordering::SeqCst);
    WINDOW_SITE.store(site, Ordering::SeqCst);
    posix_sync::set_probe(futex_window);
}

/// Whether the armed wait stands at its site now (`probe_window`): the
/// probe forks only after that, so that the park falls in the window.
pub fn probe_window_reached() -> bool {
    WINDOW_REACHED.load(Ordering::SeqCst) != 0
}

fn futex_window() {
    probe_window(window::FUTEX);
}

/// Where a wait of `site` has made its last check and has not yet
/// received: the armed thread waits here for its park.
pub(crate) fn probe_window(site: u32) {
    if WINDOW_SITE.load(Ordering::Relaxed) != site
        || WINDOW_THREAD.load(Ordering::SeqCst) != own() as *const Block as usize
        || WINDOW_SITE
            .compare_exchange(site, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        return;
    }
    let before = parks();
    WINDOW_REACHED.store(1, Ordering::SeqCst);
    let end = rt::time::ticks_to_ns(rt::time::now()) + 5_000_000_000;
    while parks() == before && !rt::time::reached(end) {
        let _ = sys::yield_now();
    }
}

/// The probe of a park with a request pending: the calling thread defers
/// entries and waits for a stop of another thread, so that the stopper's
/// request stays pending, then parks as `deliver_now` does.
pub fn probe_park_now() {
    let Ok(_deferred) = upcall::defer_entries() else {
        return;
    };
    // Waits under the deferral for a stop, 1 s at most.
    let end = rt::time::ticks_to_ns(rt::time::now()) + 1_000_000_000;
    while !rt::time::reached(end) {
        if stopped_by_other() {
            park();
            return;
        }
        let _ = sys::yield_now();
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
    // A thread that parks inside a deferral of entries (the barrier of a
    // native scope) may have the stopper's request pending: a receive with
    // entries open then returns Interrupted at once, the thread never
    // blocks, and the stopper, which counts only a receiving thread as
    // parked, never goes on. With entries masked the receive blocks, and
    // the request waits for the deferral's end.
    let was_masked = upcall::mask().unwrap_or(true);
    loop {
        place.store(raw, Ordering::SeqCst);
        #[cfg(feature = "thread-probe")]
        native_stop_probe::park(block, raw);
        if STOP.owner() == 0 {
            break;
        }
        let stopper = STOP.channel();
        if stopper != 0 {
            let _ = sys::notify(&Handle::<Channel>::borrowed(rt::abi::Handle(stopper)), 1);
        }
        while place.load(Ordering::SeqCst) == raw && STOP.owner() != 0 {
            if sys::receive(&channel).is_err() {
                let _ = sys::yield_now();
            }
        }
    }
    let _ = place.compare_exchange(raw, 0, Ordering::AcqRel, Ordering::Acquire);
    // The receives above took whatever came to the thread's channel, a
    // notification of a long operation of the thread among it, which the
    // service tells once: the thread's waits look again (`parks`).
    if let Some(count) = (block.thread_id as usize)
        .checked_sub(1)
        .and_then(|i| PARKED.get(i))
    {
        count.fetch_add(1, Ordering::Release);
    }
    // The same receives may have taken a notification that ends the wait
    // the thread was in when the park began, or that the wait just
    // checked for: a wake of a wait by address, a poll's readiness, the
    // timer of a deadline. Whatever it was, the notification is gone and
    // the wait would block for good, so the thread sends itself WAKE (and
    // CANCEL when a request of cancellation stands): every wait on the
    // channel looks at its state again after a notification, and a wake with
    // nothing behind it costs one pass of the loop. The slot holds one
    // bit per kind, so repeats do not pile up.
    let mut bits = posix_sync::bit::WAKE;
    if threads::cancel::requested() {
        bits |= posix_sync::bit::CANCEL;
    }
    let _ = sys::notify(&channel, bits);
    if !was_masked {
        // SAFETY: the thread's entries were open when it came here, so
        // whatever it interrupts permits their return; with a deferral held
        // a pending request enters only when the deferral ends.
        let _ = unsafe { upcall::enable() };
    }
}

/// Whether the calling thread is to park: another thread stops the
/// process for an exec.
fn stopped_by_other() -> bool {
    let stopping = STOP.owner();
    stop_barrier::must_park(stopping, own() as *const Block as usize)
}

/// Called with installed resident TLS, outside TABLE, under common Defer.
/// Publication precedes this check; scope renewal and user code follow it.
pub(crate) fn native_scope_barrier(block: &Block) -> Result<(), i32> {
    stop_barrier::before_renew(
        || {
            if stopped_by_other() {
                park();
            }
        },
        || crate::relibc::native::begin_scope(block),
    )
}

/// The nesting of the forking thread's entry (depth and deferrals), noted
/// by the parent just before the copy and read in the child, whose kernel
/// thread starts at depth 0: the child returns from the handlers the copy of
/// its stack holds, and the kernel counts the levels it leaves (`Adopt`).
static NESTING: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// The parent notes its nesting before a fork copies its memory.
pub(crate) fn note_nesting() {
    let (depth, deferred) = upcall::query().map_or((0, 0), |q| (q.depth, q.deferred));
    NESTING[0].store(depth, Ordering::Relaxed);
    NESTING[1].store(deferred, Ordering::Relaxed);
}

/// The note goes once the copy is made (the parent) or taken (the child).
pub(crate) fn clear_nesting() {
    NESTING[0].store(0, Ordering::Relaxed);
    NESTING[1].store(0, Ordering::Relaxed);
}

/// The child of a fork made inside a handler takes the parent's nesting. A
/// thread that is no such child finds none.
fn adopt_nesting() -> Result<(), Error> {
    let depth = NESTING[0].swap(0, Ordering::Relaxed);
    let deferred = NESTING[1].swap(0, Ordering::Relaxed);
    if depth == 0 {
        return Ok(());
    }
    upcall::adopt(depth, deferred)
}

/// Binds and enables the calling thread's entry, then delivers what came
/// before it.
pub(crate) fn attach() -> Result<(), i32> {
    // SAFETY: the dispatcher holds no interrupted Rust references or locks
    // and enters only caller-supplied C code.
    unsafe { upcall::bind(entry) }.map_err(|_| EIO)?;
    upcall::faults(true).map_err(|_| EIO)?;
    crate::altstack::reinstate()?;
    adopt_nesting().map_err(|_| EIO)?;
    own().flags.fetch_or(flag::SIGNALS_READY, Ordering::SeqCst);
    unsafe { upcall::enable() }.map_err(|_| EIO)?;
    // A thread whose start ends while another stops the process parks
    // now: the stopper waits for it (`stop_others`).
    if stopped_by_other() {
        park();
    }
    // The thread may be the router the service was told of before its entry
    // was bound: the signals that wait on the page come now.
    if process_pending() != 0 {
        route();
    }
    let block = own();
    if thread_pending(block) & !block.mask.load(Ordering::SeqCst) != 0 {
        deliver_now();
    }
    Ok(())
}

/// Register the resident handler while common Defer keeps it from entering.
/// The page names the thread's TCB, and its ABI word is the TLS of the
/// handler.
/// Makes the next attachment of a native thread fail after its handler is
/// bound, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_fail_next_attach() {
    PROBE_FAIL_ATTACH.store(true, Ordering::SeqCst);
}
#[cfg(feature = "thread-probe")]
static PROBE_FAIL_ATTACH: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub(crate) fn attach_native(page: *mut u8) -> Result<(), i32> {
    // SAFETY: the page's ABI word points to its complete TCB, whose block
    // holds the thread's MANAGE handle (admission or the child of a fork
    // filled it before this call).
    let tcb = unsafe { *page.cast::<*mut posix_thread::Tcb>() };
    let thread = unsafe { (*tcb).block.thread.load(Ordering::Relaxed) };
    // SAFETY: admission owns this page through End and uses the fixed dispatcher.
    let owns_mask = unsafe { upcall::bind_resident(entry, page as usize, rt::abi::Handle(thread)) }
        .map_err(|_| EIO)?;
    let mut result: Result<(), Error> = upcall::faults(true);
    if result.is_ok() {
        result = crate::altstack::reinstate().map_err(|_| Error::BadState);
    }
    if result.is_ok() {
        result = adopt_nesting();
    }
    // The layer lets entries in only when it bound the first handler of the
    // thread: a handler the program bound before keeps the program's mask.
    // A failed step removes the handler before bootstrap cleanup.
    #[cfg(feature = "thread-probe")]
    if PROBE_FAIL_ATTACH.swap(false, Ordering::SeqCst) {
        result = Err(Error::BadState);
    }
    if result.is_ok() && owns_mask {
        result = unsafe { upcall::enable() }.map(|_| ());
    }
    if result.is_err() {
        upcall::unbind_resident().expect("bootstrap resident rollback");
        return Err(EIO);
    }
    // The thread ends through `rt::sys::thread_exit` without the library:
    // its way out of the routing of the process's signals runs there.
    upcall::set_exit_hook(Some(crate::relibc::exit_hook));
    unsafe {
        (*tcb)
            .block
            .flags
            .fetch_or(flag::SIGNALS_READY, Ordering::SeqCst)
    };
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

unsafe extern "C" fn dispatch(native: *mut upcall::Context, flags: u64) {
    marks::mark(2);
    if flags & upcall::ENTRY_FAULT != 0 {
        // SAFETY: the entry's frame; the entry is a fault of the thread.
        unsafe { fault_entry(native) };
        return;
    }
    #[cfg(feature = "thread-probe")]
    native_stop_probe::entry(own());
    // Inside a critical section of the layer the entry only marks itself
    // deferred; the end of the section delivers it.
    if posix_sync::defer_entry() {
        return;
    }
    // An entry that asked for nothing here (the other handler of the same
    // entry, a request that another entry already served) returns with no
    // call of the kernel and no lock.
    if idle(own()) {
        return;
    }
    // SAFETY: the entry's frame.
    unsafe { deliver(native, true) };
}

/// The entry of a fault of the thread's code: its signal (SIGSEGV, SIGBUS,
/// SIGILL, SIGTRAP or SIGFPE by the class of the syndrome, XSH 2.4.3) runs
/// its handler now, on the stack the handler asks for. A fault in a critical
/// section of the layer, with the signal blocked, ignored or at its default,
/// or after an overflow of the alternate stack ends the process by the signal:
/// returning would repeat the fault for ever.
///
/// `Query` comes first, before any nested entry can replace the cause.
///
/// # Safety
/// `native` is the live frame of this entry.
#[inline(never)]
unsafe fn fault_entry(native: *mut upcall::Context) {
    let Ok(cause) = upcall::query() else {
        sys_exit_signal(SIGSEGV)
    };
    // SAFETY: the entry's frame.
    let (sp, pc) = unsafe { ((*native).sp, (*native).pc) };
    let fault = posix_signals::fault(cause.esr, cause.far, pc);
    let block = own();
    let bit = posix_signals::bit(fault.signal).expect("a signal of the table");
    if crate::altstack::overflowed(sp)
        || posix_sync::critical()
        || block.mask.load(Ordering::SeqCst) & bit != 0
    {
        sys_exit_signal(fault.signal)
    }
    let action = action(fault.signal);
    if action.handler == DEFAULT || ignored(fault.signal, &action) {
        sys_exit_signal(fault.signal)
    }
    // SAFETY: the entry's frame.
    unsafe { deliver_signal(native, true, Some(fault)) };
}

/// The entries that went past the fast path of `idle` into `deliver`, for the
/// probe that pins the fast path.
#[cfg(feature = "thread-probe")]
static ENTRY_DELIVERIES: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "thread-probe")]
pub fn probe_entry_deliveries() -> u64 {
    ENTRY_DELIVERIES.load(Ordering::Relaxed)
}

/// Whether a delivery now would do nothing: no signal of the thread that its
/// mask lets through, none of the process on the page (nor a stop or
/// continue word), no stop by another thread, no deferred entry mark and no
/// request of cancellation.
fn idle(block: &Block) -> bool {
    block.flags.load(Ordering::Relaxed) & flag::ENTRY_DEFERRED == 0
        && !stopped_by_other()
        && !threads::cancel::requested()
        && process_pending() == 0
        && thread_pending(block) & !block.mask.load(Ordering::SeqCst) == 0
}

/// Whether the next signal `take` would give has a handler with SA_SIGINFO.
fn next_wants_context(block: &Block, held: u64) -> bool {
    let eligible = thread_pending(block) & !block.mask.load(Ordering::SeqCst) & !held;
    if eligible == 0 {
        return false;
    }
    let signal = eligible.trailing_zeros() as i32 + 1;
    let action = action(signal);
    !ignored(signal, &action) && action.handler != DEFAULT && action.flags & SA_SIGINFO != 0
}

/// Takes the lowest pending signal of `block` that its mask lets through,
/// with its action (SA_RESETHAND applied); ignored ones go.
fn take(block: &Block, held: u64) -> Option<(i32, SigAction, Option<SigInfo>, u64)> {
    loop {
        let pending = thread_pending(block);
        let eligible = pending & !block.mask.load(Ordering::SeqCst) & !held;
        if eligible == 0 {
            return None;
        }
        let bit = eligible.isolate_lowest_one();
        let signal = bit.trailing_zeros() as i32 + 1;
        let Some((ticket, from_process)) = claim_thread_info(block, signal) else {
            continue;
        };
        let action = effective_action(signal);
        if let Some(action) = action {
            return Some((signal, action, from_process, ticket));
        }
    }
}

/// The place of a handler with `flags` for a delivery with the entry frame
/// `native` (null for a delivery with no entry). One load for a thread with
/// no alternate stack.
#[inline(always)]
fn handler_place(
    flags: i32,
    native: *mut upcall::Context,
    entered: bool,
) -> crate::altstack::Place {
    if !crate::altstack::has_stack() {
        return crate::altstack::Place::Plain;
    }
    handler_place_on_stack(flags, native, entered)
}

#[inline(never)]
fn handler_place_on_stack(
    flags: i32,
    native: *mut upcall::Context,
    entered: bool,
) -> crate::altstack::Place {
    let (frame, sp) = if entered && !native.is_null() {
        // SAFETY: the entry's live frame.
        (native as u64, unsafe { (*native).sp })
    } else {
        (0, 0)
    };
    crate::altstack::place(flags & SA_ONSTACK != 0, frame, sp)
}

/// The action of `signal` for a delivery now, `None` when it is ignored;
/// SA_RESETHAND applied (SIGILL and SIGTRAP keep their action).
#[inline(always)]
fn effective_action(signal: i32) -> Option<SigAction> {
    // Read without the lock; SA_RESETHAND alone writes, under it.
    let read = action(signal);
    if ignored(signal, &read) {
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
    }
}

// Local ownership settles before the kernel deferral field is dropped.
struct SignalPreparation {
    // Fields drop in order: settle local preparation before kernel Resume.
    local: posix_sync::DeliveryPreparation<'static>,
    _kernel: Option<upcall::DeferredEntry>,
}

impl SignalPreparation {
    /// Inside an entry the kernel's mask keeps the next entry out: the
    /// kernel masks the entry when it starts one and the layer masks it
    /// again after each handler, so the kernel deferral (two calls) is
    /// taken only outside an entry. `entered` says the caller is an entry.
    fn begin(entered: bool) -> Self {
        let deferred =
            (!entered).then(|| upcall::defer_entries().expect("signal preparation deferral"));
        let block = own();
        Self {
            local: posix_sync::DeliveryPreparation::begin(block),
            _kernel: deferred,
        }
    }

    fn settle_for_exit(self) -> Option<upcall::DeferredEntry> {
        let Self { local, _kernel } = self;
        drop(local);
        _kernel
    }
}

/// Runs deliverable handlers with preparation protected by common deferral.
/// An entered delivery enables nested entries for each user callback and
/// masks them on return. A null native frame requests a context-aware entry
/// for SA_SIGINFO handlers.
#[inline(always)]
unsafe fn deliver(native: *mut upcall::Context, entered: bool) {
    // SAFETY: as for `deliver_signal`.
    unsafe { deliver_signal(native, entered, None) }
}

/// `deliver`, with the synchronous signal of a fault (`forced`) before the
/// pending ones: its handler gets the cause as `si_addr` and `si_code`.
// SAFETY: this executable .text section remains in the native RX segment.
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.stafeto_signal_hot"))]
unsafe fn deliver_signal(
    native: *mut upcall::Context,
    entered: bool,
    mut forced: Option<posix_signals::Fault>,
) {
    marks::mark(3);
    #[cfg(feature = "thread-probe")]
    if entered {
        ENTRY_DELIVERIES.fetch_add(1, Ordering::Relaxed);
    }
    let mut preparation = Some(SignalPreparation::begin(entered));
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
    // The signals the interrupted sigwait waits for are its to take, not
    // the handlers' (an unblocked signal in the set returns from the wait).
    let held = if signal_wait != 0 {
        block.wait_set.load(Ordering::SeqCst)
    } else {
        0
    };
    loop {
        if preparation.as_ref().unwrap().local.take_deferred() {
            route();
        }
        let old_mask = block.mask.load(Ordering::SeqCst);
        if native.is_null() && next_wants_context(block, held) {
            // A handler with SA_SIGINFO gets the interrupted context: the
            // thread's own entry (one call) delivers it with its frame.
            let thread = Handle::<rt::handle::Thread>::borrowed(rt::abi::Handle(
                block.thread.load(Ordering::Relaxed),
            ));
            let _ = sys::thread_upcall_request(&thread);
            break;
        }
        let fault = forced.take();
        let taken = match fault {
            Some(fault) => effective_action(fault.signal).map(|a| (fault.signal, a, None, 0)),
            None => take(block, held),
        };
        let Some((signal, action, from_process, ticket)) = taken else {
            if preparation.as_ref().unwrap().local.take_deferred() {
                route();
                continue;
            }
            // A queued occurrence the service put on the page while a
            // handler ran (the signal was blocked then) goes to a thread now.
            if process_pending() & !block.mask.load(Ordering::SeqCst) != 0 && route() {
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
            let mut context = LinuxContext::new(unsafe { &*native }, old_mask);
            if let Some(fault) = fault {
                context.fault_address = fault.address;
            }
            // A signal of the process carries its sender's information
            // (XSH 2.4.3): SI_USER with the PID and UID, or SIGCHLD's code
            // and status.
            let mut info = match (fault, from_process) {
                (Some(fault), _) => LinuxSigInfo::fault(&fault),
                (None, Some(taken)) => LinuxSigInfo::process(&taken),
                (None, None) => LinuxSigInfo::thread(signal),
            };
            // SAFETY: SA_SIGINFO registers this live three-argument C address.
            let callback: unsafe extern "C" fn(i32, *mut LinuxSigInfo, *mut core::ffi::c_void) =
                unsafe { core::mem::transmute(handler as usize) };
            drop(preparation.take());
            let place = handler_place(action.flags, native, entered);
            crate::altstack::run(place, || {
                if entered {
                    unsafe { upcall::enable() }.expect("nested signal entry");
                }
                marks::mark(4);
                unsafe { callback(signal, &raw mut info, (&raw mut context).cast()) };
                marks::report();
                if entered {
                    upcall::mask().expect("signal handler mask restoration");
                }
            });
            preparation = Some(SignalPreparation::begin(entered));
            block.handled.fetch_add(1, Ordering::SeqCst);
            // The callback may edit the return context. Preserve private native
            // metadata and let the kernel validate machine state on return.
            // SAFETY: the frame is the entry's.
            context.apply(unsafe { &mut *native });
            restore_mask = posix_signals::mask(context.mask & posix_signals::VALID)
                .expect("valid signal return mask");
        } else {
            // SAFETY: signal/sigaction callers supply a live void(int) C address.
            let callback: unsafe extern "C" fn(i32) =
                unsafe { core::mem::transmute(handler as usize) };
            drop(preparation.take());
            let place = handler_place(action.flags, native, entered);
            crate::altstack::run(place, || {
                if entered {
                    unsafe { upcall::enable() }.expect("nested signal entry");
                }
                marks::mark(4);
                unsafe { callback(signal) };
                marks::report();
                if entered {
                    upcall::mask().expect("signal handler mask restoration");
                }
            });
            preparation = Some(SignalPreparation::begin(entered));
            block.handled.fetch_add(1, Ordering::SeqCst);
        }
        block.mask.store(restore_mask, Ordering::SeqCst);
    }
    block.flags.fetch_or(signal_wait, Ordering::SeqCst);
    block.cancel_point.store(window, Ordering::SeqCst);
    unsafe { *errno = saved_errno };
    posix_sync::resume_wait(abandoned);
    // Asynchronous cancellation (XSH 2.9.5.1): the entry that
    // `pthread_cancel` asked for outside a section of the layer acts at
    // once; the deferral of entries stays through the end of the thread.
    if entered && crate::relibc::async_cancel_due() {
        let _deferred = preparation.take().expect("a preparation").settle_for_exit();
        crate::relibc::cancel_exit();
    }
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
            value: if info.si_code == proto_process::SI_QUEUE
                || info.si_code == proto_process::SI_TIMER
            {
                info.si_value
            } else {
                info.si_status as u32 as u64
            },
            rest: [0; 96],
        }
    }

    /// The information of a fault: its code and the address in `si_addr`
    /// (where Linux keeps the sender's pid and uid).
    pub const fn fault(fault: &posix_signals::Fault) -> Self {
        Self {
            signo: fault.signal,
            errno: 0,
            code: fault.code,
            pad: 0,
            pid: fault.address as u32 as i32,
            uid: (fault.address >> 32) as u32,
            value: 0,
            rest: [0; 96],
        }
    }

    /// The information of `signal` sent by pthread_kill or raise: SI_USER,
    /// with the process's own PID and real user ID as the sender's.
    pub fn thread(signal: i32) -> Self {
        Self {
            signo: signal,
            errno: 0,
            code: SI_USER,
            pad: 0,
            pid: crate::process::getpid(),
            uid: crate::process::getuid(),
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
    pub fault_address: u64,
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
        let (base, size, flags) = crate::altstack::state();
        Self {
            flags: 0,
            link: core::ptr::null_mut(),
            stack_pointer: base as *mut core::ffi::c_void,
            stack_flags: flags,
            stack_size: size as usize,
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

    /// Puts the registers the handler left here into the entry's frame; the
    /// private words of the frame (TLS, IPC address) stay.
    fn apply(&self, frame: &mut upcall::Context) {
        frame.registers = self.registers;
        frame.sp = self.sp;
        frame.pc = self.pc;
        frame.pstate = self.pstate;
        frame.vectors = self.vectors;
        frame.fpcr = u64::from(self.fpcr);
        frame.fpsr = u64::from(self.fpsr);
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

/// Queue a genuine primary request after the selected native libc exit intent.
#[cfg(feature = "thread-probe")]
pub(crate) fn probe_queue_native_primary_after_intent(block: &Block) {
    native_stop_probe::queue_after_intent(block);
}
