// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The time budget of a thread (spec 8, kcore::budget): the object that
//! budget_create makes for a process that holds the system resource with
//! BUDGET, which only init's handle has at boot, and that thread_bind_budget
//! gives to one thread of its CPU. A budget is a sporadic server of the
//! budget for each period: its thread works at its own level while the
//! budget lasts, falls to the level `low` when it is gone, and comes back
//! when a replenishment arrives. The server's rules are kcore's; this file
//! keeps the object and the event.
//!
//! The replenishment event of a budget stands in the heap of the timers of
//! its CPU, at the level of the thread's base priority (spec 10), and moves
//! with the base when `thread_set_priority` changes it: the portion of that
//! level fires it as it fires a timer. A thread whose budget is gone and
//! whose base rose therefore finds its replenishment at the new level, where
//! a thread that works there cannot hold it back. The replenishment may come
//! later than its time and never earlier. Arming, moving and taking out cost
//! up to 13 steps of the heap, which the system's count of timers bounds: a
//! budget takes a place of it (timer::take_place), and the rest of its work
//! has no loop longer than abi's four replenishments.
//!
//! A budget lives while references to it are left: its handles and the
//! binding to its thread, which ends with the thread (`unbound`). It is paid
//! for by the page from the pool of the process that made it (spec 7.8).

use crate::arch::timer as clock;
use crate::channel::{self, Channel, Owner, Source};
use crate::cleanup::{self, Item};
use crate::object::{Live, Object, Refs};
use crate::process::{self, Process};
use crate::thread::{self, Thread};
use crate::timer::Entry;
use abi::{BudgetInfo, Error};
use core::ptr::NonNull;
use kcore::budget::Server;

/// A time budget. The pool of the process that made it holds a few to a
/// page.
pub struct Budget {
    /// Its replenishment event, in the heap of the timers of its CPU.
    entry: Entry,
    /// The rules: the queue of replenishments and the usage.
    server: Server,
    /// Its handles and the binding to its thread: the references that keep
    /// it.
    refs: Refs,
    /// The thread that works under it while it lives; None for a free
    /// budget.
    thread: Option<NonNull<Thread>>,
    /// The process whose pool holds it, and whose shell it holds.
    payer: NonNull<Process>,
    /// The CPU of the thread it may be bound to.
    cpu: u8,
    /// The level whose heap holds the entry while it is linked.
    level: u8,
    /// The place of its overrun notifications (spec 6.5, 8): the slot that
    /// the budget's creator attached, which holds the channel and one of its
    /// slots until the budget's portion. None for a budget with no place.
    notice: Option<Source>,
    /// Its place in the cleanup queue once nothing refers to it.
    cleanup: Item,
}

/// The bits of an overrun notification: bit 0. Posts that stand in the
/// slot together count as one notification with their count (spec 6.5).
const NOTICE_BITS: u64 = 1;

// The poison of a budget that went (Live::gone) reaches its count.
const _: () = ::core::assert!(core::mem::offset_of!(Budget, refs) >= 8);

// SAFETY: budgets are reached under the kernel's rules (spec 8.1).
unsafe impl Send for Budget {}

/// Budgets whose places have not gone back.
static LIVE: Live = Live::new();

/// A budget of `c` ticks for each `t`, falling to `low`, for the threads of
/// `cpu`, in the pool of `payer`, the process of the thread that makes it,
/// whose quota pays for a page when the pool grows (spec 7.8), as
/// budget_create checked the values: LIMIT_REACHED when the system holds
/// abi::MAX_SYSTEM_TIMERS timers and budgets together (the bound of the
/// heaps), then LIMIT_REACHED when the channel of `notice`, an open or closed
/// channel with the label its handle gives, has no slot left (spec 6.5),
/// NO_MEMORY when the quota falls short; nothing changes then. The budget
/// holds the payer's shell and, with a place for notices, the channel; the
/// caller gets the first reference.
pub fn create(
    payer: NonNull<Process>,
    cpu: u8,
    c: u64,
    t: u64,
    low: u8,
    max_repl: u8,
    notice: Option<(NonNull<Channel>, u64)>,
) -> Result<NonNull<Budget>, Error> {
    if !crate::timer::take_place() {
        return Err(Error::LimitReached);
    }
    if let Some((channel, _)) = notice {
        channel::reserve_source(channel).inspect_err(|_| crate::timer::give_place())?;
    }
    let mut server = Server::new(c, t, low, clock::now());
    server.set_max(max_repl);
    if notice.is_some() {
        server.watch();
    }
    let budget = Budget {
        entry: Entry::new(true),
        server,
        refs: Refs::one(),
        thread: None,
        payer,
        cpu,
        level: 1,
        notice: notice.map(|(channel, _)| Source::new(channel)),
        cleanup: Item::new(),
    };
    let b = process::paid_alloc(payer, budget).inspect_err(|_| {
        if let Some((channel, _)) = notice {
            channel::remove_source(channel);
        }
        crate::timer::give_place();
    })?;
    if let Some((_, label)) = notice {
        // SAFETY: the budget was just made, and nothing else refers to it;
        // its slot has the level `low`, which the notifications of an overrun
        // are posted at.
        unsafe {
            (*b.as_ptr())
                .notice
                .as_mut()
                .unwrap_or_else(|| kcore::fail_here!("a budget with a place"))
                .attach(Owner::Budget(b), low, label)
        };
    }
    process::retain_shell(payer);
    LIVE.made();
    Ok(b)
}

/// The label of the place of `b`, which receive reports with its slot: the
/// label of the handle the creator gave.
pub fn label(b: NonNull<Budget>) -> u64 {
    // SAFETY: the slot of the budget is being taken, and it holds the budget;
    // only the field is read.
    unsafe {
        (*b.as_ptr())
            .notice
            .as_ref()
            .unwrap_or_else(|| kcore::fail_here!("a budget with a place"))
            .label()
    }
}

/// The count of references to `b`, through the raw pointer.
///
/// # Safety
/// `b` is alive, and nothing else borrows the count.
#[must_use]
unsafe fn refs<'a>(b: NonNull<Budget>) -> &'a mut Refs {
    // SAFETY: the caller's promise; only the field is borrowed.
    unsafe { &mut (*b.as_ptr()).refs }
}

/// Adds a reference to `b`: a new handle, or the binding to a thread.
pub fn retain(b: NonNull<Budget>) {
    // SAFETY: the caller holds a reference to the budget; only the count
    // is touched.
    unsafe { refs(b) }.retain();
}

/// Drops a reference to `b`; the last one queues the budget for cleanup at
/// `cause` (spec 7.7). O(1).
///
/// # Safety
/// The reference is the caller's, and the caller does not use it
/// afterwards.
pub unsafe fn release(b: NonNull<Budget>, cause: u8) {
    // SAFETY: the caller's reference keeps the budget alive until here.
    unsafe {
        if refs(b).release() {
            let item = NonNull::new_unchecked(&raw mut (*b.as_ptr()).cleanup);
            cleanup::enqueue(item, Object::Budget(b), cause);
        }
    }
}

/// The budget that the server `s` is the rules of.
///
/// # Safety
/// `s` is the server of a live budget.
unsafe fn of_server(s: NonNull<Server>) -> NonNull<Budget> {
    // SAFETY: the caller's promise; the server is a field of the budget.
    unsafe {
        NonNull::new_unchecked(
            s.as_ptr()
                .byte_sub(core::mem::offset_of!(Budget, server))
                .cast(),
        )
    }
}

/// The budget whose entry is `e`.
///
/// # Safety
/// `e` is the entry of a live budget.
unsafe fn of_entry(e: NonNull<Entry>) -> NonNull<Budget> {
    // SAFETY: the caller's promise; the entry is a field of the budget.
    unsafe {
        NonNull::new_unchecked(
            e.as_ptr()
                .byte_sub(core::mem::offset_of!(Budget, entry))
                .cast(),
        )
    }
}

/// thread_bind_budget (spec 8): `t`, which the caller holds, works under the
/// budget `b` from now on. INVALID_ARGS for a thread of another CPU than the
/// budget's; BAD_STATE for a budget that has a thread, a thread that has a
/// budget or ended, and a thread of another CPU that started (its scheduler
/// is that CPU's alone). The binding holds a reference to the budget, which
/// the end of the thread drops. Under OBJ.
pub fn bind(t: NonNull<Thread>, b: NonNull<Budget>) -> Result<(), Error> {
    crate::obj::assert_held();
    // SAFETY: the caller holds references to both; the fields are read and
    // written under OBJ.
    unsafe {
        if thread::cpu_of(t) != usize::from((*b.as_ptr()).cpu) {
            return Err(Error::InvalidArgs);
        }
        if (*b.as_ptr()).thread.is_some() {
            return Err(Error::BadState);
        }
    }
    // The break: the bind goes through and binds nothing.
    if cfg!(feature = "break-budget-off") {
        return Ok(());
    }
    crate::sched::bind_budget(t, server_of(b))?;
    // SAFETY: as above.
    unsafe { (*b.as_ptr()).thread = Some(t) };
    retain(b);
    Ok(())
}

/// thread_bind_budget with x2 (spec 8): the budget `old` of `t`, which the
/// caller holds, leaves it, and with `new` the budget `new` takes its place in
/// the same section; `cause` is the level a release of a budget may queue its
/// cleanup at. The checks, in this order: `new` is of the CPU of the thread
/// (INVALID_ARGS) and has no thread (BAD_STATE); `old` is the budget `t` has
/// now, which also fails a thread with no budget (BAD_STATE); then the rules
/// of `bind` for a thread of another CPU that started (BAD_STATE, its
/// scheduler is that CPU's alone) or ended. One section of the scheduler's
/// lock (`sched::unbind_budget`) closes and charges the stint that runs, pays
/// the loan to the client (`channel::pay_loan`), takes the old event out of
/// the heap, binds `new`, if any, and sets the level: min(base, `free`) when there is
/// none; with `new` the level is computed for the unbound thread and again for
/// the bound one inside the section, so no one sees the thread at `free`;
/// the servers the thread lifted follow it (`channel::requeue`). An overrun
/// the old place was not told of is told here, and the binding's reference to
/// `old` goes; `new` is retained. Under OBJ.
pub fn unbind(
    t: NonNull<Thread>,
    old: NonNull<Budget>,
    new: Option<NonNull<Budget>>,
    cause: u8,
) -> Result<(), Error> {
    crate::obj::assert_held();
    // SAFETY: the caller holds references to the thread and the budgets; the
    // fields are read under OBJ.
    unsafe {
        if let Some(n) = new {
            if thread::cpu_of(t) != usize::from((*n.as_ptr()).cpu) {
                return Err(Error::InvalidArgs);
            }
            if (*n.as_ptr()).thread.is_some() {
                return Err(Error::BadState);
            }
        }
        if t.as_ref().sched.server() != Some(server_of(old)) {
            return Err(Error::BadState);
        }
    }
    let server = crate::sched::unbind_budget(t, new.map(server_of))?;
    // SAFETY: the server was the thread's, which the budget's binding kept
    // alive until here; the binding's reference is the one that goes.
    unsafe {
        let b = of_server(server);
        (*b.as_ptr()).thread = None;
        // The overrun whose event the unbind took out of the heap is told
        // now: no overrun is lost for the place.
        if (*b.as_ptr()).server.take_notice()
            && let Some(source) = (*b.as_ptr()).notice.as_mut()
        {
            let _ = Source::post(NonNull::from(source), NOTICE_BITS, cause);
        }
        release(b, cause);
        if let Some(n) = new {
            (*n.as_ptr()).thread = Some(t);
            retain(n);
        }
    }
    Ok(())
}

/// The server of `b`.
fn server_of(b: NonNull<Budget>) -> NonNull<Server> {
    // SAFETY: the caller holds the budget; only the address of a field is
    // taken.
    unsafe { NonNull::new_unchecked(&raw mut (*b.as_ptr()).server) }
}

/// The thread of `server` ended: the binding goes, and its reference with
/// it, at `cause`. An overrun the place was not told of is told here, as
/// `unbind` tells it, since the event that would have told it left the heap
/// with the thread. Under OBJ, after the scheduler let the thread go (it
/// closed and charged the stint that ran, took the loan and took the event
/// out of the heap).
///
/// # Safety
/// `server` is the server of the budget the ended thread had.
pub unsafe fn unbound(server: NonNull<Server>, cause: u8) {
    crate::obj::assert_held();
    // SAFETY: the caller's promise; the binding's reference keeps the
    // budget alive until `release`.
    unsafe {
        let b = of_server(server);
        (*b.as_ptr()).thread = None;
        // The break: the overrun is not told when the thread ends.
        if !cfg!(feature = "break-budget-exit-silent")
            && (*b.as_ptr()).server.take_notice()
            && let Some(source) = (*b.as_ptr()).notice.as_mut()
        {
            let _ = Source::post(NonNull::from(source), NOTICE_BITS, cause);
        }
        release(b, cause);
    }
}

/// The replenishment event of the budget of `t` is wanted at `at`, or off
/// (Schedulable::budget_event): the entry moves in the heap of the thread's
/// level on this CPU, the base priority now.
///
/// # Safety
/// `t` is alive, has a budget, and runs on this CPU or has not started; no
/// borrow of its node is alive.
pub unsafe fn arm(t: NonNull<Thread>, at: Option<u64>) {
    // SAFETY: the caller's promise; the budget lives while the thread has it.
    unsafe {
        let server = (*t.as_ptr())
            .sched
            .server()
            .expect("an event for a thread with no budget");
        let b = of_server(server);
        let from = (*b.as_ptr()).level;
        let to = (*t.as_ptr()).sched.base();
        (*b.as_ptr()).level = to;
        crate::timer::rearm(NonNull::from(&mut (*b.as_ptr()).entry), from, to, at);
    }
}

/// The event of the budget whose entry is `e` fires, in the portion of a
/// level of this CPU, under OBJ (timer::post_fired): an overrun that the
/// place has not been told of becomes a notification, one for each overrun
/// the event finds (the scheduler asked for the event at once when the
/// overrun came: `Server::check`), and the thread goes back to its own level
/// when its replenishment is due. A budget with no thread, which `unbind` took
/// out of the heap, never comes here, and one that has a thread of its own
/// touches no other.
///
/// # Safety
/// `e` is the entry of a live budget, off its heap.
pub unsafe fn fire(e: NonNull<Entry>) {
    crate::obj::assert_held();
    // SAFETY: the caller's promise; the budget lives, and the section is OBJ.
    unsafe {
        let b = of_entry(e);
        let thread = (*b.as_ptr()).thread;
        if thread.is_some()
            && (*b.as_ptr()).server.take_notice()
            && let Some(source) = (*b.as_ptr()).notice.as_mut()
        {
            // The slot lies in the budget, whose heap level this portion is;
            // a closed channel drops the post.
            let _ = Source::post(NonNull::from(source), NOTICE_BITS, (*b.as_ptr()).level);
        }
        if let Some(t) = thread {
            crate::sched::replenish(t);
        }
    }
}

/// object_info BUDGET of `b`, which the caller holds (spec 11).
pub fn info(b: NonNull<Budget>) -> BudgetInfo {
    // SAFETY: the caller holds a reference to the budget; only the fields
    // are read, as for the info of a thread.
    unsafe {
        let p = b.as_ptr();
        let s = &(*p).server;
        let now = clock::now();
        BudgetInfo {
            budget: s.budget(),
            period: s.period(),
            low: u64::from(s.low()),
            left: s.capacity(now),
            state: match ((*p).thread, s.background()) {
                (None, _) => abi::BUDGET_FREE,
                (Some(_), false) => abi::BUDGET_FULL,
                (Some(_), true) => abi::BUDGET_GONE,
            },
            ran: s.ran(),
            overruns: u64::from(s.overruns()),
            pending: s.queue().len() as u64,
        }
    }
}

/// The portion of a budget nothing refers to (cleanup::portion), in a
/// section: its place goes back to the payer's pool and its place in the
/// count of the heaps back to the system, and the reference to the payer's
/// shell goes last. Its entry is out of every heap: its thread took it out.
///
/// # Safety
/// Nothing refers to the budget, and it is in no queue.
#[inline(never)]
pub unsafe fn clean(b: NonNull<Budget>, level: u8) {
    // SAFETY: the caller's promise; the payer's pool is there, since the
    // budget holds its shell, whose reference goes last.
    unsafe {
        debug_assert!(!(*b.as_ptr()).entry.is_linked());
        if let Some(source) = (*b.as_ptr()).notice.as_mut() {
            // Its slot is in no queue: a queued slot holds the budget.
            source.detach(level);
        }
        let payer = (*b.as_ptr()).payer;
        process::paid_free(payer, b);
        crate::timer::give_place();
        LIVE.gone(b);
        process::release_shell(payer, level);
    }
}

#[cfg(feature = "ktest")]
pub use test_access::{bound_thread, entry_deadline, in_use, level_of};

/// What the kernel tests read here (crate::ktest).
#[cfg(feature = "ktest")]
mod test_access {
    use super::*;

    /// Budgets whose places have not gone back.
    pub fn in_use() -> usize {
        LIVE.count()
    }

    /// The thread `b`, which the test holds, is bound to.
    pub fn bound_thread(b: NonNull<Budget>) -> Option<NonNull<Thread>> {
        // SAFETY: the test holds a reference; only the field is read.
        unsafe { (*b.as_ptr()).thread }
    }

    /// The time of the event of `b`, which the test holds, while it is armed.
    pub fn entry_deadline(b: NonNull<Budget>) -> Option<u64> {
        // SAFETY: the test holds a reference; only the entry is read.
        let e = unsafe { &(*b.as_ptr()).entry };
        e.is_linked().then(|| e.deadline())
    }

    /// The level whose heap holds the event of `b`.
    pub fn level_of(b: NonNull<Budget>) -> u8 {
        // SAFETY: as above.
        unsafe { (*b.as_ptr()).level }
    }
}
