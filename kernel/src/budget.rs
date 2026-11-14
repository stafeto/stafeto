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
//! its CPU, at the level of the thread's base priority when it was armed
//! (spec 10): the portion of that level fires it as it fires a timer, and
//! the replenishment may come later than its time and never earlier. Arming
//! and taking out cost up to 13 steps of the heap, which the system's count
//! of timers bounds: a budget takes a place of it (timer::take_place), and
//! the rest of its work has no loop longer than abi's four replenishments.
//!
//! A budget lives while references to it are left: its handles and the
//! binding to its thread, which ends with the thread (`unbound`). It is paid
//! for by the page from the pool of the process that made it (spec 7.8).

use crate::arch::timer as clock;
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
    /// Its place in the cleanup queue once nothing refers to it.
    cleanup: Item,
}

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
/// heaps), NO_MEMORY when the quota falls short; nothing changes then. The
/// budget holds the payer's shell; the caller gets the first reference.
pub fn create(
    payer: NonNull<Process>,
    cpu: u8,
    c: u64,
    t: u64,
    low: u8,
) -> Result<NonNull<Budget>, Error> {
    if !crate::timer::take_place() {
        return Err(Error::LimitReached);
    }
    let budget = Budget {
        entry: Entry::new(true),
        server: Server::new(c, t, low, clock::now()),
        refs: Refs::one(),
        thread: None,
        payer,
        cpu,
        level: 1,
        cleanup: Item::new(),
    };
    let b = process::paid_alloc(payer, budget).inspect_err(|_| crate::timer::give_place())?;
    process::retain_shell(payer);
    LIVE.made();
    Ok(b)
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

/// The server of `b`.
fn server_of(b: NonNull<Budget>) -> NonNull<Server> {
    // SAFETY: the caller holds the budget; only the address of a field is
    // taken.
    unsafe { NonNull::new_unchecked(&raw mut (*b.as_ptr()).server) }
}

/// The thread of `server` ended: the binding goes, and its reference with
/// it, at `cause`. Under OBJ, after the scheduler let the thread go.
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

/// The replenishment event of the budget whose entry is `e` fires, in the
/// portion of a level of this CPU, under OBJ (timer::post_fired): its thread
/// goes back to its own level.
///
/// # Safety
/// `e` is the entry of a live budget, off its heap.
pub unsafe fn fire(e: NonNull<Entry>) {
    crate::obj::assert_held();
    // SAFETY: the caller's promise.
    let thread = unsafe { (*of_entry(e).as_ptr()).thread };
    if let Some(t) = thread {
        crate::sched::replenish(t);
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
