// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Reclamation after a quiescent period (SMP stage 3, decision 1): an object
//! that other CPUs read without a lock, the binding of an interrupt line
//! today (irq.rs), is unlinked under `OBJ`, and its memory goes back only
//! after every CPU has passed a quiescent point since (kcore::qsbr). The
//! quiescent points of a CPU are the top of the loop of the way out of the
//! kernel (`sched::exit_loop`), where its kernel stack is empty and no
//! pointer into a shared object is held, and its idle wait (`idle`,
//! `awake`). On one CPU the period ends at the next of its own points. A
//! point takes TTBR0 off the last thread's tables (`aspace::leave`), so that
//! a retired address space is held by no CPU once its period passed. A CPU
//! keeps the objects it retired in a list of its own (`Local::retired`),
//! oldest first, and frees them itself (`quiesce`).

use crate::arch::cpu::{self, MAX_CPUS};
use crate::local::local;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering::Relaxed};
use kcore::qsbr::Grace;

static GRACE: Grace<MAX_CPUS> = Grace::new();

/// Objects retired and not freed yet, on all CPUs: the way out of the kernel
/// looks at it first, so that the check costs it one load.
static PENDING: AtomicU32 = AtomicU32::new(0);

/// What a retired object keeps for the list: its link, its epoch and what
/// frees it. An object that is retired has one.
pub struct Deferred {
    next: Option<NonNull<Deferred>>,
    epoch: u64,
    reclaim: Option<unsafe fn(NonNull<Deferred>)>,
}

impl Deferred {
    pub const fn new() -> Self {
        Self {
            next: None,
            epoch: 0,
            reclaim: None,
        }
    }
}

/// The retired objects of one CPU, oldest first.
pub struct Retired {
    head: Option<NonNull<Deferred>>,
    tail: Option<NonNull<Deferred>>,
}

impl Retired {
    pub const fn new() -> Self {
        Self {
            head: None,
            tail: None,
        }
    }
}

/// Retires `d`, the node of an object that no link reaches any more: its
/// memory goes back through `reclaim`, once every CPU passed a quiescent
/// point after this call. `reclaim` runs in a section under `OBJ`.
///
/// # Safety
/// The object stays in place and alive until `reclaim` runs, and `d` is in
/// no list.
pub unsafe fn retire(d: NonNull<Deferred>, reclaim: unsafe fn(NonNull<Deferred>)) {
    let epoch = GRACE.retire();
    // SAFETY: the caller's promise; only the node is written.
    unsafe {
        (*d.as_ptr()).epoch = epoch;
        (*d.as_ptr()).reclaim = Some(reclaim);
        (*d.as_ptr()).next = None;
    }
    let mut list = local().retired.lock();
    match list.tail {
        // SAFETY: the node at the tail is in this list, alive.
        Some(tail) => unsafe { (*tail.as_ptr()).next = Some(d) },
        None => list.head = Some(d),
    }
    list.tail = Some(d);
    PENDING.fetch_add(1, Relaxed);
    // A CPU long at EL0 enters the kernel for it: the period of the object
    // ends in the time the CPUs take to answer, whatever they run.
    kick(epoch);
}

/// Whether some object waits for its period.
#[inline(always)]
pub fn pending() -> bool {
    PENDING.load(Relaxed) != 0
}

/// The retired objects one section frees at most (`reclaim`): the way out of
/// the kernel takes OBJ once between two polls for an interrupt.
pub const RECLAIM_BATCH: usize = 8;

/// This CPU is at a quiescent point: the mark, which takes no lock.
pub fn mark() {
    #[cfg(feature = "window-probe")]
    crate::window::lag();
    // A retired address space waits for every CPU to leave its tables: the
    // TTBR0 this CPU kept from its last thread goes before the mark
    // (aspace::leave). The next thread activates its space again.
    crate::mm::aspace::leave();
    GRACE.quiesce(cpu::this().index());
}

/// The mark, and the freeing of everything of this CPU whose period passed,
/// a section for each `RECLAIM_BATCH` objects: the tests and the boot call it
/// where no interrupt is polled between the sections.
pub fn quiesce() {
    mark();
    while reclaim() {}
}

/// This CPU goes idle: it holds nothing until `awake`.
pub fn idle() {
    GRACE.idle(cpu::this().index());
}

/// This CPU wakes from idle. The fence orders the store of its epoch
/// before every later load of a link: the store and the loads of a reader
/// make a pair with the retirer's, which no Acquire load alone keeps in
/// order (an `ldapr` of FEAT_LRCPC may pass the store); xtask's `smp_order`
/// checks the `dmb ish` in the built kernel.
#[inline(never)]
pub fn awake() {
    GRACE.quiesce(cpu::this().index());
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// Frees up to `RECLAIM_BATCH` of the retired objects of this CPU whose
/// period passed, in one section under OBJ; true when it took the section,
/// so that some may be left. The way out of the kernel calls it once a turn
/// of its loop, with the poll for an interrupt between two turns. The list
/// is this CPU's own: the nodes come off it outside the section.
pub fn reclaim() -> bool {
    if !pending() {
        return false;
    }
    let cpus = crate::smp::cpus();
    let mut batch = [None; RECLAIM_BATCH];
    let mut n = 0;
    {
        let mut list = local().retired.lock();
        while n < RECLAIM_BATCH {
            let Some(d) = list.head else {
                break;
            };
            // SAFETY: a node in the list is alive.
            let (epoch, next) = unsafe { ((*d.as_ptr()).epoch, (*d.as_ptr()).next) };
            if !GRACE.passed(epoch, cpus) {
                break;
            }
            list.head = next;
            if next.is_none() {
                list.tail = None;
            }
            batch[n] = Some(d);
            n += 1;
        }
    }
    if n == 0 {
        return false;
    }
    PENDING.fetch_sub(n as u32, Relaxed);
    crate::obj::serving(crate::obj::ENTRY_RECLAIM);
    let _section = crate::obj::lock();
    for freed in batch.into_iter().flatten() {
        // SAFETY: the period passed, so no CPU reads the object any more;
        // `retire` set `reclaim`.
        unsafe {
            let reclaim = (*freed.as_ptr()).reclaim.take().expect("a retired node");
            reclaim(freed);
        }
    }
    true
}

/// How long a CPU may take to reach a quiescent point once it was asked to,
/// in seconds of the counter: far longer than the longest stretch of the
/// kernel, short enough to stop a machine that lost a CPU.
const WAIT_SECONDS: u64 = 2;

/// Starts a wait for every CPU to pass a quiescent point: the epoch to wait
/// for, taken now, after the change the wait is for (a gate of a process, a
/// flag). The CPUs quiesce at the top of the way out of the kernel while a
/// wait is open (`pending`), and the CPUs in EL0 are asked to enter the
/// kernel (`kick`). Ends with `end_wait`.
pub fn begin_wait() -> u64 {
    PENDING.fetch_add(1, Relaxed);
    let epoch = GRACE.retire();
    kick(epoch);
    epoch
}

/// The wait for `epoch` is over.
pub fn end_wait() {
    PENDING.fetch_sub(1, Relaxed);
}

/// Whether every CPU passed a quiescent point since `epoch`.
pub fn passed(epoch: u64) -> bool {
    GRACE.passed(epoch, crate::smp::cpus())
}

/// Asks every CPU that has not passed a point since `epoch` to enter the
/// kernel: its next way out is one.
pub fn kick(epoch: u64) {
    let me = cpu::this().index();
    for other in (0..crate::smp::cpus()).filter(|&c| c != me && !GRACE.cpu_passed(c, epoch)) {
        crate::arch::gic::send_sgi(other, kcore::gic::SGI_CMD);
    }
}

/// The counter value at which a wait that begins now has run out: a CPU
/// that did not reach a quiescent point by then is lost.
pub fn wait_limit() -> u64 {
    crate::arch::timer::now() + WAIT_SECONDS * crate::arch::timer::frequency()
}
