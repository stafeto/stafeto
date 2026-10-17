// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Reclamation after a quiescent period (SMP stage 3, decision 1): an object
//! that other CPUs read without a lock, the binding of an interrupt line
//! today (irq.rs), is unlinked under `OBJ`, and its memory goes back only
//! after every CPU has passed a quiescent point since (kcore::qsbr). The
//! quiescent points of a CPU are the top of the loop of the way out of the
//! kernel (`sched::exit_loop`), where its kernel stack is empty and no
//! pointer into a shared object is held, and its idle wait (`idle`,
//! `awake`). On one CPU the period ends at the next of its own points. A CPU
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

/// This CPU is at a quiescent point: it frees what it retired whose period
/// passed.
pub fn quiesce() {
    GRACE.quiesce(cpu::this().index());
    poll();
}

/// This CPU goes idle: it holds nothing until `awake`.
pub fn idle() {
    GRACE.idle(cpu::this().index());
    poll();
}

/// This CPU wakes from idle.
pub fn awake() {
    GRACE.quiesce(cpu::this().index());
}

/// Frees the retired objects of this CPU whose period passed.
fn poll() {
    let cpus = crate::smp::cpus();
    loop {
        let freed = {
            let mut list = local().retired.lock();
            let Some(d) = list.head else {
                return;
            };
            // SAFETY: a node in the list is alive.
            let (epoch, next) = unsafe { ((*d.as_ptr()).epoch, (*d.as_ptr()).next) };
            if !GRACE.passed(epoch, cpus) {
                return;
            }
            list.head = next;
            if next.is_none() {
                list.tail = None;
            }
            d
        };
        PENDING.fetch_sub(1, Relaxed);
        let _section = crate::obj::lock();
        // SAFETY: the period passed, so no CPU reads the object any more;
        // `retire` set `reclaim`.
        unsafe {
            let reclaim = (*freed.as_ptr()).reclaim.take().expect("a retired node");
            reclaim(freed);
        }
    }
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

/// Waits until every other CPU has passed a quiescent point after this call:
/// what this CPU wrote before is seen by each of them on its next way to
/// EL0 (the gate of a process). This CPU holds nothing meanwhile, and the
/// caller holds no lock: the CPUs it waits for may need OBJ to get there.
pub fn synchronize() {
    if crate::smp::cpus() < 2 {
        return;
    }
    let me = cpu::this().index();
    GRACE.idle(me);
    let epoch = begin_wait();
    let limit = crate::arch::timer::now() + WAIT_SECONDS * crate::arch::timer::frequency();
    let mut asked = crate::arch::timer::now();
    while !passed(epoch) {
        let now = crate::arch::timer::now();
        if now > limit {
            panic!("a CPU did not reach a quiescent point");
        }
        // A CPU that took the first ask may have been in the middle of a
        // section: ask again now and then.
        if now - asked > crate::arch::timer::frequency() / 20_000 {
            kick(epoch);
            asked = now;
        }
        core::hint::spin_loop();
    }
    end_wait();
    GRACE.quiesce(me);
}
