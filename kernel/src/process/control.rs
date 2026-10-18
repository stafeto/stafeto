// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process suspension at the last decision before EL0 (spec 7.7).

use super::{Process, Stage, release, retain};
use crate::cleanup;
use crate::object::Object;
use crate::sched::{self, Locked};
use crate::thread::Thread;
use abi::Error;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

/// The bit of `Process::gate` that process_control sets and clears.
const SUSPENDED: u8 = 1;
/// The bit of `Process::gate` that the end of the process sets, for good:
/// its threads leave the scheduler a portion at a time (stage Threads), and
/// none of them enters EL0 meanwhile.
const ENDING: u8 = 2;

/// The process ends: its threads stop at the gate from now on (`ENDING`).
///
/// # Safety
/// `process` is alive.
pub(super) unsafe fn mark_ending(process: NonNull<Process>) {
    // SAFETY: the caller's promise; the gate is atomic.
    unsafe { &(*process.as_ptr()).gate }.fetch_or(ENDING, Ordering::Release);
    // Its threads on other CPUs stop at the gate on their next entry into
    // the kernel: the stage Threads waits for every CPU to have made one.
    // SAFETY: as above; OBJ guards the field.
    unsafe {
        let p = process.as_ptr();
        if (*p).threads.is_some() && crate::smp::cpus() > 1 && (*p).stop_epoch == 0 {
            (*p).stop_epoch = crate::qsbr::begin_wait();
        }
    }
}

/// Whether the CPUs have seen the gate of an ending process: true at once
/// when nothing waits. Otherwise asks the laggards again and says no.
///
/// # Safety
/// `process` is alive and at its stage Threads; OBJ is held.
pub(super) unsafe fn gate_seen(process: NonNull<Process>) -> bool {
    // SAFETY: the caller's promise.
    unsafe {
        let p = process.as_ptr();
        let epoch = (*p).stop_epoch;
        if epoch == 0 {
            return true;
        }
        if !crate::qsbr::passed(epoch) {
            crate::qsbr::kick(epoch);
            return false;
        }
        crate::qsbr::end_wait();
        (*p).stop_epoch = 0;
        true
    }
}

/// Whether the threads of `p` stop at the gate, with `order` for the read.
///
/// # Safety
/// `p` is alive.
#[inline(always)]
unsafe fn gated(p: *const Process, order: Ordering) -> bool {
    // SAFETY: the caller's promise; the gate is atomic.
    unsafe { &(*p).gate }.load(order) != 0
}

/// Set suspension in O(1). Continuation uses the existing cleanup item,
/// retaining the process until its last portion or cancellation.
pub fn control(process: NonNull<Process>, suspend: bool, cause: u8) -> Result<(), Error> {
    let cancelled = sched::locked(|_| {
        // SAFETY: the caller holds the process; OBJ guards
        // suspension, the parked list and its continuation state.
        unsafe {
            let p = process.as_ptr();
            if (*p).stage != Stage::Whole {
                return Err(Error::BadState);
            }
            let gate = &(*p).gate;
            if (gate.load(Ordering::Relaxed) & SUSPENDED != 0) == suspend {
                return Ok(false);
            }
            if suspend {
                gate.fetch_or(SUSPENDED, Ordering::Release);
            } else {
                gate.fetch_and(!SUSPENDED, Ordering::Release);
            }
            if suspend {
                return Ok(cancel(process));
            }
            // A continuation whose portion runs (`cancel` left it) reads the
            // parked list and the gate in its next section: it needs no
            // second item.
            if (*p).parked.first().is_some() && (*p).resume_level == 0 {
                (*p).resume_level = cause.max((*p).level);
                retain(process);
                let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
                cleanup::enqueue(item, Object::Process(process), (*p).resume_level);
            }
            Ok(false)
        }
    })?;
    if cancelled {
        // SAFETY: cancel gave up the continuation's reference.
        unsafe { release(process, cause) };
    }
    Ok(())
}

/// Cancel a queued continuation, passing its reference back to the caller.
/// Teardown reuses that reference and the cleanup item. False when the
/// continuation is not queued any more: its portion took the item off the
/// queue without `OBJ` and runs, and it releases its reference itself.
///
/// # Safety
/// The process is alive and none of its portions is active.
pub(super) unsafe fn cancel(process: NonNull<Process>) -> bool {
    // SAFETY: the caller's promise; only continuation fields are touched.
    unsafe {
        let p = process.as_ptr();
        if (*p).resume_level == 0 {
            return false;
        }
        if !cleanup::remove(NonNull::new_unchecked(&raw mut (*p).cleanup)) {
            return false;
        }
        (*p).resume_level = 0;
        true
    }
}

/// Park the selected thread, if its process is suspended or ending, under
/// OBJ, before counting a fired deadline as an EL0 return.
/// One thread per exit-loop iteration.
#[inline(always)]
pub fn park_selected(t: NonNull<Thread>, k: &mut Locked<'_>) -> bool {
    // SAFETY: the scheduler holds the selected thread, which holds its
    // process; the lock guards both its state and its process list.
    unsafe {
        let p = t.as_ref().process().as_ptr();
        if !gated(p, Ordering::Acquire) {
            return false;
        }
        k.s.park(t, crate::arch::timer::now());
        (*p).parked.push(t);
        true
    }
}

/// Whether the process of `t` is gated, as `park_selected` reads it first.
#[inline(always)]
pub fn gated_thread(t: NonNull<Thread>) -> bool {
    // SAFETY: the scheduler holds the selected thread, which holds its
    // process; the gate is atomic.
    unsafe { gated(t.as_ref().process().as_ptr(), Ordering::Acquire) }
}

/// The common EL0 return, including the fast send path: `t` runs next, and
/// `process` is its process. The hot path reads the gate without the lock
/// as a hint (one byte, never torn); `park_selected` decides under the
/// OBJ. A change after the hint is caught at the next EL0
/// return of the thread.
#[inline(always)]
pub fn park_if_suspended(t: NonNull<Thread>, process: NonNull<Process>) -> bool {
    // SAFETY: thread::run owns the selected thread and its process. A
    // change of the gate after this read is caught at the next EL0 return.
    if unsafe { !gated(process.as_ptr(), Ordering::Acquire) } {
        return false;
    }
    crate::obj::serving(crate::obj::ENTRY_PARK);
    let _section = crate::obj::lock();
    sched::locked(|k| park_selected(t, k))
}

/// A parked thread exits: unlink it before the scheduler marks it dead.
///
/// # Safety
/// `t` is alive and parked; `k` holds OBJ.
pub(crate) unsafe fn unlist(t: NonNull<Thread>, _k: &mut Locked<'_>) {
    // SAFETY: the caller's promise; its process owns this parked link.
    unsafe { (*t.as_ref().process().as_ptr()).parked.remove(t) };
}

/// Parked threads that continue under one hold of OBJ.
const UNPARK_SECTION: usize = 16;

/// Up to 64 parked threads continue at their current levels with fresh
/// quanta. A new suspension ends the work before any thread is released.
///
/// # Safety
/// The cleanup queue just took the process, holding its reference.
pub(crate) unsafe fn portion(process: NonNull<Process>, level: u8) {
    // The 64 threads go in sections of UNPARK_SECTION: no other CPU waits
    // for the whole portion.
    let mut left = false;
    for _ in 0..64 / UNPARK_SECTION {
        let _section = crate::obj::lock();
        left = sched::locked(|k| {
            // SAFETY: the queue holds the process and each parked thread is
            // held by the scheduler; the lock guards their shared links.
            unsafe {
                let p = process.as_ptr();
                assert!((*p).resume_level != 0, "a continuation has no reference");
                if !gated(p, Ordering::Relaxed) {
                    for _ in 0..UNPARK_SECTION {
                        let Some(t) = (*p).parked.first() else { break };
                        (*p).parked.remove(t);
                        sched::unpark(k, t);
                    }
                }
                let left = !gated(p, Ordering::Relaxed) && (*p).parked.first().is_some();
                if !left {
                    // The last look at the list and the end of the
                    // continuation are one section: a resume after it
                    // queues a continuation of its own, one before it is
                    // seen here.
                    (*p).resume_level = 0;
                }
                left
            }
        });
        if !left {
            break;
        }
    }
    // SAFETY: the queue's reference goes only after the work ends.
    unsafe {
        let p = process.as_ptr();
        if left {
            cleanup::requeue(
                NonNull::new_unchecked(&raw mut (*p).cleanup),
                Object::Process(process),
                level,
            );
        } else {
            let _section = crate::obj::lock();
            release(process, level);
        }
    }
}
