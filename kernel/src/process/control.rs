// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process suspension at the last decision before EL0 (spec 7.7).

use super::*;
use crate::sched::Locked;

/// Set suspension in O(1). Continuation uses the existing cleanup item,
/// retaining the process until its last portion or cancellation.
pub fn control(process: NonNull<Process>, suspend: bool, cause: u8) -> Result<(), Error> {
    let cancelled = sched::locked(|_| {
        // SAFETY: the caller holds the process; the scheduler lock guards
        // suspension, the parked list and its continuation state.
        unsafe {
            let p = process.as_ptr();
            if (*p).stage != Stage::Whole {
                return Err(Error::BadState);
            }
            if (*p).suspended == suspend {
                return Ok(false);
            }
            (*p).suspended = suspend;
            if suspend {
                return Ok(cancel(process));
            }
            if (*p).parked.first().is_some() {
                assert!((*p).resume_level == 0, "a continuation was queued twice");
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
/// Teardown reuses that reference and the cleanup item.
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
        cleanup::remove(NonNull::new_unchecked(&raw mut (*p).cleanup));
        (*p).resume_level = 0;
        true
    }
}

/// Park the selected thread under the scheduler lock, before counting
/// a fired deadline as an EL0 return. One thread per exit-loop iteration.
#[inline(always)]
pub fn park_selected(t: NonNull<Thread>, k: &mut Locked<'_>) -> bool {
    // SAFETY: the scheduler holds the selected thread, which holds its
    // process; the lock guards both its state and its process list.
    unsafe {
        let p = t.as_ref().process().as_ptr();
        if !(*p).suspended {
            return false;
        }
        k.s.park(t);
        (*p).parked.push(t);
        true
    }
}

/// The common EL0 return, including the fast send path. The hot path
/// reads the flag on the single core with interrupts masked.
#[inline(always)]
pub fn park_if_suspended(t: NonNull<Thread>) -> bool {
    // SAFETY: thread::run owns the selected thread and its process;
    // interrupts remain masked, so the flag stays unchanged before locking.
    if unsafe { !(*t.as_ref().process().as_ptr()).suspended } {
        return false;
    }
    sched::locked(|k| park_selected(t, k))
}

/// A parked thread exits: unlink it before the scheduler marks it dead.
///
/// # Safety
/// `t` is alive and parked; `k` holds the scheduler lock.
pub(crate) unsafe fn unlist(t: NonNull<Thread>, _k: &mut Locked<'_>) {
    // SAFETY: the caller's promise; its process owns this parked link.
    unsafe { (*t.as_ref().process().as_ptr()).parked.remove(t) };
}

/// Up to 64 parked threads continue at their current levels with fresh
/// quanta. A new suspension ends the work before any thread is released.
///
/// # Safety
/// The cleanup queue just took the process, holding its reference.
pub(crate) unsafe fn portion(process: NonNull<Process>, level: u8) {
    let left = sched::locked(|k| {
        // SAFETY: the queue holds the process and each parked thread is
        // held by the scheduler; the lock guards their shared links.
        unsafe {
            let p = process.as_ptr();
            assert!((*p).resume_level != 0, "a continuation has no reference");
            if !(*p).suspended {
                for _ in 0..64 {
                    let Some(t) = (*p).parked.first() else { break };
                    (*p).parked.remove(t);
                    k.s.unpark(t);
                }
            }
            !(*p).suspended && (*p).parked.first().is_some()
        }
    });
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
            (*p).resume_level = 0;
            release(process, level);
        }
    }
}
