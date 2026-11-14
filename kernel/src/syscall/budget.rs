// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls of time budgets (spec 8, 11): budget_create and
//! thread_bind_budget.

use super::{Args, Values, caller, cause, lookup};
use crate::arch;
use crate::arch::timer as clock;
use crate::budget;
use crate::object::Object;
use crate::process;
use crate::thread::Thread;
use abi::{BUDGET_RIGHTS, Error, MIN_BUDGET_NS, MIN_PERIOD_NS, Rights};
use core::ptr::NonNull;
use kcore::args::{cpu_arg, priority_arg};

/// The longest period: a minute, in nanoseconds, so that its ticks fit a
/// word at any counter the kernel knows.
const MAX_PERIOD_NS: u64 = 60_000_000_000;

/// budget_create(x0 system resource with BUDGET, x1 CPU, x2 budget in ns,
/// x3 period in ns, x4 the level `low`): a time budget for the threads of
/// the CPU (spec 8); x1 returns a handle to it with abi::BUDGET_RIGHTS.
/// Only a process that holds the system resource with BUDGET can make
/// one: at boot that is init's handle alone, and init hands the right on
/// only by a copy of its own handle (spec 5.2). The checks in the order
/// of spec 11: the values (INVALID_ARGS): a CPU outside the CPUs the kernel
/// can start, a budget below abi::MIN_BUDGET_NS or above the period, a
/// period outside abi::MIN_PERIOD_NS up to a minute, a level outside 1-63;
/// x0 (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without BUDGET); a CPU that is
/// not up (INVALID_ARGS); then the resources in the order the call takes
/// them: room in the caller's table (LIMIT_REACHED), a place in the
/// system's count of timers and budgets (LIMIT_REACHED), a page of the
/// caller's pool of budgets and a block of its table (NO_MEMORY). A budget
/// whose handle did not go in goes again.
#[inline(never)]
pub(super) fn budget_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let cpu = cpu_arg(a[1], arch::cpu::MAX_CPUS)?;
    if a[2] < MIN_BUDGET_NS || a[3] < MIN_PERIOD_NS || a[2] > a[3] || a[3] > MAX_PERIOD_NS {
        return Err(Error::InvalidArgs);
    }
    let low = priority_arg(a[4])?;
    lookup(thread, a[0], Rights::BUDGET, Object::resource)?;
    if !arch::cpu::is_up(cpu as usize) {
        return Err(Error::InvalidArgs);
    }
    process::handle_room(caller(thread))?;
    let clock = clock::clock();
    let b = budget::create(
        caller(thread),
        cpu as u8,
        clock.ns_to_ticks(a[2]),
        clock.ns_to_ticks(a[3]),
        low,
    )?;
    let h = process::insert_handle(caller(thread), Object::Budget(b), BUDGET_RIGHTS);
    // SAFETY: the reference `create` handed out goes; the handle, if it went
    // in, holds the budget, and without it the budget goes.
    unsafe { budget::release(b, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// thread_bind_budget(x0 thread with MANAGE, x1 budget with BUDGET): the
/// thread works under the budget from now on (spec 8): its own level while
/// the budget lasts, the budget's `low` when it is gone, and no more than the
/// level of the process it ran under while it had none. The checks in the
/// order of spec 11: x0, then x1 (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED for
/// missing rights); a thread of another CPU than the budget's
/// (INVALID_ARGS); the states (BAD_STATE): a budget a thread has, a thread
/// that has a budget or ended, a thread of another CPU that started. The
/// binding holds the budget until the thread ends; closing the handles
/// takes nothing from the thread.
#[inline(never)]
pub(super) fn thread_bind_budget(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let t = lookup(thread, a[0], Rights::MANAGE, Object::thread)?;
    let b = lookup(thread, a[1], Rights::BUDGET, Object::budget)?;
    budget::bind(t, b)?;
    Ok(Values::none())
}
