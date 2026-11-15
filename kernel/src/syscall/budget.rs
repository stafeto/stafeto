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
use crate::session;
use crate::thread::Thread;
use abi::{BUDGET_RIGHTS, Error, MIN_BUDGET_NS, MIN_PERIOD_NS, Rights};
use core::ptr::NonNull;
use kcore::args::{cpu_arg, priority_arg};

/// The longest period: a minute, in nanoseconds, so that its ticks fit a
/// word at any counter the kernel knows.
const MAX_PERIOD_NS: u64 = 60_000_000_000;

/// budget_create(x0 system resource with BUDGET, x1 CPU, x2 budget in ns,
/// x3 period in ns, x4 the level `low`, x5 a handle with NOTIFY to a channel
/// or 0, x6 the most replenishments pending, 0 for abi::SS_REPL_MAX): a time
/// budget for the threads of the CPU (spec 8); x1 returns a handle to it with
/// abi::BUDGET_RIGHTS. A budget with x5 has a place for the notifications of
/// its overruns, which the handle's channel and label give: one notification
/// (source Budget, bit 0, bits 1-63 zero) for each overrun, overruns between
/// two firings of the event merged, at the level `low` (spec 6.5, 8); a
/// handle with no label gives label 0 to every budget made through it. Only
/// a process that holds the system resource with BUDGET can make one: at boot
/// that is init's handle alone, and init hands the right on only by a copy of
/// its own handle (spec 5.2). The checks in the order of spec 11: the values
/// (INVALID_ARGS): a CPU outside the CPUs the kernel can start, a budget below
/// abi::MIN_BUDGET_NS or above the period, a period outside
/// abi::MIN_PERIOD_NS up to a minute, a level outside 1-63, x6 above
/// abi::SS_REPL_MAX; x0 (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without
/// BUDGET), then x5 when it is not 0 (the same three errors, with NOTIFY); a
/// CPU that is not up (INVALID_ARGS); then the resources in the order the call
/// takes them: room in the caller's table (LIMIT_REACHED), a place in the
/// system's count of timers and budgets (LIMIT_REACHED), a slot of the channel
/// (LIMIT_REACHED, spec 6.5), a page of the caller's pool of budgets and a
/// block of its table (NO_MEMORY). A budget whose handle did not go in goes
/// again.
#[inline(never)]
pub(super) fn budget_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let cpu = cpu_arg(a[1], arch::cpu::MAX_CPUS)?;
    if a[2] < MIN_BUDGET_NS || a[3] < MIN_PERIOD_NS || a[2] > a[3] || a[3] > MAX_PERIOD_NS {
        return Err(Error::InvalidArgs);
    }
    let low = priority_arg(a[4])?;
    let max_repl = match a[6] {
        0 => abi::SS_REPL_MAX as u8,
        n if n <= abi::SS_REPL_MAX => n as u8,
        _ => return Err(Error::InvalidArgs),
    };
    lookup(thread, a[0], Rights::BUDGET, Object::resource)?;
    let notice = match a[5] {
        0 => None,
        h => Some(lookup(thread, h, Rights::NOTIFY, |o| {
            Some((o.channel()?, o.session().map_or(0, session::label)))
        })?),
    };
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
        max_repl,
        notice,
    )?;
    let h = process::insert_handle(caller(thread), Object::Budget(b), BUDGET_RIGHTS);
    // SAFETY: the reference `create` handed out goes; the handle, if it went
    // in, holds the budget, and without it the budget goes.
    unsafe { budget::release(b, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// thread_bind_budget(x0 thread with MANAGE, x1 a new budget with BUDGET or 0,
/// x2 the thread's budget with BUDGET or 0): the thread works under the new
/// budget from now on (spec 8): its own level while the budget lasts, the
/// budget's `low` when it is gone, and no more than the level of the process it
/// ran under while it had none. x1 = x2 = 0 is INVALID_ARGS. The checks in the
/// order of spec 11: x0, x1 and x2 when not 0 (BAD_HANDLE, WRONG_TYPE,
/// ACCESS_DENIED for missing rights); a thread of another CPU than the new
/// budget's (INVALID_ARGS); the states (BAD_STATE): a budget a thread has, a
/// thread that has a budget (x2 = 0) or ended, a thread of another CPU that
/// started. The binding holds the budget until the thread ends; closing the
/// handles takes nothing from the thread. With x2 the call gives the thread's
/// budget up, and the budget handle is the proof of it: x2 must be the budget
/// the thread has (`budget::unbind`), BAD_STATE otherwise, a thread with no
/// budget among them. With x1 = 0 the thread works at min(its base, `free` of
/// its process) from now on and the budget is free to bind again with its
/// queue of replenishments as it was; with both set the new budget replaces
/// the old in one section.
#[inline(never)]
pub(super) fn thread_bind_budget(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    if a[1] == 0 && a[2] == 0 {
        return Err(Error::InvalidArgs);
    }
    let t = lookup(thread, a[0], Rights::MANAGE, Object::thread)?;
    let new = match a[1] {
        0 => None,
        h => Some(lookup(thread, h, Rights::BUDGET, Object::budget)?),
    };
    if a[2] == 0 {
        budget::bind(t, new.ok_or(Error::InvalidArgs)?)?;
        return Ok(Values::none());
    }
    let old = lookup(thread, a[2], Rights::BUDGET, Object::budget)?;
    budget::unbind(t, old, new, cause(thread))?;
    Ok(Values::none())
}
