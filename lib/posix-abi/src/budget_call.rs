// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel call that binds a time budget to a thread, in the form the plan
//! freezes for 0.5: `thread_bind_budget(x0 thread with MANAGE, x1 the new
//! budget or 0, x2 the thread's current budget or 0)`. Only x1: a bind. Only
//! x2: the budget leaves the thread (the proof is the handle of the budget).
//! Both: the thread moves to the new budget in one step. `rt::sys` carries
//! x0 and x1; this is the one place that passes x2, so that moving onto the
//! kernel part that reads it is a change of this file alone. A kernel that
//! does not read x2 binds, and refuses the other two.

use rt::abi::{Call, Error};
use rt::handle::{Budget, Handle, Thread};

fn call(thread: &Handle<Thread>, new: u64, old: u64) -> Result<(), Error> {
    let mut x = [0u64; 10];
    x[0] = thread.raw().0;
    x[1] = new;
    x[2] = old;
    // SAFETY: thread_bind_budget reads registers alone and touches no memory
    // of the program.
    let x = unsafe { rt::sys::raw::<{ Call::ThreadBindBudget.number() }>(x) };
    Error::from_code(x[0]).map_or(Ok(()), Err)
}

/// `new` becomes the budget of `thread`, which has none.
pub fn bind(thread: &Handle<Thread>, new: &Handle<Budget>) -> Result<(), Error> {
    call(thread, new.raw().0, 0)
}

/// `thread` leaves `old` for `new` with no moment between.
pub fn rebind(
    thread: &Handle<Thread>,
    new: &Handle<Budget>,
    old: &Handle<Budget>,
) -> Result<(), Error> {
    call(thread, new.raw().0, old.raw().0)
}

/// `thread` leaves `old` and has none.
pub fn unbind(thread: &Handle<Thread>, old: &Handle<Budget>) -> Result<(), Error> {
    call(thread, 0, old.raw().0)
}
