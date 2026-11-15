// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel calls that bind a time budget to a thread, in the form frozen
//! for 0.5: `thread_bind_budget(x0 thread with MANAGE, x1 the new budget or
//! 0, x2 the thread's current budget or 0)`. Only x1: a bind. Only x2: the
//! budget leaves the thread (the proof is the handle of the budget). Both:
//! the thread moves to the new budget in one step. The layer reaches them
//! only through this file.

use rt::abi::Error;
use rt::handle::{Budget, Handle, Thread};

/// `new` becomes the budget of `thread`, which has none.
pub fn bind(thread: &Handle<Thread>, new: &Handle<Budget>) -> Result<(), Error> {
    rt::sys::thread_bind_budget(thread, new)
}

/// `thread` leaves `old` for `new` with no moment between.
pub fn rebind(
    thread: &Handle<Thread>,
    new: &Handle<Budget>,
    old: &Handle<Budget>,
) -> Result<(), Error> {
    rt::sys::thread_rebind_budget(thread, new, old)
}

/// `thread` leaves `old` and has none.
pub fn unbind(thread: &Handle<Thread>, old: &Handle<Budget>) -> Result<(), Error> {
    rt::sys::thread_unbind_budget(thread, old)
}
