// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel time budget of a service's request thread (spec 8): init makes it from the
//! record's table entry and gives it in the start data under the name `serve`; the service
//! binds it to the thread that runs its loop before that thread serves anything. The thread
//! then runs at its own level for at most C of each period T and at the record's `low` level
//! for the rest, so the levels below the service keep what its budget leaves, however much
//! its clients ask. A budget the kernel refuses (its CPU is not the thread's) is an error:
//! the thread would run without a limit, so the service does not start.

use crate::handle::{Budget, Thread};
use crate::startup::Startup;
use crate::{Handle, sys};

/// The name of the request thread's budget in the start data (init's table, `Budget::name`).
pub const SERVE: &str = "serve";

/// The budget init gave under `name`, if any: a record with none (a table with no budget for
/// the service) runs unbudgeted.
pub fn take(start: &mut Startup, name: &str) -> Option<Handle<Budget>> {
    start.take::<Budget>(name).ok()
}

/// Binds `budget`, if there is one, to `thread`, which has not begun to serve: the kernel
/// keeps the budget for the life of the thread, so the handle may go. The result is told in
/// a line, `<service>: <what> runs under its budget`, which the probes require. Err when the
/// kernel refuses the budget.
pub fn bind(
    service: &str,
    what: &str,
    budget: Option<Handle<Budget>>,
    thread: &Handle<Thread>,
) -> Result<(), abi::Error> {
    let Some(budget) = budget else {
        crate::println!("{service}: {what} has no budget");
        return Ok(());
    };
    match sys::thread_bind_budget(thread, &budget) {
        Ok(()) => {
            crate::println!("{service}: {what} runs under its budget");
            Ok(())
        }
        Err(e) => {
            crate::println!("{service}: the budget of {what} is refused: {e:?}");
            Err(e)
        }
    }
}
