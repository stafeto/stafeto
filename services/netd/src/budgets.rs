// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel time budgets of the service's threads (kernel spec 8, init's table
//! `NETD_BUDGETS`). Init makes them and gives them in the start data: `switch` for the switch
//! thread and `stackN` for the stack instance on CPU N. The thread that has one runs at its
//! own level for at most its budget in each period and at level 1 for the rest of the period,
//! so the processes below the service always get what the budgets leave, however much the
//! wire and the consumers send. The thread is bound before it starts, so it never runs
//! without. The service has no pause of its own for this.

use rt::handle::{Budget, Thread};
use rt::startup::Startup;
use rt::{Handle, sys};

/// The names of the stack budgets by CPU (the names in init's table).
const STACKS: [&str; 8] = [
    "stack0", "stack1", "stack2", "stack3", "stack4", "stack5", "stack6", "stack7",
];

/// The budgets init gave: the switch thread's, and one for each CPU the service has an
/// instance on.
pub struct Budgets {
    switch: Option<Handle<Budget>>,
    stacks: [Option<Handle<Budget>>; STACKS.len()],
}

impl Budgets {
    /// Takes them from the start data. A record without budgets (a service with two devices)
    /// has none, and the threads run without.
    pub fn take(s: &mut Startup) -> Budgets {
        Budgets {
            switch: s.take::<Budget>("switch").ok(),
            stacks: STACKS.map(|name| s.take::<Budget>(name).ok()),
        }
    }

    /// The switch thread's.
    pub fn switch(&self) -> Option<&Handle<Budget>> {
        self.switch.as_ref()
    }

    /// The budget of the instance on CPU `cpu`.
    pub fn stack_on(&self, cpu: Option<u32>) -> Option<&Handle<Budget>> {
        self.stacks.get(cpu? as usize)?.as_ref()
    }
}

/// Binds `budget`, if there is one, to `thread`, which has not started: the kernel keeps the
/// budget for the life of the thread, so the handle may go. The result is told in a line, since
/// a thread that is not bound runs without a limit and nothing else shows it.
pub fn bind(what: &str, budget: Option<&Handle<Budget>>, thread: &Handle<Thread>) {
    let Some(budget) = budget else {
        rt::println!("net: {what} has no budget");
        return;
    };
    match sys::thread_bind_budget(thread, budget) {
        Ok(()) => rt::println!("net: {what} runs under its budget"),
        Err(e) => rt::println!("net: the budget of {what} is refused: {e:?}"),
    }
}
