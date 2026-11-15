// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel call that makes a time budget with the ring length of
//! SCHED_SPORADIC (`budget_create` x6, plan "forms of the calls frozen in
//! 0.5"). `rt::sys::budget_create` carries x0 to x4; this is the one place
//! that passes x6, so that moving onto the kernel part that reads it is a
//! change of this file alone.

use rt::Handle;
use rt::abi::{Call, Error, Handle as Raw};
use rt::handle::{Budget, Resource};

/// A budget of `c_ns` for each `t_ns` on `cpu`, falling to level `low`
/// when spent, with `max_repl` pending replenishments (1 to 4).
pub fn create(
    resource: &Handle<Resource>,
    cpu: u32,
    c_ns: u64,
    t_ns: u64,
    low: u8,
    max_repl: u32,
) -> Result<Handle<Budget>, Error> {
    let mut x = [0u64; 10];
    x[0] = resource.raw().0;
    x[1] = u64::from(cpu);
    x[2] = c_ns;
    x[3] = t_ns;
    x[4] = u64::from(low);
    x[6] = u64::from(max_repl);
    // SAFETY: budget_create reads registers alone and touches no memory of
    // this program.
    let x = unsafe { rt::sys::raw::<{ Call::BudgetCreate.number() }>(x) };
    match Error::from_code(x[0]) {
        None => Ok(Handle::from_raw(Raw(x[1]))),
        Some(e) => Err(e),
    }
}
