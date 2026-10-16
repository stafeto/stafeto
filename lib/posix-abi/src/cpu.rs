// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! CPU time and the nice value (XSH getrusage, times, clock_gettime of the
//! CPU-time clocks, getpriority, setpriority; spec 2, 3.5).
//!
//! The kernel counts the counter ticks each thread has run and sums them for
//! its process (object_info THREAD_STATE x5 and PROCESS_TIME), idle time and
//! cleanup not included. The process service adds the time of each child
//! that is waited for to its parent's account (Method::Account), and keeps
//! the nice value of each process, which its children inherit. All of a
//! process's time counts as user time: the kernel does not tell the time of
//! a thread in a system call from the rest.

use crate::constants::*;
use proto_process::{Method, account_op};
use rt::handle::{Handle, Thread};
use rt::sys;

/// The id of the clock of thread `id` (the number the layer gives it):
/// pthread_getcpuclockid. A CPU-time clock of another process is not given.
pub const fn thread_clock(id: u64) -> i32 {
    (id << 3 | 6) as i32
}

/// The id of the CPU-time clock of the calling process.
pub const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
/// The id of the CPU-time clock of the calling thread.
pub const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

/// The nanoseconds `ticks` of the counter make.
fn ns(ticks: u64) -> u64 {
    rt::time::ticks_to_ns(ticks)
}

/// The time the calling process's threads have run, ns.
pub fn process_ns() -> Result<u64, i32> {
    sys::process_time(crate::allocation::process())
        .map(ns)
        .map_err(|_| EIO)
}

/// The time the calling thread has run, ns.
pub fn thread_ns() -> Result<u64, i32> {
    let block = crate::threads::own_block();
    let thread = Handle::<Thread>::borrowed(rt::abi::Handle(
        block.thread.load(core::sync::atomic::Ordering::Relaxed),
    ));
    sys::thread_ran(&thread).map(ns).map_err(|_| EIO)
}

/// The time thread `id` has run, ns (ESRCH for one that is gone).
pub fn thread_ns_of(id: u64) -> Result<u64, i32> {
    if id == crate::threads::thread_number() {
        return thread_ns();
    }
    crate::relibc::with_target(id, |_, native| {
        sys::thread_ran(native).map(ns).map_err(|_| ESRCH)
    })?
}

/// The time the children that were waited for ran, theirs included, ns.
pub fn children_ns() -> Result<u64, i32> {
    let w = crate::process::request(Method::Account, &[account_op::CHILD_TIMES])?;
    crate::process::ask_value(&w).map(ns)
}

/// getpriority: the nice value of the process(es) `which` and `who` name.
pub fn nice_get(which: u32, who: u32) -> Result<i32, i32> {
    let w = crate::process::request(Method::Account, &[account_op::NICE_GET, which, who])?;
    crate::process::ask(&w).map(|value| value as i32)
}

/// setpriority: `nice` for the process(es) `which` and `who` name.
pub fn nice_set(which: u32, who: u32, nice: i32) -> Result<(), i32> {
    let w = crate::process::request(
        Method::Account,
        &[account_op::NICE_SET, which, who, nice as u32],
    )?;
    crate::process::ask(&w).map(drop)
}
