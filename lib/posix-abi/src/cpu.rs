// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! CPU time and the nice value (XSH getrusage, times, clock_gettime of the
//! CPU-time clocks, getpriority, setpriority; spec 2, 3.5).
//!
//! The kernel counts the counter ticks each thread has run and sums them for
//! its process (object_info THREAD_STATE x5 and PROCESS_TIME), idle time and
//! cleanup not included. The process service adds the time of each child
//! that is waited for to its parent's account (Method::Account), and keeps
//! the nice value of each process, which its children inherit. The kernel
//! tells the part of the time spent in it, from each entry from EL0 to the
//! decision that sends a thread back (THREAD_STATE x6, PROCESS_TIME x2):
//! that is the system time (`process_split_ns`, `thread_split_ns`,
//! `children_split_ns` give user and system time) and the rest is the user
//! time. CPU-time clocks and `clock` count both.
//!
//! The child of a fork starts its account at zero: `after_fork` keeps the
//! time its loader and its binding took as the start, here and in the
//! service. The loader of a posix_spawn child is the load of its own image
//! and counts for it.

use crate::constants::*;
use core::sync::atomic::{AtomicU64, Ordering};
use proto_process::{Method, account_op};
use rt::handle::{Handle, Thread};
use rt::sys;

/// The process time (ticks) and the part of it spent in the kernel that
/// the process had when `after_fork` ran: the loader's work of building
/// the child is behind it, and the child's own account starts from here.
static BASE_TICKS: AtomicU64 = AtomicU64::new(0);
static BASE_KERNEL: AtomicU64 = AtomicU64::new(0);
/// The same for the main thread of the child, which is its loader's thread:
/// its number, and the ticks and the kernel part it had run.
static BASE_THREAD: AtomicU64 = AtomicU64::new(0);
static BASE_THREAD_TICKS: AtomicU64 = AtomicU64::new(0);
static BASE_THREAD_KERNEL: AtomicU64 = AtomicU64::new(0);

/// The start of the account of thread `id`: what it ran before the child
/// bound its layer (the main thread only), ticks and the part in the kernel.
fn thread_base(id: u64) -> (u64, u64) {
    if id != 0 && id == BASE_THREAD.load(Ordering::Relaxed) {
        (
            BASE_THREAD_TICKS.load(Ordering::Relaxed),
            BASE_THREAD_KERNEL.load(Ordering::Relaxed),
        )
    } else {
        (0, 0)
    }
}

/// The account of the child of a fork starts at zero (XSH fork, times,
/// clock): the process's time so far, the work of its loader, is taken as
/// the start. The process service keeps the same start for what the parent
/// and `ps` see. Called in the child at the end of its binding, before the
/// program runs; what a parent's copy of the numbers held goes first.
pub fn after_fork() {
    BASE_TICKS.store(0, Ordering::Relaxed);
    BASE_KERNEL.store(0, Ordering::Relaxed);
    BASE_THREAD.store(0, Ordering::Relaxed);
    BASE_THREAD_TICKS.store(0, Ordering::Relaxed);
    BASE_THREAD_KERNEL.store(0, Ordering::Relaxed);
    let Ok((ticks, kernel)) = sys::process_times(crate::allocation::process()) else {
        return;
    };
    let kernel = kernel.min(ticks);
    BASE_TICKS.store(ticks, Ordering::Relaxed);
    BASE_KERNEL.store(kernel, Ordering::Relaxed);
    let block = crate::threads::own_block();
    let thread = Handle::<Thread>::borrowed(rt::abi::Handle(block.thread.load(Ordering::Relaxed)));
    if let (Ok(ran), Ok((all, in_kernel))) = (sys::thread_ran(&thread), sys::thread_times(&thread))
    {
        BASE_THREAD_TICKS.store(ran, Ordering::Relaxed);
        BASE_THREAD_KERNEL.store(in_kernel.min(all), Ordering::Relaxed);
        BASE_THREAD.store(crate::threads::thread_number(), Ordering::Relaxed);
    }
    // The service leaves it out of its own account of this process.
    if let Ok(mut w) = crate::process::request(Method::Account, &[account_op::FORK_BASE]) {
        if w.u64(ticks).is_ok() && w.u64(kernel).is_ok() {
            let _ = crate::process::ask(&w);
        }
    }
}

/// The id of the clock of thread `id` (the number the layer gives it):
/// pthread_getcpuclockid. A CPU-time clock of another process is not given.
pub const fn thread_clock(id: u64) -> i32 {
    (id << 3 | 6) as i32
}

/// The id of the CPU-time clock of the calling process.
pub const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
/// The id of the CPU-time clock of the calling thread.
pub const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

/// The id of the CPU-time clock of the process `pid`, another than the
/// caller's (clock_getcpuclockid).
pub const fn process_clock(pid: u32) -> i32 {
    ((pid as u64) << 3 | 5) as i32
}

/// The time process `pid` has run, ns: the process service answers for a
/// process the caller may signal (EPERM, ESRCH otherwise).
pub fn process_ns_of(pid: u32) -> Result<u64, i32> {
    let w = crate::process::request(Method::Account, &[account_op::PROCESS_TIME, pid])?;
    crate::process::ask_value(&w).map(ns)
}

/// The nanoseconds `ticks` of the counter make.
fn ns(ticks: u64) -> u64 {
    rt::time::ticks_to_ns(ticks)
}

/// The time the calling process's threads have run, ns.
pub fn process_ns() -> Result<u64, i32> {
    sys::process_time(crate::allocation::process())
        .map(|ticks| ns(ticks.saturating_sub(BASE_TICKS.load(Ordering::Relaxed))))
        .map_err(|_| EIO)
}

/// The time the calling thread has run, ns.
pub fn thread_ns() -> Result<u64, i32> {
    let block = crate::threads::own_block();
    let thread = Handle::<Thread>::borrowed(rt::abi::Handle(
        block.thread.load(core::sync::atomic::Ordering::Relaxed),
    ));
    let base = thread_base(crate::threads::thread_number()).0;
    sys::thread_ran(&thread)
        .map(|ticks| ns(ticks.saturating_sub(base)))
        .map_err(|_| EIO)
}

/// The time thread `id` has run, ns (ESRCH for one that is gone).
pub fn thread_ns_of(id: u64) -> Result<u64, i32> {
    if id == crate::threads::thread_number() {
        return thread_ns();
    }
    crate::relibc::with_target(id, |_, native| {
        let base = thread_base(id).0;
        sys::thread_ran(native)
            .map(|ticks| ns(ticks.saturating_sub(base)))
            .map_err(|_| ESRCH)
    })?
}

/// The user and the system time of the calling process, ns.
pub fn process_split_ns() -> Result<(u64, u64), i32> {
    sys::process_times(crate::allocation::process())
        .map(|(ticks, kernel)| {
            split((
                ticks.saturating_sub(BASE_TICKS.load(Ordering::Relaxed)),
                kernel.saturating_sub(BASE_KERNEL.load(Ordering::Relaxed)),
            ))
        })
        .map_err(|_| EIO)
}

/// The user and the system time of the calling thread, ns.
pub fn thread_split_ns() -> Result<(u64, u64), i32> {
    let block = crate::threads::own_block();
    let thread = Handle::<Thread>::borrowed(rt::abi::Handle(
        block.thread.load(core::sync::atomic::Ordering::Relaxed),
    ));
    let (base, base_kernel) = thread_base(crate::threads::thread_number());
    sys::thread_times(&thread)
        .map(|(ticks, kernel)| {
            split((
                ticks.saturating_sub(base),
                kernel.saturating_sub(base_kernel),
            ))
        })
        .map_err(|_| EIO)
}

/// The user and the system time of the children that were waited for,
/// theirs included, ns.
pub fn children_split_ns() -> Result<(u64, u64), i32> {
    let w = crate::process::request(Method::Account, &[account_op::CHILD_TIMES])?;
    crate::process::ask_pair(&w).map(|[ticks, kernel]| split((ticks, kernel)))
}

/// User and system time in nanoseconds from the whole in ticks and the
/// part of it spent in the kernel.
fn split((ticks, kernel): (u64, u64)) -> (u64, u64) {
    let kernel = kernel.min(ticks);
    (ns(ticks - kernel), ns(kernel))
}

/// The time the children that were waited for ran, theirs included, ns.
pub fn children_ns() -> Result<u64, i32> {
    let w = crate::process::request(Method::Account, &[account_op::CHILD_TIMES])?;
    crate::process::ask_pair(&w).map(|[ticks, _]| ns(ticks))
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
