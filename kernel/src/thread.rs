// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Threads (spec 4, 8, 8.1): a program's registers, FP and SIMD included,
//! its scheduling parameters and its process, in objects from a kernel
//! pool. The registers come first, so TPIDR_EL1, which points at the
//! running thread, points at them too (vectors.S). The running thread is the
//! one TPIDR_EL1 names; the kernel stack holds nothing of it. A thread
//! lives while references to it are left: handles, the one `create` hands
//! out, and the kernel's while the scheduler holds the thread; it holds a
//! reference to its process.

use crate::arch::user::{self, FpRegs, UserRegs};
use crate::mm::pages::KernelPages;
use crate::process::{self, Process};
use abi::Error;
use core::ptr::NonNull;
use kcore::sched::{Node, Schedulable, State};
use kcore::slab::Pool;
use kcore::sync::Lock;
pub use kcore::thread::Policy;

#[repr(C)]
pub struct Thread {
    /// First: TPIDR_EL1 and vectors.S reach it at the thread's address.
    pub regs: UserRegs,
    /// Saved while the thread does not run.
    pub fp: FpRegs,
    /// The priority `create` or thread_set_priority gave. The effective
    /// one, which picks the level, is in `sched`; the two differ from
    /// milestone 1.3 on, while a service works for a request (spec 6.6).
    pub base_priority: u8,
    /// What the scheduler keeps in the thread: the effective priority, the
    /// policy, the state, the rest of a quantum and the links of the ready
    /// list. Only the scheduler changes it (sched).
    pub sched: Node<Thread>,
    process: NonNull<Process>,
    /// Handles to the thread and the reference `create` hands out.
    refs: u32,
}

const _: () = assert!(core::mem::offset_of!(Thread, regs) == 0);

// SAFETY: threads are reached under the kernel's rules (spec 8.1): one
// CPU, interrupts masked inside the kernel, the pool behind a lock.
unsafe impl Send for Thread {}

// SAFETY: the node is a field of the thread and lives as long as it does.
unsafe impl Schedulable for Thread {
    fn node(this: NonNull<Thread>) -> NonNull<Node<Thread>> {
        // SAFETY: `this` points at a live thread.
        unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).sched) }
    }
}

static THREADS: Lock<Pool<Thread>> = Lock::new(Pool::new());

impl Thread {
    /// The thread's process, which the thread holds a reference to.
    pub fn process(&self) -> NonNull<Process> {
        self.process
    }
}

/// A stopped thread of `process` that will start at `entry` with stack
/// pointer `stack` and `arg` in x0, at `priority` under `policy`, once
/// sched::start makes it ready. The caller gets the first reference; the
/// thread holds one to `process`. INVALID_ARGS for a start outside the
/// lower half, a misaligned one or priority 0, NO_MEMORY when the pool
/// gets no page.
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "init (milestone 1.2c) starts the first thread; so far only the kernel tests do"
    )
)]
pub fn create(
    process: NonNull<Process>,
    entry: usize,
    stack: usize,
    arg: u64,
    priority: u8,
    policy: Policy,
) -> Result<NonNull<Thread>, Error> {
    kcore::thread::check_start(entry as u64, stack as u64, priority)?;
    let thread = Thread {
        regs: UserRegs::start(entry as u64, stack as u64, arg),
        fp: FpRegs::ZERO,
        base_priority: priority,
        sched: Node::new(priority, policy),
        process,
        refs: 1,
    };
    let thread = THREADS
        .lock()
        .alloc(&mut KernelPages, thread)
        .map_err(|_| Error::NoMemory)?;
    process::retain(process);
    Ok(thread)
}

/// Adds a reference to a live thread.
pub fn retain(mut thread: NonNull<Thread>) {
    // SAFETY: the caller holds a reference, so the thread is alive.
    let t = unsafe { thread.as_mut() };
    t.refs = t.refs.checked_add(1).expect("thread references overflow");
}

/// Drops a reference; the last one destroys the thread, which then drops
/// its reference to its process. When the thread is the running one, no
/// thread runs after it.
///
/// # Safety
/// The reference is the caller's, and the caller does not use it afterwards.
pub unsafe fn release(mut thread: NonNull<Thread>) {
    // SAFETY: the caller's reference keeps the thread alive until here.
    let t = unsafe { thread.as_mut() };
    t.refs -= 1;
    if t.refs > 0 {
        return;
    }
    assert!(
        !matches!(t.sched.state(), State::Ready | State::Running),
        "a thread the scheduler holds lost its last reference"
    );
    let process = t.process;
    if current() == Some(thread) {
        user::clear_current();
    }
    // SAFETY: that was the last reference; nothing uses the thread afterwards.
    unsafe { THREADS.lock().free(thread) };
    // SAFETY: the thread's reference to its process goes with it.
    unsafe { process::release(process) };
}

/// The thread whose registers, FP registers and address space are live:
/// the running one, or while the kernel idles the one that ran last.
pub fn current() -> Option<NonNull<Thread>> {
    NonNull::new(user::current().cast())
}

/// Runs `next` at EL0. A switch from another thread saves that one's FP
/// and SIMD registers and loads next's; TTBR0 goes to next's address space
/// unless it holds it already; then the kernel returns to EL0 with next's
/// registers. Never returns: the kernel stack starts over at the next
/// entry, and no value on the caller's stack is ever dropped, so the caller
/// holds none with a `Drop`: no lock guard, `AddressSpace` or the like.
pub fn run(next: NonNull<Thread>) -> ! {
    let prev = current();
    // SAFETY: the running thread and `next` are alive, and so are their
    // processes; the kernel touches them one at a time.
    unsafe {
        if prev != Some(next) {
            if let Some(mut prev) = prev {
                user::save_fp(&mut prev.as_mut().fp);
            }
            user::load_fp(&next.as_ref().fp);
        }
        let mut process = next.as_ref().process;
        process.as_mut().activate();
        user::enter(next.as_ptr().cast())
    }
}

/// Objects the thread pool holds now.
#[cfg(feature = "ktest")]
pub fn in_use() -> usize {
    THREADS.lock().in_use()
}
