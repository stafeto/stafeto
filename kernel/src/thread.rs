// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Threads (spec 4, 8, 8.1): a program's registers, FP and SIMD included,
//! its scheduling parameters and its process, in objects from a kernel
//! pool. The registers come first, so TPIDR_EL1, which points at the
//! running thread, points at them too (vectors.S). The running thread is the
//! one TPIDR_EL1 names; the kernel stack holds nothing of it.

use crate::arch::user::{self, FpRegs, UserRegs};
use crate::mm::pages::KernelPages;
use crate::process::Process;
use abi::Error;
use core::ptr::NonNull;
use kcore::slab::Pool;
use kcore::sync::Lock;
pub use kcore::thread::Policy;

#[repr(C)]
pub struct Thread {
    /// First: TPIDR_EL1 and vectors.S reach it at the thread's address.
    pub regs: UserRegs,
    /// Saved while the thread does not run.
    pub fp: FpRegs,
    /// Stored for the scheduler of milestone 1.2c.
    pub priority: u8,
    pub policy: Policy,
    process: NonNull<Process>,
}

const _: () = assert!(core::mem::offset_of!(Thread, regs) == 0);

// SAFETY: threads are reached under the kernel's rules (spec 8.1): one
// CPU, interrupts masked inside the kernel, the pool behind a lock.
unsafe impl Send for Thread {}

static THREADS: Lock<Pool<Thread>> = Lock::new(Pool::new());

impl Thread {
    #[cfg_attr(
        not(feature = "ktest"),
        expect(
            dead_code,
            reason = "only the kernel tests ask for a thread's process so far"
        )
    )]
    pub fn process(&self) -> NonNull<Process> {
        self.process
    }
}

/// A thread of `process` that will start at `entry` with stack pointer
/// `stack` and `arg` in x0; it runs once `run` picks it. INVALID_ARGS for a
/// start outside the lower half, a misaligned one or the idle priority,
/// NO_MEMORY when the pool gets no page.
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "init (milestone 1.2c) starts the first thread; so far only the kernel tests do"
    )
)]
pub fn create(
    mut process: NonNull<Process>,
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
        priority,
        policy,
        process,
    };
    let thread = THREADS
        .lock()
        .alloc(&mut KernelPages, thread)
        .map_err(|_| Error::NoMemory)?;
    // SAFETY: the caller's process is alive; its threads keep it so.
    unsafe { process.as_mut() }.add_thread();
    Ok(thread)
}

/// Destroys a thread. When it is the running one, no thread runs after it.
///
/// # Safety
/// `thread` came from `create`, and nothing uses it afterwards.
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "thread_exit (milestone 1.2c) destroys threads; so far only the kernel tests do"
    )
)]
pub unsafe fn destroy(thread: NonNull<Thread>) {
    if current() == Some(thread) {
        user::clear_current();
    }
    // SAFETY: the caller hands over a live thread.
    let mut process = unsafe { thread.as_ref() }.process;
    // SAFETY: as above; nothing uses the thread afterwards.
    unsafe { THREADS.lock().free(thread) };
    // SAFETY: the thread's process outlives it.
    unsafe { process.as_mut() }.remove_thread();
}

/// The running thread, whose registers the last entry from EL0 saved.
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
        // TTBR0 itself says whose space it holds, whatever switched it.
        let mut process = next.as_ref().process;
        if !process.as_ref().space.is_active() {
            process.as_mut().space.activate();
        }
        user::enter(next.as_ptr().cast())
    }
}

/// Objects the thread pool holds now.
#[cfg(feature = "ktest")]
pub fn in_use() -> usize {
    THREADS.lock().in_use()
}
