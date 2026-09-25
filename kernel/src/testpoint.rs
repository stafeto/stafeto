// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Test points: the places where the kernel tests (crate::ktest) watch or
//! steer the kernel from inside (spec 15.2). Kernel modules call them with
//! no cfg of their own. The build that ships gets the empty versions below,
//! which compile to nothing; the test build hands each call to the tests.
//! A point's arguments are computed in every build, so a caller passes
//! only values it already holds.

pub use points::*;

/// The build that ships: no point does anything.
#[cfg(not(feature = "ktest"))]
mod points {
    use crate::thread::Thread;
    use core::ptr::NonNull;

    /// After each portion of cleanup (cleanup::portion).
    #[inline(always)]
    pub fn portion_done() {}

    /// After a portion of the stage Close of a channel or of the stage
    /// Replies of a process (channel::clean, process::clean): the level it
    /// ran at and the heads it took.
    #[inline(always)]
    pub fn heads_taken(_: u8, _: usize) {}

    /// After the scheduler's part of the timer's interrupt
    /// (interrupt::handle).
    #[inline(always)]
    pub fn timer_fired() {}

    /// Before the kernel sleeps in `wfi` with nothing to run (sched::sleep).
    #[inline(always)]
    pub fn idle() {}

    /// Whether a fault at EL0 ends its process as spec 7.9 says
    /// (exceptions::user_fault): always.
    #[inline(always)]
    pub fn expects_fault() -> bool {
        true
    }

    /// Whether a test took system call `number` of `thread` before its
    /// dispatch (syscall::dispatch): never.
    #[inline(always)]
    pub fn test_call(_: NonNull<Thread>, _: u16) -> bool {
        false
    }

    /// Init ended (process::init_ended); the kernel then turns the machine
    /// off or stops it.
    #[inline(always)]
    pub fn init_ended() {}

    /// Whether send takes its fast path, whose conditions hold
    /// (channel::send, spec 6.4): always.
    #[inline(always)]
    pub fn fast_path() -> bool {
        true
    }

    /// Whether a BRK with immediate `imm` in kernel code is a test's marker
    /// to step over (exceptions::handle_exception): never, so every BRK
    /// stops the kernel.
    #[inline(always)]
    pub fn skip_brk(_: u16) -> bool {
        false
    }
}

/// The test build: each point goes to the tests.
#[cfg(feature = "ktest")]
mod points {
    use crate::ktest::{self, el0};
    use crate::thread::Thread;
    use core::ptr::NonNull;

    pub fn portion_done() {
        el0::portion_done();
    }

    pub fn heads_taken(level: u8, heads: usize) {
        el0::heads_taken(level, heads);
    }

    pub fn timer_fired() {
        el0::timer_fired();
    }

    pub fn idle() {
        el0::note_idle_stack();
    }

    pub fn expects_fault() -> bool {
        el0::expects_fault()
    }

    pub fn test_call(thread: NonNull<Thread>, number: u16) -> bool {
        abi::TEST_CALLS.contains(&number) && el0::syscall(thread, number)
    }

    /// The running test judges init's end, and the tests go on: this never
    /// returns.
    pub fn init_ended() {
        el0::init_ended()
    }

    pub fn skip_brk(imm: u16) -> bool {
        ktest::brk(imm)
    }

    /// The tests count the fast path's hits and may turn it off.
    pub fn fast_path() -> bool {
        el0::fast_path()
    }
}
