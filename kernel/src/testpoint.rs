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

    /// In a portion of cleanup, after the item left the queue and its work
    /// was taken, before the work runs (cleanup::portion).
    #[inline(always)]
    pub fn portion_taken() {}

    /// After each section of a continuation's portion released `OBJ`, with
    /// the number of the section (process::control::portion).
    #[inline(always)]
    pub fn section_done(_: usize) {}

    /// After a portion of the stage Close of a channel or of the stage
    /// Replies of a process (channel::clean, process::clean): the level it
    /// ran at and the heads it took.
    #[inline(always)]
    pub fn heads_taken(_: u8, _: usize) {}

    /// A process at its stage Quota (process::teardown), and whether it
    /// still has children, which the stage Children should have ended.
    #[inline(always)]
    pub fn quota_stage(_: bool) {}

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

    /// Init ended (process::init_ended); the kernel then panics.
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

    /// After the instruction cache was made coherent for the code in
    /// `frames` (arch::cache::sync_icache_frames).
    #[inline(always)]
    pub fn code_synced(_: &[u64]) {}

    /// After the descriptors that let a program execute the pages of
    /// `frames` were written (process::maps).
    #[inline(always)]
    pub fn code_mapped(_: &[u64]) {}

    /// After the stores of a change to user descriptors reached the table
    /// walker (Mmu::tables_written).
    #[inline(always)]
    pub fn tables_stored() {}

    /// After the `dsb ish` that completed the TLBIs of a batch of user
    /// pages (Mmu::user_pages_invalidated).
    #[inline(always)]
    pub fn pages_invalidated() {}

    /// Before the reference of a mapping that mem_unmap took out of the
    /// table goes (process::maps).
    #[inline(always)]
    pub fn mapping_released() {}

    /// After `irq::deliver` read the binding of `line` without a lock and
    /// before it takes `OBJ`.
    #[inline(always)]
    pub fn line_read(_: u32) {}
}

/// The test build: each point goes to the tests.
#[cfg(feature = "ktest")]
mod points {
    use crate::ktest::{self, el0};
    use crate::thread::Thread;
    use core::ptr::NonNull;

    pub fn portion_done() {
        let _test = crate::obj::test_scope();
        el0::portion_done();
    }

    pub fn quota_stage(with_children: bool) {
        let _test = crate::obj::test_scope();
        ktest::quota_stage(with_children);
    }

    /// The tests that measure a portion pay one load for this point.
    #[inline(always)]
    pub fn portion_taken() {
        if ktest::calls::kill_armed() {
            ktest::calls::portion_taken();
        }
    }

    pub fn section_done(number: usize) {
        ktest::calls::section_done(number);
    }

    pub fn heads_taken(level: u8, heads: usize) {
        let _test = crate::obj::test_scope();
        el0::heads_taken(level, heads);
    }

    pub fn timer_fired() {
        let _test = crate::obj::test_scope();
        el0::timer_fired();
    }

    pub fn idle() {
        let _test = crate::obj::test_scope();
        el0::note_idle_stack();
    }

    pub fn expects_fault() -> bool {
        el0::expects_fault()
    }

    pub fn test_call(thread: NonNull<Thread>, number: u16) -> bool {
        let _test = crate::obj::test_scope();
        let test = abi::TEST_CALLS.contains(&number);
        #[cfg(feature = "measure")]
        if test {
            crate::obj::stretch_drop();
        }
        test && el0::syscall(thread, number)
    }

    /// The running test judges init's end, and the tests go on: this never
    /// returns.
    pub fn init_ended() {
        // Init ended in a section of the kernel, which the tests never
        // return to.
        if crate::obj::held() {
            crate::obj::leave();
        }
        let _test = crate::obj::test_scope();
        el0::init_ended()
    }

    pub fn skip_brk(imm: u16) -> bool {
        ktest::brk(imm)
    }

    /// The tests count the fast path's hits and may turn it off.
    pub fn fast_path() -> bool {
        el0::fast_path()
    }

    /// A test watches the order of the two (ktest::calls).
    pub fn code_synced(frames: &[u64]) {
        ktest::calls::code_synced(frames);
    }

    pub fn code_mapped(frames: &[u64]) {
        ktest::calls::code_mapped(frames);
    }

    pub fn tables_stored() {
        ktest::calls::tables_stored();
    }

    pub fn pages_invalidated() {
        ktest::calls::pages_invalidated();
    }

    pub fn mapping_released() {
        ktest::calls::mapping_released();
    }

    pub fn line_read(line: u32) {
        let _test = crate::obj::test_scope();
        ktest::calls::line_read(line);
    }
}
