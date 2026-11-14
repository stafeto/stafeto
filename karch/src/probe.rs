// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Fault probes for `cargo xtask test`: an undefined instruction, so the
//! test can check the exception report (class, registers, backtrace), and a
//! recursion without end, so it can check the report of a stack overflow.

#[cfg(feature = "fault-probe")]
#[inline(never)]
pub fn undefined_instruction() {
    // SAFETY: the exception handler reports the fault and stops the kernel.
    unsafe { core::arch::asm!("udf #0") };
}

/// Calls itself until the kernel stack overflows into its guard page. xtask
/// looks this function up by name in the ELF.
#[cfg(feature = "overflow-probe")]
#[expect(unconditional_recursion, reason = "the probe must overflow the stack")]
#[inline(never)]
pub fn recurse(depth: u64) -> u64 {
    // Stack that the optimiser cannot drop, small enough to be stored by
    // this function's own instructions (no memcpy call that could take the
    // fault instead), and work after the call, so it is not a tail call.
    let frame = core::hint::black_box([depth; 4]);
    recurse(depth + 1).wrapping_add(frame[3])
}
