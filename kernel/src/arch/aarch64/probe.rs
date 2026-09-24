// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Fault probe for `cargo xtask test`: an undefined instruction, so the test
//! can check the exception report (class, registers, backtrace).

#[inline(never)]
pub fn undefined_instruction() {
    // SAFETY: the exception handler reports the fault and stops the kernel.
    unsafe { core::arch::asm!("udf #0") };
}
