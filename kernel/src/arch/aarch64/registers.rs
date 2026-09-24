// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Reads of system registers.

macro_rules! read_sysreg {
    ($name:literal) => {{
        let v: u64;
        // SAFETY: reading this system register at EL1 has no side effects.
        unsafe { core::arch::asm!(concat!("mrs {}, ", $name), out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }};
}

pub fn esr_el1() -> u64 {
    read_sysreg!("esr_el1")
}

pub fn far_el1() -> u64 {
    read_sysreg!("far_el1")
}

#[cfg(feature = "ktest")]
pub fn sctlr_el1() -> u64 {
    read_sysreg!("sctlr_el1")
}

#[cfg(feature = "ktest")]
pub fn ttbr0_el1() -> u64 {
    read_sysreg!("ttbr0_el1")
}

#[cfg(feature = "ktest")]
pub fn current_el() -> u64 {
    (read_sysreg!("CurrentEL") >> 2) & 3
}
