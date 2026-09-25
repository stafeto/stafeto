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

#[cfg(feature = "ktest")]
pub fn ttbr1_el1() -> u64 {
    read_sysreg!("ttbr1_el1")
}

/// PAR_EL1 after a stage-1 EL1 read translation of `va`; bit 0 set means it faults.
#[cfg(feature = "ktest")]
pub fn at_s1e1r(va: usize) -> u64 {
    let par: u64;
    // SAFETY: address translation instructions only update PAR_EL1.
    unsafe {
        core::arch::asm!("at s1e1r, {va}", "isb", "mrs {par}, par_el1", va = in(reg) va, par = out(reg) par, options(nostack, preserves_flags))
    };
    par
}

/// PAR_EL1 after a stage-1 EL1 write translation of `va`.
#[cfg(feature = "ktest")]
pub fn at_s1e1w(va: usize) -> u64 {
    let par: u64;
    // SAFETY: as in `at_s1e1r`.
    unsafe {
        core::arch::asm!("at s1e1w, {va}", "isb", "mrs {par}, par_el1", va = in(reg) va, par = out(reg) par, options(nostack, preserves_flags))
    };
    par
}
