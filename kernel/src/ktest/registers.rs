// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! System registers only the kernel tests read, and the address
//! translations they look up, beside the kernel's own readers.

pub use crate::arch::registers::*;

pub fn sctlr_el1() -> u64 {
    read_sysreg!("sctlr_el1")
}

pub fn cpacr_el1() -> u64 {
    read_sysreg!("cpacr_el1")
}

pub fn cntkctl_el1() -> u64 {
    read_sysreg!("cntkctl_el1")
}

pub fn mdscr_el1() -> u64 {
    read_sysreg!("mdscr_el1")
}

/// Only where kcore::sysreg::has_pmu says the register exists.
pub fn pmuserenr_el0() -> u64 {
    read_sysreg!("pmuserenr_el0")
}

pub fn tcr_el1() -> u64 {
    read_sysreg!("tcr_el1")
}

pub fn current_el() -> u64 {
    (read_sysreg!("CurrentEL") >> 2) & 3
}

pub fn ttbr1_el1() -> u64 {
    read_sysreg!("ttbr1_el1")
}

/// PAR_EL1 after a stage-1 EL1 read translation of `va`; bit 0 set means it faults.
pub fn at_s1e1r(va: usize) -> u64 {
    let par: u64;
    // SAFETY: address translation instructions only update PAR_EL1.
    unsafe {
        core::arch::asm!("at s1e1r, {va}", "isb", "mrs {par}, par_el1", va = in(reg) va, par = out(reg) par, options(nostack, preserves_flags))
    };
    par
}

/// PAR_EL1 after a stage-1 EL1 write translation of `va`.
pub fn at_s1e1w(va: usize) -> u64 {
    let par: u64;
    // SAFETY: as in `at_s1e1r`.
    unsafe {
        core::arch::asm!("at s1e1w, {va}", "isb", "mrs {par}, par_el1", va = in(reg) va, par = out(reg) par, options(nostack, preserves_flags))
    };
    par
}

/// PAR_EL1 after a stage-1 translation of `va` for an EL0 read: EL0's
/// rights, looked up from EL1.
pub fn at_s1e0r(va: usize) -> u64 {
    let par: u64;
    // SAFETY: as in `at_s1e1r`.
    unsafe {
        core::arch::asm!("at s1e0r, {va}", "isb", "mrs {par}, par_el1", va = in(reg) va, par = out(reg) par, options(nostack, preserves_flags))
    };
    par
}

/// PAR_EL1 after a stage-1 translation of `va` for an EL0 write.
pub fn at_s1e0w(va: usize) -> u64 {
    let par: u64;
    // SAFETY: as in `at_s1e1r`.
    unsafe {
        core::arch::asm!("at s1e0w, {va}", "isb", "mrs {par}, par_el1", va = in(reg) va, par = out(reg) par, options(nostack, preserves_flags))
    };
    par
}
