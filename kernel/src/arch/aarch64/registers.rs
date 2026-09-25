// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Reads of the system registers the kernel needs.

macro_rules! read_sysreg {
    ($name:literal) => {{
        let v: u64;
        // SAFETY: reading this system register at EL1 has no side effects.
        unsafe { core::arch::asm!(concat!("mrs {}, ", $name), out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }};
}
/// The kernel tests read more registers with it (crate::ktest::registers).
#[cfg(feature = "ktest")]
pub(crate) use read_sysreg;

pub fn esr_el1() -> u64 {
    read_sysreg!("esr_el1")
}

pub fn far_el1() -> u64 {
    read_sysreg!("far_el1")
}

pub fn id_aa64dfr0_el1() -> u64 {
    read_sysreg!("id_aa64dfr0_el1")
}

pub fn ttbr0_el1() -> u64 {
    read_sysreg!("ttbr0_el1")
}

pub fn id_aa64mmfr0_el1() -> u64 {
    read_sysreg!("id_aa64mmfr0_el1")
}
