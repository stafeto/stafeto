// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Replacing the kernel's translation tables (TTBR1) while running from them.

use super::symbols;
use kcore::layout::KERNEL_VIRT;

unsafe extern "C" {
    fn switch_ttbr1(new_root: u64, identity_root: u64, empty_root: u64, trampoline: u64);
    fn ttbr1_trampoline();
}

/// Switches TTBR1 to the tables whose root is at physical address `new_root`.
///
/// # Safety
/// The new tables must map the kernel image, its stack and everything the
/// kernel touches next at the same virtual addresses as now. The caller
/// must mask interrupts (DAIF) for the duration of the call: the switch
/// runs part of the way with TTBR0 pointed at the identity map and does not
/// tolerate being re-entered. Only one CPU may be running: the TLB flushes
/// here are local (`tlbi vmalle1`, `dsb nsh`), not broadcast to other
/// cores. `kernel_pa` must be the kernel image's actual physical load
/// address, or the physical addresses computed from it are wrong.
pub unsafe fn replace_ttbr1(new_root: u64, kernel_pa: u64) {
    let pa = |va: usize| kernel_pa + (va - KERNEL_VIRT) as u64;
    let trampoline = pa(ttbr1_trampoline as *const () as usize);
    // SAFETY: head.S's identity map covers the kernel's GiB, so the trampoline
    // runs at its physical address; the caller vouches for the new tables.
    unsafe {
        switch_ttbr1(
            new_root,
            pa(symbols::identity_table()),
            pa(symbols::empty_table()),
            trampoline,
        )
    }
}
