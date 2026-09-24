// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Translation registers and the TLB: replacing the kernel's tables (TTBR1)
//! while running from them, switching TTBR0 between address spaces, and
//! TLB maintenance, with the barriers of the Arm template (DSB ISHST, TLBI,
//! DSB ISH, ISB). None of the asm here is `nomem`: each block also keeps
//! the compiler from moving table stores across it.

use super::symbols;
use core::arch::asm;
use kcore::layout::image_pa;

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
    let pa = |va: usize| image_pa(kernel_pa, va);
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

/// Writes TTBR0_EL1, root and ASID at once, and synchronizes.
///
/// # Safety
/// `ttbr` names the root of a table tree that maps user pages only and that
/// lives while TTBR0 holds it.
pub unsafe fn set_ttbr0(ttbr: u64) {
    // SAFETY: the caller vouches for the tables; the kernel runs from TTBR1.
    unsafe { asm!("msr ttbr0_el1, {}", "isb", in(reg) ttbr, options(nostack, preserves_flags)) };
}

/// Lets the table walker see earlier table stores, and the kernel touch the
/// pages they map right away. An entry that goes from invalid to valid
/// needs nothing more: the TLB never holds invalid entries.
pub fn tables_written() {
    // SAFETY: barriers have no other effect.
    unsafe { asm!("dsb ishst", "isb", options(nostack, preserves_flags)) };
}

/// Drops the TLB entry of one user page; `operand` comes from
/// kcore::asid::tlbi_page.
pub fn invalidate_page(operand: u64) {
    // SAFETY: TLB maintenance only drops cached translations.
    unsafe {
        asm!("dsb ishst", "tlbi vale1is, {}", "dsb ish", "isb", in(reg) operand, options(nostack, preserves_flags))
    };
}

/// Drops every TLB entry of one ASID, walk-cache entries included; `operand`
/// comes from kcore::asid::tlbi_asid.
pub fn invalidate_asid(operand: u64) {
    // SAFETY: as in `invalidate_page`.
    unsafe {
        asm!("dsb ishst", "tlbi aside1is, {}", "dsb ish", "isb", in(reg) operand, options(nostack, preserves_flags))
    };
}

/// Drops every EL1&0 TLB entry of this CPU.
pub fn flush_tlb() {
    // SAFETY: as in `invalidate_page`.
    unsafe {
        asm!(
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            options(nostack, preserves_flags)
        )
    };
}
