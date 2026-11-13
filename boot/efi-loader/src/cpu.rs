// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The processor's side of the hand-over: the registers the summary prints,
//! the clean by address, and the trampoline that switches the MMU off and
//! enters the kernel the way U-Boot's `booti` does (the note, 2.1 and 2.2).

use core::arch::{asm, global_asm};

pub fn current_el() -> u64 {
    let v: u64;
    // SAFETY: reads a system register.
    unsafe { asm!("mrs {}, CurrentEL", out(reg) v, options(nomem, nostack, preserves_flags)) };
    (v >> 2) & 3
}

pub fn mpidr() -> u64 {
    let v: u64;
    // SAFETY: reads a system register.
    unsafe { asm!("mrs {}, mpidr_el1", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// SCTLR of the current level (EL1 or EL2).
pub fn sctlr() -> u64 {
    let v: u64;
    // SAFETY: reads the system register of the level the loader runs at.
    unsafe {
        if current_el() == 2 {
            asm!("mrs {}, sctlr_el2", out(reg) v, options(nomem, nostack, preserves_flags));
        } else {
            asm!("mrs {}, sctlr_el1", out(reg) v, options(nomem, nostack, preserves_flags));
        }
    }
    v
}

/// HCR_EL2, which only EL2 may read.
pub fn hcr_el2() -> u64 {
    let v: u64;
    // SAFETY: called at EL2 only.
    unsafe { asm!("mrs {}, hcr_el2", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub fn cntfrq() -> u64 {
    let v: u64;
    // SAFETY: reads a system register.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub fn id_aa64mmfr0() -> u64 {
    let v: u64;
    // SAFETY: reads a system register.
    unsafe {
        asm!("mrs {}, id_aa64mmfr0_el1", out(reg) v, options(nomem, nostack, preserves_flags))
    };
    v
}

/// Cleans and invalidates `[base, base + len)` to the point of coherency by
/// address, with the line size of `CTR_EL0.DminLine`, then `dsb sy` (the
/// note, 2.2 item 4, G18). Operations by set and way are not used: they are
/// not reliable under a hypervisor.
///
/// # Safety
/// The range lies in memory the loader may touch.
pub unsafe fn clean_range(base: u64, len: u64) {
    let ctr: u64;
    // SAFETY: reads a system register.
    unsafe { asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack, preserves_flags)) };
    let line = 4u64 << ((ctr >> 16) & 0xf);
    let mut at = base & !(line - 1);
    while at < base + len {
        // SAFETY: a clean of a line inside the range.
        unsafe { asm!("dc civac, {}", in(reg) at, options(nostack, preserves_flags)) };
        at += line;
    }
    // SAFETY: a barrier.
    unsafe { asm!("dsb sy", options(nostack, preserves_flags)) };
}

// The trampoline uses registers only: with the MMU off, data accesses are
// Device-nGnRnE and a stack access would be unaligned-faulty (G12). It
// masks the interrupts, stops both timers (the firmware may have left its
// tick on, G28), clears SCTLR.M and SCTLR.C at the current level and keeps
// SCTLR.I, invalidates the instruction cache, and jumps with x0 = the tree
// and x1 = x2 = x3 = 0 (Linux booting.rst, G1, G3).
global_asm!(
    r#"
    .section .text.stafeto_enter, "ax"
    .balign 64
    .global stafeto_enter
stafeto_enter:
    mov     x16, x0
    mov     x17, x1
    msr     daifset, #0xf
    msr     cntv_ctl_el0, xzr
    msr     cntp_ctl_el0, xzr
    mov     x6, #5
    mrs     x4, CurrentEL
    lsr     x4, x4, #2
    cmp     x4, #2
    b.eq    1f
    mrs     x5, sctlr_el1
    bic     x5, x5, x6
    msr     sctlr_el1, x5
    b       2f
1:  mrs     x5, sctlr_el2
    bic     x5, x5, x6
    msr     sctlr_el2, x5
2:  isb
    ic      iallu
    dsb     nsh
    isb
    mov     x0, x17
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    br      x16
    .global stafeto_enter_end
stafeto_enter_end:
"#
);

unsafe extern "C" {
    fn stafeto_enter(entry: u64, dtb: u64) -> !;
    static stafeto_enter_end: u8;
}

/// The trampoline's bytes, for the clean.
pub fn trampoline() -> (u64, u64) {
    let start = stafeto_enter as *const () as u64;
    let end = core::ptr::addr_of!(stafeto_enter_end) as u64;
    (start & !63, end - (start & !63))
}

/// Enters the kernel at `entry` with the tree at `dtb`.
///
/// # Safety
/// Boot services are gone, the kernel and the tree are in place and clean.
pub unsafe fn enter_kernel(entry: u64, dtb: u64) -> ! {
    // SAFETY: the caller's.
    unsafe { stafeto_enter(entry, dtb) }
}
