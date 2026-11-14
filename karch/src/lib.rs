// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The AArch64 layer of the kernel: what touches the machine. The boot code
//! (head.S), the exception vectors (vectors.S), the MMU, the caches, the
//! registers, the GIC and the timer live here, and almost every `unsafe` of
//! the hardware with them. The crate knows no kernel object: it uses `kcore`
//! for the rules and `kboot` for the boot facts, and the kernel supplies
//! what it needs from outside through closures and the symbols the assembly
//! names (`kernel_main`, `secondary_main`, `handle_exception`,
//! `handle_user_exception`).

#![no_std]
#![deny(clippy::undocumented_unsafe_blocks)]

#[macro_use]
mod failure;

pub mod cache;
pub mod cpu;
pub mod exceptions;
pub mod gic;
#[cfg(feature = "early-marks")]
pub mod marks;
pub mod mmio;
pub mod mmu;
#[cfg(any(feature = "fault-probe", feature = "overflow-probe"))]
pub mod probe;
pub mod registers;
pub mod symbols;
pub mod timer;
pub mod user;

#[cfg(feature = "early-marks")]
core::arch::global_asm!(".equ EARLY_MARKS, 1", options(raw));
core::arch::global_asm!(include_str!("head.S"), options(raw));
core::arch::global_asm!(include_str!("vectors.S"), options(raw));
core::arch::global_asm!(include_str!("mmu.S"), options(raw));
core::arch::global_asm!(include_str!("fpsimd.S"), options(raw));

/// True while an IRQ is pending at this CPU (ISR_EL1.I, bit 7), which it is
/// also while PSTATE masks it: the way out of the kernel polls this before
/// every decision, so between two portions of cleanup too (spec 7.7).
pub fn irq_pending() -> bool {
    let isr: u64;
    // SAFETY: reading ISR_EL1 has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, isr_el1", out(reg) isr, options(nomem, nostack, preserves_flags))
    };
    isr & (1 << 7) != 0
}

/// Runs `f` on the empty kernel stack: SP goes to the top of the stack, as
/// return_to_user leaves it for the next entry, so the stack `f` finds does
/// not depend on how deep the caller was. The caller's frames are
/// abandoned and no value on them is ever dropped, so the caller holds none
/// with a `Drop`. Backtraces end at `f`.
pub fn on_empty_stack(f: extern "C" fn() -> !) -> ! {
    // SAFETY: nothing on the kernel stack is used again: `f` never returns,
    // and the caller's frames hold nothing that needs dropping.
    unsafe {
        core::arch::asm!(
            "mrs x1, tpidr_el1",
            "ldr x1, [x1, #16]", // CpuBlock::stack_top
            "mov sp, x1",
            "mov x29, xzr",
            "mov x30, xzr",
            "br x0",
            in("x0") f,
            options(noreturn),
        )
    }
}
