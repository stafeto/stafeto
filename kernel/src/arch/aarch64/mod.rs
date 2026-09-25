// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

pub mod backtrace;
pub mod cache;
pub mod exceptions;
pub mod gic;
pub mod mmu;
#[cfg(any(feature = "fault-probe", feature = "overflow-probe"))]
pub mod probe;
pub mod registers;
#[cfg(feature = "ktest")]
pub mod semihosting;
pub mod symbols;
pub mod timer;
pub mod user;

core::arch::global_asm!(include_str!("head.S"), options(raw));
core::arch::global_asm!(include_str!("vectors.S"), options(raw));
core::arch::global_asm!(include_str!("mmu.S"), options(raw));
core::arch::global_asm!(include_str!("fpsimd.S"), options(raw));

/// True while an IRQ is pending at this CPU (ISR_EL1.I, bit 7), which it is
/// also while PSTATE masks it: long kernel operations poll this between
/// their portions (spec 7.7).
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "long operations (milestone 1.3) poll it; so far only the kernel tests do"
    )
)]
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
            "adrp x1, boot_stack_top",
            "add x1, x1, :lo12:boot_stack_top",
            "mov sp, x1",
            "mov x29, xzr",
            "mov x30, xzr",
            "br x0",
            in("x0") f,
            options(noreturn),
        )
    }
}
