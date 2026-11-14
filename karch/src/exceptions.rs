// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The vector table and the trap frame. vectors.S saves the registers in a
//! `TrapFrame` and calls `handle_exception` (an entry from EL1) or
//! `handle_user_exception` (an entry from EL0), which the kernel defines
//! (kernel/src/arch/exceptions.rs). An entry from EL1 that finds no room on
//! the kernel stack runs on the emergency stack and never returns.

use core::sync::atomic::AtomicBool;

/// Registers saved by vectors.S, in its layout, and the frame record that
/// links the interrupted code into backtraces.
#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr: u64,
    pub spsr: u64,
    /// SP_EL1 of the interrupted code.
    pub sp: u64,
    _padding: u64,
    pub frame_record: [u64; 2],
}

const _: () = ::core::assert!(core::mem::size_of::<TrapFrame>() == 304);

pub const VECTOR_NAMES: [&str; 16] = [
    "EL1t sync",
    "EL1t irq",
    "EL1t fiq",
    "EL1t serror",
    "EL1h sync",
    "EL1h irq",
    "EL1h fiq",
    "EL1h serror",
    "EL0 sync",
    "EL0 irq",
    "EL0 fiq",
    "EL0 serror",
    "EL0 AArch32 sync",
    "EL0 AArch32 irq",
    "EL0 AArch32 fiq",
    "EL0 AArch32 serror",
];
pub const VECTOR_EL1H_SYNC: u64 = 4;
pub const VECTOR_EL0_SYNC: u64 = 8;
pub const VECTOR_EL0_IRQ: u64 = 9;
/// Set in the vector index when the entry switched to the emergency stack.
pub const ON_EMERGENCY_STACK: u64 = 1 << 4;

/// Set by the first entry on the emergency stack. Another one starts over
/// at the top of that stack, on the frames of the first report, and may
/// fail the same way again: it stops the machine without a word.
pub static ON_EMERGENCY: AtomicBool = AtomicBool::new(false);

/// Points VBAR_EL1 at the vector table.
pub fn init() {
    // SAFETY: exception_vectors is a valid, 2 KiB aligned vector table in the
    // kernel image; the ISB makes the new VBAR take effect.
    unsafe {
        core::arch::asm!(
            "adrp {t}, exception_vectors",
            "add {t}, {t}, :lo12:exception_vectors",
            "msr vbar_el1, {t}",
            "isb",
            t = out(reg) _,
            options(nostack),
        )
    };
}
