// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exception entry for milestone 1. Every exception is reported and stops the
//! kernel, except BRK from kernel code: it is recorded and skipped, which the
//! tests use to prove the vectors and the return path work.

use super::registers;
use core::sync::atomic::{AtomicU64, Ordering};

/// Registers saved by vectors.S, in its layout.
#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr: u64,
    pub spsr: u64,
}

const _: () = assert!(core::mem::size_of::<TrapFrame>() == 272);

const VECTOR_NAMES: [&str; 16] = [
    "EL1t sync", "EL1t irq", "EL1t fiq", "EL1t serror",
    "EL1h sync", "EL1h irq", "EL1h fiq", "EL1h serror",
    "EL0 sync", "EL0 irq", "EL0 fiq", "EL0 serror",
    "EL0 AArch32 sync", "EL0 AArch32 irq", "EL0 AArch32 fiq", "EL0 AArch32 serror",
];
const VECTOR_EL1H_SYNC: u64 = 4;
/// ESR_EL1.EC of a BRK instruction in AArch64 state.
const EC_BRK64: u64 = 0x3C;

/// Immediate of the last BRK executed by kernel code.
pub static LAST_BRK: AtomicU64 = AtomicU64::new(u64::MAX);

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

#[unsafe(no_mangle)]
extern "C" fn handle_exception(frame: &mut TrapFrame, index: u64) {
    let esr = registers::esr_el1();
    let ec = esr >> 26;
    if index == VECTOR_EL1H_SYNC && ec == EC_BRK64 {
        LAST_BRK.store(esr & 0xFFFF, Ordering::Relaxed);
        // A BRK exception returns to the BRK itself; step over it.
        frame.elr += 4;
        return;
    }
    let far = registers::far_el1();
    panic!(
        "unexpected exception {}: ESR={esr:#x} (EC {ec:#x}) ELR={:#x} FAR={far:#x} SPSR={:#x}",
        VECTOR_NAMES[(index & 15) as usize],
        frame.elr,
        frame.spsr
    );
}
