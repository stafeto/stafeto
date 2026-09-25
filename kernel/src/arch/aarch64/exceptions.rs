// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exception entry. Every exception is reported with its registers and
//! stops the kernel. Test builds skip one BRK marker (kcore::esr::TEST_BRK)
//! to prove the vectors and the return path work.

use super::{registers, symbols};
use core::sync::atomic::{AtomicU64, Ordering};
use kcore::esr::{self, BrkAction};

/// Registers saved by vectors.S, in its layout, and the frame record that
/// links the interrupted code into backtraces.
#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr: u64,
    pub spsr: u64,
    pub frame_record: [u64; 2],
}

const _: () = assert!(core::mem::size_of::<TrapFrame>() == 288);

const VECTOR_NAMES: [&str; 16] = [
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
const VECTOR_EL1H_SYNC: u64 = 4;

/// Immediate of the last BRK skipped in kernel code.
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
    let syndrome = registers::esr_el1();
    if index == VECTOR_EL1H_SYNC
        && let Some(imm) = esr::brk_immediate(syndrome)
        && esr::kernel_brk_action(imm, cfg!(feature = "ktest")) == BrkAction::Skip
    {
        LAST_BRK.store(u64::from(imm), Ordering::Relaxed);
        // A BRK exception returns to the BRK itself; step over it.
        frame.elr += 4;
        return;
    }
    let far = registers::far_el1();
    let class = esr::ec(syndrome);
    if matches!(class, esr::EC_DABT_SAME | esr::EC_IABT_SAME) {
        let guard = symbols::image_layout().stack_guard as u64;
        if (guard..guard + 4096).contains(&far) {
            kprintln!("kernel stack overflow: the guard page at {guard:#x} was hit");
        }
    }
    print_frame(frame);
    if matches!(
        class,
        esr::EC_IABT_LOWER | esr::EC_IABT_SAME | esr::EC_DABT_LOWER | esr::EC_DABT_SAME
    ) {
        match esr::fault_level(syndrome) {
            Some(level) => kprintln!(
                "abort: {} at level {level}, FAR={far:#x}",
                esr::fault_status_name(syndrome)
            ),
            None => kprintln!("abort: {}, FAR={far:#x}", esr::fault_status_name(syndrome)),
        }
    }
    panic!(
        "unexpected exception {}: {} (EC {class:#x}) ESR={syndrome:#x} ELR={:#x} FAR={far:#x}",
        VECTOR_NAMES[(index & 15) as usize],
        esr::class_name(class),
        frame.elr
    );
}

fn print_frame(f: &TrapFrame) {
    for (i, v) in f.x.iter().enumerate() {
        let sep = if i % 4 == 3 { "\n" } else { "  " };
        crate::console::print(format_args!("x{i:<2} {v:#018x}{sep}"));
    }
    kprintln!(
        "\nsp_el0 {:#018x}  elr {:#018x}  spsr {:#018x}",
        f.sp_el0,
        f.elr,
        f.spsr
    );
}
