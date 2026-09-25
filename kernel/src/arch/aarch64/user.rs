// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Programs at EL0 (spec 8, 8.1): the system registers that let them run,
//! the registers of a program, the FP and SIMD registers that a switch
//! between threads saves and loads, and the way back to EL0. Entry from EL0
//! is in vectors.S: it saves the registers straight into the area TPIDR_EL1
//! points at, the running thread's, and calls handle_user_exception on the
//! empty kernel stack.

use super::{mmu, registers};
use core::arch::asm;
use kcore::sysreg::{self, CNTKCTL_EL1, CPACR_EL1, MDSCR_EL1, SCTLR_EL1, SPSR_EL0T};

/// A program's registers, saved on every entry from EL0 and loaded on the
/// way back, in the layout of vectors.S (USER_*).
#[repr(C)]
pub struct UserRegs {
    pub x: [u64; 31],
    /// SP_EL0.
    pub sp: u64,
    /// ELR_EL1: where the program goes on.
    pub elr: u64,
    /// SPSR_EL1: the program's flags and PSTATE.
    pub spsr: u64,
    /// TPIDR_EL0, the program's thread pointer.
    pub tpidr: u64,
    /// TPIDRRO_EL0, which the program reads and only the kernel writes.
    pub tpidrro: u64,
}

const _: () = {
    assert!(core::mem::size_of::<UserRegs>() == 288);
    assert!(core::mem::offset_of!(UserRegs, sp) == 248);
    assert!(core::mem::offset_of!(UserRegs, elr) == 256);
    assert!(core::mem::offset_of!(UserRegs, spsr) == 264);
    assert!(core::mem::offset_of!(UserRegs, tpidr) == 272);
    assert!(core::mem::offset_of!(UserRegs, tpidrro) == 280);
};

impl UserRegs {
    /// A thread's first registers: at `entry` with stack pointer `sp` and
    /// `arg` in x0, every other register zero, EL0t with interrupts on.
    pub fn start(entry: u64, sp: u64, arg: u64) -> UserRegs {
        let mut x = [0; 31];
        x[0] = arg;
        UserRegs {
            x,
            sp,
            elr: entry,
            spsr: SPSR_EL0T,
            tpidr: 0,
            tpidrro: 0,
        }
    }
}

/// A program's FP and SIMD registers, in the layout of fpsimd.S. The
/// kernel never uses them, so they are saved and loaded only when threads
/// switch (spec 8), not on every entry.
#[repr(C, align(16))]
pub struct FpRegs {
    pub v: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}

const _: () = {
    assert!(core::mem::size_of::<FpRegs>() == 528);
    assert!(core::mem::offset_of!(FpRegs, fpcr) == 512);
    assert!(core::mem::offset_of!(FpRegs, fpsr) == 520);
};

impl FpRegs {
    /// A new thread's: every register zero, round to nearest, no
    /// exception flags.
    pub const ZERO: FpRegs = FpRegs {
        v: [0; 32],
        fpcr: 0,
        fpsr: 0,
    };
}

unsafe extern "C" {
    fn return_to_user(regs: *mut UserRegs) -> !;
    fn fp_save(regs: *mut FpRegs);
    fn fp_load(regs: *const FpRegs);
}

/// Stores the FP and SIMD registers, which hold the state of the thread
/// that ran last.
pub fn save_fp(regs: &mut FpRegs) {
    // SAFETY: fp_save writes the 528 bytes of `regs` and nothing else.
    unsafe { fp_save(regs) }
}

/// Loads the FP and SIMD registers for the thread that runs next.
pub fn load_fp(regs: &FpRegs) {
    // SAFETY: fp_load reads `regs` and changes only FP and SIMD registers,
    // which the kernel does not use.
    unsafe { fp_load(regs) }
}

/// Opens EL0 (kcore::sysreg): FP and SIMD, the virtual counter, and the
/// SCTLR_EL1 bits for programs; keeps the debug channel and the
/// performance monitors closed, whose registers are UNKNOWN after reset.
/// Runs once the kernel tables are live: WXN would take execution away from
/// head.S's writable image blocks. No thread runs yet (TPIDR_EL1 = 0).
pub fn init() {
    // SAFETY: the kernel tables map nothing writable and executable at
    // once, so WXN takes nothing the kernel executes; the ISB makes the
    // writes take effect.
    unsafe {
        asm!(
            "msr cpacr_el1, {cpacr}",
            "msr cntkctl_el1, {cntkctl}",
            "msr mdscr_el1, {mdscr}",
            "msr tpidr_el1, xzr",
            "msr sctlr_el1, {sctlr}",
            "isb",
            cpacr = in(reg) CPACR_EL1,
            cntkctl = in(reg) CNTKCTL_EL1,
            mdscr = in(reg) MDSCR_EL1,
            sctlr = in(reg) SCTLR_EL1,
            options(nostack, preserves_flags),
        )
    };
    if sysreg::has_pmu(registers::id_aa64dfr0_el1()) {
        // SAFETY: only EL0 access to the PMU changes; the ISB applies it.
        unsafe {
            asm!(
                "msr pmuserenr_el0, xzr",
                "isb",
                options(nostack, preserves_flags)
            )
        };
    }
    // TLB entries may hold the old WXN.
    mmu::flush_tlb();
}

/// The register area of the running thread (TPIDR_EL1); null when none runs.
pub fn current() -> *mut UserRegs {
    let regs: usize;
    // SAFETY: reading TPIDR_EL1 has no side effects.
    unsafe { asm!("mrs {}, tpidr_el1", out(reg) regs, options(nomem, nostack, preserves_flags)) };
    regs as *mut UserRegs
}

/// Makes no thread the running one.
pub fn clear_current() {
    // SAFETY: TPIDR_EL1 is read only by `current` and by entry from EL0,
    // which cannot happen while the kernel runs.
    unsafe {
        asm!(
            "msr tpidr_el1, xzr",
            options(nomem, nostack, preserves_flags)
        )
    };
}

/// Returns to EL0 with `regs`, which become the running thread's
/// registers. The kernel stack is dropped: the next entry from EL0 starts
/// at its top, and no value on it is ever dropped. The caller's stack
/// holds nothing with a `Drop`: no lock guard, `AddressSpace` or the like.
///
/// # Safety
/// `regs` belongs to a thread that stays alive while it runs; TTBR0 holds
/// its process's address space; its SPSR is EL0t, either from `start` or
/// as saved on entry from EL0.
pub unsafe fn enter(regs: *mut UserRegs) -> ! {
    // SAFETY: the caller vouches for the registers and the address space.
    unsafe { return_to_user(regs) }
}
