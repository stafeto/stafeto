// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The header of the data of each CPU. TPIDR_EL1 points at the CPU's block:
//! its first field is the register area of the thread running on it (what
//! TPIDR_EL1 held when the kernel had one CPU), and the entry from EL0 loads
//! that field in one more `ldr` (vectors.S). The next fields give the CPU's
//! number and the top of its kernel stack, which the way back to EL0 and
//! `on_empty_stack` read at the same offsets. Only the CPU itself writes
//! its block, but for the fields that report its start, which the CPU that
//! started it reads. The kernel's block (kernel/src/arch/cpu.rs) is this
//! header followed by what the CPU owns.

use super::user::UserRegs;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
pub use kboot::bootinfo::MAX_CPUS;

/// The bytes of one CPU's stack slot (kernel.ld): the stack, 64 KiB, and
/// the same below it for its guard page and emergency stack.
pub const SLOT: usize = 0x2_0000;

/// A CPU that has not started, and one that is up and idle or running.
pub const OFF: u32 = 0;
pub const UP: u32 = 1;

/// 64 bytes, the Exclusives Reservation Granule of the Cortex-A53 [R11]:
/// the blocks of two CPUs never share a line.
#[repr(C, align(64))]
pub struct CpuHeader {
    /// The register area of the running thread; null when none runs.
    /// Offset 0 (vectors.S).
    regs: AtomicPtr<UserRegs>,
    /// The CPU's number: 0 is the CPU that booted the kernel.
    index: AtomicU32,
    /// `OFF` until the CPU has set itself up, then `UP`, written with
    /// release after the fields below are.
    pub state: AtomicU32,
    /// The top of the CPU's kernel stack. Offset 16 (vectors.S, lib.rs).
    stack_top: AtomicUsize,
    /// MPIDR_EL1 as the CPU reads it, and the exception level it runs
    /// the kernel at (1).
    pub mpidr: AtomicU64,
    pub level: AtomicU32,
    /// Whether the CPU's own timer fired at its deadline and not before.
    pub timer_ok: AtomicU32,
    /// GICv2: the CPU interface bit of this CPU (GICD_ITARGETSR0 read by
    /// it). GICv3: the virtual address of its redistributor's RD_base
    /// frame.
    pub gic: AtomicUsize,
    /// Whether the checks of `OBJ` apply on this CPU (`obj::assert_held`):
    /// false while the code that runs is a test's or the boot's, until this
    /// CPU first leaves the kernel. Each CPU has its own, so that a test
    /// scope on one does not switch the checks off on the others. The
    /// kernel owns it; it sits in the padding of the line, so that it
    /// changes no layout.
    pub checked: AtomicBool,
}

const _: () = {
    ::core::assert!(core::mem::offset_of!(CpuHeader, regs) == 0);
    ::core::assert!(core::mem::offset_of!(CpuHeader, stack_top) == 16);
    // The header is one line: what the CPU owns starts on the next.
    ::core::assert!(core::mem::size_of::<CpuHeader>() == 64);
};

impl CpuHeader {
    pub const fn new() -> CpuHeader {
        CpuHeader {
            regs: AtomicPtr::new(core::ptr::null_mut()),
            index: AtomicU32::new(0),
            state: AtomicU32::new(OFF),
            stack_top: AtomicUsize::new(0),
            mpidr: AtomicU64::new(0),
            level: AtomicU32::new(0),
            timer_ok: AtomicU32::new(0),
            gic: AtomicUsize::new(0),
            checked: AtomicBool::new(false),
        }
    }

    pub fn index(&self) -> usize {
        self.index.load(Ordering::Relaxed) as usize
    }

    pub fn stack_top(&self) -> usize {
        self.stack_top.load(Ordering::Relaxed)
    }

    /// Fills in the number and the stack of the CPU `index`, which has not
    /// started.
    pub fn prepare(&self, index: usize) {
        self.index.store(index as u32, Ordering::Relaxed);
        self.stack_top.store(stack_top_of(index), Ordering::Relaxed);
    }

    /// Notes what the CPU that runs this reads of itself, and that it is up:
    /// the boot CPU does it for itself (`init_boot`).
    pub fn boot(&self) {
        self.mpidr
            .store(super::registers::mpidr_el1(), Ordering::Relaxed);
        self.level.store(1, Ordering::Relaxed);
        self.state.store(UP, Ordering::Release);
    }
}

impl Default for CpuHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// The top of the kernel stack of CPU `index`: the boot stack's for CPU 0,
/// then one slot (`SLOT`) further for each CPU (kernel.ld).
pub fn stack_top_of(index: usize) -> usize {
    super::symbols::boot_stack().end + index * SLOT
}

/// Makes `header` the one TPIDR_EL1 points at, on the CPU that runs this. It
/// is the first field of the kernel's block of the CPU.
pub fn attach(header: &'static CpuHeader) {
    // SAFETY: only the entry from EL0 and the functions below read TPIDR_EL1.
    unsafe {
        asm!("msr tpidr_el1, {}", in(reg) header as *const CpuHeader, options(nostack, preserves_flags))
    };
}

/// The header of the CPU that runs this. A thread of the kernel never
/// moves between CPUs mid-call, so the answer holds while it runs.
pub fn this() -> &'static CpuHeader {
    let b: usize;
    // SAFETY: reading TPIDR_EL1 has no side effects; `attach` ran on this
    // CPU before anything calls this.
    unsafe { asm!("mrs {}, tpidr_el1", out(reg) b, options(nomem, nostack, preserves_flags)) };
    // SAFETY: TPIDR_EL1 holds the address of a header.
    unsafe { &*(b as *const CpuHeader) }
}

/// The register area of the running thread; null when none runs.
pub fn current() -> *mut UserRegs {
    this().regs.load(Ordering::Relaxed)
}

/// Makes no thread the running one.
pub fn clear_current() {
    this().regs.store(core::ptr::null_mut(), Ordering::Relaxed);
}
