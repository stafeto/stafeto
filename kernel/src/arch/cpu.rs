// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The block of each CPU: the header `karch` defines (the register area of
//! the thread running on it, its number, its stack, what the interrupt
//! controller and the timer note about it) and, on the line after it, what
//! the CPU owns (local.rs), which it reaches from TPIDR_EL1 with one load or
//! store. TPIDR_EL1 points at the header, the first field of the block.

use core::sync::atomic::Ordering;
pub use karch::cpu::{CpuHeader, MAX_CPUS, SLOT, UP};

/// The block of a CPU: the header, then what the CPU owns.
#[repr(C, align(64))]
pub struct CpuBlock {
    header: CpuHeader,
    /// What the CPU owns (local.rs), on cache lines of its own after the
    /// header.
    pub local: crate::local::Local,
}

const _: () = {
    ::core::assert!(core::mem::offset_of!(CpuBlock, header) == 0);
    // The header is one line, and what the CPU owns starts on the next.
    ::core::assert!(core::mem::offset_of!(CpuBlock, local) == 64);
};

impl core::ops::Deref for CpuBlock {
    type Target = CpuHeader;

    fn deref(&self) -> &CpuHeader {
        &self.header
    }
}

impl CpuBlock {
    const fn new() -> CpuBlock {
        CpuBlock {
            header: CpuHeader::new(),
            local: crate::local::Local::new(),
        }
    }
}

static CPUS: [CpuBlock; MAX_CPUS] = [const { CpuBlock::new() }; MAX_CPUS];

/// Whether CPU `index` has set itself up and runs (spec 8).
pub fn is_up(index: usize) -> bool {
    index < MAX_CPUS && CPUS[index].state.load(Ordering::Acquire) == UP
}

/// The block of CPU `index`.
pub fn block(index: usize) -> &'static CpuBlock {
    &CPUS[index]
}

/// Fills in the block of CPU `index`, which has not started.
pub fn prepare(index: usize) -> &'static CpuBlock {
    let b = block(index);
    b.header.prepare(index);
    crate::local::init(&b.local);
    // CPU 0 takes the memory of its ring once the allocator is up.
    #[cfg(feature = "stamps")]
    if index != 0 {
        crate::stamps::init(index);
    }
    b
}

/// Makes `block` the one TPIDR_EL1 points at, on the CPU that runs this.
pub fn attach(block: &'static CpuBlock) {
    karch::cpu::attach(&block.header);
}

/// The block of the CPU that runs this. A thread of the kernel never
/// moves between CPUs mid-call, so the answer holds while it runs.
pub fn this() -> &'static CpuBlock {
    let header: *const CpuHeader = karch::cpu::this();
    // SAFETY: TPIDR_EL1 holds the address of the header of a block of CPUS,
    // the first field of a `repr(C)` struct.
    unsafe { &*header.cast::<CpuBlock>() }
}

/// CPU 0's block, for the CPU that booted: number 0, TPIDR_EL1 pointing at
/// it. Runs first in `kernel_main`.
pub fn init_boot() {
    attach(prepare(0));
    this().header.boot();
}
