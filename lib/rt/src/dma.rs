// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Cache maintenance and barriers for a driver's DMA buffers (spec 7.3),
//! from EL0: the kernel opens `dc cvac` and `dc civac` to programs
//! (SCTLR_EL1.UCI) and CTR_EL0 (SCTLR_EL1.UCT); `dc ivac` stays closed at
//! EL0, so data a device wrote is read after `clean_invalidate`.
//!
//! A cached buffer: `clean_invalidate` before the device gets it, `clean`
//! after the program wrote what the device reads, `clean_invalidate`
//! again once the device wrote it and before the program reads it [G18].
//! Then `wmb` before the doorbell, `rmb` after reading the device's index
//! [G34].
//!
//! While the device has a cached buffer, the program does not write it:
//! a dirty line of the program's would go back over what the device wrote
//! at the next `clean_invalidate` [G18].
//!
//! An object made with abi::MEM_UNCACHED maps as Normal Non-cacheable
//! everywhere a program maps it: it needs only the barriers, never the
//! maintenance.

use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

/// The smallest data cache line in bytes, once read; 0 until then.
static LINE: AtomicUsize = AtomicUsize::new(0);

/// The smallest data cache line in bytes: `4 << CTR_EL0.DminLine[19:16]`
/// [G18], read once.
pub fn line() -> usize {
    match LINE.load(Ordering::Relaxed) {
        0 => {
            let ctr: u64;
            // SAFETY: reading CTR_EL0 has no side effects; SCTLR_EL1.UCT
            // opens it at EL0.
            unsafe {
                asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack, preserves_flags))
            };
            let line = 4 << ((ctr >> 16) & 0xF);
            LINE.store(line, Ordering::Relaxed);
            line
        }
        line => line,
    }
}

/// Writes back the lines over the `len` bytes from `addr` to the point of
/// coherency, `dc cvac`, then `dsb sy`: what the program wrote reaches
/// memory before the device reads it [G18].
pub fn clean(addr: usize, len: usize) {
    for a in abi::cache::lines(addr..addr.saturating_add(len), line()) {
        // SAFETY: cleaning a line writes back what it holds; the line is
        // the caller's mapped memory, or the instruction faults as a load
        // of it would.
        unsafe { asm!("dc cvac, {}", in(reg) a, options(nostack, preserves_flags)) };
    }
    // SAFETY: a barrier has no other effect.
    unsafe { asm!("dsb sy", options(nostack, preserves_flags)) };
}

/// Writes back and drops the lines over the `len` bytes from `addr`, `dc
/// civac`, then `dsb sy`: before the device gets a buffer, and after it
/// wrote one and before the program reads it [G18].
pub fn clean_invalidate(addr: usize, len: usize) {
    for a in abi::cache::lines(addr..addr.saturating_add(len), line()) {
        // SAFETY: as in `clean`; dropping a line after writing it back
        // loses nothing.
        unsafe { asm!("dc civac, {}", in(reg) a, options(nostack, preserves_flags)) };
    }
    // SAFETY: a barrier has no other effect.
    unsafe { asm!("dsb sy", options(nostack, preserves_flags)) };
}

/// Orders the program's stores to DMA memory before its next store to a
/// device's register, the doorbell: `dmb oshst` [G34].
pub fn wmb() {
    // SAFETY: a barrier has no other effect.
    unsafe { asm!("dmb oshst", options(nostack, preserves_flags)) };
}

/// Orders a load of a device's index before the loads of the DMA memory it
/// covers: `dmb oshld` [G34].
pub fn rmb() {
    // SAFETY: a barrier has no other effect.
    unsafe { asm!("dmb oshld", options(nostack, preserves_flags)) };
}
