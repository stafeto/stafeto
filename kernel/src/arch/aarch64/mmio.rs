// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel's access to device registers (spec 9): one `ldr` or `str` of
//! the register's width with the address in a register, no writeback and
//! no pair, which a hypervisor emulates from the syndrome of the fault
//! [G34]. `read_volatile` does not promise that form. rt::mmio has the
//! same text for programs.

use core::arch::asm;

/// Reads the 32-bit register at `addr`.
///
/// # Safety
///
/// `addr` is a 4-byte aligned register of a device the kernel tables map
/// as device memory.
pub unsafe fn read32(addr: usize) -> u32 {
    let value: u32;
    // SAFETY: the caller's promise.
    unsafe {
        asm!("ldr {v:w}, [{a}]", a = in(reg) addr, v = out(reg) value, options(nostack, preserves_flags))
    };
    value
}

/// Writes the 32-bit register at `addr`.
///
/// # Safety
///
/// As for `read32`.
pub unsafe fn write32(addr: usize, value: u32) {
    // SAFETY: the caller's promise.
    unsafe {
        asm!("str {v:w}, [{a}]", a = in(reg) addr, v = in(reg) value, options(nostack, preserves_flags))
    };
}
