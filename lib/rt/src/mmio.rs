// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Access to the registers of a device window (spec 9): each access is one
//! `ldr` or `str` of the register's width with the address in a register,
//! no writeback and no pair, which a hypervisor emulates from the syndrome
//! of the fault [G34]. Under QEMU's HVF any other form of access to an
//! emulated device stops QEMU whole; `read_volatile` does not promise the
//! form. The kernel's arch::mmio has the same text.

use core::arch::asm;

/// Reads the 8-bit register at `addr`.
///
/// # Safety
///
/// `addr` is a register of the width read, aligned to it, in a device
/// window the process maps.
pub unsafe fn read8(addr: usize) -> u8 {
    let value: u8;
    // SAFETY: the caller's promise.
    unsafe {
        asm!("ldrb {v:w}, [{a}]", a = in(reg) addr, v = out(reg) value, options(nostack, preserves_flags))
    };
    value
}

/// Writes the 8-bit register at `addr`.
///
/// # Safety
///
/// As for `read8`.
pub unsafe fn write8(addr: usize, value: u8) {
    // SAFETY: the caller's promise.
    unsafe {
        asm!("strb {v:w}, [{a}]", a = in(reg) addr, v = in(reg) value, options(nostack, preserves_flags))
    };
}

/// Reads the 32-bit register at `addr`.
///
/// # Safety
///
/// As for `read8`.
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
/// As for `read8`.
pub unsafe fn write32(addr: usize, value: u32) {
    // SAFETY: the caller's promise.
    unsafe {
        asm!("str {v:w}, [{a}]", a = in(reg) addr, v = in(reg) value, options(nostack, preserves_flags))
    };
}

/// Reads the 64-bit register at `addr`.
///
/// # Safety
///
/// As for `read8`.
pub unsafe fn read64(addr: usize) -> u64 {
    let value: u64;
    // SAFETY: the caller's promise.
    unsafe {
        asm!("ldr {v}, [{a}]", a = in(reg) addr, v = out(reg) value, options(nostack, preserves_flags))
    };
    value
}

/// Writes the 64-bit register at `addr`.
///
/// # Safety
///
/// As for `read8`.
pub unsafe fn write64(addr: usize, value: u64) {
    // SAFETY: the caller's promise.
    unsafe {
        asm!("str {v}, [{a}]", a = in(reg) addr, v = in(reg) value, options(nostack, preserves_flags))
    };
}

/// Orders the stores to memory before it ahead of the stores to device
/// registers after it: a descriptor in memory reaches the device before
/// the doorbell that tells it to look (`dmb oshst`, [G34]).
pub fn wmb() {
    // SAFETY: a barrier has no other effect.
    unsafe { asm!("dmb oshst", options(nostack, preserves_flags)) };
}
