// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Access to the registers of a device: each access is one `ldr` or `str` of
//! the register's width with the address in a register, no writeback and no
//! pair, which a hypervisor emulates from the syndrome of the fault. Under
//! QEMU's HVF any other form of access to an emulated device stops QEMU
//! whole, and `read_volatile` does not promise the form. The host's tests
//! build the volatile accesses of core in their place.

/// Reads the 32-bit register at `addr`.
///
/// # Safety
///
/// `addr` is a register of 32 bits, aligned to 4, in a device window the
/// process maps (or, in the host's tests, memory of the test).
#[inline]
pub unsafe fn read32(addr: usize) -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        let value: u32;
        // SAFETY: the caller's promise.
        unsafe {
            core::arch::asm!(
                "ldr {v:w}, [{a}]",
                a = in(reg) addr,
                v = out(reg) value,
                options(nostack, preserves_flags)
            )
        };
        value
    }
    #[cfg(not(target_arch = "aarch64"))]
    // SAFETY: the caller's promise.
    unsafe {
        core::ptr::read_volatile(addr as *const u32)
    }
}

/// Writes the 32-bit register at `addr`.
///
/// # Safety
///
/// As for `read32`.
#[inline]
pub unsafe fn write32(addr: usize, value: u32) {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: the caller's promise.
    unsafe {
        core::arch::asm!(
            "str {v:w}, [{a}]",
            a = in(reg) addr,
            v = in(reg) value,
            options(nostack, preserves_flags)
        )
    };
    #[cfg(not(target_arch = "aarch64"))]
    // SAFETY: the caller's promise.
    unsafe {
        core::ptr::write_volatile(addr as *mut u32, value)
    }
}
