// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The registers of BAR 0 as one `ldr` or `str` of 32 bits with the address
//! in a register, no writeback and no pair [G34]: a hypervisor emulates a
//! device's register from the syndrome of the fault, and `read_volatile` does
//! not promise the form. The host's tests build the volatile accesses of core
//! in their place.

/// A window over BAR 0 mapped at `va`.
#[derive(Clone, Copy, Debug)]
pub struct Bar {
    va: usize,
    len: usize,
}

impl Bar {
    /// # Safety
    ///
    /// `va` is the start of `len` bytes of device window the process maps
    /// read and write, for as long as the value is used.
    pub const unsafe fn new(va: usize, len: usize) -> Bar {
        Bar { va, len }
    }

    pub fn read32(&self, offset: u32) -> u32 {
        assert!(offset as usize + 4 <= self.len && offset.is_multiple_of(4));
        let addr = self.va + offset as usize;
        #[cfg(target_arch = "aarch64")]
        {
            let value: u32;
            // SAFETY: `addr` is a register of the window (`new`'s promise and the
            // assert).
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
        // SAFETY: as above.
        unsafe {
            core::ptr::read_volatile(addr as *const u32)
        }
    }

    pub fn write32(&self, offset: u32, value: u32) {
        assert!(offset as usize + 4 <= self.len && offset.is_multiple_of(4));
        let addr = self.va + offset as usize;
        #[cfg(target_arch = "aarch64")]
        // SAFETY: as for `read32`.
        unsafe {
            core::arch::asm!(
                "str {v:w}, [{a}]",
                a = in(reg) addr,
                v = in(reg) value,
                options(nostack, preserves_flags)
            )
        };
        #[cfg(not(target_arch = "aarch64"))]
        // SAFETY: as above.
        unsafe {
            core::ptr::write_volatile(addr as *mut u32, value)
        }
    }
}
