// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A line after `ExitBootServices` goes straight to the console port the
//! SPCR names, by polling: the firmware's console is gone, and a panic of
//! the kernel before it reads the tree is not visible on EC2 (spec 3.2).
//! The register arithmetic is `firmware_tree::console`, tested on the host;
//! this file adds the volatile accesses.

use core::arch::asm;
use firmware_tree::console::{Bus, Port};
use firmware_tree::platform::Uart;

static mut PORT: Option<Port> = None;

struct Mmio;

/// One `ldr` or `ldrb` with the address in a register and no writeback: a
/// hypervisor emulates an access to device memory from the syndrome of the
/// fault, which holds for this form only [G34]. `read_volatile` does not
/// promise it. The same text as `karch/src/mmio.rs`.
///
/// # Safety
/// `address` is a register of the port, aligned to its width.
unsafe fn load(address: u64, width: u8) -> u32 {
    let v: u32;
    // SAFETY: the caller's promise.
    unsafe {
        if width == 4 {
            asm!("ldr {v:w}, [{a}]", a = in(reg) address, v = out(reg) v, options(nostack, preserves_flags));
        } else {
            asm!("ldrb {v:w}, [{a}]", a = in(reg) address, v = out(reg) v, options(nostack, preserves_flags));
        }
    }
    v
}

/// # Safety
/// As for `load`.
unsafe fn store(address: u64, width: u8, value: u32) {
    // SAFETY: the caller's promise.
    unsafe {
        if width == 4 {
            asm!("str {v:w}, [{a}]", a = in(reg) address, v = in(reg) value, options(nostack, preserves_flags));
        } else {
            asm!("strb {v:w}, [{a}]", a = in(reg) address, v = in(reg) value, options(nostack, preserves_flags));
        }
    }
}

impl Bus for Mmio {
    fn read(&mut self, address: u64, width: u8) -> u32 {
        // SAFETY: a register of the port at the address and with the access
        // width the SPCR gave (`Uart::regs`).
        unsafe { load(address, width) }
    }

    fn write(&mut self, address: u64, width: u8, value: u32) {
        // SAFETY: as above.
        unsafe { store(address, width, value) }
    }
}

/// A 32-bit register of a device the firmware maps, in the form of `load`.
///
/// # Safety
/// `address` is a 4-byte aligned device register.
pub unsafe fn read32(address: u64) -> u32 {
    // SAFETY: the caller's.
    unsafe { load(address, 4) }
}

/// Remembers the console port; the SPCR was checked when the tables were read.
pub fn remember(u: &Uart) {
    if let Ok(p) = Port::new(u) {
        // SAFETY: the loader runs on one CPU and writes this once, before
        // the exit, and reads it after.
        unsafe { PORT = Some(p) };
    }
}

pub fn puts(text: &str) {
    // SAFETY: see `remember`.
    if let Some(port) = unsafe { *core::ptr::addr_of!(PORT) } {
        port.puts(&mut Mmio, text);
    }
}

/// The address the kernel's stage marks go to (feature `early-marks`): the
/// base of a 16550 with byte registers one apart, the only layout the
/// marks of the kernel know; 0 otherwise.
#[cfg(feature = "early-marks")]
pub fn mark_base() -> u64 {
    // SAFETY: see `remember`.
    match unsafe { *core::ptr::addr_of!(PORT) } {
        Some(p) if !p.pl011 && p.shift == 0 && p.width == 1 => p.base,
        _ => 0,
    }
}
