// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A line after `ExitBootServices` goes straight to the console port the
//! SPCR names, by polling: the firmware's console is gone, and a panic of
//! the kernel before it reads the tree is not visible on EC2 (spec 3.2).
//! The register arithmetic is `firmware_tree::console`, tested on the host;
//! this file adds the volatile accesses.

use core::ptr::{read_volatile, write_volatile};
use firmware_tree::console::{Bus, Port};
use firmware_tree::platform::Uart;

static mut PORT: Option<Port> = None;

struct Mmio;

impl Bus for Mmio {
    fn read(&mut self, address: u64, width: u8) -> u32 {
        // SAFETY: a register of the port at the address and with the access
        // width the SPCR gave (`Uart::regs`).
        unsafe {
            if width == 4 {
                read_volatile(address as *const u32)
            } else {
                u32::from(read_volatile(address as *const u8))
            }
        }
    }

    fn write(&mut self, address: u64, width: u8, value: u32) {
        // SAFETY: as above.
        unsafe {
            if width == 4 {
                write_volatile(address as *mut u32, value);
            } else {
                write_volatile(address as *mut u8, value as u8);
            }
        }
    }
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
