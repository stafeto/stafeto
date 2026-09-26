// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Early console on the QEMU `virt` PL011 at PA 0x0900_0000, reached through
//! the linear map. One CPU and interrupts masked in the kernel: no lock needed.

use crate::arch::mmio;
use core::fmt::{self, Write};
use kcore::layout::LINEAR_BASE;

const PL011_PA: usize = 0x0900_0000;
const BASE: usize = LINEAR_BASE + PL011_PA;
const DR: usize = 0x000;
const FR: usize = 0x018;
const CR: usize = 0x030;
const FR_TXFF: u32 = 1 << 5;
/// UARTEN | TXE | RXE. QEMU transmits without it; real PL011s do not.
const CR_ENABLE: u32 = 0x301;

pub fn init() {
    // SAFETY: the PL011 is device memory in the linear map both before and
    // after the switch to the kernel tables: head.S maps the first GiB of
    // physical addresses as devices, mm::kmap maps the PL011 from the device
    // tree, and on QEMU virt it sits at PL011_PA.
    unsafe { mmio::write32(BASE + CR, CR_ENABLE) }
}

fn putc(byte: u8) {
    // SAFETY: as in `init`.
    unsafe {
        while mmio::read32(BASE + FR) & FR_TXFF != 0 {}
        mmio::write32(BASE + DR, u32::from(byte));
    }
}

/// Writes `bytes` as they are, but for a CR before each LF.
pub fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        if b == b'\n' {
            putc(b'\r');
        }
        putc(b);
    }
}

struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_bytes(s.as_bytes());
        Ok(())
    }
}

pub fn print(args: fmt::Arguments<'_>) {
    let _ = Console.write_fmt(args);
}

macro_rules! kprintln {
    () => {
        $crate::console::print(format_args!("\n"))
    };
    ($($arg:tt)*) => {{
        $crate::console::print(format_args!($($arg)*));
        $crate::console::print(format_args!("\n"));
    }};
}
