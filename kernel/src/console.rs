// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Early console on the QEMU `virt` PL011 at PA 0x0900_0000, reached through
//! the linear map. One CPU and interrupts masked in the kernel: no lock needed.

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
    // SAFETY: head.S maps PA 0..1 GiB as device memory in the linear map.
    unsafe { ((BASE + CR) as *mut u32).write_volatile(CR_ENABLE) }
}

fn putc(byte: u8) {
    // SAFETY: as in `init`.
    unsafe {
        while ((BASE + FR) as *const u32).read_volatile() & FR_TXFF != 0 {}
        ((BASE + DR) as *mut u32).write_volatile(u32::from(byte));
    }
}

struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                putc(b'\r');
            }
            putc(b);
        }
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
