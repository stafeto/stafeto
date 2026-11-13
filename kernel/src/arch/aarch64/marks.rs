// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Stage marks for the first boot on a machine whose console the kernel does
//! not write yet (feature `early-marks`, never in a shipped kernel). The
//! loader passes in x1 the physical address of a 16550 with byte registers
//! one apart. `head.S` writes `A` (the first instruction), `B` (at EL1),
//! `C` (the MMU is on) and keeps the address in `EARLY_PORT_PA`; this file
//! writes `D` to `F` from `kernel_main`. A mark waits for room in the
//! transmitter for at most 1000 reads of LSR, then writes anyway.

use core::arch::asm;
use kcore::layout::LINEAR_BASE;

/// The port's physical address, set by `head.S` after `.bss` is cleared; 0
/// when the loader gave none.
#[unsafe(no_mangle)]
static mut EARLY_PORT_PA: u64 = 0;

/// The port's physical address, if the loader gave one.
pub fn port() -> Option<u64> {
    // SAFETY: written once by `head.S` before `kernel_main`.
    let pa = unsafe { core::ptr::addr_of!(EARLY_PORT_PA).read() };
    (pa != 0).then_some(pa)
}

/// Writes the letter `c` to the port through the linear map.
pub fn mark(c: u8) {
    let Some(pa) = port() else { return };
    let base = LINEAR_BASE + pa as usize;
    let mut spins = 0;
    loop {
        let lsr: u32;
        // SAFETY: LSR of the port; the boot tables and then the kernel tables
        // map its page as device memory (head.S, kmap.rs), one `ldrb` [G34].
        unsafe {
            asm!("ldrb {v:w}, [{a}]", a = in(reg) base + 5, v = out(reg) lsr, options(nostack, preserves_flags))
        };
        spins += 1;
        if lsr & (1 << 5) != 0 || spins >= 1000 {
            break;
        }
    }
    // SAFETY: THR of the same port, one `strb`.
    unsafe {
        asm!("strb {v:w}, [{a}]", a = in(reg) base, v = in(reg) u32::from(c), options(nostack, preserves_flags))
    };
}
