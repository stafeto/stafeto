// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Stack walk over frame records. The kernel is built with frame pointers,
//! so x29 points at a {previous x29, return address} pair.

use kcore::layout::KERNEL_VIRT;

const MAX_FRAMES: usize = 32;

pub fn print() {
    let mut fp: usize;
    // SAFETY: reading x29 has no side effects.
    unsafe { core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack, preserves_flags)) };
    kprintln!("backtrace (look up: lldb -b -o 'image lookup -a ADDR' target/aarch64-unknown-none-softfloat/release/kernel):");
    for depth in 0..MAX_FRAMES {
        if fp < KERNEL_VIRT || fp % 16 != 0 {
            break;
        }
        // SAFETY: fp is a 16-byte aligned address inside the kernel window,
        // where the only stack of milestone 1 lives.
        let (next, lr) = unsafe { (*(fp as *const usize), *((fp + 8) as *const usize)) };
        if lr == 0 {
            break;
        }
        kprintln!("  #{depth:<2} {:#x}", lr.wrapping_sub(4));
        fp = next;
    }
}
