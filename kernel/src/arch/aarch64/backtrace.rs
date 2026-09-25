// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Stack walk over frame records. The kernel is built with frame pointers,
//! so x29 points at a {previous x29, return address} pair.

use kcore::layout::KERNEL_VIRT;

const MAX_FRAMES: usize = 32;
/// The ELF with this build's symbols; xtask copies it there.
#[cfg(not(feature = "ktest"))]
const ELF: &str = "target/stafeto.elf";
#[cfg(feature = "ktest")]
const ELF: &str = "target/stafeto-ktest.elf";

pub fn print() {
    let mut fp: usize;
    // SAFETY: reading x29 has no side effects.
    unsafe {
        core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack, preserves_flags))
    };
    kprintln!("backtrace (look up: lldb -b -o 'image lookup -a ADDR' {ELF}):");
    for depth in 0..MAX_FRAMES {
        if fp < KERNEL_VIRT || !fp.is_multiple_of(16) {
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
