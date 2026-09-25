// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Cache maintenance. QEMU models no caches, so only real hardware shows a
//! step that is missing here.

use core::arch::asm;

/// CTR_EL0.L1Ip, bits [15:14], for a PIPT instruction cache.
const L1IP_PIPT: u64 = 0b11;

/// Makes code that the kernel wrote at `[va, va + len)` visible to
/// instruction fetch: cleans the data cache to the point of unification
/// line by line, then invalidates the instruction cache line by line, with
/// the line sizes from CTR_EL0. A VIPT instruction cache (the A53's) may
/// hold the code under the address the program runs it at, which differs
/// from `va`, so there the whole instruction cache goes instead. A loader
/// syncs every page it maps executable, whole, and not only the bytes it
/// copied: the rest of the page was zeroed through the data side, and a
/// PIPT instruction cache may still hold the frame's previous code there.
pub fn sync_icache(va: usize, len: usize) {
    let ctr: u64;
    // SAFETY: reading CTR_EL0 has no side effects.
    unsafe { asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack, preserves_flags)) };
    // DminLine, bits [19:16], and IminLine, bits [3:0]: log2 of the
    // smallest line in words.
    let dline = 4usize << ((ctr >> 16) & 0xF);
    let iline = 4usize << (ctr & 0xF);
    for line in (va & !(dline - 1)..va + len).step_by(dline) {
        // SAFETY: cleaning a line writes back what it holds and nothing else.
        unsafe { asm!("dc cvau, {}", in(reg) line, options(nostack, preserves_flags)) };
    }
    // SAFETY: a barrier has no other effect.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };
    if (ctr >> 14) & 0b11 == L1IP_PIPT {
        for line in (va & !(iline - 1)..va + len).step_by(iline) {
            // SAFETY: invalidating instruction cache lines only drops them.
            unsafe { asm!("ic ivau, {}", in(reg) line, options(nostack, preserves_flags)) };
        }
    } else {
        // SAFETY: as above, for the whole instruction cache.
        unsafe { asm!("ic ialluis", options(nostack, preserves_flags)) };
    }
    // SAFETY: barriers have no other effect.
    unsafe { asm!("dsb ish", "isb", options(nostack, preserves_flags)) };
}
