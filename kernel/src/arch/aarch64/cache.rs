// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Cache maintenance. QEMU models no caches, so only real hardware shows a
//! step that is missing here.

use core::arch::asm;
use kcore::PAGE_SIZE;
use kcore::layout::LINEAR_BASE;

/// CTR_EL0.L1Ip, bits [15:14], for a PIPT instruction cache.
const L1IP_PIPT: u64 = 0b11;

/// The smallest line of the data cache and of the instruction cache in
/// bytes, from CTR_EL0 (DminLine, bits [19:16], and IminLine, bits [3:0]:
/// log2 of the line in words), and whether the instruction cache is PIPT
/// ([G18]).
fn lines() -> (usize, usize, bool) {
    let ctr: u64;
    // SAFETY: reading CTR_EL0 has no side effects.
    unsafe { asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack, preserves_flags)) };
    let dline = 4usize << ((ctr >> 16) & 0xF);
    let iline = 4usize << (ctr & 0xF);
    (dline, iline, (ctr >> 14) & 0b11 == L1IP_PIPT)
}

/// The addresses of the data cache lines that cover `range`, by the
/// smallest line of CTR_EL0 [G18], for maintenance by virtual address.
pub(crate) fn data_lines(
    range: core::ops::Range<usize>,
) -> core::iter::StepBy<core::ops::Range<usize>> {
    abi::cache::lines(range, lines().0)
}

/// Cleans and invalidates the data cache lines of the `pages` frames from
/// `pa` to the point of coherency through the linear map, `dc civac` by
/// the smallest line of CTR_EL0, then `dsb sy` [G18]: what the kernel
/// wrote there reaches memory before a device or an uncached mapping
/// reads it, and no dirty line is left to be evicted over what a device
/// writes later (memory::fill of a contiguous object, spec 7.3).
pub fn clean_invalidate_frames(pa: u64, pages: usize) {
    let va = LINEAR_BASE + pa as usize;
    for line in data_lines(va..va + pages * PAGE_SIZE as usize) {
        // SAFETY: cleaning and invalidating a line writes back what it
        // holds and drops it; the frames are RAM the linear map covers.
        unsafe { asm!("dc civac, {}", in(reg) line, options(nostack, preserves_flags)) };
    }
    // SAFETY: a barrier has no other effect.
    unsafe { asm!("dsb sy", options(nostack, preserves_flags)) };
}

/// Makes the code in the frames `frames` visible to instruction fetch
/// before a program may run it (spec 7.4, [G18]): `dc cvau` over every
/// line of each whole page through the linear map, `dsb ish`, `ic ivau`
/// over the same lines, `dsb ish`, `isb`, one set of barriers for all of
/// them. Whole pages: what a program or the kernel wrote there went through
/// the data side, and the instruction cache may still hold the frame's
/// earlier code. A VIPT instruction cache (the A53's) may hold code under
/// the address a program runs it at, which differs from the linear map, so
/// there the whole instruction cache goes instead (`ic ialluis`).
pub fn sync_icache_frames(frames: &[u64]) {
    let (dline, iline, pipt) = lines();
    let page = PAGE_SIZE as usize;
    for &pa in frames {
        let va = LINEAR_BASE + pa as usize;
        for line in (va..va + page).step_by(dline) {
            // SAFETY: cleaning a line writes back what it holds and nothing
            // else.
            unsafe { asm!("dc cvau, {}", in(reg) line, options(nostack, preserves_flags)) };
        }
    }
    // SAFETY: a barrier has no other effect.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };
    if pipt {
        for &pa in frames {
            let va = LINEAR_BASE + pa as usize;
            for line in (va..va + page).step_by(iline) {
                // SAFETY: invalidating instruction cache lines only drops
                // them.
                unsafe { asm!("ic ivau, {}", in(reg) line, options(nostack, preserves_flags)) };
            }
        }
    } else {
        // SAFETY: as above, for the whole instruction cache.
        unsafe { asm!("ic ialluis", options(nostack, preserves_flags)) };
    }
    // SAFETY: barriers have no other effect.
    unsafe { asm!("dsb ish", "isb", options(nostack, preserves_flags)) };
    crate::testpoint::code_synced(frames);
}
