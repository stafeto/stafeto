// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Stack walk over frame records. The kernel is built with frame pointers,
//! so x29 points at a {previous x29, return address} pair; exception entry
//! adds one more record for the interrupted code.

use super::symbols;
use kcore::backtrace::{continues, record_in_stack};

const MAX_FRAMES: usize = 32;
/// The ELF with this build's symbols; xtask copies it there.
#[cfg(feature = "ktest")]
const ELF: &str = "target/stafeto-ktest.elf";
#[cfg(all(feature = "fault-probe", not(feature = "ktest")))]
const ELF: &str = "target/stafeto-probe.elf";
#[cfg(not(any(feature = "ktest", feature = "fault-probe")))]
const ELF: &str = "target/stafeto.elf";

pub fn print() {
    let stack = symbols::boot_stack();
    let mut fp: usize;
    // SAFETY: reading x29 has no side effects.
    unsafe {
        core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack, preserves_flags))
    };
    kprintln!("backtrace (look up: lldb -b -o 'image lookup -a ADDR' {ELF}):");
    for depth in 0..MAX_FRAMES {
        if !record_in_stack(fp, stack.start, stack.end) {
            break;
        }
        // SAFETY: the record lies inside the boot stack, which is mapped.
        let (next, lr) = unsafe { (*(fp as *const usize), *((fp + 8) as *const usize)) };
        if lr == 0 {
            break;
        }
        kprintln!("  #{depth:<2} {:#x}", lr.wrapping_sub(4));
        if !continues(fp, next) {
            break;
        }
        fp = next;
    }
}
