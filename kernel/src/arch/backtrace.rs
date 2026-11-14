// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Stack walk over frame records. The kernel is built with frame pointers,
//! so x29 points at a {previous x29, return address} pair; exception entry
//! adds one more record for the interrupted code. A report on the emergency
//! stack goes on into the kernel stack that overflowed.

use super::symbols;

const MAX_FRAMES: usize = 32;
/// The ELF with this build's symbols; xtask copies it there.
#[cfg(feature = "ktest")]
const ELF: &str = "target/stafeto-ktest.elf";
#[cfg(all(feature = "fault-probe", not(feature = "ktest")))]
const ELF: &str = "target/stafeto-probe.elf";
#[cfg(all(
    feature = "overflow-probe",
    not(any(feature = "ktest", feature = "fault-probe"))
))]
const ELF: &str = "target/stafeto-overflow.elf";
#[cfg(not(any(feature = "ktest", feature = "fault-probe", feature = "overflow-probe")))]
const ELF: &str = "target/stafeto.elf";

pub fn print() {
    // The stacks of this CPU: every CPU's stack has the layout of the boot
    // stack (kernel.ld), the guard page and the emergency stack below it.
    let boot = symbols::boot_stack();
    let emergency = symbols::emergency_stack();
    let top = super::cpu::this().stack_top();
    let (size, guard) = (boot.end - boot.start, boot.start - emergency.end);
    let kernel = top - size..top;
    let alternate = kernel.start - guard - (emergency.end - emergency.start)..kernel.start - guard;
    let stacks = [alternate, kernel];
    let fp: usize;
    // SAFETY: reading x29 has no side effects.
    unsafe {
        core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack, preserves_flags))
    };
    kprintln!("backtrace (look up: lldb -b -o 'image lookup -a ADDR' {ELF}):");
    // SAFETY: the walk reads only words of records inside the two stacks of
    // this CPU, and both are mapped.
    let read = |addr: usize| unsafe { *(addr as *const usize) };
    let mut depth = 0;
    kcore::backtrace::walk(fp, &stacks, MAX_FRAMES, read, |lr| {
        kprintln!("  #{depth:<2} {:#x}", lr.wrapping_sub(4));
        depth += 1;
    });
}
