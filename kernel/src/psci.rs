// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! PSCI calls to the firmware. The conduit (HVC or SMC) comes from `/psci` in
//! the device tree; until it is known, power-off just parks the CPU.

use core::sync::atomic::{AtomicU8, Ordering};
use kcore::bootinfo::PsciConduit;

const SYSTEM_OFF: u64 = 0x8400_0008;
/// CPU_ON, SMC64 calling convention (PSCI 1.x, 5.6) [G37].
const CPU_ON: u64 = 0xC400_0003;
static CONDUIT: AtomicU8 = AtomicU8::new(0);

pub fn set_conduit(c: PsciConduit) {
    let v = match c {
        PsciConduit::None => 0,
        PsciConduit::Hvc => 1,
        PsciConduit::Smc => 2,
    };
    CONDUIT.store(v, Ordering::Relaxed);
}

/// Powers the machine off once the console's transmitter is idle, up to
/// 10 ms (console::drain, spec 16.1); parks the CPU when no conduit is
/// known or the call returns.
pub fn system_off() -> ! {
    crate::console::drain();
    // SAFETY: SYSTEM_OFF does not return when it succeeds; the SMC calling
    // convention clobbers x0-x17, which clobber_abi("C") covers.
    unsafe {
        match CONDUIT.load(Ordering::Relaxed) {
            1 => core::arch::asm!("hvc #0", inout("x0") SYSTEM_OFF => _, clobber_abi("C")),
            2 => core::arch::asm!("smc #0", inout("x0") SYSTEM_OFF => _, clobber_abi("C")),
            _ => {}
        }
    }
    loop {
        // SAFETY: waiting for an event has no side effects.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
    }
}

/// PSCI CPU_ON: starts the CPU of `mpidr` (the affinity fields) at the
/// physical address `entry` with the MMU and the caches off, `context` in
/// x0. The return value is the PSCI status: 0 for success, negative for an
/// error (-4 ALREADY_ON, -2 INVALID_PARAMETERS); `None` when the device
/// tree names no conduit.
pub fn cpu_on(mpidr: u64, entry: u64, context: u64) -> Option<i32> {
    let mut status = CPU_ON;
    // SAFETY: the SMC calling convention clobbers x0-x17, which
    // clobber_abi("C") covers; CPU_ON starts another CPU and changes
    // nothing of this one.
    unsafe {
        match CONDUIT.load(Ordering::Relaxed) {
            1 => {
                core::arch::asm!("hvc #0", inout("x0") status, in("x1") mpidr, in("x2") entry, in("x3") context, clobber_abi("C"))
            }
            2 => {
                core::arch::asm!("smc #0", inout("x0") status, in("x1") mpidr, in("x2") entry, in("x3") context, clobber_abi("C"))
            }
            _ => return None,
        }
    }
    Some(status as i32)
}
