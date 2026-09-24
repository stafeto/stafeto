// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! PSCI calls to the firmware. The conduit (HVC or SMC) comes from `/psci` in
//! the device tree; until it is known, power-off just parks the CPU.

use core::sync::atomic::{AtomicU8, Ordering};
use kcore::bootinfo::PsciConduit;

#[cfg_attr(feature = "ktest", allow(dead_code))]
const SYSTEM_OFF: u64 = 0x8400_0008;
static CONDUIT: AtomicU8 = AtomicU8::new(0);

pub fn set_conduit(c: PsciConduit) {
    let v = match c {
        PsciConduit::None => 0,
        PsciConduit::Hvc => 1,
        PsciConduit::Smc => 2,
    };
    CONDUIT.store(v, Ordering::Relaxed);
}

#[cfg_attr(feature = "ktest", allow(dead_code))]
pub fn system_off() -> ! {
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
