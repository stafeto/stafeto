// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The EL1 virtual timer (spec 10): one time scale for the kernel and the
//! programs, the virtual counter CNTVCT_EL0, and a compare value that the
//! kernel sets for its next event. No periodic tick. The timer's output is a
//! level-triggered line, INTID 27: it stays up until the timer is disarmed
//! or given a later deadline, which must happen before the EOI.

use super::gic;
use kcore::gic::{DEFAULT_PRIORITY, VIRTUAL_TIMER_INTID};
use kcore::time::Clock;

pub const INTID: u32 = VIRTUAL_TIMER_INTID;

/// CNTV_CTL_EL0.ENABLE; IMASK (bit 1) stays clear.
const CTL_ENABLE: u64 = 1;

/// CNTV_CTL_EL0.ISTATUS: the counter has reached CVAL. It means something
/// only while ENABLE is set.
const CTL_ISTATUS: u64 = 1 << 2;

/// The counter frequency, CNTFRQ_EL0, set by the firmware.
pub fn frequency() -> u64 {
    let hz: u64;
    // SAFETY: reading CNTFRQ_EL0 has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) hz, options(nomem, nostack, preserves_flags))
    };
    hz
}

pub fn clock() -> Clock {
    Clock::new(frequency()).expect("CNTFRQ_EL0 is zero")
}

/// The virtual counter, read after all earlier instructions. The kernel
/// reads the counter here and nowhere else: on the PinePhone this read
/// needs the A64 counter workaround (spec 10).
pub fn now() -> u64 {
    let ticks: u64;
    // SAFETY: reading the counter has no side effects; the ISB keeps the read
    // from happening before earlier instructions.
    unsafe {
        core::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) ticks, options(nomem, nostack, preserves_flags))
    };
    ticks
}

/// Fires once the counter reaches `cval`; a value already passed fires at
/// once. Outside the kernel tests only the scheduler arms and disarms the
/// timer (sched), which remembers what the timer holds.
pub fn arm(cval: u64) {
    // SAFETY: programming the EL1 virtual timer affects only its interrupt;
    // the ISB makes the new state take effect.
    unsafe {
        core::arch::asm!(
            "msr cntv_cval_el0, {cval}",
            "msr cntv_ctl_el0, {ctl}",
            "isb",
            cval = in(reg) cval,
            ctl = in(reg) CTL_ENABLE,
            options(nomem, nostack, preserves_flags),
        )
    };
}

/// Turns the timer off; its line drops.
pub fn disarm() {
    // SAFETY: as in `arm`.
    unsafe {
        core::arch::asm!(
            "msr cntv_ctl_el0, xzr",
            "isb",
            options(nomem, nostack, preserves_flags)
        )
    };
}

/// True when the timer is on and its deadline has passed. A level line may
/// reach the GIC once more after the EOI that followed a `disarm`: an
/// INTID 27 without this is spurious and gets only its EOI.
pub fn fired() -> bool {
    ctl() & (CTL_ENABLE | CTL_ISTATUS) == CTL_ENABLE | CTL_ISTATUS
}

fn ctl() -> u64 {
    let ctl: u64;
    // SAFETY: reading CNTV_CTL_EL0 has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, cntv_ctl_el0", out(reg) ctl, options(nomem, nostack, preserves_flags))
    };
    ctl
}

/// True while the timer is on.
#[cfg(feature = "ktest")]
pub fn enabled() -> bool {
    ctl() & CTL_ENABLE != 0
}

/// The compare value the timer was last armed with; `disarm` leaves it.
pub fn cval() -> u64 {
    let cval: u64;
    // SAFETY: reading CNTV_CVAL_EL0 has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, cntv_cval_el0", out(reg) cval, options(nomem, nostack, preserves_flags))
    };
    cval
}

/// Disarms the timer and lets its line through the GIC. Returns the clock
/// for the frequency CNTFRQ_EL0 reports; panics when it is zero.
pub fn init() -> Clock {
    disarm();
    gic::set_priority(INTID, DEFAULT_PRIORITY);
    gic::unmask(INTID);
    clock()
}
