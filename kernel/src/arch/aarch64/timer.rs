// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The EL1 virtual timer (spec 10): one time scale for the kernel and the
//! programs, the virtual counter CNTVCT_EL0, and a compare value that the
//! kernel sets for its next event. No periodic tick. The timer's output is a
//! level-triggered line, INTID 27: it stays up until the timer is disarmed
//! or given a later deadline, which must happen before the EOI.

use super::gic;
use kcore::gic::{DEFAULT_PRIORITY, VIRTUAL_TIMER_INTID};
use kcore::sync::SetOnce;
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

/// The clock `init` worked out from CNTFRQ_EL0: its scale takes a long
/// division, done once (abi::time::Scale).
static CLOCK: SetOnce<Clock> = SetOnce::new();

/// The clock of the counter's frequency; `init` sets it up before
/// anything reads the time.
pub fn clock() -> Clock {
    *CLOCK.get().expect("the timer is set up at boot")
}

/// The virtual counter, read after all earlier instructions. The kernel
/// reads the counter here and nowhere else: on the PinePhone this read
/// needs the A64 counter workaround (spec 10).
pub fn now() -> u64 {
    // SAFETY: the ISB only keeps the read from happening before earlier
    // instructions.
    unsafe { core::arch::asm!("isb", options(nomem, nostack, preserves_flags)) };
    now_unordered()
}

/// The virtual counter with no ISB before the read: right after an entry
/// from EL0, which synchronizes, or where a few instructions of skew
/// matter no more than the ISB costs (the stamp of a thread leaving for EL0).
#[inline(always)]
pub fn now_unordered() -> u64 {
    let ticks: u64;
    // SAFETY: reading the counter has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) ticks, options(nomem, nostack, preserves_flags))
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
/// for the frequency CNTFRQ_EL0 reports, which `clock` gives from then on;
/// panics when it is zero.
pub fn init() -> Clock {
    disarm();
    gic::set_priority(INTID, DEFAULT_PRIORITY);
    gic::unmask(INTID);
    let clock = Clock::new(frequency()).expect("CNTFRQ_EL0 is zero");
    // A second init keeps the clock of the first: the frequency is fixed.
    let _ = CLOCK.set(clock);
    clock
}

/// What a CPU other than the first sets up for itself: its timer off and
/// its PPI, banked per CPU, let through its interface at the priority of
/// the kernel's lines.
pub fn init_cpu() {
    disarm();
    gic::set_priority(INTID, DEFAULT_PRIORITY);
    gic::unmask(INTID);
}

/// Arms this CPU's timer `ticks` from now, waits for its interrupt to
/// reach the CPU interface, acknowledges and ends it, and tells whether it
/// came with the counter at the deadline or after it (spec 10) and as
/// INTID 27. The timer is off afterwards. Polls, since PSTATE masks
/// interrupts in the kernel. It gives up a second after the deadline: the
/// counter runs while the emulator's thread of this CPU, or the one that
/// raises the timer's line, waits for a host that is busy, and a shorter
/// limit would call such a delay a timer that never fired.
pub fn self_test(ticks: u64) -> bool {
    let deadline = now() + ticks;
    arm(deadline);
    let mut ok = false;
    let give_up = deadline + frequency();
    while now() < give_up {
        if fired() && super::irq_pending() {
            if let Some(ack) = gic::acknowledge() {
                ok = now() >= deadline && cval() == deadline && ack.intid() == INTID;
                disarm();
                gic::end(ack);
            }
            break;
        }
    }
    disarm();
    ok
}
