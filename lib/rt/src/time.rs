// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Time without a system call (spec 10): the virtual counter and its
//! frequency, which the kernel lets EL0 read (CNTKCTL_EL1), and the scale
//! of the system (abi::time::Scale), which `_start` works out from the
//! frequency before `main`: the kernel converts clock_now and the
//! deadlines of timer_set with the same one.

use abi::time::Scale;
use core::arch::asm;
use core::cell::UnsafeCell;

/// The scale `init` sets before `main` and nothing changes after it.
struct Once(UnsafeCell<Option<Scale>>);

// SAFETY: the one write happens in `init`, before `main` and so before any
// other thread of the program exists; every access after it reads.
unsafe impl Sync for Once {}

static SCALE: Once = Once(UnsafeCell::new(None));

/// Works out the scale of the counter's frequency; `_start` calls it once,
/// before `main`. The kernel does not start a program on a counter
/// without a frequency.
pub(crate) fn init() {
    // SAFETY: the only write, while the program has one thread (`Once`).
    unsafe { *SCALE.0.get() = Scale::new(frequency()) };
}

/// The scale of the system (spec 10).
pub fn scale() -> Scale {
    // SAFETY: `init` wrote the value before `main`; it is only read now.
    let scale = unsafe { *SCALE.0.get() };
    scale.expect("rt works out the scale before main")
}

/// The virtual counter, CNTVCT_EL0. The ISB before it keeps the read from
/// being taken early; the asm may touch memory as far as the compiler
/// knows, so no load or store moves across it either. On the Allwinner A64
/// this read needs the counter erratum workaround (spec 10): re-read while
/// `((v + 1) & 0x1FF) <= 1`, at most 150 times, or the kernel traps EL0
/// reads; decided with the PinePhone port.
pub fn now() -> u64 {
    let ticks: u64;
    // SAFETY: reading the counter has no side effects.
    unsafe { asm!("isb", "mrs {}, cntvct_el0", out(reg) ticks, options(nostack, preserves_flags)) };
    ticks
}

/// The counter's frequency in Hz, CNTFRQ_EL0.
pub fn frequency() -> u64 {
    let hz: u64;
    // SAFETY: as in `now`.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) hz, options(nomem, nostack, preserves_flags)) };
    hz
}

/// The least counter value at which `ticks_to_ns` reaches `ns`: the tick a
/// timer with the deadline `ns` fires at, never earlier (spec 10);
/// saturates at u64::MAX.
pub fn ns_to_ticks(ns: u64) -> u64 {
    scale().ns_to_ticks(ns)
}

/// Nanoseconds in `ticks` on the scale, rounded down, as clock_now gives
/// them; saturates at u64::MAX.
pub fn ticks_to_ns(ticks: u64) -> u64 {
    scale().ticks_to_ns(ticks)
}
