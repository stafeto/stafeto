// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Time without a system call (spec 10): the virtual counter and its
//! frequency, which the kernel lets EL0 read (CNTKCTL_EL1).

use core::arch::asm;

const NANOS_PER_SEC: u128 = 1_000_000_000;

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

/// Counter ticks in `ns`, rounded up as the kernel rounds its deadlines
/// (kcore::time::Clock::ns_to_ticks); saturates at u64::MAX.
pub fn ns_to_ticks(ns: u64) -> u64 {
    let ticks = (u128::from(ns) * u128::from(frequency())).div_ceil(NANOS_PER_SEC);
    u64::try_from(ticks).unwrap_or(u64::MAX)
}

/// Nanoseconds in `ticks`, rounded down as `clock_now` rounds them
/// (kcore::time::Clock::ticks_to_ns); saturates at u64::MAX.
pub fn ticks_to_ns(ticks: u64) -> u64 {
    let ns = u128::from(ticks) * NANOS_PER_SEC / u128::from(frequency());
    u64::try_from(ns).unwrap_or(u64::MAX)
}
