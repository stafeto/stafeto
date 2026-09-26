// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Time on the generic timer's counter (spec 10): counter ticks to
//! nanoseconds and back on the scale of the system (abi::time::Scale),
//! and compare values for deadlines.

pub use abi::time::NANOS_PER_SEC;
use abi::time::Scale;

/// The counter's frequency (CNTFRQ_EL0) and the scale it fixes, which the
/// kernel works out once at boot (arch::timer::init).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    scale: Scale,
}

impl Clock {
    /// None for a zero frequency: the firmware left CNTFRQ_EL0 unset.
    pub const fn new(hz: u64) -> Option<Clock> {
        match Scale::new(hz) {
            Some(scale) => Some(Clock { scale }),
            None => None,
        }
    }

    pub const fn hz(self) -> u64 {
        self.scale.hz()
    }

    /// Nanoseconds in `ticks` on the scale, rounded down; saturates at
    /// u64::MAX.
    pub fn ticks_to_ns(self, ticks: u64) -> u64 {
        self.scale.ticks_to_ns(ticks)
    }

    /// The least tick at which `ticks_to_ns` reaches `ns`, so that a timer
    /// never fires early; saturates at u64::MAX.
    pub fn ns_to_ticks(self, ns: u64) -> u64 {
        self.scale.ns_to_ticks(ns)
    }
}

/// For the kernel tests, which set deadlines of their own and measure
/// waits; the kernel itself converts through `ns_to_ticks`.
impl Clock {
    /// Compare value for a deadline `ns` nanoseconds after the counter
    /// value `now`. A deadline beyond the counter's range saturates at
    /// u64::MAX, which the counter never reaches, instead of wrapping into
    /// the past.
    pub fn deadline_after(self, now: u64, ns: u64) -> u64 {
        now.saturating_add(self.ns_to_ticks(ns))
    }

    /// Nanoseconds from the counter value `now` until the compare value
    /// `cval`; zero once the deadline has passed.
    pub fn ns_until(self, now: u64, cval: u64) -> u64 {
        self.ticks_to_ns(cval.saturating_sub(now))
    }
}

/// The length in counter ticks of a stretch of work, such as a portion
/// (spec 7.7), that began at the counter value `start` and ended at
/// `now`, read as `now - start` and at least one: a stretch that happened
/// within one tick still counts (KSTATS x5, spec 16). The count can be one
/// tick short of the true length.
pub fn stretch(start: u64, now: u64) -> u64 {
    now.saturating_sub(start).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const QEMU_HZ: u64 = 62_500_000;
    const A64_HZ: u64 = 24_000_000;

    fn clock(hz: u64) -> Clock {
        Clock::new(hz).unwrap()
    }

    #[test]
    fn a_stretch_counts_at_least_one_tick() {
        assert_eq!(stretch(100, 100), 1);
        assert_eq!(stretch(100, 101), 1);
        assert_eq!(stretch(100, 102), 2);
        assert_eq!(stretch(100, 5_100), 5_000);
        // A counter read before the start: still a stretch that happened.
        assert_eq!(stretch(100, 99), 1);
    }

    #[test]
    fn a_clock_needs_a_frequency() {
        assert_eq!(Clock::new(0), None);
        assert_eq!(clock(QEMU_HZ).hz(), QEMU_HZ);
    }

    #[test]
    fn ticks_and_nanoseconds_at_62_5_mhz() {
        let c = clock(QEMU_HZ);
        assert_eq!(c.ticks_to_ns(1), 16);
        assert_eq!(c.ticks_to_ns(QEMU_HZ), NANOS_PER_SEC);
        assert_eq!(c.ns_to_ticks(16), 1);
        assert_eq!(c.ns_to_ticks(17), 2);
        assert_eq!(c.ns_to_ticks(NANOS_PER_SEC), QEMU_HZ);
    }

    #[test]
    fn ticks_and_nanoseconds_at_24_mhz() {
        // 10^9 / 24 MHz is no whole number: the scale is at most 1 ns
        // under the exact division (abi::time::Scale), and a deadline on
        // a tick of the exact division takes the tick after it.
        let c = clock(A64_HZ);
        assert_eq!(c.ticks_to_ns(1), 41);
        assert_eq!(c.ticks_to_ns(3), 124);
        assert_eq!(c.ticks_to_ns(A64_HZ), NANOS_PER_SEC - 1);
        assert_eq!(c.ns_to_ticks(1), 1);
        assert_eq!(c.ns_to_ticks(124), 3);
        assert_eq!(c.ns_to_ticks(125), 4);
        assert_eq!(c.ns_to_ticks(1_000), 25);
    }

    #[test]
    fn a_timer_never_fires_early() {
        for hz in [QEMU_HZ, A64_HZ] {
            let c = clock(hz);
            for ns in [1, 15, 17, 41, 42, 999, 1_000_001, 123_456_789] {
                assert!(c.ticks_to_ns(c.ns_to_ticks(ns)) >= ns, "{ns} ns at {hz} Hz");
            }
        }
    }

    #[test]
    fn large_values_do_not_overflow_in_between() {
        // A u64 product of ticks and 10^9, or of ns and the frequency,
        // would overflow here.
        let qemu = clock(QEMU_HZ);
        assert_eq!(qemu.ticks_to_ns(u64::MAX / 16), u64::MAX / 16 * 16);
        let a64 = clock(A64_HZ);
        let ticks = (u128::from(u64::MAX) * 24).div_ceil(1_000) as u64;
        assert_eq!(a64.ns_to_ticks(u64::MAX), ticks);
    }

    #[test]
    fn results_past_u64_saturate() {
        assert_eq!(clock(A64_HZ).ticks_to_ns(u64::MAX), u64::MAX);
        assert_eq!(clock(QEMU_HZ).ticks_to_ns(u64::MAX), u64::MAX);
        assert_eq!(clock(2 * NANOS_PER_SEC).ns_to_ticks(u64::MAX), u64::MAX);
    }

    #[test]
    fn a_deadline_after_now() {
        let c = clock(QEMU_HZ);
        assert_eq!(c.deadline_after(1_000, 0), 1_000);
        assert_eq!(c.deadline_after(1_000, 1_000_000), 1_000 + 62_500);
    }

    #[test]
    fn a_very_far_deadline_saturates_instead_of_wrapping() {
        let c = clock(A64_HZ);
        assert_eq!(c.deadline_after(u64::MAX - 10, NANOS_PER_SEC), u64::MAX);
        assert_eq!(c.deadline_after(1, u64::MAX), c.ns_to_ticks(u64::MAX) + 1);
        assert_eq!(
            clock(2 * NANOS_PER_SEC).deadline_after(1, u64::MAX),
            u64::MAX
        );
    }

    #[test]
    fn time_until_a_passed_deadline_is_zero() {
        let c = clock(QEMU_HZ);
        assert_eq!(c.ns_until(2_000, 1_000), 0);
        assert_eq!(c.ns_until(1_000, 1_000), 0);
        assert_eq!(c.ns_until(1_000, 1_000 + 62_500), 1_000_000);
    }
}
