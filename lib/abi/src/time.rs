// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The time scale of the system (spec 10): counter ticks to nanoseconds
//! and back by a multiply and a shift, one function for the kernel and
//! the programs, so that both read a deadline on the same scale; and the
//! deadlines of periodic work.

pub const NANOS_PER_SEC: u64 = 1_000_000_000;

/// How ticks of a counter of `hz` convert to nanoseconds and back (spec
/// 10). `ticks_to_ns(t)` is `(t * M) >> S`, with `M = floor(10^9 * 2^S /
/// hz)` and `S` the largest shift that keeps `M` under 2^64: it is never
/// above the exact division and at most 1 ns under it for values up to
/// 2^63 ns, and it is exact when 10^9 / hz is a whole number or the
/// inverse of a power of two. This scale is the nanoseconds of the
/// system: clock_now and the deadlines of timer_set use it alone.
/// `ns_to_ticks(d)` is the least tick at which `ticks_to_ns` reaches `d`:
/// a timer armed there never fires before its deadline. The multipliers
/// come from a long division in 64-bit words, once; no conversion divides
/// 128-bit values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scale {
    hz: u64,
    to_ns: Fraction,
    to_ticks: Fraction,
}

/// `(v * mul) >> shift`: a fraction with a 64-bit multiplier whose top bit
/// is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fraction {
    mul: u64,
    shift: u32,
}

impl Fraction {
    /// `num / den` rounded down to 64 bits of precision: the whole part by
    /// one 64-bit division, then one bit of the remainder at a time until
    /// the multiplier's top bit is set. `den` is not 0.
    const fn of(num: u64, den: u64) -> Fraction {
        let mut mul = num / den;
        let mut rest = num % den;
        let mut shift = 0;
        while mul < 1 << 63 {
            // Twice the remainder against `den`, without overflow: rest <
            // den, so `den - rest` fits.
            let bit = rest >= den - rest;
            rest = if bit { rest - (den - rest) } else { 2 * rest };
            mul = 2 * mul + bit as u64;
            shift += 1;
        }
        Fraction { mul, shift }
    }

    /// `v` times the fraction, rounded down; saturates at u64::MAX.
    fn apply(self, v: u64) -> u64 {
        let product = (u128::from(v) * u128::from(self.mul)) >> self.shift;
        if product > u64::MAX as u128 {
            u64::MAX
        } else {
            product as u64
        }
    }
}

impl Scale {
    /// The scale of a counter of `hz`; None for 0, a counter the firmware
    /// left without a frequency.
    pub const fn new(hz: u64) -> Option<Scale> {
        if hz == 0 {
            return None;
        }
        Some(Scale {
            hz,
            to_ns: Fraction::of(NANOS_PER_SEC, hz),
            to_ticks: Fraction::of(hz, NANOS_PER_SEC),
        })
    }

    pub const fn hz(self) -> u64 {
        self.hz
    }

    /// Nanoseconds in `ticks`: `(ticks * M) >> S`, rounded down;
    /// saturates at u64::MAX.
    pub fn ticks_to_ns(self, ticks: u64) -> u64 {
        self.to_ns.apply(ticks)
    }

    /// The least tick `t` with `ticks_to_ns(t) >= ns` (u64::MAX when there
    /// is none): an estimate that is never above it, then one tick at a
    /// time up to it: at most two steps for counters up to 1 GHz and
    /// deadlines up to 2^62 ns (146 years), three up to 2^63 ns; a faster
    /// counter takes more, about hz / 10^9 + 2.
    pub fn ns_to_ticks(self, ns: u64) -> u64 {
        let mut ticks = self.estimate(ns);
        while ticks < u64::MAX && self.ticks_to_ns(ticks) < ns {
            ticks += 1;
        }
        ticks
    }

    /// `(ns * M') >> S'`, with `M'` the fraction `hz / 10^9` rounded down:
    /// no more than the ticks in `ns`, so no more than the least tick.
    fn estimate(self, ns: u64) -> u64 {
        self.to_ticks.apply(ns)
    }
}

/// The first deadline of the form `t0 + k * period`, k >= 0, after `now`:
/// periodic work released at absolute deadlines, which never drift
/// however late each release runs (spec 10). u64::MAX when the next one
/// lies past it, and for a period of 0 once `now` reached `t0`.
pub fn next_release(t0: u64, period: u64, now: u64) -> u64 {
    if now < t0 {
        return t0;
    }
    if period == 0 {
        return u64::MAX;
    }
    let k = (now - t0) / period + 1;
    k.checked_mul(period)
        .and_then(|d| t0.checked_add(d))
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const QEMU_HZ: u64 = 62_500_000;
    const A64_HZ: u64 = 24_000_000;
    /// The frequencies of the checks: the least and the most the tests
    /// take, QEMU's, the A64's, 19.2 and 54 MHz, and a prime just under
    /// 1 GHz.
    const FREQUENCIES: [u64; 7] = [
        1_000_000,
        19_200_000,
        A64_HZ,
        54_000_000,
        QEMU_HZ,
        999_999_937,
        1_000_000_000,
    ];
    /// The largest value, in nanoseconds, the error bound holds for, and
    /// the largest deadline that takes at most two steps: past it the two
    /// roundings may add up to a third.
    const BOUND_NS: u64 = 1 << 63;
    const STEPS_BOUND_NS: u64 = 1 << 62;

    fn scale(hz: u64) -> Scale {
        Scale::new(hz).unwrap()
    }

    /// A xorshift generator: random enough to spread the checks, the same
    /// on every run.
    struct Random(u64);

    impl Random {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// A value in 1..=max, spread over its orders of magnitude.
        fn below(&mut self, max: u64) -> u64 {
            let bits = self.next() % 64 + 1;
            let v = self.next() >> (64 - bits);
            v % max + 1
        }
    }

    /// Frequencies for the checks: FREQUENCIES and 200 random ones from
    /// 1 MHz to 1 GHz.
    fn frequencies() -> Vec<u64> {
        let mut r = Random(0x5CA1E);
        let mut all = FREQUENCIES.to_vec();
        all.extend((0..200).map(|_| 1_000_000 + r.next() % 999_000_001));
        all
    }

    /// Ticks for the checks at `hz`: the edges, 1 s, and 1 000 random
    /// values whose nanoseconds stay under BOUND_NS.
    fn ticks(hz: u64, r: &mut Random) -> Vec<u64> {
        let max = (u128::from(BOUND_NS) * u128::from(hz) / u128::from(NANOS_PER_SEC)) as u64;
        let mut all = vec![0, 1, 2, 3, hz - 1, hz, hz + 1, max];
        all.extend((0..1_000).map(|_| r.below(max)));
        all
    }

    fn exact_ns(hz: u64, ticks: u64) -> u128 {
        u128::from(ticks) * u128::from(NANOS_PER_SEC) / u128::from(hz)
    }

    #[test]
    fn scale_is_within_a_nanosecond_of_division() {
        let mut r = Random(0x71C5);
        for hz in frequencies() {
            let s = scale(hz);
            for t in ticks(hz, &mut r) {
                let (got, exact) = (u128::from(s.ticks_to_ns(t)), exact_ns(hz, t));
                assert!(
                    got <= exact && exact - got <= 1,
                    "{t} ticks at {hz} Hz: {got} ns, exactly {exact}"
                );
            }
        }
    }

    #[test]
    fn scale_is_exact_at_62_5_mhz_and_1_ghz() {
        let mut r = Random(0xE8AC7);
        for hz in [QEMU_HZ, 1_000_000_000] {
            let s = scale(hz);
            for t in ticks(hz, &mut r) {
                assert_eq!(u128::from(s.ticks_to_ns(t)), exact_ns(hz, t), "{t} at {hz}");
            }
        }
        let qemu = scale(QEMU_HZ);
        assert_eq!(qemu.ticks_to_ns(1), 16);
        assert_eq!(qemu.ns_to_ticks(16), 1);
        assert_eq!(qemu.ns_to_ticks(17), 2);
        assert_eq!(qemu.ns_to_ticks(NANOS_PER_SEC), QEMU_HZ);
    }

    /// The least tick `c` with ticks_to_ns(c) >= ns, by search from below.
    fn least(s: Scale, ns: u64) -> u64 {
        let mut c = s.estimate(ns);
        while c < u64::MAX && s.ticks_to_ns(c) < ns {
            c += 1;
        }
        c
    }

    #[test]
    fn ticks_are_the_least_at_or_after() {
        let mut r = Random(0x1EA57);
        for hz in frequencies() {
            let s = scale(hz);
            let mut deadlines = vec![0, 1, 15, 16, 17, 41, 42, 125, 999, NANOS_PER_SEC];
            deadlines.extend((0..1_000).map(|_| r.below(BOUND_NS)));
            for ns in deadlines {
                let t = s.ns_to_ticks(ns);
                assert!(
                    s.ticks_to_ns(t) >= ns,
                    "{ns} ns at {hz} Hz: tick {t} is early"
                );
                assert!(
                    t == 0 || s.ticks_to_ns(t - 1) < ns,
                    "{ns} ns at {hz} Hz: tick {t} is not the least"
                );
            }
        }
    }

    #[test]
    fn correction_takes_at_most_two_steps() {
        let mut r = Random(0x2573);
        for hz in frequencies() {
            let s = scale(hz);
            for _ in 0..1_000 {
                let ns = r.below(STEPS_BOUND_NS);
                let (from, to) = (s.estimate(ns), least(s, ns));
                assert!(
                    from <= to && to - from <= 2,
                    "{ns} ns at {hz} Hz: {from}..{to}"
                );
                // The search from below agrees with ns_to_ticks.
                assert_eq!(s.ns_to_ticks(ns), to);
            }
        }
    }

    #[test]
    fn scale_keeps_order() {
        let mut r = Random(0x0DE7);
        for hz in frequencies() {
            let s = scale(hz);
            for _ in 0..1_000 {
                let (a, b) = (r.next(), r.next());
                let (lo, hi) = (a.min(b), a.max(b));
                assert!(s.ticks_to_ns(lo) <= s.ticks_to_ns(hi), "{lo} {hi} at {hz}");
                assert!(s.ns_to_ticks(lo) <= s.ns_to_ticks(hi), "{lo} {hi} at {hz}");
                assert!(s.ticks_to_ns(lo.saturating_add(1)) >= s.ticks_to_ns(lo));
            }
        }
    }

    #[test]
    fn scale_needs_a_frequency_and_saturates() {
        assert_eq!(Scale::new(0), None);
        assert_eq!(scale(A64_HZ).hz(), A64_HZ);
        assert_eq!(scale(A64_HZ).ticks_to_ns(u64::MAX), u64::MAX);
        assert_eq!(scale(2 * NANOS_PER_SEC).ns_to_ticks(u64::MAX), u64::MAX);
        assert_eq!(scale(u64::MAX).ticks_to_ns(u64::MAX), NANOS_PER_SEC - 1);
        assert_eq!(scale(1).ticks_to_ns(1), NANOS_PER_SEC);
    }

    #[test]
    fn next_release_is_absolute() {
        const T0: u64 = 1_000;
        const PERIOD: u64 = 250;
        // Before the first release, the first; at a release, the next.
        assert_eq!(next_release(T0, PERIOD, 0), T0);
        assert_eq!(next_release(T0, PERIOD, T0), T0 + PERIOD);
        // Late by any amount: the next deadline of the grid, never now
        // plus a period.
        for now in [T0 + 1, T0 + 249, T0 + 250, T0 + 251, T0 + 7_777] {
            let next = next_release(T0, PERIOD, now);
            assert!(next > now && next - now <= PERIOD, "{now}: {next}");
            assert_eq!((next - T0) % PERIOD, 0, "{now}: {next} is off the grid");
        }
        assert_eq!(next_release(T0, PERIOD, T0 + 7_777), T0 + 8_000);
        assert_eq!(next_release(T0, PERIOD, u64::MAX - 1), u64::MAX);
        assert_eq!(next_release(T0, 0, T0), u64::MAX);
    }
}
