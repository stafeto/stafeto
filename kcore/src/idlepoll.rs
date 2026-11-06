// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The window of the poll in the idle loop (spec 8.1) and the table of the
//! machines that poll. A CPU with nothing to do spins for `window` ticks
//! before it sleeps in `wfi`, so that a command another CPU posts meanwhile
//! needs no SGI and no wake-up from `wfi`. The window is the CPU's own and
//! follows its wake-ups as the window of Linux's `cpuidle-haltpoll` does.

/// The longest window, in nanoseconds.
pub const LIMIT_NS: u64 = 50_000;
/// The first window after zero, and the shortest one that is kept.
pub const START_NS: u64 = 10_000;

/// The window of one CPU, in ticks of the counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poll {
    window: u64,
    start: u64,
    limit: u64,
}

impl Poll {
    /// A window of zero with no limits yet: `scale` sets them.
    pub const fn new() -> Poll {
        Poll {
            window: 0,
            start: 0,
            limit: 0,
        }
    }

    /// Sets the start and the limit for a counter of `hz` ticks a second.
    pub fn scale(&mut self, hz: u64) {
        self.start = (u128::from(hz) * u128::from(START_NS) / 1_000_000_000) as u64;
        self.limit = (u128::from(hz) * u128::from(LIMIT_NS) / 1_000_000_000) as u64;
    }

    /// The window now, in ticks; zero sleeps at once.
    pub const fn window(&self) -> u64 {
        self.window
    }

    /// The CPU woke `slept` ticks after it began to wait. A wake-up inside
    /// the window leaves it; one after the window but within the limit
    /// doubles it (from the start when it was shorter); one after the limit
    /// halves it, and a window under the start becomes zero.
    pub fn woke(&mut self, slept: u64) {
        if slept <= self.window {
            return;
        }
        if slept <= self.limit {
            self.window = self
                .window
                .saturating_mul(2)
                .max(self.start)
                .min(self.limit);
        } else {
            self.window /= 2;
            if self.window < self.start {
                self.window = 0;
            }
        }
    }
}

impl Default for Poll {
    fn default() -> Self {
        Poll::new()
    }
}

/// The maker of the CPU in MIDR_EL1 (bits 31:24) of a guest of Apple's
/// hypervisor: HVF under QEMU and Virtualization.framework both set it.
const APPLE: u64 = 0x61;

/// Whether the machine with this MIDR_EL1 polls by default. Others (QEMU's
/// TCG, the A64 of the PinePhone, AWS) do not, until measured there.
pub const fn enabled(midr: u64) -> bool {
    (midr >> 24) & 0xff == APPLE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poll() -> Poll {
        let mut p = Poll::new();
        // 1 GHz: a tick is a nanosecond.
        p.scale(1_000_000_000);
        p
    }

    #[test]
    fn the_scale_follows_the_counter() {
        let mut p = Poll::new();
        p.scale(62_500_000);
        assert_eq!((p.start, p.limit), (625, 3_125));
    }

    #[test]
    fn a_wake_after_the_limit_from_zero_changes_nothing() {
        let mut p = poll();
        p.woke(LIMIT_NS + 1);
        assert_eq!(p.window(), 0);
    }

    #[test]
    fn zero_grows_to_the_start() {
        let mut p = poll();
        p.woke(LIMIT_NS);
        assert_eq!(p.window(), START_NS);
    }

    #[test]
    fn a_wake_after_the_window_doubles_it() {
        let mut p = poll();
        p.woke(20_000);
        p.woke(15_000);
        assert_eq!(p.window(), 20_000);
        p.woke(25_000);
        assert_eq!(p.window(), 40_000);
    }

    #[test]
    fn the_window_stops_at_the_limit() {
        let mut p = poll();
        p.woke(1);
        p.woke(LIMIT_NS);
        p.woke(LIMIT_NS);
        p.woke(LIMIT_NS);
        assert_eq!(p.window(), LIMIT_NS);
        p.woke(LIMIT_NS);
        assert_eq!(p.window(), LIMIT_NS);
    }

    #[test]
    fn a_wake_inside_the_window_keeps_it() {
        let mut p = poll();
        p.woke(LIMIT_NS);
        p.woke(LIMIT_NS);
        let w = p.window();
        p.woke(w);
        p.woke(1);
        assert_eq!(p.window(), w);
    }

    #[test]
    fn a_wake_after_the_limit_halves_it() {
        let mut p = poll();
        for _ in 0..3 {
            p.woke(LIMIT_NS);
        }
        assert_eq!(p.window(), 40_000);
        p.woke(LIMIT_NS + 1);
        assert_eq!(p.window(), 20_000);
        p.woke(LIMIT_NS + 1);
        assert_eq!(p.window(), 10_000);
    }

    #[test]
    fn a_window_under_the_start_becomes_zero() {
        let mut p = poll();
        p.woke(LIMIT_NS);
        assert_eq!(p.window(), START_NS);
        p.woke(LIMIT_NS + 1);
        assert_eq!(p.window(), 0);
    }

    #[test]
    fn an_idle_machine_gets_to_zero_in_three_long_sleeps() {
        let mut p = poll();
        for _ in 0..3 {
            p.woke(LIMIT_NS);
        }
        assert_eq!(p.window(), 40_000);
        for _ in 0..3 {
            p.woke(10 * LIMIT_NS);
        }
        assert_eq!(p.window(), 0);
    }

    #[test]
    fn the_table_takes_the_vendor_of_apple() {
        assert!(enabled(0x610f_0000));
        assert!(enabled(0x6100_0000));
        assert!(!enabled(0x410f_d034)); // Cortex-A53
        assert!(!enabled(0x410f_d070)); // TCG -cpu max reports Arm's
        assert!(!enabled(0));
        assert!(!enabled(0x0061_0000)); // 0x61 in the wrong field
    }
}
