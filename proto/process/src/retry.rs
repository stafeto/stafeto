// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! When a service tries again to register its root with the process service.
//!
//! A service sends its root with Register at its start (the PIPE, NET and
//! ENTROPY marks). A registration that failed leaves the loaders with no
//! root, and a set-ID start that needs it is refused until one arrives.
//! `Retry` keeps the count of the failures and the instant of the next
//! attempt, so the service tries again with a growing pause and says so
//! when it does not succeed, without a line for every attempt.

/// The pause after the first failure and the longest pause, nanoseconds.
pub const FIRST_NS: u64 = 1_000_000_000;
pub const LONGEST_NS: u64 = 32_000_000_000;

/// What an attempt came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attempt {
    /// The root is registered, after `failures` attempts that failed.
    Registered { failures: u32 },
    /// The attempt failed: the `count`th one, to be tried again after
    /// `wait_ns`; `report` says whether the service tells of it (the
    /// first failure and every one whose count is a power of two).
    Failed {
        count: u32,
        wait_ns: u64,
        report: bool,
    },
}

/// The pause after the `count`th failure: FIRST_NS, doubling, up to LONGEST_NS.
pub const fn wait_after(count: u32) -> u64 {
    let shift = if count == 0 { 0 } else { count - 1 };
    if shift >= 5 {
        LONGEST_NS
    } else {
        FIRST_NS << shift
    }
}

/// The state of a registration that may need more than one attempt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Retry {
    failures: u32,
    next_ns: u64,
    done: bool,
}

impl Retry {
    pub const fn new() -> Self {
        Self {
            failures: 0,
            next_ns: 0,
            done: false,
        }
    }

    /// Whether the root is registered.
    pub const fn is_done(&self) -> bool {
        self.done
    }

    /// The attempts that failed so far.
    pub const fn failures(&self) -> u32 {
        self.failures
    }

    /// Whether an attempt is due at `now_ns`: the root is not registered and
    /// the pause after the last failure has passed.
    pub const fn due(&self, now_ns: u64) -> bool {
        !self.done && now_ns >= self.next_ns
    }

    /// The result of an attempt made at `now_ns`.
    pub fn record(&mut self, now_ns: u64, ok: bool) -> Attempt {
        if ok {
            self.done = true;
            return Attempt::Registered {
                failures: self.failures,
            };
        }
        self.failures = self.failures.saturating_add(1);
        let wait_ns = wait_after(self.failures);
        self.next_ns = now_ns.saturating_add(wait_ns);
        Attempt::Failed {
            count: self.failures,
            wait_ns,
            report: self.failures.is_power_of_two(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_registration_is_due_again_after_a_growing_pause() {
        let mut retry = Retry::new();
        assert!(retry.due(0));
        let mut now = 100;
        let mut waits = Vec::new();
        for _ in 0..8 {
            assert!(retry.due(now));
            match retry.record(now, false) {
                Attempt::Failed { wait_ns, .. } => {
                    assert!(!retry.due(now + wait_ns - 1));
                    assert!(retry.due(now + wait_ns));
                    waits.push(wait_ns);
                    now += wait_ns;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(
            waits,
            [
                FIRST_NS,
                2 * FIRST_NS,
                4 * FIRST_NS,
                8 * FIRST_NS,
                16 * FIRST_NS,
                LONGEST_NS,
                LONGEST_NS,
                LONGEST_NS
            ]
        );
        assert_eq!(retry.failures(), 8);
    }

    #[test]
    fn a_registered_root_is_never_due_again() {
        let mut retry = Retry::new();
        retry.record(0, false);
        assert_eq!(retry.record(5, true), Attempt::Registered { failures: 1 });
        assert!(retry.is_done());
        assert!(!retry.due(u64::MAX));
        // The first try succeeding is no failure.
        let mut first = Retry::new();
        assert_eq!(first.record(0, true), Attempt::Registered { failures: 0 });
    }

    #[test]
    fn failures_are_reported_at_powers_of_two_only() {
        let mut retry = Retry::new();
        let mut reported = Vec::new();
        for _ in 0..17 {
            if let Attempt::Failed { count, report, .. } = retry.record(0, false)
                && report
            {
                reported.push(count);
            }
        }
        assert_eq!(reported, [1, 2, 4, 8, 16]);
    }
}
