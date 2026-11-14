// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! How long a holder of an entropy session waits for the service to come
//! back after it restarted.
//!
//! A session with the service dies with its instance. Init restarts the
//! service after a pause of 100 ms, the new instance registers its root with
//! the process service again, and a holder that finds its session closed
//! asks for a new one: through init's CONNECT when it has init's channel (a
//! program init started), through the root the process service keeps when
//! it is a loader. A request that comes in the gap between the two
//! instances fails, so a loader tries again every `PAUSE_NS` until `WAIT_NS`
//! went by since its first attempt, and then gives up: a start that needs
//! entropy and has none is refused with an error, and runs nowhere without it.
//!
//! The bound is three times the watchdog's deadline of the service (1 s): the
//! service that missed one deadline is killed at the second expiry, 1.25 s
//! in, init waits 100 ms and the new instance starts and registers in a few
//! milliseconds, so 3 s covers a restart with a margin of more than a
//! second for a loaded machine, and a service that init broke (it failed
//! again and again) costs a start 3 s at most.

/// The longest a start waits for a new instance, from its first attempt.
pub const WAIT_NS: u64 = 3_000_000_000;
/// The pause between two attempts.
pub const PAUSE_NS: u64 = 20_000_000;

/// Tries `attempt` until it gives a value or `WAIT_NS` went by since the
/// first try, with `pause(ns)` between two tries; `now` reads the clock in
/// nanoseconds. The last try comes after the bound is reached, so an
/// attempt that succeeds just then still counts.
pub fn heal<T>(
    mut now: impl FnMut() -> u64,
    mut attempt: impl FnMut() -> Option<T>,
    mut pause: impl FnMut(u64),
) -> Option<T> {
    let start = now();
    loop {
        if let Some(value) = attempt() {
            return Some(value);
        }
        let waited = now().saturating_sub(start);
        if waited >= WAIT_NS {
            return None;
        }
        pause(PAUSE_NS.min(WAIT_NS - waited));
    }
}

/// `heal`, or with `once` (a call that must not wait: GRND_NONBLOCK) one try
/// of `attempt` and no pause.
pub fn heal_or_once<T>(
    once: bool,
    now: impl FnMut() -> u64,
    mut attempt: impl FnMut() -> Option<T>,
    pause: impl FnMut(u64),
) -> Option<T> {
    if once && !cfg!(feature = "break-once-waits") {
        return attempt();
    }
    heal(now, attempt, pause)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn a_service_that_is_there_costs_no_pause() {
        let pauses = Cell::new(0);
        let got = heal(|| 0, || Some(7), |_| pauses.set(pauses.get() + 1));
        assert_eq!(got, Some(7));
        assert_eq!(pauses.get(), 0);
    }

    #[test]
    fn a_new_instance_is_found_after_the_gap() {
        let clock = Cell::new(1_000);
        let tries = Cell::new(0);
        let got = heal(
            || clock.get(),
            || {
                tries.set(tries.get() + 1);
                // The instance registers 100 ms after the first try.
                (clock.get() >= 1_000 + 100_000_000).then_some("session")
            },
            |ns| clock.set(clock.get() + ns),
        );
        assert_eq!(got, Some("session"));
        // 5 pauses of 20 ms, then the sixth try finds it.
        assert_eq!(tries.get(), 6);
    }

    #[test]
    fn a_service_that_never_comes_ends_the_wait_at_the_bound() {
        let clock = Cell::new(5);
        let tries = Cell::new(0u64);
        let waited = Cell::new(0u64);
        let got: Option<()> = heal(
            || clock.get(),
            || {
                tries.set(tries.get() + 1);
                None
            },
            |ns| {
                assert!(ns <= PAUSE_NS && ns > 0);
                waited.set(waited.get() + ns);
                clock.set(clock.get() + ns);
            },
        );
        assert_eq!(got, None);
        assert_eq!(waited.get(), WAIT_NS);
        assert_eq!(tries.get(), WAIT_NS / PAUSE_NS + 1);
    }

    #[test]
    fn a_pause_never_passes_the_bound() {
        // A clock that jumps: the last pause is the rest of the bound.
        let clock = Cell::new(0);
        let last = Cell::new(0);
        let got: Option<()> = heal(
            || clock.get(),
            || None,
            |ns| {
                last.set(ns);
                clock.set(clock.get() + ns + 5_000_000);
            },
        );
        assert_eq!(got, None);
        assert!(clock.get() >= WAIT_NS);
        assert!(last.get() <= PAUSE_NS);
    }

    #[test]
    fn a_slow_attempt_counts_in_the_bound() {
        // Each attempt itself takes 1.5 s (a CONNECT that waits): two
        // tries end the wait.
        let clock = Cell::new(0);
        let tries = Cell::new(0);
        let got: Option<()> = heal(
            || clock.get(),
            || {
                tries.set(tries.get() + 1);
                clock.set(clock.get() + 1_500_000_000);
                None
            },
            |ns| clock.set(clock.get() + ns),
        );
        assert_eq!(got, None);
        assert_eq!(tries.get(), 2);
    }

    #[test]
    fn a_call_that_must_not_wait_tries_once_and_never_pauses() {
        let pauses = Cell::new(0);
        let tries = Cell::new(0);
        let clock = Cell::new(0);
        let got: Option<u32> = heal_or_once(
            true,
            || clock.get(),
            || {
                tries.set(tries.get() + 1);
                None
            },
            |ns| {
                pauses.set(pauses.get() + 1);
                clock.set(clock.get() + ns);
            },
        );
        assert_eq!(got, None);
        assert_eq!((tries.get(), pauses.get()), (1, 0));
        // A try that succeeds gives its value, and a call that may wait waits.
        assert_eq!(heal_or_once(true, || 0, || Some(5), |_| {}), Some(5));
        let got: Option<u32> = heal_or_once(
            false,
            || clock.get(),
            || {
                tries.set(tries.get() + 1);
                None
            },
            |ns| clock.set(clock.get() + ns),
        );
        assert_eq!(got, None);
        assert!(tries.get() > 100);
    }
}
