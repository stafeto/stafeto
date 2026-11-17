// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The steps a refused request makes on its own lent time (`rt::service::Service::settle`): a
//! service that refuses a request for a resource that the cleanup after departed clients frees
//! (a table of descriptions, pages, places of the table of sessions) first makes a few steps of
//! that cleanup. What they came to is `Settled`. A call that finds a debt makes at least one step
//! of progress, so the debt is spent after a bounded number of calls and a client that sends the
//! request again on `TRY_AGAIN` never waits for good.

/// What the steps of settling came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settled {
    /// No step made progress: no cleanup is due, or what is due waits for something outside the
    /// service. The refusal stands.
    Nothing,
    /// The steps made progress and cleanup is left. The request is answered with the internal
    /// `TRY_AGAIN` unless asking the handler again succeeds, and the client library sends it
    /// again without showing the answer to the program.
    Pending,
    /// The steps made progress and no cleanup is left.
    Done,
}

/// The steps of cleanup a refused request makes at most.
pub const SETTLE_STEPS: usize = 3;
/// The ticks after which a request that settles makes no further step (the step that crosses the
/// bound ends first).
pub const SETTLE_TICKS: u64 = 8_000;

/// Runs `step` (None when it found nothing to do or made no progress, else Some(whether cleanup
/// is left after it)) up to `SETTLE_STEPS` times or until `SETTLE_TICKS` of `now` have passed,
/// whichever comes first. A step that makes no progress ends the run: the service has nothing more
/// it can do now.
pub fn run(mut now: impl FnMut() -> u64, mut step: impl FnMut() -> Option<bool>) -> Settled {
    let began = now();
    let mut progressed = false;
    let mut left = false;
    for n in 0..SETTLE_STEPS {
        if n != 0 && now().wrapping_sub(began) >= SETTLE_TICKS {
            break;
        }
        match step() {
            Some(more) => {
                progressed = true;
                left = more;
                if !more {
                    break;
                }
            }
            None => break,
        }
    }
    match (progressed, left) {
        (false, _) => Settled::Nothing,
        (true, true) => Settled::Pending,
        (true, false) => Settled::Done,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A debt of `n` steps, one unit each, worked off by calls that each make at most
    /// `SETTLE_STEPS` of them: every call that finds a debt makes progress, and the number of
    /// calls is the debt over the steps of a call, rounded up.
    #[test]
    fn every_call_that_finds_a_debt_makes_progress_and_the_calls_are_bounded() {
        for debt in [0usize, 1, 2, 3, 4, 7, 1106] {
            let mut left = debt;
            let mut calls = 0;
            loop {
                let before = left;
                let settled = run(
                    || 0,
                    || {
                        (left != 0).then(|| {
                            left -= 1;
                            left != 0
                        })
                    },
                );
                match settled {
                    Settled::Nothing => {
                        assert_eq!(before, 0, "a call that finds a debt works at it");
                        break;
                    }
                    Settled::Pending => assert!(left < before && left != 0),
                    Settled::Done => {
                        assert_eq!(left, 0);
                        calls += 1;
                        break;
                    }
                }
                calls += 1;
            }
            assert_eq!(calls, debt.div_ceil(SETTLE_STEPS), "debt {debt}");
        }
    }

    #[test]
    fn a_step_without_progress_ends_the_run_and_the_refusal_stands() {
        assert_eq!(run(|| 0, || None), Settled::Nothing);
        let mut n = 0;
        let settled = run(
            || 0,
            || {
                n += 1;
                (n == 1).then_some(true)
            },
        );
        assert_eq!(settled, Settled::Pending, "progress made, then a stall");
        assert_eq!(n, 2);
    }

    #[test]
    fn the_run_stops_when_its_ticks_are_spent_after_at_least_one_step() {
        let mut clock = 0;
        let mut steps = 0;
        let settled = run(
            || {
                clock += SETTLE_TICKS;
                clock
            },
            || {
                steps += 1;
                Some(true)
            },
        );
        assert_eq!((settled, steps), (Settled::Pending, 1));
    }
}
