// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The stop of the service, as a small state machine: SIGTERM to every process, a wait for them to
//! end, SIGKILL to those left, then the service ends. Init gives the record 5 s; the wait here is
//! 3 s, so the kills and the exit fit inside it. All-zero is the state before the stop, so the
//! struct lives in the service's zeroed memory.

/// How long the processes have to end after SIGTERM.
pub const WAIT_NS: u64 = 3_000_000_000;

/// What the service does next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Act {
    /// Send SIGTERM to every process, then call `termed`.
    Term,
    /// Wait for the ends until this time (ns on the scale of the timers).
    Wait(u64),
    /// Send SIGKILL to every process left, then call `killed`.
    Kill,
    /// Print the report and end.
    Exit,
}

/// The counts of the stop line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Processes SIGTERM was posted to (one whose action ignores it is not counted).
    pub termed: u32,
    /// Processes that were alive at the sweep and ended before the kill.
    pub ended: u32,
    /// Processes that were alive at the kill and got SIGKILL.
    pub killed: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stop {
    begun: bool,
    over: bool,
    until: u64,
    termed: u32,
    alive: u32,
    killed: u32,
}

impl Stop {
    pub const fn new() -> Self {
        Self {
            begun: false,
            over: false,
            until: 0,
            termed: 0,
            alive: 0,
            killed: 0,
        }
    }

    /// The stop notice came: the stop is on from here.
    pub const fn running(&self) -> bool {
        self.begun && !self.over
    }

    /// The first step, with `live` processes alive; none to signal ends the stop at once.
    pub fn begin(&mut self, live: u32) -> Act {
        self.begun = true;
        if live == 0 {
            self.over = true;
            return Act::Exit;
        }
        Act::Term
    }

    /// SIGTERM was posted to `posted` of the `alive` processes at `now`; the wait starts.
    pub fn termed(&mut self, now: u64, posted: u32, alive: u32) {
        self.termed = posted;
        self.alive = alive;
        self.until = now.saturating_add(WAIT_NS);
    }

    /// The step after an end, a timer or the end of the sweep.
    pub fn check(&mut self, now: u64, live: u32) -> Act {
        if self.over || live == 0 {
            self.over = true;
            Act::Exit
        } else if now >= self.until {
            Act::Kill
        } else {
            Act::Wait(self.until)
        }
    }

    /// SIGKILL went to the `alive` processes that were left.
    pub fn killed(&mut self, alive: u32) {
        self.killed = alive;
        self.over = true;
    }

    pub const fn report(&self) -> Report {
        Report {
            termed: self.termed,
            ended: self.alive.saturating_sub(self.killed),
            killed: self.killed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    #[test]
    fn nothing_alive_ends_at_once() {
        let mut stop = Stop::new();
        assert!(!stop.running());
        assert_eq!(stop.begin(0), Act::Exit);
        assert!(!stop.running());
        assert_eq!(
            stop.report(),
            Report {
                termed: 0,
                ended: 0,
                killed: 0
            }
        );
    }

    #[test]
    fn term_wait_then_kill_of_the_rest() {
        let mut stop = Stop::new();
        assert_eq!(stop.begin(3), Act::Term);
        assert!(stop.running());
        // SIGTERM is posted to two of the three: one ignores it.
        stop.termed(10 * S, 2, 3);
        assert_eq!(stop.check(10 * S, 3), Act::Wait(13 * S));
        // One ends by itself: the others are still waited for.
        assert_eq!(stop.check(11 * S, 2), Act::Wait(13 * S));
        assert_eq!(stop.check(13 * S - 1, 2), Act::Wait(13 * S));
        assert_eq!(stop.check(13 * S, 2), Act::Kill);
        stop.killed(2);
        assert!(!stop.running());
        assert_eq!(
            stop.report(),
            Report {
                termed: 2,
                ended: 1,
                killed: 2
            }
        );
    }

    #[test]
    fn all_ending_inside_the_wait_skips_the_kill() {
        let mut stop = Stop::new();
        assert_eq!(stop.begin(2), Act::Term);
        stop.termed(0, 2, 2);
        assert_eq!(stop.check(S, 1), Act::Wait(3 * S));
        assert_eq!(stop.check(2 * S, 0), Act::Exit);
        assert_eq!(
            stop.report(),
            Report {
                termed: 2,
                ended: 2,
                killed: 0
            }
        );
    }

    #[test]
    fn the_wait_fits_inside_the_record_deadline() {
        const { assert!(WAIT_NS < 5 * S) };
    }

    #[test]
    fn zeroed_memory_is_the_state_before_the_stop() {
        // SAFETY: the struct is plain integers and flags.
        let stop: Stop = unsafe { core::mem::zeroed() };
        assert!(!stop.running());
    }
}
