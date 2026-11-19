// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The lines init prints when the watchdog finds a service silent, before it kills it: what the
//! kernel says of the service's thread and of the console driver's thread, and of their time
//! budgets, at the moment of the finding. They tell a thread that waits for a reply no one sends
//! (`AwaitingReply` or `Sending`, with the driver in `Receiving`), a thread that is ready and
//! gets no CPU (`Ready` at a low level, or a driver whose time `ran` stands still between two
//! findings), and a clock that jumped (init's reading and how late its expiry was handled).
//!
//! What the kernel does not give init is left out: the CPU a thread stands on now (the lines
//! name the CPUs the record asks for), and what a blocked thread waits on (the state says
//! whether it waits for a request to be taken or for a reply, and names no one).
//!
//! This module only renders values; `serve.rs` reads them and prints.

use abi::{BUDGET_FREE, BUDGET_FULL, BUDGET_GONE, ThreadState};
use core::fmt;

/// What `object_info` gives of a thread, with its time in microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadLook {
    pub state: ThreadState,
    pub base: u8,
    pub level: u8,
    /// The time the thread has run, and the times a higher level took it off the CPU.
    pub ran_us: u64,
    pub preempts: u64,
}

/// What `object_info` gives of a time budget, in microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetLook {
    pub name: &'static str,
    pub budget_us: u64,
    pub period_us: u64,
    pub left_us: u64,
    pub low: u64,
    pub state: u64,
    pub overruns: u64,
    pub pending: u64,
}

impl BudgetLook {
    /// A place to fill.
    pub const EMPTY: BudgetLook = BudgetLook {
        name: "",
        budget_us: 0,
        period_us: 0,
        left_us: 0,
        low: 0,
        state: BUDGET_FREE,
        overruns: 0,
        pending: 0,
    };
}

/// One thread of the report: the record, its role and what was read.
pub struct Look<'a> {
    pub name: &'a str,
    /// "silent service" or "console driver".
    pub role: &'a str,
    /// The CPUs the record asks for (a mask).
    pub cpus: u8,
    /// Init's clock and the lateness of the expiry, on the line of the silent service.
    pub moment: Option<Moment>,
    /// None when init holds no handle to the thread or the call failed.
    pub thread: Option<ThreadLook>,
    pub budgets: &'a [BudgetLook],
}

/// Init's clock and the lateness of the expiry that found the service silent.
pub struct Moment {
    pub now_us: u64,
    /// How long after its deadline the second expiry was handled.
    pub late_us: u64,
    /// The times in a row an expiry came too late to judge (`Watched::late`).
    pub late_count: u32,
}

fn state_name(state: ThreadState) -> StateName {
    StateName(state)
}

struct StateName(ThreadState);

impl fmt::Display for StateName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ThreadState::Stopped => f.write_str("stopped"),
            ThreadState::Ready => f.write_str("ready"),
            ThreadState::Running => f.write_str("running"),
            ThreadState::Receiving => f.write_str("receiving"),
            ThreadState::Sending => f.write_str("sending (request queued)"),
            ThreadState::AwaitingReply => f.write_str("awaiting a reply"),
            ThreadState::Ended => f.write_str("ended"),
            ThreadState::Parked => f.write_str("parked"),
            ThreadState::Unknown(code) => write!(f, "state {code}"),
        }
    }
}

fn budget_state(state: u64) -> &'static str {
    match state {
        BUDGET_FREE => "free",
        BUDGET_FULL => "full",
        BUDGET_GONE => "gone",
        _ => "?",
    }
}

impl fmt::Display for Moment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "at {}.{:03} ms, expiry {}.{:03} ms late, late {} times in a row",
            self.now_us / 1000,
            self.now_us % 1000,
            self.late_us / 1000,
            self.late_us % 1000,
            self.late_count
        )
    }
}

impl fmt::Display for Look<'_> {
    /// `init: <name> <role> [<moment>]: thread <state> base B level L cpus 0xM ran N us preempts P;
    /// budget <name> left L of C us per T us, <state>, low V, overruns O, pending Q`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "init: {} {}", self.name, self.role)?;
        if let Some(moment) = &self.moment {
            write!(f, " {moment}")?;
        }
        f.write_str(": ")?;
        match self.thread {
            Some(t) => write!(
                f,
                "thread {} base {} level {} cpus {:#x} ran {} us preempts {}",
                state_name(t.state),
                t.base,
                t.level,
                self.cpus,
                t.ran_us,
                t.preempts
            )?,
            None => write!(f, "thread unknown, cpus {:#x}", self.cpus)?,
        }
        for b in self.budgets {
            write!(
                f,
                "; budget {} left {} of {} us per {} us, {}, low {}, overruns {}, pending {}",
                b.name,
                b.left_us,
                b.budget_us,
                b.period_us,
                budget_state(b.state),
                b.low,
                b.overruns,
                b.pending
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::{String, ToString};

    fn thread(state: ThreadState) -> ThreadLook {
        ThreadLook {
            state,
            base: 50,
            level: 32,
            ran_us: 1234,
            preempts: 7,
        }
    }

    const SERVE: BudgetLook = BudgetLook {
        name: "serve",
        budget_us: 75,
        period_us: 5000,
        left_us: 20,
        low: 32,
        state: BUDGET_GONE,
        overruns: 63,
        pending: 2,
    };

    #[test]
    fn the_line_of_a_silent_service_names_state_levels_time_and_budget() {
        let budgets = [SERVE];
        let look = Look {
            name: "tty",
            role: "silent service",
            cpus: 1,
            moment: Some(Moment {
                now_us: 52_123_456,
                late_us: 3_200,
                late_count: 0,
            }),
            thread: Some(thread(ThreadState::AwaitingReply)),
            budgets: &budgets,
        };
        assert_eq!(
            look.to_string(),
            "init: tty silent service at 52123.456 ms, expiry 3.200 ms late, late 0 times in a row: \
             thread awaiting a reply base 50 level 32 cpus 0x1 \
             ran 1234 us preempts 7; budget serve left 20 of 75 us per 5000 us, gone, low 32, \
             overruns 63, pending 2"
        );
    }

    #[test]
    fn every_state_has_a_word_and_a_thread_that_could_not_be_read_says_so() {
        let mut seen = String::new();
        for state in [
            ThreadState::Stopped,
            ThreadState::Ready,
            ThreadState::Running,
            ThreadState::Receiving,
            ThreadState::Sending,
            ThreadState::AwaitingReply,
            ThreadState::Ended,
            ThreadState::Parked,
            ThreadState::Unknown(9),
        ] {
            let look = Look {
                name: "uart",
                role: "console driver",
                cpus: 2,
                moment: None,
                thread: Some(thread(state)),
                budgets: &[],
            };
            let line = look.to_string();
            assert!(!seen.contains(&line));
            seen.push_str(&line);
            assert!(line.starts_with("init: uart console driver: thread "));
            assert!(!line.contains("budget"));
        }
        let unknown = Look {
            name: "uart",
            role: "console driver",
            cpus: 2,
            moment: None,
            thread: None,
            budgets: &[],
        };
        assert_eq!(
            unknown.to_string(),
            "init: uart console driver: thread unknown, cpus 0x2"
        );
    }

    #[test]
    fn the_budget_states_and_the_clock_are_written_out() {
        assert_eq!(budget_state(BUDGET_FREE), "free");
        assert_eq!(budget_state(BUDGET_FULL), "full");
        assert_eq!(budget_state(BUDGET_GONE), "gone");
        assert_eq!(budget_state(9), "?");
        let moment = Moment {
            now_us: 52_123_456,
            late_us: 3_200,
            late_count: 2,
        };
        assert_eq!(
            moment.to_string(),
            "at 52123.456 ms, expiry 3.200 ms late, late 2 times in a row"
        );
    }

    #[test]
    fn two_budgets_are_two_clauses_on_the_one_line() {
        let two = [
            SERVE,
            BudgetLook {
                name: "work",
                ..SERVE
            },
        ];
        let look = Look {
            name: "x",
            role: "silent service",
            cpus: 3,
            moment: None,
            thread: Some(thread(ThreadState::Ready)),
            budgets: &two,
        };
        let line = look.to_string();
        assert_eq!(line.matches("; budget ").count(), 2);
        assert!(!line.contains('\n'));
    }
}
