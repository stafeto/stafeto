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
    /// What init knows besides the thread: its refused HEARTBEATs, the service's channel and
    /// the CPUs' sleep. Only the line of a silent service has it.
    pub diag: Option<Diag<'a>>,
}

/// What a CPU counts of its time, in microseconds (`object_info` CPU).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuSleep {
    /// The time since the CPU started, and the time it slept in `wfi`.
    pub since_us: u64,
    pub idle_us: u64,
}

/// The CPUs whose sleep the line of a silent service tells.
pub const DIAG_CPUS: usize = 8;

/// What init noted at the first miss of a service, when it sent the nudge: its own clock and what
/// each CPU counted then. The line of the silence tells the sleep of each CPU since.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nudged {
    pub at_us: u64,
    pub up: usize,
    pub cpus: [CpuSleep; DIAG_CPUS],
}

impl Nudged {
    /// The sleep of CPU `n` and the time it ran since the nudge, given what it counts now. None
    /// for a CPU not noted at the nudge.
    pub fn window(&self, n: usize, now: CpuSleep) -> Option<CpuSleep> {
        let then = *self.cpus[..self.up].get(n)?;
        Some(CpuSleep {
            since_us: now.since_us.saturating_sub(then.since_us),
            idle_us: now.idle_us.saturating_sub(then.idle_us),
        })
    }
}

/// The state of the service's channel (`object_info` CHANNEL): requests queued and receivers
/// waiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelLook {
    pub queued: u64,
    pub receivers: u64,
}

/// What init adds to the line of a silent service, to tell where its sign of life got lost: a
/// service whose HEARTBEATs init refused (the count and the instant of the last answered 0), a
/// channel with a request queued or no receiver, a CPU that slept through the service's deadline.
pub struct Diag<'a> {
    pub refused: u32,
    pub last_beat_us: Option<u64>,
    /// None when init holds no channel to the service or the call failed.
    pub channel: Option<ChannelLook>,
    /// The CPU init runs on, and what each CPU of the machine counts, in the order of its number.
    pub init_cpu: Option<u64>,
    pub cpus: &'a [CpuSleep],
    /// What init noted when it sent the nudge, None when none went.
    pub nudged: Option<Nudged>,
}

/// Microseconds as `S.mmm ms`.
struct Ms(u64);

impl fmt::Display for Ms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:03} ms", self.0 / 1000, self.0 % 1000)
    }
}

impl fmt::Display for Diag<'_> {
    /// `; heartbeats refused R, last accepted at T ms|never; channel queued Q, receivers V|unknown;
    /// init on cpu C; nudged at T ms; cpu 0 slept I of S ms, W of U ms since the nudge; cpu 1 ...`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "; heartbeats refused {}, last accepted ", self.refused)?;
        match self.last_beat_us {
            Some(us) => write!(f, "at {}", Ms(us))?,
            None => f.write_str("never")?,
        }
        match self.channel {
            Some(c) => write!(
                f,
                "; channel queued {}, receivers {}",
                c.queued, c.receivers
            )?,
            None => f.write_str("; channel unknown")?,
        }
        match self.init_cpu {
            Some(cpu) => write!(f, "; init on cpu {cpu}")?,
            None => f.write_str("; init on cpu ?")?,
        }
        if let Some(n) = &self.nudged {
            write!(f, "; nudged at {}", Ms(n.at_us))?;
        }
        for (n, c) in self.cpus.iter().enumerate() {
            write!(f, "; cpu {n} slept {} of {}", Ms(c.idle_us), Ms(c.since_us))?;
            if let Some(w) = self.nudged.and_then(|nudged| nudged.window(n, *c)) {
                write!(
                    f,
                    ", {} of {} since the nudge",
                    Ms(w.idle_us),
                    Ms(w.since_us)
                )?;
            }
        }
        Ok(())
    }
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
        if let Some(diag) = &self.diag {
            write!(f, "{diag}")?;
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
            diag: None,
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
                diag: None,
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
            diag: None,
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
            diag: None,
        };
        let line = look.to_string();
        assert_eq!(line.matches("; budget ").count(), 2);
        assert!(!line.contains('\n'));
    }

    /// The planted fault of path 3 and 7: HEARTBEATs refused, a request queued with no receiver,
    /// and a CPU that slept through the deadline, all on the one line of the silent service.
    #[test]
    fn the_line_of_a_silent_service_adds_the_refusals_the_channel_and_the_sleep_of_the_cpus() {
        let budgets = [SERVE];
        let cpus = [
            CpuSleep {
                since_us: 1_666_399_000,
                idle_us: 1_600_000_500,
            },
            CpuSleep {
                since_us: 1_660_000_000,
                idle_us: 12,
            },
        ];
        let look = Look {
            name: "tty",
            role: "silent service",
            cpus: 1,
            moment: Some(Moment {
                now_us: 1_666_399,
                late_us: 2_050,
                late_count: 0,
            }),
            thread: Some(thread(ThreadState::Receiving)),
            budgets: &budgets,
            diag: Some(Diag {
                refused: 3,
                last_beat_us: Some(1_100_250),
                channel: Some(ChannelLook {
                    queued: 1,
                    receivers: 0,
                }),
                init_cpu: Some(1),
                cpus: &cpus,
                nudged: None,
            }),
        };
        let line = look.to_string();
        assert!(line.starts_with("init: tty silent service at 1666.399 ms, "));
        assert!(line.ends_with(
            "pending 2; heartbeats refused 3, last accepted at 1100.250 ms; \
             channel queued 1, receivers 0; init on cpu 1; \
             cpu 0 slept 1600000.500 ms of 1666399.000 ms; cpu 1 slept 0.012 ms of 1660000.000 ms"
        ));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn what_init_could_not_read_is_said_so_and_a_boot_with_no_fault_prints_none_of_it() {
        let diag = Diag {
            refused: 0,
            last_beat_us: None,
            channel: None,
            init_cpu: None,
            cpus: &[],
            nudged: None,
        };
        assert_eq!(
            diag.to_string(),
            "; heartbeats refused 0, last accepted never; channel unknown; init on cpu ?"
        );
        // The line of the console driver has no `diag`: no new words there.
        let driver = Look {
            name: "uart",
            role: "console driver",
            cpus: 2,
            moment: None,
            thread: None,
            budgets: &[],
            diag: None,
        };
        assert!(!driver.to_string().contains("heartbeats"));
    }

    /// The planted fault of the window: CPU 1 slept 200 ms of the 250 ms between the nudge and the
    /// silence, CPU 0 slept none of it, and a CPU that came up after the nudge has no window.
    #[test]
    fn the_line_tells_the_sleep_of_each_cpu_since_the_nudge() {
        let at = |since_us, idle_us| CpuSleep { since_us, idle_us };
        let mut then = [at(0, 0); DIAG_CPUS];
        then[0] = at(2_000_000, 88_000);
        then[1] = at(1_950_000, 190_000);
        let nudged = Nudged {
            at_us: 2_133_940,
            up: 2,
            cpus: then,
        };
        let now = [
            at(2_250_100, 88_107),
            at(2_200_300, 390_926),
            at(2_337_623, 643_436),
        ];
        assert_eq!(nudged.window(0, now[0]), Some(at(250_100, 107)));
        assert_eq!(nudged.window(1, now[1]), Some(at(250_300, 200_926)));
        assert_eq!(nudged.window(2, now[2]), None);
        assert_eq!(
            nudged.window(0, at(1, 1)),
            Some(at(0, 0)),
            "a counter that reads lower saturates at 0"
        );
        let diag = Diag {
            refused: 0,
            last_beat_us: None,
            channel: None,
            init_cpu: Some(0),
            cpus: &now,
            nudged: Some(nudged),
        };
        assert_eq!(
            diag.to_string(),
            "; heartbeats refused 0, last accepted never; channel unknown; init on cpu 0; \
             nudged at 2133.940 ms; \
             cpu 0 slept 88.107 ms of 2250.100 ms, 0.107 ms of 250.100 ms since the nudge; \
             cpu 1 slept 390.926 ms of 2200.300 ms, 200.926 ms of 250.300 ms since the nudge; \
             cpu 2 slept 643.436 ms of 2337.623 ms"
        );
    }
}
