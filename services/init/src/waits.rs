// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The waits of a record (spec 5, section 4). A record with `waits` does not
//! start when init's turn for it comes: it stands at a gate until each
//! service it names sent READY (proto_init `Ready`: the service says it
//! finished its own start and serves complete answers), or its deadline
//! passed, or an instance of a named service ended before its READY. The
//! three ways to start are the three `Release`s; the last two start the
//! record all the same, with a line that says why (the record's own program
//! decides what to do without the service). A record that stood at the gate
//! and failed stands there again for its next start.
//!
//! The gate is plain data and calls nothing: `serve.rs` makes one when it is
//! about to launch a record with waits, feeds it the READY and the end of
//! each service and the expiry of the record's timer, and launches the
//! record when a call answers `Step::Start`.

use crate::table::{Record, WAITS_MAX, Wait};
use core::fmt;
use proto_init::State;

const MS: u64 = 1_000_000;

/// What init knows of a named service when a record comes to its gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// No instance has said READY yet (or the instance is not running).
    NotReady,
    /// The running instance said READY.
    Ready,
    /// The record ended or broke for good before any READY, so none will come.
    Over,
    /// The service said READY and has ended since: there is nothing to wait for, and nothing
    /// went wrong that a line should say.
    Gone,
}

/// Why a record starts after its wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Release {
    /// Every service named sent READY.
    Ready,
    /// The deadline passed with `service` not ready; the deadline in ms.
    Late {
        service: &'static str,
        deadline_ms: u32,
    },
    /// An instance of `service` ended before its READY.
    Ended { service: &'static str },
}

/// The line init prints for the two ways that are no READY, after
/// `init: `.
impl fmt::Display for Release {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Release::Ready => write!(f, "ready"),
            Release::Late {
                service,
                deadline_ms,
            } if deadline_ms % 1000 == 0 => {
                write!(f, "{service} not ready after {} s", deadline_ms / 1000)
            }
            Release::Late {
                service,
                deadline_ms,
            } => write!(f, "{service} not ready after {deadline_ms} ms"),
            Release::Ended { service } => write!(f, "{service} ended before ready"),
        }
    }
}

/// What a call on a gate decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The record goes on waiting.
    Hold,
    /// The record starts, for this reason.
    Start(Release),
}

/// The gate of one record: which of its waits are met, and the one deadline
/// (the longest of its waits, counted from the moment the gate opened).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gate {
    waits: &'static [Wait],
    ready: [bool; WAITS_MAX],
    deadline: u64,
}

impl Gate {
    /// The gate of `record` at `now` (ns), when it has to wait: the services
    /// of `standing` that are ready count as met. Err with the release when
    /// the record need not wait: every service is ready already, or one is
    /// over without a READY.
    pub fn open(
        record: &Record,
        now: u64,
        standing: impl Fn(&str) -> Standing,
    ) -> Result<Gate, Release> {
        let mut gate = Gate {
            waits: record.waits,
            ready: [false; WAITS_MAX],
            deadline: now.saturating_add(
                u64::from(
                    record
                        .waits
                        .iter()
                        .map(|w| w.deadline_ms)
                        .max()
                        .unwrap_or(0),
                ) * MS,
            ),
        };
        for (i, wait) in record.waits.iter().enumerate() {
            match standing(wait.service) {
                Standing::Ready | Standing::Gone => gate.ready[i] = true,
                Standing::Over => {
                    return Err(Release::Ended {
                        service: wait.service,
                    });
                }
                Standing::NotReady => {}
            }
        }
        match gate.met() {
            true => Err(Release::Ready),
            false => Ok(gate),
        }
    }

    /// The deadline, in ns on the clock of `open`'s `now`: where the
    /// record's timer goes.
    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    fn met(&self) -> bool {
        self.ready[..self.waits.len()].iter().all(|&r| r)
    }

    fn position(&self, service: &str) -> Option<usize> {
        self.waits.iter().position(|w| w.service == service)
    }

    /// READY of `service`: its wait is met; the record starts when each is.
    /// A READY of a service that is not named, or a second one, changes
    /// nothing.
    pub fn ready(&mut self, service: &str) -> Step {
        if let Some(i) = self.position(service) {
            self.ready[i] = true;
        }
        if self.met() {
            Step::Start(Release::Ready)
        } else {
            Step::Hold
        }
    }

    /// An instance of `service` ended: before its READY that is the end of
    /// the wait, since no READY comes from a service that is gone (spec 5,
    /// section 4); after it, nothing.
    pub fn ended(&mut self, service: &str) -> Step {
        match self.position(service) {
            Some(i) if !self.ready[i] => Step::Start(Release::Ended {
                service: self.waits[i].service,
            }),
            _ => Step::Hold,
        }
    }

    /// The record's timer expired at `now`: past the deadline the record
    /// starts, naming the first service that is not ready; an expiry before
    /// it is a stale one (a deadline that moved) and changes nothing.
    pub fn expired(&self, now: u64) -> Step {
        if now < self.deadline {
            return Step::Hold;
        }
        match self.waits.iter().zip(self.ready).find(|(_, ready)| !ready) {
            Some((wait, _)) => Step::Start(Release::Late {
                service: wait.service,
                deadline_ms: self.waits.iter().map(|w| w.deadline_ms).max().unwrap_or(0),
            }),
            None => Step::Start(Release::Ready),
        }
    }
}

/// Whether a READY from a record is taken: only the instance of a service,
/// once it registered (RUNNING). Any other record, or a service still
/// starting, gets BAD_STATE.
pub fn ready_taken(is_service: bool, state: State) -> bool {
    is_service && state == State::Running
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table;

    const WAIT_ONE: &[Wait] = &[Wait {
        service: "pkgd",
        deadline_ms: 30_000,
    }];
    const WAIT_TWO: &[Wait] = &[
        Wait {
            service: "pkgd",
            deadline_ms: 30_000,
        },
        Wait {
            service: "blk",
            deadline_ms: 10_000,
        },
    ];

    fn waiter(waits: &'static [Wait]) -> Record {
        Record {
            name: "launcher",
            waits,
            ..table::base::LAUNCHER
        }
    }

    fn open(waits: &'static [Wait], now: u64) -> Gate {
        Gate::open(&waiter(waits), now, |_| Standing::NotReady).unwrap()
    }

    /// A READY before the deadline starts the record at once, and nothing
    /// else does.
    #[test]
    fn a_ready_before_the_deadline_starts_the_record() {
        let mut gate = open(WAIT_ONE, 5 * MS);
        assert_eq!(gate.deadline(), 5 * MS + 30_000 * MS);
        assert_eq!(gate.expired(5 * MS), Step::Hold);
        assert_eq!(gate.ended("blk"), Step::Hold);
        assert_eq!(gate.ready("blk"), Step::Hold, "a service that is not named");
        assert_eq!(gate.ready("pkgd"), Step::Start(Release::Ready));
    }

    /// A record that names two services starts after the READY of both, in
    /// either order, under the longer deadline.
    #[test]
    fn two_services_start_the_record_after_both_are_ready() {
        for order in [["pkgd", "blk"], ["blk", "pkgd"]] {
            let mut gate = open(WAIT_TWO, 0);
            assert_eq!(gate.deadline(), 30_000 * MS);
            assert_eq!(gate.ready(order[0]), Step::Hold);
            assert_eq!(gate.ready(order[0]), Step::Hold, "a second READY");
            assert_eq!(gate.ready(order[1]), Step::Start(Release::Ready));
        }
    }

    /// The deadline starts the record, naming the service that is not
    /// ready; an expiry before it is stale.
    #[test]
    fn the_deadline_starts_the_record_and_names_the_service() {
        let gate = open(WAIT_ONE, 0);
        assert_eq!(gate.expired(30_000 * MS - 1), Step::Hold);
        let late = Step::Start(Release::Late {
            service: "pkgd",
            deadline_ms: 30_000,
        });
        assert_eq!(gate.expired(30_000 * MS), late);
        assert_eq!(gate.expired(31_000 * MS), late);
        let mut two = open(WAIT_TWO, 0);
        assert_eq!(two.ready("pkgd"), Step::Hold);
        assert_eq!(
            two.expired(30_000 * MS),
            Step::Start(Release::Late {
                service: "blk",
                deadline_ms: 30_000
            })
        );
    }

    /// The end of a service before its READY starts the record; after its
    /// READY the end changes nothing.
    #[test]
    fn the_end_of_a_service_before_its_ready_starts_the_record() {
        let mut gate = open(WAIT_ONE, 0);
        assert_eq!(
            gate.ended("pkgd"),
            Step::Start(Release::Ended { service: "pkgd" })
        );
        let mut two = open(WAIT_TWO, 0);
        assert_eq!(two.ready("pkgd"), Step::Hold);
        assert_eq!(two.ended("pkgd"), Step::Hold);
        assert_eq!(
            two.ended("blk"),
            Step::Start(Release::Ended { service: "blk" })
        );
    }

    /// A record that comes to its gate after the service said READY, or
    /// after the service is over, does not wait.
    #[test]
    fn a_gate_that_opens_late_looks_at_what_the_services_did() {
        let record = waiter(WAIT_ONE);
        assert_eq!(
            Gate::open(&record, 0, |_| Standing::Ready).err(),
            Some(Release::Ready)
        );
        assert_eq!(
            Gate::open(&record, 0, |_| Standing::Gone).err(),
            Some(Release::Ready),
            "a service that ended after its READY is a met wait"
        );
        assert_eq!(
            Gate::open(&record, 0, |_| Standing::Over).err(),
            Some(Release::Ended { service: "pkgd" })
        );
        let two = waiter(WAIT_TWO);
        let gate = Gate::open(&two, 0, |s| {
            if s == "blk" {
                Standing::Ready
            } else {
                Standing::NotReady
            }
        })
        .unwrap();
        let mut gate = gate;
        assert_eq!(gate.ready("pkgd"), Step::Start(Release::Ready));
    }

    /// The lines init prints.
    #[test]
    fn the_lines_say_why() {
        let late = |service, deadline_ms| Release::Late {
            service,
            deadline_ms,
        };
        assert_eq!(
            late("pkgd", 30_000).to_string(),
            "pkgd not ready after 30 s"
        );
        assert_eq!(late("pkgd", 3_000).to_string(), "pkgd not ready after 3 s");
        assert_eq!(
            late("pkgd", 1_500).to_string(),
            "pkgd not ready after 1500 ms"
        );
        assert_eq!(
            Release::Ended { service: "pkgd" }.to_string(),
            "pkgd ended before ready"
        );
    }

    /// A READY is taken from a service that registered and from no one else.
    #[test]
    fn a_ready_comes_from_a_running_service_only() {
        assert!(ready_taken(true, State::Running));
        for state in State::ALL {
            if state != State::Running {
                assert!(!ready_taken(true, state), "{state:?}");
            }
            assert!(!ready_taken(false, state), "a client in {state:?}");
        }
    }

    /// The rules of the table for waits: each is refused, and BASE_TABLE's
    /// launcher passes with the 30 s of the note.
    #[test]
    fn the_table_checks_each_rule_of_the_waits() {
        const NONE: &[Wait] = &[];
        const FINE: &[Wait] = &[Wait {
            service: "pkgd",
            deadline_ms: 1000,
        }];
        const BLK: &[Wait] = &[Wait {
            service: "blk",
            deadline_ms: 1000,
        }];
        const GONE: &[Wait] = &[Wait {
            service: "nothing",
            deadline_ms: 1000,
        }];
        const CLIENT: &[Wait] = &[Wait {
            service: "store-probe",
            deadline_ms: 1000,
        }];
        const ZERO: &[Wait] = &[Wait {
            service: "pkgd",
            deadline_ms: 0,
        }];
        const LONG: &[Wait] = &[Wait {
            service: "pkgd",
            deadline_ms: table::WAIT_MAX_MS + 1,
        }];
        const TWICE: &[Wait] = &[
            Wait {
                service: "pkgd",
                deadline_ms: 1000,
            },
            Wait {
                service: "pkgd",
                deadline_ms: 1000,
            },
        ];
        const THREE: &[Wait] = &[
            Wait {
                service: "pkgd",
                deadline_ms: 1000,
            },
            Wait {
                service: "blk",
                deadline_ms: 1000,
            },
            Wait {
                service: "ramfs",
                deadline_ms: 1000,
            },
        ];
        let base = table::pkg::STORE_PROBE_TABLE;
        let with = |name: &str, waits: &'static [Wait]| -> Vec<Record> {
            base.iter()
                .map(|r| {
                    if r.name == name {
                        Record { waits, ..*r }
                    } else {
                        *r
                    }
                })
                .collect()
        };
        let refused = |table: Vec<Record>| {
            matches!(table::check(&table), Err(table::TableError::Waits { .. }))
        };
        assert!(table::check(&with("store-probe", NONE)).is_ok());
        assert!(table::check(&with("store-probe", FINE)).is_ok());
        // A wait for the record itself, a chain (the service waits), an
        // unknown record, a client, a deadline of 0 and one past the limit,
        // the same service twice and a third wait.
        assert!(refused(with("pkgd", FINE)));
        let mut chain = with("store-probe", FINE);
        for r in &mut chain {
            if r.name == "pkgd" {
                r.waits = BLK;
            }
        }
        assert!(refused(chain));
        for waits in [GONE, CLIENT, ZERO, LONG, TWICE, THREE] {
            assert!(refused(with("store-probe", waits)), "{waits:?}");
        }
        assert!(table::check(table::base::BASE_TABLE).is_ok());
    }
}
