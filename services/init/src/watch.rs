// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The watchdog of a service (spec 13.4). Init keeps a deadline for each
//! instance on a timer of its own; a HEARTBEAT of the service moves it to
//! "now plus the watchdog's deadline". The first expiry without a
//! heartbeat only marks the service suspect and moves the deadline one
//! period on: a service that more important ones kept off the processor
//! gets that period to send its late heartbeat. A second expiry in a row
//! is silence. Before its REGISTER an instance counts from its start. An
//! expiry before the deadline is a stale one, of a deadline that moved
//! since, and changes nothing.

/// The heartbeat of a service and its watchdog, in nanoseconds: the
/// period of its heartbeats and how long init waits for one. The checks of
/// the table (table::check) keep the period above 0 and the deadline at
/// least three periods.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watch {
    pub period_ns: u64,
    pub deadline_ns: u64,
}

impl Watch {
    /// The watchdog of an instance armed at `now`: its start, or its
    /// REGISTER; the deadline is now plus `deadline_ns`.
    pub const fn arm(self, now: u64) -> Watched {
        Watched {
            watch: self,
            deadline: now.saturating_add(self.deadline_ns),
            suspect: false,
        }
    }
}

/// The watchdog of one instance: its deadline, and whether an expiry
/// without a heartbeat marked it suspect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watched {
    watch: Watch,
    deadline: u64,
    suspect: bool,
}

/// What an expiry of the timer means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Before the deadline: an expiry of a deadline that moved since.
    Stale,
    /// The first expiry without a heartbeat: the service is suspect, and
    /// the timer goes to this deadline, one period on.
    Suspect { deadline: u64 },
    /// The second expiry in a row: the service went silent.
    Silent,
}

impl Watched {
    /// A heartbeat at `now`: the deadline moves to now plus the watchdog's
    /// deadline, and a mark of suspicion goes. Gives the new deadline, for
    /// the timer.
    pub fn beat(&mut self, now: u64) -> u64 {
        self.deadline = now.saturating_add(self.watch.deadline_ns);
        self.suspect = false;
        self.deadline
    }

    /// An expiry of the timer seen at `now` (Action).
    pub fn expired(&mut self, now: u64) -> Action {
        if now < self.deadline {
            Action::Stale
        } else if self.suspect {
            Action::Silent
        } else {
            self.suspect = true;
            self.deadline = now.saturating_add(self.watch.period_ns);
            Action::Suspect {
                deadline: self.deadline,
            }
        }
    }

    /// The deadline the timer is set to.
    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    pub fn suspect(&self) -> bool {
        self.suspect
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A period of 20 and a deadline of 100, in any unit.
    const WATCH: Watch = Watch {
        period_ns: 20,
        deadline_ns: 100,
    };

    #[test]
    fn a_beat_moves_the_deadline() {
        let mut w = WATCH.arm(1000);
        assert_eq!(w.deadline(), 1100);
        assert_eq!(w.beat(1030), 1130);
        assert_eq!(w.deadline(), 1130);
        assert_eq!(w.expired(1100), Action::Stale);
        assert_eq!(w.expired(1130), Action::Suspect { deadline: 1150 });
    }

    #[test]
    fn silence_is_confirmed_one_period_later() {
        let mut w = WATCH.arm(0);
        assert_eq!(w.expired(100), Action::Suspect { deadline: 120 });
        assert!(w.suspect());
        assert_eq!(w.expired(119), Action::Stale);
        assert_eq!(w.expired(120), Action::Silent);
        // A late expiry counts from when it came.
        let mut w = WATCH.arm(0);
        assert_eq!(w.expired(150), Action::Suspect { deadline: 170 });
        assert_eq!(w.expired(170), Action::Silent);
    }

    #[test]
    fn a_beat_during_the_confirmation_clears_it() {
        let mut w = WATCH.arm(0);
        assert_eq!(w.expired(100), Action::Suspect { deadline: 120 });
        assert_eq!(w.beat(110), 210);
        assert!(!w.suspect());
        // The expiry of the suspect deadline is stale now, and the next
        // expiry without a heartbeat marks it again, no more.
        assert_eq!(w.expired(120), Action::Stale);
        assert_eq!(w.expired(210), Action::Suspect { deadline: 230 });
    }

    #[test]
    fn a_stale_expiry_changes_nothing() {
        let mut w = WATCH.arm(0);
        let before = w;
        assert_eq!(w.expired(0), Action::Stale);
        assert_eq!(w.expired(99), Action::Stale);
        assert_eq!(w, before);
        let mut suspect = WATCH.arm(0);
        suspect.expired(100);
        let before = suspect;
        assert_eq!(suspect.expired(119), Action::Stale);
        assert_eq!(suspect, before);
    }
}
