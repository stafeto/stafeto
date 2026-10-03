// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The controlling terminals of the sessions (XBD 11.1.3; 5f): which
//! session each terminal of the terminal service belongs to. The terminal
//! service asks (proto_process SetCtty, DropCtty); the service keeps the
//! answer, so that TtySignal reaches the groups of that session alone, and
//! takes the terminal from a session whose leader ended. A terminal
//! belongs to one session at most and a session has one terminal at most.

use proto_process::{ACCESS, AGAIN, PERMISSION, TERMINALS};

pub const EVENTS: usize = proto_process::CTTY_EVENTS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub sid: u32,
    pub generation: u64,
}

#[derive(Clone, Copy)]
struct Terminal {
    link: Option<Link>,
    next: u64,
    events: [Option<Link>; EVENTS],
}

impl Terminal {
    const fn new() -> Self {
        Self {
            link: None,
            next: 1,
            events: [None; EVENTS],
        }
    }

    fn end(&mut self) {
        if let Some(link) = self.link.take() {
            let place = self
                .events
                .iter_mut()
                .find(|e| e.is_none())
                .expect("SetCtty reserved a departure");
            *place = Some(link);
        }
    }
}

pub struct Terminals {
    terminals: [Terminal; TERMINALS],
}

impl Default for Terminals {
    fn default() -> Self {
        Self::new()
    }
}

impl Terminals {
    pub const fn new() -> Self {
        Self {
            terminals: [Terminal::new(); TERMINALS],
        }
    }

    pub fn session(&self, terminal: usize) -> Option<u32> {
        self.link(terminal).map(|l| l.sid)
    }

    pub fn link(&self, terminal: usize) -> Option<Link> {
        self.terminals.get(terminal)?.link
    }

    /// One slot is reserved for the current owner's eventual departure.
    pub fn set(
        &mut self,
        terminal: usize,
        sid: u32,
        lives: impl Fn(u32) -> bool,
    ) -> Result<u64, u32> {
        if terminal >= TERMINALS || !lives(sid) {
            return Err(PERMISSION);
        }
        if let Some(held) = self.link(terminal) {
            if held.sid == sid {
                return Ok(held.generation);
            }
            if lives(held.sid) {
                return Err(ACCESS);
            }
            self.terminals[terminal].end();
        }
        if self
            .terminals
            .iter()
            .any(|t| t.link.is_some_and(|l| l.sid == sid))
        {
            return Err(ACCESS);
        }
        let t = &mut self.terminals[terminal];
        if t.events.iter().all(Option::is_some) {
            return Err(AGAIN);
        }
        let generation = t.next;
        t.next = t.next.checked_add(1).ok_or(AGAIN)?;
        t.link = Some(Link { sid, generation });
        Ok(generation)
    }

    /// The oldest event stays present, and HUP remains authorized, until Ack.
    pub fn event(&self, terminal: usize) -> Option<Link> {
        self.terminals
            .get(terminal)?
            .events
            .iter()
            .flatten()
            .min_by_key(|e| e.generation)
            .copied()
    }

    pub fn ack(&mut self, terminal: usize, generation: u64) {
        if let Some(t) = self.terminals.get_mut(terminal) {
            for e in &mut t.events {
                if e.is_some_and(|e| e.generation == generation) {
                    *e = None;
                }
            }
        }
    }

    /// A departure authorizes HUP/CONT only for its exact old connection.
    pub fn permits_exact(&self, terminal: usize, sid: u32, generation: u64, signal: u8) -> bool {
        self.link(terminal)
            .is_some_and(|link| link.sid == sid && link.generation == generation)
            || matches!(signal, 1 | 18)
                && self.terminals.get(terminal).is_some_and(|t| {
                    t.events
                        .iter()
                        .flatten()
                        .any(|e| e.sid == sid && e.generation == generation)
                })
    }

    pub fn drop_terminal(&mut self, terminal: usize) {
        if let Some(t) = self.terminals.get_mut(terminal) {
            t.end();
        }
    }

    pub fn leader_ended(&mut self, sid: u32) {
        for t in &mut self.terminals {
            if t.link.is_some_and(|l| l.sid == sid) {
                t.end();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_terminal_belongs_to_one_live_session() {
        let mut t = Terminals::new();
        let alive = |sid| sid == 300 || sid == 400;
        assert_eq!(t.set(0, 500, alive), Err(PERMISSION));
        let generation = t.set(0, 300, alive).unwrap();
        assert_eq!(t.set(0, 300, alive), Ok(generation));
        assert_eq!(t.set(0, 400, alive), Err(ACCESS));
        assert_eq!(t.set(1, 300, alive), Err(ACCESS));
        assert_eq!(t.set(TERMINALS, 400, alive), Err(PERMISSION));
        assert_eq!(t.session(0), Some(300));
        assert!(t.set(0, 400, |sid| sid == 400).is_ok());
        t.leader_ended(400);
        assert_eq!(t.session(0), None);
        assert!(t.set(0, 300, alive).is_ok());
        t.drop_terminal(0);
        assert_eq!(t.session(0), None);
    }

    #[test]
    fn a_late_ack_keeps_the_new_owner_and_hup_has_a_departure_right() {
        let mut t = Terminals::new();
        let old = t.set(0, 300, |_| true).unwrap();
        t.leader_ended(300);
        assert!(!t.permits_exact(0, 300, old, 2));
        assert!(t.permits_exact(0, 300, old, 1));
        let new = t.set(0, 400, |_| true).unwrap();
        assert!(new > old);
        assert!(t.permits_exact(0, 300, old, 18));
        assert!(!t.permits_exact(0, 400, old, 18));
        assert!(!t.permits_exact(0, 300, new, 1));
        assert_eq!(
            t.event(0),
            Some(Link {
                sid: 300,
                generation: old
            })
        );
        t.ack(0, old);
        assert_eq!(
            t.link(0),
            Some(Link {
                sid: 400,
                generation: new
            })
        );
        assert!(!t.permits_exact(0, 300, old, 1));
        assert!(t.permits_exact(0, 400, new, 2));
    }

    #[test]
    fn events_have_a_reserved_slot_and_do_not_get_lost() {
        let mut t = Terminals::new();
        for sid in 300..300 + EVENTS as u32 {
            t.set(0, sid, |_| true).unwrap();
            t.leader_ended(sid);
        }
        assert_eq!(t.set(0, 400, |_| true), Err(AGAIN));
        let event = t.event(0).unwrap();
        t.ack(0, event.generation);
        t.set(0, 400, |_| true).unwrap();
        t.leader_ended(400);
        for _ in 0..EVENTS {
            let event = t.event(0).unwrap();
            t.ack(0, event.generation);
        }
        assert_eq!(t.event(0), None);
    }
}
