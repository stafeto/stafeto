// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The controlling terminals of the sessions (XBD 11.1.3; 5f): which
//! session each terminal of the terminal service belongs to. The terminal
//! service asks (proto_process SetCtty, DropCtty); the service keeps the
//! answer, so that TtySignal reaches the groups of that session alone, and
//! takes the terminal from a session whose leader ended. A terminal
//! belongs to one session at most and a session has one terminal at most.

use proto_process::{ACCESS, PERMISSION, TERMINALS};

#[derive(Default)]
pub struct Terminals {
    sessions: [Option<u32>; TERMINALS],
}

impl Terminals {
    pub const fn new() -> Self {
        Self {
            sessions: [None; TERMINALS],
        }
    }

    /// The session of `terminal`, if one has it.
    pub fn session(&self, terminal: usize) -> Option<u32> {
        self.sessions.get(terminal).copied().flatten()
    }

    /// SetCtty: `terminal` becomes the controlling terminal of the session
    /// `sid`, whose leader `lives` says lives (PERMISSION otherwise), when
    /// the terminal has no session with a live leader and the session no
    /// other terminal (ACCESS otherwise). A session that has the terminal
    /// already keeps it.
    pub fn set(
        &mut self,
        terminal: usize,
        sid: u32,
        lives: impl Fn(u32) -> bool,
    ) -> Result<(), u32> {
        if terminal >= TERMINALS || !lives(sid) {
            return Err(PERMISSION);
        }
        match self.sessions[terminal] {
            Some(held) if held == sid => return Ok(()),
            Some(held) if lives(held) => return Err(ACCESS),
            _ => {}
        }
        if self.sessions.contains(&Some(sid)) {
            return Err(ACCESS);
        }
        self.sessions[terminal] = Some(sid);
        Ok(())
    }

    /// DropCtty: `terminal` is no session's.
    pub fn drop_terminal(&mut self, terminal: usize) {
        if let Some(place) = self.sessions.get_mut(terminal) {
            *place = None;
        }
    }

    /// The leader of the session `sid` ended: its terminal is no longer
    /// the session's (XBD 11.1.3).
    pub fn leader_ended(&mut self, sid: u32) {
        for place in &mut self.sessions {
            if *place == Some(sid) {
                *place = None;
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
        assert_eq!(t.set(0, 500, alive), Err(PERMISSION), "no live leader");
        assert_eq!(t.set(0, 300, alive), Ok(()));
        assert_eq!(t.set(0, 300, alive), Ok(()), "again");
        assert_eq!(t.set(0, 400, alive), Err(ACCESS), "taken");
        assert_eq!(t.set(1, 300, alive), Err(ACCESS), "a second terminal");
        assert_eq!(t.set(TERMINALS, 400, alive), Err(PERMISSION));
        assert_eq!(t.session(0), Some(300));
        // The holder's leader is gone: another session takes it.
        assert_eq!(t.set(0, 400, |sid| sid == 400), Ok(()));
        t.leader_ended(400);
        assert_eq!(t.session(0), None);
        assert_eq!(t.set(0, 300, alive), Ok(()));
        t.drop_terminal(0);
        assert_eq!(t.session(0), None);
    }
}
