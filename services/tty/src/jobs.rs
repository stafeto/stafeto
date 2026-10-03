// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A terminal as the controlling terminal of a session (XBD 11.1.3,
//! [P24-TERMIOS] tcsetpgrp, tcgetpgrp, tcgetsid; 5f, T3): its session and
//! its foreground process group, and the rules of the requests on them.
//! The caller is the process of a session of the service: its PID, group
//! and session (`Caller`), which the service read from the page of the
//! generations. The process service keeps the session's side of the
//! terminal (proto_process SetCtty) and says whether a session may take
//! it; here is what the terminal keeps.

use proto_tty::{INVALID, NO_FOREGROUND, NOT_CONTROLLING, PERMISSION};

/// Who sent a request: its PID, its group and its session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    pub pid: u32,
    pub pgid: u32,
    pub sid: u32,
}

/// The session a terminal is the controlling terminal of, and its
/// foreground process group.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Jobs {
    session: Option<u32>,
    foreground: Option<u32>,
}

impl Jobs {
    pub const fn new() -> Jobs {
        Jobs {
            session: None,
            foreground: None,
        }
    }

    pub fn session(&self) -> Option<u32> {
        self.session
    }

    /// The foreground group, which the terminal's signals go to.
    pub fn foreground(&self) -> Option<u32> {
        self.foreground.filter(|_| self.session.is_some())
    }

    /// Whether ACQUIRE of `caller` asks the process service at all: the
    /// caller leads its session (PERMISSION otherwise); Ok(false) for the
    /// session that has the terminal already.
    pub fn may_acquire(&self, caller: Caller) -> Result<bool, u32> {
        if caller.pid != caller.sid {
            return Err(PERMISSION);
        }
        Ok(self.session != Some(caller.sid))
    }

    /// The process service gave the terminal to the caller's session: the
    /// caller's group is the foreground group.
    pub fn acquired(&mut self, caller: Caller) {
        self.session = Some(caller.sid);
        self.foreground = Some(caller.pgid);
    }

    /// The terminal is no session's.
    pub fn release(&mut self) {
        *self = Jobs::new();
    }

    /// Whether the terminal is the controlling terminal of the caller's
    /// session (NOT_CONTROLLING otherwise).
    pub fn controlling(&self, caller: Caller) -> Result<(), u32> {
        if self.session == Some(caller.sid) {
            Ok(())
        } else {
            Err(NOT_CONTROLLING)
        }
    }

    /// tcsetpgrp: `pgid` becomes the foreground group when it is a group
    /// of the terminal's session (`in_session` says whether a member of
    /// that session is in it).
    pub fn set_foreground(
        &mut self,
        caller: Caller,
        pgid: u32,
        in_session: impl Fn(u32, u32) -> bool,
    ) -> Result<(), u32> {
        self.controlling(caller)?;
        if pgid == 0 || pgid > i32::MAX as u32 {
            return Err(INVALID);
        }
        if !in_session(pgid, caller.sid) {
            return Err(PERMISSION);
        }
        self.foreground = Some(pgid);
        Ok(())
    }

    /// tcgetpgrp: the foreground group, NO_FOREGROUND with none.
    pub fn get_foreground(&self, caller: Caller) -> Result<u32, u32> {
        self.controlling(caller)?;
        Ok(self.foreground.unwrap_or(NO_FOREGROUND))
    }

    /// tcgetsid: the session, whose number is its leader's group.
    pub fn get_session(&self, caller: Caller) -> Result<u32, u32> {
        self.controlling(caller)?;
        Ok(caller.sid)
    }
}

/// Whether some record of the page's group words `word` (one for each
/// index below `records`) is in group `pgid` of session `sid`.
pub fn group_in_session(records: usize, word: impl Fn(usize) -> u64, pgid: u32, sid: u32) -> bool {
    (0..records).any(|i| proto_process::groups_of(word(i)) == Some((pgid, sid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEADER: Caller = Caller {
        pid: 300,
        pgid: 300,
        sid: 300,
    };
    const MEMBER: Caller = Caller {
        pid: 301,
        pgid: 301,
        sid: 300,
    };
    const OTHER: Caller = Caller {
        pid: 400,
        pgid: 400,
        sid: 400,
    };

    #[test]
    fn a_leader_acquires_and_a_member_does_not() {
        let mut j = Jobs::new();
        assert_eq!(j.may_acquire(MEMBER), Err(PERMISSION), "not a leader");
        assert_eq!(j.may_acquire(LEADER), Ok(true));
        j.acquired(LEADER);
        assert_eq!(j.may_acquire(LEADER), Ok(false), "has it");
        assert_eq!(j.foreground(), Some(300));
        assert_eq!(j.controlling(MEMBER), Ok(()));
        assert_eq!(j.controlling(OTHER), Err(NOT_CONTROLLING));
        assert_eq!(j.get_session(MEMBER), Ok(300));
        j.release();
        assert_eq!(j.foreground(), None);
        assert_eq!(j.get_foreground(LEADER), Err(NOT_CONTROLLING));
    }

    /// tcsetpgrp to a group of another session is EPERM; of no member,
    /// EPERM; 0 is EINVAL; a group of the session becomes the foreground.
    #[test]
    fn the_foreground_is_a_group_of_the_session() {
        let words = [
            proto_process::groups_word(300, 300),
            proto_process::groups_word(301, 300),
            proto_process::groups_word(400, 400),
            0,
        ];
        let in_session = |pgid, sid| group_in_session(words.len(), |i| words[i], pgid, sid);
        let mut j = Jobs::new();
        j.acquired(LEADER);
        assert_eq!(j.set_foreground(MEMBER, 400, in_session), Err(PERMISSION));
        assert_eq!(j.set_foreground(MEMBER, 500, in_session), Err(PERMISSION));
        assert_eq!(j.set_foreground(MEMBER, 0, in_session), Err(INVALID));
        assert_eq!(
            j.set_foreground(OTHER, 400, in_session),
            Err(NOT_CONTROLLING)
        );
        assert_eq!(j.set_foreground(MEMBER, 301, in_session), Ok(()));
        assert_eq!(j.get_foreground(LEADER), Ok(301));
        assert_eq!(j.foreground(), Some(301));
    }
}
