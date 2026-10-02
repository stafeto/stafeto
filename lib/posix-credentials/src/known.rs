// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The credentials of a client that a service remembers (spec 2, 3.1,
//! "Учётные данные не устаревают"): the answer to Who comes with the
//! generation of the record's credentials, which the process service
//! raises before it answers a change; the service reads that generation
//! from the page it maps (Acquire, no call) before each check and asks
//! Who again only when it moved. A request sent after `setuid` returned
//! is checked by the new credentials, as the generation was raised
//! before `setuid` was answered.

use proto_process::{Credentials, RECORDS, WhoReply};

/// What Who said of a client: its PID, credentials and their generation.
#[derive(Clone, Copy, Debug, Default)]
pub struct Known {
    answer: Option<WhoReply>,
}

impl Known {
    pub const fn new() -> Self {
        Self { answer: None }
    }

    /// The client's credentials now: the remembered ones while `generation`
    /// (the page's word of the remembered PID's record, `Acquire`) stands,
    /// else what `ask` (one Who) says, which is remembered. None when `ask`
    /// has no answer; nothing is remembered then.
    pub fn credentials(
        &mut self,
        generation: impl Fn(usize) -> u64,
        ask: impl FnOnce() -> Option<WhoReply>,
    ) -> Option<Credentials> {
        if let Some(known) = self.answer
            && generation(known.pid as usize % RECORDS) == known.generation
        {
            return Some(known.credentials);
        }
        self.answer = ask();
        self.answer.map(|known| known.credentials)
    }

    /// The PID the answer was for, once there is one.
    pub fn pid(&self) -> Option<u32> {
        self.answer.map(|a| a.pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    fn answer(euid: u32, generation: u64) -> WhoReply {
        let mut credentials = Credentials::NOBODY;
        credentials.euid = euid;
        WhoReply {
            pid: 300,
            credentials,
            generation,
        }
    }

    /// Who is asked once while the generation of the record stands, and
    /// again, once, after it moved; the new credentials are those of the
    /// new answer.
    #[test]
    fn who_is_asked_again_only_when_the_generation_moved() {
        let page = Cell::new(5u64);
        let asked = Cell::new(0);
        let mut known = Known::new();
        let euid = Cell::new(0);
        let check = |known: &mut Known| {
            known
                .credentials(
                    |index| {
                        assert_eq!(index, 300 % RECORDS);
                        page.get()
                    },
                    || {
                        asked.set(asked.get() + 1);
                        Some(answer(euid.get(), page.get()))
                    },
                )
                .map(|c| c.euid)
        };
        for _ in 0..100 {
            assert_eq!(check(&mut known), Some(0));
        }
        assert_eq!(asked.get(), 1, "one Who for a hundred checks");
        // seteuid: the service raised the word before it answered.
        page.set(6);
        euid.set(65534);
        assert_eq!(
            check(&mut known),
            Some(65534),
            "the new credentials at once"
        );
        assert_eq!(check(&mut known), Some(65534));
        assert_eq!(asked.get(), 2, "one Who for the change");
        assert_eq!(known.pid(), Some(300));
    }

    /// An answer that did not come is remembered as none: the next check
    /// asks again.
    #[test]
    fn a_failed_who_is_not_remembered() {
        let mut known = Known::new();
        assert_eq!(known.credentials(|_| 0, || None), None);
        assert_eq!(
            known
                .credentials(|_| 0, || Some(answer(0, 0)))
                .map(|c| c.euid),
            Some(0)
        );
        // The record's word moved and Who failed: no credentials, and the
        // old ones do not stand in for them.
        assert_eq!(known.credentials(|_| 1, || None), None);
        assert_eq!(known.pid(), None);
    }
}
