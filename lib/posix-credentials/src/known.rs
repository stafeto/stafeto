// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The credentials of a client that a service remembers, never stale: the
//! answer of the process service (Vouch) comes with the generation of the
//! record's credentials, which the service raises before it answers a
//! change; the asking service reads that generation from the page it maps
//! (Acquire, no call) before each check and asks again only when it moved. A request sent after `setuid` returned
//! is checked by the new credentials, as the generation was raised
//! before `setuid` was answered.
//!
//! The answer also carries the ceiling of the client's process, and a small
//! memory of the shared objects the process service said the client holds
//! (`held`, ShareHeld). The process service raises the record's generation
//! when the record loses a right to such an object, so the memory is valid
//! as long as the generation of the answer stands and goes with it.

#[cfg(test)]
use proto_process::RECORDS;
use proto_process::{Credentials, Held, WhoReply};

/// What Vouch said of a client: its PID, credentials and their generation.
#[derive(Clone, Copy, Debug, Default)]
pub struct Known {
    answer: Option<Answer>,
    /// The rights the process service vouched for, the oldest replaced.
    held: [Option<Rights>; HELD_KEYS],
    next: usize,
}

/// The objects whose rights a session remembers.
pub const HELD_KEYS: usize = 4;

#[derive(Clone, Copy, Debug)]
struct Rights {
    kind: u32,
    key: u64,
    held: Held,
}

// This cache needs no Loader, limits, groups or terminal payload.
#[derive(Clone, Copy, Debug)]
struct Answer {
    pid: u32,
    index: u32,
    ceiling: u8,
    credentials: Credentials,
    generation: u64,
}

impl Known {
    pub const fn new() -> Self {
        Self {
            answer: None,
            held: [None; HELD_KEYS],
            next: 0,
        }
    }

    /// The client's credentials now: the remembered ones while `generation`
    /// (the page's word of the remembered PID's record, `Acquire`) stands,
    /// else what `ask` (one Vouch) says, which is remembered. None when `ask`
    /// has no answer; nothing is remembered then.
    pub fn credentials(
        &mut self,
        generation: impl Fn(usize) -> u64,
        ask: impl FnOnce() -> Option<WhoReply>,
    ) -> Option<Credentials> {
        if let Some(known) = self.answer
            && generation(known.index as usize) == known.generation
        {
            return Some(known.credentials);
        }
        // Another answer is another generation: what was held then is asked
        // again.
        self.held = [None; HELD_KEYS];
        self.next = 0;
        self.answer = ask().map(|who| Answer {
            pid: who.pid,
            index: who.index,
            ceiling: who.ceiling,
            credentials: who.credentials,
            generation: who.generation,
        });
        self.answer.map(|known| known.credentials)
    }

    /// The ceiling of the client's process, once there is an answer: the
    /// highest level a thread of it may have.
    pub fn ceiling(&self) -> Option<u8> {
        self.answer.map(|a| a.ceiling)
    }

    /// The record's index and the generation the answer was for.
    pub fn record(&self) -> Option<(u32, u64)> {
        self.answer.map(|a| (a.index, a.generation))
    }

    /// What right the client has to the shared object (`kind`, `key`). A
    /// remembered right stands while the page's word of the record is the
    /// generation of the answer, with no call. Otherwise `ask` (one
    /// ShareHeld, given the record's index and that generation) says; a
    /// right is remembered, and the oldest of the remembered goes out when
    /// all `HELD_KEYS` places are taken. No right is remembered: a process
    /// gains one without moving the generation, so a refusal is asked for
    /// again. With no answer, or once the generation moved on since it, the
    /// result is `Held::None`: the next `credentials` asks Vouch again.
    pub fn held(
        &mut self,
        generation: impl Fn(usize) -> u64,
        kind: u32,
        key: u64,
        ask: impl FnOnce(u32, u64) -> Option<Held>,
    ) -> Held {
        let Some(known) = self.answer else {
            return Held::None;
        };
        if generation(known.index as usize) != known.generation {
            return Held::None;
        }
        if let Some(rights) = self
            .held
            .iter()
            .flatten()
            .find(|r| r.kind == kind && r.key == key)
        {
            return rights.held;
        }
        let held = ask(known.index, known.generation).unwrap_or(Held::None);
        if held != Held::None {
            self.held[self.next] = Some(Rights { kind, key, held });
            self.next = (self.next + 1) % HELD_KEYS;
        }
        held
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
            ceiling: 31,
            pid: 300,
            credentials,
            generation,
            loader: None,
            index: 300 % RECORDS as u32,
            ctty: None,
            image: 1,
            groups: proto_process::Groups::EMPTY,
            limits: proto_process::ResourceLimits::initial(2 * 1024 * 1024),
            root: proto_process::ExpenditureRoot {
                pid: 2,
                generation: 1,
            },
        }
    }

    /// Vouch is asked once while the generation of the record stands, and
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
        assert_eq!(asked.get(), 1, "one Vouch for a hundred checks");
        // seteuid: the service raised the word before it answered.
        page.set(6);
        euid.set(65534);
        assert_eq!(
            check(&mut known),
            Some(65534),
            "the new credentials at once"
        );
        assert_eq!(check(&mut known), Some(65534));
        assert_eq!(asked.get(), 2, "one Vouch for the change");
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
        // The record's word moved and Vouch failed: no credentials, and the
        // old ones do not stand in for them.
        assert_eq!(known.credentials(|_| 1, || None), None);
        assert_eq!(known.pid(), None);
    }

    /// A right is asked for once while the generation stands, a refusal is
    /// asked for again, the generation that moved asks again, and the fifth
    /// object pushes out the oldest.
    #[test]
    fn held_is_remembered_by_generation() {
        let page = Cell::new(5u64);
        let calls = Cell::new(0);
        let mut known = Known::new();
        let generation = |_: usize| page.get();
        let ask = |known: &mut Known, key: u64, held: Held| {
            known.held(generation, 1, key, |index, asked| {
                assert_eq!(index, 300 % RECORDS as u32);
                assert_eq!(asked, page.get());
                calls.set(calls.get() + 1);
                Some(held)
            })
        };
        assert_eq!(ask(&mut known, 7, Held::Write), Held::None, "no answer yet");
        assert_eq!(calls.get(), 0);
        known.credentials(generation, || Some(answer(0, 5)));
        assert_eq!(known.ceiling(), Some(31));
        for _ in 0..50 {
            assert_eq!(ask(&mut known, 7, Held::Write), Held::Write);
        }
        assert_eq!(calls.get(), 1, "a hit is no call");
        // A refusal is not remembered.
        for _ in 0..3 {
            assert_eq!(ask(&mut known, 8, Held::None), Held::None);
        }
        assert_eq!(calls.get(), 4);
        // The generation moved: the answer is stale, nothing is held until
        // Vouch is asked again, and then the right is asked again.
        page.set(6);
        assert_eq!(ask(&mut known, 7, Held::Write), Held::None);
        assert_eq!(calls.get(), 4, "a stale answer asks nothing");
        known.credentials(generation, || Some(answer(0, 6)));
        assert_eq!(ask(&mut known, 7, Held::Write), Held::Write);
        assert_eq!(calls.get(), 5, "asked again after the move");
        // Four fit, the fifth pushes out the oldest (key 7).
        for key in 10..13 {
            assert_eq!(ask(&mut known, key, Held::Read), Held::Read);
        }
        assert_eq!(calls.get(), 8);
        for key in [7, 10, 11, 12] {
            ask(&mut known, key, Held::Read);
        }
        assert_eq!(calls.get(), 8, "four are held");
        assert_eq!(ask(&mut known, 13, Held::Write), Held::Write);
        assert_eq!(calls.get(), 9);
        assert_eq!(ask(&mut known, 7, Held::Write), Held::Write);
        assert_eq!(calls.get(), 10, "the oldest went out");
        assert_eq!(ask(&mut known, 12, Held::Read), Held::Read);
        assert_eq!(calls.get(), 10, "the others stay");
    }
}
