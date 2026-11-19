// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Who the clients of the sessions are: the notary session of the process service (asked of init
//! once, lazily, from the worker thread: the service lists no `posix` in its record, which would
//! make it a POSIX record), the page of the credentials generations (Register, once), Vouch, and the
//! copies of the identity sessions the bound sessions brought, kept until their session goes.

use core::sync::atomic::{AtomicU64, Ordering};
use datafs::server::SESSIONS;
use proto_process::WhoReply;
use rt::abi::{Access, MESSAGE_MAX, Rights};
use rt::handle::{Channel, Handle, Memory, Process};
use rt::sys;

/// Where the worker maps the page of the generations, read-only: the page after the clock's.
const GENERATIONS_AT: usize = 0x58_3000_1000;
/// The words of the page: one for each record of the process service.
const WORDS: usize = 4096 / 8;

/// The notary session and the page of generations.
pub struct Notary {
    session: Option<Handle<Channel>>,
    generations: Option<Handle<Memory>>,
    /// The instant of the last try to connect, so that a table with no process service is asked
    /// once a second at most.
    tried_at: Option<u64>,
}

/// How long after a failed try the next one may come, in nanoseconds.
const RETRY_NS: u64 = 1_000_000_000;

impl Notary {
    pub const fn new() -> Self {
        Self {
            session: None,
            generations: None,
            tried_at: None,
        }
    }

    /// The notary session connected and the page mapped. False when the table has no process
    /// service or init refuses the grant (a BIND is then ACCESS).
    pub fn ready(&mut self, parent: &Handle<Channel>, process: &Handle<Process>) -> bool {
        if self.generations.is_some() {
            return true;
        }
        let now = rt::time::ticks_to_ns(rt::time::now());
        if self
            .tried_at
            .is_some_and(|at| now.saturating_sub(at) < RETRY_NS)
        {
            return false;
        }
        self.tried_at = Some(now);
        if self.session.is_none() {
            self.session = rt::service::connect(parent, "posix").ok();
        }
        let Some(session) = self.session.as_ref() else {
            return false;
        };
        let request = proto_process::Method::Register.header().bytes();
        let Ok(mut reply) = sys::send(session, &request) else {
            return false;
        };
        let mut buffer = [0; MESSAGE_MAX];
        if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
            return false;
        }
        let Ok(memory) = reply.handles.take::<Memory>(0) else {
            return false;
        };
        if sys::mem_map(process, &memory, 0, 4096, GENERATIONS_AT, Access::Read).is_err() {
            return false;
        }
        self.generations = Some(memory);
        true
    }

    /// The generation word of the record at `index`, read with no call (Acquire). 0 when the page is
    /// not mapped or the index is not on it.
    pub fn generation(&self, index: u32) -> u64 {
        if self.generations.is_none() || index as usize >= WORDS {
            return 0;
        }
        // SAFETY: the page is mapped read-only at GENERATIONS_AT for the life of the process once
        // `generations` is set; the index is a u64 word inside it.
        unsafe { &*((GENERATIONS_AT + index as usize * 8) as *const AtomicU64) }
            .load(Ordering::Acquire)
    }

    /// Vouch: what the process service says of the client whose identity session `identity` is a
    /// copy of; None for a copy it does not vouch for.
    pub fn vouch(&self, identity: &Handle<Channel>) -> Option<WhoReply> {
        let session = self.session.as_ref()?;
        let copy = sys::handle_duplicate(identity, Rights::NOTIFY | Rights::TRANSFER).ok()?;
        let request = proto_process::Method::Vouch.header().bytes();
        let reply = sys::send_handles(session, &request, [copy.erase()]).ok()?;
        let mut buffer = [0; MESSAGE_MAX];
        WhoReply::read(reply.bytes(&mut buffer)).ok()
    }
}

impl Default for Notary {
    fn default() -> Self {
        Self::new()
    }
}

/// The identity sessions of the bound sessions, by the label of the session, until it goes.
pub struct Identities {
    slots: [Option<(u64, Handle<Channel>)>; SESSIONS],
}

impl Identities {
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; SESSIONS],
        }
    }

    /// Keeps `copy` for the session `label`; the copy of an earlier BIND closes. False when no slot
    /// is free (the sessions of the table are as many as the slots, so a session has one).
    pub fn put(&mut self, label: u64, copy: Handle<Channel>) -> bool {
        let at = self
            .slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|(l, _)| *l == label))
            .or_else(|| self.slots.iter().position(Option::is_none));
        match at {
            Some(i) => {
                self.slots[i] = Some((label, copy));
                true
            }
            None => false,
        }
    }

    pub fn get(&self, label: u64) -> Option<&Handle<Channel>> {
        self.slots
            .iter()
            .flatten()
            .find(|(l, _)| *l == label)
            .map(|(_, h)| h)
    }

    /// The session went: its copy closes.
    pub fn remove(&mut self, label: u64) {
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|(l, _)| *l == label) {
                *slot = None;
            }
        }
    }
}

impl Default for Identities {
    fn default() -> Self {
        Self::new()
    }
}
