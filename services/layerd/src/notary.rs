// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Who the clients are: the notary session of the process service (asked of init once, lazily:
//! the table lists no `posix` in the record, which would make it a POSIX record), the page of the
//! credentials generations (Register, once) and Vouch, as `services/datafs/src/identity.rs` does.

use core::sync::atomic::{AtomicU64, Ordering};
use proto_process::WhoReply;
use rt::abi::{Access, MESSAGE_MAX, Rights};
use rt::handle::{Channel, Handle, Memory, Process};
use rt::sys;

/// Where the page of the generations is mapped, read only.
const GENERATIONS_AT: usize = 0x58_3000_1000;
const WORDS: usize = 4096 / 8;
/// How long after a failed try the next one may come, in nanoseconds.
const RETRY_NS: u64 = 1_000_000_000;

pub struct Notary {
    session: Option<Handle<Channel>>,
    generations: Option<Handle<Memory>>,
    tried_at: Option<u64>,
}

impl Notary {
    pub const fn new() -> Self {
        Self {
            session: None,
            generations: None,
            tried_at: None,
        }
    }

    /// The notary session connected and the page mapped; false when the table has no process
    /// service or it is not up yet (a SESSION is then refused, and the client asks again).
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

    /// The generation word of the record at `index`, read with no call; 0 when the page is not
    /// mapped.
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
