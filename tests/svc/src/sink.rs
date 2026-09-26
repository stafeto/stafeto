// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The role `sink` (main.rs): a service that `silent` connects to and
//! greets with HELLO. When the session that greeted it goes (CLIENT_GONE,
//! which init's kill of `silent` brings), sink asks init for its STATS and
//! keeps the reply: the checker reads it through SEEN to see the level
//! init's worker ran the kill at
//! (`kill_runs_above_the_victim_and_below_its_clients`).

use crate::{FAILED, VERSION, base, method, serve};
use abi::{Error, MESSAGE_MAX};
use proto_init::{Method, STATS_LEN};
use proto_wire::Status;
use rt::handle::{Channel, Outgoing};
use rt::service::{Answer, Request, Service, Session};
use rt::startup::Startup;
use rt::{Handle, sys};

pub fn run(s: Startup) -> u64 {
    let Ok(channel) = sys::channel_create(base(&s)) else {
        return FAILED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return FAILED;
    }
    let mut sink = Sink {
        parent: &s.parent,
        seen: None,
    };
    serve(&s, &channel, &mut sink)
}

/// The sink service: its connection to init, and the first STATS reply it
/// kept, of the moment the session that greeted it went.
struct Sink<'a> {
    parent: &'a Handle<Channel>,
    seen: Option<[u8; STATS_LEN]>,
}

impl Service<1> for Sink<'_> {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = &[method::HELLO, method::SEEN];
    /// Whether the session greeted the sink with HELLO.
    type Data = bool;

    fn request(&mut self, s: &mut Session<bool, 1>, r: &mut Request<'_>) -> Answer {
        match r.method() {
            method::HELLO => {
                s.data = true;
                Answer::Status(Status::Ok)
            }
            _ => match self.seen {
                Some(bytes) => match r.reply().bytes(&bytes) {
                    Ok(()) => Answer::Reply(Outgoing::new()),
                    Err(status) => Answer::Status(status),
                },
                None => Answer::Status(Status::Kernel(Error::BadState)),
            },
        }
    }

    /// The client of `s` went: if it greeted the sink, ask init for its
    /// STATS now, in the middle of init's kill, and keep the first reply.
    fn gone(&mut self, s: &mut Session<bool, 1>) {
        if !s.data || self.seen.is_some() {
            return;
        }
        let request = Method::Stats.header().bytes();
        if let Ok(reply) = sys::send(self.parent, &request) {
            let mut buffer = [0; MESSAGE_MAX];
            let bytes = reply.bytes(&mut buffer);
            let mut seen = [0; STATS_LEN];
            let n = bytes.len().min(STATS_LEN);
            seen[..n].copy_from_slice(&bytes[..n]);
            self.seen = Some(seen);
        }
    }
}
