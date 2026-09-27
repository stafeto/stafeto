// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The role `echo` (main.rs): a service that answers ECHO, LABEL, ARGS,
//! GATE and OPEN. With `g` as byte 1 of its own arguments (`slow`) it
//! waits at the gate of the service `echo` before its REGISTER: a GATE
//! through a session with `echo` that comes back once the checker sent
//! OPEN there, against the rule that a service registers before it
//! connects (spec 13.4), for the test of waiting requests.

use crate::{FAILED, VERSION, method, serve};
use abi::MESSAGE_MAX;
use proto_init::ServiceArgs;
use proto_wire::{HEADER_LEN, Header, Reader, Status, Writer};
use rt::handle::Outgoing;
use rt::service::{Answer, Pending, Request, Service, Session};
use rt::startup::Startup;
use rt::sys;

/// Byte 1 of the own arguments of an echo that waits at the gate.
const GATE: u8 = b'g';

pub fn run(s: Startup) -> u64 {
    let Ok(args) = ServiceArgs::read(s.args()) else {
        return FAILED;
    };
    let Ok(channel) = sys::channel_create(crate::base(&s)) else {
        return FAILED;
    };
    if args.own.get(1) == Some(&GATE) && !through_gate(&s) {
        return FAILED;
    }
    if rt::service::register(&s.parent, &channel).is_err() {
        return FAILED;
    }
    let mut echo = Echo {
        args: s.args(),
        gate: None,
        open: false,
    };
    serve(&s, &channel, &mut echo)
}

/// GATE through a session with the service `echo` (rt::service::connect):
/// whether its reply came with status 0.
fn through_gate(s: &Startup) -> bool {
    let Ok(echo) = rt::service::connect(&s.parent, "echo") else {
        return false;
    };
    let mut w = Writer::new();
    let _ = Header::new(method::GATE, VERSION).write(&mut w);
    let Ok(reply) = sys::send(&echo, w.as_bytes()) else {
        return false;
    };
    let mut buffer = [0; MESSAGE_MAX];
    Reader::new(reply.bytes(&mut buffer)).u32() == Ok(Status::Ok.code())
}

/// The echo service, its start arguments and its gate: the GATE that
/// waits, and whether OPEN came.
struct Echo<'a> {
    args: &'a [u8],
    gate: Option<Pending>,
    open: bool,
}

impl Service<1> for Echo<'_> {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = &[
        method::ECHO,
        method::LABEL,
        method::ARGS,
        method::GATE,
        method::OPEN,
    ];
    type Data = ();

    fn request(&mut self, s: &mut Session<(), 1>, r: &mut Request<'_>) -> Answer {
        match r.method() {
            method::GATE if !self.open => {
                self.gate = r.defer();
                return Answer::Deferred;
            }
            method::GATE => return Answer::Status(Status::Ok),
            method::OPEN => {
                self.open = true;
                if let Some(gate) = self.gate.take() {
                    let _ = gate.answer(&proto_wire::reply(Status::Ok), Outgoing::new());
                }
                return Answer::Status(Status::Ok);
            }
            _ => {}
        }
        let (method, body, label) = (r.method(), &r.bytes()[HEADER_LEN..], s.label());
        let w = r.reply();
        let written = w.u32(Status::Ok.code()).and_then(|()| match method {
            method::ECHO => w.bytes(body),
            method::LABEL => w.u32(0).and_then(|()| w.u64(label)),
            _ => w.u32(0).and_then(|()| w.bytes(self.args)),
        });
        match written {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }
}
