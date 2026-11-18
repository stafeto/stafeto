// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The roles of the probe of init's stop of the system (main.rs, the table
//! `table-shutdown` of services/init): `quiet` is a service that takes
//! init's stop notice and does nothing, so that init kills it at its
//! deadline, and `power` stands for the service of the power button: it
//! opens sessions with the services of the image, waits a little and sends init
//! SHUTDOWN (kind off), then serves its channel as a service that stops
//! with the default handler of rt::service.

use crate::{FAILED, VERSION, method, serve};
use proto_init::{Method, SHUTDOWN_OFF, ShutdownAsk};
use proto_wire::{Header, Reader, Status, Writer};
use rt::handle::Resource;
use rt::service::{Answer, Request, Service, Session};
use rt::startup::Startup;
use rt::wait::Waiter;
use rt::{sys, time};

/// The services `power` opens a session with before it asks: each answers
/// once it registered.
const NEIGHBOURS: [&str; 3] = ["echo", "quiet", "blk"];
/// How long `power` waits after the last session.
const SETTLE_NS: u64 = 300_000_000;

/// A service of one method that answers with status 0; with `ignore` it
/// takes init's stop notice and keeps running.
struct Quiet {
    ignore: bool,
}

impl Service<1> for Quiet {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = &[method::ECHO];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, _: &mut Request<'_>) -> Answer {
        Answer::Status(Status::Ok)
    }

    fn stop(&mut self) {
        if !self.ignore {
            sys::process_exit(0)
        }
    }
}

/// The role `quiet`: it registers and serves, and ignores the stop notice.
pub fn quiet(s: Startup) -> u64 {
    let Ok(channel) = sys::channel_create(crate::base(&s)) else {
        return FAILED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return FAILED;
    }
    serve(&s, &channel, &mut Quiet { ignore: true })
}

/// The role `power`.
pub fn power(mut s: Startup) -> u64 {
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let Ok(channel) = sys::channel_create(crate::base(&s)) else {
        return FAILED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return FAILED;
    }
    let (Ok(_echo), Ok(_quiet), Ok(_blk)) = (
        rt::service::connect(&s.parent, NEIGHBOURS[0]),
        rt::service::connect(&s.parent, NEIGHBOURS[1]),
        rt::service::connect(&s.parent, NEIGHBOURS[2]),
    ) else {
        return FAILED;
    };
    let Ok(waiter) = Waiter::new(&channel, 0, crate::base(&s)) else {
        return FAILED;
    };
    let _ = waiter.receive_until(&channel, time::ticks_to_ns(time::now()) + SETTLE_NS);
    let mut w = Writer::new();
    let ask = ShutdownAsk {
        kind: SHUTDOWN_OFF,
        flags: 0,
    };
    let written = Header::new(Method::Shutdown.number(), proto_init::VERSION)
        .write(&mut w)
        .and_then(|()| ask.write(&mut w));
    if written.is_err() {
        return FAILED;
    }
    let asked = sys::send(&s.parent, w.as_bytes()).map(|reply| {
        let mut buffer = [0; abi::MESSAGE_MAX];
        Reader::new(reply.bytes(&mut buffer)).u32()
    });
    if asked != Ok(Ok(Status::Ok.code())) {
        rt::println!("power: SHUTDOWN refused");
        return FAILED;
    }
    rt::println!("power: button");
    serve(&s, &channel, &mut Quiet { ignore: false })
}
