// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Test relay: obtains clock readings in a different process.
#![no_std]
#![no_main]
use posix_clock::Client;
use proto_init::ServiceArgs;
use proto_wire::Status;
use rt::handle::{Outgoing, Resource};
use rt::service::{Answer, Config, Heartbeat, Request, Service, Session};
use rt::sys;
rt::entry!(main);
fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let Ok(session) = start.take::<rt::handle::Channel>(process_client::START_NAME) else {
        rt::println!("clock-peer: no session with the process service");
        return 6;
    };
    let args = ServiceArgs::read(start.args()).ok();
    let level = sys::thread_info(&start.thread).map_or(1, |i| i.base);
    let Ok(channel) = sys::channel_create(1) else {
        return 2;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 3;
    }
    let Ok(clock) = Client::connect(&start.parent) else {
        return 4;
    };
    let process = process_client::Client::new(session);
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &start.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    rt::println!("clock-peer: ready");
    let _ = rt::service::run::<Relay, 2, 0>(&channel, &mut Relay { clock, process }, config);
    5
}
struct Relay {
    clock: Client,
    process: process_client::Client,
}
impl Service<0> for Relay {
    const VERSION: u16 = proto_clock::VERSION;
    const METHODS: &'static [u16] = &[proto_clock::Method::Get as u16, 8, 9];
    type Data = ();
    fn request(&mut self, _: &mut Session<(), 0>, r: &mut Request<'_>) -> Answer {
        if r.method() == 8 {
            if !r.handles.is_empty() || r.body().finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            let value = match self.process.query() {
                Ok(value) => value,
                Err(status) => return Answer::Status(status),
            };
            let w = r.reply();
            w.u32(0)
                .and_then(|()| w.u32(value.pid))
                .and_then(|()| w.u32(value.parent))
                .expect("peer identity");
            for id in value.credentials.words() {
                w.u32(id).expect("peer credentials");
            }
            return Answer::Reply(Outgoing::new());
        }
        if r.method() == 9 {
            if r.handles.len() != 1 || r.body().finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            let Ok(foreign) = r.handles.take::<rt::handle::Process>(0) else {
                return Answer::Status(Status::BadSize);
            };
            // Create through its own session, which the service refuses:
            // only init holds the channel with no label.
            return Answer::Status(
                self.process
                    .create(&foreign, true)
                    .map_or_else(|error| error, |_| Status::Ok),
            );
        }
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let mut reader = r.body();
        let Ok(id) = reader.u32() else {
            return Answer::Status(Status::BadSize);
        };
        if reader.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let value = match self.clock.get(id) {
            Ok(value) => value,
            Err(status) => return Answer::Status(status),
        };
        let writer = r.reply();
        if writer
            .u32(0)
            .and_then(|()| writer.u64(value.time.seconds as u64))
            .and_then(|()| writer.u64(value.time.nanos as u64))
            .and_then(|()| writer.u64(value.resolution))
            .and_then(|()| writer.u64(value.generation))
            .is_err()
        {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }
}
