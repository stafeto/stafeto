// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Test relay: obtains clock readings in a different process, and speaks
//! to the process service through sessions it holds.
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
    let _ = rt::service::run::<Relay, 2, 0>(
        &channel,
        &mut Relay {
            clock,
            process,
            kept: None,
        },
        config,
    );
    5
}
/// The relay: method 8 queries its own record, 9 sends Create through its
/// session, 10 keeps a session another process gave it, 11 queries
/// through that session (BAD_STATE before one came).
struct Relay {
    clock: Client,
    process: process_client::Client,
    kept: Option<process_client::Client>,
}

/// Create through `session` with `start` as its start channel: the
/// service's status.
fn create(
    session: &rt::handle::Handle<rt::handle::Channel>,
    start: rt::handle::Handle<rt::handle::Any>,
) -> Status {
    let mut w = proto_wire::Writer::new();
    let body = proto_process::Create {
        quota: 64 * 1024,
        handle_limit: 16,
        ceiling: 30,
        priority: 30,
        root: true,
        parent: 0,
    };
    if proto_process::Method::Create
        .header()
        .write(&mut w)
        .is_err()
        || body.write(&mut w).is_err()
    {
        return Status::BadSize;
    }
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    match sys::send_handles(session, w.as_bytes(), [start]) {
        Ok(reply) => proto_wire::Reader::new(reply.bytes(&mut buffer))
            .u32()
            .map_or(Status::BadSize, Status::from_code),
        Err(refused) => Status::Kernel(refused.error),
    }
}
impl Service<0> for Relay {
    const VERSION: u16 = proto_clock::VERSION;
    const METHODS: &'static [u16] = &[proto_clock::Method::Get as u16, 8, 9, 10, 11];
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
            let Ok(foreign) = r.handles.take_any(0) else {
                return Answer::Status(Status::BadSize);
            };
            // Create through its own session, with the handle as its start
            // channel, which the service refuses: only its own threads and
            // init hold the channel with no label.
            return Answer::Status(create(self.process.session(), foreign));
        }
        if r.method() == 10 {
            if r.handles.len() != 1 || r.body().finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            let Ok(session) = r.handles.take::<rt::handle::Channel>(0) else {
                return Answer::Status(Status::BadSize);
            };
            self.kept = Some(process_client::Client::new(session));
            return Answer::Status(Status::Ok);
        }
        if r.method() == 11 {
            if !r.handles.is_empty() || r.body().finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            return Answer::Status(match self.kept.as_ref() {
                None => Status::Kernel(rt::abi::Error::BadState),
                Some(kept) => kept.query().map_or_else(|error| error, |_| Status::Ok),
            });
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
