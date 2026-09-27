// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Single-threaded RAM file service. Each client session has its own fds.

#![no_std]
#![no_main]

use proto_fs::{MAX_READ, MAX_WRITE, Method, VERSION, valid_path};
use proto_init::ServiceArgs;
use proto_wire::Status;
use ramfs::{Fds, Ram};
use rt::handle::{Outgoing, Resource};
use rt::service::{Answer, Config, Heartbeat, Request, Service, Session};
use rt::sys;

rt::entry!(main);

const METHODS: &[u16] = proto_fs::METHODS;
const SESSIONS: usize = 8;

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let args = ServiceArgs::read(start.args()).ok();
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return 2;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 3;
    }
    let heartbeat = Heartbeat {
        to: &start.parent,
        period_ns: args.map_or(0, |args| args.period_ns),
        priority: level,
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(heartbeat),
    };
    rt::println!("ramfs: ready");
    let mut fs = Fs {
        ram: Ram::default(),
    };
    let _ = rt::service::run::<Fs, SESSIONS, 0>(&channel, &mut fs, config);
    4
}

struct Fs {
    ram: Ram,
}

fn status(code: u32) -> Answer {
    Answer::Status(Status::from_code(code))
}

fn value(r: &mut Request<'_>, number: u32) -> Answer {
    let w = r.reply();
    if w.u32(0).and_then(|()| w.u32(number)).is_err() {
        return Answer::Status(Status::BadSize);
    }
    Answer::Reply(Outgoing::new())
}

impl Service<0> for Fs {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = Fds;

    fn request(&mut self, s: &mut Session<Fds, 0>, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        match Method::from_number(r.method()) {
            Some(Method::Open) => {
                let Ok(flags) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                let Ok(path) = body.bytes(body.left()).and_then(valid_path) else {
                    return Answer::Status(Status::BadSize);
                };
                match s.data.open(path, flags) {
                    Ok(fd) => value(r, fd),
                    Err(code) => status(code),
                }
            }
            Some(Method::Read) => {
                let (Ok(fd), Ok(count)) = (body.u32(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() || count as usize > MAX_READ {
                    return Answer::Status(Status::BadSize);
                }
                let mut bytes = [0; MAX_READ];
                match self.ram.read(&mut s.data, fd, &mut bytes[..count as usize]) {
                    Ok(n) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(n as u32))
                            .and_then(|()| w.bytes(&bytes[..n]))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::Write) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                let Ok(bytes) = body.bytes(body.left()) else {
                    return Answer::Status(Status::BadSize);
                };
                if bytes.len() > MAX_WRITE {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.write(&mut s.data, fd, bytes) {
                    Ok(n) => value(r, n as u32),
                    Err(code) => status(code),
                }
            }
            Some(Method::Seek) => {
                let (Ok(fd), Ok(offset)) = (body.u32(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match s.data.seek(fd, offset) {
                    Ok(offset) => value(r, offset),
                    Err(code) => status(code),
                }
            }
            Some(Method::Stat) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.size(&s.data, fd) {
                    Ok(size) => value(r, size),
                    Err(code) => status(code),
                }
            }
            Some(Method::Close) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match s.data.close(fd) {
                    Ok(()) => Answer::Status(Status::Ok),
                    Err(code) => status(code),
                }
            }
            None => Answer::Status(Status::UnknownMethod),
        }
    }
}
