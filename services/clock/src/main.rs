// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! System-wide realtime anchor. Starts at the Unix epoch until explicitly set.
#![no_std]
#![no_main]
use posix_time::{Clock, Error, Settings, Snapshot, Time};
use proto_clock::Method;
use proto_init::ServiceArgs;
use proto_wire::Status;
use rt::handle::{Outgoing, Resource};
use rt::service::{Answer, Config, Heartbeat, Request, Service, Session};
use rt::sys;
rt::entry!(main);

fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}
fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let args = ServiceArgs::read(start.args()).ok();
    let level = sys::thread_info(&start.thread).map_or(1, |i| i.base);
    let Ok(channel) = sys::channel_create(1) else {
        return 2;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 3;
    }
    let Ok(clock) = Clock::new(now(), rt::time::frequency()) else {
        return 4;
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &start.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    rt::println!("clock: ready (unsynchronized epoch)");
    let _ = rt::service::run::<Clocks, 8, 0>(&channel, &mut Clocks { clock }, config);
    5
}
struct Clocks {
    clock: Clock,
}
#[derive(Default)]
struct Data {
    settings: Settings,
    #[cfg(feature = "transport-probe")]
    interrupt: Option<(u16, rt::handle::Handle<rt::handle::Thread>)>,
}
#[cfg(feature = "transport-probe")]
fn interrupt(data: &mut Data, method: Method) {
    if data
        .interrupt
        .as_ref()
        .is_some_and(|(m, _)| *m == method as u16)
    {
        let (_, thread) = data.interrupt.take().expect("armed clock interruption");
        sys::thread_interrupt(&thread).expect("clock caller must await committed reply");
    }
}
fn status(result: Result<(), Error>) -> Answer {
    Answer::Status(Status::from_code(match result {
        Ok(()) => 0,
        Err(Error::Invalid) => proto_clock::INVALID,
        Err(Error::Overflow) => proto_clock::OVERFLOW,
        Err(Error::Full) => proto_clock::FULL,
    }))
}
fn snapshot(r: &mut Request<'_>, value: Snapshot) -> Answer {
    let w = r.reply();
    if w.u32(0)
        .and_then(|()| w.u64(value.time.seconds as u64))
        .and_then(|()| w.u64(value.time.nanos as u64))
        .and_then(|()| w.u64(value.resolution))
        .and_then(|()| w.u64(value.generation))
        .is_err()
    {
        return Answer::Status(Status::BadSize);
    }
    Answer::Reply(Outgoing::new())
}
impl Service<0> for Clocks {
    const VERSION: u16 = proto_clock::VERSION;
    #[cfg(not(feature = "transport-probe"))]
    const METHODS: &'static [u16] = proto_clock::METHODS;
    #[cfg(feature = "transport-probe")]
    const METHODS: &'static [u16] = &[1, 2, 3, 4];
    type Data = Data;
    fn request(&mut self, s: &mut Session<Data, 0>, r: &mut Request<'_>) -> Answer {
        #[cfg(feature = "transport-probe")]
        if r.method() == 4 {
            let mut body = r.body();
            let Ok(method) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            if body.finish().is_err()
                || r.handles.len() != 1
                || !(2..=3).contains(&method)
                || s.data.interrupt.is_some()
            {
                return Answer::Status(Status::BadSize);
            }
            let Ok(thread) = r.handles.take::<rt::handle::Thread>(0) else {
                return Answer::Status(Status::BadSize);
            };
            s.data.interrupt = Some((method as u16, thread));
            return Answer::Status(Status::Ok);
        }
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let mut body = r.body();
        match Method::from_number(r.method()) {
            Some(Method::Get) => {
                let Ok(id) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.clock.get(id, now()) {
                    Ok(value) => snapshot(r, value),
                    Err(error) => status(Err(error)),
                }
            }
            Some(Method::Set) => {
                let (Ok(nonce), Ok(seconds), Ok(nanos)) = (body.u64(), body.u64(), body.u64())
                else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let result = s.data.settings.set(
                    nonce,
                    Time {
                        seconds: seconds as i64,
                        nanos: nanos as i64,
                    },
                    now(),
                    &mut self.clock,
                );
                #[cfg(feature = "transport-probe")]
                if result.is_ok() {
                    interrupt(&mut s.data, Method::Set);
                }
                status(result)
            }
            Some(Method::Ack) => {
                let Ok(nonce) = body.u64() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let result = s.data.settings.ack(nonce);
                #[cfg(feature = "transport-probe")]
                if result.is_ok() {
                    interrupt(&mut s.data, Method::Ack);
                }
                status(result)
            }
            None => Answer::Status(Status::UnknownMethod),
        }
    }
}
