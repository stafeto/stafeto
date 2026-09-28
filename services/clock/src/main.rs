// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! System-wide realtime anchor. Starts at the Unix epoch until explicitly set.
#![no_std]
#![no_main]
use posix_time::{Clock, Error, History, Snapshot, Time};
use proto_clock::Method;
use proto_init::ServiceArgs;
use proto_wire::Status;
use rt::handle::{Channel, Handle, Outgoing, Resource};
use rt::service::{Answer, Config, Heartbeat, Request, Service, Session};
use rt::sys;
mod replies;
use replies::{Journal, Reply};
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
    let _ = rt::service::run::<Clocks, 8, 0>(
        &channel,
        &mut Clocks {
            clock,
            replies: Journal::new(start.process),
            #[cfg(feature = "transport-probe")]
            pressure: [const { None }; 128],
            watches: core::array::from_fn(|_| None),
        },
        config,
    );
    5
}
struct Watch {
    label: u64,
    channel: Handle<Channel>,
    history: History,
}
struct Clocks {
    clock: Clock,
    replies: Journal,
    #[cfg(feature = "transport-probe")]
    pressure: [Option<Handle<Channel>>; 128],
    watches: [Option<Watch>; 8],
}
impl Clocks {
    fn record(&mut self, value: i128) {
        for watch in self.watches.iter_mut().flatten() {
            watch.history.see(value);
        }
    }
    fn changed(&mut self) {
        for slot in &mut self.watches {
            if slot
                .as_ref()
                .is_some_and(|w| sys::notify(&w.channel, 1).is_err())
            {
                *slot = None;
            }
        }
    }
}
#[derive(Default)]
struct Data {
    #[cfg(feature = "transport-probe")]
    interrupt: Option<(u16, bool, rt::handle::Handle<rt::handle::Thread>)>,
}
#[cfg(feature = "transport-probe")]
fn interrupt(data: &mut Data, method: Method) {
    if data
        .interrupt
        .as_ref()
        .is_some_and(|(m, _, _)| *m == method as u16)
    {
        let (_, upcall, thread) = data.interrupt.take().expect("armed clock interruption");
        if upcall {
            sys::thread_upcall_request(&thread).expect("clock nested caller");
        } else {
            sys::thread_interrupt(&thread).expect("clock caller must await committed reply");
        }
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
    const METHODS: &'static [u16] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    type Data = Data;
    fn request(&mut self, _s: &mut Session<Data, 0>, r: &mut Request<'_>) -> Answer {
        #[cfg(feature = "transport-probe")]
        if r.method() == 11 {
            let mut body = r.body();
            let Ok(hold) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            if hold > 1 || body.finish().is_err() || !r.handles.is_empty() {
                return Answer::Status(Status::BadSize);
            }
            for slot in &mut self.pressure {
                if hold == 0 {
                    *slot = None;
                } else if slot.is_none() {
                    match sys::channel_create(1) {
                        Ok(channel) => *slot = Some(channel),
                        Err(_) => break,
                    }
                }
            }
            return Answer::Status(Status::Ok);
        }
        #[cfg(feature = "transport-probe")]
        if r.method() == 10 {
            if r.body().finish().is_err() || !r.handles.is_empty() {
                return Answer::Status(Status::BadSize);
            }
            let (used, committed, handles, memory) = self.replies.stats();
            let w = r.reply();
            w.u32(0)
                .and_then(|()| w.u64(used))
                .and_then(|()| w.u64(committed))
                .and_then(|()| w.u64(handles))
                .and_then(|()| w.u64(memory))
                .expect("clock journal statistics");
            return Answer::Reply(Outgoing::new());
        }
        #[cfg(feature = "transport-probe")]
        if r.method() == 9 {
            let mut body = r.body();
            let Ok(reject) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            if reject > 1 || body.finish().is_err() || !r.handles.is_empty() {
                return Answer::Status(Status::BadSize);
            }
            self.replies.reject = if reject != 0 { Some(r.label()) } else { None };
            return Answer::Status(Status::Ok);
        }
        #[cfg(feature = "transport-probe")]
        if matches!(r.method(), 4 | 8) {
            let mut body = r.body();
            let Ok(method) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            if body.finish().is_err()
                || r.handles.len() != 1
                || ![2, 3, 7].contains(&method)
                || _s.data.interrupt.is_some()
            {
                return Answer::Status(Status::BadSize);
            }
            let Ok(thread) = r.handles.take::<rt::handle::Thread>(0) else {
                return Answer::Status(Status::BadSize);
            };
            _s.data.interrupt = Some((method as u16, r.method() == 8, thread));
            return Answer::Status(Status::Ok);
        }
        if r.method() == Method::Watch as u16 {
            if r.body().finish().is_err() || r.handles.len() != 1 {
                return Answer::Status(Status::BadSize);
            }
            if !r
                .handles
                .info(0)
                .is_some_and(|(_, rights)| rights.contains(rt::abi::Rights::NOTIFY))
            {
                return Answer::Status(Status::Kernel(rt::abi::Error::AccessDenied));
            }
            let Ok(channel) = r.handles.take::<Channel>(0) else {
                return Answer::Status(Status::BadSize);
            };
            let index = self
                .watches
                .iter()
                .position(|w| w.as_ref().is_some_and(|w| w.label == r.label()))
                .or_else(|| self.watches.iter().position(Option::is_none));
            let Some(index) = index else {
                return status(Err(Error::Full));
            };
            let current = self
                .clock
                .current(now())
                .expect("clock counter progression");
            let mut history = self.watches[index]
                .as_ref()
                .map_or(History::new(current), |w| w.history);
            history.see(current);
            self.watches[index] = Some(Watch {
                label: r.label(),
                channel,
                history,
            });
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
                let time = Time {
                    seconds: seconds as i64,
                    nanos: nanos as i64,
                };
                if nonce == 0 || time.value().is_err() {
                    return status(Err(Error::Invalid));
                }
                let result = match self.replies.ready(r.label(), nonce) {
                    Some(Reply::Set(previous, result)) if previous == time => result,
                    Some(_) => Err(Error::Invalid),
                    None => {
                        if self.replies.reserve(r.label(), nonce).is_err() {
                            return status(Err(Error::Full));
                        }
                        let generation = self.clock.anchor().generation;
                        let tick = now();
                        self.record(self.clock.current(tick).expect("calendar before setting"));
                        let result = self.clock.set(time, tick);
                        if result.is_ok() && self.clock.anchor().generation != generation {
                            self.record(self.clock.current(tick).expect("calendar after setting"));
                            self.changed();
                        }
                        self.replies
                            .complete(r.label(), nonce, Reply::Set(time, result));
                        result
                    }
                };
                #[cfg(feature = "transport-probe")]
                if result.is_ok() {
                    interrupt(&mut _s.data, Method::Set);
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
                if nonce == 0 {
                    return status(Err(Error::Invalid));
                }
                self.replies.ack(r.label(), nonce);
                let result = Ok(());
                #[cfg(feature = "transport-probe")]
                if result.is_ok() {
                    interrupt(&mut _s.data, Method::Ack);
                }
                status(result)
            }
            Some(Method::Anchor | Method::Observe) => {
                let nonce = if r.method() == Method::Observe as u16 {
                    let Ok(nonce) = body.u64() else {
                        return Answer::Status(Status::BadSize);
                    };
                    if nonce == 0 {
                        return status(Err(Error::Invalid));
                    }
                    Some(nonce)
                } else {
                    None
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let mut anchor = self.clock.anchor();
                let peak = if let Some(nonce) = nonce {
                    let observation = match self.replies.ready(r.label(), nonce) {
                        Some(Reply::Observe(value)) => value,
                        Some(_) => return status(Err(Error::Invalid)),
                        None => {
                            let current = self
                                .clock
                                .current(now())
                                .expect("observed calendar progression");
                            let Some(watch) = self
                                .watches
                                .iter_mut()
                                .flatten()
                                .find(|w| w.label == r.label())
                            else {
                                return Answer::Status(Status::Kernel(rt::abi::Error::BadState));
                            };
                            if self.replies.reserve(r.label(), nonce).is_err() {
                                return status(Err(Error::Full));
                            }
                            let value = watch.history.take(current, anchor);
                            self.replies
                                .complete(r.label(), nonce, Reply::Observe(value));
                            value
                        }
                    };
                    anchor = observation.anchor;
                    Some(observation.peak as u128)
                } else {
                    None
                };
                #[cfg(feature = "transport-probe")]
                if nonce.is_some() {
                    interrupt(&mut _s.data, Method::Observe);
                }
                let w = r.reply();
                if w.u32(0)
                    .and_then(|()| w.u64(anchor.time.seconds as u64))
                    .and_then(|()| w.u64(anchor.time.nanos as u64))
                    .and_then(|()| w.u64(anchor.mono))
                    .and_then(|()| w.u64(anchor.resolution))
                    .and_then(|()| w.u64(anchor.generation))
                    .is_err()
                {
                    return Answer::Status(Status::BadSize);
                }
                if let Some(peak) = peak
                    && w.u64((peak >> 64) as u64)
                        .and_then(|()| w.u64(peak as u64))
                        .is_err()
                {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply(Outgoing::new())
            }
            Some(Method::Watch) | None => Answer::Status(Status::UnknownMethod),
        }
    }
    fn gone(&mut self, s: &mut Session<Data, 0>) {
        self.replies.forget(s.label());
        #[cfg(feature = "transport-probe")]
        if self.replies.reject == Some(s.label()) {
            self.replies.reject = None;
        }
        for slot in &mut self.watches {
            if slot.as_ref().is_some_and(|w| w.label == s.label()) {
                *slot = None;
            }
        }
    }
}
