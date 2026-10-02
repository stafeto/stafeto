// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! System-wide realtime anchor. Starts at the Unix epoch until explicitly set.
#![no_std]
#![no_main]
use core::sync::atomic::{AtomicU64, Ordering};
use posix_time::{Clock, Error, History, Snapshot, Time};
use proto_clock::Method;
use proto_clock::page;
use proto_init::ServiceArgs;
use proto_wire::Status;
use rt::handle::{Channel, Handle, Memory, Outgoing, Resource};
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
    let Ok(page) = Page::new(&start.process) else {
        return 6;
    };
    page.publish(&clock);
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
            page,
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
    page: Page,
    watches: [Option<Watch>; 8],
}

/// Where the service maps its page of the anchor.
const PAGE_ADDRESS: usize = 0x0E00_0000;

/// The page of the CLOCK_REALTIME anchor (proto_clock::page): the service
/// writes it, every POSIX process maps it to read.
struct Page {
    memory: Handle<Memory>,
}
impl Page {
    fn new(process: &Handle<rt::handle::Process>) -> Result<Self, rt::abi::Error> {
        let memory = sys::mem_create(page::SIZE as u64)?;
        sys::mem_map(
            process,
            &memory,
            0,
            page::SIZE as u64,
            PAGE_ADDRESS,
            rt::abi::Access::ReadWrite,
        )?;
        Ok(Self { memory })
    }
    fn word(offset: usize) -> &'static AtomicU64 {
        // SAFETY: the page is mapped read-write at PAGE_ADDRESS for the
        // service's life; its words are aligned.
        unsafe { &*((PAGE_ADDRESS + offset) as *const AtomicU64) }
    }
    /// Writes the anchor of `clock` into the place readers do not look at,
    /// then moves the counter to it.
    fn publish(&self, clock: &Clock) {
        let anchor = clock.anchor();
        let value = anchor.time.value().expect("valid stored calendar anchor");
        let sequence = Self::word(page::SEQUENCE).load(Ordering::Relaxed);
        let place = page::PLACES + ((sequence + 1) % 2) as usize * page::PLACE_SIZE;
        // The writes of the place come after the last move of the counter
        // for every processor: a reader that saw that move and reads this
        // place (as sequence s+2 later) never mixes it with the old one, as
        // Linux's write of a latch (smp_wmb) keeps it. One processor needs
        // no barrier; several do.
        core::sync::atomic::fence(Ordering::Release);
        Self::word(place + page::LOW).store(value as u64, Ordering::Relaxed);
        Self::word(place + page::HIGH).store((value >> 64) as u64, Ordering::Relaxed);
        Self::word(place + page::MONO).store(anchor.mono, Ordering::Relaxed);
        Self::word(place + page::GENERATION).store(anchor.generation, Ordering::Relaxed);
        Self::word(page::SEQUENCE).store(sequence + 1, Ordering::Release);
    }
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
    const METHODS: &'static [u16] = proto_clock::METHODS;
    type Data = ();
    fn request(&mut self, _: &mut Session<(), 0>, r: &mut Request<'_>) -> Answer {
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
                let (Ok(seconds), Ok(nanos)) = (body.u64(), body.u64()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let time = Time {
                    seconds: seconds as i64,
                    nanos: nanos as i64,
                };
                if time.value().is_err() {
                    return status(Err(Error::Invalid));
                }
                let generation = self.clock.anchor().generation;
                let tick = now();
                self.record(self.clock.current(tick).expect("calendar before setting"));
                let result = self.clock.set(time, tick);
                if result.is_ok() && self.clock.anchor().generation != generation {
                    self.page.publish(&self.clock);
                    self.record(self.clock.current(tick).expect("calendar after setting"));
                    self.changed();
                }
                status(result)
            }
            Some(Method::Anchor | Method::Observe) => {
                let observe = r.method() == Method::Observe as u16;
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let mut anchor = self.clock.anchor();
                let peak = if observe {
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
                    let observation = watch.history.take(current, anchor);
                    anchor = observation.anchor;
                    Some(observation.peak as u128)
                } else {
                    None
                };
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
            Some(Method::Page) => {
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let rights = rt::abi::Rights::MAP_READ.union(rt::abi::Rights::TRANSFER);
                let Ok(copy) = sys::handle_duplicate(&self.page.memory, rights) else {
                    return Answer::Status(Status::Kernel(rt::abi::Error::NoMemory));
                };
                let mut handles = Outgoing::new();
                if handles.push(copy.erase()).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                if r.reply().u32(0).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply(handles)
            }
            Some(Method::Watch) | None => Answer::Status(Status::UnknownMethod),
        }
    }
    fn gone(&mut self, s: &mut Session<(), 0>) {
        for slot in &mut self.watches {
            if slot.as_ref().is_some_and(|w| w.label == s.label()) {
                *slot = None;
            }
        }
    }
}
