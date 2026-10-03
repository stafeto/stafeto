// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! System-wide realtime anchor. Starts at the Unix epoch until explicitly set.
#![no_std]
#![no_main]
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU64, Ordering};
use posix_credentials::known::Known;
use posix_time::{Clock, Error, History, Snapshot, Time};
use proto_clock::Method;
use proto_clock::page;
use proto_init::ServiceArgs;
use proto_wire::Status;
use rt::handle::{Channel, Handle, Memory, Outgoing, Process, Resource};
use rt::service::{Answer, Config, Heartbeat, Request, Service, Session};
use rt::sys;
rt::entry!(main);

/// The sessions: the POSIX processes init starts and their children, each
/// with a session of its own (Clone): the 255 records of the process
/// service and the services beside them.
const SESSIONS: usize = 320;
/// The clones the service keeps alive at most, for all its clients: one
/// for each record of the process service and room beside them.
const CLONES: usize = 320;
/// The mark of the labels the service gives itself (Clone): bit 63, which
/// no label of init has.
const OWN: u64 = 1 << 63;
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
    let _ = rt::service::run::<Clocks, SESSIONS, 0>(
        &channel,
        &mut Clocks {
            channel: Handle::borrowed(channel.raw()),
            level,
            given: 0,
            clones: proto_wire::clones::Clones::new(),
            clock,
            page,
            watches: core::array::from_fn(|_| None),
            process: Handle::borrowed(start.process.raw()),
            parent: Handle::borrowed(start.parent.raw()),
            notary: None,
            generations: None,
            identities: core::array::from_fn(|_| None),
            evict: 0,
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
/// What the service knows of the process behind a session: a copy of its
/// identity session of the process service, which a SET of the session
/// brought, and what the process service vouched, with the generation of
/// the credentials.
struct Identity {
    label: u64,
    channel: Handle<Channel>,
    known: Known,
}
struct Clocks {
    /// The service's channel, which the sessions Clone gives are copies
    /// of, at the loop's level, and how many it gave.
    channel: ManuallyDrop<Handle<Channel>>,
    level: u8,
    given: u64,
    /// The sessions Clone gave that live, bounded for each client.
    clones: proto_wire::clones::Clones<CLONES>,
    clock: Clock,
    page: Page,
    watches: [Option<Watch>; 8],
    /// The service's own process, to map the generations page in.
    process: ManuallyDrop<Handle<Process>>,
    /// Its channel to init, for the notary session.
    parent: ManuallyDrop<Handle<Channel>>,
    /// The notary session with the process service, which init gives the
    /// clock on CONNECT (init's VOUCHERS): the one channel the service
    /// trusts for who a client is; asked for at the first SET.
    notary: Option<Handle<Channel>>,
    /// The page of the credentials generations of the process service,
    /// through the notary session (Register).
    generations: Option<Handle<Memory>>,
    identities: [Option<Identity>; 8],
    /// The place a session with none takes when all are used: each is
    /// taken in turn, and its session brings its copy again.
    evict: usize,
}

/// Where the service maps the process service's page of the credentials
/// generations, read-only.
const GENERATIONS_ADDRESS: usize = 0x0F00_0000;

/// The generation of the credentials of the record at `index`, read from
/// the page with no call (Acquire); the page is mapped.
fn generation(index: usize) -> u64 {
    // SAFETY: the page is mapped for reading at GENERATIONS_ADDRESS for the
    // service's life once `generations` is set, which every caller checked;
    // an index below RECORDS (a PID modulo it) is a u64 word inside it.
    unsafe { &*((GENERATIONS_ADDRESS + index * 8) as *const AtomicU64) }.load(Ordering::Acquire)
}

/// Vouch through the notary session: what the process service says of
/// the client whose identity session `identity` is a copy of (none for a
/// channel of anyone else). The request goes to the process service alone,
/// never to a client (spec 2, 2).
fn vouch(notary: &Handle<Channel>, identity: &Handle<Channel>) -> Option<proto_process::WhoReply> {
    let rights = rt::abi::Rights::NOTIFY | rt::abi::Rights::TRANSFER;
    let copy = sys::handle_duplicate(identity, rights).ok()?;
    let request = proto_process::Method::Vouch.header().bytes();
    let reply = sys::send_handles(notary, &request, [copy.erase()]).ok()?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    proto_process::WhoReply::read(reply.bytes(&mut buffer)).ok()
}

impl Clocks {
    /// The notary session (asked of init once) and the page of the
    /// generations mapped through it (Register), once.
    fn notary(&mut self) -> bool {
        if self.notary.is_none() {
            self.notary = rt::service::connect(&self.parent, "posix").ok();
        }
        let Some(notary) = self.notary.as_ref() else {
            return false;
        };
        if self.generations.is_some() {
            return true;
        }
        let request = proto_process::Method::Register.header().bytes();
        let Ok(mut reply) = sys::send(notary, &request) else {
            return false;
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
            return false;
        }
        let Ok(memory) = reply.handles.take::<Memory>(0) else {
            return false;
        };
        // The object is a page, of which the generations take GENERATIONS_SIZE.
        let mapped = sys::mem_map(
            &self.process,
            &memory,
            0,
            4096,
            GENERATIONS_ADDRESS,
            rt::abi::Access::Read,
        );
        if mapped.is_err() {
            return false;
        }
        self.generations = Some(memory);
        true
    }

    /// Whether the process behind the session `label` may set the clock:
    /// its effective UID is 0 (spec 2, 3.1). `offered` is the identity
    /// session the request brought, which the session keeps in place of
    /// the one before: after an exec the session moved to the new image,
    /// whose identity is another, and the old one vouches for nothing
    ///. The process service vouches for it through
    /// the notary session, and what it said is remembered with the
    /// generation of the credentials and asked again only when the
    /// generation on the page moved: no call to the process service
    /// otherwise, and a SET sent after `setuid` returned sees the new
    /// credentials. A channel that is no identity session, no identity
    /// session, or any failure: no.
    fn may_set(&mut self, label: u64, offered: Option<Handle<Channel>>) -> bool {
        if !self.notary() {
            return false;
        }
        let found = self
            .identities
            .iter()
            .position(|i| i.as_ref().is_some_and(|i| i.label == label));
        let slot = match (found, offered) {
            (Some(slot), None) => slot,
            (Some(slot), Some(channel)) => {
                self.identities[slot] = Some(Identity {
                    label,
                    channel,
                    known: Known::new(),
                });
                slot
            }
            (None, Some(channel)) => {
                // A free place, or else each in turn: the session whose
                // place went brings its copy with its next SET again.
                let slot = self
                    .identities
                    .iter()
                    .position(Option::is_none)
                    .unwrap_or_else(|| {
                        self.evict = (self.evict + 1) % self.identities.len();
                        self.evict
                    });
                self.identities[slot] = Some(Identity {
                    label,
                    channel,
                    known: Known::new(),
                });
                slot
            }
            (None, None) => return false,
        };
        let Some(mut identity) = self.identities[slot].take() else {
            return false;
        };
        let notary = self.notary.as_ref().expect("the notary session");
        let allowed = identity
            .known
            .credentials(generation, || vouch(notary, &identity.channel))
            .is_some_and(|c| c.euid == 0);
        self.identities[slot] = Some(identity);
        allowed
    }
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
        if r.method() == Method::Clone as u16 {
            if r.body().finish().is_err() || !r.handles.is_empty() {
                return Answer::Status(Status::BadSize);
            }
            if self.clones.room(r.label()).is_err() {
                return Answer::Status(Status::Kernel(rt::abi::Error::LimitReached));
            }
            self.given += 1;
            let rights = rt::abi::Rights::SEND.union(rt::abi::Rights::TRANSFER);
            let label = OWN | self.given;
            return match sys::handle_label(&self.channel, rights, label, self.level) {
                Ok(session) => {
                    if r.reply().u32(0).is_err() {
                        return Answer::Status(Status::BadSize);
                    }
                    let _ = self.clones.add(label, r.label());
                    Answer::Reply([session.erase()].into())
                }
                Err(e) => Answer::Status(Status::Kernel(e)),
            };
        }
        if r.handles.len() > usize::from(r.method() == Method::Set as u16) {
            return Answer::Status(Status::BadSize);
        }
        let offered = r.handles.take::<Channel>(0).ok();
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
                if !self.may_set(r.label(), offered) {
                    return Answer::Status(Status::from_code(proto_clock::PERMISSION));
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
            Some(Method::Watch | Method::Clone) | None => Answer::Status(Status::UnknownMethod),
        }
    }
    /// The last copy of a session Clone gave went.
    fn closed(&mut self, label: u64) {
        self.clones.gone(label);
    }
    fn gone(&mut self, s: &mut Session<(), 0>) {
        for slot in &mut self.identities {
            if slot.as_ref().is_some_and(|i| i.label == s.label()) {
                *slot = None;
            }
        }
        for slot in &mut self.watches {
            if slot.as_ref().is_some_and(|w| w.label == s.label()) {
                *slot = None;
            }
        }
    }
}
