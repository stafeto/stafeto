// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The entropy service (proto_entropy, SEED): every POSIX process may ask
//! it for a key of 32 bytes, the output of the service's generator with
//! fast key erasure (entropy::Source), which the process's own generator
//! runs on. The service holds no window and no DMA; the device's driver
//! (`rng`, services/virtio-rng) feeds it.
//!
//! Two threads. The loop (rt::service) answers SEED from the generator in
//! one step, a block of ChaCha20, and never calls the driver: before the
//! device's first bytes a SEED waits as a long operation in two steps
//! (proto_wire::long), or gets NOT_READY with NONBLOCK; once they came,
//! every SEED is answered at once. The feeder thread is the driver's only
//! client: it takes FIRST_BYTES at the start and RESEED_BYTES every
//! RESEED_NS through the driver's fills, hands them to the loop through
//! FEED and a notification, and sleeps; when the driver ends it connects
//! again, waiting in init while the driver restarts, and the loop goes on
//! answering from the generator meanwhile. The number of the device's
//! reads does not depend on the clients. The seeds that waited for the
//! first bytes hear of them TELLS a step. CLONE gives a child of a client
//! a session of the service's own label.
//!
//! Every copy of a key or of the device's bytes the service makes is
//! erased with volatile stores once it went (posix_random::erase): the
//! generator's, FEED, the feeder's buffers and its message buffer. A reply
//! of SEED goes in the registers of the reply (40 bytes, inline), which
//! the kernel copies and the next reply overwrites.

#![no_std]
#![no_main]

use abi::{Error, MESSAGE_MAX, Rights, Source as From};
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use entropy::{FIRST_BYTES, RESEED_NS, Source, Start};
use proto_entropy::{Fill, Key, Method, NOT_READY, Seed, VERSION};
use proto_init::ServiceArgs;
use proto_wire::clones::Clones;
use proto_wire::{Status, Writer, long};
use rt::handle::{Channel, Outgoing, Resource, Thread};
use rt::service::{
    Answer, Config, Heartbeat, LongOps, LongSession, Notice, Request, Service, Session,
};
use rt::wait::{Waited, Waiter};
use rt::{Handle, Stack, sys, time};

rt::entry!(main);

/// The sessions of the service's channel: every POSIX process may hold
/// one, init's or a clone (CLONE), and the process service keeps 255 of
/// them; room beside them, as the clock service has.
const SESSIONS: usize = 320;
/// The clones the service keeps alive at most, for all its clients.
const CLONES: usize = 320;
/// The mark of the labels the service gives itself (CLONE): bit 63, which
/// no label of init has.
const OWN: u64 = 1 << 63;
/// The seeds that wait for the device's first bytes, at most; the layer
/// asks again after a pause when they are all taken.
const WAITING: usize = 64;
/// The seeds one step tells that the first bytes came: each tell is a
/// notify of the kernel (about 470 ticks), so a step stays well under term
/// B; the loop notifies itself (TELL) for the rest.
const TELLS: usize = 8;
/// The bits of the notifications on the loop's channel: the feeder's
/// bytes, and the rest of the seeds to tell.
const FED: u64 = 1;
const TELL: u64 = 2;
/// The feeder's wait before its first fill in the probes' build
/// (feature `slow-start`), so that seeds wait for the first bytes.
#[cfg(feature = "slow-start")]
const SLOW_START_NS: u64 = 500_000_000;
/// The code of a service whose feeder could not start its waits.
const NO_FEEDER_WAITS: u64 = 6;
/// How long the feeder waits for one fill, and before it connects again
/// to a driver that broke.
const FILL_NS: u64 = 1_000_000_000;
const RETRY_NS: u64 = 1_000_000_000;

/// The codes of a start that failed.
const NO_START_DATA: u64 = 1;
const NOT_REGISTERED: u64 = 3;
const NO_FEEDER: u64 = 4;
const STOPPED: u64 = 5;

/// The bytes the feeder hands the loop: FULL while they wait for it.
struct Feed {
    full: AtomicBool,
    len: AtomicUsize,
    bytes: UnsafeCell<[u8; FIRST_BYTES]>,
}

// SAFETY: the feeder writes `bytes` only while `full` is clear, and the
// loop reads them only while it is set; the flag orders the two.
unsafe impl Sync for Feed {}

static FEED: Feed = Feed {
    full: AtomicBool::new(false),
    len: AtomicUsize::new(0),
    bytes: UnsafeCell::new([0; FIRST_BYTES]),
};

/// What the feeder takes from the main thread: its connection to init, a
/// copy of the loop's channel with NOTIFY and no label, and its level.
static PARENT: AtomicU64 = AtomicU64::new(0);
static NOTIFY: AtomicU64 = AtomicU64::new(0);
static LEVEL: AtomicU64 = AtomicU64::new(1);

const FEEDER_STACK: usize = 8 * 1024;
static STACK: Stack<FEEDER_STACK> = Stack::new();
/// The feeder's message buffer, the page after the main thread's.
const FEEDER_BUFFER: usize = abi::INIT_MSGBUF as usize + 4096;

/// The table of sessions, outside the loop's stack.
struct Table(UnsafeCell<[Option<Session<LongSession, 1>>; SESSIONS]>);

// SAFETY: only the main thread reaches it, once.
unsafe impl Sync for Table {}

static TABLE: Table = Table(UnsafeCell::new([const { None }; SESSIONS]));

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let args = ServiceArgs::read(s.args()).ok();
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return NOT_REGISTERED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return NOT_REGISTERED;
    }
    let Ok(notify) = sys::handle_duplicate(&channel, Rights::NOTIFY) else {
        return NO_FEEDER;
    };
    PARENT.store(s.parent.raw().0, Ordering::Release);
    NOTIFY.store(notify.into_raw().0, Ordering::Release);
    LEVEL.store(u64::from(level), Ordering::Release);
    // SAFETY: STACK is the feeder's alone, and the page after the main
    // thread's message buffer is free.
    let feeder = unsafe {
        sys::thread_create(
            &s.process,
            feed,
            STACK.top(),
            0,
            level,
            abi::Policy::Fifo,
            FEEDER_BUFFER,
        )
    };
    let Ok(feeder) = feeder else {
        return NO_FEEDER;
    };
    if sys::thread_start(&feeder).is_err() {
        return NO_FEEDER;
    }
    let mut service = Entropy {
        source: Source::new(),
        ops: LongOps::new(),
        clones: Clones::new(),
        telling: [(0, 0); WAITING],
        told: 0,
        to_tell: 0,
        notify: Handle::borrowed(rt::abi::Handle(NOTIFY.load(Ordering::Acquire))),
        channel: Handle::borrowed(channel.raw()),
        level,
        _feeder: feeder,
    };
    #[cfg(feature = "steps")]
    rt::service::report_steps(11);
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &s.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    // SAFETY: only the main thread reaches TABLE, here once.
    let table = unsafe { &mut *TABLE.0.get() };
    let _ = rt::service::run_in(&channel, &mut service, config, table);
    STOPPED
}

/// The loop: the generator, the seeds that wait for its first bytes, and
/// the feeder, which lives as long as the service.
struct Entropy {
    source: Source,
    ops: LongOps<WAITING>,
    /// The sessions CLONE gave that live, bounded for each client; the
    /// channel they are copies of.
    clones: Clones<CLONES>,
    /// The seeds that waited when the first bytes came, told TELLS a step:
    /// `told` of `to_tell` so far.
    telling: [(u64, u64); WAITING],
    told: usize,
    to_tell: usize,
    /// The loop's own copy of its channel with NOTIFY (TELL).
    notify: ManuallyDrop<Handle<Channel>>,
    channel: ManuallyDrop<Handle<Channel>>,
    level: u8,
    _feeder: Handle<Thread>,
}

impl Entropy {
    /// SEED: the key at once once the device fed the generator; WAIT k
    /// before, or NOT_READY with NONBLOCK.
    fn seed(&mut self, s: &mut Session<LongSession, 1>, r: &mut Request<'_>) -> Answer {
        let flags = match Seed::read(r.body()) {
            Ok(seed) => seed.flags,
            Err(status) => return Answer::Status(status),
        };
        match self.source.start(flags) {
            Start::Ready(mut key) => {
                let answer = long_answer(r, long::Reply::Ready(&key));
                posix_random::erase(&mut key);
                answer
            }
            Start::NotReady => Answer::Status(NOT_READY),
            Start::Wait => match self.ops.start(&mut s.data, r.label()) {
                Ok(key) => long_answer(r, long::Reply::Wait(key)),
                Err(error) => Answer::Status(Status::Kernel(error)),
            },
        }
    }

    /// SEED_TAKE and SEED_CANCEL: the key once the generator is ready, or
    /// ARMED (keeping the handle with NOTIFY the first SEED_TAKE brings),
    /// or CANCELLED.
    fn take(
        &mut self,
        s: &mut Session<LongSession, 1>,
        r: &mut Request<'_>,
        cancel: bool,
    ) -> Answer {
        let key = match Key::read(r.body()) {
            Ok(key) => key.key,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        if !self.ops.waits(label, key) {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        if let Some(seed) = self.source.take() {
            self.ops.finish(&mut s.data, label, key);
            let mut seed = seed;
            let answer = long_answer(r, long::Reply::Ready(&seed));
            posix_random::erase(&mut seed);
            return answer;
        }
        if cancel {
            self.ops.finish(&mut s.data, label, key);
            return long_answer(r, long::Reply::Cancelled);
        }
        if !r.handles.is_empty() {
            match r.handles.take::<Channel>(0) {
                Ok(notify) => {
                    let _ = self.ops.arm(label, key, notify);
                }
                Err(error) => return Answer::Status(Status::Kernel(error)),
            }
        }
        long_answer(r, long::Reply::Armed)
    }

    /// CLONE: a new session for a child of the client, a copy of the
    /// service's channel with SEND, TRANSFER and a label of the service's
    /// own; LIMIT_REACHED past the clones of the client or of the service.
    fn clone_session(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let Ok(label) = self.clones.give(OWN, r.label()) else {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        };
        let rights = Rights::SEND | Rights::TRANSFER;
        match sys::handle_label(&self.channel, rights, label, self.level) {
            Ok(session) => {
                if r.reply().u32(Status::Ok.code()).is_err() {
                    self.clones.gone(label);
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply([session.erase()].into())
            }
            Err(error) => {
                self.clones.gone(label);
                Answer::Status(Status::Kernel(error))
            }
        }
    }

    /// Tells TELLS of the seeds that waited for the first bytes, and
    /// notifies the loop for the rest; a seed that went meanwhile is
    /// passed over (LongOps::tell).
    fn tell(&mut self) {
        rt::service::step_own();
        let end = (self.told + TELLS).min(self.to_tell);
        for &(label, key) in &self.telling[self.told..end] {
            self.ops.tell(label, key);
        }
        self.told = end;
        if self.told < self.to_tell {
            let _ = sys::notify(&self.notify, TELL);
        }
    }

    /// The feeder's bytes came: they seed or reseed the generator, and the
    /// seeds that waited for the first hear of it, WAITING at most.
    fn fed(&mut self) {
        rt::service::step_own();
        if !FEED.full.load(Ordering::Acquire) {
            return;
        }
        let len = FEED.len.load(Ordering::Relaxed);
        // SAFETY: FULL is set: the feeder does not touch the bytes until
        // the loop clears it.
        let bytes = unsafe { &mut *FEED.bytes.get() };
        let first = self.source.feed(&bytes[..len.min(FIRST_BYTES)]);
        posix_random::erase(bytes);
        FEED.full.store(false, Ordering::Release);
        if first {
            rt::println!("entropy: seeded from the device");
            self.to_tell = 0;
            for op in self.ops.keys().take(WAITING) {
                self.telling[self.to_tell] = op;
                self.to_tell += 1;
            }
            self.told = 0;
            self.tell();
        } else {
            #[cfg(feature = "report")]
            rt::println!(
                "entropy: reseeded from the device ({})",
                self.source.reseeds()
            );
        }
    }
}

const METHODS: &[u16] = &[
    Method::Seed.number(),
    Method::SeedTake.number(),
    Method::SeedCancel.number(),
    Method::Clone.number(),
];

impl Service<1> for Entropy {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = LongSession;

    fn request(&mut self, s: &mut Session<LongSession, 1>, r: &mut Request<'_>) -> Answer {
        match Method::from_number(r.method()) {
            Some(Method::Seed) => self.seed(s, r),
            Some(Method::SeedTake) => self.take(s, r, false),
            Some(Method::SeedCancel) => self.take(s, r, true),
            Some(Method::Clone) => self.clone_session(r),
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    fn gone(&mut self, s: &mut Session<LongSession, 1>) {
        self.ops.gone(&mut s.data);
    }

    /// The last copy of a session CLONE gave went.
    fn closed(&mut self, label: u64) {
        self.clones.gone(label);
    }

    fn notification(&mut self, n: Notice) {
        if n.source == From::Unlabeled && n.bits & FED != 0 {
            self.fed();
        }
        if n.source == From::Unlabeled && n.bits & TELL != 0 {
            self.tell();
        }
    }
}

/// The reply of a long operation, through the request's reply buffer.
fn long_answer(r: &mut Request<'_>, reply: long::Reply<'_>) -> Answer {
    match reply.write(r.reply()) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}

/// The feeder thread: connects to the driver, takes the device's bytes,
/// hands them to the loop, sleeps RESEED_NS, and again; a driver that
/// ended or broke gets a new connection, after RETRY_NS when init refused.
extern "C" fn feed(_: u64) -> ! {
    let parent = Handle::<Channel>::borrowed(abi::Handle(PARENT.load(Ordering::Acquire)));
    let notify = Handle::<Channel>::borrowed(abi::Handle(NOTIFY.load(Ordering::Acquire)));
    let level = LEVEL.load(Ordering::Acquire) as u8;
    // A feeder that cannot wait ends the service, and init starts it
    // again: a service without its feeder would keep every SEED waiting.
    let Ok(own) = sys::channel_create(level) else {
        rt::println!("entropy: the feeder has no channel");
        sys::process_exit(NO_FEEDER_WAITS);
    };
    let Ok(timer) = Waiter::new(&own, 0, level) else {
        rt::println!("entropy: the feeder has no timer");
        sys::process_exit(NO_FEEDER_WAITS);
    };
    let feeder = Feeder { own, timer, level };
    #[cfg(feature = "slow-start")]
    feeder.sleep(SLOW_START_NS);
    let mut fed = false;
    let mut bytes = [0; FIRST_BYTES];
    loop {
        let Ok(rng) = rt::service::connect(&parent, "rng") else {
            feeder.sleep(RETRY_NS);
            continue;
        };
        loop {
            let n = if fed {
                entropy::RESEED_BYTES
            } else {
                FIRST_BYTES
            };
            if feeder.fill(&rng, &mut bytes[..n]).is_err() {
                break;
            }
            // A device that gives the same bytes over and over would give
            // every boot the same keys: its bytes go, and it is asked again.
            if entropy::looks_constant(&bytes[..n]) {
                rt::println!("entropy: the device's bytes look constant; asking again");
                posix_random::erase(&mut bytes);
                feeder.sleep(RETRY_NS);
                continue;
            }
            if !FEED.full.load(Ordering::Acquire) {
                // SAFETY: FULL is clear: the loop does not read the bytes
                // until the feeder sets it.
                let place = unsafe { &mut *FEED.bytes.get() };
                place[..n].copy_from_slice(&bytes[..n]);
                FEED.len.store(n, Ordering::Relaxed);
                FEED.full.store(true, Ordering::Release);
                let _ = sys::notify(&notify, FED);
                fed = true;
            }
            posix_random::erase(&mut bytes);
            feeder.sleep(RESEED_NS);
        }
    }
}

/// The feeder's own channel, where the driver tells it a fill is done,
/// and the timer of its waits there.
struct Feeder {
    own: Handle<Channel>,
    timer: Waiter,
    level: u8,
}

impl Feeder {
    /// Waits `ns` on the feeder's channel, whatever else comes there.
    fn sleep(&self, ns: u64) {
        let deadline = time::ticks_to_ns(time::now()).saturating_add(ns);
        while let Ok(Waited::Got(_)) = self.timer.receive_until(&self.own, deadline) {}
    }

    /// A fill of `out.len()` bytes through `rng` in two steps (proto_entropy,
    /// FILL): WAIT k, then FILL_TAKE with a copy of the feeder's channel
    /// labelled k, until the bytes come. A driver that ended closes that
    /// copy, which ends the wait too; FILL_NS bounds it.
    fn fill(&self, rng: &Handle<Channel>, out: &mut [u8]) -> Result<(), ()> {
        let mut w = Writer::new();
        Fill {
            n: out.len() as u32,
        }
        .write(&mut w)
        .map_err(drop)?;
        let key = match call(rng, w.as_bytes(), None, out)? {
            (long::READY, _) => return Ok(()),
            (long::WAIT, key) => key,
            _ => return Err(()),
        };
        let mut take = Writer::new();
        Key { key }
            .write(Method::FillTake, &mut take)
            .map_err(drop)?;
        // The first FILL_TAKE brings the labelled copy, which the driver
        // keeps while the fill waits.
        let rights = Rights::NOTIFY | Rights::TRANSFER;
        let mut copy = Some(sys::handle_label(&self.own, rights, key, self.level).map_err(drop)?);
        let deadline = time::ticks_to_ns(time::now()).saturating_add(FILL_NS);
        loop {
            match call(rng, take.as_bytes(), copy.take(), out)? {
                (long::READY, _) => return Ok(()),
                (long::ARMED, _) => {}
                _ => return Err(()),
            }
            loop {
                match self.timer.receive_until(&self.own, deadline) {
                    Ok(Waited::Got(sys::Received::Notification {
                        source: From::Session,
                        label,
                        ..
                    })) if label == key => break,
                    Ok(Waited::Got(_)) => {}
                    _ => {
                        // The deadline: the fill goes, and the driver with
                        // it if it no longer answers.
                        let mut cancel = Writer::new();
                        if (Key { key }).write(Method::FillCancel, &mut cancel).is_ok() {
                            let _ = sys::send(rng, cancel.as_bytes());
                        }
                        return Err(());
                    }
                }
            }
        }
    }
}

/// One request to the driver, with `notify` when there is one, and its
/// long reply: its kind; READY bytes go into `out`, all of them, and WAIT
/// gives its key.
fn call(
    rng: &Handle<Channel>,
    request: &[u8],
    notify: Option<Handle<Channel>>,
    out: &mut [u8],
) -> Result<(u32, u64), ()> {
    let reply = match notify {
        None => sys::send(rng, request).map_err(drop)?,
        Some(n) => sys::send_handles(rng, request, [n.erase()]).map_err(drop)?,
    };
    let mut buffer = [0; MESSAGE_MAX];
    let result = match long::Reply::read(reply.bytes(&mut buffer)) {
        Ok(long::Reply::Ready(bytes)) if bytes.len() == out.len() => {
            out.copy_from_slice(bytes);
            Ok((long::READY, 0))
        }
        Ok(long::Reply::Wait(key)) => Ok((long::WAIT, key)),
        Ok(long::Reply::Armed) => Ok((long::ARMED, 0)),
        _ => Err(()),
    };
    // The device's bytes leave no copy behind: the reply in the stack's
    // buffer, and the part past the inline words in the feeder's message
    // buffer.
    posix_random::erase(&mut buffer);
    // SAFETY: the feeder's message buffer is mapped read and write at
    // FEEDER_BUFFER for the thread's life, and nothing else uses it.
    let data = unsafe { core::slice::from_raw_parts_mut(FEEDER_BUFFER as *mut u8, MESSAGE_MAX) };
    posix_random::erase(data);
    result
}
