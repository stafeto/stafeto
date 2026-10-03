// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The role `long` (main.rs): a service of long operations in two steps
//! (proto_wire::long, rt::service::LongOps) for rtbench 2 and the probes.
//! It speaks the protocol of the console's driver (proto_uart) under the
//! name `uart`, so that `read` of standard input in a POSIX process reaches
//! it:
//!
//! - READ_START of 16 bytes or more: the data is ready 1 ms later; the
//!   service reads the counter (`CNTVCT_EL0`) then and the result is its
//!   value as 16 hexadecimal digits (rtbench S6);
//! - READ_START of fewer bytes: the data is ready when FEED gives a byte
//!   (rtbench S5, the probes); a byte fed with no such read waiting makes
//!   the next READ_START answer READY at once;
//! - READ_TAKE, READ_CANCEL: as proto_uart says;
//! - WRITE: the bytes are dropped and all count as written (the echo);
//! - PING: the status alone (rtbench S9);
//! - STATS: the operations that wait and the handles they hold;
//! - FEED: one byte, after the header, for the reads that wait for one;
//! - HOLD with a u32 of milliseconds and a u32 mode: after its next WAIT
//!   reply (mode 0) or FEED (mode 1) the service waits that long on a
//!   channel of its own, out of `receive` on its service channel, so that
//!   a request sent meanwhile stands in the queue, where an interrupt can
//!   take it back; with mode 2 it waits inside the next READ_START, before
//!   its reply, so that its client waits for that reply;
//! - STORM with a thread handle (MANAGE): the service keeps the thread and
//!   replies with a labelled copy of its channel with NOTIFY and TRANSFER,
//!   which the client hands to the clock service (WATCH); then the clock
//!   tells of each SET before its reply, the service, above the clock,
//!   runs at once and makes an entry request (thread_upcall_request) of the
//!   thread at every other notification, counting those that found it
//!   waiting for its reply. STORM with no handle lets the thread go and
//!   replies with the requests made and those counted.
//!
//! LongOps keeps 16 operations of a session and 24 in all; the state is
//! static, off the service's 16 KiB stack.

use crate::{FAILED, LONG_SESSIONS, base, serve_with};
use abi::{Error, Rights};
use proto_uart::{Method, ReadKey, ReadRequest, VERSION, WriteReply};
use proto_wire::{HEADER_LEN, Status, long};
use rt::handle::{Channel, Outgoing, Thread, Timer};
use rt::service::{Answer, LongOps, LongSession, Notice, Request, Service, Session};
use rt::startup::Startup;
use rt::{Handle, sys, time};

/// Methods of this service alone, past those of the driver.
pub const PING: u16 = 16;
pub const STATS: u16 = 17;
pub const FEED: u16 = 18;
pub const STORM: u16 = 19;
pub const HOLD: u16 = 20;
/// The delay from a timed read to the readiness of its data.
const DELAY_NS: u64 = 1_000_000;
/// The fewest bytes of a timed read.
const TIMED: u32 = 16;
/// The label of the service's own timer, apart from the heartbeat's 0.
const TIMER_LABEL: u64 = 1;
/// The label of the copy of the channel STORM gives.
const STORM_LABEL: u64 = 2;
/// The label of the copy of the channel the service tells itself to hold
/// with.
const HOLD_LABEL: u64 = 3;
const OPS: usize = 24;

pub fn run(s: Startup) -> u64 {
    let level = base(&s);
    let Ok(channel) = sys::channel_create(level) else {
        return FAILED;
    };
    // The timer posts through a labelled copy of the channel: its
    // notifications come to `notification`, the heartbeat keeps label 0.
    let Ok(labelled) = sys::handle_label(&channel, Rights::RECEIVE, TIMER_LABEL, level) else {
        return FAILED;
    };
    let Ok(timer) = sys::timer_create(&labelled, level) else {
        return FAILED;
    };
    let Ok(hold) = sys::handle_label(&channel, Rights::NOTIFY, HOLD_LABEL, level) else {
        return FAILED;
    };
    let Ok(pause) = sys::channel_create(level) else {
        return FAILED;
    };
    let Ok(pause_timer) = sys::timer_create(&pause, level) else {
        return FAILED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return FAILED;
    }
    // SAFETY: the service's one thread takes the state once.
    let long = unsafe { &mut *STATE.0.get() };
    long.write(Long {
        channel: channel.raw(),
        level,
        storm: None,
        hold_ms: 0,
        hold_mode: 0,
        hold,
        pause,
        pause_timer,
        seen: 0,
        given: 0,
        requested: 0,
        awaiting: 0,
        timer,
        _labelled: labelled,
        ops: LongOps::new(),
        data: [const { None }; OPS],
        fed: None,
    });
    // SAFETY: written just above.
    serve_with::<_, LONG_SESSIONS>(&s, &channel, unsafe { long.assume_init_mut() })
}

struct State(core::cell::UnsafeCell<core::mem::MaybeUninit<Long>>);
// SAFETY: only the service's one thread reaches it, once.
unsafe impl Sync for State {}
static STATE: State = State(core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()));

/// What an operation waits for and what it has.
struct Op {
    label: u64,
    key: u64,
    /// The deadline of a timed read, or none for one that waits for FEED.
    due: Option<u64>,
    /// The result once ready.
    result: Option<([u8; 16], usize)>,
}

struct Long {
    /// The service's channel, which `run` holds.
    channel: abi::Handle,
    /// The service's level, that of its channel.
    level: u8,
    /// The thread of STORM, and its counts: notifications, entry requests
    /// made, and those that found the thread waiting for its reply.
    storm: Option<Handle<Thread>>,
    /// HOLD: the milliseconds to wait after the next WAIT, 0 for none; the
    /// copy of the channel that tells the service so, and its own channel
    /// and timer to wait on.
    hold_ms: u32,
    hold_mode: u32,
    hold: Handle<Channel>,
    pause: Handle<Channel>,
    pause_timer: Handle<Timer>,
    seen: u64,
    /// The sessions CLONE gave (the labels 1 << 63 | n).
    given: u64,
    requested: u32,
    awaiting: u32,
    timer: Handle<Timer>,
    _labelled: Handle<Channel>,
    ops: LongOps<OPS>,
    data: [Option<Op>; OPS],
    fed: Option<u8>,
}

impl Long {
    /// CLONE as the console's driver does it: a session of a label of the
    /// service's own (bit 63) for a child of the client.
    fn clone_session(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        self.given += 1;
        let label = 1 << 63 | self.given;
        let channel = Handle::<Channel>::borrowed(self.channel);
        match sys::handle_label(&channel, Rights::SEND | Rights::TRANSFER, label, self.level) {
            Ok(session) => {
                if r.reply().u32(0).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply([session.erase()].into())
            }
            Err(e) => Answer::Status(Status::Kernel(e)),
        }
    }

    fn op(&mut self, label: u64, key: u64) -> Option<usize> {
        self.data
            .iter()
            .position(|o| o.as_ref().is_some_and(|o| o.label == label && o.key == key))
    }

    fn arm_timer(&self) {
        if let Some(due) = self
            .data
            .iter()
            .flatten()
            .filter_map(|o| o.result.is_none().then_some(o.due).flatten())
            .min()
        {
            let _ = sys::timer_set(&self.timer, due);
        }
    }

    fn start(&mut self, session: &mut LongSession, r: &mut Request<'_>) -> Answer {
        let request = match ReadRequest::read(r.body()) {
            Ok(request) => request,
            Err(status) => return Answer::Status(status),
        };
        if self.hold_ms != 0 && self.hold_mode == 2 {
            self.pause();
        }
        let timed = request.max >= TIMED;
        if !timed && let Some(byte) = self.fed.take() {
            return reply(r, long::Reply::Ready(&[byte]));
        }
        let key = match self.ops.start(session, r.label()) {
            Ok(key) => key,
            Err(error) => return Answer::Status(Status::Kernel(error)),
        };
        let place = self
            .data
            .iter()
            .position(Option::is_none)
            .expect("a place for each op");
        self.data[place] = Some(Op {
            label: r.label(),
            key,
            due: timed.then(|| time::ticks_to_ns(time::now()) + DELAY_NS),
            result: None,
        });
        self.arm_timer();
        if self.hold_ms != 0 && self.hold_mode == 0 {
            let _ = sys::notify(&self.hold, 1);
        }
        reply(r, long::Reply::Wait(key))
    }

    fn take(&mut self, session: &mut LongSession, r: &mut Request<'_>, cancel: bool) -> Answer {
        let key = match ReadKey::read(r.body()) {
            Ok(key) => key.key,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        let Some(place) = self.op(label, key) else {
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        if let Some((bytes, len)) = self.data[place].as_ref().and_then(|o| o.result) {
            self.data[place] = None;
            self.ops.finish(session, label, key);
            return reply(r, long::Reply::Ready(&bytes[..len]));
        }
        if cancel {
            self.data[place] = None;
            self.ops.finish(session, label, key);
            return reply(r, long::Reply::Cancelled);
        }
        if !r.handles.is_empty() {
            match r.handles.take::<Channel>(0) {
                Ok(notify) => {
                    if let Err(error) = self.ops.arm(label, key, notify) {
                        return Answer::Status(Status::Kernel(error));
                    }
                }
                Err(error) => return Answer::Status(Status::Kernel(error)),
            }
        }
        reply(r, long::Reply::Armed)
    }

    fn storm(&mut self, r: &mut Request<'_>) -> Answer {
        if r.handles.is_empty() {
            self.storm = None;
            let w = r.reply();
            return match w
                .u32(Status::Ok.code())
                .and_then(|()| w.u32(self.requested))
                .and_then(|()| w.u32(self.awaiting))
            {
                Ok(()) => Answer::Reply(Outgoing::new()),
                Err(status) => Answer::Status(status),
            };
        }
        let thread = match r.handles.take::<Thread>(0) {
            Ok(thread) => thread,
            Err(error) => return Answer::Status(Status::Kernel(error)),
        };
        let channel = Handle::<Channel>::borrowed(self.channel);
        let rights = Rights::NOTIFY | Rights::TRANSFER;
        let copy = match sys::handle_label(
            &channel,
            rights | Rights::DUPLICATE,
            STORM_LABEL,
            self.level,
        ) {
            Ok(copy) => copy,
            Err(error) => return Answer::Status(Status::Kernel(error)),
        };
        (self.storm, self.seen, self.requested, self.awaiting) = (Some(thread), 0, 0, 0);
        match r.reply().u32(Status::Ok.code()) {
            Ok(()) => Answer::Reply([copy.erase()].into()),
            Err(status) => Answer::Status(status),
        }
    }

    /// HOLD: waits `hold_ms` on the service's own channel, then forgets it.
    fn pause(&mut self) {
        let due = time::ticks_to_ns(time::now()) + u64::from(self.hold_ms) * 1_000_000;
        self.hold_ms = 0;
        self.hold_mode = 0;
        if sys::timer_set(&self.pause_timer, due).is_ok() {
            let _ = sys::receive(&self.pause);
        }
    }

    /// A result is ready for the operation in `place`: its client is told.
    fn ready(&mut self, place: usize, bytes: [u8; 16], len: usize) {
        let op = self.data[place].as_mut().expect("a waiting op");
        op.result = Some((bytes, len));
        let (label, key) = (op.label, op.key);
        self.ops.tell(label, key);
    }
}

fn reply(r: &mut Request<'_>, reply: long::Reply<'_>) -> Answer {
    match reply.write(r.reply()) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}

impl Service<1> for Long {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = &[
        Method::Write.number(),
        Method::ReadStart.number(),
        Method::ReadTake.number(),
        Method::ReadCancel.number(),
        Method::Clone.number(),
        PING,
        STATS,
        FEED,
        STORM,
        HOLD,
    ];
    type Data = LongSession;

    fn request(&mut self, s: &mut Session<LongSession, 1>, r: &mut Request<'_>) -> Answer {
        match r.method() {
            n if n == Method::ReadStart.number() => self.start(&mut s.data, r),
            n if n == Method::ReadTake.number() => self.take(&mut s.data, r, false),
            n if n == Method::ReadCancel.number() => self.take(&mut s.data, r, true),
            n if n == Method::Clone.number() => self.clone_session(r),
            n if n == Method::Write.number() => {
                let written = (r.bytes().len() - HEADER_LEN) as u32;
                match (WriteReply { written }).write(r.reply()) {
                    Ok(()) => Answer::Reply(Outgoing::new()),
                    Err(status) => Answer::Status(status),
                }
            }
            STATS => {
                let (live, held) = self.ops.counts();
                let w = r.reply();
                match w
                    .u32(Status::Ok.code())
                    .and_then(|()| w.u32(live as u32))
                    .and_then(|()| w.u32(held as u32))
                {
                    Ok(()) => Answer::Reply(Outgoing::new()),
                    Err(status) => Answer::Status(status),
                }
            }
            FEED => {
                let Some(&byte) = r.bytes().get(HEADER_LEN) else {
                    return Answer::Status(Status::BadSize);
                };
                let waiting: Option<usize> = self.data.iter().position(|o| {
                    o.as_ref().is_some_and(|o| {
                        o.label == r.label() && o.due.is_none() && o.result.is_none()
                    })
                });
                match waiting {
                    Some(place) => {
                        let mut bytes = [0; 16];
                        bytes[0] = byte;
                        self.ready(place, bytes, 1);
                    }
                    None => self.fed = Some(byte),
                }
                if self.hold_ms != 0 && self.hold_mode == 1 {
                    let _ = sys::notify(&self.hold, 1);
                }
                Answer::Status(Status::Ok)
            }
            STORM => self.storm(r),
            HOLD => {
                let mut body = r.body();
                let Ok(ms) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                self.hold_ms = ms;
                self.hold_mode = body.u32().unwrap_or(0);
                Answer::Status(Status::Ok)
            }
            _ => Answer::Status(Status::Ok),
        }
    }

    fn gone(&mut self, s: &mut Session<LongSession, 1>) {
        let label = s.label();
        self.ops.gone(&mut s.data);
        for op in &mut self.data {
            if op.as_ref().is_some_and(|o| o.label == label) {
                *op = None;
            }
        }
    }

    fn notification(&mut self, n: Notice) {
        if n.label == HOLD_LABEL && self.hold_ms != 0 && self.hold_mode != 2 {
            self.pause();
            return;
        }

        if n.label == STORM_LABEL {
            self.seen += 1;
            if let Some(thread) = &self.storm
                && self.seen % 2 == 1
            {
                let awaiting = sys::thread_info(thread)
                    .is_ok_and(|i| i.state == abi::ThreadState::AwaitingReply);
                if sys::thread_upcall_request(thread).is_ok() {
                    self.requested += 1;
                    self.awaiting += u32::from(awaiting);
                }
            }
            return;
        }
        if n.label != TIMER_LABEL {
            return;
        }
        let now = time::ticks_to_ns(time::now());
        for place in 0..OPS {
            let due = self.data[place]
                .as_ref()
                .is_some_and(|o| o.result.is_none() && o.due.is_some_and(|d| d <= now));
            if !due {
                continue;
            }
            let stamp = time::now();
            let mut digits = [0; 16];
            for (index, digit) in digits.iter_mut().enumerate() {
                let nibble = (stamp >> (60 - 4 * index)) & 0xF;
                *digit = b"0123456789abcdef"[nibble as usize];
            }
            self.ready(place, digits, 16);
        }
        self.arm_timer();
    }
}
