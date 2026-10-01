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
//! - FEED: one byte, after the header, for the reads that wait for one.
//!
//! LongOps keeps 16 operations of a session and 24 in all; the state is
//! static, off the service's 16 KiB stack.

use crate::{FAILED, base, serve};
use abi::{Error, Rights};
use proto_uart::{Method, ReadKey, ReadRequest, VERSION, WriteReply};
use proto_wire::{HEADER_LEN, Status, long};
use rt::handle::{Channel, Outgoing, Timer};
use rt::service::{Answer, LongOps, Notice, Request, Service, Session};
use rt::startup::Startup;
use rt::{Handle, sys, time};

/// Methods of this service alone, past those of the driver.
pub const PING: u16 = 16;
pub const STATS: u16 = 17;
pub const FEED: u16 = 18;
/// The delay from a timed read to the readiness of its data.
const DELAY_NS: u64 = 1_000_000;
/// The fewest bytes of a timed read.
const TIMED: u32 = 16;
/// The label of the service's own timer, apart from the heartbeat's 0.
const TIMER_LABEL: u64 = 1;
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
    if rt::service::register(&s.parent, &channel).is_err() {
        return FAILED;
    }
    // SAFETY: the service's one thread takes the state once.
    let long = unsafe { &mut *STATE.0.get() };
    long.write(Long {
        timer,
        _labelled: labelled,
        ops: LongOps::new(),
        data: [const { None }; OPS],
        fed: None,
    });
    // SAFETY: written just above.
    serve(&s, &channel, unsafe { long.assume_init_mut() })
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
    timer: Handle<Timer>,
    _labelled: Handle<Channel>,
    ops: LongOps<OPS>,
    data: [Option<Op>; OPS],
    fed: Option<u8>,
}

impl Long {
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

    fn start(&mut self, r: &mut Request<'_>) -> Answer {
        let request = match ReadRequest::read(r.body()) {
            Ok(request) => request,
            Err(status) => return Answer::Status(status),
        };
        let timed = request.max >= TIMED;
        if !timed && let Some(byte) = self.fed.take() {
            return reply(r, long::Reply::Ready(&[byte]));
        }
        let key = match self.ops.start(r.label()) {
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
        reply(r, long::Reply::Wait(key))
    }

    fn take(&mut self, r: &mut Request<'_>, cancel: bool) -> Answer {
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
            self.ops.finish(label, key);
            return reply(r, long::Reply::Ready(&bytes[..len]));
        }
        if cancel {
            self.data[place] = None;
            self.ops.finish(label, key);
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
        PING,
        STATS,
        FEED,
    ];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, r: &mut Request<'_>) -> Answer {
        match r.method() {
            n if n == Method::ReadStart.number() => self.start(r),
            n if n == Method::ReadTake.number() => self.take(r, false),
            n if n == Method::ReadCancel.number() => self.take(r, true),
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
                Answer::Status(Status::Ok)
            }
            _ => Answer::Status(Status::Ok),
        }
    }

    fn gone(&mut self, s: &mut Session<(), 1>) {
        let label = s.label();
        self.ops.gone(label);
        for op in &mut self.data {
            if op.as_ref().is_some_and(|o| o.label == label) {
                *op = None;
            }
        }
    }

    fn notification(&mut self, n: Notice) {
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
