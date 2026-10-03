// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The role `S`: a quiet driver of the console under the name `uart`,
//! for the measure of the terminal service's steps (xtask tty, under
//! -icount). On QEMU the PL011 sends at once, so the driver's interrupts
//! at 60 would run inside every step of the service that writes; this
//! driver has no interrupt. What the service waits for in its call, it
//! does as the PL011's driver does: WRITE_SOME puts the bytes into the
//! driver's ring (uart::writes, uart::output) and the first pass of the
//! transmission takes TX_PASS bytes from it; then the port has sent the
//! rest (Output::discard_clients). It speaks the methods of
//! proto_uart the service sends:
//!
//! - READ_START, READ_TAKE, READ_CANCEL: the bytes FEED gave, as the
//!   PL011's driver gives its input; one read waits at most;
//! - WRITE_SOME: PART bytes at most, none while HOLD holds; the bytes taken
//!   are counted;
//! - ROOM: armed while HOLD holds, room otherwise; the handle of the first
//!   ROOM stays;
//! - FEED (16): bytes of input, after the header;
//! - HOLD (17): a u32, 1 to hold the output, 0 to let it go, which tells
//!   an armed ROOM;
//! - TAKEN (18): status 0 and the count u64 of the bytes WRITE_SOME took.

use crate::FAILED;
use abi::Error;
use proto_init::ServiceArgs;
use proto_uart::{Method, ReadKey, ReadRequest, RoomReply, VERSION, WriteReply, WriteRequest};
use proto_wire::{Status, long};
use rt::handle::{Channel, Outgoing};
use rt::service::{Answer, Config, Heartbeat, Request, Service, Session};
use rt::startup::Startup;
use rt::{Handle, sys};
use uart::irq::TX_PASS;
use uart::output::Output;
use uart::writes::Writes;

/// The driver's rings, in `.bss`: too big for the stub's stack.
struct Rings {
    output: Output,
    writes: Writes<()>,
}
struct Bss(core::cell::UnsafeCell<Rings>);
// SAFETY: only the stub's one thread reaches it, once (`run`).
unsafe impl Sync for Bss {}
static RINGS: Bss = Bss(core::cell::UnsafeCell::new(Rings {
    output: Output::new(),
    writes: Writes::new(),
}));

pub const FEED: u16 = 16;
pub const HOLD: u16 = 17;
pub const TAKEN: u16 = 18;
/// The most bytes one WRITE_SOME takes.
pub const PART: usize = 300;
/// The bytes of input it keeps.
const INPUT: usize = 512;

struct Stub {
    input: [u8; INPUT],
    len: usize,
    /// The read that waits: its key, its handle, whether it was told, and
    /// the most bytes it takes.
    reader: Option<(u64, Option<Handle<Channel>>, bool, usize)>,
    next_key: u64,
    hold: bool,
    room: Option<Handle<Channel>>,
    armed: bool,
    taken: u64,
    rings: &'static mut Rings,
}

impl Stub {
    /// Up to `max` bytes of input, out of the ring.
    fn take(&mut self, max: usize, out: &mut [u8]) -> usize {
        let n = self.len.min(max).min(out.len());
        out[..n].copy_from_slice(&self.input[..n]);
        self.input.copy_within(n..self.len, 0);
        self.len -= n;
        n
    }

    fn tell_reader(&mut self) {
        if self.len == 0 {
            return;
        }
        if let Some((_, Some(notify), told, _)) = self.reader.as_mut()
            && !*told
        {
            *told = true;
            let _ = sys::notify(notify, 1);
        }
    }

    fn read(&mut self, r: &mut Request<'_>, method: Method) -> Answer {
        let mut out = [0; INPUT];
        let reply = match method {
            Method::ReadStart => {
                let Ok(request) = ReadRequest::read(r.body()) else {
                    return Answer::Status(Status::BadSize);
                };
                if self.reader.is_some() {
                    return Answer::Status(Status::Kernel(Error::BadState));
                }
                if self.len > 0 {
                    let n = self.take(request.max as usize, &mut out);
                    return long_answer(r, long::Reply::Ready(&out[..n]));
                }
                self.next_key += 1;
                self.reader = Some((self.next_key, None, false, request.max as usize));
                long::Reply::Wait(self.next_key)
            }
            _ => {
                let Ok(key) = ReadKey::read(r.body()) else {
                    return Answer::Status(Status::BadSize);
                };
                if self.reader.as_ref().is_none_or(|(k, ..)| *k != key.key) {
                    return Answer::Status(Status::Kernel(Error::BadState));
                }
                if self.len > 0 {
                    let max = self.reader.take().map_or(0, |(.., max)| max);
                    let n = self.take(max, &mut out);
                    return long_answer(r, long::Reply::Ready(&out[..n]));
                }
                if method == Method::ReadCancel {
                    self.reader = None;
                    long::Reply::Cancelled
                } else {
                    if !r.handles.is_empty()
                        && let Ok(handle) = r.handles.take::<Channel>(0)
                        && let Some((_, notify, told, _)) = self.reader.as_mut()
                    {
                        *notify = Some(handle);
                        *told = false;
                    }
                    long::Reply::Armed
                }
            }
        };
        long_answer(r, reply)
    }
}

fn long_answer(r: &mut Request<'_>, reply: long::Reply<'_>) -> Answer {
    match reply.write(r.reply()) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}

const METHODS: &[u16] = &[7, 8, 9, 11, 12, FEED, HOLD, TAKEN];

impl Service<0> for Stub {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 0>, r: &mut Request<'_>) -> Answer {
        match r.method() {
            FEED => {
                let bytes = r.body();
                let n = bytes.left().min(INPUT - self.len);
                let Ok(fed) = r.body().bytes(n) else {
                    return Answer::Status(Status::BadSize);
                };
                self.input[self.len..self.len + n].copy_from_slice(fed);
                self.len += n;
                self.tell_reader();
                Answer::Status(Status::Ok)
            }
            HOLD => {
                let Ok(hold) = r.body().u32() else {
                    return Answer::Status(Status::BadSize);
                };
                self.hold = hold != 0;
                if !self.hold
                    && core::mem::take(&mut self.armed)
                    && let Some(room) = &self.room
                {
                    let _ = sys::notify(room, 1);
                }
                Answer::Status(Status::Ok)
            }
            TAKEN => {
                let w = r.reply();
                if w.u32(0).is_err() || w.u64(self.taken).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply(Outgoing::new())
            }
            n => match Method::from_number(n) {
                Some(m @ (Method::ReadStart | Method::ReadTake | Method::ReadCancel)) => {
                    self.read(r, m)
                }
                Some(Method::WriteSome) => {
                    let Ok(request) = WriteRequest::read(r.body()) else {
                        return Answer::Status(Status::BadSize);
                    };
                    let part = &request.bytes[..request.bytes.len().min(PART)];
                    let Rings { output, writes } = &mut *self.rings;
                    let n = if self.hold {
                        0
                    } else {
                        writes.write_some(output, part)
                    };
                    for _ in 0..TX_PASS {
                        if output.next_byte().is_none() {
                            break;
                        }
                    }
                    output.discard_clients();
                    self.taken += n as u64;
                    match (WriteReply { written: n as u32 }).write(r.reply()) {
                        Ok(()) => Answer::Reply(Outgoing::new()),
                        Err(status) => Answer::Status(status),
                    }
                }
                Some(Method::Room) => {
                    if !r.handles.is_empty()
                        && self.room.is_none()
                        && let Ok(handle) = r.handles.take::<Channel>(0)
                    {
                        self.room = Some(handle);
                    }
                    self.armed = self.hold;
                    let reply = RoomReply {
                        room: if self.hold { 0 } else { 4096 },
                        armed: self.hold,
                    };
                    match reply.write(r.reply()) {
                        Ok(()) => Answer::Reply(Outgoing::new()),
                        Err(status) => Answer::Status(status),
                    }
                }
                _ => Answer::Status(Status::UnknownMethod),
            },
        }
    }
}

pub fn run(s: Startup) -> u64 {
    let args = ServiceArgs::read(s.args()).ok();
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return FAILED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return FAILED;
    }
    let mut stub = Stub {
        input: [0; INPUT],
        len: 0,
        reader: None,
        next_key: 0,
        hold: false,
        room: None,
        armed: false,
        taken: 0,
        // SAFETY: only this thread reaches RINGS, here once.
        rings: unsafe { &mut *RINGS.0.get() },
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &s.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    let _ = rt::service::run::<Stub, 4, 0>(&channel, &mut stub, config);
    FAILED
}
