// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The role `long` (main.rs): a service of long operations for rtbench 2,
//! which speaks version 1 of the protocol of the console's driver
//! (proto_uart) under the name `uart`, so that `read` of standard input in
//! a POSIX process reaches it. It answers a read with a deferred reply, as the
//! driver does for input that has not come:
//!
//! - READ_CANCELABLE of 16 bytes or more: 1 ms after the request the data
//!   is ready; the service reads the counter (`CNTVCT_EL0`) at that moment
//!   and replies with its value as 16 hexadecimal digits, so that the
//!   reader measures from the readiness of the data to the return of its
//!   `read` (scenario S6);
//! - READ_CANCELABLE of fewer bytes: no data ever, the read waits until
//!   CANCEL_READ (the reader waiting for input of scenario S5);
//! - CANCEL_READ: the matching read gets INTERRUPTED, as from the driver;
//! - WRITE: the bytes are dropped and all count as written (the echo of
//!   the client's input);
//! - PING: the status alone, the empty round trip through rt::service
//!   (scenario S9).
//!
//! One read waits at a time; a second gets BAD_STATE.

use crate::{FAILED, base, serve};
use abi::{Error, Rights};
use proto_uart::{CancelRead, CancelableRead, Method, ReadReply, VERSION, WriteReply};
use proto_wire::{HEADER_LEN, Status, Writer};
use rt::handle::{Channel, Outgoing, Timer};
use rt::service::{Answer, Notice, Pending, Request, Service, Session};
use rt::startup::Startup;
use rt::{Handle, sys, time};

/// PING: a method of this service alone, past those of the driver.
pub const PING: u16 = 7;
/// The delay from a timed read to the readiness of its data.
const DELAY_NS: u64 = 1_000_000;
/// The fewest bytes of a read that gets data.
const TIMED: u32 = 16;
/// The label of the service's own timer, apart from the heartbeat's 0.
const TIMER_LABEL: u64 = 1;

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
    let mut long = Long {
        timer,
        _labelled: labelled,
        reader: None,
    };
    serve(&s, &channel, &mut long)
}

/// The read that waits: its client, its id, its reply and whether data
/// comes to it.
struct Reader {
    label: u64,
    id: u64,
    pending: Pending,
    timed: bool,
}

struct Long {
    timer: Handle<Timer>,
    _labelled: Handle<Channel>,
    reader: Option<Reader>,
}

impl Long {
    fn read(&mut self, r: &mut Request<'_>) -> Answer {
        let request = match CancelableRead::read(r.body()) {
            Ok(request) => request,
            Err(status) => return Answer::Status(status),
        };
        if self.reader.is_some() {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let label = r.label();
        let Some(pending) = r.defer() else {
            return Answer::Deferred;
        };
        let timed = request.max >= TIMED;
        if timed {
            let deadline = time::ticks_to_ns(time::now()) + DELAY_NS;
            if sys::timer_set(&self.timer, deadline).is_err() {
                refuse(pending, Error::BadState);
                return Answer::Deferred;
            }
        }
        self.reader = Some(Reader {
            label,
            id: request.id,
            pending,
            timed,
        });
        Answer::Deferred
    }

    fn cancel(&mut self, r: &Request<'_>) -> Answer {
        let cancel = match CancelRead::read(r.body()) {
            Ok(cancel) => cancel,
            Err(status) => return Answer::Status(status),
        };
        if self
            .reader
            .as_ref()
            .is_some_and(|w| w.label == r.label() && w.id == cancel.id)
        {
            let reader = self.reader.take().expect("matching reader");
            let _ = sys::timer_cancel(&self.timer);
            refuse(reader.pending, Error::Interrupted);
        }
        Answer::Status(Status::Ok)
    }
}

impl Service<1> for Long {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = &[
        Method::Write.number(),
        Method::ReadCancelable.number(),
        Method::CancelRead.number(),
        PING,
    ];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, r: &mut Request<'_>) -> Answer {
        match r.method() {
            n if n == Method::ReadCancelable.number() => self.read(r),
            n if n == Method::CancelRead.number() => self.cancel(r),
            n if n == Method::Write.number() => {
                let written = (r.bytes().len() - HEADER_LEN) as u32;
                match (WriteReply { written }).write(r.reply()) {
                    Ok(()) => Answer::Reply(Outgoing::new()),
                    Err(status) => Answer::Status(status),
                }
            }
            _ => Answer::Status(Status::Ok),
        }
    }

    fn gone(&mut self, s: &mut Session<(), 1>) {
        if self.reader.as_ref().is_some_and(|w| w.label == s.label()) {
            self.reader = None;
            let _ = sys::timer_cancel(&self.timer);
        }
    }

    fn notification(&mut self, n: Notice) {
        if n.label != TIMER_LABEL || !self.reader.as_ref().is_some_and(|w| w.timed) {
            return;
        }
        let reader = self.reader.take().expect("timed reader");
        let stamp = time::now();
        let mut digits = [0; 16];
        for (index, digit) in digits.iter_mut().enumerate() {
            let nibble = (stamp >> (60 - 4 * index)) & 0xF;
            *digit = b"0123456789abcdef"[nibble as usize];
        }
        let mut w = Writer::new();
        // Sixteen bytes after eight fit a reply.
        let _ = ReadReply { bytes: &digits }.write(&mut w);
        let _ = reader.pending.answer(w.as_bytes(), Outgoing::new());
    }
}

/// A reply that is the status of `error` alone.
fn refuse(pending: Pending, error: Error) {
    let _ = pending.answer(&proto_wire::reply(Status::Kernel(error)), Outgoing::new());
}
