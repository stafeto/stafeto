// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The role `silent` (main.rs): a service that registers, connects to
//! `sink` and greets it with HELLO, leaves a CONNECT to `hog` waiting in
//! init from a thread of its own, and answers ECHO. On HANG it raises
//! its own thread to the ceiling of byte 1 of its own arguments (32) and
//! spins in the handler: its heartbeat stops, and only a thread above its
//! ceiling can kill it, so the watchdog restarts it
//! (`silent_service_is_restarted_by_the_watchdog`).

use crate::{FAILED, VERSION, base, method, serve};
use abi::{Policy, START_CHANNEL};
use proto_init::ServiceArgs;
use proto_wire::{HEADER_LEN, Header, Status, Writer};
use rt::handle::{Channel, Outgoing, Thread};
use rt::service::{Answer, Request, Service, Session};
use rt::startup::Startup;
use rt::{Handle, Stack, sys};

/// The stack of the thread whose CONNECT to `hog` waits in init for good.
static WAIT_STACK: Stack<4096> = Stack::new();

pub fn run(s: Startup) -> u64 {
    let Ok(args) = ServiceArgs::read(s.args()) else {
        return FAILED;
    };
    let level = args.own.get(1).copied().unwrap_or(1);
    let Ok(channel) = sys::channel_create(base(&s)) else {
        return FAILED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return FAILED;
    }
    let Ok(sink) = rt::service::connect(&s.parent, "sink") else {
        return FAILED;
    };
    let mut w = Writer::new();
    let _ = Header::new(method::HELLO, VERSION).write(&mut w);
    if sys::send(&sink, w.as_bytes()).is_err() {
        return FAILED;
    }
    // A CONNECT that waits in init as long as silent lives: hog never
    // starts (a_client_that_goes_leaves_its_waiting_connect).
    let buffer = abi::INIT_MSGBUF as usize + 4096;
    // SAFETY: WAIT_STACK is the thread's alone.
    let t = unsafe {
        sys::thread_create(
            &s.process,
            wait_for_hog,
            WAIT_STACK.top(),
            0,
            base(&s),
            Policy::Fifo,
            buffer,
        )
    };
    match t.map(|t| (sys::thread_start(&t), t)) {
        Ok((Ok(()), t)) => drop(t),
        _ => return FAILED,
    }
    let mut silent = Silent {
        thread: &s.thread,
        level,
        _sink: sink,
    };
    serve(&s, &channel, &mut silent)
}

/// CONNECT to `hog`, which waits until silent goes.
extern "C" fn wait_for_hog(_: u64) -> ! {
    let parent = Handle::<Channel>::borrowed(START_CHANNEL);
    let _ = rt::service::connect(&parent, "hog");
    sys::thread_exit()
}

/// The silent service: its own thread, the level it hangs at, and the
/// session with `sink` it holds until it is killed.
struct Silent<'a> {
    thread: &'a Handle<Thread>,
    level: u8,
    _sink: Handle<Channel>,
}

impl Service<1> for Silent<'_> {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = &[method::ECHO, method::HANG];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, r: &mut Request<'_>) -> Answer {
        if r.method() == method::HANG {
            let _ = sys::thread_set_priority(self.thread, self.level, Policy::Fifo);
            loop {
                core::hint::spin_loop();
            }
        }
        let body = &r.bytes()[HEADER_LEN..];
        let w = r.reply();
        match w.u32(Status::Ok.code()).and_then(|()| w.bytes(body)) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }
}
