// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The window manager of stafeto: a client of init's table that asks the
//! compositor (the service `gpu`) for the manager's session, which init
//! gives to the clients `table::COMP_MANAGERS` names. It subscribes, and
//! then answers the events of its ring: a new window gets the focus and the
//! top place (FOCUS), and the chords of the keys switch the windows (LIST,
//! then FOCUS). What it decides is in the library (`wm`): the policy and its
//! chords are described there. The compositor does the clicks itself.
//!
//! Every call is a request that the compositor answers in one step: LIST
//! carries at most MAX_WINDOWS records, and the ring is read 32 events at a
//! time. The manager waits on its own channel, which the compositor notifies
//! with EVENTS_BIT when the ring has something, for a period at most: that
//! channel never closes when the compositor ends (the manager holds its
//! receiving side), so a quiet period ends with DESCRIBE, and a compositor
//! that is gone refuses it. It ends with code 0 on the
//! chord that ends it, and with a code of its own when the compositor is
//! gone or a call fails otherwise (the compositor treats the end of its
//! session as the manager's death and goes on by its own rules: the window
//! that has the focus keeps it, the first window shown takes it again, a
//! click moves it).

#![no_std]
#![no_main]

use abi::{Error, MESSAGE_MAX, Rights};
use proto_comp::{
    Description, Event, MAX_EVENTS, Method, WindowRecord, manage, read_events, read_list,
    write_manage,
};
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Resource};
use rt::sys;
use rt::wait::{Waited, Waiter};
use rt::{Handle, time};
use wm::{Chords, Command, next_focus};

rt::entry!(main);

/// The windows the compositor has at most (services/compositor MAX_WINDOWS).
const MAX_WINDOWS: usize = 8;
/// The pause between two tries of the compositor's screen, and how long the
/// manager waits for it.
const RETRY_NS: u64 = 20_000_000;
/// How long the manager waits for events before it asks the compositor
/// whether it is there.
const PERIOD_NS: u64 = 1_000_000_000;
const WAIT_NS: u64 = 60_000_000_000;
/// The codes of the manager's end: no start data, no channel, no session
/// with the compositor, a call that failed, the compositor gone.
const NO_START_DATA: u64 = 1;
const NO_CHANNEL: u64 = 2;
const NO_COMPOSITOR: u64 = 3;
const FAILED: u64 = 4;
const COMPOSITOR_GONE: u64 = 5;

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(level) else {
        return NO_CHANNEL;
    };
    let Ok(display) = rt::service::connect(&start.parent, "gpu") else {
        return NO_COMPOSITOR;
    };
    match run(&display, &channel, level) {
        Ok(()) => {
            rt::println!("wm: ended");
            0
        }
        Err(code) => {
            rt::println!("wm: failed with code {code}");
            code
        }
    }
}

/// The end code of a call that the kernel refused.
fn refused(error: Error) -> u64 {
    if error == Error::PeerClosed {
        COMPOSITOR_GONE
    } else {
        FAILED
    }
}

/// The status of a reply.
fn status_of(bytes: &[u8]) -> Result<Status, u64> {
    let word = bytes.get(..4).ok_or(FAILED)?;
    Ok(Status::from_code(u32::from_le_bytes([
        word[0], word[1], word[2], word[3],
    ])))
}

/// FOCUS of window `id`. The compositor refuses a window that went since
/// the event with INVALID, which is no failure of the manager's; any other
/// refusal is.
fn focus(display: &Handle<Channel>, id: u32) -> Result<(), u64> {
    let mut w = Writer::new();
    write_manage(manage::FOCUS, id, 0, 0, &mut w).map_err(|_| FAILED)?;
    let reply = sys::send(display, w.as_bytes()).map_err(refused)?;
    let mut buffer = [0; MESSAGE_MAX];
    match status_of(reply.bytes(&mut buffer))? {
        Status::Ok => Ok(()),
        status if status == proto_comp::code(proto_comp::INVALID) => Ok(()),
        _ => Err(FAILED),
    }
}

/// LIST, then FOCUS of the window `next_focus` names.
fn cycle(display: &Handle<Channel>, forward: bool) -> Result<(), u64> {
    let mut w = Writer::new();
    write_manage(manage::LIST, 0, 0, 0, &mut w).map_err(|_| FAILED)?;
    let reply = sys::send(display, w.as_bytes()).map_err(refused)?;
    let mut buffer = [0; MESSAGE_MAX];
    let mut windows = [WindowRecord::default(); MAX_WINDOWS];
    let mut n = 0;
    read_list(reply.bytes(&mut buffer), |r| {
        if n < windows.len() {
            windows[n] = r;
            n += 1;
        }
    })
    .map_err(|_| FAILED)?;
    match next_focus(&windows[..n], forward) {
        Some(id) => focus(display, id),
        None => Ok(()),
    }
}

/// EVENTS of the manager's ring, once: each event goes to the chords and
/// what they ask is done. The number of events taken, and whether the
/// manager is to end.
fn take(display: &Handle<Channel>, chords: &mut Chords) -> Result<(usize, bool), u64> {
    let reply = sys::send(display, &Method::Events.header().bytes()).map_err(refused)?;
    let mut buffer = [0; MESSAGE_MAX];
    let mut events = [Event::default(); MAX_EVENTS];
    let mut n = 0;
    let flags = read_events(reply.bytes(&mut buffer), |e| {
        if n < events.len() {
            events[n] = e;
            n += 1;
        }
    })
    .map_err(|_| FAILED)?;
    if flags & proto_comp::LOST != 0 {
        // The keys down are no longer known.
        chords.reset();
    }
    for e in &events[..n] {
        match chords.event(e) {
            Some(Command::Focus(id)) => focus(display, id)?,
            Some(Command::Cycle { forward }) => cycle(display, forward)?,
            Some(Command::Quit) => return Ok((n, true)),
            None => {}
        }
    }
    Ok((n, false))
}

/// Waits until something comes on `channel` (the compositor says by a bit
/// that the ring has events) or the period passes. The channel is the
/// manager's own and never closes when the compositor ends, so a quiet
/// period ends with DESCRIBE, which a compositor that is gone refuses with
/// PEER_CLOSED.
fn wait_for_events(
    display: &Handle<Channel>,
    channel: &Handle<Channel>,
    waiter: &Waiter,
) -> Result<(), u64> {
    let deadline = time::ticks_to_ns(time::now()).saturating_add(PERIOD_NS);
    match waiter.receive_until(channel, deadline) {
        Ok(Waited::Got(_)) => Ok(()),
        Ok(Waited::Expired) => {
            sys::send(display, &Method::Describe.header().bytes()).map_err(refused)?;
            Ok(())
        }
        Err(error) => Err(refused(error)),
    }
}

/// DESCRIBE until the compositor has its screen (it says CLEARING while the
/// display driver is being set up).
fn when_ready(display: &Handle<Channel>, channel: &Handle<Channel>, level: u8) -> Result<(), u64> {
    let waiter = Waiter::new(channel, 0, level).map_err(|_| NO_CHANNEL)?;
    let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
    loop {
        let reply = sys::send(display, &Method::Describe.header().bytes()).map_err(refused)?;
        let mut buffer = [0; MESSAGE_MAX];
        match Description::read(reply.bytes(&mut buffer)) {
            Ok(_) => return Ok(()),
            Err(status) if status == proto_gpu::code(proto_gpu::CLEARING) => {}
            Err(_) => return Err(FAILED),
        }
        let now = time::ticks_to_ns(time::now());
        if now > end {
            return Err(FAILED);
        }
        while let Ok(Waited::Got(_)) = waiter.receive_until(channel, now.saturating_add(RETRY_NS)) {
        }
    }
}

fn run(display: &Handle<Channel>, channel: &Handle<Channel>, level: u8) -> Result<(), u64> {
    when_ready(display, channel, level)?;
    let notify = sys::handle_duplicate(channel, Rights::NOTIFY | Rights::TRANSFER)
        .map_err(|_| NO_CHANNEL)?;
    let mut w = Writer::new();
    write_manage(manage::SUBSCRIBE, 0, 0, 0, &mut w).map_err(|_| FAILED)?;
    let reply = sys::send_handles(display, w.as_bytes(), [notify.erase()])
        .map_err(|refused_call| refused(refused_call.error))?;
    let mut buffer = [0; MESSAGE_MAX];
    if status_of(reply.bytes(&mut buffer))? != Status::Ok {
        return Err(FAILED);
    }
    rt::println!("wm: subscribed");
    let waiter = Waiter::new(channel, 0, level).map_err(|_| NO_CHANNEL)?;
    let mut chords = Chords::new();
    loop {
        // The ring is read dry before each wait: the events that came before
        // the subscription, and those that a full read left.
        loop {
            let (n, quit) = take(display, &mut chords)?;
            if quit {
                return Ok(());
            }
            if n == 0 {
                break;
            }
        }
        wait_for_events(display, channel, &waiter)?;
    }
}
