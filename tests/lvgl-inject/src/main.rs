// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The injector of the LVGL demo's scenario (stage G4, `lvgl-probe`). A native
//! program started with the image, whose `Display` session is the
//! compositor's input session (init gives it the label INPUT_MARK by its
//! name, `table::COMP_INJECTORS`). It waits for the window of the demo (an
//! open window and a frame shown after it appeared), injects the 22 events of
//! `scenario.rs` and ends, printing `lvgl-inject: 22 events`.
//!
//! The events go one after the other with no pause between them. Nothing of
//! the frames depends on that: INJECT is a call that returns when the
//! compositor has put the event in the window's ring (in order, 64 places,
//! the 22 of the scenario and FOCUS_IN fit), and the demo, in the probe's
//! mode, takes one change at a time from its own queue and gives the next
//! only when the frame is settled (`ports/lvgl/schedule.c`). The arrival
//! time of an event, the speed of the machine and the pauses here change the
//! moment the demo reads the ring, and the sequence it reads is the same.
//!
//! The pointer is injected in the screen's coordinates; the demo's window
//! covers the screen at (0, 0), so they are the window's own.

#![no_std]
#![no_main]

mod scenario;

use abi::MESSAGE_MAX;
use proto_comp::{Description, Event, Method};
use proto_gpu::{HEIGHT, WIDTH};
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Handle, Resource};
use rt::wait::{Waited, Waiter};
use rt::{sys, time};

rt::entry!(main);

/// The period of the poll for the window, and the longest wait: the window
/// comes when someone types the demo's line into the shell.
const POLL_NS: u64 = if cfg!(feature = "quick") {
    5_000_000
} else {
    20_000_000
};
const WAIT_NS: u64 = 900_000_000_000;

// The kinds are the protocol's.
const _: () = {
    assert!(scenario::KEY == proto_comp::KEY);
    assert!(scenario::MOVE == proto_comp::MOVE);
    assert!(scenario::BUTTON == proto_comp::BUTTON);
    assert!(WIDTH == 640 && HEIGHT == 400);
    assert!(scenario::changes() == scenario::CHANGES);
};

fn say<E: core::fmt::Debug>(what: &'static str) -> impl Fn(E) -> &'static str {
    move |e| {
        rt::println!("lvgl-inject: {what}: {e:?}");
        what
    }
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(level) else {
        return 1;
    };
    let Ok(waiter) = Waiter::new(&channel, 0, level) else {
        return 1;
    };
    match run(&start.parent, &channel, &waiter) {
        Ok(()) => {
            rt::println!("lvgl-inject: {} events", scenario::EVENTS);
            0
        }
        Err(reason) => {
            rt::println!("lvgl-inject: failed: {reason}");
            2
        }
    }
}

/// Waits `ns` on the program's own channel, which nothing notifies.
fn sleep(channel: &Handle<Channel>, waiter: &Waiter, ns: u64) {
    let deadline = time::ticks_to_ns(time::now()).saturating_add(ns);
    while let Ok(Waited::Got(_)) = waiter.receive_until(channel, deadline) {}
}

fn describe(display: &Handle<Channel>) -> Result<Description, Status> {
    let reply = sys::send(display, &Method::Describe.header().bytes()).map_err(Status::Kernel)?;
    let mut buffer = [0; MESSAGE_MAX];
    Description::read(reply.bytes(&mut buffer))
}

fn inject(display: &Handle<Channel>, row: scenario::Row) -> Result<(), &'static str> {
    let event = Event::at(row.kind, row.code, row.value, row.x, row.y);
    let mut w = Writer::new();
    event.write_inject(&mut w).map_err(say("INJECT's bytes"))?;
    let reply = sys::send(display, w.as_bytes()).map_err(say("INJECT"))?;
    let mut buffer = [0; MESSAGE_MAX];
    let word = reply
        .bytes(&mut buffer)
        .get(..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or("a short reply")?;
    match Status::from_code(word) {
        Status::Ok => Ok(()),
        status => {
            rt::println!("lvgl-inject: INJECT of {event:?} said {status:?}");
            Err("INJECT was refused")
        }
    }
}

fn run(
    parent: &Handle<Channel>,
    channel: &Handle<Channel>,
    waiter: &Waiter,
) -> Result<(), &'static str> {
    let display = rt::service::connect(parent, "gpu").map_err(say("connect to gpu"))?;
    let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
    // The frames shown while no window was open are the baseline: a frame
    // beyond it, with a window open and the service settled, is the window's
    // first, whenever the poll came to see it.
    let mut baseline = 0u32;
    loop {
        match describe(&display) {
            Ok(d) if d.open == 0 => baseline = d.frames,
            Ok(d) => {
                if d.frames.wrapping_sub(baseline) as i32 > 0 && d.busy == 0 {
                    break;
                }
            }
            // The compositor says CLEARING while the driver is set up.
            Err(s) if s == proto_gpu::code(proto_gpu::CLEARING) => {}
            Err(_) => return Err("DESCRIBE"),
        }
        if time::ticks_to_ns(time::now()) > end {
            return Err("the window never came");
        }
        sleep(channel, waiter, POLL_NS);
    }
    for row in scenario::ROWS {
        inject(&display, row)?;
    }
    Ok(())
}
