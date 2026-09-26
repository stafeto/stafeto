// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A wait with a bound (spec 6.1, 10): calls have no timeouts, so a thread
//! bounds its receive with a timer on the channel it receives from. A
//! `Waiter` owns that timer; `receive_until` arms it, waits, and tells the
//! expiry of its deadline from what else came.

use crate::handle::{Channel, Handle, Timer};
use crate::sys::{self, Received};
use crate::time;
use abi::{Error, Source};

/// A timer on a channel for waits with a bound (spec 10). The channel has
/// one receiving thread, the one that waits: any thread in receive there
/// could take the timer's notification. The timer's notifications carry
/// the label of the handle it was made through; the program makes no other
/// timer through a handle with that label on that channel, so that label
/// and source name this timer's expiries.
///
/// The timer's slot has the base priority of the waiting thread: an
/// expiry then wakes the thread at its own level, ahead of the threads
/// below it, and lifts it no higher until its next receive (spec 6.6). A
/// thread that changes its base priority makes a new `Waiter`; one that
/// lowers itself after a notification lifted it first ends the lift with
/// a receive that does not wait (sys::try_receive).
///
/// After any end of a wait, Expired or Got, a bit of this timer may still
/// come: the kernel no longer arms the timer, but its expiry may lie in
/// the slot. Code that receives on the channel outside `receive_until`
/// passes over timer notifications with this label.
pub struct Waiter {
    timer: Handle<Timer>,
    label: u64,
}

/// How `receive_until` ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Waited {
    /// A request or a notification came before the deadline; the timer is
    /// no longer armed.
    Got(Received),
    /// The deadline came first: the counter reached it.
    Expired,
}

impl Waiter {
    /// timer_create on `channel`, a handle with RECEIVE and the label
    /// `label` (0 for none), with the slot at `priority`: the base
    /// priority of the thread that waits. The errors are timer_create's.
    pub fn new(channel: &Handle<Channel>, label: u64, priority: u8) -> Result<Waiter, Error> {
        let timer = sys::timer_create(channel, priority)?;
        Ok(Waiter { timer, label })
    }

    /// Waits in receive on `channel`, the one the timer is on, until
    /// something comes or the deadline, nanoseconds on the scale of
    /// clock_now, passes (spec 10). An expiry of this timer counts once
    /// the counter reached the deadline's tick (time::ns_to_ticks), where
    /// the kernel fires it, never earlier; one that comes before is stale,
    /// an earlier wait's that timer_cancel left in the slot, and the wait
    /// goes on. Anything else ends the wait and cancels the timer. The
    /// errors are timer_set's and receive's; a wait that failed in receive
    /// leaves the timer cancelled.
    pub fn receive_until(&self, channel: &Handle<Channel>, deadline: u64) -> Result<Waited, Error> {
        sys::timer_set(&self.timer, deadline)?;
        let at = time::ns_to_ticks(deadline);
        let got = loop {
            match sys::receive(channel) {
                Ok(Received::Notification {
                    source: Source::Timer,
                    label,
                    ..
                }) if label == self.label => {
                    if time::now() >= at {
                        return Ok(Waited::Expired);
                    }
                }
                other => break other,
            }
        };
        // A timer the process holds cancels; the request the wait took
        // must reach the caller whatever the call says.
        let _ = sys::timer_cancel(&self.timer);
        got.map(Waited::Got)
    }
}
