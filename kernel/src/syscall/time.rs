// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls of time (spec 10, 11): clock_now and the timers of programs.

use super::{Args, Values, caller, caller_ceiling, cause, lookup};
use crate::arch::timer as clock;
use crate::object::Object;
use crate::process;
use crate::thread::Thread;
use crate::{session, timer};
use abi::{Error, OWNER_RIGHTS, Rights};
use core::ptr::NonNull;
use kcore::args::{priority_arg, under_ceilings};

/// clock_now(): x1 returns the counter in nanoseconds, rounded down
/// (spec 10): the scale of the deadlines of timer_set.
pub(super) fn clock_now() -> Result<Values, Error> {
    Ok(Values::new(&[clock::clock().ticks_to_ns(clock::now())]))
}

/// timer_create(x0 channel with RECEIVE, x1 priority): a timer on the
/// channel, not armed, whose notifications have the priority and the
/// label of the handle (spec 10); x1 returns a handle to it with
/// DUPLICATE, TRANSFER and MANAGE (abi::OWNER_RIGHTS). The channel is the
/// caller's own to receive from: its slots and the priorities that lift
/// its receivers are the receiver's. The checks in the order of spec 11:
/// the priority, 1-63 (INVALID_ARGS); the handle (BAD_HANDLE, WRONG_TYPE,
/// ACCESS_DENIED without RECEIVE); the priority above the caller's ceiling
/// (ACCESS_DENIED); then the resources in the order the call takes them:
/// room in the caller's table (LIMIT_REACHED), abi::MAX_TIMERS timers the
/// caller pays for (LIMIT_REACHED), abi::MAX_SYSTEM_TIMERS timers in the
/// system (LIMIT_REACHED), a slot of the channel (LIMIT_REACHED,
/// spec 6.5), a page of the caller's pool of timers and a block of its
/// table (NO_MEMORY). A channel with a handle with RECEIVE is open. A
/// timer whose handle did not go in goes again.
pub(super) fn timer_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let priority = priority_arg(a[1])?;
    let (c, label) = lookup(thread, a[0], Rights::RECEIVE, |o| {
        Some((o.channel()?, o.session().map_or(0, session::label)))
    })?;
    under_ceilings(priority, &[caller_ceiling(thread)])?;
    process::handle_room(caller(thread))?;
    let t = timer::create(caller(thread), c, label, priority)?;
    let h = process::insert_handle(caller(thread), Object::Timer(t), OWNER_RIGHTS);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the timer, and without it the timer goes.
    unsafe { timer::release(t, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// timer_set(x0 timer with MANAGE, x1 deadline): the timer fires at the
/// deadline, nanoseconds on the scale of clock_now, rounded up to counter
/// ticks so that it never fires early (spec 10). A deadline the counter
/// reached fires in the call: bit 0 into the timer's slot, which goes to
/// the top receiver that waits or into the channel's queue, as notify
/// puts it; any other arms the timer, and an armed one moves. PEER_CLOSED
/// once the channel closed, and the timer stays as it was. No memory is
/// taken.
pub(super) fn timer_set(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let t = lookup(thread, a[0], Rights::MANAGE, Object::timer)?;
    let deadline = clock::clock().ns_to_ticks(a[1]);
    timer::set(t, deadline, cause(thread))?;
    Ok(Values::none())
}

/// timer_cancel(x0 timer with MANAGE): the timer is armed no more; bits it
/// posted stay in its slot until receive takes them (spec 10). A timer
/// that is not armed is left as it is: 0.
pub(super) fn timer_cancel(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let t = lookup(thread, a[0], Rights::MANAGE, Object::timer)?;
    timer::cancel(t);
    Ok(Values::none())
}
