// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls of devices (spec 9, 11): device_window_create, irq_bind and irq_ack.

use super::{Args, Values, caller, caller_ceiling, cause, lookup};
use crate::memory;
use crate::object::Object;
use crate::process;
use crate::thread::Thread;
use crate::{arch, channel, irq, session};
use abi::{Error, OWNER_RIGHTS, Rights, WINDOW_RIGHTS};
use core::ptr::NonNull;
use kcore::args::{line_arg, priority_arg, trigger_arg, under_ceilings};

/// device_window_create(x0 system resource with DEVICE, x1 address, x2
/// length): a device window, a memory object over the physical range
/// rounded out to whole pages (spec 9); x1 returns a handle to it with
/// abi::WINDOW_RIGHTS, which mem_map shows as Device-nGnRE, never
/// executable (spec 7.4). The checks in the order of spec 11: a length of
/// 0, a range that wraps around, ends past 2^48 or holds more than
/// abi::MAX_MEMORY (INVALID_ARGS, kcore::window::round_out); x0
/// (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without DEVICE); a page of the
/// range shared with RAM or a device of the kernel (INVALID_ARGS,
/// memory::check_window); then the resources in the order the call takes
/// them: room in the caller's table (LIMIT_REACHED), a page of the caller's
/// pool of memory objects and a block of its table (NO_MEMORY). A window
/// whose handle did not go in goes again. A window over a page of the
/// console's port takes the port from the kernel while it lives (spec
/// 3.2, memory::create_window).
pub(super) fn device_window_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let (base, pages) = kcore::window::round_out(a[1], a[2])?;
    lookup(thread, a[0], Rights::DEVICE, Object::resource)?;
    memory::check_window(base, pages)?;
    process::handle_room(caller(thread))?;
    let m = memory::create_window(caller(thread), base, pages as usize)?;
    let h = process::insert_handle(caller(thread), Object::Memory(m), WINDOW_RIGHTS);
    // SAFETY: the reference `create_window` handed out goes; the handle, if
    // it went in, holds the window, and without it the window goes.
    unsafe { memory::release(m, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// irq_bind(x0 system resource with DEVICE, x1 line, x2 channel with
/// NOTIFY, x3 priority, x4 flags): the line's interrupts come as
/// notifications of the channel (spec 9), bit 0 into a slot of the
/// priority with the label of the handle; x1 returns a handle to the
/// binding with DUPLICATE, TRANSFER and MANAGE (abi::OWNER_RIGHTS). The
/// channel may be a registration handle a service gave init: NOTIFY is
/// the right to post into it. The line is edge-triggered with
/// abi::TRIGGER_EDGE in the flags, level-triggered without, and open at
/// once. The checks in the order of spec 11: a line outside the shared
/// ones, a priority outside 1-63 and a flag
/// other than TRIGGER_EDGE (INVALID_ARGS); x0 (BAD_HANDLE, WRONG_TYPE,
/// ACCESS_DENIED without DEVICE), x2 (BAD_HANDLE, WRONG_TYPE,
/// ACCESS_DENIED without NOTIFY); the priority above the caller's ceiling
/// (ACCESS_DENIED); a line with a binding (BAD_STATE), a closed channel
/// (PEER_CLOSED); then the resources in the order the call takes them:
/// room in the caller's table (LIMIT_REACHED), a slot of the channel
/// (LIMIT_REACHED, spec 6.5), a page of the caller's pool of bindings and
/// a block of its table (NO_MEMORY). A binding whose handle did not go in
/// goes again, and its line with it.
pub(super) fn irq_bind(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let line = line_arg(a[1], arch::gic::lines())?;
    let priority = priority_arg(a[3])?;
    let edge = trigger_arg(a[4])?;
    lookup(thread, a[0], Rights::DEVICE, Object::resource)?;
    let (c, label) = lookup(thread, a[2], Rights::NOTIFY, |o| {
        Some((o.channel()?, o.session().map_or(0, session::label)))
    })?;
    under_ceilings(priority, &[caller_ceiling(thread)])?;
    if irq::is_bound(line) {
        return Err(Error::BadState);
    }
    if channel::is_closed(c) {
        return Err(Error::PeerClosed);
    }
    process::handle_room(caller(thread))?;
    let b = irq::bind(caller(thread), c, label, line, priority, edge)?;
    let h = process::insert_handle(caller(thread), Object::Irq(b), OWNER_RIGHTS);
    // SAFETY: the reference `bind` handed out goes; the handle, if it went
    // in, holds the binding, and without it the binding and its line go.
    unsafe { irq::release_handle(b, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// irq_ack(x0 binding with MANAGE): the line an interrupt masked opens
/// again (spec 9); an open line stays open, 0 all the same. PEER_CLOSED once
/// the binding's channel closed, and the line stays masked.
pub(super) fn irq_ack(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let b = lookup(thread, a[0], Rights::MANAGE, Object::irq)?;
    irq::ack(b)?;
    Ok(Values::none())
}
