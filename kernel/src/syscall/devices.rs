// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls of devices (spec 9, 11): device_window_create, msi_create,
//! irq_bind and irq_ack.

use super::{Args, Values, caller, caller_ceiling, cause, lookup};
use crate::arch::its::{self, Position};
use crate::memory;
use crate::msi;
use crate::object::Object;
use crate::process;
use crate::thread::Thread;
use crate::{arch, channel, irq, session};
use abi::{Error, OWNER_RIGHTS, Rights, WINDOW_RIGHTS};
use core::ptr::NonNull;
use kcore::args::{cpu_arg, event_flags_arg, line_arg, priority_arg, trigger_arg, under_ceilings};

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
#[inline(never)]
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
#[inline(never)]
pub(super) fn irq_bind(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let cpu = cpu_arg(a[5], arch::cpu::MAX_CPUS)?;
    // The kind of x0 picks the call: an MSI device binds an event, the
    // system resource a line; a handle that is neither goes the way of the
    // line, whose checks give its errors.
    // The lookup is inside the section: the pointer it gives holds no
    // reference, and another CPU may close the device meanwhile.
    let mut commands = None;
    let result = super::objects(|| {
        let device = lookup(thread, a[0], Rights::MANAGE, Object::msi);
        if !matches!(device, Err(Error::WrongType | Error::BadHandle)) {
            irq_bind_event(thread, a, cpu, device, &mut commands)
        } else {
            irq_bind_line(thread, a, cpu)
        }
    });
    // The commands of an event are in the queue (spec 8.1): the ITS is told
    // outside the section, and the call waits one segment for it, no more.
    // The mapping is in force once the ITS ran the commands, which the
    // driver sees as a notification after it unmasks its vector and looks
    // at its queues once (spec 9).
    if let Some(pos) = commands {
        its::ring();
        let mapped = its::wait_once(pos);
        return result.map(|mut values| {
            values.push(u64::from(mapped));
            values
        });
    }
    result
}

/// The part of irq_bind that binds a shared line (see `irq_bind`).
fn irq_bind_line(thread: NonNull<Thread>, a: &Args, cpu: u32) -> Result<Values, Error> {
    let line = line_arg(a[1], arch::gic::lines())?;
    let priority = priority_arg(a[3])?;
    let edge = trigger_arg(a[4])?;
    check_cpu(cpu)?;
    lookup(thread, a[0], Rights::DEVICE, Object::resource)?;
    let (c, label) = notify_channel(thread, a[2])?;
    under_ceilings(priority, &[caller_ceiling(thread)])?;
    if irq::is_bound(line) {
        return Err(Error::BadState);
    }
    if channel::is_closed(c) {
        return Err(Error::PeerClosed);
    }
    process::handle_room(caller(thread))?;
    let b = irq::bind(caller(thread), c, label, line, priority, edge, cpu)?;
    let h = process::insert_handle(caller(thread), Object::Irq(b), OWNER_RIGHTS);
    // SAFETY: the reference `bind` handed out goes; the handle, if it went
    // in, holds the binding, and without it the binding and its line go.
    unsafe { irq::release_handle(b, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// The part of irq_bind that binds an event of an MSI device (spec 9): x0
/// a device with MANAGE, x1 the event, x2 a channel with NOTIFY, x3 the
/// priority, x4 flags, which are 0 (an LPI is always edge-triggered), x5
/// the CPU. The checks in the order of spec 11: priority, flags and CPU
/// outside the values (INVALID_ARGS); x0 (WRONG_TYPE, ACCESS_DENIED without
/// MANAGE), the event past the device's (INVALID_ARGS), x2 (BAD_HANDLE,
/// WRONG_TYPE, ACCESS_DENIED without NOTIFY); the priority above the
/// caller's ceiling (ACCESS_DENIED); an event with a binding (BAD_STATE), a
/// closed channel (PEER_CLOSED); then the resources: room in the caller's
/// table (LIMIT_REACHED), a slot of the channel and a free LPI
/// (LIMIT_REACHED), the room for its commands in the ITS queue
/// (LIMIT_REACHED), a page of the caller's pool of bindings and a block of
/// its table (NO_MEMORY). Returns x1 the binding, x2 the MSI address, x3
/// the MSI data, x4 (added by `irq_bind`) 1 when the ITS ran the commands
/// of the mapping and 0 when it did not yet, and in `commands` the count the commands of the ITS are
/// at in the queue.
fn irq_bind_event(
    thread: NonNull<Thread>,
    a: &Args,
    cpu: u32,
    device: Result<NonNull<msi::Msi>, Error>,
    commands: &mut Option<Position>,
) -> Result<Values, Error> {
    let priority = priority_arg(a[3])?;
    event_flags_arg(a[4])?;
    check_cpu(cpu)?;
    let device = device?;
    let event = msi::claim(device, a[1])?;
    let (c, label) = notify_channel(thread, a[2])?;
    under_ceilings(priority, &[caller_ceiling(thread)])?;
    if channel::is_closed(c) {
        return Err(Error::PeerClosed);
    }
    process::handle_room(caller(thread))?;
    let (b, pos) = irq::bind_event(caller(thread), c, label, device, event, priority, cpu)?;
    *commands = Some(pos);
    let info = irq::info(b);
    let h = process::insert_handle(caller(thread), Object::Irq(b), OWNER_RIGHTS);
    // SAFETY: the reference `bind_event` handed out goes; the handle, if it
    // went in, holds the binding, and without it the binding and its event
    // go with it.
    unsafe { irq::release_handle(b, cause(thread)) };
    let h = h?;
    Ok(Values::new(&[h.0, info.msi_address, info.msi_data]))
}

/// The channel of handle `h` with NOTIFY, and the label of the handle.
#[inline(never)]
fn notify_channel(
    thread: NonNull<Thread>,
    h: u64,
) -> Result<(NonNull<channel::Channel>, u64), Error> {
    lookup(thread, h, Rights::NOTIFY, |o| {
        Some((o.channel()?, o.session().map_or(0, session::label)))
    })
}

/// INVALID_ARGS for a CPU that is not up.
fn check_cpu(cpu: u32) -> Result<(), Error> {
    if arch::cpu::is_up(cpu as usize) {
        Ok(())
    } else {
        Err(Error::InvalidArgs)
    }
}

/// msi_create(x0 system resource with DEVICE, x1 requester ID, x2 events):
/// the MSI device of a PCI function (spec 9); x1 returns a handle to it with
/// abi::OWNER_RIGHTS. The checks in the order of spec 11: the values (events
/// outside 1..=abi::MAX_MSI_EVENTS, a requester ID the device tree's
/// `msi-map` does not name, a DeviceID past the device table, no ITS:
/// INVALID_ARGS); x0 (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without
/// DEVICE); a DeviceID that has a device (BAD_STATE); then the resources:
/// room in the caller's table, a place in DEVICES (LIMIT_REACHED), a place
/// in the pool of devices of the caller, which grows by a page the quota
/// pays for (NO_MEMORY), and the room for the MAPD in the ITS queue
/// (LIMIT_REACHED). The MAPD goes into the queue in the section and the ITS
/// is told after it; the call does not wait for the ITS (spec 8.1, 9).
#[inline(never)]
pub(super) fn msi_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let device_id = msi::check(a[1], a[2])?;
    let mut commands = None;
    let result = super::objects(|| {
        lookup(thread, a[0], Rights::DEVICE, Object::resource)?;
        process::handle_room(caller(thread))?;
        let (m, pos) = msi::create(caller(thread), device_id, a[2] as u32)?;
        commands = Some(pos);
        let h = process::insert_handle(caller(thread), Object::Msi(m), OWNER_RIGHTS);
        // SAFETY: the reference `create` handed out goes; the handle, if it
        // went in, holds the device, and without it the device goes.
        unsafe { msi::release(m, cause(thread)) };
        Ok(Values::new(&[h?.0]))
    });
    if commands.is_some() {
        its::ring();
    }
    result
}

/// irq_ack(x0 binding with MANAGE): the line an interrupt masked opens
/// again (spec 9); an open line stays open, 0 all the same. PEER_CLOSED once
/// the binding's channel closed, and the line stays masked. For an event of
/// an MSI device WOULD_BLOCK while the ITS has not run the commands of its
/// mapping (irq_bind returned x4 = 0): the driver asks again before it
/// unmasks its vector (spec 9). The check reads a register of the ITS and
/// goes after the section.
#[inline(never)]
pub(super) fn irq_ack(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let mut mapping = None;
    super::objects(|| {
        let b = lookup(thread, a[0], Rights::MANAGE, Object::irq)?;
        irq::ack(b, &mut mapping)
    })?;
    if mapping.is_some_and(|at| !its::mapped(at)) {
        return Err(Error::WouldBlock);
    }
    Ok(Values::none())
}
