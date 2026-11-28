// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The window manager's calls (`<stafeto/manager.h>`): the compositor's MANAGE
//! operations and the manager's ring of events, on the process's session with
//! the display service. The session carries the manager's mark only in a
//! process the init table names (`table::COMP_MANAGERS`, for a process of POSIX
//! the program `desk`); every other session, a child's clone of the manager's
//! included, gets NOT_ALLOWED, which is EPERM here.
//!
//! The subscription is a labelled copy of the process's shared channel (see
//! the parent module): the service sends it a bit when the ring has events,
//! and `wait_all` reports the bit as `table::MANAGER_BIT`. One thread at a
//! time takes the ring's events (the second gets EBUSY).

use super::{
    EBADF, EBUSY, EINVAL, EIO, ENODEV, Held, LABEL_SEQUENCE, MANAGER_GONE, MANAGER_LABEL,
    MANAGER_PENDING, call, channel, drop_channel_if_unused, ensure_channel, level, lock,
    memory_errno, opened, status_of,
};
use comp_client::errno;
use comp_client::events::Taker;
use comp_client::flag::Flag;
use comp_client::layout::WindowEvent;
use comp_client::manager::{self, ManagerInfo, ManagerWindow};
use comp_client::table;
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, Ordering};
use proto_comp::{Info, Method, manage, write_manage};
use proto_wire::{Status, Writer};
use rt::abi::{MESSAGE_MAX, Rights};
use rt::handle::{Channel, Handle, Outgoing};
use rt::sys;

/// A thread takes the ring's events.
static TAKING: AtomicBool = AtomicBool::new(false);
static STASH: Held = Held(UnsafeCell::new(Taker::new()));

/// A fork's child has no subscription and no events held.
pub(super) fn after_fork() {
    TAKING.store(false, Ordering::Release);
    // SAFETY: the child's only thread.
    unsafe { *STASH.0.get() = Taker::new() };
}

/// The process's session with the display service.
fn session() -> Result<ManuallyDrop<Handle<Channel>>, i32> {
    let display = crate::display::session().ok_or(ENODEV)?;
    Ok(Handle::<Channel>::borrowed(display))
}

/// The session of a call that needs the subscription: the service the manager
/// subscribed to is not gone.
fn subscribed() -> Result<ManuallyDrop<Handle<Channel>>, i32> {
    if MANAGER_LABEL.load(Ordering::Acquire) == 0 {
        return Err(EBADF);
    }
    if MANAGER_GONE.load(Ordering::Acquire) {
        return Err(ENODEV);
    }
    session()
}

/// One MANAGE request on the session: the reply, with the call's own errno.
fn manage_call(
    display: &Handle<Channel>,
    op: u32,
    a: u32,
    b: u32,
    c: u32,
    handles: Outgoing,
) -> Result<rt::sys::Reply, i32> {
    let mut request = Writer::new();
    write_manage(op, a, b, c, &mut request).map_err(|_| EIO)?;
    let reply = call(display, request.as_bytes(), handles).map_err(|e| {
        if e == rt::abi::Error::PeerClosed {
            MANAGER_GONE.store(true, Ordering::Release);
        }
        errno::kernel(e)
    })?;
    match status_of(&reply) {
        Status::Ok => Ok(reply),
        status => Err(refusal(status)),
    }
}

/// The errno of a refusal; REVOKED and NO_DEVICE mean the service is gone.
fn refusal(status: Status) -> i32 {
    let errno = manager::status(status);
    if errno == ENODEV {
        MANAGER_GONE.store(true, Ordering::Release);
    }
    errno
}

/// `stafeto_manager_subscribe`: the process's ring of manager events, with a
/// copy of the shared channel that the service notifies. EPERM for a session
/// without the manager's mark, EBUSY when a subscription is held (this
/// process's or another's).
pub fn subscribe() -> Result<(), i32> {
    let display = session()?;
    let _lock = lock();
    if MANAGER_LABEL.load(Ordering::Acquire) != 0 {
        return Err(EBUSY);
    }
    ensure_channel()?;
    let label = table::manager_label(LABEL_SEQUENCE.fetch_add(1, Ordering::AcqRel));
    let result = (|| {
        let notify = sys::handle_label(
            &channel(),
            Rights::NOTIFY | Rights::TRANSFER,
            label,
            level(),
        )
        .map_err(memory_errno)?;
        // The label is known before the service can notify, so a bit that
        // comes at once finds it.
        MANAGER_PENDING.store(false, Ordering::Release);
        MANAGER_GONE.store(false, Ordering::Release);
        MANAGER_LABEL.store(label, Ordering::Release);
        manage_call(
            &display,
            manage::SUBSCRIBE,
            0,
            0,
            0,
            [notify.erase()].into(),
        )
        .map(|_| ())
    })();
    if result.is_err() {
        MANAGER_LABEL.store(0, Ordering::Release);
        drop_channel_if_unused();
    }
    result
}

/// `stafeto_manager_events`: up to `out.len()` events of the manager's ring
/// and the flags, fewer only when the ring is empty.
pub fn events(out: &mut [WindowEvent]) -> Result<(usize, u32), i32> {
    let display = subscribed()?;
    if out.is_empty() {
        return Err(EINVAL);
    }
    let Some(_taking) = Flag::take(&TAKING) else {
        return Err(EBUSY);
    };
    // SAFETY: `TAKING` is held.
    let taker = unsafe { &mut *STASH.0.get() };
    taker.take(out, |list| {
        let reply =
            call(&display, &Method::Events.header().bytes(), Outgoing::new()).map_err(|e| {
                if e == rt::abi::Error::PeerClosed {
                    MANAGER_GONE.store(true, Ordering::Release);
                }
                errno::kernel(e)
            })?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut n = 0;
        let flags = proto_comp::read_events(reply.bytes(&mut buffer), |event| {
            if n < list.len() {
                list[n] = event.into();
                n += 1;
            }
        })
        .map_err(refusal)?;
        Ok((n, flags & proto_comp::LOST != 0))
    })
}

/// `stafeto_manager_list`: the windows, the lowest first, up to `out.len()`.
pub fn list(out: &mut [ManagerWindow]) -> Result<usize, i32> {
    let display = subscribed()?;
    let reply = manage_call(&display, manage::LIST, 0, 0, 0, Outgoing::new())?;
    let mut buffer = [0; MESSAGE_MAX];
    let mut n = 0;
    proto_comp::read_list(reply.bytes(&mut buffer), |record| {
        if n < out.len() {
            out[n] = record.into();
            n += 1;
        }
    })
    .map_err(refusal)?;
    Ok(n)
}

/// `stafeto_manager_info`: the flags, the capacity and the texts of window `id`.
pub fn info(id: u32) -> Result<ManagerInfo, i32> {
    let display = subscribed()?;
    let reply = manage_call(&display, manage::INFO, id, 0, 0, Outgoing::new())?;
    let mut buffer = [0; MESSAGE_MAX];
    let info = Info::read(reply.bytes(&mut buffer)).map_err(refusal)?;
    Ok(ManagerInfo::from(&info))
}

fn operation(op: u32, a: u32, b: u32, c: u32) -> Result<(), i32> {
    let display = subscribed()?;
    manage_call(&display, op, a, b, c, Outgoing::new()).map(|_| ())
}

/// `stafeto_manager_move`: window `id` to (`x`, `y`).
pub fn move_to(id: u32, x: u32, y: u32) -> Result<(), i32> {
    operation(manage::MOVE, id, x, y)
}

/// `stafeto_manager_raise`.
pub fn raise(id: u32) -> Result<(), i32> {
    operation(manage::RAISE, id, 0, 0)
}

/// `stafeto_manager_focus`.
pub fn focus(id: u32) -> Result<(), i32> {
    operation(manage::FOCUS, id, 0, 0)
}

/// `stafeto_manager_visible`.
pub fn visible(id: u32, shown: bool) -> Result<(), i32> {
    operation(manage::VISIBLE, id, u32::from(shown), 0)
}

/// `stafeto_manager_configure`: window `id` is asked for `w` by `h` (0 by 0:
/// the client chooses) with the state bits `states`.
pub fn configure(id: u32, w: u32, h: u32, states: u32) -> Result<(), i32> {
    if w > 0xffff || h > 0xffff || states & !proto_comp::STATES != 0 {
        return Err(EINVAL);
    }
    operation(manage::CONFIGURE, id, manage::size(w, h), states)
}

/// `stafeto_manager_close`: window `id` is asked to close itself.
pub fn close(id: u32) -> Result<(), i32> {
    operation(manage::CLOSE, id, 0, 0)
}

/// `stafeto_manager_link`: window `follower` (a window of the manager's own)
/// follows `leader`; `manager::NO_WINDOW` for `follower` breaks the link.
pub fn link(leader: u32, follower: u32) -> Result<(), i32> {
    operation(manage::LINK, leader, follower, 0)
}

/// `stafeto_window_id`: the service's number of the open window `win`.
pub fn window_id(win: i32) -> Result<u32, i32> {
    Ok(opened(win)?.id.load(Ordering::Acquire))
}
