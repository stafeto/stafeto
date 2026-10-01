// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls on handles (spec 11): handle_close and handle_duplicate.

use super::{Args, Values, caller, caller_ceiling, cause, lookup};
use crate::object::Object;
use crate::process;
use crate::thread::Thread;
use crate::{channel, session};
use abi::{Error, Handle, Rights};
use core::ptr::NonNull;
use kcore::args::{notify_priority_arg, rights_arg, under_ceilings};

/// handle_close(x0 handle), no right needed: the handle's reference goes,
/// and the last reference queues the object for cleanup at the caller's
/// priority. Closing a handle to a thread or a process does not end it.
pub(super) fn handle_close(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    process::close_handle(caller(thread), Handle(a[0]), cause(thread))?;
    Ok(Values::none())
}

/// handle_duplicate(x0 handle with DUPLICATE, x1 rights, x2 label, x3
/// priority): a copy of the handle with the rights, a subset of the
/// handle's own, in x1 (spec 5.2, 5.3). With label 0 and priority 0 the
/// copy names the same object, whatever its kind; a copy of a handle with
/// a label carries that label and counts as one more copy of its session.
/// A label that is not 0 goes on a copy of a channel handle that has none:
/// the copy names a new session of the channel with the label and a slot
/// of the priority, 1-63, which the caller's pool of sessions holds and its
/// quota pays for. The checks in the order of spec 11: bits no right has, a
/// priority without a label or a label without a priority 1-63
/// (INVALID_ARGS); the handle (BAD_HANDLE), a label on what is no channel
/// (WRONG_TYPE), no DUPLICATE or a right the handle lacks (ACCESS_DENIED);
/// the priority above the caller's ceiling (ACCESS_DENIED); a label on a
/// handle with one (BAD_STATE) or on a closed channel (PEER_CLOSED); then
/// the resources in the order the call takes them: room in the caller's
/// table (LIMIT_REACHED), a slot of the channel (LIMIT_REACHED, spec 6.5),
/// a page of the caller's pool of sessions and a block of its table
/// (NO_MEMORY). A session whose handle did not go in goes again.
pub(super) fn handle_duplicate(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let rights = rights_arg(a[1])?;
    let label = a[2];
    let priority = notify_priority_arg(a[3], label != 0)?;
    let needed = Rights::DUPLICATE | rights;
    if label == 0 {
        let object = lookup(thread, a[0], needed, |o| Some(*o))?;
        let h = process::insert_handle(caller(thread), object, rights)?;
        return Ok(Values::new(&[h.0]));
    }
    let (c, labelled) = lookup(thread, a[0], needed, |o| {
        Some((o.channel()?, o.session().is_some()))
    })?;
    under_ceilings(priority, &[caller_ceiling(thread)])?;
    if labelled {
        return Err(Error::BadState);
    }
    if channel::is_closed(c) {
        return Err(Error::PeerClosed);
    }
    process::handle_room(caller(thread))?;
    let s = session::create(caller(thread), c, label, priority)?;
    let h = process::insert_handle(caller(thread), Object::Session(s), rights);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the session, and without it the session goes.
    unsafe { session::unref(s, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}
