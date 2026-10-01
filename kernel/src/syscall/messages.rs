// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls of channels and messages (spec 6, 11): channel_create, notify, receive, send and reply.

use super::{Args, Values, caller, caller_ceiling, cause, lookup, set_result};
use crate::channel::Via;
use crate::object::Object;
use crate::process;
use crate::thread::{self, Thread};
use crate::{channel, session};
use abi::{CHANNEL_RIGHTS, Error, Rights};
use core::ptr::NonNull;
use kcore::args::{Desc, bits_arg, handle_values_arg, priority_arg, under_ceilings, wait_arg};

/// channel_create(x0 priority): a channel whose slot of label 0 has the
/// priority (spec 6.5); x1 returns a handle to it with SEND, NOTIFY,
/// RECEIVE, DUPLICATE and TRANSFER (abi::CHANNEL_RIGHTS). The priority is
/// 1-63 (INVALID_ARGS) and no higher than the caller's ceiling
/// (ACCESS_DENIED). Resources come last, in the order the call occupies
/// them (spec 11): the caller's table has room for the handle
/// (LIMIT_REACHED), then the caller's quota pays for a page of its pool of
/// channels when the pool grows and for a block of its table (NO_MEMORY).
/// A channel whose handle did not go in goes again.
pub(super) fn channel_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let priority = priority_arg(a[0])?;
    under_ceilings(priority, &[caller_ceiling(thread)])?;
    process::handle_room(caller(thread))?;
    let c = channel::create(caller(thread), priority)?;
    let h = process::insert_handle(caller(thread), Object::Channel(c), CHANNEL_RIGHTS);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the channel.
    unsafe { channel::release(c, Rights::NONE, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// notify(x0 channel with NOTIFY, x1 bits): the bits first, since bit 63,
/// CLIENT_GONE, is the kernel's (INVALID_ARGS); then the handle, and
/// PEER_CLOSED once no handle with RECEIVE is left (spec 6.5, 6.8). The
/// bits go into the channel's slot of label 0, or through a handle with a
/// label into its session's slot (spec 5.3), ORed with those not yet
/// received, and the slot to the top receiver that waits or into the
/// queue of slots. A receiver woken above the caller runs before the call
/// returns. No memory is taken, and nothing waits.
pub(super) fn notify(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let bits = bits_arg(a[1])?;
    let (c, s) = lookup(thread, a[0], Rights::NOTIFY, |o| {
        Some((o.channel()?, o.session()))
    })?;
    match s {
        Some(s) => session::notify(s, bits, cause(thread))?,
        None => channel::notify(c, bits, cause(thread))?,
    }
    Ok(Values::none())
}

/// receive(x0 channel with RECEIVE, x1 flags): the flags first, bit 16
/// NO_WAIT and no other (INVALID_ARGS), then the handle. A call that passed
/// its checks ends the caller's boost by its last notification or request
/// (spec 6.6). What the queue has comes at once: a notification in x1-x11
/// as abi::Notification::to_words puts them, after which the caller works
/// at the slot's priority, under its ceiling, until its next receive; or a
/// request in x1-x11 as abi::Message::to_words puts them, the label of the
/// handle it came through in x10 and the token of its reply in x11, after
/// which the caller works at the client's priority, under its ceiling,
/// until its reply with the token or its next receive. With nothing
/// queued, WOULD_BLOCK under NO_WAIT; otherwise the caller waits in the
/// channel (spec 6.1), and the end of the wait writes its result: a
/// notification, a request, or PEER_CLOSED in x0 alone once the last
/// handle with RECEIVE went. The call writes its own result: x0-x11 are
/// its (channel::receive).
pub(super) fn receive(thread: NonNull<Thread>, a: &Args) {
    let taken = wait_arg(a[1]).and_then(|wait| {
        let c = lookup(thread, a[0], Rights::RECEIVE, Object::channel)?;
        channel::receive(thread, c, wait)
    });
    if let Err(e) = taken {
        set_result(thread, Err(e));
    }
}

/// The values of the handles of the message the caller sends or answers
/// with (spec 6.1, 6.2), read once from its message buffer before any
/// check: INVALID_ARGS for a value listed twice or equal to `channel`, x0
/// of send.
fn message_handles(
    thread: NonNull<Thread>,
    desc: Desc,
    channel: Option<u64>,
) -> Result<[u64; abi::MESSAGE_HANDLES], Error> {
    if desc.handles == 0 {
        return Ok([0; abi::MESSAGE_HANDLES]);
    }
    let values = thread::handle_values(thread, desc.handles);
    handle_values_arg(&values[..desc.handles], channel)?;
    Ok(values)
}

/// The handles of a message in the order it lists them (spec 6.1, 11):
/// BAD_HANDLE, then ACCESS_DENIED without TRANSFER; a handle to an object
/// of any kind travels.
fn check_handles(thread: NonNull<Thread>, values: &[u64]) -> Result<(), Error> {
    values
        .iter()
        .try_for_each(|&h| lookup(thread, h, Rights::TRANSFER, |_| Some(())))
}

/// send(x0 channel with SEND, x1 description, x2-x9 bytes 0-63 of the
/// request): a request and the wait for its reply (spec 6.1). The checks in
/// the order of spec 11: the description (abi::MESSAGE_MAX bytes and
/// abi::MESSAGE_HANDLES handles at most, NO_WAIT, no other bit) and the
/// values of its handles, which the message buffer holds
/// (`message_handles`); then x0, a channel or a labelled one (BAD_HANDLE,
/// WRONG_TYPE, ACCESS_DENIED without SEND), and the handles
/// (`check_handles`); then the state (BAD_STATE when the caller's count of
/// requests ran out, PEER_CLOSED once the channel closed, WOULD_BLOCK
/// under NO_WAIT when no receiver waits); then the room for the handles in
/// the table of a receiver that waits (LIMIT_REACHED, NO_MEMORY). x0 alone
/// changes on an error; the handles stay with the caller, but for
/// PEER_CLOSED, LIMIT_REACHED and NO_MEMORY, when they go. Otherwise the
/// handles leave the caller's table and the caller waits, its request
/// queued by its effective priority or taken by the top receiver that
/// waits at once, until the reply writes x0-x9: 0, the description and the
/// data, or an error of the reply's handles in x0 alone. Bytes 64 up to
/// the length of the request and of the reply go between the message
/// buffers, and the values and info words of the handles into them (spec
/// 6.2; channel::send). A receiver that takes the request on the fast path
/// runs at once (spec 6.4).
pub(super) fn send(thread: NonNull<Thread>, a: &Args) {
    let sent = Desc::from_send(a[1]).and_then(|desc| {
        let values = message_handles(thread, desc, Some(a[0]))?;
        let via = lookup(thread, a[0], Rights::SEND, |o| match *o {
            Object::Channel(c) => Some(Via::Channel(c)),
            Object::Session(s) => Some(Via::Session(s)),
            _ => None,
        })?;
        let values = &values[..desc.handles];
        check_handles(thread, values)?;
        channel::send(thread, via, desc, values)
    });
    match sent {
        Ok(Some(receiver)) => thread::run(receiver),
        Ok(None) => {}
        Err(e) => set_result(thread, Err(e)),
    }
}

/// reply(x0 token, x1 description, x2-x9 bytes 0-63 of the reply): the
/// reply to the request the token names, which a thread of the caller's
/// process accepted (spec 6.1). The description first (NO_WAIT is
/// INVALID_ARGS: reply never waits) and the values of its handles
/// (`message_handles`), then the handles (`check_handles`); a reply with the
/// token of the caller's boost ends the boost, whatever comes of it (spec
/// 6.6); then the token: BAD_STATE for one that names no request waiting
/// for this process's reply, a used one among them, and PEER_CLOSED for one
/// whose client ended while it waited (spec 6.8); then the room for the
/// handles in the client's table (LIMIT_REACHED, NO_MEMORY), which fails
/// the client's send too and uses the token up. x0 alone changes on an
/// error; the handles stay with the caller, but for PEER_CLOSED,
/// LIMIT_REACHED and NO_MEMORY, when they go. Otherwise x0 is 0, and the
/// client gets the reply, bytes 64 up to its length through the message
/// buffers and the handles in its table (spec 6.2; channel::reply).
pub(super) fn reply(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let desc = Desc::from_reply(a[1])?;
    let values = message_handles(thread, desc, None)?;
    let values = &values[..desc.handles];
    check_handles(thread, values)?;
    channel::reply(thread, a[0], desc, values)?;
    Ok(Values::none())
}
