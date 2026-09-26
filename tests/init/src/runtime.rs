// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of the runtime, lib/rt, on top of the calls (spec 5.4, 6.1,
//! 10, 13.2): handles that own their entry of the table, the handles of a
//! message, init's first handles, the strict build of the test images,
//! where BAD_HANDLE from a typed call panics, and waits with a bound.

use crate::channels::{take_one, unlabeled};
use crate::harness::*;
use crate::messages::answer_all;
use crate::processes::{Gift, ran};
use crate::timers::timer_at;
use crate::transfers::{close_raw, copy_raw, give, handle_client};
use rt::wait::{Waited, Waiter};

/// The tests of this module, in the order they run.
pub(crate) const TESTS: [Test; 14] = [
    ("dropped_handle_closes", dropped_handle_closes),
    ("into_raw_keeps_the_handle", into_raw_keeps_the_handle),
    ("borrowed_handle_stays_open", borrowed_handle_stays_open),
    ("init_handles_come_once", init_handles_come_once),
    (
        "incoming_handles_close_unless_taken",
        incoming_handles_close_unless_taken,
    ),
    (
        "refused_send_gives_the_handles_back",
        refused_send_gives_the_handles_back,
    ),
    ("take_checks_the_kind", take_checks_the_kind),
    (
        "strict_child_panics_on_bad_handle",
        strict_child_panics_on_bad_handle,
    ),
    (
        "strict_child_panics_on_a_double_close",
        strict_child_panics_on_a_double_close,
    ),
    (
        "raw_call_returns_bad_handle_in_a_strict_build",
        raw_call_returns_bad_handle_in_a_strict_build,
    ),
    ("wait_ends_at_its_deadline", wait_ends_at_its_deadline),
    (
        "wait_returns_an_early_message",
        wait_returns_an_early_message,
    ),
    (
        "stale_expiry_does_not_end_a_wait",
        stale_expiry_does_not_end_a_wait,
    ),
    ("wait_leaves_no_timer_armed", wait_leaves_no_timer_armed),
];

/// Init's live handles (PROCESS_HANDLES).
fn live() -> Result<u64, &'static str> {
    sys::process_handles(&own())
        .map(|h| h.live)
        .map_err(|_| "PROCESS_HANDLES of init failed")
}

/// Spec 5.4, 13.2: a handle that goes out of scope closes its entry: init
/// has as many live handles as before the copy, and the copy's value is
/// BAD_HANDLE.
fn dropped_handle_closes() -> Outcome {
    let before = live()?;
    let value = {
        let h = copy(&resource(), Rights::NONE)?;
        h.raw()
    };
    let after = live()?;
    check(after == before, "a handle that went out of scope stayed")?;
    check(
        close_raw(value) == Err(Error::BadHandle),
        "the value of a dropped handle still names a handle",
    )
}

/// Spec 13.2: into_raw leaves the entry open: one live handle more, and a
/// raw close with the value passes.
fn into_raw_keeps_the_handle() -> Outcome {
    let before = live()?;
    let value = copy(&resource(), Rights::NONE)?.into_raw();
    let after = live()?;
    let closed = close_raw(value);
    check(after == before + 1, "into_raw closed the handle")?;
    check(closed.is_ok(), "the value into_raw gave names no handle")
}

/// Spec 13.2: a view of a handle (Handle::borrowed) closes nothing when it
/// goes: a notification through the view comes, and the channel's own
/// handle still works afterwards.
fn borrowed_handle_stays_open() -> Outcome {
    let c = channel(QUIET)?;
    let before = live()?;
    let posted = {
        let view = Handle::<Channel>::borrowed(c.raw());
        sys::notify(&view, 1)
    };
    let after = live()?;
    let heard = take_one(&c);
    let again = sys::notify(&c, 2);
    let heard_again = take_one(&c);
    close(c)?;
    check(after == before, "a view closed its handle")?;
    check(
        posted.is_ok() && heard == Ok(unlabeled(1, 1)),
        "a notification through a view did not come",
    )?;
    check(
        again.is_ok() && heard_again == Ok(unlabeled(2, 1)),
        "the channel's handle did not stay open after its view went",
    )
}

/// Spec 13.2, 13.3: init's first handles come once: `main` took them, and
/// a second call gives none; the handles it gave still work.
fn init_handles_come_once() -> Outcome {
    let again = rt::init_handles();
    let twice = again.is_some();
    // A second set would close init's own handles as it went.
    core::mem::forget(again);
    check(!twice, "init's first handles came a second time")?;
    check(
        sys::process_state(&own()) == Ok(ProcessState::Alive) && sys::thread_info(&me()).is_ok(),
        "init's first handles no longer work",
    )
}

/// Spec 5.4, 6.1: the handles of a message that its receiver did not take
/// close with it. A client above init sends two copies of a channel with
/// NOTIFY and TRANSFER; init takes the first, answers, and lets the
/// message go: the second is BAD_HANDLE, one live handle fewer, and the
/// first notifies.
fn incoming_handles_close_unless_taken() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let rights = Rights::NOTIFY | Rights::TRANSFER;
    give(&[copy_raw(&e, rights)?, copy_raw(&e, rights)?]);
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let (other, _) = rt::msgbuf::handle(1);
    let before = live()?;
    let (taken, replied) = match got {
        Ok(Received::Message {
            mut handles, token, ..
        }) => (handles.take::<Channel>(0), token.reply(&[]).is_ok()),
        _ => (Err(Error::BadState), false),
    };
    let after = live()?;
    let gone = close_raw(other);
    let posted = taken
        .as_ref()
        .map_err(|&e| e)
        .and_then(|h| sys::notify(h, 1));
    let heard = take_one(&e);
    close(t)?;
    if let Ok(h) = taken {
        close(h)?;
    }
    close(c)?;
    close(e)?;
    check(replied && ended(0), "the client did not get the reply")?;
    check(
        after + 1 == before && gone == Err(Error::BadHandle),
        "a handle nobody took stayed open",
    )?;
    check(
        posted.is_ok() && heard == Ok(unlabeled(1, 1)),
        "the handle init took did not work",
    )
}

/// Spec 6.1: a send the kernel refuses gives back the handles it left in
/// the caller's table and keeps those it took. With NO_WAIT and no
/// receiver, WOULD_BLOCK brings both copies back, which still close;
/// through a channel that closed, PEER_CLOSED brings none, and their
/// values are BAD_HANDLE.
fn refused_send_gives_the_handles_back() -> Outcome {
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    let rights = Rights::NOTIFY | Rights::TRANSFER;
    let pair = || -> Result<[Handle<Any>; 2], &'static str> {
        Ok([copy(&e, rights)?.erase(), copy(&e, rights)?.erase()])
    };
    let blocked = sys::try_send_handles(&c, &[], pair()?);
    let back = match blocked {
        Err(Refused {
            error: Error::WouldBlock,
            back: Some(back),
        }) => back.into_iter().all(|h| h.close().is_ok()),
        _ => false,
    };
    let shut = channel(QUIET)?;
    let left = copy(&shut, Rights::SEND)?;
    close(shut)?;
    let sent = pair()?;
    let values = sent.each_ref().map(|h| h.raw());
    let closed = sys::send_handles(&left, &[], sent);
    let taken = matches!(
        closed,
        Err(Refused {
            error: Error::PeerClosed,
            back: None,
        })
    );
    let gone = values
        .iter()
        .all(|&v| close_raw(v) == Err(Error::BadHandle));
    close(left)?;
    close(c)?;
    close(e)?;
    check(back, "WOULD_BLOCK did not give both handles back")?;
    check(
        taken && gone,
        "PEER_CLOSED gave handles back or left them in the table",
    )
}

/// Spec 13.2: `Incoming::take` checks the kind in the info word: a
/// channel taken as a timer is WRONG_TYPE and stays, and taken as a
/// channel it works.
fn take_checks_the_kind() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    give(&[copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?]);
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let mut got = sys::try_receive(&c);
    let (wrong, right) = match &mut got {
        Ok(Received::Message { handles, .. }) => (
            handles.take::<Timer>(0).map(drop),
            handles.take::<Channel>(0),
        ),
        _ => (Ok(()), Err(Error::BadState)),
    };
    let posted = right
        .as_ref()
        .map_err(|&e| e)
        .and_then(|h| sys::notify(h, 1));
    let heard = take_one(&e);
    let replied = answer_all([got]);
    close(t)?;
    if let Ok(h) = right {
        close(h)?;
    }
    close(c)?;
    close(e)?;
    check(
        wrong == Err(Error::WrongType),
        "a channel was taken as a timer",
    )?;
    check(
        posted.is_ok() && heard == Ok(unlabeled(1, 1)),
        "the channel was not there to take after the wrong kind",
    )?;
    check(replied && ended(0), "the client did not get the reply")
}

/// Why a child that panicked ended.
const PANICKED: ProcessState = ProcessState::Exited {
    code: abi::PANIC_EXIT_CODE,
};

/// Spec 5.4: in the strict build of the test images BAD_HANDLE from a
/// typed call panics: a child that notifies through the value of a
/// channel it closed ends with abi::PANIC_EXIT_CODE, and its panic, which
/// xtask finds whole, names notify.
fn strict_child_panics_on_bad_handle() -> Outcome {
    check(
        ran(Role::BadHandle, &[], &[Gift::Debug]) == Ok(PANICKED),
        "a child of the strict build went on after BAD_HANDLE",
    )
}

/// Spec 5.4: the close of a dropped handle panics on BAD_HANDLE as a
/// typed call does: a child that closes a channel and then drops a second
/// handle with its value ends with abi::PANIC_EXIT_CODE, and its panic
/// names handle_close.
fn strict_child_panics_on_a_double_close() -> Outcome {
    check(
        ran(Role::DoubleClose, &[], &[Gift::Debug]) == Ok(PANICKED),
        "a child of the strict build closed a handle twice without a panic",
    )
}

/// Spec 5.4: sys::raw returns BAD_HANDLE in the strict build too: the
/// test init, a strict build itself, closes the value of a handle it
/// closed through a raw call and gets the code in x0 alone.
fn raw_call_returns_bad_handle_in_a_strict_build() -> Outcome {
    const N: u16 = Call::HandleClose.number();
    check(
        cfg!(debug_assertions),
        "the test init is not a strict build",
    )?;
    let gone = closed_handle()?;
    check(
        x0_alone::<N>(&[gone], Error::BadHandle.code()),
        "a raw call with a closed handle did not return BAD_HANDLE in x0 alone",
    )
}

/// The bound of a wait that something else ends first: a thread switch or
/// a message already there takes far less; the bound only ends a test
/// that failed.
const BOUND_NS: u64 = 100_000_000;

/// A waiter on `c`, a channel handle without a label, at init's level.
fn waiter(c: &Handle<Channel>) -> Result<Waiter, &'static str> {
    Waiter::new(c, 0, TEST_PRIORITY).map_err(|_| "Waiter::new failed")
}

/// Waits in receive on a timer of a channel of its own until `deadline`
/// passed; the receive that finds nothing afterwards ends the boost of
/// the expiry (spec 6.6).
fn wait_past(deadline: u64) -> Outcome {
    let c = channel(QUIET)?;
    let t = timer_at(&c, QUIET)?;
    let waited = arm(&t, deadline).map(|()| sys::receive(&c));
    let _ = sys::try_receive(&c);
    close(t)?;
    close(c)?;
    check(
        matches!(waited, Ok(Ok(Received::Notification { .. }))),
        "the wait past a deadline did not end at its timer",
    )
}

/// Spec 10, 15.2 (time): a wait with nothing to take ends with Expired,
/// and the counter has reached the deadline: in nanoseconds of the scale
/// and at the tick where the kernel fires it.
fn wait_ends_at_its_deadline() -> Outcome {
    let c = channel(QUIET)?;
    let w = waiter(&c)?;
    let deadline = clock_now()? + 2_000_000;
    let waited = w.receive_until(&c, deadline);
    let now = time::now();
    let rest = sys::try_receive(&c);
    drop(w);
    close(c)?;
    check(
        waited == Ok(Waited::Expired),
        "the wait did not end at its deadline",
    )?;
    check(
        now >= time::ns_to_ticks(deadline) && time::ticks_to_ns(now) >= deadline,
        "the wait ended before its deadline",
    )?;
    check(
        rest == Err(Error::WouldBlock),
        "something came after the expiry",
    )
}

/// Notifies the channel whose handle HANDLES holds for `slot`, then ends:
/// a thread below init runs once init waits.
extern "C" fn notify_then_end(slot: u64) -> ! {
    let _ = sys::notify(&handle(slot as usize), NOTIFIED);
    ENDED[slot as usize].store(1, Relaxed);
    sys::thread_exit()
}

/// Spec 6.1, 10: what comes before the deadline ends the wait with Got. A
/// thread below init, which runs once init waits, notifies the channel:
/// the notification comes, and once the deadline passed the channel is
/// still empty, since the wait cancelled its timer.
fn wait_returns_an_early_message() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let w = waiter(&c)?;
    let t = spawn(0, notify_then_end, 0, LEVEL, Policy::Fifo)?;
    let deadline = clock_now()? + BOUND_NS;
    let waited = w.receive_until(&c, deadline);
    let passed = wait_past(deadline + 1_000_000);
    let info = sys::channel_info(&c);
    let rest = sys::try_receive(&c);
    close(t)?;
    drop(w);
    close(c)?;
    passed?;
    check(
        waited == Ok(Waited::Got(unlabeled(NOTIFIED, 1))) && ended(0),
        "the notification before the deadline did not end the wait",
    )?;
    check(
        info.is_ok_and(|i| i.queued == 0) && rest == Err(Error::WouldBlock),
        "the timer of a wait that ended early fired",
    )
}

/// Spec 10: an expiry of an earlier wait does not end the next one. The
/// first wait has a deadline that passed and a notification of a slot
/// above the timer's waiting: timer_set fires at once, the notification
/// comes first and ends the wait, and the expiry stays in the slot. The
/// second wait takes that expiry before its own deadline, goes on, and
/// ends at its deadline, STALE_MARGIN_NS on: a host that holds the run up
/// for less between timer_set and receive keeps the stale expiry apart
/// from the deadline.
fn stale_expiry_does_not_end_a_wait() -> Outcome {
    const STALE_MARGIN_NS: u64 = 20_000_000;
    let c = channel(NOTICE)?;
    let w = waiter(&c)?;
    let notified = sys::notify(&c, NOTIFIED);
    let first = w.receive_until(&c, clock_now()?);
    let deadline = clock_now()? + STALE_MARGIN_NS;
    let second = w.receive_until(&c, deadline);
    let now = time::now();
    let rest = sys::try_receive(&c);
    drop(w);
    close(c)?;
    check(
        notified.is_ok() && first == Ok(Waited::Got(unlabeled(NOTIFIED, 1))),
        "the notification did not end the first wait",
    )?;
    check(
        second == Ok(Waited::Expired) && time::ticks_to_ns(now) >= deadline,
        "a stale expiry ended the second wait before its deadline",
    )?;
    check(
        rest == Err(Error::WouldBlock),
        "something came after the expiry",
    )
}

/// Spec 10: a wait leaves no timer armed, whether it ended at its deadline
/// or with a message: after an expiry and then a wait that a notification
/// already there ends, nothing comes into the channel until a third
/// deadline after the second.
fn wait_leaves_no_timer_armed() -> Outcome {
    let c = channel(NOTICE)?;
    let w = waiter(&c)?;
    let expired = w.receive_until(&c, clock_now()? + 1_000_000);
    let notified = sys::notify(&c, NOTIFIED);
    let second = clock_now()? + BOUND_NS;
    let got = w.receive_until(&c, second);
    let passed = wait_past(second + 1_000_000);
    let rest = sys::try_receive(&c);
    drop(w);
    close(c)?;
    passed?;
    check(
        expired == Ok(Waited::Expired),
        "the first wait did not expire",
    )?;
    check(
        notified.is_ok() && got == Ok(Waited::Got(unlabeled(NOTIFIED, 1))),
        "the notification did not end the second wait",
    )?;
    check(
        rest == Err(Error::WouldBlock),
        "a timer stayed armed after a wait",
    )
}
