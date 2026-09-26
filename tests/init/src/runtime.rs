// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of the runtime, lib/rt, on top of the calls (spec 5.4, 6.1,
//! 10, 13.2, 13.3): handles that own their entry of the table, the handles
//! of a message, init's first handles, the strict build of the test
//! images, where BAD_HANDLE from a typed call panics, waits with a bound,
//! the start protocol, and the loop of a service with its sessions and its
//! heartbeat.

use crate::channels::{take_one, unlabeled};
use crate::harness::*;
use crate::messages::{answer_all, record};
use crate::processes::{Gift, Kid, LEAF_QUOTA, START, kid_mark, ran, reset_kid_marks, spawn_under};
use crate::timers::timer_at;
use crate::transfers::{close_raw, copy_raw, give, handle_client};
use abi::time::next_release;
use child::server;
use proto_init::{Method, StartReply, VERSION};
use proto_wire::{Header, Name, Status, Writer};
use rt::startup::{Answered, Giver, StartError};
use rt::wait::{Waited, Waiter};

/// The tests of this module, in the order they run.
pub(crate) const TESTS: [Test; 33] = [
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
    (
        "startup_brings_process_thread_and_names",
        startup_brings_process_thread_and_names,
    ),
    ("startup_comes_once", startup_comes_once),
    (
        "startup_spans_several_replies",
        startup_spans_several_replies,
    ),
    (
        "startup_refuses_another_version",
        startup_refuses_another_version,
    ),
    (
        "startup_refuses_a_repeated_name",
        startup_refuses_a_repeated_name,
    ),
    ("leftover_start_handles_close", leftover_start_handles_close),
    (
        "spawn_names_start_and_exit_by_one_label",
        spawn_names_start_and_exit_by_one_label,
    ),
    (
        "giver_answers_when_its_reply_fails",
        giver_answers_when_its_reply_fails,
    ),
    (
        "giver_refuses_out_of_layout_and_after_last",
        giver_refuses_out_of_layout_and_after_last,
    ),
    (
        "failed_spawn_leaves_no_handles",
        failed_spawn_leaves_no_handles,
    ),
    (
        "service_frees_a_session_on_client_gone",
        service_frees_a_session_on_client_gone,
    ),
    (
        "service_refuses_past_its_handle_limit_and_goes_on",
        service_refuses_past_its_handle_limit_and_goes_on,
    ),
    (
        "service_refuses_past_its_table_and_goes_on",
        service_refuses_past_its_table_and_goes_on,
    ),
    (
        "issued_objects_are_limited_per_session",
        issued_objects_are_limited_per_session,
    ),
    (
        "service_answers_an_unknown_method",
        service_answers_an_unknown_method,
    ),
    (
        "service_refuses_a_short_request",
        service_refuses_a_short_request,
    ),
    (
        "deferred_reply_is_answered_when_its_session_goes",
        deferred_reply_is_answered_when_its_session_goes,
    ),
    (
        "heartbeats_keep_their_absolute_period",
        heartbeats_keep_their_absolute_period,
    ),
    (
        "busy_handler_stops_the_heartbeat",
        busy_handler_stops_the_heartbeat,
    ),
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
            back: Some(mut back),
            ..
        }) => back.len() == 2 && core::iter::from_fn(|| back.pop()).all(|h| h.close().is_ok()),
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
            ..
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

/// Exited with `code`.
const fn exited(code: u64) -> ProcessState {
    ProcessState::Exited { code }
}

/// Why a child at LEVEL whose start data `give` answers ended: `give` gets
/// the child, whose thread runs, and the start data spawn got ready.
fn started(
    quota: u64,
    give: impl FnOnce(&Kid, Giver) -> Outcome,
) -> Result<ProcessState, &'static str> {
    let kid = Kid::load(quota, 16, LEVEL)?;
    let state = kid
        .start()
        .and_then(|()| kid.giver())
        .and_then(|giver| give(&kid, giver))
        .and_then(|()| kid.end());
    kid.close()?;
    let_run()?;
    state
}

/// Start data of a child without its role's handles: its role's arguments
/// alone.
fn with_args(mut giver: Giver, args: &[u8]) -> Result<Giver, &'static str> {
    giver
        .set_args(args)
        .map_err(|_| "the arguments did not go into the start data")?;
    Ok(giver)
}

/// Answers the next START of `kid` with a reply of its own (proto_init):
/// `handles`, values init holds, under `names`, and `args`, with LAST when
/// `last`.
fn start_reply(
    kid: &Kid,
    names: &[&str],
    handles: &[abi::Handle],
    args: &[u8],
    last: bool,
) -> Outcome {
    let (_, _, token) = kid.ear.start_request()?;
    let mut named = [None; proto_init::START_NAMES];
    for (n, name) in named.iter_mut().zip(names) {
        *n = Some(Name::new(name.as_bytes()).map_err(|_| "not a name")?);
    }
    let mut w = Writer::new();
    StartReply {
        last,
        names: named,
        args,
    }
    .write(&mut w)
    .map_err(|_| "a reply to START out of its layout")?;
    reply_values(token, w.as_bytes(), handles).map_err(|_| "the reply to START failed")
}

/// Spec 13.3: rt::startup brings the child its own process and thread,
/// named `process` and `thread`, and the handles under the other names,
/// each taken once and of its kind (Role::Named, with the system resource
/// and the boot image). Start data without `thread` fail with Missing.
fn startup_brings_process_thread_and_names() -> Outcome {
    let named = ran(Role::Named, &[], &[Gift::Debug, Gift::Image]);
    let threadless = started(LEAF_QUOTA, |kid, _| {
        let mut giver = Giver::new();
        let process = copy(&kid.process, Rights::MANAGE | Rights::TRANSFER)?;
        giver
            .give("process", process.erase())
            .map_err(|_| "the process did not go into the start data")?;
        let giver = with_args(giver, &child::args(Role::Exit, &[0]))?;
        kid.ear.give(giver).map(drop)
    });
    check(
        named == Ok(exited(0)),
        "the start data did not bring the process, the thread and the names",
    )?;
    check(
        threadless == Ok(exited(child::start_failed(StartError::Missing))),
        "start data without the thread did not fail with Missing",
    )
}

/// Spec 13.2, 13.3: the first handles come once. Init, whose first thread
/// started with x0 0, has no start data; a child gets Taken from a second
/// rt::startup and None from rt::init_handles (Role::Once).
fn startup_comes_once() -> Outcome {
    let in_init = rt::startup().map(drop);
    let again = ran(Role::Once, &[], &[]);
    check(in_init == Err(StartError::Taken), "init got start data")?;
    check(
        again == Ok(exited(0)),
        "a child got its start data or init's first handles a second time",
    )
}

/// Spec 13.3: start data of 8 handles and 256 bytes of arguments take two
/// replies, LAST on the second, and the child gets all of them
/// (Role::Spans), from a Giver, which sends the arguments whole with the
/// first reply, and from replies made by hand, which split them into 200
/// and 56 bytes. Arguments of 257 bytes over two replies fail with
/// TooMuch.
fn startup_spans_several_replies() -> Outcome {
    let mut replies = 0;
    let spans = started(LEAF_QUOTA, |kid, mut giver| {
        for name in ["0", "1", "2", "3", "4", "5"] {
            let h = copy(&resource(), Rights::TRANSFER)?;
            giver
                .give(name, h.erase())
                .map_err(|_| "a handle did not go into the start data")?;
        }
        let mut args = [0; rt::startup::ARGS_MAX];
        args[..64].copy_from_slice(&child::args(Role::Spans, &[]));
        for (i, byte) in args.iter_mut().enumerate().skip(64) {
            *byte = i as u8;
        }
        replies = kid.ear.give(with_args(giver, &args)?)?;
        Ok(())
    });
    let split = started(LEAF_QUOTA, |kid, _| {
        let mut args = [0; rt::startup::ARGS_MAX];
        args[..64].copy_from_slice(&child::args(Role::Spans, &[]));
        for (i, byte) in args.iter_mut().enumerate().skip(64) {
            *byte = i as u8;
        }
        let copies = || copy_raw(&resource(), Rights::TRANSFER);
        let first = [
            kid.gift(Gift::Own)?,
            kid.gift(Gift::Thread)?,
            copies()?,
            copies()?,
        ];
        start_reply(
            kid,
            &["process", "thread", "0", "1"],
            &first,
            &args[..200],
            false,
        )?;
        let second = [copies()?, copies()?, copies()?, copies()?];
        start_reply(kid, &["2", "3", "4", "5"], &second, &args[200..], true)
    });
    let too_much = started(LEAF_QUOTA, |kid, _| {
        let own = [kid.gift(Gift::Own)?, kid.gift(Gift::Thread)?];
        start_reply(kid, &["process", "thread"], &own, &[0; 200], false)?;
        start_reply(kid, &[], &[], &[0; 57], true)
    });
    check(
        spans == Ok(exited(0)) && replies == 2,
        "start data of 8 handles and 256 bytes did not come in two replies",
    )?;
    check(
        split == Ok(exited(0)),
        "arguments split over two replies did not come whole",
    )?;
    check(
        too_much == Ok(exited(child::start_failed(StartError::TooMuch))),
        "arguments of 257 bytes did not fail with TooMuch",
    )
}

/// Spec 13.3: a START the parent refuses ends rt::startup with its status:
/// the child of a parent that answers BAD_VERSION ends with the code of
/// Refused(BAD_VERSION).
fn startup_refuses_another_version() -> Outcome {
    let state = started(LEAF_QUOTA, |kid, _| {
        let (_, _, token) = kid.ear.start_request()?;
        token
            .reply(&proto_wire::reply(Status::BadVersion))
            .map_err(|_| "the refusal of START failed")
    });
    check(
        state
            == Ok(exited(child::start_failed(StartError::Refused(
                Status::BadVersion,
            )))),
        "the child did not end with the parent's BAD_VERSION",
    )
}

/// Spec 13.3: a name that comes twice, here in two replies, makes the
/// start data Malformed.
fn startup_refuses_a_repeated_name() -> Outcome {
    let state = started(LEAF_QUOTA, |kid, _| {
        let first = [kid.gift(Gift::Own)?, kid.gift(Gift::Debug)?];
        start_reply(kid, &["process", "twice"], &first, &[], false)?;
        let second = [kid.gift(Gift::Thread)?, kid.gift(Gift::Debug)?];
        start_reply(kid, &["thread", "twice"], &second, &[], true)
    });
    check(
        state == Ok(exited(child::start_failed(StartError::Malformed))),
        "a name that came twice did not fail with Malformed",
    )
}

/// Spec 5.4, 13.3: what the child does not take of its start data closes
/// when the start data go. The child gets a copy of a channel of init with
/// NOTIFY and a label under a name it never asks for, and runs Role::Echo:
/// while its request waits for init's reply, the copy's CLIENT_GONE is
/// there.
fn leftover_start_handles_close() -> Outcome {
    const LEFT: u64 = 0x1EF7;
    let c = channel(QUIET)?;
    let mut gone = Err(Error::WouldBlock);
    let state = started(LEAF_QUOTA, |kid, mut giver| {
        let left = session(&c, Rights::NOTIFY | Rights::TRANSFER, LEFT, QUIET)?;
        giver
            .give("leftover", left.erase())
            .map_err(|_| "the copy did not go into the start data")?;
        kid.ear.give(with_args(
            giver,
            &child::args(Role::Echo, &[0; child::ARGS]),
        )?)?;
        let Received::Message { token, .. } = kid.ear.next()? else {
            return Err("the child did not send its words back");
        };
        gone = sys::try_receive(&c);
        token
            .reply(&0u64.to_le_bytes())
            .map_err(|_| "the reply to the child failed")
    });
    close(c)?;
    check(
        state == Ok(exited(0)),
        "the child that left a handle did not run",
    )?;
    check(
        gone == Ok(labelled(LEFT, CLIENT_GONE, 1)),
        "a handle the child did not take stayed open",
    )
}

/// Spec 13.3, 13.4: one label names a spawned child: its START comes with
/// the label of its spawn, and so does the notification of its end.
fn spawn_names_start_and_exit_by_one_label() -> Outcome {
    let kid = Kid::load(LEAF_QUOTA, 16, LEVEL)?;
    let heard = kid.start().and_then(|()| {
        let Received::Message {
            label,
            len,
            token,
            words,
            ..
        } = kid.ear.next()?
        else {
            return Err("the child sent no START");
        };
        let mut giver = with_args(kid.giver()?, &child::args(Role::Exit, &[0]))?;
        let answered = giver.answer(&abi::inline_bytes(&words)[..len.min(64)], token);
        let end = kid.ear.next()?;
        Ok((label, answered, end))
    });
    let label = kid.label;
    kid.close()?;
    let_run()?;
    let (start, answered, end) = heard?;
    check(
        label == START && start == label && answered == Ok(Answered::Last),
        "the START did not come with the label of the spawn",
    )?;
    check(
        end == crate::channels::exit_notice(label),
        "the notification of the child's end did not come with that label",
    )
}

/// Spec 6.1, 13.3: a reply to START that the kernel refuses before it
/// reaches the request, here for a handle without TRANSFER, still answers
/// the child: the Giver answers the START with the error as its status,
/// and the child ends with the code of Refused(ACCESS_DENIED). The three
/// handles of the reply come back into the Giver, and go when it goes.
fn giver_answers_when_its_reply_fails() -> Outcome {
    let state = started(LEAF_QUOTA, |kid, mut giver| {
        let stuck = copy(&resource(), Rights::NONE)?;
        giver
            .give("stuck", stuck.erase())
            .map_err(|_| "the copy did not go into the start data")?;
        let mut giver = with_args(giver, &child::args(Role::Exit, &[0]))?;
        let (bytes, len, token) = kid.ear.start_request()?;
        let before = live()?;
        let answered = giver.answer(&bytes[..len.min(64)], token);
        let held = live()?;
        drop(giver);
        let after = live()?;
        check(
            answered == Err(Error::AccessDenied),
            "the Giver did not give ACCESS_DENIED back",
        )?;
        check(
            held == before && after + 3 == before,
            "the handles of the reply did not come back into the Giver",
        )
    });
    let refused = StartError::Refused(Status::Kernel(Error::AccessDenied));
    check(
        state == Ok(exited(child::start_failed(refused))),
        "the child did not end with the status of the reply that failed",
    )
}

/// What `ask_giver` sends a Giver in turn: START of version 2, START of 9
/// bytes, a request of method 4, START, and START after LAST.
fn giver_requests() -> [([u8; 9], usize); 5] {
    let start = Method::Start.number();
    let mut long = [0; 9];
    long[..8].copy_from_slice(&Header::new(start, VERSION).bytes());
    let with = |h: Header| {
        let mut b = [0; 9];
        b[..8].copy_from_slice(&h.bytes());
        (b, 8)
    };
    [
        with(Header::new(start, VERSION + 1)),
        (long, 9),
        with(Header::new(Method::Heartbeat.number(), VERSION)),
        with(Header::new(start, VERSION)),
        with(Header::new(start, VERSION)),
    ]
}

/// Sends giver_requests in turn through the channel HANDLES holds for
/// slot 0; `result(0)` gets the status of each reply, or the error code of
/// its send with bit 32, then the thread ends.
extern "C" fn ask_giver(_: u64) -> ! {
    for (i, (bytes, len)) in giver_requests().into_iter().enumerate() {
        let word = match sys::send(&handle(0), &bytes[..len]) {
            Ok(reply) => u64::from(reply.words[0] as u32),
            Err(e) => 1 << 32 | e.code(),
        };
        RESULTS[0][i].store(word, Relaxed);
    }
    ENDED[0].store(1, Relaxed);
    sys::thread_exit()
}

/// Spec 13.3: the parent's side refuses what is out of the layout. A
/// thread of init below it sends a Giver with no handles, through a
/// channel of init, START of version 2, which gets BAD_VERSION, START of 9
/// bytes, BAD_SIZE, a request of method 4, which comes back with its
/// token (the test answers it UNKNOWN_METHOD), START, which gets LAST, and
/// START once more, BAD_STATE. The thread sees the same statuses.
fn giver_refuses_out_of_layout_and_after_last() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let w = waiter(&c)?;
    let mut giver = with_args(Giver::new(), &[7; 8])?;
    let t = spawn(0, ask_giver, 0, LOW, Policy::Fifo)?;
    let mut answers = [0; 5];
    let mut other = false;
    for answer in &mut answers {
        let Ok(Waited::Got(Received::Message {
            len, token, words, ..
        })) = w.receive_until(&c, clock_now()? + BOUND_NS)
        else {
            break;
        };
        *answer = match giver.answer(&abi::inline_bytes(&words)[..len.min(64)], token) {
            Ok(Answered::Refused(status)) => status.code(),
            Ok(Answered::Last) => Status::Ok.code(),
            Ok(Answered::Other { method: 4, token }) => {
                other = true;
                let _ = token.reply(&proto_wire::reply(Status::UnknownMethod));
                Status::UnknownMethod.code()
            }
            _ => u32::MAX,
        };
    }
    let passed = let_run();
    close(t)?;
    drop(w);
    close(c)?;
    passed?;
    let expected = [
        Status::BadVersion,
        Status::BadSize,
        Status::UnknownMethod,
        Status::Ok,
        Status::Kernel(Error::BadState),
    ]
    .map(Status::code);
    check(
        answers == expected && other,
        "the Giver did not refuse another version, another size and a START after LAST",
    )?;
    check(
        ended(0) && result(0)[..5] == expected.map(u64::from),
        "the thread did not get the statuses of the Giver",
    )
}

/// Spec 13.3: a spawn that fails leaves nothing behind. With a quota of
/// one page the load fails with NO_MEMORY; init has as many live handles
/// as before, and the copies of the channel with the spawn's label went:
/// the CLIENT_GONE of their session is there, and nothing else.
fn failed_spawn_leaves_no_handles() -> Outcome {
    let c = channel(QUIET)?;
    let before = live()?;
    let spawned = spawn_under(&c, PAGE as u64, 16, LEVEL, LEVEL)?;
    let after = live()?;
    let gone = sys::try_receive(&c);
    let rest = sys::try_receive(&c);
    close(c)?;
    check(
        matches!(spawned, Err(Error::NoMemory)),
        "a spawn with a quota of one page did not fail with NO_MEMORY",
    )?;
    check(after == before, "a spawn that failed left a handle of init")?;
    check(
        gone == Ok(labelled(START, CLIENT_GONE, 1)) && rest == Err(Error::WouldBlock),
        "a copy of the channel of a spawn that failed stayed",
    )
}

/// The quota of a child that runs the test service (Role::Server,
/// Role::Busy): a page of its pool of timers more, for the timer of its
/// heartbeat.
const SERVER_QUOTA: u64 = LEAF_QUOTA + PAGE as u64;
/// The period of the heartbeats of the tests: QEMU without -icount wakes
/// a thread 1 to 3 ms after its deadline on a quiet host, which a quarter
/// of a period of 20 ms leaves room for.
const PERIOD_NS: u64 = 20_000_000;
/// The status of a refusal past a limit.
const LIMIT: Status = Status::Kernel(Error::LimitReached);

/// A child at LEVEL that runs `role` (child::server) on a new channel,
/// with a heartbeat every `period` nanoseconds (0 for none) and `more`
/// after the channel in its start data; `with` gets the child and a
/// handle to the channel with SEND and DUPLICATE, which makes the
/// sessions of the clients. The child has the channel's only handle with
/// RECEIVE, so each send fails with PEER_CLOSED once the service ended.
/// The child is killed after `with`.
fn serving(
    role: Role,
    period: u64,
    more: Option<Gift>,
    with: impl FnOnce(&Kid, &Handle<Channel>) -> Outcome,
) -> Outcome {
    let c = channel(QUIET)?;
    let maker = copy(&c, Rights::SEND | Rights::DUPLICATE)?;
    let kid = Kid::load(SERVER_QUOTA, 16, LEVEL)?;
    let first = Gift::Given(c.into_raw());
    let gifts = [first, more.unwrap_or(first)];
    let gifts = &gifts[..1 + usize::from(more.is_some())];
    let served = kid
        .start()
        .and_then(|()| kid.serve(role, &[period, LEVEL.into()], gifts))
        .and_then(|()| with(&kid, &maker));
    kid.close()?;
    close(maker)?;
    let_run()?;
    served
}

/// A client of the test service: a copy of `maker` with SEND and the
/// label of client `i`.
fn client(maker: &Handle<Channel>, i: u64) -> Result<Handle<Channel>, &'static str> {
    session(maker, Rights::SEND, 0x5E51 + i, QUIET)
}

/// The status in bytes 0..4 of `word`, the first word of a reply, and the
/// u32 after it.
fn status_of(word: u64) -> (Status, u32) {
    (Status::from_code(word as u32), (word >> 32) as u32)
}

/// The reply to `bytes` through `s` with `handles`: its status and the
/// u32 after it.
fn asked(
    s: &Handle<Channel>,
    bytes: &[u8],
    handles: impl Into<Outgoing>,
) -> Result<(Status, u32), &'static str> {
    let reply =
        sys::send_handles(s, bytes, handles).map_err(|_| "a request to the service failed")?;
    Ok(status_of(reply.words[0]))
}

/// The reply to a request of `method` of the test service, its header
/// alone, through `s`: its status and the u32 after it.
fn ask(s: &Handle<Channel>, method: u16) -> Result<(Status, u32), &'static str> {
    ask_with(s, method, Outgoing::new())
}

/// `ask` with `handles`.
fn ask_with(
    s: &Handle<Channel>,
    method: u16,
    handles: impl Into<Outgoing>,
) -> Result<(Status, u32), &'static str> {
    asked(s, &Header::new(method, server::VERSION).bytes(), handles)
}

/// Spec 5.3, 5.4: CLIENT_GONE ends a session: the handle the service kept
/// for the client closes, and the place of the session is free. The
/// service keeps a copy with a label of a channel of init for the first
/// client, which then closes its only handle: the copy's CLIENT_GONE
/// comes to init, and two more clients fill the table of two.
fn service_frees_a_session_on_client_gone() -> Outcome {
    const KEPT: u64 = 0x6E97;
    serving(Role::Server, 0, None, |_, maker| {
        let e = channel(QUIET)?;
        let w = waiter(&e)?;
        let first = client(maker, 0)?;
        let kept = session(&e, Rights::NOTIFY | Rights::TRANSFER, KEPT, QUIET)?;
        let keep = ask_with(&first, server::KEEP, [kept.erase()])?;
        close(first)?;
        let heard = w.receive_until(&e, clock_now()? + BOUND_NS);
        let after = [
            ask(&client(maker, 1)?, server::SESSIONS)?,
            ask(&client(maker, 2)?, server::SESSIONS)?,
        ];
        check(keep.0 == Status::Ok, "the service did not keep the handle")?;
        check(
            heard == Ok(Waited::Got(labelled(KEPT, CLIENT_GONE, 1))),
            "the handle the service kept stayed open after its client went",
        )?;
        check(
            after == [(Status::Ok, 1), (Status::Ok, 2)],
            "the session of the client that went kept its place",
        )
    })
}

/// Spec 5.4: a session holds at most HELD handles: past them the client
/// gets LIMIT_REACHED, and the service goes on. The test service keeps
/// two copies of the system resource, the third gets LIMIT_REACHED, and
/// the next request is answered.
fn service_refuses_past_its_handle_limit_and_goes_on() -> Outcome {
    serving(Role::Server, 0, None, |_, maker| {
        let c = client(maker, 0)?;
        let mut kept = [Status::Ok; server::HELD + 1];
        for k in &mut kept {
            let h = copy(&resource(), Rights::TRANSFER)?;
            *k = ask_with(&c, server::KEEP, [h.erase()])?.0;
        }
        let after = ask(&c, server::SESSIONS);
        check(
            kept == [Status::Ok, Status::Ok, LIMIT],
            "the limit of handles of a session did not hold",
        )?;
        check(
            after == Ok((Status::Ok, 1)),
            "the service did not go on after a refusal",
        )
    })
}

/// Spec 5.4: the table of sessions has a fixed size: a client past it
/// gets LIMIT_REACHED, the service goes on, and no session gives its
/// place. The test service has two; the third client is refused, and
/// the first is still served in its session.
fn service_refuses_past_its_table_and_goes_on() -> Outcome {
    serving(Role::Server, 0, None, |_, maker| {
        let clients = [client(maker, 0)?, client(maker, 1)?, client(maker, 2)?];
        let asked = [0, 1, 2, 0].map(|i| ask(&clients[i], server::SESSIONS));
        check(
            asked[..2] == [Ok((Status::Ok, 1)), Ok((Status::Ok, 2))],
            "two clients did not get a session each",
        )?;
        check(
            matches!(asked[2], Ok((LIMIT, _))),
            "a client past the table got a session",
        )?;
        check(
            asked[3] == Ok((Status::Ok, 2)),
            "the service did not go on, or a session gave its place",
        )
    })
}

/// Spec 5.4: a session gets at most ISSUED objects, and one that comes
/// back makes room: the third ISSUE of a client gets LIMIT_REACHED, the
/// next after RETURN passes, and another client has a count of its own.
fn issued_objects_are_limited_per_session() -> Outcome {
    use server::{ISSUE, RETURN};
    serving(Role::Server, 0, None, |_, maker| {
        let (first, second) = (client(maker, 0)?, client(maker, 1)?);
        let asked = [ISSUE, ISSUE, ISSUE, RETURN, ISSUE].map(|m| ask(&first, m).map(|a| a.0));
        let other = ask(&second, ISSUE);
        check(
            asked
                == [
                    Ok(Status::Ok),
                    Ok(Status::Ok),
                    Ok(LIMIT),
                    Ok(Status::Ok),
                    Ok(Status::Ok),
                ],
            "the objects given to a session were not limited",
        )?;
        check(
            other == Ok((Status::Ok, 0)),
            "a client got the count of another",
        )
    })
}

/// Spec 13.8: a request of a method the service does not have gets
/// UNKNOWN_METHOD, one of another version BAD_VERSION, and the service
/// goes on.
fn service_answers_an_unknown_method() -> Outcome {
    serving(Role::Server, 0, None, |_, maker| {
        let c = client(maker, 0)?;
        let unknown = Header::new(99, server::VERSION).bytes();
        let other = Header::new(server::SESSIONS, server::VERSION + 1).bytes();
        let refused = [unknown, other].map(|b| asked(&c, &b, Outgoing::new()).map(|a| a.0));
        let after = ask(&c, server::SESSIONS);
        check(
            refused == [Ok(Status::UnknownMethod), Ok(Status::BadVersion)],
            "an unknown method or another version was not refused",
        )?;
        check(
            after == Ok((Status::Ok, 1)),
            "the service did not go on after a refusal",
        )
    })
}

/// Spec 13.8: a request shorter than its header, one whose header has
/// bytes 4..8 other than zero, and one longer than its method takes get
/// BAD_SIZE, and the service goes on.
fn service_refuses_a_short_request() -> Outcome {
    serving(Role::Server, 0, None, |_, maker| {
        let c = client(maker, 0)?;
        let header = Header::new(server::SESSIONS, server::VERSION).bytes();
        let mut dirty = header;
        dirty[7] = 1;
        let mut long = [0; 12];
        long[..8].copy_from_slice(&header);
        let sizes =
            [&header[..4], &dirty, &long].map(|b| asked(&c, b, Outgoing::new()).map(|a| a.0));
        let after = ask(&c, server::SESSIONS);
        check(
            sizes == [Ok(Status::BadSize); 3],
            "a request of the wrong size was not refused with BAD_SIZE",
        )?;
        check(
            after == Ok((Status::Ok, 1)),
            "the service did not go on after a refusal",
        )
    })
}

/// The method a `service_client` asks for.
static ASKED: AtomicU64 = AtomicU64::new(0);

/// A client of the test service in `slot`: sends the header of the
/// method in ASKED through the handle HANDLES holds for `slot`; `result`
/// gives the code of the send, 0 when it passed, and the reply's first
/// word. Then notifies the channel HANDLES holds for the next slot, if it
/// holds one, and ends.
extern "C" fn service_client(slot: u64) -> ! {
    let s = slot as usize;
    let header = Header::new(ASKED.load(Relaxed) as u16, server::VERSION).bytes();
    match sys::send(&handle(s), &header) {
        Ok(reply) => record(s, &[0, reply.words[0]]),
        Err(e) => record(s, &[e.code()]),
    }
    ENDED[s].store(1, Relaxed);
    if HANDLES[s + 1].load(Relaxed) != 0 {
        let _ = sys::notify(&handle(s + 1), NOTIFIED);
    }
    sys::thread_exit()
}

/// Spec 6.8, 13.2: a reply the service deferred gets PEER_CLOSED when its
/// session goes. A thread of init above the child sends DEFER through the
/// only handle of a client, which init then closes: the request the
/// service took holds no copy, its CLIENT_GONE comes after the request,
/// and the reply the session held tells the thread PEER_CLOSED.
fn deferred_reply_is_answered_when_its_session_goes() -> Outcome {
    reset_results();
    let done = channel(QUIET)?;
    let served = serving(Role::Server, 0, None, |_, maker| {
        let c = client(maker, 0)?;
        HANDLES[0].store(c.raw().0, Relaxed);
        HANDLES[1].store(done.raw().0, Relaxed);
        ASKED.store(server::DEFER.into(), Relaxed);
        let w = waiter(&done)?;
        let t = spawn(0, service_client, 0, HIGH, Policy::Fifo)?;
        close(c)?;
        let heard = w.receive_until(&done, clock_now()? + BOUND_NS);
        close(t)?;
        check(
            heard == Ok(Waited::Got(unlabeled(NOTIFIED, 1))) && ended(0),
            "the deferred request was not answered when its session went",
        )?;
        let [code, word, ..] = result(0);
        check(
            code == 0 && status_of(word) == (Status::Kernel(Error::PeerClosed), 0),
            "the deferred request was not answered with PEER_CLOSED",
        )
    });
    close(done)?;
    served
}

/// The next request of `kid`, which must be HEARTBEAT (proto_init): the
/// clock when it came, and its token.
fn heartbeat(kid: &Kid) -> Result<(u64, Token), &'static str> {
    let beat = Method::Heartbeat.header().bytes();
    match kid.ear.next()? {
        Received::Message {
            label: START,
            len,
            token,
            words,
            ..
        } if abi::inline_bytes(&words)[..len.min(64)] == beat[..] => Ok((clock_now()?, token)),
        _ => Err("the service sent no HEARTBEAT"),
    }
}

/// Answers a HEARTBEAT.
fn beat_back(token: Token) -> Outcome {
    token
        .reply(&proto_wire::reply(Status::Ok))
        .map_err(|_| "the reply to HEARTBEAT failed")
}

/// The HEARTBEAT that waits on the channel of `kid` now, past the
/// CLIENT_GONE of copies and the late expiries of its `Ear`: its token.
fn heartbeat_now(kid: &Kid) -> Result<Token, &'static str> {
    let beat = Method::Heartbeat.header().bytes();
    loop {
        match kid.ear.now() {
            Ok(Received::Notification {
                source: Source::Timer,
                ..
            }) => continue,
            Ok(Received::Message {
                label: START,
                len,
                token,
                words,
                ..
            }) if abi::inline_bytes(&words)[..len.min(64)] == beat[..] => return Ok(token),
            _ => return Err("a heartbeat did not come by its absolute deadline"),
        }
    }
}

/// Spec 10, 13.4: the heartbeat keeps its absolute period, t0 + k·T with
/// t0 the clock the child marked before its loop, and the check goes by
/// the order of events alone. Init answers each HEARTBEAT three quarters
/// of a period past the last deadline, then waits until half a period
/// past the deadline after its reply (next_release) and takes the next
/// HEARTBEAT, which must be there. Init waits on a timer whose slot is at
/// 1, below the child: when the host holds the run up and both deadlines
/// pass at once, the child still sends first, so a late host fails
/// nothing. A heartbeat armed from the reply (now + T) would come a
/// quarter of a period after that check.
fn heartbeats_keep_their_absolute_period() -> Outcome {
    const BEATS: usize = 8;
    serving(Role::Server, PERIOD_NS, None, |kid, _| {
        let pause = channel(QUIET)?;
        let w = Waiter::new(&pause, 0, 1).map_err(|_| "Waiter::new failed")?;
        let wait_until = |at: u64| match w.receive_until(&pause, at) {
            Ok(Waited::Expired) => Ok(()),
            _ => Err("a pause of the test did not end at its deadline"),
        };
        let (_, mut token) = heartbeat(kid)?;
        let t0 = kid_mark(child::SERVED_AT);
        for _ in 0..BEATS {
            let last = next_release(t0, PERIOD_NS, clock_now()?) - PERIOD_NS;
            wait_until(last + PERIOD_NS * 3 / 4)?;
            beat_back(token)?;
            let due = next_release(t0, PERIOD_NS, clock_now()?);
            wait_until(due + PERIOD_NS / 2)?;
            token = heartbeat_now(kid)?;
        }
        beat_back(token)
    })
}

/// Spec 13.4: the heartbeat goes from the thread that serves requests, so
/// a handler that hangs stops it. A thread of init below the child sends
/// BUSY once init waits: while the handler spins, no HEARTBEAT comes for
/// three periods; once a notification lets the handler end, the
/// heartbeat comes back. Init waits on a timer at its own level, which
/// wakes it above the handler that spins.
fn busy_handler_stops_the_heartbeat() -> Outcome {
    reset_results();
    reset_kid_marks();
    let spin = channel(QUIET)?;
    let gift = Gift::Given(copy_raw(&spin, Rights::RECEIVE | Rights::TRANSFER)?);
    let served = serving(Role::Busy, PERIOD_NS, Some(gift), |kid, maker| {
        beat_back(heartbeat(kid)?.1)?;
        let c = client(maker, 0)?;
        HANDLES[0].store(c.raw().0, Relaxed);
        ASKED.store(server::BUSY.into(), Relaxed);
        let pause = channel(QUIET)?;
        let w = waiter(&pause)?;
        let t = spawn(0, service_client, 0, LOW, Policy::Fifo)?;
        let paused = w.receive_until(&pause, clock_now()? + 3 * PERIOD_NS);
        let silent = kid.ear.now() == Err(Error::WouldBlock);
        let spinning = kid_mark(child::SPINS);
        let notified = sys::notify(&spin, 1);
        let back = heartbeat(kid).and_then(|(_, token)| beat_back(token));
        close(t)?;
        check(
            paused == Ok(Waited::Expired) && silent && spinning == 1,
            "a heartbeat came while the handler was busy",
        )?;
        check(
            notified.is_ok() && back.is_ok(),
            "the heartbeat did not come back after the handler",
        )
    });
    close(spin)?;
    served?;
    check(
        ended(0) && result(0)[..2] == [0, 0],
        "the busy handler did not answer",
    )
}
