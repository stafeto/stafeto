// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of the runtime, lib/rt, on top of the calls (spec 5.4, 6.1,
//! 10, 13.2, 13.3): handles that own their entry of the table, the handles
//! of a message, init's first handles, the strict build of the test
//! images, where BAD_HANDLE from a typed call panics, waits with a bound,
//! and the start protocol.

use crate::channels::{take_one, unlabeled};
use crate::harness::*;
use crate::messages::answer_all;
use crate::processes::{Gift, Kid, LEAF_QUOTA, START, ran, spawn_under};
use crate::timers::timer_at;
use crate::transfers::{close_raw, copy_raw, give, handle_client};
use proto_init::{Method, StartReply, VERSION};
use proto_wire::{Header, Name, Status, Writer};
use rt::startup::{Answered, Giver, StartError};
use rt::wait::{Waited, Waiter};

/// The tests of this module, in the order they run.
pub(crate) const TESTS: [Test; 24] = [
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
