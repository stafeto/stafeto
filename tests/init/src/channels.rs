// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of channels, notifications, copies of handles and sessions, and
//! of the exit and start channels of children (spec 5, 6.5, 6.8, 13.3).

use crate::harness::*;
use crate::processes::caller_ceiling;

/// The tests of this module, in the order they run.
pub(crate) const TESTS: [Test; 26] = [
    (
        "channel_create_checks_its_priority",
        channel_create_checks_its_priority,
    ),
    (
        "notify_and_receive_need_their_rights",
        notify_and_receive_need_their_rights,
    ),
    (
        "notifications_merge_bits_and_count",
        notifications_merge_bits_and_count,
    ),
    ("notify_refuses_bit_63", notify_refuses_bit_63),
    (
        "receive_without_waiting_is_would_block",
        receive_without_waiting_is_would_block,
    ),
    (
        "notification_runs_at_its_priority",
        notification_runs_at_its_priority,
    ),
    (
        "boost_ends_at_the_next_receive",
        boost_ends_at_the_next_receive,
    ),
    (
        "waiting_receiver_gets_peer_closed",
        waiting_receiver_gets_peer_closed,
    ),
    ("duplicate_narrows_rights", duplicate_narrows_rights),
    (
        "handle_duplicate_checks_its_arguments",
        handle_duplicate_checks_its_arguments,
    ),
    (
        "client_gone_after_the_last_copy",
        client_gone_after_the_last_copy,
    ),
    ("label_cannot_change", label_cannot_change),
    (
        "session_priority_under_the_ceiling",
        session_priority_under_the_ceiling,
    ),
    (
        "session_notice_carries_its_label",
        session_notice_carries_its_label,
    ),
    (
        "higher_notification_comes_first",
        higher_notification_comes_first,
    ),
    (
        "notify_after_close_is_peer_closed",
        notify_after_close_is_peer_closed,
    ),
    ("slot_limit_is_1024", slot_limit_is_1024),
    (
        "sources_give_their_slots_back",
        sources_give_their_slots_back,
    ),
    (
        "exit_notice_comes_after_the_quota",
        exit_notice_comes_after_the_quota,
    ),
    (
        "exit_notice_carries_the_label",
        exit_notice_carries_the_label,
    ),
    ("exit_channel_needs_notify", exit_channel_needs_notify),
    (
        "exit_priority_under_the_ceiling",
        exit_priority_under_the_ceiling,
    ),
    (
        "start_channel_moves_into_the_child",
        start_channel_moves_into_the_child,
    ),
    ("start_channel_needs_transfer", start_channel_needs_transfer),
    (
        "start_handle_must_be_a_channel",
        start_handle_must_be_a_channel,
    ),
    (
        "client_gone_when_the_child_dies",
        client_gone_when_the_child_dies,
    ),
];

/// notify with raw registers.
fn raw_notify(x: Regs) -> Regs {
    // SAFETY: notify only reads its registers.
    unsafe { sys::raw::<{ Call::Notify.number() }>(x) }
}

/// receive with raw registers, for calls that must fail and change x0
/// alone.
fn raw_receive(x: Regs) -> Regs {
    // SAFETY: receive only reads its registers, and writes x10 and x11,
    // which `raw` gives up, only when it takes something.
    unsafe { sys::raw::<{ Call::Receive.number() }>(x) }
}

/// A notification of the slot of label 0.
pub(crate) fn unlabeled(bits: u64, count: u32) -> Received {
    Received::Notification {
        source: Source::Unlabeled,
        label: 0,
        bits,
        count,
    }
}

/// What `c` has, taken without waiting; then a second receive, which
/// finds nothing, ends the boost the first one gave init (spec 6.6).
pub(crate) fn take_one(c: &Handle<Channel>) -> Result<Received, &'static str> {
    let got = sys::try_receive(c);
    let rest = sys::try_receive(c);
    check(
        rest == Err(Error::WouldBlock),
        "a second receive found something",
    )?;
    got.map_err(|_| "receive found nothing")
}

/// channel_create takes a priority of 1-63 with no bits above its byte
/// (spec 11): anything else fails with INVALID_ARGS and changes x0 alone.
/// Init may take any priority under its ceiling of 63; the handle carries
/// NOTIFY and RECEIVE, and a notification goes through it and comes back.
/// A priority above the caller's ceiling fails with ACCESS_DENIED alone:
/// 31 in a child under ceiling 30 (`caller_ceiling`).
fn channel_create_checks_its_priority() -> Outcome {
    for priority in [0, abi::PRIORITY_LEVELS.into(), 0x100 | u64::from(LEVEL)] {
        let mut x = marked();
        x[0] = priority;
        // SAFETY: channel_create only reads its registers.
        let after = unsafe { sys::raw::<{ Call::CreateChannel.number() }>(x) };
        check(
            after[0] == Error::InvalidArgs.code() && after[1..] == x[1..],
            "a priority outside 1-63 did not fail with INVALID_ARGS alone",
        )?;
    }
    close(channel(abi::PRIORITY_LEVELS - 1)?)?;
    let c = channel(QUIET)?;
    let posted = sys::notify(&c, 1);
    let got = take_one(&c);
    close(c)?;
    check(
        posted.is_ok() && got == Ok(unlabeled(1, 1)),
        "a new channel did not carry a notification",
    )?;
    caller_ceiling(Checked::CreateChannel)
}

/// notify and receive take a channel (spec 11): a process is WRONG_TYPE,
/// a closed handle BAD_HANDLE, and x0 alone changes. A copy of the channel
/// with RECEIVE alone does not notify, and one with NOTIFY alone does not
/// receive: ACCESS_DENIED, and x0 alone changes.
fn notify_and_receive_need_their_rights() -> Outcome {
    let c = channel(QUIET)?;
    let gone = c.raw();
    close(c)?;
    for (h, error) in [
        (init::PROCESS.raw(), Error::WrongType),
        (gone, Error::BadHandle),
    ] {
        let mut x = marked();
        x[..2].copy_from_slice(&[h.0, 1]);
        let after = raw_notify(x);
        check(
            after[0] == error.code() && after[1..] == x[1..],
            "notify took a handle that is not a live channel",
        )?;
        x[1] = abi::NO_WAIT;
        let after = raw_receive(x);
        check(
            after[0] == error.code() && after[1..] == x[1..],
            "receive took a handle that is not a live channel",
        )?;
    }
    let c = channel(QUIET)?;
    let (notify_only, receive_only) = (copy(&c, Rights::NOTIFY)?, copy(&c, Rights::RECEIVE)?);
    let mut x = marked();
    x[..2].copy_from_slice(&[receive_only.raw().0, 1]);
    let notified = raw_notify(x);
    let mut y = marked();
    y[..2].copy_from_slice(&[notify_only.raw().0, abi::NO_WAIT]);
    let received = raw_receive(y);
    close(notify_only)?;
    close(receive_only)?;
    close(c)?;
    check(
        notified[0] == Error::AccessDenied.code() && notified[1..] == x[1..],
        "a copy without NOTIFY notified",
    )?;
    check(
        received[0] == Error::AccessDenied.code() && received[1..] == y[1..],
        "a copy without RECEIVE received",
    )
}

/// Spec 15.2 (notifications): three notify calls with different bits before
/// a receive come as one notification of the slot of label 0: the bits
/// ORed, the count 3, and receive writes 0 as the label and the token in
/// x10 and x11, whatever they held (spec 11). The slot is empty
/// afterwards.
fn notifications_merge_bits_and_count() -> Outcome {
    let c = channel(QUIET)?;
    let posted = [0b001, 0b100, 0b100 | 1 << 40]
        .into_iter()
        .try_for_each(|bits| sys::notify(&c, bits));
    let got = receive_x0_to_x11(c.raw(), 0x5A, 0x5B);
    let rest = sys::try_receive(&c);
    close(c)?;
    check(posted.is_ok(), "notify failed")?;
    let merged = abi::Notification {
        source: Source::Unlabeled,
        label: 0,
        bits: 0b101 | 1 << 40,
        count: 3,
    };
    check(
        got[0] == 0 && got[1..] == merged.to_words(),
        "the bits did not merge, the count is not 3, or x10 and x11 are not 0",
    )?;
    check(
        rest == Err(Error::WouldBlock),
        "a second receive found something",
    )
}

/// receive with NO_WAIT through `h`, with `x10` and `x11` in x10 and x11:
/// x0-x11 as the kernel left them (spec 11).
fn receive_x0_to_x11(h: abi::Handle, x10: u64, x11: u64) -> [u64; 12] {
    let mut x = [0; 12];
    x[..2].copy_from_slice(&[h.0, abi::NO_WAIT]);
    x[10..].copy_from_slice(&[x10, x11]);
    // SAFETY: receive uses no memory of the program and changes x0-x11
    // only.
    unsafe {
        core::arch::asm!(
            "svc #{n}",
            n = const Call::Receive.number(),
            inout("x0") x[0],
            inout("x1") x[1],
            inout("x2") x[2],
            inout("x3") x[3],
            inout("x4") x[4],
            inout("x5") x[5],
            inout("x6") x[6],
            inout("x7") x[7],
            inout("x8") x[8],
            inout("x9") x[9],
            inout("x10") x[10],
            inout("x11") x[11],
            options(nostack),
        )
    };
    x
}

/// Bit 63 is CLIENT_GONE, which only the kernel posts (spec 5.3, 6.5):
/// notify with it fails with INVALID_ARGS before the handle is looked at,
/// changes x0 alone and posts nothing. notify with no bits counts.
fn notify_refuses_bit_63() -> Outcome {
    let c = channel(QUIET)?;
    let mut x = marked();
    x[..2].copy_from_slice(&[c.raw().0, 1 << 63 | 1]);
    let after = raw_notify(x);
    let mut bad = x;
    bad[0] = 0;
    let first = raw_notify(bad)[0];
    let nothing = sys::try_receive(&c);
    let posted = sys::notify(&c, 0);
    let got = take_one(&c);
    close(c)?;
    check(
        after[0] == Error::InvalidArgs.code() && after[1..] == x[1..],
        "bit 63 did not fail with INVALID_ARGS alone",
    )?;
    check(
        first == Error::InvalidArgs.code(),
        "the handle was looked at before the bits",
    )?;
    check(
        nothing == Err(Error::WouldBlock),
        "a notify that failed posted",
    )?;
    check(
        posted.is_ok() && got == Ok(unlabeled(0, 1)),
        "a notify with no bits did not count",
    )
}

/// Spec 15.2 (refusals): receive with NO_WAIT on an empty channel fails
/// with WOULD_BLOCK and changes x0 alone; flags other than NO_WAIT are
/// INVALID_ARGS, before the handle is looked at.
fn receive_without_waiting_is_would_block() -> Outcome {
    let c = channel(QUIET)?;
    let mut x = marked();
    x[..2].copy_from_slice(&[c.raw().0, abi::NO_WAIT]);
    let after = raw_receive(x);
    let odd: [Regs; 3] = [abi::NO_WAIT | 1, 1 << 17, 1 << 63].map(|flags| {
        let mut y = x;
        y[..2].copy_from_slice(&[0, flags]);
        raw_receive(y)
    });
    let typed = sys::try_receive(&c);
    close(c)?;
    check(
        after[0] == Error::WouldBlock.code() && after[1..] == x[1..],
        "receive with NO_WAIT on an empty channel did not fail with WOULD_BLOCK alone",
    )?;
    check(
        odd.iter().all(|r| r[0] == Error::InvalidArgs.code()),
        "a flag other than NO_WAIT was taken",
    )?;
    check(
        typed == Err(Error::WouldBlock),
        "try_receive did not fail with WOULD_BLOCK",
    )
}

/// A thread of init that waits in receive on the channel `h`, takes one
/// thing and leaves in mark 0 the result's error code, or 1 and in mark 2
/// what mark 1 held then; then asks again without waiting and leaves 1 in
/// mark 3 when that found nothing (WOULD_BLOCK). Ends afterwards.
extern "C" fn receive_twice(h: u64) -> ! {
    let c = Handle::<Channel>::from_raw(abi::Handle(h));
    match sys::receive(&c) {
        Ok(_) => {
            MARKS[2].store(mark(1), Relaxed);
            MARKS[0].store(1, Relaxed);
        }
        Err(e) => MARKS[0].store(e.code(), Relaxed),
    }
    if sys::try_receive(&c) == Err(Error::WouldBlock) {
        MARKS[3].store(1, Relaxed);
    }
    sys::thread_exit()
}

/// A receiver of init at LOW waiting on a new channel whose slot of label
/// 0 has `priority`: init lets it run until it waits.
fn waiting_receiver(priority: u8) -> Result<(Handle<Channel>, Handle<Thread>), &'static str> {
    reset_marks();
    let c = channel(priority)?;
    let r = spawn(0, receive_twice, c.raw().0, LOW, Policy::Fifo)?;
    let_run()?;
    Ok((c, r))
}

/// Spec 15.2 (notifications): a receiver at base priority 5 waits, and a
/// thread at init's level 20 is ready behind init. A notification of
/// priority 25 wakes the receiver at 25 (spec 6.6): it runs before notify
/// returns, ahead of the ready thread, which has not run by then.
fn notification_runs_at_its_priority() -> Outcome {
    let (c, r) = waiting_receiver(NOTICE)?;
    let peer = spawn(1, add_mark, 1, TEST_PRIORITY, Policy::Fifo)?;
    let waited = mark(0);
    let posted = sys::notify(&c, 1);
    let (ran, peer_before) = (mark(0), mark(2));
    let_run()?;
    let peer_after = mark(1);
    close(peer)?;
    close(r)?;
    close(c)?;
    check(waited == 0, "the receiver did not wait")?;
    check(
        posted.is_ok() && ran == 1,
        "the receiver did not run at the notification's priority before notify returned",
    )?;
    check(
        peer_before == 0 && peer_after == 1,
        "the thread at init's level ran before the notified receiver",
    )
}

/// The boost lasts until the receiver's next receive (spec 6.6): woken at
/// 25 as above, the receiver asks again at once without waiting, which
/// drops it to its base of 5, below init: init runs again before the
/// receiver gets past that receive.
fn boost_ends_at_the_next_receive() -> Outcome {
    let (c, r) = waiting_receiver(NOTICE)?;
    let posted = sys::notify(&c, 1);
    let (first, second) = (mark(0), mark(3));
    let_run()?;
    let later = mark(3);
    close(r)?;
    close(c)?;
    check(
        posted.is_ok() && first == 1,
        "the notification did not wake the receiver above init",
    )?;
    check(
        second == 0,
        "the receiver kept the notification's priority past its next receive",
    )?;
    check(
        later == 1,
        "the receiver's second receive did not find the channel empty",
    )
}

/// Spec 15.2 (refusals): a receiver waits; init closes the only handle with
/// RECEIVE, which closes the channel (spec 6.8): the receiver wakes with
/// PEER_CLOSED.
fn waiting_receiver_gets_peer_closed() -> Outcome {
    let (c, r) = waiting_receiver(LEVEL)?;
    let waited = mark(0);
    close(c)?;
    let_run()?;
    close(r)?;
    check(waited == 0, "the receiver did not wait")?;
    check(
        mark(0) == Error::PeerClosed.code(),
        "the waiting receiver did not get PEER_CLOSED",
    )
}

/// handle_duplicate with raw registers.
fn raw_duplicate(x: Regs) -> Regs {
    // SAFETY: handle_duplicate only reads its registers.
    unsafe { sys::raw::<{ Call::HandleDuplicate.number() }>(x) }
}

/// x0-x9 for handle_duplicate of `h` with `rights`, `label` and
/// `priority`, the rest marked.
fn duplicate_regs(h: abi::Handle, rights: Rights, label: u64, priority: u64) -> Regs {
    let mut x = marked();
    x[..4].copy_from_slice(&[h.0, rights.0.into(), label, priority]);
    x
}

/// handle_duplicate copies a handle of any kind with a subset of its
/// rights (spec 5.2, 11) and changes x0 and x1 alone: a copy of a channel
/// with NOTIFY alone notifies, does not receive (ACCESS_DENIED) and, with
/// no DUPLICATE, is copied no further. A right the original lacks fails
/// with ACCESS_DENIED, bits no right has with INVALID_ARGS before the
/// handle is looked at, and both change x0 alone. A copy of init's process
/// with no rights names it still.
fn duplicate_narrows_rights() -> Outcome {
    let c = channel(QUIET)?;
    let x = duplicate_regs(c.raw(), Rights::NOTIFY, 0, 0);
    let after = raw_duplicate(x);
    let made = after[0] == 0 && after[1] != 0 && after[2..] == x[2..];
    let n = Handle::<Channel>::from_raw(abi::Handle(after[1]));
    let posted = sys::notify(&n, 1);
    let refused = sys::try_receive(&n);
    let further = sys::handle_duplicate(&n, Rights::NOTIFY);
    let got = take_one(&c);
    let y = duplicate_regs(c.raw(), CHANNEL_RIGHTS | Rights::MANAGE, 0, 0);
    let wider = raw_duplicate(y);
    let odd = [1 << 12, 1 << 32].map(|rights| {
        let mut z = x;
        z[..2].copy_from_slice(&[0, rights]);
        let after = raw_duplicate(z);
        after[0] == Error::InvalidArgs.code() && after[1..] == z[1..]
    });
    let own = copy(&init::PROCESS, Rights::NONE)?;
    let state = sys::process_state(&own);
    close(own)?;
    close(n)?;
    close(c)?;
    check(made, "the copy did not come in x1 alone")?;
    check(
        posted.is_ok() && got == Ok(unlabeled(1, 1)),
        "the copy with NOTIFY did not notify",
    )?;
    check(
        refused == Err(Error::AccessDenied),
        "the copy with NOTIFY alone received",
    )?;
    check(
        further == Err(Error::AccessDenied),
        "a copy without DUPLICATE was copied",
    )?;
    check(
        wider[0] == Error::AccessDenied.code() && wider[1..] == y[1..],
        "a copy took a right the original lacks",
    )?;
    check(
        odd.iter().all(|&ok| ok),
        "bits no right has did not fail with INVALID_ARGS alone",
    )?;
    check(
        state == Ok(ProcessState::Alive),
        "a copy of init's process with no rights does not name it",
    )
}

/// handle_duplicate(x0 handle, x1 rights, x2 label, x3 priority) checks
/// its values first, then the handle, whether a label goes on it, then its
/// rights (spec 5.3, 11), and changes x0 alone on an error: a priority
/// without a label, a label without a priority and a priority outside
/// 1-63 or with bits past its byte fail with INVALID_ARGS through a closed
/// handle too; a closed handle and handle 0 fail with BAD_HANDLE; a label
/// on what is no channel fails with WRONG_TYPE, a copy without DUPLICATE
/// of init's process too; a label on a channel copy without DUPLICATE
/// fails with ACCESS_DENIED. Rights no right has and rights the original
/// lacks are duplicate_narrows_rights. The priority of a label above the
/// caller's own ceiling fails with ACCESS_DENIED alone after the handle and
/// before whether a label goes on it: 31 in a child under ceiling 30
/// (`caller_ceiling`).
fn handle_duplicate_checks_its_arguments() -> Outcome {
    let gone = closed_handle()?;
    let c = channel(QUIET)?;
    let notify_only = copy(&c, Rights::NOTIFY)?;
    let own = copy(&init::PROCESS, Rights::NONE)?;
    let result = duplicate_cases(gone, notify_only.raw().0, own.raw().0);
    close(own)?;
    close(notify_only)?;
    close(c)?;
    result.and_then(|()| caller_ceiling(Checked::Label))
}

fn duplicate_cases(gone: u64, notify_only: u64, own: u64) -> Outcome {
    const N: u16 = Call::HandleDuplicate.number();
    let notify = u64::from(Rights::NOTIFY.0);
    let values = [[0, 0, 5], [0, 7, 0], [0, 7, 64], [0, 7, 0x100 | 5]]
        .into_iter()
        .all(|[rights, label, priority]| {
            x0_alone::<N>(&[gone, rights, label, priority], Error::InvalidArgs.code())
        });
    let handles = x0_alone::<N>(&[gone, 0, 0, 0], Error::BadHandle.code())
        && x0_alone::<N>(&[0, 0, 7, 5], Error::BadHandle.code());
    let kinds = [init::RESOURCE.raw().0, own]
        .into_iter()
        .all(|h| x0_alone::<N>(&[h, 0, 7, 5], Error::WrongType.code()));
    let right = x0_alone::<N>(&[notify_only, notify, 7, 5], Error::AccessDenied.code());
    check(
        values,
        "a bad label or priority did not fail with INVALID_ARGS alone before the handle",
    )?;
    check(
        handles,
        "a closed handle or handle 0 did not fail with BAD_HANDLE alone",
    )?;
    check(
        kinds,
        "a label on what is no channel did not fail with WRONG_TYPE alone before the rights",
    )?;
    check(
        right,
        "a label on a copy without DUPLICATE did not fail with ACCESS_DENIED alone",
    )
}

/// A label goes on a channel handle once (spec 5.3): a new label on a
/// handle that carries one fails with BAD_STATE and changes x0 alone, and
/// a copy with label 0 carries the same label. A label on a handle that is
/// no channel fails with WRONG_TYPE.
fn label_cannot_change() -> Outcome {
    let c = channel(QUIET)?;
    let first = session(&c, Rights::NOTIFY | Rights::DUPLICATE, 7, QUIET)?;
    let x = duplicate_regs(first.raw(), Rights::NOTIFY, 8, QUIET.into());
    let after = raw_duplicate(x);
    let same = copy(&first, Rights::NOTIFY)?;
    let posted = sys::notify(&same, 1);
    let got = take_one(&c);
    let process = sys::handle_label(&retyped(&init::PROCESS), Rights::NONE, 9, QUIET);
    close(c)?;
    close(same)?;
    close(first)?;
    check(
        after[0] == Error::BadState.code() && after[1..] == x[1..],
        "a handle with a label took a new one",
    )?;
    check(
        posted.is_ok() && got == Ok(labelled(7, 1, 1)),
        "a copy with label 0 did not keep the label",
    )?;
    check(
        process == Err(Error::WrongType),
        "a handle to a process took a label",
    )
}

/// The priority of a session's slot (spec 5.3, 6.5): with a label 1-63,
/// 63, init's ceiling, included; without one exactly 0; anything else
/// fails with INVALID_ARGS and changes x0 alone. A receiver at LOW waits
/// on a channel whose slot of label 0 has LEVEL, below init; notify
/// through a session of priority NOTICE wakes it above init (spec 6.6), so
/// it runs before notify returns. A priority above the caller's own
/// ceiling is handle_duplicate_checks_its_arguments.
fn session_priority_under_the_ceiling() -> Outcome {
    let (c, r) = waiting_receiver(LEVEL)?;
    let refused = [
        (9, 0),
        (0, u64::from(QUIET)),
        (9, abi::PRIORITY_LEVELS.into()),
        (9, 0x100 | u64::from(QUIET)),
    ]
    .map(|(label, priority)| {
        let x = duplicate_regs(c.raw(), Rights::NOTIFY, label, priority);
        let after = raw_duplicate(x);
        after[0] == Error::InvalidArgs.code() && after[1..] == x[1..]
    });
    let top = session(&c, Rights::NOTIFY, 63, abi::PRIORITY_LEVELS - 1)?;
    let s = session(&c, Rights::NOTIFY, 25, NOTICE)?;
    let waited = mark(0);
    let posted = sys::notify(&s, 1);
    let ran = mark(0);
    let_run()?;
    close(r)?;
    close(c)?;
    close(s)?;
    close(top)?;
    check(
        refused.iter().all(|&ok| ok),
        "a priority outside 1-63 with a label, or one without a label, was taken",
    )?;
    check(waited == 0, "the receiver did not wait")?;
    check(
        posted.is_ok() && ran == 1,
        "the receiver did not run at the session's priority before notify returned",
    )
}

/// Spec 15.2 (notifications): notify through a handle with a label goes
/// into its session's slot (spec 5.3, 6.5), and receive gives the source
/// «session», the label, the bits and the count; notify through the handle
/// with no label still goes into the slot of label 0. At one level they
/// come in the order they came. Bit 63 fails through a session too.
fn session_notice_carries_its_label() -> Outcome {
    let c = channel(QUIET)?;
    let s = session(&c, Rights::NOTIFY, 0x5E55, QUIET)?;
    let posted = [
        sys::notify(&s, 0b01),
        sys::notify(&s, 0b10),
        sys::notify(&c, 0b100),
    ];
    let bit_63 = sys::notify(&s, CLIENT_GONE);
    let first = sys::try_receive(&c);
    let second = take_one(&c);
    close(c)?;
    close(s)?;
    check(posted.iter().all(Result::is_ok), "notify failed")?;
    check(
        bit_63 == Err(Error::InvalidArgs),
        "bit 63 went through a session",
    )?;
    check(
        first == Ok(labelled(0x5E55, 0b11, 2)),
        "the session's notification did not carry its label, bits and count",
    )?;
    check(
        second == Ok(unlabeled(0b100, 1)),
        "the slot of label 0 did not come after the session's",
    )
}

/// Spec 15.2 (refusals): two handles carry one label, the second a copy of
/// the first. Closing the first posts nothing; closing the last posts
/// CLIENT_GONE, bit 63, into the session's slot with the label (spec 5.3),
/// and the bits the client posted before it left come in the same receive.
fn client_gone_after_the_last_copy() -> Outcome {
    let c = channel(QUIET)?;
    let first = session(&c, Rights::NOTIFY | Rights::DUPLICATE, 0xC1, QUIET)?;
    let last = copy(&first, Rights::NOTIFY)?;
    close(first)?;
    check(
        sys::try_receive(&c) == Err(Error::WouldBlock),
        "closing one of two copies posted into the session's slot",
    )?;
    let posted = sys::notify(&last, 0b10);
    close(last)?;
    let got = take_one(&c);
    close(c)?;
    check(
        posted.is_ok() && got == Ok(labelled(0xC1, 0b10 | CLIENT_GONE, 2)),
        "the last copy did not leave CLIENT_GONE with the label and the client's bits",
    )
}

/// Spec 15.2 (notifications): slots come by priority, and in the order they
/// came within a level (spec 6.3). The slot of label 0 at LEVEL is posted
/// first, then two sessions at HIGH: receive takes the first session, the
/// second, then the slot of label 0.
fn higher_notification_comes_first() -> Outcome {
    let c = channel(LEVEL)?;
    let a = session(&c, Rights::NOTIFY, 0xA, HIGH)?;
    let b = session(&c, Rights::NOTIFY, 0xB, HIGH)?;
    let posted = [sys::notify(&c, 1), sys::notify(&a, 2), sys::notify(&b, 4)];
    let got = [(); 4].map(|()| sys::try_receive(&c));
    close(c)?;
    close(a)?;
    close(b)?;
    check(posted.iter().all(Result::is_ok), "notify failed")?;
    check(
        got == [
            Ok(labelled(0xA, 2, 1)),
            Ok(labelled(0xB, 4, 1)),
            Ok(unlabeled(1, 1)),
            Err(Error::WouldBlock),
        ],
        "the slots did not come by priority and within a level in their order",
    )
}

/// Spec 15.2 (refusals): when the last handle with RECEIVE goes, the
/// channel closes (spec 6.5, 6.8): notify through a copy with NOTIFY and
/// through a session fails with PEER_CLOSED and changes x0 alone, and so
/// does a new label; a copy with label 0 is still made.
fn notify_after_close_is_peer_closed() -> Outcome {
    let c = channel(QUIET)?;
    let left = copy(&c, Rights::NOTIFY | Rights::DUPLICATE)?;
    let s = session(&c, Rights::NOTIFY, 0xDEAD, QUIET)?;
    let posted = sys::notify(&s, 1);
    close(c)?;
    let mut x = marked();
    x[..2].copy_from_slice(&[left.raw().0, 1]);
    let mut y = marked();
    y[..2].copy_from_slice(&[s.raw().0, 1]);
    let z = duplicate_regs(left.raw(), Rights::NOTIFY, 0xBEEF, QUIET.into());
    let after = [raw_notify(x), raw_notify(y), raw_duplicate(z)];
    let plain = copy(&left, Rights::NOTIFY);
    let copied = plain.is_ok();
    if let Ok(h) = plain {
        close(h)?;
    }
    close(left)?;
    close(s)?;
    check(posted.is_ok(), "notify through a session failed")?;
    check(
        after
            .iter()
            .zip([x, y, z])
            .all(|(a, x)| a[0] == Error::PeerClosed.code() && a[1..] == x[1..]),
        "notify or a new label on a closed channel did not fail with PEER_CLOSED alone",
    )?;
    check(
        copied,
        "a copy of a closed channel with label 0 was not made",
    )
}

/// Spec 15.2 (notifications): a channel has abi::MAX_SLOTS slots, its slot
/// of label 0 among them (spec 6.5). Init makes 1023 sessions and closes
/// each at once, and CLIENT_GONE keeps each in the channel's queue. The
/// next label fails with LIMIT_REACHED and changes x0 alone, and so does a
/// child with the channel as its exit channel, even with a quota init has
/// not: the slot comes before the quota (spec 11). Once receive took the
/// first CLIENT_GONE, that session went, and a new label fits. Every
/// session leaves with CLIENT_GONE, in the order they left.
fn slot_limit_is_1024() -> Outcome {
    let c = channel(QUIET)?;
    let last = u64::from(abi::MAX_SLOTS) - 1;
    for label in 1..=last {
        close(session(&c, Rights::NONE, label, QUIET)?)?;
    }
    let x = duplicate_regs(c.raw(), Rights::NONE, last + 1, QUIET.into());
    let after = raw_duplicate(x);
    let own = sys::process_memory(&init::PROCESS).map_err(|_| "PROCESS_MEMORY of init failed")?;
    let mut y = create_regs(c.raw(), QUIET.into(), abi::Handle::INVALID);
    y[0] = (own.quota - own.returned - own.used + 1).next_multiple_of(PAGE as u64);
    let exit = raw_create(y);
    let first = sys::try_receive(&c);
    let again = sys::handle_label(&c, Rights::NONE, last + 1, QUIET);
    let remade = again.is_ok();
    if let Ok(h) = again {
        close(h)?;
    }
    let order =
        (2..=last + 1).all(|label| sys::try_receive(&c) == Ok(labelled(label, CLIENT_GONE, 1)));
    let rest = sys::try_receive(&c);
    close(c)?;
    check(
        after[0] == Error::LimitReached.code() && after[1..] == x[1..],
        "a session past 1023 and the slot of label 0 was made",
    )?;
    check(
        failed(exit, y, Error::LimitReached),
        "an exit channel with no slot left did not fail with LIMIT_REACHED before the quota",
    )?;
    check(
        first == Ok(labelled(1, CLIENT_GONE, 1)),
        "the first session did not leave with CLIENT_GONE",
    )?;
    check(remade, "no new session fit once one went")?;
    check(
        order && rest == Err(Error::WouldBlock),
        "the sessions did not leave with CLIENT_GONE in their order",
    )
}

/// Spec 15.2 (notifications): a source of notifications gives its slot of
/// the channel back as it goes (spec 6.5). On one channel, a thousand
/// times, a session leaves with CLIENT_GONE, a timer goes, and a child
/// whose exit channel it is ends; then 1023 sessions still fit beside the
/// slot of label 0, and the next one fails with LIMIT_REACHED.
fn sources_give_their_slots_back() -> Outcome {
    const ROUNDS: u64 = 1000;
    let c = channel(QUIET)?;
    let churned = (1..=ROUNDS).try_for_each(|label| {
        close(session(&c, Rights::NONE, label, QUIET)?)?;
        let gone = sys::try_receive(&c);
        close(timer(&c)?)?;
        let child = sys::process_create_with(LEAST_QUOTA, 16, LOW, Some((&c, QUIET)), None);
        close(child.map_err(|_| "process_create with an exit channel failed")?)?;
        let ended = sys::try_receive(&c);
        check(
            gone == Ok(labelled(label, CLIENT_GONE, 1)) && ended == Ok(exit_notice(0)),
            "a session or a child did not leave with its notification",
        )
    });
    let last = u64::from(abi::MAX_SLOTS) - 1;
    let filled = churned.and_then(|()| {
        (1..=last).try_for_each(|label| close(session(&c, Rights::NONE, label, QUIET)?))
    });
    let past = sys::handle_label(&c, Rights::NONE, last + 1, QUIET);
    let refused = past.as_ref().err() == Some(&Error::LimitReached);
    if let Ok(h) = past {
        close(h)?;
    }
    while sys::try_receive(&c).is_ok() {}
    close(c)?;
    filled?;
    check(
        refused,
        "a session past 1023 and the slot of label 0 was made",
    )
}

/// A test's exit channel, at QUIET, and a copy of it with NOTIFY and the
/// label CHILD that names the test's children as their x3. Closing the
/// channel first lets the copy's session go without CLIENT_GONE.
pub(crate) fn exit_channel() -> Result<(Handle<Channel>, Handle<Channel>), &'static str> {
    let exits = channel(QUIET)?;
    let name = session(&exits, Rights::NOTIFY, CHILD, QUIET)?;
    Ok((exits, name))
}

/// A child with no code like `child`, whose end the channel of `name`
/// hears of at `priority` (process_create x3, x4; spec 7.9).
pub(crate) fn heard_child(
    name: &Handle<Channel>,
    priority: u8,
    ceiling: u8,
) -> Result<Handle<Process>, &'static str> {
    sys::process_create_with(CHILD_QUOTA, 16, ceiling, Some((name, priority)), None)
        .map_err(|_| "process_create with an exit channel failed")
}

/// The exit notification of a child whose exit channel carried `label`:
/// bit 0, once (spec 7.9).
pub(crate) fn exit_notice(label: u64) -> Received {
    Received::Notification {
        source: Source::Exit,
        label,
        bits: 1,
        count: 1,
    }
}

/// Waits in receive on `exits` for the exit notification of the child
/// whose exit channel carried `label` (spec 7.9); then a receive without
/// waiting ends its boost and finds nothing more.
pub(crate) fn wait_exit(exits: &Handle<Channel>, label: u64) -> Outcome {
    let got = sys::receive(exits);
    let rest = sys::try_receive(exits);
    check(
        got == Ok(exit_notice(label)),
        "the exit notification did not come with the child's label",
    )?;
    check(
        rest == Err(Error::WouldBlock),
        "something came after the exit notification",
    )
}

/// x0-x9 for process_create of a child with CHILD_QUOTA, 16 handles and
/// ceiling LOW, and `x3`, `x4` and `x5`, the rest marked.
pub(crate) fn create_regs(x3: abi::Handle, x4: u64, x5: abi::Handle) -> Regs {
    let mut x = marked();
    x[..6].copy_from_slice(&[CHILD_QUOTA, 16, LOW.into(), x3.0, x4, x5.0]);
    x
}

/// process_create with raw registers.
pub(crate) fn raw_create(x: Regs) -> Regs {
    // SAFETY: process_create only reads its registers.
    unsafe { sys::raw::<{ Call::ProcessCreate.number() }>(x) }
}

/// Spec 7.9: the parent hears of a child's end once the child gave back
/// the free part of its quota. A thread of init above init waits on the
/// exit channel; init kills the child, whose teardown runs at init's
/// level, and the notification wakes the thread in the middle of it:
/// PROCESS_MEMORY of the child shows then that the child returned its
/// quota but what it still uses.
fn exit_notice_comes_after_the_quota() -> Outcome {
    reset_marks();
    let (exits, name) = exit_channel()?;
    let c = heard_child(&name, QUIET, LOW)?;
    MARKS[1].store(c.raw().0, Relaxed);
    let w = spawn(0, watch_exit, exits.raw().0, HIGH, Policy::Fifo)?;
    let killed = sys::process_kill(&c);
    let (heard, returned, free) = (mark(0), mark(2), mark(3));
    close(w)?;
    close(c)?;
    close(exits)?;
    close(name)?;
    check(killed.is_ok(), "process_kill failed")?;
    check(
        heard == 1,
        "the waiting thread did not get the exit notification",
    )?;
    check(
        returned > 0 && returned == free,
        "the exit notification came before the child's quota went back",
    )
}

/// A thread of init that waits in receive on the channel `h` for the exit
/// notification of the child whose handle mark 1 holds and reads the
/// child's memory at once: 1 in mark 0 when the notification came, what
/// the child returned in mark 2 and its quota but what it uses in mark 3.
/// Ends afterwards.
extern "C" fn watch_exit(h: u64) -> ! {
    let exits = Handle::<Channel>::from_raw(abi::Handle(h));
    let got = sys::receive(&exits);
    let child = Handle::<Process>::from_raw(abi::Handle(mark(1)));
    if let Ok(m) = sys::process_memory(&child) {
        MARKS[2].store(m.returned, Relaxed);
        MARKS[3].store(m.quota - m.used, Relaxed);
    }
    MARKS[0].store(u64::from(got == Ok(exit_notice(CHILD))), Relaxed);
    sys::thread_exit()
}

/// The exit notification carries the label of the handle process_create
/// took as x3 (spec 7.9): a copy with a label gives it, the channel's
/// handle with none gives 0; the source is «exit», bit 0, count 1.
fn exit_notice_carries_the_label() -> Outcome {
    let (exits, name) = exit_channel()?;
    let labelled = heard_child(&name, QUIET, LOW)?;
    let plain = heard_child(&exits, QUIET, LOW)?;
    let killed = [sys::process_kill(&labelled), sys::process_kill(&plain)];
    let first = sys::try_receive(&exits);
    let second = take_one(&exits);
    close(labelled)?;
    close(plain)?;
    close(exits)?;
    close(name)?;
    check(killed.iter().all(Result::is_ok), "process_kill failed")?;
    check(
        first == Ok(exit_notice(CHILD)),
        "the exit notification did not carry the label of x3",
    )?;
    check(
        second == Ok(exit_notice(0)),
        "the exit notification through a handle with no label did not carry 0",
    )
}

/// x3 of process_create is a channel with NOTIFY (spec 11, 13.3): a copy
/// without NOTIFY fails with ACCESS_DENIED, a process with WRONG_TYPE, a
/// closed handle with BAD_HANDLE, a channel that closed with PEER_CLOSED;
/// each changes x0 alone, and no child is made.
fn exit_channel_needs_notify() -> Outcome {
    let c = channel(QUIET)?;
    let receive_only = copy(&c, Rights::RECEIVE)?;
    let shut = channel(QUIET)?;
    let left = copy(&shut, Rights::NOTIFY)?;
    let gone = shut.raw();
    close(shut)?;
    let before = sys::process_handles(&init::PROCESS);
    let refused = [
        (receive_only.raw(), Error::AccessDenied),
        (init::PROCESS.raw(), Error::WrongType),
        (gone, Error::BadHandle),
        (left.raw(), Error::PeerClosed),
    ]
    .map(|(h, error)| {
        let x = create_regs(h, QUIET.into(), abi::Handle::INVALID);
        failed(raw_create(x), x, error)
    });
    let after = sys::process_handles(&init::PROCESS);
    close(receive_only)?;
    close(left)?;
    close(c)?;
    check(
        refused.iter().all(|&ok| ok),
        "x3 that is no open channel with NOTIFY did not fail alone",
    )?;
    check(
        before.is_ok() && after == before,
        "a child of a call that failed has a handle",
    )
}

/// x4 of process_create, the priority of the exit notification (spec 7.9,
/// 11): 1-63 with an exit channel, 63, init's ceiling, included, and
/// exactly 0 without one; anything else fails with INVALID_ARGS and
/// changes x0 alone. A receiver at LOW waits on the exit channel; the
/// end of a child that init kills comes at NOTICE and wakes it above init
/// before process_kill returns. x4 above the caller's own ceiling fails
/// with ACCESS_DENIED alone after the handles in x3 and x5, and x3 on a
/// channel that closed fails with PEER_CLOSED only under that ceiling: 31
/// and 30 in a child under ceiling 30 (`caller_ceiling`).
fn exit_priority_under_the_ceiling() -> Outcome {
    let (c, r) = waiting_receiver(QUIET)?;
    let name = session(&c, Rights::NOTIFY, CHILD, QUIET)?;
    let n = name.raw();
    let refused = [
        (n, 0),
        (abi::Handle::INVALID, u64::from(QUIET)),
        (n, abi::PRIORITY_LEVELS.into()),
        (n, 0x100 | u64::from(QUIET)),
    ]
    .map(|(x3, x4)| {
        let x = create_regs(x3, x4, abi::Handle::INVALID);
        failed(raw_create(x), x, Error::InvalidArgs)
    });
    let top = heard_child(&name, abi::PRIORITY_LEVELS - 1, LOW);
    let heard = heard_child(&name, NOTICE, LOW)?;
    let waited = mark(0);
    let killed = sys::process_kill(&heard);
    let ran = mark(0);
    let_run()?;
    close(r)?;
    close(c)?;
    close(heard)?;
    let highest = top.is_ok();
    if let Ok(top) = top {
        close(top)?;
    }
    close(name)?;
    check(
        refused.iter().all(|&ok| ok),
        "a priority outside 1-63 with x3, or one without x3, was taken",
    )?;
    check(
        highest,
        "the exit priority 63 under init's ceiling was refused",
    )?;
    check(waited == 0, "the receiver did not wait")?;
    check(
        killed.is_ok() && ran == 1,
        "the receiver did not run at the exit notification's priority before process_kill returned",
    )?;
    caller_ceiling(Checked::ExitChannel)
}

/// x5 of process_create moves a channel handle with TRANSFER into entry 0
/// of the child's table (spec 13.3): init's handle is gone (BAD_HANDLE),
/// the child's table holds one live handle, and the channel lives on with
/// it, since it carried RECEIVE: a copy of init with NOTIFY notifies. The
/// child's end lets that handle go, and the channel closes: notify then
/// fails with PEER_CLOSED. The child's exit channel closes before its end
/// with nothing queued; the notification is lost, and the child's shell
/// goes once init closes its handle.
fn start_channel_moves_into_the_child() -> Outcome {
    let c = channel(QUIET)?;
    let n = copy(&c, Rights::NOTIFY)?;
    let (exits, name) = exit_channel()?;
    let moved = c.raw();
    let used = || sys::process_memory(&init::PROCESS).map(|m| m.used);
    let before = used();
    let made = sys::process_create_with(CHILD_QUOTA, 16, LOW, Some((&name, QUIET)), Some(c));
    let Ok(child) = made else {
        close(n)?;
        close(exits)?;
        close(name)?;
        return Err("process_create with a start channel failed");
    };
    // The exit channel closes with nothing queued: the stage Close has
    // nothing to take, and the exit notification finds it closed.
    close(exits)?;
    let gone = Handle::<Channel>::from_raw(moved).close();
    let table = sys::process_handles(&child);
    let open = sys::notify(&n, 1);
    let killed = sys::process_kill(&child);
    let shut = sys::notify(&n, 1);
    close(child)?;
    let back = used();
    close(n)?;
    close(name)?;
    check(
        before.is_ok() && back == before,
        "the child's shell stayed after its exit notification met a closed channel",
    )?;
    check(gone == Err(Error::BadHandle), "init kept the start channel")?;
    check(
        table.is_ok_and(|t| t.live == 1),
        "the child's table does not hold the start channel",
    )?;
    check(
        open.is_ok() && killed.is_ok() && shut == Err(Error::PeerClosed),
        "the channel did not live with the child's handle and close with it",
    )
}

/// x5 needs TRANSFER (spec 11): a copy without it fails with ACCESS_DENIED
/// and changes x0 alone, and the handle stays init's.
fn start_channel_needs_transfer() -> Outcome {
    let c = channel(QUIET)?;
    let kept = copy(&c, Rights::NOTIFY | Rights::RECEIVE)?;
    let x = create_regs(abi::Handle::INVALID, 0, kept.raw());
    let after = raw_create(x);
    let posted = sys::notify(&kept, 1);
    let got = take_one(&kept);
    close(kept)?;
    close(c)?;
    check(
        failed(after, x, Error::AccessDenied),
        "x5 without TRANSFER did not fail with ACCESS_DENIED alone",
    )?;
    check(
        posted.is_ok() && got == Ok(unlabeled(1, 1)),
        "the handle without TRANSFER did not stay init's",
    )
}

/// x5 names a channel (spec 11, 13.3): a process fails with WRONG_TYPE, a
/// closed handle with BAD_HANDLE, and x3 is looked at first.
fn start_handle_must_be_a_channel() -> Outcome {
    let c = channel(QUIET)?;
    let gone = c.raw();
    close(c)?;
    let own = init::PROCESS.raw();
    let refused = [
        (abi::Handle::INVALID, 0, own, Error::WrongType),
        (abi::Handle::INVALID, 0, gone, Error::BadHandle),
        (gone, u64::from(QUIET), own, Error::BadHandle),
    ]
    .map(|(x3, x4, x5, error)| {
        let x = create_regs(x3, x4, x5);
        failed(raw_create(x), x, error)
    });
    check(
        refused.iter().all(|&ok| ok),
        "x5 that is no live channel did not fail alone, or came before x3",
    )
}

/// Spec 15.2 (refusals): one handle, a copy with a label, NOTIFY and
/// TRANSFER, is both x3 and x5 (spec 13.3): it moves into the child, and
/// its label names the child's end. When init kills the child, the
/// child's table lets the copy go, which posts CLIENT_GONE with the label
/// (spec 5.3), and after the child's stage Quota the exit notification
/// comes with the same label.
fn client_gone_when_the_child_dies() -> Outcome {
    let exits = channel(QUIET)?;
    let name = session(&exits, Rights::NOTIFY | Rights::TRANSFER, CHILD, QUIET)?;
    let x = create_regs(name.raw(), QUIET.into(), name.raw());
    let after = raw_create(x);
    let made = after[0] == 0 && after[2..] == x[2..];
    let moved = name.close();
    let child = Handle::<Process>::from_raw(abi::Handle(after[1]));
    let killed = sys::process_kill(&child);
    let got = [(); 3].map(|()| sys::try_receive(&exits));
    if made {
        close(child)?;
    }
    close(exits)?;
    check(made, "process_create with one handle as x3 and x5 failed")?;
    check(
        moved == Err(Error::BadHandle),
        "the copy did not move into the child",
    )?;
    check(
        killed.is_ok()
            && got
                == [
                    Ok(labelled(CHILD, CLIENT_GONE, 1)),
                    Ok(exit_notice(CHILD)),
                    Err(Error::WouldBlock),
                ],
        "the child's end did not post CLIENT_GONE and then the exit notification with the label",
    )
}
