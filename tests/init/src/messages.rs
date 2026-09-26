// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of requests and replies: registers, order, priorities and the end
//! of either side (spec 6.1, 6.3, 6.4, 6.6, 6.8).

use crate::channels::exit_channel;
use crate::harness::*;

/// The tests of this module, in the order they run.
pub(crate) const TESTS: [Test; 21] = [
    ("send_checks_its_arguments", send_checks_its_arguments),
    (
        "request_carries_registers_and_label",
        request_carries_registers_and_label,
    ),
    (
        "bytes_past_the_length_come_as_zero",
        bytes_past_the_length_come_as_zero,
    ),
    ("reply_carries_registers_back", reply_carries_registers_back),
    ("second_reply_is_bad_state", second_reply_is_bad_state),
    (
        "send_without_waiting_is_would_block",
        send_without_waiting_is_would_block,
    ),
    (
        "send_without_waiting_to_a_waiting_server_gets_the_reply",
        send_without_waiting_to_a_waiting_server_gets_the_reply,
    ),
    ("requests_come_by_priority", requests_come_by_priority),
    (
        "requests_and_notifications_share_one_order",
        requests_and_notifications_share_one_order,
    ),
    (
        "server_below_its_client_runs_at_the_client",
        server_below_its_client_runs_at_the_client,
    ),
    ("boost_ends_with_its_reply", boost_ends_with_its_reply),
    ("other_reply_keeps_the_boost", other_reply_keeps_the_boost),
    ("receive_ends_a_request_boost", receive_ends_a_request_boost),
    (
        "high_client_waits_for_one_started_request",
        high_client_waits_for_one_started_request,
    ),
    (
        "send_to_a_closed_channel_is_peer_closed",
        send_to_a_closed_channel_is_peer_closed,
    ),
    (
        "queued_client_gets_peer_closed_on_close",
        queued_client_gets_peer_closed_on_close,
    ),
    (
        "accepted_request_outlives_the_close",
        accepted_request_outlives_the_close,
    ),
    ("close_runs_at_the_top_waiter", close_runs_at_the_top_waiter),
    (
        "client_gone_comes_after_queued_requests",
        client_gone_comes_after_queued_requests,
    ),
    (
        "set_priority_moves_a_waiting_sender",
        set_priority_moves_a_waiting_sender,
    ),
    (
        "notification_boost_outlives_an_older_reply",
        notification_boost_outlives_an_older_reply,
    ),
];

/// The label of a client's copy of a channel.
pub(crate) const CLIENT_LABEL: u64 = 0xC11E;

pub(crate) fn record(slot: usize, words: &[u64]) {
    for (r, &w) in RESULTS[slot].iter().zip(words) {
        r.store(w, Relaxed);
    }
}

/// send with raw registers.
pub(crate) fn raw_send(x: Regs) -> Regs {
    // SAFETY: send only reads its registers; the calls that come here fail
    // or are answered by threads of the test.
    unsafe { sys::raw::<{ Call::Send.number() }>(x) }
}

/// reply with raw registers.
pub(crate) fn raw_reply(x: Regs) -> Regs {
    // SAFETY: reply only reads its registers and never waits.
    unsafe { sys::raw::<{ Call::Reply.number() }>(x) }
}

/// The token of the request queued in `c`, taken without waiting.
pub(crate) fn take_token(c: &Handle<Channel>) -> Result<Token, &'static str> {
    match sys::try_receive(c) {
        Ok(Received::Message { token, .. }) => Ok(token),
        _ => Err("no request came"),
    }
}

/// A client that sends with the registers RAW holds and leaves x0-x9 of
/// the call in `result`; then ends.
pub(crate) extern "C" fn raw_client(slot: u64) -> ! {
    let s = slot as usize;
    let after = raw_send(core::array::from_fn(|i| RAW[i].load(Relaxed)));
    record(s, &after);
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// A service in `slot`: takes a request on the channel HANDLES holds for
/// it and leaves its length, words, label and token in `result`, and mark
/// 1 at that moment in SEEN; answers with the request's own bytes and
/// leaves the reply's code in `result`; sets mark 2 and ends.
pub(crate) extern "C" fn server(slot: u64) -> ! {
    let s = slot as usize;
    match sys::receive(&handle(s)) {
        Ok(Received::Message {
            label,
            len,
            token,
            words,
            ..
        }) => {
            let mut w = [0; 12];
            w[1] = len as u64;
            w[2..10].copy_from_slice(&words);
            w[10] = label;
            w[11] = token.raw();
            record(s, &w);
            SEEN.store(mark(1), Relaxed);
            let bytes = abi::inline_bytes(&words);
            let replied = token.reply(&bytes[..len.min(abi::INLINE_MAX)]);
            RESULTS[s][0].store(replied.map_or_else(|e| e.code(), |()| 0), Relaxed);
        }
        Ok(_) => record(s, &[u64::MAX]),
        Err(e) => record(s, &[e.code()]),
    }
    MARKS[2].store(1, Relaxed);
    sys::thread_exit()
}

/// send and reply check their values first (spec 6.1, 11): a length above
/// 1024, more than 4 handles, a bit no description has, and NO_WAIT for
/// reply fail with INVALID_ARGS before the handle or the token is looked
/// at; then the handle of send: BAD_HANDLE, WRONG_TYPE for a process,
/// ACCESS_DENIED for a copy without SEND, and PEER_CLOSED once the channel
/// closed. Each changes x0 alone. rt refuses more than 1024 bytes
/// itself.
fn send_checks_its_arguments() -> Outcome {
    let c = channel(QUIET)?;
    let notify_only = copy(&c, Rights::NOTIFY)?;
    let shut = channel(QUIET)?;
    let left = copy(&shut, Rights::SEND)?;
    let gone = shut.raw();
    close(shut)?;
    let cases = [
        (c.raw(), 1025, Error::InvalidArgs),
        (c.raw(), 5 << abi::HANDLES_SHIFT, Error::InvalidArgs),
        (c.raw(), 1 << 11, Error::InvalidArgs),
        (c.raw(), 1 << 24, Error::InvalidArgs),
        (c.raw(), 1 << 63, Error::InvalidArgs),
        (gone, 1025, Error::InvalidArgs),
        (gone, 8, Error::BadHandle),
        (init::PROCESS.raw(), 8, Error::WrongType),
        (notify_only.raw(), 8, Error::AccessDenied),
        (left.raw(), 8, Error::PeerClosed),
    ];
    let sent = cases.map(|(h, desc, error)| {
        let mut x = marked();
        x[..2].copy_from_slice(&[h.0, desc]);
        failed(raw_send(x), x, error)
    });
    let replied =
        [(0, abi::NO_WAIT), (1 << 16, abi::NO_WAIT | 8), (0, 1025)].map(|(token, desc)| {
            let mut x = marked();
            x[..2].copy_from_slice(&[token, desc]);
            failed(raw_reply(x), x, Error::InvalidArgs)
        });
    let typed = sys::send(&c, &[0; abi::MESSAGE_MAX + 1]);
    close(notify_only)?;
    close(left)?;
    close(c)?;
    check(
        sent.iter().all(|&ok| ok),
        "send took a bad description or handle, or changed more than x0",
    )?;
    check(
        replied.iter().all(|&ok| ok),
        "reply took a bad description or looked at the token first",
    )?;
    check(
        typed == Err(Error::InvalidArgs),
        "rt sent more than 1024 bytes",
    )
}

/// Spec 15.2 (messages): a request carries its bytes 0-63 in x2-x9 and
/// comes with the label of the handle it went through (spec 5.3, 6.1). A
/// client above init sends 16 bytes through a copy with a label, and then
/// another through the channel's own handle; init takes each request
/// without waiting: its bytes, no handles, a token that is not 0, and the
/// label, or 0. Init's reply lets each client go.
fn request_carries_registers_and_label() -> Outcome {
    let c = channel(QUIET)?;
    let labelled = session(&c, Rights::SEND, CLIENT_LABEL, QUIET)?;
    let result = [(&labelled, CLIENT_LABEL), (&c, 0)]
        .into_iter()
        .try_for_each(|(h, label)| {
            reset_results();
            HANDLES[0].store(h.raw().0, Relaxed);
            let t = spawn(0, client, 0, HIGH, Policy::Fifo)?;
            let taken = match sys::try_receive(&c) {
                Ok(Received::Message {
                    label: l,
                    len,
                    handles,
                    token,
                    words: w,
                }) => {
                    let whole = (l, len, handles, w) == (label, 16, 0, words(&request(0)));
                    let named = token.raw() != 0;
                    token.reply(&[]).is_ok() && whole && named
                }
                _ => false,
            };
            close(t)?;
            check(
                taken,
                "the request did not come with its bytes, its label and a token",
            )?;
            check(
                ended(0) && result(0)[..2] == [0, 0],
                "the client did not get the reply",
            )
        });
    close(labelled)?;
    close(c)?;
    result
}

/// Bytes past the length come as zeros (spec 6.1): a client sends 13 bytes
/// through raw registers with every bit of x2-x9 set; init takes x2 whole,
/// the low 5 bytes of x3 and zeros in x4-x9.
fn bytes_past_the_length_come_as_zero() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let x: Regs = core::array::from_fn(|i| match i {
        0 => c.raw().0,
        1 => 13,
        _ => u64::MAX,
    });
    for (r, v) in RAW.iter().zip(x) {
        r.store(v, Relaxed);
    }
    let t = spawn(0, raw_client, 0, HIGH, Policy::Fifo)?;
    let (seen, replied) = match sys::try_receive(&c) {
        Ok(Received::Message {
            len, words, token, ..
        }) => (Some((len, words)), token.reply(&[]).is_ok()),
        _ => (None, false),
    };
    close(t)?;
    close(c)?;
    let mut want = [0; 8];
    want[0] = u64::MAX;
    want[1] = (1 << 40) - 1;
    check(
        seen == Some((13, want)),
        "the bytes past the length did not come as zeros",
    )?;
    check(replied && ended(0), "the client did not get the reply")
}

/// Spec 15.2 (messages): the reply comes back in x0-x9 of send (spec 6.1,
/// 11): 0, its description and its bytes. Init answers a client with 13
/// bytes through raw registers, every bit of x2-x9 set: the client gets x2
/// whole, 5 bytes of x3 and zeros, and init's reply changes its x0 alone.
/// A second client gets 64 bytes whole.
fn reply_carries_registers_back() -> Outcome {
    let c = channel(QUIET)?;
    let result = reply_rounds(&c);
    close(c)?;
    result
}

fn reply_rounds(c: &Handle<Channel>) -> Outcome {
    reset_results();
    HANDLES[0].store(c.raw().0, Relaxed);
    let t = spawn(0, client, 0, HIGH, Policy::Fifo)?;
    let mut x = [u64::MAX; 10];
    x[0] = take_token(c)?.raw();
    x[1] = 13;
    let after = raw_reply(x);
    close(t)?;
    let mut want = [0; 10];
    want[1] = 13;
    want[2] = u64::MAX;
    want[3] = (1 << 40) - 1;
    check(
        after[0] == 0 && after[1..] == x[1..],
        "reply failed or changed more than x0",
    )?;
    check(
        ended(0) && result(0)[..10] == want,
        "the reply did not come with zeros past its length",
    )?;
    HANDLES[1].store(c.raw().0, Relaxed);
    let t = spawn(1, client, 1, HIGH, Policy::Fifo)?;
    let bytes: [u8; 64] = core::array::from_fn(|i| 0xC0 ^ i as u8);
    let replied = take_token(c)?.reply(&bytes);
    close(t)?;
    let mut want = [0; 10];
    want[1] = 64;
    want[2..].copy_from_slice(&words(&bytes));
    check(
        replied.is_ok() && ended(1) && result(1)[..10] == want,
        "the 64 bytes of a reply did not come whole",
    )
}

/// A client that sends twice through the channel HANDLES holds for
/// `slot`, the second time once the first reply came; `result` gives the
/// second reply. Ends then.
extern "C" fn client_twice(slot: u64) -> ! {
    let s = slot as usize;
    let first = sys::send(&handle(s), &request(s));
    let second = sys::send(&handle(s), &request(s));
    record(s, &[first.and(second).map_or_else(|e| e.code(), |_| 0)]);
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// Spec 15.2 (messages): a token answers once (spec 6.1). Init answers a
/// client, which sends again at once; while init holds the second request,
/// the first token, the count after the second and count 0 fail with
/// BAD_STATE, change x0 alone and leave the client waiting; the second
/// token answers it.
fn second_reply_is_bad_state() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let t = spawn(0, client_twice, 0, HIGH, Policy::Fifo)?;
    let result = second_rounds(&c);
    close(t)?;
    close(c)?;
    result
}

fn second_rounds(c: &Handle<Channel>) -> Outcome {
    let first = take_token(c)?;
    let stale = first.raw();
    let replied = first.reply(&[]);
    let second = take_token(c)?;
    let raw = second.raw();
    let again = [stale, raw + (1 << 16), raw & 0xFFFF].map(|v| {
        let mut x = marked();
        x[..2].copy_from_slice(&[v, 0]);
        failed(raw_reply(x), x, Error::BadState)
    });
    let waited = !ended(0);
    let last = second.reply(&[]);
    check(
        replied.is_ok() && last.is_ok() && ended(0) && result(0)[0] == 0,
        "a reply did not reach the client",
    )?;
    check(
        again.iter().all(|&ok| ok) && waited,
        "an old, guessed or zero token was taken, or the call changed more than x0",
    )
}

/// Spec 15.2 (refusals): send with NO_WAIT fails with WOULD_BLOCK when no
/// thread waits in receive (spec 6.1), changes x0 alone and queues
/// nothing. A thread above init makes the call, so init finds its result
/// when spawn returns; a request it left would get a reply, so that the
/// thread never stays waiting.
fn send_without_waiting_is_would_block() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let mut x = marked();
    x[..2].copy_from_slice(&[c.raw().0, abi::NO_WAIT | 8]);
    for (r, v) in RAW.iter().zip(x) {
        r.store(v, Relaxed);
    }
    let t = spawn(0, raw_client, 0, HIGH, Policy::Fifo)?;
    let (came_back, after) = (ended(0), result(0));
    let left = match sys::try_receive(&c) {
        Ok(Received::Message { token, .. }) => {
            let _ = token.reply(&[]);
            true
        }
        got => got != Err(Error::WouldBlock),
    };
    close(c)?;
    let_run()?;
    close(t)?;
    check(
        came_back && after[0] == Error::WouldBlock.code() && after[1..10] == x[1..],
        "send with NO_WAIT and no receiver did not fail with WOULD_BLOCK alone",
    )?;
    check(!left, "a send that failed left a request")
}

/// With NO_WAIT, send to a service that waits in receive goes through
/// (spec 6.1): the service takes the request at once, and init waits for
/// the reply all the same: its own bytes back.
fn send_without_waiting_to_a_waiting_server_gets_the_reply() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let s = spawn(0, server, 0, LOW, Policy::Fifo)?;
    let_run()?;
    let bytes = request(3);
    let got = sys::try_send(&c, &bytes);
    let_run()?;
    close(s)?;
    close(c)?;
    check(
        got == Ok(Reply {
            len: 16,
            handles: 0,
            words: words(&bytes),
        }),
        "send with NO_WAIT to a waiting service did not get the reply",
    )?;
    check(
        mark(2) == 1 && result(0)[0] == 0,
        "the service's reply failed",
    )
}

/// Spec 15.2 (priorities): requests wait by the priorities of their
/// clients, within a level in the order they came (spec 6.3). Clients at
/// 10, 30 and 20 send in that order, through copies labelled with their
/// priorities, before init receives; init takes them as 30, 20, 10.
fn requests_come_by_priority() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let levels = [LEVEL, HIGH, TEST_PRIORITY];
    let mut copies = [const { None }; 3];
    for (i, &level) in levels.iter().enumerate() {
        let h = session(&c, Rights::SEND, level.into(), QUIET)?;
        HANDLES[i].store(h.raw().0, Relaxed);
        copies[i] = Some(h);
    }
    let mut threads = [const { None }; 3];
    for (i, &level) in levels.iter().enumerate() {
        threads[i] = Some(spawn(i, client, i as u64, level, Policy::Fifo)?);
        // Each sends before the next: the client at 30 at once, the others
        // once init lets them.
        let_run()?;
    }
    let got = [(); 3].map(|()| sys::try_receive(&c));
    let labels = got.each_ref().map(|g| match g {
        Ok(Received::Message { label, .. }) => *label,
        _ => 0,
    });
    let replied = answer_all(got);
    let_run()?;
    for h in threads.into_iter().flatten() {
        close(h)?;
    }
    for h in copies.into_iter().flatten() {
        close(h)?;
    }
    close(c)?;
    check(
        labels == [30, 20, 10],
        "the requests did not come by the priorities of their clients",
    )?;
    check(
        replied && (0..3).all(ended),
        "a client did not get its reply",
    )
}

/// Answers each request among `got` with no bytes; true when every reply
/// went.
pub(crate) fn answer_all<const N: usize>(got: [Result<Received, Error>; N]) -> bool {
    got.into_iter().all(|g| match g {
        Ok(Received::Message { token, .. }) => token.reply(&[]).is_ok(),
        _ => true,
    })
}

/// Requests and notifications wait in one order by level (spec 6.3):
/// clients at 30 and 10 send, and init notifies the channel, whose slot of
/// label 0 has priority 25: receive gives the request at 30, the
/// notification, then the request at 10.
fn requests_and_notifications_share_one_order() -> Outcome {
    reset_results();
    let c = channel(NOTICE)?;
    let high = session(&c, Rights::SEND, HIGH.into(), QUIET)?;
    let low = session(&c, Rights::SEND, LEVEL.into(), QUIET)?;
    HANDLES[0].store(high.raw().0, Relaxed);
    HANDLES[1].store(low.raw().0, Relaxed);
    let a = spawn(0, client, 0, HIGH, Policy::Fifo)?;
    let b = spawn(1, client, 1, LEVEL, Policy::Fifo)?;
    let_run()?;
    let posted = sys::notify(&c, 1);
    let got = [(); 3].map(|()| sys::try_receive(&c));
    let order = got.each_ref().map(|g| match g {
        Ok(Received::Message { label, .. }) => *label,
        Ok(Received::Notification {
            source: Source::Unlabeled,
            ..
        }) => NOTICE.into(),
        _ => 0,
    });
    let replied = answer_all(got);
    let_run()?;
    for h in [a, b] {
        close(h)?;
    }
    for h in [high, low, c] {
        close(h)?;
    }
    check(
        posted.is_ok() && order == [30, 25, 10],
        "the requests and the notification did not come in one order by level",
    )?;
    check(
        replied && ended(0) && ended(1),
        "a client did not get its reply",
    )
}

/// Spec 15.2 (priorities): a service below its client works at the
/// client's priority from the request on (spec 6.6). A service at 10
/// waits, a thread at init's level 20 is ready behind init, and a client
/// at 30 sends: the service answers before the thread at 20 runs, which it
/// sees in that thread's mark, and the client has its reply by the time
/// init runs again.
fn server_below_its_client_runs_at_the_client() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    HANDLES[2].store(c.raw().0, Relaxed);
    let s = spawn(0, server, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    let peer = spawn(1, add_mark, 1, TEST_PRIORITY, Policy::Fifo)?;
    let k = spawn(2, client, 2, HIGH, Policy::Fifo)?;
    let answered = ended(2);
    let_run()?;
    for h in [k, peer, s] {
        close(h)?;
    }
    close(c)?;
    check(
        answered && SEEN.load(Relaxed) == 0,
        "the service did not answer at its client's priority before the thread at 20 ran",
    )?;
    check(
        mark(1) == 1 && mark(2) == 1,
        "the thread at 20 or the service did not end",
    )
}

/// The boost by a client ends with the reply to it (spec 6.6): a service
/// at 10 takes the request of a client at 30 and answers it, and it drops
/// to 10 at once: init at 20 runs before the service goes on past its
/// reply.
fn boost_ends_with_its_reply() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    HANDLES[1].store(c.raw().0, Relaxed);
    let s = spawn(0, server, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    let k = spawn(1, client, 1, HIGH, Policy::Fifo)?;
    let (answered, went_on) = (ended(1), mark(2));
    let_run()?;
    for h in [k, s] {
        close(h)?;
    }
    close(c)?;
    check(answered, "the client did not get the reply")?;
    check(
        went_on == 0,
        "the service went on past its reply at its client's priority",
    )?;
    check(mark(2) == 1, "the service did not end")
}

/// A service that takes two requests on the channel HANDLES holds for
/// `slot`, the second while it holds the first; it answers the first and
/// sets mark 2, answers the second and sets mark 3, and ends.
extern "C" fn serve_two(slot: u64) -> ! {
    let c = handle(slot as usize);
    if let (
        Ok(Received::Message { token: first, .. }),
        Ok(Received::Message { token: second, .. }),
    ) = (sys::receive(&c), sys::receive(&c))
    {
        let _ = first.reply(&[]);
        MARKS[2].store(1, Relaxed);
        let _ = second.reply(&[]);
        MARKS[3].store(1, Relaxed);
    }
    sys::thread_exit()
}

/// A reply with another token keeps the boost (spec 6.6): a service at 10
/// takes the request of a client at 25, then in its next receive that of
/// a client at 30, which boosts it to 30. It answers the first and goes on
/// at 30: its mark is there before init at 20 runs. It answers the second
/// and drops to 10: init runs before it goes on.
fn other_reply_keeps_the_boost() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    for h in &HANDLES[..3] {
        h.store(c.raw().0, Relaxed);
    }
    let s = spawn(0, serve_two, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    let first = spawn(1, client, 1, NOTICE, Policy::Fifo)?;
    let second = spawn(2, client, 2, HIGH, Policy::Fifo)?;
    let (kept, dropped, answered) = (mark(2), mark(3), ended(1) && ended(2));
    let_run()?;
    for h in [first, second, s] {
        close(h)?;
    }
    close(c)?;
    check(answered, "a client did not get its reply")?;
    check(kept == 1, "a reply with another token ended the boost")?;
    check(
        dropped == 0,
        "the reply with the boost's own token did not end it",
    )
}

/// A service that takes a request on the channel HANDLES holds for
/// `slot`, asks it again without waiting, sets mark 2, and mark 3 when
/// that found nothing; then answers and ends.
extern "C" fn serve_after_empty_receive(slot: u64) -> ! {
    let c = handle(slot as usize);
    if let Ok(Received::Message { token, .. }) = sys::receive(&c) {
        let again = sys::try_receive(&c);
        MARKS[2].store(1, Relaxed);
        MARKS[3].store(u64::from(again == Err(Error::WouldBlock)), Relaxed);
        let _ = token.reply(&[]);
    }
    sys::thread_exit()
}

/// The next receive ends the boost by a client (spec 6.6): a service at 10
/// takes the request of a client at 30 and asks the channel again without
/// waiting: WOULD_BLOCK, and it drops to 10, so init at 20 runs before it
/// goes on; its reply from 10 still reaches the client.
fn receive_ends_a_request_boost() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    HANDLES[1].store(c.raw().0, Relaxed);
    let s = spawn(0, serve_after_empty_receive, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    let k = spawn(1, client, 1, HIGH, Policy::Fifo)?;
    let went_on = mark(2);
    let_run()?;
    for h in [k, s] {
        close(h)?;
    }
    close(c)?;
    check(
        went_on == 0,
        "the service went on at its client's priority past its next receive",
    )?;
    check(
        mark(3) == 1 && ended(1) && result(1)[0] == 0,
        "the second receive found something, or the client did not get the reply",
    )
}

/// The service of `high_client_waits_for_one_started_request`: takes a
/// request on the channel HANDLES holds for slot 0 and holds it until the
/// channel of slot 3 gets a notification, as for work of its own; answers
/// it, and takes the next request at once. SEEN gets mark 1 at the first
/// reply, mark 0 mark 1 at the second take. It answers that request too,
/// sets mark 3 and ends.
extern "C" fn worker(_: u64) -> ! {
    let c = handle(0);
    if let Ok(Received::Message { token, .. }) = sys::receive(&c) {
        let _ = sys::receive(&handle(3));
        SEEN.store(mark(1), Relaxed);
        let _ = token.reply(&[]);
        if let Ok(Received::Message { token, .. }) = sys::receive(&c) {
            MARKS[0].store(mark(1), Relaxed);
            let _ = token.reply(&[]);
        }
    }
    MARKS[3].store(1, Relaxed);
    sys::thread_exit()
}

/// The spinning thread of `high_client_waits_for_one_started_request`:
/// counts in mark 1, notifies the channel HANDLES holds for slot 3 once,
/// and counts on until mark 3 is set; then ends.
pub(crate) extern "C" fn spin(_: u64) -> ! {
    MARKS[1].fetch_add(1, Relaxed);
    let _ = sys::notify(&handle(3), 1);
    while mark(3) == 0 {
        MARKS[1].fetch_add(1, Relaxed);
    }
    sys::thread_exit()
}

/// Spec 15.2 (priorities): a client above others waits for at most one
/// request its service began (spec 6.6). A service at 30 takes the request
/// of a client at 10 and holds it; a client at 25 sends meanwhile, and a
/// thread at 20 counts and then lets the service go on. The service
/// answers the first request and takes the second at once: the counting
/// thread did not run in between, and both clients get their replies.
fn high_client_waits_for_one_started_request() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let work = channel(QUIET)?;
    for (h, v) in HANDLES.iter().zip([&c, &c, &c, &work]) {
        h.store(v.raw().0, Relaxed);
    }
    let s = spawn(0, worker, 0, HIGH, Policy::Fifo)?;
    let first = spawn(1, client, 1, LEVEL, Policy::Fifo)?;
    let_run()?;
    let counting = spawn(3, spin, 3, TEST_PRIORITY, Policy::Fifo)?;
    let second = spawn(2, client, 2, NOTICE, Policy::Fifo)?;
    let_run()?;
    for h in [s, first, counting, second] {
        close(h)?;
    }
    close(work)?;
    close(c)?;
    let (at_reply, at_take) = (SEEN.load(Relaxed), mark(0));
    check(ended(1) && ended(2), "a client did not get its reply")?;
    check(
        at_reply > 0 && at_take == at_reply,
        "the thread at 20 ran between the reply and the next request",
    )
}

// The departure of a side (spec 5.3, 6.8, 7.7): a closed channel refuses
// requests and wakes those that wait; a request a service took outlives
// the close; CLIENT_GONE comes after the requests of its label; a thread
// gives its number back as it ends.

/// Spec 15.2 (refusals): send through any handle of a channel whose last
/// handle with RECEIVE went fails with PEER_CLOSED (spec 6.8), with
/// NO_WAIT too, and changes x0 alone.
fn send_to_a_closed_channel_is_peer_closed() -> Outcome {
    let c = channel(QUIET)?;
    let plain = copy(&c, Rights::SEND)?;
    let named = session(&c, Rights::SEND, CLIENT_LABEL, QUIET)?;
    close(c)?;
    let sent = [(&plain, 8), (&named, 8), (&plain, abi::NO_WAIT | 8)].map(|(h, desc)| {
        let mut x = marked();
        x[..2].copy_from_slice(&[h.raw().0, desc]);
        failed(raw_send(x), x, Error::PeerClosed)
    });
    close(plain)?;
    close(named)?;
    check(
        sent.iter().all(|&ok| ok),
        "send to a closed channel did not fail with PEER_CLOSED alone",
    )
}

/// Spec 15.2 (refusals): a request that waits in the queue of a channel
/// whose last handle with RECEIVE goes gets PEER_CLOSED (spec 6.8): a
/// client below init sends through a copy with SEND and waits; init closes
/// its own handle, and the stage Close wakes the client, whose send fails
/// with PEER_CLOSED in x0 alone.
fn queued_client_gets_peer_closed_on_close() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let sender = copy(&c, Rights::SEND)?;
    let mut x = marked();
    x[..2].copy_from_slice(&[sender.raw().0, 8]);
    for (r, v) in RAW.iter().zip(x) {
        r.store(v, Relaxed);
    }
    let t = spawn(0, raw_client, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    let waited = !ended(0);
    close(c)?;
    let_run()?;
    close(t)?;
    close(sender)?;
    check(waited, "the client did not wait")?;
    let after = result(0);
    check(
        ended(0) && after[0] == Error::PeerClosed.code() && after[1..10] == x[1..],
        "the queued client did not get PEER_CLOSED alone when the channel closed",
    )
}

/// Spec 15.2 (refusals): a request a service took outlives the close of
/// its channel (spec 6.8): init takes the request of a client, closes the
/// channel's last handle with RECEIVE, and answers; the client gets the
/// reply.
fn accepted_request_outlives_the_close() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let sender = copy(&c, Rights::SEND)?;
    HANDLES[0].store(sender.raw().0, Relaxed);
    let t = spawn(0, client, 0, HIGH, Policy::Fifo)?;
    let token = take_token(&c);
    close(c)?;
    let replied = token.map(|token| token.reply(&request(0)));
    close(t)?;
    close(sender)?;
    let mut want = [0; 10];
    want[1] = 16;
    want[2..].copy_from_slice(&words(&request(0)));
    check(
        replied == Ok(Ok(())) && ended(0) && result(0)[..10] == want,
        "the reply to a request taken before the close did not reach the client",
    )
}

/// The stage Close runs at the level of the top thread that waits (spec
/// 7.7): a thread at 30 waits in receive on a channel whose last handle
/// with RECEIVE lies in a child with no code; a thread at 5 kills the
/// child, whose teardown runs at 5, closes the channel with the child's
/// handles and then tells a thread at 20 of the end through the exit
/// channel. The waiter wakes with PEER_CLOSED before the thread at 20 runs.
/// Then the same with a sender at 30 whose request waits in the queue.
fn close_runs_at_the_top_waiter() -> Outcome {
    [false, true].into_iter().try_for_each(close_round)
}

/// A round of `close_runs_at_the_top_waiter`: the thread at 30 sends when
/// `sender`, and receives otherwise.
fn close_round(sender: bool) -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let moved = copy(&c, Rights::RECEIVE | Rights::TRANSFER)?;
    let (exits, name) = exit_channel()?;
    let child = sys::process_create_with(CHILD_QUOTA, 16, LOW, Some((&name, QUIET)), Some(moved))
        .map_err(|_| "process_create with a start channel failed")?;
    let send = copy(&c, Rights::SEND)?;
    let waits = if sender { &send } else { &c };
    HANDLES[0].store(waits.raw().0, Relaxed);
    HANDLES[1].store(exits.raw().0, Relaxed);
    HANDLES[2].store(child.raw().0, Relaxed);
    let entry = if sender {
        send_then_look
    } else {
        receive_then_look
    };
    let w = spawn(0, entry, 0, HIGH, Policy::Fifo)?;
    // The child's copy is the last handle with RECEIVE from now on.
    close(c)?;
    let m = spawn(1, mark_at_notice, 1, TEST_PRIORITY, Policy::Fifo)?;
    let k = spawn(2, kill_child, 2, LOW, Policy::Fifo)?;
    let_run()?;
    for h in [w, m, k] {
        close(h)?;
    }
    for h in [send, exits, name] {
        close(h)?;
    }
    close(child)?;
    let got = result(0);
    check(
        ended(0) && got[0] == Error::PeerClosed.code() && result(2)[0] == 0,
        "the thread that waited did not get PEER_CLOSED, or process_kill failed",
    )?;
    check(
        got[1] == 0 && mark(1) == 1,
        "the thread at 20 ran before the stage Close woke the thread at 30",
    )
}

/// Waits in receive on the channel HANDLES holds for `slot`; leaves the
/// error code of the call and mark 1 at its return in `result`; ends.
pub(crate) extern "C" fn receive_then_look(slot: u64) -> ! {
    let s = slot as usize;
    let code = sys::receive(&handle(s)).map_or_else(|e| e.code(), |_| 0);
    record(s, &[code, mark(1)]);
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// The same with send of request(slot).
extern "C" fn send_then_look(slot: u64) -> ! {
    let s = slot as usize;
    let code = sys::send(&handle(s), &request(s)).map_or_else(|e| e.code(), |_| 0);
    record(s, &[code, mark(1)]);
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// Waits in receive on the channel HANDLES holds for `slot`, sets mark 1
/// at its return, and ends.
pub(crate) extern "C" fn mark_at_notice(slot: u64) -> ! {
    let _ = sys::receive(&handle(slot as usize));
    MARKS[1].store(1, Relaxed);
    sys::thread_exit()
}

/// Kills the process whose handle HANDLES holds for `slot`, leaves the
/// code of the call in `result`, and ends.
extern "C" fn kill_child(slot: u64) -> ! {
    let s = slot as usize;
    let child = Handle::<Process>::from_raw(abi::Handle(HANDLES[s].load(Relaxed)));
    let code = sys::process_kill(&child).map_or_else(|e| e.code(), |()| 0);
    record(s, &[code]);
    sys::thread_exit()
}

/// CLIENT_GONE comes after the requests of its label (spec 5.3): a client
/// at 10 sends through a copy with a label, whose session's slot has
/// priority 40, and init closes the copy, the last one, while the request
/// waits in the queue. Init takes the request first, then CLIENT_GONE
/// with the label: the request held a copy until init took it.
fn client_gone_comes_after_queued_requests() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let named = session(&c, Rights::SEND, CLIENT_LABEL, 40)?;
    HANDLES[0].store(named.raw().0, Relaxed);
    let t = spawn(0, client, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    close(named)?;
    // The last receive finds nothing, which ends the boost of CLIENT_GONE.
    let got = [(); 3].map(|()| sys::try_receive(&c));
    let label = match &got[0] {
        Ok(Received::Message { label, .. }) => *label,
        _ => 0,
    };
    let after =
        got[1] == Ok(labelled(CLIENT_LABEL, CLIENT_GONE, 1)) && got[2] == Err(Error::WouldBlock);
    let replied = answer_all(got);
    let_run()?;
    close(t)?;
    close(c)?;
    check(
        label == CLIENT_LABEL,
        "the request did not come first, with its label",
    )?;
    check(after, "CLIENT_GONE did not come after the request")?;
    check(
        replied && ended(0) && result(0)[0] == 0,
        "the client did not get the reply",
    )
}

/// thread_set_priority moves a thread that waits in send in the channel's
/// queue by the rules of the ready queue (spec 6.3): clients at 10, 10 and
/// 11 send in that order through copies labelled 1, 2 and 3; init raises
/// the second to 11, which puts it at the tail of 11, behind the third,
/// and takes the requests: 3, 2, 1.
fn set_priority_moves_a_waiting_sender() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let mut copies = [const { None }; 3];
    for (i, h) in copies.iter_mut().enumerate() {
        let s = session(&c, Rights::SEND, i as u64 + 1, QUIET)?;
        HANDLES[i].store(s.raw().0, Relaxed);
        *h = Some(s);
    }
    let mut threads = [const { None }; 3];
    for (i, level) in [LEVEL, LEVEL, LEVEL + 1].into_iter().enumerate() {
        threads[i] = Some(spawn(i, client, i as u64, level, Policy::Fifo)?);
        // Each sends before the next, once init lets it.
        let_run()?;
    }
    let raised = threads[1]
        .as_ref()
        .map(|t| sys::thread_set_priority(t, LEVEL + 1, Policy::Fifo));
    let got = [(); 3].map(|()| sys::try_receive(&c));
    let labels = got.each_ref().map(|g| match g {
        Ok(Received::Message { label, .. }) => *label,
        _ => 0,
    });
    let replied = answer_all(got);
    let_run()?;
    for h in threads.into_iter().flatten() {
        close(h)?;
    }
    for h in copies.into_iter().flatten() {
        close(h)?;
    }
    close(c)?;
    check(
        raised == Some(Ok(())) && labels == [3, 2, 1],
        "the raised sender did not move to the tail of its new level",
    )?;
    check(
        replied && (0..3).all(ended),
        "a client did not get its reply",
    )
}

/// The service of `notification_boost_outlives_an_older_reply`: takes a
/// request on the channel HANDLES holds for `slot`, then a notification on
/// it; answers the request and sets SEEN to 1 more than mark 1; ends.
extern "C" fn answer_after_notice(slot: u64) -> ! {
    let c = handle(slot as usize);
    if let Ok(Received::Message { token, .. }) = sys::receive(&c) {
        let _ = sys::receive(&c);
        let _ = token.reply(&[]);
        SEEN.store(mark(1) + 1, Relaxed);
    }
    sys::thread_exit()
}

/// A reply to an older request keeps the boost of a notification taken
/// after it (spec 6.6): a service at 10 takes the request of a client at
/// 15 and then, in its next receive, a notification of the channel's slot
/// at 30; it answers the request and sets its mark still at 30, before a
/// ready thread at init's level runs. That receive ended the boost by the
/// request and forgot its token.
fn notification_boost_outlives_an_older_reply() -> Outcome {
    reset_results();
    let c = channel(HIGH)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    HANDLES[1].store(c.raw().0, Relaxed);
    let s = spawn(0, answer_after_notice, 0, LEVEL, Policy::Fifo)?;
    let k = spawn(1, client, 1, 15, Policy::Fifo)?;
    // The client's request waits until the service takes it, and the
    // service waits again.
    let_run()?;
    let peer = spawn(2, add_mark, 1, TEST_PRIORITY, Policy::Fifo)?;
    let posted = sys::notify(&c, 1);
    let seen = SEEN.load(Relaxed);
    let_run()?;
    for h in [s, k, peer] {
        close(h)?;
    }
    close(c)?;
    check(
        posted.is_ok() && seen == 1,
        "the reply to the older request ended the boost of the notification",
    )?;
    check(
        ended(1) && mark(1) == 1,
        "the client did not get its reply, or the thread at 20 did not end",
    )
}

/// More threads than the system has numbers (spec 8: 1024).
pub(crate) const PAST_NUMBERS: usize = 1100;
