// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of message buffers and of the handles and memory objects that
//! travel with messages (spec 6.1, 6.2).

use crate::channels::{create_regs, raw_create, take_one, unlabeled};
use crate::harness::*;
use crate::memory::memory_object;
use crate::messages::{
    CLIENT_LABEL, PAST_NUMBERS, answer_all, raw_reply, raw_send, record, server, take_token,
};
use crate::processes::{Gift, Kid, PROVIDER_QUOTA, counts_at_rest, quota_of};

/// The tests of this module, in the order they run.
pub(crate) const TESTS: [Test; 26] = [
    (
        "exited_threads_hold_no_numbers",
        exited_threads_hold_no_numbers,
    ),
    ("buffer_address_is_in_tpidrro", buffer_address_is_in_tpidrro),
    ("long_request_arrives_whole", long_request_arrives_whole),
    ("long_reply_arrives_whole", long_reply_arrives_whole),
    (
        "short_message_leaves_the_buffers_alone",
        short_message_leaves_the_buffers_alone,
    ),
    (
        "kernel_leaves_bytes_0_to_63_of_the_buffer",
        kernel_leaves_bytes_0_to_63_of_the_buffer,
    ),
    ("bytes_past_the_length_stay", bytes_past_the_length_stay),
    (
        "receiver_quota_fails_the_sender",
        receiver_quota_fails_the_sender,
    ),
    (
        "failed_create_keeps_the_start_handle",
        failed_create_keeps_the_start_handle,
    ),
    ("handles_move_with_a_request", handles_move_with_a_request),
    ("handles_move_with_a_reply", handles_move_with_a_reply),
    ("rights_stay_narrowed", rights_stay_narrowed),
    (
        "label_travels_with_its_handle",
        label_travels_with_its_handle,
    ),
    (
        "receive_right_moves_without_closing_the_channel",
        receive_right_moves_without_closing_the_channel,
    ),
    (
        "a_failed_check_takes_no_handle",
        a_failed_check_takes_no_handle,
    ),
    (
        "peer_closed_takes_the_handles",
        peer_closed_takes_the_handles,
    ),
    (
        "full_waiting_receiver_fails_the_sender",
        full_waiting_receiver_fails_the_sender,
    ),
    (
        "queued_request_that_does_not_fit_fails_its_sender",
        queued_request_that_does_not_fit_fails_its_sender,
    ),
    (
        "reply_that_does_not_fit_fails_both",
        reply_that_does_not_fit_fails_both,
    ),
    (
        "closed_handle_stays_bad_after_many_transfers",
        closed_handle_stays_bad_after_many_transfers,
    ),
    (
        "send_handle_cannot_travel_in_its_own_send",
        send_handle_cannot_travel_in_its_own_send,
    ),
    ("same_handle_twice_is_invalid", same_handle_twice_is_invalid),
    (
        "memory_object_carries_a_request",
        memory_object_carries_a_request,
    ),
    (
        "memory_object_comes_back_in_a_reply",
        memory_object_comes_back_in_a_reply,
    ),
    (
        "narrowed_memory_handle_maps_read_only",
        narrowed_memory_handle_maps_read_only,
    ),
    ("shared_pages_show_both_sides", shared_pages_show_both_sides),
];

/// The handles `exited_threads_hold_no_numbers` keeps.
static HELD: [AtomicU64; PAST_NUMBERS] = [const { AtomicU64::new(0) }; PAST_NUMBERS];

/// A thread gives its number back as it ends (spec 6.1, 8): init makes
/// more threads than the system has numbers, one after another, each above
/// init, so that it runs and exits at once, and keeps its handle; none
/// fails with LIMIT_REACHED. Then init closes the handles.
fn exited_threads_hold_no_numbers() -> Outcome {
    reset_marks();
    let mut made = Ok(());
    for held in &HELD {
        let t = thread(0, add_mark, 0, HIGH, Policy::Fifo).and_then(|t| {
            let started = sys::thread_start(&t);
            held.store(t.raw().0, Relaxed);
            started.map_err(|_| "thread_start failed")
        });
        if let Err(why) = t {
            made = Err(why);
            break;
        }
    }
    for held in &HELD {
        let h = held.swap(0, Relaxed);
        if h != 0 {
            close(Handle::<Thread>::from_raw(abi::Handle(h)))?;
        }
    }
    check(
        made.is_ok() && mark(0) == PAST_NUMBERS as u64,
        "a thread that exited kept its number: thread_create failed",
    )
}

// The message buffer (spec 6.2): TPIDRRO_EL0 holds its address; bytes 64
// and up of a message go from the sender's buffer into the receiver's, at
// their offsets, and the kernel leaves bytes 0-63 and the bytes past the
// length alone.

/// The seeds of the patterns of the buffer tests: init's buffer, a
/// client's buffer, and the bytes of a message.
const INIT_SEED: u8 = 0x11;
const CLIENT_SEED: u8 = 0x5B;
const MESSAGE_SEED: u8 = 0xC3;

/// MESSAGE_MAX bytes that differ from those of another seed at each
/// offset.
fn pattern(seed: u8) -> [u8; abi::MESSAGE_MAX] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(31) ^ (i >> 8) as u8 ^ seed)
}

/// Fills the data of the calling thread's message buffer with
/// pattern(seed).
fn fill_buffer(seed: u8) {
    rt::msgbuf::write(0, &pattern(seed));
}

/// The data of the calling thread's message buffer.
fn buffer_data() -> [u8; abi::MESSAGE_MAX] {
    let mut data = [0; abi::MESSAGE_MAX];
    rt::msgbuf::read(0, &mut data);
    data
}

/// Leaves the address of its message buffer in mark `i` and ends.
extern "C" fn note_buffer(i: u64) -> ! {
    MARKS[i as usize].store(rt::msgbuf::address() as u64, Relaxed);
    sys::thread_exit()
}

/// Spec 6.2: TPIDRRO_EL0 holds the address of the thread's message buffer:
/// abi::INIT_MSGBUF for init's first thread, and for a thread
/// thread_create made, the page it named.
fn buffer_address_is_in_tpidrro() -> Outcome {
    reset_marks();
    let own = rt::msgbuf::address();
    let t = spawn(0, note_buffer, 0, HIGH, Policy::Fifo)?;
    close(t)?;
    check(
        own == abi::INIT_MSGBUF as usize,
        "init's TPIDRRO_EL0 does not hold its message buffer",
    )?;
    check(
        mark(0) == buffer(0) as u64,
        "a new thread's TPIDRRO_EL0 does not hold its message buffer",
    )
}

/// A client in slot 0 that fills its buffer with pattern(CLIENT_SEED),
/// sends the first `len` bytes of pattern(MESSAGE_SEED) through the
/// channel HANDLES holds for it, and leaves the code and the length of
/// the reply in `result`; ends.
extern "C" fn pattern_client(len: u64) -> ! {
    fill_buffer(CLIENT_SEED);
    match sys::send(&handle(0), &pattern(MESSAGE_SEED)[..len as usize]) {
        Ok(reply) => record(0, &[0, reply.len as u64]),
        Err(e) => record(0, &[e.code()]),
    }
    ENDED[0].store(1, Relaxed);
    sys::thread_exit()
}

/// Spec 15.2 (messages): a request of 1024 bytes arrives whole (spec 6.1,
/// 6.2): a client above init sends pattern bytes, and init takes the
/// request without waiting: its buffer holds all of them.
fn long_request_arrives_whole() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let max = abi::MESSAGE_MAX;
    let t = spawn(0, pattern_client, max as u64, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let whole = matches!(got, Ok(Received::Message { len, .. }) if len == max)
        && buffer_data() == pattern(MESSAGE_SEED);
    let replied = answer_all([got]);
    close(t)?;
    close(c)?;
    check(whole, "the request of 1024 bytes did not arrive whole")?;
    check(
        replied && ended(0) && result(0)[..2] == [0, 0],
        "the client did not get the reply",
    )
}

/// A client in slot 0 that sends request(0) through the channel HANDLES
/// holds for it and, once the reply came, leaves in `result` the code, the
/// length of the reply and 1 when its buffer holds pattern(MESSAGE_SEED);
/// ends.
extern "C" fn client_looks(_: u64) -> ! {
    match sys::send(&handle(0), &request(0)) {
        Ok(reply) => {
            let whole = buffer_data() == pattern(MESSAGE_SEED);
            record(0, &[0, reply.len as u64, u64::from(whole)]);
        }
        Err(e) => record(0, &[e.code()]),
    }
    ENDED[0].store(1, Relaxed);
    sys::thread_exit()
}

/// Spec 15.2 (messages): a reply of 1024 bytes arrives whole: a client
/// above init sends 16 bytes, init answers with pattern bytes, and the
/// client's buffer holds all of them when its send returns.
fn long_reply_arrives_whole() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let t = spawn(0, client_looks, 0, HIGH, Policy::Fifo)?;
    let replied = take_token(&c).map(|token| token.reply(&pattern(MESSAGE_SEED)));
    close(t)?;
    close(c)?;
    check(
        replied == Ok(Ok(())) && ended(0),
        "the reply failed or did not reach the client",
    )?;
    check(
        result(0)[..3] == [0, abi::MESSAGE_MAX as u64, 1],
        "the reply of 1024 bytes did not arrive whole",
    )
}

/// A client in slot 0 that fills its buffer with pattern(CLIENT_SEED),
/// sends 64 bytes through the channel HANDLES holds for it and leaves in
/// `result` the code and 1 when its buffer still holds the pattern after
/// the reply; ends.
extern "C" fn short_client(_: u64) -> ! {
    fill_buffer(CLIENT_SEED);
    match sys::send(&handle(0), &[0xC5; abi::INLINE_MAX]) {
        Ok(_) => record(0, &[0, u64::from(buffer_data() == pattern(CLIENT_SEED))]),
        Err(e) => record(0, &[e.code()]),
    }
    ENDED[0].store(1, Relaxed);
    sys::thread_exit()
}

/// Messages of 64 bytes leave the buffers alone (spec 6.2): they travel in
/// x2-x9 only. Init's buffer and a client's hold patterns; the client
/// sends 64 bytes, init takes them and answers with 64: both buffers keep
/// their patterns.
fn short_message_leaves_the_buffers_alone() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    fill_buffer(INIT_SEED);
    let t = spawn(0, short_client, 0, HIGH, Policy::Fifo)?;
    let token = take_token(&c);
    let kept = buffer_data() == pattern(INIT_SEED);
    let replied = token.map(|token| token.reply(&[0x3C; abi::INLINE_MAX]));
    close(t)?;
    close(c)?;
    check(kept, "a request of 64 bytes changed the receiver's buffer")?;
    check(
        replied == Ok(Ok(())) && ended(0) && result(0)[..2] == [0, 1],
        "a reply of 64 bytes changed the client's buffer",
    )
}

/// A client in slot 0 that fills its buffer with pattern(CLIENT_SEED) and
/// sends 8 bytes with raw registers through the channel HANDLES holds for
/// it; then leaves in `result` x0-x2 of the call and 1 when its buffer
/// holds bytes 64-127 of pattern(INIT_SEED) and its own pattern elsewhere;
/// ends.
extern "C" fn raw_looker(_: u64) -> ! {
    fill_buffer(CLIENT_SEED);
    let mut x = marked();
    x[..2].copy_from_slice(&[HANDLES[0].load(Relaxed), 8]);
    let after = raw_send(x);
    let mut want = pattern(CLIENT_SEED);
    want[64..128].copy_from_slice(&pattern(INIT_SEED)[64..128]);
    let seen = u64::from(buffer_data() == want);
    record(0, &[after[0], after[1], after[2], seen]);
    ENDED[0].store(1, Relaxed);
    sys::thread_exit()
}

/// The kernel leaves bytes 0-63 of the buffers alone (spec 6.2): they
/// travel in x2-x9. A client fills its buffer with a pattern and sends;
/// init fills its own with another and answers with 128 bytes through raw
/// registers, every bit of x2-x9 set. The client gets init's registers in
/// x2-x9 and bytes 64-127 of init's buffer; its own bytes 0-63 and past
/// 127 stay.
fn kernel_leaves_bytes_0_to_63_of_the_buffer() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let t = spawn(0, raw_looker, 0, HIGH, Policy::Fifo)?;
    fill_buffer(INIT_SEED);
    let mut x = [u64::MAX; 10];
    x[1] = 128;
    let after = take_token(&c).map(|token| {
        x[0] = token.raw();
        raw_reply(x)
    });
    close(t)?;
    close(c)?;
    check(
        after.is_ok_and(|a| a[0] == 0) && ended(0),
        "the reply failed or did not reach the client",
    )?;
    check(
        result(0)[..4] == [0, 128, u64::MAX, 1],
        "the kernel touched bytes 0-63 or past the length of a buffer",
    )
}

/// The receiver's buffer past the length stays as it was (spec 6.2): init's
/// buffer holds a pattern; a client, its buffer full of another, sends 100
/// bytes, and init takes them: its buffer holds the 100 bytes and its own
/// pattern after them.
fn bytes_past_the_length_stay() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    fill_buffer(INIT_SEED);
    let t = spawn(0, pattern_client, 100, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let came = matches!(got, Ok(Received::Message { len: 100, .. }));
    let data = buffer_data();
    let replied = answer_all([got]);
    close(t)?;
    close(c)?;
    let mut want = pattern(INIT_SEED);
    want[..100].copy_from_slice(&pattern(MESSAGE_SEED)[..100]);
    check(
        came && data == want,
        "a request of 100 bytes changed the receiver's buffer past its length",
    )?;
    check(
        replied && ended(0) && result(0)[..2] == [0, 0],
        "the client did not get the reply",
    )
}

// Handles in messages (spec 6.1, 6.2): a request or a reply carries up to
// four handles, whose values lie in the message buffer; they move from the
// sender's table into the receiver's with their rights and labels, and the
// buffer tells the receiver the kind and the rights of each. They stay
// with the sender when a check of the call fails, and go when the call
// fails with PEER_CLOSED, LIMIT_REACHED or NO_MEMORY.

/// The handles `handle_client` sends, and how many of them.
static GIVEN: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static GIVEN_COUNT: AtomicU64 = AtomicU64::new(0);

/// Entries init's table has at most (kcore::handles::MAX_HANDLES): its
/// limit, which the kernel sets.
const INIT_HANDLES: usize = 16384;

/// The copies `fill_table` made, which `empty_table` closes.
static FILLED: [AtomicU64; INIT_HANDLES] = [const { AtomicU64::new(0) }; INIT_HANDLES];

/// Values that name no live handle: the next generation of entry 1000 of
/// init's table, which no test reaches (spec 5.1).
const STALE: abi::Handle = abi::Handle::new(1000, 1 << 40);

/// Sets the handles `handle_client` sends.
pub(crate) fn give(handles: &[abi::Handle]) {
    for (g, h) in GIVEN.iter().zip(handles) {
        g.store(h.0, Relaxed);
    }
    GIVEN_COUNT.store(handles.len() as u64, Relaxed);
}

/// A client in `slot` that sends request(slot) with the handles GIVEN
/// holds through the channel HANDLES holds for it, and leaves in `result`
/// the code, the length and the count of handles of the reply, then the
/// value and the info word of each handle the reply brought; ends.
pub(crate) extern "C" fn handle_client(slot: u64) -> ! {
    let s = slot as usize;
    let n = GIVEN_COUNT.load(Relaxed) as usize;
    let handles: [abi::Handle; 4] = core::array::from_fn(|i| abi::Handle(GIVEN[i].load(Relaxed)));
    match sys::send_handles(&handle(s), &request(s), &handles[..n]) {
        Ok(reply) => {
            let mut w = [0; 11];
            w[1] = reply.len as u64;
            w[2] = reply.handles as u64;
            for i in 0..reply.handles {
                let (h, (kind, rights)) = rt::msgbuf::handle(i);
                w[3 + 2 * i] = h.0;
                w[4 + 2 * i] = abi::msgbuf::info(kind, rights);
            }
            record(s, &w);
        }
        Err(e) => record(s, &[e.code()]),
    }
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// handle_close with the value `h`, for values that must be bad.
pub(crate) fn close_raw(h: abi::Handle) -> Result<(), Error> {
    Handle::<Channel>::from_raw(h).close()
}

/// Whether each of `handles` is gone: closing it is BAD_HANDLE.
fn all_gone(handles: &[abi::Handle]) -> bool {
    handles
        .iter()
        .all(|&h| close_raw(h) == Err(Error::BadHandle))
}

/// A copy of `h` with `rights` as a raw value, which the test hands the
/// kernel in a message.
pub(crate) fn copy_raw<K>(h: &Handle<K>, rights: Rights) -> Result<abi::Handle, &'static str> {
    copy(h, rights).map(|c| c.raw())
}

/// x0-x9 of a raw send through `h` of 8 bytes and `handles`, whose values
/// go into the message buffer, the rest marked.
fn handle_regs(h: abi::Handle, handles: &[abi::Handle], flags: u64) -> Regs {
    rt::msgbuf::put_handles(handles);
    let mut x = marked();
    x[..2].copy_from_slice(&[
        h.0,
        8 | (handles.len() as u64) << abi::HANDLES_SHIFT | flags,
    ]);
    x
}

/// Fills init's table with copies of the system resource without rights
/// until it has room for `room` handles more; returns how many copies it
/// keeps, which `empty_table` closes.
fn fill_table(room: usize) -> Result<usize, &'static str> {
    let mut n = 0;
    loop {
        match sys::handle_duplicate(&init::RESOURCE, Rights::NONE) {
            Ok(h) => FILLED[n].store(h.raw().0, Relaxed),
            Err(Error::LimitReached) => break,
            Err(_) => return Err("handle_duplicate failed"),
        }
        n += 1;
    }
    for _ in 0..room {
        n -= 1;
        close_raw(abi::Handle(FILLED[n].load(Relaxed))).map_err(|_| "handle_close failed")?;
    }
    Ok(n)
}

/// Closes the first `n` copies of `fill_table`.
fn empty_table(n: usize) -> Outcome {
    FILLED[..n].iter().try_for_each(|h| {
        close_raw(abi::Handle(h.load(Relaxed))).map_err(|_| "handle_close failed")
    })
}

/// Spec 15.2 (messages): handles move with a request (spec 6.1, 6.2). A
/// client above init sends a copy of a channel, a timer, init's process
/// and the system resource, each with TRANSFER and some other rights;
/// init takes the request without waiting: four handles, whose info words
/// give the kind and the rights of each, the same as the client's. The
/// client's values are gone from the table (BAD_HANDLE), and the new ones
/// live.
fn handles_move_with_a_request() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    let tm = timer(&e)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let rights = [
        Rights::SEND | Rights::NOTIFY | Rights::TRANSFER,
        Rights::MANAGE | Rights::TRANSFER,
        Rights::MANAGE | Rights::TRANSFER,
        Rights::DEBUG | Rights::TRANSFER,
    ];
    let sent = [
        copy_raw(&e, rights[0])?,
        copy_raw(&tm, rights[1])?,
        copy_raw(&init::PROCESS, rights[2])?,
        copy_raw(&init::RESOURCE, rights[3])?,
    ];
    give(&sent);
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let came: [_; 4] = core::array::from_fn(rt::msgbuf::handle);
    let kinds = [
        abi::ObjectKind::Channel,
        abi::ObjectKind::Timer,
        abi::ObjectKind::Process,
        abi::ObjectKind::Resource,
    ];
    let four = matches!(got, Ok(Received::Message { handles: 4, .. }));
    let told = (0..4).all(|i| came[i].1 == (kinds[i], rights[i]));
    let replied = answer_all([got]);
    let gone = all_gone(&sent);
    let live = came.iter().all(|&(h, _)| close_raw(h).is_ok());
    close(t)?;
    for h in [c, e] {
        close(h)?;
    }
    close(tm)?;
    check(
        four && told,
        "the request did not bring four handles with their kinds and rights",
    )?;
    check(
        gone && live,
        "the handles did not leave the client's values for new ones",
    )?;
    check(
        replied && ended(0) && result(0)[..3] == [0, 0, 0],
        "the client did not get the reply",
    )
}

/// Spec 15.2 (messages): handles move with a reply. A client above init
/// sends; init answers with a copy of a channel and one of the client's
/// thread: the client's send brings two handles, whose values and info
/// words it leaves; init's values are gone, and the client's live.
fn handles_move_with_a_reply() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    give(&[]);
    let rights = [
        Rights::NOTIFY | Rights::TRANSFER,
        Rights::MANAGE | Rights::TRANSFER,
    ];
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let sent = [copy_raw(&e, rights[0])?, copy_raw(&t, rights[1])?];
    let replied = take_token(&c)?.reply_handles(&[], &sent);
    let got = result(0);
    let gone = all_gone(&sent);
    let live = [got[3], got[5]]
        .iter()
        .all(|&h| close_raw(abi::Handle(h)).is_ok());
    close(t)?;
    close(c)?;
    close(e)?;
    let infos = [
        abi::msgbuf::info(abi::ObjectKind::Channel, rights[0]),
        abi::msgbuf::info(abi::ObjectKind::Thread, rights[1]),
    ];
    check(
        replied.is_ok() && ended(0) && got[..3] == [0, 0, 2],
        "the reply did not bring two handles",
    )?;
    check(
        [got[4], got[6]] == infos,
        "the handles of the reply came with other kinds or rights",
    )?;
    check(
        gone && live,
        "the handles did not leave init's values for the client's",
    )
}

/// Spec 15.2 (messages): rights stay as narrow as the handle that moved
/// (spec 5.2, 6.1). A client sends a copy of a channel with SEND and
/// TRANSFER only; init's new handle says so, receives through it with
/// ACCESS_DENIED, and cannot copy it without DUPLICATE.
fn rights_stay_narrowed() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let narrow = Rights::SEND | Rights::TRANSFER;
    give(&[copy_raw(&c, narrow)?]);
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let (h, info) = rt::msgbuf::handle(0);
    let came = Handle::<Channel>::from_raw(h);
    let refused = sys::try_receive(&came) == Err(Error::AccessDenied)
        && sys::handle_duplicate(&came, Rights::NONE) == Err(Error::AccessDenied);
    let replied = answer_all([got]);
    close(came)?;
    close(t)?;
    close(c)?;
    check(
        info == (abi::ObjectKind::Channel, narrow),
        "the handle came with other rights",
    )?;
    check(refused, "a right the handle lacked came with it")?;
    check(replied && ended(0), "the client did not get the reply")
}

/// Spec 15.2 (messages): a label travels with its handle, and the copies
/// of its session stay as they were (spec 5.3): a client sends the only
/// copy with a label of a channel; no CLIENT_GONE comes meanwhile, a
/// notification through init's new handle comes with the label, and
/// CLIENT_GONE comes once init closes it.
fn label_travels_with_its_handle() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let named = session(&e, Rights::NOTIFY | Rights::TRANSFER, CLIENT_LABEL, QUIET)?;
    give(&[named.raw()]);
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let (h, info) = rt::msgbuf::handle(0);
    let came = Handle::<Channel>::from_raw(h);
    let early = sys::try_receive(&e);
    let posted = sys::notify(&came, 1);
    let heard = take_one(&e);
    close(came)?;
    let gone = take_one(&e);
    let replied = answer_all([got]);
    close(t)?;
    close(c)?;
    close(e)?;
    check(
        early == Err(Error::WouldBlock),
        "the session's CLIENT_GONE came while its handle moved",
    )?;
    check(
        info == (abi::ObjectKind::Channel, Rights::NOTIFY | Rights::TRANSFER),
        "a handle with a label came as another kind",
    )?;
    check(
        posted.is_ok() && heard == Ok(labelled(CLIENT_LABEL, 1, 1)),
        "a notification through the handle that moved lost its label",
    )?;
    check(
        gone == Ok(labelled(CLIENT_LABEL, CLIENT_GONE, 1)),
        "CLIENT_GONE did not come once the handle that moved went",
    )?;
    check(replied && ended(0), "the client did not get the reply")
}

/// The last handle with RECEIVE moves without closing its channel (spec
/// 5.3, 6.1): a client sends it; a copy with NOTIFY notifies meanwhile,
/// and init receives the notification through its new handle; once init
/// closes that, notify fails with PEER_CLOSED.
fn receive_right_moves_without_closing_the_channel() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    let n = copy(&e, Rights::NOTIFY)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    give(&[e.raw()]);
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let came = Handle::<Channel>::from_raw(rt::msgbuf::handle(0).0);
    let open = sys::notify(&n, 1);
    let heard = take_one(&came);
    close(came)?;
    let shut = sys::notify(&n, 1);
    let replied = answer_all([got]);
    close(n)?;
    close(t)?;
    close(c)?;
    check(
        open.is_ok() && heard == Ok(unlabeled(1, 1)),
        "the channel closed when its last handle with RECEIVE moved",
    )?;
    check(
        shut == Err(Error::PeerClosed),
        "the channel stayed open once the handle that moved went",
    )?;
    check(replied && ended(0), "the client did not get the reply")
}

/// The handles stay with the sender when a check of the call fails (spec
/// 6.1, 11): a bad x0, one of another kind or without SEND, a handle of the
/// message without TRANSFER or bad after good ones, and NO_WAIT with no
/// receiver fail send, as a token that names nothing fails reply; each
/// changes x0 alone, and the good handles still close.
fn a_failed_check_takes_no_handle() -> Outcome {
    let c = channel(QUIET)?;
    let notify_only = copy(&c, Rights::NOTIFY)?;
    let e = channel(QUIET)?;
    let good = [
        copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?,
        copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?,
    ];
    let held = copy_raw(&e, Rights::NOTIFY)?;
    let [a, b] = good;
    let cases = [
        (STALE, &[a, b][..], 0, Error::BadHandle),
        (init::PROCESS.raw(), &[a, b], 0, Error::WrongType),
        (notify_only.raw(), &[a, b], 0, Error::AccessDenied),
        (c.raw(), &[a, b, held], 0, Error::AccessDenied),
        (c.raw(), &[a, b, STALE], 0, Error::BadHandle),
        (c.raw(), &[a, b], abi::NO_WAIT, Error::WouldBlock),
    ];
    let sent = cases.map(|(h, handles, flags, error)| {
        let x = handle_regs(h, handles, flags);
        failed(raw_send(x), x, error)
    });
    let x = handle_regs(abi::Handle(1 << 16), &[a, b], 0);
    let replied = failed(raw_reply(x), x, Error::BadState);
    let kept = [a, b, held].iter().all(|&h| close_raw(h).is_ok());
    close(notify_only)?;
    close(c)?;
    close(e)?;
    check(
        sent.iter().all(|&ok| ok),
        "send with a failing check did not fail as it should, x0 alone",
    )?;
    check(
        replied,
        "reply with a bad token did not fail with BAD_STATE alone",
    )?;
    check(kept, "a call that failed a check took a handle")
}

/// PEER_CLOSED takes the handles (spec 6.1): send with two handles through
/// a copy of a channel whose last handle with RECEIVE went fails with
/// PEER_CLOSED in x0 alone, and the handles are gone.
fn peer_closed_takes_the_handles() -> Outcome {
    let c = channel(QUIET)?;
    let left = copy(&c, Rights::SEND)?;
    let e = channel(QUIET)?;
    let sent = [
        copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?,
        copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?,
    ];
    close(c)?;
    let x = handle_regs(left.raw(), &sent, 0);
    let after = raw_send(x);
    let gone = all_gone(&sent);
    close(left)?;
    close(e)?;
    check(
        failed(after, x, Error::PeerClosed),
        "send to a closed channel did not fail with PEER_CLOSED alone",
    )?;
    check(gone, "PEER_CLOSED left the handles with the sender")
}

/// A receiver whose table has no room fails the sender (spec 6.1): a
/// thread of init waits in receive, and init fills its own table but for
/// three entries; send with four handles fails with LIMIT_REACHED in x0
/// alone, the handles are gone, and the receiver waits on: a request with
/// no handles and NO_WAIT then reaches it.
fn full_waiting_receiver_fails_the_sender() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let w = spawn(0, server, 0, LOW, Policy::Fifo)?;
    let_run()?;
    let sent: [abi::Handle; 4] = [
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
    ];
    let n = fill_table(3)?;
    let x = handle_regs(c.raw(), &sent, 0);
    let after = raw_send(x);
    empty_table(n)?;
    let gone = all_gone(&sent);
    let waited = result(0) == [0; 12];
    let got = sys::try_send(&c, &request(1));
    let_run()?;
    close(w)?;
    close(c)?;
    check(
        failed(after, x, Error::LimitReached),
        "send to a receiver with no room did not fail with LIMIT_REACHED alone",
    )?;
    check(
        gone && waited,
        "the handles stayed, or the receiver took the request",
    )?;
    check(
        got.is_ok() && result(0)[..2] == [0, 16] && result(0)[2..4] == words(&request(1))[..2],
        "the receiver did not take the next request",
    )
}

/// A receiver whose quota falls short for a chunk of its table fails the
/// sender (spec 6.1, 7.5): a thread of init waits in receive; init fills
/// its table to the end of a page of its pool of blocks, a child takes the
/// rest of init's quota, and send with four handles fails with NO_MEMORY in
/// x0 alone; the handles are gone, and the receiver waits on: a request
/// with no handles and NO_WAIT then reaches it.
fn receiver_quota_fails_the_sender() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let w = spawn(0, server, 0, LOW, Policy::Fifo)?;
    let_run()?;
    let sent: [abi::Handle; 4] = [
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
    ];
    // A free place in init's pool of shells for the child below.
    close(child(LOW)?)?;
    let n = fill_to_a_page()?;
    let own = sys::process_memory(&init::PROCESS).map_err(|_| "PROCESS_MEMORY of init failed")?;
    let rest = (own.quota - own.returned - own.used) / PAGE as u64 * PAGE as u64;
    let hog = sys::process_create(rest, 16, LOW);
    let x = handle_regs(c.raw(), &sent, 0);
    let after = raw_send(x);
    let made = hog.is_ok();
    if let Ok(hog) = hog {
        close(hog)?;
    }
    empty_table(n)?;
    let gone = all_gone(&sent);
    let waited = result(0) == [0; 12];
    let got = sys::try_send(&c, &request(1));
    let_run()?;
    close(w)?;
    close(c)?;
    check(made, "the child that takes init's quota was not made")?;
    check(
        failed(after, x, Error::NoMemory),
        "send to a receiver with no quota for a chunk did not fail with NO_MEMORY alone",
    )?;
    check(
        gone && waited,
        "the handles stayed, or the receiver took the request",
    )?;
    check(
        got.is_ok() && result(0)[..2] == [0, 16],
        "the receiver did not take the next request",
    )
}

/// A child that fails leaves the start channel with init (spec 13.3): a
/// quota of a page falls short at entry 0 of the child's table, NO_MEMORY,
/// and x0 alone changes; the handle x5 named still works, and init has its
/// quota back. With init's table full the call fails with LIMIT_REACHED
/// before it makes anything (spec 11), x0 alone, and x5 stays as well. The
/// exit channel of the failed calls gets its slot back: the channel goes
/// afterwards with no source left.
fn failed_create_keeps_the_start_handle() -> Outcome {
    let c = channel(QUIET)?;
    let exit = copy(&c, Rights::NOTIFY)?;
    let used = || sys::process_memory(&init::PROCESS).map(|m| m.used);
    let before = used();
    let mut x = create_regs(exit.raw(), QUIET.into(), c.raw());
    x[0] = PAGE as u64;
    let after = raw_create(x);
    let back = used();
    let n = fill_table(0)?;
    let y = create_regs(exit.raw(), QUIET.into(), c.raw());
    let full = raw_create(y);
    empty_table(n)?;
    let posted = sys::notify(&c, 1);
    let got = take_one(&c);
    let kept = c.close();
    // The channel goes now: it holds no source but its slot of label 0.
    close(exit)?;
    check(
        failed(after, x, Error::NoMemory),
        "a child with a quota of a page did not fail with NO_MEMORY alone",
    )?;
    check(
        failed(full, y, Error::LimitReached),
        "a child with init's table full did not fail with LIMIT_REACHED alone",
    )?;
    check(
        posted.is_ok() && got == Ok(unlabeled(1, 1)) && kept.is_ok(),
        "init lost the start channel of a child that failed",
    )?;
    check(
        before.is_ok() && back == before,
        "a child that failed kept init's quota",
    )
}

/// Fills init's table to the end of a page of its pool of blocks, which
/// holds two chunks of 64 entries (spec 5.1, 7.8), but for one entry: the
/// copy that makes init pay for a page starts the page's first chunk, and
/// 126 more fill it and the second but for its last entry. Returns the
/// copies, which `empty_table` closes; it closes them itself on a failure.
fn fill_to_a_page() -> Result<usize, &'static str> {
    let used = || sys::process_memory(&init::PROCESS).map(|m| m.used);
    let mut n = 0;
    let mut left = None;
    while left != Some(0) {
        let before = used();
        let Ok(h) = sys::handle_duplicate(&init::RESOURCE, Rights::NONE) else {
            empty_table(n)?;
            return Err("handle_duplicate failed");
        };
        FILLED[n].store(h.raw().0, Relaxed);
        n += 1;
        left = match left {
            Some(k) => Some(k - 1),
            None if used() != before => Some(126),
            None => None,
        };
    }
    Ok(n)
}

/// A request whose handles do not fit fails its sender, and receive takes
/// the next head (spec 6.1): a client below init sends four handles
/// through a copy with a label, and another one no handles through the
/// channel, and both wait; init closes the copy, so the first request
/// holds the session's last copy (spec 5.3), fills its table and receives
/// without waiting: the first client gets LIMIT_REACHED, and init gets the
/// second request. Before the first client runs again, its handles are
/// gone, the only copy of a session of another channel among them, whose
/// CLIENT_GONE comes there; and so is the copy its request held, whose
/// CLIENT_GONE comes after the second request.
fn queued_request_that_does_not_fit_fails_its_sender() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    let named = session(&c, Rights::SEND, CLIENT_LABEL, QUIET)?;
    HANDLES[0].store(named.raw().0, Relaxed);
    HANDLES[1].store(c.raw().0, Relaxed);
    let sent: [abi::Handle; 4] = [
        session(&e, Rights::NOTIFY | Rights::TRANSFER, CLIENT_LABEL, QUIET)?.raw(),
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
    ];
    give(&sent);
    let first = spawn(0, handle_client, 0, LOW, Policy::Fifo)?;
    let_run()?;
    close(named)?;
    let second = spawn(1, client, 1, LOW, Policy::Fifo)?;
    let_run()?;
    let n = fill_table(0)?;
    let got = sys::try_receive(&c);
    empty_table(n)?;
    let gone = all_gone(&sent);
    let dropped = take_one(&e);
    let released = take_one(&c);
    let waited = !ended(0);
    let words_of = match &got {
        Ok(Received::Message { words, .. }) => Some(*words),
        _ => None,
    };
    let replied = answer_all([got]);
    let_run()?;
    close(first)?;
    close(second)?;
    close(c)?;
    close(e)?;
    check(
        ended(0) && result(0)[0] == Error::LimitReached.code(),
        "the sender whose handles did not fit did not get LIMIT_REACHED",
    )?;
    check(waited, "the sender that failed ran before init looked")?;
    check(
        gone && dropped == Ok(labelled(CLIENT_LABEL, CLIENT_GONE, 1)),
        "the handles of the request that failed stayed with its sender",
    )?;
    check(
        released == Ok(labelled(CLIENT_LABEL, CLIENT_GONE, 1)),
        "the request that failed kept its copy of the session",
    )?;
    check(
        words_of == Some(words(&request(1))) && replied && ended(1) && result(1)[0] == 0,
        "receive did not take the next request",
    )
}

/// A reply whose handles do not fit fails both sides and uses the token up
/// (spec 6.1): a client above init sends; init fills its table and answers
/// with four handles, the only copy of a session of another channel among
/// them: LIMIT_REACHED for the reply, in x0 alone, and for the client's
/// send; the handles are gone, and CLIENT_GONE comes on the other channel;
/// a second reply with the token is BAD_STATE. Init's next reply, with a
/// handle, brings it to a second client: the reply that failed left
/// nothing on its way.
fn reply_that_does_not_fit_fails_both() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    for h in &HANDLES[..2] {
        h.store(c.raw().0, Relaxed);
    }
    let sent: [abi::Handle; 4] = [
        session(&e, Rights::NOTIFY | Rights::TRANSFER, CLIENT_LABEL, QUIET)?.raw(),
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
    ];
    let t = spawn(0, client, 0, HIGH, Policy::Fifo)?;
    let token = take_token(&c)?.raw();
    let n = fill_table(0)?;
    let x = handle_regs(abi::Handle(token), &sent, 0);
    let after = raw_reply(x);
    empty_table(n)?;
    let gone = all_gone(&sent);
    let dropped = take_one(&e);
    let mut again = marked();
    again[..2].copy_from_slice(&[token, 0]);
    let second = raw_reply(again);
    give(&[]);
    let next = spawn(1, handle_client, 1, HIGH, Policy::Fifo)?;
    let moved = copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?;
    let replied = take_token(&c)?.reply_handles(&[], &[moved]);
    let came = result(1);
    let live = close_raw(abi::Handle(came[3])).is_ok();
    close(t)?;
    close(next)?;
    close(c)?;
    close(e)?;
    check(
        failed(after, x, Error::LimitReached),
        "a reply with no room at the client did not fail with LIMIT_REACHED alone",
    )?;
    check(
        ended(0) && result(0)[0] == Error::LimitReached.code(),
        "the client's send did not fail with the reply",
    )?;
    check(
        gone && dropped == Ok(labelled(CLIENT_LABEL, CLIENT_GONE, 1)),
        "the handles of the reply that failed stayed",
    )?;
    check(
        failed(second, again, Error::BadState),
        "the reply that failed left its token",
    )?;
    check(
        replied.is_ok() && ended(1) && came[..3] == [0, 0, 1] && live,
        "the next reply did not bring its handle",
    )
}

/// Rounds of `closed_handle_stays_bad_after_many_transfers`.
const TRANSFERS: u64 = 1000;

/// A client that sends TRANSFERS requests through the channel HANDLES
/// holds for `slot`, each with a new copy of the handle GIVEN holds, the
/// next once the reply came; leaves the first error or 0 in `result`;
/// ends.
extern "C" fn transfers(slot: u64) -> ! {
    let s = slot as usize;
    let object = Handle::<Channel>::from_raw(abi::Handle(GIVEN[0].load(Relaxed)));
    let mut code = 0;
    for _ in 0..TRANSFERS {
        let sent = sys::handle_duplicate(&object, Rights::NOTIFY | Rights::TRANSFER)
            .and_then(|h| sys::send_handles(&handle(s), &[], &[h.raw()]));
        if let Err(e) = sent {
            code = e.code();
            break;
        }
    }
    record(s, &[code]);
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// Spec 15.2 (messages): a handle that was closed stays bad however often
/// the client sends that object again (spec 5.1): a client sends a new copy
/// of a channel 1000 times; init keeps the value of the first handle that
/// came and closes each: the first value is BAD_HANDLE after every
/// transfer, and no later one repeats it.
fn closed_handle_stays_bad_after_many_transfers() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    give(&[e.raw()]);
    let t = spawn(0, transfers, 0, HIGH, Policy::Fifo)?;
    let mut first = None;
    let mut bad = true;
    for round in 0..TRANSFERS {
        let got = sys::try_receive(&c);
        let (h, _) = rt::msgbuf::handle(0);
        let came = matches!(got, Ok(Received::Message { handles: 1, .. }));
        let first = *first.get_or_insert(h);
        bad &= came
            && (round == 0) == (h == first)
            && close_raw(h).is_ok()
            && close_raw(first) == Err(Error::BadHandle);
        if !answer_all([got]) {
            bad = false;
        }
        if !bad {
            break;
        }
    }
    close(t)?;
    close(c)?;
    close(e)?;
    check(
        bad,
        "the value of a handle that was closed came back or named a handle",
    )?;
    check(
        ended(0) && result(0)[0] == 0,
        "the client's transfers failed",
    )
}

/// Spec 15.2 (messages): x0 of send cannot travel in its own message (spec
/// 6.1): send whose handles hold x0, a channel or a copy with a label,
/// fails with INVALID_ARGS in x0 alone, and the handle still works.
fn send_handle_cannot_travel_in_its_own_send() -> Outcome {
    let c = channel(QUIET)?;
    let named = session(&c, Rights::SEND | Rights::TRANSFER, CLIENT_LABEL, QUIET)?;
    let sent = [c.raw(), named.raw()].map(|h| {
        let x = handle_regs(h, &[h], abi::NO_WAIT);
        failed(raw_send(x), x, Error::InvalidArgs)
    });
    let posted = sys::notify(&c, 1);
    let heard = take_one(&c);
    close(named)?;
    let gone = take_one(&c);
    close(c)?;
    check(
        sent.iter().all(|&ok| ok),
        "send took its own handle in its message",
    )?;
    check(
        posted.is_ok() && heard == Ok(unlabeled(1, 1)),
        "the channel's handle did not stay",
    )?;
    check(
        gone == Ok(labelled(CLIENT_LABEL, CLIENT_GONE, 1)),
        "the copy with a label did not stay",
    )
}

/// A value listed twice in a message fails send and reply with
/// INVALID_ARGS before anything is looked up (spec 6.1, 11), x0 alone; the
/// handle stays.
fn same_handle_twice_is_invalid() -> Outcome {
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    let a = copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?;
    let x = handle_regs(c.raw(), &[a, a], abi::NO_WAIT);
    let sent = failed(raw_send(x), x, Error::InvalidArgs);
    let y = handle_regs(abi::Handle(0), &[a, a], 0);
    let replied = failed(raw_reply(y), y, Error::InvalidArgs);
    let kept = close_raw(a).is_ok();
    close(c)?;
    close(e)?;
    check(sent, "send took a handle listed twice")?;
    check(replied, "reply took a handle listed twice")?;
    check(kept, "a handle listed twice was taken")
}

// Memory objects in messages (spec 6.2, 15.2): a handle to a memory
// object moves with a request or a reply as any handle does, with the
// rights of the copy that moves, and the receiver maps the object into its
// own space with its own mem_map. The services are children with code
// (Role::Service, Role::Provider), which init reaches through a thread of
// its own at HIGH (`memory_client`).

/// The length of the objects of these tests: all a child maps at
/// child::SHARED.
const SHARED_LEN: u64 = (child::SHARED_PAGES * PAGE) as u64;
/// Init's word in a shared object, and the service's.
const INIT_WORD: u64 = 0x1417_5EE5;
const CHILD_WORD: u64 = 0xC41D_5EE5;

/// The two words `memory_client` sends.
static ASKED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// A client in `slot` that sends the words ASKED holds with the handles
/// GIVEN holds through the channel HANDLES holds for it, and leaves in
/// `result` the code of its call, the count of handles of the reply, the
/// value and the info word of its first handle, and its eight words; then
/// ends.
extern "C" fn memory_client(slot: u64) -> ! {
    let s = slot as usize;
    let n = GIVEN_COUNT.load(Relaxed) as usize;
    let handles: [abi::Handle; 4] = core::array::from_fn(|i| abi::Handle(GIVEN[i].load(Relaxed)));
    let words = [
        ASKED[0].load(Relaxed),
        ASKED[1].load(Relaxed),
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let bytes = abi::inline_bytes(&words);
    match sys::send_handles(&handle(s), &bytes[..16], &handles[..n]) {
        Ok(reply) => {
            let mut w = [0; 12];
            w[1] = reply.handles as u64;
            if reply.handles > 0 {
                let (h, (kind, rights)) = rt::msgbuf::handle(0);
                w[2] = h.0;
                w[3] = abi::msgbuf::info(kind, rights);
            }
            w[4..].copy_from_slice(&reply.words);
            record(s, &w);
        }
        Err(e) => record(s, &[e.code()]),
    }
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// A child with `role` and its quota answers one request with `words` and
/// `handles`, which a thread of init at HIGH sends (`memory_client`)
/// through a channel whose handle with RECEIVE the child gets, with its
/// own process: what the client got (`result`, the reply's words from 4
/// on) and why the child ended, once it ended.
pub(crate) fn served(
    role: Role,
    words: [u64; 2],
    handles: &[abi::Handle],
) -> Result<([u64; 12], ProcessState), &'static str> {
    reset_results();
    let c = channel(LEVEL)?;
    let send = copy(&c, Rights::SEND)?;
    HANDLES[0].store(send.raw().0, Relaxed);
    for (a, w) in ASKED.iter().zip(words) {
        a.store(w, Relaxed);
    }
    give(handles);
    let kid = Kid::load(quota_of(role), 16, LEVEL)?;
    let asked = kid
        .start()
        .and_then(|()| kid.serve(role, &[], &[Gift::Given(c.raw()), Gift::Own]))
        .and_then(|()| spawn(0, memory_client, 0, HIGH, Policy::Fifo));
    // The child runs once init waits for its end.
    let state = kid.end();
    kid.close()?;
    close(send)?;
    close(asked?)?;
    check(ended(0), "the client did not come back from its request")?;
    Ok((result(0), state?))
}

/// Writes PATTERN plus i into word i of `m`, of SHARED_LEN bytes, through a
/// mapping at WINDOW that goes again; returns the sum of the words.
fn with_pattern(m: &Handle<Memory>) -> Result<u64, &'static str> {
    const PATTERN: u64 = 0x0B1E_C700_0000;
    map(m, 0, SHARED_LEN, WINDOW, Access::ReadWrite)?;
    let mut sum = 0u64;
    for i in 0..SHARED_LEN as usize / 8 {
        let w = PATTERN + i as u64;
        // SAFETY: the window is init's mapping of `m`, read and write.
        unsafe { (WINDOW as *mut u64).add(i).write_volatile(w) };
        sum = sum.wrapping_add(w);
    }
    unmap(WINDOW, SHARED_LEN)?;
    Ok(sum)
}

/// Spec 15.2 (messages), 6.2: a memory object carries a request. Init
/// fills an object with a pattern and sends a copy of its handle with
/// MAP_READ and TRANSFER alone to a service, a child: the info word the
/// child finds with the handle names a memory object with those rights,
/// and the child maps the object R, adds its words up and answers with the
/// sum, the pattern's. The copy left init's table.
fn memory_object_carries_a_request() -> Outcome {
    let m = memory_object(child::SHARED_PAGES as u64)?;
    let sum = with_pattern(&m);
    let rights = Rights::MAP_READ | Rights::TRANSFER;
    let sent = copy_raw(&m, rights)?;
    let got = sum.and_then(|_| served(Role::Service, [SHARED_LEN, 0], &[sent]));
    let gone = close_raw(sent) == Err(Error::BadHandle);
    close(m)?;
    let (reply, state) = got?;
    check(
        state == ProcessState::Exited { code: 0 },
        "the service did not answer",
    )?;
    check(
        reply[4] == abi::msgbuf::info(abi::ObjectKind::Memory, rights),
        "the handle came to the service as no memory object, or with other rights",
    )?;
    check(
        Ok(reply[5]) == sum,
        "the service did not see the pattern init wrote",
    )?;
    check(gone, "the copy that moved stayed in init's table")
}

/// Spec 15.2 (messages), 5.2, 7.4: a memory object comes back in a reply,
/// and outlives its maker (spec 7.5). A provider, a child, makes an
/// object, which its quota pays for by its parts, fills it with a
/// pattern and answers init's request with a copy of its handle with
/// MAP_READ and TRANSFER alone, and ends. Then init maps the object R and
/// reads the pattern, and RW fails with ACCESS_DENIED alone. While init
/// holds the object, the memory init gave the provider is not all back;
/// once it closes the handle, it is.
fn memory_object_comes_back_in_a_reply() -> Outcome {
    const N: u16 = Call::MemMap.number();
    const SEED: u64 = 0x5EED_0000_0000;
    let before = counts_at_rest()?;
    let (reply, state) = served(Role::Provider, [child::SHARED_PAGES as u64, SEED], &[])?;
    let m = Handle::<Memory>::from_raw(abi::Handle(reply[2]));
    let args = [
        init::PROCESS.raw().0,
        m.raw().0,
        0,
        SHARED_LEN,
        WINDOW as u64,
        Access::ReadWrite.raw(),
    ];
    let refused = x0_alone::<N>(&args, Error::AccessDenied.code());
    let seen = map(&m, 0, SHARED_LEN, WINDOW, Access::Read).and_then(|()| {
        // SAFETY: the window is init's mapping of the object, readable.
        let words = (0..SHARED_LEN as usize / 8)
            .all(|i| unsafe { (WINDOW as *const u64).add(i).read_volatile() } == SEED + i as u64);
        unmap(WINDOW, SHARED_LEN).map(|()| words)
    });
    let held = counts_at_rest()?;
    close(m)?;
    let after = counts_at_rest()?;
    let rights = Rights::MAP_READ | Rights::TRANSFER;
    check(
        state == ProcessState::Exited { code: 0 }
            && reply[1] == 1
            && reply[3] == abi::msgbuf::info(abi::ObjectKind::Memory, rights),
        "the provider's reply did not bring its object with MAP_READ and TRANSFER",
    )?;
    check(
        reply[4] == PROVIDER_QUOTA - 3 * PAGE as u64,
        "the provider did not pay for its object, the node of its list and a page of its pool",
    )?;
    check(
        seen == Ok(true) && refused,
        "init did not read the pattern of the provider that ended, or mapped it RW",
    )?;
    check(
        held.0 > before.0 && after == before,
        "the memory of the provider came back before its object went, or not at all",
    )
}

/// Spec 15.2 (messages), 5.2, 7.4: a memory object's handle that moves
/// with MAP_READ and TRANSFER alone maps R only (spec 6.2): at the service
/// that gets it, mem_map RW and RX and mem_protect of its mapping R to RW
/// and to RX fail with ACCESS_DENIED, and R maps.
fn narrowed_memory_handle_maps_read_only() -> Outcome {
    let m = memory_object(child::SHARED_PAGES as u64)?;
    let sent = copy_raw(&m, Rights::MAP_READ | Rights::TRANSFER)?;
    let got = served(Role::Service, [SHARED_LEN, 0], &[sent]);
    close(m)?;
    let (reply, state) = got?;
    check(
        state == ProcessState::Exited { code: 0 },
        "the service did not map the object R",
    )?;
    check(
        reply[7..11] == [Error::AccessDenied.code(); 4],
        "the service mapped the object RW or RX, or made its mapping so",
    )
}

/// Spec 15.2 (messages), 6.2: pages of a memory object in a message show
/// both sides. Init maps an object RW and writes INIT_WORD into its first
/// word, and sends a copy with MAP_READ, MAP_WRITE and TRANSFER to a
/// service, which maps it RW, finds INIT_WORD and writes CHILD_WORD into
/// the second word, which init reads through its own mapping.
fn shared_pages_show_both_sides() -> Outcome {
    let m = memory_object(child::SHARED_PAGES as u64)?;
    map(&m, 0, SHARED_LEN, WINDOW, Access::ReadWrite)?;
    let word = WINDOW as *mut u64;
    // SAFETY: the window is init's mapping of the object, read and write.
    unsafe { word.write_volatile(INIT_WORD) };
    let rights = Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER;
    let got = copy_raw(&m, rights)
        .and_then(|sent| served(Role::Service, [SHARED_LEN, CHILD_WORD], &[sent]));
    // SAFETY: as above.
    let seen = unsafe { word.add(1).read_volatile() };
    unmap(WINDOW, SHARED_LEN)?;
    close(m)?;
    let (reply, state) = got?;
    check(
        state == ProcessState::Exited { code: 0 } && reply[7] == 0,
        "the service did not map the object RW",
    )?;
    check(reply[6] == INIT_WORD, "the service did not see init's word")?;
    check(seen == CHILD_WORD, "init did not see the service's word")
}
