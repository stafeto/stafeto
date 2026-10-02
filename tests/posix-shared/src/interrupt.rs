// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Live-thread IPC interruption, EINTR cleanup and successful read retry.

use super::*;
use rt::abi::{Call, Error, Policy, Rights, ThreadState};
use rt::handle::{Process, Thread};

static STACKS: [Stack<16384>; 6] = [const { Stack::new() }; 6];
static SOURCE: AtomicUsize = AtomicUsize::new(0);
static CHANNEL: AtomicUsize = AtomicUsize::new(0);
static ACCEPTED: AtomicUsize = AtomicUsize::new(0);
static MOVED: AtomicUsize = AtomicUsize::new(0);
static RETRY: AtomicUsize = AtomicUsize::new(0);
static RESULTS: [AtomicUsize; 6] = [const { AtomicUsize::new(0) }; 6];

fn passed(slot: usize, good: bool) -> ! {
    RESULTS[slot].store(if good { 1 } else { 2 }, Ordering::Release);
    sys::thread_exit()
}

fn channel() -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(CHANNEL.load(Ordering::Acquire) as u64))
}

fn registers() -> sys::Regs {
    core::array::from_fn(|i| 0xabcd0000 + i as u64)
}

extern "C" fn receiving(_: u64) -> ! {
    let mut before = registers();
    before[0] = channel().raw().0;
    before[1] = 0;
    // SAFETY: channel is live and receive only reads these registers.
    let after = unsafe { sys::raw::<{ Call::Receive.number() }>(before) };
    passed(
        0,
        after[0] == Error::Interrupted.code() && after[1..] == before[1..],
    )
}

extern "C" fn sending(_: u64) -> ! {
    let mut before = registers();
    before[0] = SOURCE.load(Ordering::Acquire) as u64;
    before[1] = 8 | (1 << rt::abi::HANDLES_SHIFT);
    rt::msgbuf::put_handles(&[rt::abi::Handle(MOVED.load(Ordering::Acquire) as u64)]);
    // SAFETY: one owned transfer handle and a live channel, no borrowed buffer.
    let after = unsafe { sys::raw::<{ Call::Send.number() }>(before) };
    if after[0] != Error::Interrupted.code() || after[1..] != before[1..] {
        passed(1, false);
    }
    // Two more requests from this live thread: the accepted one is not
    // taken back by an interrupt and gets its reply whole, and the next
    // token on the same thread number is a new one.
    before[0] = channel().raw().0;
    before[1] = 6 | (1 << rt::abi::HANDLES_SHIFT);
    before[2] = rt::abi::inline_words(b"second")[0];
    rt::msgbuf::put_handles(&[rt::abi::Handle(ACCEPTED.load(Ordering::Acquire) as u64)]);
    // SAFETY: second owned transfer and live channel as above.
    let after = unsafe { sys::raw::<{ Call::Send.number() }>(before) };
    if after[0] != 0 || after[1] != 8 || after[2] != rt::abi::inline_words(b"accepted")[0] {
        passed(1, false);
    }
    let good = sys::send(&channel(), b"third").is_ok_and(|reply| {
        reply.len == 2 && reply.words[0] & 0xffff == u64::from(u16::from_le_bytes(*b"ok"))
    });
    passed(1, good)
}

extern "C" fn file_request(_: u64) -> ! {
    let good = tls::with_process(|| {
        let mut path = [0xa5; 129];
        let errno = unsafe { abi::__errno_location() };
        unsafe { *errno = EINVAL };
        !unsafe { abi::getcwd(path.as_mut_ptr(), path.len()) }.is_null()
            && &path[..2] == b"/\0"
            && unsafe { *errno } == EINVAL
    });
    passed(2, good)
}

fn state(t: &Handle<Thread>, expected: ThreadState) -> bool {
    sys::thread_info(t).is_ok_and(|info| info.state == expected)
}

fn create(
    process: &Handle<Process>,
    slot: usize,
    entry: extern "C" fn(u64) -> !,
) -> Option<Handle<Thread>> {
    // SAFETY: each static stack and distinct message page are used once.
    unsafe {
        sys::thread_create(
            process,
            entry,
            STACKS[slot].top(),
            0,
            30,
            Policy::Fifo,
            0xe00000 + slot * 4096,
        )
    }
    .ok()
}

fn interrupt(t: &Handle<Thread>, slot: usize) -> bool {
    if sys::thread_interrupt(t).is_err() {
        return false;
    }
    // A receive of a priority-30 request can boost main to 30. Yield lets
    // its just-woken peer run and either end or submit its next request.
    let _ = sys::yield_now();
    slot == 1
        || (RESULTS[slot].load(Ordering::Acquire) == 1
            && state(
                t,
                if slot == 3 {
                    ThreadState::Receiving
                } else {
                    ThreadState::Ended
                },
            ))
}

fn gone(raw: rt::abi::Handle) -> bool {
    let mut args = [0; 10];
    args[0] = raw.0;
    // SAFETY: checking the already-consumed handle through the raw ABI.
    unsafe { sys::raw::<{ Call::HandleClose.number() }>(args)[0] == Error::BadHandle.code() }
}

fn rejected(raw: u64, error: Error) -> bool {
    let mut before = registers();
    before[0] = raw;
    // SAFETY: invalid, wrong-type, restricted, or non-waiting target only.
    let after = unsafe { sys::raw::<{ Call::ThreadInterrupt.number() }>(before) };
    after[0] == error.code() && after[1..] == before[1..]
}

fn ipc(process: &Handle<Process>, main: &Handle<Thread>) -> bool {
    let Ok(c) = sys::channel_create(1) else {
        return fail(70);
    };
    CHANNEL.store(c.raw().0 as usize, Ordering::Release);
    let Some(receiver) = create(process, 0, receiving) else {
        return fail(71);
    };
    let Ok(restricted) = sys::handle_duplicate(&receiver, Rights::NONE) else {
        return fail(72);
    };
    if !rejected(0, Error::BadHandle)
        || !rejected(c.raw().0, Error::WrongType)
        || !rejected(restricted.raw().0, Error::AccessDenied)
        || !rejected(receiver.raw().0, Error::BadState)
        || !rejected(main.raw().0, Error::BadState)
        || sys::thread_set_priority(&receiver, 10, Policy::Fifo).is_err()
        || sys::thread_start(&receiver).is_err()
        || !state(&receiver, ThreadState::Ready)
        || !rejected(receiver.raw().0, Error::BadState)
        || sys::thread_set_priority(&receiver, 30, Policy::Fifo).is_err()
        || !state(&receiver, ThreadState::Receiving)
        || !interrupt(&receiver, 0)
        || !rejected(receiver.raw().0, Error::BadState)
        || sys::notify(&c, 1).is_err()
        || !matches!(
            sys::try_receive(&c),
            Ok(sys::Received::Notification { bits: 1, .. })
        )
    {
        return fail(73);
    }
    rt::println!("posix-interrupt-probe: receive and rights ok");
    let Ok(moved) = sys::channel_create(1) else {
        return fail(74);
    };
    let Ok(watch) = sys::handle_duplicate(&moved, Rights::NOTIFY) else {
        return fail(74);
    };
    let Ok(accepted) = sys::channel_create(1) else {
        return fail(74);
    };
    let Ok(accepted_watch) = sys::handle_duplicate(&accepted, Rights::NOTIFY) else {
        return fail(74);
    };
    ACCEPTED.store(accepted.into_raw().0 as usize, Ordering::Release);
    let raw = moved.into_raw();
    MOVED.store(raw.0 as usize, Ordering::Release);
    let Ok(source) = sys::handle_label(&c, Rights::SEND, 55, 1) else {
        return fail(75);
    };
    SOURCE.store(source.raw().0 as usize, Ordering::Release);
    let Some(sender) = create(process, 1, sending) else {
        return fail(75);
    };
    if sys::thread_start(&sender).is_err() || !state(&sender, ThreadState::Sending) {
        return fail(76);
    }
    // The wait is the last owner of this session until interruption.
    drop(source);
    if !interrupt(&sender, 1)
        || !state(&sender, ThreadState::Sending)
        || !gone(raw)
        || sys::notify(&watch, 1) != Err(Error::PeerClosed)
    {
        return fail(76);
    }
    let Ok(sys::Received::Message {
        token: old,
        len: 6,
        mut handles,
        ..
    }) = sys::try_receive(&c)
    else {
        return fail(77);
    };
    if !matches!(
        sys::try_receive(&c),
        Ok(sys::Received::Notification {
            label: 55,
            bits: rt::abi::CLIENT_GONE,
            count: 1,
            ..
        })
    ) {
        return fail(77);
    }
    let Ok(delivered) = handles.take::<Channel>(0) else {
        return fail(78);
    };
    // An accepted request is not taken back (spec 6.1): thread_interrupt
    // is BAD_STATE, the request's handle stays delivered, and the reply
    // goes once.
    if !state(&sender, ThreadState::AwaitingReply)
        || sys::thread_interrupt(&sender) != Err(Error::BadState)
        || !state(&sender, ThreadState::AwaitingReply)
        || sys::notify(&accepted_watch, 1).is_err()
        || !matches!(
            sys::try_receive(&delivered),
            Ok(sys::Received::Notification { bits: 1, .. })
        )
    {
        return fail(78);
    }
    let used = old.raw();
    if old.reply(b"accepted").is_err() {
        return fail(80);
    }
    // The token went with its reply.
    let mut before = registers();
    before[0] = used;
    before[1] = 5;
    // SAFETY: a reply with no handles and an inline body.
    let after = unsafe { sys::raw::<{ Call::Reply.number() }>(before) };
    if after[0] != Error::BadState.code() {
        return fail(80);
    }
    let Ok(sys::Received::Message {
        token: next,
        len: 5,
        ..
    }) = sys::try_receive(&c)
    else {
        return fail(81);
    };
    if next.raw() == used || next.reply(b"ok").is_err() {
        return fail(82);
    }
    let _ = sys::yield_now();
    if RESULTS[1].load(Ordering::Acquire) != 1 || !state(&sender, ThreadState::Ended) {
        return fail(83);
    }
    rt::println!("posix-interrupt-probe: queued handles, and accepted requests answered once");
    true
}

/// One request of the two-step read to the driver: its long reply.
fn long_call(
    uart: &Handle<Channel>,
    request: &proto_wire::Writer,
    handle: Option<Handle<Channel>>,
    out: &mut [u8],
) -> Option<(u32, usize, u64)> {
    let reply = match handle {
        None => sys::send(uart, request.as_bytes()).ok()?,
        Some(handle) => sys::send_handles(uart, request.as_bytes(), [handle.erase()]).ok()?,
    };
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    match proto_wire::long::Reply::read(reply.bytes(&mut buffer)).ok()? {
        proto_wire::long::Reply::Ready(bytes) => {
            out[..bytes.len()].copy_from_slice(bytes);
            Some((proto_wire::long::READY, bytes.len(), 0))
        }
        proto_wire::long::Reply::Wait(key) => Some((proto_wire::long::WAIT, 0, key)),
        proto_wire::long::Reply::Armed => Some((proto_wire::long::ARMED, 0, 0)),
        proto_wire::long::Reply::Cancelled => Some((proto_wire::long::CANCELLED, 0, 0)),
    }
}

fn start(uart: &Handle<Channel>) -> Option<u64> {
    let mut w = proto_wire::Writer::new();
    proto_uart::ReadRequest { max: 1 }
        .write_start(&mut w)
        .ok()?;
    match long_call(uart, &w, None, &mut [0; 1])? {
        (proto_wire::long::WAIT, _, key) => Some(key),
        _ => None,
    }
}

fn keyed(
    uart: &Handle<Channel>,
    method: proto_uart::Method,
    key: u64,
    handle: Option<Handle<Channel>>,
    out: &mut [u8],
) -> Option<(u32, usize)> {
    let mut w = proto_wire::Writer::new();
    proto_uart::ReadKey { key }.write(method, &mut w).ok()?;
    long_call(uart, &w, handle, out).map(|(kind, n, _)| (kind, n))
}

/// The read in two steps of the console's driver (proto_uart 2): a read
/// that waits holds no reply; once armed with a labelled copy of a channel
/// it is told when input came and takes it; a cancel before input has no
/// effect; a cancel after input came gives that input, so nothing is lost.
fn two_step_reads() -> bool {
    let Some(raw) = uart_route().and_then(|input| input.uart()) else {
        return fail(91);
    };
    let uart = Handle::<Channel>::borrowed(raw);
    let Ok(notified) = sys::channel_create(30) else {
        return fail(92);
    };
    let Some(key) = start(&uart) else {
        return fail(93);
    };
    let Ok(labelled) = sys::handle_label(&notified, Rights::NOTIFY | Rights::TRANSFER, key, 30)
    else {
        return fail(94);
    };
    let mut byte = [0; 1];
    if keyed(
        &uart,
        proto_uart::Method::ReadTake,
        key,
        Some(labelled),
        &mut byte,
    ) != Some((proto_wire::long::ARMED, 0))
    {
        return fail(94);
    }
    rt::println!("posix-interrupt-probe: read waits armed");
    // The host types "r": the driver tells this read and keeps the byte.
    match sys::receive(&notified) {
        Ok(sys::Received::Notification {
            source: rt::abi::Source::Session,
            label,
            bits: 1,
            ..
        }) if label == key => {}
        _ => return fail(95),
    }
    if keyed(&uart, proto_uart::Method::ReadTake, key, None, &mut byte)
        != Some((proto_wire::long::READY, 1))
        || byte != *b"r"
    {
        return fail(95);
    }
    rt::println!("posix-interrupt-probe: told, taken");
    // The terminal sends a CR after the byte: let it come and take it.
    let Ok(pause) = sys::channel_create(30) else {
        return fail(96);
    };
    let Ok(timer) = sys::timer_create(&pause, 30) else {
        return fail(96);
    };
    let _ = sys::timer_set(&timer, sys::clock_now().unwrap_or(0) + 20_000_000);
    let _ = sys::receive(&pause);
    let key = loop {
        let mut w = proto_wire::Writer::new();
        if (proto_uart::ReadRequest { max: 1 })
            .write_start(&mut w)
            .is_err()
        {
            return fail(96);
        }
        match long_call(&uart, &w, None, &mut byte) {
            Some((proto_wire::long::READY, _, _)) => {}
            Some((proto_wire::long::WAIT, _, key)) => break key,
            _ => return fail(96),
        }
    };
    if keyed(&uart, proto_uart::Method::ReadCancel, key, None, &mut byte)
        != Some((proto_wire::long::CANCELLED, 0))
        || keyed(&uart, proto_uart::Method::ReadCancel, key, None, &mut byte).is_some()
    {
        return fail(96);
    }
    let Some(key) = start(&uart) else {
        return fail(97);
    };
    let Ok(labelled) = sys::handle_label(&notified, Rights::NOTIFY | Rights::TRANSFER, key, 30)
    else {
        return fail(97);
    };
    if keyed(
        &uart,
        proto_uart::Method::ReadTake,
        key,
        Some(labelled),
        &mut byte,
    ) != Some((proto_wire::long::ARMED, 0))
    {
        return fail(97);
    }
    rt::println!("posix-interrupt-probe: retry waiting");
    // The host types "q": the cancel that comes after it gives the byte.
    loop {
        match sys::receive(&notified) {
            Ok(sys::Received::Notification {
                source: rt::abi::Source::Session,
                label,
                bits,
                ..
            }) if label == key && bits & 1 != 0 => break,
            Ok(_) => {}
            Err(_) => return fail(98),
        }
    }
    if keyed(&uart, proto_uart::Method::ReadCancel, key, None, &mut byte)
        != Some((proto_wire::long::READY, 1))
        || byte != *b"q"
    {
        return fail(98);
    }
    rt::println!("posix-interrupt-probe: a cancel after input gives the input");
    // The notification left main at its priority, 30, until a receive:
    // back to 29, so that the next readers run ahead of it.
    let _ = sys::try_receive(&pause);
    true
}

extern "C" fn echo_read(_: u64) -> ! {
    let good = tls::with_process(|| {
        let input = rt::fs::Input::from_uart(Some(channel().raw()));
        let mut bytes = [0xa5; 4];
        let errno = unsafe { abi::__errno_location() };
        unsafe { *errno = EIO };
        input.read(&mut bytes) == Ok(2)
            && bytes == [b'e', b'\n', 0xa5, 0xa5]
            && unsafe { *errno } == EIO
    });
    passed(4, good)
}

fn delivered_data_survives_echo_interrupt(process: &Handle<Process>) -> bool {
    let Ok(c) = sys::channel_create(1) else {
        return fail(95);
    };
    CHANNEL.store(c.raw().0 as usize, Ordering::Release);
    let Some(reader) = create(process, 4, echo_read) else {
        return fail(95);
    };
    if sys::thread_start(&reader).is_err() {
        return fail(95);
    }
    let Ok(sys::Received::Message {
        token,
        words,
        len: 16,
        ..
    }) = sys::try_receive(&c)
    else {
        return fail(95);
    };
    if words[0] != u64::from_le_bytes(proto_uart::Method::Read.header().bytes()) || words[1] != 4 {
        return fail(95);
    }
    let mut reply = proto_wire::Writer::new();
    if (proto_uart::ReadReply { bytes: b"e\r" })
        .write(&mut reply)
        .is_err()
        || token.reply(reply.as_bytes()).is_err()
    {
        return fail(95);
    }
    let _ = sys::yield_now();
    let Ok(sys::Received::Message {
        token,
        words,
        len: 11,
        ..
    }) = sys::try_receive(&c)
    else {
        return fail(95);
    };
    // The echo's request is accepted: an interrupt does not take it back,
    // its reply goes, and the read gives the bytes delivered.
    let mut written = proto_wire::Writer::new();
    if words[0] != u64::from_le_bytes(proto_uart::Method::Write.header().bytes())
        || !state(&reader, ThreadState::AwaitingReply)
        || sys::thread_interrupt(&reader) != Err(Error::BadState)
        || !state(&reader, ThreadState::AwaitingReply)
        || (proto_uart::WriteReply { written: 2 })
            .write(&mut written)
            .is_err()
        || token.reply(written.as_bytes()).is_err()
    {
        return fail(95);
    }
    let _ = sys::yield_now();
    if RESULTS[4].load(Ordering::Acquire) != 1 || !state(&reader, ThreadState::Ended) {
        return fail(95);
    }
    rt::println!("posix-interrupt-probe: delivered bytes survive an interrupt of the echo");
    true
}

fn uart_route() -> Option<rt::fs::Input> {
    let mut request = proto_wire::Writer::new();
    posix_request::Request::Read { fd: 0, count: 2 }
        .write(&mut request)
        .ok()?;
    let mut reply = [0; rt::abi::MESSAGE_MAX];
    let len = shared::probe(request.as_bytes(), &mut reply).ok()?;
    match posix_request::Reply::read(&reply[..len]).ok()? {
        posix_request::Reply::Input {
            uart: Some(raw), ..
        } => Some(rt::fs::Input::from_uart(Some(rt::abi::Handle(raw)))),
        _ => None,
    }
}

pub fn run(process: &Handle<Process>, main: &Handle<Thread>) -> bool {
    // Main is a thread of relibc: the layer keeps its level (its base, to
    // which it comes back after a lock of the layer), so the move goes
    // through the layer.
    if abi::threads::set_level(29).is_err() || !ipc(process, main) {
        return false;
    }
    // End the receive boost; return to base 29 so newly started clients run
    // ahead of main.
    let Ok(empty) = sys::channel_create(1) else {
        return fail(84);
    };
    let _ = sys::try_receive(&empty);
    RETRY.store(empty.raw().0 as usize, Ordering::Release);
    // No file worker: a thread's file request runs in that thread, under
    // the lock of the process's files, and has no IPC of its own to
    // interrupt.
    let Some(request) = create(process, 2, file_request) else {
        return fail(85);
    };
    if sys::thread_start(&request).is_err()
        || RESULTS[2].load(Ordering::Acquire) != 1
        || !state(&request, ThreadState::Ended)
    {
        return fail(86);
    }
    rt::println!("posix-interrupt-probe: a file request runs in its own thread");
    if !two_step_reads() {
        return false;
    }
    if !delivered_data_survives_echo_interrupt(process) {
        return false;
    }
    rt::println!("posix-interrupt-probe: ok");
    true
}
