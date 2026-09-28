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
    // Two more requests from this live thread exercise accepted cancellation
    // and the next token's validity on the same thread number.
    before[0] = channel().raw().0;
    before[1] = 6 | (1 << rt::abi::HANDLES_SHIFT);
    before[2] = rt::abi::inline_words(b"second")[0];
    rt::msgbuf::put_handles(&[rt::abi::Handle(ACCEPTED.load(Ordering::Acquire) as u64)]);
    // SAFETY: second owned transfer and live channel as above.
    let after = unsafe { sys::raw::<{ Call::Send.number() }>(before) };
    if after[0] != Error::Interrupted.code() || after[1..] != before[1..] {
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
        unsafe { abi::getcwd(path.as_mut_ptr(), path.len()) }.is_null()
            && unsafe { *errno } == EINTR
            && path == [0xa5; 129]
    });
    passed(2, good)
}

extern "C" fn console_read(_: u64) -> ! {
    let good = tls::with_process(|| {
        let mut bytes = [0xa5; 4];
        let errno = unsafe { abi::__errno_location() };
        unsafe { *errno = EINVAL };
        let retry =
            Handle::<Channel>::borrowed(rt::abi::Handle(RETRY.load(Ordering::Acquire) as u64));
        for attempt in 0..2 {
            bytes.fill(0xa5);
            if attempt == 1 {
                RESULTS[3].store(4, Ordering::Release);
            }
            if unsafe { abi::read(0, bytes.as_mut_ptr(), bytes.len()) } != -1
                || unsafe { *errno } != EINTR
                || bytes != [0xa5; 4]
            {
                return false;
            }
            RESULTS[3].store(1, Ordering::Release);
            if sys::receive(&retry).is_err() {
                return false;
            }
        }
        // Same thread, same descriptor and UART session. A stale deferred read
        // would refuse this new request or consume its bytes for a dead token.
        RESULTS[3].store(5, Ordering::Release);
        let ending = if cfg!(feature = "native-interrupt") {
            b'\r'
        } else {
            b'\n'
        };
        for expected in [b'q', ending] {
            if unsafe { abi::read(0, bytes.as_mut_ptr(), 1) } != 1
                || bytes[0] != expected
                || unsafe { *errno } != EINTR
            {
                return false;
            }
        }
        true
    });
    let retry = Handle::<Channel>::borrowed(rt::abi::Handle(RETRY.load(Ordering::Acquire) as u64));
    RESULTS[3].store(if good { 3 } else { 2 }, Ordering::Release);
    let _ = sys::notify(&retry, 2);
    sys::thread_exit()
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
    if !state(&sender, ThreadState::AwaitingReply)
        || !interrupt(&sender, 1)
        || sys::notify(&accepted_watch, 1).is_err()
        || !matches!(
            sys::try_receive(&delivered),
            Ok(sys::Received::Notification { bits: 1, .. })
        )
    {
        return fail(78);
    }
    // A late reply consumes transfer handles even though the client is alive.
    let Ok(late) = sys::channel_create(1) else {
        return fail(79);
    };
    let Ok(late_watch) = sys::handle_duplicate(&late, Rights::NOTIFY) else {
        return fail(79);
    };
    let late = late.into_raw();
    rt::msgbuf::put_handles(&[late]);
    let mut before = registers();
    before[0] = old.raw();
    before[1] = 8 | (1 << rt::abi::HANDLES_SHIFT);
    // SAFETY: the token is abandoned and this reply transfers one owned handle.
    let after = unsafe { sys::raw::<{ Call::Reply.number() }>(before) };
    if after[0] != Error::PeerClosed.code()
        || after[1..] != before[1..]
        || !gone(late)
        || sys::notify(&late_watch, 1) != Err(Error::PeerClosed)
    {
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
    if next.raw() == old.raw()
        || old.reply(b"stale") != Err(Error::BadState)
        || next.reply(b"ok").is_err()
    {
        return fail(82);
    }
    let _ = sys::yield_now();
    if RESULTS[1].load(Ordering::Acquire) != 1 || !state(&sender, ThreadState::Ended) {
        return fail(83);
    }
    rt::println!("posix-interrupt-probe: queued handles and accepted tokens ok");
    true
}

#[cfg(not(feature = "native-interrupt"))]
extern "C" fn active_read(_: u64) -> ! {
    let mut request = proto_wire::Writer::new();
    let encoded = (proto_uart::CancelableRead {
        max: 1,
        id: u64::MAX,
    })
    .write(&mut request);
    let good = encoded.is_ok()
        && sys::send(&channel(), request.as_bytes())
            .is_ok_and(|reply| reply.len == 8 && reply.words[0] == Error::Interrupted.code());
    passed(5, good)
}

#[cfg(not(feature = "native-interrupt"))]
fn cancel_live_read(process: &Handle<Process>) -> bool {
    let Some(raw) = uart_route().and_then(|input| input.uart()) else {
        return fail(97);
    };
    CHANNEL.store(raw.0 as usize, Ordering::Release);
    let Some(reader) = create(process, 5, active_read) else {
        return fail(97);
    };
    if sys::thread_start(&reader).is_err() || !state(&reader, ThreadState::AwaitingReply) {
        return fail(97);
    }
    let mut request = proto_wire::Writer::new();
    if (proto_uart::CancelRead { id: u64::MAX })
        .write(&mut request)
        .is_err()
        || !sys::send(&channel(), request.as_bytes())
            .is_ok_and(|reply| reply.len == 8 && reply.words[0] == 0)
        || RESULTS[5].load(Ordering::Acquire) != 1
        || !state(&reader, ThreadState::Ended)
    {
        return fail(97);
    }
    rt::println!("posix-interrupt-probe: explicit cancellation wakes live reader");
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
        len: 24,
        ..
    }) = sys::try_receive(&c)
    else {
        return fail(95);
    };
    if words[0] != u64::from_le_bytes(proto_uart::Method::ReadCancelable.header().bytes())
        || words[1] != 4
        || words[2] == 0
    {
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
    if words[0] != u64::from_le_bytes(proto_uart::Method::Write.header().bytes())
        || !state(&reader, ThreadState::AwaitingReply)
        || !interrupt(&reader, 4)
        || token.reply(b"late").is_ok()
    {
        return fail(95);
    }
    rt::println!("posix-interrupt-probe: delivered bytes survive echo interruption");
    true
}

#[cfg(not(feature = "native-interrupt"))]
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

// Keep the interrupted client ready below main until UART has tried its dead
// reply. IRQ runs above main, so real input arrives before CancelRead executes.
#[cfg(not(feature = "native-interrupt"))]
fn interrupt_before_irq(reader: &Handle<Thread>) -> bool {
    let Some(input) = uart_route() else {
        return fail(94);
    };
    if sys::thread_set_priority(reader, 10, Policy::Fifo).is_err()
        || sys::thread_interrupt(reader).is_err()
        || !state(reader, ThreadState::Ready)
    {
        return fail(94);
    }
    rt::println!("posix-interrupt-probe: interrupted before cleanup");
    let start = rt::time::now();
    let mut bytes = [0; 2];
    loop {
        match input.read(&mut bytes) {
            Ok(2) if bytes == *b"r\n" => break,
            Err(proto_wire::Status::Kernel(Error::BadState))
                if rt::time::now().saturating_sub(start) < 5_000_000_000 => {}
            _ => return fail(94),
        }
    }
    if RESULTS[3].load(Ordering::Acquire) != 0
        || sys::thread_set_priority(reader, 30, Policy::Fifo).is_err()
    {
        return fail(94);
    }
    rt::println!("posix-interrupt-probe: abandoned reply preserved input");
    RESULTS[3].load(Ordering::Acquire) == 1 && state(reader, ThreadState::Receiving)
}

pub fn run(process: &Handle<Process>, main: &Handle<Thread>) -> bool {
    if sys::thread_set_priority(main, 29, Policy::Fifo).is_err() || !ipc(process, main) {
        return false;
    }
    // End the receive boost; return to base 29 so newly started clients run
    // ahead of main while the file owner stays at base 1.
    let Ok(empty) = sys::channel_create(1) else {
        return fail(84);
    };
    let _ = sys::try_receive(&empty);
    RETRY.store(empty.raw().0 as usize, Ordering::Release);
    let Some(request) = create(process, 2, file_request) else {
        return fail(85);
    };
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = EIO };
    if sys::thread_start(&request).is_err()
        || !state(&request, ThreadState::Sending)
        || sys::thread_interrupt(&request).is_err()
        || unsafe { *errno } != EIO
    {
        return fail(86);
    }
    // The interrupted client must Fetch/Ack before returning EINTR. Main's own
    // round trip lets the lower-priority file owner process that control traffic.
    let mut path = [0; 129];
    if unsafe { abi::getcwd(path.as_mut_ptr(), path.len()) }.is_null()
        || &path[..2] != b"/\0"
        || unsafe { *errno } != EIO
        || RESULTS[2].load(Ordering::Acquire) != 1
        || !state(&request, ThreadState::Ended)
    {
        return fail(87);
    }
    rt::println!("posix-interrupt-probe: file RPC EINTR ok");
    let Some(reader) = create(process, 3, console_read) else {
        return fail(88);
    };
    let Ok(before_read) = sys::process_handles(process) else {
        return fail(89);
    };
    if sys::thread_start(&reader).is_err() {
        return fail(89);
    }
    // The file owner completes read preparation at priority 1 while main's
    // own file round trip waits. Native input then sleeps on its timer;
    // UART input waits for an accepted driver request without incoming bytes.
    let mut info = core::mem::MaybeUninit::<posix_abi::metadata::Stat>::uninit();
    if unsafe { posix_abi::metadata::fstat(0, info.as_mut_ptr()) } != 0 {
        return fail(90);
    }
    let expected = if cfg!(feature = "native-interrupt") {
        ThreadState::Receiving
    } else {
        ThreadState::AwaitingReply
    };
    // Native polling can briefly run between sleeps; observe the current
    // state rather than relying on a fixed host delay.
    for _ in 0..64 {
        if state(&reader, expected) {
            break;
        }
        let _ = sys::yield_now();
    }
    let Ok(during_read) = sys::process_handles(process) else {
        return fail(91);
    };
    let temporary = if cfg!(feature = "native-interrupt") {
        2
    } else {
        0
    };
    if !state(&reader, expected) || during_read.live != before_read.live + temporary {
        return fail(91);
    }
    #[cfg(not(feature = "native-interrupt"))]
    let interrupted = interrupt_before_irq(&reader);
    #[cfg(feature = "native-interrupt")]
    let interrupted = interrupt(&reader, 3);
    if !interrupted
        || sys::process_handles(process).map(|handles| handles.live) != Ok(before_read.live)
        || unsafe { *errno } != EIO
    {
        return fail(91);
    }
    let fd = unsafe { abi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
    let mut byte = 0;
    if fd != 3
        || unsafe { abi::read(fd, &mut byte, 1) } != 1
        || byte != b's'
        || unsafe { abi::close(fd) } != 0
        || unsafe { *errno } != EIO
    {
        return fail(92);
    }
    rt::println!("posix-interrupt-probe: console EINTR and continued file I/O ok");
    // Interrupt another empty read, with no IRQ to retire the old request.
    // This phase requires the explicit CancelRead handler to remove it.
    if sys::notify(&empty, 1).is_err()
        || unsafe { posix_abi::metadata::fstat(0, info.as_mut_ptr()) } != 0
        || RESULTS[3].load(Ordering::Acquire) != 4
        || !state(&reader, expected)
        || !interrupt(&reader, 3)
        || sys::process_handles(process).map(|handles| handles.live) != Ok(before_read.live)
    {
        return fail(96);
    }
    rt::println!("posix-interrupt-probe: empty-read cancellation acknowledged");
    if sys::notify(&empty, 1).is_err()
        || unsafe { posix_abi::metadata::fstat(0, info.as_mut_ptr()) } != 0
        || RESULTS[3].load(Ordering::Acquire) != 5
        || !state(&reader, expected)
    {
        return fail(93);
    }
    rt::println!("posix-interrupt-probe: retry waiting");
    if sys::receive(&empty).is_err()
        || RESULTS[3].load(Ordering::Acquire) != 3
        || !state(&reader, ThreadState::Ended)
        || unsafe { *errno } != EIO
    {
        return fail(93);
    }
    rt::println!("posix-interrupt-probe: retry preserved input and errno");
    #[cfg(not(feature = "native-interrupt"))]
    if !cancel_live_read(process) {
        return false;
    }
    if !delivered_data_survives_echo_interrupt(process) {
        return false;
    }
    rt::println!("posix-interrupt-probe: ok");
    true
}
