// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Long operations in two steps with the test service `long` (tests/svc,
//! role `l`): a ready result in the reply of the start, one call; a wait,
//! its bit, and the take; a signal before the result cancels with no
//! effect (EINTR), a signal right before the result comes gives the result;
//! with SA_RESTART the read waits on; the 17th operation of a session gets
//! EAGAIN; a client that goes frees its operations and their handles.
use super::*;
use crate::layer::signals::{self as api, SigAction};
use proto_uart::{Method, ReadKey, ReadRequest};
use proto_wire::{Writer, long};

static SERVICE: AtomicU64 = AtomicU64::new(0);
static RESULT: AtomicU64 = AtomicU64::new(0);
static HANDLED: AtomicUsize = AtomicUsize::new(0);
const STATS: u16 = 17;
const FEED: u16 = 18;
const HOLD: u16 = 20;
const VERSION: u16 = proto_uart::VERSION;

fn service() -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(SERVICE.load(Ordering::Acquire)))
}

fn feed(byte: u8) -> bool {
    let mut w = Writer::new();
    proto_wire::Header::new(FEED, VERSION)
        .write(&mut w)
        .unwrap();
    w.bytes(&[byte]).unwrap();
    sys::send(&service(), w.as_bytes()).is_ok_and(|r| r.words[0] as u32 == 0)
}

/// The operations of `channel`'s service that wait and the handles they
/// hold.
fn stats(channel: &Handle<Channel>) -> (u32, u32) {
    let mut w = Writer::new();
    proto_wire::Header::new(STATS, VERSION)
        .write(&mut w)
        .unwrap();
    let reply = sys::send(channel, w.as_bytes()).expect("long STATS");
    ((reply.words[0] >> 32) as u32, reply.words[1] as u32)
}

fn start_request() -> Writer {
    sized_start(1)
}

fn sized_start(max: u32) -> Writer {
    let mut w = Writer::new();
    ReadRequest { max }.write_start(&mut w).unwrap();
    w
}

/// A read of one byte in two steps through the layer: the byte, or the
/// error number.
fn read_one() -> Result<u8, i32> {
    let mut out = [0; 1];
    abi::long::run(
        &service(),
        start_request().as_bytes(),
        |cancel, key, w| {
            let method = if cancel {
                Method::ReadCancel
            } else {
                Method::ReadTake
            };
            ReadKey { key }.write(method, w)
        },
        &mut out,
    )
    .map(|_| out[0])
}

unsafe extern "C" fn reader(_: *mut c_void) -> *mut c_void {
    if threads::set_level(20).is_err() {
        return ptr::null_mut();
    }
    let value = match read_one() {
        Ok(byte) => u64::from(byte),
        Err(error) => 0x1000 + error as u64,
    };
    RESULT.store(value, Ordering::SeqCst);
    ptr::null_mut()
}

unsafe extern "C" fn on_signal(_: i32) {
    HANDLED.fetch_add(1, Ordering::SeqCst);
}

/// A handler that reads itself: a timed read of 16 bytes, ready 1 ms
/// later, in two steps nested in the read it interrupted.
unsafe extern "C" fn reading_handler(_: i32) {
    HANDLED.fetch_add(1, Ordering::SeqCst);
    let mut out = [0; 16];
    let read = abi::long::run(
        &service(),
        sized_start(16).as_bytes(),
        |cancel, key, w| {
            let method = if cancel {
                Method::ReadCancel
            } else {
                Method::ReadTake
            };
            ReadKey { key }.write(method, w)
        },
        &mut out,
    );
    if read != Ok(16) {
        INNER_FAILED.fetch_add(1, Ordering::SeqCst);
    }
}
static INNER_FAILED: AtomicUsize = AtomicUsize::new(0);

/// Whether RESULT is `value` within `ms` milliseconds.
fn result_within(value: u64, ms: usize) -> bool {
    let pause = abi::metadata::Timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000,
    };
    (0..ms).any(|_| {
        if RESULT.load(Ordering::SeqCst) == value {
            return true;
        }
        let _ = unsafe { crate::layer::sleep::nanosleep(&pause, ptr::null_mut()) };
        false
    })
}

fn hold(ms: u32, mode: u32) -> bool {
    let mut w = Writer::new();
    proto_wire::Header::new(HOLD, VERSION)
        .write(&mut w)
        .unwrap();
    w.u32(ms).unwrap();
    w.u32(mode).unwrap();
    sys::send(&service(), w.as_bytes()).is_ok()
}

fn handler(flags: i32) -> bool {
    let action = SigAction {
        handler: on_signal as *const () as u64,
        mask: 0,
        flags,
    };
    unsafe { api::sigaction(SIGUSR1, &action, ptr::null_mut()) == 0 }
}

/// A reader at 20, waiting in its read when this returns.
fn waiting_reader() -> Option<u64> {
    RESULT.store(0, Ordering::SeqCst);
    let mut id = 0;
    if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(reader), ptr::null_mut()) } != 0 {
        return None;
    }
    let native = unsafe { threads::probe_native(id) }.ok()?;
    waiting(&native).then_some(id)
}

fn joined(id: u64) -> u64 {
    assert_eq!(unsafe { ffi::pthread_join(id, ptr::null_mut()) }, 0);
    RESULT.load(Ordering::SeqCst)
}

pub(super) fn run(parent: &Handle<Channel>) -> bool {
    let Ok(channel) = rt::service::connect(parent, "long") else {
        return failed(660);
    };
    SERVICE.store(channel.raw().0, Ordering::Release);
    // A result ready at the start: one call, no labelled copy.
    let calls = (0..4)
        .map(|_| {
            if !feed(b'a') {
                return u64::MAX;
            }
            let before = sys::calls();
            let got = read_one();
            let used = sys::calls() - before;
            if got == Ok(b'a') { used } else { u64::MAX }
        })
        .min()
        .unwrap();
    if calls != 1 {
        rt::println!("long-op-probe: {} calls for a ready result", calls);
        return failed(661);
    }
    // A wait, its bit and the take.
    let Some(id) = waiting_reader() else {
        return failed(662);
    };
    if stats(&channel) != (1, 1) || !feed(b'b') || joined(id) != u64::from(b'b') {
        return failed(663);
    }
    rt::println!("long-op-probe: ready at once in one call; wait, bit and take");
    // A signal before the result: cancelled, EINTR, nothing left.
    if !handler(0) {
        return failed(664);
    }
    let Some(id) = waiting_reader() else {
        return failed(665);
    };
    if ffi::pthread_kill(id, SIGUSR1) != 0
        || joined(id) != 0x1000 + EINTR as u64
        || stats(&channel) != (0, 0)
    {
        return failed(666);
    }
    // A signal, then the result before the reader runs: the cancel gives
    // the result.
    let Some(id) = waiting_reader() else {
        return failed(667);
    };
    if ffi::pthread_kill(id, SIGUSR1) != 0 || !feed(b'c') || joined(id) != u64::from(b'c') {
        return failed(668);
    }
    rt::println!("long-op-probe: a signal cancels with EINTR, or gives a result that came");
    // With SA_RESTART the read waits on through the handler.
    let before = HANDLED.load(Ordering::SeqCst);
    if !handler(SA_RESTART) {
        return failed(669);
    }
    let Some(id) = waiting_reader() else {
        return failed(670);
    };
    if ffi::pthread_kill(id, SIGUSR1) != 0 {
        return failed(671);
    }
    let native = unsafe { threads::probe_native(id) }.expect("reader handle");
    if !waiting(&native)
        || HANDLED.load(Ordering::SeqCst) != before + 1
        || !feed(b'd')
        || joined(id) != u64::from(b'd')
    {
        return failed(672);
    }
    let restored = SigAction {
        handler: api::DEFAULT,
        mask: 0,
        flags: 0,
    };
    if unsafe { api::sigaction(SIGUSR1, &restored, ptr::null_mut()) } != 0 {
        return failed(673);
    }
    rt::println!("long-op-probe: with SA_RESTART the read waits on");
    // Sixteen operations of a session wait; the 17th gets LIMIT_REACHED.
    let mut keys = [0u64; 16];
    for key in &mut keys {
        let reply = sys::send(&channel, start_request().as_bytes()).expect("start");
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        match long::Reply::read(reply.bytes(&mut buffer)) {
            Ok(long::Reply::Wait(k)) => *key = k,
            _ => return failed(674),
        }
    }
    let reply = sys::send(&channel, start_request().as_bytes()).expect("17th start");
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    if long::Reply::read(reply.bytes(&mut buffer))
        != Err(proto_wire::Status::Kernel(rt::abi::Error::LimitReached))
    {
        return failed(675);
    }
    for key in keys {
        let mut w = Writer::new();
        ReadKey { key }.write(Method::ReadCancel, &mut w).unwrap();
        let reply = sys::send(&channel, w.as_bytes()).expect("cancel");
        if long::Reply::read(reply.bytes(&mut buffer)) != Ok(long::Reply::Cancelled) {
            return failed(676);
        }
    }
    // A client that goes takes its waiting, armed operation and its handle
    // with it.
    let Ok(other) = rt::service::connect(parent, "long") else {
        return failed(677);
    };
    let reply = sys::send(&other, start_request().as_bytes()).expect("start of the other");
    let Ok(long::Reply::Wait(key)) = long::Reply::read(reply.bytes(&mut buffer)) else {
        return failed(678);
    };
    let notified = sys::channel_create(30).expect("notified channel");
    let labelled = sys::handle_label(
        &notified,
        rt::abi::Rights::NOTIFY | rt::abi::Rights::TRANSFER,
        key,
        30,
    )
    .expect("labelled copy");
    let mut w = Writer::new();
    ReadKey { key }.write(Method::ReadTake, &mut w).unwrap();
    let reply = sys::send_handles(&other, w.as_bytes(), [labelled.erase()]).expect("take");
    if long::Reply::read(reply.bytes(&mut buffer)) != Ok(long::Reply::Armed)
        || stats(&channel) != (1, 1)
    {
        return failed(679);
    }
    drop(other);
    if stats(&channel) != (0, 0) {
        return failed(680);
    }
    rt::println!(
        "long-op-probe: the 17th operation of a session gets EAGAIN; a client that goes frees its record and handle"
    );
    // A signal takes back the "take" that waits in the queue of the
    // service, which holds 50 ms after its WAIT: the read cancels, EINTR,
    // nothing stays in the service, and the next read goes through.
    if !handler(0) {
        return failed(681);
    }
    let mut w = Writer::new();
    proto_wire::Header::new(HOLD, VERSION)
        .write(&mut w)
        .unwrap();
    w.u32(50).unwrap();
    if sys::send(&channel, w.as_bytes()).is_err() {
        return failed(681);
    }
    RESULT.store(0, Ordering::SeqCst);
    let mut id = 0;
    if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(reader), ptr::null_mut()) } != 0 {
        return failed(682);
    }
    let native = unsafe { threads::probe_native(id) }.expect("reader handle");
    let pause = abi::metadata::Timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000,
    };
    let _ = unsafe { crate::layer::sleep::nanosleep(&pause, ptr::null_mut()) };
    let queued = sys::thread_info(&native).is_ok_and(|i| i.state == rt::abi::ThreadState::Sending);
    if !queued
        || ffi::pthread_kill(id, SIGUSR1) != 0
        || joined(id) != 0x1000 + EINTR as u64
        || stats(&channel) != (0, 0)
    {
        rt::println!(
            "long-op-probe: take queued {}, then {:?} in the service",
            queued,
            stats(&channel)
        );
        return failed(683);
    }
    let Some(id) = waiting_reader() else {
        return failed(684);
    };
    if !feed(b'h') || joined(id) != u64::from(b'h') {
        return failed(684);
    }
    rt::println!("long-op-probe: a signal that takes back a queued take cancels the operation");
    // With SA_RESTART, a signal that takes back the "take" after the bit
    // (the service holds 50 ms after FEED) sends it again: the service
    // told once and tells no second time, and the read gets its byte.
    if !handler(SA_RESTART) || !hold(50, 1) {
        return failed(685);
    }
    let Some(id) = waiting_reader() else {
        return failed(685);
    };
    let native = unsafe { threads::probe_native(id) }.expect("reader handle");
    if !feed(b'j') {
        return failed(686);
    }
    let _ = unsafe { crate::layer::sleep::nanosleep(&pause, ptr::null_mut()) };
    let queued = sys::thread_info(&native).is_ok_and(|i| i.state == rt::abi::ThreadState::Sending);
    if !queued || ffi::pthread_kill(id, SIGUSR1) != 0 || !result_within(u64::from(b'j'), 1000) {
        rt::println!(
            "long-op-probe: second take queued {}, result {:#x}",
            queued,
            RESULT.load(Ordering::SeqCst)
        );
        return failed(687);
    }
    joined(id);
    rt::println!("long-op-probe: a second take taken back with SA_RESTART goes again");
    // A handler without SA_RESTART that reads itself leaves the mark of
    // the read it interrupted: that read ends with EINTR.
    let action = SigAction {
        handler: reading_handler as *const () as u64,
        mask: 0,
        flags: 0,
    };
    if unsafe { api::sigaction(SIGUSR1, &action, ptr::null_mut()) } != 0 {
        return failed(688);
    }
    let Some(id) = waiting_reader() else {
        return failed(688);
    };
    if ffi::pthread_kill(id, SIGUSR1) != 0
        || !result_within(0x1000 + EINTR as u64, 1000)
        || INNER_FAILED.load(Ordering::SeqCst) != 0
    {
        rt::println!(
            "long-op-probe: outer read {:#x} after a reading handler",
            RESULT.load(Ordering::SeqCst)
        );
        return failed(689);
    }
    joined(id);
    if stats(&channel) != (0, 0)
        || unsafe { api::sigaction(SIGUSR1, &restored, ptr::null_mut()) } != 0
    {
        return failed(689);
    }
    rt::println!("long-op-probe: a handler that reads keeps the interrupted read's EINTR");
    // A signal while the reader waits for the reply of its "start" (the
    // service holds 50 ms inside it): its handler runs on the way back
    // from that reply, outside `receive`, and the read ends with EINTR
    // before it waits.
    if !handler(0) || !hold(50, 2) {
        return failed(690);
    }
    RESULT.store(0, Ordering::SeqCst);
    let mut id = 0;
    if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(reader), ptr::null_mut()) } != 0 {
        return failed(690);
    }
    let native = unsafe { threads::probe_native(id) }.expect("reader handle");
    let _ = unsafe { crate::layer::sleep::nanosleep(&pause, ptr::null_mut()) };
    let awaiting =
        sys::thread_info(&native).is_ok_and(|i| i.state == rt::abi::ThreadState::AwaitingReply);
    if !awaiting
        || ffi::pthread_kill(id, SIGUSR1) != 0
        || !result_within(0x1000 + EINTR as u64, 1000)
    {
        rt::println!(
            "long-op-probe: start awaited {}, result {:#x}",
            awaiting,
            RESULT.load(Ordering::SeqCst)
        );
        return failed(691);
    }
    joined(id);
    if stats(&channel) != (0, 0)
        || unsafe { api::sigaction(SIGUSR1, &restored, ptr::null_mut()) } != 0
    {
        return failed(691);
    }
    rt::println!("long-op-probe: a signal in the reply of start ends the read with EINTR");
    true
}
