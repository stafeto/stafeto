// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real nested callers retain observations and settings until their own ACK.
use super::*;
use core::cell::UnsafeCell;
use core::sync::atomic::AtomicPtr;
struct Snapshots(UnsafeCell<[Option<Observation>; 700]>);
// SAFETY: only the main probe accesses this array, after the nested worker
// and all of its handlers have been joined. No callback accesses it.
unsafe impl Sync for Snapshots {}
static SNAPSHOTS: Snapshots = Snapshots(UnsafeCell::new([None; 700]));
use posix_clock::Client;
use posix_time::{Observation, SECOND, Time};
use proto_clock::{Method, REALTIME};
use proto_wire::{Status, Writer};
rt::upcall_entry!(entry, dispatch);
static CLIENT: AtomicPtr<Client> = AtomicPtr::new(ptr::null_mut());
static NATIVE: AtomicU64 = AtomicU64::new(0);
static DEPTH: AtomicUsize = AtomicUsize::new(0);
static HANDLERS: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicUsize = AtomicUsize::new(0);
fn client() -> &'static Client {
    // SAFETY: run publishes an immutable client, joins the sole worker and its
    // synchronous handlers before clearing the pointer, then drops the client.
    unsafe { &*CLIENT.load(Ordering::Acquire) }
}
fn time(seconds: i64) -> Time {
    Time { seconds, nanos: 0 }
}
fn near(peak: i128, seconds: i64) -> bool {
    (i128::from(seconds) * SECOND..i128::from(seconds + 1) * SECOND).contains(&peak)
}
unsafe extern "C" fn dispatch() {
    let depth = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    HANDLERS.fetch_add(1, Ordering::SeqCst);
    let errno = unsafe { abi::__errno_location() };
    let saved = unsafe { *errno };
    let c = client();
    let native = Handle::borrowed(rt::abi::Handle(NATIVE.load(Ordering::Acquire)));
    let set_mode = MODE.load(Ordering::Acquire) == 1;
    let method = if set_mode {
        Method::Set
    } else {
        Method::Observe
    };
    if depth == 1 {
        c.probe_upcall(&native, method).unwrap();
        unsafe { rt::upcall::enable() }.unwrap();
    }
    let passed = if set_mode {
        c.set(time(4000 + depth as i64)).is_ok()
    } else {
        c.set(time(1000 + 1000 * depth as i64)).unwrap();
        if depth == 2 {
            c.probe_interrupt(&native, Method::Ack).unwrap();
        }
        c.observe()
            .is_ok_and(|value| near(value.peak, 1000 + 1000 * depth as i64))
    };
    if !passed || unsafe { *errno } != saved {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    rt::upcall::mask().unwrap();
    unsafe { *errno = saved };
    DEPTH.fetch_sub(1, Ordering::SeqCst);
}
unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    let native = unsafe { threads::probe_native(threads::pthread_self()) }.unwrap();
    NATIVE.store(native.raw().0, Ordering::Release);
    let c = client();
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    unsafe { rt::upcall::bind(entry) }.unwrap();
    unsafe { rt::upcall::enable() }.unwrap();
    c.probe_upcall(&native, Method::Observe).unwrap();
    let observed = c.observe();
    if !observed.is_ok_and(|value| near(value.peak, 2_000_000))
        || HANDLERS.load(Ordering::Acquire) != 2
        || ERRORS.load(Ordering::Acquire) != 0
        || unsafe { *errno } != 777
    {
        failed(300);
        return ptr::null_mut();
    }
    MODE.store(1, Ordering::Release);
    let generation = c.get(REALTIME).unwrap().generation;
    c.probe_upcall(&native, Method::Set).unwrap();
    if c.set(time(4000)).is_err()
        || HANDLERS.load(Ordering::Acquire) != 4
        || ERRORS.load(Ordering::Acquire) != 0
        || c.get(REALTIME).unwrap().generation != generation + 3
        || !near(c.get(REALTIME).unwrap().time.value().unwrap(), 4002)
        || DEPTH.load(Ordering::Acquire) != 0
        || unsafe { *errno } != 777
    {
        failed(301);
        return ptr::null_mut();
    }
    rt::upcall::mask().unwrap();
    rt::upcall::unbind().unwrap();
    ptr::dangling_mut::<c_void>()
}
fn set_packet(nonce: u64, seconds: i64) -> Writer {
    let mut w = Writer::new();
    Method::Set.header().write(&mut w).unwrap();
    w.u64(nonce).unwrap();
    w.u64(seconds as u64).unwrap();
    w.u64(0).unwrap();
    w
}
fn same(a: Observation, b: Observation) -> bool {
    a.anchor == b.anchor && a.peak == b.peak
}
fn retained(c: &Client, watch: &Handle<Channel>) -> bool {
    // Beyond the old SET table and enough observations to grow a second chunk.
    const COUNT: usize = 700;
    let base = 1u64 << 62;
    let before = c.probe_stats().unwrap();
    // SAFETY: main owns this probe array throughout the retained-result phase.
    let snapshots = unsafe { &mut *SNAPSHOTS.0.get() };
    for (i, slot) in snapshots.iter_mut().enumerate() {
        if i == COUNT / 2 {
            c.watch(watch).unwrap();
        }
        if i < 80 {
            c.probe_call(set_packet(base + i as u64, 5000 + i as i64).as_bytes())
                .unwrap();
        }
        *slot = Some(c.probe_observe(base + COUNT as u64 + i as u64).unwrap());
    }
    let full = c.probe_stats().unwrap();
    if full.1 <= before.1 {
        return failed(302);
    }
    if !matches!(c.probe_call(set_packet(base + COUNT as u64, 1).as_bytes()),
        Err(e) if e == Status::from_code(proto_clock::INVALID))
    {
        return failed(313);
    }
    if !matches!(c.probe_observe(0), Err(e) if e == Status::from_code(proto_clock::INVALID))
        || c.probe_ack(0) != Err(Status::from_code(proto_clock::INVALID))
    {
        return failed(314);
    }
    let transient = sys::channel_create(1).unwrap();
    c.watch(&transient).unwrap();
    drop(transient);
    c.set(time(8000)).unwrap();
    // Failed notification removes the watch, but ready snapshots must survive.
    if !matches!(c.observe(), Err(Status::Kernel(rt::abi::Error::BadState))) {
        return failed(315);
    }
    let generation = c.get(REALTIME).unwrap().generation;
    for i in (0..COUNT).rev() {
        let nonce = base + COUNT as u64 + i as u64;
        let replay = match c.probe_observe(nonce) {
            Ok(value) => value,
            Err(_) => return failed(303),
        };
        if !same(replay, snapshots[i].unwrap()) {
            return failed(303);
        }
        if i < 80 {
            c.probe_call(set_packet(base + i as u64, 5000 + i as i64).as_bytes())
                .unwrap();
            // A different operation cannot reuse the retained SET nonce.
            if !matches!(c.probe_observe(base + i as u64), Err(e) if e == Status::from_code(proto_clock::INVALID))
            {
                return failed(304);
            }
            c.probe_ack(base + i as u64).unwrap();
        }
        c.probe_ack(nonce).unwrap();
        c.probe_ack(nonce).unwrap();
    }
    if c.get(REALTIME).unwrap().generation != generation || c.probe_stats().unwrap().0 != before.0 {
        return failed(305);
    }
    c.watch(watch).unwrap();
    let warmed = c.probe_stats().unwrap();
    for _ in 0..2000 {
        c.observe().unwrap();
    }
    if c.probe_stats().unwrap() != warmed {
        return failed(306);
    }
    rt::println!(
        "clock-reply-probe: 780 retained results, growth, exact snapshots after watch closure, ACK reuse"
    );
    true
}
fn failure(c: &Client) -> bool {
    c.set(time(9000)).unwrap();
    c.observe().unwrap();
    c.set(time(10_000)).unwrap();
    c.set(time(9000)).unwrap();
    let before = c.get(REALTIME).unwrap();
    let used = c.probe_stats().unwrap();
    c.probe_reject(true).unwrap();
    let set = c.set(time(1));
    let observed = c.observe();
    c.probe_ack(123).unwrap();
    c.probe_reject(false).unwrap();
    if set != Err(Status::from_code(proto_clock::FULL))
        || !matches!(observed, Err(e) if e == Status::from_code(proto_clock::FULL))
        || c.get(REALTIME).unwrap().generation != before.generation
        || !near(c.observe().unwrap().peak, 10_000)
        || c.probe_stats().unwrap() != used
    {
        return failed(307);
    }
    rt::println!("clock-reply-probe: reservation failure preserves clock, generation and interval");
    true
}
fn pressure(c: &Client) -> bool {
    c.probe_pressure(true).unwrap();
    c.probe_pressure(false).unwrap();
    let baseline = c.probe_stats().unwrap();
    let generation = c.get(REALTIME).unwrap().generation;
    let base = 1u64 << 61;
    c.probe_pressure(true).unwrap();
    let mut count = 0;
    let exhausted = loop {
        match c.probe_observe(base + count) {
            Ok(_) if count < 2000 => count += 1,
            Err(e) if e == Status::from_code(proto_clock::FULL) => break true,
            _ => break false,
        }
    };
    let denied = c.set(time(1)) == Err(Status::from_code(proto_clock::FULL));
    let unchanged = c.get(REALTIME).unwrap().generation == generation;
    // ACK and reusing a freed node require no extra kernel handles or maps.
    let recovered = if count != 0 {
        c.probe_ack(base).unwrap();
        c.probe_observe(base).is_ok()
    } else {
        false
    };
    for nonce in base..base + count {
        c.probe_ack(nonce).unwrap();
    }
    c.probe_pressure(false).unwrap();
    if !exhausted || !denied || !unchanged || !recovered || c.probe_stats().unwrap() != baseline {
        return failed(312);
    }
    rt::println!(
        "clock-reply-probe: actual handle exhaustion rejects growth before SET; ACK reuses storage"
    );
    true
}
pub(super) fn run(parent: &Handle<Channel>) -> bool {
    let c = Client::connect(parent).unwrap();
    let watch = sys::channel_create(1).unwrap();
    c.watch(&watch).unwrap();
    let saved = c.get(REALTIME).unwrap().time;
    c.set(time(2_000_000)).unwrap();
    c.set(time(1000)).unwrap();
    CLIENT.store((&c as *const Client).cast_mut(), Ordering::Release);
    let mut child = 0;
    let mut value = ptr::null_mut();
    let created =
        unsafe { threads::pthread_create(&mut child, ptr::null(), Some(worker), ptr::null_mut()) };
    let joined = created == 0 && unsafe { threads::pthread_join(child, &mut value) } == 0;
    CLIENT.store(ptr::null_mut(), Ordering::Release);
    if !joined || value.is_null() {
        return failed(308);
    }
    rt::println!(
        "clock-reply-probe: two nested OBSERVE/SET handlers, snapshots, generation, errno, ACK interruption"
    );
    if !retained(&c, &watch) || !failure(&c) || !pressure(&c) {
        return false;
    }
    // A closed session must release deliberately unacknowledged results.
    let baseline = c.probe_stats().unwrap();
    for i in 0..100 {
        {
            let abandoned = Client::connect(parent).unwrap();
            abandoned.watch(&watch).unwrap();
            abandoned
                .probe_call(set_packet(1, 9000).as_bytes())
                .unwrap();
            abandoned.probe_observe(2).unwrap();
            if c.probe_stats().unwrap().0 <= baseline.0 {
                return failed(309);
            }
            if i == 0 {
                c.probe_ack(1).unwrap();
                if c.probe_stats().unwrap().0 <= baseline.0 {
                    return failed(310);
                }
            }
        }
        if c.probe_stats().unwrap() != baseline {
            return failed(311);
        }
    }
    c.set(saved).unwrap();
    rt::println!("clock-reply-probe: session-scoped ACK and 100 disconnected journals reclaimed");
    true
}
