// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Independent-process readings, and SET once under continuous signals:
//! the kernel answers an accepted request once, so the clock service needs
//! no journal (spec 6.1).
use super::*;
use abi::clock::{self, CLOCK_MONOTONIC, CLOCK_REALTIME};
use abi::metadata::Timespec;
use posix_clock::Client;
use posix_time::Time;
use proto_clock::{Method, REALTIME};
use proto_wire::{Status, Writer};

pub(super) struct Peers {
    direct: Client,
    relay: Client,
    /// A session of the service `l` (tests/svc), above the clock.
    long: Handle<Channel>,
}
impl Peers {
    /// The sessions of the probe's own (posix-crt connected the layer's
    /// clock).
    pub(super) fn connect(parent: &Handle<Channel>) -> Result<Self, Status> {
        Ok(Self {
            direct: Client::connect(parent)?,
            relay: Client::connect_named(parent, "clock-peer")?,
            long: rt::service::connect(parent, "long")?,
        })
    }
}
unsafe extern "C" fn reader(_: *mut c_void) -> *mut c_void {
    let mut value = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    if unsafe { clock::clock_gettime(CLOCK_REALTIME, &mut value) } != 0
        || unsafe { *errno } != 777
        || !(123_456..=123_457).contains(&value.tv_sec)
    {
        return ptr::null_mut();
    }
    VALUE as *mut c_void
}
unsafe extern "C" fn setter(argument: *mut c_void) -> *mut c_void {
    let value = Timespec {
        tv_sec: 20_000_000_000 + argument as i64,
        tv_nsec: 42_123,
    };
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    if unsafe { clock::clock_settime(CLOCK_REALTIME, &value) } != 0 || unsafe { *errno } != 777 {
        return ptr::null_mut();
    }
    VALUE as *mut c_void
}
/// The SETs of the storm, each to another date.
const STORM_SETS: usize = 300;
/// The method STORM of the service `l` (tests/svc).
const STORM: u16 = 19;
static STORM_LONG: AtomicU64 = AtomicU64::new(0);
static STORM_CLOCK: AtomicU64 = AtomicU64::new(0);
/// STORM to `l` with a copy of the calling thread's handle: `l` keeps the
/// thread, and the clock session `clock` tells `l` of each SET (WATCH).
fn storm_start(long: &Handle<Channel>, clock: &Client) -> bool {
    let Ok(native) = (unsafe { threads::probe_native(ffi::pthread_self()) }) else {
        return false;
    };
    let rights = rt::abi::Rights::MANAGE | rt::abi::Rights::TRANSFER;
    let Ok(copy) = sys::handle_duplicate(&native, rights) else {
        return false;
    };
    let request = proto_wire::Header::new(STORM, proto_uart::VERSION).bytes();
    let Ok(mut reply) = sys::send_handles(long, &request, [copy.erase()]) else {
        return false;
    };
    let Ok(notified) = reply.handles.take::<Channel>(0) else {
        return false;
    };
    clock.watch(&notified).is_ok()
}
/// STORM with no handle: `l` lets the thread go; the entry requests it
/// made and those that found the thread waiting for its reply.
fn storm_end(long: &Handle<Channel>) -> Option<(u32, u32)> {
    let request = proto_wire::Header::new(STORM, proto_uart::VERSION).bytes();
    let reply = sys::send(long, &request).ok()?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut r = proto_wire::Reader::new(reply.bytes(&mut buffer));
    (r.u32().ok()? == 0).then_some(())?;
    Some((r.u32().ok()?, r.u32().ok()?))
}
/// STORM_SETS SETs while `l`, above the clock service, makes an entry
/// request of this thread at every other SET, before the clock replies.
unsafe extern "C" fn storm_setter(_: *mut c_void) -> *mut c_void {
    // SAFETY: `sets_once_under_entries` keeps the Peers alive until it
    // joined this thread.
    let p = unsafe { &*(STORM_CLOCK.load(Ordering::SeqCst) as *const Peers) };
    let long = Handle::<Channel>::borrowed(rt::abi::Handle(STORM_LONG.load(Ordering::SeqCst)));
    if !storm_start(&long, &p.direct) {
        return ptr::null_mut();
    }
    for n in 0..STORM_SETS {
        let value = Timespec {
            tv_sec: 30_000_000_000 + n as i64,
            tv_nsec: 0,
        };
        if unsafe { clock::clock_settime(CLOCK_REALTIME, &value) } != 0 {
            return ptr::null_mut();
        }
    }
    VALUE as *mut c_void
}
/// SET under continuous entry requests, as signals make them, takes effect
/// exactly once: the generation of the clock grows by one a SET, each
/// request found the setter waiting for its reply, and the kernel left
/// that wait be (spec 6.1).
fn sets_once_under_entries(p: &Peers) -> bool {
    let before = p.direct.get(REALTIME).expect("generation before the storm");
    STORM_CLOCK.store(p as *const Peers as u64, Ordering::SeqCst);
    STORM_LONG.store(p.long.raw().0, Ordering::SeqCst);
    let mut setter = 0;
    let mut result = ptr::null_mut();
    if unsafe {
        ffi::pthread_create(
            &mut setter,
            ptr::null(),
            Some(storm_setter),
            ptr::null_mut(),
        )
    } != 0
        || unsafe { ffi::pthread_join(setter, &mut result) } != 0
        || result as usize != VALUE
    {
        return failed(153);
    }
    let after = p.direct.get(REALTIME).expect("generation after the storm");
    let Some((requested, awaiting)) = storm_end(&p.long) else {
        return failed(154);
    };
    if after.generation != before.generation + STORM_SETS as u64
        || requested as usize != STORM_SETS / 2
        || awaiting != requested
    {
        rt::println!(
            "clock-storm-probe: {} SETs moved the generation by {}; {} entry requests, {} in the reply wait",
            STORM_SETS,
            after.generation - before.generation,
            requested,
            awaiting
        );
        return failed(155);
    }
    rt::println!(
        "posix-thread-probe: {} clock SETs under {} entry requests in their reply waits took effect once each",
        STORM_SETS,
        requested
    );
    true
}
fn set_packet(time: Time) -> Writer {
    let mut w = Writer::new();
    Method::Set.header().write(&mut w).unwrap();
    w.u64(time.seconds as u64).unwrap();
    w.u64(time.nanos as u64).unwrap();
    w
}
pub(super) fn run(p: &Peers) -> bool {
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let _ = settle();
    let before_handles = sys::process_handles(&process)
        .expect("clock handles baseline")
        .live;
    let before_used = sys::process_memory(&process)
        .expect("clock warmed quota baseline")
        .used;
    let saved = p.direct.get(REALTIME).expect("clock saved").time;
    let mut mono = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { clock::clock_gettime(CLOCK_MONOTONIC, &mut mono) } != 0 {
        return failed(140);
    }
    for index in 0..2 {
        let before = p.direct.get(REALTIME).expect("clock generation before");
        let value = Timespec {
            tv_sec: 20_000_000_000 + index as i64,
            tv_nsec: 42_123,
        };
        let mut child = 0;
        let mut result = ptr::null_mut();
        if unsafe {
            ffi::pthread_create(&mut child, ptr::null(), Some(setter), index as *mut c_void)
        } != 0
            || unsafe { ffi::pthread_join(child, &mut result) } != 0
            || result as usize != VALUE
        {
            return failed(141);
        }
        let direct = p.direct.get(REALTIME).expect("clock generation after");
        let other = p.relay.get(REALTIME).expect("clock other process");
        if direct.generation != before.generation + 1
            || other.generation != direct.generation
            || !(value.tv_sec - 1..=value.tv_sec + 1).contains(&other.time.seconds)
            || other.time.value().unwrap() < direct.time.value().unwrap()
        {
            return failed(142);
        }
    }
    let value = Timespec {
        tv_sec: 123_456,
        tv_nsec: 0,
    };
    if unsafe { clock::clock_settime(CLOCK_REALTIME, &value) } != 0 {
        return failed(143);
    }
    let mut child = 0;
    let mut result = ptr::null_mut();
    if unsafe { ffi::pthread_create(&mut child, ptr::null(), Some(reader), ptr::null_mut()) } != 0
        || unsafe { ffi::pthread_join(child, &mut result) } != 0
        || result as usize != VALUE
    {
        return failed(144);
    }
    let mut later = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { clock::clock_gettime(CLOCK_MONOTONIC, &mut later) } != 0
        || (later.tv_sec, later.tv_nsec) < (mono.tv_sec, mono.tv_nsec)
    {
        return failed(145);
    }
    // A SET with a byte past its body changes nothing.
    let generation = p.direct.get(REALTIME).unwrap().generation;
    let mut malformed = set_packet(Time::ZERO);
    malformed.u32(0).unwrap();
    if p.direct.raw(malformed.as_bytes()) != Err(Status::BadSize)
        || p.direct.get(REALTIME).unwrap().generation != generation
    {
        return failed(149);
    }
    if !sets_once_under_entries(p) {
        return false;
    }
    let value = Timespec {
        tv_sec: saved.seconds,
        tv_nsec: saved.nanos,
    };
    if unsafe { clock::clock_settime(CLOCK_REALTIME, &value) } != 0 {
        return failed(150);
    }
    let _ = settle();
    if sys::process_handles(&process)
        .expect("clock handles after")
        .live
        != before_handles
        || sys::process_memory(&process)
            .expect("clock quota after")
            .used
            != before_used
    {
        return failed(151);
    }
    rt::println!("posix-thread-probe: shared clocks, independent process, SET once");
    true
}
