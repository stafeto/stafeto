// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Independent-process readings and real interruption after SET/ACK commits.
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
}
impl Peers {
    /// # Safety
    /// Single-threaded startup before any ABI calls.
    pub(super) unsafe fn connect(parent: &Handle<Channel>) -> Result<Self, Status> {
        unsafe { clock::init(parent) }?;
        Ok(Self {
            direct: Client::connect(parent)?,
            relay: Client::connect_named(parent, "clock-peer")?,
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
unsafe extern "C" fn interrupted_setter(argument: *mut c_void) -> *mut c_void {
    let index = argument as usize;
    let method = if index == 0 { Method::Set } else { Method::Ack };
    // Native children have owner handles with DUPLICATE; startup deliberately
    // gives the first thread only MANAGE and TRANSFER.
    let native =
        unsafe { threads::probe_native(threads::pthread_self()) }.expect("clock child handle");
    clock::probe_interrupt(&native, method).expect("arm clock committed-reply interruption");
    let value = Timespec {
        tv_sec: 20_000_000_000 + index as i64,
        tv_nsec: 42_123,
    };
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    if unsafe { clock::clock_settime(CLOCK_REALTIME, &value) } != 0 || unsafe { *errno } != 777 {
        return ptr::null_mut();
    }
    VALUE as *mut c_void
}
fn set_packet(nonce: u64, time: Time) -> Writer {
    let mut w = Writer::new();
    Method::Set.header().write(&mut w).unwrap();
    w.u64(nonce).unwrap();
    w.u64(time.seconds as u64).unwrap();
    w.u64(time.nanos as u64).unwrap();
    w
}
fn ack_packet(nonce: u64) -> Writer {
    let mut w = Writer::new();
    Method::Ack.header().write(&mut w).unwrap();
    w.u64(nonce).unwrap();
    w
}
pub(super) fn run(p: &Peers) -> bool {
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
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
            threads::pthread_create(
                &mut child,
                ptr::null(),
                Some(interrupted_setter),
                index as *mut c_void,
            )
        } != 0
            || unsafe { threads::pthread_join(child, &mut result) } != 0
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
    if unsafe { threads::pthread_create(&mut child, ptr::null(), Some(reader), ptr::null_mut()) }
        != 0
        || unsafe { threads::pthread_join(child, &mut result) } != 0
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
    // Retain one SET, change global time through a different session, then
    // replay the old SET. It must preserve the newer setting and generation.
    let nonce = 1u64 << 63;
    let packet = set_packet(
        nonce,
        Time {
            seconds: 500,
            nanos: 17,
        },
    );
    p.direct
        .probe_call(packet.as_bytes())
        .expect("retained clock setting");
    let value = Timespec {
        tv_sec: 900,
        tv_nsec: 0,
    };
    if unsafe { clock::clock_settime(CLOCK_REALTIME, &value) } != 0 {
        return failed(146);
    }
    let generation = p.direct.get(REALTIME).unwrap().generation;
    p.direct
        .probe_call(packet.as_bytes())
        .expect("retry clock after another client set");
    let other = p.relay.get(REALTIME).unwrap();
    if other.generation != generation || !(899..=901).contains(&other.time.seconds) {
        return failed(147);
    }
    let bad = set_packet(
        nonce,
        Time {
            seconds: 501,
            nanos: 17,
        },
    );
    if p.direct.probe_call(bad.as_bytes()) != Err(Status::from_code(proto_clock::INVALID)) {
        return failed(148);
    }
    let ack = ack_packet(nonce);
    p.direct
        .probe_call(ack.as_bytes())
        .expect("ack retained setting");
    p.direct
        .probe_call(ack.as_bytes())
        .expect("repeat setting ack");
    let mut malformed = set_packet(nonce + 1, Time::ZERO);
    malformed.u32(0).unwrap();
    if p.direct.probe_call(malformed.as_bytes()) != Err(Status::BadSize)
        || p.direct.get(REALTIME).unwrap().generation != generation
    {
        return failed(149);
    }
    let value = Timespec {
        tv_sec: saved.seconds,
        tv_nsec: saved.nanos,
    };
    if unsafe { clock::clock_settime(CLOCK_REALTIME, &value) } != 0 {
        return failed(150);
    }
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
    rt::println!(
        "posix-thread-probe: shared clocks, independent process, committed SET/ACK interruption"
    );
    true
}
