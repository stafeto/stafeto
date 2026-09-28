// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! POSIX clocks: immutable common counter and a system-wide realtime service.
use crate::{constants::*, fail};
use core::cell::UnsafeCell;
use core::ffi::c_int;
use posix_clock::Client;
use posix_time::{Time, resolution};
use posix_types::Timespec;
use proto_wire::Status;
use rt::handle::{Channel, Handle};

pub const CLOCK_REALTIME: c_int = 0;
pub const CLOCK_MONOTONIC: c_int = 1;
struct State(UnsafeCell<Option<Client>>);
// SAFETY: startup writes once before creating threads. Afterwards only shared
// Client methods run; handles stay owned until the entire process exits.
unsafe impl Sync for State {}
static STATE: State = State(UnsafeCell::new(None));

/// # Safety
/// Called once during single-threaded startup, before any clock ABI call.
pub unsafe fn init(parent: &Handle<Channel>) -> Result<(), Status> {
    // SAFETY: the caller exclusively owns startup initialization.
    let slot = unsafe { &mut *STATE.0.get() };
    if slot.is_some() {
        return Err(Status::Kernel(rt::abi::Error::BadState));
    }
    *slot = Some(Client::connect(parent)?);
    Ok(())
}
fn client() -> Result<&'static Client, c_int> {
    // SAFETY: startup finishes initialization before application threads start.
    unsafe { &*STATE.0.get() }.as_ref().ok_or(EIO)
}
/// Arm a real service interruption on this process's clock endpoint.
#[cfg(feature = "transport-probe")]
pub fn probe_interrupt(
    thread: &Handle<rt::handle::Thread>,
    method: proto_clock::Method,
) -> Result<(), Status> {
    client()
        .map_err(|_| Status::Kernel(rt::abi::Error::BadState))?
        .probe_interrupt(thread, method)
}
fn error(status: Status) -> c_int {
    match status.code() {
        proto_clock::INVALID => EINVAL,
        proto_clock::OVERFLOW => EOVERFLOW,
        proto_clock::FULL => EAGAIN,
        _ => EIO,
    }
}
fn valid(id: c_int) -> Result<(), c_int> {
    if id == CLOCK_REALTIME || id == CLOCK_MONOTONIC {
        Ok(())
    } else {
        Err(EINVAL)
    }
}
unsafe fn store(result: Result<Time, c_int>, out: *mut Timespec) -> c_int {
    match result {
        Ok(time) => {
            // SAFETY: the entry point checked null; the caller supplies one Timespec.
            unsafe {
                out.write(Timespec {
                    tv_sec: time.seconds,
                    tv_nsec: time.nanos,
                })
            };
            0
        }
        Err(code) => fail(code) as c_int,
    }
}
/// # Safety
/// out is writable and aligned for Timespec; the current thread has an ABI scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_gettime(id: c_int, out: *mut Timespec) -> c_int {
    if out.is_null() {
        return fail(EFAULT) as c_int;
    }
    let result = valid(id).and_then(|()| {
        if id == CLOCK_MONOTONIC {
            Ok(Time::from_mono(rt::time::ticks_to_ns(rt::time::now())))
        } else {
            client()?.get(id as u32).map(|v| v.time).map_err(error)
        }
    });
    unsafe { store(result, out) }
}
/// # Safety
/// out is null or writable/aligned for Timespec; the thread has an ABI scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_getres(id: c_int, out: *mut Timespec) -> c_int {
    if let Err(code) = valid(id) {
        return fail(code) as c_int;
    }
    if out.is_null() {
        return 0;
    }
    let result = resolution(rt::time::frequency())
        .map(Time::from_mono)
        .map_err(|_| EIO);
    unsafe { store(result, out) }
}
/// # Safety
/// time supplies one readable aligned Timespec; the thread has an ABI scope.
/// Connecting to the clock service grants setting permission in the current
/// capability table. CLOCK_MONOTONIC is never settable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_settime(id: c_int, time: *const Timespec) -> c_int {
    if id != CLOCK_REALTIME {
        return fail(EINVAL) as c_int;
    }
    if time.is_null() {
        return fail(EFAULT) as c_int;
    }
    // SAFETY: caller supplies one live Timespec.
    let time = unsafe { time.read() };
    let value = Time {
        seconds: time.tv_sec,
        nanos: time.tv_nsec,
    };
    let result = value
        .value()
        .map_err(|_| EINVAL)
        .and_then(|_| client()?.set(value).map_err(error));
    result.map_or_else(|code| fail(code) as c_int, |()| 0)
}
