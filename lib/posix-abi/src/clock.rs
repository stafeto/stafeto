// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! POSIX clocks: immutable common counter and a system-wide realtime service.
use crate::constants::*;
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering, fence};
use posix_clock::Client;
use posix_time::{Time, resolution};
use posix_types::Timespec;
use proto_clock::page;
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
/// Where a process maps the clock service's page of the anchor.
const PAGE_ADDRESS: usize = 0x0E00_0000;
/// Set once the page is mapped: CLOCK_REALTIME reads it with no IPC.
static PAGE: AtomicBool = AtomicBool::new(false);

/// Maps the clock service's page of the CLOCK_REALTIME anchor for reading
/// (spec 2, 3.6); without it CLOCK_REALTIME asks the service each time.
///
/// # Safety
/// Called once during startup, after `init`; PAGE_ADDRESS is free.
pub unsafe fn attach_page(process: &Handle<rt::handle::Process>) -> Result<(), Status> {
    let memory = client().map_err(|_| Status::BadSize)?.page()?;
    rt::sys::mem_map(
        process,
        &memory,
        0,
        page::SIZE as u64,
        PAGE_ADDRESS,
        rt::abi::Access::Read,
    )
    .map_err(Status::Kernel)?;
    PAGE.store(true, Ordering::Release);
    Ok(())
}

fn word(offset: usize) -> &'static AtomicU64 {
    // SAFETY: the page is mapped for reading at PAGE_ADDRESS once PAGE is
    // set, for the process's life; its words are aligned.
    unsafe { &*((PAGE_ADDRESS + offset) as *const AtomicU64) }
}

/// The anchor in the page: its ns, monotonic instant and generation, read
/// whole (proto_clock::page); none without the page.
fn page_anchor() -> Option<(i128, u64, u64)> {
    if !PAGE.load(Ordering::Acquire) {
        return None;
    }
    loop {
        let sequence = word(page::SEQUENCE).load(Ordering::Acquire);
        let place = page::PLACES + (sequence % 2) as usize * page::PLACE_SIZE;
        let low = word(place + page::LOW).load(Ordering::Relaxed);
        let high = word(place + page::HIGH).load(Ordering::Relaxed);
        let mono = word(place + page::MONO).load(Ordering::Relaxed);
        let generation = word(place + page::GENERATION).load(Ordering::Relaxed);
        fence(Ordering::Acquire);
        if word(page::SEQUENCE).load(Ordering::Relaxed) == sequence {
            let value = ((u128::from(high) << 64) | u128::from(low)) as i128;
            return Some((value, mono, generation));
        }
    }
}

/// CLOCK_REALTIME from the page, and the generation of its anchor.
fn page_realtime() -> Option<Result<(Time, u64), c_int>> {
    let (value, mono, generation) = page_anchor()?;
    let now = rt::time::ticks_to_ns(rt::time::now());
    let elapsed = i128::from(now.saturating_sub(mono));
    Some(
        Time::from_value(value + elapsed)
            .map(|time| (time, generation))
            .map_err(|_| EOVERFLOW),
    )
}

/// CLOCK_REALTIME and the generation of its anchor through the page, for
/// the guest probes; EIO without the page.
#[cfg(feature = "thread-probe")]
pub fn probe_realtime() -> Result<(Time, u64), c_int> {
    page_realtime().unwrap_or(Err(EIO))
}

fn client() -> Result<&'static Client, c_int> {
    // SAFETY: startup finishes initialization before application threads start.
    unsafe { &*STATE.0.get() }.as_ref().ok_or(EIO)
}
/// The calendar now (ns of CLOCK_REALTIME) and the monotonic instant it
/// belongs to: the middle of the request to the clock service.
pub(crate) fn realtime_anchor() -> Result<(i128, u64), c_int> {
    if let Some((value, mono, _)) = page_anchor() {
        return Ok((value, mono));
    }
    let before = rt::time::ticks_to_ns(rt::time::now());
    let snapshot = client()?.get(proto_clock::REALTIME).map_err(error)?;
    let after = rt::time::ticks_to_ns(rt::time::now());
    let time = snapshot.time.value().map_err(|_| EOVERFLOW)?;
    Ok((time, before + (after - before) / 2))
}
fn error(status: Status) -> c_int {
    match status.code() {
        proto_clock::INVALID => EINVAL,
        proto_clock::OVERFLOW => EOVERFLOW,
        proto_clock::FULL => EAGAIN,
        proto_clock::PERMISSION => EPERM,
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
/// The time of clock `id`: MONOTONIC from the counter, REALTIME from the
/// page or the service; no errno.
pub fn gettime(id: c_int) -> Result<Time, c_int> {
    valid(id)?;
    if id == CLOCK_MONOTONIC {
        Ok(Time::from_mono(rt::time::ticks_to_ns(rt::time::now())))
    } else if let Some(read) = page_realtime() {
        read.map(|(time, _)| time)
    } else {
        client()?.get(id as u32).map(|v| v.time).map_err(error)
    }
}

/// The resolution of clock `id`: one tick of the counter.
pub fn getres(id: c_int) -> Result<Time, c_int> {
    valid(id)?;
    resolution(rt::time::frequency())
        .map(Time::from_mono)
        .map_err(|_| EIO)
}

/// Sets CLOCK_REALTIME to `time` through the clock service, which lets
/// only a process whose effective UID is 0 do it (EPERM otherwise, the
/// process's identity session telling who it is); CLOCK_MONOTONIC is never
/// settable.
pub fn settime(id: c_int, time: Timespec) -> Result<(), c_int> {
    if id != CLOCK_REALTIME {
        return Err(EINVAL);
    }
    let value = Time {
        seconds: time.tv_sec,
        nanos: time.tv_nsec,
    };
    value.value().map_err(|_| EINVAL)?;
    client()?
        .set(value, crate::process::identity())
        .map_err(error)
}
