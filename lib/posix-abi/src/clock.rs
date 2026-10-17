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

/// The monotonic instant the process began at (nanoseconds): `process_time`
/// counts from it.
static PROCESS_START: AtomicU64 = AtomicU64::new(0);

fn restart_process_time() {
    PROCESS_START.store(
        rt::time::ticks_to_ns(rt::time::now()).max(1),
        Ordering::Release,
    );
}

/// The time the process has run, for C `clock`: the kernel accounts no
/// processor time, so this is the time since the process began (its start,
/// or the fork that made it), an upper bound of the processor time used.
pub fn process_time() -> Time {
    let start = PROCESS_START.load(Ordering::Acquire);
    Time::from_mono(rt::time::ticks_to_ns(rt::time::now()).saturating_sub(start))
}

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
    restart_process_time();
    Ok(())
}
/// The clock through `session`, a session the program was given (its
/// loader's start, spec 2, 3.2).
///
/// # Safety
/// As for `init`.
pub unsafe fn init_with(session: Handle<Channel>) -> Result<(), Status> {
    // SAFETY: the caller exclusively owns startup initialization.
    let slot = unsafe { &mut *STATE.0.get() };
    if slot.is_some() {
        return Err(Status::Kernel(rt::abi::Error::BadState));
    }
    *slot = Some(Client::from_session(session));
    restart_process_time();
    Ok(())
}

/// The clock of a forked child (spec 2, 3.2): its own session `session`,
/// a clone of its parent's, in place of the parent's, which names nothing
/// of the child's and goes without a close, and the page of the anchor
/// mapped again into its process `process`, which its loader did not copy.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(
    session: Option<Handle<Channel>>,
    process: &Handle<rt::handle::Process>,
) -> Result<(), Status> {
    // SAFETY: the caller's promise gives this borrow alone.
    let slot = unsafe { &mut *STATE.0.get() };
    if let Some(parent) = core::mem::replace(slot, session.map(Client::from_session)) {
        core::mem::forget(parent);
    }
    // The processor time of a child counts from its fork.
    restart_process_time();
    let attached = PAGE.swap(false, Ordering::AcqRel);
    if attached && slot.is_some() {
        // SAFETY: the caller's promise; the copy left PAGE_ADDRESS free.
        unsafe { attach_page(process) }?;
    }
    Ok(())
}

/// The process's session with the clock service.
pub fn session() -> Option<&'static Handle<Channel>> {
    client().ok().map(Client::session)
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
    if id == CLOCK_REALTIME || id == CLOCK_MONOTONIC || cpu_clock(id) {
        Ok(())
    } else {
        Err(EINVAL)
    }
}
/// Whether `id` is a CPU-time clock: of the process (2), of the calling
/// thread (3), or of the thread whose number is `id >> 3` (low bits 6).
fn cpu_clock(id: c_int) -> bool {
    id == crate::cpu::CLOCK_PROCESS_CPUTIME_ID
        || id == crate::cpu::CLOCK_THREAD_CPUTIME_ID
        || (id > 0 && id & 7 == 6)
}
/// The time of clock `id`: MONOTONIC from the counter, REALTIME from the
/// page or the service; no errno.
pub fn gettime(id: c_int) -> Result<Time, c_int> {
    valid(id)?;
    if cpu_clock(id) {
        let ns = match id {
            crate::cpu::CLOCK_PROCESS_CPUTIME_ID => crate::cpu::process_ns()?,
            crate::cpu::CLOCK_THREAD_CPUTIME_ID => crate::cpu::thread_ns()?,
            _ => crate::cpu::thread_ns_of((id >> 3) as u64)?,
        };
        Ok(Time::from_mono(ns))
    } else if id == CLOCK_MONOTONIC {
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
    // The calendar's lead over the monotonic scale, before and after.
    let lead = || realtime_anchor().map(|(calendar, mono)| calendar - i128::from(mono));
    let before = lead();
    client()?
        .set(value, crate::process::identity())
        .map_err(error)?;
    // The timers armed with an absolute time follow the step.
    if let (Ok(before), Ok(after)) = (before, lead()) {
        let delta = (after - before).clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
        if delta != 0 {
            let _ = crate::timers::clock_step(delta);
        }
    }
    Ok(())
}
