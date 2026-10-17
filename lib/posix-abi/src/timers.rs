// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! POSIX timers and the alarm over the process service (Ф7): the service
//! keeps the timers of the process (`Method::Timer`) and sends their
//! signals the way `kill` does; the layer turns the calendar into the
//! scale of the kernel's timers. A `timer_t` is the service's id in its
//! low 32 bits and the clock of the timer above them (REALTIME or
//! MONOTONIC), which an absolute time on that clock needs.
//!
//! Absolute CLOCK_REALTIME times are turned into the monotonic scale when
//! the timer is armed; a later setting of the calendar does not move them.

use crate::constants::*;
use crate::process::{ask, ask_setting, request};
use posix_types::Timespec;
use proto_process::timer_op as op;

const SECOND: i128 = 1_000_000_000;
/// TIMER_ABSTIME of relibc's time.h.
pub const TIMER_ABSTIME: i32 = 1;
/// The numbers of SIGEV_ in relibc's signal.h.
pub const SIGEV_SIGNAL: i32 = 0;
pub const SIGEV_NONE: i32 = 1;

/// A timer's time and interval, `struct itimerspec` without its order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spec {
    pub interval: Timespec,
    pub value: Timespec,
}

fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}

fn timespec(ns: u64) -> Timespec {
    Timespec {
        tv_sec: (ns / 1_000_000_000) as i64,
        tv_nsec: (ns % 1_000_000_000) as i64,
    }
}

fn nanos(t: Timespec) -> i128 {
    i128::from(t.tv_sec) * SECOND + i128::from(t.tv_nsec)
}

fn valid(t: Timespec) -> bool {
    (0..1_000_000_000).contains(&t.tv_nsec)
}

fn clock_of(timer: usize) -> i32 {
    (timer >> 32) as i32
}

fn id_of(timer: usize) -> u32 {
    timer as u32
}

fn check_clock(clock: i32) -> Result<(), i32> {
    if clock == crate::clock::CLOCK_REALTIME || clock == crate::clock::CLOCK_MONOTONIC {
        Ok(())
    } else {
        Err(EINVAL)
    }
}

/// A timer on `clock` that sends `signal` (1 to 64; 0: SIGEV_NONE) with
/// the value `value` (the bytes of sigval; with `own_id` the number of the
/// timer): its `timer_t`. EAGAIN when the
/// process holds its share of timers or the service has no place.
pub fn create(clock: i32, signal: i32, value: u64, own_id: bool) -> Result<usize, i32> {
    check_clock(clock)?;
    if !(0..=64).contains(&signal) {
        return Err(EINVAL);
    }
    // Bit 8 of the signal: the value the signal carries is the timer's id.
    let signal = signal as u32 | if own_id { 0x100 } else { 0 };
    let mut w = request(proto_process::Method::Timer, &[op::CREATE, signal])?;
    w.u64(value).map_err(|_| EIO)?;
    let id = ask(&w)?;
    Ok(id as usize | (clock as usize) << 32)
}

/// Deletes the timer; EINVAL for one that is none of the process's.
pub fn delete(timer: usize) -> Result<(), i32> {
    let w = request(proto_process::Method::Timer, &[op::DELETE, id_of(timer)])?;
    ask(&w).map(drop)
}

/// The overrun count of the signal last sent.
pub fn overrun(timer: usize) -> Result<i32, i32> {
    let w = request(proto_process::Method::Timer, &[op::OVERRUN, id_of(timer)])?;
    ask(&w).map(|n| n as i32)
}

fn spec(setting: [u64; 2]) -> Spec {
    Spec {
        interval: timespec(setting[1]),
        value: timespec(setting[0]),
    }
}

/// The time left of the timer and its interval.
pub fn gettime(timer: usize) -> Result<Spec, i32> {
    let w = request(proto_process::Method::Timer, &[op::GET, id_of(timer)])?;
    ask_setting(&w).map(spec)
}

/// The monotonic instant of `value` for a timer of `clock`: relative to now,
/// or an absolute time on its clock. Not before now.
fn instant(clock: i32, absolute: bool, value: Timespec) -> Result<u64, i32> {
    let start = now();
    let target = if !absolute {
        i128::from(start) + nanos(value)
    } else if clock == crate::clock::CLOCK_MONOTONIC {
        nanos(value)
    } else {
        let (calendar, mono) = crate::clock::realtime_anchor()?;
        nanos(value) - calendar + i128::from(mono)
    };
    Ok(target.clamp(i128::from(start), i128::from(u64::MAX)) as u64)
}

/// The deadline and interval of a setting, in the service's form.
fn arming(clock: i32, flags: i32, new: Spec) -> Result<(u32, u64, u64), i32> {
    if flags & !TIMER_ABSTIME != 0 {
        return Err(EINVAL);
    }
    if new.value.tv_sec == 0 && new.value.tv_nsec == 0 {
        return Ok((0, 0, 0));
    }
    if !valid(new.value) || !valid(new.interval) || new.value.tv_sec < 0 || new.interval.tv_sec < 0
    {
        return Err(EINVAL);
    }
    let deadline = instant(clock, flags & TIMER_ABSTIME != 0, new.value)?;
    let interval = nanos(new.interval).clamp(0, i128::from(u64::MAX)) as u64;
    // An absolute time of CLOCK_REALTIME follows the steps of the calendar.
    let follows = flags & TIMER_ABSTIME != 0 && clock == crate::clock::CLOCK_REALTIME;
    Ok((1 | if follows { op::ARMED_REALTIME } else { 0 }, deadline, interval))
}

/// Arms the timer with `new` (a zero value disarms it); the setting
/// before. With TIMER_ABSTIME `new.value` is a time on the timer's clock.
pub fn settime(timer: usize, flags: i32, new: Spec) -> Result<Spec, i32> {
    let (armed, deadline, interval) = arming(clock_of(timer), flags, new)?;
    let mut w = request(
        proto_process::Method::Timer,
        &[op::SET, id_of(timer), armed],
    )?;
    w.u64(deadline)
        .and_then(|()| w.u64(interval))
        .map_err(|_| EIO)?;
    ask_setting(&w).map(spec)
}

/// The alarm of the process (ITIMER_REAL): arms it `value` from now and
/// then every `interval` (value 0 disarms it); the setting before, in
/// nanoseconds: the time left and the interval.
pub fn set_alarm(value: u64, interval: u64) -> Result<[u64; 2], i32> {
    let (armed, deadline) = if value == 0 {
        (0, 0)
    } else {
        (1, now().saturating_add(value))
    };
    let mut w = request(proto_process::Method::Timer, &[op::ALARM_SET, armed])?;
    w.u64(deadline)
        .and_then(|()| w.u64(interval))
        .map_err(|_| EIO)?;
    ask_setting(&w)
}

/// The alarm of the process: the time left and the interval, in nanoseconds.
pub fn get_alarm() -> Result<[u64; 2], i32> {
    let w = request(proto_process::Method::Timer, &[op::ALARM_GET])?;
    ask_setting(&w)
}

/// The calendar of CLOCK_REALTIME was set `delta` ns ahead of the monotonic
/// scale (superuser): the timers armed with an absolute time of it move.
pub(crate) fn clock_step(delta: i64) -> Result<(), i32> {
    let mut w = request(proto_process::Method::Timer, &[op::CLOCK_STEP])?;
    w.u64(delta as u64).map_err(|_| EIO)?;
    ask(&w).map(drop)
}
