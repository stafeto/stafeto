// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! C sleep in the calling thread: its timer on its own channel (posix-sync),
//! `receive` until the deadline. An entry of signals ends the sleep with
//! EINTR and, for a relative sleep, the time left; bit CANCEL of the channel
//! or an entry with cancellation requested ends it at its cancellation
//! point. An absolute deadline on CLOCK_REALTIME becomes a monotonic
//! instant, checked on the calendar once it passed; a calendar set forward
//! does not wake the sleep earlier, until the clock patch of relibc.
use super::{cancel, own_block};
use crate::constants::*;
use core::sync::atomic::Ordering;
use posix_time::{Deadline, Sleep};
use posix_types::Timespec;
use rt::abi::{Error, Source};
use rt::handle::{Channel, Handle, Timer};
use rt::sys;

pub const TIMER_ABSTIME: i32 = 1;

fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}

/// The monotonic instant of an absolute deadline on `deadline.clock`; for
/// CLOCK_REALTIME through the clock's anchor now, rechecked after it passed.
fn absolute_target(deadline: Deadline) -> Result<u64, i32> {
    let target = if deadline.clock == proto_clock::REALTIME {
        let (time, mono) = crate::clock::realtime_anchor()?;
        deadline.value() - time + i128::from(mono)
    } else {
        deadline.value()
    };
    Ok(target.clamp(0, i128::from(u64::MAX)) as u64)
}

/// Whether an absolute deadline passed on its own clock.
fn absolute_passed(deadline: Deadline) -> Result<bool, i32> {
    if deadline.clock == proto_clock::REALTIME {
        let (time, _) = crate::clock::realtime_anchor()?;
        return Ok(deadline.value() <= time);
    }
    Ok(deadline.value() <= i128::from(rt::time::ticks_to_ns(rt::time::now())))
}

/// The monotonic instant of `deadline`.
fn target(deadline: Sleep) -> Result<u64, i32> {
    match deadline {
        Sleep::Relative(end) => Ok(end.clamp(0, i128::from(u64::MAX)) as u64),
        Sleep::Absolute(deadline) => absolute_target(deadline),
    }
}

/// Whether `deadline` passed on its own clock.
fn passed(deadline: Sleep) -> Result<bool, i32> {
    match deadline {
        Sleep::Relative(end) => Ok(end <= i128::from(now())),
        Sleep::Absolute(deadline) => absolute_passed(deadline),
    }
}

/// Sleeps `ns` nanoseconds of CLOCK_MONOTONIC, no point of cancellation,
/// for the probes inside the layer.
pub(crate) fn probe_pause(ns: u64) {
    let start = now();
    if let Ok(deadline) = Sleep::new(
        proto_clock::MONOTONIC,
        false,
        (ns / 1_000_000_000) as i64,
        (ns % 1_000_000_000) as i64,
        start,
    ) {
        let _ = sleep_until(deadline);
    }
}

/// Sleeps on the calling thread's timer until `deadline`: EINTR when an
/// entry or a request of cancellation ended it before.
pub(crate) fn sleep_until(deadline: Sleep) -> Result<(), i32> {
    sleep_in(deadline, true)
}

/// A relative pause of `nanos` nanoseconds on CLOCK_MONOTONIC inside a
/// function that is no point of cancellation (crate::random): a caught
/// signal ends it with EINTR, a request of cancellation leaves it on and
/// stays for the next point.
pub(crate) fn pause(nanos: i64) -> Result<(), i32> {
    let deadline = Sleep::new(crate::clock::CLOCK_MONOTONIC as u32, false, 0, nanos, now())
        .map_err(|_| EINVAL)?;
    sleep_in(deadline, false)
}

/// `sleep_until`, a request of cancellation ending it only when `point`.
fn sleep_in(deadline: Sleep, point: bool) -> Result<(), i32> {
    let block = own_block();
    let channel =
        Handle::<Channel>::borrowed(rt::abi::Handle(block.channel.load(Ordering::Relaxed)));
    let timer = Handle::<Timer>::borrowed(rt::abi::Handle(block.timer.load(Ordering::Relaxed)));
    let mut at = target(deadline)?;
    let result = loop {
        if rt::time::reached(at) {
            if passed(deadline)? {
                break Ok(());
            }
            // The calendar moved back: sleep to its new instant.
            at = target(deadline)?;
            continue;
        }
        // An entry between the timer and `receive` stays pending and makes
        // `receive` return at once; a handler that sleeps itself cannot
        // take this wait's timer meanwhile.
        let handled = block.handled.load(Ordering::SeqCst);
        let guard = rt::upcall::defer_entries().expect("sleep entry deferral");
        let _ = sys::timer_set(&timer, at);
        let got = sys::receive(&channel);
        drop(guard);
        match got {
            Ok(sys::Received::Notification {
                source: Source::Unlabeled,
                bits,
                ..
            }) if point && bits & posix_sync::bit::CANCEL != 0 && cancel::requested() => {
                break Err(EINTR);
            }
            Ok(_) => {}
            // An entry that ran no handler (a stop of exec or fork parked
            // the thread) leaves the sleep on: EINTR is for a caught signal.
            Err(Error::Interrupted)
                if block.handled.load(Ordering::SeqCst) == handled
                    && !(point && cancel::requested()) => {}
            Err(Error::Interrupted) => break Err(EINTR),
            Err(error) => panic!("sleep receive: {error:?}"),
        }
    };
    let _ = sys::timer_cancel(&timer);
    result
}

/// Sleeps on `clock` for `requested` (an absolute time with
/// TIMER_ABSTIME): Ok at its end; EINTR with the time left of a relative
/// sleep when a caught signal cut it; EINVAL for a bad request. A point
/// of cancellation.
pub fn clock_nanosleep(
    clock: i32,
    flags: i32,
    requested: Timespec,
) -> Result<(), (i32, Option<Timespec>)> {
    let point = cancel::Point::begin();
    let result = (|| {
        if !matches!(flags, 0 | TIMER_ABSTIME) {
            return Err((EINVAL, None));
        }
        let start = now();
        let deadline = Sleep::new(
            clock as u32,
            flags == TIMER_ABSTIME,
            requested.tv_sec,
            requested.tv_nsec,
            start,
        )
        .map_err(|_| (EINVAL, None))?;
        match sleep_until(deadline) {
            Err(EINTR) => {
                let left = deadline
                    .remaining(now())
                    .map_err(|_| (EOVERFLOW, None))?
                    .map(|time| Timespec {
                        tv_sec: time.seconds,
                        tv_nsec: time.nanos,
                    });
                Err((EINTR, left))
            }
            other => other.map_err(|error| (error, None)),
        }
    })();
    point.finish();
    result
}

/// clock_nanosleep with CLOCK_REALTIME and a relative interval.
pub fn nanosleep(requested: Timespec) -> Result<(), (i32, Option<Timespec>)> {
    clock_nanosleep(crate::clock::CLOCK_REALTIME, 0, requested)
}
