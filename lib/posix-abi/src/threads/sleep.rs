// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! C sleep in the calling thread: its timer on its own channel (posix-sync),
//! `receive` until the deadline. An entry of signals ends the sleep with
//! EINTR and, for a relative sleep, the time left; bit CANCEL of the channel
//! or an entry with cancellation requested ends it at its cancellation
//! point. An absolute deadline on CLOCK_REALTIME becomes a monotonic
//! instant, checked on the calendar once it passed; a calendar set forward
//! does not wake the sleep earlier, until the clock patch of relibc.
use super::{cancel, mutex, own_block};
use crate::{constants::*, fail};
use core::sync::atomic::Ordering;
use posix_time::Sleep;
use posix_types::Timespec;
use rt::abi::{Error, Source};
use rt::handle::{Channel, Handle, Timer};
use rt::sys;

pub const TIMER_ABSTIME: i32 = 1;

fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}

/// The monotonic instant of `deadline`.
fn target(deadline: Sleep) -> Result<u64, i32> {
    match deadline {
        Sleep::Relative(end) => Ok(end.clamp(0, i128::from(u64::MAX)) as u64),
        Sleep::Absolute(deadline) => mutex::monotonic_target(deadline),
    }
}

/// Whether `deadline` passed on its own clock.
fn passed(deadline: Sleep) -> Result<bool, i32> {
    match deadline {
        Sleep::Relative(end) => Ok(end <= i128::from(now())),
        Sleep::Absolute(deadline) => mutex::passed(deadline),
    }
}

/// Sleeps on the calling thread's timer until `deadline`: EINTR when an
/// entry or a request of cancellation ended it before.
pub(crate) fn sleep_until(deadline: Sleep) -> Result<(), i32> {
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
        let guard = rt::upcall::defer_entries().expect("sleep entry deferral");
        let _ = sys::timer_set(&timer, at);
        let got = sys::receive(&channel);
        drop(guard);
        match got {
            Ok(sys::Received::Notification {
                source: Source::Unlabeled,
                bits,
                ..
            }) if bits & posix_sync::bit::CANCEL != 0 && cancel::requested() => {
                break Err(EINTR);
            }
            Ok(_) => {}
            Err(Error::Interrupted) => break Err(EINTR),
            Err(error) => panic!("sleep receive: {error:?}"),
        }
    };
    let _ = sys::timer_cancel(&timer);
    result
}

/// # Safety
/// The caller is managed. request supplies a readable aligned Timespec; remaining
/// is null or writable. They may name the same object. Absolute calls ignore remaining.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_nanosleep(
    clock: i32,
    flags: i32,
    requested: *const Timespec,
    remaining: *mut Timespec,
) -> i32 {
    let point = cancel::Point::begin();
    let result = (|| {
        if requested.is_null() {
            return Err(EFAULT);
        }
        if !matches!(flags, 0 | TIMER_ABSTIME) {
            return Err(EINVAL);
        }
        // SAFETY: caller supplies one Timespec; copy before touching a possible alias.
        let value = unsafe { requested.read() };
        let start = now();
        let deadline = Sleep::new(
            clock as u32,
            flags == TIMER_ABSTIME,
            value.tv_sec,
            value.tv_nsec,
            start,
        )
        .map_err(|_| EINVAL)?;
        let result = sleep_until(deadline);
        if result == Err(EINTR)
            && !remaining.is_null()
            && let Some(time) = deadline.remaining(now()).map_err(|_| EOVERFLOW)?
        {
            // SAFETY: caller supplies writable storage, possibly aliasing the copied request.
            unsafe {
                remaining.write(Timespec {
                    tv_sec: time.seconds,
                    tv_nsec: time.nanos,
                })
            };
        }
        result
    })();
    point.finish();
    result.map_or_else(|error| error, |()| 0)
}
/// # Safety
/// As for clock_nanosleep with CLOCK_REALTIME and a relative interval.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nanosleep(requested: *const Timespec, remaining: *mut Timespec) -> i32 {
    let status = unsafe { clock_nanosleep(crate::clock::CLOCK_REALTIME, 0, requested, remaining) };
    if status == 0 { 0 } else { fail(status) as i32 }
}
