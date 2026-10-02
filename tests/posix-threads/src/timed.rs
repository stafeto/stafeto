// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! relibc's timed locks over the layer's waits by address, from a thread
//! while main holds the mutex: a passed deadline gives ETIMEDOUT at once, a
//! future one after it, a bad one EINVAL, and a release before the
//! deadline gives the lock. A deadline on CLOCK_REALTIME whose calendar
//! steps back after the wait began is checked again: the lock waits for
//! the new instant.
use super::*;
use crate::layer::clock::{self, CLOCK_REALTIME};
use abi::metadata::Timespec;
use ffi::{Mutex, pthread_mutex_lock, pthread_mutex_timedlock, pthread_mutex_unlock};

static LOCK: Mutex = Mutex::new();
static SECONDS: AtomicU64 = AtomicU64::new(0);
static NANOS: AtomicU64 = AtomicU64::new(0);
static RESULT: AtomicUsize = AtomicUsize::new(0);
static ELAPSED: AtomicU64 = AtomicU64::new(0);

/// A deadline on the calendar taken when the check starts, the result and
/// the least time it takes.
type Check = (fn() -> Timespec, i32, u64);

const BAD: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 1_000_000_000,
};

fn lock() -> *mut Mutex {
    ptr::from_ref(&LOCK).cast_mut()
}
fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}
fn spec(ns: u64) -> Timespec {
    Timespec {
        tv_sec: (ns / 1_000_000_000) as i64,
        tv_nsec: (ns % 1_000_000_000) as i64,
    }
}
fn realtime() -> u64 {
    let mut value = spec(0);
    assert_eq!(
        unsafe { clock::clock_gettime(CLOCK_REALTIME, &mut value) },
        0
    );
    value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64
}
fn set(ns: u64) {
    assert_eq!(
        unsafe { clock::clock_settime(CLOCK_REALTIME, &spec(ns)) },
        0
    );
}
/// A timed lock until SECONDS and NANOS; its result and how long it took.
unsafe extern "C" fn timed(_: *mut c_void) -> *mut c_void {
    let at = Timespec {
        tv_sec: SECONDS.load(Ordering::SeqCst) as i64,
        tv_nsec: NANOS.load(Ordering::SeqCst) as i64,
    };
    let start = now();
    let at = ffi::Timespec {
        tv_sec: at.tv_sec,
        tv_nsec: at.tv_nsec,
    };
    let result = unsafe { pthread_mutex_timedlock(lock(), &at) };
    ELAPSED.store(now() - start, Ordering::SeqCst);
    RESULT.store(result as usize, Ordering::SeqCst);
    if result == 0 && unsafe { pthread_mutex_unlock(lock()) } != 0 {
        RESULT.store(usize::MAX, Ordering::SeqCst);
    }
    ptr::null_mut()
}
fn start(at: Timespec) -> u64 {
    SECONDS.store(at.tv_sec as u64, Ordering::SeqCst);
    NANOS.store(at.tv_nsec as u64, Ordering::SeqCst);
    let mut id = 0;
    assert_eq!(
        unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(timed), ptr::null_mut()) },
        0
    );
    id
}
/// The result and duration of the timed lock of thread `id`, once it ended.
fn outcome(id: u64) -> (i32, u64) {
    assert_eq!(unsafe { ffi::pthread_join(id, ptr::null_mut()) }, 0);
    (
        RESULT.load(Ordering::SeqCst) as i32,
        ELAPSED.load(Ordering::SeqCst),
    )
}

pub(super) fn run() -> bool {
    if unsafe { pthread_mutex_lock(lock()) } != 0 {
        return failed(160);
    }
    // Each deadline is taken when its check starts.
    let checks: [Check; 3] = [
        (|| spec(realtime() - 1), ETIMEDOUT, 0),
        (|| BAD, EINVAL, 0),
        (|| spec(realtime() + 20_000_000), ETIMEDOUT, 15_000_000),
    ];
    for (index, (at, expected, at_least)) in checks.into_iter().enumerate() {
        let (result, elapsed) = outcome(start(at()));
        if result != expected || elapsed < at_least {
            rt::println!(
                "posix-timed-mutex-probe: check {} gave {} after {} ns",
                index,
                result,
                elapsed
            );
            return failed(161);
        }
    }
    // A release before the deadline gives the lock.
    let id = start(spec(realtime() + 2_000_000_000));
    if !futex_blocked(id) || unsafe { pthread_mutex_unlock(lock()) } != 0 {
        return failed(162);
    }
    let (result, elapsed) = outcome(id);
    if result != 0 || elapsed >= 2_000_000_000 {
        return failed(163);
    }
    // The calendar steps back 200 ms while the wait for +30 ms runs: the
    // lock times out only at the new instant.
    if unsafe { pthread_mutex_lock(lock()) } != 0 {
        return failed(164);
    }
    let (calendar, monotonic) = (realtime(), now());
    let id = start(spec(calendar + 30_000_000));
    if !futex_blocked(id) {
        return failed(165);
    }
    set(realtime() - 200_000_000);
    let (result, elapsed) = outcome(id);
    set(calendar + (now() - monotonic));
    if result != ETIMEDOUT || elapsed < 200_000_000 {
        rt::println!(
            "posix-timed-mutex-probe: the stepped calendar gave {} after {} ns",
            result,
            elapsed
        );
        return failed(166);
    }
    if unsafe { pthread_mutex_unlock(lock()) } != 0 {
        return failed(167);
    }
    rt::println!(
        "posix-timed-mutex-probe: passed, bad and future deadlines, release and a calendar step back ok"
    );
    true
}
