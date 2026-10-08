// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Waits by address in the layer (posix-sync, spec 2, 3.4): no call of the
//! kernel for `futex_wake` without waiters nor for a mutex without a rival;
//! EAGAIN for a word that differs; a deadline takes the node out and the
//! bucket's count back to 0; the highest level wakes first, equals in the
//! order they came; 10^5 handoffs of a mutex between two threads lose no
//! wakeup; an entry of signals inside the layer's lock waits for its end.
use super::*;
#[path = "futex_deadline.rs"]
mod deadline_check;
#[path = "futex_watchdog.rs"]
mod watchdog;
use crate::layer::signals::{self as api, SigAction};
use core::sync::atomic::AtomicU32;
use ffi::{Mutex, pthread_mutex_lock, pthread_mutex_unlock};
use posix_sync::{CLOCK_MONOTONIC, EAGAIN, ETIMEDOUT, LayerLock, futex_wait, futex_wake};
use rt::wait::{Waited, Waiter};

static WORD: AtomicU32 = AtomicU32::new(0);
static GATE: AtomicU32 = AtomicU32::new(0);
static ORDER: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static NEXT: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static SHARED: Mutex = Mutex::new();
static COUNT: AtomicU64 = AtomicU64::new(0);
static LAYER: LayerLock = LayerLock::new();
static HANDLED: AtomicUsize = AtomicUsize::new(0);
static IN_SECTION: AtomicUsize = AtomicUsize::new(0);
const HANDOFFS: u64 = 100_000;

fn error() {
    ERRORS.fetch_add(1, Ordering::SeqCst);
}

fn done() {
    let channel = Handle::<Channel>::borrowed(rt::abi::Handle(DONE.load(Ordering::Acquire)));
    sys::notify(&channel, 1).expect("futex probe done");
}

/// The least count of kernel calls `run` makes in eight tries: the
/// counter is the process's, and a helper thread of the layer may wake
/// during one.
fn calls(mut run: impl FnMut()) -> u64 {
    (0..8)
        .map(|_| {
            let before = sys::calls();
            run();
            sys::calls() - before
        })
        .min()
        .unwrap()
}

/// Waits at its level (the argument) for GATE, then says in which place
/// it woke.
unsafe extern "C" fn ordered(argument: *mut c_void) -> *mut c_void {
    let level = argument as usize as u8;
    if threads::set_level(level).is_err() {
        error();
    }
    if futex_wait(&GATE, 0, CLOCK_MONOTONIC, None).is_err() {
        error();
    }
    let place = NEXT.fetch_add(1, Ordering::SeqCst);
    ORDER[place].store(ffi::pthread_self(), Ordering::SeqCst);
    done();
    ptr::null_mut()
}

/// Takes and gives back the shared mutex HANDOFFS times, the other thread
/// waiting in between.
unsafe extern "C" fn handoff(_: *mut c_void) -> *mut c_void {
    let mutex = ptr::from_ref(&SHARED).cast_mut();
    for _ in 0..HANDOFFS {
        if unsafe { pthread_mutex_lock(mutex) } != 0 {
            error();
        }
        COUNT.fetch_add(1, Ordering::Relaxed);
        // The other thread comes to wait on the held mutex.
        let _ = sys::yield_now();
        if unsafe { pthread_mutex_unlock(mutex) } != 0 {
            error();
        }
        let _ = sys::yield_now();
    }
    done();
    ptr::null_mut()
}

static STOP: AtomicUsize = AtomicUsize::new(0);
static VISITS: AtomicU64 = AtomicU64::new(0);
const VISITS_WANTED: u64 = 2000;

/// At level 20, holds the shared mutex 20 us at a time until STOP.
unsafe extern "C" fn holder(_: *mut c_void) -> *mut c_void {
    if threads::set_level(20).is_err() {
        error();
    }
    let mutex = ptr::from_ref(&SHARED).cast_mut();
    while STOP.load(Ordering::SeqCst) == 0 {
        if unsafe { pthread_mutex_lock(mutex) } != 0 {
            error();
        }
        let end = rt::time::ticks_to_ns(rt::time::now()) + 20_000;
        while !rt::time::reached(end) {}
        if unsafe { pthread_mutex_unlock(mutex) } != 0 {
            error();
        }
    }
    ptr::null_mut()
}

/// At level 30, sleeps 50 us and takes the mutex, VISITS_WANTED times: it
/// often finds the holder inside, and the holder's wake preempts it.
unsafe extern "C" fn visitor(_: *mut c_void) -> *mut c_void {
    if threads::set_level(30).is_err() {
        error();
    }
    let mutex = ptr::from_ref(&SHARED).cast_mut();
    let pause = abi::metadata::Timespec {
        tv_sec: 0,
        tv_nsec: 50_000,
    };
    for _ in 0..VISITS_WANTED {
        let _ = unsafe { crate::layer::sleep::nanosleep(&pause, ptr::null_mut()) };
        if unsafe { pthread_mutex_lock(mutex) } != 0 {
            error();
        }
        VISITS.fetch_add(1, Ordering::Relaxed);
        if unsafe { pthread_mutex_unlock(mutex) } != 0 {
            error();
        }
    }
    STOP.store(1, Ordering::SeqCst);
    done();
    ptr::null_mut()
}

unsafe extern "C" fn on_signal(_: i32) {
    if posix_sync::critical() {
        IN_SECTION.fetch_add(1, Ordering::SeqCst);
    }
    HANDLED.fetch_add(1, Ordering::SeqCst);
}

fn create(callback: unsafe extern "C" fn(*mut c_void) -> *mut c_void, value: usize) -> u64 {
    let mut id = 0;
    if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(callback), value as *mut c_void) }
        != 0
    {
        error();
    }
    id
}

fn join(id: u64) {
    if unsafe { ffi::pthread_join(id, ptr::null_mut()) } != 0 {
        error();
    }
}

pub(super) fn run() -> bool {
    let done_channel = sys::channel_create(30).expect("futex done channel");
    DONE.store(done_channel.raw().0, Ordering::Release);
    let waiter = Waiter::new(&done_channel, 1, 30).expect("futex watchdog");
    let mutex = ptr::from_ref(&SHARED).cast_mut();
    let wake = calls(|| {
        futex_wake(&WORD, 1);
    });
    let pair = calls(|| {
        if unsafe { pthread_mutex_lock(mutex) } != 0 || unsafe { pthread_mutex_unlock(mutex) } != 0
        {
            error();
        }
    });
    if wake != 0 || pair != 0 {
        rt::println!(
            "futex-probe: {} calls for a wake, {} for a pair",
            wake,
            pair
        );
        return failed(620);
    }
    if futex_wait(&WORD, 1, CLOCK_MONOTONIC, None) != Err(EAGAIN)
        || posix_sync::bucket_waiters(&WORD) != 0
    {
        return failed(621);
    }
    let deadline = rt::time::ticks_to_ns(rt::time::now()) + 5_000_000;
    loop {
        let result = futex_wait(&WORD, 0, CLOCK_MONOTONIC, Some(deadline));
        let reached = rt::time::reached(deadline);
        let waiters = posix_sync::bucket_waiters(&WORD);
        let word = WORD.load(Ordering::Acquire);
        let outcome = match result {
            Err(ETIMEDOUT) => deadline_check::Outcome::Timeout,
            Ok(posix_sync::Woken::Woken) => deadline_check::Outcome::Woken,
            _ => deadline_check::Outcome::Other,
        };
        match deadline_check::select(outcome, reached, word, waiters) {
            deadline_check::Decision::Retry => continue,
            deadline_check::Decision::Done => break,
            deadline_check::Decision::Fail => {
                let tag = match result {
                    Err(errno) => -errno,
                    Ok(posix_sync::Woken::Woken) => 1,
                    Ok(posix_sync::Woken::Entry) => 2,
                };
                rt::println!(
                    "futex-probe: deadline result={} reached={} waiters={}",
                    tag,
                    u32::from(reached),
                    waiters
                );
                return failed(622);
            }
        }
    }
    rt::println!(
        "futex-probe: no kernel call without waiters or rivals; EAGAIN and a deadline leave the bucket empty"
    );

    // Levels 10, 20, 30 and a second 20 after the first: the highest
    // wakes first, equals in the order they came.
    let ids = [10, 20, 30, 20].map(|level| {
        let id = create(ordered, level);
        if !futex_blocked(id) {
            error();
        }
        id
    });
    for place in 0..4 {
        let wake = futex_wake(&GATE, 1);
        let (received, receive_error) = if wake == 1 {
            let deadline = rt::time::ticks_to_ns(rt::time::now()) + 1_000_000_000;
            match watchdog::receive(deadline, rt::abi::Error::Interrupted, |deadline| {
                waiter.receive_until(&done_channel, deadline)
            }) {
                Ok(Waited::Got(_)) => (1u32, 0u64),
                Ok(Waited::Expired) => (2, 0),
                Err(error) => (3, error.code()),
            }
        } else {
            (0, 0)
        };
        let next = NEXT.load(Ordering::SeqCst);
        if wake != 1 || received != 1 || next != place + 1 {
            let errors = ERRORS.load(Ordering::SeqCst);
            let waiters = posix_sync::bucket_waiters(&GATE);
            rt::println!(
                "futex-probe: ordered place={} wake={} receive={} next={} errors={} waiters={} receive_error={}",
                place,
                wake,
                received,
                next,
                errors,
                waiters,
                receive_error
            );
            return failed(623);
        }
    }
    ids.into_iter().for_each(join);
    let order = ORDER.each_ref().map(|o| o.load(Ordering::SeqCst));
    if order != [ids[2], ids[1], ids[3], ids[0]] || posix_sync::bucket_waiters(&GATE) != 0 {
        rt::println!("futex-probe: woke {:?} of {:?}", order, ids);
        return failed(624);
    }
    rt::println!("futex-probe: the highest level wakes first, equals in the order they came");

    // Two threads hand a mutex over 10^5 times; a lost wakeup stops both
    // and the watchdog sees it.
    let pair = [create(handoff, 0), create(handoff, 1)];
    for _ in pair {
        let deadline = rt::time::ticks_to_ns(rt::time::now()) + 10_000_000_000;
        if !matches!(
            watchdog::receive(deadline, rt::abi::Error::Interrupted, |deadline| {
                waiter.receive_until(&done_channel, deadline)
            }),
            Ok(Waited::Got(_))
        ) {
            rt::println!(
                "futex-probe: handoffs stopped at {}",
                COUNT.load(Ordering::Relaxed)
            );
            return failed(625);
        }
    }
    pair.into_iter().for_each(join);
    if COUNT.load(Ordering::Relaxed) != 2 * HANDOFFS || ERRORS.load(Ordering::SeqCst) != 0 {
        return failed(626);
    }
    // A higher thread that the holder's wake preempts at once.
    let pair = [create(holder, 0), create(visitor, 0)];
    let deadline = rt::time::ticks_to_ns(rt::time::now()) + 10_000_000_000;
    if !matches!(
        watchdog::receive(deadline, rt::abi::Error::Interrupted, |deadline| {
            waiter.receive_until(&done_channel, deadline)
        }),
        Ok(Waited::Got(_))
    ) {
        rt::println!(
            "futex-probe: visits stopped at {}",
            VISITS.load(Ordering::Relaxed)
        );
        return failed(629);
    }
    pair.into_iter().for_each(join);
    if VISITS.load(Ordering::Relaxed) != VISITS_WANTED || ERRORS.load(Ordering::SeqCst) != 0 {
        return failed(630);
    }
    rt::println!(
        "futex-probe: 2 x 10^5 mutex handoffs and 2000 visits from a higher level without a lost wakeup"
    );

    // An entry inside the layer's lock waits for its end.
    let action = SigAction {
        handler: on_signal as *const () as u64,
        mask: 0,
        flags: 0,
    };
    if unsafe { api::sigaction(SIGUSR1, &action, ptr::null_mut()) } != 0 {
        return failed(627);
    }
    let guard = LAYER.lock();
    let raised = api::raise(SIGUSR1);
    let inside = HANDLED.load(Ordering::SeqCst);
    drop(guard);
    let restored = SigAction {
        handler: api::DEFAULT,
        mask: 0,
        flags: 0,
    };
    if raised != 0
        || inside != 0
        || HANDLED.load(Ordering::SeqCst) != 1
        || IN_SECTION.load(Ordering::SeqCst) != 0
        || unsafe { api::sigaction(SIGUSR1, &restored, ptr::null_mut()) } != 0
        || ERRORS.load(Ordering::SeqCst) != 0
    {
        return failed(628);
    }
    rt::println!("futex-probe: a signal inside the layer's lock comes at its end");
    true
}
