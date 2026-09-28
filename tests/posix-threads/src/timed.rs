// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real waits, both calendar steps, monotonic expiry and committed outcomes.
use super::*;
use abi::clock::{self, CLOCK_MONOTONIC, CLOCK_REALTIME};
use abi::metadata::Timespec;
use core::cell::UnsafeCell;
use rt::wait::{Waited, Waiter};
use threads::mutex::{
    self, Mutex, pthread_mutex_clocklock, pthread_mutex_lock, pthread_mutex_unlock,
};

static LOCK: Mutex = Mutex::new();
static DONE_CHANNEL: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);
static PUBLISHED: AtomicU64 = AtomicU64::new(0);
struct Payload(UnsafeCell<u64>);
// SAFETY: all ordinary payload access holds LOCK.
unsafe impl Sync for Payload {}
static PAYLOAD: Payload = Payload(UnsafeCell::new(0));
struct Args {
    clock: i32,
    deadline: Timespec,
    pending: bool,
    low: bool,
    epoch: u64,
}
fn lock() -> *mut Mutex {
    ptr::from_ref(&LOCK).cast_mut()
}
fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}
fn mono(ns: u64) -> Timespec {
    Timespec {
        tv_sec: (ns / 1_000_000_000) as i64,
        tv_nsec: (ns % 1_000_000_000) as i64,
    }
}
fn set(seconds: i64) {
    let value = Timespec {
        tv_sec: seconds,
        tv_nsec: 0,
    };
    assert_eq!(unsafe { clock::clock_settime(CLOCK_REALTIME, &value) }, 0);
}
unsafe extern "C" fn contender(argument: *mut c_void) -> *mut c_void {
    // The harness explicitly publishes its stack argument before creation.
    let epoch = PUBLISHED.load(Ordering::Acquire);
    let args = unsafe { &*argument.cast::<Args>() };
    assert_eq!(args.epoch, epoch);
    if args.low {
        let native = unsafe { threads::probe_native(threads::pthread_self()) }.unwrap();
        sys::thread_set_priority(&native, 10, rt::abi::Policy::Fifo).unwrap();
    }
    if args.pending {
        assert_eq!(threads::pthread_cancel(threads::pthread_self()), 0);
    }
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    let status = unsafe { pthread_mutex_clocklock(lock(), args.clock, &args.deadline) };
    let mut outcome = status as usize + 1;
    if status == 0 {
        if unsafe { *PAYLOAD.0.get() } != 555 {
            outcome = 0;
        }
        unsafe { *PAYLOAD.0.get() = 556 };
        if unsafe { pthread_mutex_unlock(lock()) } != 0 {
            outcome = 0;
        }
    }
    if unsafe { *errno } != 777 {
        outcome = 0;
    }
    DONE.store(outcome, Ordering::Release);
    let done = Handle::<Channel>::borrowed(rt::abi::Handle(DONE_CHANNEL.load(Ordering::Acquire)));
    sys::notify(&done, 1).unwrap();
    threads::cancel::pthread_testcancel();
    outcome as *mut c_void
}
fn child(args: &Args) -> u64 {
    DONE.store(0, Ordering::Release);
    PUBLISHED.store(args.epoch, Ordering::Release);
    let mut id = 0;
    assert_eq!(
        unsafe {
            threads::pthread_create(
                &mut id,
                ptr::null(),
                Some(contender),
                ptr::from_ref(args).cast_mut().cast(),
            )
        },
        0
    );
    id
}
fn blocked(id: u64) -> bool {
    let native = unsafe { threads::probe_native(id) }.unwrap();
    waiting(&native) && mutex::probe_waiting(id) == Ok(true)
}
fn join(id: u64, expected: usize) -> bool {
    let mut result = ptr::null_mut();
    (unsafe { threads::pthread_join(id, &mut result) }) == 0 && result as usize == expected
}
fn finished(done: &Handle<Channel>, waiter: &Waiter, expected: usize) -> bool {
    let limit = now().saturating_add(500_000_000);
    loop {
        match waiter.receive_until(done, limit) {
            Ok(Waited::Got(_)) => {
                if DONE.load(Ordering::Acquire) != 0 {
                    return DONE.load(Ordering::Acquire) == expected;
                }
            }
            _ => return false,
        }
    }
}
fn held() {
    assert_eq!(unsafe { pthread_mutex_lock(lock()) }, 0);
    unsafe { *PAYLOAD.0.get() = 555 };
}
fn release() {
    assert_eq!(unsafe { pthread_mutex_unlock(lock()) }, 0);
}

pub(super) fn run() -> bool {
    let saved = {
        let mut value = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(
            unsafe { clock::clock_gettime(CLOCK_REALTIME, &mut value) },
            0
        );
        value
    };
    let done = sys::channel_create(30).unwrap();
    let waiter = Waiter::new(&done, 0, 30).unwrap();
    DONE_CHANNEL.store(done.raw().0, Ordering::Release);
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let gate = sys::channel_create(30).unwrap();
    let before_handles = sys::process_handles(&process).unwrap().live;
    let before_used = sys::process_memory(&process).unwrap().used;

    // Live monotonic wait: external interruptions preserve the original deadline.
    held();
    let deadline = now() + 200_000_000;
    let args = Args {
        clock: CLOCK_MONOTONIC,
        deadline: mono(deadline),
        pending: false,
        low: false,
        epoch: 1,
    };
    let id = child(&args);
    let native = unsafe { threads::probe_native(id) }.unwrap();
    for _ in 0..3 {
        if !blocked(id) || sys::thread_interrupt(&native).is_err() {
            return failed(160);
        }
    }
    mutex::probe_interrupt_timed_reply();
    if !finished(&done, &waiter, ETIMEDOUT as usize + 1)
        || now() < deadline
        || !join(id, ETIMEDOUT as usize + 1)
        || mutex::probe_waiting(threads::pthread_self()) != Ok(false)
    {
        return failed(161);
    }
    // Timeout does not grant or release the still-held mutex.
    release();

    // A later registration with an earlier deadline must move the shared timer.
    held();
    let first_deadline = now() + 600_000_000;
    let first = Args {
        clock: CLOCK_MONOTONIC,
        deadline: mono(first_deadline),
        pending: false,
        low: false,
        epoch: 9,
    };
    let early_deadline = now() + 150_000_000;
    let second = Args {
        clock: CLOCK_MONOTONIC,
        deadline: mono(early_deadline),
        pending: false,
        low: false,
        epoch: 10,
    };
    let late = child(&first);
    if !blocked(late) {
        return failed(183);
    }
    let early = child(&second);
    if !blocked(early) {
        return failed(184);
    }
    if !finished(&done, &waiter, ETIMEDOUT as usize + 1)
        || now() < early_deadline
        || now() >= first_deadline
        || !blocked(late)
        || !join(early, ETIMEDOUT as usize + 1)
    {
        return failed(185);
    }
    if !finished(&done, &waiter, ETIMEDOUT as usize + 1)
        || now() < first_deadline
        || !join(late, ETIMEDOUT as usize + 1)
    {
        return failed(186);
    }
    release();

    // A forward calendar step must wake an otherwise ten-second wait promptly.
    set(10_000);
    held();
    let args = Args {
        clock: CLOCK_REALTIME,
        deadline: Timespec {
            tv_sec: 10_010,
            tv_nsec: 0,
        },
        pending: false,
        low: false,
        epoch: 2,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(162);
    }
    // Drain old cleanup/timer notices before testing a notification-only wake.
    if !matches!(
        waiter.receive_until(&done, now() + 20_000_000),
        Ok(Waited::Expired)
    ) || DONE.load(Ordering::Acquire) != 0
        || sys::thread_info(&threads::probe_owner()).unwrap().state != ThreadState::Receiving
    {
        return failed(162);
    }
    set(10_020);
    if !finished(&done, &waiter, ETIMEDOUT as usize + 1) || !join(id, ETIMEDOUT as usize + 1) {
        return failed(163);
    }
    release();

    // Hold the actual owner outside its channel while time briefly crosses the
    // deadline and returns. Interrupt the consuming observation after it commits;
    // its retained interval peak must survive the rejected reply as well.
    set(10_000);
    held();
    let args = Args {
        clock: CLOCK_REALTIME,
        deadline: Timespec {
            tv_sec: 10_010,
            tv_nsec: 0,
        },
        pending: false,
        low: false,
        epoch: 7,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(176);
    }
    threads::probe_pause_owner(&gate);
    let owner = threads::probe_owner();
    for _ in 0..20 {
        if threads::probe_owner_parked()
            && sys::thread_info(&owner).unwrap().state == ThreadState::Receiving
        {
            break;
        }
        if !matches!(
            waiter.receive_until(&done, now() + 1_000_000),
            Ok(Waited::Expired)
        ) {
            return failed(177);
        }
    }
    if !threads::probe_owner_parked()
        || sys::thread_info(&owner).unwrap().state != ThreadState::Receiving
    {
        return failed(178);
    }
    clock::probe_interrupt(&owner, proto_clock::Method::Observe).unwrap();
    set(10_020);
    set(10_000);
    if !threads::probe_owner_parked() {
        return failed(179);
    }
    sys::notify(&gate, 1).unwrap();
    if !finished(&done, &waiter, ETIMEDOUT as usize + 1) || !join(id, ETIMEDOUT as usize + 1) {
        return failed(180);
    }
    release();
    // Pause between accepting the replacement IPC token and updating the wait.
    // A retry remains the same active deadline across a brief clock crossing.
    set(10_000);
    held();
    let args = Args {
        clock: CLOCK_REALTIME,
        deadline: Timespec {
            tv_sec: 10_010,
            tv_nsec: 0,
        },
        pending: false,
        low: false,
        epoch: 12,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(189);
    }
    let native = unsafe { threads::probe_native(id) }.unwrap();
    mutex::probe_gate_retry(&gate, id);
    sys::thread_interrupt(&native).unwrap();
    for _ in 0..20 {
        if threads::probe_owner_parked()
            && sys::thread_info(&owner).unwrap().state == ThreadState::Receiving
        {
            break;
        }
        if !matches!(
            waiter.receive_until(&done, now() + 1_000_000),
            Ok(Waited::Expired)
        ) {
            return failed(190);
        }
    }
    if !threads::probe_owner_parked()
        || sys::thread_info(&owner).unwrap().state != ThreadState::Receiving
    {
        return failed(190);
    }
    set(10_020);
    set(10_000);
    sys::notify(&gate, 1).unwrap();
    if !finished(&done, &waiter, ETIMEDOUT as usize + 1) || !join(id, ETIMEDOUT as usize + 1) {
        return failed(191);
    }
    release();

    // The old interval peak must not expire a later registered wait.
    held();
    let args = Args {
        clock: CLOCK_REALTIME,
        deadline: Timespec {
            tv_sec: 10_010,
            tv_nsec: 0,
        },
        pending: false,
        low: false,
        epoch: 8,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(181);
    }
    release();
    if !finished(&done, &waiter, 1) || !join(id, 1) {
        return failed(182);
    }

    // A deadline near time_t::MAX still expires when current calendar time
    // advances beyond time_t; the observer's wide peak carries this crossing.
    set(10_000);
    held();
    let args = Args {
        clock: CLOCK_REALTIME,
        deadline: Timespec {
            tv_sec: i64::MAX,
            tv_nsec: 999_999_999,
        },
        pending: false,
        low: false,
        epoch: 11,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(187);
    }
    let maximum = Timespec {
        tv_sec: i64::MAX,
        tv_nsec: 999_999_999,
    };
    assert_eq!(unsafe { clock::clock_settime(CLOCK_REALTIME, &maximum) }, 0);
    if !finished(&done, &waiter, ETIMEDOUT as usize + 1) || !join(id, ETIMEDOUT as usize + 1) {
        return failed(188);
    }
    release();

    // Backwards step invalidates the old monotonic timer deadline.
    set(10_000);
    held();
    let original = now() + 200_000_000;
    let args = Args {
        clock: CLOCK_REALTIME,
        deadline: Timespec {
            tv_sec: 10_000,
            tv_nsec: 200_000_000,
        },
        pending: false,
        low: false,
        epoch: 3,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(164);
    }
    set(9_990);
    if !matches!(
        waiter.receive_until(&done, original + 20_000_000),
        Ok(Waited::Expired)
    ) || DONE.load(Ordering::Acquire) != 0
        || !blocked(id)
    {
        return failed(165);
    }
    set(10_001);
    if !finished(&done, &waiter, ETIMEDOUT as usize + 1) || !join(id, ETIMEDOUT as usize + 1) {
        return failed(166);
    }
    release();

    // Calendar steps cannot expire a monotonic wait, and deferred cancellation
    // remains pending until the timeout has returned with unchanged errno.
    held();
    let deadline = now() + 200_000_000;
    let args = Args {
        clock: CLOCK_MONOTONIC,
        deadline: mono(deadline),
        pending: true,
        low: false,
        epoch: 4,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(167);
    }
    set(20_000);
    if !matches!(
        waiter.receive_until(&done, deadline - 100_000_000),
        Ok(Waited::Expired)
    ) || DONE.load(Ordering::Acquire) != 0
        || !blocked(id)
    {
        return failed(168);
    }
    if !finished(&done, &waiter, ETIMEDOUT as usize + 1)
        || now() < deadline
        || !join(id, usize::MAX)
    {
        return failed(169);
    }
    release();

    // Granted ownership survives an interrupted reply, even when REALTIME then
    // moves past the saved deadline before this lower-priority child retries.
    set(10_000);
    held();
    let args = Args {
        clock: CLOCK_REALTIME,
        deadline: Timespec {
            tv_sec: 10_010,
            tv_nsec: 0,
        },
        pending: false,
        low: true,
        epoch: 5,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(170);
    }
    mutex::probe_interrupt_timed_reply();
    release();
    set(10_020);
    if !finished(&done, &waiter, 1) || !join(id, 1) {
        return failed(171);
    }
    assert_eq!(unsafe { pthread_mutex_lock(lock()) }, 0);
    if unsafe { *PAYLOAD.0.get() } != 556 {
        return failed(172);
    }
    release();

    // A valid deadline beyond u64 nanoseconds waits until normal unlock.
    held();
    let args = Args {
        clock: CLOCK_MONOTONIC,
        deadline: Timespec {
            tv_sec: i64::MAX,
            tv_nsec: 0,
        },
        pending: false,
        low: false,
        epoch: 6,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(173);
    }
    release();
    if !finished(&done, &waiter, 1) || !join(id, 1) {
        return failed(174);
    }
    assert_eq!(unsafe { clock::clock_settime(CLOCK_REALTIME, &saved) }, 0);
    if sys::process_handles(&process).unwrap().live != before_handles
        || sys::process_memory(&process).unwrap().used != before_used
    {
        return failed(175);
    }
    rt::println!(
        "posix-timed-mutex-probe: deadlines, both calendar steps, live/reply interruption, pending and quota ok"
    );
    true
}
