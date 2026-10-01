// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Actual sleep deadlines, interruption, cancellation and shared observation.
use super::*;
use abi::clock::{self, CLOCK_MONOTONIC, CLOCK_REALTIME};
use abi::metadata::Timespec;
use rt::wait::{Waited, Waiter};
use threads::{
    cancel::{self, Cleanup},
    sleep::{self, TIMER_ABSTIME},
};

static DONE_CHANNEL: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);
static PUBLISHED: AtomicU64 = AtomicU64::new(0);
static REM_SEC: AtomicU64 = AtomicU64::new(0);
static REM_NS: AtomicU64 = AtomicU64::new(0);
static RETURNED: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicUsize = AtomicUsize::new(0);
struct Args {
    clock: i32,
    flags: i32,
    time: Timespec,
    mode: u8,
    epoch: u64,
}
fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}
fn time(ns: u64) -> Timespec {
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
fn notify() {
    let channel =
        Handle::<Channel>::borrowed(rt::abi::Handle(DONE_CHANNEL.load(Ordering::Acquire)));
    sys::notify(&channel, 1).unwrap();
}
unsafe extern "C" fn cleanup(argument: *mut c_void) {
    let remaining = unsafe { &*argument.cast::<Timespec>() };
    let remainder = MODE.load(Ordering::Acquire) != 2 || remaining.tv_sec < 30;
    let status = if remainder
        && remaining.tv_sec >= 0
        && remaining.tv_nsec >= 0
        && remaining.tv_nsec < 1_000_000_000
    {
        1000
    } else {
        999
    };
    DONE.store(status, Ordering::Release);
    notify();
}
unsafe extern "C" fn worker(argument: *mut c_void) -> *mut c_void {
    let epoch = PUBLISHED.load(Ordering::Acquire);
    let args = unsafe { &*argument.cast::<Args>() };
    assert_eq!(args.epoch, epoch);
    let mut remaining = Timespec {
        tv_sec: 777,
        tv_nsec: 888,
    };
    let mut node = Cleanup::new();
    if args.mode >= 2 {
        unsafe {
            cancel::__stafeto_cleanup_push(
                &mut node,
                Some(cleanup),
                ptr::from_mut(&mut remaining).cast(),
            )
        };
    }
    if args.mode == 3 {
        assert_eq!(threads::pthread_cancel(threads::pthread_self()), 0);
    }
    if args.mode == 4 {
        assert_eq!(
            unsafe { cancel::pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, ptr::null_mut()) },
            0
        );
        assert_eq!(threads::pthread_cancel(threads::pthread_self()), 0);
    }
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    let status = if args.mode == 1 {
        remaining = args.time;
        let alias = ptr::from_mut(&mut remaining);
        unsafe { sleep::nanosleep(alias.cast_const(), alias) }
    } else {
        unsafe { sleep::clock_nanosleep(args.clock, args.flags, &args.time, &mut remaining) }
    };
    let expected_errno = if args.mode == 1 && status == -1 {
        EINTR
    } else {
        777
    };
    REM_SEC.store(remaining.tv_sec as u64, Ordering::Relaxed);
    REM_NS.store(remaining.tv_nsec as u64, Ordering::Relaxed);
    let outcome = if unsafe { *errno } == expected_errno {
        (status + 2) as usize
    } else {
        999
    };
    RETURNED.store(outcome, Ordering::Release);
    DONE.store(outcome, Ordering::Release);
    notify();
    if args.mode == 4 {
        assert_eq!(
            unsafe { cancel::pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, ptr::null_mut()) },
            0
        );
        cancel::pthread_testcancel();
    }
    if args.mode >= 2 {
        unsafe { cancel::__stafeto_cleanup_pop(&mut node, 0) };
    }
    outcome as *mut c_void
}
fn child(args: &Args) -> u64 {
    DONE.store(0, Ordering::Release);
    RETURNED.store(0, Ordering::Release);
    PUBLISHED.store(args.epoch, Ordering::Release);
    MODE.store(args.mode as usize, Ordering::Release);
    let mut id = 0;
    assert_eq!(
        unsafe {
            threads::pthread_create(
                &mut id,
                ptr::null(),
                Some(worker),
                ptr::from_ref(args).cast_mut().cast(),
            )
        },
        0
    );
    id
}
/// Whether pthread `id` sleeps: in receive on its own channel.
fn blocked(id: u64) -> bool {
    let native = unsafe { threads::probe_native(id) }.unwrap();
    waiting(&native)
}
fn finished(channel: &Handle<Channel>, waiter: &Waiter, expected: usize) -> bool {
    let limit = now() + 500_000_000;
    loop {
        match waiter.receive_until(channel, limit) {
            Ok(Waited::Got(_)) if DONE.load(Ordering::Acquire) == expected => return true,
            Ok(Waited::Got(_)) if DONE.load(Ordering::Acquire) == 0 => {}
            _ => return false,
        }
    }
}
fn join(id: u64, expected: usize) -> bool {
    let mut value = ptr::null_mut();
    (unsafe { threads::pthread_join(id, &mut value) }) == 0 && value as usize == expected
}
fn sentinel() -> bool {
    REM_SEC.load(Ordering::Relaxed) == 777 && REM_NS.load(Ordering::Relaxed) == 888
}

pub(super) fn run() -> bool {
    let mut saved = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { clock::clock_gettime(CLOCK_REALTIME, &mut saved) },
        0
    );
    let channel = sys::channel_create(30).unwrap();
    let waiter = Waiter::new(&channel, 0, 30).unwrap();
    DONE_CHANNEL.store(channel.raw().0, Ordering::Release);
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let before_handles = sys::process_handles(&process).unwrap().live;
    let before_used = sys::process_memory(&process).unwrap().used;

    // Relative REALTIME remains a duration through both settings.
    set(10_000);
    let start = now();
    let args = Args {
        clock: CLOCK_REALTIME,
        flags: 0,
        time: time(300_000_000),
        mode: 0,
        epoch: 1,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(200);
    }
    set(20_000);
    set(1);
    if !matches!(
        waiter.receive_until(&channel, start + 100_000_000),
        Ok(Waited::Expired)
    ) || DONE.load(Ordering::Acquire) != 0
        || !blocked(id)
    {
        return failed(201);
    }
    if !finished(&channel, &waiter, 2) || now() < start + 300_000_000 || !join(id, 2) || !sentinel()
    {
        return failed(202);
    }

    // An actual interruption returns elapsed remainder, including rqtp/rmtp aliasing.
    let args = Args {
        clock: CLOCK_REALTIME,
        flags: 0,
        time: time(300_000_000),
        mode: 1,
        epoch: 2,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(203);
    }
    if !matches!(
        waiter.receive_until(&channel, now() + 20_000_000),
        Ok(Waited::Expired)
    ) {
        return failed(204);
    }
    let native = unsafe { threads::probe_native(id) }.unwrap();
    sys::thread_interrupt(&native).unwrap();
    if !finished(&channel, &waiter, 1)
        || !join(id, 1)
        || REM_SEC.load(Ordering::Relaxed) != 0
        || REM_NS.load(Ordering::Relaxed) == 0
        || REM_NS.load(Ordering::Relaxed) >= 300_000_000
    {
        return failed(205);
    }

    // clock_nanosleep returns EINTR without errno and does not touch absolute rmtp.
    let args = Args {
        clock: CLOCK_MONOTONIC,
        flags: TIMER_ABSTIME,
        time: time(now() + 300_000_000),
        mode: 0,
        epoch: 3,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(206);
    }
    let native = unsafe { threads::probe_native(id) }.unwrap();
    sys::thread_interrupt(&native).unwrap();
    if !finished(&channel, &waiter, EINTR as usize + 2)
        || !join(id, EINTR as usize + 2)
        || !sentinel()
    {
        return failed(207);
    }

    // Absolute MONOTONIC success uses the original counter deadline.
    let deadline = now() + 100_000_000;
    let args = Args {
        clock: CLOCK_MONOTONIC,
        flags: TIMER_ABSTIME,
        time: time(deadline),
        mode: 0,
        epoch: 10,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(226);
    }
    set(30_000);
    if !finished(&channel, &waiter, 2) || now() < deadline || !join(id, 2) || !sentinel() {
        return failed(227);
    }

    // Backward settings cannot let an old monotonic timer end calendar sleep.
    set(10_000);
    let original = now() + 150_000_000;
    let args = Args {
        clock: CLOCK_REALTIME,
        flags: TIMER_ABSTIME,
        time: Timespec {
            tv_sec: 10_000,
            tv_nsec: 150_000_000,
        },
        mode: 0,
        epoch: 5,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(211);
    }
    set(9_990);
    if !matches!(
        waiter.receive_until(&channel, original + 20_000_000),
        Ok(Waited::Expired)
    ) || DONE.load(Ordering::Acquire) != 0
        || !blocked(id)
    {
        return failed(212);
    }
    // A calendar set forward wakes no sleep before 5h (#146): an interrupt
    // ends this one.
    let native = unsafe { threads::probe_native(id) }.unwrap();
    sys::thread_interrupt(&native).unwrap();
    if !finished(&channel, &waiter, EINTR as usize + 2) || !join(id, EINTR as usize + 2) {
        return failed(213);
    }

    // Cancellation of a sleeping thread runs its cleanup.
    let args = Args {
        clock: CLOCK_MONOTONIC,
        flags: 0,
        time: Timespec {
            tv_sec: 30,
            tv_nsec: 0,
        },
        mode: 2,
        epoch: 7,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(219);
    }
    assert_eq!(threads::pthread_cancel(id), 0);
    if !finished(&channel, &waiter, 1000)
        || !join(id, usize::MAX)
        || RETURNED.load(Ordering::Acquire) != 0
    {
        return failed(220);
    }
    // A pending request is accepted even at a zero-duration cancellation point.
    let args = Args {
        clock: CLOCK_REALTIME,
        flags: 0,
        time: time(0),
        mode: 3,
        epoch: 8,
    };
    let id = child(&args);
    if !finished(&channel, &waiter, 1000)
        || !join(id, usize::MAX)
        || RETURNED.load(Ordering::Acquire) != 0
    {
        return failed(221);
    }
    // Disabled cancellation preserves duration and success, then runs at testcancel.
    let start = now();
    let args = Args {
        clock: CLOCK_MONOTONIC,
        flags: 0,
        time: time(100_000_000),
        mode: 4,
        epoch: 9,
    };
    let id = child(&args);
    if !blocked(id) {
        return failed(222);
    }
    let limit = now() + 500_000_000;
    while DONE.load(Ordering::Acquire) != 1000 {
        if !matches!(waiter.receive_until(&channel, limit), Ok(Waited::Got(_))) {
            return failed(223);
        }
    }
    if !join(id, usize::MAX)
        || now() < start + 100_000_000
        || RETURNED.load(Ordering::Acquire) != 2
        || !sentinel()
    {
        return failed(224);
    }
    assert_eq!(unsafe { clock::clock_settime(CLOCK_REALTIME, &saved) }, 0);
    if sys::process_handles(&process).unwrap().live != before_handles
        || sys::process_memory(&process).unwrap().used != before_used
    {
        return failed(225);
    }
    rt::println!(
        "posix-sleep-probe: relative/absolute clocks, EINTR remainder, a calendar stepped back and cancellation ok"
    );
    true
}
