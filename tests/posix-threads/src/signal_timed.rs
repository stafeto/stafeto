// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real monotonic timeouts, fixed retries, clock steps and a late SEND race.
use super::*;
use abi::clock::{self, CLOCK_REALTIME};
use abi::metadata::Timespec;
use abi::signals::{self as api, SigAction, SigInfo};
use rt::wait::{Waited, Waiter};
static DONE: AtomicU64 = AtomicU64::new(0);
static RESULT: AtomicUsize = AtomicUsize::new(0);
static SENT: AtomicUsize = AtomicUsize::new(0);
static SLEPT: AtomicUsize = AtomicUsize::new(0);
static MUTEX_DONE: AtomicUsize = AtomicUsize::new(0);
static MUTEX: threads::mutex::Mutex = threads::mutex::Mutex::new();
static HANDLED: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
#[derive(Clone, Copy)]
struct Args {
    mode: usize,
    timeout: Option<Timespec>,
}
const fn bit(signal: i32) -> u64 {
    1 << (signal - 1)
}
const BLOCKED: u64 = bit(SIGUSR1) | bit(SIGUSR2);
fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}
fn notify() {
    let done = Handle::<Channel>::borrowed(rt::abi::Handle(DONE.load(Ordering::Acquire)));
    sys::notify(&done, 1).unwrap();
}
fn sentinel() -> SigInfo {
    SigInfo {
        si_code: -999,
        si_errno: -42,
        si_pid: 123,
        si_uid: u32::MAX,
        si_status: -1,
        si_addr: 0x8765_4321_fedc_ba98,
        si_value: u64::MAX,
        ..SigInfo::thread(777)
    }
}
unsafe extern "C" fn handler(signal: i32) {
    let fd = unsafe { abi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
    let mut byte = 0;
    if signal != SIGTERM
        || fd < 0
        || unsafe { abi::read(fd, &mut byte, 1) } != 1
        || byte != b's'
        || unsafe { abi::close(fd) } != 0
    {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    unsafe { *abi::__errno_location() = 901 };
    HANDLED.fetch_add(1, Ordering::Release);
    notify();
}
unsafe extern "C" fn worker(raw: *mut c_void) -> *mut c_void {
    // SAFETY: parent retains this immutable argument until join; copy immediately.
    let args = unsafe { *raw.cast::<Args>() };
    if args.mode == 8 {
        threads::probe_interrupt_signal_reply(46);
    }
    unsafe { *abi::__errno_location() = 777 };
    if args.mode == 6 {
        assert_eq!(api::raise(SIGUSR2), 0);
    }
    if args.mode == 0 {
        // Both the committed timeout and ACK are interrupted before receipt.
        threads::probe_interrupt_signal_reply(46);
        threads::probe_ack_interrupt();
    }
    let set = if args.mode == 6 { 0 } else { bit(SIGUSR1) };
    let mut info = sentinel();
    let start = now();
    let timeout = args.timeout.as_ref().map_or(ptr::null(), ptr::from_ref);
    let status = unsafe { api::sigtimedwait(&set, &mut info, timeout) };
    let elapsed = now() - start;
    let mut passed = if (3..=5).contains(&args.mode) {
        status == SIGUSR1
            && info == SigInfo::thread(SIGUSR1)
            && unsafe { *abi::__errno_location() } == 777
    } else {
        status == -1
            && unsafe { *abi::__errno_location() } == EAGAIN
            && info == sentinel()
            && elapsed >= args.timeout.unwrap().tv_nsec as u64
    };
    let mut mask = 0;
    let mut pending = 0;
    passed &= unsafe { api::pthread_sigmask(-99, ptr::null(), &mut mask) } == 0
        && mask == BLOCKED
        && api::probe_waiting(threads::pthread_self()) == Ok(false)
        && unsafe { api::sigpending(&mut pending) } == 0
        && pending
            == if args.mode == 6 {
                bit(SIGUSR2)
            } else if args.mode == 7 || args.mode == 8 {
                bit(SIGUSR1)
            } else {
                0
            };
    if args.mode == 7 || args.mode == 8 {
        // The late signal stays pending after timeout and is accepted by a new poll.
        let zero = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        passed &= unsafe { api::sigtimedwait(&set, &mut info, &zero) } == SIGUSR1
            && info == SigInfo::thread(SIGUSR1)
            && unsafe { *abi::__errno_location() } == EAGAIN;
    }
    RESULT.store(if passed { 1 } else { 2 }, Ordering::Release);
    notify();
    usize::from(passed) as *mut c_void
}
unsafe extern "C" fn sleeper(_: *mut c_void) -> *mut c_void {
    let duration = Timespec {
        tv_sec: 0,
        tv_nsec: 5_000_000,
    };
    let status = unsafe { threads::sleep::nanosleep(&duration, ptr::null_mut()) };
    SLEPT.store(if status == 0 { 1 } else { 2 }, Ordering::Release);
    notify();
    usize::from(status == 0) as *mut c_void
}
unsafe extern "C" fn mutex_waiter(_: *mut c_void) -> *mut c_void {
    let end = now() + 10_000_000;
    let deadline = Timespec {
        tv_sec: (end / 1_000_000_000) as i64,
        tv_nsec: (end % 1_000_000_000) as i64,
    };
    let status = unsafe {
        threads::mutex::pthread_mutex_clocklock(
            ptr::addr_of!(MUTEX).cast_mut(),
            clock::CLOCK_MONOTONIC,
            &deadline,
        )
    };
    MUTEX_DONE.store(if status == ETIMEDOUT { 1 } else { 2 }, Ordering::Release);
    notify();
    usize::from(status == ETIMEDOUT) as *mut c_void
}
unsafe extern "C" fn sender(raw: *mut c_void) -> *mut c_void {
    let passed = api::pthread_kill(raw as u64, SIGUSR1) == 0;
    SENT.store(if passed { 1 } else { 2 }, Ordering::Release);
    notify();
    usize::from(passed) as *mut c_void
}
fn create(callback: unsafe extern "C" fn(*mut c_void) -> *mut c_void, raw: *mut c_void) -> u64 {
    let mut id = 0;
    assert_eq!(
        unsafe { threads::pthread_create(&mut id, ptr::null(), Some(callback), raw) },
        0
    );
    id
}
fn join(id: u64) -> bool {
    let mut value = ptr::null_mut();
    (unsafe { threads::pthread_join(id, &mut value) }) == 0 && value as usize == 1
}
fn blocked(id: u64) -> bool {
    let native = unsafe { threads::probe_native(id) }.unwrap();
    waiting_registered(&native, || api::probe_waiting(id) == Ok(true))
}
fn wait_flag(done: &Handle<Channel>, waiter: &Waiter, flag: &AtomicUsize) -> bool {
    let limit = now() + 1_000_000_000;
    while flag.load(Ordering::Acquire) == 0 {
        if !matches!(waiter.receive_until(done, limit), Ok(Waited::Got(_))) {
            return false;
        }
    }
    flag.load(Ordering::Acquire) == 1
}
pub(super) fn run() -> bool {
    let done = sys::channel_create(30).unwrap();
    let gate = sys::channel_create(30).unwrap();
    let waiter = Waiter::new(&done, 0, 30).unwrap();
    DONE.store(done.raw().0, Ordering::Release);
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let handles = sys::process_handles(&process).unwrap().live;
    let memory = sys::process_memory(&process).unwrap().used;
    let mut inherited = 0;
    let mut old_action = posix_signals::INITIAL;
    let action = SigAction {
        handler: handler as *const () as u64,
        mask: 0,
        flags: 0,
    };
    let mut saved = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { api::pthread_sigmask(SIG_BLOCK, &BLOCKED, &mut inherited) } != 0
        || unsafe { api::sigaction(SIGTERM, &action, &mut old_action) } != 0
        || unsafe { clock::clock_gettime(CLOCK_REALTIME, &mut saved) } != 0
    {
        return failed(462);
    }
    let before_ack = threads::probe_ack_interrupts();
    for mode in 0..9 {
        RESULT.store(0, Ordering::Release);
        SENT.store(0, Ordering::Release);
        SLEPT.store(0, Ordering::Release);
        MUTEX_DONE.store(0, Ordering::Release);
        HANDLED.store(0, Ordering::Release);
        ERRORS.store(0, Ordering::Release);
        let timeout = match mode {
            0 => Some(Timespec {
                tv_sec: 0,
                tv_nsec: 20_000_000,
            }),
            1 | 2 => Some(Timespec {
                tv_sec: 0,
                tv_nsec: 150_000_000,
            }),
            3 => Some(Timespec {
                tv_sec: 2,
                tv_nsec: 0,
            }),
            4 => Some(Timespec {
                tv_sec: i64::MAX,
                tv_nsec: 999_999_999,
            }),
            5 => None,
            6 => Some(Timespec {
                tv_sec: 0,
                tv_nsec: 10_000_000,
            }),
            _ => Some(Timespec {
                tv_sec: 0,
                tv_nsec: 250_000_000,
            }),
        };
        let args = Args { mode, timeout };
        if mode == 8 {
            threads::probe_pause_signal_wait_retry(&gate);
        }
        let id = create(worker, ptr::from_ref(&args).cast_mut().cast());
        let mut helper = None;
        let mut mutex_helper = None;
        if mode == 0 {
            assert_eq!(
                unsafe { threads::mutex::pthread_mutex_lock(ptr::addr_of!(MUTEX).cast_mut()) },
                0
            );
            helper = Some(create(sleeper, ptr::null_mut()));
            mutex_helper = Some(create(mutex_waiter, ptr::null_mut()));
        } else if mode != 6 {
            if !blocked(id) {
                return failed(463);
            }
            let deadline = api::probe_wait_deadline(id).unwrap();
            if mode == 4 && !deadline.is_some_and(|value| value > i128::from(u64::MAX))
                || mode == 5 && deadline.is_some()
                || mode != 5 && deadline.is_none()
            {
                return failed(464);
            }
            if mode == 1 || mode == 2 {
                let native = unsafe { threads::probe_native(id) }.unwrap();
                for _ in 0..3 {
                    if sys::thread_interrupt(&native).is_err()
                        || !blocked(id)
                        || api::probe_wait_deadline(id).unwrap() != deadline
                    {
                        return failed(465);
                    }
                }
                if mode == 2 {
                    if api::pthread_kill(id, SIGTERM) != 0
                        || !wait_flag(&done, &waiter, &HANDLED)
                        || !blocked(id)
                        || HANDLED.load(Ordering::Acquire) != 1
                        || api::probe_wait_deadline(id).unwrap() != deadline
                    {
                        return failed(466);
                    }
                    // Neither direction of a calendar step changes the stored deadline.
                    for seconds in [10_000, 1] {
                        let value = Timespec {
                            tv_sec: seconds,
                            tv_nsec: 0,
                        };
                        if unsafe { clock::clock_settime(CLOCK_REALTIME, &value) } != 0
                            || api::probe_wait_deadline(id).unwrap() != deadline
                        {
                            return failed(486);
                        }
                    }
                }
            } else if (3..=5).contains(&mode) {
                if api::pthread_kill(id, SIGUSR1) != 0 {
                    return failed(476);
                }
            } else if mode == 8 {
                // A real rejected response is committed before the client parks.
                let native = unsafe { threads::probe_native(id) }.unwrap();
                let limit = now() + 500_000_000;
                while !threads::probe_signal_wait_retry_parked() && now() < limit {
                    if !matches!(
                        waiter.receive_until(&done, now() + 1_000_000),
                        Ok(Waited::Expired)
                    ) {
                        return failed(487);
                    }
                }
                if !threads::probe_signal_wait_retry_parked()
                    || sys::thread_info(&native).unwrap().state != ThreadState::Receiving
                    || RESULT.load(Ordering::Acquire) != 0
                    || api::probe_waiting(id) != Ok(false)
                    || api::pthread_kill(id, SIGUSR1) != 0
                {
                    return failed(487);
                }
                sys::notify(&gate, 1).unwrap();
            } else {
                // Hold SEND inside the real owner past the original deadline.
                threads::probe_pause_signal_send(&gate);
                helper = Some(create(sender, id as *mut c_void));
                let owner = threads::probe_owner();
                let limit = now() + 100_000_000;
                while !threads::probe_owner_parked() && now() < limit {
                    if !matches!(
                        waiter.receive_until(&done, now() + 1_000_000),
                        Ok(Waited::Expired)
                    ) {
                        return failed(477);
                    }
                }
                if !threads::probe_owner_parked()
                    || sys::thread_info(&owner).unwrap().state != ThreadState::Receiving
                    || !matches!(
                        waiter.receive_until(&done, deadline.unwrap() as u64 + 20_000_000),
                        Ok(Waited::Expired)
                    )
                {
                    return failed(478);
                }
                sys::notify(&gate, 1).unwrap();
            }
        }
        if !wait_flag(&done, &waiter, &RESULT) || !join(id) {
            return failed(467 + mode);
        }
        if let Some(helper) = helper {
            let flag = if mode == 0 { &SLEPT } else { &SENT };
            if !wait_flag(&done, &waiter, flag) || !join(helper) {
                return failed(479);
            }
        }
        if let Some(helper) = mutex_helper
            && (!wait_flag(&done, &waiter, &MUTEX_DONE)
                || !join(helper)
                || unsafe { threads::mutex::pthread_mutex_unlock(ptr::addr_of!(MUTEX).cast_mut()) }
                    != 0)
        {
            return failed(488);
        }
        if ERRORS.load(Ordering::Acquire) != 0 {
            return failed(480);
        }
        while sys::try_receive(&done).is_ok() {}
    }
    if threads::probe_ack_interrupts() != before_ack + 1
        || unsafe { clock::clock_settime(CLOCK_REALTIME, &saved) } != 0
        || unsafe { api::sigaction(SIGTERM, &old_action, ptr::null_mut()) } != 0
        || unsafe { api::pthread_sigmask(SIG_SETMASK, &inherited, ptr::null_mut()) } != 0
        || sys::process_handles(&process).unwrap().live != handles
        || sys::process_memory(&process).unwrap().used != memory
    {
        return failed(481);
    }
    rt::println!(
        "signal-timed-probe: monotonic timeout, fixed retries, clock steps, wide/null intervals, mixed waits and late SEND ok"
    );
    true
}
