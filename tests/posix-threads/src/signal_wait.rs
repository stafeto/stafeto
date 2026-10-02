// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Pending/live acceptance, thread targeting, retry and cancellation cleanup.
use super::*;
use crate::layer::signals::{self as api, SigAction, SigInfo};
use core::sync::atomic::AtomicBool;
use ffi::Cleanup;
use rt::wait::{Waited, Waiter};
static INFO: AtomicBool = AtomicBool::new(false);
static TIMED: AtomicBool = AtomicBool::new(false);
static MODE: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static RETURNED: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];
static CLEANED: AtomicUsize = AtomicUsize::new(0);
static HANDLED: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
const fn bit(signal: i32) -> u64 {
    1 << (signal - 1)
}
const BLOCKED: u64 = bit(SIGUSR1) | bit(SIGUSR2);
fn mask() -> u64 {
    let mut set = 0;
    assert_eq!(
        unsafe { api::pthread_sigmask(-1, ptr::null(), &mut set) },
        0
    );
    set
}
fn pending() -> u64 {
    let mut set = 0;
    assert_eq!(unsafe { api::sigpending(&mut set) }, 0);
    set
}
fn notify() {
    let done = Handle::<Channel>::borrowed(rt::abi::Handle(DONE.load(Ordering::Acquire)));
    sys::notify(&done, 1).unwrap();
}
unsafe extern "C" fn handler(signal: i32) {
    if signal != SIGTERM {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    HANDLED.fetch_add(1, Ordering::AcqRel);
    let fd = unsafe { ffi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
    let mut byte = 0;
    if fd < 0
        || unsafe { ffi::read(fd, &mut byte, 1) } != 1
        || byte != b's'
        || unsafe { ffi::close(fd) } != 0
    {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    unsafe { *ffi::__errno_location() = 901 };
}
struct Output {
    signal: i32,
    info: SigInfo,
}
fn sentinel() -> SigInfo {
    SigInfo {
        si_code: -999,
        si_value: u64::MAX,
        ..SigInfo::thread(777)
    }
}
unsafe extern "C" fn cleanup(argument: *mut c_void) {
    let output = unsafe { &*argument.cast::<Output>() };
    let signal = output.signal;
    let mode = MODE.load(Ordering::Acquire);
    if api::probe_waiting(ffi::pthread_self()) != Ok(false)
        || mask() != BLOCKED
        || unsafe { *ffi::__errno_location() } != 777
        || signal != if mode == 5 { SIGUSR1 } else { 777 }
        || (INFO.load(Ordering::Acquire)
            && output.info
                != if mode == 5 {
                    SigInfo::thread(SIGUSR1)
                } else {
                    sentinel()
                })
    {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    CLEANED.fetch_add(1, Ordering::Release);
    notify();
}
unsafe extern "C" fn worker(argument: *mut c_void) -> *mut c_void {
    let index = argument as usize;
    let mode = MODE.load(Ordering::Acquire);
    let errno = unsafe { ffi::__errno_location() };
    unsafe { *errno = 777 };
    if mask() != BLOCKED || pending() != 0 {
        return ptr::null_mut();
    }
    let mut output = Output {
        signal: 777,
        info: sentinel(),
    };
    let mut node = Cleanup::new();
    unsafe { ffi::cleanup_push(&mut node, Some(cleanup), ptr::from_mut(&mut output).cast()) };
    if mode == 0 {
        assert_eq!(api::raise(SIGUSR1), 0);
        assert_eq!(api::raise(SIGUSR1), 0);
    }
    if mode == 4 || mode == 5 {
        if mode == 5 {
            assert_eq!(
                unsafe { ffi::pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, ptr::null_mut()) },
                0
            );
        }
        assert_eq!(ffi::pthread_cancel(ffi::pthread_self()), 0);
    }
    let set = if mode == 6 { 0 } else { bit(SIGUSR1) };
    let with_info = INFO.load(Ordering::Acquire);
    let status = if with_info {
        let signal = if TIMED.load(Ordering::Acquire) {
            let timeout = abi::metadata::Timespec {
                tv_sec: 3,
                tv_nsec: 0,
            };
            unsafe { api::sigtimedwait(&set, &mut output.info, &timeout) }
        } else {
            unsafe { api::sigwaitinfo(&set, &mut output.info) }
        };
        if signal >= 0 {
            output.signal = signal;
            0
        } else {
            signal
        }
    } else {
        unsafe { api::sigwait(&set, &mut output.signal) }
    };
    let mut action = posix_signals::INITIAL;
    let passed = status == 0
        && output.signal == SIGUSR1
        && (!with_info || output.info == SigInfo::thread(SIGUSR1))
        && mask() == BLOCKED
        && pending()
            == if mode == 1 && index == 1 {
                bit(SIGUSR2)
            } else {
                0
            }
        && unsafe { *errno } == 777
        && unsafe { api::sigaction(SIGUSR1, ptr::null(), &mut action) } == 0
        && action.handler == handler as *const () as u64
        && action.flags == SA_RESETHAND;
    if !passed {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    RETURNED[index].store(usize::from(passed), Ordering::Release);
    if mode == 5 {
        assert_eq!(
            unsafe { ffi::pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, ptr::null_mut()) },
            0
        );
        ffi::pthread_testcancel();
    }
    unsafe { ffi::cleanup_pop(&mut node, 0) };
    notify();
    usize::from(passed) as *mut c_void
}
fn blocked(id: u64) -> bool {
    let native = unsafe { threads::probe_native(id) }.unwrap();
    waiting_registered(&native, || api::probe_waiting(id) == Ok(true))
}
fn joined(id: u64, expected: usize) -> bool {
    let mut value = ptr::null_mut();
    (unsafe { ffi::pthread_join(id, &mut value) }) == 0 && value as usize == expected
}
pub(super) fn run() -> bool {
    let done = sys::channel_create(30).unwrap();
    let waiter = Waiter::new(&done, 0, 30).unwrap();
    DONE.store(done.raw().0, Ordering::Release);
    let mut previous = [posix_signals::INITIAL; 2];
    for (index, signal) in [SIGUSR1, SIGTERM].into_iter().enumerate() {
        let action = SigAction {
            handler: handler as *const () as u64,
            mask: 0,
            flags: if signal == SIGUSR1 { SA_RESETHAND } else { 0 },
        };
        if unsafe { api::sigaction(signal, &action, &mut previous[index]) } != 0 {
            return failed(420);
        }
    }
    let mut old_mask = 0;
    if unsafe { api::pthread_sigmask(SIG_BLOCK, &BLOCKED, &mut old_mask) } != 0 {
        return failed(421);
    }
    for (with_info, timed) in [(false, false), (true, false), (true, true)] {
        INFO.store(with_info, Ordering::Release);
        TIMED.store(timed, Ordering::Release);
        for mode in 0..7 {
            MODE.store(mode, Ordering::Release);
            CLEANED.store(0, Ordering::Release);
            HANDLED.store(0, Ordering::Release);
            ERRORS.store(0, Ordering::Release);
            for result in &RETURNED {
                result.store(0, Ordering::Release);
            }
            let count = if mode == 1 { 2 } else { 1 };
            let mut ids = [0; 2];
            for (index, id) in ids.iter_mut().enumerate().take(count) {
                if unsafe {
                    ffi::pthread_create(id, ptr::null(), Some(worker), index as *mut c_void)
                } != 0
                {
                    return failed(422);
                }
            }
            if mode != 0 && mode != 4 {
                for id in ids.iter().take(count) {
                    if !blocked(*id) {
                        return failed(423);
                    }
                }
                if mode == 6 {
                    if ffi::pthread_cancel(ids[0]) != 0 {
                        return failed(424);
                    }
                } else {
                    let native = unsafe { threads::probe_native(ids[0]) }.unwrap();
                    for _ in 0..3 {
                        if sys::thread_interrupt(&native).is_err() || !blocked(ids[0]) {
                            return failed(425);
                        }
                    }
                    if mode == 2
                        && (ffi::pthread_kill(ids[0], SIGTERM) != 0
                            || !blocked(ids[0])
                            || HANDLED.load(Ordering::Acquire) != 1)
                    {
                        return failed(426);
                    }
                    if count == 2 && ffi::pthread_kill(ids[1], SIGUSR2) != 0 {
                        return failed(427);
                    }
                    if ffi::pthread_kill(ids[0], SIGUSR1) != 0 {
                        return failed(428);
                    }
                }
            }
            let now = || rt::time::ticks_to_ns(rt::time::now());
            if !matches!(
                waiter.receive_until(&done, now() + 500_000_000),
                Ok(Waited::Got(_))
            ) {
                return failed(429);
            }
            if count == 2 {
                if RETURNED[1].load(Ordering::Acquire) != 0
                    || !blocked(ids[1])
                    || ffi::pthread_kill(ids[1], SIGUSR1) != 0
                {
                    return failed(430);
                }
                if !matches!(
                    waiter.receive_until(&done, now() + 500_000_000),
                    Ok(Waited::Got(_))
                ) {
                    return failed(431);
                }
            }
            for id in ids.iter().take(count) {
                if !joined(*id, if mode >= 4 { usize::MAX } else { 1 }) {
                    return failed(432 + mode);
                }
            }
            if ERRORS.load(Ordering::Acquire) != 0
                || CLEANED.load(Ordering::Acquire) != usize::from(mode >= 4)
                || (mode == 5 && RETURNED[0].load(Ordering::Acquire) != 1)
                || HANDLED.load(Ordering::Acquire) != usize::from(mode == 2)
            {
                return failed(440 + mode);
            }
        }
    }
    for (index, signal) in [SIGUSR1, SIGTERM].into_iter().enumerate() {
        if unsafe { api::sigaction(signal, &previous[index], ptr::null_mut()) } != 0 {
            return failed(447);
        }
    }
    if unsafe { api::pthread_sigmask(SIG_SETMASK, &old_mask, ptr::null_mut()) } != 0 {
        return failed(448);
    }
    rt::println!(
        "signal-wait-probe: sigwait/sigwaitinfo/sigtimedwait pending/live acceptance, targeting, handler/reply interruption, masks, dispositions, errno and cancellation cleanup ok"
    );
    true
}
