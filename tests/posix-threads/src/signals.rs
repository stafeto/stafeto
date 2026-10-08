// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real process dispositions, thread masks, native nesting and IPC wakeups.
use super::*;
use crate::layer::signals::{self as api, SigAction, SigSet};
use core::sync::atomic::AtomicBool;
use rt::wait::{Waited, Waiter};
static MODE: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static DEPTH: AtomicUsize = AtomicUsize::new(0);
static MAX_DEPTH: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static ID: AtomicU64 = AtomicU64::new(0);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static GATE: AtomicU64 = AtomicU64::new(0);
static HALT: AtomicUsize = AtomicUsize::new(0);
fn bit(signal: i32) -> SigSet {
    1 << (signal - 1)
}
fn mask() -> SigSet {
    let mut mask = 0;
    assert_eq!(
        unsafe { api::pthread_sigmask(-99, ptr::null(), &mut mask) },
        0
    );
    mask
}
fn pending() -> SigSet {
    let mut pending = 0;
    assert_eq!(unsafe { api::sigpending(&mut pending) }, 0);
    pending
}
fn channel(raw: &AtomicU64) -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(raw.load(Ordering::Acquire)))
}
fn action(flags: i32) -> SigAction {
    SigAction {
        handler: handler as *const () as u64,
        mask: bit(SIGUSR2),
        flags,
    }
}
unsafe extern "C" fn handler(signal: i32) {
    let count = COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    let depth = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    MAX_DEPTH.fetch_max(depth, Ordering::SeqCst);
    let mode = MODE.load(Ordering::Acquire);
    let effective = mask();
    let own_blocked = mode != 2;
    if signal != SIGUSR1
        || abi::process::getpid() <= 1
        || abi::process::getppid() != 1
        || ffi::pthread_self() != ID.load(Ordering::Acquire)
        || (effective & bit(SIGUSR1) != 0) != own_blocked
        || effective & bit(SIGUSR2) == 0
    {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    if (mode == 1 || mode == 2)
        && count == 1
        && (api::raise(SIGUSR1) != 0
            || COUNT.load(Ordering::Acquire) != if mode == 2 { 2 } else { 1 })
    {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    if mode == 6 {
        let mut old = posix_signals::INITIAL;
        if unsafe { api::sigaction(SIGUSR1, ptr::null(), &mut old) } != 0
            || old.handler != api::DEFAULT
        {
            ERRORS.fetch_add(1, Ordering::Release);
        }
    }
    if mode == 9
        && count == 1
        && (unsafe { api::pthread_sigmask(SIG_SETMASK, &bit(SIGTERM), ptr::null_mut()) } != 0
            || api::raise(SIGUSR1) != 0
            || COUNT.load(Ordering::Acquire) != 2
            || mask() != bit(SIGTERM))
    {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    if mode == 8 {
        // The errno-only scope preserves identity without providing file context.
        unsafe { *ffi::__errno_location() = 901 };
        DEPTH.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    // Required signal-safe file calls use the independent process file owner.
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
    DEPTH.fetch_sub(1, Ordering::SeqCst);
}
unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    ID.store(ffi::pthread_self(), Ordering::Release);
    let mode = MODE.load(Ordering::Acquire);
    let errno = unsafe { ffi::__errno_location() };
    unsafe { *errno = 777 };
    let mut passed = true;
    if mode <= 2 || mode == 6 {
        passed &= mask() == 0;
        let mut old = posix_signals::INITIAL;
        passed &= unsafe {
            api::sigaction(
                SIGUSR1,
                &action(if mode == 2 {
                    SA_NODEFER
                } else if mode == 6 {
                    SA_RESETHAND
                } else {
                    0
                }),
                &mut old,
            )
        } == 0;
        passed &= api::raise(SIGUSR1) == 0;
        passed &= COUNT.load(Ordering::Acquire) == if mode == 1 || mode == 2 { 2 } else { 1 };
        passed &= MAX_DEPTH.load(Ordering::Acquire) == if mode == 2 { 2 } else { 1 };
        passed &= mask() == 0 && pending() == 0 && unsafe { *errno } == 777;
        passed &= ffi::pthread_kill(ffi::pthread_self(), 0) == 0;
    } else if mode == 8 {
        // A nested scope of the layer keeps the thread's block.
        passed &= abi::tls::with_process(|| {
            api::raise(SIGUSR1) == 0
                && COUNT.load(Ordering::Acquire) == 1
                && ffi::pthread_self() == ID.load(Ordering::Acquire)
        });
        passed &= unsafe { *errno } == 777;
    } else if mode == 9 {
        passed &= api::raise(SIGUSR1) == 0
            && COUNT.load(Ordering::Acquire) == 2
            && MAX_DEPTH.load(Ordering::Acquire) == 2
            && mask() == 0
            && unsafe { *errno } == 777;
    } else if mode == 3 || mode == 4 {
        let native = unsafe { threads::probe_native(ffi::pthread_self()) }.unwrap();
        NATIVE.store(native.raw().0, Ordering::Release);
        // Through the layer, which keeps the level the holders of its locks
        // come back to.
        threads::set_level(10).unwrap();
        let drain = sys::channel_create(10).unwrap();
        assert_eq!(sys::try_receive(&drain), Err(rt::abi::Error::WouldBlock));
        drop(drain);
        sys::notify(&channel(&READY), 1).unwrap();
        if mode == 3 {
            while HALT.load(Ordering::Acquire) == 0 {
                core::hint::spin_loop();
            }
        } else {
            passed &= sys::receive(&channel(&GATE)) == Err(rt::abi::Error::Interrupted);
        }
        passed &= COUNT.load(Ordering::Acquire) == 1 && unsafe { *errno } == 777;
    } else if mode == 5 || mode == 7 {
        passed &= mask() == bit(SIGUSR1) && pending() == 0;
        passed &= api::raise(SIGUSR1) == 0
            && pending() == bit(SIGUSR1)
            && COUNT.load(Ordering::Acquire) == 0;
        if mode == 5 {
            passed &=
                unsafe { api::pthread_sigmask(SIG_UNBLOCK, &bit(SIGUSR1), ptr::null_mut()) } == 0;
            passed &= COUNT.load(Ordering::Acquire) == 1 && pending() == 0 && mask() == 0;
        } else {
            sys::notify(&channel(&READY), 1).unwrap();
            passed &= sys::receive(&channel(&GATE)).is_ok();
            passed &= pending() == 0 && COUNT.load(Ordering::Acquire) == 0;
        }
        passed &= unsafe { *errno } == 777;
    }
    passed &= ERRORS.load(Ordering::Acquire) == 0 && DEPTH.load(Ordering::Acquire) == 0;
    sys::notify(&channel(&DONE), 1).unwrap();
    usize::from(passed) as *mut c_void
}
pub(super) fn run() -> bool {
    let ready = sys::channel_create(30).unwrap();
    let done = sys::channel_create(30).unwrap();
    let gate = sys::channel_create(10).unwrap();
    let ready_waiter = Waiter::new(&ready, 0, 30).unwrap();
    let done_waiter = Waiter::new(&done, 0, 30).unwrap();
    READY.store(ready.raw().0, Ordering::Release);
    DONE.store(done.raw().0, Ordering::Release);
    GATE.store(gate.raw().0, Ordering::Release);
    let now = || rt::time::ticks_to_ns(rt::time::now());
    let mut original = posix_signals::INITIAL;
    if unsafe { api::sigaction(SIGUSR1, &action(0), &mut original) } != 0 {
        return failed(370);
    }
    for mode in 0..10 {
        MODE.store(mode, Ordering::Release);
        COUNT.store(0, Ordering::Release);
        DEPTH.store(0, Ordering::Release);
        MAX_DEPTH.store(0, Ordering::Release);
        ERRORS.store(0, Ordering::Release);
        HALT.store(0, Ordering::Release);
        if unsafe { api::sigaction(SIGUSR1, &action(0), ptr::null_mut()) } != 0 {
            return failed(371);
        }
        if mode == 5 || mode == 7 {
            if unsafe { api::pthread_sigmask(SIG_BLOCK, &bit(SIGUSR1), ptr::null_mut()) } != 0
                || api::raise(SIGUSR1) != 0
            {
                return failed(372);
            }
            // The child inherits this mask, but not this parent's pending signal.
            if pending() != bit(SIGUSR1) {
                return failed(373);
            }
        }
        let mut id = 0;
        let mut result = ptr::null_mut();
        if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(worker), ptr::null_mut()) } != 0
        {
            return failed(374);
        }
        if mode == 3 {
            rt::println!("signal-action-probe: testing CPU delivery");
        }
        if mode == 3 || mode == 4 || mode == 7 {
            if !matches!(
                {
                    let deadline = now() + 500_000_000;
                    crate::watchdog::receive(deadline, rt::abi::Error::Interrupted, |deadline| {
                        ready_waiter.receive_until(&ready, deadline)
                    })
                },
                Ok(Waited::Got(_))
            ) {
                return failed(375);
            }
            if !matches!(
                {
                    let deadline = now() + 20_000_000;
                    crate::watchdog::receive(deadline, rt::abi::Error::Interrupted, |deadline| {
                        ready_waiter.receive_until(&ready, deadline)
                    })
                },
                Ok(Waited::Expired)
            ) {
                return failed(376);
            }
            if mode == 7 {
                let ignore = SigAction {
                    handler: api::IGNORE,
                    ..posix_signals::INITIAL
                };
                if unsafe { api::sigaction(SIGUSR1, &ignore, ptr::null_mut()) } != 0
                    || pending() != 0
                    || ffi::pthread_kill(id, SIGUSR1) != 0
                {
                    return failed(377);
                }
                sys::notify(&gate, 1).unwrap();
            } else {
                if mode == 4
                    && sys::thread_info(&Handle::<Thread>::borrowed(rt::abi::Handle(
                        NATIVE.load(Ordering::Acquire),
                    )))
                    .unwrap()
                    .state
                        != ThreadState::Receiving
                {
                    return failed(378);
                }
                if ffi::pthread_kill(id, SIGUSR1) != 0 {
                    return failed(379);
                }
                if mode == 3 {
                    if !matches!(
                        {
                            let deadline = now() + 20_000_000;
                            crate::watchdog::receive(
                                deadline,
                                rt::abi::Error::Interrupted,
                                |deadline| ready_waiter.receive_until(&ready, deadline),
                            )
                        },
                        Ok(Waited::Expired)
                    ) {
                        return failed(380);
                    }
                    if COUNT.load(Ordering::Acquire) != 1 {
                        return failed(381);
                    }
                    HALT.store(1, Ordering::Release);
                }
            }
        }
        if !matches!(
            {
                let deadline = now() + 500_000_000;
                crate::watchdog::receive(deadline, rt::abi::Error::Interrupted, |deadline| {
                    done_waiter.receive_until(&done, deadline)
                })
            },
            Ok(Waited::Got(_))
        ) {
            return failed(382);
        }
        if unsafe { ffi::pthread_join(id, &mut result) } != 0 || result as usize != 1 {
            return failed(383 + mode);
        }
        if ffi::pthread_kill(ffi::pthread_self(), 65) != EINVAL {
            return failed(392);
        }
        if mode == 5 || mode == 7 {
            let ignore = SigAction {
                handler: api::IGNORE,
                ..posix_signals::INITIAL
            };
            if unsafe { api::sigaction(SIGUSR1, &ignore, ptr::null_mut()) } != 0
                || pending() != 0
                || unsafe { api::pthread_sigmask(SIG_SETMASK, &0, ptr::null_mut()) } != 0
            {
                return failed(393);
            }
        }
    }
    if !under_pressure() {
        return false;
    }
    if unsafe { api::sigaction(SIGUSR1, &original, ptr::null_mut()) } != 0 {
        return failed(394);
    }
    rt::println!(
        "signal-action-probe: C handlers, self/CPU/IPC delivery, mask inheritance, pending/ignore, nesting, reset and retained replies ok"
    );
    true
}

static PRESSURE_RESULT: AtomicUsize = AtomicUsize::new(0);
static PRESSURE_WAIT: AtomicBool = AtomicBool::new(false);
unsafe extern "C" fn pressure_info_handler(
    signal: i32,
    info: *mut api::LinuxSigInfo,
    raw: *mut c_void,
) {
    // SAFETY: SA_SIGINFO supplies live per-delivery snapshots.
    let (info, context) = unsafe { (&*info, &*raw.cast::<api::LinuxContext>()) };
    if *info != api::LinuxSigInfo::thread(signal)
        || context.mask != 0
        || context.sp == 0
        || context.pc == 0
    {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    unsafe { handler(signal) };
}
unsafe extern "C" fn pressure(_: *mut c_void) -> *mut c_void {
    sys::receive(&channel(&GATE)).unwrap();
    ID.store(ffi::pthread_self(), Ordering::Release);
    let errno = unsafe { ffi::__errno_location() };
    unsafe { *errno = 777 };
    let mut old = posix_signals::INITIAL;
    let info_action = SigAction {
        handler: pressure_info_handler as *const () as u64,
        ..action(SA_SIGINFO)
    };
    let mut passed = unsafe { api::sigaction(SIGUSR1, &info_action, &mut old) } == 0;
    passed &= unsafe { api::pthread_sigmask(SIG_BLOCK, &bit(SIGUSR1), ptr::null_mut()) } == 0;
    passed &= api::raise(SIGUSR1) == 0 && api::raise(SIGUSR1) == 0;
    passed &= pending() == bit(SIGUSR1) && COUNT.load(Ordering::Acquire) == 0;
    passed &= unsafe { api::pthread_sigmask(SIG_UNBLOCK, &bit(SIGUSR1), ptr::null_mut()) } == 0;
    passed &= COUNT.load(Ordering::Acquire) == 1
        && mask() == 0
        && pending() == 0
        && ERRORS.load(Ordering::Acquire) == 0
        && unsafe { *errno } == 777;
    passed &= unsafe { api::pthread_sigmask(SIG_BLOCK, &bit(SIGUSR1), ptr::null_mut()) } == 0;
    passed &= api::raise(SIGUSR1) == 0 && api::raise(SIGUSR1) == 0;
    let mut info = api::SigInfo::thread(777);
    passed &= unsafe { api::sigwaitinfo(&bit(SIGUSR1), &mut info) } == SIGUSR1
        && info == api::SigInfo::thread(SIGUSR1)
        && pending() == 0
        && mask() == bit(SIGUSR1);
    PRESSURE_WAIT.store(true, Ordering::Release);
    info = api::SigInfo::thread(777);
    let timeout = abi::metadata::Timespec {
        tv_sec: 3,
        tv_nsec: 0,
    };
    passed &= unsafe { api::sigtimedwait(&bit(SIGUSR1), &mut info, &timeout) } == SIGUSR1
        && info == api::SigInfo::thread(SIGUSR1)
        && pending() == 0
        && mask() == bit(SIGUSR1)
        && COUNT.load(Ordering::Acquire) == 1
        && unsafe { *errno } == 777;
    info = api::SigInfo::thread(777);
    let timeout = abi::metadata::Timespec {
        tv_sec: 0,
        tv_nsec: 2_000_000,
    };
    passed &= unsafe { api::sigtimedwait(&bit(SIGUSR1), &mut info, &timeout) } == -1
        && unsafe { *errno } == EAGAIN
        && info == api::SigInfo::thread(777)
        && mask() == bit(SIGUSR1);
    let zero = abi::metadata::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    passed &= unsafe { api::sigtimedwait(&bit(SIGUSR1), &mut info, &zero) } == -1
        && unsafe { *errno } == EAGAIN
        && info == api::SigInfo::thread(777);
    PRESSURE_RESULT.store(usize::from(passed), Ordering::Release);
    usize::from(passed) as *mut c_void
}
fn under_pressure() -> bool {
    MODE.store(10, Ordering::Release);
    COUNT.store(0, Ordering::Release);
    MAX_DEPTH.store(0, Ordering::Release);
    ERRORS.store(0, Ordering::Release);
    let gate = sys::channel_create(30).unwrap();
    let wake = sys::channel_create(30).unwrap();
    let timer = sys::timer_create(&wake, 30).unwrap();
    GATE.store(gate.raw().0, Ordering::Release);
    let mut id = 0;
    if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(pressure), ptr::null_mut()) } != 0 {
        return failed(395);
    }
    let native = unsafe { threads::probe_native(id) }.unwrap();
    let retained = sys::handle_duplicate(&native, rt::abi::Rights::MANAGE).unwrap();
    sys::notify(&gate, 1).unwrap();
    let deadline = sys::clock_now().unwrap() + 5_000_000_000;
    let mut delivered = false;
    while sys::thread_info(&retained).unwrap().state != ThreadState::Ended {
        if !delivered
            && PRESSURE_WAIT.load(Ordering::Acquire)
            && crate::layer::signals::probe_waiting(id) == Ok(true)
        {
            if ffi::pthread_kill(id, SIGUSR1) != 0 {
                return failed(398);
            }
            delivered = true;
        }
        let now = sys::clock_now().unwrap();
        if now >= deadline {
            return failed(396);
        }
        let poll_deadline = now + 1_000_000;
        sys::timer_set(&timer, poll_deadline).unwrap();
        crate::watchdog::receive(poll_deadline, rt::abi::Error::Interrupted, |_| {
            sys::receive(&wake)
        })
        .unwrap();
    }
    // Native Ended and the release/acquire publication precede all reclamation.
    let passed = delivered && PRESSURE_RESULT.load(Ordering::Acquire) == 1;
    let mut result = ptr::null_mut();
    if !passed || unsafe { ffi::pthread_join(id, &mut result) } != 0 || result as usize != 1 {
        return failed(397);
    }
    rt::println!(
        "signal-action-probe: actions, mask, coalesced SA_SIGINFO, signal-safe I/O, pending/live sigwaitinfo/sigtimedwait and timeout, and managed exit"
    );
    true
}
