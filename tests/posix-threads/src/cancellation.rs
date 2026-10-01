// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Cancellation releases join claims before handlers and closes IPC-entry races.

use super::*;
use threads::cancel::{self, Cleanup};

static CANCEL_TARGET: AtomicU64 = AtomicU64::new(0);
static CLEANUP_READY: AtomicU64 = AtomicU64::new(0);
static CLEANUP_RELEASE: AtomicU64 = AtomicU64::new(0);
static CLEANUP_RESULT: AtomicUsize = AtomicUsize::new(0);
static RACE_GATE: AtomicU64 = AtomicU64::new(0);
static RACE_NATIVE: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn join_cleanup(_: *mut c_void) {
    let mut old = 99;
    if unsafe { cancel::pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &mut old) } != 0
        || old != PTHREAD_CANCEL_DISABLE
    {
        CLEANUP_RESULT.store(2, Ordering::Release);
        return;
    }
    cancel::pthread_testcancel();
    {
        let ready =
            Handle::<Channel>::borrowed(rt::abi::Handle(CLEANUP_READY.load(Ordering::Acquire)));
        let release =
            Handle::<Channel>::borrowed(rt::abi::Handle(CLEANUP_RELEASE.load(Ordering::Acquire)));
        sys::notify(&ready, 1).expect("cleanup ready");
        sys::receive(&release).expect("cleanup release");
    }
    CLEANUP_RESULT.store(1, Ordering::Release);
}
unsafe extern "C" fn cancelled_joiner(_: *mut c_void) -> *mut c_void {
    let mut cleanup = Cleanup::new();
    unsafe { cancel::__stafeto_cleanup_push(&mut cleanup, Some(join_cleanup), ptr::null_mut()) };
    let mut value = ptr::null_mut();
    let _ = unsafe { threads::pthread_join(CANCEL_TARGET.load(Ordering::Acquire), &mut value) };
    unsafe { cancel::__stafeto_cleanup_pop(&mut cleanup, 0) };
    CLEANUP_RESULT.store(3, Ordering::Release);
    value
}
unsafe extern "C" fn race_cleanup(_: *mut c_void) {
    CLEANUP_RESULT.store(1, Ordering::Release);
}
unsafe extern "C" fn before_wait(argument: *mut c_void) -> *mut c_void {
    let ready = Handle::<Channel>::borrowed(rt::abi::Handle(argument as u64));
    let gate = Handle::<Channel>::borrowed(rt::abi::Handle(RACE_GATE.load(Ordering::Acquire)));
    let native = unsafe { threads::probe_native(threads::pthread_self()) }.expect("self handle");
    RACE_NATIVE.store(native.raw().0, Ordering::Release);
    sys::thread_set_priority(&native, 10, rt::abi::Policy::Fifo).expect("race target priority");
    let mut cleanup = Cleanup::new();
    unsafe { cancel::__stafeto_cleanup_push(&mut cleanup, Some(race_cleanup), ptr::null_mut()) };
    threads::probe_cancel_window(|| {
        sys::notify(&ready, 1).expect("window ready");
        // Main at priority 30 records cancellation while this priority-10
        // thread is still Ready, before it enters receive. As the layer's
        // points do, entries wait while it checks and enters the wait: a
        // request that came before is seen by the check, one that comes
        // after interrupts the wait.
        let deferred = rt::upcall::defer_entries().expect("window deferral");
        if !cancel::requested() && sys::receive(&gate) != Err(rt::abi::Error::Interrupted) {
            sys::process_exit(80);
        }
        drop(deferred);
    });
    CLEANUP_RESULT.store(3, Ordering::Release);
    unsafe { cancel::__stafeto_cleanup_pop(&mut cleanup, 0) };
    ptr::null_mut()
}

pub fn run() -> bool {
    let target_gate = sys::channel_create(1).expect("cancel target gate");
    let ready = sys::channel_create(30).expect("cleanup ready channel");
    let release = sys::channel_create(1).expect("cleanup release channel");
    CLEANUP_READY.store(ready.raw().0, Ordering::Release);
    CLEANUP_RELEASE.store(release.raw().0, Ordering::Release);
    CLEANUP_RESULT.store(0, Ordering::Release);
    let mut target = 0;
    let mut child = 0;
    let mut value = ptr::null_mut();
    if unsafe {
        threads::pthread_create(
            &mut target,
            ptr::null(),
            Some(gated),
            target_gate.raw().0 as *mut c_void,
        )
    } != 0
    {
        return failed(13);
    }
    CANCEL_TARGET.store(target, Ordering::Release);
    if unsafe {
        threads::pthread_create(
            &mut child,
            ptr::null(),
            Some(cancelled_joiner),
            ptr::null_mut(),
        )
    } != 0
    {
        return failed(14);
    }
    let native = unsafe { threads::probe_native(child) }.expect("cancelled joiner handle");
    if !waiting(&native) || threads::pthread_cancel(child) != 0 || sys::receive(&ready).is_err() {
        return failed(15);
    }
    // The cancelled thread remains blocked in its handler. Another thread
    // must already be able to claim the original target before cleanup ends.
    if sys::notify(&target_gate, 1).is_err()
        || unsafe { threads::pthread_join(target, &mut value) } != 0
        || value as usize != VALUE
    {
        return failed(16);
    }
    if sys::notify(&release, 1).is_err()
        || unsafe { threads::pthread_join(child, &mut value) } != 0
        || value != cancel::CANCELED
        || CLEANUP_RESULT.load(Ordering::Acquire) != 1
    {
        return failed(17);
    }
    rt::println!("posix-cancel-probe: live join released before cleanup finished");

    CLEANUP_RESULT.store(0, Ordering::Release);
    let race_ready = sys::channel_create(30).expect("race ready channel");
    let race_gate = sys::channel_create(1).expect("race gate");
    RACE_GATE.store(race_gate.raw().0, Ordering::Release);
    if unsafe {
        threads::pthread_create(
            &mut child,
            ptr::null(),
            Some(before_wait),
            race_ready.raw().0 as *mut c_void,
        )
    } != 0
        || sys::receive(&race_ready).is_err()
    {
        return failed(20);
    }
    let native = Handle::<Thread>::borrowed(rt::abi::Handle(RACE_NATIVE.load(Ordering::Acquire)));
    if !sys::thread_info(&native).is_ok_and(|info| info.state == ThreadState::Ready) {
        return failed(21);
    }
    if threads::pthread_cancel(child) != 0 {
        return failed(22);
    }
    rt::println!("posix-cancel-probe: cancellation recorded before IPC wait");
    if unsafe { threads::pthread_join(child, &mut value) } != 0
        || value != cancel::CANCELED
        || CLEANUP_RESULT.load(Ordering::Acquire) != 1
    {
        return failed(23);
    }
    rt::println!("posix-cancel-probe: a request before the wait ends it at its point");
    true
}
