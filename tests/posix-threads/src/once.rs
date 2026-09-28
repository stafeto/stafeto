// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Blocking once waiters, published application data and nested cancellation.

use super::*;
use core::cell::UnsafeCell;
use threads::{
    cancel,
    once::{self, Control, pthread_once},
};

static BLOCKED: Control = Control::new();
static OUTER: Control = Control::new();
static INNER: Control = Control::new();
static ROLLBACK: Control = Control::new();
static ROLLBACK_CALLS: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static RELEASE: AtomicU64 = AtomicU64::new(0);
static AFTER_ONCE: AtomicU64 = AtomicU64::new(0);
static TARGET_ID: AtomicU64 = AtomicU64::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static PHASE: AtomicUsize = AtomicUsize::new(0);
static RETURNED: AtomicUsize = AtomicUsize::new(0);
static OUTER_CALLS: AtomicUsize = AtomicUsize::new(0);
static INNER_CALLS: AtomicUsize = AtomicUsize::new(0);
static RECOVERED: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);

struct Data(UnsafeCell<[u64; 4]>);
// SAFETY: the sole once initializer writes; consumers read only after successful
// pthread_once publication. No test-side release/acquire publishes these bytes.
unsafe impl Sync for Data {}
static DATA: Data = Data(UnsafeCell::new([0; 4]));
const EXPECTED: [u64; 4] = [0x1234, 0x5678, 0x9abc, 0xdef0];

fn control(control: &'static Control) -> *mut Control {
    core::ptr::from_ref(control).cast_mut()
}
fn ready() {
    let channel = Handle::<Channel>::borrowed(rt::abi::Handle(READY.load(Ordering::Acquire)));
    sys::notify(&channel, 1).expect("once readiness");
}
unsafe extern "C" fn initialize_blocked() {
    CALLS.fetch_add(1, Ordering::Relaxed);
    PHASE.store(1, Ordering::Relaxed);
    ready();
    let channel = Handle::<Channel>::borrowed(rt::abi::Handle(RELEASE.load(Ordering::Acquire)));
    sys::receive(&channel).expect("once initializer release");
    unsafe { *DATA.0.get() = EXPECTED };
    PHASE.store(2, Ordering::Relaxed);
}
unsafe extern "C" fn initialize_worker(argument: *mut c_void) -> *mut c_void {
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    if argument as usize == 1 && threads::pthread_cancel(threads::pthread_self()) != 0 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    if unsafe { pthread_once(control(&BLOCKED), Some(initialize_blocked)) } != 0
        || PHASE.load(Ordering::Relaxed) != 2
        || unsafe { *errno } != 777
        || unsafe { *DATA.0.get() } != EXPECTED
    {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    RETURNED.fetch_add(1, Ordering::Relaxed);
    if argument as usize == 2 {
        let ready = Handle::<Channel>::borrowed(rt::abi::Handle(READY.load(Ordering::Acquire)));
        let gate = Handle::<Channel>::borrowed(rt::abi::Handle(AFTER_ONCE.load(Ordering::Acquire)));
        sys::notify(&ready, 2).expect("fast retry returned");
        sys::receive(&gate).expect("fast retry release");
    }
    cancel::pthread_testcancel();
    VALUE as *mut c_void
}
unsafe extern "C" fn initialize_inner() {
    if INNER_CALLS.fetch_add(1, Ordering::Relaxed) == 0 {
        ready();
        let _ =
            unsafe { threads::pthread_join(TARGET_ID.load(Ordering::Acquire), ptr::null_mut()) };
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
}
unsafe extern "C" fn initialize_outer() {
    OUTER_CALLS.fetch_add(1, Ordering::Relaxed);
    if unsafe { pthread_once(control(&INNER), Some(initialize_inner)) } != 0 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
}
unsafe extern "C" fn recover(_: *mut c_void) {
    // Both internal rollback nodes precede this outer application handler.
    if unsafe { pthread_once(control(&OUTER), Some(initialize_outer)) } != 0 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    RECOVERED.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "C" fn cancelled_initializer(_: *mut c_void) -> *mut c_void {
    let mut cleanup = cancel::Cleanup::new();
    unsafe { cancel::__stafeto_cleanup_push(&mut cleanup, Some(recover), ptr::null_mut()) };
    let _ = unsafe { pthread_once(control(&OUTER), Some(initialize_outer)) };
    unsafe { cancel::__stafeto_cleanup_pop(&mut cleanup, 0) };
    ERRORS.fetch_add(1, Ordering::Relaxed);
    ptr::null_mut()
}
unsafe extern "C" fn retrying_initializer(_: *mut c_void) -> *mut c_void {
    if unsafe { pthread_once(control(&OUTER), Some(initialize_outer)) } != 0 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    VALUE as *mut c_void
}

unsafe extern "C" fn initialize_rollback() {
    if ROLLBACK_CALLS.fetch_add(1, Ordering::Relaxed) == 0 {
        ready();
        let _ =
            unsafe { threads::pthread_join(TARGET_ID.load(Ordering::Acquire), ptr::null_mut()) };
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
}
unsafe extern "C" fn rollback_worker(_: *mut c_void) -> *mut c_void {
    if unsafe { pthread_once(control(&ROLLBACK), Some(initialize_rollback)) } != 0 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    VALUE as *mut c_void
}

pub(super) fn run() -> bool {
    let ready_channel = sys::channel_create(30).expect("once ready channel");
    let release = sys::channel_create(30).expect("once release channel");
    let finish = sys::channel_create(30).expect("once finish gate");
    let after = sys::channel_create(30).expect("once post-return gate");
    AFTER_ONCE.store(after.raw().0, Ordering::Release);
    READY.store(ready_channel.raw().0, Ordering::Release);
    RELEASE.store(release.raw().0, Ordering::Release);
    once::probe_interrupt_replies();
    let mut initializer = 0;
    if unsafe {
        threads::pthread_create(
            &mut initializer,
            ptr::null(),
            Some(initialize_worker),
            ptr::null_mut(),
        )
    } != 0
    {
        return failed(50);
    }
    sys::receive(&ready_channel).expect("initializer entered");
    let native = unsafe { threads::probe_native(initializer) }.expect("lower priority initializer");
    sys::thread_set_priority(&native, 10, rt::abi::Policy::Fifo).expect("initializer priority");
    // Priority-30 contenders must block so the priority-10 initializer can run.
    let mut waiters = [0; 6];
    for (index, waiter) in waiters.iter_mut().enumerate() {
        if unsafe {
            threads::pthread_create(
                waiter,
                ptr::null(),
                Some(initialize_worker),
                (index + 1) as *mut c_void,
            )
        } != 0
        {
            return failed(51);
        }
        let native = unsafe { threads::probe_native(*waiter) }.expect("once waiter handle");
        for _ in 0..3 {
            if !waiting(&native) || sys::thread_interrupt(&native).is_err() {
                return failed(52);
            }
        }
        if !waiting(&native) || RETURNED.load(Ordering::Relaxed) != 0 {
            return failed(53);
        }
    }
    once::probe_gate_finish(ready_channel.raw().0, finish.raw().0);
    sys::notify(&release, 1).expect("publish initialization");
    sys::receive(&ready_channel).expect("publication before FINISH");
    let native = unsafe { threads::probe_native(waiters[1]) }.expect("completed retry handle");
    sys::thread_interrupt(&native).expect("retry after publication");
    sys::receive(&ready_channel).expect("completed retry returned");
    if once::probe_waiting(waiters[1]) != Ok(false) || RETURNED.load(Ordering::Relaxed) != 1 {
        return failed(64);
    }
    sys::notify(&after, 1).expect("continue returned waiter");
    sys::notify(&finish, 1).expect("deliver FINISH");
    let mut value = ptr::null_mut();
    if unsafe { threads::pthread_join(initializer, &mut value) } != 0 || value as usize != VALUE {
        return failed(54);
    }
    for (index, waiter) in waiters.into_iter().enumerate() {
        if unsafe { threads::pthread_join(waiter, &mut value) } != 0
            || value
                != if index == 0 {
                    cancel::CANCELED
                } else {
                    VALUE as *mut c_void
                }
        {
            return failed(55);
        }
    }
    if CALLS.load(Ordering::Relaxed) != 1
        || RETURNED.load(Ordering::Relaxed) != 7
        || ERRORS.load(Ordering::Relaxed) != 0
    {
        return failed(56);
    }
    rt::println!(
        "posix-thread-probe: once waiters block, retry interruption and preserve pending cancellation"
    );

    let mut target = 0;
    if unsafe {
        threads::pthread_create(
            &mut target,
            ptr::null(),
            Some(gated),
            release.raw().0 as *mut c_void,
        )
    } != 0
    {
        return failed(57);
    }
    TARGET_ID.store(target, Ordering::Release);
    once::probe_interrupt_replies();
    if unsafe {
        threads::pthread_create(
            &mut initializer,
            ptr::null(),
            Some(cancelled_initializer),
            ptr::null_mut(),
        )
    } != 0
    {
        return failed(58);
    }
    sys::receive(&ready_channel).expect("nested initialization entered");
    let native = unsafe { threads::probe_native(initializer) }.expect("nested initializer handle");
    if !waiting(&native) {
        return failed(59);
    }
    let mut waiter = 0;
    if unsafe {
        threads::pthread_create(
            &mut waiter,
            ptr::null(),
            Some(retrying_initializer),
            ptr::null_mut(),
        )
    } != 0
    {
        return failed(60);
    }
    let retry = unsafe { threads::probe_native(waiter) }.expect("nested once waiter");
    if !waiting(&retry) || threads::pthread_cancel(initializer) != 0 {
        return failed(61);
    }
    if unsafe { threads::pthread_join(initializer, &mut value) } != 0
        || value != cancel::CANCELED
        || unsafe { threads::pthread_join(waiter, &mut value) } != 0
        || value as usize != VALUE
        || OUTER_CALLS.load(Ordering::Relaxed) != 2
        || INNER_CALLS.load(Ordering::Relaxed) != 2
        || RECOVERED.load(Ordering::Relaxed) != 1
        || ERRORS.load(Ordering::Relaxed) != 0
    {
        return failed(62);
    }
    rt::println!(
        "posix-thread-probe: nested once cancellation resets ownership before cleanup recovery"
    );
    if unsafe {
        threads::pthread_create(
            &mut initializer,
            ptr::null(),
            Some(rollback_worker),
            ptr::null_mut(),
        )
    } != 0
    {
        return failed(65);
    }
    sys::receive(&ready_channel).expect("standalone rollback entered");
    let native =
        unsafe { threads::probe_native(initializer) }.expect("rollback initializer handle");
    if !waiting(&native)
        || unsafe {
            threads::pthread_create(
                &mut waiter,
                ptr::null(),
                Some(rollback_worker),
                ptr::null_mut(),
            )
        } != 0
    {
        return failed(66);
    }
    let retry = unsafe { threads::probe_native(waiter) }.expect("rollback waiter handle");
    if !waiting(&retry) || threads::pthread_cancel(initializer) != 0 {
        return failed(67);
    }
    if unsafe { threads::pthread_join(initializer, &mut value) } != 0
        || value != cancel::CANCELED
        || unsafe { threads::pthread_join(waiter, &mut value) } != 0
        || value as usize != VALUE
        || ROLLBACK_CALLS.load(Ordering::Relaxed) != 2
        || ERRORS.load(Ordering::Relaxed) != 0
    {
        return failed(68);
    }
    rt::println!("posix-thread-probe: once rollback wakes a waiter without application recovery");
    sys::notify(&release, 1).expect("release abandoned join target");
    if unsafe { threads::pthread_join(target, &mut value) } != 0 || value as usize != VALUE {
        return failed(63);
    }
    true
}
