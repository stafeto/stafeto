// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real interrupted key replies, cross-thread deletion and destructor joins.

use super::*;
use ffi::{pthread_getspecific, pthread_key_create, pthread_key_delete, pthread_setspecific};

static MAIN_KEY: AtomicU64 = AtomicU64::new(0);
static MAIN_CALLS: AtomicUsize = AtomicUsize::new(0);
static KEY: AtomicU64 = AtomicU64::new(0);
static TARGET_ID: AtomicU64 = AtomicU64::new(0);
static GATE: AtomicU64 = AtomicU64::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static DESTRUCTIONS: AtomicUsize = AtomicUsize::new(0);
static RESULT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn destructor(value: *mut c_void) {
    let ready = Handle::<Channel>::borrowed(rt::abi::Handle(READY.load(Ordering::Acquire)));
    let gate = Handle::<Channel>::borrowed(rt::abi::Handle(GATE.load(Ordering::Acquire)));
    if value as usize != VALUE || !pthread_getspecific(KEY.load(Ordering::Acquire)).is_null() {
        RESULT.store(2, Ordering::Release);
    }
    DESTRUCTIONS.fetch_add(1, Ordering::AcqRel);
    sys::notify(&ready, 1).expect("destructor started");
    sys::receive(&gate).expect("destructor release");
}
unsafe extern "C" fn child(_: *mut c_void) -> *mut c_void {
    if pthread_setspecific(KEY.load(Ordering::Acquire), VALUE as *const c_void) != 0 {
        RESULT.store(2, Ordering::Release);
    }
    VALUE as *mut c_void
}
unsafe extern "C" fn joiner(_: *mut c_void) -> *mut c_void {
    let mut value = ptr::null_mut();
    if unsafe { ffi::pthread_join(TARGET_ID.load(Ordering::Acquire), &mut value) } != 0
        || value as usize != VALUE
    {
        RESULT.store(2, Ordering::Release);
    }
    value
}
unsafe extern "C" fn deleted_binding(_: *mut c_void) -> *mut c_void {
    let old = KEY.load(Ordering::Acquire);
    let ready = Handle::<Channel>::borrowed(rt::abi::Handle(READY.load(Ordering::Acquire)));
    let gate = Handle::<Channel>::borrowed(rt::abi::Handle(GATE.load(Ordering::Acquire)));
    if pthread_setspecific(old, VALUE as *const c_void) != 0 {
        RESULT.store(2, Ordering::Release);
    }
    sys::notify(&ready, 1).expect("binding stored");
    sys::receive(&gate).expect("key reused");
    let new = KEY.load(Ordering::Acquire);
    if new == old
        || !pthread_getspecific(new).is_null()
        || pthread_setspecific(old, VALUE as *const c_void) != EINVAL
    {
        RESULT.store(2, Ordering::Release);
    }
    VALUE as *mut c_void
}

unsafe extern "C" fn main_destructor(value: *mut c_void) {
    let key = MAIN_KEY.load(Ordering::Acquire);
    assert!(pthread_getspecific(key).is_null());
    MAIN_CALLS.fetch_add(1, Ordering::AcqRel);
    assert_eq!(pthread_setspecific(key, value), 0);
}
pub(super) fn main_completed() -> bool {
    MAIN_CALLS.load(Ordering::Acquire) == PTHREAD_DESTRUCTOR_ITERATIONS as usize
        && pthread_getspecific(MAIN_KEY.load(Ordering::Acquire)).is_null()
}

pub(super) fn run() -> bool {
    let gate = sys::channel_create(30).expect("destructor gate");
    let ready = sys::channel_create(30).expect("destructor readiness");
    GATE.store(gate.raw().0, Ordering::Release);
    READY.store(ready.raw().0, Ordering::Release);
    let mut key = 0;
    if unsafe { pthread_key_create(&mut key, Some(destructor)) } != 0
        || !pthread_getspecific(key).is_null()
    {
        return failed(40);
    }
    KEY.store(key, Ordering::Release);
    let mut target = 0;
    if unsafe { ffi::pthread_create(&mut target, ptr::null(), Some(child), ptr::null_mut()) } != 0 {
        return failed(41);
    }
    TARGET_ID.store(target, Ordering::Release);
    sys::receive(&ready).expect("destructor readiness");
    let mut waiter = 0;
    if unsafe { ffi::pthread_create(&mut waiter, ptr::null(), Some(joiner), ptr::null_mut()) } != 0
    {
        return failed(42);
    }
    let native = unsafe { threads::probe_native(waiter) }.expect("destructor join waiter");
    if !waiting(&native) || DESTRUCTIONS.load(Ordering::Acquire) != 1 {
        return failed(43);
    }
    sys::notify(&gate, 1).expect("finish destructor");
    if unsafe { ffi::pthread_join(waiter, ptr::null_mut()) } != 0
        || RESULT.load(Ordering::Acquire) != 0
        || pthread_key_delete(key) != 0
    {
        return failed(44);
    }
    rt::println!("posix-thread-probe: interrupted key replies and destructor join ordering ok");

    if unsafe { pthread_key_create(&mut key, Some(destructor)) } != 0 {
        return failed(45);
    }
    KEY.store(key, Ordering::Release);
    if unsafe {
        ffi::pthread_create(
            &mut target,
            ptr::null(),
            Some(deleted_binding),
            ptr::null_mut(),
        )
    } != 0
    {
        return failed(46);
    }
    sys::receive(&ready).expect("cross-thread binding ready");
    if pthread_key_delete(key) != 0
        || unsafe { pthread_key_create(&mut key, Some(destructor)) } != 0
    {
        return failed(47);
    }
    KEY.store(key, Ordering::Release);
    sys::notify(&gate, 1).expect("resume after key reuse");
    if unsafe { ffi::pthread_join(target, ptr::null_mut()) } != 0
        || RESULT.load(Ordering::Acquire) != 0
        || DESTRUCTIONS.load(Ordering::Acquire) != 1
        || pthread_key_delete(key) != 0
    {
        return failed(48);
    }
    rt::println!("posix-thread-probe: deleted keys discard bindings in other live threads");
    if unsafe { pthread_key_create(&mut key, Some(main_destructor)) } != 0
        || pthread_setspecific(key, VALUE as *const c_void) != 0
    {
        return failed(49);
    }
    MAIN_KEY.store(key, Ordering::Release);
    true
}
