// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! relibc's mutex over the layer's waits by address: contended ordinary
//! writes, kinds (EDEADLK, recursion, EBUSY, EPERM), and the release by a
//! cleanup handler of a cancelled holder that wakes the next waiter.

use super::*;
use core::cell::UnsafeCell;
use ffi::{
    Mutex, MutexAttr, pthread_mutex_destroy, pthread_mutex_init, pthread_mutex_lock,
    pthread_mutex_trylock, pthread_mutex_unlock, pthread_mutexattr_destroy, pthread_mutexattr_init,
    pthread_mutexattr_settype,
};

static LOCK: Mutex = Mutex::new();
static CLEANUP_LOCK: Mutex = Mutex::new();
static READY: AtomicU64 = AtomicU64::new(0);
static CANCEL_TARGET: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static CLEANED: AtomicUsize = AtomicUsize::new(0);
static RECOVERED: AtomicUsize = AtomicUsize::new(0);
const ROUNDS: u64 = 500;
struct Data(UnsafeCell<[u64; 2]>);
// SAFETY: all reads and writes of these ordinary words hold LOCK.
unsafe impl Sync for Data {}
static DATA: Data = Data(UnsafeCell::new([0; 2]));
fn address(mutex: &'static Mutex) -> *mut Mutex {
    ptr::from_ref(mutex).cast_mut()
}
fn ready() {
    let c = Handle::<Channel>::borrowed(rt::abi::Handle(READY.load(Ordering::Acquire)));
    sys::notify(&c, 1).expect("mutex ready");
}
fn error() {
    ERRORS.fetch_add(1, Ordering::Relaxed);
}
/// Adds to both words ROUNDS times under LOCK, yielding inside so that the
/// others wait on it.
unsafe extern "C" fn contender(argument: *mut c_void) -> *mut c_void {
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    for _ in 0..ROUNDS {
        if unsafe { pthread_mutex_lock(address(&LOCK)) } != 0 {
            error();
            return ptr::null_mut();
        }
        let data = unsafe { &mut *DATA.0.get() };
        let before = data[0];
        let _ = sys::yield_now();
        if data[0] != before || data[1] != before {
            error();
        }
        data[0] += 1;
        data[1] += 1;
        if unsafe { pthread_mutex_unlock(address(&LOCK)) } != 0 {
            error();
        }
    }
    if unsafe { *errno } != 777 {
        error();
    }
    argument
}
unsafe extern "C" fn unlock_cleanup(_: *mut c_void) {
    if unsafe { pthread_mutex_unlock(address(&CLEANUP_LOCK)) } != 0 {
        error();
    }
    CLEANED.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "C" fn cancellation_owner(_: *mut c_void) -> *mut c_void {
    if unsafe { pthread_mutex_lock(address(&CLEANUP_LOCK)) } != 0 {
        error();
        return ptr::null_mut();
    }
    let mut cleanup = ffi::Cleanup::new();
    unsafe { ffi::cleanup_push(&mut cleanup, Some(unlock_cleanup), ptr::null_mut()) };
    ready();
    let _ = unsafe { ffi::pthread_join(CANCEL_TARGET.load(Ordering::Acquire), ptr::null_mut()) };
    unsafe { ffi::cleanup_pop(&mut cleanup, 1) };
    error();
    ptr::null_mut()
}
unsafe extern "C" fn recover(_: *mut c_void) -> *mut c_void {
    if unsafe { pthread_mutex_lock(address(&CLEANUP_LOCK)) } != 0 {
        error();
    } else {
        RECOVERED.fetch_add(1, Ordering::Relaxed);
        if unsafe { pthread_mutex_unlock(address(&CLEANUP_LOCK)) } != 0 {
            error();
        }
    }
    VALUE as *mut c_void
}
fn create(callback: unsafe extern "C" fn(*mut c_void) -> *mut c_void, value: usize) -> Option<u64> {
    let mut id = 0;
    (unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(callback), value as *mut c_void) }
        == 0)
        .then_some(id)
}
fn join(id: u64, expected: *mut c_void) -> bool {
    let mut value = ptr::null_mut();
    (unsafe { ffi::pthread_join(id, &mut value) }) == 0 && value == expected
}

pub(super) fn run() -> bool {
    let ready_channel = sys::channel_create(30).expect("mutex ready channel");
    READY.store(ready_channel.raw().0, Ordering::Release);
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 123 };
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let _ = settle();
    let before_handles = sys::process_handles(&process)
        .expect("mutex handle baseline")
        .live;
    let mut children = [0; 4];
    for (index, id) in children.iter_mut().enumerate() {
        let Some(child) = create(contender, index) else {
            return failed(90);
        };
        *id = child;
    }
    for (index, child) in children.into_iter().enumerate() {
        if !join(child, index as *mut c_void) {
            return failed(91);
        }
    }
    let data = unsafe { *DATA.0.get() };
    if data != [4 * ROUNDS, 4 * ROUNDS]
        || ERRORS.load(Ordering::Relaxed) != 0
        || unsafe { *errno } != 123
        || unsafe { pthread_mutex_trylock(address(&LOCK)) } != 0
        || unsafe { pthread_mutex_trylock(address(&LOCK)) } != EBUSY
        || unsafe { pthread_mutex_unlock(address(&LOCK)) } != 0
        || unsafe { pthread_mutex_destroy(address(&LOCK)) } != 0
    {
        return failed(92);
    }
    rt::println!("posix-mutex-probe: four contended writers, trylock and EBUSY ok");

    let mut attr = MutexAttr::new();
    let object = Mutex::new();
    let a = &raw mut attr;
    let m = object.get();
    // Error checking: a second lock of the owner is EDEADLK, an unlock of
    // a mutex it does not hold EPERM.
    if unsafe { pthread_mutexattr_init(a) } != 0
        || unsafe { pthread_mutexattr_settype(a, PTHREAD_MUTEX_ERRORCHECK) } != 0
        || unsafe { pthread_mutex_init(m, a) } != 0
        || unsafe { pthread_mutex_lock(m) } != 0
        || unsafe { pthread_mutex_lock(m) } != EDEADLK
        || unsafe { pthread_mutex_trylock(m) } != EBUSY
        || unsafe { pthread_mutex_unlock(m) } != 0
        || unsafe { pthread_mutex_unlock(m) } != EPERM
        || unsafe { pthread_mutex_destroy(m) } != 0
    {
        return failed(93);
    }
    // Recursion counts; a partial release keeps the mutex.
    if unsafe { pthread_mutexattr_settype(a, PTHREAD_MUTEX_RECURSIVE) } != 0
        || unsafe { pthread_mutex_init(m, a) } != 0
        || unsafe { pthread_mutex_lock(m) } != 0
        || unsafe { pthread_mutex_lock(m) } != 0
        || unsafe { pthread_mutex_trylock(m) } != 0
        || unsafe { pthread_mutex_unlock(m) } != 0
        || unsafe { pthread_mutex_unlock(m) } != 0
        || object.word().load(Ordering::Relaxed) == 0
        || unsafe { pthread_mutex_unlock(m) } != 0
        || object.word().load(Ordering::Relaxed) != 0
        || unsafe { pthread_mutex_unlock(m) } != EPERM
        || unsafe { pthread_mutex_destroy(m) } != 0
        || unsafe { pthread_mutexattr_destroy(a) } != 0
    {
        return failed(94);
    }
    rt::println!("posix-mutex-probe: EDEADLK, EPERM, recursion and partial release ok");

    // A cancelled holder's cleanup releases the mutex to its waiter.
    let target_gate = sys::channel_create(30).expect("cancellation join target gate");
    let Some(target) = create(gated, target_gate.raw().0 as usize) else {
        return failed(97);
    };
    CANCEL_TARGET.store(target, Ordering::Release);
    let Some(owner) = create(cancellation_owner, 0) else {
        return failed(98);
    };
    sys::receive(&ready_channel).expect("cleanup owner holds mutex");
    let native = unsafe { threads::probe_native(owner) }.expect("cancellation owner");
    if !waiting(&native) {
        return failed(99);
    }
    let Some(waiter) = create(recover, 0) else {
        return failed(100);
    };
    if !futex_blocked(waiter) || ffi::pthread_cancel(owner) != 0 {
        return failed(101);
    }
    if !join(owner, ffi::CANCELED)
        || !join(waiter, VALUE as *mut c_void)
        || CLEANED.load(Ordering::Relaxed) != 1
        || RECOVERED.load(Ordering::Relaxed) != 1
        || ERRORS.load(Ordering::Relaxed) != 0
    {
        return failed(102);
    }
    sys::notify(&target_gate, 1).expect("release unclaimed join target");
    if !join(target, VALUE as *mut c_void)
        || unsafe { pthread_mutex_destroy(address(&CLEANUP_LOCK)) } != 0
        || unsafe { *errno } != 123
    {
        return failed(103);
    }
    drop(target_gate);
    let _ = settle();
    if sys::process_handles(&process)
        .expect("mutex final handles")
        .live
        != before_handles
    {
        return failed(104);
    }
    rt::println!("posix-mutex-probe: cancellation cleanup hands the mutex to its waiter ok");
    true
}
