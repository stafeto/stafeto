// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Live mutex waiters, interrupted handoff, ordinary writes and cleanup release.

use super::*;
use core::cell::UnsafeCell;
use threads::{
    cancel,
    mutex::{
        self, Mutex, pthread_mutex_destroy, pthread_mutex_lock, pthread_mutex_trylock,
        pthread_mutex_unlock,
    },
};

static LOCK: Mutex = Mutex::new();
static CLEANUP_LOCK: Mutex = Mutex::new();
static READY: AtomicU64 = AtomicU64::new(0);
static GATE: AtomicU64 = AtomicU64::new(0);
static CANCEL_TARGET: AtomicU64 = AtomicU64::new(0);
static ENTERED: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static CLEANED: AtomicUsize = AtomicUsize::new(0);
static RECOVERED: AtomicUsize = AtomicUsize::new(0);
struct Data(UnsafeCell<[u64; 8]>);
// SAFETY: all reads and writes of these ordinary words hold LOCK. Readiness
// flags are Relaxed and do not publish the protected payload to lock consumers.
unsafe impl Sync for Data {}
static DATA: Data = Data(UnsafeCell::new([0; 8]));
fn address(mutex: &'static Mutex) -> *mut Mutex {
    ptr::from_ref(mutex).cast_mut()
}
fn ready() {
    let c = Handle::<Channel>::borrowed(rt::abi::Handle(READY.load(Ordering::Acquire)));
    sys::notify(&c, 1).expect("mutex ready");
}
unsafe extern "C" fn contender(argument: *mut c_void) -> *mut c_void {
    let index = argument as usize;
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    if index == 0 && threads::pthread_cancel(threads::pthread_self()) != 0 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    if unsafe { pthread_mutex_lock(address(&LOCK)) } != 0 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
        return ptr::null_mut();
    }
    if ENTERED.fetch_add(1, Ordering::Relaxed) != 0 || unsafe { *errno } != 777 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    let data = unsafe { &mut *DATA.0.get() };
    let step = data[0] as usize;
    if step >= 6 || data[1] != 0xabc0 + step as u64 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    } else {
        data[step + 2] = index as u64;
        data[0] += 1;
        data[1] += 1;
    }
    if index == 5 {
        ready();
        let gate = Handle::<Channel>::borrowed(rt::abi::Handle(GATE.load(Ordering::Acquire)));
        sys::receive(&gate).expect("hold transferred mutex");
    }
    if ENTERED.fetch_sub(1, Ordering::Relaxed) != 1
        || unsafe { pthread_mutex_unlock(address(&LOCK)) } != 0
        || unsafe { *errno } != 777
    {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    cancel::pthread_testcancel();
    (VALUE + index) as *mut c_void
}
unsafe extern "C" fn unlock_cleanup(_: *mut c_void) {
    if unsafe { pthread_mutex_unlock(address(&CLEANUP_LOCK)) } != 0 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    CLEANED.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "C" fn cancellation_owner(_: *mut c_void) -> *mut c_void {
    if unsafe { pthread_mutex_lock(address(&CLEANUP_LOCK)) } != 0 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
        return ptr::null_mut();
    }
    let mut cleanup = cancel::Cleanup::new();
    unsafe { cancel::__stafeto_cleanup_push(&mut cleanup, Some(unlock_cleanup), ptr::null_mut()) };
    ready();
    let _ =
        unsafe { threads::pthread_join(CANCEL_TARGET.load(Ordering::Acquire), ptr::null_mut()) };
    unsafe { cancel::__stafeto_cleanup_pop(&mut cleanup, 1) };
    ERRORS.fetch_add(1, Ordering::Relaxed);
    ptr::null_mut()
}
unsafe extern "C" fn recover(_: *mut c_void) -> *mut c_void {
    if unsafe { pthread_mutex_lock(address(&CLEANUP_LOCK)) } != 0 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    } else {
        RECOVERED.fetch_add(1, Ordering::Relaxed);
        if unsafe { pthread_mutex_unlock(address(&CLEANUP_LOCK)) } != 0 {
            ERRORS.fetch_add(1, Ordering::Relaxed);
        }
    }
    VALUE as *mut c_void
}
fn blocked(id: u64) -> bool {
    let Ok(native) = (unsafe { threads::probe_native(id) }) else {
        return false;
    };
    waiting(&native) && mutex::probe_waiting(id) == Ok(true)
}
fn create(callback: unsafe extern "C" fn(*mut c_void) -> *mut c_void, value: usize) -> Option<u64> {
    let mut id = 0;
    (unsafe { threads::pthread_create(&mut id, ptr::null(), Some(callback), value as *mut c_void) }
        == 0)
        .then_some(id)
}
fn join(id: u64, expected: *mut c_void) -> bool {
    let mut value = ptr::null_mut();
    (unsafe { threads::pthread_join(id, &mut value) }) == 0 && value == expected
}

pub(super) fn run() -> bool {
    let ready_channel = sys::channel_create(30).expect("mutex ready channel");
    let gate = sys::channel_create(30).expect("mutex owner gate");
    READY.store(ready_channel.raw().0, Ordering::Release);
    GATE.store(gate.raw().0, Ordering::Release);
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 123 };
    if unsafe { pthread_mutex_lock(address(&LOCK)) } != 0 {
        return failed(90);
    }
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let before_handles = sys::process_handles(&process)
        .expect("mutex handle baseline")
        .live;
    let before_used = sys::process_memory(&process)
        .expect("mutex warmed quota baseline")
        .used;
    let mut children = [0; 6];
    for (index, id) in children.iter_mut().enumerate() {
        let Some(child) = create(contender, index) else {
            return failed(91);
        };
        *id = child;
        let native = unsafe { threads::probe_native(child) }.expect("mutex contender handle");
        let priority = if index == 5 {
            5
        } else if index < 2 {
            10
        } else {
            (10 + index) as u8
        };
        sys::thread_set_priority(&native, priority, rt::abi::Policy::Fifo)
            .expect("mutex waiter priority");
        for _ in 0..3 {
            if !blocked(child) || sys::thread_interrupt(&native).is_err() {
                return failed(92);
            }
        }
        if !blocked(child) || ENTERED.load(Ordering::Relaxed) != 0 {
            return failed(93);
        }
    }
    let native = unsafe { threads::probe_native(children[5]) }.expect("reprioritized mutex waiter");
    sys::thread_set_priority(&native, 30, rt::abi::Policy::Fifo)
        .expect("raise already waiting contender");
    unsafe { *DATA.0.get() = [0, 0xabc0, 99, 99, 99, 99, 99, 99] };
    // Interrupt the committed handoff, the unlocking reply, and subsequent
    // failed try/destroy replies. No ownership change may run twice.
    mutex::probe_interrupt_replies();
    if unsafe { pthread_mutex_unlock(address(&LOCK)) } != 0 {
        return failed(94);
    }
    sys::receive(&ready_channel).expect("highest priority contender holds mutex");
    if mutex::probe_waiting(children[5]) != Ok(false)
        || ENTERED.load(Ordering::Relaxed) != 1
        || unsafe { pthread_mutex_trylock(address(&LOCK)) } != EBUSY
        || unsafe { pthread_mutex_destroy(address(&LOCK)) } != EBUSY
        || unsafe { pthread_mutex_unlock(address(&LOCK)) } != EPERM
    {
        return failed(95);
    }
    for &id in &children[..5] {
        if !blocked(id) {
            return failed(96);
        }
    }
    sys::notify(&gate, 1).expect("release critical section");
    for (index, child) in children.into_iter().enumerate() {
        if !join(
            child,
            if index == 0 {
                cancel::CANCELED
            } else {
                (VALUE + index) as *mut c_void
            },
        ) {
            return failed(97);
        }
    }
    if unsafe { pthread_mutex_lock(address(&LOCK)) } != 0 {
        return failed(98);
    }
    let data = unsafe { *DATA.0.get() };
    if data != [6, 0xabc6, 5, 4, 3, 2, 0, 1]
        || ENTERED.load(Ordering::Relaxed) != 0
        || ERRORS.load(Ordering::Relaxed) != 0
        || unsafe { *errno } != 123
    {
        return failed(99);
    }
    if unsafe { pthread_mutex_unlock(address(&LOCK)) } != 0
        || unsafe { pthread_mutex_destroy(address(&LOCK)) } != 0
    {
        return failed(100);
    }
    rt::println!(
        "posix-mutex-probe: priority handoff, ordinary writes, live/reply interruption and deferred pending ok"
    );

    // Recursive partial release and count exhaustion leave ownership intact.
    let mut attr = core::mem::MaybeUninit::<mutex::Attributes>::uninit();
    let mut recursive = core::mem::MaybeUninit::<Mutex>::uninit();
    let a = attr.as_mut_ptr();
    let m = recursive.as_mut_ptr();
    if unsafe { mutex::pthread_mutexattr_init(a) } != 0
        || unsafe { mutex::pthread_mutexattr_settype(a, PTHREAD_MUTEX_RECURSIVE) } != 0
        || unsafe { mutex::pthread_mutex_init(m, a) } != 0
        || unsafe { pthread_mutex_lock(m) } != 0
    {
        return failed(101);
    }
    unsafe { mutex::probe_recursion(m, u32::MAX) };
    mutex::probe_interrupt_replies();
    if unsafe { pthread_mutex_lock(m) } != EAGAIN
        || unsafe { pthread_mutex_trylock(m) } != EAGAIN
        || unsafe { pthread_mutex_destroy(m) } != EBUSY
    {
        return failed(102);
    }
    unsafe { mutex::probe_recursion(m, 2) };
    if unsafe { pthread_mutex_unlock(m) } != 0
        || unsafe { pthread_mutex_destroy(m) } != EBUSY
        || unsafe { pthread_mutex_unlock(m) } != 0
        || unsafe { pthread_mutex_destroy(m) } != 0
        || unsafe { mutex::pthread_mutexattr_destroy(a) } != 0
    {
        return failed(103);
    }

    let target_gate = sys::channel_create(30).expect("cancellation join target gate");
    let Some(target) = create(gated, target_gate.raw().0 as usize) else {
        return failed(104);
    };
    CANCEL_TARGET.store(target, Ordering::Release);
    let Some(owner) = create(cancellation_owner, 0) else {
        return failed(105);
    };
    sys::receive(&ready_channel).expect("cleanup owner holds mutex");
    let native = unsafe { threads::probe_native(owner) }.expect("cancellation owner");
    if !waiting(&native) {
        return failed(106);
    }
    let Some(waiter) = create(recover, 0) else {
        return failed(107);
    };
    if !blocked(waiter) || threads::pthread_cancel(owner) != 0 {
        return failed(108);
    }
    if !join(owner, cancel::CANCELED)
        || !join(waiter, VALUE as *mut c_void)
        || CLEANED.load(Ordering::Relaxed) != 1
        || RECOVERED.load(Ordering::Relaxed) != 1
        || ERRORS.load(Ordering::Relaxed) != 0
    {
        return failed(109);
    }
    sys::notify(&target_gate, 1).expect("release unclaimed join target");
    if !join(target, VALUE as *mut c_void)
        || unsafe { pthread_mutex_destroy(address(&CLEANUP_LOCK)) } != 0
        || unsafe { *errno } != 123
    {
        return failed(110);
    }
    drop(target_gate);
    if sys::process_handles(&process)
        .expect("mutex final handles")
        .live
        != before_handles
        || sys::process_memory(&process)
            .expect("mutex final quota")
            .used
            != before_used
    {
        return failed(111);
    }
    rt::println!(
        "posix-mutex-probe: recursive overflow/partial release and cancellation cleanup handoff ok"
    );
    true
}
