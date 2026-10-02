// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Once over waits by address: waiters wait by address while the routine
//! runs and all see its writes; a cancelled routine rolls the control back
//! and a waiter runs it; nested once objects complete.

use super::*;
use core::cell::UnsafeCell;
use ffi::{Once as Control, pthread_once};

static BLOCKED: Control = Control::new();
static OUTER: Control = Control::new();
static INNER: Control = Control::new();
static ROLLBACK: Control = Control::new();
static RELEASE: AtomicU64 = AtomicU64::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static ROLLBACK_CALLS: AtomicUsize = AtomicUsize::new(0);
static NESTED: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);

struct Data(UnsafeCell<[u64; 4]>);
// SAFETY: the sole once routine writes; others read only after pthread_once
// returned.
unsafe impl Sync for Data {}
static DATA: Data = Data(UnsafeCell::new([0; 4]));
const EXPECTED: [u64; 4] = [0x1234, 0x5678, 0x9abc, 0xdef0];

fn control(control: &'static Control) -> *mut Control {
    ptr::from_ref(control).cast_mut()
}
fn error() {
    ERRORS.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "C" fn initialize_blocked() {
    CALLS.fetch_add(1, Ordering::Relaxed);
    let channel = Handle::<Channel>::borrowed(rt::abi::Handle(RELEASE.load(Ordering::Acquire)));
    sys::receive(&channel).expect("once routine release");
    unsafe { *DATA.0.get() = EXPECTED };
}
unsafe extern "C" fn blocked_worker(_: *mut c_void) -> *mut c_void {
    if unsafe { pthread_once(control(&BLOCKED), Some(initialize_blocked)) } != 0
        || unsafe { *DATA.0.get() } != EXPECTED
    {
        error();
    }
    VALUE as *mut c_void
}
unsafe extern "C" fn initialize_inner() {
    NESTED.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "C" fn initialize_outer() {
    if unsafe { pthread_once(control(&INNER), Some(initialize_inner)) } != 0 {
        error();
    }
    NESTED.fetch_add(10, Ordering::Relaxed);
}
/// The first call cancels its own thread inside the routine.
unsafe extern "C" fn initialize_rollback() {
    if ROLLBACK_CALLS.fetch_add(1, Ordering::Relaxed) == 0 {
        if ffi::pthread_cancel(ffi::pthread_self()) != 0 {
            error();
        }
        ffi::pthread_testcancel();
        error();
    }
}
unsafe extern "C" fn rollback_worker(_: *mut c_void) -> *mut c_void {
    if unsafe { pthread_once(control(&ROLLBACK), Some(initialize_rollback)) } != 0 {
        error();
    }
    VALUE as *mut c_void
}
fn create(callback: unsafe extern "C" fn(*mut c_void) -> *mut c_void) -> u64 {
    let mut id = 0;
    if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(callback), ptr::null_mut()) } != 0 {
        error();
    }
    id
}
fn join(id: u64, expected: *mut c_void) -> bool {
    let mut value = ptr::null_mut();
    (unsafe { ffi::pthread_join(id, &mut value) }) == 0 && value == expected
}

pub(super) fn run() -> bool {
    let release = sys::channel_create(30).expect("once release channel");
    RELEASE.store(release.raw().0, Ordering::Release);
    // The first runs the routine; the others wait by address.
    let ids = [
        create(blocked_worker),
        create(blocked_worker),
        create(blocked_worker),
    ];
    for &id in &ids[1..] {
        if !futex_blocked(id) {
            return failed(50);
        }
    }
    sys::notify(&release, 1).expect("release the once routine");
    for id in ids {
        if !join(id, VALUE as *mut c_void) {
            return failed(51);
        }
    }
    if CALLS.load(Ordering::Relaxed) != 1
        || unsafe { pthread_once(control(&BLOCKED), Some(initialize_blocked)) } != 0
        || CALLS.load(Ordering::Relaxed) != 1
        || unsafe { pthread_once(control(&OUTER), Some(initialize_outer)) } != 0
        || unsafe { pthread_once(control(&OUTER), Some(initialize_outer)) } != 0
        || NESTED.load(Ordering::Relaxed) != 11
    {
        return failed(52);
    }
    // A cancelled routine rolls back; the next caller runs it.
    let cancelled = create(rollback_worker);
    if !join(cancelled, ffi::CANCELED) {
        return failed(53);
    }
    let retry = create(rollback_worker);
    if !join(retry, VALUE as *mut c_void)
        || ROLLBACK_CALLS.load(Ordering::Relaxed) != 2
        || ERRORS.load(Ordering::Relaxed) != 0
    {
        return failed(54);
    }
    rt::println!(
        "posix-thread-probe: once waiters wait by address, nested once, and a cancelled routine rolls back"
    );
    true
}
