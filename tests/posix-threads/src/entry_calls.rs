// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel calls between a signal sent to a thread that counts and the
//! first line of its handler. The entry of the layer takes no deferral of
//! the kernel while it is inside an entry (the mask of the entry keeps the
//! next one out), so the number is the same on each delivery and a change of
//! the delivery path shows here at once.
use super::*;
use crate::layer::signals::{self as api, SigAction};

/// The calls from the mark of the sender to the first line of the handler,
/// without the sender's receive: the sender's `pthread_kill` and the layer's
/// calls on the target before its handler runs (the one that enables nested
/// entries).
const ENTRY_CALLS_TO_HANDLER: u64 = 4;
/// The calls from the mark to the return into the interrupted code,
/// without the sender's receive: the former plus the call that masks the
/// entry again after the handler. Measured: 4 + 1 (9 when a delivery inside
/// an entry takes the kernel's deferral, as it did before).
const ENTRY_DELIVERY_CALLS: u64 = 5;

static READY: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static STOP: AtomicUsize = AtomicUsize::new(0);
static AT_START: AtomicU64 = AtomicU64::new(0);
static AT_END: AtomicU64 = AtomicU64::new(0);

fn channel(raw: &AtomicU64) -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(raw.load(Ordering::Acquire)))
}
unsafe extern "C" fn handler(_signal: c_int) {
    AT_START.store(sys::calls(), Ordering::SeqCst);
    STOP.store(1, Ordering::SeqCst);
}
unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    let native = unsafe { threads::probe_native(ffi::pthread_self()) }.unwrap();
    sys::thread_set_priority(&native, 10, rt::abi::Policy::Fifo).unwrap();
    // The launch notification leaves a boost until the next receive.
    let drain = sys::channel_create(10).unwrap();
    assert_eq!(sys::try_receive(&drain), Err(rt::abi::Error::WouldBlock));
    drop(drain);
    sys::notify(&channel(&READY), 1).unwrap();
    // Busy at a level below main: no call of the kernel until the handler.
    while STOP.load(Ordering::SeqCst) == 0 {
        core::hint::spin_loop();
    }
    // The entry has returned into this loop.
    AT_END.store(sys::calls(), Ordering::SeqCst);
    sys::notify(&channel(&DONE), 1).unwrap();
    ptr::null_mut()
}

pub(super) fn run() -> bool {
    let ready = sys::channel_create(30).unwrap();
    let done = sys::channel_create(30).unwrap();
    READY.store(ready.raw().0, Ordering::Release);
    DONE.store(done.raw().0, Ordering::Release);
    STOP.store(0, Ordering::Release);
    let action = SigAction {
        handler: handler as *const () as u64,
        mask: 0,
        flags: 0,
    };
    let mut old = posix_signals::INITIAL;
    if unsafe { api::sigaction(SIGUSR1, &action, &mut old) } != 0 {
        return failed(1601);
    }
    let mut id = 0;
    if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(worker), ptr::null_mut()) } != 0 {
        return failed(1602);
    }
    if sys::receive(&ready).is_err() {
        return failed(1603);
    }
    let mark = sys::calls();
    if ffi::pthread_kill(id, SIGUSR1) != 0 {
        return failed(1604);
    }
    // One call for this receive, counted before the target runs.
    if sys::receive(&done).is_err() {
        return failed(1605);
    }
    let to_handler = AT_START.load(Ordering::SeqCst) - mark - 1;
    let calls = AT_END.load(Ordering::SeqCst) - mark - 1;
    if unsafe { ffi::pthread_join(id, ptr::null_mut()) } != 0 {
        return failed(1606);
    }
    if unsafe { api::sigaction(SIGUSR1, &old, ptr::null_mut()) } != 0 {
        return failed(1607);
    }
    if to_handler != ENTRY_CALLS_TO_HANDLER || calls != ENTRY_DELIVERY_CALLS {
        rt::println!(
            "entry-calls: {to_handler} kernel calls to the handler (expected {ENTRY_CALLS_TO_HANDLER}), {calls} to the return (expected {ENTRY_DELIVERY_CALLS})"
        );
        return failed(1608);
    }
    rt::println!(
        "entry-calls: {to_handler} kernel calls from pthread_kill to the handler, {calls} to the return"
    );
    true
}
