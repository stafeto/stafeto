// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Deferred entries preserve interruptibility.
use super::*;
use rt::{
    abi::Error,
    upcall,
    wait::{Waited, Waiter},
};
rt::upcall_entry!(entry, dispatch);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static GATE: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static RESULT: AtomicUsize = AtomicUsize::new(0);
fn native() -> core::mem::ManuallyDrop<Handle<Thread>> {
    Handle::borrowed(rt::abi::Handle(NATIVE.load(Ordering::Acquire)))
}
fn channel(raw: &AtomicU64) -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(raw.load(Ordering::Acquire)))
}
fn poke() {
    sys::thread_upcall_request(&native()).unwrap();
}
unsafe extern "C" fn dispatch() {
    COUNT.fetch_add(1, Ordering::SeqCst);
}
fn simple() -> bool {
    let gate = sys::channel_create(10).unwrap();
    let outer = upcall::defer_entries().unwrap();
    let inner = upcall::defer_entries().unwrap();
    poke();
    poke();
    if COUNT.load(Ordering::Acquire) != 0
        || sys::receive(&gate) != Err(Error::Interrupted)
        || sys::try_receive(&gate) != Err(Error::WouldBlock)
    {
        return failed(340);
    }
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let _ = settle();
    let handles = sys::process_handles(&process).unwrap().live;
    let moved = sys::channel_create(10).unwrap();
    match sys::send_handles(&gate, b"not queued", [moved.erase()]) {
        Err(refused) if refused.error == Error::Interrupted && refused.back.is_none() => (),
        _ => return failed(341),
    }
    let _ = settle();
    if sys::process_handles(&process).unwrap().live != handles
        || sys::send(&gate, b"inline") != Err(Error::Interrupted)
        || sys::send(&gate, &[0x55; 80]) != Err(Error::Interrupted)
        || sys::try_receive(&gate) != Err(Error::WouldBlock)
    {
        return failed(342);
    }
    sys::notify(&gate, 1).unwrap();
    if sys::receive(&gate) != Err(Error::Interrupted)
        || !matches!(
            sys::try_receive(&gate),
            Ok(sys::Received::Notification { bits: 1, .. })
        )
    {
        return failed(343);
    }
    drop(inner);
    if COUNT.load(Ordering::Acquire) != 0 {
        return failed(344);
    }
    drop(outer);
    if COUNT.load(Ordering::Acquire) != 1 || upcall::mask() != Ok(false) {
        return failed(345);
    }
    let guard = upcall::defer_entries().unwrap();
    poke();
    drop(guard);
    if COUNT.load(Ordering::Acquire) != 1 || upcall::mask() != Ok(true) {
        return failed(346);
    }
    // A changed application mask remains changed after dropping the guard.
    let guard = upcall::defer_entries().unwrap();
    unsafe { upcall::enable() }.unwrap();
    if COUNT.load(Ordering::Acquire) != 1 || sys::receive(&gate) != Err(Error::Interrupted) {
        return failed(347);
    }
    upcall::mask().unwrap();
    drop(guard);
    if COUNT.load(Ordering::Acquire) != 1 {
        return failed(348);
    }
    unsafe { upcall::enable() }.unwrap();
    if COUNT.load(Ordering::Acquire) != 2 {
        return failed(349);
    }
    true
}
unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    let native_handle = unsafe { threads::probe_native(ffi::pthread_self()) }.unwrap();
    NATIVE.store(native_handle.raw().0, Ordering::Release);
    unsafe { upcall::bind(entry) }.unwrap();
    unsafe { upcall::enable() }.unwrap();
    let passed = match MODE.load(Ordering::Acquire) {
        0 => simple(),
        1 | 2 => {
            let outer = upcall::defer_entries().unwrap();
            let inner = upcall::defer_entries().unwrap();
            sys::notify(&channel(&READY), 1).unwrap();
            // A receive is interrupted; a request the service accepted
            // gets its reply, and the entry waits for the deferrals.
            let interrupted = if MODE.load(Ordering::Acquire) == 1 {
                sys::receive(&channel(&GATE)) == Err(Error::Interrupted)
            } else {
                sys::send(&channel(&GATE), b"live wait").is_ok_and(|reply| reply.len == 4)
            };
            let before = COUNT.load(Ordering::Acquire) == 0;
            drop(inner);
            let nested = COUNT.load(Ordering::Acquire) == 0;
            drop(outer);
            interrupted && before && nested && COUNT.load(Ordering::Acquire) == 1
        }
        _ => false,
    };
    upcall::unbind().unwrap();
    RESULT.store(if passed { 1 } else { 2 }, Ordering::Release);
    sys::notify(&channel(&DONE), 1).unwrap();
    ptr::with_exposed_provenance_mut(usize::from(passed))
}
pub(super) fn run() -> bool {
    let ready = sys::channel_create(30).unwrap();
    let gate = sys::channel_create(10).unwrap();
    let done = sys::channel_create(30).unwrap();
    let waiter = Waiter::new(&ready, 0, 30).unwrap();
    let done_waiter = Waiter::new(&done, 0, 30).unwrap();
    READY.store(ready.raw().0, Ordering::Release);
    GATE.store(gate.raw().0, Ordering::Release);
    DONE.store(done.raw().0, Ordering::Release);
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let _ = settle();
    let handles = sys::process_handles(&process).unwrap().live;
    for mode in 0..3 {
        MODE.store(mode, Ordering::Release);
        COUNT.store(0, Ordering::Release);
        ERRORS.store(0, Ordering::Release);
        RESULT.store(0, Ordering::Release);
        let mut id = 0;
        let mut result = ptr::null_mut();
        if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(worker), ptr::null_mut()) } != 0
        {
            return failed(355);
        }
        if mode == 1 || mode == 2 {
            let now = || rt::time::ticks_to_ns(rt::time::now());
            if !matches!(
                {
                    let deadline = now() + 10_000_000_000;
                    crate::watchdog::receive(deadline, rt::abi::Error::Interrupted, |deadline| {
                        waiter.receive_until(&ready, deadline)
                    })
                },
                Ok(Waited::Got(_))
            ) {
                return failed(356);
            }
            let token = if mode == 2 {
                match sys::receive(&gate).unwrap() {
                    sys::Received::Message { token, .. } => Some(token),
                    _ => return failed(357),
                }
            } else {
                if !matches!(
                    {
                        let deadline = now() + 20_000_000;
                        crate::watchdog::receive(
                            deadline,
                            rt::abi::Error::Interrupted,
                            |deadline| waiter.receive_until(&ready, deadline),
                        )
                    },
                    Ok(Waited::Expired)
                ) || sys::thread_info(&native()).unwrap().state != ThreadState::Receiving
                {
                    return failed(358);
                }
                None
            };
            poke();
            if let Some(token) = token {
                // The request of the worker stays accepted through the
                // request of an entry: its reply goes (spec 6.1).
                let reply = token.reply(b"late");
                if reply != Ok(()) {
                    rt::println!("borrow-guard-probe: reply {:?}", reply);
                    return failed(359);
                }
            }
        }
        let deadline = rt::time::ticks_to_ns(rt::time::now()) + 10_000_000_000;
        if !matches!(
            {
                crate::watchdog::receive(deadline, rt::abi::Error::Interrupted, |deadline| {
                    done_waiter.receive_until(&done, deadline)
                })
            },
            Ok(Waited::Got(_))
        ) {
            return failed(369);
        }
        if unsafe { ffi::pthread_join(id, &mut result) } != 0
            || result as usize != 1
            || RESULT.load(Ordering::Acquire) != 1
        {
            return failed(360 + mode);
        }
    }
    let _ = settle();
    if sys::process_handles(&process).unwrap().live != handles {
        return failed(368);
    }
    rt::println!("borrow-guard-probe: live/pending IPC, transfer consumption and nested masks ok");
    true
}
