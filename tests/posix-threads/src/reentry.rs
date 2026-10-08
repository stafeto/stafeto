// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real nested native handlers must retain the outer cancellation wait.
use super::*;
use rt::wait::{Waited, Waiter};

rt::upcall_entry!(entry, dispatch);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static GATE: AtomicU64 = AtomicU64::new(0);
static FD: AtomicUsize = AtomicUsize::new(0);
static DEPTH: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static CLEANED: AtomicUsize = AtomicUsize::new(0);
fn channel(raw: &AtomicU64) -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(raw.load(Ordering::Acquire)))
}
fn unchanged(epoch: u64) {
    if epoch == 0
        || threads::probe_cancel_active() != epoch
        || !threads::probe_console_waiting(ffi::pthread_self())
    {
        ERRORS.fetch_add(1, Ordering::Release);
    }
}
fn request() {
    let native = Handle::<Thread>::borrowed(rt::abi::Handle(NATIVE.load(Ordering::Acquire)));
    sys::thread_upcall_request(&native).unwrap();
}
unsafe extern "C" fn dispatch() {
    let epoch = threads::probe_cancel_active();
    unchanged(epoch);
    let depth = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    CALLS.fetch_add(1, Ordering::SeqCst);
    if depth == 1 {
        threads::probe_cancel_window(|| {
            let nested = threads::probe_cancel_active();
            if nested == 0 || nested == epoch {
                ERRORS.fetch_add(1, Ordering::Release);
            }
            threads::probe_cancel_console();
            unsafe { rt::upcall::enable() }.unwrap();
            request();
            rt::upcall::mask().unwrap();
            unchanged(nested);
        });
        unchanged(epoch);
    }
    let errno = unsafe { ffi::__errno_location() };
    let saved = unsafe { *errno };
    let fd = FD.load(Ordering::Acquire) as i32;
    // Successful transfer uses Point::end; zero/error use Point::finish.
    if unsafe { ffi::write(fd, b"R".as_ptr(), 1) } != 1 {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    unchanged(epoch);
    if unsafe { ffi::write(fd, ptr::null(), 0) } != 0 {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    unchanged(epoch);
    if unsafe { ffi::write(-1, ptr::null(), 0) } != -1 || unsafe { *errno } != EBADF {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    unchanged(epoch);
    unsafe { *errno = saved };
    DEPTH.fetch_sub(1, Ordering::SeqCst);
}
unsafe extern "C" fn cleanup(_: *mut c_void) {
    CLEANED.store(1, Ordering::Release);
    sys::notify(&channel(&DONE), 1).unwrap();
}
unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    let native = unsafe { threads::probe_native(ffi::pthread_self()) }.unwrap();
    NATIVE.store(native.raw().0, Ordering::Release);
    let errno = unsafe { ffi::__errno_location() };
    unsafe { *errno = 777 };
    let mut cleanup_node = ffi::Cleanup::new();
    unsafe { ffi::cleanup_push(&mut cleanup_node, Some(cleanup), ptr::null_mut()) };
    unsafe { rt::upcall::bind(entry) }.unwrap();
    threads::probe_cancel_window(|| {
        let epoch = threads::probe_cancel_active();
        threads::probe_cancel_console();
        unsafe { rt::upcall::enable() }.unwrap();
        request();
        rt::upcall::mask().unwrap();
        unchanged(epoch);
        if unsafe { *errno } != 777 || CALLS.load(Ordering::Acquire) != 2 {
            ERRORS.fetch_add(1, Ordering::Release);
        }
        sys::notify(&channel(&READY), 1).unwrap();
        // Only a restored outer window lets pthread_cancel interrupt this wait.
        if sys::receive(&channel(&GATE)) != Err(rt::abi::Error::Interrupted) {
            ERRORS.fetch_add(1, Ordering::Release);
        }
    });
    ERRORS.fetch_add(1, Ordering::Release);
    ptr::null_mut()
}
fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}
pub(super) fn run() -> bool {
    let fd = unsafe { ffi::open(c"/tmp/probe".as_ptr(), O_RDWR) };
    if fd < 0 || unsafe { ffi::lseek(fd, 0, SEEK_SET) } != 0 {
        return failed(240);
    }
    FD.store(fd as usize, Ordering::Release);
    let ready = sys::channel_create(30).unwrap();
    let done = sys::channel_create(30).unwrap();
    let gate = sys::channel_create(30).unwrap();
    let ready_waiter = Waiter::new(&ready, 0, 30).unwrap();
    let done_waiter = Waiter::new(&done, 0, 30).unwrap();
    READY.store(ready.raw().0, Ordering::Release);
    DONE.store(done.raw().0, Ordering::Release);
    GATE.store(gate.raw().0, Ordering::Release);
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let _ = settle();
    let before_handles = sys::process_handles(&process).unwrap().live;
    let before_used = sys::process_memory(&process).unwrap().used;
    let mut id = 0;
    assert_eq!(
        unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(worker), ptr::null_mut()) },
        0
    );
    if !matches!(
        {
            let deadline = now() + 500_000_000;
            crate::watchdog::receive(deadline, rt::abi::Error::Interrupted, |deadline| {
                ready_waiter.receive_until(&ready, deadline)
            })
        },
        Ok(Waited::Got(_))
    ) {
        return failed(241);
    }
    if ffi::pthread_cancel(id) != 0 {
        return failed(242);
    }
    if !matches!(
        {
            let deadline = now() + 500_000_000;
            crate::watchdog::receive(deadline, rt::abi::Error::Interrupted, |deadline| {
                done_waiter.receive_until(&done, deadline)
            })
        },
        Ok(Waited::Got(_))
    ) || CLEANED.load(Ordering::Acquire) != 1
    {
        return failed(243);
    }
    let mut value = ptr::null_mut();
    if unsafe { ffi::pthread_join(id, &mut value) } != 0
        || value != ffi::CANCELED
        || ERRORS.load(Ordering::Acquire) != 0
        || threads::probe_cancel_active() != 0
        || !settle()
        || sys::process_handles(&process).unwrap().live != before_handles
        || sys::process_memory(&process).unwrap().used != before_used
    {
        return failed(244);
    }
    let mut bytes = [0; 2];
    if unsafe { ffi::lseek(fd, 0, SEEK_SET) } != 0
        || unsafe { ffi::read(fd, bytes.as_mut_ptr(), 2) } != 2
        || bytes != *b"RR"
        || unsafe { ffi::close(fd) } != 0
    {
        return failed(245);
    }
    rt::println!(
        "cancel-reentry-probe: nested handler writes retain outer wait, cancellation cleanup and quota ok"
    );
    true
}
