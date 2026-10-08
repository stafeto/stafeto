// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real read cancellation cleans UART/Virtio waits before the user's handler.

use super::*;
use ffi::Cleanup;
static CLEANED: AtomicUsize = AtomicUsize::new(0);
static BODY_RETURNED: AtomicUsize = AtomicUsize::new(0);
static HANDLED: AtomicUsize = AtomicUsize::new(0);

/// A handler that returns: the read it entered goes on waiting.
unsafe extern "C" fn returns(_: i32) {
    HANDLED.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn cleanup(_: *mut c_void) {
    let mut old = 99;
    if unsafe { ffi::pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &mut old) } != 0
        || old != PTHREAD_CANCEL_DISABLE
    {
        CLEANED.store(2, Ordering::Release);
        return;
    }
    ffi::pthread_testcancel();
    rt::println!("posix-cancel-input-probe: cleanup read waiting");
    let mut bytes = [0; 2];
    let mut length = 0;
    // Consume the host's character and CR, even if separate IRQs split them.
    // The same session must accept new reads after the old cancellation ack.
    while length < bytes.len() {
        let result = unsafe { ffi::read(0, bytes.as_mut_ptr().add(length), bytes.len() - length) };
        if result <= 0 {
            CLEANED.store(3, Ordering::Release);
            return;
        }
        length += result as usize;
    }
    if bytes != *b"z\n" {
        CLEANED.store(3, Ordering::Release);
        return;
    }
    CLEANED.store(1, Ordering::Release);
}
unsafe extern "C" fn reader(_: *mut c_void) -> *mut c_void {
    let mut node = Cleanup::new();
    unsafe { ffi::cleanup_push(&mut node, Some(cleanup), ptr::null_mut()) };
    let mut byte = 0;
    let _ = unsafe { ffi::read(0, &mut byte, 1) };
    BODY_RETURNED.store(1, Ordering::Release);
    unsafe { ffi::cleanup_pop(&mut node, 0) };
    ptr::null_mut()
}

fn console_waiting(id: u64, native: &Handle<Thread>) -> bool {
    let wake = sys::channel_create(30).expect("console poll wake");
    let timer = sys::timer_create(&wake, 30).expect("console poll timer");
    for _ in 0..100 {
        if threads::probe_console_waiting(id)
            && sys::thread_info(native).is_ok_and(|info| info.state == ThreadState::Receiving)
        {
            return true;
        }
        let deadline = sys::clock_now().expect("console clock") + 1_000_000;
        sys::timer_set(&timer, deadline).expect("console deadline");
        crate::watchdog::receive(deadline, rt::abi::Error::Interrupted, |_| {
            sys::receive(&wake)
        })
        .expect("console wake");
    }
    false
}

pub fn run() -> bool {
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let mut child = 0;
    let mut value = ptr::null_mut();
    // Warm the file journal, thread slot and stack tables before measuring
    // reclamation. Journal mappings are retained for reuse until process exit.
    let mut cwd = [0; 2];
    if unsafe { ffi::getcwd(cwd.as_mut_ptr().cast(), cwd.len()) }.is_null() {
        return failed(30);
    }
    if unsafe { ffi::pthread_create(&mut child, ptr::null(), Some(returning), ptr::null_mut()) }
        != 0
        || unsafe { ffi::pthread_join(child, &mut value) } != 0
    {
        return failed(30);
    }
    // A read in two steps labels a copy of the reader's channel: the page
    // of the pool of sessions it takes stays with the process. Warm it.
    let warm = sys::channel_create(30).expect("session pool warm channel");
    drop(sys::handle_label(&warm, rt::abi::Rights::NOTIFY, 1, 30).expect("session pool warm"));
    drop(warm);
    let _ = settle();
    let handles = sys::process_handles(&process)
        .expect("console baseline handles")
        .live;
    let used = sys::process_memory(&process)
        .expect("console baseline quota")
        .used;
    let errno = unsafe { ffi::__errno_location() };
    unsafe { *errno = 123 };
    if unsafe { ffi::pthread_create(&mut child, ptr::null(), Some(reader), ptr::null_mut()) } != 0 {
        return failed(31);
    }
    let native = unsafe { threads::probe_native(child) }.expect("console reader handle");
    // A signal whose handler returns (SA_RESTART) comes inside the read: the read's
    // window of cancellation must be back when the handler returned, or
    // the request below would not reach the wait.
    let action = posix_abi::signals::SigAction {
        handler: returns as *const () as u64,
        mask: 0,
        // The read goes on after the handler (no EINTR).
        flags: posix_abi::constants::SA_RESTART,
    };
    if !console_waiting(child, &native)
        || posix_abi::signals::sigaction(posix_abi::constants::SIGUSR1, Some(action)).is_err()
        || ffi::pthread_kill(child, posix_abi::constants::SIGUSR1) != 0
    {
        return failed(37);
    }
    for _ in 0..1000 {
        if HANDLED.load(Ordering::SeqCst) == 1 {
            break;
        }
        let _ = sys::yield_now();
    }
    if HANDLED.load(Ordering::SeqCst) != 1
        || !console_waiting(child, &native)
        || ffi::pthread_cancel(child) != 0
        || unsafe { ffi::pthread_join(child, &mut value) } != 0
        || value != ffi::CANCELED
        || CLEANED.load(Ordering::Acquire) != 1
        || BODY_RETURNED.load(Ordering::Acquire) != 0
    {
        return failed(32);
    }
    if !settle()
        || sys::process_handles(&process)
            .expect("console returned handles")
            .live
            != handles
        || sys::process_memory(&process)
            .expect("console returned quota")
            .used
            != used
    {
        return failed(33);
    }
    rt::println!("posix-cancel-input-probe: read after cancellation waiting");
    let mut byte = 0;
    if unsafe { ffi::read(0, &mut byte, 1) } != 1 || byte != b'v' || unsafe { *errno } != 123 {
        return failed(34);
    }
    rt::println!("posix-cancel-input-probe: ok");
    true
}
