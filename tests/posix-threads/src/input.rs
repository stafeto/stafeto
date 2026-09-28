// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real read cancellation cleans UART/Virtio waits before the user's handler.

use super::*;
use threads::cancel::{self, Cleanup};
static CLEANED: AtomicUsize = AtomicUsize::new(0);
static BODY_RETURNED: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn cleanup(_: *mut c_void) {
    let mut old = 99;
    if unsafe { cancel::pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &mut old) } != 0
        || old != PTHREAD_CANCEL_DISABLE
    {
        CLEANED.store(2, Ordering::Release);
        return;
    }
    cancel::pthread_testcancel();
    rt::println!("posix-cancel-input-probe: cleanup read waiting");
    let mut bytes = [0; 2];
    let mut length = 0;
    // Consume the host's character and CR, even if separate IRQs split them.
    // The same session must accept new reads after the old cancellation ack.
    while length < bytes.len() {
        let result = unsafe { abi::read(0, bytes.as_mut_ptr().add(length), bytes.len() - length) };
        if result <= 0 {
            CLEANED.store(3, Ordering::Release);
            return;
        }
        length += result as usize;
    }
    let ending = if cfg!(feature = "native-cancel-input") {
        b'\r'
    } else {
        b'\n'
    };
    if bytes != [b'z', ending] {
        CLEANED.store(3, Ordering::Release);
        return;
    }
    CLEANED.store(1, Ordering::Release);
}
unsafe extern "C" fn reader(_: *mut c_void) -> *mut c_void {
    let mut node = Cleanup::new();
    unsafe { cancel::__stafeto_cleanup_push(&mut node, Some(cleanup), ptr::null_mut()) };
    let mut byte = 0;
    let _ = unsafe { abi::read(0, &mut byte, 1) };
    BODY_RETURNED.store(1, Ordering::Release);
    unsafe { cancel::__stafeto_cleanup_pop(&mut node, 0) };
    ptr::null_mut()
}

fn console_waiting(id: u64, native: &Handle<Thread>) -> bool {
    let wake = sys::channel_create(30).expect("console poll wake");
    let timer = sys::timer_create(&wake, 30).expect("console poll timer");
    for _ in 0..100 {
        let waiting = if cfg!(feature = "native-cancel-input") {
            ThreadState::Receiving
        } else {
            ThreadState::AwaitingReply
        };
        if threads::probe_console_waiting(id)
            && sys::thread_info(native).is_ok_and(|info| info.state == waiting)
        {
            return true;
        }
        sys::timer_set(&timer, sys::clock_now().expect("console clock") + 1_000_000)
            .expect("console deadline");
        sys::receive(&wake).expect("console wake");
    }
    false
}

pub fn run() -> bool {
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let mut child = 0;
    let mut value = ptr::null_mut();
    // Warm the thread slot and stack page tables before measuring reclamation.
    if unsafe { threads::pthread_create(&mut child, ptr::null(), Some(returning), ptr::null_mut()) }
        != 0
        || unsafe { threads::pthread_join(child, &mut value) } != 0
    {
        return failed(30);
    }
    let handles = sys::process_handles(&process)
        .expect("console baseline handles")
        .live;
    let used = sys::process_memory(&process)
        .expect("console baseline quota")
        .used;
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 123 };
    if unsafe { threads::pthread_create(&mut child, ptr::null(), Some(reader), ptr::null_mut()) }
        != 0
    {
        return failed(31);
    }
    let native = unsafe { threads::probe_native(child) }.expect("console reader handle");
    if !console_waiting(child, &native)
        || threads::pthread_cancel(child) != 0
        || unsafe { threads::pthread_join(child, &mut value) } != 0
        || value != cancel::CANCELED
        || CLEANED.load(Ordering::Acquire) != 1
        || BODY_RETURNED.load(Ordering::Acquire) != 0
    {
        return failed(32);
    }
    if sys::process_handles(&process)
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
    if unsafe { abi::read(0, &mut byte, 1) } != 1 || byte != b'v' || unsafe { *errno } != 123 {
        return failed(34);
    }
    rt::println!("posix-cancel-input-probe: ok");
    true
}
