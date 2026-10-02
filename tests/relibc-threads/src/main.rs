// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A C main on relibc whose threads the layer makes, with the layer's
//! views the C side checks (threads.c).

#![no_std]
#![no_main]

use core::ffi::{c_int, c_ulong};

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

/// The calling thread's window of cancellation (0 outside a point).
#[unsafe(no_mangle)]
extern "C" fn relibc_threads_cancel_window() -> u64 {
    posix_abi::threads::probe_cancel_active()
}

/// Whether the thread whose relibc `pthread_t` is `thread` has ended for
/// the kernel (its place stays until relibc releases it).
#[unsafe(no_mangle)]
extern "C" fn relibc_threads_ended(thread: u64) -> c_int {
    // SAFETY: the thread keeps its place until its detach or join.
    let ended = unsafe { posix_abi::threads::probe_native(thread) }.is_ok_and(|native| {
        rt::sys::thread_info(&native).is_ok_and(|info| info.state == rt::abi::ThreadState::Ended)
    });
    c_int::from(ended)
}

/// The places of the layer's table of threads that hold a thread.
#[unsafe(no_mangle)]
extern "C" fn relibc_threads_places() -> c_int {
    posix_abi::relibc::occupied() as c_int
}

/// Frees what the ended and released threads held.
#[unsafe(no_mangle)]
extern "C" fn relibc_threads_collect() {
    posix_abi::relibc::collect();
}

/// The bytes the layer's heap took from the kernel so far.
#[unsafe(no_mangle)]
extern "C" fn relibc_threads_heap() -> c_ulong {
    posix_abi::allocation::probe_committed() as c_ulong
}

/// Moves the calling thread to kernel level `level`.
#[unsafe(no_mangle)]
extern "C" fn relibc_threads_set_level(level: c_int) -> c_int {
    match posix_abi::threads::set_level(level as u8) {
        Ok(()) => 0,
        Err(errno) => errno,
    }
}

/// CLOCK_REALTIME through the clock service's page, and the generation of
/// its anchor: -1 without the page.
///
/// # Safety
/// `seconds` and `nanos` are writable.
#[unsafe(no_mangle)]
unsafe extern "C" fn relibc_threads_realtime(seconds: *mut i64, nanos: *mut i64) -> i64 {
    match posix_abi::clock::probe_realtime() {
        Ok((time, generation)) => {
            // SAFETY: the caller's promise.
            unsafe {
                seconds.write(time.seconds);
                nanos.write(time.nanos);
            }
            generation as i64
        }
        Err(_) => -1,
    }
}

/// The kernel calls of the process so far (rt, feature count-calls).
#[unsafe(no_mangle)]
extern "C" fn relibc_threads_calls() -> u64 {
    rt::sys::calls()
}
