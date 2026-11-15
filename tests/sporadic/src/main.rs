// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A C main on relibc that sets threads and a child process under sporadic
//! servers and reads back what the layer, the process service and init
//! made of them (sporadic.c).

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

use core::ffi::c_int;

/// The base level, the level the kernel has the thread work at now and its
/// state code of the thread whose relibc `pthread_t` is `thread`; 0 or an
/// errno.
///
/// # Safety
/// The three pointers are writable; the thread keeps its place.
#[unsafe(no_mangle)]
unsafe extern "C" fn sporadic_info(
    thread: u64,
    base: *mut c_int,
    priority: *mut c_int,
    state: *mut c_int,
) -> c_int {
    // SAFETY: the thread keeps its place while this reads it.
    let Ok(native) = (unsafe { posix_abi::threads::probe_native(thread) }) else {
        return 3;
    };
    let Ok(info) = rt::sys::thread_info(&native) else {
        return 5;
    };
    // SAFETY: the caller's promise.
    unsafe {
        base.write(c_int::from(info.base));
        priority.write(c_int::from(info.priority));
        state.write(info.state.code() as c_int);
    }
    0
}
