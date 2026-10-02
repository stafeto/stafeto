// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A C main on relibc whose threads the layer makes, with the layer's
//! views the C side checks (threads.c).

#![no_std]
#![no_main]

use core::ffi::{c_int, c_ulong};

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

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
