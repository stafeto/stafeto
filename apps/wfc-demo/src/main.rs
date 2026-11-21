// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The scene demo (wfc-demo.c) on relibc: posix-crt, built with its features
//! `wfc` and `window`, starts the layer and carries the functions of
//! `<WF/wfc.h>` and `<stafeto/window.h>`; relibc starts C.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

/// The counters of the composition service (`posix_abi::wfc::counters`): eight
/// numbers in `out` (frames, direct, late, skipped, failed, capped, bypassed,
/// bands), 0, or -1 when the service does not answer.
///
/// # Safety
/// `out` points to eight writable numbers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wd_counters(out: *mut u32) -> i32 {
    match posix_abi::wfc::counters() {
        Some(c) => {
            for (i, v) in c.iter().enumerate() {
                // SAFETY: the caller's array of eight.
                unsafe { *out.add(i) = *v };
            }
            0
        }
        None => -1,
    }
}
