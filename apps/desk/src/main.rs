// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The window manager `desk` (ports/desk): posix-crt, built with its feature
//! `window`, starts the layer and carries the functions of
//! `<stafeto/window.h>` and `<stafeto/manager.h>`; relibc starts the C `main`
//! in ports/desk/main.c. The two functions below are the C side's view of the
//! layer's heap, for the memory line of the probe.

#![no_std]
#![no_main]

use core::ffi::c_ulong;

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

/// The bytes the layer's heap took from the kernel so far.
#[unsafe(no_mangle)]
extern "C" fn desk_heap_bytes() -> c_ulong {
    posix_abi::allocation::probe_committed() as c_ulong
}

/// The pages of the room in objects of their own (the windows' buffers among
/// them).
#[unsafe(no_mangle)]
extern "C" fn desk_own_pages() -> c_ulong {
    posix_abi::allocation::probe_own_pages() as c_ulong
}
