// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The producer of the probe of OpenWF Composition (wfc-producer.c) on relibc: posix-crt, built
//! with its feature `window`, starts the layer and carries the functions of
//! `<stafeto/window.h>`; relibc starts C.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

// The screen of the first revision (`<stafeto/display.h>`), which a static
// program has no C functions for: the role `s` opens it, draws a pattern and
// shows it, so that its window is a source of the first revision for a scene.

/// Opens the screen of the first revision: 0 and the address of its points in
/// `*pixels`, or the errno.
///
/// # Safety
/// `pixels` points to a writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wp_screen_open(pixels: *mut *mut core::ffi::c_void) -> i32 {
    match posix_abi::display::open() {
        Ok(screen) => {
            // SAFETY: the caller's pointer.
            unsafe { *pixels = screen.pixels as *mut core::ffi::c_void };
            0
        }
        Err(errno) => errno,
    }
}

/// Shows the first `rows` lines of the screen of the first revision: 0 or the
/// errno.
#[unsafe(no_mangle)]
pub extern "C" fn wp_screen_flush(rows: u32) -> i32 {
    posix_abi::display::flush(0, 0, 640, rows)
        .err()
        .unwrap_or(0)
}
