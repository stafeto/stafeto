// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C functions of the screen and the keys, exported from libc.so
//! (sub-project 3, part 3b; spec 3, 3.7; `<stafeto/display.h>`). Each is
//! the layer's call (`posix_abi::display`) with the errno set as C expects:
//! 0 or the count, or -1 with errno.

use core::ffi::{c_int, c_void};
use posix_abi::display;

unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}

fn fail(errno: i32) -> c_int {
    // SAFETY: relibc's errno of this thread.
    unsafe { *__errno_location() = errno };
    -1
}

/// `struct stafeto_display` of the header.
#[repr(C)]
pub struct Description {
    width: u32,
    height: u32,
    stride: u32,
    format: u32,
    pixels: *mut c_void,
}

const _: () = {
    // The layouts of `struct stafeto_display` and `struct stafeto_key` of
    // the header.
    assert!(core::mem::size_of::<Description>() == 24);
    assert!(core::mem::align_of::<Description>() == 8);
    assert!(core::mem::size_of::<display::Key>() == 8);
    assert!(core::mem::align_of::<display::Key>() == 4);
};

/// Opens the screen of the process and describes it. A process that has
/// it gets the same description again.
///
/// # Safety
/// `d` is null or points to a writable `struct stafeto_display`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_display_open(d: *mut Description) -> c_int {
    if d.is_null() {
        return fail(posix_abi::constants::EINVAL);
    }
    match display::open() {
        Ok(screen) => {
            // SAFETY: the caller's pointer, checked for null.
            unsafe {
                d.write(Description {
                    width: screen.width,
                    height: screen.height,
                    stride: screen.stride,
                    format: screen.format,
                    pixels: screen.pixels as *mut c_void,
                })
            };
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Shows the rectangle (x, y, w, h) of the screen and waits for the show.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_display_flush(x: c_int, y: c_int, w: c_int, h: c_int) -> c_int {
    let (Ok(x), Ok(y), Ok(w), Ok(h)) = (
        u32::try_from(x),
        u32::try_from(y),
        u32::try_from(w),
        u32::try_from(h),
    ) else {
        return fail(posix_abi::constants::EINVAL);
    };
    match display::flush(x, y, w, h) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Reads up to `max` key events without waiting: the count, 0 for none.
///
/// # Safety
/// `k` is null or points to room for `max` events.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_input_read(k: *mut display::Key, max: c_int) -> c_int {
    if k.is_null() || max <= 0 {
        return fail(posix_abi::constants::EINVAL);
    }
    // SAFETY: the caller gives room for `max` events.
    let out = unsafe { core::slice::from_raw_parts_mut(k, max as usize) };
    match display::input_read(out) {
        Ok(count) => count as c_int,
        Err(errno) => fail(errno),
    }
}

/// Closes the screen and gives it back.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_display_close() -> c_int {
    match display::close() {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}
