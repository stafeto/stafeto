// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C functions of the windows of the composition service
//! (`<stafeto/window.h>`, `lib/posix-crt/window/stafeto/window.h`), behind
//! the feature `window`: a statically linked program turns it on, and
//! libc.so is built without it. Each is the layer's call
//! (`posix_abi::window`) with the errno set as C expects: 0, a count or
//! the window's number, or -1 with errno. The layouts of the structures are
//! `comp_client::layout`, which holds the same assertions as the header. The
//! manager's calls (`<stafeto/manager.h>`) are at the end of the file.

use comp_client::layout::{self, Rect, Screen, Window, WindowEvent};
use comp_client::manager::{ManagerInfo, ManagerWindow};
use comp_client::table;
use core::ffi::{c_char, c_int};
use posix_abi::constants::EINVAL;
use posix_abi::window;

unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}

fn fail(errno: i32) -> c_int {
    // SAFETY: relibc's errno of this thread.
    unsafe { *__errno_location() = errno };
    -1
}

/// Describes the screen.
///
/// # Safety
/// `s` is null or points to a writable `struct stafeto_screen`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_screen_describe(s: *mut Screen) -> c_int {
    if s.is_null() {
        return fail(EINVAL);
    }
    match window::screen() {
        Ok(screen) => {
            // SAFETY: the caller's pointer, checked for null.
            unsafe { s.write(screen) };
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Makes the window and describes it in `*out`: the window's number.
///
/// # Safety
/// `out` is null or points to a writable `struct stafeto_window`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_window_open(
    x: c_int,
    y: c_int,
    w: c_int,
    h: c_int,
    format: u32,
    buffers: u32,
    flags: u32,
    out: *mut Window,
) -> c_int {
    if out.is_null() {
        return fail(EINVAL);
    }
    match window::open(x, y, w, h, format, buffers, flags) {
        Ok((number, opened)) => {
            // SAFETY: the caller's pointer, checked for null.
            unsafe { out.write(opened) };
            number
        }
        Err(errno) => fail(errno),
    }
}

/// Describes the open window `win` in `*out`, as `stafeto_window_open` did.
///
/// # Safety
/// `out` is null or points to a writable `struct stafeto_window`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_window_info(win: c_int, out: *mut Window) -> c_int {
    if out.is_null() {
        return fail(EINVAL);
    }
    match window::info(win) {
        Ok(described) => {
            // SAFETY: the caller's pointer, checked for null.
            unsafe { out.write(described) };
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Posts `buffer` with the `count` rectangles `r` (none: the whole window).
///
/// # Safety
/// `r` is null or points to `count` `struct stafeto_rect`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_window_post(
    win: c_int,
    buffer: u32,
    r: *const Rect,
    count: u32,
) -> c_int {
    let rects: &[Rect] = if count == 0 {
        &[]
    } else if r.is_null() {
        return fail(EINVAL);
    } else {
        // SAFETY: the caller gives `count` rectangles.
        unsafe { core::slice::from_raw_parts(r, count as usize) }
    };
    match window::post(win, buffer, rects) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// The buffers the library counts free, as a mask.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_window_free_buffers(win: c_int) -> u32 {
    window::free(win)
}

/// Waits for a bit of the service; `*bits` (null allowed) gets the bits.
///
/// # Safety
/// `bits` is null or points to a writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_window_wait(win: c_int, timeout_ns: u64, bits: *mut u32) -> c_int {
    match window::wait(win, timeout_ns) {
        Ok(got) => {
            if !bits.is_null() {
                // SAFETY: the caller's pointer, checked for null.
                unsafe { bits.write(got) };
            }
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Waits until a buffer of `mask` is free; `*free` (null allowed) gets the
/// free ones among them. The bits of the service stay for
/// `stafeto_window_wait`.
///
/// # Safety
/// `free` is null or points to a writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_window_wait_free(
    win: c_int,
    mask: u32,
    timeout_ns: u64,
    free: *mut u32,
) -> c_int {
    match window::wait_free(win, mask, timeout_ns) {
        Ok(got) => {
            if !free.is_null() {
                // SAFETY: the caller's pointer, checked for null.
                unsafe { free.write(got) };
            }
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Takes up to `max` events without waiting: the count.
///
/// # Safety
/// `e` is null or points to room for `max` events, `flags` is null or
/// points to a writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_window_events(
    win: c_int,
    e: *mut WindowEvent,
    max: c_int,
    flags: *mut u32,
) -> c_int {
    if e.is_null() || max <= 0 {
        return fail(EINVAL);
    }
    // SAFETY: the caller gives room for `max` events.
    let out = unsafe { core::slice::from_raw_parts_mut(e, max as usize) };
    match window::events(win, out) {
        Ok((count, lost)) => {
            if !flags.is_null() {
                // SAFETY: the caller's pointer, checked for null.
                unsafe { flags.write(lost) };
            }
            count as c_int
        }
        Err(errno) => fail(errno),
    }
}

/// Waits until the frame of the last post is on the screen.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_window_shown(win: c_int, timeout_ns: u64) -> c_int {
    match window::shown(win, timeout_ns) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Closes the window.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_window_close(win: c_int) -> c_int {
    match window::close(win) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Waits for the bits of any window of the process; `bits[k]` gets window
/// k's bits (0 for the windows with none) and the call returns the mask of
/// the windows that have some.
///
/// # Safety
/// `bits` is null or points to eight writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_windows_wait(timeout_ns: u64, bits: *mut u32) -> c_int {
    let mut got = [0u32; table::WINDOWS_MAX];
    match window::wait_all(timeout_ns, &mut got) {
        Ok(mask) => {
            if !bits.is_null() {
                // SAFETY: the caller gives room for eight words.
                unsafe { core::ptr::copy_nonoverlapping(got.as_ptr(), bits, got.len()) };
            }
            mask as c_int
        }
        Err(errno) => fail(errno),
    }
}

/// Gives the window a title (a C string of at most 64 bytes).
///
/// # Safety
/// `title` is null or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_window_set_title(win: c_int, title: *const c_char) -> c_int {
    set_text(win, layout::TEXT_TITLE, title)
}

/// Gives the window the kind of its program (a C string of at most 64
/// bytes).
///
/// # Safety
/// `app_id` is null or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_window_set_app_id(win: c_int, app_id: *const c_char) -> c_int {
    set_text(win, layout::TEXT_APP, app_id)
}

fn set_text(win: c_int, which: u32, text: *const c_char) -> c_int {
    if text.is_null() {
        return fail(EINVAL);
    }
    // SAFETY: the caller's string, checked for null. A string past the longest
    // text is cut one byte past it, which the layer refuses.
    let bytes = unsafe {
        let mut len = 0;
        while len <= layout::TEXT_MAX && *text.add(len) != 0 {
            len += 1;
        }
        core::slice::from_raw_parts(text.cast::<u8>(), len)
    };
    match window::set_text(win, which, bytes) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Changes the window's size inside its capacity: the size of the next post.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_window_resize(win: c_int, w: u32, h: u32, serial: u32) -> c_int {
    match window::resize(win, w, h, serial) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// The most width and height `stafeto_window_resize` takes.
///
/// # Safety
/// `w` and `h` are null or point to a writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_window_capacity(win: c_int, w: *mut u32, h: *mut u32) -> c_int {
    match window::capacity(win) {
        Ok((cap_w, cap_h)) => {
            // SAFETY: the caller's pointers, checked for null.
            unsafe {
                if !w.is_null() {
                    w.write(cap_w);
                }
                if !h.is_null() {
                    h.write(cap_h);
                }
            }
            0
        }
        Err(errno) => fail(errno),
    }
}

// ---------------------------------------------------------------- the manager

/// Subscribes the process to the manager's ring of events.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_manager_subscribe() -> c_int {
    match window::subscribe() {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Takes up to `max` events of the manager's ring without waiting: the count.
///
/// # Safety
/// `e` is null or points to room for `max` events, `flags` is null or points
/// to a writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_manager_events(
    e: *mut WindowEvent,
    max: c_int,
    flags: *mut u32,
) -> c_int {
    if e.is_null() || max <= 0 {
        return fail(EINVAL);
    }
    // SAFETY: the caller gives room for `max` events.
    let out = unsafe { core::slice::from_raw_parts_mut(e, max as usize) };
    match window::manager_events(out) {
        Ok((count, lost)) => {
            if !flags.is_null() {
                // SAFETY: the caller's pointer, checked for null.
                unsafe { flags.write(lost) };
            }
            count as c_int
        }
        Err(errno) => fail(errno),
    }
}

/// Lists the windows, the lowest in the order of depth first: the count.
///
/// # Safety
/// `w` is null or points to room for `max` records.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_manager_list(w: *mut ManagerWindow, max: c_int) -> c_int {
    if w.is_null() || max <= 0 {
        return fail(EINVAL);
    }
    // SAFETY: the caller gives room for `max` records.
    let out = unsafe { core::slice::from_raw_parts_mut(w, max as usize) };
    match window::manager_list(out) {
        Ok(count) => count as c_int,
        Err(errno) => fail(errno),
    }
}

/// Describes window `id` in `*out`.
///
/// # Safety
/// `out` is null or points to a writable `struct stafeto_manager_info`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_manager_info(id: u32, out: *mut ManagerInfo) -> c_int {
    if out.is_null() {
        return fail(EINVAL);
    }
    match window::manager_info(id) {
        Ok(described) => {
            // SAFETY: the caller's pointer, checked for null.
            unsafe { out.write(described) };
            0
        }
        Err(errno) => fail(errno),
    }
}

fn done(result: Result<(), i32>) -> c_int {
    match result {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Moves window `id` to (`x`, `y`).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_manager_move(id: u32, x: u32, y: u32) -> c_int {
    done(window::move_to(id, x, y))
}

/// Raises window `id` to the top.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_manager_raise(id: u32) -> c_int {
    done(window::raise(id))
}

/// Gives window `id` the keyboard's focus.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_manager_focus(id: u32) -> c_int {
    done(window::focus(id))
}

/// Shows (`shown` not 0) or hides window `id`.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_manager_visible(id: u32, shown: c_int) -> c_int {
    done(window::visible(id, shown != 0))
}

/// Asks window `id` for a size and states.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_manager_configure(id: u32, w: u32, h: u32, states: u32) -> c_int {
    done(window::configure(id, w, h, states))
}

/// Asks window `id` to close itself.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_manager_close(id: u32) -> c_int {
    done(window::manager_close(id))
}

/// Ties window `follower` (one of the manager's own) to window `leader`.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_manager_link(leader: u32, follower: u32) -> c_int {
    done(window::link(leader, follower))
}

/// The service's number of the process's open window `win`.
///
/// # Safety
/// `id` is null or points to a writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_window_id(win: c_int, id: *mut u32) -> c_int {
    if id.is_null() {
        return fail(EINVAL);
    }
    match window::window_id(win) {
        Ok(number) => {
            // SAFETY: the caller's pointer, checked for null.
            unsafe { id.write(number) };
            0
        }
        Err(errno) => fail(errno),
    }
}
