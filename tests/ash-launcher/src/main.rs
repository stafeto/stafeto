// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The program init starts for the shell image. It spawns `/bin/busybox` as
//! the dialog's getty (5f; a program init starts has no code of its own to
//! fork, one of the loader has), whose file is the one copy of BusyBox in the
//! image, and waits for it. The getty makes a session of its own, opens the
//! console, which becomes the session's controlling terminal with the
//! getty's group in its foreground, puts it in descriptors 0, 1 and 2, sets
//! `TERM` and execs `/bin/ash -i`; the launcher, in another session, waits
//! for it. INTR at the console so reaches the shell and its commands and
//! never the launcher.

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int};

// posix-crt starts the process and hands the thread to relibc, which calls
// `main` below.
#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

/// The first argument of the getty (BusyBox's own, tests/busybox).
const GETTY: &core::ffi::CStr = c"ash-getty";

unsafe extern "C" {
    fn posix_spawn(
        pid: *mut c_int,
        path: *const c_char,
        actions: *const core::ffi::c_void,
        attr: *const core::ffi::c_void,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn __errno_location() -> *mut c_int;
    static environ: *const *const c_char;
}

/// Starts the getty, which becomes the shell, and waits for it: its exit
/// status, 128 plus the signal that ended it, or 125 when it did not
/// start.
fn launch_ash() -> c_int {
    const EINTR: c_int = 4;
    let argv = [GETTY.as_ptr(), core::ptr::null()];
    let mut pid: c_int = 0;
    // SAFETY: the path and the arguments are NUL-terminated and live on;
    // no file actions or attributes (null); environ is relibc's.
    let started = unsafe {
        posix_spawn(
            &mut pid,
            c"/bin/busybox".as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            argv.as_ptr(),
            environ,
        )
    };
    if started != 0 {
        rt::println!("ash-launch: cannot start the getty: error {started}");
        return 125;
    }
    let mut status: c_int = 0;
    // SAFETY: `status` is writable and `pid` is the child of this process.
    while unsafe { waitpid(pid, &mut status, 0) } < 0 {
        // SAFETY: relibc's errno of this thread.
        if unsafe { *__errno_location() } != EINTR {
            return 125;
        }
    }
    if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        128 + (status & 0x7f)
    }
}

#[unsafe(no_mangle)]
extern "C" fn main(_argc: isize, _argv: *mut *mut c_char, _envp: *mut *mut c_char) -> c_int {
    launch_ash()
}
