// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! BusyBox on relibc: the probe's C main invokes BusyBox's dispatcher.

#![no_std]
#![no_main]

#[cfg(any(
    all(feature = "ash-probe", feature = "ash-interactive"),
    all(feature = "ash-probe", feature = "ls-probe"),
    all(feature = "ash-interactive", feature = "ls-probe")
))]
compile_error!("choose one BusyBox probe");

use core::ffi::{c_char, c_int};

// posix-crt starts the process and hands the thread to relibc, which calls
// `main` below.
#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

unsafe extern "C" {
    /// BusyBox's main, renamed when tools/build-busybox.py compiles it.
    fn busybox_main(argc: c_int, argv: *const *const c_char) -> c_int;
}

/// The probe's C main: the applet and its arguments of the build's
/// feature, then BusyBox's dispatcher.
#[unsafe(no_mangle)]
extern "C" fn main(_: isize, _: *mut *mut c_char, _: *mut *mut c_char) -> c_int {
    #[cfg(not(any(
        feature = "ash-probe",
        feature = "ash-interactive",
        feature = "ls-probe"
    )))]
    let argv = [
        c"busybox".as_ptr(),
        c"cat".as_ptr(),
        c"/etc/motd".as_ptr(),
        core::ptr::null(),
    ];
    #[cfg(feature = "ash-probe")]
    let argv = [
        c"busybox".as_ptr(),
        c"ash".as_ptr(),
        c"-c".as_ptr(),
        c"echo shell-ready; exit 0".as_ptr(),
        core::ptr::null(),
    ];
    #[cfg(feature = "ash-interactive")]
    let argv = [
        c"busybox".as_ptr(),
        c"ash".as_ptr(),
        c"-i".as_ptr(),
        core::ptr::null(),
    ];
    #[cfg(feature = "ls-probe")]
    let argv = [
        c"busybox".as_ptr(),
        c"ls".as_ptr(),
        c"-1".as_ptr(),
        c"/".as_ptr(),
        c"/etc".as_ptr(),
        core::ptr::null(),
    ];
    // SAFETY: BusyBox and relibc are statically linked; argv has
    // NUL-terminated strings and a final null pointer.
    let code = unsafe { busybox_main((argv.len() - 1) as c_int, argv.as_ptr()) };
    if code == 0 {
        rt::println!("busybox-probe: ok");
    } else {
        rt::println!("busybox-probe: failed {code}");
    }
    code
}
