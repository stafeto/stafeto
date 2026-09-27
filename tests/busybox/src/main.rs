// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Invoke BusyBox's dispatcher from the boot image.

#![no_std]
#![no_main]

#[cfg(any(
    all(feature = "ash-probe", feature = "ash-interactive"),
    all(feature = "ash-probe", feature = "ls-probe"),
    all(feature = "ash-interactive", feature = "ls-probe")
))]
compile_error!("choose one BusyBox probe");

use core::ffi::{c_char, c_int};
use rt::handle::Resource;

rt::entry!(main);

unsafe extern "C" {
    #[link_name = "main"]
    fn busybox_main(argc: c_int, argv: *const *const c_char) -> c_int;
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    #[cfg(feature = "ash-interactive")]
    let connected = posix_bridge::init_with_uart(&start.parent);
    #[cfg(not(feature = "ash-interactive"))]
    let connected = posix_bridge::init(&start.parent);
    if connected.is_err() {
        return 2;
    }
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
    // SAFETY: BusyBox and Picolibc are statically linked; argv has
    // NUL-terminated strings and a final null pointer.
    let code = unsafe { busybox_main((argv.len() - 1) as c_int, argv.as_ptr()) };
    if code == 0 {
        rt::println!("busybox-probe: ok");
    } else {
        rt::println!("busybox-probe: failed {code}");
    }
    code as u64
}
