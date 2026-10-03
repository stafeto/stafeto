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

#[cfg(all(feature = "ash-interactive", not(feature = "applets")))]
compile_error!("the ash dialog's launcher is a mode of the applets build");

use core::ffi::{c_char, c_int};

// posix-crt starts the process and hands the thread to relibc, which calls
// `main` below.
#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

unsafe extern "C" {
    /// BusyBox's main, renamed when tools/build-busybox.py compiles it.
    fn busybox_main(argc: c_int, argv: *const *const c_char) -> c_int;
}

/// The first argument of the launcher: the program init starts for the
/// dialog (its record's own arguments). It starts `/bin/ash` as a POSIX
/// process from its file, the way every child starts, with the console
/// it reads and writes, and waits for it.
#[cfg(feature = "ash-interactive")]
const LAUNCHER: &core::ffi::CStr = c"ash-launch";

#[cfg(feature = "ash-interactive")]
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

/// Starts `/bin/ash -i` and waits for it: its exit status, 128 plus the
/// signal that ended it, or 125 when it did not start.
#[cfg(feature = "ash-interactive")]
fn launch_ash() -> c_int {
    const EINTR: c_int = 4;
    let argv = [c"ash".as_ptr(), c"-i".as_ptr(), core::ptr::null()];
    let mut pid: c_int = 0;
    // SAFETY: the path and the arguments are NUL-terminated and live on;
    // no file actions or attributes (null); relibc's environ is the
    // process's environment.
    let started = unsafe {
        posix_spawn(
            &mut pid,
            c"/bin/ash".as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            argv.as_ptr(),
            environ,
        )
    };
    if started != 0 {
        rt::println!("ash-launch: cannot start /bin/ash: error {started}");
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

/// BusyBox's dispatcher with the program's own arguments.
#[cfg(feature = "applets")]
#[unsafe(no_mangle)]
extern "C" fn main(argc: isize, argv: *mut *mut c_char, _: *mut *mut c_char) -> c_int {
    #[cfg(feature = "ash-interactive")]
    // SAFETY: relibc's start gives argc strings, so argv[0] exists when
    // argc is above 0.
    if argc > 0 && unsafe { core::ffi::CStr::from_ptr(*argv) } == LAUNCHER {
        return launch_ash();
    }
    // SAFETY: relibc's start gives argv with argc strings and a final null
    // pointer; BusyBox's dispatcher takes the applet from argv[0].
    unsafe { busybox_main(argc as c_int, argv.cast()) }
}

/// The probe's C main: the applet and its arguments of the build's
/// feature, then BusyBox's dispatcher.
#[cfg(not(feature = "applets"))]
#[unsafe(no_mangle)]
extern "C" fn main(_: isize, _: *mut *mut c_char, _: *mut *mut c_char) -> c_int {
    #[cfg(not(any(feature = "ash-probe", feature = "ls-probe")))]
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
