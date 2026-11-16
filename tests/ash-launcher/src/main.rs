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
//!
//! With the feature `dropbear` it also starts the SSH server of the package
//! `dropbear` (`/bin/dropbear -F -R -s -j -k`) and starts it again a second
//! after it ends: it ends at once while the network service has no address
//! to listen on.

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

/// The SSH server: in the foreground (`-F`, the launcher is its parent), host
/// keys made when first needed (`-R`), no password login at all (`-s`), no
/// local or remote port forwarding (`-j`, `-k`). It is built without syslog,
/// so its log goes to the standard error and the option `-E` does not exist.
#[cfg(feature = "dropbear")]
const DROPBEAR: &[&core::ffi::CStr] = &[c"dropbear", c"-F", c"-R", c"-s", c"-j", c"-k"];
/// The same words as one line, which the launcher prints (`/proc/<pid>/cmdline`
/// holds the name of the program alone); xtask's `net-ssh` reads it.
#[cfg(feature = "dropbear")]
const DROPBEAR_LINE: &str = "dropbear -F -R -s -j -k";

#[cfg(feature = "dropbear")]
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[cfg(feature = "dropbear")]
unsafe extern "C" {
    fn nanosleep(request: *const Timespec, remaining: *mut Timespec) -> c_int;
}

/// The one-second wait before the server starts again.
#[cfg(feature = "dropbear")]
fn pause() {
    let request = Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    // SAFETY: `request` is readable; the remaining time is not asked for. A
    // signal that cuts the wait short only starts the server a little early.
    unsafe { nanosleep(&request, core::ptr::null_mut()) };
}

/// Starts `path` with `arguments` (the first is the name it runs under):
/// its process number, or the error of `posix_spawn`.
fn spawn(path: &core::ffi::CStr, arguments: &[&core::ffi::CStr]) -> Result<c_int, c_int> {
    let mut argv = [core::ptr::null::<c_char>(); 9];
    for (slot, argument) in argv.iter_mut().zip(arguments) {
        *slot = argument.as_ptr();
    }
    let mut pid: c_int = 0;
    // SAFETY: the path and the arguments are NUL-terminated and live on, the
    // list ends in a null pointer (there are at most 8 arguments); no file
    // actions or attributes (null); environ is relibc's.
    let started = unsafe {
        posix_spawn(
            &mut pid,
            path.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            argv.as_ptr(),
            environ,
        )
    };
    if started == 0 { Ok(pid) } else { Err(started) }
}

/// Starts the getty, which becomes the shell, and waits for it: its exit
/// status, 128 plus the signal that ended it, or 125 when it did not
/// start.
fn launch_ash() -> c_int {
    const EINTR: c_int = 4;
    // The console of a machine like EC2 shows complete lines only, and the
    // prompt has none: this line says that the shell is on its way.
    rt::println!("ash-launch: ash on tty");
    let pid = match spawn(c"/bin/busybox", &[GETTY]) {
        Ok(pid) => pid,
        Err(error) => {
            rt::println!("ash-launch: cannot start the getty: error {error}");
            return 125;
        }
    };
    #[cfg(feature = "dropbear")]
    let mut server = start_server();
    let mut status: c_int = 0;
    // The getty alone, or any child when the server runs beside it.
    let wanted = if cfg!(feature = "dropbear") { -1 } else { pid };
    loop {
        // SAFETY: `status` is writable; `wanted` is a child of this process or -1.
        let ended = unsafe { waitpid(wanted, &mut status, 0) };
        if ended < 0 {
            // SAFETY: relibc's errno of this thread.
            if unsafe { *__errno_location() } != EINTR {
                return 125;
            }
            continue;
        }
        if ended == pid {
            break;
        }
        #[cfg(feature = "dropbear")]
        if ended == server {
            pause();
            server = start_server();
        }
    }
    if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        128 + (status & 0x7f)
    }
}

/// Starts the SSH server: its process number, or 0 when it did not start (the
/// launcher then never sees it end and does not try again).
#[cfg(feature = "dropbear")]
fn start_server() -> c_int {
    rt::println!("ash-launch: {DROPBEAR_LINE}");
    match spawn(c"/bin/dropbear", DROPBEAR) {
        Ok(pid) => pid,
        Err(error) => {
            rt::println!("ash-launch: cannot start dropbear: error {error}");
            0
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn main(_argc: isize, _argv: *mut *mut c_char, _envp: *mut *mut c_char) -> c_int {
    launch_ash()
}
