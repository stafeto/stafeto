// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The program init starts for the probe of the screen and the keys
//! (`cargo xtask display-probe`), and the helper the probe starts.
//!
//! * `display-run ROLE`: spawns `/bin/display-probe ROLE`, the dynamic C
//!   program on libc.so (tests/posix-so/dyn/display-probe.c), waits for it
//!   and ends with its status. A program init starts has no code of its
//!   own to fork, one of the loader has.
//! * `display-run crash`: sends CRASH on the process's `Display` session,
//!   which the display service of the probe's image answers by ending with
//!   a fault. The C probe starts it to see its calls refused afterwards.

#![no_std]
#![no_main]

use core::ffi::{CStr, c_char, c_int};
use rt::handle::{Channel, Handle};

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

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

/// Starts the probe in `role` and waits: its exit status, 128 plus the
/// signal that ended it, or 125 when it did not start.
fn run_probe(role: &CStr) -> c_int {
    const EINTR: c_int = 4;
    let argv = [c"display-probe".as_ptr(), role.as_ptr(), core::ptr::null()];
    let mut pid: c_int = 0;
    // SAFETY: the path and the arguments are NUL-terminated and live on;
    // no file actions or attributes (null); environ is relibc's.
    let started = unsafe {
        posix_spawn(
            &mut pid,
            c"/bin/display-probe".as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            argv.as_ptr(),
            environ,
        )
    };
    if started != 0 {
        rt::println!("display-run: cannot start the probe: error {started}");
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

/// CRASH to the display service through the process's session.
fn crash() -> c_int {
    let Some(session) = posix_abi::display::session() else {
        rt::println!("display-run: no session with the display service");
        return 1;
    };
    // The service ends on the request and never answers: the channel's end
    // is the answer.
    match rt::sys::send(
        &Handle::<Channel>::borrowed(session),
        &proto_gpu::Method::Crash.header().bytes(),
    ) {
        Err(_) => 0,
        Ok(_) => {
            rt::println!("display-run: the display service answered CRASH");
            2
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn main(argc: isize, argv: *mut *mut c_char, _envp: *mut *mut c_char) -> c_int {
    let role = if argc > 1 {
        // SAFETY: relibc gives `argc` NUL-terminated arguments.
        unsafe { CStr::from_ptr(*argv.add(1)) }
    } else {
        c"run"
    };
    if role == c"crash" {
        crash()
    } else {
        run_probe(role)
    }
}
