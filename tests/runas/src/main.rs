// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `runas <uid> <path> [arguments]`: the group and then the user become `<uid>` (the group
//! first, since a process that is not the superuser cannot change it), and the program at
//! `<path>` replaces this one and runs with the arguments. The supplementary groups are emptied
//! first, so the program has the one group and the one user. It is a program of the probes
//! only (`cargo xtask pkg-probe` puts it at `/test/runas`): it shows what a program that is not
//! the superuser's gets from the package tool. It ends with 125 for a bad command line, 126
//! when an ID cannot be set and 127 when the program does not start, the codes a shell uses.

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int};

// The C library and the layer under it are linked for the symbols the start and `setuid` need.
use libc_ffi as _;
use posix_abi as _;
use rt as _;

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

unsafe extern "C" {
    fn setgroups(count: usize, list: *const u32) -> c_int;
    fn setgid(id: u32) -> c_int;
    fn setuid(id: u32) -> c_int;
    fn execv(path: *const c_char, argv: *const *mut c_char) -> c_int;
}

/// The decimal number in the NUL-terminated string `text`; None for anything else.
///
/// # Safety
/// `text` is a NUL-terminated string.
unsafe fn number(text: *const c_char) -> Option<u32> {
    // SAFETY: by the caller's promise.
    let bytes = unsafe { core::ffi::CStr::from_ptr(text).to_bytes() };
    if bytes.is_empty() || bytes.len() > 9 {
        return None;
    }
    let mut n = 0u32;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n * 10 + u32::from(b - b'0');
    }
    Some(n)
}

#[unsafe(no_mangle)]
extern "C" fn main(argc: isize, argv: *mut *mut c_char, _: *mut *mut c_char) -> c_int {
    if argc < 3 {
        return 125;
    }
    // SAFETY: relibc supplies `argc` live NUL-terminated strings and a NULL after them.
    unsafe {
        let Some(id) = number(*argv.add(1)) else {
            return 125;
        };
        // The supplementary groups of the superuser go first; the group and the user follow.
        if setgroups(0, core::ptr::null()) != 0 || setgid(id) != 0 || setuid(id) != 0 {
            return 126;
        }
        execv(*argv.add(2), argv.add(2) as *const *mut c_char);
    }
    127
}
