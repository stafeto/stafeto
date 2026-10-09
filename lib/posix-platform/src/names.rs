// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The names of relibc's stafeto platform: unlink, mkdir and access as the
//! `*at` forms of Linux AArch64 (the values of AT_FDCWD and of the flags are
//! Linux's, as relibc's headers have them). Each returns 0 or a value, or the
//! negated errno.

use super::{call, files, value};
use core::ffi::{c_char, c_int};

/// The path of a C string, or the errno that is its answer.
macro_rules! path {
    ($pointer:expr) => {
        // SAFETY: the caller's promise, as of the C declaration.
        match unsafe { posix_abi::path($pointer) } {
            Ok(path) => path,
            Err(errno) => return -errno,
        }
    };
}

fn unit(result: Result<(), c_int>) -> c_int {
    value(result.map(|()| 0)) as c_int
}

/// unlink and rmdir (`flags` 0 or AT_REMOVEDIR).
///
/// # Safety
/// `path` is a live C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_unlinkat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
) -> c_int {
    let path = path!(path);
    unit(call(|| posix_abi::names::unlinkat(dirfd, path, flags)))
}

/// mkdir with the creation mask of the process.
///
/// # Safety
/// `path` is a live C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_mkdirat(dirfd: c_int, path: *const c_char, mode: u32) -> c_int {
    let path = path!(path);
    let mask = files::umask();
    unit(call(|| posix_abi::names::mkdirat(dirfd, path, mode, mask)))
}

/// access and faccessat (`flags` 0 or AT_EACCESS).
///
/// # Safety
/// `path` is a live C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_faccessat(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flags: c_int,
) -> c_int {
    let path = path!(path);
    unit(call(|| {
        posix_abi::names::faccessat(dirfd, path, mode, flags)
    }))
}
