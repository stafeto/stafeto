// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! AArch64 LP64 stat layout and checked conversion from file-service metadata.

use crate::{constants::*, fail, fd, path};
use core::ffi::{c_char, c_int};
use posix_fs::NodeInfo;
use posix_request::Request;

pub use posix_types::{Stat, Timespec};

unsafe fn store(result: Result<NodeInfo, c_int>, out: *mut Stat) -> c_int {
    let result = result.and_then(|info| {
        Stat::try_from(info).map_err(|error| match error {
            posix_types::ConversionError::Malformed => EIO,
            posix_types::ConversionError::Overflow => EOVERFLOW,
        })
    });
    match result {
        Ok(stat) => {
            // SAFETY: entry points checked null; the caller supplies one aligned Stat.
            unsafe { out.write(stat) };
            0
        }
        Err(error) => fail(error) as c_int,
    }
}

/// # Safety
/// name is a live C string, out is writable/aligned for Stat, and this thread
/// has an initialized ABI scope. On error the destination is left untouched.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn stat(name: *const c_char, out: *mut Stat) -> c_int {
    if out.is_null() {
        return fail(EFAULT) as c_int;
    }
    let result =
        unsafe { path(name) }.and_then(|path| crate::shared::information(Request::Stat { path }));
    unsafe { store(result, out) }
}

/// # Safety
/// Same contract as stat. The current RAM namespace contains no symbolic links;
/// final-component no-follow resolution must be extended when links are added.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn lstat(name: *const c_char, out: *mut Stat) -> c_int {
    unsafe { stat(name, out) }
}

/// # Safety
/// out is writable/aligned for Stat; this thread has an initialized ABI scope.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn fstat(number: c_int, out: *mut Stat) -> c_int {
    if out.is_null() {
        return fail(EFAULT) as c_int;
    }
    let result = fd(number).and_then(|fd| crate::shared::information(Request::Fstat { fd }));
    unsafe { store(result, out) }
}
