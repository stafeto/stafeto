// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The names and metadata of relibc's stafeto platform: unlink, mkdir,
//! rename, link, symlink, readlink, chmod, chown, access and utimens as the
//! `*at` forms of Linux AArch64 (the values of AT_FDCWD and of the flags are
//! Linux's, as relibc's headers have them). Each returns 0 or a value, or the
//! negated errno. `fchmod`, `fchown` and `futimens` are the `*at` calls with an
//! empty path and AT_EMPTY_PATH.

use super::{call, files, value};
use core::ffi::{c_char, c_int};
use posix_abi::constants::{EFAULT, ERANGE};
use posix_abi::names::Time;

/// relibc's struct timespec on AArch64 Linux.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinuxTimespec {
    seconds: i64,
    nanos: i64,
}
const _: () = {
    assert!(core::mem::size_of::<LinuxTimespec>() == 16);
};

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

/// rename and renameat.
///
/// # Safety
/// `old` and `new` are live C strings or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_renameat(
    old_dirfd: c_int,
    old: *const c_char,
    new_dirfd: c_int,
    new: *const c_char,
) -> c_int {
    let old = path!(old);
    let new = path!(new);
    unit(call(|| {
        posix_abi::names::renameat(old_dirfd, old, new_dirfd, new)
    }))
}

/// link and linkat (`flags` 0 or AT_SYMLINK_FOLLOW).
///
/// # Safety
/// `old` and `new` are live C strings or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_linkat(
    old_dirfd: c_int,
    old: *const c_char,
    new_dirfd: c_int,
    new: *const c_char,
    flags: c_int,
) -> c_int {
    let old = path!(old);
    let new = path!(new);
    unit(call(|| {
        posix_abi::names::linkat(old_dirfd, old, new_dirfd, new, flags)
    }))
}

/// symlink and symlinkat.
///
/// # Safety
/// `target` and `linkpath` are live C strings or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_symlinkat(
    target: *const c_char,
    new_dirfd: c_int,
    linkpath: *const c_char,
) -> c_int {
    let target = path!(target);
    let linkpath = path!(linkpath);
    unit(call(|| {
        posix_abi::names::symlinkat(target, new_dirfd, linkpath)
    }))
}

/// readlink and readlinkat: the bytes of the link, no NUL.
///
/// # Safety
/// `path` is a live C string or null; `buf` is writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_readlinkat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut u8,
    len: usize,
) -> isize {
    if buf.is_null() {
        return -(EFAULT as isize);
    }
    // SAFETY: the caller's promise.
    let path = match unsafe { posix_abi::path(path) } {
        Ok(path) => path,
        Err(errno) => return -(errno as isize),
    };
    // SAFETY: the caller's promise.
    let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    value(call(|| posix_abi::names::readlinkat(dirfd, path, out)).map(|n| n as i64)) as isize
}

/// chmod, fchmod and fchmodat (`flags`: AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH).
///
/// # Safety
/// `path` is a live C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_fchmodat(
    dirfd: c_int,
    path: *const c_char,
    mode: u32,
    flags: c_int,
) -> c_int {
    let path = path!(path);
    unit(call(|| {
        posix_abi::names::fchmodat(dirfd, path, mode, flags)
    }))
}

/// chown, lchown, fchown and fchownat (an ID of -1 keeps the field).
///
/// # Safety
/// `path` is a live C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_fchownat(
    dirfd: c_int,
    path: *const c_char,
    uid: u32,
    gid: u32,
    flags: c_int,
) -> c_int {
    let path = path!(path);
    unit(call(|| {
        posix_abi::names::fchownat(dirfd, path, uid, gid, flags)
    }))
}

/// utimensat and futimens: `times` points at two timespecs, null for now.
///
/// # Safety
/// `path` is a live C string or null; `times` is null or readable for two
/// timespecs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_utimensat(
    dirfd: c_int,
    path: *const c_char,
    times: *const LinuxTimespec,
    flags: c_int,
) -> c_int {
    let path = path!(path);
    let times = (!times.is_null()).then(|| {
        // SAFETY: the caller's promise.
        let pair = unsafe { core::slice::from_raw_parts(times, 2) };
        [pair[0], pair[1]].map(|time| Time {
            seconds: time.seconds,
            nanos: time.nanos,
        })
    });
    unit(call(|| {
        posix_abi::names::utimensat(dirfd, path, times, flags)
    }))
}

/// fstatvfs and statvfs in relibc's struct statvfs (eleven unsigned long).
#[repr(C)]
pub struct LinuxStatvfs {
    words: [u64; 11],
}
const _: () = {
    assert!(core::mem::size_of::<LinuxStatvfs>() == 88);
};

/// statvfs of a path.
///
/// # Safety
/// `path` is a live C string or null; `out` is writable for a LinuxStatvfs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_statvfs(path: *const c_char, out: *mut LinuxStatvfs) -> c_int {
    if out.is_null() {
        return -EFAULT;
    }
    let path = path!(path);
    match call(|| posix_abi::names::statvfs(path)) {
        Ok(words) => {
            // SAFETY: the caller's promise.
            unsafe { out.write(LinuxStatvfs { words }) };
            0
        }
        Err(errno) => -errno,
    }
}

/// fstatvfs of a descriptor.
///
/// # Safety
/// `out` is writable for a LinuxStatvfs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_fstatvfs(fd: c_int, out: *mut LinuxStatvfs) -> c_int {
    if out.is_null() {
        return -EFAULT;
    }
    match call(|| posix_abi::names::fstatvfs(fd)) {
        Ok(words) => {
            // SAFETY: the caller's promise.
            unsafe { out.write(LinuxStatvfs { words }) };
            0
        }
        Err(errno) => -errno,
    }
}

/// fchdir: the current directory becomes the directory `fd` names.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fchdir(fd: c_int) -> c_int {
    unit(call(|| posix_abi::names::fchdir(fd)))
}

/// realpath: the canonical path of `path` into `buf`, with its NUL; its
/// length, or the negated errno. `len` is the size of the buffer: ERANGE
/// when the path and its NUL do not fit.
///
/// # Safety
/// `path` is a live C string or null; `buf` is writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_realpath(path: *const c_char, buf: *mut u8, len: usize) -> isize {
    if buf.is_null() {
        return -(EFAULT as isize);
    }
    // SAFETY: the caller's promise.
    let path = match unsafe { posix_abi::path(path) } {
        Ok(path) => path,
        Err(errno) => return -(errno as isize),
    };
    let mut canonical = [0; posix_abi::names::MAX_PATH + 1];
    let length = match call(|| posix_abi::names::realpath(path, &mut canonical)) {
        Ok(length) => length,
        Err(errno) => return -(errno as isize),
    };
    if length >= len {
        return -(ERANGE as isize);
    }
    // SAFETY: the caller's promise: `len` bytes, and `length < len`.
    let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    out[..length].copy_from_slice(&canonical[..length]);
    out[length] = 0;
    length as isize
}
