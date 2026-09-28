// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Experimental C file ABI 1 and startup, backed entirely by Rust. Entry points
//! require the initialized current-thread scope. The C caller supplies live,
//! properly sized buffers; null pointers are reported as EFAULT. No Picolibc.

#![no_std]

pub mod allocation;
pub mod constants;
pub mod directory;
pub mod locale;
pub mod metadata;
pub mod ordering;
pub mod scan;
pub mod shared;
pub mod tls;

use constants::*;
use core::ffi::{c_char, c_int};
use core::ptr;
use posix_fs::{DescriptorFlags, FsError, PosixFs, SeekFrom};

const _: () = {
    assert!(core::mem::size_of::<usize>() == 8);
    assert!(core::mem::size_of::<core::ffi::c_long>() == 8);
    assert!(core::mem::size_of::<c_int>() == 4);
};

fn error(error: FsError) -> c_int {
    match error {
        FsError::NoEntry => ENOENT,
        FsError::PermissionDenied => EACCES,
        FsError::BadFileDescriptor => EBADF,
        FsError::IsDirectory => EISDIR,
        FsError::NotDirectory => ENOTDIR,
        FsError::NoSpace => ENOSPC,
        FsError::TooManyOpenFiles => EMFILE,
        FsError::NotSeekable => ESPIPE,
        FsError::OffsetOverflow => EOVERFLOW,
        FsError::NoData => ENXIO,
        FsError::NameTooLong => ENAMETOOLONG,
        FsError::InvalidArgument => EINVAL,
        FsError::UnsupportedEncoding => EILSEQ,
        FsError::Io => EIO,
    }
}

fn fail(code: c_int) -> i64 {
    // SAFETY: errno belongs only to the current thread's live scope.
    unsafe { *tls::errno() = code };
    -1
}

fn file<T: Send>(run: impl FnOnce(&mut PosixFs) -> Result<T, FsError> + Send) -> Result<T, c_int> {
    shared::context(|_, files| run(files).map_err(error))
}

fn fd(fd: c_int) -> Result<u32, c_int> {
    u32::try_from(fd).map_err(|_| EBADF)
}

fn descriptor_flags(flags: c_int) -> DescriptorFlags {
    DescriptorFlags {
        close_on_exec: flags & O_CLOEXEC != 0,
        close_on_fork: flags & O_CLOFORK != 0,
    }
}

unsafe fn path<'a>(pointer: *const c_char) -> Result<&'a [u8], c_int> {
    if pointer.is_null() {
        return Err(EFAULT);
    }
    for length in 0..=128 {
        // SAFETY: the caller supplies a readable, terminated C string.
        if unsafe { *pointer.add(length) } == 0 {
            // SAFETY: these bytes were readable and precede the terminator.
            return Ok(unsafe { core::slice::from_raw_parts(pointer.cast(), length) });
        }
    }
    Err(ENAMETOOLONG)
}

/// # Safety
/// Called inside a current-thread ABI scope. The returned pointer stays live
/// until the scope ends; it must not be shared between threads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __errno_location() -> *mut c_int {
    tls::errno()
}

/// # Safety
/// `name` is a live C string and this thread has an initialized file scope.
/// The initial ABI accepts access mode, O_DIRECTORY and close-on-exec/fork flags.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn open(name: *const c_char, flags: c_int) -> c_int {
    let result = (|| {
        let name = unsafe { path(name) }?;
        if flags & !(O_ACCMODE | O_DIRECTORY | O_CLOEXEC | O_CLOFORK) != 0
            || flags & O_ACCMODE == O_ACCMODE
        {
            return Err(EINVAL);
        }
        file(|files| {
            let directory = if flags & O_DIRECTORY != 0 {
                posix_fs::DIRECTORY_ONLY
            } else {
                0
            };
            let fd = files.open(name, (flags & O_ACCMODE) as u32 | directory)?;
            files.set_descriptor_flags(fd, descriptor_flags(flags))?;
            Ok(fd)
        })
    })();
    result.map_or_else(|code| fail(code) as c_int, |fd| fd as c_int)
}

/// # Safety
/// This thread has an initialized ABI scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn close(number: c_int) -> c_int {
    fd(number)
        .and_then(|fd| file(|files| files.close(fd)))
        .map_or_else(|code| fail(code) as c_int, |()| 0)
}

/// # Safety
/// `buffer` supplies `count` writable bytes (may be null for zero bytes).
/// This thread has an initialized ABI scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn read(number: c_int, buffer: *mut u8, count: usize) -> isize {
    if count > isize::MAX as usize {
        return fail(EINVAL) as isize;
    }
    if buffer.is_null() && count != 0 {
        return fail(EFAULT) as isize;
    }
    let result = fd(number)
        .and_then(|fd| file(|files| files.prepare_read(fd, count)))
        .and_then(|read| read.complete().map_err(error));
    result.map_or_else(
        |code| fail(code) as isize,
        |(length, bytes)| {
            if length != 0 {
                // SAFETY: the C caller supplies count bytes; the bounded result fits.
                // Publish application-visible output on the calling thread.
                unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, length) };
            }
            length as isize
        },
    )
}

/// # Safety
/// `buffer` supplies `count` readable bytes (may be null for zero bytes).
/// This thread has an initialized ABI scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(number: c_int, buffer: *const u8, count: usize) -> isize {
    if count > isize::MAX as usize {
        return fail(EINVAL) as isize;
    }
    if buffer.is_null() && count != 0 {
        return fail(EFAULT) as isize;
    }
    let result = fd(number).and_then(|fd| {
        let bytes = if count == 0 {
            &[]
        } else {
            // SAFETY: the caller promises this readable extent.
            unsafe { core::slice::from_raw_parts(buffer, count) }
        };
        file(|files| files.write(fd, bytes))
    });
    result.map_or_else(|code| fail(code) as isize, |n| n as isize)
}

/// # Safety
/// This thread has an initialized ABI scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lseek(number: c_int, offset: i64, origin: c_int) -> i64 {
    let result = fd(number).and_then(|fd| {
        let origin = match origin {
            SEEK_SET => SeekFrom::Start,
            SEEK_CUR => SeekFrom::Current,
            SEEK_END => SeekFrom::End,
            SEEK_DATA => SeekFrom::Data,
            SEEK_HOLE => SeekFrom::Hole,
            _ => return Err(EINVAL),
        };
        file(|files| files.lseek(fd, offset, origin))
    });
    result.unwrap_or_else(fail)
}

/// # Safety
/// This thread has an initialized ABI scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup(number: c_int) -> c_int {
    fd(number)
        .and_then(|fd| file(|files| files.dup(fd)))
        .map_or_else(|code| fail(code) as c_int, |fd| fd as c_int)
}

/// # Safety
/// This thread has an initialized ABI scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup2(source: c_int, target: c_int) -> c_int {
    let result = fd(source).and_then(|source| {
        let target = fd(target)?;
        file(|files| files.dup2(source, target))
    });
    result.map_or_else(|code| fail(code) as c_int, |fd| fd as c_int)
}

/// # Safety
/// This thread has an initialized ABI scope. Flags must be O_CLOEXEC/CLOFORK.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup3(source: c_int, target: c_int, flags: c_int) -> c_int {
    let result = fd(source).and_then(|source| {
        let target = fd(target)?;
        if flags & !(O_CLOEXEC | O_CLOFORK) != 0 {
            return Err(EINVAL);
        }
        file(|files| files.dup3(source, target, descriptor_flags(flags)))
    });
    result.map_or_else(|code| fail(code) as c_int, |fd| fd as c_int)
}

/// # Safety
/// `name` is a live C string; this thread has an initialized ABI scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chdir(name: *const c_char) -> c_int {
    let result = unsafe { path(name) }.and_then(|path| file(|files| files.chdir(path)));
    result.map_or_else(|code| fail(code) as c_int, |()| 0)
}

/// # Safety
/// `buffer` supplies `size` writable bytes; this thread has an ABI scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getcwd(buffer: *mut c_char, size: usize) -> *mut c_char {
    let result = if buffer.is_null() {
        Err(EFAULT)
    } else if size == 0 {
        Err(EINVAL)
    } else {
        let mut path = [0; 129];
        file(|files| {
            let cwd = files.cwd();
            path[..cwd.len()].copy_from_slice(cwd);
            Ok(cwd.len())
        })
        .and_then(|length| {
            if size <= length {
                return Err(ERANGE);
            }
            // SAFETY: the C caller promises at least size writable bytes.
            unsafe { ptr::copy_nonoverlapping(path.as_ptr().cast(), buffer, length + 1) };
            Ok(buffer)
        })
    };
    result.unwrap_or_else(|code| {
        fail(code);
        ptr::null_mut()
    })
}

/// # Safety
/// All process threads and resources are abandoned by this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _exit(status: c_int) -> ! {
    rt::sys::process_exit((status & 255) as u64)
}

/// Numeric ABI revision, callable before thread initialization.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_posix_abi_version() -> c_int {
    ABI_VERSION as c_int
}
