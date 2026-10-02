// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Experimental C file ABI 1 and startup, backed entirely by Rust. Entry points
//! require the initialized current-thread scope. The C caller supplies live,
//! properly sized buffers; null pointers are reported as EFAULT. No Picolibc.

#![no_std]

pub mod allocation;
pub mod clock;
pub mod constants;
pub mod directory;
pub mod long;
pub mod metadata;
pub mod process;
pub mod relibc;
pub mod shared;
pub mod signals;
pub mod threads;
pub mod tls;

use constants::*;
use core::ffi::{c_char, c_int};
use core::ptr;
use core::sync::atomic::{AtomicU8, Ordering};
use posix_fs::{DescriptorFlags, FsError, SeekFrom};
use posix_request::{MESSAGE_MAX, Reply, Request};
use rt::handle::{Channel, Handle};

const _: () = {
    assert!(core::mem::size_of::<usize>() == 8);
    assert!(core::mem::size_of::<core::ffi::c_long>() == 8);
    assert!(core::mem::size_of::<c_int>() == 4);
};

static CEILING: AtomicU8 = AtomicU8::new(0);

/// The process's ceiling (spec 6.6): one level above the main thread's
/// base, as init's POSIX record gives it (audit 3, decision 1.5), set once
/// at startup (`set_ceiling`). The locks of the layer raise their holders
/// there, and the exit channels of pthreads post at it.
fn ceiling() -> Result<u8, rt::abi::Error> {
    match CEILING.load(Ordering::Relaxed) {
        0 => Err(rt::abi::Error::BadState),
        known => Ok(known),
    }
}

/// The ceiling one above `main_level`; when the process may not use it
/// (a record whose ceiling is main's level), main's level, which the
/// caller says. One `channel_create` checks it.
fn set_ceiling(main_level: u8) -> u8 {
    let above = main_level
        .saturating_add(1)
        .min(rt::abi::PRIORITY_LEVELS - 1);
    let level = match rt::sys::channel_create(above) {
        Ok(_) => above,
        Err(_) => main_level,
    };
    CEILING.store(level, Ordering::Relaxed);
    level
}

/// The process's ceiling, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_ceiling() -> u8 {
    ceiling().expect("the ceiling")
}

/// The errno of a file error.
pub fn error(error: FsError) -> c_int {
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
        FsError::Interrupted => EINTR,
        FsError::Io => EIO,
    }
}

fn fail(code: c_int) -> i64 {
    // SAFETY: errno belongs only to the current thread's live scope.
    unsafe { *tls::errno() = code };
    -1
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
pub unsafe extern "C" fn __errno_location() -> *mut c_int {
    tls::errno()
}

/// # Safety
/// `name` is a live C string and this thread has an initialized file scope.
/// The initial ABI accepts access mode, O_DIRECTORY and close-on-exec/fork flags.
pub unsafe extern "C" fn open(name: *const c_char, flags: c_int) -> c_int {
    let result = (|| {
        let name = unsafe { path(name) }?;
        if flags & !(O_ACCMODE | O_DIRECTORY | O_CLOEXEC | O_CLOFORK) != 0
            || flags & O_ACCMODE == O_ACCMODE
        {
            return Err(EINVAL);
        }
        shared::number(Request::Open {
            path: name,
            flags: flags as u32,
        })
    })();
    result.map_or_else(|code| fail(code) as c_int, |fd| fd as c_int)
}

/// # Safety
/// This thread has an initialized ABI scope.
pub unsafe extern "C" fn close(number: c_int) -> c_int {
    fd(number)
        .and_then(|fd| shared::unit(Request::Close { fd }))
        .map_or_else(|code| fail(code) as c_int, |()| 0)
}

/// # Safety
/// `buffer` supplies `count` writable bytes (may be null for zero bytes).
/// This thread has an initialized ABI scope.
pub unsafe extern "C" fn read(number: c_int, buffer: *mut u8, count: usize) -> isize {
    let point = threads::cancel::Point::begin();
    let result = unsafe { read_inner(number, buffer, count) };
    if result > 0 {
        point.end();
    } else {
        point.finish();
    }
    result
}

// Keep cancellation outside frames holding transport resources and buffers.
unsafe fn read_inner(number: c_int, buffer: *mut u8, count: usize) -> isize {
    if count > isize::MAX as usize {
        return fail(EINVAL) as isize;
    }
    if buffer.is_null() && count != 0 {
        return fail(EFAULT) as isize;
    }
    let mut message = [0; MESSAGE_MAX];
    let result = fd(number).and_then(|fd| {
        let count = count.min(posix_request::MAX_READ);
        match shared::dispatch(
            Request::Read {
                fd,
                count: count as u32,
            },
            &mut message,
        )? {
            Reply::Bytes(bytes) => {
                if bytes.len() > count {
                    return Err(EIO);
                }
                if !bytes.is_empty() {
                    // SAFETY: the validated result fits the caller's writable extent.
                    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len()) };
                }
                Ok(bytes.len())
            }
            Reply::Input { uart, extent } => {
                if extent as usize > count {
                    return Err(EIO);
                }
                // SAFETY: as the caller of read promises.
                unsafe { console_read(uart, extent, buffer) }
            }
            _ => Err(EIO),
        }
    });
    result.map_or_else(|code| fail(code) as isize, |length| length as isize)
}

/// The console's branch of `read`, in its own frame: its buffers stay off
/// the stack of reads of files, which go on under the lock of the files.
///
/// # Safety
/// `buffer` supplies `extent` writable bytes.
#[inline(never)]
unsafe fn console_read(uart: Option<u64>, extent: u32, buffer: *mut u8) -> Result<usize, i32> {
    let input = rt::fs::Input::from_uart(uart.map(rt::abi::Handle));
    let uart = Handle::<Channel>::borrowed(uart.map(rt::abi::Handle).ok_or(EBADF)?);
    let mut bytes = [0; posix_request::MAX_READ];
    threads::cancel::console_wait();
    // A thread the layer did not attach has no channel of its
    // own: a plain read waits for input.
    // SAFETY: the block, when there is one, is this thread's.
    let attached = unsafe { posix_thread::block().as_ref() }
        .is_some_and(|b| b.channel.load(Ordering::Relaxed) != 0);
    if !attached {
        let length = input
            .read(&mut bytes[..extent as usize])
            .map_err(|status| error(status.into()))?;
        if length != 0 {
            // SAFETY: the transport returned at most the validated extent.
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, length) };
        }
        return Ok(length);
    }
    // A read in two steps waits on the thread's own channel: a
    // signal or a request of cancellation ends it at once.
    let mut start = proto_wire::Writer::new();
    proto_uart::ReadRequest { max: extent }
        .write_start(&mut start)
        .map_err(|_| EINVAL)?;
    let mut raw = [0; posix_request::MAX_READ];
    let got = long::run(
        &uart,
        start.as_bytes(),
        |cancel, key, w| {
            let method = if cancel {
                proto_uart::Method::ReadCancel
            } else {
                proto_uart::Method::ReadTake
            };
            proto_uart::ReadKey { key }.write(method, w)
        },
        &mut raw[..extent as usize],
    )?;
    let length = input.deliver(&raw[..got], &mut bytes[..extent as usize]);
    if length != 0 {
        // SAFETY: the transport returned at most the validated extent.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, length) };
    }
    Ok(length)
}

/// # Safety
/// `buffer` supplies `count` readable bytes (may be null for zero bytes).
/// This thread has an initialized ABI scope.
pub unsafe extern "C" fn write(number: c_int, buffer: *const u8, count: usize) -> isize {
    let point = threads::cancel::Point::begin();
    let result = unsafe { write_inner(number, buffer, count) };
    if result > 0 {
        point.end();
    } else {
        point.finish();
    }
    result
}

unsafe fn write_inner(number: c_int, buffer: *const u8, count: usize) -> isize {
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
            unsafe { core::slice::from_raw_parts(buffer, count.min(posix_request::MAX_WRITE)) }
        };
        shared::number(Request::Write { fd, bytes })
    });
    result.map_or_else(|code| fail(code) as isize, |n| n as isize)
}

/// # Safety
/// This thread has an initialized ABI scope.
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
        shared::number(Request::Seek { fd, offset, origin }).map(|offset| offset as i64)
    });
    result.unwrap_or_else(fail)
}

/// # Safety
/// This thread has an initialized ABI scope.
pub unsafe extern "C" fn dup(number: c_int) -> c_int {
    fd(number)
        .and_then(|fd| shared::number(Request::Dup { fd }))
        .map_or_else(|code| fail(code) as c_int, |fd| fd as c_int)
}

/// # Safety
/// This thread has an initialized ABI scope.
pub unsafe extern "C" fn dup2(source: c_int, target: c_int) -> c_int {
    let result = fd(source).and_then(|source| {
        let target = fd(target)?;
        shared::number(Request::Dup2 { source, target })
    });
    result.map_or_else(|code| fail(code) as c_int, |fd| fd as c_int)
}

/// # Safety
/// This thread has an initialized ABI scope. Flags must be O_CLOEXEC/CLOFORK.
pub unsafe extern "C" fn dup3(source: c_int, target: c_int, flags: c_int) -> c_int {
    let result = fd(source).and_then(|source| {
        let target = fd(target)?;
        if flags & !(O_CLOEXEC | O_CLOFORK) != 0 {
            return Err(EINVAL);
        }
        shared::number(Request::Dup3 {
            source,
            target,
            flags: flags as u32,
        })
    });
    result.map_or_else(|code| fail(code) as c_int, |fd| fd as c_int)
}

/// # Safety
/// `name` is a live C string; this thread has an initialized ABI scope.
pub unsafe extern "C" fn chdir(name: *const c_char) -> c_int {
    let result = unsafe { path(name) }.and_then(|path| shared::unit(Request::Chdir { path }));
    result.map_or_else(|code| fail(code) as c_int, |()| 0)
}

/// # Safety
/// `buffer` supplies `size` writable bytes; this thread has an ABI scope.
pub unsafe extern "C" fn getcwd(buffer: *mut c_char, size: usize) -> *mut c_char {
    let result = if buffer.is_null() {
        Err(EFAULT)
    } else if size == 0 {
        Err(EINVAL)
    } else {
        let mut message = [0; MESSAGE_MAX];
        shared::dispatch(Request::Cwd, &mut message).and_then(|reply| {
            let Reply::Bytes(path) = reply else {
                return Err(EIO);
            };
            if size <= path.len() {
                return Err(ERANGE);
            }
            // SAFETY: the caller supplies room for the complete path and terminator.
            unsafe {
                ptr::copy_nonoverlapping(path.as_ptr().cast(), buffer, path.len());
                *buffer.add(path.len()) = 0;
            }
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
pub unsafe extern "C" fn _exit(status: c_int) -> ! {
    rt::sys::process_exit((status & 255) as u64)
}
