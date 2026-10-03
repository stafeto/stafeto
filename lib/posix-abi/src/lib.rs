// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The POSIX system layer in Rust: files, descriptors, the process's
//! pages, threads, waits, cancellation, signals, clocks and credentials,
//! which relibc's platform (posix-platform's `stafeto_*`) calls. Its
//! functions give a value or an errno (`Result<_, i32>`) and keep no errno
//! of their own; the C side is relibc's.

#![no_std]

pub mod allocation;
pub mod clock;
pub mod constants;
pub mod fork;
pub mod long;
pub mod metadata;
pub mod pipes;
pub mod process;
pub mod relibc;
pub mod shared;
pub mod signals;
pub mod terminal;
pub mod threads;
pub mod tls;

use constants::*;
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicU8, Ordering};
use posix_fs::{DescriptorFlags, FsError, SeekFrom};
use posix_request::{MAX_PATH, MESSAGE_MAX, Reply, Request};
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
        FsError::Again => EAGAIN,
        FsError::Broken => EPIPE,
        FsError::TooManyInSystem => ENFILE,
        FsError::Io => EIO,
    }
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

/// The bytes of the C string at `pointer`, at most `MAX_PATH` of them.
///
/// # Safety
/// `pointer` is null or a readable, terminated C string.
pub unsafe fn path<'a>(pointer: *const c_char) -> Result<&'a [u8], c_int> {
    if pointer.is_null() {
        return Err(EFAULT);
    }
    for length in 0..=MAX_PATH {
        // SAFETY: the caller supplies a readable, terminated C string.
        if unsafe { *pointer.add(length) } == 0 {
            // SAFETY: these bytes were readable and precede the terminator.
            return Ok(unsafe { core::slice::from_raw_parts(pointer.cast(), length) });
        }
    }
    Err(ENAMETOOLONG)
}

/// Opens `name` with the access mode, O_DIRECTORY, O_CHANGES and the
/// close-on-exec and close-on-fork flags of `flags`: the descriptor or an errno.
pub fn open(name: &[u8], flags: c_int) -> Result<c_int, c_int> {
    if flags & !(O_ACCMODE | O_DIRECTORY | O_CLOEXEC | O_CLOFORK | O_CHANGES | O_NOCTTY) != 0
        || flags & O_ACCMODE == O_ACCMODE
    {
        return Err(EINVAL);
    }
    shared::number(Request::Open {
        path: name,
        flags: flags as u32,
    })
    .map(|fd| fd as c_int)
}

pub fn close(number: c_int) -> Result<(), c_int> {
    shared::unit(Request::Close { fd: fd(number)? })
}

/// Reads into `buffer`: a point of cancellation.
pub fn read(number: c_int, buffer: &mut [u8]) -> Result<usize, c_int> {
    let point = threads::cancel::Point::begin();
    let result = read_inner(number, buffer);
    if result.is_ok_and(|n| n > 0) {
        point.end();
    } else {
        point.finish();
    }
    result
}

// Keep cancellation outside frames holding transport resources and buffers.
fn read_inner(number: c_int, buffer: &mut [u8]) -> Result<usize, c_int> {
    let mut message = [0; MESSAGE_MAX];
    let fd = fd(number)?;
    let count = buffer.len().min(posix_request::MAX_READ);
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
            buffer[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
        Reply::Input { uart, extent } => {
            if extent as usize > count {
                return Err(EIO);
            }
            console_read(uart, &mut buffer[..extent as usize])
        }
        _ => Err(EIO),
    }
}

/// The console's branch of `read`, in its own frame: its buffers stay off
/// the stack of reads of files, which go on under the lock of the files.
#[inline(never)]
fn console_read(uart: Option<u64>, buffer: &mut [u8]) -> Result<usize, i32> {
    let extent = buffer.len();
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
            .read(&mut bytes[..extent])
            .map_err(|status| error(status.into()))?;
        buffer[..length].copy_from_slice(&bytes[..length]);
        return Ok(length);
    }
    // A read in two steps waits on the thread's own channel: a
    // signal or a request of cancellation ends it at once.
    let mut start = proto_wire::Writer::new();
    proto_uart::ReadRequest { max: extent as u32 }
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
        &mut raw[..extent],
    )?;
    let length = input.deliver(&raw[..got], &mut bytes[..extent]);
    buffer[..length].copy_from_slice(&bytes[..length]);
    Ok(length)
}

/// Writes `bytes`: to a file or the console at most the transport's
/// extent, to a pipe all of them unless a signal or O_NONBLOCK stops it
/// (pipes::write). EPIPE comes after SIGPIPE went to the calling thread,
/// and its handler ran ([write]). A point of cancellation.
pub fn write(number: c_int, bytes: &[u8]) -> Result<usize, c_int> {
    let point = threads::cancel::Point::begin();
    let result = fd(number)
        .and_then(|fd| shared::number(Request::Write { fd, bytes }))
        .map(|n| n as usize);
    if result == Err(EPIPE) {
        let _ = signals::raise(SIGPIPE);
    }
    if result.is_ok_and(|n| n > 0) {
        point.end();
    } else {
        point.finish();
    }
    result
}

pub fn lseek(number: c_int, offset: i64, origin: c_int) -> Result<i64, c_int> {
    let fd = fd(number)?;
    let origin = match origin {
        SEEK_SET => SeekFrom::Start,
        SEEK_CUR => SeekFrom::Current,
        SEEK_END => SeekFrom::End,
        SEEK_DATA => SeekFrom::Data,
        SEEK_HOLE => SeekFrom::Hole,
        _ => return Err(EINVAL),
    };
    shared::number(Request::Seek { fd, offset, origin }).map(|offset| offset as i64)
}

/// pipe2 ([P24-PIPE]): a new pipe of the pipe service, its read end and
/// its write end at the two lowest free descriptors, with O_NONBLOCK on
/// both descriptions and FD_CLOEXEC and FD_CLOFORK as `flags` say;
/// EINVAL for another flag, ENOSYS for a process without a session with
/// the pipe service, ENFILE and EMFILE past the service's limits or the
/// table's.
pub fn pipe2(flags: c_int) -> Result<[c_int; 2], c_int> {
    if flags & !(O_NONBLOCK | O_CLOEXEC | O_CLOFORK) != 0 {
        return Err(EINVAL);
    }
    let transport = shared::with_files(|files| {
        files.pipes().ok_or(ENOSYS)?;
        Ok(files.transport())
    })?;
    let (read, write) = pipes::create(transport, flags & O_NONBLOCK != 0)?;
    let inserted = shared::with_files(|files| {
        files
            .insert_pipe(read, write, descriptor_flags(flags))
            .map_err(error)
    });
    match inserted {
        Ok((read, write)) => Ok([read as c_int, write as c_int]),
        Err(errno) => {
            let _ = transport.release(Some(posix_fs::Target::Pipe(read)));
            let _ = transport.release(Some(posix_fs::Target::Pipe(write)));
            Err(errno)
        }
    }
}

/// F_GETFL (`set` None) or F_SETFL of `number` when it names a pipe: its
/// flags, or 0 once set; None for a descriptor of another kind.
pub fn pipe_status_flags(number: c_int, set: Option<c_int>) -> Result<Option<c_int>, c_int> {
    shared::held(fd(number)?, |transport, target| match target {
        posix_fs::Target::Pipe(end) => match set {
            None => pipes::status_flags(transport, end).map(Some),
            Some(flags) => pipes::set_status_flags(transport, end, flags).map(|()| Some(0)),
        },
        _ => Ok(None),
    })
}

pub fn dup(number: c_int) -> Result<c_int, c_int> {
    shared::number(Request::Dup { fd: fd(number)? }).map(|fd| fd as c_int)
}

pub fn dup2(source: c_int, target: c_int) -> Result<c_int, c_int> {
    shared::number(Request::Dup2 {
        source: fd(source)?,
        target: fd(target)?,
    })
    .map(|fd| fd as c_int)
}

pub fn chdir(name: &[u8]) -> Result<(), c_int> {
    shared::unit(Request::Chdir { path: name })
}

/// The working directory into `buffer`, NUL-terminated: its length.
pub fn getcwd(buffer: &mut [u8]) -> Result<usize, c_int> {
    if buffer.is_empty() {
        return Err(EINVAL);
    }
    let mut message = [0; MESSAGE_MAX];
    let Reply::Bytes(path) = shared::dispatch(Request::Cwd, &mut message)? else {
        return Err(EIO);
    };
    if buffer.len() <= path.len() {
        return Err(ERANGE);
    }
    buffer[..path.len()].copy_from_slice(path);
    buffer[path.len()] = 0;
    Ok(path.len())
}

/// Ends the process with `status`; its threads and resources go with it.
pub fn exit(status: c_int) -> ! {
    rt::sys::process_exit((status & 255) as u64)
}
