// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Picolibc's POSIX hooks backed by a RAM file-service connection.

#![no_std]

use core::cell::UnsafeCell;
use proto_wire::Status;
use rt::Handle;
use rt::fs::Files;
use rt::handle::Channel;

struct FilesCell(UnsafeCell<Option<Files>>);

// SAFETY: initialization and the exported hooks run on one guest thread.
unsafe impl Sync for FilesCell {}

static FILES: FilesCell = FilesCell(UnsafeCell::new(None));

/// Initialize the one-threaded POSIX bridge before calling C code.
pub fn init(parent: &Handle<Channel>) -> Result<(), Status> {
    let files = Files::connect(parent)?;
    // SAFETY: the caller initializes before invoking C on this thread.
    unsafe { *FILES.0.get() = Some(files) };
    Ok(())
}

fn files() -> &'static Files {
    // SAFETY: initialized before C runs, then accessed by one thread.
    unsafe { (*FILES.0.get()).as_ref().expect("files initialized") }
}

fn result(value: Result<u32, Status>) -> i64 {
    value.map_or_else(|status| -(status.code() as i64), i64::from)
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_open(path: *const u8, len: usize, flags: u32) -> i32 {
    if path.is_null() || len > proto_fs::MAX_PATH {
        return -(proto_wire::BAD_SIZE as i32);
    }
    // SAFETY: C passes a string of `len` bytes that is live for this call.
    let bytes = unsafe { core::slice::from_raw_parts(path, len) };
    let Ok(path) = core::str::from_utf8(bytes) else {
        return -(proto_wire::BAD_SIZE as i32);
    };
    result(files().open(path, flags)) as i32
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_close(fd: u32) -> i32 {
    files()
        .close(fd)
        .map_or_else(|status| -(status.code() as i32), |()| 0)
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_read(fd: u32, buf: *mut u8, count: usize) -> isize {
    if count == 0 {
        return 0;
    }
    if buf.is_null() {
        return -(proto_wire::BAD_SIZE as isize);
    }
    // SAFETY: C passes `count` writable bytes for the duration of the call.
    let out = unsafe { core::slice::from_raw_parts_mut(buf, count) };
    files()
        .read(fd, out)
        .map_or_else(|status| -(status.code() as isize), |n| n as isize)
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_write(fd: u32, buf: *const u8, count: usize) -> isize {
    if count == 0 {
        return 0;
    }
    if buf.is_null() {
        return -(proto_wire::BAD_SIZE as isize);
    }
    // SAFETY: C passes `count` readable bytes for the duration of the call.
    let bytes = unsafe { core::slice::from_raw_parts(buf, count) };
    files()
        .write(fd, bytes)
        .map_or_else(|status| -(status.code() as isize), |n| n as isize)
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_seek(fd: u32, offset: u32) -> i64 {
    result(files().lseek(fd, offset))
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_size(fd: u32) -> i64 {
    result(files().fstat_size(fd))
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_exit(status: i32) -> ! {
    rt::sys::process_exit(status as u64)
}
