// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls of the C library the program makes besides the spawn: the
//! memory allocator over `malloc` and `free`, the output to the descriptors
//! 1 and 2, the files, the clock and the pause. The output goes through
//! `write` of the C library and not through the console of the services, so
//! that `pkg list | wc -l` and a redirection work.

use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::{c_char, c_int, c_void};
use libc_ffi::{self as c, O_RDONLY, Timespec};

unsafe extern "C" {
    fn posix_memalign(out: *mut *mut c_void, align: usize, size: usize) -> c_int;
    fn clock_gettime(clock: c_int, out: *mut Timespec) -> c_int;
    fn nanosleep(request: *const Timespec, rest: *mut Timespec) -> c_int;
    fn geteuid() -> u32;
    fn mkdir(path: *const c_char, mode: u32) -> c_int;
}

/// The allocator of the program: the C library's `malloc`, and `posix_memalign`
/// for an alignment above 16.
pub struct Malloc;

// SAFETY: `malloc`, `posix_memalign` and `free` of the C library are a correct allocator;
// they are called as the trait says.
unsafe impl GlobalAlloc for Malloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= 16 {
            // SAFETY: any size is allowed.
            return unsafe { c::malloc(layout.size()) };
        }
        let mut out: *mut c_void = core::ptr::null_mut();
        // SAFETY: the alignment is a power of two that is a multiple of a pointer's size.
        if unsafe { posix_memalign(&mut out, layout.align(), layout.size()) } != 0 {
            return core::ptr::null_mut();
        }
        out.cast()
    }

    unsafe fn dealloc(&self, pointer: *mut u8, _: Layout) {
        // SAFETY: `pointer` came from `alloc` above.
        unsafe { c::free(pointer) };
    }
}

/// Writes all of `bytes` to the descriptor `fd`.
pub fn write_all(fd: c_int, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: the pointer and the length are those of a live slice.
        let n = unsafe { c::write(fd, bytes.as_ptr(), bytes.len()) };
        if n <= 0 {
            if n < 0 && c::errno() == EINTR {
                continue;
            }
            return;
        }
        bytes = &bytes[n as usize..];
    }
}

/// A line to the standard output.
pub fn out(line: &str) {
    write_all(1, line.as_bytes());
    write_all(1, b"\n");
}

/// A line to the standard error.
pub fn err(line: &str) {
    write_all(2, line.as_bytes());
    write_all(2, b"\n");
}

/// Text without a newline to the standard output (the start of a line
/// that a later call ends).
pub fn out_part(text: &str) {
    write_all(1, text.as_bytes());
}

pub const EINTR: c_int = 4;
pub const O_WRONLY: c_int = 1;
pub const O_CREAT: c_int = 0o100;
pub const O_TRUNC: c_int = 0o1000;

fn cstring(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(text.len() + 1);
    bytes.extend_from_slice(text.as_bytes());
    bytes.push(0);
    bytes
}

/// The bytes of the file at `path`, up to `most`; None when it cannot be read.
pub fn read_file(path: &str, most: usize) -> Option<Vec<u8>> {
    let name = cstring(path);
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { c::open(name.as_ptr().cast(), O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        // SAFETY: the chunk is the room given.
        let n = unsafe { c::read(fd, chunk.as_mut_ptr(), chunk.len()) };
        if n < 0 && c::errno() == EINTR {
            continue;
        }
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n as usize]);
        if out.len() > most {
            out.truncate(most);
            break;
        }
    }
    // SAFETY: the descriptor opened above.
    unsafe { c::close(fd) };
    Some(out)
}

/// The file at `path` with `bytes`, mode 0644; whether it was written.
pub fn write_file(path: &str, bytes: &[u8]) -> bool {
    let name = cstring(path);
    // SAFETY: a NUL-terminated path; the mode is read for O_CREAT.
    let fd = unsafe {
        c::open(
            name.as_ptr().cast(),
            O_WRONLY | O_CREAT | O_TRUNC,
            0o644 as c_int,
        )
    };
    if fd < 0 {
        return false;
    }
    let mut left = bytes;
    let mut ok = true;
    while !left.is_empty() {
        // SAFETY: the pointer and the length are those of a live slice.
        let n = unsafe { c::write(fd, left.as_ptr(), left.len()) };
        if n < 0 && c::errno() == EINTR {
            continue;
        }
        if n <= 0 {
            ok = false;
            break;
        }
        left = &left[n as usize..];
    }
    // SAFETY: the descriptor opened above.
    unsafe { c::close(fd) };
    ok
}

/// A directory with every one above it, mode 0755; the errors of those that
/// are there are not told.
pub fn make_directories(path: &str) {
    let mut at = 0;
    while let Some(next) = path[at + 1..].find('/') {
        at += 1 + next;
        mkdir_one(&path[..at]);
    }
    mkdir_one(path);
}

fn mkdir_one(path: &str) {
    let name = cstring(path);
    // SAFETY: a NUL-terminated path.
    unsafe { mkdir(name.as_ptr().cast(), 0o755) };
}

/// The wall clock in seconds, from `CLOCK_REALTIME` (the service of the clock reads the PL031).
pub fn now() -> u64 {
    let mut t = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid out pointer.
    unsafe { clock_gettime(0, &mut t) };
    t.tv_sec.max(0) as u64
}

pub fn pause_ms(ms: i64) {
    let t = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    // SAFETY: a valid request and no remainder wanted.
    unsafe { nanosleep(&t, core::ptr::null_mut()) };
}

/// Whether the process runs as the superuser.
pub fn is_root() -> bool {
    // SAFETY: no arguments.
    unsafe { geteuid() == 0 }
}

/// The words of `argv` as strings; a word that is not UTF-8 is cut at the bad byte's place.
///
/// # Safety
/// `argv` holds `argc` NUL-terminated strings, as the C start gives them.
pub unsafe fn arguments(argc: isize, argv: *mut *mut c_char) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..argc.max(0) {
        // SAFETY: by the caller's promise.
        let word = unsafe { core::ffi::CStr::from_ptr(*argv.offset(i)) };
        out.push(String::from_utf8_lossy(word.to_bytes()).into_owned());
    }
    out
}

/// The environment as `(name, value)` pairs.
///
/// # Safety
/// `envp` is a NULL-terminated array of NUL-terminated strings.
pub unsafe fn environment(envp: *mut *mut c_char) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut at = envp;
    // SAFETY: by the caller's promise.
    while !at.is_null() && unsafe { !(*at).is_null() } {
        // SAFETY: as above.
        let word = unsafe { core::ffi::CStr::from_ptr(*at) };
        let text = String::from_utf8_lossy(word.to_bytes()).into_owned();
        if let Some((name, value)) = text.split_once('=') {
            out.push((name.into(), value.into()));
        }
        // SAFETY: the array continues to its NULL.
        at = unsafe { at.add(1) };
    }
    out
}
