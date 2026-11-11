// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The time stamps of the process along the packet path (lib/trace, the
//! feature `trace`): the calls of the sockets and `epoll_pwait` of the layer,
//! and the points of a stack in the process (`stafeto_trace_*` of
//! libc.so). The first record registers the dump of the ring, which the
//! process writes to its standard error as it exits. Without the feature
//! every function is empty.

#[cfg(feature = "trace")]
mod on {
    use core::sync::atomic::{AtomicBool, Ordering::Relaxed};

    unsafe extern "C" {
        fn atexit(f: extern "C" fn()) -> i32;
        fn getpid() -> i32;
        fn calloc(n: usize, size: usize) -> *mut u8;
        fn write(fd: i32, bytes: *const u8, len: usize) -> isize;
    }

    static REGISTERED: AtomicBool = AtomicBool::new(false);

    extern "C" fn at_exit() {
        // SAFETY: plain calls of the C library.
        let pid = unsafe { getpid() };
        let mut label = [b'w'; 12];
        let mut n = 1;
        let mut digits = [0u8; 10];
        let (mut v, mut d) = (pid.max(0) as u32, 0);
        loop {
            digits[d] = b'0' + (v % 10) as u8;
            d += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        while d > 0 {
            d -= 1;
            label[n] = digits[d];
            n += 1;
        }
        let label = core::str::from_utf8(&label[..n]).unwrap_or("w");
        trace::dump(label, 12_288, |line| {
            let mut text = [0u8; 96];
            text[..line.len()].copy_from_slice(line.as_bytes());
            text[line.len()] = b'\n';
            // SAFETY: the bytes are ours; a lost line is a lost record.
            unsafe { write(2, text.as_ptr(), line.len() + 1) };
        });
    }

    pub fn point(id: u8, key: u32) {
        if !REGISTERED.swap(true, Relaxed) {
            trace::set_frequency(rt::time::frequency());
            // SAFETY: plain calls of the C library; the ring lives for ever. A process that
            // makes no record (a shell) takes no memory for it.
            unsafe {
                let ring = calloc(trace::RECORDS * 2, 8);
                if !ring.is_null() {
                    trace::install(ring.cast());
                }
                atexit(at_exit)
            };
        }
        trace::point(id, key);
    }

    pub fn frame(id: u8, frame: &[u8], from_client: bool) {
        if let Some(key) = trace::frame_key(frame, from_client) {
            point(id, key);
        }
    }
}

#[cfg(feature = "trace")]
pub use on::{frame, point};

/// A record of `id` with `key`.
#[cfg(not(feature = "trace"))]
#[inline(always)]
pub fn point(_: u8, _: u32) {}

/// A record of `id` keyed by the segment in `frame`.
#[cfg(not(feature = "trace"))]
#[inline(always)]
pub fn frame(_: u8, _: &[u8], _: bool) {}
