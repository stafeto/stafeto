// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C functions of the claimed network device, exported from libc.so
//! (spec 6, 3.9; `<stafeto/fast.h>`). Each is the layer's call
//! (`posix_abi::fast`) with the errno set as C expects: 0 or a count, or -1
//! with errno.

use core::ffi::{c_int, c_uint};
use posix_abi::fast::{self, FastClaim, FastConfig};
use posix_abi::fastnet;

unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}

fn fail(errno: i32) -> c_int {
    // SAFETY: relibc's errno of this thread.
    unsafe { *__errno_location() = errno };
    -1
}

/// Claims the second network device and describes it in `*out`.
///
/// # Safety
/// `out` is null or points to a writable `struct stafeto_fast_claim`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_fast_claim(out: *mut FastClaim, flags: c_uint) -> c_int {
    // SAFETY: the caller's pointer, checked for null.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return fail(posix_abi::constants::EINVAL);
    };
    match fast::claim(out, flags) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Attaches to the network service's switch and describes the ring in `*out`.
///
/// # Safety
/// `out` is null or points to a writable `struct stafeto_fast_claim`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_fast_attach(out: *mut FastClaim) -> c_int {
    // SAFETY: the caller's pointer, checked for null.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return fail(posix_abi::constants::EINVAL);
    };
    match fast::attach(out) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Holds TCP port `port` with the switch: the descriptor of the hold.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fast_port_hold(port: c_uint, reuseport: c_int) -> c_int {
    let Ok(port) = u16::try_from(port) else {
        return fail(posix_abi::constants::EINVAL);
    };
    match fast::port_hold(port, reuseport != 0) {
        Ok(fd) => fd,
        Err(errno) => fail(errno),
    }
}

/// Whether `port` belongs to this process's own stack (a port it holds, or one of the block of
/// its consumer's temporary ports): 1 or 0. The glue of the stack asks it for each packet of the
/// loopback network that its own loopback interface sends out.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fast_own_port(port: c_uint) -> c_int {
    u16::try_from(port).is_ok_and(fast::own_port).into()
}

/// Joins the group of the port description `fd` as the attached consumer.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fast_port_join(fd: c_int) -> c_int {
    match fast::port_join(fd) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Tells the switch's thread that frames wait in the ring's TX.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fast_poke() -> c_int {
    match fast::poke() {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Waits for the network service's notification.
///
/// # Safety
/// `bits` is null or points to a writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_fast_wait(timeout_ns: u64, bits: *mut u32) -> c_int {
    match fast::wait(timeout_ns) {
        Ok(got) => {
            // SAFETY: the caller's pointer, checked for null.
            if let Some(bits) = unsafe { bits.as_mut() } {
                *bits = got;
            }
            0
        }
        Err(errno) => fail(errno),
    }
}

/// The counters of the sleeps of the program's loop: `out[0]` sleeps, `out[1]`
/// wakes by a notification of the service, `out[2]` wakes by the deadline,
/// `out[3]` wakes by an event of another descriptor.
///
/// # Safety
/// `out` is null or points to four writable `uint64_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_fast_wake_counts(out: *mut u64) {
    if out.is_null() {
        return;
    }
    for (k, value) in posix_abi::epoll::wake_counts().into_iter().enumerate() {
        // SAFETY: the caller's pointer holds four words.
        unsafe { out.add(k).write(value) };
    }
}

/// Tells the network service of frames in the bypass ring.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fast_kick(count: u32) -> c_int {
    match fast::kick(count) {
        Ok(taken) => taken as c_int,
        Err(errno) => fail(errno),
    }
}

/// The second address.
///
/// # Safety
/// `out` is null or points to a writable `struct stafeto_fast_config`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_fast_config(out: *mut FastConfig) -> c_int {
    // SAFETY: the caller's pointer, checked for null.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return fail(posix_abi::constants::EINVAL);
    };
    match fast::config() {
        Ok(config) => {
            *out = config;
            0
        }
        Err(errno) => fail(errno),
    }
}

/// For the probe of the owner only (not in `<stafeto/fast.h>`): asks a
/// network service built for the probe to fault. Returns 0 when the service
/// answered (it did not fault) and -1 with errno when it ended or refused.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fast_probe_crash() -> c_int {
    match fast::probe_crash() {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Registers the program's table of the stack (see `<stafeto/fast.h>`).
///
/// # Safety
/// `table` is null or points to a whole `struct stafeto_fast_table`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_fast_register(table: *const fastnet::FastTable) -> c_int {
    // SAFETY: the caller's promise.
    match unsafe { fastnet::register(table) } {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// The bits the layer banked for the claiming thread, taken.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fast_take_pending() -> u32 {
    fast::take_pending()
}

/// Whether the service let go of the notifications.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fast_lost() -> c_int {
    c_int::from(fast::lost())
}

/// A record of the packet path's time stamps (feature `trace`).
#[cfg(feature = "trace")]
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_trace_point(id: c_uint, key: c_uint) {
    posix_abi::tracing::point(id as u8, key);
}

/// A record keyed by the segment of TCP in the Ethernet frame `frame` of
/// `len` bytes (nothing for a frame without data); `from_client`: it came from
/// the client.
///
/// # Safety
/// `frame` points to `len` readable bytes.
#[cfg(feature = "trace")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_trace_frame(
    id: c_uint,
    frame: *const u8,
    len: c_uint,
    from_client: c_int,
) {
    if !frame.is_null() {
        // SAFETY: the caller's bytes.
        let bytes = unsafe { core::slice::from_raw_parts(frame, len as usize) };
        posix_abi::tracing::frame(id as u8, bytes, from_client != 0);
    }
}
