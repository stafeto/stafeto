// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The layer's signal, sleep and clock calls as the stages call them: a C
//! style over the layer's Rust interface (a value or an errno), with the
//! errno in relibc's errno of the thread, as relibc's own wrappers would
//! set it. The layer itself keeps no errno.

use core::ffi::c_int;

fn failed(errno: c_int) -> c_int {
    libc_ffi::set_errno(errno);
    -1
}

pub mod signals {
    use super::failed;
    use core::ffi::c_int;
    use posix_abi::signals as layer;
    pub use posix_abi::signals::{
        DEFAULT, IGNORE, LinuxContext, LinuxSigInfo, SigAction, SigInfo, SigSet,
        probe_hold_actions, probe_waiting,
    };

    /// # Safety
    /// `act` is null or readable, `old` null or writable.
    pub unsafe fn sigaction(signal: c_int, act: *const SigAction, old: *mut SigAction) -> c_int {
        // SAFETY: the caller's promise.
        match layer::sigaction(signal, unsafe { act.as_ref() }.copied()) {
            Ok(previous) => {
                // SAFETY: the caller's promise.
                if let Some(old) = unsafe { old.as_mut() } {
                    *old = previous;
                }
                0
            }
            Err(errno) => failed(errno),
        }
    }

    /// The error number, as pthread_sigmask gives it.
    ///
    /// # Safety
    /// `set` is null or readable, `old` null or writable.
    pub unsafe fn pthread_sigmask(how: c_int, set: *const SigSet, old: *mut SigSet) -> c_int {
        // SAFETY: the caller's promise.
        match layer::pthread_sigmask(how, unsafe { set.as_ref() }.copied()) {
            Ok(previous) => {
                // SAFETY: the caller's promise.
                if let Some(old) = unsafe { old.as_mut() } {
                    *old = previous;
                }
                0
            }
            Err(errno) => errno,
        }
    }

    pub fn raise(signal: c_int) -> c_int {
        match layer::raise(signal) {
            Ok(()) => 0,
            Err(errno) => failed(errno),
        }
    }

    /// # Safety
    /// `set` is writable.
    pub unsafe fn sigpending(set: *mut SigSet) -> c_int {
        // SAFETY: the caller's promise.
        unsafe { set.write(layer::sigpending()) };
        0
    }

    /// # Safety
    /// `set` readable, `info` null or writable, `timeout` null or readable.
    pub unsafe fn sigtimedwait(
        set: *const SigSet,
        info: *mut SigInfo,
        timeout: *const posix_abi::metadata::Timespec,
    ) -> c_int {
        // SAFETY: the caller's promise.
        let (set, info, timeout) = unsafe { (set.read(), info.as_mut(), timeout.as_ref()) };
        match layer::sigtimedwait(set, info, timeout.copied()) {
            Ok(signal) => signal,
            Err(errno) => failed(errno),
        }
    }

    /// # Safety
    /// As for sigtimedwait, with no end.
    pub unsafe fn sigwaitinfo(set: *const SigSet, info: *mut SigInfo) -> c_int {
        // SAFETY: the caller's promise.
        unsafe { sigtimedwait(set, info, core::ptr::null()) }
    }

    /// The error number, as sigwait gives it.
    ///
    /// # Safety
    /// `set` readable, `signal` writable.
    pub unsafe fn sigwait(set: *const SigSet, signal: *mut c_int) -> c_int {
        // SAFETY: the caller's promise.
        match layer::sigtimedwait(unsafe { set.read() }, None, None) {
            Ok(got) => {
                // SAFETY: the caller's promise.
                unsafe { signal.write(got) };
                0
            }
            Err(errno) => errno,
        }
    }
}

pub mod sleep {
    use super::failed;
    use core::ffi::c_int;
    pub use posix_abi::threads::sleep::TIMER_ABSTIME;
    use posix_abi::{metadata::Timespec, threads::sleep as layer};

    /// The error number, as clock_nanosleep gives it.
    ///
    /// # Safety
    /// `requested` readable, `remaining` null or writable.
    pub unsafe fn clock_nanosleep(
        clock: c_int,
        flags: c_int,
        requested: *const Timespec,
        remaining: *mut Timespec,
    ) -> c_int {
        // SAFETY: the caller's promise.
        match layer::clock_nanosleep(clock, flags, unsafe { requested.read() }) {
            Ok(()) => 0,
            Err((errno, left)) => {
                // SAFETY: the caller's promise.
                if let (Some(left), Some(out)) = (left, unsafe { remaining.as_mut() }) {
                    *out = left;
                }
                errno
            }
        }
    }

    /// # Safety
    /// As for clock_nanosleep.
    pub unsafe fn nanosleep(requested: *const Timespec, remaining: *mut Timespec) -> c_int {
        // SAFETY: the caller's promise.
        match unsafe { clock_nanosleep(posix_abi::clock::CLOCK_REALTIME, 0, requested, remaining) }
        {
            0 => 0,
            errno => failed(errno),
        }
    }
}

pub mod clock {
    use super::failed;
    use core::ffi::c_int;
    pub use posix_abi::clock::{CLOCK_MONOTONIC, CLOCK_REALTIME};
    use posix_abi::metadata::Timespec;

    /// # Safety
    /// `out` is writable.
    pub unsafe fn clock_gettime(id: c_int, out: *mut Timespec) -> c_int {
        match posix_abi::clock::gettime(id) {
            Ok(time) => {
                // SAFETY: the caller's promise.
                unsafe {
                    out.write(Timespec {
                        tv_sec: time.seconds,
                        tv_nsec: time.nanos,
                    })
                };
                0
            }
            Err(errno) => failed(errno),
        }
    }

    /// # Safety
    /// `time` is readable.
    pub unsafe fn clock_settime(id: c_int, time: *const Timespec) -> c_int {
        // SAFETY: the caller's promise.
        match posix_abi::clock::settime(id, unsafe { time.read() }) {
            Ok(()) => 0,
            Err(errno) => failed(errno),
        }
    }
}
