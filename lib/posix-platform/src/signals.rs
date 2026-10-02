// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Signals for relibc's stafeto platform: relibc's Linux AArch64 layouts
//! and numbers (struct sigaction, a 64-bit sigset_t, siginfo_t, SIG_BLOCK
//! and the SA_ flags) translated to the layer's (posix-abi::signals). The
//! layer has signals 1 to 31; a real-time signal is EINVAL, and the bits
//! 32 to 64 of a set are dropped.

use super::{call, value};
use core::ffi::c_int;
use posix_abi::constants::{EINVAL, ENOSYS};
use posix_abi::signals::{SigAction, SigSet};
use posix_types::Timespec;

/// relibc's `struct sigaction` (Linux AArch64): handler, flags, restorer,
/// mask.
#[repr(C)]
pub struct LinuxSigaction {
    handler: usize,
    flags: c_int,
    restorer: usize,
    mask: u64,
}
const _: () = assert!(core::mem::size_of::<LinuxSigaction>() == 32);

/// Linux's SA_ flags the layer has, with the layer's values.
const FLAGS: [(u32, i32); 4] = [
    (0x4000_0000, posix_types::constants::SA_NODEFER),
    (0x8000_0000, posix_types::constants::SA_RESETHAND),
    (0x0000_0004, posix_types::constants::SA_SIGINFO),
    (0x1000_0000, posix_types::constants::SA_RESTART),
];

/// The signals of the layer in a Linux set.
const LAYER: u64 = posix_signals::VALID;

fn to_layer_flags(flags: c_int) -> i32 {
    FLAGS
        .iter()
        .filter(|(linux, _)| flags as u32 & linux != 0)
        .fold(0, |all, (_, ours)| all | ours)
}

fn to_linux_flags(flags: i32) -> c_int {
    FLAGS
        .iter()
        .filter(|(_, ours)| flags & ours != 0)
        .fold(0, |all, (linux, _)| all | *linux) as c_int
}

/// # Safety
/// `act` is null or readable, `old` null or writable, relibc's layout.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_sigaction(
    signal: c_int,
    act: *const LinuxSigaction,
    old: *mut LinuxSigaction,
) -> c_int {
    // SAFETY: the caller's promise.
    let new = unsafe { act.as_ref() }.map(|act| SigAction {
        handler: act.handler as u64,
        mask: act.mask & LAYER,
        flags: to_layer_flags(act.flags),
    });
    let previous = match call(|| posix_abi::signals::sigaction(signal, new)) {
        Ok(previous) => previous,
        Err(errno) => return -errno,
    };
    // SAFETY: the caller's promise.
    if let Some(old) = unsafe { old.as_mut() } {
        *old = LinuxSigaction {
            handler: previous.handler as usize,
            flags: to_linux_flags(previous.flags),
            restorer: 0,
            mask: previous.mask,
        };
    }
    0
}

/// # Safety
/// `set` is null or readable, `old` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_sigprocmask(how: c_int, set: *const u64, old: *mut u64) -> c_int {
    // Linux's SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK are 0, 1, 2. With no
    // set, `how` means nothing (POSIX): only the mask is read.
    let how = match how {
        0 => posix_types::constants::SIG_BLOCK,
        1 => posix_types::constants::SIG_UNBLOCK,
        2 => posix_types::constants::SIG_SETMASK,
        _ if set.is_null() => posix_types::constants::SIG_BLOCK,
        _ => return -EINVAL,
    };
    // SAFETY: the caller's promise.
    let set = unsafe { set.as_ref() }.map(|set| set & LAYER & !posix_signals::UNBLOCKABLE);
    let previous: SigSet = match posix_abi::signals::pthread_sigmask(how, set) {
        Ok(previous) => previous,
        Err(errno) => return -errno,
    };
    // SAFETY: the caller's promise.
    if let Some(old) = unsafe { old.as_mut() } {
        *old = previous;
    }
    0
}

/// # Safety
/// `set` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_sigpending(set: *mut u64) -> c_int {
    if set.is_null() {
        return -posix_abi::constants::EFAULT;
    }
    // SAFETY: the caller's promise.
    unsafe { set.write(posix_abi::signals::sigpending()) };
    0
}

/// # Safety
/// `mask` is readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_sigsuspend(mask: *const u64) -> c_int {
    // SAFETY: the caller's promise.
    let mask = unsafe { mask.read() } & LAYER & !posix_signals::UNBLOCKABLE;
    -posix_abi::signals::suspend(mask)
}

/// Linux's siginfo_t: 128 bytes, the signal, errno and code first.
const SIGINFO_SIZE: usize = 128;
/// si_code of a signal sent by tkill (pthread_kill, raise).
const SI_TKILL: c_int = -6;

/// # Safety
/// `set` is readable, `info` null or writable for a Linux siginfo_t,
/// `timeout` null or readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_sigtimedwait(
    set: *const u64,
    info: *mut u8,
    timeout: *const Timespec,
) -> c_int {
    // SAFETY: the caller's promise.
    let set = unsafe { set.read() } & LAYER;
    // A set of no signal the layer has would wait for good: refused as
    // unsupported (POSIX's EINVAL for sigwait).
    if set == 0 {
        return -EINVAL;
    }
    // SAFETY: the caller's promise.
    let timeout = unsafe { timeout.as_ref() }.copied();
    let status =
        value(call(|| posix_abi::signals::sigtimedwait(set, None, timeout)).map(i64::from));
    if status > 0 && !info.is_null() {
        // SAFETY: the caller's promise.
        unsafe {
            info.write_bytes(0, SIGINFO_SIZE);
            info.cast::<c_int>().write(status as c_int);
            info.cast::<c_int>().add(2).write(SI_TKILL);
        }
    }
    status as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_raise(signal: c_int) -> c_int {
    value(call(|| posix_abi::signals::raise(signal)).map(|()| 0)) as c_int
}

/// kill: the process's own signals go to the calling thread until the
/// process service routes them (5b); other processes are ENOSYS.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_kill(pid: c_int, signal: c_int) -> c_int {
    if pid != 0 && pid != posix_abi::process::getpid() {
        return -ENOSYS;
    }
    stafeto_raise(signal)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_kill(id: c_int, signal: c_int) -> c_int {
    -posix_abi::signals::kill_relibc_thread(id as u64, signal)
}
