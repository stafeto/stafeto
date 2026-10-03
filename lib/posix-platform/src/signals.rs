// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Signals for relibc's stafeto platform: relibc's Linux AArch64 layouts
//! and numbers (struct sigaction, a 64-bit sigset_t, siginfo_t, SIG_BLOCK
//! and the SA_ flags) translated to the layer's (posix-abi::signals). The
//! layer has signals 1 to 31; a real-time signal is EINVAL, and the bits
//! 32 to 64 of a set are dropped.

use super::{call, value};
use core::ffi::c_int;
use posix_abi::constants::EINVAL;
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
const FLAGS: [(u32, i32); 6] = [
    (0x4000_0000, posix_types::constants::SA_NODEFER),
    (0x8000_0000, posix_types::constants::SA_RESETHAND),
    (0x0000_0004, posix_types::constants::SA_SIGINFO),
    (0x1000_0000, posix_types::constants::SA_RESTART),
    (0x0000_0001, posix_types::constants::SA_NOCLDSTOP),
    (0x0000_0002, posix_types::constants::SA_NOCLDWAIT),
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
    let mut taken = posix_types::SigInfo::thread(0);
    let status = value(
        call(|| posix_abi::signals::sigtimedwait(set, Some(&mut taken), timeout)).map(i64::from),
    );
    if status > 0 && !info.is_null() {
        // A thread's signal says SI_TKILL; the process's carries what its
        // sender gave: si_code, si_pid, si_uid, and SIGCHLD's si_status.
        let code = if taken.si_code == posix_types::constants::SI_THREAD {
            SI_TKILL
        } else {
            taken.si_code
        };
        // SAFETY: the caller's promise.
        unsafe {
            info.write_bytes(0, SIGINFO_SIZE);
            info.cast::<c_int>().write(status as c_int);
            info.cast::<c_int>().add(2).write(code);
            info.cast::<c_int>().add(4).write(taken.si_pid);
            info.cast::<u32>().add(5).write(taken.si_uid);
            info.cast::<c_int>().add(6).write(taken.si_status);
        }
    }
    status as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_raise(signal: c_int) -> c_int {
    value(call(|| posix_abi::signals::raise(signal)).map(|()| 0)) as c_int
}

/// kill through the process service: a PID, 0 for the caller's group, -1
/// for every process but the caller's, below -1 the group -pid.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_kill(pid: c_int, signal: c_int) -> c_int {
    value(call(|| posix_abi::process::kill(pid, signal)).map(|()| 0)) as c_int
}

/// killpg through the process service (posix_abi::process::killpg).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_killpg(pgrp: c_int, signal: c_int) -> c_int {
    value(call(|| posix_abi::process::killpg(pgrp, signal)).map(|()| 0)) as c_int
}

/// setpgid of `pid` to `pgid` through the process service.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_setpgid(pid: c_int, pgid: c_int) -> c_int {
    value(call(|| posix_abi::process::setpgid(pid, pgid)).map(|()| 0)) as c_int
}

/// setsid: the new session's number, or the negated errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_setsid() -> c_int {
    value(call(|| posix_abi::process::setsid().map(i64::from))) as c_int
}

/// getpgid of `pid`: the group's number, or the negated errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_getpgid(pid: c_int) -> c_int {
    value(call(|| posix_abi::process::getpgid(pid).map(i64::from))) as c_int
}

/// getsid of `pid`: the session's number, or the negated errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_getsid(pid: c_int) -> c_int {
    value(call(|| posix_abi::process::getsid(pid).map(i64::from))) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_kill(id: c_int, signal: c_int) -> c_int {
    -posix_abi::signals::kill_relibc_thread(id as u64, signal)
}

/// A directed job generation obtained through the caller's own process session.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_job_ticket(signal: c_int) -> u64 {
    posix_abi::signals::probe_job_ticket(signal)
}

/// A delayed default stop request carrying the caller's original generation.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_stop_ticket(signal: c_int, ticket: u64) -> c_int {
    posix_abi::signals::probe_stop_ticket(signal, ticket)
}

/// Assign a process signal to the current blocked thread for an exec race probe.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_assign_job(signal: c_int) -> c_int {
    posix_abi::signals::probe_assign_job(signal)
}

/// Return a captured process signal with its original ticket.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_return_job(signal: c_int, ticket: u64) -> c_int {
    posix_abi::signals::probe_return_job(signal, ticket)
}

/// Exercise authenticated return information without manufacturing a generation.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_return_job_info(
    signal: c_int,
    ticket: u64,
    pid: c_int,
    code: c_int,
) -> c_int {
    posix_abi::signals::probe_return_job_info(signal, ticket, pid, code)
}

/// Refuse the next return before sending, to exercise ownership recovery.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_return_failure() {
    posix_abi::signals::probe_return_failure();
}

/// Route while a pending assignment of the same number remains in the caller.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_route_job(signal: c_int) -> c_int {
    posix_abi::signals::probe_route_job(signal)
}

/// Exercise the pre-attachment block without a relibc thread number.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_zero_return() -> c_int {
    posix_abi::signals::probe_zero_return()
}

/// Assign a process signal for the sender-information regression.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_assign_signal(signal: c_int) -> c_int {
    posix_abi::signals::probe_assign_signal(signal)
}

/// Publish a sender assignment before the next new thread starts.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_thread_start(hook: Option<extern "C" fn(u64)>) {
    posix_abi::relibc::probe_start_window(hook);
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_route_newborn(id: u64, signal: c_int) -> c_int {
    posix_abi::signals::probe_route_newborn(id, signal)
}

/// Replace a local pending signal inside its origin snapshot and claim.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_local_claim(hook: Option<extern "C" fn(c_int)>) {
    posix_abi::signals::probe_local_claim_window(hook);
}
