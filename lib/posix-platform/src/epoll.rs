// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! epoll for relibc's `sys/epoll.h`: the three calls over the layer's
//! instances (`posix_abi::epoll`); the output events change only after success.
use super::{call, value};
use core::ffi::c_int;
use posix_abi::{
    constants::{EFAULT, EINVAL},
    epoll::{self, EpollEvent},
    wait,
};

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_epoll_create1(flags: c_int) -> c_int {
    value(call(|| epoll::create(flags)).map(i64::from)) as c_int
}

/// # Safety
/// `event` is null or readable as an `epoll_event`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_epoll_ctl(
    epfd: c_int,
    op: c_int,
    fd: c_int,
    event: *const EpollEvent,
) -> c_int {
    // SAFETY: the caller's promise.
    let event = unsafe { event.as_ref() }.copied();
    value(call(|| epoll::ctl(epfd, op, fd, event)).map(|()| 0)) as c_int
}

/// # Safety
/// `events` is writable for `maxevents` events; a non-null `mask` is readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_epoll_pwait(
    epfd: c_int,
    events: *mut EpollEvent,
    maxevents: c_int,
    timeout: c_int,
    mask: *const u64,
) -> c_int {
    if maxevents < 1 {
        return -EINVAL;
    }
    if events.is_null() {
        return -EFAULT;
    }
    // SAFETY: a non-null mask is readable by the caller's promise.
    let mask = unsafe { mask.as_ref() }
        .copied()
        .map(|m| m & posix_signals::VALID);
    let duration = (timeout >= 0).then(|| timeout as u64 * 1_000_000);
    // The events are written into a buffer of the layer first: the caller's
    // array changes only after success, and at most 64 events come at once.
    let wanted = (maxevents as usize).min(wait::MAX_LARGE);
    let mut buffer = [EpollEvent::default(); 64];
    let room = wanted.min(buffer.len());
    match call(|| epoll::pwait(epfd, &mut buffer[..room], duration, mask)) {
        Ok(count) => {
            for (k, event) in buffer[..count].iter().enumerate() {
                // SAFETY: `count` is at most `maxevents`, which the caller made writable.
                unsafe { events.add(k).write(*event) };
            }
            count as c_int
        }
        Err(errno) => -errno,
    }
}
