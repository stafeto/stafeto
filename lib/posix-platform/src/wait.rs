// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Direct readiness interfaces; output pointers change only after success.
use super::call;
use core::ffi::c_int;
use posix_abi::{
    constants::{EFAULT, EINVAL},
    wait,
};
use posix_types::{FdSet, PollFd, Timespec, Timeval};

/// # Safety
/// `fds` holds `count` readable and writable pollfd objects.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_poll(
    fds: *mut PollFd,
    count: usize,
    milliseconds: c_int,
) -> c_int {
    let duration = (milliseconds >= 0).then(|| milliseconds as u64 * 1_000_000);
    // SAFETY: the caller supplies the pollfd array.
    unsafe { poll(fds, count, Ok(duration), None) }
}
/// # Safety
/// `fds` holds `count` pollfd objects; optional time and mask are readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_ppoll(
    fds: *mut PollFd,
    count: usize,
    time: *const Timespec,
    mask: *const u64,
) -> c_int {
    // SAFETY: non-null optional pointers are readable by the caller's promise.
    let duration = unsafe { time.as_ref() }
        .copied()
        .map(wait::timespec)
        .transpose();
    // SAFETY: the caller supplies the optional mask.
    let mask = unsafe { mask.as_ref() }
        .copied()
        .map(|m| m & posix_signals::VALID);
    // SAFETY: the caller supplies the pollfd array.
    unsafe { poll(fds, count, duration, mask) }
}
unsafe fn poll(
    fds: *mut PollFd,
    count: usize,
    duration: Result<Option<u64>, i32>,
    mask: Option<u64>,
) -> c_int {
    if count > wait::MAX {
        return -EINVAL;
    }
    if count != 0 && fds.is_null() {
        return -EFAULT;
    }
    let mut input = [PollFd::default(); wait::MAX];
    if count != 0 {
        // SAFETY: the caller supplies count readable objects, bounded above.
        input[..count].copy_from_slice(unsafe { core::slice::from_raw_parts(fds, count) });
    }
    match call(|| wait::poll(&mut input[..count], duration?, mask)) {
        Ok(count_ready) => {
            for (index, item) in input[..count].iter().enumerate() {
                // SAFETY: the caller supplies count writable objects.
                unsafe {
                    (*fds.add(index)).revents = item.revents;
                }
            }
            count_ready as c_int
        }
        Err(error) => -error,
    }
}
/// # Safety
/// Non-null sets and time are readable and writable in their C layouts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_select(
    nfds: c_int,
    read: *mut FdSet,
    write: *mut FdSet,
    except: *mut FdSet,
    time: *mut Timeval,
) -> c_int {
    // SAFETY: the caller supplies the optional time.
    let duration = unsafe { time.as_ref() }
        .copied()
        .map(wait::timeval)
        .transpose();
    // SAFETY: the caller supplies optional sets.
    match unsafe { select(nfds, [read, write, except], duration, None) } {
        Ok((count, remaining)) => {
            if !time.is_null() {
                let ns = remaining.unwrap_or(0);
                // SAFETY: the caller supplies a writable timeval.
                unsafe {
                    *time = Timeval {
                        tv_sec: (ns / 1_000_000_000) as i64,
                        tv_usec: ((ns % 1_000_000_000) / 1000) as i64,
                    };
                }
            }
            count as c_int
        }
        Err(error) => -error,
    }
}
/// # Safety
/// Non-null sets are readable/writable; time and mask are readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_pselect(
    nfds: c_int,
    read: *mut FdSet,
    write: *mut FdSet,
    except: *mut FdSet,
    time: *const Timespec,
    mask: *const u64,
) -> c_int {
    // SAFETY: the caller supplies optional time and mask.
    let duration = unsafe { time.as_ref() }
        .copied()
        .map(wait::timespec)
        .transpose();
    let mask = unsafe { mask.as_ref() }
        .copied()
        .map(|m| m & posix_signals::VALID);
    // SAFETY: the caller supplies optional sets.
    match unsafe { select(nfds, [read, write, except], duration, mask) } {
        Ok((count, _)) => count as c_int,
        Err(error) => -error,
    }
}
unsafe fn select(
    nfds: c_int,
    pointers: [*mut FdSet; 3],
    duration: Result<Option<u64>, i32>,
    mask: Option<u64>,
) -> Result<(usize, Option<u64>), i32> {
    let mut sets = [[0; 16]; 3];
    for (set, pointer) in sets.iter_mut().zip(pointers) {
        // SAFETY: the caller supplies each optional readable set.
        if let Some(input) = unsafe { pointer.as_ref() } {
            *set = *input;
        }
    }
    let result = call(|| wait::select(nfds, &mut sets, duration?, mask))?;
    for (set, pointer) in sets.into_iter().zip(pointers) {
        if !pointer.is_null() {
            // SAFETY: the caller supplies each writable set.
            unsafe {
                *pointer = set;
            }
        }
    }
    Ok(result)
}
