// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! System calls (spec 11): `svc #number` at EL0, arguments in x0-x9, the
//! result code in x0 (0 for success). Milestone 1.2c brings the first
//! calls; until then only test builds know numbers, their own.

use crate::thread::Thread;
use abi::Error;
use core::ptr::NonNull;

/// Carries out system call `number` for `thread`, the running thread that
/// made it. Returns when `thread` is to go on; a call that switches to
/// another thread does not return.
pub fn dispatch(thread: NonNull<Thread>, number: u16) {
    #[cfg(feature = "ktest")]
    if crate::ktest::el0::syscall(thread, number) {
        return;
    }
    // No call has this number.
    let _ = number;
    set_result(thread, Err(Error::InvalidArgs));
}

/// Puts a system call's result code in the thread's x0.
pub fn set_result(mut thread: NonNull<Thread>, result: Result<(), Error>) {
    let code = match result {
        Ok(()) => 0,
        Err(e) => e as u64,
    };
    // SAFETY: the running thread is alive, and nothing else refers to it now.
    unsafe { thread.as_mut() }.regs.x[0] = code;
}
