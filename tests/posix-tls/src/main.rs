// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Native guest threads retain distinct errno across context switches.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicUsize, Ordering};
use posix_abi::{__errno_location, constants, tls};
use rt::{Stack, abi::Policy, sys};

rt::entry!(main);

static STACK: Stack<16384> = Stack::new();
static POINTER: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);

extern "C" fn worker(_: u64) -> ! {
    let passed = tls::with_errno(|| {
        // SAFETY: this worker's TLS scope is live for all accesses.
        let pointer = unsafe { __errno_location() };
        POINTER.store(pointer as usize, Ordering::Release);
        unsafe { *pointer = constants::EINVAL };
        for _ in 0..8 {
            if sys::yield_now().is_err() || unsafe { *pointer } != constants::EINVAL {
                return false;
            }
        }
        true
    });
    DONE.store(if passed { 1 } else { 2 }, Ordering::Release);
    sys::thread_exit()
}

fn main(_: u64) -> u64 {
    let Some(own) = rt::init_handles() else {
        return 1;
    };
    rt::console::set(own.resource);
    let passed = tls::with_errno(|| {
        // SAFETY: the initial thread's errno exists in this scope.
        let pointer = unsafe { __errno_location() };
        unsafe { *pointer = constants::EIO };
        let nested = tls::with_errno(|| {
            let other = unsafe { __errno_location() };
            unsafe { *other = constants::ENOENT };
            other != pointer
        });
        if !nested
            || unsafe { __errno_location() } != pointer
            || unsafe { *pointer } != constants::EIO
        {
            return false;
        }
        // SAFETY: the static stack is used once by this worker. The buffer
        // page is outside program segments and the initial message buffer.
        let Ok(thread) = (unsafe {
            sys::thread_create(
                &own.process,
                worker,
                STACK.top(),
                0,
                63,
                Policy::Fifo,
                0x900000,
            )
        }) else {
            return false;
        };
        if sys::thread_start(&thread).is_err() {
            return false;
        }
        for _ in 0..128 {
            if unsafe { *pointer } != constants::EIO {
                return false;
            }
            if DONE.load(Ordering::Acquire) != 0 {
                return DONE.load(Ordering::Acquire) == 1
                    && POINTER.load(Ordering::Acquire) != pointer as usize;
            }
            if sys::yield_now().is_err() {
                return false;
            }
        }
        false
    });
    if passed {
        rt::println!("posix-tls-probe: ok");
        0
    } else {
        rt::println!("posix-tls-probe: failed");
        2
    }
}
