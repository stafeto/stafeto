// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Native guest threads retain distinct errno and share a process heap.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicUsize, Ordering};
use posix_abi::allocation::{self, free, malloc};
use posix_abi::{__errno_location, constants, tls};
use rt::{Stack, abi::Policy, sys};

rt::entry!(main);

static STACK: Stack<16384> = Stack::new();
static POINTER: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);
static FAILURE: AtomicUsize = AtomicUsize::new(0);

fn failed(code: usize) -> bool {
    FAILURE.store(code, Ordering::Release);
    false
}

static TRANSFER: AtomicUsize = AtomicUsize::new(0);
static RETURNED: AtomicUsize = AtomicUsize::new(0);

extern "C" fn worker(done_channel: u64) -> ! {
    let passed = tls::with_errno(|| {
        // SAFETY: this worker's TLS scope is live for all accesses.
        let pointer = unsafe { __errno_location() };
        POINTER.store(pointer as usize, Ordering::Release);
        unsafe { *pointer = constants::EINVAL };
        let input = TRANSFER.load(Ordering::Acquire) as *mut u8;
        if input.is_null() {
            return failed(1);
        }
        // SAFETY: the initial thread transferred this live allocation exclusively.
        for index in 0..43 {
            if unsafe { input.add(index).read() } != index as u8 {
                return failed(2);
            }
        }
        unsafe { free(input) };
        for count in 1..65 {
            let block = unsafe { malloc(count) };
            if block.is_null() || unsafe { *pointer } != constants::EINVAL {
                return failed(3);
            }
            unsafe {
                block.write_bytes(55, count);
                free(block);
            }
        }
        let output = unsafe { malloc(91) };
        if output.is_null() {
            return failed(4);
        }
        unsafe { output.write_bytes(77, 91) };
        RETURNED.store(output as usize, Ordering::Release);
        for _ in 0..8 {
            if sys::yield_now().is_err() || unsafe { *pointer } != constants::EINVAL {
                return failed(5);
            }
        }
        true
    });
    DONE.store(if passed { 1 } else { 2 }, Ordering::Release);
    let channel =
        rt::handle::Handle::<rt::handle::Channel>::borrowed(rt::abi::Handle(done_channel));
    let _ = sys::notify(&channel, 1);
    sys::thread_exit()
}

fn main(_: u64) -> u64 {
    let Some(own) = rt::init_handles() else {
        return 1;
    };
    rt::console::set(own.resource);
    // SAFETY: only the initial thread exists; the heap ranges are unused.
    if unsafe {
        allocation::init(
            match sys::handle_duplicate(&own.process, rt::abi::Rights::MANAGE) {
                Ok(process) => process,
                Err(_) => return 3,
            },
        )
    }
    .is_err()
    {
        return 3;
    }
    let passed = tls::with_errno(|| {
        // SAFETY: the initial thread's errno exists in this scope.
        let pointer = unsafe { __errno_location() };
        unsafe { *pointer = constants::EIO };
        let transfer = unsafe { malloc(43) };
        if transfer.is_null() {
            return failed(6);
        }
        for index in 0..43 {
            unsafe { transfer.add(index).write(index as u8) };
        }
        TRANSFER.store(transfer as usize, Ordering::Release);
        let nested = tls::with_errno(|| {
            let other = unsafe { __errno_location() };
            unsafe { *other = constants::ENOENT };
            other != pointer
        });
        if !nested
            || unsafe { __errno_location() } != pointer
            || unsafe { *pointer } != constants::EIO
        {
            return failed(7);
        }
        // SAFETY: the static stack is used once by this worker. The buffer
        // page is outside program segments and the initial message buffer.
        let Ok(completion) = sys::channel_create(63) else {
            return failed(17);
        };
        let Ok(thread) = (unsafe {
            sys::thread_create(
                &own.process,
                worker,
                STACK.top(),
                completion.raw().0,
                63,
                Policy::Fifo,
                0x900000,
            )
        }) else {
            return failed(8);
        };
        if sys::thread_start(&thread).is_err() {
            return failed(9);
        }
        for _ in 0..32 {
            if unsafe { *pointer } != constants::EIO {
                return failed(10);
            }
            let block = unsafe { malloc(37) };
            if block.is_null() {
                return failed(14);
            }
            unsafe {
                block.write_bytes(33, 37);
                free(block);
            }
            if sys::yield_now().is_err() {
                return failed(15);
            }
        }
        if sys::receive(&completion).is_err() {
            return failed(18);
        }
        if DONE.load(Ordering::Acquire) != 1 || POINTER.load(Ordering::Acquire) == pointer as usize
        {
            return failed(11);
        }
        let output = RETURNED.load(Ordering::Acquire) as *mut u8;
        if output.is_null() {
            return failed(12);
        }
        for index in 0..91 {
            if unsafe { output.add(index).read() } != 77 {
                return failed(13);
            }
        }
        unsafe { free(output) };
        (unsafe { *pointer }) == constants::EIO
    });
    if passed {
        rt::println!("posix-tls-probe: ok");
        0
    } else {
        rt::println!(
            "posix-tls-probe: failed stage {} done {}",
            FAILURE.load(Ordering::Acquire),
            DONE.load(Ordering::Acquire)
        );
        2
    }
}
