// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Native threads share the layer's descriptors, offsets and working
//! directory.
//! The probe is a C program on relibc (posix-crt starts it, relibc calls
//! its `main`); its native threads use the layer through its scopes.

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicUsize, Ordering};
use posix_abi::{self as abi, constants::*, shared, tls};
use rt::{
    Stack,
    handle::{Channel, Handle},
    sys,
};
// relibc's libc.a.
use libc_ffi as _;

#[cfg(feature = "input-probe")]
mod input;

#[cfg(feature = "interrupt-probe")]
mod interrupt;

mod wire;

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;
#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
static STACK: Stack<16384> = Stack::new();
#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
static FD: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
static ALIAS: AtomicUsize = AtomicUsize::new(0);
static ERROR: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
static HISTOGRAM: [AtomicUsize; 256] = [const { AtomicUsize::new(0) }; 256];
#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
static MAIN_BYTES: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
static WORKER_BYTES: AtomicUsize = AtomicUsize::new(0);

fn fail(stage: usize) -> bool {
    ERROR.store(stage, Ordering::Release);
    false
}

#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
fn reading(fd: i32, worker: bool) -> bool {
    let mut byte = 0;
    loop {
        match abi::read(fd, core::slice::from_mut(&mut byte)) {
            Ok(0) => return true,
            Ok(1) => {}
            _ => return false,
        }
        if worker {
            WORKER_BYTES.fetch_add(1, Ordering::Relaxed);
        } else {
            MAIN_BYTES.fetch_add(1, Ordering::Relaxed);
        }
        HISTOGRAM[byte as usize].fetch_add(1, Ordering::Relaxed);
        let _ = sys::yield_now();
    }
}

#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
extern "C" fn worker(completion: u64) -> ! {
    let passed = tls::with_process(|| {
        let fd = FD.load(Ordering::Acquire) as i32;
        let alias = ALIAS.load(Ordering::Acquire) as i32;
        let mut byte = 0;
        if abi::read(alias, core::slice::from_mut(&mut byte)) != Ok(1) || byte != b't' {
            return fail(10);
        }
        if abi::close(fd).is_err() || abi::chdir(b"/etc").is_err() {
            return fail(12);
        }
        // Leaving a nested thread scope must not close the process's fds.
        let nested = tls::with_process(|| abi::lseek(alias, 0, SEEK_CUR) == Ok(2));
        if !nested {
            return fail(13);
        }
        DONE.store(1, Ordering::Release);
        let channel = Handle::<Channel>::borrowed(rt::abi::Handle(completion));
        if sys::notify(&channel, 1).is_err() {
            return fail(14);
        }
        // Main acknowledges resetting the shared offset before concurrent reads.
        if sys::receive(&channel).is_err() {
            return fail(15);
        }
        if !reading(alias, true) {
            return fail(16);
        }
        true
    });
    DONE.store(if passed { 2 } else { 3 }, Ordering::Release);
    let channel = Handle::<Channel>::borrowed(rt::abi::Handle(completion));
    let _ = sys::notify(&channel, 2);
    sys::thread_exit()
}

/// The probe's C main: posix-crt connected the files (with the console's
/// driver for the input and interrupt probes) and the heap.
#[unsafe(no_mangle)]
extern "C" fn main(_: isize, _: *mut *mut c_char, _: *mut *mut c_char) -> c_int {
    let process = abi::allocation::process().raw();
    #[cfg(feature = "interrupt-probe")]
    let main = abi::threads::main_handle();
    if !wire::before_heap() {
        rt::println!(
            "posix-shared-probe: startup failed stage {}",
            ERROR.load(Ordering::Acquire)
        );
        return 3;
    }
    #[cfg(feature = "interrupt-probe")]
    let passed = tls::with_process(|| {
        let process = Handle::<rt::handle::Process>::borrowed(process);
        wire::payload() && interrupt::run(&process, &main) && shared::cleanup().is_ok()
    });
    #[cfg(feature = "input-probe")]
    let passed = tls::with_process(|| {
        let process = Handle::<rt::handle::Process>::borrowed(process);
        wire::payload() && input::run(&process) && shared::cleanup().is_ok()
    });
    #[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
    let passed = in_native_thread(process);
    if passed {
        rt::println!("posix-shared-probe: ok");
        0
    } else {
        rt::println!(
            "posix-shared-probe: failed stage {} done {}",
            ERROR.load(Ordering::Acquire),
            DONE.load(Ordering::Acquire)
        );
        4
    }
}

/// The scenario of the default probe: a native thread the layer did not
/// attach (`driver`) and its own native worker share the process's
/// descriptors, offsets and working directory. Both are
/// native, at one level, as the scenario needs: a thread of relibc would
/// rise to the ceiling for the layer's locks, which a native thread cannot.
#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
fn in_native_thread(process: rt::abi::Handle) -> bool {
    let Ok(completion) = sys::channel_create(30) else {
        return fail(27);
    };
    PROCESS.store(process.0 as usize, Ordering::Release);
    let process = Handle::<rt::handle::Process>::borrowed(process);
    // SAFETY: the static stack is used once; the message page is disjoint
    // from the worker's.
    let Ok(thread) = (unsafe {
        sys::thread_create(
            &process,
            driver,
            DRIVER_STACK.top(),
            completion.raw().0,
            30,
            rt::abi::Policy::Fifo,
            0xc01000,
        )
    }) else {
        return fail(27);
    };
    if sys::thread_start(&thread).is_err() || sys::receive(&completion).is_err() {
        return fail(28);
    }
    PASSED.load(Ordering::Acquire) == 1
}

#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
static DRIVER_STACK: Stack<16384> = Stack::new();
#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
static PROCESS: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
static PASSED: AtomicUsize = AtomicUsize::new(0);

#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
extern "C" fn driver(completion: u64) -> ! {
    let process = rt::abi::Handle(PROCESS.load(Ordering::Acquire) as u64);
    let passed = tls::with_process(|| scenario(process));
    PASSED.store(usize::from(passed), Ordering::Release);
    let channel = Handle::<Channel>::borrowed(rt::abi::Handle(completion));
    let _ = sys::notify(&channel, 1);
    sys::thread_exit()
}

#[cfg(not(any(feature = "input-probe", feature = "interrupt-probe")))]
fn scenario(process: rt::abi::Handle) -> bool {
    if !wire::payload() {
        return false;
    }
    let (Ok(fd), Ok(alias)) = (abi::open(b"/etc/motd", O_RDONLY), abi::dup(3)) else {
        return fail(4);
    };
    if fd != 3 || alias != 4 {
        return fail(4);
    }
    let mut byte = 0;
    if abi::read(fd, core::slice::from_mut(&mut byte)) != Ok(1) || byte != b's' {
        return fail(5);
    }
    FD.store(fd as usize, Ordering::Release);
    ALIAS.store(alias as usize, Ordering::Release);
    let Ok(completion) = sys::channel_create(30) else {
        return fail(6);
    };
    let process = Handle::<rt::handle::Process>::borrowed(process);
    // SAFETY: static stack is used once; this message page is disjoint from workers.
    let Ok(thread) = (unsafe {
        sys::thread_create(
            &process,
            worker,
            STACK.top(),
            completion.raw().0,
            30,
            rt::abi::Policy::Fifo,
            0xc00000,
        )
    }) else {
        return fail(7);
    };
    if sys::thread_start(&thread).is_err() || sys::receive(&completion).is_err() {
        return fail(8);
    }
    if DONE.load(Ordering::Acquire) != 1 {
        return fail(9);
    }
    let mut cwd = [0; 129];
    if abi::getcwd(&mut cwd) != Ok(4) || &cwd[..5] != b"/etc\0" {
        return fail(17);
    }
    // The worker closed fd for the process; the alias kept its offset.
    if abi::lseek(fd, 0, SEEK_CUR) != Err(EBADF) || abi::lseek(alias, 0, SEEK_CUR) != Ok(2) {
        return fail(18);
    }
    let opened = abi::open(b"motd", O_RDONLY);
    if opened != Ok(fd) || abi::close(fd).is_err() {
        return fail(20);
    }
    if abi::lseek(alias, 0, SEEK_SET) != Ok(0) {
        return fail(21);
    }
    if sys::notify(&completion, 4).is_err()
        || !reading(alias, false)
        || sys::receive(&completion).is_err()
    {
        return fail(22);
    }
    if DONE.load(Ordering::Acquire) != 2
        || MAIN_BYTES.load(Ordering::Acquire) == 0
        || WORKER_BYTES.load(Ordering::Acquire) == 0
    {
        return fail(23);
    }
    let mut expected = [0usize; 256];
    for byte in b"stafeto ramfs\n" {
        expected[*byte as usize] += 1;
    }
    if HISTOGRAM
        .iter()
        .zip(expected)
        .any(|(count, expected)| count.load(Ordering::Acquire) != expected)
    {
        return fail(26);
    }
    // The working directory the worker changed holds motd.
    let Ok(motd) = abi::open(b"motd", O_RDONLY) else {
        return fail(24);
    };
    if abi::close(motd).is_err() || abi::close(alias).is_err() {
        return fail(25);
    }
    if shared::cleanup().is_err() {
        return fail(25);
    }
    true
}
