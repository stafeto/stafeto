// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Native threads share Rust POSIX descriptors, offsets, cwd and directory streams.

#![no_std]
#![no_main]

use core::{
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};
use posix_abi::{self as abi, constants::*, shared, tls};
#[cfg(not(feature = "input-probe"))]
use posix_abi::{directory, metadata};
use posix_fs::PosixFs;
use rt::{
    Stack,
    handle::{Channel, Handle, Resource},
    sys,
};

#[cfg(feature = "input-probe")]
mod input;

mod wire;

rt::entry!(main);
#[cfg(not(feature = "input-probe"))]
static STACK: Stack<16384> = Stack::new();
#[cfg(not(feature = "input-probe"))]
static FD: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(feature = "input-probe"))]
static ALIAS: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(feature = "input-probe"))]
static DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static ERROR: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(feature = "input-probe"))]
static HISTOGRAM: [AtomicUsize; 256] = [const { AtomicUsize::new(0) }; 256];
#[cfg(not(feature = "input-probe"))]
static MAIN_BYTES: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(feature = "input-probe"))]
static WORKER_BYTES: AtomicUsize = AtomicUsize::new(0);

fn fail(stage: usize) -> bool {
    ERROR.store(stage, Ordering::Release);
    false
}

#[cfg(not(feature = "input-probe"))]
fn reading(fd: i32, worker: bool) -> bool {
    let mut byte = 0;
    loop {
        let result = unsafe { abi::read(fd, &mut byte, 1) };
        if result == 0 {
            return true;
        }
        if result != 1 {
            return false;
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

#[cfg(not(feature = "input-probe"))]
extern "C" fn worker(completion: u64) -> ! {
    let passed = tls::with_process(|| {
        let errno = unsafe { abi::__errno_location() };
        unsafe { *errno = EINVAL };
        let fd = FD.load(Ordering::Acquire) as i32;
        let alias = ALIAS.load(Ordering::Acquire) as i32;
        let dir = DIRECTORY.load(Ordering::Acquire) as *mut directory::Stream;
        let mut byte = 0;
        if unsafe { abi::read(alias, &mut byte, 1) } != 1 || byte != b't' {
            return fail(10);
        }
        let entry = unsafe { directory::readdir(dir) };
        if entry.is_null()
            || unsafe { (*entry).d_ino } != 1
            || unsafe { directory::telldir(dir) } != 2
        {
            return fail(11);
        }
        if unsafe { abi::close(fd) } != 0 || unsafe { abi::chdir(c"/etc".as_ptr()) } != 0 {
            return fail(12);
        }
        // Leaving a nested thread scope must not close process streams or fds.
        let nested = tls::with_process(|| unsafe { abi::lseek(alias, 0, SEEK_CUR) } == 2);
        if !nested || unsafe { *errno } != EINVAL {
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
        unsafe { *errno = EINVAL };
        if !reading(alias, true) || unsafe { *errno } != EINVAL {
            return fail(16);
        }
        true
    });
    DONE.store(if passed { 2 } else { 3 }, Ordering::Release);
    let channel = Handle::<Channel>::borrowed(rt::abi::Handle(completion));
    let _ = sys::notify(&channel, 2);
    sys::thread_exit()
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let files = if cfg!(all(feature = "input-probe", not(feature = "native-input"))) {
        PosixFs::connect_with_uart(&start.parent)
    } else {
        PosixFs::connect(&start.parent)
    };
    let Ok(files) = files else {
        return 2;
    };
    let process = start.process.raw();
    // SAFETY: startup has exclusive ownership; both reserved message pages are unused.
    if unsafe { shared::init(&start.process, files) }.is_err()
        || !wire::before_heap()
        || unsafe { abi::allocation::init(start.process) }.is_err()
    {
        rt::println!(
            "posix-shared-probe: startup failed stage {}",
            ERROR.load(Ordering::Acquire)
        );
        return 3;
    }
    #[cfg(feature = "input-probe")]
    let passed = tls::with_process(|| {
        let process = Handle::<rt::handle::Process>::borrowed(process);
        wire::payload() && input::run(&process, &start.thread) && shared::cleanup().is_ok()
    });
    #[cfg(not(feature = "input-probe"))]
    let passed = tls::with_process(|| {
        if !wire::payload() {
            return false;
        }
        let errno = unsafe { abi::__errno_location() };
        unsafe { *errno = EIO };
        let fd = unsafe { abi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
        let alias = unsafe { abi::dup(fd) };
        let dir = unsafe { directory::opendir(c"/etc".as_ptr()) };
        if fd != 3 || alias != 4 || dir.is_null() {
            return fail(4);
        }
        let mut byte = 0;
        if unsafe { abi::read(fd, &mut byte, 1) } != 1
            || byte != b's'
            || unsafe { directory::readdir(dir) }.is_null()
        {
            return fail(5);
        }
        FD.store(fd as usize, Ordering::Release);
        ALIAS.store(alias as usize, Ordering::Release);
        DIRECTORY.store(dir as usize, Ordering::Release);
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
        if DONE.load(Ordering::Acquire) != 1 || unsafe { *errno } != EIO {
            return fail(9);
        }
        let mut cwd = [0; 129];
        if unsafe { abi::getcwd(cwd.as_mut_ptr(), cwd.len()) }.is_null() || &cwd[..5] != b"/etc\0" {
            return fail(17);
        }
        let mut info = core::mem::MaybeUninit::<metadata::Stat>::uninit();
        if unsafe { metadata::fstat(fd, info.as_mut_ptr()) } != -1
            || unsafe { *errno } != EBADF
            || unsafe { abi::lseek(alias, 0, SEEK_CUR) } != 2
        {
            return fail(18);
        }
        let entry = unsafe { directory::readdir(dir) };
        if entry.is_null()
            || unsafe { (*entry).d_ino } != 4
            || unsafe { directory::closedir(dir) } != 0
        {
            return fail(19);
        }
        let opened = unsafe { abi::open(c"motd".as_ptr(), O_RDONLY) };
        if opened != fd || unsafe { abi::close(opened) } != 0 {
            return fail(20);
        }
        if unsafe { abi::lseek(alias, 0, SEEK_SET) } != 0 {
            return fail(21);
        }
        unsafe { *errno = EIO };
        if sys::notify(&completion, 4).is_err()
            || !reading(alias, false)
            || sys::receive(&completion).is_err()
        {
            return fail(22);
        }
        if DONE.load(Ordering::Acquire) != 2
            || MAIN_BYTES.load(Ordering::Acquire) == 0
            || WORKER_BYTES.load(Ordering::Acquire) == 0
            || unsafe { *errno } != EIO
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
        let mut list = ptr::null_mut();
        let count = unsafe {
            abi::scan::scandir(c".".as_ptr(), &mut list, None, Some(abi::scan::alphasort))
        };
        if count != 3 {
            return fail(24);
        }
        for index in 0..count as usize {
            unsafe { abi::allocation::free((*list.add(index)).cast()) };
        }
        unsafe { abi::allocation::free(list.cast()) };
        if unsafe { abi::close(alias) } != 0 {
            return fail(25);
        }
        if shared::cleanup().is_err() {
            return fail(25);
        }
        true
    });
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
