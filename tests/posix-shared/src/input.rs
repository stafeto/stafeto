// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! File progress while a different thread waits for console input.

use super::*;
use posix_abi::metadata;
use rt::handle::Process;

static INPUT_STACK: Stack<16384> = Stack::new();
static SECOND: AtomicUsize = AtomicUsize::new(0);
static RESULT: AtomicUsize = AtomicUsize::new(0);
static ENTERED: AtomicUsize = AtomicUsize::new(0);

extern "C" fn reader(completion: u64) -> ! {
    let passed = tls::with_process(|| {
        let errno = unsafe { abi::__errno_location() };
        unsafe { *errno = EINVAL };
        ENTERED.store(1, Ordering::Release);
        // fd 3 is closed and reused by main after this read has begun.
        let mut byte = 0;
        if unsafe { abi::read(3, &mut byte, 1) } != 1 || byte != b'x' {
            return false;
        }
        let second = SECOND.load(Ordering::Acquire) as i32;
        for expected in b"yz\n" {
            if unsafe { abi::read(second, &mut byte, 1) } != 1 || byte != *expected {
                return false;
            }
        }
        unsafe { *errno == EINVAL }
    });
    RESULT.store(if passed { 1 } else { 2 }, Ordering::Release);
    let completion = Handle::<Channel>::borrowed(rt::abi::Handle(completion));
    let _ = sys::notify(&completion, 1);
    sys::thread_exit()
}

pub fn run(process: &Handle<Process>) -> bool {
    let errno = unsafe { abi::__errno_location() };
    let first = unsafe { abi::dup(0) };
    let second = unsafe { abi::dup(0) };
    if first != 3
        || second != 4
        || unsafe { abi::read(first, ptr::null_mut(), 0) } != 0
        || unsafe { abi::read(1, ptr::null_mut(), 0) } != -1
        || unsafe { *errno } != EBADF
    {
        return fail(30);
    }
    SECOND.store(second as usize, Ordering::Release);
    unsafe { *errno = EIO };
    // UART read really blocks: the higher-priority client reaches the driver
    // before main resumes.
    // Through the layer, which keeps the level of a thread of relibc.
    if abi::threads::set_level(29).is_err() {
        return fail(31);
    }
    let Ok(completion) = sys::channel_create(30) else {
        return fail(32);
    };
    // SAFETY: static stack and message page are used once, disjoint from other threads.
    let Ok(thread) = (unsafe {
        sys::thread_create(
            process,
            reader,
            INPUT_STACK.top(),
            completion.raw().0,
            30,
            rt::abi::Policy::Fifo,
            0xd00000,
        )
    }) else {
        return fail(33);
    };
    if sys::thread_start(&thread).is_err() {
        return fail(34);
    }
    // Let the reader submit preparation. The following metadata round trip
    // completes before close/reuse, after the earlier queued preparation.
    for _ in 0..16 {
        let _ = sys::yield_now();
    }
    if ENTERED.load(Ordering::Acquire) != 1 || RESULT.load(Ordering::Acquire) != 0 {
        return fail(35);
    }
    let mut info = core::mem::MaybeUninit::<metadata::Stat>::uninit();
    if unsafe { metadata::fstat(second, info.as_mut_ptr()) } != 0
        || unsafe { abi::close(first) } != 0
    {
        return fail(36);
    }
    let file = unsafe { abi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
    if file != first || unsafe { abi::dup2(file, 0) } != 0 {
        return fail(37);
    }
    let mut byte = 0;
    if unsafe { abi::read(0, &mut byte, 1) } != 1
        || byte != b's'
        || unsafe { abi::lseek(file, 0, SEEK_CUR) } != 1
        || unsafe { *errno } != EIO
        || RESULT.load(Ordering::Acquire) != 0
    {
        return fail(38);
    }
    let block = unsafe { abi::allocation::malloc(16) };
    if block.is_null() {
        return fail(40);
    }
    unsafe { abi::allocation::free(block) };
    if unsafe { *errno } != EIO {
        return fail(41);
    }
    // The host sends no bytes until it observes this marker. A blocked file
    // owner deadlocks before the marker, causing the dialog to time out.
    rt::println!("posix-input-probe: files ready while input waits");
    if sys::receive(&completion).is_err()
        || RESULT.load(Ordering::Acquire) != 1
        || unsafe { *errno } != EIO
        || unsafe { abi::close(file) } != 0
        || unsafe { abi::close(second) } != 0
    {
        return fail(39);
    }
    rt::println!("posix-input-probe: ok");
    true
}
