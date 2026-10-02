// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! File progress while a different thread waits for console input.

use super::*;
use rt::handle::Process;

static INPUT_STACK: Stack<16384> = Stack::new();
static SECOND: AtomicUsize = AtomicUsize::new(0);
static RESULT: AtomicUsize = AtomicUsize::new(0);
static ENTERED: AtomicUsize = AtomicUsize::new(0);

extern "C" fn reader(completion: u64) -> ! {
    let passed = tls::with_process(|| {
        ENTERED.store(1, Ordering::Release);
        // fd 3 is closed and reused by main after this read has begun.
        let mut byte = 0;
        if abi::read(3, core::slice::from_mut(&mut byte)) != Ok(1) || byte != b'x' {
            return false;
        }
        let second = SECOND.load(Ordering::Acquire) as i32;
        for expected in b"yz\n" {
            if abi::read(second, core::slice::from_mut(&mut byte)) != Ok(1) || byte != *expected {
                return false;
            }
        }
        true
    });
    RESULT.store(if passed { 1 } else { 2 }, Ordering::Release);
    let completion = Handle::<Channel>::borrowed(rt::abi::Handle(completion));
    let _ = sys::notify(&completion, 1);
    sys::thread_exit()
}

pub fn run(process: &Handle<Process>) -> bool {
    let (Ok(first), Ok(second)) = (abi::dup(0), abi::dup(0)) else {
        return fail(30);
    };
    if first != 3
        || second != 4
        || abi::read(first, &mut []) != Ok(0)
        || abi::read(1, &mut []) != Err(EBADF)
    {
        return fail(30);
    }
    SECOND.store(second as usize, Ordering::Release);
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
    // A round trip under the files' lock: the console seeks nowhere.
    if abi::lseek(second, 0, SEEK_CUR) != Err(ESPIPE) || abi::close(first).is_err() {
        return fail(36);
    }
    let file = abi::open(b"/etc/motd", O_RDONLY);
    if file != Ok(first) || abi::dup2(first, 0) != Ok(0) {
        return fail(37);
    }
    let file = first;
    let mut byte = 0;
    if abi::read(0, core::slice::from_mut(&mut byte)) != Ok(1)
        || byte != b's'
        || abi::lseek(file, 0, SEEK_CUR) != Ok(1)
        || RESULT.load(Ordering::Acquire) != 0
    {
        return fail(38);
    }
    // The process's pages go on while input waits.
    let Ok(pages) = abi::allocation::map_pages(4096) else {
        return fail(40);
    };
    // SAFETY: the page came from map_pages just now.
    unsafe { abi::allocation::unmap_pages(pages, 4096) };
    // The host sends no bytes until it observes this marker. A blocked file
    // owner deadlocks before the marker, causing the dialog to time out.
    rt::println!("posix-input-probe: files ready while input waits");
    if sys::receive(&completion).is_err()
        || RESULT.load(Ordering::Acquire) != 1
        || abi::close(file).is_err()
        || abi::close(second).is_err()
    {
        return fail(39);
    }
    rt::println!("posix-input-probe: ok");
    true
}
