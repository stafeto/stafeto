// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A POSIX process without helper threads: before its first pthread its
//! main thread is its only one, so raw threads of the kernel go up to
//! LIMIT_REACHED at exactly MAX_THREADS - 1. The threads never start, and
//! they go with their handles.
use super::*;
use rt::abi::{Error, MAX_THREADS, Policy};

static HELD: [AtomicU64; MAX_THREADS as usize] =
    [const { AtomicU64::new(0) }; MAX_THREADS as usize];
static STACK: rt::Stack<4096> = rt::Stack::new();
/// The message pages of the raw threads, one each, past those of pthreads.
const BUFFERS: usize = 0x2800000;
const PAGE: usize = 4096;

extern "C" fn never(_: u64) -> ! {
    sys::thread_exit()
}

pub(super) fn run() -> bool {
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let mut made = 0;
    let mut refused = None;
    while made < HELD.len() {
        // SAFETY: the threads never start; the stack is never used, and
        // each message page is a distinct unused one.
        let created = unsafe {
            sys::thread_create(
                &process,
                never,
                STACK.top(),
                0,
                1,
                Policy::Fifo,
                BUFFERS + made * PAGE,
            )
        };
        match created {
            Ok(thread) => {
                HELD[made].store(thread.into_raw().0, Ordering::Relaxed);
                made += 1;
            }
            Err(error) => {
                refused = Some(error);
                break;
            }
        }
    }
    for held in &HELD[..made] {
        drop(Handle::<Thread>::from_raw(rt::abi::Handle(
            held.swap(0, Ordering::Relaxed),
        )));
    }
    if made != MAX_THREADS as usize - 1 || refused != Some(Error::LimitReached) {
        rt::println!("one-thread-probe: {} raw threads, then {:?}", made, refused);
        return failed(15);
    }
    rt::println!(
        "one-thread-probe: a single-threaded POSIX process has one thread: {} raw threads more",
        made
    );
    true
}
