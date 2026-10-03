// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The thread that takes what comes into the channel of the identity
//! sessions (5c): the ends of identity sessions (CLIENT_GONE), each of
//! which holds a slot of the channel until it is received, and the
//! notifications processes send through their own copies. Vouch reads the
//! label of a copy with object_info LABEL and never looks into the queue,
//! so nothing there has a meaning: the thread takes it and drops it, one
//! receive at a time, each a call of the kernel bounded on its own. No
//! step of the loop empties the channel, and none grows with the number
//! of processes. The thread works at the loop's level and runs whenever
//! the loop waits; its stack and message buffer are its own.

use core::sync::atomic::{AtomicU64, Ordering};
use rt::handle::{Channel, Handle, Process, Thread};
use rt::{Stack, abi, sys};

const STACK_SIZE: usize = 4 * 1024;
static STACK: Stack<STACK_SIZE> = Stack::new();
/// The thread's message buffer, three pages after the main thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 3 * 4096;
/// The identity channel, which the service keeps for good, and the
/// thread's own handle.
static IDENTITIES: AtomicU64 = AtomicU64::new(0);
static THREAD: AtomicU64 = AtomicU64::new(0);

/// Starts the thread at `level` in `own`, the service's process, on the
/// channel `identities`.
pub fn start(
    own: &Handle<Process>,
    identities: &Handle<Channel>,
    level: u8,
) -> Result<(), abi::Error> {
    IDENTITIES.store(identities.raw().0, Ordering::Release);
    // SAFETY: STACK is the thread's alone, and the page three after the
    // main thread's buffer is free.
    let thread = unsafe {
        sys::thread_create(own, taker, STACK.top(), 0, level, abi::Policy::Fifo, BUFFER)
    }?;
    // The thread lives as long as the service.
    THREAD.store(thread.into_raw().0, Ordering::Release);
    sys::thread_start(&Handle::<Thread>::borrowed(abi::Handle(
        THREAD.load(Ordering::Acquire),
    )))
}

extern "C" fn taker(_: u64) -> ! {
    let identities = Handle::<Channel>::borrowed(abi::Handle(IDENTITIES.load(Ordering::Acquire)));
    loop {
        // An end or a notification goes as it is taken; the channel stays
        // open as long as the service, and the thread ends with it.
        if sys::receive(&identities).is_err() {
            sys::thread_exit();
        }
    }
}
