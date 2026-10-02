// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The thread that tells init of an exec: a record of init's table that
//! makes one gets a new process, and init, which reads the end of the
//! record from the process it keeps a copy of, must take the new one
//! (REPLACED, proto_init). The loop never sends to init, which lies below
//! it, so this thread waits in the loop for the next ExecCommit of such a
//! record (Replace), sends init the new process, and names the record in
//! its next Replace, on which the loop lets the new image run and the old
//! one go on. The thread works at the loop's level; its stack and message
//! buffer are its own.

use crate::make;
use core::sync::atomic::{AtomicU64, Ordering};
use proto_process::Method;
use proto_wire::{Reader, Writer};
use rt::handle::{Handle, Thread};
use rt::{Stack, abi, sys};

const STACK_SIZE: usize = 16 * 1024;
static STACK: Stack<STACK_SIZE> = Stack::new();
/// The thread's message buffer, two pages after the main thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 2 * 4096;
/// The value of the thread's own handle, which the service keeps for good.
static THREAD: AtomicU64 = AtomicU64::new(0);

/// Starts the thread at `level` in `own`, the service's process.
pub fn start(own: &Handle<rt::handle::Process>, level: u8) -> Result<(), abi::Error> {
    // SAFETY: STACK is the thread's alone, and the page two after the main
    // thread's buffer is free.
    let thread = unsafe {
        sys::thread_create(
            own,
            replacer,
            STACK.top(),
            0,
            level,
            abi::Policy::Fifo,
            BUFFER,
        )
    }?;
    // The thread lives as long as the service.
    THREAD.store(thread.into_raw().0, Ordering::Release);
    sys::thread_start(&Handle::<Thread>::borrowed(abi::Handle(
        THREAD.load(Ordering::Acquire),
    )))
}

extern "C" fn replacer(_: u64) -> ! {
    let init = make::init();
    let channel = make::channel();
    let mut buffer = [0; abi::MESSAGE_MAX];
    let mut done = 0u64;
    loop {
        let mut w = Writer::new();
        if Method::Replace.header().write(&mut w).is_err() || w.u64(done).is_err() {
            sys::process_exit(11);
        }
        done = 0;

        let mut reply = match sys::send(&channel, w.as_bytes()) {
            Ok(reply) => reply,
            Err(abi::Error::Interrupted) => continue,
            // The loop does not answer any more: the service ends.
            Err(_) => sys::process_exit(12),
        };
        let mut r = Reader::new(reply.bytes(&mut buffer));
        let work = (|| Ok::<_, proto_wire::Status>((r.u32()?, r.u32()?, r.u64()?, r.u64()?)))();
        let (Ok((0, _, label, ticket)), Ok(process)) =
            (work, reply.handles.take::<rt::handle::Process>(0))
        else {
            continue;
        };
        let mut w = Writer::new();
        if proto_init::Method::Replaced.header().write(&mut w).is_ok() && w.u64(ticket).is_ok() {
            // Init's answer matters little: it keeps the old process of a
            // record it knows no more, and the exec goes on either way.
            let _ = sys::send_handles(&init, w.as_bytes(), [process.erase()]);
        }
        done = label;
    }
}
