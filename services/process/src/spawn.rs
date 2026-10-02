// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The spawning thread (5b, until the loader of 5c): it takes the next
//! Spawn from the loop (Next), asks init for the record of init's table
//! that starts on demand under its name (SPAWN, proto_init), makes the
//! child with the parent's label as for ADOPT (make.rs) and gives it to
//! init with ADOPTED; the parent's Spawn gets the child's PID with Loaded,
//! or a status with Abandon. Its stack, message buffer and loader window
//! are its own; it works at the loop's level but for the load.

use crate::make::{self, Failed};
use core::sync::atomic::{AtomicU64, Ordering};
use proto_init::Adoption;
use proto_process::{Create, Method, Next};
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Handle, Process, Thread};
use rt::{Stack, abi, sys};

const STACK_SIZE: usize = 16 * 1024;
static STACK: Stack<STACK_SIZE> = Stack::new();
/// The thread's message buffer, two pages after the main thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 2 * 4096;
/// Where the thread maps the objects of a program it loads.
const WINDOW: usize = 0x61_0000_0000;
/// The value of the thread's own handle, which the service keeps for good.
static THREAD: AtomicU64 = AtomicU64::new(0);

/// Starts the spawning thread at `level` in `own`, the service's process.
pub fn start(own: &Handle<Process>, level: u8) -> Result<(), abi::Error> {
    // SAFETY: STACK is the thread's alone, and the page two after the main
    // thread's buffer is free.
    let thread = unsafe {
        sys::thread_create(
            own,
            spawner,
            STACK.top(),
            0,
            level,
            abi::Policy::Fifo,
            BUFFER,
        )
    }?;
    // The thread lives as long as the service, and sets its own priority.
    THREAD.store(thread.into_raw().0, Ordering::Release);
    sys::thread_start(&Handle::<Thread>::borrowed(abi::Handle(
        THREAD.load(Ordering::Acquire),
    )))
}

/// The status the parent's Spawn gets for a refusal of SPAWN: NOT_FOUND
/// for a name of no record that starts on demand, AGAIN for one whose
/// instance lives or for any other refusal.
fn refused(status: Status) -> Status {
    match status {
        Status::Kernel(abi::Error::AccessDenied) => Status::from_code(proto_process::NOT_FOUND),
        _ => Status::from_code(proto_process::AGAIN),
    }
}

extern "C" fn spawner(_: u64) -> ! {
    let init = make::init();
    let own = Handle::<Thread>::borrowed(abi::Handle(THREAD.load(Ordering::Acquire)));
    let channel = make::channel();
    let mut buffer = [0; abi::MESSAGE_MAX];
    loop {
        let next = match sys::send(&channel, &Method::Next.header().bytes()) {
            Ok(reply) => Next::read(reply.bytes(&mut buffer)),
            Err(e) => Err(Status::Kernel(e)),
        };
        // The loop answers one Next at a time; a refusal would only come
        // again, so the service ends, and init fails its POSIX records.
        let Ok(next) = next else {
            sys::process_exit(10);
        };
        let mut w = Writer::new();
        if proto_init::Method::Spawn.header().write(&mut w).is_err()
            || w.name(Some(next.name)).is_err()
        {
            continue;
        }
        let mut reply = match sys::send(&init, w.as_bytes()) {
            Ok(reply) => reply,
            Err(e) => {
                let _ = make::abandon(0, next.parent, refused(Status::Kernel(e)));
                continue;
            }
        };
        let bytes = reply.bytes(&mut buffer);
        let adoption = match make::status(bytes) {
            Ok(Status::Ok) => Adoption::read(bytes),
            Ok(status) | Err(status) => Err(status),
        };
        let adoption = match adoption {
            Ok(adoption) => adoption,
            Err(status) => {
                let _ = make::abandon(0, next.parent, refused(status));
                continue;
            }
        };
        let create = Create {
            quota: adoption.quota,
            handle_limit: adoption.handle_limit,
            ceiling: adoption.ceiling,
            priority: adoption.priority,
            root: false,
            parent: next.parent,
        };
        let handed = (
            reply.handles.take::<Channel>(0),
            reply.handles.take::<Channel>(1),
        );
        let made = match handed {
            // SAFETY: only this thread maps and uses WINDOW.
            (Ok(start), Ok(witness)) => unsafe {
                make::make(
                    &create,
                    [start, witness],
                    &adoption.program,
                    WINDOW,
                    &own,
                    adoption.priority.max(next.level),
                )
            },
            _ => Err(Failed {
                status: Status::BadSize,
                label: None,
            }),
        };
        make::adopted(adoption.ticket, made, next.parent);
    }
}
