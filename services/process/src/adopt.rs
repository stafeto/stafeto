// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The receiving thread (spec 2, section 3.1): it asks init for the next
//! POSIX record of init's table to start (ADOPT, proto_init), makes its
//! process with the parameters and the start channel init gave (make.rs),
//! and gives init the record's session, the process and its thread
//! (ADOPTED); once init answered, it starts the thread and tells the loop
//! (Loaded), or kills the process (Abandon). The request goes down to
//! init, which holds it until a record waits; init never waits for the
//! service (spec 6.7). The thread works at the loop's level but for the
//! load; its stack, message buffer and loader window are its own.

use crate::make::{self, Failed, Made};
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU64, Ordering};
use proto_init::{Adoption, Method};
use proto_process::Create;
use proto_wire::{Reader, Status, Writer};
use rt::handle::{Channel, Handle, Process, Thread};
use rt::{Stack, abi, sys};

const STACK_SIZE: usize = 16 * 1024;
static STACK: Stack<STACK_SIZE> = Stack::new();
/// The thread's message buffer, the page after the main thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 4096;
/// Where the thread maps the objects of a program it loads.
const WINDOW: usize = 0x60_0000_0000;
/// The values of init's channel (Startup::parent) and of the thread's own
/// handle, which the service keeps for good.
static HANDLES: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// Starts the receiving thread at `level` in `own`, the service's process.
pub fn start(own: &Handle<Process>, parent: &Handle<Channel>, level: u8) -> Result<(), abi::Error> {
    HANDLES[0].store(parent.raw().0, Ordering::Relaxed);
    // SAFETY: STACK is the thread's alone, and the page after the main
    // thread's buffer is free.
    let thread = unsafe {
        sys::thread_create(
            own,
            receiver,
            STACK.top(),
            0,
            level,
            abi::Policy::Fifo,
            BUFFER,
        )
    }?;
    // The thread lives as long as the service, and sets its own priority.
    HANDLES[1].store(thread.into_raw().0, Ordering::Release);
    let thread = Handle::<Thread>::borrowed(abi::Handle(HANDLES[1].load(Ordering::Acquire)));
    sys::thread_start(&thread)
}

/// The status of a reply, its first word.
fn status(bytes: &[u8]) -> Result<Status, Status> {
    Ok(Status::from_code(Reader::new(bytes).u32()?))
}

extern "C" fn receiver(_: u64) -> ! {
    let parent = Handle::<Channel>::borrowed(abi::Handle(HANDLES[0].load(Ordering::Relaxed)));
    let own = Handle::<Thread>::borrowed(abi::Handle(HANDLES[1].load(Ordering::Acquire)));
    let mut buffer = [0; abi::MESSAGE_MAX];
    #[cfg(feature = "adoption-refusals")]
    refusals(&parent);
    loop {
        let mut reply = match sys::send(&parent, &Method::Adopt.header().bytes()) {
            Ok(reply) => reply,
            Err(abi::Error::Interrupted) => continue,
            // The service cannot take processes any more: it ends, so that
            // init sees its failure and fails the POSIX records that wait.
            Err(_) => sys::process_exit(7),
        };
        // A refusal of init (a second ADOPT, a reply out of the layout)
        // would only come again: the service ends, as above.
        let Ok(adoption) = Adoption::read(reply.bytes(&mut buffer)) else {
            sys::process_exit(8);
        };
        let create = Create {
            quota: adoption.quota,
            handle_limit: adoption.handle_limit,
            ceiling: adoption.ceiling,
            priority: adoption.priority,
            root: adoption.root,
        };
        let made = match reply.handles.take::<Channel>(0) {
            // SAFETY: only this thread maps and uses WINDOW.
            Ok(start) => unsafe { make::make(&create, start, &adoption.program, WINDOW, &own) },
            Err(_) => Err(Failed {
                status: Status::BadSize,
                label: None,
            }),
        };
        adopted(&parent, adoption.ticket, made);
    }
}

/// ADOPTED for `ticket` with what `made` gave: the session, the process
/// and a copy of its thread, then thread_start and Loaded once init took
/// them; a refusal of init, or no process, ends the record (Abandon).
fn adopted(parent: &ManuallyDrop<Handle<Channel>>, ticket: u64, made: Result<Made, Failed>) {
    let mut w = Writer::new();
    if Method::Adopted.header().write(&mut w).is_err() || w.u64(ticket).is_err() {
        return;
    }
    let made = match made {
        Ok(made) => made,
        Err(failed) => {
            if let Some(label) = failed.label {
                let _ = make::tell(proto_process::Method::Abandon, label);
            }
            let _ = w.u32(failed.status.code().max(1));
            // Init answers at once; a lost answer leaves its record waiting
            // until the start channel's end, which the failure closed.
            let _ = sys::send(parent, w.as_bytes());
            return;
        }
    };
    let Made {
        label,
        process,
        session,
        thread,
        ..
    } = made;
    let copy = sys::handle_duplicate(&thread, abi::Rights::MANAGE | abi::Rights::TRANSFER);
    let taken = w.u32(0).is_ok()
        && copy.is_ok_and(|copy| {
            let mut buffer = [0; abi::MESSAGE_MAX];
            let handles = [session.erase(), process.erase(), copy.erase()];
            sys::send_handles(parent, w.as_bytes(), handles)
                .is_ok_and(|reply| status(reply.bytes(&mut buffer)) == Ok(Status::Ok))
        });
    if taken && sys::thread_start(&thread).is_ok() {
        let _ = make::tell(proto_process::Method::Loaded, label);
    } else {
        let _ = make::tell(proto_process::Method::Abandon, label);
    }
}

/// The refusals of ADOPT and ADOPTED that only the service can reach
/// (adoption-refusals): ADOPT with a byte after the header and ADOPTED with
/// one after its body BAD_SIZE, ADOPTED with a ticket no record has
/// INVALID_ARGS. Says so in one line.
#[cfg(feature = "adoption-refusals")]
fn refusals(parent: &Handle<Channel>) {
    let answer = |w: &Writer| {
        let mut buffer = [0; abi::MESSAGE_MAX];
        sys::send(parent, w.as_bytes())
            .map_err(Status::Kernel)
            .and_then(|reply| status(reply.bytes(&mut buffer)))
    };
    let mut adopt = Writer::new();
    let _ = Method::Adopt.header().write(&mut adopt);
    let _ = adopt.u32(0);
    let adopted = |ticket: u64, extra: bool| {
        let mut w = Writer::new();
        let _ = Method::Adopted.header().write(&mut w);
        let _ = w.u64(ticket);
        let _ = w.u32(1);
        if extra {
            let _ = w.u32(0);
        }
        w
    };
    let ok = answer(&adopt) == Ok(Status::BadSize)
        && answer(&adopted(u64::MAX, true)) == Ok(Status::BadSize)
        && answer(&adopted(u64::MAX, false)) == Ok(Status::Kernel(abi::Error::InvalidArgs));
    let verdict = if ok { "ok" } else { "failed" };
    rt::println!("posix-process: adoption refusals {verdict}");
}
