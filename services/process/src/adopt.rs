// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The adopter (spec 2, section 3.1): a thread of the service that asks
//! init for the next POSIX process init loaded (ADOPT, proto_init), makes
//! its record through the service's own channel with no label (Create),
//! and gives init the session (ADOPTED), so that init starts the process.
//! The request goes down to init, which holds it until a process waits;
//! init never waits for the service (spec 6.7). The thread works at the
//! loop's level; its stack and message buffer are its own.

use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU64, Ordering};
use process_client::Client;
use proto_init::Method;
use proto_wire::{Reader, Status, Writer};
use rt::handle::{Channel, Handle, Process};
use rt::{Stack, abi, sys};

const STACK_SIZE: usize = 16 * 1024;
static STACK: Stack<STACK_SIZE> = Stack::new();
/// The adopter's message buffer, the page after the main thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 4096;
/// The values of init's channel (Startup::parent) and of the service's
/// channel, which the main thread keeps for good.
static HANDLES: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// Starts the adopter at `level` in `own`, the service's process.
pub fn start(
    own: &Handle<Process>,
    parent: &Handle<Channel>,
    channel: &Handle<Channel>,
    level: u8,
) -> Result<(), abi::Error> {
    HANDLES[0].store(parent.raw().0, Ordering::Relaxed);
    HANDLES[1].store(channel.raw().0, Ordering::Relaxed);
    // SAFETY: STACK is the adopter's alone, and the page after the main
    // thread's buffer is free.
    let thread = unsafe {
        sys::thread_create(
            own,
            adopter,
            STACK.top(),
            0,
            level,
            abi::Policy::Fifo,
            BUFFER,
        )
    }?;
    sys::thread_start(&thread)?;
    // The thread lives as long as the service; its handle may go.
    Ok(())
}

/// The status of a reply, its first word.
fn status(bytes: &[u8]) -> Result<Status, Status> {
    Ok(Status::from_code(Reader::new(bytes).u32()?))
}

extern "C" fn adopter(_: u64) -> ! {
    let parent = Handle::<Channel>::borrowed(abi::Handle(HANDLES[0].load(Ordering::Relaxed)));
    let own = Handle::<Channel>::borrowed(abi::Handle(HANDLES[1].load(Ordering::Relaxed)));
    let records = ManuallyDrop::new(Client::new(ManuallyDrop::into_inner(own)));
    let mut buffer = [0; abi::MESSAGE_MAX];
    loop {
        let mut reply = match sys::send(&parent, &Method::Adopt.header().bytes()) {
            Ok(reply) => reply,
            Err(abi::Error::Interrupted) => continue,
            // Init lives as long as the system; nothing is left to adopt.
            Err(_) => sys::thread_exit(),
        };
        let bytes = reply.bytes(&mut buffer);
        let mut r = Reader::new(bytes);
        let taken = (|| -> Result<(u64, bool), Status> {
            if status(bytes)? != Status::Ok {
                return Err(Status::BadSize);
            }
            // The status takes a header's 8 bytes, as in every reply.
            r.u32()?;
            r.u32()?;
            let (ticket, root) = (r.u64()?, r.u32()?);
            r.finish()?;
            Ok((ticket, root == 1))
        })();
        let Ok((ticket, root)) = taken else {
            continue;
        };
        let made = reply
            .handles
            .take::<Process>(0)
            .map_err(|_| Status::BadSize)
            .and_then(|process| records.create(&process, root));
        let mut w = Writer::new();
        let code = match &made {
            Ok(_) => 0,
            Err(status) => status.code().max(1),
        };
        if Method::Adopted.header().write(&mut w).is_err()
            || w.u64(ticket).is_err()
            || w.u32(code).is_err()
        {
            continue;
        }
        // Init answers at once; a lost answer leaves its process waiting
        // for a session no longer coming, which only the service's end
        // settles.
        let _ = match made {
            Ok((_, session)) => sys::send_handles(&parent, w.as_bytes(), [session.erase()])
                .map(drop)
                .map_err(|e| e.error),
            Err(_) => sys::send(&parent, w.as_bytes()).map(drop),
        };
    }
}
