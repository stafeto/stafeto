// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The registration of the service's root with the process service
//! (`proto_net::ROOT`, Register with the NET mark of the notary session), for
//! the loaders to verify the Net session of a set-ID program with.
//!
//! A thread of its own makes it (`rt::roots::keep`): the connection to the
//! process service waits in init until the process service has started, and
//! neither the loop of an instance, with its heartbeat and its step bound, nor
//! the switch thread may wait for that. The thread tries again, with a
//! growing pause, until the root is registered, says so when it does not
//! succeed, and ends.

use core::sync::atomic::{AtomicU64, Ordering};
use netd::switchlogic::tables::MAX_INSTANCES;
use rt::handle::{Channel, Process};
use rt::{Handle, Stack as ThreadStack, sys};

const STACK_BYTES: usize = 16 * 1024;
static STACK: ThreadStack<STACK_BYTES> = ThreadStack::new();
/// The message buffer of the thread: the page after those of the instances.
const BUFFER: usize = abi::INIT_MSGBUF as usize + (2 + MAX_INSTANCES) * 4096;

/// What the thread takes from the first one: the connection to init, the
/// channel of the first instance (the root is a copy of it) and the level.
static PARENT: AtomicU64 = AtomicU64::new(0);
static CHANNEL: AtomicU64 = AtomicU64::new(0);
static LEVEL: AtomicU64 = AtomicU64::new(1);

/// Starts the thread. `parent` and `channel` stay open for the life of the
/// service. A thread that does not start leaves the service with no root,
/// which it says: a set-ID start that needs the root is refused.
pub fn start(
    process: &Handle<Process>,
    parent: &Handle<Channel>,
    channel: &Handle<Channel>,
    level: u8,
) {
    PARENT.store(parent.raw().0, Ordering::Release);
    CHANNEL.store(channel.raw().0, Ordering::Release);
    LEVEL.store(u64::from(level), Ordering::Release);
    // SAFETY: STACK is the thread's alone, and the page of its message buffer
    // is free.
    let thread = unsafe {
        sys::thread_create(
            process,
            run,
            STACK.top(),
            0,
            level,
            abi::Policy::Fifo,
            BUFFER,
        )
    };
    match thread {
        Ok(thread) if sys::thread_start(&thread).is_ok() => core::mem::forget(thread),
        _ => rt::println!(
            "net: no thread to register the root; set-ID starts are refused until it is registered"
        ),
    }
}

extern "C" fn run(_: u64) -> ! {
    let parent = Handle::<Channel>::borrowed(abi::Handle(PARENT.load(Ordering::Acquire)));
    let channel = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Ordering::Acquire)));
    let level = LEVEL.load(Ordering::Acquire) as u8;
    rt::roots::keep(&parent, &channel, proto_net::ROOT, level, "net")
}
