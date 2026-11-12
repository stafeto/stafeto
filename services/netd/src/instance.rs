// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A stack instance of the service: what one thread of `rt::service` owns of the network. The
//! smoltcp interface with its sets of sockets (`stack`), the table of places of the
//! descriptions and what hangs on them (`net`: the sessions' sockets, the interest sets, the
//! long operations, the counters), and the device the stack sees (`device`), which is a lane of
//! rings of buffer numbers to the switch. The instance is an internal consumer of the switch
//! (`netd::switchlogic::tables::Internal`): it has a number there, and the switch hands it the
//! frames of the tables' decisions through its lane without copying them.
//!
//! The thread of the instance runs `rt::service::run_in` on a channel of its own (`launch`),
//! above every process, and a thread of the process that has nothing else to do waits
//! (`wait_forever`). Several instances, each in a thread on its own CPU, are the next stages;
//! what they share (the port registry, the neighbours, the address) is theirs to settle.

use crate::device::NetDevice;
use crate::net::{Client, Net};
use crate::stack::Stack;
use crate::switch::Lane;
use rt::handle::{Channel, Process};
use rt::service::{Config, Session};
use rt::{Handle, Stack as ThreadStack, sys};

/// The pieces of one instance.
pub struct Instance<'a> {
    /// The rings between the instance and the switch (its place in them is its number as a
    /// consumer in the switch's tables).
    pub lane: &'static Lane,
    pub device: NetDevice,
    pub stack: Stack<'static>,
    pub net: &'a mut Net,
}

impl<'a> Instance<'a> {
    pub fn new(
        lane: &'static Lane,
        device: NetDevice,
        stack: Stack<'static>,
        net: &'a mut Net,
    ) -> Instance<'a> {
        Instance {
            lane,
            device,
            stack,
            net,
        }
    }
}

/// What the instance's thread takes from the thread that made it: the driver (which stays on
/// the stack of the first thread, and lives as long as that thread waits), the channel and
/// the table of sessions of its loop, and the function that runs the loop and returns the
/// program's code when it ends.
pub struct Launch<'a, D> {
    pub driver: &'a mut D,
    pub channel: &'a Handle<Channel>,
    pub config: Option<Config<'a>>,
    pub sessions: &'a mut [Option<Session<Client, 0>>],
    pub entry: fn(&mut Launch<'_, D>) -> u64,
}

const STACK_BYTES: usize = 64 * 1024;
static STACK: ThreadStack<STACK_BYTES> = ThreadStack::new();
/// The message buffer of the thread: the page after the switch's, which follows the first
/// thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 2 * 4096;

/// Why the thread did not start.
#[derive(Debug)]
pub struct NotStarted;

/// Starts the instance's thread at `priority` over `launch`, which stays where it is until the
/// service ends. The thread runs `launch.entry` and ends the program with its code.
pub fn start<D>(
    launch: &mut Launch<'_, D>,
    process: &Handle<Process>,
    priority: u8,
) -> Result<(), NotStarted> {
    let arg = core::ptr::from_mut(launch) as u64;
    // SAFETY: STACK is the thread's alone, and the page after the switch thread's message
    // buffer is free; `arg` points to a launch that outlives the thread (the first thread
    // waits for ever after this).
    let thread = unsafe {
        sys::thread_create(
            process,
            thread_main::<D>,
            STACK.top(),
            arg,
            priority,
            abi::Policy::Fifo,
            BUFFER,
        )
    }
    .map_err(|_| NotStarted)?;
    sys::thread_start(&thread).map_err(|_| NotStarted)?;
    // The thread runs as long as the program does; its handle is not needed.
    core::mem::forget(thread);
    Ok(())
}

extern "C" fn thread_main<D>(arg: u64) -> ! {
    // SAFETY: `start` passed the address of a launch that is alive and that this thread alone
    // uses from here on.
    let launch = unsafe { &mut *(arg as *mut Launch<'_, D>) };
    let code = (launch.entry)(launch);
    sys::process_exit(code)
}

/// The first thread has made all there is to make: it waits on a channel nobody writes to, at
/// the level of the service, so that the driver on its stack stays.
pub fn wait_forever(priority: u8) -> ! {
    let channel = sys::channel_create_wait(priority);
    loop {
        match &channel {
            Ok(c) => {
                let _ = sys::receive(c);
            }
            Err(_) => sys::process_exit(crate::STOPPED),
        }
    }
}
