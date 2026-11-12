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
//! (`wait_forever`). The service runs one instance for each CPU of its mask, each in a thread
//! on its own CPU (`start`); what they share is one address (`netd::published`), one port
//! space (`netd::ports::CLAIMS`) and the rings of the switch, one lane for each.

use crate::device::NetDevice;
use crate::net::{Client, Net};
use crate::stack::Stack;
use crate::switch::Lane;
use netd::switchlogic::tables::MAX_INSTANCES;
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
static STACKS: [ThreadStack<STACK_BYTES>; MAX_INSTANCES] =
    [const { ThreadStack::new() }; MAX_INSTANCES];
/// The message buffer of instance `k`'s thread: the pages after the switch's, which follows
/// the first thread's.
const fn buffer(k: usize) -> usize {
    abi::INIT_MSGBUF as usize + (2 + k) * 4096
}

/// Why the thread did not start.
#[derive(Debug)]
pub struct NotStarted;

/// Starts the thread of instance `k` on CPU `cpu` (the kernel's choice when none) at
/// `priority` over `launch`, which stays where it is until the service ends. The thread runs
/// `launch.entry` and ends the program with its code.
pub fn start<D>(
    launch: &mut Launch<'_, D>,
    process: &Handle<Process>,
    priority: u8,
    k: usize,
    cpu: Option<u32>,
) -> Result<(), NotStarted> {
    let arg = core::ptr::from_mut(launch) as u64;
    // SAFETY: the stack of `k` is the thread's alone, and the page of its message buffer is
    // free; `arg` points to a launch that outlives the thread (the first thread waits for
    // ever after this).
    let thread = unsafe {
        sys::thread_create_on(
            process,
            thread_main::<D>,
            STACKS[k].top(),
            arg,
            priority,
            abi::Policy::Fifo,
            buffer(k),
            None,
            // The CPU plus one; 0 is the CPU of the caller.
            cpu.map_or(0, |c| c as u8 + 1),
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
