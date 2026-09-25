// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! System calls (spec 11, abi::Call): the number in `svc #n`, the
//! arguments in x0-x9; on success x0 is 0 and the values follow from x1,
//! on an error x0 alone holds the code. Every call is said to change
//! x0-x9, so that a later kernel may return more values, and `receive`
//! x0-x11; the kernel keeps every other register. `raw` makes any call
//! with any registers, for tests that hand the kernel bad ones; the
//! functions after it are the typed calls of milestones 1.2c to 1.3b,
//! which take and return handles typed by the kind of their object
//! (`Handle`).

use crate::handle::{Channel, Handle, Process, Resource, Thread};
use abi::{
    Call, Error, KernelStats, Notification, Policy, ProcessHandles, ProcessMemory, ProcessState,
    Source,
};
use core::arch::asm;

/// x0-x9 as a call takes and leaves them.
pub type Regs = [u64; 10];

/// System call `N` with `x` in x0-x9; returns x0-x9 as the kernel left
/// them. x10 and x11 count as changed, which `receive` does when it takes
/// something (spec 11). No number is refused here: the kernel fails an
/// unknown one with INVALID_ARGS.
///
/// # Safety
/// A call can make the kernel run code or use memory of the program
/// against Rust's rules: thread_create starts code at any address on any
/// stack. The caller answers for what the call does.
#[inline(always)]
pub unsafe fn raw<const N: u16>(x: Regs) -> Regs {
    let mut x = x;
    // SAFETY: the caller's promise; the kernel changes x0-x9 only.
    unsafe {
        asm!(
            "svc #{n}",
            n = const N,
            inout("x0") x[0],
            inout("x1") x[1],
            inout("x2") x[2],
            inout("x3") x[3],
            inout("x4") x[4],
            inout("x5") x[5],
            inout("x6") x[6],
            inout("x7") x[7],
            inout("x8") x[8],
            inout("x9") x[9],
            lateout("x10") _,
            lateout("x11") _,
            options(nostack),
        )
    };
    x
}

/// Call `N` with `args` in x0 and up and zero in the rest: x0-x9 on
/// success, the error otherwise, `Error::Unknown` for a code of a later
/// kernel.
fn call<const N: u16>(args: &[u64]) -> Result<Regs, Error> {
    let mut x = [0; 10];
    x[..args.len()].copy_from_slice(args);
    // SAFETY: the calls made through here run no code of the program and
    // use none of its memory; thread_create, which can, is unsafe itself.
    let x = unsafe { raw::<N>(x) };
    match Error::from_code(x[0]) {
        None => Ok(x),
        Some(e) => Err(e),
    }
}

/// The handle a call returned in x1.
fn returned<K>(x: &Regs) -> Handle<K> {
    Handle::from_raw(abi::Handle(x[1]))
}

impl<K> Handle<K> {
    /// handle_close: the handle goes, and its object with its last
    /// reference. Closing a handle to a thread or a process does not end
    /// it.
    pub fn close(self) -> Result<(), Error> {
        call::<{ Call::HandleClose.number() }>(&[self.raw().0]).map(drop)
    }
}

/// process_create with no exit channel and no start channel, the only kind
/// before channels come: a process with an empty address space, a memory
/// quota of `quota` bytes (whole pages, counted from milestone 1.3), room
/// for `handle_limit` handles and priority ceiling `ceiling`. Entry 0 of
/// its table is a stub, so abi::START_CHANNEL is bad there for good. The
/// handle carries DUPLICATE, TRANSFER and MANAGE.
pub fn process_create(
    quota: u64,
    handle_limit: u32,
    ceiling: u8,
) -> Result<Handle<Process>, Error> {
    let args = [quota, handle_limit.into(), ceiling.into(), 0, 0];
    let x = call::<{ Call::ProcessCreate.number() }>(&args)?;
    Ok(returned(&x))
}

/// process_kill: the process ends, whatever its threads do; 0 for one that
/// ended before. Killing the caller's own process does not return.
pub fn process_kill(process: &Handle<Process>) -> Result<(), Error> {
    call::<{ Call::ProcessKill.number() }>(&[process.raw().0]).map(drop)
}

/// process_exit: the caller's process ends with `code`.
pub fn process_exit(code: u64) -> ! {
    // SAFETY: the call ends the process and does not return.
    unsafe {
        asm!(
            "svc #{n}",
            n = const Call::ProcessExit.number(),
            in("x0") code,
            options(noreturn, nostack),
        )
    }
}

/// thread_create: a stopped thread of `process`, the caller's own, that
/// runs `entry(arg)` with stack pointer `stack`, at `priority` under
/// `policy`, with its message buffer at page `buffer` of the process. The
/// handle carries DUPLICATE, TRANSFER and MANAGE. A thread at an address
/// of another process takes `raw`.
///
/// # Safety
/// `stack` is the top of memory nothing else uses while the thread lives
/// (a `Stack`).
pub unsafe fn thread_create(
    process: &Handle<Process>,
    entry: extern "C" fn(u64) -> !,
    stack: usize,
    arg: u64,
    priority: u8,
    policy: Policy,
    buffer: usize,
) -> Result<Handle<Thread>, Error> {
    let args = [
        process.raw().0,
        entry as *const () as u64,
        stack as u64,
        arg,
        priority.into(),
        policy as u64,
        buffer as u64,
    ];
    let x = call::<{ Call::ThreadCreate.number() }>(&args)?;
    Ok(returned(&x))
}

/// thread_start: the stopped thread becomes ready; above the caller, it
/// runs before the call returns.
pub fn thread_start(thread: &Handle<Thread>) -> Result<(), Error> {
    call::<{ Call::ThreadStart.number() }>(&[thread.raw().0]).map(drop)
}

/// thread_exit: the calling thread ends; the last started thread of a
/// process ends the process with code 0.
pub fn thread_exit() -> ! {
    // SAFETY: the call ends the thread and does not return.
    unsafe {
        asm!(
            "svc #{n}",
            n = const Call::ThreadExit.number(),
            options(noreturn, nostack),
        )
    }
}

/// thread_set_priority: the thread's priority (1-63, no higher than both
/// ceilings) and policy change; a thread raised above the caller, or one
/// the caller lowered itself below, runs before the call returns.
pub fn thread_set_priority(
    thread: &Handle<Thread>,
    priority: u8,
    policy: Policy,
) -> Result<(), Error> {
    let args = [thread.raw().0, priority.into(), policy as u64];
    call::<{ Call::ThreadSetPriority.number() }>(&args).map(drop)
}

/// yield: the caller goes to the tail of its level, and the next thread
/// there runs; lower levels do not.
pub fn yield_now() -> Result<(), Error> {
    call::<{ Call::Yield.number() }>(&[]).map(drop)
}

/// object_info(PROCESS_STATE): whether the process lives and, if not,
/// why it ended; a state of a later kernel comes back as `Unknown`.
pub fn process_state(process: &Handle<Process>) -> Result<ProcessState, Error> {
    let args = [process.raw().0, abi::INFO_PROCESS_STATE, 0];
    let x = call::<{ Call::ObjectInfo.number() }>(&args)?;
    Ok(ProcessState::from_words([x[1], x[2], x[3], x[4]]))
}

/// object_info(PROCESS_MEMORY): the process's quota, what is charged to it
/// and what went back to its parent, in bytes.
pub fn process_memory(process: &Handle<Process>) -> Result<ProcessMemory, Error> {
    let args = [process.raw().0, abi::INFO_PROCESS_MEMORY, 0];
    let x = call::<{ Call::ObjectInfo.number() }>(&args)?;
    Ok(ProcessMemory::from_words([x[1], x[2], x[3]]))
}

/// object_info(PROCESS_HANDLES): the process's live handles, its retired
/// entries and its limit.
pub fn process_handles(process: &Handle<Process>) -> Result<ProcessHandles, Error> {
    let args = [process.raw().0, abi::INFO_PROCESS_HANDLES, 0];
    let x = call::<{ Call::ObjectInfo.number() }>(&args)?;
    Ok(ProcessHandles::from_words([x[1], x[2], x[3]]))
}

/// object_info(KERNEL_STATS) through the system resource with KSTATS: what
/// the kernel counts about itself, times in counter ticks.
pub fn kernel_stats(resource: &Handle<Resource>) -> Result<KernelStats, Error> {
    let args = [resource.raw().0, abi::INFO_KERNEL_STATS, 0];
    let x = call::<{ Call::ObjectInfo.number() }>(&args)?;
    Ok(KernelStats::from_words([
        x[1], x[2], x[3], x[4], x[5], x[6], x[7],
    ]))
}

/// debug_write: up to abi::INLINE_MAX bytes to the console through the
/// system resource with DEBUG; returns their count. More bytes fail with
/// INVALID_ARGS, as the kernel would fail them.
pub fn debug_write(resource: &Handle<Resource>, bytes: &[u8]) -> Result<usize, Error> {
    if bytes.len() > abi::INLINE_MAX {
        return Err(Error::InvalidArgs);
    }
    let mut args = [0; 10];
    args[0] = resource.raw().0;
    args[1] = bytes.len() as u64;
    args[2..].copy_from_slice(&abi::inline_words(bytes));
    let x = call::<{ Call::DebugWrite.number() }>(&args)?;
    Ok(x[1] as usize)
}

/// channel_create: a channel whose slot of label 0 has `priority` (1-63,
/// no higher than the caller's ceiling). The handle carries SEND, NOTIFY,
/// RECEIVE, DUPLICATE and TRANSFER (abi::CHANNEL_RIGHTS).
pub fn channel_create(priority: u8) -> Result<Handle<Channel>, Error> {
    let x = call::<{ Call::CreateChannel.number() }>(&[priority.into()])?;
    Ok(returned(&x))
}

/// notify: `bits` go into the channel's slot of label 0 (spec 6.5), ORed
/// with those not yet received; a receiver that waits above the caller
/// runs before the call returns. Bit 63 is the kernel's (INVALID_ARGS);
/// PEER_CLOSED once no handle with RECEIVE is left.
pub fn notify(channel: &Handle<Channel>, bits: u64) -> Result<(), Error> {
    call::<{ Call::Notify.number() }>(&[channel.raw().0, bits]).map(drop)
}

/// What `receive` took (spec 6.1, 6.5): a notification; requests come in
/// milestone 1.3c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    Notification {
        source: Source,
        label: u64,
        bits: u64,
        count: u32,
    },
}

/// receive: waits until the channel has something and takes it. The caller
/// works at the priority of the notification it took, under its ceiling,
/// until its next receive (spec 6.6). PEER_CLOSED when the last handle
/// with RECEIVE goes while the caller waits.
pub fn receive(channel: &Handle<Channel>) -> Result<Received, Error> {
    receive_with(channel, 0)
}

/// receive with abi::NO_WAIT: WOULD_BLOCK when the channel has nothing.
pub fn try_receive(channel: &Handle<Channel>) -> Result<Received, Error> {
    receive_with(channel, abi::NO_WAIT)
}

/// receive with `flags`; the call is said to change x0-x11 (spec 11).
fn receive_with(channel: &Handle<Channel>, flags: u64) -> Result<Received, Error> {
    let mut x = [0; 12];
    x[0] = channel.raw().0;
    x[1] = flags;
    // SAFETY: receive uses no memory of the program; it writes x0-x11 only.
    unsafe {
        asm!(
            "svc #{n}",
            n = const Call::Receive.number(),
            inout("x0") x[0],
            inout("x1") x[1],
            inout("x2") x[2],
            inout("x3") x[3],
            inout("x4") x[4],
            inout("x5") x[5],
            inout("x6") x[6],
            inout("x7") x[7],
            inout("x8") x[8],
            inout("x9") x[9],
            inout("x10") x[10],
            inout("x11") x[11],
            options(nostack),
        )
    };
    if let Some(e) = Error::from_code(x[0]) {
        return Err(e);
    }
    let words = x[1..].try_into().expect("x1-x11");
    let Notification {
        source,
        label,
        bits,
        count,
    } = Notification::from_words(words);
    Ok(Received::Notification {
        source,
        label,
        bits,
        count,
    })
}
