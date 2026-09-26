// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! System calls (spec 11, abi::Call): the number in `svc #n`, the
//! arguments in x0-x9; on success x0 is 0 and the values follow from x1,
//! on an error x0 alone holds the code. Every call is said to change
//! x0-x9, so that a later kernel may return more values, and `receive`
//! x0-x11; the kernel keeps every other register. `raw` makes any call
//! with any registers, for tests that hand the kernel bad ones; the
//! functions after it are the typed calls of milestones 1.2c to 1.3e,
//! which take and return handles typed by the kind of their object
//! (`Handle`), and the token of a request, which answers it once
//! (`Token`).

use crate::handle::{Channel, Handle, Interrupt, Memory, Process, Resource, Thread, Timer};
use crate::msgbuf;
use abi::{
    Access, Call, Error, HANDLES_SHIFT, INLINE_MAX, IrqInfo, KernelStats, MESSAGE_HANDLES,
    MESSAGE_MAX, MemoryInfo, Message, Notification, Policy, ProcessHandles, ProcessMemory,
    ProcessState, Rights, SOURCE_SHIFT, Source, TRIGGER_EDGE,
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
    // use none of its memory; thread_create, mem_unmap and mem_protect,
    // which can, are unsafe themselves.
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

/// handle_duplicate with no new label (spec 5.2, 5.3): a copy of `h` with
/// `rights`, which the handle has, and it needs DUPLICATE. A copy of a
/// handle with a label carries that label.
pub fn handle_duplicate<K>(h: &Handle<K>, rights: Rights) -> Result<Handle<K>, Error> {
    let args = [h.raw().0, rights.0.into(), 0, 0];
    let x = call::<{ Call::HandleDuplicate.number() }>(&args)?;
    Ok(returned(&x))
}

/// handle_duplicate with a new label: a copy of `channel`, a handle with no
/// label and with DUPLICATE, that carries `rights` and `label` (not 0).
/// The kernel makes a session for it (spec 5.3), whose slot has `priority`
/// (1-63, no higher than the caller's ceiling) and which the caller's
/// quota pays for. notify through the copy and its copies goes into the
/// session's slot, and receive reports the label; when the last of them
/// goes, the session's slot gets CLIENT_GONE.
pub fn handle_label(
    channel: &Handle<Channel>,
    rights: Rights,
    label: u64,
    priority: u8,
) -> Result<Handle<Channel>, Error> {
    let args = [channel.raw().0, rights.0.into(), label, priority.into()];
    let x = call::<{ Call::HandleDuplicate.number() }>(&args)?;
    Ok(returned(&x))
}

/// process_create with no exit channel and no start channel: a process
/// with an empty address space, a memory quota of `quota` bytes (whole
/// pages, counted from milestone 1.3), room for `handle_limit` handles and
/// priority ceiling `ceiling`. Entry 0 of its table is a stub, so
/// abi::START_CHANNEL is bad there for good. The handle carries
/// DUPLICATE, TRANSFER and MANAGE.
pub fn process_create(
    quota: u64,
    handle_limit: u32,
    ceiling: u8,
) -> Result<Handle<Process>, Error> {
    process_create_with(quota, handle_limit, ceiling, None, None).map_err(|(e, _)| e)
}

/// process_create with channels (spec 7.9, 13.3). `exit`, a channel handle
/// with NOTIFY and a priority (1-63, no higher than the caller's
/// ceiling), hears of the child's end once the child gave its quota back:
/// a notification of that priority, bit 0, with the label of the handle.
/// `start`, a channel handle with TRANSFER, moves into the child's entry 0
/// (abi::START_CHANNEL) with its rights, label and all; when the call
/// fails it stays the caller's and comes back with the error.
pub fn process_create_with(
    quota: u64,
    handle_limit: u32,
    ceiling: u8,
    exit: Option<(&Handle<Channel>, u8)>,
    start: Option<Handle<Channel>>,
) -> Result<Handle<Process>, (Error, Option<Handle<Channel>>)> {
    let (x3, x4) = exit.map_or((0, 0), |(c, priority)| (c.raw().0, priority.into()));
    let x5 = start.as_ref().map_or(0, |c| c.raw().0);
    let args = [quota, handle_limit.into(), ceiling.into(), x3, x4, x5];
    match call::<{ Call::ProcessCreate.number() }>(&args) {
        Ok(x) => Ok(returned(&x)),
        Err(e) => Err((e, start)),
    }
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
        x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8],
    ]))
}

/// object_info(MEMORY): the object's size in bytes, the pages whose frames
/// it owns and its mappings now.
pub fn memory_info(memory: &Handle<Memory>) -> Result<MemoryInfo, Error> {
    let args = [memory.raw().0, abi::INFO_MEMORY, 0];
    let x = call::<{ Call::ObjectInfo.number() }>(&args)?;
    Ok(MemoryInfo::from_words([x[1], x[2], x[3]]))
}

/// object_info(IRQ): the binding's line, whether it is masked until
/// `irq_ack`, and whether it is edge-triggered.
pub fn irq_info(irq: &Handle<Interrupt>) -> Result<IrqInfo, Error> {
    let args = [irq.raw().0, abi::INFO_IRQ, 0];
    let x = call::<{ Call::ObjectInfo.number() }>(&args)?;
    Ok(IrqInfo::from_words([x[1], x[2], x[3]]))
}

/// device_window_create through the system resource with DEVICE: a device
/// window over the physical range of `len` bytes from `addr`, rounded out
/// to whole pages, a memory object that touches no RAM and no device of
/// the kernel (spec 9). `mem_map` shows it R or RW as Device-nGnRE; the
/// handle carries abi::WINDOW_RIGHTS, without MAP_EXEC. Registers are read
/// and written with volatile accesses of their width.
pub fn device_window_create(
    resource: &Handle<Resource>,
    addr: u64,
    len: u64,
) -> Result<Handle<Memory>, Error> {
    let x = call::<{ Call::DeviceWindowCreate.number() }>(&[resource.raw().0, addr, len])?;
    Ok(returned(&x))
}

/// irq_bind through the system resource with DEVICE: the interrupts of
/// `line`, a shared line (spec 9), come as notifications of `channel`, a
/// handle with NOTIFY, bit 0 into a slot of `priority` with the label of
/// the handle, edge-triggered when `edge`, level-triggered otherwise. Each
/// one masks the line until `irq_ack`; the line is open at once. One
/// binding a line (BAD_STATE); the caller's quota pays for it. The handle
/// carries DUPLICATE, TRANSFER and MANAGE.
pub fn irq_bind(
    resource: &Handle<Resource>,
    line: u32,
    channel: &Handle<Channel>,
    priority: u8,
    edge: bool,
) -> Result<Handle<Interrupt>, Error> {
    let flags = if edge { TRIGGER_EDGE } else { 0 };
    let args = [
        resource.raw().0,
        line.into(),
        channel.raw().0,
        priority.into(),
        flags,
    ];
    let x = call::<{ Call::IrqBind.number() }>(&args)?;
    Ok(returned(&x))
}

/// irq_ack: the line an interrupt masked opens again, once the driver
/// served the device, cleared its source and read a register back (spec
/// 9, 13.5). PEER_CLOSED once the binding's channel closed.
pub fn irq_ack(irq: &Handle<Interrupt>) -> Result<(), Error> {
    call::<{ Call::IrqAck.number() }>(&[irq.raw().0]).map(drop)
}

/// mem_create: a memory object of `size` bytes, whole pages up to
/// abi::MAX_MEMORY, whose frames the kernel takes and zeroes before the
/// call returns (spec 7.3); the caller's quota pays for them, for the
/// nodes of their list and for the object's place. The handle carries
/// abi::MEMORY_RIGHTS.
pub fn mem_create(size: u64) -> Result<Handle<Memory>, Error> {
    let x = call::<{ Call::MemCreate.number() }>(&[size, 0])?;
    Ok(returned(&x))
}

/// mem_map: shows `len` bytes of `memory` from byte `offset` at `addr` of
/// `process`, a handle with MANAGE, with `access` (spec 7.4): R needs
/// MAP_READ, RW MAP_WRITE as well, RX MAP_EXEC as well. The pages of the
/// range must be free there: no mapping and no message buffer of a thread.
/// The process pays for the table of its mappings and for the tables of
/// its space, whoever maps into it; the mapping keeps the object alive
/// until it goes.
pub fn mem_map(
    process: &Handle<Process>,
    memory: &Handle<Memory>,
    offset: u64,
    len: u64,
    addr: usize,
    access: Access,
) -> Result<(), Error> {
    let args = [
        process.raw().0,
        memory.raw().0,
        offset,
        len,
        addr as u64,
        access.raw(),
    ];
    call::<{ Call::MemMap.number() }>(&args).map(drop)
}

/// mem_unmap: the mapping of `process` that is exactly `len` bytes from
/// `addr` goes (spec 7.4).
///
/// # Safety
/// Nothing the caller uses lies in the mapping, when it is the caller's
/// own.
pub unsafe fn mem_unmap(process: &Handle<Process>, addr: usize, len: u64) -> Result<(), Error> {
    call::<{ Call::MemUnmap.number() }>(&[process.raw().0, addr as u64, len]).map(drop)
}

/// mem_protect: the pages of the mapping of `process` that is exactly
/// `len` bytes from `addr` get `access`, within the rights the object was
/// mapped with (spec 7.4).
///
/// # Safety
/// Nothing the caller uses in the mapping needs an access `access` takes
/// away, when it is the caller's own.
pub unsafe fn mem_protect(
    process: &Handle<Process>,
    addr: usize,
    len: u64,
    access: Access,
) -> Result<(), Error> {
    let args = [process.raw().0, addr as u64, len, access.raw()];
    call::<{ Call::MemProtect.number() }>(&args).map(drop)
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

/// What `receive` took (spec 6.1, 6.5): a notification, or a request with
/// its bytes 0-63 and the token that answers it. A request of more than
/// 64 bytes lies whole in the thread's message buffer (`msgbuf`), and so
/// do the handles it brought (msgbuf::handle).
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    Notification {
        source: Source,
        label: u64,
        bits: u64,
        count: u32,
    },
    Message {
        /// The label of the handle the request came through, 0 for none.
        label: u64,
        len: usize,
        handles: usize,
        token: Token,
        /// Bytes 0-63 as abi::inline_words packs them, zero past `len`.
        words: [u64; 8],
    },
}

/// The token of a request `receive` took (spec 6.1, 13.2): the right to
/// answer it once, from any thread of the process. It is neither `Copy`
/// nor `Clone`, and `reply` takes it, so a second reply does not build.
#[derive(Debug, PartialEq, Eq)]
pub struct Token(u64);

// Token is not Clone, and so not Copy (spec 13.2): were it Clone, the
// path below would name two impls of the trait, and the crate would not
// build.
const _: fn() = || {
    trait AmbiguousIfClone<A> {
        fn some_item() {}
    }
    impl<T> AmbiguousIfClone<()> for T {}
    #[allow(dead_code)]
    struct IsClone;
    impl<T: Clone> AmbiguousIfClone<IsClone> for T {}
    let _ = <Token as AmbiguousIfClone<_>>::some_item;
};

impl Token {
    /// The value the kernel knows the token by, for tests that hand the
    /// kernel values it must refuse.
    pub const fn raw(&self) -> u64 {
        self.0
    }

    /// reply: `bytes`, up to abi::MESSAGE_MAX, go to the client, whose
    /// send returns them (spec 6.1): bytes 0-63 in x2-x9, the rest through
    /// the message buffers. The call never waits. BAD_STATE when the token
    /// names no request that waits for this process's reply, PEER_CLOSED
    /// when its client ended while it waited. More bytes fail with
    /// INVALID_ARGS, as the kernel would fail them.
    pub fn reply(self, bytes: &[u8]) -> Result<(), Error> {
        self.reply_handles(bytes, &[])
    }

    /// reply with `handles` as well, at most abi::MESSAGE_HANDLES, each
    /// with TRANSFER: they move into the client's table with their rights
    /// and labels (spec 6.1). They leave the caller's table when the call
    /// succeeds, and when it fails with PEER_CLOSED, LIMIT_REACHED or
    /// NO_MEMORY; with the last two the table of the client had no room
    /// for them, and its send fails the same way. On any other error they
    /// stay.
    pub fn reply_handles(self, bytes: &[u8], handles: &[abi::Handle]) -> Result<(), Error> {
        let args = message_regs(self.0, bytes, handles, 0)?;
        call::<{ Call::Reply.number() }>(&args).map(drop)
    }
}

/// What `send` returns (spec 6.1): the reply's length, the count of
/// handles it brought, and its bytes 0-63 as abi::inline_words packs them,
/// zero past `len`. A reply of more than 64 bytes lies whole in the
/// thread's message buffer (`msgbuf`), and so do its handles
/// (msgbuf::handle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    pub len: usize,
    pub handles: usize,
    pub words: [u64; 8],
}

/// x0-x9 of a message of `bytes` and `handles` through `target`, a channel
/// or a token, with `flags` in its description: bytes 0-63 in x2-x9, and
/// the rest, written into the message buffer at their offsets, with the
/// values of the handles (msgbuf::put_handles). INVALID_ARGS for more than
/// abi::MESSAGE_MAX bytes or abi::MESSAGE_HANDLES handles.
fn message_regs(
    target: u64,
    bytes: &[u8],
    handles: &[abi::Handle],
    flags: u64,
) -> Result<Regs, Error> {
    if bytes.len() > MESSAGE_MAX || handles.len() > MESSAGE_HANDLES {
        return Err(Error::InvalidArgs);
    }
    let (inline, rest) = bytes.split_at(bytes.len().min(INLINE_MAX));
    msgbuf::write(INLINE_MAX, rest);
    msgbuf::put_handles(handles);
    let mut x = [0; 10];
    x[0] = target;
    x[1] = bytes.len() as u64 | (handles.len() as u64) << HANDLES_SHIFT | flags;
    x[2..].copy_from_slice(&abi::inline_words(inline));
    Ok(x)
}

/// After a message of `len` bytes came in x2-x9 as `words`: one of more
/// than 64 bytes gets its bytes 0-63 into the message buffer too, where
/// the kernel put the rest (spec 6.2).
fn keep_whole(len: usize, words: &[u64; 8]) {
    if len > INLINE_MAX {
        msgbuf::write(0, &abi::inline_bytes(words));
    }
}

/// send: the request `bytes`, up to abi::MESSAGE_MAX, through `channel`,
/// a handle with SEND, with or without a label, and the wait for its reply
/// (spec 6.1): bytes 0-63 go in x2-x9, the rest through the message
/// buffers. The request waits by the caller's effective priority, and the
/// receiver works at that priority until it answers (spec 6.6).
/// PEER_CLOSED once the channel closed or when the service ended before
/// its reply, BAD_STATE when the thread's count of requests ran out; more
/// bytes fail with INVALID_ARGS.
pub fn send(channel: &Handle<Channel>, bytes: &[u8]) -> Result<Reply, Error> {
    send_with(channel, bytes, &[], 0)
}

/// send with abi::NO_WAIT: WOULD_BLOCK when no thread waits in receive on
/// the channel. A request a receiver took waits for its reply all the
/// same.
pub fn try_send(channel: &Handle<Channel>, bytes: &[u8]) -> Result<Reply, Error> {
    send_with(channel, bytes, &[], abi::NO_WAIT)
}

/// send with `handles` as well, at most abi::MESSAGE_HANDLES, each with
/// TRANSFER, none of them `channel`: they move into the receiver's table
/// with their rights and labels (spec 6.1), and the reply may bring handles
/// back (msgbuf::handle). They leave the caller's table when the call
/// succeeds, and when it fails with PEER_CLOSED, LIMIT_REACHED or
/// NO_MEMORY, the last two when the receiver's table or the reply's had no
/// room for them; on any other error they stay.
pub fn send_handles(
    channel: &Handle<Channel>,
    bytes: &[u8],
    handles: &[abi::Handle],
) -> Result<Reply, Error> {
    send_with(channel, bytes, handles, 0)
}

fn send_with(
    channel: &Handle<Channel>,
    bytes: &[u8],
    handles: &[abi::Handle],
    flags: u64,
) -> Result<Reply, Error> {
    let args = message_regs(channel.raw().0, bytes, handles, flags)?;
    let x = call::<{ Call::Send.number() }>(&args)?;
    let mut words = [0; 11];
    words[..9].copy_from_slice(&x[1..]);
    let m = Message::from_words(words);
    keep_whole(m.len, &m.words);
    Ok(Reply {
        len: m.len,
        handles: m.handles,
        words: m.words,
    })
}

/// receive: waits until the channel has something and takes it. The caller
/// works at the priority of the notification or of the client it took,
/// under its ceiling, until its next receive or, for a request, its reply
/// with the token (spec 6.6). PEER_CLOSED when the last handle with
/// RECEIVE goes while the caller waits.
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
    let words: [u64; 11] = x[1..].try_into().expect("x1-x11");
    if Source::from_code((words[0] >> SOURCE_SHIFT) & 0xF) == Source::Message {
        let m = Message::from_words(words);
        keep_whole(m.len, &m.words);
        return Ok(Received::Message {
            label: m.label,
            len: m.len,
            handles: m.handles,
            token: Token(m.token),
            words: m.words,
        });
    }
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

/// clock_now: nanoseconds on the counter's scale (spec 10), rounded down;
/// the scale of the deadlines of `timer_set`. A program may read the
/// counter itself (`time::now`) and convert it the same way
/// (`time::ticks_to_ns`).
pub fn clock_now() -> Result<u64, Error> {
    let x = call::<{ Call::ClockNow.number() }>(&[])?;
    Ok(x[1])
}

/// timer_create: a timer on `channel`, a handle with RECEIVE, whose
/// notifications have `priority` (1-63, no higher than the caller's
/// ceiling) and the label of the handle (spec 10). It is not armed. The
/// caller's quota pays for it, and it holds one of the channel's slots
/// until it goes; a process pays for abi::MAX_TIMERS at most
/// (LIMIT_REACHED). The handle carries DUPLICATE, TRANSFER and MANAGE.
pub fn timer_create(channel: &Handle<Channel>, priority: u8) -> Result<Handle<Timer>, Error> {
    let x = call::<{ Call::TimerCreate.number() }>(&[channel.raw().0, priority.into()])?;
    Ok(returned(&x))
}

/// timer_set: the timer fires at `deadline`, nanoseconds on the scale of
/// `clock_now`, never before: bit 0 goes into its slot, and `receive`
/// reports it as a notification of a timer. A deadline that passed fires
/// in the call itself; a timer that was armed moves to the new deadline.
/// PEER_CLOSED once the channel closed.
pub fn timer_set(timer: &Handle<Timer>, deadline: u64) -> Result<(), Error> {
    call::<{ Call::TimerSet.number() }>(&[timer.raw().0, deadline]).map(drop)
}

/// timer_cancel: the timer is armed no more; what it posted already stays
/// in its slot. A timer that is not armed is left as it is.
pub fn timer_cancel(timer: &Handle<Timer>) -> Result<(), Error> {
    call::<{ Call::TimerCancel.number() }>(&[timer.raw().0]).map(drop)
}
