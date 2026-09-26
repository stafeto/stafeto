// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the tests of every module share: the imports, init's first
//! handles, the priorities and quotas of the tests, init's own threads and
//! the checks (spec 15.2).

use crate::messages::record;
use crate::timers::timer_at;
pub(crate) use abi::{
    Access, CHANNEL_RIGHTS, CLIENT_GONE, Call, ChannelInfo, Error, IrqInfo, MemoryInfo,
    OWNER_RIGHTS, Policy, ProcessHandles, ProcessMemory, ProcessState, Rights, Source,
    TRIGGER_EDGE, ThreadInfo, ThreadState, WINDOW_RIGHTS,
};
pub(crate) use bootimg::{Part, Program};
pub(crate) use child::{Checked, Role, marked, x0_alone};
pub(crate) use core::mem::ManuallyDrop;
pub(crate) use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
pub(crate) use rt::handle::{
    Any, Channel, Incoming, Interrupt, Memory, Outgoing, Process, Resource, Thread, Timer,
};
pub(crate) use rt::sys::{self, Received, Refused, Regs, Reply, Token};
pub(crate) use rt::{Handle, Stack, loader, println, time};

pub(crate) type Outcome = Result<(), &'static str>;

/// A test's name and body.
pub(crate) type Test = (&'static str, fn() -> Outcome);

/// The values of init's first handles (rt::init_handles), which `main`
/// keeps for the whole run: the system resource, which the console owns,
/// init's process, its first thread and the boot image.
static INIT: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// Keeps init's first handles for the whole run; the resource goes to the
/// console, which owns it from then on.
pub(crate) fn keep(init: rt::InitHandles) {
    INIT[0].store(init.resource.raw().0, Relaxed);
    INIT[1].store(init.process.into_raw().0, Relaxed);
    INIT[2].store(init.thread.into_raw().0, Relaxed);
    INIT[3].store(init.boot_image.into_raw().0, Relaxed);
    rt::console::set(init.resource);
}

fn kept<K>(i: usize) -> ManuallyDrop<Handle<K>> {
    Handle::borrowed(abi::Handle(INIT[i].load(Relaxed)))
}

/// A view of the system resource with DEVICE, DEBUG, KSTATS, DUPLICATE and
/// TRANSFER.
pub(crate) fn resource() -> ManuallyDrop<Handle<Resource>> {
    kept(0)
}

/// A view of init's own process.
pub(crate) fn own() -> ManuallyDrop<Handle<Process>> {
    kept(1)
}

/// A view of init's first thread, the one the tests run in.
pub(crate) fn me() -> ManuallyDrop<Handle<Thread>> {
    kept(2)
}

/// A view of the boot image.
pub(crate) fn image() -> ManuallyDrop<Handle<Memory>> {
    kept(3)
}

/// Counter ticks of the counted loop the run starts with (main.rs,
/// `loop_ticks`).
pub(crate) static LOOP_TICKS: AtomicU64 = AtomicU64::new(0);

/// Whether the run is under -icount: the loop took 20 000 ticks and a
/// few more, one instruction each (xtask checks the same range).
pub(crate) fn under_icount() -> bool {
    (20_000..=20_100).contains(&LOOP_TICKS.load(Relaxed))
}

/// Init's priority while the tests run.
pub(crate) const TEST_PRIORITY: u8 = 20;
/// Levels below init, for threads that run when init lets them, and one
/// above it, for threads that run at once.
pub(crate) const LOW: u8 = 5;
pub(crate) const LEVEL: u8 = 10;
pub(crate) const HIGH: u8 = 30;
/// The priority of the notifications of the priority tests: above init.
pub(crate) const NOTICE: u8 = 25;
/// The priority of the notifications init takes itself: the lowest level.
pub(crate) const QUIET: u8 = 1;

pub(crate) const PAGE: usize = 4096;
pub(crate) const STACK_SIZE: usize = 16 * 1024;
/// The quota of a child with a thread or two (spec 7.5).
pub(crate) const CHILD_QUOTA: u64 = 64 * 1024;
/// The least quota this kernel takes for a child (spec 7.5): its root
/// table and the page of its pool of blocks, with the directory of its
/// table and the chunk with entry 0. Its shell is init's (spec 7.8).
pub(crate) const LEAST_QUOTA: u64 = 8 * 1024;
/// Rounds of `create_kill_cycles_leak_nothing`.
pub(crate) const CYCLES: u32 = 1000;
/// Threads of init's own process a test may have at a time.
pub(crate) const SLOTS: usize = 4;
/// The label of the copy of a test's exit channel that names its
/// children (process_create x3).
pub(crate) const CHILD: u64 = 0xC41D;
/// The label of the copy of a channel a timer is made through.
pub(crate) const TIMED: u64 = 0x71AE;
/// The bits a thread of init notifies with before a timer's deadline.
pub(crate) const NOTIFIED: u64 = 0b1001;

pub(crate) static STACKS: [Stack<STACK_SIZE>; SLOTS] = [const { Stack::new() }; SLOTS];

/// Words the threads of a test leave for it.
pub(crate) static MARKS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// The entry of a thread of a child: the child has no code, so nothing is
/// mapped there, and the thread faults as soon as it runs.
pub(crate) const CHILD_ENTRY: u64 = 0x1000;
/// The message buffer of that thread, on the next page: the page gives the
/// child a level 3 table for its first 2 MiB.
pub(crate) const CHILD_BUFFER: u64 = 0x2000;
/// The fault of that thread: an instruction abort from EL0 (EC 0x20) with
/// IL set and a translation fault at level 3 (IFSC 0x07).
pub(crate) const CHILD_FAULT_ESR: u64 = 0x8200_0007;

/// A line debug_write prints with bytes other than zero past its length.
pub(crate) const STOPS: &[u8] = b"debug_write stops at its length";
/// A line debug_write prints with all 64 bytes of x2-x9.
pub(crate) const LINE: &[u8; 64] =
    b"test init: debug_write prints all 64 bytes of x2 to x9 in order\n";

pub(crate) fn check(ok: bool, why: &'static str) -> Outcome {
    if ok { Ok(()) } else { Err(why) }
}

pub(crate) fn close<K>(h: Handle<K>) -> Outcome {
    h.close().map_err(|_| "handle_close failed")
}

/// A view of the same handle with another kind in its type, for a call
/// that must fail with WRONG_TYPE.
pub(crate) fn retyped<K, L>(h: &Handle<K>) -> ManuallyDrop<Handle<L>> {
    Handle::borrowed(h.raw())
}

pub(crate) fn reset_marks() {
    for m in &MARKS {
        m.store(0, Relaxed);
    }
}

pub(crate) fn mark(i: usize) -> u64 {
    MARKS[i].load(Relaxed)
}

/// The message buffer of the thread in `slot`, above init's own. A thread's
/// buffer goes when it ends, so the next test takes the page again.
pub(crate) fn buffer(slot: usize) -> usize {
    abi::INIT_MSGBUF as usize + (slot + 1) * PAGE
}

/// A stopped thread of init's process in `slot` that runs `entry(arg)`.
pub(crate) fn thread(
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    arg: u64,
    priority: u8,
    policy: Policy,
) -> Result<Handle<Thread>, &'static str> {
    // SAFETY: each test lets its threads end before the next test uses the
    // slot, so the stack is the thread's alone.
    let t = unsafe {
        sys::thread_create(
            &own(),
            entry,
            STACKS[slot].top(),
            arg,
            priority,
            policy,
            buffer(slot),
        )
    };
    t.map_err(|_| "thread_create failed")
}

/// `thread`, started.
pub(crate) fn spawn(
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    arg: u64,
    priority: u8,
    policy: Policy,
) -> Result<Handle<Thread>, &'static str> {
    let t = thread(slot, entry, arg, priority, policy)?;
    sys::thread_start(&t).map_err(|_| "thread_start failed")?;
    Ok(t)
}

/// Lets every thread below init run until it ends: init lowers itself to
/// 1 and, once it runs again, takes TEST_PRIORITY back.
pub(crate) fn let_run() -> Outcome {
    sys::thread_set_priority(&me(), 1, Policy::Fifo).map_err(|_| "init could not lower itself")?;
    sys::thread_set_priority(&me(), TEST_PRIORITY, Policy::Fifo)
        .map_err(|_| "init could not take its priority back")
}

/// A child with no code, CHILD_QUOTA, room for 16 handles and ceiling
/// `ceiling`.
pub(crate) fn child(ceiling: u8) -> Result<Handle<Process>, &'static str> {
    sys::process_create(CHILD_QUOTA, 16, ceiling).map_err(|_| "process_create failed")
}

/// A stopped thread of `process` at CHILD_ENTRY, FIFO at `priority`.
pub(crate) fn child_thread(
    process: &Handle<Process>,
    priority: u8,
) -> Result<Handle<Thread>, Error> {
    let mut x = [0; 10];
    x[0] = process.raw().0;
    x[1] = CHILD_ENTRY;
    x[4] = priority.into();
    x[5] = Policy::Fifo as u64;
    x[6] = CHILD_BUFFER;
    // SAFETY: the thread runs in another process and touches nothing of
    // init's.
    let after = unsafe { sys::raw::<{ Call::ThreadCreate.number() }>(x) };
    match Error::from_code(after[0]) {
        None => Ok(Handle::from_raw(abi::Handle(after[1]))),
        Some(e) => Err(e),
    }
}

/// Adds 1 to mark `i` and ends.
pub(crate) extern "C" fn add_mark(i: u64) -> ! {
    MARKS[i as usize].fetch_add(1, Relaxed);
    sys::thread_exit()
}

/// The value of a copy of the system resource that init closed: BAD_HANDLE
/// from then on (spec 5.1).
pub(crate) fn closed_handle() -> Result<u64, &'static str> {
    let h = copy(&resource(), Rights::NONE)?;
    let value = h.raw().0;
    close(h)?;
    Ok(value)
}

/// Init's used memory, the free frames and the pages of kernel pools.
pub(crate) fn counts() -> Result<(u64, u64, u64), &'static str> {
    let used = sys::process_memory(&own()).map_err(|_| "PROCESS_MEMORY of init failed")?;
    let stats = sys::kernel_stats(&resource()).map_err(|_| "KERNEL_STATS failed")?;
    Ok((used.used, stats.free_frames, stats.pool_pages))
}

/// A channel with its slot of label 0 at `priority`.
pub(crate) fn channel(priority: u8) -> Result<Handle<Channel>, &'static str> {
    sys::channel_create(priority).map_err(|_| "channel_create failed")
}

/// A copy of `h` with `rights` and no new label.
pub(crate) fn copy<K>(h: &Handle<K>, rights: Rights) -> Result<Handle<K>, &'static str> {
    sys::handle_duplicate(h, rights).map_err(|_| "handle_duplicate failed")
}

/// A copy of the channel handle `c` with `rights` and the new label
/// `label`: a session whose slot has `priority`.
pub(crate) fn session(
    c: &Handle<Channel>,
    rights: Rights,
    label: u64,
    priority: u8,
) -> Result<Handle<Channel>, &'static str> {
    sys::handle_label(c, rights, label, priority).map_err(|_| "a label did not go on a copy")
}

/// A notification of the session with `label`.
pub(crate) fn labelled(label: u64, bits: u64, count: u32) -> Received {
    Received::Notification {
        source: Source::Session,
        label,
        bits,
        count,
    }
}

/// The call failed with `error` and changed x0 alone.
pub(crate) fn failed(after: Regs, x: Regs, error: Error) -> bool {
    after[0] == error.code() && after[1..] == x[1..]
}

/// A timer on `c` at QUIET, whose notifications never lift init above its
/// threads (spec 6.6).
pub(crate) fn timer(c: &Handle<Channel>) -> Result<Handle<Timer>, &'static str> {
    timer_at(c, QUIET)
}

pub(crate) fn clock_now() -> Result<u64, &'static str> {
    sys::clock_now().map_err(|_| "clock_now failed")
}

pub(crate) fn arm(t: &Handle<Timer>, deadline: u64) -> Outcome {
    sys::timer_set(t, deadline).map_err(|_| "timer_set failed")
}

/// Where the tests of mappings show their objects: a gigabyte of init's
/// space far from its program, its stack and its buffers.
pub(crate) const WINDOW: usize = 0x40_0000_0000;
/// The object of the tests of busy mappings: 64 MiB, whose mapping takes
/// 512 portions, and the period of the timer that wakes a thread until it
/// finds the mapping in the middle of them: long enough for the mapping to
/// go on between two wakes under -icount.
pub(crate) const BIG: u64 = 64 << 20;
pub(crate) const PROBE_PERIOD_NS: u64 = 200_000;
/// The timer of the tests of busy mappings, for the thread it wakes.
pub(crate) static PROBE_TIMER: AtomicU64 = AtomicU64::new(0);
/// Init's own mappings: its code, its read-only data, its data and its
/// stack, which the kernel made (spec 13.3), and the boot image and the
/// page of marks of its children (`prepare`).
pub(crate) const INIT_MAPPINGS: usize = 6;
/// `mov x0, #42` and `ret`: a function that returns 42.
pub(crate) const RETURN_42: [u32; 2] = [0xD280_0540, 0xD65F_03C0];

/// mem_map of `len` bytes of `m` from `offset` at `addr` of init.
pub(crate) fn map(
    m: &Handle<Memory>,
    offset: u64,
    len: u64,
    addr: usize,
    access: Access,
) -> Outcome {
    sys::mem_map(&own(), m, offset, len, addr, access).map_err(|_| "mem_map failed")
}

/// mem_unmap of the mapping of init that is `len` bytes from `addr`.
pub(crate) fn unmap(addr: usize, len: u64) -> Outcome {
    // SAFETY: the tests unmap only their own windows, which nothing else
    // uses.
    unsafe { sys::mem_unmap(&own(), addr, len) }.map_err(|_| "mem_unmap failed")
}

/// Per slot: the handle the thread there uses (`client`, `server`), and
/// what it got (`result`).
pub(crate) static HANDLES: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
pub(crate) static RESULTS: [[AtomicU64; 12]; SLOTS] =
    [const { [const { AtomicU64::new(0) }; 12] }; SLOTS];
/// Per slot: the thread there came back from its call.
pub(crate) static ENDED: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// x0-x9 of the send of `raw_client`.
pub(crate) static RAW: [AtomicU64; 10] = [const { AtomicU64::new(0) }; 10];
/// Mark 1 when `server` took its request.
pub(crate) static SEEN: AtomicU64 = AtomicU64::new(0);

pub(crate) fn reset_results() {
    reset_marks();
    SEEN.store(0, Relaxed);
    for word in RESULTS
        .iter()
        .flatten()
        .chain(&HANDLES)
        .chain(&ENDED)
        .chain(&RAW)
    {
        word.store(0, Relaxed);
    }
}

/// What the thread in `slot` got: the error code of its call or 0, then
/// as `send` or `receive` leave a message: the length, the words of bytes
/// 0-63, the label and the token.
pub(crate) fn result(slot: usize) -> [u64; 12] {
    core::array::from_fn(|i| RESULTS[slot][i].load(Relaxed))
}

/// Whether the thread in `slot` came back from its call.
pub(crate) fn ended(slot: usize) -> bool {
    ENDED[slot].load(Relaxed) == 1
}

/// A view of the channel handle that HANDLES holds for `slot`.
pub(crate) fn handle(slot: usize) -> ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(abi::Handle(HANDLES[slot].load(Relaxed)))
}

/// The 16 bytes the client in `slot` sends.
pub(crate) fn request(slot: usize) -> [u8; 16] {
    core::array::from_fn(|i| (16 * slot + i + 1) as u8)
}

/// `bytes` as x2-x9 carry them.
pub(crate) fn words(bytes: &[u8]) -> [u64; 8] {
    abi::inline_words(bytes)
}

/// A client of a test in `slot`: sends request(slot) through the handle
/// HANDLES holds for it and waits for the reply, which `result` gives,
/// with 0 for the code; then ends.
pub(crate) extern "C" fn client(slot: u64) -> ! {
    let s = slot as usize;
    match sys::send(&handle(s), &request(s)) {
        Ok(reply) => {
            let mut w = [0; 10];
            w[1] = reply.len as u64;
            w[2..].copy_from_slice(&reply.words);
            record(s, &w);
        }
        Err(e) => record(s, &[e.code()]),
    }
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// `raw`, at most four values the caller holds, as a set of handles that
/// owns them; INVALID_ARGS for more.
fn owning(raw: &[abi::Handle]) -> Result<Outgoing, Error> {
    if raw.len() > abi::MESSAGE_HANDLES {
        return Err(Error::InvalidArgs);
    }
    let mut set = Outgoing::new();
    for &h in raw {
        // At most four, as checked above.
        let _ = set.push(Handle::from_raw(h));
    }
    Ok(set)
}

/// The error of a refused send or reply; the handles that came back are
/// the caller's values again.
fn kept_back(refused: Refused) -> Error {
    if let Some(mut back) = refused.back {
        while let Some(h) = back.pop() {
            h.into_raw();
        }
    }
    refused.error
}

/// sys::send_handles with the values `raw`, at most four, which the caller
/// holds; the values the kernel leaves (abi::Error::keeps_handles) stay the
/// caller's. More than four fail with INVALID_ARGS.
pub(crate) fn send_values(
    c: &Handle<Channel>,
    bytes: &[u8],
    raw: &[abi::Handle],
) -> Result<Reply, Error> {
    sys::send_handles(c, bytes, owning(raw)?).map_err(kept_back)
}

/// Token::reply_handles with the values `raw`, as `send_values`.
pub(crate) fn reply_values(t: Token, bytes: &[u8], raw: &[abi::Handle]) -> Result<(), Error> {
    t.reply_handles(bytes, owning(raw)?).map_err(kept_back)
}

/// The handles that came in `handles` as values the caller holds from now
/// on, each with the kind of its object and its rights, as msgbuf::handle
/// gives them; abi::Handle::INVALID past their count.
pub(crate) fn values(handles: &mut Incoming) -> [(abi::Handle, (abi::ObjectKind, Rights)); 4] {
    core::array::from_fn(|i| match (handles.info(i), handles.take_any(i)) {
        (Some(info), Ok(h)) => (h.into_raw(), info),
        _ => (
            abi::Handle::INVALID,
            (abi::ObjectKind::Unknown(0), Rights::NONE),
        ),
    })
}

/// `values` of the handles of the message `got` took, if it took one.
pub(crate) fn came(
    got: &mut Result<Received, Error>,
) -> [(abi::Handle, (abi::ObjectKind, Rights)); 4] {
    match got {
        Ok(Received::Message { handles, .. }) => values(handles),
        _ => values(&mut Incoming::none()),
    }
}
