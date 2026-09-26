// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Threads (spec 4, 8, 8.1): a program's registers, FP and SIMD included,
//! its scheduling parameters, its message buffer, its own slot of a
//! channel's queue, the handles of its request on their way, the long call
//! it is making, its number in the system table and its process, in objects
//! from the pool of threads of their process. The registers come first, so
//! TPIDR_EL1, which points at the running thread, points at them too
//! (vectors.S). The running thread is the one TPIDR_EL1 names; the kernel
//! stack holds nothing of it. A thread lives while references to it are
//! left: handles, the one `create` hands out, and the kernel's while the
//! scheduler holds the thread, from its start until its end, while it waits
//! in `send` or `receive` too (spec 8.1); it holds a reference to its
//! process. A thread that ended stays as a shell without its buffer and its
//! number until its last reference goes, which queues it for cleanup (spec
//! 7.7): its number goes back as it ends, or with its portion when it never
//! started. Its process pays from its quota for the pages of its pool of
//! threads (spec 7.8) and for the buffer while it lasts (spec 7.5).

use crate::arch::user::{self, FpRegs, UserRegs};
use crate::channel::{Owner, Wait};
use crate::cleanup::{self, Item};
use crate::memory::{self, Memory};
use crate::mm::phys::{self, Frame};
use crate::object::{self, Live, Moving, Object, Refs};
use crate::process::{self, Process};
use crate::sched::{self, Tokens};
use abi::{Call, Error, MESSAGE_HANDLES, Policy, msgbuf};
use core::ops::Range;
use core::ptr::NonNull;
use kcore::notify::Slot;
use kcore::paging::Attrs;
use kcore::sched::{Node, Schedulable, State};

#[repr(C)]
pub struct Thread {
    /// First: TPIDR_EL1 and vectors.S reach it at the thread's address.
    pub regs: UserRegs,
    /// Saved while the thread does not run.
    pub fp: FpRegs,
    /// What the scheduler keeps in the thread: the base priority, which
    /// `create` or thread_set_priority gave, the boost of a notification or
    /// of a request's client (spec 6.6) and the effective priority they
    /// make, the policy, the state, the rest of a quantum and the links of
    /// the ready list. Only the scheduler changes it (sched), and the
    /// channel under the scheduler's lock.
    pub sched: Node<Thread>,
    /// What it waits for in `send` or `receive`, and where its slot stands
    /// meanwhile (channel::Wait); only the channel changes it, under the
    /// scheduler's lock.
    pub waits: Option<Wait>,
    /// Its own slot of a channel's queue (spec 6.1): its place there while
    /// it waits in `receive`, its request while it waits in `send`, and its
    /// place in the queue of accepted requests of the process that took
    /// the request, at the level of its effective priority when it began
    /// to wait, and at each thread_set_priority since (channel::requeue,
    /// spec 6.3). Only the channel changes it, under the scheduler's lock.
    slot: Slot<Owner>,
    /// The handles of its request or reply on their way (spec 6.1): out of
    /// its process's table, until the meeting puts them into the table of
    /// the receiver, which it does at once for a reply or when a receiver
    /// waits. A request that waits in the queue of a channel keeps them;
    /// they go with PEER_CLOSED at the stage Close, with the buffer when the
    /// thread ends, and when the meeting finds no room for them
    /// (`drop_transit`). Only `set_transit`, `take_transit` and
    /// `drop_transit` change it.
    transit: Moving,
    /// The long call it is making (spec 7.7), from the first entry of its
    /// `svc` to its last portion; a thread that ends midway lets it go with
    /// its buffer (`drop_long`). Only `begin_long`, `end_long` and
    /// `drop_long` change it.
    long: Option<Long>,
    /// Its number in the system table (spec 6.1, 7.8), from `create` until
    /// it ends (sched::exit) or, when it never started, until its portion
    /// of cleanup: the tokens of its requests carry it. None once it went
    /// back (`give_number`), so a taken number always names a live thread.
    index: Option<u16>,
    /// The token of the request whose client boosts it (spec 6.6): a reply
    /// with it ends the boost. 0 when a notification boosts it, or nothing.
    pub boost_token: u64,
    /// Links in the list of its process's threads that have not ended,
    /// which process::end walks; None once the thread left it. Only
    /// process::{add_thread, remove_thread} change them.
    pub siblings: Option<Siblings>,
    /// The page `give_buffer` mapped for messages (spec 6.2); it goes when
    /// the thread exits (`exit`), at the stage Buffers of its process, or
    /// when the thread goes.
    buffer: Option<Buffer>,
    process: NonNull<Process>,
    /// Handles to the thread, the reference `create` hands out and the
    /// kernel's from `start` to the end.
    refs: Refs,
    /// Its place in the cleanup queue once its last reference goes.
    cleanup: Item,
}

/// A long call a thread is making (spec 7.7): what the next entry of its
/// `svc` goes on with, after the call started over for an interrupt
/// (syscall::restart).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Long {
    /// mem_create: the object being made, whose only reference this is
    /// until the object is whole and a handle takes its place.
    Create(NonNull<Memory>),
}

impl Long {
    /// The call that goes on.
    pub fn call(self) -> Call {
        match self {
            Long::Create(_) => Call::MemCreate,
        }
    }
}

/// Neighbours in the list of a process's threads.
#[derive(Clone, Copy)]
pub struct Siblings {
    pub prev: Option<NonNull<Thread>>,
    pub next: Option<NonNull<Thread>>,
}

/// A thread's message buffer: page `va` of its process, backed by `frame`,
/// which belongs to the thread (spec 6.2, 11).
struct Buffer {
    va: usize,
    frame: Frame,
}

const _: () = assert!(core::mem::offset_of!(Thread, regs) == 0);

// Three threads to a page of a pool (spec 7.8).
const _: () = assert!(kcore::slab::Pool::<Thread>::PER_PAGE >= 3);

// SAFETY: threads are reached under the kernel's rules (spec 8.1): one
// CPU, interrupts masked inside the kernel.
unsafe impl Send for Thread {}

/// Threads the system has at most (spec 8): the entries of the table of
/// thread numbers, which thread_create takes and a thread gives back as it
/// ends, or with its portion of cleanup when it never started.
pub const THREADS: usize = 1024;

// SAFETY: the node is a field of the thread and lives as long as it does.
unsafe impl Schedulable for Thread {
    fn node(this: NonNull<Thread>) -> NonNull<Node<Thread>> {
        // SAFETY: `this` points at a live thread.
        unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).sched) }
    }
}

/// Threads whose slots have not gone back.
static LIVE: Live = Live::new();

impl Thread {
    /// The thread's process, which the thread holds a reference to.
    pub fn process(&self) -> NonNull<Process> {
        self.process
    }

    /// The effective priority: the level of the cleanup the thread's calls
    /// and faults cause (spec 7.7).
    pub fn priority(&self) -> u8 {
        self.sched.priority()
    }
}

/// A stopped thread of `process` that will start at `entry` with stack
/// pointer `stack` and `arg` in x0, at `priority` under `policy`, once
/// `start` makes it ready. It has no message buffer until `give_buffer`.
/// The caller gets the first reference; the thread holds one to `process`
/// and joins its threads, it takes a number of the system table (spec
/// 6.1, 7.8), and its slot is in the pool of threads of `process`, whose
/// quota pays for a page when the pool grows. INVALID_ARGS for a start
/// outside the lower half, a misaligned one or priority 0, LIMIT_REACHED
/// when the process has abi::MAX_THREADS threads that have not ended and
/// then when the system has THREADS threads, NO_MEMORY when the quota
/// falls short for a page. The limits come first: a thread past them takes
/// nothing (spec 8, 11). `priority` is at most the ceiling of `process`:
/// the call checked it.
pub fn create(
    process: NonNull<Process>,
    entry: usize,
    stack: usize,
    arg: u64,
    priority: u8,
    policy: Policy,
) -> Result<NonNull<Thread>, Error> {
    kcore::args::check_start(entry as u64, stack as u64, priority)?;
    // SAFETY: the caller holds a reference to the process.
    let ceiling = unsafe { process.as_ref() }.ceiling();
    assert!(
        priority <= ceiling,
        "a thread above the ceiling of its process; the call checks it first"
    );
    process::thread_room(process)?;
    if sched::locked(|k| k.tokens.available()) == 0 {
        return Err(Error::LimitReached);
    }
    let thread = Thread {
        regs: UserRegs::start(entry as u64, stack as u64, arg),
        fp: FpRegs::ZERO,
        sched: Node::new(priority, policy),
        waits: None,
        // The owner is the thread's own place, known once it has one.
        slot: Slot::new(priority, Owner::Thread(NonNull::dangling())),
        transit: [None; MESSAGE_HANDLES],
        long: None,
        index: None,
        boost_token: 0,
        siblings: None,
        buffer: None,
        process,
        refs: Refs::one(),
        cleanup: Item::new(),
    };
    let thread = process::paid_alloc(process, thread)?;
    let index = sched::locked(|k| k.tokens.alloc(thread)).expect("a free thread number went");
    // SAFETY: the thread was just made, nothing else refers to it, and its
    // slot is in no queue.
    unsafe {
        (*thread.as_ptr()).slot = Slot::new(priority, Owner::Thread(thread));
        (*thread.as_ptr()).index = Some(index);
    }
    LIVE.made();
    process::retain(process);
    process::add_thread(process, thread);
    Ok(thread)
}

/// The own slot of `t` (Thread::slot), which lives as long as the thread.
pub fn slot(t: NonNull<Thread>) -> NonNull<Slot<Owner>> {
    // SAFETY: the caller holds the thread; only the field's address is
    // taken.
    unsafe { NonNull::new_unchecked(&raw mut (*t.as_ptr()).slot) }
}

/// The number of `t` in the system table (spec 6.1), which a thread that
/// has not ended holds.
pub fn index(t: NonNull<Thread>) -> u16 {
    // SAFETY: the caller holds the thread; only the field is read.
    unsafe { (*t.as_ptr()).index }.expect("a thread that has not ended holds its number")
}

/// Gives the number of `t` back to the table of thread numbers `tokens`,
/// unless it went back before (spec 6.1, 7.7): as the thread ends
/// (sched::exit), or with the portion of a thread that never started.
///
/// # Safety
/// `t` is alive; `tokens` is the locked table (sched::locked).
pub unsafe fn give_number(t: NonNull<Thread>, tokens: &mut Tokens) {
    // SAFETY: the caller's promise; only the field is touched.
    if let Some(index) = unsafe { (*t.as_ptr()).index.take() } {
        tokens.free(index);
    }
}

/// Gives `t` its message buffer (spec 6.2, 11): a fresh zeroed frame
/// mapped at page `va` of its process, readable and writable, never
/// executable, whose address TPIDRRO_EL0 of the thread holds from now on.
/// The frame is the thread's and goes when the thread ends; the quota of
/// the process pays for it and for the tables (phys::alloc_zeroed).
/// INVALID_ARGS for a page that is mapped already, NO_MEMORY when the
/// quota runs out; the thread has no buffer then.
pub fn give_buffer(t: NonNull<Thread>, va: usize) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the thread, which holds its
    // process.
    let p = unsafe { t.as_ref() }.process;
    // SAFETY: the thread's reference keeps the process, which lives: its
    // stage Quota is far.
    let frame = phys::alloc_zeroed(0, unsafe { process::account(p) })?;
    if let Err(e) = process::map_page(p, va, frame.pa(), Attrs::USER_DATA) {
        // SAFETY: as above; no table maps the frame, since the map failed.
        unsafe { phys::free(frame, process::account(p)) };
        return Err(e);
    }
    // SAFETY: as above; only the fields are written.
    unsafe {
        (*t.as_ptr()).buffer = Some(Buffer { va, frame });
        (*t.as_ptr()).regs.tpidrro = va as u64;
    }
    Ok(())
}

/// Gives the message buffer's frame back, if the thread has one, and
/// refunds it to the process (phys::free): its page is unmapped first, with
/// its TLB entry, while the process's space lives; otherwise the page went
/// with the space. The handles of a request the thread made go with it,
/// and what a long call it was making held, each released at `cause`
/// (`drop_transit`, `drop_long`, spec 6.1, 7.7).
///
/// # Safety
/// `t` is alive, waits in no queue, and does not run at EL0 again with its
/// buffer.
pub unsafe fn drop_buffer(t: NonNull<Thread>, cause: u8) {
    // SAFETY: the caller's promise; only the fields are touched, since the
    // thread may be released from its process's table meanwhile.
    let (buffer, p) = unsafe {
        drop_transit(t, cause);
        drop_long(t, cause);
        ((*t.as_ptr()).buffer.take(), (*t.as_ptr()).process)
    };
    let Some(Buffer { va, frame }) = buffer else {
        return;
    };
    let unmapped = process::unmap_page(p, va);
    assert!(
        unmapped.is_none_or(|pa| pa == frame.pa()),
        "a message buffer's page mapped another frame"
    );
    // SAFETY: the thread holds its process, whose buffers go no later than
    // its stage Buffers, before its stage Quota; the page and its TLB
    // entry went just now, or with the space and its ASID.
    unsafe { phys::free(frame, process::account(p)) };
}

/// Copies bytes `range` of the message buffer of `from` to the same
/// offsets of that of `to` (spec 6.2): bytes 64 up to the length of a
/// message, at most 960, frame to frame through the linear map; the kernel
/// reads no table of a program. A thread that sends, receives or answers
/// has its buffer until it ends.
///
/// # Safety
/// `to` and `from` are alive and differ, and nothing else borrows their
/// buffers.
pub unsafe fn copy_message(to: NonNull<Thread>, from: NonNull<Thread>, range: Range<usize>) {
    // SAFETY: the caller's promise; the two buffers are two objects.
    let (to, from) = unsafe { (&mut (*to.as_ptr()).buffer, &(*from.as_ptr()).buffer) };
    let (Some(to), Some(from)) = (to.as_mut(), from.as_ref()) else {
        unreachable!("a thread that takes part in a message has its buffer");
    };
    to.frame.copy_from(&from.frame, range);
}

/// Puts `moving`, the handles of a message of `t` that just left its
/// process's table (process::take_handles), on their way in `t`
/// (Thread::transit, spec 6.1). The field is empty: the handles of the
/// thread's last message went into a table (`take_transit`) or were
/// released (`drop_transit`). A field that is not empty stops the kernel,
/// since handles written over would keep their references for ever.
///
/// # Safety
/// `t` is alive, and nothing else borrows the field.
pub unsafe fn set_transit(t: NonNull<Thread>, moving: Moving) {
    // SAFETY: the caller's promise; only the field is touched.
    let transit = unsafe { &mut (*t.as_ptr()).transit };
    assert!(
        transit.iter().all(Option::is_none),
        "handles on their way are written over"
    );
    *transit = moving;
}

/// The handles on their way in `t` (Thread::transit), which leave it empty
/// for the table of the thread their message comes to (channel::deliver).
///
/// # Safety
/// `t` is alive, and nothing else borrows the field.
pub unsafe fn take_transit(t: NonNull<Thread>) -> Moving {
    // SAFETY: the caller's promise; only the field is touched.
    let transit = unsafe { &mut (*t.as_ptr()).transit };
    core::mem::replace(transit, [None; MESSAGE_HANDLES])
}

/// The handles on their way in `t` (Thread::transit), which no table took,
/// go, each released at `cause` as a closed handle is (spec 6.1): returns
/// how many. O(1): at most abi::MESSAGE_HANDLES.
///
/// # Safety
/// `t` is alive, waits in no queue, and does not run meanwhile.
pub unsafe fn drop_transit(t: NonNull<Thread>, cause: u8) -> usize {
    // SAFETY: the caller's promise; only the field is touched.
    let transit = unsafe { &mut (*t.as_ptr()).transit };
    if transit[0].is_none() {
        return 0;
    }
    let moving = core::mem::replace(transit, [None; MESSAGE_HANDLES]);
    let n = moving.iter().flatten().count();
    // SAFETY: the references were the handles', which left the table.
    unsafe { object::release_moving(moving, cause) };
    n
}

/// The long call `t` is making, if any (spec 7.7).
pub fn long(t: NonNull<Thread>) -> Option<Long> {
    // SAFETY: the caller holds the thread; only the field is read.
    unsafe { (*t.as_ptr()).long }
}

/// `t`, the running thread, which makes no long call, begins `long`: the
/// next entries of its `svc` go on with it (syscall::dispatch) until
/// `end_long` (spec 7.7).
pub fn begin_long(t: NonNull<Thread>, long: Long) {
    // SAFETY: the running thread is alive; only the field is touched.
    let field = unsafe { &mut (*t.as_ptr()).long };
    assert!(field.is_none(), "a thread begins a second long call");
    *field = Some(long);
}

/// The long call of `t`, the running thread, ended in its last portion:
/// what it held is the caller's (spec 7.7).
pub fn end_long(t: NonNull<Thread>) -> Option<Long> {
    // SAFETY: the running thread is alive; only the field is touched.
    unsafe { (*t.as_ptr()).long.take() }
}

/// The long call of `t` stops for good (spec 7.7): what it held goes, the
/// object of a mem_create released at `cause`. Returns the units of work
/// it took: 1 with a call, 0 without. O(1).
///
/// # Safety
/// `t` is alive, and nothing uses what its call held afterwards.
pub unsafe fn drop_long(t: NonNull<Thread>, cause: u8) -> usize {
    // SAFETY: the caller's promise; only the field is touched.
    match unsafe { (*t.as_ptr()).long.take() } {
        Some(Long::Create(m)) => {
            // SAFETY: the call held the object's reference, which goes.
            unsafe { memory::release(m, cause) };
            1
        }
        None => 0,
    }
}

/// The values of the `n` handles a message of `t` carries, which its
/// program put in its message buffer (abi::msgbuf::HANDLES, spec 6.2): read
/// once, before any check. A thread that sends or answers with handles has
/// its buffer until it ends.
pub fn handle_values(t: NonNull<Thread>, n: usize) -> [u64; MESSAGE_HANDLES] {
    // SAFETY: the caller holds the thread; only the field is borrowed.
    let Some(buffer) = (unsafe { &(*t.as_ptr()).buffer }) else {
        unreachable!("a thread that takes part in a message has its buffer");
    };
    let mut values = [0; MESSAGE_HANDLES];
    for (i, v) in values.iter_mut().enumerate().take(n) {
        *v = buffer.frame.word(msgbuf::HANDLES + 8 * i);
    }
    values
}

/// Writes the handles a message brought to `t`, their values and info
/// words (process::put_handles), into its message buffer at
/// abi::msgbuf::HANDLES and INFO (spec 6.2); the rest of both stays.
///
/// # Safety
/// `t` is alive, and nothing else borrows its buffer.
pub unsafe fn write_handles(t: NonNull<Thread>, handles: &[(u64, u64)]) {
    // SAFETY: the caller's promise.
    let Some(buffer) = (unsafe { &mut (*t.as_ptr()).buffer }) else {
        unreachable!("a thread that takes part in a message has its buffer");
    };
    for (i, &(value, info)) in handles.iter().enumerate() {
        buffer.frame.set_word(msgbuf::HANDLES + 8 * i, value);
        buffer.frame.set_word(msgbuf::INFO + 8 * i, info);
    }
}

/// A stopped thread becomes ready (thread_start, and the kernel for
/// init's first thread): the tail of its level with a new quantum, and a
/// started thread of its process from now on. BAD_STATE when its process
/// has ended or the thread started before.
pub fn start(t: NonNull<Thread>) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the thread.
    let p = unsafe { t.as_ref() }.process;
    process::check_alive(p)?;
    sched::start(t)?;
    process::thread_started(p).expect("a live process takes a thread");
    Ok(())
}

/// thread_exit: the running thread `t` ends. Its buffer goes, it leaves
/// the scheduler, with the kernel's reference, and its process's list of
/// threads that have not ended; as the last started thread of its process
/// it ends the process. What that releases is queued for cleanup at the
/// thread's priority. The caller leaves through sched::resume: `t` may be
/// queued for cleanup.
///
/// # Safety
/// `t` is the running thread, and the caller does not use it afterwards.
pub unsafe fn exit(t: NonNull<Thread>) {
    // SAFETY: the running thread is alive and holds its process; the
    // reference taken here keeps the process when the thread goes.
    let (p, cause) = unsafe { (t.as_ref().process, t.as_ref().priority()) };
    process::retain(p);
    // SAFETY: the thread never runs at EL0 again, and the caller hands it
    // over; the process lives until the release below.
    unsafe {
        drop_buffer(t, cause);
        sched::exit(t, cause);
        process::remove_thread(p, t);
        process::thread_exited(p, cause);
        process::release(p, cause);
    }
}

/// The count of references to `thread`, through the raw pointer.
///
/// # Safety
/// `thread` is alive, and nothing else borrows the count.
#[must_use]
unsafe fn refs<'a>(thread: NonNull<Thread>) -> &'a mut Refs {
    // SAFETY: the caller's promise; only the field is borrowed.
    unsafe { &mut (*thread.as_ptr()).refs }
}

/// Adds a reference to a live thread (Refs::retain).
pub fn retain(thread: NonNull<Thread>) {
    // SAFETY: the caller holds a reference, so the thread is alive.
    unsafe { refs(thread) }.retain();
}

/// Drops a reference; the last one queues the thread for cleanup at
/// `cause`, the level of the cleanup this release starts (spec 7.7).
///
/// # Safety
/// The reference is the caller's, and the caller does not use it afterwards.
pub unsafe fn release(thread: NonNull<Thread>, cause: u8) {
    // SAFETY: the caller's reference keeps the thread alive until here.
    if !unsafe { refs(thread) }.release() {
        return;
    }
    // SAFETY: as above; only the scheduler's part is read.
    let state = unsafe { thread.as_ref() }.sched.state();
    assert!(
        matches!(state, State::Stopped | State::Dead),
        "a thread the scheduler holds lost its last reference"
    );
    // SAFETY: that was the last reference: nothing reaches the thread
    // until its portion, and the pool keeps it in place.
    unsafe {
        let item = NonNull::new_unchecked(&raw mut (*thread.as_ptr()).cleanup);
        cleanup::enqueue(item, Object::Thread(thread), cause);
    }
}

/// The portion of a thread nobody refers to (cleanup): its buffer goes with
/// the handles of a request it made, released at `level`, its number goes
/// back to the system table with its count if it never started (spec 6.1),
/// it leaves its process's list if it is still there, its slot
/// goes back to its process's pool, and then its reference to its process,
/// queued at `level` if it was the last. When the thread ran last, no
/// thread ran after it.
///
/// # Safety
/// No reference to `thread` is left, and it is in no queue.
pub unsafe fn clean(thread: NonNull<Thread>, level: u8) {
    // SAFETY: the caller's promise.
    let process = unsafe { thread.as_ref() }.process;
    if current() == Some(thread) {
        user::clear_current();
    }
    // SAFETY: nothing uses the thread afterwards, and it leaves its
    // process's list before its slot goes.
    unsafe {
        drop_buffer(thread, level);
        sched::locked(|k| give_number(thread, k.tokens));
        process::remove_thread(process, thread);
        process::paid_free(process, thread);
        LIVE.gone(thread);
    }
    // SAFETY: the thread's reference to its process goes with it.
    unsafe { process::release(process, level) };
}

// The poison of a thread that went (Live::gone) reaches its count.
const _: () = assert!(core::mem::offset_of!(Thread, refs) >= 8);

/// The thread whose registers, FP registers and address space are live:
/// the running one, or while the kernel idles the one that ran last.
pub fn current() -> Option<NonNull<Thread>> {
    NonNull::new(user::current().cast())
}

/// Runs `next` at EL0. A switch from another thread saves that one's FP
/// and SIMD registers and loads next's; TTBR0 goes to next's address space
/// unless it holds it already; then the kernel returns to EL0 with next's
/// registers. Never returns: the kernel stack starts over at the next
/// entry, and no value on the caller's stack is ever dropped, so the caller
/// holds none with a `Drop`: no lock guard, `AddressSpace` or the like.
pub fn run(next: NonNull<Thread>) -> ! {
    let prev = current();
    // SAFETY: the running thread and `next` are alive, and so are their
    // processes; the kernel touches them one at a time.
    unsafe {
        if prev != Some(next) {
            if let Some(mut prev) = prev {
                user::save_fp(&mut prev.as_mut().fp);
            }
            user::load_fp(&next.as_ref().fp);
        }
        let mut process = next.as_ref().process;
        process.as_mut().activate();
        user::enter(next.as_ptr().cast())
    }
}

/// Threads whose slots have not gone back.
#[cfg(feature = "ktest")]
pub fn in_use() -> usize {
    LIVE.count()
}
