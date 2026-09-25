// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Threads (spec 4, 8, 8.1): a program's registers, FP and SIMD included,
//! its scheduling parameters, its message buffer and its process, in
//! objects from the pool of threads of their process. The registers come
//! first, so TPIDR_EL1, which points at the running thread, points at them
//! too (vectors.S). The
//! running thread is the one TPIDR_EL1 names; the kernel stack holds
//! nothing of it. A thread lives while references to it are left: handles,
//! the one `create` hands out, and the kernel's while the scheduler holds
//! the thread; it holds a reference to its process. A thread that ended
//! stays as a shell without its buffer until its last reference goes,
//! which queues it for cleanup (spec 7.7). Its process pays from its quota
//! for the pages of its pool of threads (spec 7.8) and for the buffer
//! while it lasts (spec 7.5).

use crate::arch::user::{self, FpRegs, UserRegs};
use crate::cleanup::{self, Item};
use crate::mm::phys::FRAMES;
use crate::object::Object;
use crate::process::{self, Process};
use crate::sched;
use abi::Error;
use core::ptr::NonNull;
use kcore::frames::PAGE_SIZE;
use kcore::layout::LINEAR_BASE;
use kcore::paging::Attrs;
use kcore::sched::{Node, Schedulable, State};
pub use kcore::thread::Policy;

#[repr(C)]
pub struct Thread {
    /// First: TPIDR_EL1 and vectors.S reach it at the thread's address.
    pub regs: UserRegs,
    /// Saved while the thread does not run.
    pub fp: FpRegs,
    /// The priority `create` or thread_set_priority gave. The effective
    /// one, which picks the level, is in `sched`; the two differ from
    /// milestone 1.3 on, while a service works for a request (spec 6.6).
    pub base_priority: u8,
    /// What the scheduler keeps in the thread: the effective priority, the
    /// policy, the state, the rest of a quantum and the links of the ready
    /// list. Only the scheduler changes it (sched).
    pub sched: Node<Thread>,
    /// Links in the list of its process's threads that have not ended,
    /// which process::end walks; None once the thread left it. Only
    /// process::{add_thread, remove_thread} change them.
    pub siblings: Option<Siblings>,
    /// The page `give_buffer` mapped for messages; it goes when the thread
    /// exits (`exit`), at the stage Buffers of its process, or when the
    /// thread goes.
    buffer: Option<Buffer>,
    process: NonNull<Process>,
    /// Handles to the thread, the reference `create` hands out and the
    /// kernel's from `start` to the end.
    refs: u32,
    /// Its place in the cleanup queue once its last reference goes.
    cleanup: Item,
}

/// Neighbours in the list of a process's threads.
#[derive(Clone, Copy)]
pub struct Siblings {
    pub prev: Option<NonNull<Thread>>,
    pub next: Option<NonNull<Thread>>,
}

/// A thread's message buffer: page `va` of its process, backed by the
/// frame at `pa`, which belongs to the thread (spec 11).
#[derive(Clone, Copy)]
struct Buffer {
    va: usize,
    pa: u64,
}

const _: () = assert!(core::mem::offset_of!(Thread, regs) == 0);

// SAFETY: threads are reached under the kernel's rules (spec 8.1): one
// CPU, interrupts masked inside the kernel.
unsafe impl Send for Thread {}

// SAFETY: the node is a field of the thread and lives as long as it does.
unsafe impl Schedulable for Thread {
    fn node(this: NonNull<Thread>) -> NonNull<Node<Thread>> {
        // SAFETY: `this` points at a live thread.
        unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).sched) }
    }
}

/// Threads whose slots have not gone back (test builds).
#[cfg(feature = "ktest")]
static LIVE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

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
/// and joins its threads, and its slot is in the pool of threads of
/// `process`, whose quota pays for a page when the pool grows. INVALID_ARGS
/// for a start outside the lower half, a misaligned one or priority 0,
/// LIMIT_REACHED when the process has abi::MAX_THREADS threads that have
/// not ended, NO_MEMORY when the quota falls short for a page. The limit
/// comes first: a thread past it takes nothing. `priority` is at most the
/// ceiling of `process`: the call checked it.
pub fn create(
    process: NonNull<Process>,
    entry: usize,
    stack: usize,
    arg: u64,
    priority: u8,
    policy: Policy,
) -> Result<NonNull<Thread>, Error> {
    kcore::thread::check_start(entry as u64, stack as u64, priority)?;
    // SAFETY: the caller holds a reference to the process.
    let ceiling = unsafe { process.as_ref() }.ceiling();
    assert!(
        priority <= ceiling,
        "a thread above the ceiling of its process; the call checks it first"
    );
    process::thread_room(process)?;
    let thread = Thread {
        regs: UserRegs::start(entry as u64, stack as u64, arg),
        fp: FpRegs::ZERO,
        base_priority: priority,
        sched: Node::new(priority, policy),
        siblings: None,
        buffer: None,
        process,
        refs: 1,
        cleanup: Item::new(),
    };
    let thread = process::thread_slot(process, thread)?;
    #[cfg(feature = "ktest")]
    LIVE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    process::retain(process);
    process::add_thread(process, thread);
    Ok(thread)
}

/// Gives `t` its message buffer (spec 11): a fresh zeroed frame mapped
/// at page `va` of its process, readable and writable, never executable.
/// The frame is the thread's and goes when the thread ends; the quota of
/// the process pays for it and for the tables. INVALID_ARGS for a page
/// that is mapped already, NO_MEMORY when the quota runs out; the thread
/// has no buffer then. A charge that passed always finds its frame (spec
/// 7.8).
pub fn give_buffer(t: NonNull<Thread>, va: usize) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the thread, which holds its
    // process.
    let p = unsafe { t.as_ref() }.process;
    process::charge(p, PAGE_SIZE)?;
    let pa = FRAMES
        .lock()
        .as_mut()
        .expect("frame allocator")
        .alloc(0)
        .expect("a charge that passed found no frame (spec 7.8)");
    // SAFETY: the frame was just allocated and lies in the linear map; no
    // program sees it before it is zeroed.
    unsafe {
        core::ptr::write_bytes(
            (LINEAR_BASE + pa as usize) as *mut u8,
            0,
            PAGE_SIZE as usize,
        )
    };
    if let Err(e) = process::map_page(p, va, pa, Attrs::USER_DATA) {
        FRAMES.lock().as_mut().expect("frame allocator").free(pa, 0);
        process::refund(p, PAGE_SIZE);
        return Err(e);
    }
    // SAFETY: as above; only the field is written.
    unsafe { (*t.as_ptr()).buffer = Some(Buffer { va, pa }) };
    Ok(())
}

/// Gives the message buffer's frame back, if the thread has one, and
/// refunds it to the process: its page is unmapped first, with its TLB
/// entry, while the process's space lives; otherwise the page went with
/// the space.
///
/// # Safety
/// `t` is alive and does not run at EL0 again with its buffer.
pub unsafe fn drop_buffer(t: NonNull<Thread>) {
    // SAFETY: the caller's promise; only the fields are touched, since the
    // thread may be released from its process's table meanwhile.
    let (buffer, p) = unsafe { ((*t.as_ptr()).buffer.take(), (*t.as_ptr()).process) };
    let Some(Buffer { va, pa }) = buffer else {
        return;
    };
    let unmapped = process::unmap_page(p, va);
    assert!(
        unmapped.is_none_or(|frame| frame == pa),
        "a message buffer's page mapped another frame"
    );
    FRAMES.lock().as_mut().expect("frame allocator").free(pa, 0);
    process::refund(p, PAGE_SIZE);
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
        drop_buffer(t);
        sched::exit(t, cause);
        process::remove_thread(p, t);
        process::thread_exited(p, cause);
        process::release(p, cause);
    }
}

/// The count of references to `thread`, through the raw pointer. Test
/// builds stop a thread that went: the poison of its slot reaches the
/// count (`clean`).
///
/// # Safety
/// `thread` is alive, and nothing else borrows the count.
unsafe fn refs<'a>(thread: NonNull<Thread>) -> &'a mut u32 {
    // SAFETY: the caller's promise; only the field is borrowed.
    let refs = unsafe { &mut (*thread.as_ptr()).refs };
    #[cfg(feature = "ktest")]
    assert!(
        *refs != u32::from_ne_bytes([POISON; 4]),
        "a thread is used after it went"
    );
    refs
}

/// Adds a reference to a live thread. A thread nobody refers to waits for
/// its portion, and taking it back from the queue would free it twice.
pub fn retain(thread: NonNull<Thread>) {
    // SAFETY: the caller holds a reference, so the thread is alive.
    let refs = unsafe { refs(thread) };
    assert!(*refs > 0, "a thread nobody refers to is retained");
    *refs = refs.checked_add(1).expect("thread references overflow");
}

/// Drops a reference; the last one queues the thread for cleanup at
/// `cause`, the level of the cleanup this release starts (spec 7.7).
///
/// # Safety
/// The reference is the caller's, and the caller does not use it afterwards.
pub unsafe fn release(thread: NonNull<Thread>, cause: u8) {
    // SAFETY: the caller's reference keeps the thread alive until here.
    let refs = unsafe { refs(thread) };
    *refs = refs
        .checked_sub(1)
        .expect("a thread is released once too often");
    if *refs > 0 {
        return;
    }
    // SAFETY: as above; only the scheduler's part is read.
    let state = unsafe { thread.as_ref() }.sched.state();
    assert!(
        !matches!(state, State::Ready | State::Running),
        "a thread the scheduler holds lost its last reference"
    );
    // SAFETY: that was the last reference: nothing reaches the thread
    // until its portion, and the pool keeps it in place.
    unsafe {
        let item = NonNull::new_unchecked(&raw mut (*thread.as_ptr()).cleanup);
        cleanup::enqueue(item, Object::Thread(thread), cause);
    }
}

/// The portion of a thread nobody refers to (cleanup): its buffer goes,
/// it leaves its process's list if it is still there, its slot goes back
/// to its process's pool, and then its reference to its process, queued
/// at `level` if it was the last. When the thread ran last, no thread ran
/// after it.
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
        drop_buffer(thread);
        process::remove_thread(process, thread);
        process::free_thread_slot(process, thread);
        // Test builds poison the slot past the pool's link, as for
        // processes: `refs` stops a use after free.
        #[cfg(feature = "ktest")]
        core::ptr::write_bytes(
            thread.cast::<u8>().as_ptr().add(8),
            POISON,
            core::mem::size_of::<Thread>() - 8,
        );
    }
    #[cfg(feature = "ktest")]
    LIVE.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: the thread's reference to its process goes with it.
    unsafe { process::release(process, level) };
}

/// What test builds fill a gone thread with, past the pool's link.
#[cfg(feature = "ktest")]
const POISON: u8 = 0xA5;

// The poison reaches `refs`, which `refs` checks.
#[cfg(feature = "ktest")]
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
    LIVE.load(core::sync::atomic::Ordering::Relaxed)
}
