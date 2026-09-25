// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Threads (spec 4, 8, 8.1): a program's registers, FP and SIMD included,
//! its scheduling parameters, its message buffer and its process, in
//! objects from a kernel pool. The registers come first, so TPIDR_EL1,
//! which points at the running thread, points at them too (vectors.S). The
//! running thread is the one TPIDR_EL1 names; the kernel stack holds
//! nothing of it. A thread lives while references to it are left: handles,
//! the one `create` hands out, and the kernel's while the scheduler holds
//! the thread; it holds a reference to its process. A thread that ended
//! stays as a shell without its buffer until its last reference goes.

use crate::arch::user::{self, FpRegs, UserRegs};
use crate::mm::pages::KernelPages;
use crate::mm::phys::FRAMES;
use crate::process::{self, Process};
use crate::sched;
use abi::Error;
use core::ptr::NonNull;
use kcore::frames::PAGE_SIZE;
use kcore::layout::LINEAR_BASE;
use kcore::paging::Attrs;
use kcore::sched::{Node, Schedulable, State};
use kcore::slab::Pool;
use kcore::sync::Lock;
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
    /// Links in the list of its process's threads, which process::end
    /// walks; only process::{add_thread, remove_thread} change them.
    pub siblings: Siblings,
    /// The page `give_buffer` mapped for messages; it goes when the thread
    /// ends (`exit`, process::end) or goes.
    buffer: Option<Buffer>,
    process: NonNull<Process>,
    /// Handles to the thread, the reference `create` hands out and the
    /// kernel's from `start` to the end.
    refs: u32,
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
// CPU, interrupts masked inside the kernel, the pool behind a lock.
unsafe impl Send for Thread {}

// SAFETY: the node is a field of the thread and lives as long as it does.
unsafe impl Schedulable for Thread {
    fn node(this: NonNull<Thread>) -> NonNull<Node<Thread>> {
        // SAFETY: `this` points at a live thread.
        unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).sched) }
    }
}

static THREADS: Lock<Pool<Thread>> = Lock::new(Pool::new());

impl Thread {
    /// The thread's process, which the thread holds a reference to.
    pub fn process(&self) -> NonNull<Process> {
        self.process
    }
}

/// A stopped thread of `process` that will start at `entry` with stack
/// pointer `stack` and `arg` in x0, at `priority` under `policy`, once
/// `start` makes it ready. It has no message buffer until `give_buffer`.
/// The caller gets the first reference; the thread holds one to `process`
/// and joins its threads. INVALID_ARGS for a start outside the lower half,
/// a misaligned one or priority 0, NO_MEMORY when the pool gets no page.
/// `priority` is at most the ceiling of `process`: the call checked it.
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
    let thread = Thread {
        regs: UserRegs::start(entry as u64, stack as u64, arg),
        fp: FpRegs::ZERO,
        base_priority: priority,
        sched: Node::new(priority, policy),
        siblings: Siblings {
            prev: None,
            next: None,
        },
        buffer: None,
        process,
        refs: 1,
    };
    let thread = THREADS
        .lock()
        .alloc(&mut KernelPages, thread)
        .map_err(|_| Error::NoMemory)?;
    process::retain(process);
    process::add_thread(process, thread);
    Ok(thread)
}

/// Gives `t` its message buffer (spec 11): a fresh zeroed frame mapped
/// at page `va` of its process, readable and writable, never executable.
/// The frame is the thread's and goes when the thread ends. INVALID_ARGS
/// for a page that is mapped already, NO_MEMORY when frames or table
/// memory run out; the thread has no buffer then.
pub fn give_buffer(t: NonNull<Thread>, va: usize) -> Result<(), Error> {
    let pa = FRAMES
        .lock()
        .as_mut()
        .expect("frame allocator")
        .alloc(0)
        .ok_or(Error::NoMemory)?;
    // SAFETY: the frame was just allocated and lies in the linear map; no
    // program sees it before it is zeroed.
    unsafe {
        core::ptr::write_bytes(
            (LINEAR_BASE + pa as usize) as *mut u8,
            0,
            PAGE_SIZE as usize,
        )
    };
    // SAFETY: the caller holds a reference to the thread, which holds its
    // process.
    let p = unsafe { t.as_ref() }.process;
    if let Err(e) = process::map_page(p, va, pa, Attrs::USER_DATA) {
        FRAMES.lock().as_mut().expect("frame allocator").free(pa, 0);
        return Err(e);
    }
    // SAFETY: as above; only the field is written.
    unsafe { (*t.as_ptr()).buffer = Some(Buffer { va, pa }) };
    Ok(())
}

/// Gives the message buffer's frame back, if the thread has one: its page
/// is unmapped first, with its TLB entry, while the process's space lives;
/// otherwise the page went with the space.
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
/// the scheduler, with the kernel's reference, and as the last started
/// thread of its process it ends the process. The caller leaves through
/// sched::resume: `t` may be gone.
///
/// # Safety
/// `t` is the running thread, and the caller does not use it afterwards.
pub unsafe fn exit(t: NonNull<Thread>) {
    // SAFETY: the running thread is alive and holds its process; the
    // reference taken here keeps the process when the thread goes.
    let p = unsafe { t.as_ref() }.process;
    process::retain(p);
    // SAFETY: the thread never runs at EL0 again, and the caller hands it
    // over; the process lives until the release below.
    unsafe {
        drop_buffer(t);
        sched::exit(t);
        process::thread_exited(p);
        process::release(p);
    }
}

/// Adds a reference to a live thread.
pub fn retain(mut thread: NonNull<Thread>) {
    // SAFETY: the caller holds a reference, so the thread is alive.
    let t = unsafe { thread.as_mut() };
    t.refs = t.refs.checked_add(1).expect("thread references overflow");
}

/// Drops a reference; the last one destroys the thread, which then drops
/// its reference to its process. When the thread is the running one, no
/// thread runs after it.
///
/// # Safety
/// The reference is the caller's, and the caller does not use it afterwards.
pub unsafe fn release(mut thread: NonNull<Thread>) {
    // SAFETY: the caller's reference keeps the thread alive until here.
    let t = unsafe { thread.as_mut() };
    t.refs -= 1;
    if t.refs > 0 {
        return;
    }
    assert!(
        !matches!(t.sched.state(), State::Ready | State::Running),
        "a thread the scheduler holds lost its last reference"
    );
    let process = t.process;
    if current() == Some(thread) {
        user::clear_current();
    }
    // SAFETY: that was the last reference; nothing uses the thread
    // afterwards, and it leaves its process's list before its slot goes.
    unsafe {
        drop_buffer(thread);
        process::remove_thread(process, thread);
        THREADS.lock().free(thread);
        // Test builds poison the slot past the pool's link, as for processes.
        #[cfg(feature = "ktest")]
        core::ptr::write_bytes(
            thread.cast::<u8>().as_ptr().add(8),
            0xA5,
            core::mem::size_of::<Thread>() - 8,
        );
    }
    // SAFETY: the thread's reference to its process goes with it.
    unsafe { process::release(process) };
}

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

/// Objects the thread pool holds now.
#[cfg(feature = "ktest")]
pub fn in_use() -> usize {
    THREADS.lock().in_use()
}
