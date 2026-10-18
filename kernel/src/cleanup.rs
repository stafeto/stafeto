// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The cleanup queue (spec 7.7). The last reference to an object only
//! queues it, in O(1); the object is taken apart later, a portion at a
//! time, on the empty kernel stack between two polls for interrupts
//! (sched::resume). A portion never takes another object apart inside
//! itself: what it releases is queued in turn, so the kernel stack does
//! not grow with how deep objects hold each other. Each item stands at a
//! level of 1-63, the level of its cause: the effective priority of the
//! thread whose call let the last reference go, or the level of the item
//! whose portion let it go. The scheduler treats the queue as one more
//! thread at the queue's top level (kcore::sched::Scheduler::pick), so
//! cleanup never delays work above its cause and never starves: in idle
//! every level runs. Neither the interrupt code nor the cleanup takes a
//! level from thread::current(), which names the last thread that ran.
//! Besides objects, the queue holds the firings of timers: an item for
//! each level of 1-63, which the timer interrupt queues at its level
//! (crate::timer::expire), and whose portion fires expired timers of that
//! level (spec 10).

use crate::arch::cpu::{self, CpuBlock};
use crate::arch::timer;
use crate::local::local;
use crate::object::Object;
use crate::{channel, process, session, thread};
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use kcore::sched::{Link, Linked, ReadyQueue};
use kcore::time::stretch;

/// What an item stands in the queue for.
pub enum Work {
    /// An object to take apart.
    Object(Object),
    /// The firing of the timers of the item's level (crate::timer::fire).
    Timers,
}

impl From<Object> for Work {
    fn from(object: Object) -> Work {
        Work::Object(object)
    }
}

/// What an object keeps for the cleanup queue, or the timers keep for a
/// level: its link there and, while it is queued, its work. An object has
/// one item: it is queued again only after its first portion took it out.
pub struct Item {
    link: Link<Item>,
    work: Option<Work>,
}

impl Item {
    /// An item in no queue.
    pub const fn new() -> Item {
        Item {
            link: Link::new(0),
            work: None,
        }
    }
}

/// The lock of one CPU's queue and the queue it guards, for as long as the
/// guard lives.
struct QueueGuard {
    queue: *mut Queue,
    block: &'static CpuBlock,
    /// Whether the guard holds the spin lock: a push in a section under
    /// `OBJ` does not, since every other CPU that changes the queue does it
    /// in a section too, and a section excludes it.
    spinning: bool,
}

impl core::ops::Deref for QueueGuard {
    type Target = Queue;
    fn deref(&self) -> &Queue {
        // SAFETY: the guard holds the queue's lock or a section of `OBJ`.
        unsafe { &*self.queue }
    }
}

impl core::ops::DerefMut for QueueGuard {
    fn deref_mut(&mut self) -> &mut Queue {
        // SAFETY: as above.
        unsafe { &mut *self.queue }
    }
}

impl Drop for QueueGuard {
    fn drop(&mut self) {
        if self.spinning {
            self.block.local.queue_spin.store(false, Ordering::Release);
        }
    }
}

/// Takes the queue of CPU `block`. Interrupts are masked in the kernel and
/// a holder never waits for anything while it holds the lock, so the wait
/// is as long as one of the short holds below.
fn lock_queue(block: &'static CpuBlock) -> QueueGuard {
    spin_lock_queue(block, true)
}

fn spin_lock_queue(block: &'static CpuBlock, spinning: bool) -> QueueGuard {
    if spinning {
        while block.local.queue_spin.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }
    QueueGuard {
        queue: block.local.queue.as_ptr().cast_mut(),
        block,
        spinning,
    }
}

/// The queue of the CPU that runs this.
fn lock_own_queue() -> QueueGuard {
    lock_queue(cpu::this())
}

impl Item {
    /// The CPU whose queue holds the item, or held it last: set under that
    /// queue's lock (`push`), read by a section on another CPU that raises
    /// or removes the item.
    fn cpu(this: NonNull<Item>) -> usize {
        // SAFETY: the caller's item is alive; the owner tag is a byte.
        unsafe { Link::owner_at(&raw const (*this.as_ptr()).link) as usize }
    }
}

// SAFETY: the link is a field of the item.
unsafe impl Linked for Item {
    fn link(this: NonNull<Item>) -> NonNull<Link<Item>> {
        // SAFETY: `this` points at a live item.
        unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).link) }
    }
}

pub(crate) struct Queue {
    items: ReadyQueue<Item>,
    /// Items queued now.
    len: u64,
    /// The longest portion so far, of cleanup or of a long call
    /// (`count_portion`), in counter ticks.
    longest: u64,
    /// A portion began while an interrupt was pending.
    #[cfg(feature = "ktest")]
    late: bool,
}

// SAFETY: items are reached under the kernel's rules (spec 8.1): one CPU,
// interrupts masked inside the kernel.
unsafe impl Send for Queue {}

impl Queue {
    pub(crate) const fn new() -> Queue {
        Queue {
            items: ReadyQueue::new(),
            len: 0,
            longest: 0,
            #[cfg(feature = "ktest")]
            late: false,
        }
    }
}

/// Queues `work` at the tail of `level` (1-63): the last reference of its
/// object just went, or its teardown begins (process::end), or timers of
/// the level expired.
///
/// # Safety
/// `item` is the object's own, or the level's for its timers, and in no
/// queue; the object stays alive and in place, and nothing else takes it
/// apart, until its portion.
pub unsafe fn enqueue(item: NonNull<Item>, work: impl Into<Work>, level: u8) {
    // SAFETY: the caller's promise.
    unsafe { push(item, work.into(), level, false) }
}

/// Queues `work` again at the head of `level` after its portion left
/// work for the next one: the next portion at that level goes on with it,
/// as a preempted thread goes on first at its level (spec 8), so one
/// teardown ends before the next begins.
///
/// # Safety
/// As for `enqueue`.
pub unsafe fn requeue(item: NonNull<Item>, work: impl Into<Work>, level: u8) {
    // SAFETY: the caller's promise.
    unsafe { push(item, work.into(), level, true) }
}

/// Takes an item's work out of the queue in O(1): true when it was queued.
/// False when the owner's portion took it off the queue already, with its
/// work, which happens with no hold of `OBJ` (`portion`): that portion
/// runs the work and keeps the reference the item stood for, and the item
/// is not in the queue until the portion queues it again.
///
/// # Safety
/// `item` is alive; its work belongs to the object, which is at its stage
/// or in its continuation, and queued or in its portion.
pub unsafe fn remove(item: NonNull<Item>) -> bool {
    // The item is queued on the CPU that pushed it, which may be another
    // CPU than this: its queue, under its lock.
    let mut q = loop {
        let at = Item::cpu(item);
        let q = lock_queue(cpu::block(at));
        if Item::cpu(item) == at {
            break q;
        }
    };
    // SAFETY: the caller's promise; the link is read under the queue's
    // lock, which `portion` holds when it takes the item.
    unsafe {
        if !(*item.as_ptr()).link.is_queued() {
            return false;
        }
        q.items.remove(item);
        (*item.as_ptr()).work = None;
    }
    q.len -= 1;
    true
}

/// Moves a queued object to the head of `level`, unless it stands higher:
/// the object whose portion calls it waits for this one, right behind it
/// (the stage Children of a process, spec 7.7).
///
/// # Safety
/// `item` is the object's own, and the object is queued and alive.
pub unsafe fn raise(item: NonNull<Item>, level: u8) {
    // SAFETY: the caller's promise.
    unsafe { lift(item, level, true) }
}

/// Moves a queued object to the head of `level` when that is above its
/// own, and leaves it in its place otherwise: a waiter of its stage Close
/// or Replies rose (thread_set_priority, spec 7.7).
///
/// # Safety
/// As for `raise`.
pub unsafe fn raise_above(item: NonNull<Item>, level: u8) {
    // SAFETY: the caller's promise.
    unsafe { lift(item, level, false) }
}

/// `raise` with `level_too`, `raise_above` without it: whether an object
/// at `level` moves to its head as well.
///
/// # Safety
/// As for `raise`.
unsafe fn lift(item: NonNull<Item>, level: u8, level_too: bool) {
    // The queue of the CPU that pushed the item, under its lock; a CPU
    // that owns another queue than this one raises the item there and asks
    // its owner to look again (its next way out of the kernel decides).
    let (mut q, at) = loop {
        let at = Item::cpu(item);
        let q = lock_queue(cpu::block(at));
        if Item::cpu(item) == at {
            break (q, at);
        }
    };
    // SAFETY: the caller's promise; the link is touched only while the
    // queue's lock is held.
    let raised = unsafe {
        let link = &raw mut (*item.as_ptr()).link;
        // The owner took the item meanwhile: its portion runs, and there
        // is nothing to raise.
        if !(*link).is_queued() {
            return;
        }
        let own = (*link).level();
        let raised = own < level || level_too && own == level;
        if raised {
            q.items.remove(item);
            (*link).set_level(level);
            q.items.push_head(item);
        }
        raised
    };
    drop(q);
    if raised && at != cpu::this().index() {
        crate::arch::gic::send_sgi(at, kcore::gic::SGI_CMD);
    }
}

/// # Safety
/// As for `enqueue`.
unsafe fn push(item: NonNull<Item>, work: Work, level: u8, head: bool) {
    let this = cpu::this();
    // A push in a section under `OBJ` takes no lock: every other CPU that
    // changes this queue does it in a section too, which excludes it, and
    // the portion that takes items off it runs on this CPU.
    let spin = !crate::obj::held();
    if spin {
        while this.local.queue_spin.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }
    // SAFETY: the lock or the section excludes the other CPUs; the caller's
    // promise for the item.
    unsafe {
        let q = &mut *this.local.queue.as_ptr().cast_mut();
        let i = &mut *item.as_ptr();
        i.link.set_owner(this.index() as u8);
        i.work = Some(work);
        i.link.set_level(level);
        if head {
            q.items.push_head(item);
        } else {
            q.items.push_tail(item);
        }
        q.len += 1;
    }
    if spin {
        this.local.queue_spin.store(false, Ordering::Release);
    }
}

/// The top level of the queue; None when it is empty.
pub fn top() -> Option<u8> {
    lock_own_queue().items.top()
}

/// The top level during the scheduler's decision, without the lock: one
/// relaxed load of the queue's mask (`ReadyQueue::top_unlocked`), which a
/// holder of the lock on another core may change meanwhile. The decision
/// treats the answer as a hint and takes OBJ before it acts.
#[cfg(not(feature = "locked-decide"))]
pub fn top_for_decide() -> Option<u8> {
    // SAFETY: the queue is a static; only its atomic mask is read.
    unsafe { ReadyQueue::top_unlocked(&raw const (*local().queue.as_ptr()).items) }
}

/// One portion (sched::resume): the item at the head of the top level
/// leaves the queue, and its object's portion runs, or the firing of the
/// timers of that level; what that releases is queued at the same level,
/// and work left queues itself again (`requeue`). Nothing happens when the
/// queue is empty.
pub fn portion() {
    #[cfg(feature = "ktest")]
    if crate::arch::irq_pending() {
        lock_own_queue().late = true;
    }
    let start = timer::now();
    let (work, level) = {
        let mut q = lock_own_queue();
        let Some(level) = q.items.top() else {
            return;
        };
        let item = q.items.first(level).expect("a level with its bit set");
        // SAFETY: a queued item is alive and in this queue; its work is
        // taken in the same hold, so that an item that is not queued has no
        // work either (`remove` says false then).
        let work = unsafe {
            q.items.remove(item);
            (*item.as_ptr()).work.take()
        };
        q.len -= 1;
        (work.expect("queued work"), level)
    };
    crate::testpoint::portion_taken();
    crate::obj::serving(crate::obj::ENTRY_CLEANUP);
    // SAFETY: nothing refers to the object any more.
    unsafe {
        match work {
            Work::Object(Object::Process(p)) => {
                crate::obj::serving(crate::obj::CLEAN_PROCESS);
                process::clean(p, level)
            }
            Work::Object(Object::Thread(t)) => {
                crate::obj::serving(crate::obj::CLEAN_THREAD);
                let _section = crate::obj::lock();
                thread::clean(t, level)
            }
            Work::Object(Object::Channel(c)) => {
                crate::obj::serving(crate::obj::CLEAN_CHANNEL);
                channel::clean(c, level)
            }
            Work::Object(Object::Session(s)) => {
                crate::obj::serving(crate::obj::CLEAN_SESSION);
                let _section = crate::obj::lock();
                session::clean(s, level)
            }
            Work::Object(Object::Timer(t)) => {
                crate::obj::serving(crate::obj::CLEAN_TIMER);
                let _section = crate::obj::lock();
                crate::timer::clean(t, level)
            }
            Work::Object(Object::Memory(m)) => {
                crate::obj::serving(crate::obj::CLEAN_MEMORY);
                crate::memory::clean(m, level)
            }
            Work::Object(Object::Irq(b)) => {
                crate::obj::serving(crate::obj::CLEAN_IRQ);
                let _section = crate::obj::lock();
                crate::irq::clean(b, level)
            }
            Work::Object(Object::Resource) => {
                unreachable!("the system resource is never queued")
            }
            Work::Timers => crate::timer::fire(level),
        }
    }
    crate::obj::serving(0);
    let took = stretch(start, timer::now());
    crate::testpoint::portion_done();
    note_longest(took);
}

/// Items queued now, for KSTATS (spec 16).
pub fn len() -> u64 {
    lock_own_queue().len
}

/// A portion of a long call (spec 7.7) that began at `start`, in counter
/// ticks, counts toward the longest portion as one of cleanup does: both
/// add to the blocking of any thread (KSTATS x5).
pub fn count_portion(start: u64) {
    note_longest(stretch(start, timer::now()));
}

/// Notes a portion that took `took` ticks. Only this CPU reads or writes
/// `longest`, so it takes no lock, and it touches the field alone: another
/// CPU may be raising an item of the queue meanwhile.
fn note_longest(took: u64) {
    let q = cpu::this().local.queue.as_ptr().cast_mut();
    // SAFETY: the field is the owner's alone, and the owner is this CPU.
    unsafe {
        let longest = &raw mut (*q).longest;
        *longest = (*longest).max(took);
    }
}

/// The longest portion so far, of cleanup or of a long call, in counter
/// ticks, for KSTATS.
pub fn longest() -> u64 {
    lock_own_queue().longest
}

/// The longest portion so far, which goes back to 0: a test that checks
/// what a call counts takes it first (KSTATS x5).
#[cfg(feature = "ktest")]
pub fn take_longest() -> u64 {
    core::mem::take(&mut lock_own_queue().longest)
}

/// Runs portions until the queue is empty: tests that count the objects
/// in pools call it, since the queue otherwise waits for the next way out
/// of the kernel, and frees what waited for a quiescent period (qsbr).
#[cfg(feature = "ktest")]
pub fn drain() {
    loop {
        while top().is_some() {
            // Each portion is a stretch of its own, as between two polls of
            // the way out of the kernel (obj::stretch_begins).
            #[cfg(feature = "measure")]
            crate::obj::stretch_begins(timer::now());
            portion();
            #[cfg(feature = "measure")]
            crate::obj::stretch_ends(timer::now());
        }
        if !crate::qsbr::pending() {
            return;
        }
        // The kernel stack is empty here too: a quiescent point frees the
        // retired objects, which may queue more.
        crate::qsbr::quiesce();
        if top().is_none() {
            return;
        }
    }
}

/// Whether a portion began while an interrupt was pending since the last
/// call.
#[cfg(feature = "ktest")]
pub fn take_late() -> bool {
    core::mem::take(&mut lock_own_queue().late)
}
