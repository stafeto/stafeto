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

use crate::arch::timer;
use crate::object::Object;
use crate::{channel, process, session, thread};
use core::ptr::NonNull;
use kcore::sched::{Link, Linked, ReadyQueue};
use kcore::sync::Lock;

/// What an object keeps for the cleanup queue: its link there and, while
/// it is queued, the object itself. An object has one item: it is queued
/// again only after its first portion took it out.
pub struct Item {
    link: Link<Item>,
    object: Option<Object>,
}

impl Item {
    /// An item in no queue.
    pub const fn new() -> Item {
        Item {
            link: Link::new(1),
            object: None,
        }
    }
}

// SAFETY: the link is a field of the item.
unsafe impl Linked for Item {
    fn link(this: NonNull<Item>) -> NonNull<Link<Item>> {
        // SAFETY: `this` points at a live item.
        unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).link) }
    }
}

struct Queue {
    items: ReadyQueue<Item>,
    /// Items queued now.
    len: u64,
    /// The longest portion so far, in counter ticks.
    longest: u64,
    /// A portion began while an interrupt was pending.
    #[cfg(feature = "ktest")]
    late: bool,
}

// SAFETY: items are reached under the kernel's rules (spec 8.1): one CPU,
// interrupts masked inside the kernel.
unsafe impl Send for Queue {}

static QUEUE: Lock<Queue> = Lock::new(Queue {
    items: ReadyQueue::new(),
    len: 0,
    longest: 0,
    #[cfg(feature = "ktest")]
    late: false,
});

/// Queues `object` at the tail of `level` (1-63): its last reference just
/// went, or its teardown begins (process::end).
///
/// # Safety
/// `item` is the object's own and in no queue; the object stays alive and
/// in place, and nothing else takes it apart, until its portion.
pub unsafe fn enqueue(item: NonNull<Item>, object: Object, level: u8) {
    // SAFETY: the caller's promise.
    unsafe { push(item, object, level, false) }
}

/// Queues `object` again at the head of `level` after its portion left
/// work for the next one: the next portion at that level goes on with it,
/// as a preempted thread goes on first at its level (spec 8), so one
/// teardown ends before the next begins.
///
/// # Safety
/// As for `enqueue`.
pub unsafe fn requeue(item: NonNull<Item>, object: Object, level: u8) {
    // SAFETY: the caller's promise.
    unsafe { push(item, object, level, true) }
}

/// Moves a queued object to the head of `level`, unless it stands higher:
/// the object whose portion calls it waits for this one, right behind it
/// (the stage Children of a process, spec 7.7).
///
/// # Safety
/// `item` is the object's own, and the object is queued and alive.
pub unsafe fn raise(item: NonNull<Item>, level: u8) {
    let mut q = QUEUE.lock();
    // SAFETY: the caller's promise; the link is touched only while the
    // item is out of the queue.
    unsafe {
        let link = &raw mut (*item.as_ptr()).link;
        assert!((*link).is_queued(), "an item is raised while not queued");
        if (*link).level() <= level {
            q.items.remove(item);
            (*link).set_level(level);
            q.items.push_head(item);
        }
    }
}

/// # Safety
/// As for `enqueue`.
unsafe fn push(item: NonNull<Item>, object: Object, level: u8, head: bool) {
    let mut q = QUEUE.lock();
    // SAFETY: the caller's promise.
    unsafe {
        let i = &mut *item.as_ptr();
        i.object = Some(object);
        i.link.set_level(level);
        if head {
            q.items.push_head(item);
        } else {
            q.items.push_tail(item);
        }
    }
    q.len += 1;
}

/// The top level of the queue; None when it is empty.
pub fn top() -> Option<u8> {
    QUEUE.lock().items.top()
}

/// One portion (sched::resume): the item at the head of the top level
/// leaves the queue, and its object's portion runs; what that releases is
/// queued at the same level, and an object with work left queues itself
/// again (`requeue`). Nothing happens when the queue is empty.
pub fn portion() {
    #[cfg(feature = "ktest")]
    if crate::arch::irq_pending() {
        QUEUE.lock().late = true;
    }
    let start = timer::now();
    let taken = {
        let mut q = QUEUE.lock();
        q.items.top().map(|level| {
            let item = q.items.first(level).expect("a level with its bit set");
            // SAFETY: a queued item is alive and in this queue.
            unsafe { q.items.remove(item) };
            q.len -= 1;
            (item, level)
        })
    };
    let Some((item, level)) = taken else {
        return;
    };
    // SAFETY: the item's object stays alive until its portion, which is
    // this one; the item is not used afterwards.
    let object = unsafe { (*item.as_ptr()).object.take() }.expect("a queued object");
    // SAFETY: nothing refers to the object any more.
    unsafe {
        match object {
            Object::Process(p) => process::clean(p, level),
            Object::Thread(t) => thread::clean(t, level),
            Object::Channel(c) => channel::clean(c, level),
            Object::Session(s) => session::clean(s, level),
            Object::Timer(t) => crate::timer::clean(t, level),
            Object::Resource => unreachable!("the system resource is never queued"),
        }
    }
    let took = timer::now().saturating_sub(start);
    #[cfg(feature = "ktest")]
    crate::ktest::el0::portion_done();
    let mut q = QUEUE.lock();
    q.longest = q.longest.max(took);
}

/// Items queued now, for KSTATS (spec 16).
pub fn len() -> u64 {
    QUEUE.lock().len
}

/// The longest portion so far in counter ticks, for KSTATS.
pub fn longest() -> u64 {
    QUEUE.lock().longest
}

/// Runs portions until the queue is empty: tests that count the objects
/// in pools call it, since the queue otherwise waits for the next way out
/// of the kernel.
#[cfg(feature = "ktest")]
pub fn drain() {
    while top().is_some() {
        portion();
    }
}

/// Whether a portion began while an interrupt was pending since the last
/// call.
#[cfg(feature = "ktest")]
pub fn take_late() -> bool {
    core::mem::take(&mut QUEUE.lock().late)
}
