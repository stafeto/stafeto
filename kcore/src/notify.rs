// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Notification slots (spec 6.5) and the queues of a channel (spec 6.3).
//! Every source of notifications has its own slot from its creation on:
//! the channel's slot for label 0, a session, a timer, the exit of a
//! process. A post ORs bits into the slot and counts it, and the slot goes
//! to a thread waiting in `receive` at once or into the channel's queue of
//! slots, once. The queue of slots and the queue of waiting receivers are
//! both queues of 64 levels (`ReadyQueue`), the order of arrival within a
//! level; while a slot is queued no receiver waits. Nothing here
//! allocates, and every operation takes constant time.

use crate::sched::{self, Link, Linked, ReadyQueue, Schedulable};
use abi::Error;
use core::ptr::NonNull;

/// Bit 63, CLIENT_GONE: only the kernel posts it, into the slot of a
/// session whose last copy went (spec 5.3).
pub const BIT_CLIENT_GONE: u64 = 1 << 63;

/// The bits of `notify` from a register: INVALID_ARGS with bit 63, in any
/// slot, so that no client fakes the end of another; no bits at all are
/// fine.
pub fn bits_arg(raw: u64) -> Result<u64, Error> {
    if raw & BIT_CLIENT_GONE == 0 {
        Ok(raw)
    } else {
        Err(Error::InvalidArgs)
    }
}

/// What a post did to a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posted {
    /// The slot stood in no queue: it goes to a waiting receiver or into
    /// its channel's queue.
    First,
    /// The slot stands in its channel's queue already; the bits merged.
    Merged,
}

/// A notification slot (spec 6.5): the bits its source posted and not yet
/// received, ORed together, and how many posts they merge, saturating at
/// u32::MAX. `O` tells the kernel which source it is; the level of its
/// link is its priority, fixed when the source is created. A slot is
/// empty whenever it stands in no queue: a post puts it in or hands it to
/// a receiver, who takes it.
pub struct Slot<O> {
    link: Link<Slot<O>>,
    bits: u64,
    count: u32,
    owner: O,
}

// SAFETY: the link is a field of the slot.
unsafe impl<O> Linked for Slot<O> {
    fn link(this: NonNull<Self>) -> NonNull<Link<Self>> {
        // SAFETY: `this` points at a live slot.
        unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).link) }
    }
}

impl<O: Copy> Slot<O> {
    /// An empty slot of `priority` for the source `owner`. The priority
    /// is 1-63 and under its creator's ceiling, as the caller checked.
    pub const fn new(priority: u8, owner: O) -> Slot<O> {
        Slot {
            link: Link::new(priority),
            bits: 0,
            count: 0,
            owner,
        }
    }

    /// The priority of the notification: the level of the queue it stands
    /// in and of the boost it gives its receiver.
    pub fn priority(&self) -> u8 {
        self.link.level()
    }

    pub fn owner(&self) -> O {
        self.owner
    }

    /// Whether the slot stands in its channel's queue.
    pub fn is_queued(&self) -> bool {
        self.link.is_queued()
    }

    /// ORs `bits` in and counts one more post, saturating at u32::MAX.
    pub fn post(&mut self, bits: u64) -> Posted {
        self.bits |= bits;
        self.count = self.count.saturating_add(1);
        if self.link.is_queued() {
            Posted::Merged
        } else {
            Posted::First
        }
    }

    /// What `receive` gives: the bits and the count; the slot is empty
    /// again.
    pub fn take(&mut self) -> (u64, u32) {
        let taken = (self.bits, self.count);
        self.bits = 0;
        self.count = 0;
        taken
    }
}

/// Where a post into a channel went.
pub enum Post<T> {
    /// The slot stood in the queue already; the bits merged there.
    Merged,
    /// The slot went to the tail of its level.
    Queued,
    /// A receiver waited: the head of the top level of waiters left the
    /// queue and takes the slot now. The caller takes the slot into the
    /// thread's result (`Slot::take`), boosts it to the slot's priority
    /// (`Scheduler::boost`) and wakes it (`Scheduler::wake`).
    Deliver(NonNull<T>),
}

/// The queues of a channel (spec 6.3, 6.5): the slots with something
/// posted, by priority and in the order they came within a level, and
/// the threads waiting in `receive`, by effective priority and in the
/// order they came within a level, through the scheduler's link of each
/// (a waiting thread stands in no ready list). While a slot is queued no
/// thread waits: a post hands the slot to a waiting receiver at once, and
/// a receiver waits only when no slot is queued. Every operation takes
/// constant time; items stay in their objects, and nothing allocates.
pub struct Queue<O, T> {
    slots: ReadyQueue<Slot<O>>,
    waiters: ReadyQueue<T>,
}

impl<O: Copy, T: Schedulable> Queue<O, T> {
    pub const fn new() -> Self {
        Queue {
            slots: ReadyQueue::new(),
            waiters: ReadyQueue::new(),
        }
    }

    /// No slot is queued and no thread waits.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty() && self.waiters.is_empty()
    }

    /// A post of `bits` into `slot`, one of this channel's (spec 6.5): the
    /// bits merge into the slot; a slot that stood in no queue goes to the
    /// top waiter, or else to the tail of its level.
    ///
    /// # Safety
    /// `slot` is alive and stands in no other queue, and it stays alive
    /// and in place until it leaves this one.
    pub unsafe fn post(&mut self, slot: NonNull<Slot<O>>, bits: u64) -> Post<T> {
        // SAFETY: the caller's promise; the borrow ends here.
        if unsafe { (*slot.as_ptr()).post(bits) } == Posted::Merged {
            return Post::Merged;
        }
        match self.take_waiter() {
            Some(t) => Post::Deliver(t),
            None => {
                // SAFETY: the caller's promise; the slot is in no queue.
                unsafe { self.slots.push_tail(slot) };
                Post::Queued
            }
        }
    }

    /// `receive`: the slot it takes, the head of the top level, out of
    /// the queue; None when no slot is queued. The caller empties it
    /// (`Slot::take`).
    pub fn take_slot(&mut self) -> Option<NonNull<Slot<O>>> {
        let top = self.slots.top()?;
        let slot = self.slots.first(top).expect("a level with its bit set");
        // SAFETY: the slot is in this queue, and a queued slot is alive
        // (`post`).
        unsafe { self.slots.remove(slot) };
        Some(slot)
    }

    /// `receive` with no slot queued: `t`, which waits already
    /// (`Scheduler::block`), goes to the tail of its level.
    ///
    /// # Safety
    /// `t` is alive and in no queue, and stays alive and in place until it
    /// leaves this one.
    pub unsafe fn wait(&mut self, t: NonNull<T>) {
        assert!(
            self.slots.is_empty(),
            "a receiver waits while a slot is queued"
        );
        // SAFETY: the caller's promise.
        unsafe { self.waiters.push_tail(t) };
    }

    /// The top waiter, the head of the top level, out of the queue: the
    /// receiver a post goes to, and the next to wake with PEER_CLOSED when
    /// the channel closes (spec 6.8).
    pub fn take_waiter(&mut self) -> Option<NonNull<T>> {
        let top = self.waiters.top()?;
        let t = self.waiters.first(top).expect("a level with its bit set");
        // SAFETY: the thread is in this queue, and a waiting thread is
        // alive (`wait`).
        unsafe { self.waiters.remove(t) };
        Some(t)
    }

    /// A waiting thread leaves the queue wherever it stands: its end while
    /// it waits (sched::exit, spec 7.7).
    ///
    /// # Safety
    /// `t` is alive and waits in this queue.
    pub unsafe fn cancel(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise.
        unsafe { self.waiters.remove(t) };
    }

    /// thread_set_priority of `t`, which waits here: it moves to its new
    /// level (sched::requeue).
    ///
    /// # Safety
    /// As for `cancel`.
    pub unsafe fn requeue(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise.
        unsafe { sched::requeue(&mut self.waiters, t) };
    }
}

impl<O: Copy, T: Schedulable> Default for Queue<O, T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::Node;
    use abi::Policy;

    /// A slot that stays in place while the test runs, and its pointer.
    fn slot(priority: u8, name: char) -> (Box<Slot<char>>, NonNull<Slot<char>>) {
        let mut b = Box::new(Slot::new(priority, name));
        let p = NonNull::from(&mut *b);
        (b, p)
    }

    /// What `q` gives to `receive`, in order, each slot's name with its
    /// bits and count.
    fn received(q: &mut Queue<char, Thread>) -> Vec<(char, u64, u32)> {
        let mut got = Vec::new();
        while let Some(s) = q.take_slot() {
            // SAFETY: the tests keep their slots alive.
            let s = unsafe { &mut *s.as_ptr() };
            assert!(!s.is_queued());
            let (bits, count) = s.take();
            got.push((s.owner(), bits, count));
        }
        got
    }

    #[test]
    fn slot_merges_bits_and_counts() {
        let (mut s, _) = slot(10, 'a');
        assert_eq!((s.priority(), s.owner()), (10, 'a'));
        for bits in [0b001, 0b100, 0b001, 0] {
            assert_eq!(s.post(bits), Posted::First);
        }
        assert_eq!(s.take(), (0b101, 4));
    }

    #[test]
    fn count_saturates() {
        let (mut s, _) = slot(10, 'a');
        s.count = u32::MAX - 1;
        s.post(1);
        s.post(2);
        assert_eq!(s.take(), (0b11, u32::MAX));
    }

    #[test]
    fn take_empties_the_slot() {
        let (mut s, _) = slot(10, 'a');
        s.post(0b11);
        assert_eq!(s.take(), (0b11, 1));
        assert_eq!(s.take(), (0, 0));
        s.post(1 << 40);
        assert_eq!(s.take(), (1 << 40, 1));
    }

    #[test]
    fn bit_63_is_refused() {
        assert_eq!(BIT_CLIENT_GONE, 1 << 63);
        for raw in [BIT_CLIENT_GONE, BIT_CLIENT_GONE | 1, u64::MAX] {
            assert_eq!(bits_arg(raw), Err(Error::InvalidArgs), "{raw:#x}");
        }
        for raw in [0, 1, !BIT_CLIENT_GONE] {
            assert_eq!(bits_arg(raw), Ok(raw), "{raw:#x}");
        }
        // The kernel posts it itself when a client goes.
        let (mut s, _) = slot(10, 'a');
        s.post(BIT_CLIENT_GONE);
        assert_eq!(s.take(), (BIT_CLIENT_GONE, 1));
    }

    #[test]
    fn a_queued_slot_is_not_queued_twice() {
        let mut q = Queue::new();
        let (_a, a) = slot(10, 'a');
        // SAFETY: the test keeps its slots alive.
        unsafe {
            assert!(matches!(q.post(a, 0b01), Post::Queued));
            assert!(matches!(q.post(a, 0b10), Post::Merged));
        }
        assert_eq!(received(&mut q), [('a', 0b11, 2)]);
        // Taken, it goes into the queue again with the next post.
        // SAFETY: as above.
        assert!(matches!(unsafe { q.post(a, 0b100) }, Post::Queued));
        assert_eq!(received(&mut q), [('a', 0b100, 1)]);
        assert!(q.is_empty());
    }

    #[test]
    fn slots_of_one_level_keep_their_order() {
        let mut q = Queue::new();
        let (_a, a) = slot(30, 'a');
        let (_b, b) = slot(30, 'b');
        let (_c, c) = slot(30, 'c');
        // SAFETY: the test keeps its slots alive.
        unsafe {
            for s in [b, a, c, b] {
                q.post(s, 1);
            }
        }
        assert_eq!(received(&mut q), [('b', 1, 2), ('a', 1, 1), ('c', 1, 1)]);
    }

    #[test]
    fn higher_slot_comes_first() {
        let mut q = Queue::new();
        let (_l, l) = slot(10, 'l');
        let (_a, a) = slot(30, 'a');
        let (_b, b) = slot(30, 'b');
        // SAFETY: the test keeps its slots alive.
        unsafe {
            for s in [l, a, b] {
                q.post(s, 1);
            }
        }
        assert_eq!(received(&mut q), [('a', 1, 1), ('b', 1, 1), ('l', 1, 1)]);
    }

    /// A thread as the channel's queue sees it: only its scheduler's node.
    struct Thread {
        node: Node<Thread>,
        name: char,
    }

    // SAFETY: the node is a field of the thread.
    unsafe impl Schedulable for Thread {
        fn node(this: NonNull<Thread>) -> NonNull<Node<Thread>> {
            // SAFETY: `this` points at a live thread.
            unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).node) }
        }
    }

    #[test]
    fn a_post_goes_to_the_top_waiter_at_once() {
        // Each thread keeps its address in its box while the vector grows.
        let mut threads = Vec::new();
        let mut q = Queue::new();
        let mut wait = |name: char, level: u8, q: &mut Queue<char, Thread>| {
            threads.push(Box::new(Thread {
                node: Node::new(level, Policy::RoundRobin),
                name,
            }));
            let t = NonNull::from(&mut **threads.last_mut().expect("a thread"));
            // SAFETY: the vector keeps its threads alive; no slot is queued.
            unsafe { q.wait(t) };
            t
        };
        // A (10), B (20) and C (20) wait in `receive`, in that order.
        wait('a', 10, &mut q);
        wait('b', 20, &mut q);
        wait('c', 20, &mut q);
        assert!(!q.is_empty());
        let (_s, s) = slot(5, 's');
        // Each post goes to the top waiter at once: B, C, then A; the slot
        // never stands in the queue.
        let mut order = String::new();
        for bits in [1, 2, 4] {
            // SAFETY: the test keeps its slot and threads alive.
            let Post::Deliver(t) = (unsafe { q.post(s, bits) }) else {
                panic!("a post with a receiver waiting did not go to it");
            };
            // SAFETY: as above.
            unsafe {
                order.push(t.as_ref().name);
                assert!(!(*s.as_ptr()).is_queued());
                assert_eq!((*s.as_ptr()).take(), (bits, 1));
            }
        }
        assert_eq!(order, "bca");
        // With no one waiting it queues.
        // SAFETY: as above.
        assert!(matches!(unsafe { q.post(s, 8) }, Post::Queued));
        assert_eq!(received(&mut q), [('s', 8, 1)]);
        // A receiver that left (killed while it waited) gets nothing.
        let d = wait('d', 20, &mut q);
        wait('e', 10, &mut q);
        // SAFETY: as above; D waits in `q`.
        unsafe { q.cancel(d) };
        // SAFETY: as above.
        let Post::Deliver(t) = (unsafe { q.post(s, 16) }) else {
            panic!("a post with a receiver waiting did not go to it");
        };
        // SAFETY: as above.
        assert_eq!(unsafe { t.as_ref() }.name, 'e');
        assert!(q.is_empty());
    }

    #[test]
    #[should_panic(expected = "a receiver waits while a slot is queued")]
    fn no_receiver_waits_while_a_slot_is_queued() {
        let mut q = Queue::new();
        let (_s, s) = slot(5, 's');
        // SAFETY: the test keeps its slot alive.
        assert!(matches!(unsafe { q.post(s, 1) }, Post::Queued));
        let mut t = Box::new(Thread {
            node: Node::new(10, Policy::RoundRobin),
            name: 'a',
        });
        // SAFETY: the box keeps the thread alive; the queue refuses it.
        unsafe { q.wait(NonNull::from(&mut *t)) };
    }
}
