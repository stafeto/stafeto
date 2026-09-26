// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Notification slots (spec 6.5) and the queue of a channel (spec 6.3).
//! Every source of notifications has its own slot from its creation on:
//! the channel's slot for label 0, a session, a timer, the exit of a
//! process; and every thread has one of its own, its request while it
//! waits in `send` and its place while it waits in `receive` (spec 6.1).
//! A post ORs bits into the slot and counts it, and the slot goes to a
//! thread waiting in `receive` at once or into the channel's queue, once.
//! The queue holds slots and requests, or receivers that wait, never both:
//! a queue of 64 levels (`ReadyQueue`), the order of arrival within a
//! level. Nothing here allocates, and every operation takes constant time.

use crate::sched::{Link, Linked, ReadyQueue};
use core::ptr::NonNull;

/// What a post did to a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posted {
    /// The slot stood in no queue: it goes to a waiting receiver or into
    /// its channel's queue.
    First,
    /// The slot stands in its channel's queue already; the bits merged.
    Merged,
}

/// A slot of a channel's queue (spec 6.3, 6.5): the bits its source posted
/// and not yet received, ORed together, and how many posts they merge,
/// saturating at u32::MAX. `O` tells the kernel which source it is; the
/// level of its link is its priority, fixed when the source is created. A
/// slot is empty whenever it stands in no queue: a post puts it in or
/// hands it to a receiver, who takes it. A thread's own slot carries no
/// bits: its level is the thread's effective priority when it waits.
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

    /// A new priority, 1-63, for a slot that stands in no queue: a thread's
    /// own slot takes the thread's effective priority each time it waits.
    pub fn set_priority(&mut self, priority: u8) {
        self.link.set_level(priority);
    }

    pub fn owner(&self) -> O {
        self.owner
    }

    /// Whether the slot stands in a queue.
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
pub enum Post<O> {
    /// The slot stood in the queue already; the bits merged there.
    Merged,
    /// The slot went to the tail of its level.
    Queued,
    /// A receiver waited: its own slot, the head of the top level, left
    /// the queue, and the receiver takes the posted slot now. The caller
    /// takes the slot into the receiver's result (`Slot::take`), boosts the
    /// receiver to the slot's priority (`Scheduler::boost`) and wakes it
    /// (`Scheduler::wake`).
    Deliver(NonNull<Slot<O>>),
}

/// The queue of a channel (spec 6.3, 6.5): the slots with something posted
/// and the requests of threads waiting in `send`, by priority and in the
/// order they came within a level; or the threads waiting in `receive`,
/// through their own slots, by effective priority and in the order they
/// came. Never both: a post or a request goes to a waiting receiver at
/// once, and a receiver waits only when nothing is queued. Every operation
/// takes constant time; items stay in their objects, and nothing
/// allocates.
pub struct Queue<O> {
    items: ReadyQueue<Slot<O>>,
    /// The items are receivers that wait, not slots and requests.
    receivers: bool,
    /// The items in the queue: one more at each insert, one less at each
    /// removal (object_info CHANNEL, spec 11).
    len: u32,
}

impl<O: Copy> Queue<O> {
    pub const fn new() -> Self {
        Queue {
            items: ReadyQueue::new(),
            receivers: false,
            len: 0,
        }
    }

    /// The slots and requests queued, and the receivers that wait: one of
    /// the two is 0. O(1).
    pub fn counts(&self) -> (u32, u32) {
        if self.receivers {
            (0, self.len)
        } else {
            (self.len, 0)
        }
    }

    /// Nothing is queued and no receiver waits.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Whether receivers wait: what `send` and a post hand over at once.
    pub fn has_receivers(&self) -> bool {
        self.receivers && !self.items.is_empty()
    }

    /// The top level of what waits or is queued: the level a portion of
    /// the stage Close takes its heads from (spec 7.7); None when empty.
    pub fn top(&self) -> Option<u8> {
        self.items.top()
    }

    /// The head of the top level, left in the queue: the receiver that
    /// `send` would hand a request to, or what `receive` would take. A
    /// meeting looks at it before it makes room for the handles of the
    /// message (spec 6.1). None when empty.
    pub fn head(&self) -> Option<NonNull<Slot<O>>> {
        self.items.first(self.items.top()?)
    }

    /// A post of `bits` into `slot`, one of this channel's (spec 6.5): the
    /// bits merge into the slot; a slot that stood in no queue goes to the
    /// top waiter, or else to the tail of its level.
    ///
    /// # Safety
    /// `slot` is alive and stands in no other queue, and it stays alive
    /// and in place until it leaves this one.
    pub unsafe fn post(&mut self, slot: NonNull<Slot<O>>, bits: u64) -> Post<O> {
        // SAFETY: the caller's promise; the borrow ends here.
        if unsafe { (*slot.as_ptr()).post(bits) } == Posted::Merged {
            return Post::Merged;
        }
        match self.take_waiter() {
            Some(r) => Post::Deliver(r),
            None => {
                // SAFETY: the caller's promise; the slot is in no queue.
                unsafe { self.enqueue(slot) };
                Post::Queued
            }
        }
    }

    /// `send` (spec 6.1, 6.3): `request`, the sender's own slot at the level
    /// of its effective priority, goes to the top receiver that waits,
    /// whose slot leaves the queue: Some. Otherwise it goes to the tail of
    /// its level: None.
    ///
    /// # Safety
    /// As for `post`.
    pub unsafe fn send(&mut self, request: NonNull<Slot<O>>) -> Option<NonNull<Slot<O>>> {
        let receiver = self.take_waiter();
        if receiver.is_none() {
            // SAFETY: the caller's promise; the request is in no queue.
            unsafe { self.enqueue(request) };
        }
        receiver
    }

    /// A slot or a request goes to the tail of its level; the queue holds
    /// no receiver.
    ///
    /// # Safety
    /// As for `post`.
    unsafe fn enqueue(&mut self, item: NonNull<Slot<O>>) {
        self.receivers = false;
        self.len += 1;
        // SAFETY: the caller's promise.
        unsafe { self.items.push_tail(item) };
    }

    /// `receive`: the head of the top level, a slot or a request, out of
    /// the queue; None when nothing is queued. The caller empties a slot
    /// (`Slot::take`).
    pub fn take_slot(&mut self) -> Option<NonNull<Slot<O>>> {
        if self.receivers {
            return None;
        }
        self.take_head()
    }

    /// `receive` with nothing queued: `receiver`, the slot of a thread that
    /// waits already (`Scheduler::block`) at the level of its effective
    /// priority, goes to the tail of its level.
    ///
    /// # Safety
    /// As for `post`.
    pub unsafe fn wait(&mut self, receiver: NonNull<Slot<O>>) {
        assert!(
            self.receivers || self.items.is_empty(),
            "a receiver waits while a slot or a request is queued"
        );
        self.receivers = true;
        self.len += 1;
        // SAFETY: the caller's promise.
        unsafe { self.items.push_tail(receiver) };
    }

    /// The slot of the top waiter, the head of the top level, out of the
    /// queue: the receiver a post or a request goes to, and the next to
    /// wake with PEER_CLOSED when the channel closes (spec 6.8).
    pub fn take_waiter(&mut self) -> Option<NonNull<Slot<O>>> {
        if !self.receivers {
            return None;
        }
        self.take_head()
    }

    /// The head of the top level, out of the queue.
    fn take_head(&mut self) -> Option<NonNull<Slot<O>>> {
        let top = self.items.top()?;
        let item = self.items.first(top).expect("a level with its bit set");
        self.len -= 1;
        // SAFETY: the item is in this queue, and a queued item is alive
        // (`post`, `send`, `wait`).
        unsafe { self.items.remove(item) };
        Some(item)
    }

    /// A receiver or a request leaves the queue wherever it stands: its
    /// thread ends while it waits (sched::exit, spec 7.7).
    ///
    /// # Safety
    /// `item` is alive and stands in this queue.
    pub unsafe fn cancel(&mut self, item: NonNull<Slot<O>>) {
        self.len -= 1;
        // SAFETY: the caller's promise.
        unsafe { self.items.remove(item) };
    }

    /// thread_set_priority of the thread of `item`, which waits here: its
    /// slot moves to `level`, its new effective priority, by the rules of
    /// the ready queue (spec 6.3; ReadyQueue::move_to).
    ///
    /// # Safety
    /// As for `cancel`; `level` is 1-63.
    pub unsafe fn move_to(&mut self, item: NonNull<Slot<O>>, level: u8) {
        // SAFETY: the caller's promise.
        unsafe { self.items.move_to(item, level) };
    }
}

impl<O: Copy> Default for Queue<O> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::CLIENT_GONE;

    /// A slot that stays in place while the test runs, and its pointer.
    fn slot(priority: u8, name: char) -> (Box<Slot<char>>, NonNull<Slot<char>>) {
        let mut b = Box::new(Slot::new(priority, name));
        let p = NonNull::from(&mut *b);
        (b, p)
    }

    /// What `q` gives to `receive`, in order, each slot's name with its
    /// bits and count.
    fn received(q: &mut Queue<char>) -> Vec<(char, u64, u32)> {
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
        // The kernel posts CLIENT_GONE itself when a client goes.
        s.post(CLIENT_GONE);
        assert_eq!(s.take(), (CLIENT_GONE, 1));
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

    /// The names of what `q` gives to `receive`, in order.
    fn taken(q: &mut Queue<char>) -> String {
        let mut names = String::new();
        while let Some(s) = q.take_slot() {
            // SAFETY: the tests keep their slots alive.
            names.push(unsafe { s.as_ref() }.owner());
        }
        names
    }

    /// The name of the slot `s`, which the test keeps alive.
    fn name(s: NonNull<Slot<char>>) -> char {
        // SAFETY: the tests keep their slots alive.
        unsafe { s.as_ref() }.owner()
    }

    #[test]
    fn a_post_goes_to_the_top_waiter_at_once() {
        let mut q = Queue::new();
        // A (10), B (20) and C (20) wait in `receive`, in that order,
        // through their own slots.
        let waiters =
            [('a', 10), ('b', 20), ('c', 20), ('d', 20), ('e', 10)].map(|(n, l)| slot(l, n));
        // SAFETY: the test keeps its slots alive; nothing is queued.
        unsafe {
            for (_, w) in &waiters[..3] {
                q.wait(*w);
            }
        }
        assert!(!q.is_empty() && q.has_receivers());
        let (_s, s) = slot(5, 's');
        // Each post goes to the top waiter at once: B, C, then A; the slot
        // never stands in the queue.
        let mut order = String::new();
        for bits in [1, 2, 4] {
            // SAFETY: the test keeps its slots alive.
            let Post::Deliver(r) = (unsafe { q.post(s, bits) }) else {
                panic!("a post with a receiver waiting did not go to it");
            };
            order.push(name(r));
            // SAFETY: as above.
            unsafe {
                assert!(!(*s.as_ptr()).is_queued() && !(*r.as_ptr()).is_queued());
                assert_eq!((*s.as_ptr()).take(), (bits, 1));
            }
        }
        assert_eq!(order, "bca");
        // With no one waiting it queues.
        // SAFETY: as above.
        assert!(matches!(unsafe { q.post(s, 8) }, Post::Queued));
        assert!(!q.has_receivers());
        assert_eq!(received(&mut q), [('s', 8, 1)]);
        // A receiver that left (killed while it waited) gets nothing.
        let (d, e) = (waiters[3].1, waiters[4].1);
        // SAFETY: as above; D waits in `q`.
        unsafe {
            q.wait(d);
            q.wait(e);
            q.cancel(d);
        }
        // SAFETY: as above.
        let Post::Deliver(r) = (unsafe { q.post(s, 16) }) else {
            panic!("a post with a receiver waiting did not go to it");
        };
        assert_eq!(name(r), 'e');
        assert!(q.is_empty());
    }

    #[test]
    #[should_panic(expected = "a receiver waits while a slot or a request is queued")]
    fn no_receiver_waits_while_a_slot_is_queued() {
        let mut q = Queue::new();
        let (_s, s) = slot(5, 's');
        let (_r, r) = slot(10, 'r');
        // SAFETY: the test keeps its slots alive; the queue refuses R.
        unsafe {
            assert!(matches!(q.post(s, 1), Post::Queued));
            q.wait(r);
        }
    }

    /// The queue holds receivers or else slots and requests, and the kind
    /// turns only through an empty queue: receivers that wait take the
    /// requests that come, then requests queue, and a receiver takes them
    /// in `receive` instead of waiting; a receiver that would wait behind a
    /// queued request stops the kernel.
    #[test]
    #[should_panic(expected = "a receiver waits while a slot or a request is queued")]
    fn no_receiver_waits_while_a_request_is_queued() {
        let mut q = Queue::new();
        let [r1, r2, r3, a, b, c] = [
            ('1', 10),
            ('2', 10),
            ('3', 10),
            ('a', 20),
            ('b', 20),
            ('c', 20),
        ]
        .map(|(n, l)| slot(l, n));
        // SAFETY: the test keeps its slots alive.
        unsafe {
            q.wait(r1.1);
            assert!(q.has_receivers() && q.take_slot().is_none());
            assert_eq!(q.send(a.1).map(name), Some('1'));
            assert!(q.is_empty() && !q.has_receivers());
            assert_eq!(q.send(b.1), None);
            assert!(!q.has_receivers() && q.take_waiter().is_none());
            assert_eq!(q.take_slot().map(name), Some('b'));
            q.wait(r2.1);
            assert_eq!(q.take_waiter().map(name), Some('2'));
            assert_eq!(q.send(c.1), None);
            q.wait(r3.1);
        }
    }

    /// Spec 6.3: requests and slots share one order, by level and within a
    /// level by arrival. A slot at 30, a request at 20 and a request at 30
    /// come to `receive` as 30, 30, 20; a request comes once, with nothing
    /// merged into it.
    #[test]
    fn requests_and_slots_share_one_order() {
        let mut q = Queue::new();
        let (_s, s) = slot(30, 's');
        let (_a, a) = slot(20, 'a');
        let (_b, b) = slot(30, 'b');
        // SAFETY: the test keeps its slots alive.
        unsafe {
            assert!(matches!(q.post(s, 1), Post::Queued));
            assert_eq!(q.send(a), None);
            assert_eq!(q.send(b), None);
            assert!(matches!(q.post(s, 2), Post::Merged));
        }
        assert_eq!((q.top(), q.head().map(name)), (Some(30), Some('s')));
        assert_eq!(received(&mut q), [('s', 3, 2), ('b', 0, 0), ('a', 0, 0)]);
        assert!(q.is_empty() && q.top().is_none());
    }

    /// object_info CHANNEL (spec 11): the queue counts its slots and
    /// requests, or its receivers, as they come and go by every path: a
    /// post, a merge, a request, a receive, a wait, a delivery to a waiter,
    /// a thread that leaves and a move to another level.
    #[test]
    fn queue_counts_its_items() {
        let mut q = Queue::new();
        let [s, t, a, r1, r2, r3] = [
            ('s', 30),
            ('t', 10),
            ('a', 20),
            ('1', 10),
            ('2', 10),
            ('3', 20),
        ]
        .map(|(n, l)| slot(l, n));
        assert_eq!(q.counts(), (0, 0));
        // SAFETY: the test keeps its slots alive.
        unsafe {
            q.post(s.1, 1);
            q.post(t.1, 1);
            q.post(s.1, 2);
            assert_eq!(q.send(a.1), None);
            assert_eq!(q.counts(), (3, 0));
            q.move_to(a.1, 40);
            q.cancel(a.1);
            assert_eq!(q.counts(), (2, 0));
            assert_eq!(taken(&mut q), "st");
            assert_eq!(q.counts(), (0, 0));
            q.wait(r1.1);
            q.wait(r2.1);
            q.wait(r3.1);
            assert_eq!(q.counts(), (0, 3));
            assert!(matches!(q.post(s.1, 4), Post::Deliver(_)));
            q.cancel(r2.1);
            assert_eq!(q.counts(), (0, 1));
            assert_eq!(q.take_waiter().map(name), Some('1'));
            assert_eq!(q.counts(), (0, 0));
        }
    }

    /// A request finds the top receiver that waits and goes to it at once
    /// (spec 6.1): it never stands in the queue, and the receiver's slot
    /// leaves it. With no receiver left, the next request queues.
    #[test]
    fn a_request_goes_straight_to_a_waiting_receiver() {
        let mut q = Queue::new();
        let [low, high, a, b, c] =
            [('l', 10), ('h', 20), ('a', 5), ('b', 30), ('c', 5)].map(|(n, l)| slot(l, n));
        // SAFETY: the test keeps its slots alive.
        unsafe {
            q.wait(low.1);
            q.wait(high.1);
            assert_eq!(q.head().map(name), Some('h'));
            assert_eq!(q.send(a.1).map(name), Some('h'));
            assert!(!(*a.1.as_ptr()).is_queued() && !(*high.1.as_ptr()).is_queued());
            assert!(q.has_receivers());
            assert_eq!(q.send(b.1).map(name), Some('l'));
            assert!(q.is_empty());
            assert_eq!(q.send(c.1), None);
            assert!((*c.1.as_ptr()).is_queued() && !q.has_receivers());
        }
        assert_eq!(taken(&mut q), "c");
    }

    /// thread_set_priority of a thread that waits moves its slot by the
    /// rules of the ready queue (spec 6.3, 8): raised, to the tail of its
    /// new level; lowered, to the head; at its own level it stays.
    #[test]
    fn moved_request_follows_the_ready_rules() {
        let mut q = Queue::new();
        let [a, b, c, d] = [('a', 10), ('b', 10), ('c', 20), ('d', 20)].map(|(n, l)| slot(l, n));
        // SAFETY: the test keeps its slots alive; each request is queued.
        unsafe {
            for (_, r) in [&a, &b, &c, &d] {
                assert_eq!(q.send(*r), None);
            }
            q.move_to(a.1, 20);
            q.move_to(d.1, 10);
            q.move_to(b.1, 10);
        }
        assert_eq!(taken(&mut q), "cadb");
        // Receivers move the same way.
        // SAFETY: as above.
        unsafe {
            for (_, r) in [&a, &b, &c] {
                (*r.as_ptr()).set_priority(10);
                q.wait(*r);
            }
            q.move_to(c.1, 5);
            q.move_to(a.1, 15);
        }
        let order: String = core::iter::from_fn(|| q.take_waiter().map(name)).collect();
        assert_eq!(order, "abc");
    }

    /// The requests a service accepted wait for replies in a queue of the
    /// same kind in its process (spec 6.8), each at the level its client
    /// had: the top level is that of the top client still there, whether
    /// the others were answered or went.
    #[test]
    fn accepted_top_follows_live_clients() {
        let mut q = Queue::new();
        let mut accepted = ReadyQueue::new();
        let [a, b, c] = [('a', 10), ('b', 30), ('c', 20)].map(|(n, l)| slot(l, n));
        // SAFETY: the test keeps its slots alive; each goes into one queue
        // at a time.
        unsafe {
            for (_, r) in [&a, &b, &c] {
                assert_eq!(q.send(*r), None);
            }
            while let Some(r) = q.take_slot() {
                accepted.push_tail(r);
            }
            assert_eq!(accepted.top(), Some(30));
            // B is answered: C's level is the top.
            accepted.remove(b.1);
            assert_eq!(accepted.top(), Some(20));
            // A's client went: its place goes at once.
            accepted.remove(a.1);
            assert_eq!(accepted.top(), Some(20));
            accepted.remove(c.1);
        }
        assert_eq!(accepted.top(), None);
    }
}
