// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The scheduler's rules (spec 8), with no hardware in them: a ready list
//! for each of the 64 priority levels, a bit mask of the levels that have
//! ready threads, round robin with a quantum and FIFO by the POSIX rules,
//! the deadline the timer needs, and the checks of priorities against the
//! ceilings of processes. Every operation takes constant time. Times are
//! counter ticks; the kernel keeps one `Scheduler` and calls it at every
//! decision. The running thread is in no list (Benno scheduling). The same
//! queue of 64 levels holds the kernel's cleanup work (spec 7.7), which
//! the decision treats as one more thread: a portion runs when its level
//! is at least the running thread's and every ready one's. A thread that
//! waits in `receive` (spec 8.1) is in no ready list either: it stands in
//! the queue of what it waits for, a queue of 64 levels of its own through
//! the same link, by the same rules (`requeue`).
//!
//! A thread has a base priority, which thread_create and
//! thread_set_priority set, and a boost by the notification slot it took
//! in `receive` (spec 6.6), never above the ceiling of its process; the
//! effective priority, the higher of the two, picks its level.
//!
//! Where a thread goes; into a tail always with a new quantum, into a head
//! always with the rest of its quantum:
//!
//! | Event | Place | Quantum |
//! |---|---|---|
//! | preempted by a higher level | head of its level | keeps the rest; none left counts as the end |
//! | its quantum ended (the timer's interrupt only) | tail of its level | new |
//! | `yield` | tail of its level | new |
//! | became ready (`thread_start`, the end of a wait) | tail of its level | new |
//! | effective priority raised (base or boost) | tail of the new level | new; a running thread keeps its rest |
//! | priority unchanged | stays | kept; new when FIFO becomes round robin |
//! | effective priority lowered (base, the end of a boost) | head of the new level | keeps the rest |

use abi::{Error, PRIORITY_LEVELS, Policy};
use core::ptr::NonNull;

const LEVELS: usize = PRIORITY_LEVELS as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Created, not started yet.
    Stopped,
    /// In the list of its level.
    Ready,
    /// On the CPU, in no list.
    Running,
    /// Waits in `receive` (spec 8.1): off the CPU and in no ready list; it
    /// may stand in the queue of what it waits for.
    Waiting,
    /// Ended; it never runs again.
    Dead,
}

/// Where an item of a `ReadyQueue` stands: its level and its neighbours
/// there. The item keeps it inside itself; only the queue changes the
/// neighbours, and the level changes only while the item is in no list.
pub struct Link<T> {
    level: u8,
    queued: bool,
    prev: Option<NonNull<T>>,
    next: Option<NonNull<T>>,
}

impl<T> Link<T> {
    /// An item at `level`, in no list.
    pub const fn new(level: u8) -> Link<T> {
        Link {
            level,
            queued: false,
            prev: None,
            next: None,
        }
    }

    pub fn level(&self) -> u8 {
        self.level
    }

    /// Moves an item that is in no list to `level`.
    pub fn set_level(&mut self, level: u8) {
        assert!(!self.queued, "the level of a queued item changes");
        self.level = level;
    }

    /// Whether the item stands in a queue.
    pub fn is_queued(&self) -> bool {
        self.queued
    }
}

/// An item a `ReadyQueue` can hold.
///
/// # Safety
/// `link` returns a pointer to a `Link` inside the object `this` points
/// at, valid as long as that object lives.
pub unsafe trait Linked: Sized {
    fn link(this: NonNull<Self>) -> NonNull<Link<Self>>;
}

/// What the scheduler keeps in each thread.
pub struct Node<T> {
    policy: Policy,
    state: State,
    /// Ticks left of a round-robin quantum while the thread is ready.
    slice_left: u64,
    /// The base priority.
    base: u8,
    /// The boost by a notification slot (spec 6.6), already cut down to
    /// the ceiling of the thread's process; 0 for none.
    boost: u8,
    /// The level is the effective priority.
    link: Link<T>,
}

impl<T> Node<T> {
    /// A stopped thread's node with the base priority `priority` and no
    /// boost. The priority is checked by the caller (priority_arg,
    /// kcore::thread::check_start).
    pub const fn new(priority: u8, policy: Policy) -> Node<T> {
        Node {
            policy,
            state: State::Stopped,
            slice_left: 0,
            base: priority,
            boost: 0,
            link: Link::new(priority),
        }
    }

    /// The effective priority, which picks the thread's level.
    pub fn priority(&self) -> u8 {
        self.link.level
    }

    /// The base priority, which thread_set_priority sets.
    pub fn base(&self) -> u8 {
        self.base
    }

    /// The boost by a notification slot; 0 when there is none.
    pub fn boost(&self) -> u8 {
        self.boost
    }

    /// The level the base and the boost make. It differs from `priority`
    /// only for a waiting thread between thread_set_priority and
    /// `requeue`.
    fn effective(&self) -> u8 {
        self.base.max(self.boost)
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Ticks left of the quantum of a ready round-robin thread.
    pub fn slice_left(&self) -> u64 {
        self.slice_left
    }
}

/// A thread the scheduler can hold.
///
/// # Safety
/// `node` returns a pointer to a `Node` inside the object `this` points
/// at, valid as long as that object lives.
pub unsafe trait Schedulable: Sized {
    fn node(this: NonNull<Self>) -> NonNull<Node<Self>>;
}

// SAFETY: the link is a field of the node, which lives as long as the
// thread (Schedulable's contract).
unsafe impl<T: Schedulable> Linked for T {
    fn link(this: NonNull<T>) -> NonNull<Link<T>> {
        // SAFETY: the node is alive while `this` is.
        unsafe { NonNull::new_unchecked(&raw mut (*T::node(this).as_ptr()).link) }
    }
}

/// The node of `t`.
///
/// # Safety
/// `t` is alive, and nothing else refers to its node meanwhile.
unsafe fn node<'a, T: Schedulable>(t: NonNull<T>) -> &'a mut Node<T> {
    // SAFETY: the caller's promise and Schedulable's contract.
    unsafe { T::node(t).as_mut() }
}

/// The link of `t`.
///
/// # Safety
/// As for `node`.
unsafe fn link<'a, T: Linked>(t: NonNull<T>) -> &'a mut Link<T> {
    // SAFETY: the caller's promise and Linked's contract.
    unsafe { T::link(t).as_mut() }
}

/// Items ready at 64 levels: threads ready to run, or objects ready to be
/// taken apart (the kernel's cleanup queue). A doubly linked list for each
/// level, its links in the items, and a bit for each level with an item in
/// it. Every operation takes constant time.
pub struct ReadyQueue<T> {
    mask: u64,
    heads: [Option<NonNull<T>>; LEVELS],
    tails: [Option<NonNull<T>>; LEVELS],
}

impl<T: Linked> ReadyQueue<T> {
    pub const fn new() -> Self {
        ReadyQueue {
            mask: 0,
            heads: [None; LEVELS],
            tails: [None; LEVELS],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.mask == 0
    }

    /// The highest level with an item: 63 minus the leading zeros of the
    /// mask, one instruction (CLZ).
    pub fn top(&self) -> Option<u8> {
        if self.mask == 0 {
            None
        } else {
            Some(63 - self.mask.leading_zeros() as u8)
        }
    }

    /// The item at the head of `level`: the next to run or be worked on
    /// there.
    pub fn first(&self, level: u8) -> Option<NonNull<T>> {
        self.heads[usize::from(level)]
    }

    /// The level of `t`, checked: level 0 goes to nothing.
    ///
    /// # Safety
    /// As for `node`.
    unsafe fn level(t: NonNull<T>) -> usize {
        // SAFETY: the caller's promise.
        let level = unsafe { link(t) }.level;
        assert!(
            (1..PRIORITY_LEVELS).contains(&level),
            "an item at level {level} is queued; level 0 goes to nothing"
        );
        usize::from(level)
    }

    /// Puts `t` at the head of its level.
    ///
    /// # Safety
    /// `t` is alive and in no list, and stays alive and in place until it
    /// leaves this one.
    pub unsafe fn push_head(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise; the old head is in this list.
        unsafe {
            let level = Self::level(t);
            let old = self.heads[level];
            let l = link(t);
            assert!(!l.queued, "an item is queued twice");
            l.queued = true;
            l.prev = None;
            l.next = old;
            match old {
                Some(h) => link(h).prev = Some(t),
                None => self.tails[level] = Some(t),
            }
            self.heads[level] = Some(t);
            self.mask |= 1 << level;
        }
    }

    /// Puts `t` at the tail of its level.
    ///
    /// # Safety
    /// As for `push_head`.
    pub unsafe fn push_tail(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise; the old tail is in this list.
        unsafe {
            let level = Self::level(t);
            let old = self.tails[level];
            let l = link(t);
            assert!(!l.queued, "an item is queued twice");
            l.queued = true;
            l.next = None;
            l.prev = old;
            match old {
                Some(tail) => link(tail).next = Some(t),
                None => self.heads[level] = Some(t),
            }
            self.tails[level] = Some(t);
            self.mask |= 1 << level;
        }
    }

    /// Takes `t` out of its level, wherever it stands; an emptied level
    /// clears its bit.
    ///
    /// # Safety
    /// `t` is alive and in this queue.
    pub unsafe fn remove(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise; its neighbours are in this list.
        unsafe {
            let level = Self::level(t);
            let l = link(t);
            assert!(l.queued, "an item leaves a queue it is not in");
            l.queued = false;
            let (prev, next) = (l.prev.take(), l.next.take());
            match prev {
                Some(p) => link(p).next = next,
                None => self.heads[level] = next,
            }
            match next {
                Some(x) => link(x).prev = prev,
                None => self.tails[level] = prev,
            }
            if self.heads[level].is_none() {
                self.mask &= !(1 << level);
            }
        }
    }
}

impl<T: Linked> Default for ReadyQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// What the kernel does next, from a decision.
pub enum Decision<T> {
    /// This thread runs.
    Run(NonNull<T>),
    /// One portion of the cleanup queue's work, then a new decision.
    Clean,
    /// Nothing to do: the kernel sleeps until an interrupt.
    Idle,
}

/// The ready queue, the running thread and the end of its quantum.
///
/// Every thread handed to an `unsafe` method stays alive and in place from
/// `start` until `exit`; the scheduler keeps pointers to it meanwhile.
pub struct Scheduler<T> {
    ready: ReadyQueue<T>,
    running: Option<NonNull<T>>,
    /// Counter value at which the running thread's quantum ends; used for
    /// a round-robin thread only.
    slice_end: u64,
    quantum: u64,
}

// SAFETY: the scheduler holds pointers to threads that the kernel hands
// it, and moving it moves them along, as moving the threads would.
unsafe impl<T: Send> Send for Scheduler<T> {}

impl<T: Schedulable> Scheduler<T> {
    /// A scheduler with nothing to run and a round-robin quantum of
    /// `quantum` ticks (Clock::ns_to_ticks(abi::RR_QUANTUM_NS)).
    pub const fn new(quantum: u64) -> Self {
        Scheduler {
            ready: ReadyQueue::new(),
            running: None,
            slice_end: 0,
            quantum,
        }
    }

    /// Sets the quantum in ticks, at boot, once the counter's frequency is
    /// known and before any thread starts.
    pub fn set_quantum(&mut self, quantum: u64) {
        assert!(quantum > 0, "a round-robin quantum of 0 ticks");
        self.quantum = quantum;
    }

    pub fn ready(&self) -> &ReadyQueue<T> {
        &self.ready
    }

    /// The thread on the CPU; None while the kernel idles.
    pub fn running(&self) -> Option<NonNull<T>> {
        self.running
    }

    /// The deadline the timer needs (spec 8): the nearer of the end of the
    /// running thread's quantum, when it is round robin, and `next_timer`,
    /// the earliest timer of a program (timer::Heap::first). For a FIFO
    /// thread and while idle only `next_timer` counts.
    pub fn deadline(&self, next_timer: Option<u64>) -> Option<u64> {
        let slice = self.running.and_then(|r| {
            // SAFETY: the running thread is alive (the contract of `start`).
            let policy = unsafe { node(r) }.policy;
            (policy == Policy::RoundRobin).then_some(self.slice_end)
        });
        match (slice, next_timer) {
            (Some(s), Some(t)) => Some(s.min(t)),
            (s, t) => s.or(t),
        }
    }

    /// A stopped thread becomes ready: the tail of its level with a new
    /// quantum. It runs at the next `pick` only when its level is above the
    /// running thread's. BAD_STATE for a thread that started before.
    ///
    /// # Safety
    /// `t` is alive and stays alive and in place until `exit`.
    pub unsafe fn start(&mut self, t: NonNull<T>) -> Result<(), Error> {
        assert!(
            self.quantum > 0,
            "a thread started before the quantum was set"
        );
        // SAFETY: the caller's promise.
        unsafe {
            let n = node(t);
            if n.state != State::Stopped {
                return Err(Error::BadState);
            }
            n.state = State::Ready;
            n.slice_left = self.quantum;
            self.ready.push_tail(t);
        }
        Ok(())
    }

    /// The decision at `now`, with `cleanup` the top level of the cleanup
    /// queue (None when it is empty). The running thread goes on unless a
    /// ready thread is above its level or the cleanup is at its level or
    /// above; then it goes back to the head of its level with the rest of
    /// its quantum, so that neither eats into its quantum. Cleanup at a
    /// level no ready thread is above comes next (`Clean`), before a thread
    /// of its own level; else the head of the top level runs (`Run`), its
    /// quantum from `now`; with neither, `Idle`.
    ///
    /// # Safety
    /// Every thread the scheduler holds is alive.
    pub unsafe fn pick(&mut self, now: u64, cleanup: Option<u8>) -> Decision<T> {
        if let Some(r) = self.running {
            // SAFETY: the running thread is alive.
            let level = unsafe { node(r) }.priority();
            let above = self.ready.top().is_some_and(|top| top > level);
            if !above && cleanup.is_none_or(|c| c < level) {
                return Decision::Run(r);
            }
            // SAFETY: as above.
            unsafe { self.preempt(r, now) }
        }
        let top = self.ready.top();
        if let Some(c) = cleanup
            && top.is_none_or(|top| c >= top)
        {
            return Decision::Clean;
        }
        let Some(top) = top else {
            return Decision::Idle;
        };
        let next = self.ready.first(top).expect("a level with its bit set");
        // SAFETY: a ready thread is alive and in the queue.
        unsafe {
            self.ready.remove(next);
            let n = node(next);
            n.state = State::Running;
            self.slice_end = now.saturating_add(n.slice_left);
            // The field counts only while the thread is ready: whatever
            // puts it back gives it a quantum or the rest of this one.
            n.slice_left = 0;
        }
        self.running = Some(next);
        Decision::Run(next)
    }

    /// The running thread `r` goes back to the head of its level with the
    /// rest of its quantum; with nothing left, to the tail with a new one,
    /// as at the end of a quantum.
    ///
    /// # Safety
    /// `r` is the running thread.
    unsafe fn preempt(&mut self, r: NonNull<T>, now: u64) {
        let rest = self.slice_end.saturating_sub(now);
        // SAFETY: the caller's promise; the node's borrow ends before the
        // list takes the thread.
        unsafe {
            let n = node(r);
            let ended = n.policy == Policy::RoundRobin && rest == 0;
            n.state = State::Ready;
            n.slice_left = if ended { self.quantum } else { rest };
            if ended {
                self.ready.push_tail(r);
            } else {
                self.ready.push_head(r);
            }
        }
        self.running = None;
    }

    /// The timer's interrupt at `now`: a round-robin thread whose quantum
    /// is over goes to the tail of its level with a new quantum. Nothing
    /// else looks at the quantum, so a decision elsewhere never ends it.
    /// `pick` comes next; a thread alone at its level gets itself back.
    ///
    /// # Safety
    /// As for `pick`.
    pub unsafe fn tick(&mut self, now: u64) {
        let Some(r) = self.running else {
            return;
        };
        // SAFETY: the running thread is alive.
        unsafe {
            let n = node(r);
            if n.policy != Policy::RoundRobin || now < self.slice_end {
                return;
            }
            n.state = State::Ready;
            n.slice_left = self.quantum;
            self.ready.push_tail(r);
        }
        self.running = None;
    }

    /// `yield`: the running thread goes to the tail of its level with a new
    /// quantum, under either policy. `pick` comes next, and a thread alone
    /// at its level gets itself back: lower levels never run through
    /// `yield`.
    ///
    /// # Safety
    /// As for `pick`.
    pub unsafe fn yield_running(&mut self) {
        let Some(r) = self.running.take() else {
            return;
        };
        // SAFETY: the running thread is alive.
        unsafe {
            let n = node(r);
            n.state = State::Ready;
            n.slice_left = self.quantum;
            self.ready.push_tail(r);
        }
    }

    /// thread_set_priority, by the rules of `pthread_setschedprio`:
    /// `priority` becomes the base priority, and the effective one, the
    /// higher of the base and the boost, moves the thread. A ready thread
    /// raised goes to the tail of its new level with a new quantum, lowered
    /// to the head with the rest of its quantum, unchanged stays where it
    /// is; a boost above the new base keeps it where it is. A thread that
    /// turns from FIFO to round robin gets a new quantum, running from
    /// `now` when it runs. A running thread stays on the CPU and keeps its
    /// quantum; lowered below a ready thread, it gives the CPU up at the
    /// next `pick`. A stopped thread only takes the values; so does a
    /// waiting one, and when it stands in the queue of what it waits for,
    /// `requeue` moves it there right after. BAD_STATE for a thread that
    /// ended. `priority` is 1-63, as priority_arg checks.
    ///
    /// # Safety
    /// `t` is alive; the scheduler's threads are alive.
    pub unsafe fn set_priority(
        &mut self,
        t: NonNull<T>,
        priority: u8,
        policy: Policy,
        now: u64,
    ) -> Result<(), Error> {
        assert!((1..PRIORITY_LEVELS).contains(&priority));
        // SAFETY: the caller's promise.
        let (state, to_round_robin) = unsafe {
            let n = node(t);
            (
                n.state,
                n.policy == Policy::Fifo && policy == Policy::RoundRobin,
            )
        };
        match state {
            State::Dead => return Err(Error::BadState),
            // SAFETY: the caller's promise.
            State::Ready if to_round_robin => unsafe { node(t) }.slice_left = self.quantum,
            State::Running if to_round_robin => {
                self.slice_end = now.saturating_add(self.quantum);
            }
            _ => {}
        }
        // SAFETY: the caller's promise; the borrow ends before the move.
        let level = unsafe {
            let n = node(t);
            n.policy = policy;
            n.base = priority;
            n.effective()
        };
        // SAFETY: the caller's promise.
        unsafe { self.relevel(t, level) };
        Ok(())
    }

    /// `receive` hands `t` a notification slot of `level` (spec 6.6): the
    /// effective priority becomes the higher of the base and `level`, but
    /// never above `ceiling`, the priority ceiling of the thread's process
    /// (spec 8). A boost only raises: one below the thread's boost leaves
    /// it as it is. The thread moves as a raised one: running, it keeps
    /// the CPU and its quantum; ready, it goes to the tail of its new level
    /// with a new quantum; waiting and out of every queue, it takes the
    /// level, and `wake` puts it there.
    ///
    /// # Safety
    /// As for `set_priority`; a waiting `t` stands in no queue.
    pub unsafe fn boost(&mut self, t: NonNull<T>, level: u8, ceiling: u8) {
        // SAFETY: the caller's promise; the borrow ends before the move.
        let level = unsafe {
            let n = node(t);
            n.boost = n.boost.max(level.min(ceiling));
            n.effective()
        };
        // SAFETY: the caller's promise.
        unsafe { self.relevel(t, level) };
    }

    /// The boost ends (the thread's next `receive`): the effective priority
    /// falls back to the base. A running thread keeps the CPU and its
    /// quantum and gives the CPU up at the next `pick` to a ready thread
    /// above its base; a ready one goes to the head of its base's level
    /// with the rest of its quantum.
    ///
    /// # Safety
    /// As for `boost`.
    pub unsafe fn unboost(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise; the borrow ends before the move.
        let level = unsafe {
            let n = node(t);
            n.boost = 0;
            n.effective()
        };
        // SAFETY: the caller's promise.
        unsafe { self.relevel(t, level) };
    }

    /// Moves `t` to `level` by the rules of the table above; only a ready
    /// thread changes its list and quantum. A waiting thread that stands
    /// in a queue keeps its level until the caller's `requeue`.
    ///
    /// # Safety
    /// As for `set_priority`.
    unsafe fn relevel(&mut self, t: NonNull<T>, level: u8) {
        // SAFETY: the caller's promise; every borrow of the node ends
        // before a list takes the thread.
        unsafe {
            let (state, old, queued) = {
                let n = node(t);
                (n.state, n.link.level, n.link.queued)
            };
            if level == old {
                return;
            }
            match state {
                State::Ready => {
                    self.ready.remove(t);
                    node(t).link.set_level(level);
                    if level > old {
                        node(t).slice_left = self.quantum;
                        self.ready.push_tail(t);
                    } else {
                        self.ready.push_head(t);
                    }
                }
                State::Waiting if queued => {}
                _ => node(t).link.set_level(level),
            }
        }
    }

    /// `receive` with nothing to take (spec 8.1): the running thread waits.
    /// It leaves the CPU for no list; the caller puts it in the queue it
    /// waits in. Nothing runs until `pick`. The rest of its quantum is
    /// gone: the end of the wait gives it a new one.
    ///
    /// # Safety
    /// As for `pick`.
    pub unsafe fn block(&mut self) -> NonNull<T> {
        let r = self.running.take().expect("no thread runs to wait");
        // SAFETY: the running thread is alive.
        unsafe { node(r) }.state = State::Waiting;
        r
    }

    /// The end of a wait (spec 8): `t`, out of the queue it waited in,
    /// becomes ready at the tail of its level with a new quantum. It runs
    /// at the next `pick` only when its level is above the running
    /// thread's.
    ///
    /// # Safety
    /// `t` is alive and in no queue; the scheduler's threads are alive.
    pub unsafe fn wake(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise; the borrow ends before the list
        // takes the thread.
        unsafe {
            let n = node(t);
            assert!(
                n.state == State::Waiting,
                "a thread that does not wait wakes"
            );
            assert!(
                n.link.level == n.effective(),
                "a thread wakes at a stale level"
            );
            n.state = State::Ready;
            n.slice_left = self.quantum;
            self.ready.push_tail(t);
        }
    }

    /// The thread ends (thread_exit, process_kill, a fault, the stop
    /// wave), whatever its state: it leaves its list and never runs again.
    /// When it was the running one, nothing runs until `pick`. A waiting
    /// thread leaves the queue it waited in first (the caller's).
    ///
    /// # Safety
    /// `t` is alive; after this the scheduler no longer refers to it.
    pub unsafe fn exit(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise.
        let (state, queued) = unsafe {
            let n = node(t);
            (n.state, n.link.queued)
        };
        match state {
            State::Running => {
                assert!(
                    self.running == Some(t),
                    "a running thread is not the running one"
                );
                self.running = None;
            }
            // SAFETY: a ready thread is in the queue.
            State::Ready => unsafe { self.ready.remove(t) },
            State::Waiting => assert!(!queued, "a waiting thread ends in a queue"),
            State::Stopped | State::Dead => {}
        }
        // SAFETY: the caller's promise.
        unsafe { node(t) }.state = State::Dead;
    }
}

/// thread_set_priority of `t`, which waits in `queue` (spec 6.3, 8): it
/// moves to the level its base and boost make, by the rules of the ready
/// queue. Raised, it goes to the tail of its new level; lowered, to the
/// head; unchanged, it stays.
///
/// # Safety
/// `t` is alive, waits, and stands in `queue`.
pub unsafe fn requeue<T: Schedulable>(queue: &mut ReadyQueue<T>, t: NonNull<T>) {
    // SAFETY: the caller's promise; every borrow of the node ends before
    // the queue takes the thread.
    unsafe {
        let (state, old, level) = {
            let n = node(t);
            (n.state, n.link.level, n.effective())
        };
        assert!(
            state == State::Waiting,
            "a thread that does not wait moves in a queue of waiters"
        );
        if level == old {
            return;
        }
        queue.remove(t);
        node(t).link.set_level(level);
        if level > old {
            queue.push_tail(t);
        } else {
            queue.push_head(t);
        }
    }
}

/// A one-shot timer, as the scheduler sees it: the virtual timer's
/// CNTV_CVAL_EL0 and CNTV_CTL_EL0 in the kernel, a fake in tests.
pub trait Timer {
    /// Fires once the counter reaches `deadline`.
    fn arm(&mut self, deadline: u64);
    fn disarm(&mut self);
}

/// The deadline the timer holds, so that the kernel writes the timer only
/// when the deadline changes: a return to the same thread writes nothing.
/// The kernel arms and disarms the timer through `set`; only the timer's
/// interrupt handler turns it off directly, since the line must drop before
/// the EOI whatever this remembers, and then starts over with `new`.
pub struct Armed {
    deadline: Option<u64>,
}

impl Armed {
    /// The timer is off, as after boot.
    pub const fn new() -> Armed {
        Armed { deadline: None }
    }

    pub fn get(&self) -> Option<u64> {
        self.deadline
    }

    /// Arms `timer` for `deadline`, or disarms it for None, unless it holds
    /// that already.
    pub fn set(&mut self, timer: &mut impl Timer, deadline: Option<u64>) {
        if deadline == self.deadline {
            return;
        }
        match deadline {
            Some(d) => timer.arm(d),
            None => timer.disarm(),
        }
        self.deadline = deadline;
    }
}

impl Default for Armed {
    fn default() -> Self {
        Self::new()
    }
}

/// A priority from a register, as `thread_create` and
/// `thread_set_priority` take it: 1-63. INVALID_ARGS for 0, 64 and up, and
/// bits set above the byte.
pub fn priority_arg(raw: u64) -> Result<u8, Error> {
    match u8::try_from(raw) {
        Ok(p) if (1..PRIORITY_LEVELS).contains(&p) => Ok(p),
        _ => Err(Error::InvalidArgs),
    }
}

/// A policy from a register: INVALID_ARGS for a value abi::Policy lacks.
pub fn policy_arg(raw: u64) -> Result<Policy, Error> {
    Policy::from_raw(raw).ok_or(Error::InvalidArgs)
}

/// The priority of a source's slot (spec 6.5) from a register: in
/// `process_create` 0 exactly when there is no exit channel, in
/// `handle_duplicate` exactly when there is no new label (`channel` false),
/// otherwise a priority. INVALID_ARGS for anything else.
pub fn notify_priority_arg(raw: u64, channel: bool) -> Result<u8, Error> {
    match (channel, raw) {
        (false, 0) => Ok(0),
        (true, _) => priority_arg(raw),
        (false, _) => Err(Error::InvalidArgs),
    }
}

/// ACCESS_DENIED when `priority` is above any of `ceilings` (spec 8):
/// for `thread_create` and `thread_set_priority` the ceilings of the
/// thread's process and of the caller's, for the ceiling of a child and a
/// notification priority the caller's. A priority is authority too: a
/// handle to another process's thread does not lift the thread above the
/// caller's own ceiling.
pub fn under_ceilings(priority: u8, ceilings: &[u8]) -> Result<(), Error> {
    if ceilings.iter().all(|&c| priority <= c) {
        Ok(())
    } else {
        Err(Error::AccessDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::Lock;
    use crate::time::Clock;
    use abi::RR_QUANTUM_NS;

    /// Counter ticks per millisecond at QEMU's 62.5 MHz.
    const MS: u64 = 62_500;
    /// The quantum in ticks: 4 ms.
    const Q: u64 = 4 * MS;
    const RR: Policy = Policy::RoundRobin;
    const FIFO: Policy = Policy::Fifo;

    struct Fake {
        node: Node<Fake>,
        name: char,
    }

    // SAFETY: the node is a field of the fake thread.
    unsafe impl Schedulable for Fake {
        fn node(this: NonNull<Fake>) -> NonNull<Node<Fake>> {
            // SAFETY: `this` points at a live fake thread.
            unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).node) }
        }
    }

    /// Fake threads that stay in place while the test runs, and the
    /// scheduler under test.
    struct World {
        #[expect(
            clippy::vec_box,
            reason = "each fake thread keeps its address while the vector grows"
        )]
        threads: Vec<Box<Fake>>,
        s: Scheduler<Fake>,
    }

    impl World {
        fn new() -> World {
            World {
                threads: Vec::new(),
                s: Scheduler::new(Q),
            }
        }

        /// A stopped thread named `name`.
        fn thread(&mut self, name: char, priority: u8, policy: Policy) -> NonNull<Fake> {
            let mut b = Box::new(Fake {
                node: Node::new(priority, policy),
                name,
            });
            let t = NonNull::from(&mut *b);
            self.threads.push(b);
            t
        }

        /// A thread that is ready at once.
        fn started(&mut self, name: char, priority: u8, policy: Policy) -> NonNull<Fake> {
            let t = self.thread(name, priority, policy);
            self.start(t);
            t
        }

        fn start(&mut self, t: NonNull<Fake>) {
            // SAFETY: the world keeps its threads alive.
            unsafe { self.s.start(t) }.unwrap();
        }

        /// The name of the thread `pick` chooses at `now` with an empty
        /// cleanup queue, '-' for idle.
        fn pick(&mut self, now: u64) -> char {
            self.decide(now, None)
        }

        /// The decision at `now` with the cleanup queue's top level
        /// `cleanup`: the name of the thread that runs, '*' for a portion
        /// of cleanup, '-' for idle.
        fn decide(&mut self, now: u64, cleanup: Option<u8>) -> char {
            // SAFETY: as above.
            match unsafe { self.s.pick(now, cleanup) } {
                Decision::Run(t) => name(t),
                Decision::Clean => '*',
                Decision::Idle => '-',
            }
        }

        /// The timer's interrupt at `now`, then a decision.
        fn tick(&mut self, now: u64) -> char {
            // SAFETY: as above.
            unsafe { self.s.tick(now) };
            self.pick(now)
        }

        fn yield_at(&mut self, now: u64) -> char {
            // SAFETY: as above.
            unsafe { self.s.yield_running() };
            self.pick(now)
        }

        fn set(&mut self, t: NonNull<Fake>, priority: u8, policy: Policy, now: u64) {
            // SAFETY: as above.
            unsafe { self.s.set_priority(t, priority, policy, now) }.unwrap();
        }

        fn exit(&mut self, t: NonNull<Fake>) {
            // SAFETY: as above.
            unsafe { self.s.exit(t) };
        }

        /// The running thread waits, as in `receive` with nothing to take.
        fn block(&mut self) -> NonNull<Fake> {
            // SAFETY: as above.
            unsafe { self.s.block() }
        }

        fn wake(&mut self, t: NonNull<Fake>) {
            // SAFETY: as above; the tests wake threads that are in no queue.
            unsafe { self.s.wake(t) };
        }

        fn boost(&mut self, t: NonNull<Fake>, level: u8, ceiling: u8) {
            // SAFETY: as above.
            unsafe { self.s.boost(t, level, ceiling) };
        }

        fn unboost(&mut self, t: NonNull<Fake>) {
            // SAFETY: as above.
            unsafe { self.s.unboost(t) };
        }

        /// The names on `level` of the ready queue, head first.
        fn level(&self, level: u8) -> String {
            queued(self.s.ready(), level)
        }
    }

    /// The names on `level` of `q`, head first.
    fn queued(q: &ReadyQueue<Fake>, level: u8) -> String {
        let mut names = String::new();
        let mut t = q.first(level);
        while let Some(next) = t {
            names.push(name(next));
            t = node(next).link.next;
        }
        names
    }

    fn name(t: NonNull<Fake>) -> char {
        // SAFETY: the world keeps its threads alive.
        unsafe { t.as_ref() }.name
    }

    fn node(t: NonNull<Fake>) -> &'static Node<Fake> {
        // SAFETY: as above; the tests only read through it.
        unsafe { Fake::node(t).as_ref() }
    }

    // SAFETY: the tests touch fake threads from one thread at a time.
    unsafe impl Send for Fake {}

    /// The kernel keeps its scheduler in a static behind a lock and sets the
    /// quantum once it knows the counter's frequency.
    #[test]
    fn a_scheduler_fits_a_static_lock() {
        static SCHED: Lock<Scheduler<Fake>> = Lock::new(Scheduler::new(0));
        let mut s = SCHED.lock();
        s.set_quantum(Q);
        let mut a = Box::new(Fake {
            node: Node::new(10, RR),
            name: 'a',
        });
        let t = NonNull::from(&mut *a);
        // SAFETY: the thread outlives its time in the scheduler.
        unsafe {
            s.start(t).unwrap();
            assert!(matches!(s.pick(MS, None), Decision::Run(r) if r == t));
            assert_eq!(s.deadline(None), Some(5 * MS));
            s.exit(t);
        }
    }

    #[test]
    fn the_quantum_is_4_ms_of_counter_ticks() {
        let qemu = Clock::new(62_500_000).unwrap();
        assert_eq!(qemu.ns_to_ticks(RR_QUANTUM_NS), Q);
        assert_eq!(qemu.ns_to_ticks(RR_QUANTUM_NS), 250_000);
        let a64 = Clock::new(24_000_000).unwrap();
        assert_eq!(a64.ns_to_ticks(RR_QUANTUM_NS), 96_000);
    }

    /// Runs the ready threads to the end, highest first: the name of each
    /// in the order they ran.
    fn drain(w: &mut World) -> String {
        let mut order = String::new();
        while let Some(t) = w.s.running() {
            order.push(name(t));
            w.exit(t);
            w.pick(0);
        }
        order
    }

    #[test]
    fn ready_queue_picks_highest_level_first() {
        let mut w = World::new();
        assert_eq!(w.s.ready().top(), None);
        for (name, level) in [('a', 1), ('b', 30), ('c', 63), ('d', 5), ('e', 30)] {
            w.started(name, level, FIFO);
        }
        assert_eq!(w.s.ready().top(), Some(63));
        assert_eq!(w.pick(0), 'c');
        assert_eq!(w.s.ready().top(), Some(30));
        assert_eq!(drain(&mut w), "cbeda");
        assert_eq!(w.s.ready().top(), None);
        assert!(w.s.ready().is_empty());
        assert_eq!(w.pick(0), '-');
    }

    #[test]
    fn every_level_from_1_to_63_has_its_bit() {
        let mut w = World::new();
        // 37 and 63 are coprime: every level once, in a scrambled order.
        for i in 0..63u32 {
            let level = (i * 37 % 63 + 1) as u8;
            w.started(
                char::from_u32(0x100 + u32::from(level)).unwrap(),
                level,
                FIFO,
            );
        }
        assert_eq!(w.s.ready().top(), Some(63));
        w.pick(0);
        let levels: Vec<u32> = drain(&mut w).chars().map(|c| c as u32 - 0x100).collect();
        assert_eq!(levels, (1..=63).rev().collect::<Vec<u32>>());
    }

    #[test]
    fn a_level_empties_its_bit() {
        let mut w = World::new();
        let a = w.started('a', 40, FIFO);
        let b = w.started('b', 7, FIFO);
        assert_eq!(w.s.ready().top(), Some(40));
        w.exit(a);
        assert_eq!(w.s.ready().top(), Some(7));
        w.exit(b);
        assert_eq!(w.s.ready().top(), None);
        assert_eq!(w.level(40), "");
        assert_eq!(w.level(7), "");
    }

    #[test]
    #[should_panic(expected = "level 0")]
    fn level_0_is_never_queued() {
        let mut w = World::new();
        w.started('a', 0, FIFO);
    }

    #[test]
    fn ready_queue_head_tail_and_remove() {
        let mut w = World::new();
        let a = w.started('a', 10, RR);
        let b = w.started('b', 10, RR);
        let c = w.started('c', 10, RR);
        assert_eq!(w.level(10), "abc");
        // Taking the middle one out links its neighbours.
        w.exit(b);
        assert_eq!(w.level(10), "ac");
        // A preempted thread goes to the head.
        assert_eq!(w.pick(0), 'a');
        w.started('h', 20, FIFO);
        assert_eq!(w.pick(MS), 'h');
        assert_eq!(w.level(10), "ac");
        w.exit(c);
        assert_eq!(w.level(10), "a");
        w.exit(a);
        assert_eq!(w.level(10), "");
        assert_eq!(w.s.ready().top(), None);
    }

    #[test]
    fn preempted_thread_keeps_its_place_and_the_rest_of_its_quantum() {
        let mut w = World::new();
        let a = w.started('a', 10, RR);
        w.started('b', 10, RR);
        assert_eq!(w.pick(0), 'a');
        assert_eq!(w.s.deadline(None), Some(4 * MS));
        // At 1 ms a higher thread starts and runs for 2 ms.
        let h = w.started('h', 20, RR);
        assert_eq!(w.pick(MS), 'h');
        assert_eq!(w.level(10), "ab");
        assert_eq!(node(a).slice_left(), 3 * MS);
        w.exit(h);
        // A goes on before B, with the 3 ms it had left.
        assert_eq!(w.pick(3 * MS), 'a');
        assert_eq!(w.s.deadline(None), Some(6 * MS));
        assert_eq!(w.tick(6 * MS), 'b');
        assert_eq!(w.s.deadline(None), Some(10 * MS));
    }

    #[test]
    fn preempted_at_the_end_of_its_quantum_goes_to_the_tail() {
        let mut w = World::new();
        let a = w.started('a', 10, RR);
        w.started('b', 10, RR);
        assert_eq!(w.pick(0), 'a');
        // The quantum is over, and the timer's interrupt has not come yet.
        w.started('h', 20, FIFO);
        assert_eq!(w.pick(4 * MS + 7), 'h');
        assert_eq!(w.level(10), "ba");
        assert_eq!(node(a).slice_left(), Q);
    }

    #[test]
    fn two_round_robin_threads_switch_every_quantum() {
        let mut w = World::new();
        w.started('a', 10, RR);
        w.started('b', 10, RR);
        let mut now = 0;
        let mut trace = vec![(now, w.pick(now))];
        for _ in 0..4 {
            now = w.s.deadline(None).expect("a round-robin thread runs");
            trace.push((now, w.tick(now)));
        }
        assert_eq!(
            trace,
            [
                (0, 'a'),
                (4 * MS, 'b'),
                (8 * MS, 'a'),
                (12 * MS, 'b'),
                (16 * MS, 'a')
            ]
        );
    }

    #[test]
    fn late_timer_starts_the_next_quantum_when_it_comes() {
        let mut w = World::new();
        w.started('a', 10, RR);
        w.started('b', 10, RR);
        assert_eq!(w.pick(0), 'a');
        // The interrupt comes 1 ms late: B's quantum runs from then.
        assert_eq!(w.tick(5 * MS), 'b');
        assert_eq!(w.s.deadline(None), Some(9 * MS));
    }

    #[test]
    fn early_timer_changes_nothing() {
        let mut w = World::new();
        w.started('a', 10, RR);
        w.started('b', 10, RR);
        assert_eq!(w.pick(0), 'a');
        assert_eq!(w.tick(4 * MS - 1), 'a');
        assert_eq!(w.s.deadline(None), Some(4 * MS));
        assert_eq!(w.level(10), "b");
    }

    #[test]
    fn lone_round_robin_thread_gets_a_new_quantum_without_a_switch() {
        let mut w = World::new();
        let a = w.started('a', 10, RR);
        w.started('l', 5, RR);
        assert_eq!(w.pick(0), 'a');
        assert_eq!(w.tick(4 * MS), 'a');
        assert_eq!(w.s.running(), Some(a));
        assert_eq!(w.s.deadline(None), Some(8 * MS));
        assert_eq!(w.tick(8 * MS), 'a');
        assert_eq!(w.s.deadline(None), Some(12 * MS));
    }

    #[test]
    fn fifo_threads_switch_only_on_yield() {
        let mut w = World::new();
        w.started('a', 10, FIFO);
        w.started('b', 10, FIFO);
        assert_eq!(w.pick(0), 'a');
        assert_eq!(w.s.deadline(None), None);
        for now in [4 * MS, 100 * MS, 1000 * MS] {
            assert_eq!(w.tick(now), 'a');
        }
        assert_eq!(w.yield_at(1001 * MS), 'b');
        assert_eq!(w.tick(2000 * MS), 'b');
        assert_eq!(w.yield_at(2001 * MS), 'a');
    }

    #[test]
    fn yield_goes_to_the_tail_with_a_new_quantum() {
        let mut w = World::new();
        let a = w.started('a', 10, RR);
        w.started('b', 10, RR);
        w.started('c', 10, RR);
        assert_eq!(w.pick(0), 'a');
        assert_eq!(w.yield_at(MS), 'b');
        assert_eq!(w.level(10), "ca");
        assert_eq!(node(a).slice_left(), Q);
        assert_eq!(w.s.deadline(None), Some(5 * MS));
    }

    #[test]
    fn yield_of_a_lone_thread_returns_to_it_and_never_to_lower_levels() {
        let mut w = World::new();
        let x = w.started('x', 20, RR);
        w.started('l', 5, RR);
        assert_eq!(w.pick(0), 'x');
        assert_eq!(w.yield_at(MS), 'x');
        assert_eq!(w.s.deadline(None), Some(5 * MS));
        w.set(x, 20, FIFO, 2 * MS);
        assert_eq!(w.yield_at(3 * MS), 'x');
        assert_eq!(w.level(5), "l");
    }

    #[test]
    fn set_priority_follows_setschedprio() {
        let mut w = World::new();
        let r = w.started('r', 30, RR);
        let x = w.started('x', 10, RR);
        let a = w.started('a', 10, FIFO);
        let y = w.started('y', 10, RR);
        w.started('d', 20, RR);
        w.started('e', 5, RR);
        assert_eq!(w.pick(0), 'r');
        // Unchanged: the thread keeps its place; from FIFO to round robin
        // it gets a new quantum.
        w.set(a, 10, RR, MS);
        assert_eq!(w.level(10), "xay");
        assert_eq!(node(a).slice_left(), Q);
        // Raised: the tail of the new level, a new quantum.
        w.set(x, 20, RR, MS);
        assert_eq!(w.level(20), "dx");
        assert_eq!(w.level(10), "ay");
        assert_eq!(node(x).slice_left(), Q);
        // Lowered: the head of the new level with the rest it had.
        w.set(y, 5, RR, MS);
        assert_eq!(w.level(5), "ye");
        assert_eq!(w.level(10), "a");
        // None of them is above the running thread.
        assert_eq!(w.pick(MS), 'r');
        // The running thread raised keeps its quantum.
        w.set(r, 40, RR, 2 * MS);
        assert_eq!(w.s.deadline(None), Some(4 * MS));
        assert_eq!(w.pick(2 * MS), 'r');
        // Lowered below a ready thread: it is preempted with its rest and
        // waits at the head of its new level.
        w.set(r, 20, RR, 3 * MS);
        assert_eq!(w.pick(3 * MS), 'r');
        w.set(r, 15, RR, 3 * MS);
        assert_eq!(w.pick(3 * MS), 'd');
        assert_eq!(w.level(15), "r");
        assert_eq!(node(r).slice_left(), MS);
    }

    #[test]
    fn raising_a_ready_thread_above_the_running_one_preempts_it() {
        let mut w = World::new();
        let r = w.started('r', 10, RR);
        let b = w.started('b', 5, RR);
        assert_eq!(w.pick(0), 'r');
        w.set(b, 11, RR, MS);
        assert_eq!(w.pick(MS), 'b');
        assert_eq!(w.level(10), "r");
        assert_eq!(node(r).slice_left(), 3 * MS);
    }

    /// A thread preempted in the middle of its quantum: a FIFO thread above
    /// takes the CPU `used` ticks after `from` and ends at once.
    fn preempt_after(w: &mut World, from: u64, used: u64) {
        let h = w.started('h', 60, FIFO);
        assert_eq!(w.pick(from + used), 'h');
        w.exit(h);
    }

    #[test]
    fn tail_gives_a_whole_quantum_after_a_partly_used_one() {
        let mut w = World::new();
        let a = w.started('a', 10, RR);
        w.started('b', 10, RR);
        assert_eq!(w.pick(0), 'a');
        preempt_after(&mut w, 0, MS);
        assert_eq!(node(a).slice_left(), 3 * MS);
        assert_eq!(w.pick(3 * MS), 'a');
        // The end of the quantum: a whole new one, not the old rest.
        assert_eq!(w.tick(6 * MS), 'b');
        assert_eq!(node(a).slice_left(), Q);
        assert_eq!(w.tick(10 * MS), 'a');
        assert_eq!(w.s.deadline(None), Some(14 * MS));
        // yield after a preemption: a whole new quantum as well.
        preempt_after(&mut w, 10 * MS, MS);
        assert_eq!(w.pick(12 * MS), 'a');
        assert_eq!(w.yield_at(13 * MS), 'b');
        assert_eq!(node(a).slice_left(), Q);
    }

    #[test]
    fn set_priority_of_a_partly_used_quantum() {
        for (to, want_left) in [(20, Q), (5, 3 * MS)] {
            let mut w = World::new();
            let b = w.started('b', 10, RR);
            w.started('c', 10, RR);
            assert_eq!(w.pick(0), 'b');
            let h = w.started('h', 60, FIFO);
            assert_eq!(w.pick(MS), 'h');
            assert_eq!(node(b).slice_left(), 3 * MS);
            // Raised: the tail with a new quantum; lowered: the head with the rest.
            w.set(b, to, RR, 2 * MS);
            assert_eq!(w.level(to), "b");
            assert_eq!(node(b).slice_left(), want_left, "to level {to}");
            w.exit(h);
        }
    }

    #[test]
    fn running_thread_changing_policy() {
        let mut w = World::new();
        let r = w.started('r', 10, FIFO);
        assert_eq!(w.pick(0), 'r');
        assert_eq!(w.s.deadline(None), None);
        // To round robin: a quantum from now.
        w.set(r, 10, RR, 3 * MS);
        assert_eq!(w.s.deadline(None), Some(7 * MS));
        // Back to FIFO: no deadline.
        w.set(r, 10, FIFO, 4 * MS);
        assert_eq!(w.s.deadline(None), None);
    }

    #[test]
    fn stopped_and_dead_threads_and_set_priority() {
        let mut w = World::new();
        let s = w.thread('s', 10, RR);
        w.started('k', 12, RR);
        w.set(s, 14, FIFO, 0);
        assert_eq!(w.level(14), "");
        assert_eq!(node(s).state(), State::Stopped);
        w.start(s);
        assert_eq!(w.level(14), "s");
        assert_eq!(node(s).policy(), FIFO);
        w.exit(s);
        // SAFETY: the world keeps its threads alive.
        let dead = unsafe { w.s.set_priority(s, 20, RR, 0) };
        assert_eq!(dead, Err(Error::BadState));
    }

    #[test]
    fn start_of_an_equal_thread_does_not_switch() {
        let mut w = World::new();
        let a = w.started('a', 10, RR);
        assert_eq!(w.pick(0), 'a');
        let b = w.thread('b', 10, RR);
        w.start(b);
        assert_eq!(w.pick(4 * MS - 1), 'a');
        assert_eq!(w.s.deadline(None), Some(4 * MS));
        // Even past the end of the quantum, only the timer ends it.
        assert_eq!(w.pick(5 * MS), 'a');
        assert_eq!(w.tick(5 * MS), 'b');
        // A higher thread runs at once.
        let h = w.thread('h', 11, FIFO);
        w.start(h);
        assert_eq!(w.pick(5 * MS), 'h');
        // A thread starts once.
        for t in [a, b, h] {
            // SAFETY: the world keeps its threads alive.
            assert_eq!(unsafe { w.s.start(t) }, Err(Error::BadState));
        }
    }

    #[test]
    fn exit_takes_a_thread_out_of_every_state() {
        let mut w = World::new();
        let running = w.started('r', 30, RR);
        let ready = w.started('q', 20, RR);
        let stopped = w.thread('s', 20, RR);
        assert_eq!(w.pick(0), 'r');
        w.exit(ready);
        w.exit(stopped);
        w.exit(running);
        assert_eq!(w.s.running(), None);
        for t in [running, ready, stopped] {
            assert_eq!(node(t).state(), State::Dead);
            // A second exit changes nothing.
            w.exit(t);
        }
        assert_eq!(w.pick(MS), '-');
        assert_eq!(w.s.deadline(None), None);
        // SAFETY: the world keeps its threads alive.
        assert_eq!(unsafe { w.s.start(stopped) }, Err(Error::BadState));
    }

    #[test]
    fn waiting_thread_leaves_the_cpu() {
        let mut w = World::new();
        let a = w.started('a', 20, RR);
        let b = w.started('b', 10, RR);
        assert_eq!(w.pick(0), 'a');
        assert_eq!(w.block(), a);
        assert_eq!(node(a).state(), State::Waiting);
        assert_eq!((w.s.running(), w.s.deadline(None)), (None, None));
        assert!(!node(a).link.is_queued() && w.level(20).is_empty());
        // Nothing of A's level is left: a lower thread runs.
        assert_eq!(w.pick(MS), 'b');
        assert_eq!(w.block(), b);
        assert_eq!(w.pick(2 * MS), '-');
    }

    #[test]
    fn woken_thread_goes_to_the_tail_with_a_new_quantum() {
        let mut w = World::new();
        let a = w.started('a', 10, RR);
        w.started('b', 10, RR);
        w.started('c', 10, RR);
        assert_eq!(w.pick(0), 'a');
        // A waits 1 ms into its quantum; B runs from then.
        w.block();
        assert_eq!(w.pick(MS), 'b');
        // Woken at 2 ms: behind C, with a whole quantum; B goes on.
        w.wake(a);
        assert_eq!(node(a).state(), State::Ready);
        assert_eq!(w.level(10), "ca");
        assert_eq!(node(a).slice_left(), Q);
        assert_eq!(w.pick(2 * MS), 'b');
        assert_eq!(w.s.deadline(None), Some(5 * MS));
        assert_eq!(w.tick(5 * MS), 'c');
        assert_eq!(w.tick(9 * MS), 'a');
        assert_eq!(w.s.deadline(None), Some(13 * MS));
        // Woken above the running thread, it runs at the next decision.
        let h = w.started('h', 20, FIFO);
        assert_eq!(w.pick(10 * MS), 'h');
        w.block();
        assert_eq!(w.pick(11 * MS), 'a');
        w.wake(h);
        assert_eq!(w.pick(12 * MS), 'h');
        assert_eq!(w.level(10), "abc");
    }

    #[test]
    fn waiting_thread_ends_without_a_list() {
        let mut w = World::new();
        let a = w.started('a', 10, RR);
        let b = w.started('b', 10, RR);
        w.started('c', 10, RR);
        assert_eq!(w.pick(0), 'a');
        w.block();
        assert_eq!(w.pick(MS), 'b');
        // The stop wave or a kill ends A while it waits.
        w.exit(a);
        assert_eq!(node(a).state(), State::Dead);
        assert_eq!((w.level(10), w.s.running()), ("c".into(), Some(b)));
        // SAFETY: the world keeps its threads alive.
        assert_eq!(unsafe { w.s.start(a) }, Err(Error::BadState));
    }

    #[test]
    #[should_panic(expected = "a waiting thread ends in a queue")]
    fn a_waiting_thread_ends_out_of_its_queue() {
        let mut w = World::new();
        let a = w.started('a', 10, RR);
        assert_eq!(w.pick(0), 'a');
        w.block();
        let mut q = ReadyQueue::new();
        // SAFETY: the world keeps its threads alive.
        unsafe { q.push_tail(a) };
        w.exit(a);
    }

    #[test]
    fn waiting_thread_moves_in_its_queue_on_a_new_priority() {
        let mut w = World::new();
        let mut q = ReadyQueue::new();
        // A, B and C wait in `q`, in the order they came.
        let [a, b, c] = [('a', 10), ('b', 10), ('c', 20)].map(|(name, level)| {
            w.started(name, level, RR);
            assert_eq!(w.pick(0), name);
            let t = w.block();
            // SAFETY: the world keeps its threads alive.
            unsafe { q.push_tail(t) };
            t
        });
        // Raised: the tail of its new level.
        w.set(a, 20, RR, MS);
        // SAFETY: A waits in `q`.
        unsafe { requeue(&mut q, a) };
        assert_eq!((queued(&q, 20), queued(&q, 10)), ("ca".into(), "b".into()));
        // Lowered: the head of its new level.
        w.set(c, 10, RR, MS);
        // SAFETY: C waits in `q`.
        unsafe { requeue(&mut q, c) };
        assert_eq!((queued(&q, 20), queued(&q, 10)), ("a".into(), "cb".into()));
        // Unchanged: it stays, at the head too.
        w.set(c, 10, FIFO, MS);
        // SAFETY: C waits in `q`.
        unsafe { requeue(&mut q, c) };
        assert_eq!(queued(&q, 10), "cb");
        assert_eq!(
            [a, b, c].map(|t| (node(t).priority(), node(t).state())),
            [
                (20, State::Waiting),
                (10, State::Waiting),
                (10, State::Waiting)
            ]
        );
        // They wait: neither the ready queue nor the CPU holds them.
        assert!(w.s.ready().is_empty() && w.s.running().is_none());
        // Through the channel's queue: the raised waiter takes the post.
        let mut ch: crate::notify::Queue<char, Fake> = crate::notify::Queue::new();
        let [d, _e] = [('d', 10), ('e', 20)].map(|(name, level)| {
            w.started(name, level, RR);
            assert_eq!(w.pick(2 * MS), name);
            let t = w.block();
            // SAFETY: the world keeps its threads alive.
            unsafe { ch.wait(t) };
            t
        });
        w.set(d, 30, RR, 2 * MS);
        // SAFETY: D waits in `ch`.
        unsafe { ch.requeue(d) };
        let mut s = crate::notify::Slot::new(5, 's');
        // SAFETY: the slot outlives the queue's use of it.
        let crate::notify::Post::Deliver(t) = (unsafe { ch.post(NonNull::from(&mut s), 1) }) else {
            panic!("no delivery");
        };
        assert_eq!(t, d);
    }

    #[test]
    fn boost_raises_until_it_ends() {
        let mut w = World::new();
        let r = w.started('r', 5, RR);
        assert_eq!(w.pick(0), 'r');
        // `receive` hands R a slot of level 25: it goes on at 25 with the
        // quantum it has.
        w.boost(r, 25, 63);
        assert_eq!(
            (node(r).priority(), node(r).base(), node(r).boost()),
            (25, 5, 25)
        );
        // A boost only raises: a lower slot leaves it at 25.
        w.boost(r, 10, 63);
        assert_eq!(node(r).priority(), 25);
        let m = w.started('m', 20, RR);
        assert_eq!(w.pick(MS), 'r');
        assert_eq!(w.s.deadline(None), Some(4 * MS));
        // Its next `receive` ends the boost: M, above its base, takes the
        // CPU, and R waits at the head of its base level with the rest.
        w.unboost(r);
        assert_eq!((node(r).priority(), node(r).boost()), (5, 0));
        assert_eq!(w.pick(2 * MS), 'm');
        assert_eq!(w.level(5), "r");
        assert_eq!(node(r).slice_left(), 2 * MS);
        // M waits; a slot of level 30 raises it out of the queue, and it
        // wakes at the tail of 30 with a new quantum.
        w.block();
        assert_eq!(w.pick(3 * MS), 'r');
        w.boost(m, 30, 63);
        w.wake(m);
        assert_eq!((w.level(30), node(m).slice_left()), ("m".into(), Q));
        assert_eq!(w.pick(3 * MS), 'm');
        assert_eq!(w.level(5), "r");
    }

    #[test]
    fn boost_is_capped_by_the_ceiling() {
        let mut w = World::new();
        let r = w.started('r', 10, FIFO);
        assert_eq!(w.pick(0), 'r');
        // A slot of level 40 for a thread whose process has the ceiling 30.
        w.boost(r, 40, 30);
        assert_eq!((node(r).priority(), node(r).boost()), (30, 30));
        // A thread of level 35 runs first.
        w.started('h', 35, FIFO);
        assert_eq!(w.pick(MS), 'h');
        assert_eq!(w.level(30), "r");
        // Under the ceiling the slot's level counts.
        w.unboost(r);
        w.boost(r, 25, 30);
        assert_eq!((node(r).priority(), w.level(25)), (25, "r".into()));
    }

    #[test]
    fn base_change_keeps_a_higher_boost() {
        let mut w = World::new();
        let r = w.started('r', 5, RR);
        w.started('b', 7, RR);
        assert_eq!(w.pick(0), 'b');
        // A ready thread boosted: the tail of its new level.
        w.boost(r, 25, 63);
        assert_eq!(w.level(25), "r");
        // A new base under the boost: it stays where it is.
        w.set(r, 10, RR, MS);
        assert_eq!(
            (node(r).priority(), node(r).base(), w.level(25)),
            (25, 10, "r".into())
        );
        // A new base above the boost: the base counts.
        w.set(r, 30, RR, MS);
        assert_eq!((node(r).priority(), w.level(30)), (30, "r".into()));
        // The boost ends: the new base stays.
        w.unboost(r);
        assert_eq!((node(r).priority(), node(r).boost()), (30, 0));
        // Its end under a lower base: the head of the base's level.
        w.set(r, 7, RR, MS);
        w.boost(r, 25, 63);
        w.unboost(r);
        assert_eq!((node(r).priority(), w.level(7)), (7, "r".into()));
        assert_eq!(w.pick(MS), 'b');
    }

    #[test]
    fn lowered_running_thread_goes_on_until_a_higher_one() {
        let mut w = World::new();
        let r = w.started('r', 5, RR);
        assert_eq!(w.pick(0), 'r');
        w.boost(r, 25, 63);
        w.started('b', 5, RR);
        w.unboost(r);
        // Nothing above its base: it keeps the CPU and its quantum, ahead of
        // B of its own level.
        assert_eq!(w.pick(MS), 'r');
        assert_eq!(w.s.deadline(None), Some(4 * MS));
        // A thread above it comes: R leaves for the head of its level with
        // the rest.
        w.started('h', 6, RR);
        assert_eq!(w.pick(2 * MS), 'h');
        assert_eq!(w.level(5), "rb");
        assert_eq!(node(r).slice_left(), 2 * MS);
    }

    /// Counts what the scheduler writes to the timer.
    #[derive(Default)]
    struct FakeTimer {
        armed: Option<u64>,
        writes: u32,
    }

    impl Timer for FakeTimer {
        fn arm(&mut self, deadline: u64) {
            self.armed = Some(deadline);
            self.writes += 1;
        }

        fn disarm(&mut self) {
            self.armed = None;
            self.writes += 1;
        }
    }

    #[test]
    fn deadline_is_the_quantum_end_or_none() {
        let mut w = World::new();
        let mut timer = FakeTimer::default();
        let mut armed = Armed::new();
        // Idle: no deadline, and the timer is off already.
        assert_eq!(w.pick(0), '-');
        armed.set(&mut timer, w.s.deadline(None));
        assert_eq!((timer.armed, timer.writes), (None, 0));
        // A round-robin thread: the end of its quantum.
        w.started('a', 10, RR);
        w.started('b', 10, RR);
        assert_eq!(w.pick(MS), 'a');
        armed.set(&mut timer, w.s.deadline(None));
        assert_eq!((timer.armed, timer.writes), (Some(5 * MS), 1));
        // Back to the same thread after a call: nothing written.
        assert_eq!(w.pick(2 * MS), 'a');
        armed.set(&mut timer, w.s.deadline(None));
        assert_eq!(timer.writes, 1);
        // The next quantum: one write.
        assert_eq!(w.tick(5 * MS), 'b');
        armed.set(&mut timer, w.s.deadline(None));
        assert_eq!((timer.armed, timer.writes), (Some(9 * MS), 2));
        // A FIFO thread: the timer goes off.
        let f = w.started('f', 20, FIFO);
        assert_eq!(w.pick(6 * MS), 'f');
        armed.set(&mut timer, w.s.deadline(None));
        assert_eq!((timer.armed, timer.writes), (None, 3));
        assert_eq!(armed.get(), None);
        // B goes on with the 3 ms it had left.
        w.exit(f);
        assert_eq!(w.pick(7 * MS), 'b');
        armed.set(&mut timer, w.s.deadline(None));
        assert_eq!((timer.armed, timer.writes), (Some(10 * MS), 4));
        assert_eq!(armed.get(), Some(10 * MS));
    }

    #[test]
    fn deadline_is_the_nearer_of_quantum_and_timer() {
        let mut w = World::new();
        // Idle: only the timer of a program.
        assert_eq!(w.pick(0), '-');
        assert_eq!(w.s.deadline(None), None);
        assert_eq!(w.s.deadline(Some(7 * MS)), Some(7 * MS));
        // A round-robin thread from 1 ms: its quantum ends at 5 ms.
        w.started('a', 10, RR);
        w.started('b', 10, RR);
        assert_eq!(w.pick(MS), 'a');
        assert_eq!(w.s.deadline(Some(9 * MS)), Some(5 * MS));
        assert_eq!(w.s.deadline(Some(3 * MS)), Some(3 * MS));
        // The interrupt of the nearer timer does not end the quantum.
        assert_eq!(w.tick(3 * MS), 'a');
        assert_eq!(w.s.deadline(None), Some(5 * MS));
        // A FIFO thread: only the timer.
        w.started('f', 20, FIFO);
        assert_eq!(w.pick(4 * MS), 'f');
        assert_eq!(w.s.deadline(None), None);
        assert_eq!(w.s.deadline(Some(9 * MS)), Some(9 * MS));
    }

    #[test]
    fn cleanup_runs_when_its_level_is_highest() {
        let mut w = World::new();
        let a = w.started('a', 10, RR);
        w.started('b', 5, RR);
        assert_eq!(w.decide(0, Some(20)), '*');
        // Nothing runs while the cleanup works; the thread waits at the
        // head of its level.
        assert_eq!(w.s.running(), None);
        assert_eq!(w.s.deadline(None), None);
        assert_eq!(w.level(10), "a");
        assert_eq!(w.decide(MS, None), 'a');
        // A running thread gives the CPU up to cleanup above it.
        assert_eq!(w.decide(2 * MS, Some(11)), '*');
        assert_eq!(w.level(10), "a");
        assert_eq!(node(a).state(), State::Ready);
        // In idle every level of cleanup runs, 1 too.
        w.exit(a);
        let mut idle = World::new();
        assert_eq!(idle.decide(0, Some(1)), '*');
        assert_eq!(idle.decide(0, None), '-');
    }

    #[test]
    fn equal_level_cleanup_goes_first() {
        let mut w = World::new();
        let a = w.started('a', 10, FIFO);
        w.started('b', 10, FIFO);
        // Before a ready thread of its level.
        assert_eq!(w.decide(0, Some(10)), '*');
        assert_eq!(w.level(10), "ab");
        assert_eq!(w.decide(0, None), 'a');
        // Before the running thread of its level, which waits at the head.
        assert_eq!(w.decide(MS, Some(10)), '*');
        assert_eq!(w.level(10), "ab");
        assert_eq!(node(a).state(), State::Ready);
        assert_eq!(w.decide(2 * MS, None), 'a');
    }

    #[test]
    fn preempted_by_cleanup_keeps_the_rest_of_its_quantum() {
        let mut w = World::new();
        let a = w.started('a', 10, RR);
        let b = w.started('b', 10, RR);
        assert_eq!(w.pick(0), 'a');
        assert_eq!(w.s.deadline(None), Some(4 * MS));
        // 1 ms in, cleanup at the same level takes 2 ms.
        assert_eq!(w.decide(MS, Some(10)), '*');
        assert_eq!(node(a).slice_left(), 3 * MS);
        assert_eq!(w.decide(2 * MS, Some(10)), '*');
        // A goes on before B, with the 3 ms it had left.
        assert_eq!(w.decide(3 * MS, None), 'a');
        assert_eq!(w.s.deadline(None), Some(6 * MS));
        assert_eq!(w.tick(6 * MS), 'b');
        // A quantum that ended under the cleanup starts anew at the tail.
        assert_eq!(w.decide(10 * MS, Some(10)), '*');
        assert_eq!(w.level(10), "ab");
        assert_eq!(node(b).slice_left(), Q);
    }

    #[test]
    fn cleanup_below_a_ready_thread_waits() {
        let mut w = World::new();
        w.started('a', 10, FIFO);
        assert_eq!(w.decide(0, Some(9)), 'a');
        assert_eq!(w.decide(MS, Some(9)), 'a');
        // A thread above the cleanup runs first, the cleanup after it.
        let h = w.started('h', 20, FIFO);
        assert_eq!(w.decide(2 * MS, Some(15)), 'h');
        w.exit(h);
        assert_eq!(w.decide(3 * MS, Some(15)), '*');
        assert_eq!(w.decide(4 * MS, Some(9)), 'a');
    }

    /// Items that are not threads: the cleanup queue's.
    struct Item {
        link: Link<Item>,
        name: char,
    }

    // SAFETY: the link is a field of the item.
    unsafe impl Linked for Item {
        fn link(this: NonNull<Item>) -> NonNull<Link<Item>> {
            // SAFETY: `this` points at a live item.
            unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).link) }
        }
    }

    fn names(q: &ReadyQueue<Item>, level: u8) -> String {
        let mut names = String::new();
        let mut t = q.first(level);
        while let Some(i) = t {
            // SAFETY: the test keeps its items alive.
            let item = unsafe { i.as_ref() };
            names.push(item.name);
            t = item.link.next;
        }
        names
    }

    #[test]
    fn ready_queue_holds_any_linked_item() {
        let mut items: Vec<Box<Item>> = [('a', 10), ('b', 10), ('c', 30), ('d', 10)]
            .into_iter()
            .map(|(name, level)| {
                Box::new(Item {
                    link: Link::new(level),
                    name,
                })
            })
            .collect();
        let [a, b, c, d] = [0, 1, 2, 3].map(|i| NonNull::from(&mut *items[i]));
        let mut q = ReadyQueue::new();
        // SAFETY: the items stay alive and in place while queued.
        unsafe {
            q.push_tail(a);
            q.push_tail(b);
            q.push_tail(c);
            q.push_head(d);
        }
        assert_eq!(
            (q.top(), names(&q, 10), names(&q, 30)),
            (Some(30), "dab".into(), "c".into())
        );
        assert!(items[0].link.is_queued());
        // SAFETY: as above.
        unsafe {
            q.remove(c);
            q.remove(a);
        }
        assert_eq!((q.top(), names(&q, 10)), (Some(10), "db".into()));
        // Out of the queue, an item may change its level and come back.
        items[2].link.set_level(5);
        // SAFETY: as above.
        unsafe { q.push_tail(c) };
        assert_eq!((q.first(5), items[2].link.level()), (Some(c), 5));
        // SAFETY: as above.
        unsafe {
            q.remove(b);
            q.remove(d);
            q.remove(c);
        }
        assert!(q.is_empty() && !items[0].link.is_queued());
    }

    #[test]
    #[should_panic(expected = "an item is queued twice")]
    fn an_item_is_queued_once() {
        let mut item = Box::new(Item {
            link: Link::new(3),
            name: 'x',
        });
        let i = NonNull::from(&mut *item);
        let mut q = ReadyQueue::new();
        // SAFETY: the item stays alive and in place while queued.
        unsafe {
            q.push_tail(i);
            q.push_head(i);
        }
    }

    #[test]
    #[should_panic(expected = "the level of a queued item changes")]
    fn a_queued_item_keeps_its_level() {
        let mut item = Box::new(Item {
            link: Link::new(3),
            name: 'x',
        });
        let i = NonNull::from(&mut *item);
        let mut q = ReadyQueue::new();
        // SAFETY: the item stays alive and in place while queued.
        unsafe { q.push_tail(i) };
        item.link.set_level(4);
    }

    #[test]
    fn priority_arguments() {
        assert_eq!(priority_arg(1), Ok(1));
        assert_eq!(priority_arg(63), Ok(63));
        for raw in [0, 64, 255, 1 << 8 | 10, 1 << 32 | 10, u64::MAX] {
            assert_eq!(priority_arg(raw), Err(Error::InvalidArgs), "{raw:#x}");
        }
        assert_eq!(policy_arg(0), Ok(RR));
        assert_eq!(policy_arg(1), Ok(FIFO));
        for raw in [2, 1 << 32, u64::MAX] {
            assert_eq!(policy_arg(raw), Err(Error::InvalidArgs), "{raw:#x}");
        }
    }

    #[test]
    fn priority_ceilings() {
        // thread_create and thread_set_priority: the thread's process and
        // the caller's, whichever is lower.
        assert_eq!(under_ceilings(40, &[40, 63]), Ok(()));
        assert_eq!(under_ceilings(41, &[40, 63]), Err(Error::AccessDenied));
        assert_eq!(under_ceilings(41, &[63, 40]), Err(Error::AccessDenied));
        assert_eq!(under_ceilings(1, &[1, 1]), Ok(()));
        // process_create: a child's ceiling is at most its parent's.
        assert_eq!(under_ceilings(30, &[30]), Ok(()));
        assert_eq!(under_ceilings(31, &[30]), Err(Error::AccessDenied));
        // The notification priority: 0 without an exit channel, and only
        // then; with one, a priority at most the caller's ceiling.
        assert_eq!(notify_priority_arg(0, false), Ok(0));
        assert_eq!(notify_priority_arg(5, false), Err(Error::InvalidArgs));
        assert_eq!(notify_priority_arg(0, true), Err(Error::InvalidArgs));
        assert_eq!(notify_priority_arg(64, true), Err(Error::InvalidArgs));
        assert_eq!(notify_priority_arg(5, true), Ok(5));
        assert_eq!(under_ceilings(5, &[4]), Err(Error::AccessDenied));
    }
}
