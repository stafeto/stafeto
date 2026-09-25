// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The scheduler's rules (spec 8), with no hardware in them: a ready list
//! for each of the 64 priority levels, a bit mask of the levels that have
//! ready threads, round robin with a quantum and FIFO by the POSIX rules,
//! the deadline the timer needs, and the checks of priorities against the
//! ceilings of processes. Every operation takes constant time. Times are
//! counter ticks; the kernel keeps one `Scheduler` and calls it at every
//! decision. The running thread is in no list (Benno scheduling).
//!
//! Where a thread goes; into a tail always with a new quantum, into a head
//! always with the rest of its quantum:
//!
//! | Event | Place | Quantum |
//! |---|---|---|
//! | preempted by a higher level | head of its level | keeps the rest; none left counts as the end |
//! | its quantum ended (the timer's interrupt only) | tail of its level | new |
//! | `yield` | tail of its level | new |
//! | became ready (`thread_start`; from 1.3 the end of a wait) | tail of its level | new |
//! | priority raised | tail of the new level | new; a running thread keeps its rest |
//! | priority unchanged | stays | kept; new when FIFO becomes round robin |
//! | priority lowered | head of the new level | keeps the rest |

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
    /// Ended; it never runs again.
    Dead,
}

/// What the scheduler keeps in each thread.
pub struct Node<T> {
    /// The effective priority, which picks the thread's level.
    priority: u8,
    policy: Policy,
    state: State,
    /// Ticks left of a round-robin quantum while the thread is ready.
    slice_left: u64,
    prev: Option<NonNull<T>>,
    next: Option<NonNull<T>>,
}

impl<T> Node<T> {
    /// A stopped thread's node. The priority is checked by the caller
    /// (priority_arg, kcore::thread::check_start).
    pub const fn new(priority: u8, policy: Policy) -> Node<T> {
        Node {
            priority,
            policy,
            state: State::Stopped,
            slice_left: 0,
            prev: None,
            next: None,
        }
    }

    pub fn priority(&self) -> u8 {
        self.priority
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

/// The node of `t`.
///
/// # Safety
/// `t` is alive, and nothing else refers to its node meanwhile.
unsafe fn node<'a, T: Schedulable>(t: NonNull<T>) -> &'a mut Node<T> {
    // SAFETY: the caller's promise and Schedulable's contract.
    unsafe { T::node(t).as_mut() }
}

/// The ready threads: a doubly linked list for each level, its links in
/// the threads' nodes, and a bit for each level with a thread in it.
pub struct ReadyQueue<T> {
    mask: u64,
    heads: [Option<NonNull<T>>; LEVELS],
    tails: [Option<NonNull<T>>; LEVELS],
}

impl<T: Schedulable> ReadyQueue<T> {
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

    /// The highest level with a ready thread: 63 minus the leading zeros
    /// of the mask, one instruction (CLZ).
    pub fn top(&self) -> Option<u8> {
        if self.mask == 0 {
            None
        } else {
            Some(63 - self.mask.leading_zeros() as u8)
        }
    }

    /// The thread at the head of `level`: the next to run there.
    pub fn first(&self, level: u8) -> Option<NonNull<T>> {
        self.heads[usize::from(level)]
    }

    /// The level of `t`, checked: level 0 goes to no thread.
    ///
    /// # Safety
    /// As for `node`.
    unsafe fn level(t: NonNull<T>) -> usize {
        // SAFETY: the caller's promise.
        let level = unsafe { node(t) }.priority;
        assert!(
            (1..PRIORITY_LEVELS).contains(&level),
            "a thread at level {level} is queued; level 0 goes to no thread"
        );
        usize::from(level)
    }

    /// Puts `t` at the head of its level.
    ///
    /// # Safety
    /// `t` is alive and in no list, and stays alive and in place until it
    /// leaves this one.
    unsafe fn push_head(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise; the old head is in this list.
        unsafe {
            let level = Self::level(t);
            let old = self.heads[level];
            let n = node(t);
            n.prev = None;
            n.next = old;
            match old {
                Some(h) => node(h).prev = Some(t),
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
    unsafe fn push_tail(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise; the old tail is in this list.
        unsafe {
            let level = Self::level(t);
            let old = self.tails[level];
            let n = node(t);
            n.next = None;
            n.prev = old;
            match old {
                Some(tail) => node(tail).next = Some(t),
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
    /// `t` is in this queue.
    unsafe fn remove(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise; its neighbours are in this list.
        unsafe {
            let level = Self::level(t);
            let n = node(t);
            let (prev, next) = (n.prev.take(), n.next.take());
            match prev {
                Some(p) => node(p).next = next,
                None => self.heads[level] = next,
            }
            match next {
                Some(x) => node(x).prev = prev,
                None => self.tails[level] = prev,
            }
            if self.heads[level].is_none() {
                self.mask &= !(1 << level);
            }
        }
    }
}

impl<T: Schedulable> Default for ReadyQueue<T> {
    fn default() -> Self {
        Self::new()
    }
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

    /// The deadline the timer needs: the end of the running thread's
    /// quantum when it is round robin; None for a FIFO thread and while
    /// idle. From milestone 1.3 the nearest timer of a program joins it.
    pub fn deadline(&self) -> Option<u64> {
        let r = self.running?;
        // SAFETY: the running thread is alive (the contract of `start`).
        let policy = unsafe { node(r) }.policy;
        (policy == Policy::RoundRobin).then_some(self.slice_end)
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

    /// The decision: the thread to run from `now` on, or None to idle. The
    /// running thread goes on unless a ready thread is above its level;
    /// then it goes back to the head of its level with the rest of its
    /// quantum. The chosen thread's quantum runs from `now`.
    ///
    /// # Safety
    /// Every thread the scheduler holds is alive.
    pub unsafe fn pick(&mut self, now: u64) -> Option<NonNull<T>> {
        if let Some(r) = self.running {
            // SAFETY: the running thread is alive.
            let level = unsafe { node(r) }.priority;
            match self.ready.top() {
                Some(top) if top > level => {
                    // SAFETY: as above.
                    unsafe { self.preempt(r, now) }
                }
                _ => return Some(r),
            }
        }
        let top = self.ready.top()?;
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
        Some(next)
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

    /// thread_set_priority, by the rules of `pthread_setschedprio`: a ready
    /// thread raised goes to the tail of its new level with a new quantum,
    /// lowered to the head with the rest of its quantum, unchanged stays
    /// where it is. A thread that turns from FIFO to round robin gets a new
    /// quantum, running from `now` when it runs. A running thread stays on
    /// the CPU and keeps its quantum; lowered below a ready thread, it
    /// gives the CPU up at the next `pick`. A stopped thread only takes the
    /// values. BAD_STATE for a thread that ended. `priority` is 1-63, as
    /// priority_arg checks.
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
        let (state, old, to_round_robin) = unsafe {
            let n = node(t);
            let to_round_robin = n.policy == Policy::Fifo && policy == Policy::RoundRobin;
            (n.state, n.priority, to_round_robin)
        };
        let moves = state == State::Ready && priority != old;
        match state {
            State::Dead => return Err(Error::BadState),
            // SAFETY: a ready thread is in the queue.
            _ if moves => unsafe { self.ready.remove(t) },
            State::Running if to_round_robin => {
                self.slice_end = now.saturating_add(self.quantum);
            }
            _ => {}
        }
        // SAFETY: the caller's promise; the thread is in no list if it moves.
        unsafe {
            let n = node(t);
            n.priority = priority;
            n.policy = policy;
            if state == State::Ready && (priority > old || to_round_robin) {
                n.slice_left = self.quantum;
            }
            if moves && priority > old {
                self.ready.push_tail(t);
            } else if moves {
                self.ready.push_head(t);
            }
        }
        Ok(())
    }

    /// The thread ends (thread_exit, process_kill, a fault), whatever its
    /// state: it leaves its list and never runs again. When it was the
    /// running one, nothing runs until `pick`.
    ///
    /// # Safety
    /// `t` is alive; after this the scheduler no longer refers to it.
    pub unsafe fn exit(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise.
        match unsafe { node(t) }.state {
            State::Running => {
                assert!(
                    self.running == Some(t),
                    "a running thread is not the running one"
                );
                self.running = None;
            }
            // SAFETY: a ready thread is in the queue.
            State::Ready => unsafe { self.ready.remove(t) },
            State::Stopped | State::Dead => {}
        }
        // SAFETY: the caller's promise.
        unsafe { node(t) }.state = State::Dead;
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

/// The notification priority of `process_create`: 0 exactly when there is
/// no exit channel, otherwise a priority. INVALID_ARGS for anything else.
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

        /// The name of the thread `pick` chooses at `now`, '-' for idle.
        fn pick(&mut self, now: u64) -> char {
            // SAFETY: as above.
            let t = unsafe { self.s.pick(now) };
            t.map_or('-', name)
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

        /// The names on `level`, head first.
        fn level(&self, level: u8) -> String {
            let mut names = String::new();
            let mut t = self.s.ready().first(level);
            while let Some(next) = t {
                names.push(name(next));
                t = node(next).next;
            }
            names
        }
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
            assert_eq!(s.pick(MS), Some(t));
            assert_eq!(s.deadline(), Some(5 * MS));
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
        assert_eq!(w.s.deadline(), Some(4 * MS));
        // At 1 ms a higher thread starts and runs for 2 ms.
        let h = w.started('h', 20, RR);
        assert_eq!(w.pick(MS), 'h');
        assert_eq!(w.level(10), "ab");
        assert_eq!(node(a).slice_left(), 3 * MS);
        w.exit(h);
        // A goes on before B, with the 3 ms it had left.
        assert_eq!(w.pick(3 * MS), 'a');
        assert_eq!(w.s.deadline(), Some(6 * MS));
        assert_eq!(w.tick(6 * MS), 'b');
        assert_eq!(w.s.deadline(), Some(10 * MS));
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
            now = w.s.deadline().expect("a round-robin thread runs");
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
        assert_eq!(w.s.deadline(), Some(9 * MS));
    }

    #[test]
    fn early_timer_changes_nothing() {
        let mut w = World::new();
        w.started('a', 10, RR);
        w.started('b', 10, RR);
        assert_eq!(w.pick(0), 'a');
        assert_eq!(w.tick(4 * MS - 1), 'a');
        assert_eq!(w.s.deadline(), Some(4 * MS));
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
        assert_eq!(w.s.deadline(), Some(8 * MS));
        assert_eq!(w.tick(8 * MS), 'a');
        assert_eq!(w.s.deadline(), Some(12 * MS));
    }

    #[test]
    fn fifo_threads_switch_only_on_yield() {
        let mut w = World::new();
        w.started('a', 10, FIFO);
        w.started('b', 10, FIFO);
        assert_eq!(w.pick(0), 'a');
        assert_eq!(w.s.deadline(), None);
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
        assert_eq!(w.s.deadline(), Some(5 * MS));
    }

    #[test]
    fn yield_of_a_lone_thread_returns_to_it_and_never_to_lower_levels() {
        let mut w = World::new();
        let x = w.started('x', 20, RR);
        w.started('l', 5, RR);
        assert_eq!(w.pick(0), 'x');
        assert_eq!(w.yield_at(MS), 'x');
        assert_eq!(w.s.deadline(), Some(5 * MS));
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
        assert_eq!(w.s.deadline(), Some(4 * MS));
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
        assert_eq!(w.s.deadline(), Some(14 * MS));
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
        assert_eq!(w.s.deadline(), None);
        // To round robin: a quantum from now.
        w.set(r, 10, RR, 3 * MS);
        assert_eq!(w.s.deadline(), Some(7 * MS));
        // Back to FIFO: no deadline.
        w.set(r, 10, FIFO, 4 * MS);
        assert_eq!(w.s.deadline(), None);
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
        assert_eq!(w.s.deadline(), Some(4 * MS));
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
        assert_eq!(w.s.deadline(), None);
        // SAFETY: the world keeps its threads alive.
        assert_eq!(unsafe { w.s.start(stopped) }, Err(Error::BadState));
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
        armed.set(&mut timer, w.s.deadline());
        assert_eq!((timer.armed, timer.writes), (None, 0));
        // A round-robin thread: the end of its quantum.
        w.started('a', 10, RR);
        w.started('b', 10, RR);
        assert_eq!(w.pick(MS), 'a');
        armed.set(&mut timer, w.s.deadline());
        assert_eq!((timer.armed, timer.writes), (Some(5 * MS), 1));
        // Back to the same thread after a call: nothing written.
        assert_eq!(w.pick(2 * MS), 'a');
        armed.set(&mut timer, w.s.deadline());
        assert_eq!(timer.writes, 1);
        // The next quantum: one write.
        assert_eq!(w.tick(5 * MS), 'b');
        armed.set(&mut timer, w.s.deadline());
        assert_eq!((timer.armed, timer.writes), (Some(9 * MS), 2));
        // A FIFO thread: the timer goes off.
        let f = w.started('f', 20, FIFO);
        assert_eq!(w.pick(6 * MS), 'f');
        armed.set(&mut timer, w.s.deadline());
        assert_eq!((timer.armed, timer.writes), (None, 3));
        assert_eq!(armed.get(), None);
        // B goes on with the 3 ms it had left.
        w.exit(f);
        assert_eq!(w.pick(7 * MS), 'b');
        armed.set(&mut timer, w.s.deadline());
        assert_eq!((timer.armed, timer.writes), (Some(10 * MS), 4));
        assert_eq!(armed.get(), Some(10 * MS));
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
