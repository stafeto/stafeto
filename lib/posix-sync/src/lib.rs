// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Waits by address in the POSIX layer, without a call of the kernel of
//! their own (spec 2, 3.4): what relibc's `Pal::futex_wait` and
//! `futex_wake` become, the critical sections of the layer, and its lock.
//!
//! A table of 64 buckets by the hash of the address. A bucket holds the
//! count of the threads that wait in it or are about to, the word of its
//! lock, and a doubly linked list of the nodes of the waiting threads (in
//! their blocks, posix-thread), by level, first come first among equals.
//! A thread waits in `receive` on its own channel; its timer (on the same
//! channel) bounds the wait. A waker unlinks nodes under the lock and
//! notifies each thread's channel with bit 0 there, so that a thread that
//! sees its node gone knows the notification is in its slot already and
//! nothing touches its channel after it left.
//!
//! The lock of a bucket never spins: the thread marks itself in a critical
//! section, raises itself to the ceiling of its process (immediate
//! ceiling) and takes the word with a CAS, or yields to the holder. No
//! thread holds two locks of buckets. An entry of signals that comes inside
//! a critical section only marks itself deferred; the end of the section
//! delivers it (`configure`).
//!
//! Wakeups are not lost: the waiter counts itself in the bucket before it
//! compares the word, the waker changed the word before it reads the count
//! (SeqCst on both sides), and a notification stays in the slot of the
//! channel until the waiter's `receive`. A WAKE left in the slot (after
//! `resume_wait`, or after a wait that ended by its deadline) gives the
//! next wait a spurious wakeup, which `futex_wait` allows: harmless.

#![no_std]

use abi::{Error, Policy, Source};
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32, AtomicUsize, Ordering};
use posix_thread::{Block, flag};
use rt::handle::{Channel, Handle, Thread, Timer};
use rt::sys;

pub const EINVAL: i32 = 22;
pub const EAGAIN: i32 = 11;
pub const ETIMEDOUT: i32 = 110;
/// The clocks of a deadline (spec 2, 3.4): MONOTONIC now; the clock patch
/// of relibc adds the clock of the caller without changing the call.
pub const CLOCK_MONOTONIC: u32 = 1;

/// Bits of the slot of label 0 of a thread's channel.
pub mod bit {
    /// A waker unlinked the thread's node, or someone asks it to look again.
    pub const WAKE: u64 = 1 << 0;
    /// Cancellation was asked for (posix-abi).
    pub const CANCEL: u64 = 1 << 2;
}

static CEILING: AtomicU8 = AtomicU8::new(0);
static DEFERRED: AtomicUsize = AtomicUsize::new(0);

/// The ceiling of the process, which the lock of a bucket raises its holder
/// to, and the function that delivers an entry deferred by a critical
/// section. Called once at the start of the process.
pub fn configure(ceiling: u8, deferred: fn()) {
    CEILING.store(ceiling, Ordering::Relaxed);
    DEFERRED.store(deferred as usize, Ordering::Release);
}

fn current() -> Option<&'static Block> {
    // SAFETY: a block lives while its thread runs (posix-thread).
    unsafe { posix_thread::block().as_ref() }
}

/// Starts a critical section of the calling thread: an entry of signals
/// waits for the end of the outermost one.
pub fn enter() {
    if let Some(block) = current() {
        block.flags.fetch_add(flag::DEPTH_ONE, Ordering::SeqCst);
    }
}

/// Ends a critical section; the end of the outermost one delivers an entry
/// that came inside it, with no call of the kernel.
pub fn leave() {
    let Some(block) = current() else {
        return;
    };
    let old = block.flags.fetch_sub(flag::DEPTH_ONE, Ordering::SeqCst);
    debug_assert!(old >> flag::DEPTH_SHIFT != 0, "balanced critical sections");
    if old >> flag::DEPTH_SHIFT == 1
        && block
            .flags
            .fetch_and(!flag::ENTRY_DEFERRED, Ordering::SeqCst)
            & flag::ENTRY_DEFERRED
            != 0
    {
        let deferred = DEFERRED.load(Ordering::Acquire);
        if deferred != 0 {
            // SAFETY: `configure` stored a `fn()` there.
            let deliver: fn() = unsafe { core::mem::transmute(deferred) };
            deliver();
        }
    }
}

/// Whether the calling thread is in a critical section.
pub fn critical() -> bool {
    current().is_some_and(|b| b.flags.load(Ordering::SeqCst) >> flag::DEPTH_SHIFT != 0)
}

/// For the entry of signals: inside a critical section it marks itself
/// deferred and says so, and the dispatcher returns at once.
pub fn defer_entry() -> bool {
    match current() {
        Some(block) if block.flags.load(Ordering::SeqCst) >> flag::DEPTH_SHIFT != 0 => {
            block.flags.fetch_or(flag::ENTRY_DEFERRED, Ordering::SeqCst);
            true
        }
        _ => false,
    }
}

/// The table of waits by address is empty again, its locks free: in a
/// forked child the nodes of its parent's other threads are not threads
/// of the child (spec 2, 3.2). The child's only thread waits in none.
pub fn after_fork() {
    for bucket in &TABLE {
        bucket.head.store(ptr::null_mut(), Ordering::Relaxed);
        bucket.tail.store(ptr::null_mut(), Ordering::Relaxed);
        bucket.waiters.store(0, Ordering::Relaxed);
        bucket.lock.store(0, Ordering::Release);
    }
}

/// Runs `run` holding the lock of the bucket of `address`, for the probes
/// of a fork while another thread holds it.
pub fn hold_bucket(address: usize, run: impl FnOnce()) {
    let _held = lock(bucket(address));
    run();
}

/// A bucket: the count of its waiters, the word of its lock and its list.
#[repr(C, align(32))]
struct Bucket {
    waiters: AtomicU32,
    lock: AtomicU32,
    head: AtomicPtr<Block>,
    tail: AtomicPtr<Block>,
}

const BUCKETS: usize = 64;
static TABLE: [Bucket; BUCKETS] = [const {
    Bucket {
        waiters: AtomicU32::new(0),
        lock: AtomicU32::new(0),
        head: AtomicPtr::new(ptr::null_mut()),
        tail: AtomicPtr::new(ptr::null_mut()),
    }
}; BUCKETS];
const _: () = assert!(core::mem::size_of::<Bucket>() == 32);

fn bucket(address: usize) -> &'static Bucket {
    let hash = ((address >> 2) as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 58;
    &TABLE[hash as usize]
}

fn own_thread(block: &Block) -> Option<core::mem::ManuallyDrop<Handle<Thread>>> {
    match block.thread.load(Ordering::Relaxed) {
        0 => None,
        raw => Some(Handle::borrowed(abi::Handle(raw))),
    }
}

/// The lock of `bucket` for the calling thread, which has `block`.
struct Held<'a> {
    bucket: &'a Bucket,
    block: Option<&'a Block>,
}

/// Whether `block`'s thread holds or waits for a raising lock of the
/// layer, and so stays at the ceiling.
fn raised(block: &Block) -> bool {
    block.flags.load(Ordering::Relaxed) & flag::RAISED_MASK != 0
}

/// Moves the thread of `block` to `level` through its own handle.
fn set_level(block: &Block, level: u8) {
    if let Some(thread) = own_thread(block) {
        let policy =
            Policy::from_raw(block.policy.load(Ordering::Relaxed)).unwrap_or(Policy::RoundRobin);
        let _ = sys::thread_set_priority(&thread, level, policy);
    }
}

fn lock(bucket: &'static Bucket) -> Held<'static> {
    enter();
    let block = current();
    if let Some(block) = block {
        debug_assert!(
            block.flags.fetch_or(flag::BUCKET, Ordering::Relaxed) & flag::BUCKET == 0,
            "one lock of a bucket at a time"
        );
        let ceiling = CEILING.load(Ordering::Relaxed);
        if ceiling != 0 && !raised(block) {
            set_level(block, ceiling);
        }
    }
    // One processor (spec 2, 3.4; until SMP): the holder runs at the ceiling and
    // holds no second lock of a bucket, so only a holder preempted before
    // its raise can make this loop turn, and yielding runs it. The step of
    // rule 3 of the ABI for several processors (16 tries, then the node on
    // the stack, a bit and a look again) comes with SMP; a build for more
    // than one processor must not take this loop as it is: a debug build
    // stops when the loop turns more than a holder preempted before its
    // raise can make it.
    let mut turns = 0u32;
    while bucket
        .lock
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        if cfg!(debug_assertions) {
            turns += 1;
            assert!(
                turns < 64,
                "the lock of a bucket yields for one processor only, until SMP"
            );
        }
        // The holder is a thread of this process at the ceiling, preempted:
        // yielding gives it the processor.
        let _ = sys::yield_now();
    }
    Held { bucket, block }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.bucket.lock.store(0, Ordering::Release);
        if let Some(block) = self.block {
            debug_assert!(
                block.flags.fetch_and(!flag::BUCKET, Ordering::Relaxed) & flag::BUCKET != 0
            );
            // A holder of a raising lock of the layer stays at the ceiling.
            if CEILING.load(Ordering::Relaxed) != 0 && !raised(block) {
                set_level(block, block.base_level.load(Ordering::Relaxed) as u8);
            }
        }
        leave();
    }
}

fn node(block: &Block) -> *mut Block {
    ptr::from_ref(block).cast_mut()
}

/// Links `block` into the held bucket after the last node of its level or
/// a higher one: at most one step for each waiting thread of the process.
fn insert(held: &Held<'_>, block: &Block) {
    let level = block.level.load(Ordering::Relaxed);
    let mut before = held.bucket.head.load(Ordering::Relaxed);
    let mut after: *mut Block = ptr::null_mut();
    // SAFETY: the nodes of a held bucket are blocks of waiting threads.
    while let Some(next) = unsafe { before.as_ref() } {
        if next.level.load(Ordering::Relaxed) < level {
            break;
        }
        after = before;
        before = next.next.load(Ordering::Relaxed) as *mut Block;
    }
    block.previous.store(after as usize, Ordering::Relaxed);
    block.next.store(before as usize, Ordering::Relaxed);
    // SAFETY: as above.
    match unsafe { after.as_ref() } {
        Some(after) => after.next.store(node(block) as usize, Ordering::Relaxed),
        None => held.bucket.head.store(node(block), Ordering::Relaxed),
    }
    // SAFETY: as above.
    match unsafe { before.as_ref() } {
        Some(before) => before
            .previous
            .store(node(block) as usize, Ordering::Relaxed),
        None => held.bucket.tail.store(node(block), Ordering::Relaxed),
    }
}

/// Unlinks `block` from the held bucket in O(1) and marks it gone.
fn remove(held: &Held<'_>, block: &Block) {
    let previous = block.previous.load(Ordering::Relaxed) as *mut Block;
    let next = block.next.load(Ordering::Relaxed) as *mut Block;
    // SAFETY: neighbours are nodes of the held bucket.
    match unsafe { previous.as_ref() } {
        Some(previous) => previous.next.store(next as usize, Ordering::Relaxed),
        None => held.bucket.head.store(next, Ordering::Relaxed),
    }
    // SAFETY: as above.
    match unsafe { next.as_ref() } {
        Some(next) => next.previous.store(previous as usize, Ordering::Relaxed),
        None => held.bucket.tail.store(previous, Ordering::Relaxed),
    }
    block.address.store(0, Ordering::Relaxed);
    held.bucket.waiters.fetch_sub(1, Ordering::SeqCst);
}

/// How a wait ended without an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Woken {
    /// A waker, or a spurious wakeup: the caller looks at its word again.
    Woken,
    /// An entry of signals or a request of cancellation came; the caller
    /// checks for cancellation and looks again.
    Entry,
}

/// Waits while `*word == value`, until `futex_wake`, an entry of signals or
/// the absolute deadline on `clock` (ns of CLOCK_MONOTONIC). EAGAIN when the
/// word differs, ETIMEDOUT when the deadline passed, EINVAL for another
/// clock or a thread without its channel. Spurious wakeups come back as
/// `Woken::Woken`.
pub fn futex_wait(
    word: &AtomicU32,
    value: u32,
    clock: u32,
    deadline: Option<u64>,
) -> Result<Woken, i32> {
    if clock != CLOCK_MONOTONIC {
        return Err(EINVAL);
    }
    let Some(block) = current() else {
        return Err(EINVAL);
    };
    let channel = block.channel.load(Ordering::Relaxed);
    let timer = block.timer.load(Ordering::Relaxed);
    if channel == 0 || (deadline.is_some() && timer == 0) {
        return Err(EINVAL);
    }
    let address = ptr::from_ref(word) as usize;
    let bucket = bucket(address);
    // Counted before the comparison: a waker that changed the word sees it.
    bucket.waiters.fetch_add(1, Ordering::SeqCst);
    {
        let held = lock(bucket);
        if word.load(Ordering::SeqCst) != value {
            bucket.waiters.fetch_sub(1, Ordering::SeqCst);
            return Err(EAGAIN);
        }
        block.address.store(address, Ordering::Relaxed);
        block
            .level
            .store(block.base_level.load(Ordering::Relaxed), Ordering::Relaxed);
        insert(&held, block);
        block.flags.fetch_or(flag::WAITING, Ordering::SeqCst);
    }
    let channel = Handle::<Channel>::borrowed(abi::Handle(channel));
    let timer = Handle::<Timer>::borrowed(abi::Handle(timer));
    if let Some(deadline) = deadline {
        let _ = sys::timer_set(&timer, deadline);
    }
    let outcome = loop {
        match sys::receive(&channel) {
            Ok(sys::Received::Notification {
                source: Source::Unlabeled,
                bits,
                ..
            }) => {
                break if bits & bit::CANCEL != 0 {
                    Ok(Woken::Entry)
                } else {
                    Ok(Woken::Woken)
                };
            }
            Ok(sys::Received::Notification {
                source: Source::Timer,
                ..
            }) => {
                if deadline.is_some_and(rt::time::reached) {
                    break Err(ETIMEDOUT);
                }
            }
            Ok(_) => {}
            Err(Error::Interrupted) => break Ok(Woken::Entry),
            Err(error) => panic!("wait by address: {error:?}"),
        }
    };
    if deadline.is_some() {
        let _ = sys::timer_cancel(&timer);
    }
    let held = lock(bucket);
    block.flags.fetch_and(!flag::WAITING, Ordering::SeqCst);
    if block.address.load(Ordering::Relaxed) == address {
        remove(&held, block);
        outcome
    } else {
        // A waker unlinked the node, or an entry did (`abandon`): the wait
        // was answered.
        Ok(outcome.unwrap_or(Woken::Woken))
    }
}

/// For the entry of signals, before its first handler: when the calling
/// thread is in a wait by address, the wait ends here. Its node leaves the
/// bucket, if a waker has not unlinked it already, so that a handler that
/// waits by address, sleeps or takes a lock of the layer with the same
/// block finds no node of it linked, and no wake meant for the wait is
/// eaten by a wait of the handler unnoticed. Returns whether the thread was
/// in a wait; `resume_wait` with it after the handlers.
pub fn abandon() -> bool {
    let Some(block) = current() else {
        return false;
    };
    if block.flags.fetch_and(!flag::WAITING, Ordering::SeqCst) & flag::WAITING == 0 {
        return false;
    }
    let address = block.address.load(Ordering::Relaxed);
    if address != 0 {
        let held = lock(bucket(address));
        if block.address.load(Ordering::Relaxed) == address {
            remove(&held, block);
        }
    }
    true
}

/// After the handlers of an entry that `abandon` ended a wait for: the wait
/// goes on as one that was woken, with WAKE in its slot (a spurious wakeup,
/// which `futex_wait` allows): its caller looks at its word again.
pub fn resume_wait(abandoned: bool) {
    let Some(block) = current().filter(|_| abandoned) else {
        return;
    };
    block.flags.fetch_or(flag::WAITING, Ordering::SeqCst);
    let channel = Handle::<Channel>::borrowed(abi::Handle(block.channel.load(Ordering::Relaxed)));
    let _ = sys::notify(&channel, bit::WAKE);
}

/// Wakes up to `count` threads that wait on `word`, the highest level
/// first; returns how many. Never fails (relibc unwraps its result). With
/// no waiter in the bucket it makes no call of the kernel.
pub fn futex_wake(word: *const AtomicU32, count: u32) -> u32 {
    let address = word as usize;
    let bucket = bucket(address);
    if bucket.waiters.load(Ordering::SeqCst) == 0 || count == 0 {
        return 0;
    }
    let held = lock(bucket);
    let mut woken = 0;
    let mut cursor = held.bucket.head.load(Ordering::Relaxed);
    // SAFETY: the nodes of a held bucket are blocks of waiting threads.
    while let Some(block) = unsafe { cursor.as_ref() } {
        if woken == count {
            break;
        }
        cursor = block.next.load(Ordering::Relaxed) as *mut Block;
        if block.address.load(Ordering::Relaxed) != address {
            continue;
        }
        remove(&held, block);
        // Under the lock: once the waiter sees its node gone, nothing more
        // touches its channel.
        let channel =
            Handle::<Channel>::borrowed(abi::Handle(block.channel.load(Ordering::Relaxed)));
        let _ = sys::notify(&channel, bit::WAKE);
        woken += 1;
    }
    drop(held);
    woken
}

/// Whether the thread of `block` waits by address now (its node is linked).
pub fn waiting(block: &Block) -> bool {
    block.address.load(Ordering::Acquire) != 0
}

/// The bucket of `word`, for measurements that need two words of one.
pub fn bucket_of(word: *const AtomicU32) -> usize {
    let found = bucket(word as usize);
    TABLE
        .iter()
        .position(|b| ptr::eq(b, found))
        .expect("a bucket of the table")
}

/// The waiters counted in the bucket of `word`, for tests.
pub fn bucket_waiters(word: *const AtomicU32) -> u32 {
    bucket(word as usize).waiters.load(Ordering::SeqCst)
}

/// The lock of the layer (spec 2, 3.4): a word 0 (free), 1 (held), 2 (held,
/// with waiters) over the table, the holder in a critical section for as
/// long as it holds it.
pub struct LayerLock {
    word: AtomicU32,
    raise: bool,
}

impl LayerLock {
    /// A lock whose holder stays at its own level: no call of the kernel
    /// with no rival.
    pub const fn new() -> Self {
        LayerLock {
            word: AtomicU32::new(0),
            raise: false,
        }
    }

    /// A lock whose holder runs at the ceiling of the process from before
    /// it takes the word until after it lets it go, as the holder of the
    /// lock of a bucket (immediate ceiling): no application thread delays
    /// it. Two calls of the kernel a section, none for a thread already at
    /// the ceiling through another such lock.
    pub const fn raising() -> Self {
        LayerLock {
            word: AtomicU32::new(0),
            raise: true,
        }
    }

    pub fn lock(&self) -> LayerGuard<'_> {
        enter();
        let raised = self.raise && raise();
        if self
            .word
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.word.swap(2, Ordering::Acquire) != 0 {
                if futex_wait(&self.word, 2, CLOCK_MONOTONIC, None) == Err(EINVAL) {
                    let _ = sys::yield_now();
                }
            }
        }
        LayerGuard { lock: self, raised }
    }
}

/// The calling thread enters a raising lock: at the ceiling from the first.
fn raise() -> bool {
    let Some(block) = current() else {
        return false;
    };
    let ceiling = CEILING.load(Ordering::Relaxed);
    let old = block.flags.fetch_add(flag::RAISED_ONE, Ordering::SeqCst);
    debug_assert!(
        old & flag::RAISED_MASK != flag::RAISED_MASK,
        "raising locks nest too deep"
    );
    if old & flag::RAISED_MASK == 0 && ceiling != 0 {
        set_level(block, ceiling);
    }
    true
}

/// The calling thread leaves a raising lock: back to its base level after
/// the last.
fn lower() {
    let Some(block) = current() else {
        return;
    };
    let old = block.flags.fetch_sub(flag::RAISED_ONE, Ordering::SeqCst);
    debug_assert!(old & flag::RAISED_MASK != 0, "balanced raising locks");
    if old & flag::RAISED_MASK == flag::RAISED_ONE && CEILING.load(Ordering::Relaxed) != 0 {
        set_level(block, block.base_level.load(Ordering::Relaxed) as u8);
    }
}

impl Default for LayerLock {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LayerGuard<'a> {
    lock: &'a LayerLock,
    raised: bool,
}

impl Drop for LayerGuard<'_> {
    fn drop(&mut self) {
        if self.lock.word.swap(0, Ordering::Release) == 2 {
            futex_wake(&self.lock.word, 1);
        }
        if self.raised {
            lower();
        }
        leave();
    }
}
