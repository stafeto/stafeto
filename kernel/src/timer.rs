// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The timers of programs (spec 10); arch::timer is the kernel's own. A
//! timer is a source of notifications on a channel (spec 6.5): it lies in
//! the pool of timers of the process that made it, which pays for it by
//! the page (spec 7.8), counts it toward abi::MAX_TIMERS and holds its
//! shell until the timer's place goes back. It holds its channel with a
//! counted reference and one of the channel's slots, and its own slot of
//! the priority timer_create gave, with the label of the handle it was
//! made through. An armed timer stands in one binary heap for the whole
//! system, its node inside the timer (kcore::timer::Heap): arming and
//! cancelling take O(log n) and allocate nothing, and the earliest
//! deadline, O(1), joins the end of a quantum in the kernel's timer
//! (sched::decide). The kernel's timer interrupt takes the expired ones
//! off the heap before its EOI, at most BATCH of them (`expire`); each
//! posts bit 0 into its slot at the slot's priority. A timer lives while
//! references to it are left: its handles, the one `create` hands out, and
//! its slot's while the slot stands in the channel's queue. The last one
//! marks it dying and queues it (spec 7.7): a dying timer fires no more,
//! and its portion takes it off the heap and lets the channel and the
//! payer's shell go. The heap's lock and the scheduler's are never held
//! together: a post takes the scheduler's lock only once the heap's went.

use crate::arch::timer as clock;
use crate::channel::{self, Channel, Owner};
use crate::cleanup::{self, Item};
use crate::object::Object;
use crate::process::{self, Process};
use abi::{Error, Rights};
use core::ptr::NonNull;
use kcore::notify::Slot;
use kcore::sync::Lock;
use kcore::timer::{Heap, HeapLink, HeapNode};

/// Expired timers one interrupt takes, at most (spec 10): the rest waits
/// in the heap, and the next interrupt comes right after the EOI.
pub const BATCH: usize = 64;

/// The bits of an expiry (spec 6.5): bit 0, once.
const TIMER_BITS: u64 = 1;

pub struct Timer {
    /// Its node in the heap while it is armed, with the deadline in ticks.
    node: HeapLink<Timer>,
    /// The slot of its expiries.
    slot: Slot<Owner>,
    /// Its handles, the reference `create` hands out, and its slot's while
    /// the slot is queued: the references that keep it.
    refs: u32,
    /// The label of the handle it was made through (spec 5.3).
    label: u64,
    /// The channel, which it holds with a counted reference.
    channel: NonNull<Channel>,
    /// The process whose pool of timers holds it, and whose shell it
    /// holds.
    payer: NonNull<Process>,
    /// Its last reference went: it fires no more, and its portion takes it
    /// off the heap.
    dying: bool,
    /// Its place in the cleanup queue once nothing refers to it.
    cleanup: Item,
}

// SAFETY: timers are reached under the kernel's rules (spec 8.1): one CPU,
// interrupts masked inside the kernel.
unsafe impl Send for Timer {}

// SAFETY: the node is a field of the timer.
unsafe impl HeapNode for Timer {
    fn heap_link(this: NonNull<Timer>) -> NonNull<HeapLink<Timer>> {
        // SAFETY: `this` points at a live timer.
        unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).node) }
    }
}

/// The armed timers of the system, and the longest batch of expiries so
/// far in ticks, for KSTATS.
struct Timers {
    heap: Heap<Timer>,
    longest_batch: u64,
}

static TIMERS: Lock<Timers> = Lock::new(Timers {
    heap: Heap::new(),
    longest_batch: 0,
});

/// Timers whose places have not gone back (test builds).
#[cfg(feature = "ktest")]
static LIVE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// A timer of `payer`, the process of the thread that makes it, on `c`,
/// an open channel, whose slot has `priority` and `label`, as timer_create
/// checked them (spec 10): LIMIT_REACHED when the payer has
/// abi::MAX_TIMERS, then when the channel has no slot left (spec 6.5),
/// NO_MEMORY when the payer's quota falls short for a page of its pool of
/// timers (spec 7.8). The timer is not armed; it holds the channel and the
/// payer's shell. The caller gets the first reference.
pub fn create(
    payer: NonNull<Process>,
    c: NonNull<Channel>,
    label: u64,
    priority: u8,
) -> Result<NonNull<Timer>, Error> {
    process::timer_room(payer)?;
    channel::add_source(c)?;
    let timer = Timer {
        node: HeapLink::new(),
        // The owner is the timer's own place, known once it has one.
        slot: Slot::new(priority, Owner::Timer(NonNull::dangling())),
        refs: 1,
        label,
        channel: c,
        payer,
        dying: false,
        cleanup: Item::new(),
    };
    let t = process::timer_slot(payer, timer).inspect_err(|_| channel::remove_source(c))?;
    // SAFETY: the timer was just made, nothing else refers to it, and its
    // slot is in no queue.
    unsafe { (*t.as_ptr()).slot = Slot::new(priority, Owner::Timer(t)) };
    channel::retain(c, Rights::NONE);
    process::retain_shell(payer);
    #[cfg(feature = "ktest")]
    LIVE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Ok(t)
}

/// The count of references to `t`, through the raw pointer. Test builds
/// stop a timer that went: the poison of its place reaches the count.
///
/// # Safety
/// `t` is alive, and nothing else borrows the count.
unsafe fn refs<'a>(t: NonNull<Timer>) -> &'a mut u32 {
    // SAFETY: the caller's promise; only the field is borrowed.
    let refs = unsafe { &mut (*t.as_ptr()).refs };
    #[cfg(feature = "ktest")]
    assert!(
        *refs != u32::from_ne_bytes([POISON; 4]),
        "a timer is used after it went"
    );
    refs
}

/// The slot of `t`, which lives as long as the timer.
fn slot(t: NonNull<Timer>) -> NonNull<Slot<Owner>> {
    // SAFETY: the caller holds a reference to the timer, or the heap does;
    // only the field's address is taken.
    unsafe { NonNull::new_unchecked(&raw mut (*t.as_ptr()).slot) }
}

/// The label of `t`, which receive reports with its slot.
pub fn label(t: NonNull<Timer>) -> u64 {
    // SAFETY: the slot of the timer is being taken, and it holds the timer;
    // only the field is read.
    unsafe { (*t.as_ptr()).label }
}

/// Adds a reference to `t`: a new handle, or its slot's when the slot just
/// went into the channel's queue (channel::post), which holds the timer
/// until receive or the stage Close takes the slot (spec 6.5).
pub fn retain(t: NonNull<Timer>) {
    // SAFETY: the caller holds a reference to the timer; only the count is
    // touched.
    let refs = unsafe { refs(t) };
    assert!(*refs > 0, "a timer nobody refers to is retained");
    *refs = refs.checked_add(1).expect("timer references overflow");
}

/// Drops a reference to `t`. The last one marks the timer dying, so that
/// it fires no more, and queues it for cleanup at `cause` (spec 7.7); its
/// portion takes it off the heap. O(1).
///
/// # Safety
/// The reference is the caller's, and the caller does not use it
/// afterwards.
pub unsafe fn release(t: NonNull<Timer>, cause: u8) {
    // SAFETY: the caller's reference keeps the timer alive until here; the
    // pool keeps it in place until its portion.
    unsafe {
        let refs = refs(t);
        *refs = refs
            .checked_sub(1)
            .expect("a timer is released once too often");
        if *refs == 0 {
            let p = t.as_ptr();
            (*p).dying = true;
            let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
            cleanup::enqueue(item, Object::Timer(t), cause);
        }
    }
}

/// timer_set (spec 10) of `t`, which the caller's handle holds, for the
/// counter value `deadline`, which the call rounded up from nanoseconds:
/// PEER_CLOSED once the channel closed, and the timer stays as it was.
/// Otherwise an armed timer leaves the heap first; a deadline the counter
/// reached fires in the call, bit 0 into the slot at `cause`, the caller's
/// priority, and any other goes into the heap. O(log n).
pub fn set(t: NonNull<Timer>, deadline: u64, cause: u8) -> Result<(), Error> {
    // SAFETY: the caller's handle holds the timer, which holds its channel;
    // only the field is read.
    let c = unsafe { (*t.as_ptr()).channel };
    if channel::is_closed(c) {
        return Err(Error::PeerClosed);
    }
    let now = clock::now();
    {
        let mut g = TIMERS.lock();
        // SAFETY: the timer is alive; one in the heap stays in place until
        // it leaves, and its portion takes it out first.
        unsafe {
            if (*t.as_ptr()).node.is_linked() {
                g.heap.remove(t);
            }
            if deadline > now {
                g.heap.insert(t, deadline);
                return Ok(());
            }
        }
    }
    // SAFETY: the caller's handle holds the timer and so its channel; the
    // slot lives as long as the timer. The channel is open: a closed one
    // would only drop the post.
    let _ = unsafe { channel::post(c, slot(t), TIMER_BITS, cause) };
    Ok(())
}

/// timer_cancel (spec 10) of `t`, which the caller's handle holds: an
/// armed timer leaves the heap, and what it posted stays in its slot. A
/// timer that is not armed is left as it is. O(log n).
pub fn cancel(t: NonNull<Timer>) {
    let mut g = TIMERS.lock();
    // SAFETY: the timer is alive and, if linked, in this heap.
    unsafe {
        if (*t.as_ptr()).node.is_linked() {
            g.heap.remove(t);
        }
    }
}

/// The earliest deadline of an armed timer, in O(1), for the kernel's
/// timer (sched::decide).
pub fn first() -> Option<u64> {
    TIMERS.lock().heap.first()
}

/// The kernel's timer interrupt at `now`, before its EOI (sched::timer_fired):
/// the timers whose deadlines the counter reached leave the heap, the
/// earliest first, at most BATCH of them; each that is not dying posts bit
/// 0 into its slot at the slot's priority, the level of whatever the post
/// lets go (spec 7.7), a dying one nothing. The rest stays in the heap, and
/// the next decision arms the kernel's timer for a deadline already past,
/// so the next interrupt comes right after the EOI (spec 10). The heap's
/// lock goes before each post. The batch's time counts for KSTATS.
pub fn expire(now: u64) {
    let start = clock::now();
    let mut fired = 0;
    while fired < BATCH {
        let Some(t) = TIMERS.lock().heap.pop_expired(now) else {
            break;
        };
        fired += 1;
        // SAFETY: a timer off the heap is alive until its portion, which no
        // interrupt runs; a timer that is not dying holds its channel and
        // has a reference left.
        unsafe {
            if (*t.as_ptr()).dying {
                continue;
            }
            let priority = (*t.as_ptr()).slot.priority();
            let _ = channel::post((*t.as_ptr()).channel, slot(t), TIMER_BITS, priority);
        }
    }
    if fired > 0 {
        let took = clock::now().saturating_sub(start);
        let mut g = TIMERS.lock();
        g.longest_batch = g.longest_batch.max(took);
    }
}

/// The longest batch of expiries so far in ticks, for KSTATS (spec 16).
pub fn longest_batch() -> u64 {
    TIMERS.lock().longest_batch
}

/// The portion of a timer nothing refers to (cleanup::portion), at
/// `level`: it leaves the heap, if it is armed, gives its slot in the
/// channel back, its place goes back to the payer's pool, and then the
/// references to the channel and to the payer's shell go, each of which
/// may queue what it held at `level`. Its slot is in no queue: a queued
/// slot holds the timer. O(log n).
///
/// # Safety
/// Nothing refers to the timer, and it is in no queue.
pub unsafe fn clean(t: NonNull<Timer>, level: u8) {
    {
        let mut g = TIMERS.lock();
        // SAFETY: the caller's promise; the timer is in the heap if linked.
        unsafe {
            if (*t.as_ptr()).node.is_linked() {
                g.heap.remove(t);
            }
        }
    }
    // SAFETY: as above; only the fields are read.
    let (c, payer) = unsafe { ((*t.as_ptr()).channel, (*t.as_ptr()).payer) };
    assert!(
        // SAFETY: as above.
        !unsafe { (*t.as_ptr()).slot.is_queued() },
        "a timer goes while its slot is queued"
    );
    channel::remove_source(c);
    // SAFETY: nothing uses the timer afterwards; the payer's pool is there,
    // since the timer holds the payer's shell.
    unsafe { process::free_timer_slot(payer, t) };
    #[cfg(feature = "ktest")]
    LIVE.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    // Test builds poison the place past the pool's link, as for sessions:
    // `refs` stops a use after free.
    #[cfg(feature = "ktest")]
    // SAFETY: the place is the pool's again; its first word is the link.
    unsafe {
        core::ptr::write_bytes(
            t.cast::<u8>().as_ptr().add(8),
            POISON,
            core::mem::size_of::<Timer>() - 8,
        )
    };
    // SAFETY: the timer's references to its channel and to its payer's
    // shell go with it.
    unsafe {
        channel::release(c, Rights::NONE, level);
        process::release_shell(payer, level);
    }
}

/// What test builds fill a gone timer with, past the pool's link.
#[cfg(feature = "ktest")]
const POISON: u8 = 0xA5;

// The poison reaches `refs`, which `refs` checks.
#[cfg(feature = "ktest")]
const _: () = assert!(core::mem::offset_of!(Timer, refs) >= 8);

/// Timers whose places have not gone back.
#[cfg(feature = "ktest")]
pub fn in_use() -> usize {
    LIVE.load(core::sync::atomic::Ordering::Relaxed)
}

/// The deadline of `t`, which the test knows alive, in ticks while it is
/// armed.
#[cfg(feature = "ktest")]
pub fn deadline(t: NonNull<Timer>) -> Option<u64> {
    // SAFETY: the test knows the timer alive; only the node is read.
    let node = unsafe { &(*t.as_ptr()).node };
    node.is_linked().then(|| node.deadline())
}

/// Whether the slot of `t`, which is alive, stands in its channel's queue:
/// the timer posted, and nothing took the slot since.
#[cfg(feature = "ktest")]
pub fn posted(t: NonNull<Timer>) -> bool {
    // SAFETY: the test knows the timer alive; only the slot is read.
    unsafe { (*t.as_ptr()).slot.is_queued() }
}

/// The process that pays for `t`, which the test holds.
#[cfg(feature = "ktest")]
pub fn payer(t: NonNull<Timer>) -> NonNull<Process> {
    // SAFETY: the test holds a reference to the timer; only the field is
    // read.
    unsafe { (*t.as_ptr()).payer }
}

/// Forgets the longest batch, so that a test measures its own.
#[cfg(feature = "ktest")]
pub fn reset_longest_batch() {
    TIMERS.lock().longest_batch = 0;
}
