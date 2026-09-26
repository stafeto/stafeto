// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The timers of programs (spec 10); arch::timer is the kernel's own. A
//! timer is a source of notifications on a channel (spec 6.5): it lies in
//! the pool of timers of the process that made it, which pays for it by the
//! page (spec 7.8), counts it toward abi::MAX_TIMERS and holds its shell
//! until the timer's place goes back. It is a source of the channel
//! (channel::Source): it holds the channel with a counted reference and one
//! of the channel's slots, and its own slot of the priority timer_create
//! gave, with the label of the handle it was made through. An armed timer
//! stands in the heap of its level, the priority of its slot, its node
//! inside the timer (kcore::timer::Levels): arming and cancelling take
//! O(log n) and allocate nothing, and the nearest deadline of the levels
//! whose firing is not queued, O(1), joins the end of a quantum in the
//! kernel's timer (sched::decide). The kernel's timer interrupt takes no
//! timer off: each level whose top expired queues its own item of the
//! cleanup queue at that level (`expire`), and the item's portion takes up
//! to FIRE_PORTION expired timers of the level, each posting bit 0 into its
//! slot at that level (`fire`, spec 7.7, 10). A timer lives while
//! references to it are left: its handles, the one `create` hands out, and
//! its slot's while the slot stands in the channel's queue. The last one
//! marks it dying and queues it (spec 7.7): a dying timer fires no more,
//! and its portion takes it off its heap and lets the channel and the
//! payer's shell go. The lock of the levels and the scheduler's are never
//! held together: a post takes the scheduler's lock only once the lock of
//! the levels went.

use crate::arch::timer as clock;
use crate::channel::{self, Channel, Owner, Source};
use crate::cleanup::{self, Item, Work};
use crate::object::{Live, Object, Refs};
use crate::process::{self, Process};
use abi::Error;
use core::cell::UnsafeCell;
use core::ptr::NonNull;
use kcore::sync::Lock;
use kcore::timer::{Firing, HeapLink, HeapNode, LEVELS, Levels};

/// The bits of an expiry (spec 6.5): bit 0, once.
const TIMER_BITS: u64 = 1;

pub struct Timer {
    /// Its node in the heap while it is armed, with the deadline in ticks.
    node: HeapLink<Timer>,
    /// Its source of notifications: the slot of its expiries, the label of
    /// the handle it was made through (spec 5.3) and the channel.
    source: Source,
    /// Its handles, the reference `create` hands out, and its slot's while
    /// the slot is queued: the references that keep it.
    refs: Refs,
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

/// The armed timers of the system by level, and the longest portion of
/// firings so far in ticks, for KSTATS.
struct Timers {
    levels: Levels<Timer>,
    longest_firing: u64,
}

static TIMERS: Lock<Timers> = Lock::new(Timers {
    levels: Levels::new(),
    longest_firing: 0,
});

/// The items of the cleanup queue for the firings of levels 1-63, the
/// first for level 1. The item of a level is queued from the interrupt
/// that found its top expired until its last portion settles it: while
/// the level is pending (kcore::timer::Levels::expired).
struct Firings([UnsafeCell<Item>; LEVELS]);

// SAFETY: an item is reached only through the cleanup queue, under its
// lock, and by `expire` and `fire`, which queue it only while the level is
// not pending and from its own portion.
unsafe impl Sync for Firings {}

static FIRINGS: Firings = Firings([const { UnsafeCell::new(Item::new()) }; LEVELS]);

/// The item of the firings of `level`.
fn firing(level: u8) -> NonNull<Item> {
    let item = &FIRINGS.0[usize::from(level) - 1];
    // SAFETY: a static is never null.
    unsafe { NonNull::new_unchecked(item.get()) }
}

/// Timers whose places have not gone back.
static LIVE: Live = Live::new();

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
    channel::reserve_source(c)?;
    let timer = Timer {
        node: HeapLink::new(),
        source: Source::new(c),
        refs: Refs::one(),
        payer,
        dying: false,
        cleanup: Item::new(),
    };
    let t = process::paid_alloc(payer, timer).inspect_err(|_| channel::remove_source(c))?;
    // SAFETY: the timer was just made, and nothing else refers to it.
    unsafe {
        (*t.as_ptr())
            .source
            .attach(Owner::Timer(t), priority, label)
    };
    process::retain_shell(payer);
    LIVE.made();
    Ok(t)
}

/// The count of references to `t`, through the raw pointer.
///
/// # Safety
/// `t` is alive, and nothing else borrows the count.
#[must_use]
unsafe fn refs<'a>(t: NonNull<Timer>) -> &'a mut Refs {
    // SAFETY: the caller's promise; only the field is borrowed.
    unsafe { &mut (*t.as_ptr()).refs }
}

/// The source of `t`, which lives as long as the timer.
fn source(t: NonNull<Timer>) -> NonNull<Source> {
    // SAFETY: the caller holds a reference to the timer, or the heap does;
    // only the field's address is taken.
    unsafe { NonNull::new_unchecked(&raw mut (*t.as_ptr()).source) }
}

/// The level of `t`: the priority of its slot, which never changes.
fn level(t: NonNull<Timer>) -> u8 {
    // SAFETY: the caller holds a reference to the timer, or the heap does;
    // only the slot is read.
    unsafe { (*t.as_ptr()).source.priority() }
}

/// The label of `t`, which receive reports with its slot.
pub fn label(t: NonNull<Timer>) -> u64 {
    // SAFETY: the slot of the timer is being taken, and it holds the timer;
    // only the field is read.
    unsafe { (*t.as_ptr()).source.label() }
}

/// Adds a reference to `t`: a new handle, or its slot's when the slot just
/// went into the channel's queue (channel::post), which holds the timer
/// until receive or the stage Close takes the slot (spec 6.5).
pub fn retain(t: NonNull<Timer>) {
    // SAFETY: the caller holds a reference to the timer; only the count is
    // touched.
    unsafe { refs(t) }.retain();
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
        if refs(t).release() {
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
/// Otherwise an armed timer leaves the heap of its level first; a deadline
/// the counter reached fires in the call, bit 0 into the slot at `cause`,
/// the caller's priority, and any other goes into the heap. O(log n), and
/// up to 63 comparisons when the top of the level changes.
pub fn set(t: NonNull<Timer>, deadline: u64, cause: u8) -> Result<(), Error> {
    // SAFETY: the caller's handle holds the timer, which holds its channel;
    // only the field is read.
    let c = unsafe { (*t.as_ptr()).source.channel() };
    if channel::is_closed(c) {
        return Err(Error::PeerClosed);
    }
    let now = clock::now();
    let level = level(t);
    {
        let mut g = TIMERS.lock();
        // SAFETY: the timer is alive; one in the heap of its level stays in
        // place until it leaves, and its portion takes it out first.
        unsafe {
            if (*t.as_ptr()).node.is_linked() {
                g.levels.remove(level, t);
            }
            if deadline > now {
                g.levels.insert(level, t, deadline);
                return Ok(());
            }
        }
    }
    // SAFETY: the caller's handle holds the timer, which is attached; the
    // slot lives as long as the timer. The channel is open: a closed one
    // would only drop the post.
    let _ = unsafe { Source::post(source(t), TIMER_BITS, cause) };
    Ok(())
}

/// timer_cancel (spec 10) of `t`, which the caller's handle holds: an
/// armed timer leaves the heap of its level, and what it posted stays in
/// its slot. A timer that is not armed is left as it is. O(log n), and up
/// to 63 comparisons when the top of the level changes.
pub fn cancel(t: NonNull<Timer>) {
    let level = level(t);
    let mut g = TIMERS.lock();
    // SAFETY: the timer is alive and, if linked, in the heap of its level.
    unsafe {
        if (*t.as_ptr()).node.is_linked() {
            g.levels.remove(level, t);
        }
    }
}

/// The nearest deadline of the levels whose firing is not queued, in O(1),
/// for the kernel's timer (sched::decide, spec 8).
pub fn first() -> Option<u64> {
    TIMERS.lock().levels.nearest()
}

/// The kernel's timer interrupt at `now`, before its EOI
/// (sched::timer_fired): each level whose top expired and whose firing is
/// not queued yet queues its item at the tail of that level of the cleanup
/// queue (spec 7.7, 10). No timer leaves a heap here, and the nearest
/// deadline leaves those levels out until their firing settles. Up to 63
/// levels.
pub fn expire(now: u64) {
    let mut due = TIMERS.lock().levels.expired(now);
    while due != 0 {
        let level = due.trailing_zeros() as u8;
        due &= due - 1;
        // SAFETY: the level was not pending, so its item is in no queue.
        unsafe { cleanup::enqueue(firing(level), Work::Timers, level) };
    }
}

/// The portion of the firing of `level` (cleanup::portion): `fire_at`
/// with the counter read once, as the portion begins.
pub fn fire(level: u8) {
    fire_at(level, clock::now());
}

/// The portion of the firing of `level` at `now`: up to
/// kcore::timer::FIRE_PORTION timers of the level whose deadlines are not
/// after `now` leave its heap, the earliest first; each that is not dying
/// posts bit 0 into its slot at `level`, its slot's priority, which is the
/// level of whatever the post lets go (spec 7.7); a dying one nothing. The
/// lock of the levels goes before each post. With timers left that
/// expired by `now`, the item goes back to the head of the level, and the
/// next portion takes them and those that expired meanwhile; otherwise the
/// level settles, and its next top counts for the kernel's timer again.
/// The portion's time counts for KSTATS. O(FIRE_PORTION log n). The
/// level's item is in no queue: its portion took it out, or the level is
/// not pending.
pub fn fire_at(level: u8, now: u64) {
    let start = clock::now();
    let mut step = Firing::new(level);
    loop {
        let next = step.next(&mut TIMERS.lock().levels, now);
        let Some(t) = next else {
            break;
        };
        // SAFETY: a timer off its heap is alive until its portion, which
        // needs a reference gone and no queue; a timer that is not dying
        // holds its channel and has a reference left.
        unsafe {
            if (*t.as_ptr()).dying {
                continue;
            }
            let _ = Source::post(source(t), TIMER_BITS, level);
        }
    }
    let more = {
        let mut g = TIMERS.lock();
        let more = step.finish(&mut g.levels, now);
        let took = clock::now().saturating_sub(start);
        g.longest_firing = g.longest_firing.max(took);
        more
    };
    if more {
        // SAFETY: the level's item is in no queue, by the contract of
        // this function.
        unsafe { cleanup::requeue(firing(level), Work::Timers, level) };
    }
}

/// The longest portion of firings so far in ticks, for KSTATS (spec 16).
pub fn longest_firing() -> u64 {
    TIMERS.lock().longest_firing
}

/// The portion of a timer nothing refers to (cleanup::portion), at
/// `level`: it leaves its heap, if it is armed, its source goes, which
/// gives its slot in the channel back and lets the channel go
/// (Source::detach), its place goes back to the payer's pool, and then the
/// reference to the payer's shell goes; each may queue what it held at
/// `level`. Its slot is in no queue: a queued slot holds the timer.
/// O(log n).
///
/// # Safety
/// Nothing refers to the timer, and it is in no queue.
pub unsafe fn clean(t: NonNull<Timer>, level: u8) {
    {
        let own = self::level(t);
        let mut g = TIMERS.lock();
        // SAFETY: the caller's promise; the timer is in the heap of its
        // level if linked.
        unsafe {
            if (*t.as_ptr()).node.is_linked() {
                g.levels.remove(own, t);
            }
        }
    }
    // SAFETY: as above; nothing uses the timer afterwards; the payer's
    // pool is there, since the timer holds the payer's shell, whose
    // reference goes last.
    unsafe {
        let payer = (*t.as_ptr()).payer;
        (*t.as_ptr()).source.detach(level);
        process::paid_free(payer, t);
        LIVE.gone(t);
        process::release_shell(payer, level);
    }
}

// The poison of a timer that went (Live::gone) reaches its count.
const _: () = assert!(core::mem::offset_of!(Timer, refs) >= 8);

#[cfg(feature = "ktest")]
pub use test_access::{deadline, in_use, payer, posted, reset_longest_firing};

/// What the kernel tests read and steer here (crate::ktest).
#[cfg(feature = "ktest")]
mod test_access {
    use super::*;

    /// Timers whose places have not gone back.
    pub fn in_use() -> usize {
        LIVE.count()
    }

    /// The deadline of `t`, which the test knows alive, in ticks while it is
    /// armed.
    pub fn deadline(t: NonNull<Timer>) -> Option<u64> {
        // SAFETY: the test knows the timer alive; only the node is read.
        let node = unsafe { &(*t.as_ptr()).node };
        node.is_linked().then(|| node.deadline())
    }

    /// Whether the slot of `t`, which is alive, stands in its channel's queue:
    /// the timer posted, and nothing took the slot since.
    pub fn posted(t: NonNull<Timer>) -> bool {
        // SAFETY: the test knows the timer alive; only the slot is read.
        unsafe { (*t.as_ptr()).source.is_queued() }
    }

    /// The process that pays for `t`, which the test holds.
    pub fn payer(t: NonNull<Timer>) -> NonNull<Process> {
        // SAFETY: the test holds a reference to the timer; only the field is
        // read.
        unsafe { (*t.as_ptr()).payer }
    }

    /// Forgets the longest portion of firings, so that a test measures its
    /// own.
    pub fn reset_longest_firing() {
        TIMERS.lock().longest_firing = 0;
    }
}
