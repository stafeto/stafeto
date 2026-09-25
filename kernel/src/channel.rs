// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Channels (spec 4, 6.1, 6.3, 6.5, 6.8) as milestone 1.3b has them:
//! notifications and the threads that wait for them in `receive`; requests
//! come in milestone 1.3c. A channel lies in the pool of channels of the
//! process that made it, which pays for it by the page (spec 7.8), and
//! holds that process's shell until its slot goes back. It has the slot of
//! label 0, whose priority channel_create gave, and the queues of
//! kcore::notify: slots with something posted and receivers that wait,
//! each by priority and in the order they came. The queue of receivers
//! links threads through the scheduler's own links, so every change to the
//! queues happens under the scheduler's lock (sched::locked). A channel
//! lives while references to it are left: handles with any rights, threads
//! that wait in it, the sources of notifications that have a slot there
//! (sessions and exits of processes), and the cleanup queue's while it
//! closes; the last one queues its shell (spec 7.7). Every source holds
//! one of its abi::MAX_SLOTS slots, the slot of label 0 among them, from
//! its creation until it goes, and a slot that stands in the queue holds
//! its owner until receive or the stage Close takes it (spec 6.5). The last
//! handle with RECEIVE closes it in the call itself: `notify` fails with
//! PEER_CLOSED from then on, nothing new waits or is queued, and the stage
//! Close wakes the receivers that wait with PEER_CLOSED and empties the
//! queued slots, letting their owners go, CLOSE_PORTION a portion.

use crate::cleanup::{self, Item};
use crate::object::Object;
use crate::process::{self, Process};
use crate::session::{self, Session};
use crate::thread::Thread;
use crate::{sched, syscall};
use abi::{Error, MAX_SLOTS, Notification, Rights, Source};
use core::ptr::NonNull;
use kcore::notify::{Post, Queue, Slot};
use kcore::sched::Scheduler;

/// Heads a portion of the stage Close takes, at most: receivers that wait
/// first, then queued slots (spec 7.7).
const CLOSE_PORTION: usize = 64;

/// Whose slot it is (spec 6.5), which gives the source and the label that
/// `receive` reports. The slot of label 0 is the channel's own; the slot of
/// any other source lies in its owner, which a queued slot holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// The channel: `notify` through a handle with no label.
    Channel,
    /// A session: `notify` through a handle with its label, and
    /// CLIENT_GONE (spec 5.3).
    Session(NonNull<Session>),
    /// The end of a process, whose shell holds the slot (spec 7.9).
    Exit(NonNull<Process>),
}

impl Owner {
    fn source(self) -> Source {
        match self {
            Owner::Channel => Source::Unlabeled,
            Owner::Session(_) => Source::Session,
            Owner::Exit(_) => Source::Exit,
        }
    }

    fn label(self) -> u64 {
        match self {
            Owner::Channel => 0,
            Owner::Session(s) => session::label(s),
            Owner::Exit(p) => process::exit_label(p),
        }
    }

    /// The slot just went into the queue, and it holds its owner from now
    /// on (spec 6.5); the channel holds its own slot. Only counts, so it
    /// runs under the scheduler's lock.
    fn hold(self) {
        match self {
            Owner::Channel => {}
            Owner::Session(s) => session::hold(s),
            Owner::Exit(p) => process::retain_shell(p),
        }
    }

    /// The slot left the queue: receive or the stage Close took it, and
    /// the reference `hold` took goes at `cause`, which may queue the owner.
    ///
    /// # Safety
    /// `hold` took the reference, and the slot is in no queue.
    unsafe fn let_go(self, cause: u8) {
        match self {
            Owner::Channel => {}
            // SAFETY: the caller's promise.
            Owner::Session(s) => unsafe { session::unref(s, cause) },
            // SAFETY: as above.
            Owner::Exit(p) => unsafe { process::release_shell(p, cause) },
        }
    }
}

pub struct Channel {
    /// The slot of label 0.
    slot: Slot<Owner>,
    /// Slots with something posted and receivers that wait; reached only
    /// with the scheduler locked (`queue`).
    queue: Queue<Owner, Thread>,
    /// Handles to it with RECEIVE; the last one to go closes it.
    receivers: u32,
    /// Handles to it, threads that wait in it, the sources that have a
    /// slot in it, and the cleanup queue's while it is at its stage Close:
    /// the references that keep it.
    refs: u32,
    /// Sources with a slot in it, the slot of label 0 among them: at most
    /// abi::MAX_SLOTS (spec 6.5).
    sources: u32,
    /// No handle with RECEIVE is left (spec 6.8).
    closed: bool,
    /// The process whose pool of channels holds it, and whose shell it
    /// holds.
    payer: NonNull<Process>,
    /// Its place in the cleanup queue: at the stage Close with a reference
    /// of the queue's own, and as a shell once nothing refers to it.
    cleanup: Item,
}

// SAFETY: channels are reached under the kernel's rules (spec 8.1): one
// CPU, interrupts masked inside the kernel.
unsafe impl Send for Channel {}

/// Channels whose slots have not gone back (test builds).
#[cfg(feature = "ktest")]
static LIVE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Portions of the stage Close so far, the most heads one took, and the
/// levels they ran at, a bit each (test builds).
#[cfg(feature = "ktest")]
static CLOSE_PORTIONS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "ktest")]
static CLOSE_HEADS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "ktest")]
static CLOSE_LEVELS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// A channel of `payer`, the process of the thread that makes it, whose
/// slot of label 0 has `priority`: 1-63 and no higher than the payer's
/// ceiling, as the call checked. The caller gets the first reference. The
/// channel takes a slot in the payer's pool of channels, whose quota pays
/// for a page when the pool grows (spec 7.8), and holds the payer's shell.
/// NO_MEMORY when the quota falls short.
pub fn create(payer: NonNull<Process>, priority: u8) -> Result<NonNull<Channel>, Error> {
    let channel = Channel {
        slot: Slot::new(priority, Owner::Channel),
        queue: Queue::new(),
        receivers: 0,
        refs: 1,
        sources: 1,
        closed: false,
        payer,
        cleanup: Item::new(),
    };
    let c = process::channel_slot(payer, channel)?;
    process::retain_shell(payer);
    #[cfg(feature = "ktest")]
    LIVE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Ok(c)
}

/// The count of references to `c`, through the raw pointer. Test builds
/// stop a channel that went: the poison of its slot reaches the count.
///
/// # Safety
/// `c` is alive, and nothing else borrows the count.
unsafe fn refs<'a>(c: NonNull<Channel>) -> &'a mut u32 {
    // SAFETY: the caller's promise; only the field is borrowed.
    let refs = unsafe { &mut (*c.as_ptr()).refs };
    #[cfg(feature = "ktest")]
    assert!(
        *refs != u32::from_ne_bytes([POISON; 4]),
        "a channel is used after it went"
    );
    refs
}

/// The queues of `c`, which hold threads through the scheduler's links:
/// reached only with the scheduler locked, which `_locked` shows
/// (sched::locked).
///
/// # Safety
/// `c` is alive.
unsafe fn queue(c: NonNull<Channel>, _locked: &mut Scheduler<Thread>) -> &mut Queue<Owner, Thread> {
    // SAFETY: the caller's promise; only the field is borrowed.
    unsafe { &mut (*c.as_ptr()).queue }
}

/// Adds the reference of a new handle with `rights`, or of a thread that
/// waits (no rights). A handle with RECEIVE counts toward those whose last
/// one closes the channel, and a closed channel takes none.
pub fn retain(c: NonNull<Channel>, rights: Rights) {
    // SAFETY: the caller holds a reference, so the channel is alive; only
    // the fields are touched.
    unsafe {
        let refs = refs(c);
        assert!(*refs > 0, "a channel nobody refers to is retained");
        *refs = refs.checked_add(1).expect("channel references overflow");
        if rights.contains(Rights::RECEIVE) {
            let p = c.as_ptr();
            assert!(!(*p).closed, "a handle with RECEIVE to a closed channel");
            (*p).receivers += 1;
        }
    }
}

/// Drops a reference that had `rights`: the last handle with RECEIVE
/// closes the channel (`close`), and the last reference queues its shell
/// for cleanup at `cause` (spec 7.7). Nothing is taken apart here.
///
/// # Safety
/// The reference is the caller's, and the caller does not use it
/// afterwards.
pub unsafe fn release(c: NonNull<Channel>, rights: Rights, cause: u8) {
    let p = c.as_ptr();
    // SAFETY: the caller's reference keeps the channel alive until here;
    // only the fields are touched.
    unsafe {
        if rights.contains(Rights::RECEIVE) {
            (*p).receivers = (*p)
                .receivers
                .checked_sub(1)
                .expect("a handle with RECEIVE is released once too often");
            if (*p).receivers == 0 {
                close(c, cause);
            }
        }
        let refs = refs(c);
        *refs = refs
            .checked_sub(1)
            .expect("a channel is released once too often");
        if *refs == 0 {
            let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
            cleanup::enqueue(item, Object::Channel(c), cause);
        }
    }
}

/// Whether the last handle with RECEIVE to `c`, which the caller holds,
/// went (spec 6.8).
pub fn is_closed(c: NonNull<Channel>) -> bool {
    // SAFETY: the caller holds a reference to the channel; only the field
    // is read.
    unsafe { (*c.as_ptr()).closed }
}

/// A new source of notifications takes one of the slots of `c`, which the
/// caller holds (spec 6.5): LIMIT_REACHED when abi::MAX_SLOTS are taken,
/// the slot of label 0 among them. The source gives it back as it goes
/// (`remove_source`).
pub fn add_source(c: NonNull<Channel>) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the channel; only the field
    // is touched.
    let sources = unsafe { &mut (*c.as_ptr()).sources };
    if *sources >= MAX_SLOTS {
        return Err(Error::LimitReached);
    }
    *sources += 1;
    Ok(())
}

/// A source of `c` goes, or was not made, and gives its slot back.
pub fn remove_source(c: NonNull<Channel>) {
    // SAFETY: the source holds the channel; only the field is touched.
    let sources = unsafe { &mut (*c.as_ptr()).sources };
    *sources = sources
        .checked_sub(1)
        .filter(|&n| n > 0)
        .expect("a source gave back a slot it did not take");
}

/// The last handle with RECEIVE went (spec 6.1, 6.8): the channel is closed
/// from now on. With receivers that wait or slots queued it goes to the
/// cleanup queue at `cause`, with a reference of the queue's own, for its
/// stage Close. O(1).
///
/// # Safety
/// The caller holds a reference to `c`.
unsafe fn close(c: NonNull<Channel>, cause: u8) {
    let p = c.as_ptr();
    // SAFETY: the caller's reference keeps the channel alive; only the
    // fields are touched.
    unsafe {
        (*p).closed = true;
        if sched::locked(|s| queue(c, s).is_empty()) {
            return;
        }
        let refs = refs(c);
        *refs = refs.checked_add(1).expect("channel references overflow");
        let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
        cleanup::enqueue(item, Object::Channel(c), cause);
    }
}

/// What `receive` reports for `slot`, which just left the queue: its bits
/// and count, the slot empty again, with its owner's source and label, and
/// the slot's priority.
///
/// # Safety
/// `slot` is alive and in no queue.
unsafe fn notice(slot: NonNull<Slot<Owner>>) -> (Notification, u8) {
    // SAFETY: the caller's promise.
    let s = unsafe { &mut *slot.as_ptr() };
    let (bits, count) = s.take();
    let owner = s.owner();
    let n = Notification {
        source: owner.source(),
        label: owner.label(),
        bits,
        count,
    };
    (n, s.priority())
}

/// The ceiling of the process of `t`, which a boost never passes (spec 8).
fn ceiling(t: NonNull<Thread>) -> u8 {
    // SAFETY: the thread is alive and holds its process.
    unsafe { t.as_ref().process().as_ref() }.ceiling()
}

/// notify (spec 6.5): `bits` into the slot of label 0 of `c`; `cause`, the
/// notifier's priority, is the level of the cleanup a reference let go
/// here may start. PEER_CLOSED once the channel closed. O(1).
pub fn notify(c: NonNull<Channel>, bits: u64, cause: u8) -> Result<(), Error> {
    let p = c.as_ptr();
    // SAFETY: the caller's handle keeps the channel alive; the slot of
    // label 0 lives as long as the channel.
    unsafe { post(c, NonNull::new_unchecked(&raw mut (*p).slot), bits, cause) }
}

/// A post of `bits` into `slot`, one of the slots of `c` (spec 6.5):
/// PEER_CLOSED once the channel closed, and nothing is posted then: each
/// source of notifications comes here, so none posts into a closed
/// channel, and a source that is no call drops that error. Otherwise the
/// bits merge. A slot that stood in no queue goes to the top receiver that
/// waits, which takes it at once: its registers get the notification, it
/// works at the slot's priority under its ceiling, it becomes ready at the
/// tail of that level with a new quantum (spec 6.1), and the reference of
/// its wait goes. Otherwise the slot goes to the tail of its level in the
/// queue of slots and holds its owner there. It takes the scheduler's lock
/// itself. O(1).
///
/// # Safety
/// The caller holds a reference to `c` and to the owner of `slot`, which
/// lives as long as the owner.
pub unsafe fn post(
    c: NonNull<Channel>,
    slot: NonNull<Slot<Owner>>,
    bits: u64,
    cause: u8,
) -> Result<(), Error> {
    if is_closed(c) {
        return Err(Error::PeerClosed);
    }
    let woke = sched::locked(|s| {
        // SAFETY: the caller's promise; the slot stays in place.
        let t = match unsafe { queue(c, s).post(slot, bits) } {
            Post::Merged => return false,
            Post::Queued => {
                // SAFETY: as above.
                unsafe { (*slot.as_ptr()).owner() }.hold();
                return false;
            }
            Post::Deliver(t) => t,
        };
        // SAFETY: the slot left no queue; `t` left the queue of receivers
        // and is alive, since the kernel's reference keeps a thread that
        // waits.
        unsafe {
            let (n, priority) = notice(slot);
            (*t.as_ptr()).waits = None;
            syscall::set_notification(t, n);
            s.boost(t, priority, ceiling(t));
            s.wake(t);
        }
        true
    });
    if woke {
        // SAFETY: the reference was the wait's; the caller's keeps the
        // channel.
        unsafe { release(c, Rights::NONE, cause) };
    }
    Ok(())
}

/// receive (spec 6.1, 6.5, 6.6) for `t`, the running thread, on `c`, to
/// which it holds a handle with RECEIVE, so the channel is open. First the
/// boost of `t`'s last notification ends. Then the head of the top level of
/// the queue of slots leaves the queue, emptied, and `t` works at the
/// slot's priority under its ceiling until its next receive; the slot lets
/// its owner go at that priority, after the scheduler's lock: Some. With no
/// slot queued, WOULD_BLOCK when `wait` is false; otherwise `t` waits at the
/// tail of its level of the receivers, holding a reference to `c`, and
/// gets its result when the wait ends (`post`, `clean`): None. O(1).
pub fn receive(
    t: NonNull<Thread>,
    c: NonNull<Channel>,
    wait: bool,
) -> Result<Option<Notification>, Error> {
    let ceiling = ceiling(t);
    let taken = sched::locked(|s| {
        // SAFETY: the running thread and the channel, which its handle
        // holds, are alive.
        unsafe {
            s.unboost(t);
            if let Some(slot) = queue(c, s).take_slot() {
                let (n, priority) = notice(slot);
                s.boost(t, priority, ceiling);
                return Ok(Some((n, (*slot.as_ptr()).owner())));
            }
            if !wait {
                return Err(Error::WouldBlock);
            }
            let running = s.block();
            assert!(running == t, "a thread that does not run waits");
            queue(c, s).wait(t);
            (*t.as_ptr()).waits = Some(c);
        }
        retain(c, Rights::NONE);
        Ok(None)
    })?;
    let Some((n, owner)) = taken else {
        return Ok(None);
    };
    // SAFETY: the slot left the queue, whose reference to its owner goes;
    // the running thread is alive.
    unsafe { owner.let_go(t.as_ref().priority()) };
    Ok(Some(n))
}

/// The end of `t` while it waits in a channel (sched::exit, spec 7.7): it
/// leaves the channel's queue of receivers, wherever it stands there, and
/// the reference of its wait goes to the caller, which lets it go once the
/// scheduler has let the thread go. None for a thread that waits nowhere.
/// O(1).
///
/// # Safety
/// `t` is alive; `locked` is the locked scheduler.
pub unsafe fn cancel(
    t: NonNull<Thread>,
    locked: &mut Scheduler<Thread>,
) -> Option<NonNull<Channel>> {
    // SAFETY: the caller's promise; a thread that waits holds its channel.
    unsafe {
        let c = (*t.as_ptr()).waits.take()?;
        queue(c, locked).cancel(t);
        Some(c)
    }
}

/// thread_set_priority of `t` (sched::set_priority): a thread that waits
/// in a channel moves in its queue of receivers to the level its new
/// priority makes (spec 6.1). O(1).
///
/// # Safety
/// As for `cancel`.
pub unsafe fn requeue(t: NonNull<Thread>, locked: &mut Scheduler<Thread>) {
    // SAFETY: the caller's promise; a thread that waits holds its channel.
    unsafe {
        if let Some(c) = (*t.as_ptr()).waits {
            queue(c, locked).requeue(t);
        }
    }
}

/// One portion of a channel in the cleanup queue (cleanup::portion), taken
/// at `level`. At the stage Close, while the queue's reference holds it: up
/// to CLOSE_PORTION heads leave the queues, receivers that wait first, each
/// woken with PEER_CLOSED at the tail of its level with a new quantum
/// (spec 6.1, 6.8) and without the reference of its wait, then slots,
/// emptied, each letting its owner go at `level` (a session whose copies
/// went goes, as after receive); a head a time under the scheduler's lock,
/// its owner after it. With heads left the channel goes back to the head
/// of `level`, and otherwise the queue's reference goes, which queues the
/// shell when it was the last. With no reference left, the shell's
/// portion: the slot goes back to the payer's pool, and then the reference
/// to the payer's shell.
///
/// # Safety
/// The channel was just taken from the queue.
pub unsafe fn clean(c: NonNull<Channel>, level: u8) {
    // SAFETY: the caller's promise: the queue's reference keeps the channel
    // at its stage Close, and nothing refers to a shell.
    if unsafe { *refs(c) } == 0 {
        // SAFETY: as above.
        unsafe { free(c, level) };
        return;
    }
    let mut woken = 0u32;
    let mut heads = 0u32;
    for _ in 0..CLOSE_PORTION {
        let head = sched::locked(|s| {
            // SAFETY: the channel is alive; a thread that waits is alive,
            // and a queued slot holds its owner, in which it lies.
            unsafe {
                if let Some(t) = queue(c, s).take_waiter() {
                    (*t.as_ptr()).waits = None;
                    syscall::set_result(t, Err(Error::PeerClosed));
                    s.wake(t);
                    return Some(None);
                }
                queue(c, s).take_slot().map(|slot| {
                    (*slot.as_ptr()).take();
                    Some((*slot.as_ptr()).owner())
                })
            }
        });
        match head {
            None => break,
            Some(None) => woken += 1,
            // SAFETY: the slot left the queue, whose reference to its
            // owner goes.
            Some(Some(owner)) => unsafe { owner.let_go(level) },
        }
        heads += 1;
    }
    // SAFETY: as above.
    let left = sched::locked(|s| unsafe { !queue(c, s).is_empty() });
    #[cfg(feature = "ktest")]
    {
        use core::sync::atomic::Ordering::Relaxed;
        CLOSE_PORTIONS.fetch_add(1, Relaxed);
        CLOSE_HEADS.fetch_max(heads, Relaxed);
        CLOSE_LEVELS.fetch_or(1 << level, Relaxed);
    }
    #[cfg(not(feature = "ktest"))]
    let _ = heads;
    // SAFETY: the references of the waits go; the queue's keeps the
    // channel, and then goes itself once nothing is left.
    unsafe {
        let refs = refs(c);
        *refs = refs
            .checked_sub(woken)
            .filter(|&n| n > 0)
            .expect("the queue's reference to a closing channel went");
        if left {
            let item = NonNull::new_unchecked(&raw mut (*c.as_ptr()).cleanup);
            cleanup::requeue(item, Object::Channel(c), level);
        } else {
            release(c, Rights::NONE, level);
        }
    }
}

/// A channel's shell portion: its slot goes back to the pool it came from,
/// the payer's, and then the reference to the payer's shell, which queues
/// that shell at `level` if it was the last. The queues are empty by now,
/// and no source but the slot of label 0 is left: a thread that waits,
/// the stage Close and every source hold references.
///
/// # Safety
/// Nothing refers to the channel, and it is in no queue.
unsafe fn free(c: NonNull<Channel>, level: u8) {
    // SAFETY: the caller's promise; only the fields are read.
    let (payer, sources) = unsafe { ((*c.as_ptr()).payer, (*c.as_ptr()).sources) };
    assert!(
        // SAFETY: as above.
        sources == 1 && sched::locked(|s| unsafe { queue(c, s).is_empty() }),
        "a channel goes with a source or something in its queues"
    );
    // SAFETY: nothing uses the channel afterwards; the payer's pool is
    // there, since the channel holds the payer's shell.
    unsafe { process::free_channel_slot(payer, c) };
    #[cfg(feature = "ktest")]
    LIVE.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    // Test builds poison the slot past the pool's link, as for threads:
    // `refs` stops a use after free.
    #[cfg(feature = "ktest")]
    // SAFETY: the slot is the pool's again; its first word is the link.
    unsafe {
        core::ptr::write_bytes(
            c.cast::<u8>().as_ptr().add(8),
            POISON,
            core::mem::size_of::<Channel>() - 8,
        )
    };
    // SAFETY: the channel's reference to its payer's shell goes with it.
    unsafe { process::release_shell(payer, level) };
}

/// What test builds fill a gone channel with, past the pool's link.
#[cfg(feature = "ktest")]
const POISON: u8 = 0xA5;

// The poison reaches `refs`, which `refs` checks.
#[cfg(feature = "ktest")]
const _: () = assert!(core::mem::offset_of!(Channel, refs) >= 8);

/// Channels whose slots have not gone back.
#[cfg(feature = "ktest")]
pub fn in_use() -> usize {
    LIVE.load(core::sync::atomic::Ordering::Relaxed)
}

/// Portions of the stage Close since the last call, the most heads one
/// took, and the levels they ran at.
#[cfg(feature = "ktest")]
pub fn take_close_portions() -> (u32, u32, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    (
        CLOSE_PORTIONS.swap(0, Relaxed),
        CLOSE_HEADS.swap(0, Relaxed),
        CLOSE_LEVELS.swap(0, Relaxed),
    )
}

/// The process that pays for `c`, which the test holds.
#[cfg(feature = "ktest")]
pub fn payer(c: NonNull<Channel>) -> NonNull<Process> {
    // SAFETY: the test holds a reference to the channel; only the field is
    // read.
    unsafe { (*c.as_ptr()).payer }
}
