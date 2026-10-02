// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Channels (spec 4, 6.1, 6.3, 6.5, 6.8): notifications, requests and their
//! replies, and the threads that wait for them. A channel lies in the pool
//! of channels of the process that made it, which pays for it by the page
//! (spec 7.8), and holds that process's shell until its slot goes back. It
//! has the slot of label 0, whose priority channel_create gave, and the
//! queue of kcore::notify: slots with something posted and the requests of
//! threads that wait in `send`, or receivers that wait, by priority and in
//! the order they came. A thread waits through its own slot, which is its
//! request in `send`; a request a receiver took waits for its reply in the
//! queue of accepted requests of the receiver's process
//! (process::accepted), and a token of the table of thread numbers names it
//! (spec 6.1). The handles of a message move from the sender's table into
//! the receiver's with their references; a request that waits in a queue
//! carries them (Thread::transit). The queues change together with the
//! states of the threads in them, so every change to them happens under the
//! scheduler's lock (sched::locked). A channel lives while references to it
//! are left: handles with any rights, threads that wait in it, the sources
//! of notifications that have a slot there (sessions, exits of processes,
//! timers and interrupt bindings, each through its `Source`), and the
//! cleanup queue's while it closes; the last one queues its shell (spec
//! 7.7). Every source holds one of its abi::MAX_SLOTS slots, the slot of
//! label 0 among them, from its creation until it goes, and a slot that
//! stands in the queue holds its owner until receive or the stage Close
//! takes it (spec 6.5). The last handle with RECEIVE closes it in the call
//! itself: `notify` and `send` fail with PEER_CLOSED from then on, nothing
//! new waits or is queued, and the stage Close wakes the threads that wait
//! with PEER_CLOSED or empties the queued slots, letting their owners go,
//! CLOSE_PORTION heads of one level a portion, at the level of its top
//! waiter when that is above the cause (spec 7.7). A request a receiver
//! took lives on without the channel.

use crate::cleanup::{self, Item};
use crate::irq::{self, Irq};
use crate::object::{self, Live, Object, Refs};
use crate::process::{self, Process};
use crate::sched::{self, Locked};
use crate::session::{self, Session};
use crate::syscall;
use crate::thread::{self, Thread};
use crate::timer::{self, Timer};
use crate::{arch, testpoint};
use abi::{ChannelInfo, Error, INLINE_MAX, MAX_SLOTS, Notification, Rights};
use core::ptr::NonNull;
use kcore::args::{Desc, mask_tail};
use kcore::notify::{Post, Queue, Slot};
use kcore::sched::Scheduler;

mod message;
mod source;

pub use message::{Via, Wait, cancel, raise, receive, reply, requeue, send, withdraw};
pub use source::{Owner, Source, notify};

/// The work a portion of the stage Close does, at most (spec 7.7): each
/// head of one level, a thread that waits or a queued slot, is a unit, and
/// each handle a sender's request carries one more; the head that reaches
/// it is the portion's last.
const CLOSE_PORTION: usize = 32;

pub struct Channel {
    /// The slot of label 0.
    slot: Slot<Owner>,
    /// Slots with something posted and requests, or receivers that wait;
    /// reached only with the scheduler locked (`queue`).
    queue: Queue<Owner>,
    /// Handles to it with RECEIVE; the last one to go closes it.
    receivers: u32,
    /// Handles to it, threads that wait in it (in receive, or in send
    /// through a handle with no label), the sources that have a slot in it,
    /// and the cleanup queue's while it is at its stage Close: the
    /// references that keep it.
    refs: Refs,
    /// Sources with a slot in it, the slot of label 0 among them: at most
    /// abi::MAX_SLOTS (spec 6.5).
    sources: u32,
    /// No handle with RECEIVE is left (spec 6.8).
    closed: bool,
    /// The level of the cause of its close: its stage Close runs at the
    /// higher of it and the top level of its queue (spec 7.7).
    cause: u8,
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

// Six channels to a page of a pool (spec 7.8).
const _: () = assert!(core::mem::size_of::<Channel>() <= 1024);

/// Channels whose slots have not gone back.
static LIVE: Live = Live::new();

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
        refs: Refs::one(),
        sources: 1,
        closed: false,
        cause: 0,
        payer,
        cleanup: Item::new(),
    };
    let c = process::paid_alloc(payer, channel)?;
    process::retain_shell(payer);
    LIVE.made();
    Ok(c)
}

/// The count of references to `c`, through the raw pointer.
///
/// # Safety
/// `c` is alive, and nothing else borrows the count.
#[must_use]
unsafe fn refs<'a>(c: NonNull<Channel>) -> &'a mut Refs {
    // SAFETY: the caller's promise; only the field is borrowed.
    unsafe { &mut (*c.as_ptr()).refs }
}

/// The queue of `c`, which changes together with the states of the
/// threads in it: reached only with the scheduler locked, which `_locked`
/// shows (sched::locked).
///
/// # Safety
/// `c` is alive.
unsafe fn queue(c: NonNull<Channel>, _locked: &mut Scheduler<Thread>) -> &mut Queue<Owner> {
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
        refs(c).retain();
        if rights.contains(Rights::RECEIVE) {
            let p = c.as_ptr();
            assert!(!(*p).closed, "a handle with RECEIVE to a closed channel");
            (*p).receivers = (*p)
                .receivers
                .checked_add(1)
                .expect("channel receivers overflow");
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
        if refs(c).release() {
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

/// object_info CHANNEL of `c`, which the caller holds (spec 11): the slots
/// and requests in its queue and the receivers that wait there, read with
/// the scheduler locked, its sources, the slot of label 0 among them, and
/// whether it is closed. O(1).
pub fn info(c: NonNull<Channel>) -> ChannelInfo {
    // SAFETY: the caller holds a reference to the channel.
    let (queued, receivers) = sched::locked(|k| unsafe { queue(c, k.s) }.counts());
    // SAFETY: as above; only the fields are read.
    let (sources, closed) = unsafe { ((*c.as_ptr()).sources, (*c.as_ptr()).closed) };
    ChannelInfo {
        queued: queued.into(),
        receivers: receivers.into(),
        sources: sources.into(),
        closed,
    }
}

/// A new source of notifications takes one of the slots of `c`, which the
/// caller holds (spec 6.5), before its object has a place: LIMIT_REACHED
/// when abi::MAX_SLOTS are taken, the slot of label 0 among them, and
/// nothing changes. The source gives it back as it goes (Source::detach),
/// or at once when its object is not made (`remove_source`).
pub fn reserve_source(c: NonNull<Channel>) -> Result<(), Error> {
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
/// from now on. With threads that wait or slots queued it goes to the
/// cleanup queue with a reference of the queue's own, for its stage Close,
/// at the higher of `cause` and the top level of its queue (spec 7.7).
/// O(1).
///
/// # Safety
/// The caller holds a reference to `c`.
unsafe fn close(c: NonNull<Channel>, cause: u8) {
    let p = c.as_ptr();
    // SAFETY: the caller's reference keeps the channel alive; only the
    // fields are touched.
    unsafe {
        (*p).closed = true;
        let Some(top) = sched::locked(|k| queue(c, k.s).top()) else {
            return;
        };
        (*p).cause = cause;
        refs(c).take();
        let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
        cleanup::enqueue(item, Object::Channel(c), top.max(cause));
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

/// The thread whose own slot `slot` is (Owner::Thread).
///
/// # Safety
/// `slot` is alive.
unsafe fn thread_of(slot: NonNull<Slot<Owner>>) -> NonNull<Thread> {
    // SAFETY: the caller's promise.
    match unsafe { slot.as_ref() }.owner() {
        Owner::Thread(t) => t,
        _ => unreachable!("a receiver waits through a slot that is not its own"),
    }
}

/// The ceiling of the process of `t`, which a boost never passes (spec 8).
fn ceiling(t: NonNull<Thread>) -> u8 {
    // SAFETY: the thread is alive and holds its process.
    unsafe { t.as_ref().process().as_ref() }.ceiling()
}

/// What receive or the stage Close took from a channel's queue, which it
/// lets go after the scheduler's lock.
enum Taken {
    /// A notification slot, which held its owner.
    Slot(Owner),
    /// A thread that waited, which held what it went through (receive and
    /// the stage Close) or the channel (the stage Close), and the sender
    /// whose handles no table took, a meeting that failed or the stage
    /// Close, which go after the lock too (thread::drop_transit).
    Request(Via, Option<NonNull<Thread>>),
}

/// One portion of a channel in the cleanup queue (cleanup::portion), taken
/// at `level`. At the stage Close, while the queue's reference holds it:
/// heads of the top level leave the queue, CLOSE_PORTION units of work at
/// most: threads that wait in receive or in send, each woken with
/// PEER_CLOSED at the tail of its level with a new quantum (spec 6.1, 6.8),
/// its wait letting go what it held and a sender's handles going, up to
/// abi::MESSAGE_HANDLES, at the cause of the close; or slots, emptied, each
/// letting its owner go at that cause (a session whose copies went goes, as
/// after receive); a head a time under the scheduler's lock, what it held
/// after it. With heads left the channel goes back to the head of the
/// higher of the cause and their top level (spec 7.7), and otherwise the
/// queue's reference goes, which queues the shell at the cause when it was
/// the last. With no reference left, the shell's portion: the slot goes
/// back to the payer's pool, and then the reference to the payer's shell.
///
/// # Safety
/// The channel was just taken from the queue.
pub unsafe fn clean(c: NonNull<Channel>, level: u8) {
    // SAFETY: the caller's promise: the queue's reference keeps the channel
    // at its stage Close, and nothing refers to a shell.
    if unsafe { refs(c) }.get() == 0 {
        // SAFETY: as above.
        unsafe { free(c, level) };
        return;
    }
    // SAFETY: as above; only the field is read.
    let cause = unsafe { (*c.as_ptr()).cause };
    // SAFETY: as above.
    let top = sched::locked(|k| unsafe { queue(c, k.s).top() });
    let mut woken = 0u32;
    let mut heads = 0;
    let mut work = 0;
    while work < CLOSE_PORTION {
        let head = sched::locked(|k| {
            // SAFETY: the channel is alive; a thread that waits is alive,
            // and a queued slot holds its owner, in which it lies.
            unsafe {
                let q = queue(c, k.s);
                if q.top() != top {
                    return None;
                }
                let slot = q.take_waiter().or_else(|| q.take_slot())?;
                let owner = (*slot.as_ptr()).owner();
                let Owner::Thread(t) = owner else {
                    (*slot.as_ptr()).take();
                    return Some(Taken::Slot(owner));
                };
                let (via, sender) = match (*t.as_ptr()).waits.take() {
                    Some(Wait::Receive(_)) => (Via::Channel(c), None),
                    Some(Wait::Send(via)) => (via, Some(t)),
                    _ => unreachable!("a thread in a channel's queue waits for no channel"),
                };
                syscall::set_result(t, Err(Error::PeerClosed));
                k.s.wake(t);
                Some(Taken::Request(via, sender))
            }
        });
        match head {
            None => break,
            Some(Taken::Request(via, sender)) => {
                if let Some(sender) = sender {
                    // SAFETY: the sender is alive, since the kernel's
                    // reference keeps a ready thread, and it does not run
                    // before the portion ends.
                    work += unsafe { thread::drop_transit(sender, cause) };
                }
                match via {
                    // The references to the channel itself go below.
                    Via::Channel(_) => woken += 1,
                    // SAFETY: the thread's wait held the session.
                    via => unsafe { via.let_go(cause) },
                }
            }
            // SAFETY: the slot left the queue, whose reference to its
            // owner goes.
            Some(Taken::Slot(owner)) => unsafe { owner.let_go(cause) },
        }
        heads += 1;
        work += 1;
    }
    // SAFETY: as above.
    let left = sched::locked(|k| unsafe { queue(c, k.s).top() });
    crate::testpoint::heads_taken(level, heads);
    // SAFETY: the references of the waits go; the queue's keeps the
    // channel, and then goes itself once nothing is left.
    unsafe {
        refs(c).release_many(woken);
        match left {
            Some(top) => {
                let item = NonNull::new_unchecked(&raw mut (*c.as_ptr()).cleanup);
                cleanup::requeue(item, Object::Channel(c), top.max(cause));
            }
            None => release(c, Rights::NONE, cause),
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
        sources == 1 && sched::locked(|k| unsafe { queue(c, k.s).is_empty() }),
        "a channel goes with a source or something in its queues"
    );
    // SAFETY: nothing uses the channel afterwards; the payer's pool is
    // there, since the channel holds the payer's shell.
    unsafe {
        process::paid_free(payer, c);
        LIVE.gone(c);
    }
    // SAFETY: the channel's reference to its payer's shell goes with it.
    unsafe { process::release_shell(payer, level) };
}

// The poison of a channel that went (Live::gone) reaches its count.
const _: () = assert!(core::mem::offset_of!(Channel, refs) >= 8);

#[cfg(feature = "ktest")]
pub use test_access::{in_use, payer, sources};

/// What the kernel tests read and steer here (crate::ktest).
#[cfg(feature = "ktest")]
mod test_access {
    use super::*;

    /// Channels whose slots have not gone back.
    pub fn in_use() -> usize {
        LIVE.count()
    }

    /// The process that pays for `c`, which the test holds.
    pub fn payer(c: NonNull<Channel>) -> NonNull<Process> {
        // SAFETY: the test holds a reference to the channel; only the field is
        // read.
        unsafe { (*c.as_ptr()).payer }
    }

    /// The sources with a slot in `c`, which the test holds, the slot of
    /// label 0 among them.
    pub fn sources(c: NonNull<Channel>) -> u32 {
        // SAFETY: as above.
        unsafe { (*c.as_ptr()).sources }
    }
}
