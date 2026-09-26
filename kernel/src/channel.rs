// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Channels (spec 4, 6.1, 6.3, 6.5, 6.8): notifications, requests and
//! their replies, and the threads that wait for them. A channel lies in the
//! pool of channels of the process that made it, which pays for it by the
//! page (spec 7.8), and holds that process's shell until its slot goes
//! back. It has the slot of label 0, whose priority channel_create gave,
//! and the queue of kcore::notify: slots with something posted and the
//! requests of threads that wait in `send`, or receivers that wait, by
//! priority and in the order they came. A thread waits through its own
//! slot, which is its request in `send`; a request a receiver took waits
//! for its reply in the queue of accepted requests of the receiver's
//! process (process::accepted), and a token of the table of thread numbers
//! names it (spec 6.1). The handles of a message move from the sender's
//! table into the receiver's with their references; a request that waits
//! in a queue carries them (Thread::transit). The queues change together
//! with the states of the threads in them, so every change to them happens
//! under the scheduler's lock (sched::locked). A channel lives while
//! references to it are left: handles with any rights, threads that wait
//! in it, the sources of notifications that have a slot there (sessions,
//! exits of processes and timers), and the cleanup queue's while it
//! closes; the last one queues its shell (spec 7.7). Every source holds
//! one of its abi::MAX_SLOTS slots, the slot of label 0 among them, from
//! its creation until it goes, and a slot that stands in the queue holds
//! its owner until receive or the stage Close takes it (spec 6.5). The
//! last handle with RECEIVE closes it in the call itself: `notify` and
//! `send` fail with PEER_CLOSED from then on, nothing new waits or is
//! queued, and the stage Close wakes the threads that wait with
//! PEER_CLOSED or empties the queued slots, letting their owners go,
//! CLOSE_PORTION heads of one level a portion, at the level of its top
//! waiter when that is above the cause (spec 7.7). A request a receiver
//! took lives on without the channel.

use crate::cleanup::{self, Item};
use crate::object::{self, Live, Object, Refs};
use crate::process::{self, Process};
use crate::sched::{self, Locked};
use crate::session::{self, Session};
use crate::syscall;
use crate::thread::{self, Thread};
use crate::timer::{self, Timer};
use crate::{arch, testpoint};
use abi::{Error, INLINE_MAX, MAX_SLOTS, Notification, Rights, Source};
use core::ptr::NonNull;
use kcore::args::{Desc, mask_tail};
use kcore::notify::{Post, Queue, Slot};
use kcore::sched::Scheduler;

/// The work a portion of the stage Close does, at most (spec 7.7): each
/// head of one level, a thread that waits or a queued slot, is a unit, and
/// each handle a sender's request carries one more; the head that reaches
/// it is the portion's last.
const CLOSE_PORTION: usize = 32;

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
    /// A timer (spec 10).
    Timer(NonNull<Timer>),
    /// A thread's own slot (spec 6.1), which lies in it: its place while
    /// it waits in receive, its request while it waits in send. It carries
    /// no notification, and its thread's wait holds what it needs.
    Thread(NonNull<Thread>),
}

impl Owner {
    fn source(self) -> Source {
        match self {
            Owner::Channel => Source::Unlabeled,
            Owner::Session(_) => Source::Session,
            Owner::Exit(_) => Source::Exit,
            Owner::Timer(_) => Source::Timer,
            Owner::Thread(_) => unreachable!("a thread's slot carries no notification"),
        }
    }

    fn label(self) -> u64 {
        match self {
            Owner::Channel => 0,
            Owner::Session(s) => session::label(s),
            Owner::Exit(p) => process::exit_label(p),
            Owner::Timer(t) => timer::label(t),
            Owner::Thread(_) => unreachable!("a thread's slot carries no notification"),
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
            Owner::Timer(t) => timer::retain(t),
            Owner::Thread(_) => unreachable!("a thread's slot is posted"),
        }
    }

    /// The slot left the queue: receive or the stage Close took it, and
    /// the reference `hold` took goes at `cause`, which may queue the owner.
    ///
    /// # Safety
    /// `hold` took the reference, and the slot is in no queue.
    unsafe fn let_go(self, cause: u8) {
        match self {
            Owner::Channel | Owner::Thread(_) => {}
            // SAFETY: the caller's promise.
            Owner::Session(s) => unsafe { session::unref(s, cause) },
            // SAFETY: as above.
            Owner::Exit(p) => unsafe { process::release_shell(p, cause) },
            // SAFETY: as above.
            Owner::Timer(t) => unsafe { timer::release(t, cause) },
        }
    }
}

/// What a request went through (spec 5.3, 6.1): a handle to the channel
/// with no label, or one with a label, which names a session of the
/// channel; the receiver gets the label with the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Channel(NonNull<Channel>),
    Session(NonNull<Session>),
}

impl Via {
    /// The channel the request goes into.
    pub fn channel(self) -> NonNull<Channel> {
        match self {
            Via::Channel(c) => c,
            Via::Session(s) => session::channel(s),
        }
    }

    /// The label the receiver gets: the session's, or 0.
    fn label(self) -> u64 {
        match self {
            Via::Channel(_) => 0,
            Via::Session(s) => session::label(s),
        }
    }

    /// A request that waits in the queue holds what it went through from
    /// now on (spec 6.1): the channel, or one more copy of the session, so
    /// that CLIENT_GONE comes after the request (spec 5.3). Only counts, so
    /// it runs under the scheduler's lock.
    fn hold(self) {
        match self {
            Via::Channel(c) => retain(c, Rights::NONE),
            Via::Session(s) => session::retain(s, Rights::NONE),
        }
    }

    /// The reference a wait held goes at `cause`, which may queue what it
    /// held (spec 7.7); the last copy of a session posts CLIENT_GONE
    /// (session::release), so it runs after the scheduler's lock.
    ///
    /// # Safety
    /// The reference is the caller's: `hold` took it, or a wait in receive
    /// holds the channel.
    pub unsafe fn let_go(self, cause: u8) {
        match self {
            // SAFETY: the caller's promise.
            Via::Channel(c) => unsafe { release(c, Rights::NONE, cause) },
            // SAFETY: as above.
            Via::Session(s) => unsafe { session::release(s, Rights::NONE, cause) },
        }
    }
}

/// What a thread waits for, and where its own slot stands meanwhile (spec
/// 6.1, 8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    /// In receive on the channel, its slot in the channel's queue; the wait
    /// holds a reference to the channel.
    Receive(NonNull<Channel>),
    /// In send, its slot, its request, in the queue of the channel it went
    /// through; the wait holds that (`Via::hold`).
    Send(Via),
    /// Its request accepted by a thread of the process, its slot in the
    /// process's queue of accepted requests: it waits for the reply and
    /// holds nothing; the stage Replies of the process wakes it if the
    /// process ends first (spec 6.8).
    Reply(NonNull<Process>),
}

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
    let woke = sched::locked(|k| {
        // SAFETY: the caller's promise; the slot stays in place.
        let t = match unsafe { queue(c, k.s).post(slot, bits) } {
            Post::Merged => return false,
            Post::Queued => {
                // SAFETY: as above.
                unsafe { (*slot.as_ptr()).owner() }.hold();
                return false;
            }
            // SAFETY: the receiver's slot lies in its thread.
            Post::Deliver(r) => unsafe { thread_of(r) },
        };
        // SAFETY: the slot left no queue; `t` left the queue and is alive,
        // since the kernel's reference keeps a thread that waits.
        unsafe {
            let (n, priority) = notice(slot);
            (*t.as_ptr()).waits = None;
            syscall::set_notification(t, n);
            k.s.boost(t, priority, ceiling(t));
            k.s.wake(t);
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

/// What the first look of receive at a channel's queue came to.
enum Looked {
    /// What it took under the scheduler's lock, if anything.
    Done(Option<Taken>),
    /// The request at the head, of this client, whose handles need room in
    /// the receiver's table first.
    Handles(NonNull<Thread>),
}

/// The description of the request of `client`, which waits in `send`: its
/// own x1, which the call checked.
///
/// # Safety
/// `client` is alive.
unsafe fn sent(client: NonNull<Thread>) -> Desc {
    // SAFETY: the caller's promise; only the register is read.
    Desc::from_send(unsafe { (*client.as_ptr()).regs.x[1] })
        .expect("a request's description was checked")
}

/// The handles `values` of a message of `t`, the running thread, go where
/// no table takes them (spec 6.1): out of its process's table, each
/// released at `t`'s priority.
fn drop_handles(t: NonNull<Thread>, values: &[u64]) {
    // SAFETY: the running thread is alive and holds its process.
    let (p, cause) = unsafe { (t.as_ref().process(), t.as_ref().priority()) };
    let moving = process::take_handles(p, values);
    // SAFETY: the references were the handles', which left the table.
    unsafe { object::release_moving(moving, cause) };
}

/// receive (spec 6.1, 6.5, 6.6) for `t`, the running thread, on `c`, to
/// which it holds a handle with RECEIVE, so the channel is open; it writes
/// `t`'s result itself. First the boost of `t`'s last notification or
/// request ends. Then the head of the top level of the queue leaves it: a
/// slot, emptied into x0-x11, after which `t` works at the slot's priority
/// under its ceiling until its next receive, and the slot lets its owner
/// go at that priority after the scheduler's lock; or a request, which `t`
/// takes (`accept`) once its handles have room in the table of `t`'s
/// process (process::reserve_handles), the reference of its sender's wait
/// going after the lock. A request whose handles find no room fails its
/// sender with that error, LIMIT_REACHED or NO_MEMORY, and its handles go at
/// `t`'s priority; the call then starts over at its `svc` with its
/// registers as they were (syscall::restart), and takes the next head
/// (spec 6.1). With nothing queued, WOULD_BLOCK when `wait` is false;
/// otherwise `t` waits through its own slot at the tail of its level,
/// holding a reference to `c`, and gets its result when the wait ends
/// (`post`, `send`, `clean`). O(1).
pub fn receive(t: NonNull<Thread>, c: NonNull<Channel>, wait: bool) -> Result<(), Error> {
    let ceiling = ceiling(t);
    let looked = sched::locked(|k| {
        // SAFETY: the running thread and the channel, which its handle
        // holds, are alive; the sender of a queued request waits, so it is
        // alive, and its wait holds what it went through.
        unsafe {
            k.s.unboost(t);
            (*t.as_ptr()).boost_token = 0;
            let q = queue(c, k.s);
            if !q.has_receivers()
                && let Some(slot) = q.head()
            {
                let owner = (*slot.as_ptr()).owner();
                if let Owner::Thread(client) = owner {
                    if sent(client).handles > 0 {
                        // Its handles need room first, which may take a page.
                        return Ok(Looked::Handles(client));
                    }
                    return Ok(Looked::Done(Some(take_request(k, t, c, client, Ok(())))));
                }
                q.take_slot();
                let (n, priority) = notice(slot);
                syscall::set_notification(t, n);
                k.s.boost(t, priority, ceiling);
                return Ok(Looked::Done(Some(Taken::Slot(owner))));
            }
            if !wait {
                return Err(Error::WouldBlock);
            }
            let running = k.s.block();
            assert!(running == t, "a thread that does not run waits");
            let slot = thread::slot(t);
            (*slot.as_ptr()).set_priority(t.as_ref().priority());
            queue(c, k.s).wait(slot);
            (*t.as_ptr()).waits = Some(Wait::Receive(c));
        }
        retain(c, Rights::NONE);
        Ok(Looked::Done(None))
    })?;
    let taken = match looked {
        Looked::Done(taken) => taken,
        Looked::Handles(client) => {
            // SAFETY: the running thread holds its process; the client
            // waits, so it is alive.
            let n = unsafe { sent(client) }.handles;
            let fit = process::reserve_handles(unsafe { t.as_ref() }.process(), n);
            // SAFETY: nothing changed the queue meanwhile: one CPU, and
            // interrupts are masked in the kernel (spec 8.1).
            Some(sched::locked(|k| unsafe {
                take_request(k, t, c, client, fit)
            }))
        }
    };
    // SAFETY: the running thread is alive; the reference of the slot or of
    // the sender's wait goes, and so do the handles no table took; nothing
    // uses them afterwards.
    unsafe {
        let cause = t.as_ref().priority();
        match taken {
            Some(Taken::Slot(owner)) => owner.let_go(cause),
            Some(Taken::Request(via, sender)) => {
                if let Some(sender) = sender {
                    thread::drop_transit(sender, cause);
                }
                via.let_go(cause);
            }
            None => {}
        }
    }
    Ok(())
}

/// The request of `client`, the head of the queue of `c`, leaves it for
/// `t`'s receive (spec 6.1): with room for its handles (`fit`), `t` takes
/// it (`accept`); otherwise its sender wakes with that error in x0 alone,
/// at the tail of its level with a new quantum, and `t`'s call starts over
/// (syscall::restart). Returns what the request's wait held, and the
/// sender whose handles no table took, for after the lock. O(1).
///
/// # Safety
/// `t` runs; `c` is alive, and `client` waits in send at the head of its
/// queue; `k` is the locked scheduler.
unsafe fn take_request(
    k: &mut Locked<'_>,
    t: NonNull<Thread>,
    c: NonNull<Channel>,
    client: NonNull<Thread>,
    fit: Result<(), Error>,
) -> Taken {
    // SAFETY: the caller's promise; the client's wait holds what it went
    // through, and its handles lie in it.
    unsafe {
        let taken = queue(c, k.s).take_slot();
        assert!(
            taken == Some(thread::slot(client)),
            "the head of a channel's queue moved while its receiver made room"
        );
        let Some(Wait::Send(via)) = (*client.as_ptr()).waits else {
            unreachable!("a request whose thread does not send");
        };
        if let Err(e) = fit {
            (*client.as_ptr()).waits = None;
            syscall::set_result(client, Err(e));
            k.s.wake(client);
            syscall::restart(t);
            return Taken::Request(via, Some(client));
        }
        accept(k, t, client, via, sent(client));
        Taken::Request(via, None)
    }
}

/// send (spec 6.1, 6.3) for `t`, the running thread, through `via`, to
/// which it holds a handle with SEND, with the description `desc` and the
/// handles `values` of its process, all checked; the request is `t`'s own
/// x1-x9. The checks of state in the order of spec 11: BAD_STATE when `t`
/// has no count of requests left (spec 6.1); PEER_CLOSED once the channel
/// closed, and the handles go then, released at `t`'s priority;
/// WOULD_BLOCK with NO_WAIT when no receiver waits. Otherwise the top
/// receiver that waits takes the request at once (`accept`) once its
/// handles have room in the receiver's table (process::reserve_handles):
/// LIMIT_REACHED or NO_MEMORY otherwise, the handles go and the receiver
/// waits on. With the request taken or no receiver waiting, `t` waits for
/// the reply (Ok), its own slot at the level of its effective priority and
/// its handles out of its process's table (process::take_handles): the
/// receiver becomes ready at the tail of its level with a new quantum, the
/// reference of its wait going after the scheduler's lock; or else the
/// slot goes to the tail of its level in the channel's queue (spec 6.3),
/// holding `via` and the handles (Thread::transit) until a receive takes
/// it. A message of registers alone may take the fast path (`fast_send`),
/// and Ok names the receiver then, which the caller runs at once. O(1).
pub fn send(
    t: NonNull<Thread>,
    via: Via,
    desc: Desc,
    values: &[u64],
) -> Result<Option<NonNull<Thread>>, Error> {
    let c = via.channel();
    sched::locked(|k| k.tokens.check_count(thread::index(t)))?;
    if is_closed(c) {
        drop_handles(t, values);
        return Err(Error::PeerClosed);
    }
    if desc.len <= INLINE_MAX
        && values.is_empty()
        && let Some(r) = fast_send(t, via, desc)
    {
        return Ok(Some(r));
    }
    let receiver = sched::locked(|k| {
        // SAFETY: the channel, which the sender's handle holds, is alive; a
        // thread that waits in receive is alive, and its slot lies in it.
        unsafe {
            let q = queue(c, k.s);
            q.has_receivers()
                .then(|| thread_of(q.head().expect("a receiver")))
        }
    });
    if desc.no_wait && receiver.is_none() {
        return Err(Error::WouldBlock);
    }
    if let Some(r) = receiver
        && !values.is_empty()
        // SAFETY: a thread that waits is alive and holds its process.
        && let Err(e) = process::reserve_handles(unsafe { r.as_ref() }.process(), values.len())
    {
        drop_handles(t, values);
        return Err(e);
    }
    if !values.is_empty() {
        // SAFETY: the running thread holds its process, and its handles on
        // their way are its own.
        unsafe { thread::set_transit(t, process::take_handles(t.as_ref().process(), values)) };
    }
    let took = sched::locked(|k| {
        // SAFETY: the running thread and the channel, which its handle
        // holds, are alive; a thread that waits in receive is alive, and
        // nothing changed the queue since it was looked at: one CPU, and
        // interrupts are masked in the kernel (spec 8.1).
        unsafe {
            let running = k.s.block();
            assert!(running == t, "a thread that does not run sends");
            let slot = thread::slot(t);
            (*slot.as_ptr()).set_priority(t.as_ref().priority());
            let Some(r) = queue(c, k.s).send(slot) else {
                (*t.as_ptr()).waits = Some(Wait::Send(via));
                via.hold();
                return false;
            };
            let r = thread_of(r);
            assert!(Some(r) == receiver, "the receiver of a request changed");
            (*r.as_ptr()).waits = None;
            accept(k, r, t, via, desc);
            k.s.wake(r);
            true
        }
    });
    if took {
        // SAFETY: the reference was the receiver's wait's; the sender's
        // handle keeps the channel, and the sender is alive.
        unsafe { release(c, Rights::NONE, t.as_ref().priority()) };
    }
    Ok(None)
}

/// The fast path of send (spec 6.4) for `t`, the running thread, through
/// `via`, with `desc`, a message of registers alone: the top receiver that
/// waits in the channel takes the request (`accept`) and runs at once in
/// place of `t` (sched::hand_off), when the top level of the cleanup queue
/// is below the receiver's effective priority after the boost the request
/// gives it, no interrupt is pending, and that priority is above every
/// ready thread's. The state is the one the slow path leaves. The
/// reference of the receiver's wait goes after the scheduler's lock.
/// Returns the receiver, which the caller runs; None, with nothing changed,
/// when a condition fails. O(1).
fn fast_send(t: NonNull<Thread>, via: Via, desc: Desc) -> Option<NonNull<Thread>> {
    let c = via.channel();
    // Read before the scheduler's lock: the locks do not nest.
    let cleanup = cleanup::top();
    let next_timer = timer::first();
    let r = sched::hand_off(next_timer, |k| {
        // SAFETY: the running thread and the channel, which its handle
        // holds, are alive; a thread that waits in receive is alive, and
        // its slot lies in it.
        unsafe {
            let q = queue(c, k.s);
            if !q.has_receivers() {
                return None;
            }
            let r = thread_of(q.head()?);
            let n = &r.as_ref().sched;
            let boost = n.boost().max(t.as_ref().priority().min(ceiling(r)));
            let level = n.base().max(boost);
            if cleanup.is_some_and(|l| l >= level)
                || arch::irq_pending()
                || k.s.ready().top().is_some_and(|top| top >= level)
                || !testpoint::fast_path()
            {
                return None;
            }
            let running = k.s.block();
            assert!(running == t, "a thread that does not run sends");
            let slot = thread::slot(t);
            (*slot.as_ptr()).set_priority(t.as_ref().priority());
            let taken = queue(c, k.s).send(slot);
            assert!(
                taken == Some(thread::slot(r)),
                "the receiver of a request changed"
            );
            (*r.as_ptr()).waits = None;
            accept(k, r, t, via, desc);
            Some(r)
        }
    })?;
    // SAFETY: the reference was the receiver's wait's; the sender's handle
    // keeps the channel, and the sender is alive.
    unsafe { release(c, Rights::NONE, t.as_ref().priority()) };
    Some(r)
}

/// Writes a message from `from`, its sender, into `to`, the thread it
/// comes to (spec 6.1, 6.2, 11): x0 0, x1 the description, x2-x9 bytes
/// 0-63 from the sender's registers, zero past the length; bytes 64 up to
/// the length go from the sender's message buffer into the receiver's, at
/// the same offsets (thread::copy_message); the handles on their way in
/// `from` (Thread::transit) go into the table of `to`'s process, which
/// made room for them, and their values and info words into `to`'s buffer
/// (process::put_handles, thread::write_handles). O(1): at most 960 bytes
/// and four handles.
///
/// # Safety
/// `to` and `from` are alive and differ; nothing else borrows their
/// registers or buffers; `from` carries `desc.handles` handles.
unsafe fn deliver(to: NonNull<Thread>, from: NonNull<Thread>, desc: Desc) {
    // SAFETY: the caller's promise; the two threads are two objects.
    unsafe {
        let x = &mut (*to.as_ptr()).regs.x;
        x[0] = 0;
        x[1] = desc.result();
        x[2..10].copy_from_slice(&from.as_ref().regs.x[2..10]);
        mask_tail(&mut x[2..10], desc.len);
        if desc.len > INLINE_MAX {
            thread::copy_message(to, from, INLINE_MAX..desc.len);
        }
        if desc.handles > 0 {
            let put = process::put_handles(to.as_ref().process(), thread::take_transit(from));
            thread::write_handles(to, &put[..desc.handles]);
        }
    }
}

/// The request of `client` goes to `r`, the receiver, in its receive (spec
/// 6.1, 6.6): the client's count grows by 1 and the token names the
/// request; the client's own slot goes to the tail of its level in the
/// queue of accepted requests of `r`'s process, where the client waits for
/// the reply; x0-x11 of `r` get the message (`deliver`) with its handles,
/// the label of `via` and the token; and `r` works at the client's level,
/// under its own ceiling, until its reply with this token or its next
/// receive. O(1).
///
/// # Safety
/// `r` and `client` are alive and differ; `client` waits in send through
/// `via` with the description `desc` and carries its handles, its slot in
/// no queue; the table of `r`'s process has room for them; `r` has no
/// boost.
unsafe fn accept(
    k: &mut Locked<'_>,
    r: NonNull<Thread>,
    client: NonNull<Thread>,
    via: Via,
    desc: Desc,
) {
    let token = k.tokens.accept(thread::index(client));
    // SAFETY: the caller's promise; the two threads' registers are two
    // objects.
    unsafe {
        let p = r.as_ref().process();
        let slot = thread::slot(client);
        process::accepted(p, k.s).push_tail(slot);
        (*client.as_ptr()).waits = Some(Wait::Reply(p));
        deliver(r, client, desc);
        let to = &mut (*r.as_ptr()).regs.x;
        to[10] = via.label();
        to[11] = token;
        k.s.boost(r, (*slot.as_ptr()).priority(), ceiling(r));
        (*r.as_ptr()).boost_token = token;
    }
}

/// reply (spec 6.1, 6.6) of `t`, the running thread, with its x1-x9, the
/// description `desc` and the handles `values` of its process, all
/// checked, to the request `token` names. A reply with the token of `t`'s
/// boost ends the boost first, whatever comes of it (spec 6.6). Then
/// BAD_STATE when the token names no request that waits for a reply from
/// `t`'s process: a number outside the table, a count other than the
/// number's last, or a client that waits for no reply or for one from
/// another process; nothing else happens then. PEER_CLOSED when its client
/// ended while it waited (Table::mark_dead, spec 6.8), each time it is
/// tried, and the handles go. Otherwise the token is used up: the client
/// leaves the queue of accepted requests and becomes ready at the tail of
/// its level with a new quantum, its registers holding the message with
/// its handles (`deliver`) once they have room in the client's table
/// (process::reserve_handles); with no room the reply and the client's
/// send both fail with LIMIT_REACHED or NO_MEMORY, in x0 alone, and the
/// handles go. Handles that go are released at `t`'s priority. Never
/// waits. O(1).
pub fn reply(t: NonNull<Thread>, token: u64, desc: Desc, values: &[u64]) -> Result<(), Error> {
    let client = sched::locked(|k| {
        // SAFETY: the running thread is alive; so is a thread whose number
        // is taken (it gives the number back as it ends); a client that
        // waits is not `t`.
        unsafe {
            if token != 0 && (*t.as_ptr()).boost_token == token {
                k.s.unboost(t);
                (*t.as_ptr()).boost_token = 0;
            }
            let client = k.tokens.check(token)?;
            if (*client.as_ptr()).waits != Some(Wait::Reply(t.as_ref().process())) {
                return Err(Error::BadState);
            }
            Ok(client)
        }
    });
    let client = match client {
        Err(Error::PeerClosed) => {
            drop_handles(t, values);
            return Err(Error::PeerClosed);
        }
        client => client?,
    };
    // SAFETY: the running thread and the client that waits for its reply
    // are alive and hold their processes; the running thread's handles on
    // their way are its own.
    let fit = unsafe {
        if values.is_empty() {
            Ok(())
        } else {
            let fit = process::reserve_handles(client.as_ref().process(), values.len());
            thread::set_transit(t, process::take_handles(t.as_ref().process(), values));
            fit
        }
    };
    sched::locked(|k| {
        // SAFETY: as above; the process that took the request holds the
        // client's slot, and nothing changed since the check: one CPU, and
        // interrupts are masked in the kernel (spec 8.1).
        unsafe {
            let p = t.as_ref().process();
            process::accepted(p, k.s).remove(thread::slot(client));
            (*client.as_ptr()).waits = None;
            match fit {
                Ok(()) => deliver(client, t, desc),
                Err(e) => syscall::set_result(client, Err(e)),
            }
            k.s.wake(client);
        }
    });
    if fit.is_err() {
        // SAFETY: the running thread is alive, and no table took its
        // handles.
        unsafe { thread::drop_transit(t, t.as_ref().priority()) };
    }
    fit
}

/// The end of `t` while it waits (sched::exit, spec 6.8, 7.7): its slot
/// leaves the queue it stands in, wherever it stands there: a channel's, or
/// the queue of accepted requests of the process that took its request,
/// and then its number keeps the mark of a thread that died waiting for
/// its reply (Table::mark_dead). What the wait held, a channel or a
/// session, goes to the caller, which lets it go once the scheduler has
/// let the thread go (`Via::let_go`); the handles of a request stay in the
/// thread until its buffer goes (thread::drop_buffer). None for a thread
/// that waits for nothing, or for a reply. O(1).
///
/// # Safety
/// `t` is alive; `k` is the locked scheduler.
pub unsafe fn cancel(t: NonNull<Thread>, k: &mut Locked<'_>) -> Option<Via> {
    let slot = thread::slot(t);
    // SAFETY: the caller's promise; a wait holds its channel or session,
    // and the process that accepted the request holds the slot.
    unsafe {
        match (*t.as_ptr()).waits.take()? {
            Wait::Receive(c) => {
                queue(c, k.s).cancel(slot);
                Some(Via::Channel(c))
            }
            Wait::Send(via) => {
                queue(via.channel(), k.s).cancel(slot);
                Some(via)
            }
            Wait::Reply(p) => {
                process::accepted(p, k.s).remove(slot);
                k.tokens.mark_dead(thread::index(t));
                None
            }
        }
    }
}

/// thread_set_priority of `t` (sched::set_priority): the slot of a thread
/// that waits moves in its queue, a channel's or that of accepted
/// requests, to the level of the thread's new effective priority, by the
/// rules of the ready queue (spec 6.1, 6.3). Returns the wait, for `raise`
/// after the scheduler's lock. O(1).
///
/// # Safety
/// As for `cancel`.
pub unsafe fn requeue(t: NonNull<Thread>, k: &mut Locked<'_>) -> Option<Wait> {
    let slot = thread::slot(t);
    // SAFETY: the caller's promise, as in `cancel`.
    unsafe {
        let level = t.as_ref().priority();
        let waits = (*t.as_ptr()).waits;
        match waits {
            Some(Wait::Receive(c)) => queue(c, k.s).move_to(slot, level),
            Some(Wait::Send(via)) => queue(via.channel(), k.s).move_to(slot, level),
            Some(Wait::Reply(p)) => process::accepted(p, k.s).move_to(slot, level),
            None => {}
        }
        waits
    }
}

/// After `requeue` of a thread that waits in `w`, once the scheduler's lock
/// went (sched::set_priority, spec 7.7): a channel at its stage Close, or a
/// process at its stage Replies, goes up in the cleanup queue to the level
/// of its top waiter when that is higher. O(1).
///
/// # Safety
/// The thread still waits in `w`, which keeps the channel, or the process's
/// shell, alive.
pub unsafe fn raise(w: Wait) {
    let c = match w {
        Wait::Receive(c) => c,
        Wait::Send(via) => via.channel(),
        // SAFETY: the caller's promise.
        Wait::Reply(p) => return unsafe { process::raise_replies(p) },
    };
    if !is_closed(c) {
        return;
    }
    // SAFETY: as above; a closed channel with a thread in its queue stands
    // in the cleanup queue at its stage Close.
    unsafe {
        let p = c.as_ptr();
        let top = sched::locked(|k| queue(c, k.s).top()).expect("the thread's slot is queued");
        let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
        cleanup::raise_above(item, top.max((*p).cause));
    }
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
pub use test_access::{in_use, payer};

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
}
