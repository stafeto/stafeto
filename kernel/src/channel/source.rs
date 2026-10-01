// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The sources of notifications of a channel and their slots (spec 6.5): `Owner`, `Source`, `notify` and `post`.

use super::*;

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
    /// The end of a thread through thread_exit, which lies in the thread
    /// (thread_create x7, spec 6.5).
    ThreadEnd(NonNull<Thread>),
    /// A timer (spec 10).
    Timer(NonNull<Timer>),
    /// An interrupt binding (spec 9).
    Irq(NonNull<Irq>),
    /// A thread's own slot (spec 6.1), which lies in it: its place while
    /// it waits in receive, its request while it waits in send. It carries
    /// no notification, and its thread's wait holds what it needs.
    Thread(NonNull<Thread>),
}

impl Owner {
    pub(super) fn source(self) -> abi::Source {
        match self {
            Owner::Channel => abi::Source::Unlabeled,
            Owner::Session(_) => abi::Source::Session,
            Owner::Exit(_) | Owner::ThreadEnd(_) => abi::Source::Exit,
            Owner::Timer(_) => abi::Source::Timer,
            Owner::Irq(_) => abi::Source::Interrupt,
            Owner::Thread(_) => unreachable!("a thread's slot carries no notification"),
        }
    }

    pub(super) fn label(self) -> u64 {
        match self {
            Owner::Channel => 0,
            Owner::Session(s) => session::label(s),
            Owner::Exit(p) => process::exit_label(p),
            Owner::ThreadEnd(t) => thread::exit_label(t),
            Owner::Timer(t) => timer::label(t),
            Owner::Irq(b) => irq::label(b),
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
            Owner::ThreadEnd(t) => thread::retain(t),
            Owner::Timer(t) => timer::retain(t),
            Owner::Irq(b) => irq::retain(b),
            Owner::Thread(_) => unreachable!("a thread's slot is posted"),
        }
    }

    /// The slot left the queue: receive or the stage Close took it, and
    /// the reference `hold` took goes at `cause`, which may queue the owner.
    ///
    /// # Safety
    /// `hold` took the reference, and the slot is in no queue.
    pub(super) unsafe fn let_go(self, cause: u8) {
        match self {
            Owner::Channel | Owner::Thread(_) => {}
            // SAFETY: the caller's promise.
            Owner::Session(s) => unsafe { session::unref(s, cause) },
            // SAFETY: as above.
            Owner::Exit(p) => unsafe { process::release_shell(p, cause) },
            // SAFETY: as above.
            Owner::ThreadEnd(t) => unsafe { thread::release(t, cause) },
            // SAFETY: as above.
            Owner::Timer(t) => unsafe { timer::release(t, cause) },
            // SAFETY: as above.
            Owner::Irq(b) => unsafe { irq::release(b, cause) },
        }
    }
}

/// A source of notifications on a channel (spec 6.5): a session, a timer,
/// the end of a process or of a thread or an interrupt binding, which it
/// lies in. It holds
/// one of the channel's slots from channel::reserve_source until `detach`,
/// and the channel with a counted reference from `attach` until then; its
/// own slot, whose owner is the object it lies in, and the label receive
/// reports with it, come with `attach`, once the object has its place.
pub struct Source {
    slot: Option<Slot<Owner>>,
    label: u64,
    channel: NonNull<Channel>,
}

impl Source {
    /// A source on `c`, whose slot reserve_source took, for an object that
    /// has no place yet: it has no slot of its own and holds nothing until
    /// `attach`.
    pub const fn new(c: NonNull<Channel>) -> Source {
        Source {
            slot: None,
            label: 0,
            channel: c,
        }
    }

    /// The object the source lies in has its place, which `owner` names:
    /// the source gets its slot of `priority` with `label`, and holds the
    /// channel from now on.
    pub fn attach(&mut self, owner: Owner, priority: u8, label: u64) {
        assert!(self.slot.is_none(), "a source is attached twice");
        self.slot = Some(Slot::new(priority, owner));
        self.label = label;
        retain(self.channel, Rights::NONE);
    }

    /// The channel, which the source holds.
    pub fn channel(&self) -> NonNull<Channel> {
        self.channel
    }

    /// The label receive reports with the source's slot (spec 5.3).
    pub fn label(&self) -> u64 {
        self.label
    }

    fn own_slot(&self) -> &Slot<Owner> {
        self.slot.as_ref().expect("an attached source")
    }

    /// The priority of the source's slot.
    pub fn priority(&self) -> u8 {
        self.own_slot().priority()
    }

    /// Whether the source's slot stands in the channel's queue.
    pub fn is_queued(&self) -> bool {
        self.own_slot().is_queued()
    }

    /// Posts `bits` into the slot of the source `this` points at, at
    /// `cause`, as `post` does: PEER_CLOSED once the channel closed. O(1).
    ///
    /// # Safety
    /// The source is attached, and its object lives until the post
    /// returns: the caller holds it, or its slot does.
    pub unsafe fn post(this: NonNull<Source>, bits: u64, cause: u8) -> Result<(), Error> {
        // SAFETY: the caller's promise; the borrows end before the post,
        // and the slot stays in place with its object.
        unsafe {
            let c = (*this.as_ptr()).channel;
            let slot = NonNull::from((*this.as_ptr()).slot.as_mut().expect("an attached source"));
            post(c, slot, bits, cause)
        }
    }

    /// The source goes with its object (the object's portion, spec 7.7):
    /// its slot of the channel goes back, and then its reference to the
    /// channel at `level`, which may queue the channel. Its own slot is in
    /// no queue: a queued slot holds the object. O(1).
    ///
    /// # Safety
    /// The source is attached, nothing refers to its object, and it is not
    /// used afterwards.
    pub unsafe fn detach(&mut self, level: u8) {
        assert!(!self.is_queued(), "a source goes while its slot is queued");
        remove_source(self.channel);
        // SAFETY: the reference `attach` took goes.
        unsafe { release(self.channel, Rights::NONE, level) };
    }
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
