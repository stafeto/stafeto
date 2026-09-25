// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Sessions (spec 4, 5.3): what a channel handle with a label names. A
//! label goes on a copy of a channel handle once, in handle_duplicate,
//! which makes the session: it holds the channel with a counted reference,
//! the label and a notification slot of the priority the call gave, and it
//! takes one of the channel's slots (abi::MAX_SLOTS) until it goes. It lies
//! in the pool of sessions of the process that made the call, which pays
//! for it by the page (spec 7.8), and holds that process's shell until its
//! slot goes back. It counts the handles that name it, its copies: when
//! the last one goes, through handle_close or with the table of a process
//! that ended, CLIENT_GONE goes into its slot while the channel is open
//! (spec 5.3, 6.8). A session lives while references to it are left: its
//! copies, the one `create` hands out, its slot's while the slot stands in
//! the channel's queue (spec 6.5), which receive and the channel's stage
//! Close let go when they take the slot, and that of each request through
//! one of its copies while the request waits in the queue; the last one
//! queues it, and its portion lets the channel and the payer's shell go.

use crate::channel::{self, Channel, Owner};
use crate::cleanup::{self, Item};
use crate::object::Object;
use crate::process::{self, Process};
use abi::{CLIENT_GONE, Error, Rights};
use core::ptr::NonNull;
use kcore::notify::Slot;

pub struct Session {
    /// The slot of its notifications: notify through its handles, and
    /// CLIENT_GONE once they went.
    slot: Slot<Owner>,
    /// Its copies, the reference `create` hands out, and its slot's while
    /// the slot is queued: the references that keep it.
    refs: u32,
    /// Handles that name it (spec 5.3).
    copies: u32,
    label: u64,
    /// The channel, which it holds with a counted reference.
    channel: NonNull<Channel>,
    /// The process whose pool of sessions holds it, and whose shell it
    /// holds.
    payer: NonNull<Process>,
    /// Its place in the cleanup queue once nothing refers to it.
    cleanup: Item,
}

// SAFETY: sessions are reached under the kernel's rules (spec 8.1): one
// CPU, interrupts masked inside the kernel.
unsafe impl Send for Session {}

/// Sessions whose slots have not gone back (test builds).
#[cfg(feature = "ktest")]
static LIVE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// A session of `c`, an open channel, with `label`, not 0, and a slot of
/// `priority`, 1-63 under the payer's ceiling, as handle_duplicate checked
/// them (spec 5.3): it takes one of the channel's slots, LIMIT_REACHED
/// past abi::MAX_SLOTS, then a place in the pool of sessions of `payer`,
/// the process of the thread that makes it, whose quota pays for a page
/// when the pool grows (spec 7.8), NO_MEMORY when it falls short. It holds
/// the channel and the payer's shell. The caller gets the first reference,
/// which is no copy and goes through `unref`.
pub fn create(
    payer: NonNull<Process>,
    c: NonNull<Channel>,
    label: u64,
    priority: u8,
) -> Result<NonNull<Session>, Error> {
    channel::add_source(c)?;
    let session = Session {
        // The owner is the session's own place, known once it has one.
        slot: Slot::new(priority, Owner::Session(NonNull::dangling())),
        refs: 1,
        copies: 0,
        label,
        channel: c,
        payer,
        cleanup: Item::new(),
    };
    let s = process::session_slot(payer, session).inspect_err(|_| channel::remove_source(c))?;
    // SAFETY: the session was just made, nothing else refers to it, and its
    // slot is in no queue.
    unsafe { (*s.as_ptr()).slot = Slot::new(priority, Owner::Session(s)) };
    channel::retain(c, Rights::NONE);
    process::retain_shell(payer);
    #[cfg(feature = "ktest")]
    LIVE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Ok(s)
}

/// The count of references to `s`, through the raw pointer. Test builds
/// stop a session that went: the poison of its place reaches the count.
///
/// # Safety
/// `s` is alive, and nothing else borrows the count.
unsafe fn refs<'a>(s: NonNull<Session>) -> &'a mut u32 {
    // SAFETY: the caller's promise; only the field is borrowed.
    let refs = unsafe { &mut (*s.as_ptr()).refs };
    #[cfg(feature = "ktest")]
    assert!(
        *refs != u32::from_ne_bytes([POISON; 4]),
        "a session is used after it went"
    );
    refs
}

/// The slot of `s`, which lives as long as the session.
fn slot(s: NonNull<Session>) -> NonNull<Slot<Owner>> {
    // SAFETY: the caller holds a reference to the session; only the
    // field's address is taken.
    unsafe { NonNull::new_unchecked(&raw mut (*s.as_ptr()).slot) }
}

/// The channel `s` names, which it holds.
pub fn channel(s: NonNull<Session>) -> NonNull<Channel> {
    // SAFETY: the caller holds a reference to the session; only the field
    // is read.
    unsafe { (*s.as_ptr()).channel }
}

/// The label of `s`, which receive reports with its slot (spec 5.3).
pub fn label(s: NonNull<Session>) -> u64 {
    // SAFETY: the caller holds a reference to the session, or its slot is
    // being taken; only the field is read.
    unsafe { (*s.as_ptr()).label }
}

/// Adds a handle with `rights` that names `s`: one more copy (spec 5.3).
/// A copy with RECEIVE counts toward the channel's handles with RECEIVE
/// as well, whose last one closes it.
pub fn retain(s: NonNull<Session>, rights: Rights) {
    // SAFETY: the caller holds a reference, so the session is alive; only
    // the fields are touched.
    unsafe {
        let refs = refs(s);
        assert!(*refs > 0, "a session nobody refers to is retained");
        *refs = refs.checked_add(1).expect("session references overflow");
        let p = s.as_ptr();
        (*p).copies = (*p).copies.checked_add(1).expect("session copies overflow");
        if rights.contains(Rights::RECEIVE) {
            channel::retain((*p).channel, Rights::RECEIVE);
        }
    }
}

/// Drops a handle with `rights` that named `s`, at `cause`: a copy with
/// RECEIVE first leaves the channel's count, whose last one closes the
/// channel. The last copy posts CLIENT_GONE, bit 63, into the session's
/// slot (spec 5.3, 6.8), where it merges with the bits not yet received; a
/// closed channel gets nothing (channel::post). Then the handle's
/// reference goes (`unref`), and with nothing left the session goes. O(1).
///
/// # Safety
/// The handle was the caller's, and it is gone.
pub unsafe fn release(s: NonNull<Session>, rights: Rights, cause: u8) {
    // SAFETY: the handle's reference keeps the session alive until its
    // `unref`; only the fields are touched.
    unsafe {
        refs(s);
        let p = s.as_ptr();
        let c = (*p).channel;
        if rights.contains(Rights::RECEIVE) {
            channel::release(c, Rights::RECEIVE, cause);
        }
        (*p).copies = (*p)
            .copies
            .checked_sub(1)
            .expect("a session's handle is released once too often");
        if (*p).copies == 0 {
            // PEER_CLOSED: the session goes at once (spec 5.3).
            let _ = channel::post(c, slot(s), CLIENT_GONE, cause);
        }
        unref(s, cause);
    }
}

/// The slot of `s` just went into its channel's queue (channel::post), or
/// a request through a handle with its label did (channel::send), and that
/// holds the session from now on (spec 6.1, 6.5): until receive or the
/// stage Close takes it, or the request's thread ends, and lets the
/// reference go (`unref`).
pub fn hold(s: NonNull<Session>) {
    // SAFETY: the channel's caller holds a reference to the session; only
    // the count is touched.
    let refs = unsafe { refs(s) };
    *refs = refs.checked_add(1).expect("session references overflow");
}

/// Drops a reference to `s` that no handle held: the one `create` handed
/// out, or its slot's once receive or the stage Close took the slot. The
/// last reference queues the session for cleanup at `cause` (spec 7.7).
///
/// # Safety
/// The reference is the caller's, and the caller does not use it
/// afterwards.
pub unsafe fn unref(s: NonNull<Session>, cause: u8) {
    // SAFETY: the caller's reference keeps the session alive until here;
    // the pool keeps it in place until its portion.
    unsafe {
        let refs = refs(s);
        *refs = refs
            .checked_sub(1)
            .expect("a session is released once too often");
        if *refs == 0 {
            let item = NonNull::new_unchecked(&raw mut (*s.as_ptr()).cleanup);
            cleanup::enqueue(item, Object::Session(s), cause);
        }
    }
}

/// notify through a handle that names `s` (spec 5.3, 6.5): `bits` into
/// the session's slot, as channel::notify posts into the slot of label 0.
/// PEER_CLOSED once the channel closed. O(1).
pub fn notify(s: NonNull<Session>, bits: u64, cause: u8) -> Result<(), Error> {
    // SAFETY: the caller's handle holds the session, which holds the
    // channel; the slot lives as long as the session.
    unsafe { channel::post(channel(s), slot(s), bits, cause) }
}

/// The portion of a session nothing refers to (cleanup::portion), at
/// `level`: it gives its slot in the channel back, its place goes back to
/// the payer's pool, and then the references to the channel and to the
/// payer's shell go, each of which may queue what it held at `level`.
/// Its slot is in no queue: a queued slot holds the session. O(1).
///
/// # Safety
/// Nothing refers to the session, and it is in no queue.
pub unsafe fn clean(s: NonNull<Session>, level: u8) {
    // SAFETY: the caller's promise; only the fields are read.
    let (c, payer) = unsafe { ((*s.as_ptr()).channel, (*s.as_ptr()).payer) };
    channel::remove_source(c);
    // SAFETY: nothing uses the session afterwards; the payer's pool is
    // there, since the session holds the payer's shell.
    unsafe { process::free_session_slot(payer, s) };
    #[cfg(feature = "ktest")]
    LIVE.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    // Test builds poison the place past the pool's link, as for channels:
    // `refs` stops a use after free.
    #[cfg(feature = "ktest")]
    // SAFETY: the place is the pool's again; its first word is the link.
    unsafe {
        core::ptr::write_bytes(
            s.cast::<u8>().as_ptr().add(8),
            POISON,
            core::mem::size_of::<Session>() - 8,
        )
    };
    // SAFETY: the session's references to its channel and to its payer's
    // shell go with it.
    unsafe {
        channel::release(c, Rights::NONE, level);
        process::release_shell(payer, level);
    }
}

/// What test builds fill a gone session with, past the pool's link.
#[cfg(feature = "ktest")]
const POISON: u8 = 0xA5;

// The poison reaches `refs`, which `refs` checks.
#[cfg(feature = "ktest")]
const _: () = assert!(core::mem::offset_of!(Session, refs) >= 8);

#[cfg(feature = "ktest")]
pub use test_access::{in_use, payer, priority};

/// What the kernel tests read and steer here (crate::ktest).
#[cfg(feature = "ktest")]
mod test_access {
    use super::*;

    /// Sessions whose places have not gone back.
    pub fn in_use() -> usize {
        LIVE.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// The priority of the slot of `s`, which the test holds.
    pub fn priority(s: NonNull<Session>) -> u8 {
        // SAFETY: the test holds a reference to the session; only the slot is
        // read.
        unsafe { (*s.as_ptr()).slot.priority() }
    }

    /// The process that pays for `s`, which the test holds.
    pub fn payer(s: NonNull<Session>) -> NonNull<Process> {
        // SAFETY: the test holds a reference to the session; only the field is
        // read.
        unsafe { (*s.as_ptr()).payer }
    }
}
