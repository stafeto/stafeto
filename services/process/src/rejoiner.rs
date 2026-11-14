// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The thread of EntropyRejoin (rejoin.rs): it takes the new sessions of the
//! entropy service for the processes that asked, at the entropy service's
//! level (`proto_process::REJOIN_LEVEL`), so that the loop, at the process
//! service's level, never sends to the entropy service and a step of the
//! loop never waits for it. The loop gives a place of its queue a copy of the
//! service's root and tells the thread (a bit of the place); the thread sends
//! VERIFY_SESSION through the copy with a channel of its own, as a loader
//! does for a start (services/loader `heal_entropy`), which the root answers
//! with a new clone, puts the clone or its failure in the place and tells
//! the loop (REJOINED), which answers the process. The thread makes one
//! attempt for each request and never waits for a new instance: the client
//! asks again after its own pause. The thread's stack and message buffer
//! are its own.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use posix_process_service::rejoin::{Outcome, QUEUE};
use proto_wire::{Reader, Status};
use rt::handle::{Channel, Handle, Process, Thread};
use rt::sys::Received;
use rt::{Stack, abi, sys};

const STACK_SIZE: usize = 8 * 1024;
static STACK: Stack<STACK_SIZE> = Stack::new();
/// The thread's message buffer, four pages after the main thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 4 * 4096;

/// What the loop and the thread pass through a place of the queue: the copy
/// of the root, the session the thread got (0 for none), and whether the
/// thread is done. The loop writes the copy and clears the flag before it
/// tells the thread; the thread writes the session and sets the flag before
/// it tells the loop.
struct Place {
    root: AtomicU64,
    session: AtomicU64,
    /// Set when the root refused for good (no clones left).
    refused: AtomicBool,
    done: AtomicBool,
}

static PLACES: [Place; QUEUE] = [const {
    Place {
        root: AtomicU64::new(0),
        session: AtomicU64::new(0),
        refused: AtomicBool::new(false),
        done: AtomicBool::new(false),
    }
}; QUEUE];
/// The channel the thread waits on, and the copy of the loop's channel that
/// tells the loop (label REJOINED).
static WAITS: AtomicU64 = AtomicU64::new(0);
static TELLS: AtomicU64 = AtomicU64::new(0);
static THREAD: AtomicU64 = AtomicU64::new(0);

/// Starts the thread in `own`, the service's process; `tells` is the copy of
/// the loop's channel with NOTIFY and the label REJOINED. The copy of the
/// thread's channel the loop tells it through comes back.
pub fn start(own: &Handle<Process>, tells: Handle<Channel>) -> Result<Handle<Channel>, abi::Error> {
    let waits = sys::channel_create(proto_process::REJOIN_LEVEL)?;
    let wake = sys::handle_duplicate(&waits, abi::Rights::NOTIFY)?;
    WAITS.store(waits.into_raw().0, Ordering::Release);
    TELLS.store(tells.into_raw().0, Ordering::Release);
    // SAFETY: STACK is the thread's alone, and the page four after the main
    // thread's buffer is free.
    let thread = unsafe {
        sys::thread_create(
            own,
            serve,
            STACK.top(),
            0,
            proto_process::REJOIN_LEVEL,
            abi::Policy::Fifo,
            BUFFER,
        )
    }?;
    // The thread lives as long as the service.
    THREAD.store(thread.into_raw().0, Ordering::Release);
    sys::thread_start(&Handle::<Thread>::borrowed(abi::Handle(
        THREAD.load(Ordering::Acquire),
    )))?;
    Ok(wake)
}

/// Gives `place` the copy `root` of the entropy service's root and tells the
/// thread through `wake`; false when the thread could not be told (the copy
/// closes, and nothing was given).
pub fn give(wake: &Handle<Channel>, place: usize, root: Handle<Channel>) -> bool {
    let slot = &PLACES[place];
    slot.done.store(false, Ordering::Release);
    slot.session.store(0, Ordering::Release);
    slot.root.store(root.raw().0, Ordering::Release);
    if sys::notify(wake, 1 << place).is_err() {
        slot.root.store(0, Ordering::Release);
        return false;
    }
    // The thread closes the copy.
    let _ = root.into_raw();
    true
}

/// What the thread made of the request in `place`: None while it works; else
/// the outcome and, for a new session, the session.
pub fn take(place: usize) -> Option<(Outcome, Option<Handle<Channel>>)> {
    let slot = &PLACES[place];
    if !slot.done.load(Ordering::Acquire) {
        return None;
    }
    slot.done.store(false, Ordering::Relaxed);
    let raw = slot.session.swap(0, Ordering::Acquire);
    if raw != 0 {
        return Some((Outcome::Given, Some(Handle::from_raw(abi::Handle(raw)))));
    }
    let outcome = if slot.refused.swap(false, Ordering::Acquire) {
        Outcome::Refused
    } else {
        Outcome::Failed
    };
    Some((outcome, None))
}

extern "C" fn serve(_: u64) -> ! {
    let waits = Handle::<Channel>::borrowed(abi::Handle(WAITS.load(Ordering::Acquire)));
    // The channel offered with each request: the root answers a channel that
    // is no session of the entropy service with a new session and lets the
    // channel go, with no request sent through it.
    let Ok(offer) = sys::channel_create(proto_process::REJOIN_LEVEL) else {
        sys::thread_exit();
    };
    loop {
        match sys::receive(&waits) {
            Ok(Received::Notification { bits, .. }) => {
                for place in 0..PLACES.len() {
                    if bits >> place & 1 != 0 {
                        attempt(place, &offer);
                    }
                }
            }
            Ok(_) => {}
            Err(_) => sys::thread_exit(),
        }
    }
}

/// One attempt for the request in `place`, then the loop is told.
fn attempt(place: usize, offer: &Handle<Channel>) {
    let slot = &PLACES[place];
    let root = Handle::<Channel>::from_raw(abi::Handle(slot.root.swap(0, Ordering::Acquire)));
    let session = verify(&root, offer);
    drop(root);
    match session {
        Ok(session) => slot.session.store(session.into_raw().0, Ordering::Release),
        Err(outcome) => slot
            .refused
            .store(outcome == Outcome::Refused, Ordering::Release),
    }
    slot.done.store(true, Ordering::Release);
    let tells = Handle::<Channel>::borrowed(abi::Handle(TELLS.load(Ordering::Acquire)));
    let _ = sys::notify(&tells, 1);
}

/// VERIFY_SESSION through `root` with a copy of `offer`: the new session of
/// the entropy service; `Refused` when the root says it has no clones left
/// (the kernel's LimitReached, which reaches the client as it is); `Failed`
/// for any other refusal (the root closed with its instance, a failed call).
fn verify(root: &Handle<Channel>, offer: &Handle<Channel>) -> Result<Handle<Channel>, Outcome> {
    let offered = sys::handle_duplicate(offer, abi::Rights::SEND | abi::Rights::TRANSFER)
        .map_err(|_| Outcome::Failed)?;
    let request = proto_entropy::Method::VerifySession.header().bytes();
    let mut reply =
        sys::send_handles(root, &request, [offered.erase()]).map_err(|_| Outcome::Failed)?;
    let mut buffer = [0; abi::MESSAGE_MAX];
    match Reader::new(reply.bytes(&mut buffer)).u32() {
        Ok(0) => reply
            .handles
            .take::<Channel>(0)
            .map_err(|_| Outcome::Failed),
        Ok(code) if Status::from_code(code) == Status::Kernel(abi::Error::LimitReached) => {
            Err(Outcome::Refused)
        }
        _ => Err(Outcome::Failed),
    }
}
