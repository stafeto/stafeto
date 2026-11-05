// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's place for the package service (sub-project 5, part 3b;
//! spec 5, 3.11): the session with the service (`proto_pkg`) that the start
//! area gives in the slot `Packages`, as `display` keeps the display
//! service's. The part holds the session and its life across `fork`, spawn
//! and `exec`:
//!
//! * `session()` is the process's `Packages` session (SEND, DUPLICATE,
//!   TRANSFER), None in an image without the package service. LIST, INFO
//!   and the other requests go on it; it is sent, never closed or replaced
//!   by the caller. The service asks the process service who the caller is
//!   (Vouch) for the requests that change the store, so the session itself
//!   gives no right.
//! * A forked or spawned child gets a session of its own (a CLONE the
//!   parent made, `clone_session`); `exec` moves the session to the new
//!   image. A set-ID program starts without one (`posix-crt`).
//!
//! The session is cloned for every `fork` and spawn that has one: one
//! request to the package service (`cargo xtask pkg-slot` measures the
//! price in a fork). A refusal fails no fork: the child has no session and
//! the line says so. A service that ended (PEER_CLOSED) closes the
//! process's session, so that no later fork asks again.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rt::handle::{Channel, Handle};

/// A refusal of a CLONE was said already.
static REFUSED: AtomicBool = AtomicBool::new(false);

/// The session with the package service, 0 for none.
static SESSION: AtomicU64 = AtomicU64::new(0);

/// The process's session with the package service, which the start gives
/// (init's CONNECT, or the loader's slot Packages).
///
/// # Safety
/// Startup, on the only thread.
pub unsafe fn init(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
}

/// A forked child: `session`, the clone the parent made, takes the place of
/// the parent's value, which names nothing of the child's.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
}

/// The session with the package service, for the requests and for the
/// clones a child gets.
pub fn session() -> Option<rt::abi::Handle> {
    match SESSION.load(Ordering::Acquire) {
        0 => None,
        raw => Some(rt::abi::Handle(raw)),
    }
}

/// Hides the session for the calls of a fork or spawn that follow (a
/// probe of the price of the clone), or shows it again: the value that was
/// there comes back to the caller, 0 for none.
#[cfg(feature = "thread-probe")]
pub fn probe_swap_session(raw: u64) -> u64 {
    SESSION.swap(raw, Ordering::AcqRel)
}

/// A clone of the process's session for a child (proto_pkg CLONE), when it
/// has one. A refusal fails no fork or spawn: the child gets no session. A
/// service that ended (PEER_CLOSED) closes the process's session; another
/// refusal (the service at its limit of sessions) writes a line, once for the process.
pub(crate) fn clone_session() -> Option<Handle<Channel>> {
    let packages = session()?;
    match rt::service::clone_session(
        &Handle::<Channel>::borrowed(packages),
        &proto_pkg::Method::Clone.header().bytes(),
    ) {
        Ok(clone) => Some(clone),
        Err(proto_wire::Status::Kernel(rt::abi::Error::PeerClosed)) => {
            let raw = SESSION.swap(0, Ordering::AcqRel);
            if raw != 0 {
                drop(Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
            }
            None
        }
        Err(status) => {
            // One line for the process, not one for each fork of a busy system.
            if !REFUSED.swap(true, Ordering::Relaxed) {
                rt::println!(
                    "posix: the package service refused a session for a child ({status:?}); the child has none"
                );
            }
            None
        }
    }
}
