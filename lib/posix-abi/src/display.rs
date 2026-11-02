// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's place for the display service (sub-project 3, part 3a;
//! spec 3, 3.8): the session with the service (`proto_gpu`) that the start
//! area gives in the slot `Display`, as `random` keeps the entropy
//! service's. The part holds the session and its life across `fork`,
//! spawn and `exec`, and the display piece of the memory map (the buffer of
//! the screen). The calls of the screen itself (OPEN, FLUSH, CLOSE and the
//! C functions on them) are part 3b's and build on this interface:
//!
//! * `session()` is the process's `Display` session (SEND, DUPLICATE,
//!   TRANSFER), None in an image without the display service: the C
//!   function then answers ENODEV. OPEN goes on it; it is sent, never
//!   closed or replaced by the caller.
//! * `map_buffer(buffer, pages)` makes the buffer that OPEN returned the
//!   process's display piece and gives its address (EBUSY with one
//!   already, ENOMEM past the limits); `unmap_buffer()` takes it out
//!   (CLOSE, `exec`, exit), with the object's handle.
//! * A forked child gets a session of its own (a CLONE the parent made,
//!   `clone_session`), no owner session and no display piece: the hole
//!   where the parent's buffer is faults on any touch. `munmap` and
//!   `mprotect` on the piece give EINVAL.
//!
//! The session is cloned for every `fork` and spawn that has one: one
//! request to the display service (`cargo xtask posix-display` measures
//! the price in a fork). A refusal fails no fork: the child has no session
//! and its screen calls give ENODEV; the line says so.

use core::sync::atomic::{AtomicU64, Ordering};
use rt::handle::{Channel, Handle, Memory};

/// The session with the display service, 0 for none.
static SESSION: AtomicU64 = AtomicU64::new(0);

/// The process's session with the display service, which the start gives
/// (init's CONNECT, or the loader's slot Display).
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

/// The session with the display service, for the requests and for the
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

/// A clone of the process's session for a child (proto_gpu CLONE), when it
/// has one. A refusal (a service that ended or restarts, or is at its
/// limit) fails no fork or spawn: the child gets no session; the line says
/// so.
pub(crate) fn clone_session() -> Option<Handle<Channel>> {
    let display = session()?;
    match rt::service::clone_session(
        &Handle::<Channel>::borrowed(display),
        &proto_gpu::Method::Clone.header().bytes(),
    ) {
        Ok(clone) => Some(clone),
        Err(status) => {
            rt::println!(
                "posix: the display service refused a session for a child ({status:?}); the child has none"
            );
            None
        }
    }
}

/// `buffer`, `pages` pages with MAP_READ and MAP_WRITE, becomes the display
/// piece of the memory map: its address. EBUSY when the map has one,
/// ENOMEM past the room, the limits or the table; the handle goes with a
/// refusal.
pub fn map_buffer(buffer: Handle<Memory>, pages: usize) -> Result<usize, i32> {
    crate::allocation::heap(|state| state.map_display(buffer, pages))
}

/// The display piece leaves the map and the process, and its object
/// closes; Ok when there is none.
pub fn unmap_buffer() -> Result<(), i32> {
    crate::allocation::heap(|state| state.unmap_display())
}

/// The address and pages of the display piece, None without one.
pub fn buffer() -> Option<(usize, usize)> {
    crate::allocation::regions(|map| map.display_piece())
}
