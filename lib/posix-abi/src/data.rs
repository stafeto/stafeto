// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's place for the data file service (`proto_data`): the session that the start area
//! gives in the slot `Data`, as `packages` keeps the package service's. The slot is empty until a
//! process uses `/data` (the process takes a session from the root of the service with TakeRoot
//! and SESSION, step by step in the layer's paths for `/data`); a forked or spawned child gets a
//! clone of the session only when it holds descriptions of `/data` or a current directory there,
//! and `exec` moves the session to the new image. A set-ID program starts with the session the
//! loader verified with the service's root: the genuine one with its descriptions, or none.
//!
//! This part holds the session and its life across `fork`. The session is sent, never closed or
//! replaced by a caller.

use core::sync::atomic::{AtomicU64, Ordering};
use rt::handle::{Channel, Handle};

/// The session with the data file service, 0 for none.
static SESSION: AtomicU64 = AtomicU64::new(0);

/// The process's session with the data file service, which the loader's slot Data gives.
///
/// # Safety
/// Startup, on the only thread.
pub unsafe fn init(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
}

/// A forked child: `session`, the clone the parent made, takes the place of the parent's value,
/// which names nothing of the child's.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
}

/// The session with the data file service, for the requests.
pub fn session() -> Option<rt::abi::Handle> {
    match SESSION.load(Ordering::Acquire) {
        0 => None,
        raw => Some(rt::abi::Handle(raw)),
    }
}
