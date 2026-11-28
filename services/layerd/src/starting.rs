// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The answers STARTING of the service, counted by the cause. A client that gets STARTING asks
//! again after a pause, so each answer is a wait for it; the measurement of the layered root reads
//! how many there were and why (the line the service prints when the counts grow: `layerd:
//! STARTING answered ...`), before READY (`Build`) and after it.

use core::sync::atomic::{AtomicU32, Ordering};

/// Why a request was answered STARTING.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Cause {
    /// The index is being built (before READY).
    Build,
    /// The notary of identities is not ready.
    Notary,
    /// The table of jobs is full, or the session holds its share of it.
    Jobs,
    /// The table of copies up is full (or the queue of files, or the waiters of a session).
    Copies,
    /// The arena of names waits for its compaction.
    Compaction,
    /// The queue of the reaper is full.
    Reaper,
    /// No place for the lower directory of a listing.
    Listing,
    /// A change waits for the lock of the changes.
    Lock,
}

/// The names of the causes in the line, in the order of `Cause`.
pub const NAMES: [&str; 8] = [
    "build",
    "notary",
    "jobs",
    "copies",
    "compaction",
    "reaper",
    "listing",
    "lock",
];

static COUNTS: [AtomicU32; 8] = [const { AtomicU32::new(0) }; 8];

/// Counts an answer STARTING for `cause`; the code of the answer.
pub fn code(cause: Cause) -> u32 {
    COUNTS[cause as usize].fetch_add(1, Ordering::Relaxed);
    proto_layer::STARTING
}

/// The counts so far, in the order of `NAMES`.
pub fn counts() -> [u32; 8] {
    core::array::from_fn(|i| COUNTS[i].load(Ordering::Relaxed))
}
