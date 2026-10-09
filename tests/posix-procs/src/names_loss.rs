// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The loss of a reply in the middle of an operation on names. The request
//! was answered by the service and the answer did not reach the layer: the
//! hook of the driver (`posix_abi::change::probe_hook`) drops the first reply
//! of one kind of request, and the loop of the operation sends the same
//! request again. names-loss.c reads what the operation did.
use core::sync::atomic::{AtomicU32, Ordering::SeqCst};
use posix_abi::change::{Probe, probe_hook};

/// The kinds, as names-loss.c numbers them.
const START: u32 = 1;
const SECOND: u32 = 2;
const DONE: u32 = 3;
const COMMIT: u32 = 4;
const RELEASE: u32 = 5;
const KINDS: usize = 6;

/// The kind whose next reply is lost (0 for none), how many replies went,
/// and how many requests of each kind the loop sent.
static ARMED: AtomicU32 = AtomicU32::new(0);
static LOST: AtomicU32 = AtomicU32::new(0);
static SEEN: [AtomicU32; KINDS] = [const { AtomicU32::new(0) }; KINDS];

fn index(kind: Probe) -> Option<u32> {
    Some(match kind {
        Probe::Start => START,
        Probe::Second => SECOND,
        Probe::Done => DONE,
        Probe::Commit => COMMIT,
        Probe::Release => RELEASE,
        Probe::Step => return None,
    })
}

fn lose(kind: Probe) -> bool {
    let Some(kind) = index(kind) else {
        return false;
    };
    SEEN[kind as usize].fetch_add(1, SeqCst);
    // Once for each arming: the repeated request is answered.
    if ARMED.load(SeqCst) == kind && ARMED.compare_exchange(kind, 0, SeqCst, SeqCst).is_ok() {
        LOST.fetch_add(1, SeqCst);
        return true;
    }
    false
}

/// Loses the next reply of `kind` (1 Start, 2 Second, 3 the Step that
/// commits, 4 the Commit of a Data job, 5 Release), and counts afresh.
#[unsafe(no_mangle)]
pub extern "C" fn files_loss_arm(kind: i32) -> i32 {
    if !(START as i32..=RELEASE as i32).contains(&kind) {
        return -1;
    }
    LOST.store(0, SeqCst);
    for seen in &SEEN {
        seen.store(0, SeqCst);
    }
    ARMED.store(kind as u32, SeqCst);
    probe_hook(Some(lose));
    0
}

/// How many replies were lost since the arming.
#[unsafe(no_mangle)]
pub extern "C" fn files_loss_lost() -> i32 {
    LOST.load(SeqCst) as i32
}

/// How many requests of `kind` the loop sent since the arming.
#[unsafe(no_mangle)]
pub extern "C" fn files_loss_seen(kind: i32) -> i32 {
    SEEN.get(kind as usize)
        .map_or(-1, |seen| seen.load(SeqCst) as i32)
}

/// No more hook.
#[unsafe(no_mangle)]
pub extern "C" fn files_loss_disarm() {
    ARMED.store(0, SeqCst);
    probe_hook(None);
}
