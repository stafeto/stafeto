// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Bounded departure preserves canonical publication and Notify custody order.

use super::waiters::Pool;
use super::{
    wait_notifications::Notifications,
    wait_receipts::{Queue, SHARE},
};
use crate::Ram;
use proto_fs::WaitPhase;

const PORTION: usize = 8;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Progress {
    pub visited: usize,
    pub released: usize,
    pub cancel_actor: bool,
}

/// The caller authenticates the full Places/label and cancels the sole Actor
/// when requested. Active receipts remain paid until its canonical completion.
pub fn part<H>(
    queue: &mut Queue,
    sleepers: &mut Pool,
    notifications: &mut Notifications<H>,
    ram: &mut Ram<'_>,
    owner: (usize, u64),
    first: usize,
    mut notify: impl FnMut(&H),
) -> Result<Progress, u32> {
    let (place, label) = owner;
    if first > SHARE || place >= crate::places::COUNT || label == 0 {
        return Err(proto_fs::INVALID_ARGUMENT);
    }
    let mut progress = Progress::default();
    for slot in first..SHARE.min(first.saturating_add(PORTION)) {
        progress.visited += 1;
        let Some(id) = queue.occupied(place, label, slot as u32)? else {
            continue;
        };
        if queue.query(id)?.phase != WaitPhase::Complete {
            progress.cancel_actor |= queue.request_cancel(id)?;
        }
        if queue.query(id)?.phase == WaitPhase::Complete {
            notifications.complete(queue, sleepers, id, &mut notify)?;
            queue.release(id, &mut ram.storage)?;
            progress.released += 1;
        }
    }
    Ok(progress)
}

#[cfg(test)]
#[path = "wait_departure_tests.rs"]
mod tests;
