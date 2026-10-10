// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Authenticated WAIT ingress retains outcomes independently of Control keys.
//! The service must check the genuine Places/label pair before every entry.

use super::wait_receipts::{Id, Queue};
use crate::{Fds, Ram};
use proto_fs::{WaitKey, WaitPhase, WaitReply, WaitStart};

pub fn replay(
    queue: &Queue,
    place: usize,
    owner: u64,
    wire: WaitStart,
) -> Result<Option<WaitReply>, u32> {
    wire.validate().map_err(|error| error.code())?;
    let Some(id) = queue.occupied(place, owner, wire.key.slot)? else {
        return Ok(None);
    };
    if id.key() != wire.key {
        return Err(if wire.key.generation <= id.key().generation {
            proto_fs::OPEN_RETIRED
        } else {
            proto_fs::JOBS_FULL
        });
    }
    queue.same_start(id, wire)?;
    queue.query(id).map(Some)
}

pub fn start(
    queue: &mut Queue,
    ram: &mut Ram<'_>,
    fds: &Fds,
    place: usize,
    owner: u64,
    wire: WaitStart,
) -> Result<WaitReply, u32> {
    if let Some(result) = replay(queue, place, owner, wire)? {
        return Ok(result);
    }
    if queue.is_retired(place, owner, wire.key)? {
        return Err(proto_fs::OPEN_RETIRED);
    }
    if fds.departed {
        return Err(proto_fs::BAD_FD);
    }
    let captured = ram.capture_wait(fds, wire)?;
    let id = queue.admit(place, owner, wire, captured, &mut ram.storage)?;
    queue.query(id)
}

fn exact(queue: &Queue, place: usize, owner: u64, key: WaitKey) -> Result<Option<Id>, u32> {
    key.validate()?;
    match queue.occupied(place, owner, key.slot)? {
        Some(id) if id.key() == key => Ok(Some(id)),
        Some(id) => Err(if key.generation <= id.key().generation {
            proto_fs::OPEN_RETIRED
        } else {
            proto_fs::JOBS_FULL
        }),
        None => Ok(None),
    }
}

pub fn query(queue: &Queue, place: usize, owner: u64, key: WaitKey) -> Result<WaitReply, u32> {
    if let Some(id) = exact(queue, place, owner, key)? {
        return queue.query(id);
    }
    Err(if queue.is_retired(place, owner, key)? {
        proto_fs::OPEN_RETIRED
    } else {
        proto_fs::NO_ENTRY
    })
}

/// The true flag asks the service to cancel its active actor, without discarding it.
pub fn cancel(
    queue: &mut Queue,
    place: usize,
    owner: u64,
    key: WaitKey,
) -> Result<(WaitReply, bool), u32> {
    if let Some(id) = exact(queue, place, owner, key)? {
        let active = queue.request_cancel(id)?;
        return Ok((queue.query(id)?, active));
    }
    queue.retire(place, owner, key)?;
    Ok((
        WaitReply {
            phase: WaitPhase::Complete,
            result: proto_fs::LOCK_CANCELLED,
        },
        false,
    ))
}

/// Only a canonical terminal receipt can be released; absence fences a late Start.
pub fn release(
    queue: &mut Queue,
    ram: &mut Ram<'_>,
    place: usize,
    owner: u64,
    key: WaitKey,
) -> Result<(), u32> {
    if let Some(id) = exact(queue, place, owner, key)? {
        return queue.release(id, &mut ram.storage);
    }
    queue.retire(place, owner, key)
}

#[cfg(test)]
#[path = "wait_server_tests.rs"]
mod tests;
