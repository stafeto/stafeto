// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Authenticated WAIT ingress retains outcomes independently of Control keys.
//! The service must check the genuine Places/label pair before every entry.

use super::wait_receipts::{Id, Queue};
use super::{
    Owner,
    actor::{Error, Response},
    service::LockService,
    waiters::{Input, Phase as SleepPhase, Pool, RegistrationToken},
};
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

/// The sole shared actor checks the genuine numeric fd before every attempt.
pub fn begin(
    queue: &mut Queue,
    locks: &mut LockService,
    ram: &mut Ram<'_>,
    id: Id,
    fds: Option<&Fds>,
) -> Result<(), u32> {
    assert!(!locks.busy());
    let (captured, phase, cancelling) = queue.snapshot(id)?;
    if phase != super::wait_receipts::Phase::Ready || cancelling {
        return Err(proto_fs::INVALID_ARGUMENT);
    }
    if !source_live(ram, fds, captured) {
        return queue.complete(id, terminal(proto_fs::BAD_FD));
    }
    match locks.start(&mut ram.storage, captured.request, captured.root) {
        Ok(()) => queue.activate(id),
        Err(error) => {
            let result = super::request::reply(Err(error));
            queue.complete(id, terminal(result.result))
        }
    }
}

fn source_live(ram: &Ram<'_>, fds: Option<&Fds>, captured: super::request::Captured) -> bool {
    fds.filter(|fds| !fds.departed)
        .and_then(|fds| ram.live_description(fds, captured.source).ok())
        .is_some_and(|(inode, _)| inode == captured.request.inode)
}
fn terminal(result: u32) -> WaitReply {
    WaitReply {
        phase: WaitPhase::Complete,
        result,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Finish {
    Retried(Id),
    Sleeping(RegistrationToken),
    /// Publish before notifying and closing the corresponding registration's handle.
    Complete(Id),
}

pub fn finish(
    queue: &mut Queue,
    sleepers: &mut Pool,
    ram: &mut Ram<'_>,
    result: Result<Response, Error>,
    fds: Option<&Fds>,
    pid_live: impl FnOnce(u32) -> bool,
) -> Result<Finish, u32> {
    let id = queue.active().ok_or(proto_fs::INVALID_ARGUMENT)?;
    let (captured, _, cancelling) = queue.snapshot(id)?;
    if result == Err(Error::Cancelled) && !cancelling {
        let owner_live = match captured.request.owner {
            Owner::Process(pid) => pid_live(pid),
            Owner::Description { slot, generation } => ram
                .lock_parts()
                .1
                .live(crate::storage::Token { slot, generation }),
        };
        if owner_live && source_live(ram, fds, captured) && queue.retry_active()? {
            return Ok(Finish::Retried(id));
        }
    }
    if matches!(result, Err(Error::Conflict(_))) {
        if cancelling {
            queue.complete(id, terminal(proto_fs::LOCK_CANCELLED))?;
        } else if !source_live(ram, fds, captured) {
            queue.complete(id, terminal(proto_fs::BAD_FD))?;
        } else {
            let super::actor::Command::Set(Some(kind)) = captured.request.command else {
                return Err(proto_fs::INVALID_ARGUMENT);
            };
            match sleepers.register(Input {
                receipt: id,
                root: captured.root,
                inode: captured.request.inode,
                range: captured.request.range,
                kind,
            }) {
                Ok(registration) => {
                    if sleepers.snapshot(registration)?.1 == SleepPhase::Running {
                        sleepers.sleep(registration)?;
                    }
                    queue.sleep(id, false)?;
                    return Ok(Finish::Sleeping(registration));
                }
                Err(code) => queue.complete(id, terminal(code))?,
            }
        }
    } else {
        queue.complete_active(result)?;
    }
    Ok(Finish::Complete(id))
}

#[cfg(test)]
#[path = "wait_server_tests.rs"]
mod tests;
