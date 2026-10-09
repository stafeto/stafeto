// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The client side of the Change jobs of the file service, over plain
//! numbers so that the host tests run it: the loop of one operation (Start,
//! Second, Step until done) against a wire the caller supplies, the Release
//! that follows it, the choice of the records a thread left by a long jump,
//! the refusals the layer gives to the virtual names of the terminal, and the
//! access check by the metadata of a node.
//!
//! The wire of the layer sends the requests of the service; the wire of the
//! tests answers them from a model. The loop never takes a new key after a
//! lost reply: it sends the same request again, and the service, which keeps
//! the job by its key, executes the effect at most once.
#![no_std]
#![forbid(unsafe_code)]

pub mod dirent;

use entries::{Frame, nested};
use posix_fd::{ControlPhase, ControlSnapshot, ControlToken, OwnerToken};
use proto_fs::{
    Base, ChangeDone, ChangeOp, ChangePhase, ChangeStart, DataOutcome, DataPhase, DataResult,
    DataStart, OpenKey, RESULT_MAX,
};
use proto_wire::Status;

/// The pause before a Start is sent again after `refusals` answers of
/// JOBS_FULL, in nanoseconds: 1, 2, 4, 8 and then 16 milliseconds. A thread
/// that waits for room long leaves the service to the work that frees it.
pub fn room_pause_ns(refusals: u32) -> i64 {
    1_000_000 << refusals.min(4)
}

/// What every loop needs of the service apart from its own requests: the
/// Release that ends a job, the refresh of the credentials, and the wait for
/// room in the table.
pub trait Service {
    fn release(&mut self, key: OpenKey) -> Result<(), Status>;
    /// Complete a refresh of the credentials the service asked for.
    fn authenticate(&mut self) -> Result<(), Status>;
    /// The table of the service is full: free what this process can free, and
    /// sleep one millisecond outside the deferral of signals.
    fn wait_for_room(&mut self);
}

/// What the loop needs of the world around one operation.
pub trait Wire: Service {
    /// Whether the record of the operation is still the operation's own. A
    /// child of `fork` made in a handler has dropped it: the job belongs to
    /// the parent, and the child answers EIO when the handler returns.
    fn live(&mut self) -> bool;
    fn start(&mut self, start: &ChangeStart<'_>) -> Result<ChangePhase, Status>;
    fn second(&mut self, key: OpenKey, base: Base, bytes: &[u8]) -> Result<(), Status>;
    fn step(
        &mut self,
        key: OpenKey,
        out: &mut [u8; RESULT_MAX],
    ) -> Result<Option<ChangeDone>, Status>;
}

/// Why an operation did not run to the end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    /// EIO: the key came back retired, the job vanished, or the record of the
    /// operation went with a `fork`. The effect may or may not have happened.
    Io,
    /// A status of the protocol the loop does not repeat on its own.
    Status(Status),
}

/// Whether a failed request goes again unchanged. `room` says that the
/// request may meet JOBS_FULL (Start alone does).
fn again<W: Service>(wire: &mut W, status: Status, room: bool) -> Result<(), Failure> {
    match status {
        // The handler ran, or the request never left: send it again.
        Status::Kernel(abi::Error::Interrupted) => Ok(()),
        Status::Unknown(proto_fs::AUTHENTICATING) => wire.authenticate().map_err(Failure::Status),
        Status::Unknown(proto_fs::JOBS_FULL) if room => {
            wire.wait_for_room();
            Ok(())
        }
        // The key is retired, taken, or unknown, or the table is full where
        // it cannot be: the job and its outcome are not where they should be.
        Status::Unknown(
            proto_fs::OPEN_RETIRED
            | proto_fs::TOO_MANY_OPEN_FILES
            | proto_fs::NO_ENTRY
            | proto_fs::JOBS_FULL,
        ) => Err(Failure::Io),
        status => Err(Failure::Status(status)),
    }
}

/// One operation: Start, then Second for the operations with two paths,
/// then Step until the job is done. The bytes of the result go to `out`. The
/// key is the caller's and stays the same through every repeat. The caller
/// sends Release afterwards, whatever this returns.
pub fn drive<W: Wire>(
    wire: &mut W,
    start: &ChangeStart<'_>,
    second: Option<(Base, &[u8])>,
    out: &mut [u8; RESULT_MAX],
) -> Result<ChangeDone, Failure> {
    loop {
        if !wire.live() {
            return Err(Failure::Io);
        }
        match wire.start(start) {
            Ok(_) => break,
            Err(status) => again(wire, status, true)?,
        }
    }
    if let Some((base, bytes)) = second {
        loop {
            if !wire.live() {
                return Err(Failure::Io);
            }
            match wire.second(start.key, base, bytes) {
                Ok(()) => break,
                Err(status) => again(wire, status, false)?,
            }
        }
    }
    loop {
        if !wire.live() {
            return Err(Failure::Io);
        }
        match wire.step(start.key, out) {
            Ok(Some(done)) => return Ok(done),
            Ok(None) => {}
            Err(status) => again(wire, status, false)?,
        }
    }
}

/// Release until the service answers. A session that is gone has no job to
/// release, and a refusal the service never gives ends the loop too: the
/// record of the job has done what it can.
pub fn release<W: Service>(wire: &mut W, key: OpenKey) {
    loop {
        match wire.release(key) {
            Ok(()) => return,
            Err(Status::Kernel(abi::Error::Interrupted)) => {}
            // The cleanup of a Data job takes a step for each private page.
            Err(Status::Unknown(proto_fs::RESOLVING)) => {}
            Err(Status::Unknown(proto_fs::AUTHENTICATING)) => {
                if wire.authenticate().is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// What the loop of a Data job needs of the world: the requests of the
/// service by the key and by the job, on top of what every loop needs.
pub trait DataWire: Service {
    /// As `Wire::live`.
    fn live(&mut self) -> bool;
    fn start(&mut self, args: &DataStart) -> Result<(DataPhase, u64), Status>;
    fn step(&mut self, job: u64) -> Result<(), Status>;
    fn commit(&mut self, job: u64, args: &DataStart) -> Result<DataOutcome, Status>;
    /// The service wants the clock read again before the effect: let the
    /// other threads run, and ask again.
    fn pause(&mut self);
}

/// One Data operation that moves no bytes (a truncate): Start, Step until the
/// job is ready, Commit. The key is the caller's and stays the same through
/// every repeat; a lost reply is answered by the same request, and the
/// service gives the saved outcome of a Commit it already made, so the effect
/// happens at most once. The caller sends Release afterwards, whatever this
/// returns: the service ends the Data job with it.
///
/// A terminal refusal of the service (a status that comes with the job
/// completed and without effect) is `Failure::Status`.
pub fn drive_data<W: DataWire>(wire: &mut W, args: &DataStart) -> Result<(), Failure> {
    let job = loop {
        if !wire.live() {
            return Err(Failure::Io);
        }
        match wire.start(args) {
            Ok((_, job)) => break job,
            // JOBS_FULL (no place for the job in the service) waits for room;
            // TOO_MANY_OPEN_FILES (the key is taken by another generation, or
            // the client's own count is wrong) is an I/O error, as in Change.
            Err(status) => again(wire, status, true)?,
        }
    };
    loop {
        if !wire.live() {
            return Err(Failure::Io);
        }
        match wire.step(job) {
            Ok(()) => break,
            Err(Status::Unknown(proto_fs::RESOLVING)) => {}
            Err(status) => again(wire, status, false)?,
        }
    }
    loop {
        if !wire.live() {
            return Err(Failure::Io);
        }
        match wire.commit(job, args) {
            Ok(outcome) => {
                return match outcome.result {
                    DataResult::Bytes(_) => Ok(()),
                    DataResult::FailedNoEffect(code) => Err(Failure::Status(Status::Unknown(code))),
                    DataResult::None => Err(Failure::Io),
                };
            }
            // The service reads the clock for the effect: ask again.
            Err(Status::Unknown(proto_fs::TIME_DEFERRED | proto_fs::RESOLVING)) => wire.pause(),
            Err(status) => again(wire, status, false)?,
        }
    }
}

/// The record a thread must release now, found among `records`.
///
/// `me` is the thread that collects (None for a helper that only takes
/// records without an owner), `current` the frame where its operation began,
/// and `skip` the record of that operation itself. A record of `me` whose
/// frame does not contain `current` is abandoned: the operation that made it
/// has left by a long jump, or its thread frame is gone. A record without an
/// owner belongs to a thread that ended; it is released by whoever finds it.
/// A record left by a long jump stays until the thread begins an operation
/// from a frame no deeper than the left one (see the test of that limit).
/// The second field says that the record is `me`'s own, to be acknowledged
/// after its Release.
pub fn pick_abandoned(
    me: Option<OwnerToken>,
    current: Frame,
    skip: Option<ControlToken>,
    records: impl Iterator<Item = (ControlToken, ControlSnapshot<Frame>)>,
) -> Option<(ControlToken, bool)> {
    for (token, snapshot) in records {
        if Some(token) == skip || snapshot.phase == ControlPhase::Cleaned {
            continue;
        }
        match snapshot.owner {
            None => return Some((token, false)),
            Some(owner) if Some(owner) == me && !nested(current, snapshot.recovery) => {
                return Some((token, true));
            }
            Some(_) => {}
        }
    }
    None
}

/// The operations with a path that a virtual name of the terminal may meet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Named {
    Unlink,
    Rmdir,
    Mkdir,
    Symlink,
    Link,
    Rename,
    Access,
    Chmod,
    Chown,
    Times,
}

/// The answer of the layer for a virtual name, before any request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// EEXIST: the name exists.
    Exists,
    /// EBUSY: the name cannot go.
    Busy,
    /// EXDEV: the name lies on another device than the RAM service.
    CrossDevice,
    /// EROFS: the service of the terminal keeps its metadata.
    ReadOnly,
    /// Access checks the metadata the terminal service gives for stat.
    ByMetadata,
}

/// What the layer answers for an operation whose first path is a virtual name
/// (`first`) or whose second path is one (`second`). The first path is the
/// only path of the single-path operations, the name that Mkdir and Symlink
/// create, the old name of Link and Rename. The second path is the new name
/// of Link and Rename. A link or rename from a virtual name is EXDEV before
/// the new name is looked at.
pub fn virtual_refusal(op: Named, first: bool, second: bool) -> Option<Refusal> {
    match op {
        Named::Unlink | Named::Rmdir if first => Some(Refusal::Busy),
        Named::Mkdir | Named::Symlink if first => Some(Refusal::Exists),
        Named::Link | Named::Rename if first => Some(Refusal::CrossDevice),
        Named::Link if second => Some(Refusal::Exists),
        Named::Rename if second => Some(Refusal::CrossDevice),
        Named::Access if first => Some(Refusal::ByMetadata),
        Named::Chmod | Named::Chown | Named::Times if first => Some(Refusal::ReadOnly),
        _ => None,
    }
}

/// The bits of `access` (R_OK 4, W_OK 2, X_OK 1) that a node with these
/// metadata gives to the caller `uid`, `gid`: whether all are given. The
/// superuser reads and writes everything and executes what has an execute bit
/// or is a directory. No supplementary groups yet.
pub fn mode_allows(
    mode: u32,
    is_directory: bool,
    owner: u32,
    group: u32,
    uid: u32,
    gid: u32,
    access: u32,
) -> bool {
    let wanted = access & 7;
    if uid == 0 {
        return wanted & 1 == 0 || is_directory || mode & 0o111 != 0;
    }
    let granted = if uid == owner {
        (mode >> 6) & 7
    } else if gid == group {
        (mode >> 3) & 7
    } else {
        mode & 7
    };
    wanted & !granted == 0
}

/// Whether the operation takes two paths.
pub fn two_paths(op: ChangeOp) -> bool {
    op.needs_second() && op != ChangeOp::Symlink
}

#[cfg(test)]
mod tests;
