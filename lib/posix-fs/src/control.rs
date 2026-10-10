// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact source entries and typed terminal payloads survive lock cleanup.

use super::{FsError, PosixFs, RamTarget, Target};
use entries::{Frame, nested};
use posix_fd::{
    ControlClaimToken, ControlPhase, ControlResult, ControlSnapshot, ControlToken, EntryToken,
    OwnerToken,
};
use proto_fs::{DataDescription, LockCommand, LockKind, LockPhase, LockReply, LockStart, OpenKey};
use proto_wire::Reader;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Input {
    pub command: LockCommand,
    pub kind: LockKind,
    pub whence: u32,
    pub start: i64,
    pub length: i64,
    pub pid: i32,
}

/// Constructed only from a strictly decoded complete service response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalReply(LockReply);
impl TerminalReply {
    pub fn read(bytes: &[u8]) -> Result<Self, FsError> {
        Self::from_reply(LockReply::read(Reader::new(bytes)).map_err(FsError::from)?)
    }
    /// Validate an already decoded receipt without a second wire buffer.
    pub fn from_reply(reply: LockReply) -> Result<Self, FsError> {
        reply.validate().map_err(FsError::from)?;
        if reply.phase != LockPhase::Complete {
            return Err(FsError::InvalidArgument);
        }
        Ok(Self(reply))
    }
    pub fn reply(self) -> LockReply {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelReason {
    Abandoned,
    Close,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockRecovery {
    source: EntryToken,
    backend: RamTarget,
    input: Input,
    outcome: Option<LockReply>,
    cancel_reason: CancelReason,
}
impl LockRecovery {
    pub fn source(self) -> EntryToken {
        self.source
    }
    pub fn backend(self) -> RamTarget {
        self.backend
    }
    pub fn input(self) -> Input {
        self.input
    }
    pub fn outcome(self) -> Option<LockReply> {
        self.outcome
    }
    pub fn cancel_reason(self) -> CancelReason {
        self.cancel_reason
    }
    pub fn request(self, token: ControlToken) -> LockStart {
        LockStart {
            key: OpenKey {
                slot: token.slot() as u32,
                generation: token.generation(),
            },
            description: DataDescription {
                packed: self.backend.fd()
                    | self.backend.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT,
                generation: self.backend.generation(),
            },
            command: self.input.command,
            kind: self.input.kind,
            whence: self.input.whence,
            start: self.input.start,
            length: self.input.length,
            pid: self.input.pid,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Change,
    Closing { prefer_wait: bool },
    Lock(LockRecovery),
    Drain(super::drain::Recovery),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recovery {
    frame: Frame,
    kind: Kind,
}
impl Recovery {
    pub(crate) fn change(frame: Frame) -> Self {
        Self {
            frame,
            kind: Kind::Change,
        }
    }
    pub(crate) fn closing(frame: Frame) -> Self {
        Self {
            frame,
            kind: Kind::Closing { prefer_wait: false },
        }
    }
    pub(crate) fn next_close_fence(mut self) -> Result<(Self, bool), posix_fd::Error> {
        let Kind::Closing {
            ref mut prefer_wait,
        } = self.kind
        else {
            return Err(posix_fd::Error::InvalidArgument);
        };
        let selected = *prefer_wait;
        *prefer_wait = !selected;
        Ok((self, selected))
    }
    pub fn frame(self) -> Frame {
        self.frame
    }
    pub fn lock(self) -> Option<LockRecovery> {
        match self.kind {
            Kind::Lock(lock) => Some(lock),
            Kind::Change | Kind::Closing { .. } | Kind::Drain(_) => None,
        }
    }
    pub fn is_change(self) -> bool {
        matches!(self.kind, Kind::Change)
    }
    pub(crate) fn from_drain(frame: Frame, recovery: super::drain::Recovery) -> Self {
        Self {
            frame,
            kind: Kind::Drain(recovery),
        }
    }
    pub fn drain(self) -> Option<super::drain::Recovery> {
        match self.kind {
            Kind::Drain(recovery) => Some(recovery),
            _ => None,
        }
    }
    pub(crate) fn update_drain(
        mut self,
        recovery: super::drain::Recovery,
    ) -> Result<Self, posix_fd::Error> {
        if !matches!(self.kind, Kind::Drain(_)) {
            return Err(posix_fd::Error::InvalidArgument);
        }
        self.kind = Kind::Drain(recovery);
        Ok(self)
    }
    fn save_terminal(mut self, terminal: TerminalReply) -> Result<Self, posix_fd::Error> {
        let Kind::Lock(ref mut lock) = self.kind else {
            return Err(posix_fd::Error::InvalidArgument);
        };
        if !lock.input.command.get() && terminal.reply().blocker.is_some() {
            return Err(posix_fd::Error::InvalidArgument);
        }
        if lock.outcome.is_some_and(|old| old != terminal.reply()) {
            return Err(posix_fd::Error::InvalidArgument);
        }
        lock.outcome = Some(terminal.reply());
        Ok(self)
    }
}

pub type Snapshot = ControlSnapshot<Recovery>;
impl PosixFs {
    /// A valid main-stack jump locally abandons exact owner frames, once.
    /// Complete receipts survive; no transport or capability is touched here.
    pub fn mark_control_jump(&mut self, owner: OwnerToken, target: Frame) {
        let mut tokens = [None; posix_fd::JOBS_MAX];
        for (index, token) in self.control_tokens().enumerate() {
            tokens[index] = Some(token);
        }
        for token in tokens.into_iter().flatten() {
            if let Ok(snapshot) = self.control_snapshot(token)
                && snapshot.owner == Some(owner)
                && nested(snapshot.recovery.frame(), target)
            {
                let _ = self.descriptors.abandon_control(token);
            }
        }
    }

    pub fn control_tokens(&self) -> impl Iterator<Item = ControlToken> + '_ {
        self.descriptors.control_tokens()
    }
    pub fn control_snapshot(&self, token: ControlToken) -> Result<Snapshot, FsError> {
        self.descriptors
            .control_snapshot(token)
            .map_err(FsError::from)
    }
    pub fn lock_source(&self, fd: u32) -> Result<EntryToken, FsError> {
        self.descriptors.entry_token(fd).map_err(FsError::from)
    }
    /// Capture and register an exact numeric lifetime before the first IPC.
    pub fn begin_lock_record(
        &mut self,
        owner: OwnerToken,
        source: EntryToken,
        frame: Frame,
        input: Input,
    ) -> Result<(ControlToken, ControlClaimToken), FsError> {
        if self.descriptors.entry_token(source.fd).ok() != Some(source) {
            return Err(FsError::BadFileDescriptor);
        }
        let backend = match self.descriptors.get(source.fd).map_err(FsError::from)? {
            Target::Ram(backend) | Target::Random(backend) => backend,
            _ => return Err(FsError::InvalidArgument),
        };
        let lock = LockRecovery {
            source,
            backend,
            input,
            outcome: None,
            cancel_reason: CancelReason::Abandoned,
        };
        let recovery = Recovery {
            frame,
            kind: Kind::Lock(lock),
        };
        // Validate the copied request before consuming paid custody.
        LockStart {
            key: OpenKey {
                slot: 32,
                generation: 1,
            },
            description: DataDescription {
                packed: backend.fd()
                    | backend.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT,
                generation: backend.generation(),
            },
            command: input.command,
            kind: input.kind,
            whence: input.whence,
            start: input.start,
            length: input.length,
            pid: input.pid,
        }
        .validate()
        .map_err(FsError::from)?;
        self.descriptors
            .begin_control(owner, recovery)
            .map_err(FsError::from)
    }
    pub fn lock_snapshot(&self, token: ControlToken) -> Result<Snapshot, FsError> {
        let snapshot = self.control_snapshot(token)?;
        if snapshot.recovery.lock().is_none() {
            return Err(FsError::InvalidArgument);
        }
        Ok(snapshot)
    }
    pub fn complete_lock_record(
        &mut self,
        claim: ControlClaimToken,
        result: ControlResult,
        terminal: TerminalReply,
    ) -> Result<Snapshot, FsError> {
        validate_result(result, terminal)?;
        self.descriptors
            .complete_control_with(claim, result, |recovery| recovery.save_terminal(terminal))
            .map_err(FsError::from)
    }
    pub fn publish_lock_cleanup(
        &mut self,
        token: ControlToken,
        result: ControlResult,
        terminal: TerminalReply,
    ) -> Result<Snapshot, FsError> {
        self.lock_snapshot(token)?;
        validate_result(result, terminal)?;
        self.descriptors
            .control_publish_cleanup(token, result, |recovery| recovery.save_terminal(terminal))
            .map_err(FsError::from)
    }
    pub fn lock_is_live(&self, claim: ControlClaimToken) -> bool {
        self.lock_snapshot(claim.control()).is_ok() && self.descriptors.control_is_working(claim)
    }
    pub fn begin_lock_cleanup(
        &mut self,
        token: ControlToken,
        reason: CancelReason,
    ) -> Result<Snapshot, FsError> {
        self.lock_snapshot(token)?;
        self.descriptors
            .control_begin_cleanup_with(token, |mut recovery| {
                let Kind::Lock(ref mut lock) = recovery.kind else {
                    return Err(posix_fd::Error::InvalidArgument);
                };
                lock.cancel_reason = reason;
                Ok(recovery)
            })
            .map_err(FsError::from)?;
        self.lock_snapshot(token)
    }
    /// Cleanup cannot discard an unsaved canonical receipt.
    pub fn finish_lock_cleanup(&mut self, token: ControlToken) -> Result<(), FsError> {
        if self.lock_snapshot(token)?.result.is_none() {
            return Err(FsError::InvalidArgument);
        }
        self.descriptors
            .control_finish_cleanup(token)
            .map_err(FsError::from)
    }
    /// Copy the complete outcome before the acknowledgement can return its slot.
    pub fn ack_lock_record(
        &mut self,
        token: ControlToken,
        owner: OwnerToken,
    ) -> Result<(ControlResult, Option<LockReply>), FsError> {
        let saved = self.lock_snapshot(token)?;
        let outcome = saved
            .recovery
            .lock()
            .ok_or(FsError::InvalidArgument)?
            .outcome();
        let result = self
            .descriptors
            .ack_control(token, owner)
            .map_err(FsError::from)?;
        Ok((result, outcome))
    }
    pub fn lock_tokens_for(&self, source: EntryToken) -> impl Iterator<Item = ControlToken> + '_ {
        self.control_tokens().filter(move |&token| {
            self.lock_snapshot(token).is_ok_and(|snapshot| {
                snapshot
                    .recovery
                    .lock()
                    .is_some_and(|lock| lock.source() == source)
            })
        })
    }
    /// Revoke one exact source's unpaid command before its numeric close event.
    /// The resident table has sixteen prepaid records; this step performs no RPC.
    pub fn fence_lock_for_close(
        &mut self,
        source: EntryToken,
    ) -> Result<Option<ControlToken>, FsError> {
        let token = self.control_tokens().find(|&token| {
            self.control_snapshot(token).is_ok_and(|snapshot| {
                snapshot.phase != ControlPhase::Cleaned
                    && snapshot
                        .recovery
                        .lock()
                        .is_some_and(|lock| lock.source() == source)
            })
        });
        if let Some(token) = token {
            self.begin_lock_cleanup(token, CancelReason::Close)?;
        }
        Ok(token)
    }
    /// Select one abandoned Lock debt and acknowledge already cleaned local frames.
    /// Every candidate is an exact resident token copied in one bounded table scan.
    pub fn pick_lock_cleanup(
        &mut self,
        me: Option<OwnerToken>,
        current: Frame,
        skip: Option<ControlToken>,
    ) -> Result<Option<ControlToken>, FsError> {
        let mut tokens = [None; posix_fd::JOBS_MAX];
        for (index, token) in self.control_tokens().enumerate() {
            tokens[index] = Some(token);
        }
        for token in tokens.into_iter().flatten() {
            if Some(token) == skip {
                continue;
            }
            let snapshot = self.control_snapshot(token)?;
            if snapshot.recovery.lock().is_none() {
                continue;
            }
            let mine = snapshot.owner.is_some() && snapshot.owner == me;
            if snapshot.owner.is_some() && (!mine || nested(current, snapshot.recovery.frame())) {
                continue;
            }
            if snapshot.phase == ControlPhase::Cleaned {
                if let Some(owner) = snapshot.owner.filter(|_| mine) {
                    self.ack_lock_record(token, owner)?;
                }
                continue;
            }
            self.begin_lock_cleanup(token, CancelReason::Abandoned)?;
            return Ok(Some(token));
        }
        Ok(None)
    }
    pub fn abandon_lock_owner(
        &mut self,
        owner: OwnerToken,
    ) -> Option<posix_fd::ControlAbandoned<Recovery>> {
        self.descriptors
            .abandon_control_owner_if(owner, |recovery| recovery.lock().is_some())
    }
}

fn validate_result(result: ControlResult, terminal: TerminalReply) -> Result<(), FsError> {
    let valid = if terminal.reply().result == 0 {
        result == ControlResult::Value(0)
    } else {
        matches!(result, ControlResult::Failed(errno) if errno > 0)
    };
    if valid {
        Ok(())
    } else {
        Err(FsError::InvalidArgument)
    }
}
