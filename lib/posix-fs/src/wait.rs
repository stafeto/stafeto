// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Resident WAIT recovery only: no RPC, syscall, channel Drop or public activation.
//! NativeScope must cover channel creation and Arm clone transfer in the future driver.

use super::{FsError, PosixFs, RamTarget, Target};
use entries::{Frame, nested};
use posix_fd::{
    EntryToken, OwnerToken, WaitCancelReason, WaitChannelDebt, WaitClaim, WaitRecordPhase,
    WaitResult, WaitSnapshot, WaitToken,
};
use proto_fs::{DataDescription, LockKind, WaitKey, WaitMode, WaitPhase, WaitReply, WaitStart};
use proto_wire::Reader;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Input {
    pub mode: WaitMode,
    pub kind: LockKind,
    pub whence: u32,
    pub start: i64,
    pub length: i64,
    pub pid: i32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalReply(WaitReply);
impl TerminalReply {
    pub fn read(bytes: &[u8]) -> Result<Self, FsError> {
        Self::from_reply(WaitReply::read(Reader::new(bytes)).map_err(FsError::from)?)
    }
    pub fn from_reply(reply: WaitReply) -> Result<Self, FsError> {
        reply.validate().map_err(FsError::from)?;
        if reply.phase != WaitPhase::Complete
            || matches!(
                reply.result,
                proto_fs::LOCK_CONFLICT
                    | proto_fs::JOBS_FULL
                    | proto_fs::AUTHENTICATING
                    | proto_fs::RESOLVING
            )
        {
            return Err(FsError::InvalidArgument);
        }
        Ok(Self(reply))
    }
    pub fn reply(self) -> WaitReply {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recovery {
    source: EntryToken,
    backend: RamTarget,
    frame: Frame,
    input: Input,
    outcome: Option<WaitReply>,
}
impl Recovery {
    pub fn source(self) -> EntryToken {
        self.source
    }
    pub fn backend(self) -> RamTarget {
        self.backend
    }
    pub fn frame(self) -> Frame {
        self.frame
    }
    pub fn input(self) -> Input {
        self.input
    }
    pub fn outcome(self) -> Option<WaitReply> {
        self.outcome
    }
    pub fn request(self, token: WaitToken) -> WaitStart {
        self.request_key(WaitKey {
            slot: token.slot() as u32,
            generation: token.generation(),
        })
    }
    fn request_key(self, key: WaitKey) -> WaitStart {
        WaitStart {
            key,
            description: DataDescription {
                packed: self.backend.fd()
                    | self.backend.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT,
                generation: self.backend.generation(),
            },
            mode: self.input.mode,
            kind: self.input.kind,
            whence: self.input.whence,
            start: self.input.start,
            length: self.input.length,
            pid: self.input.pid,
        }
    }
    fn terminal(mut self, reply: TerminalReply) -> Result<Self, posix_fd::Error> {
        if self.outcome.is_some_and(|old| old != reply.reply()) {
            return Err(posix_fd::Error::InvalidArgument);
        }
        self.outcome = Some(reply.reply());
        Ok(self)
    }
}
pub type Snapshot = WaitSnapshot<Recovery>;
impl PosixFs {
    pub fn wait_tokens(&self) -> impl Iterator<Item = WaitToken> + '_ {
        self.waits.tokens()
    }
    pub fn wait_snapshot(&self, token: WaitToken) -> Result<Snapshot, FsError> {
        self.waits.snapshot(token).map_err(FsError::from)
    }
    /// Pay the record before channel creation or the first service message.
    pub fn begin_wait_record(
        &mut self,
        owner: OwnerToken,
        source: EntryToken,
        frame: Frame,
        input: Input,
    ) -> Result<(WaitToken, WaitClaim), FsError> {
        if self.descriptors.entry_token(source.fd).ok() != Some(source) {
            return Err(FsError::BadFileDescriptor);
        }
        let backend = match self.descriptors.get(source.fd).map_err(FsError::from)? {
            Target::Ram(b) | Target::Random(b) => b,
            _ => return Err(FsError::InvalidArgument),
        };
        let recovery = Recovery {
            source,
            backend,
            frame,
            input,
            outcome: None,
        };
        recovery
            .request_key(WaitKey {
                slot: 0,
                generation: 1,
            })
            .validate()
            .map_err(FsError::from)?;
        self.waits.begin(owner, recovery).map_err(FsError::from)
    }
    /// On success the record owns the full raw RECEIVE handle; close on failure
    /// remains the driver's debt, outside FILES_LOCK and under NativeScope.
    pub fn attach_wait_channel(&mut self, claim: WaitClaim, raw: u64) -> Result<(), FsError> {
        self.waits.attach_channel(claim, raw).map_err(FsError::from)
    }
    pub fn wait_is_live(&self, claim: WaitClaim) -> bool {
        self.waits.is_working(claim)
    }
    pub fn complete_wait_record(
        &mut self,
        claim: WaitClaim,
        result: WaitResult,
        terminal: TerminalReply,
    ) -> Result<Snapshot, FsError> {
        validate_result(result, terminal)?;
        self.waits
            .complete(claim, result, |r| r.terminal(terminal))
            .map_err(FsError::from)
    }
    pub fn publish_wait_cleanup(
        &mut self,
        token: WaitToken,
        result: WaitResult,
        terminal: TerminalReply,
    ) -> Result<Snapshot, FsError> {
        validate_result(result, terminal)?;
        self.waits
            .publish(token, result, |r| r.terminal(terminal))
            .map_err(FsError::from)
    }
    pub fn begin_wait_cleanup(
        &mut self,
        token: WaitToken,
        reason: WaitCancelReason,
    ) -> Result<Snapshot, FsError> {
        self.waits
            .begin_cleanup(token, reason)
            .map_err(FsError::from)
    }
    pub fn finish_wait_cleanup(&mut self, token: WaitToken) -> Result<(), FsError> {
        self.waits.finish_cleanup(token).map_err(FsError::from)
    }
    pub fn wait_channel_debt(&self, token: WaitToken) -> Result<Option<WaitChannelDebt>, FsError> {
        self.waits.channel_debt(token).map_err(FsError::from)
    }
    pub fn confirm_wait_channel_closed(&mut self, debt: WaitChannelDebt) -> Result<(), FsError> {
        self.waits
            .confirm_channel_closed(debt)
            .map_err(FsError::from)
    }
    pub fn ack_wait_record(
        &mut self,
        token: WaitToken,
        owner: OwnerToken,
    ) -> Result<(WaitResult, Recovery), FsError> {
        self.waits.ack(token, owner).map_err(FsError::from)
    }
    pub fn abandon_wait_owner(&mut self, owner: OwnerToken) -> Option<WaitToken> {
        self.waits.abandon_owner(owner)
    }
    /// One exact source debt per bounded scan; all canonical receipts survive.
    pub fn fence_wait_for_close(
        &mut self,
        source: EntryToken,
    ) -> Result<Option<WaitToken>, FsError> {
        let token = self.wait_tokens().find(|&t| {
            self.wait_snapshot(t)
                .is_ok_and(|s| s.recovery.source() == source && s.phase != WaitRecordPhase::Cleaned)
        });
        if let Some(t) = token {
            self.begin_wait_cleanup(t, WaitCancelReason::Close)?;
        }
        Ok(token)
    }
    /// Ack cleaned abandoned local frames and select at most one unpaid record.
    /// A Cleaned record still owing channel close is returned to its helper.
    pub fn pick_wait_cleanup(
        &mut self,
        me: Option<OwnerToken>,
        current: Frame,
        skip: Option<WaitToken>,
    ) -> Result<Option<WaitToken>, FsError> {
        let mut tokens = [None; posix_fd::WAIT_RECORDS];
        for (i, t) in self.wait_tokens().enumerate() {
            tokens[i] = Some(t);
        }
        for token in tokens.into_iter().flatten() {
            if Some(token) == skip {
                continue;
            }
            let snapshot = self.wait_snapshot(token)?;
            let mine = snapshot.owner.is_some() && snapshot.owner == me;
            if snapshot.owner.is_some() && (!mine || nested(current, snapshot.recovery.frame())) {
                continue;
            }
            if snapshot.phase == WaitRecordPhase::Cleaned && snapshot.channel.is_none() {
                if let Some(owner) = snapshot.owner {
                    self.waits.ack(token, owner).map_err(FsError::from)?;
                } else {
                    self.waits.ack_abandoned(token).map_err(FsError::from)?;
                }
                continue;
            }
            self.begin_wait_cleanup(token, WaitCancelReason::Abandoned)?;
            return Ok(Some(token));
        }
        Ok(None)
    }
    /// No sysclose of parent-only IDs, no cancellation of parent's paid requests.
    pub fn discard_wait_after_fork(&mut self) {
        self.waits.discard_after_fork();
    }
}
fn validate_result(result: WaitResult, terminal: TerminalReply) -> Result<(), FsError> {
    if terminal.reply().result == 0 && result == WaitResult::Value(0)
        || terminal.reply().result != 0 && matches!(result,WaitResult::Failed(e)if e>0)
    {
        Ok(())
    } else {
        Err(FsError::InvalidArgument)
    }
}
