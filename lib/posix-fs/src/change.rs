// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The record of a Change job in the table of descriptors. The paid record
//! of an operation on names and metadata stands for one job of the session in
//! the service and holds the frame where the operation began, so that a
//! thread that left the operation by a long jump can be told from one that
//! is still inside it.

use super::{FsError, PosixFs};
use entries::Frame;
pub use posix_fd::{
    ControlAbandoned, ControlClaimToken, ControlCleanup, ControlPhase, ControlResult,
    ControlSnapshot, ControlToken, JOBS_MAX, JobPlace, OwnerToken,
};

impl PosixFs {
    /// Whether `owner` finds a place for one more job. The check and the
    /// `begin_*` that follows run under one hold of the lock.
    pub fn job_place(&self, owner: OwnerToken) -> JobPlace {
        self.descriptors.job_place(owner)
    }

    /// The address of the word of the places of jobs, for a thread that waits
    /// for one. Shared pins PosixFs before admission.
    pub fn jobs_wait_address(&self) -> usize {
        core::ptr::from_ref(self.descriptors.jobs_wait_word()) as usize
    }

    /// A paid record for a Change job begun in `frame`. Its token names the
    /// key of the job: the slot and the generation.
    pub fn begin_change_record(
        &mut self,
        owner: OwnerToken,
        frame: Frame,
    ) -> Result<(ControlToken, ControlClaimToken), FsError> {
        self.descriptors
            .begin_control(owner, super::control::Recovery::change(frame))
            .map_err(FsError::from)
    }

    pub fn change_snapshot(&self, token: ControlToken) -> Result<ControlSnapshot<Frame>, FsError> {
        let snapshot = self
            .descriptors
            .control_snapshot(token)
            .map_err(FsError::from)?;
        if !snapshot.recovery.is_change() {
            return Err(FsError::InvalidArgument);
        }
        Ok(ControlSnapshot {
            owner: snapshot.owner,
            claimant: snapshot.claimant,
            phase: snapshot.phase,
            recovery: snapshot.recovery.frame(),
            result: snapshot.result,
        })
    }

    pub fn change_tokens(&self) -> impl Iterator<Item = ControlToken> + '_ {
        self.descriptors
            .control_tokens()
            .filter(|&token| self.change_snapshot(token).is_ok())
    }

    /// Whether the record is still the one the operation began with: a child
    /// of `fork` has dropped it.
    pub fn change_is_live(&self, claim: ControlClaimToken) -> bool {
        self.change_snapshot(claim.control()).is_ok() && self.descriptors.control_is_working(claim)
    }

    pub fn complete_change_record(
        &mut self,
        claim: ControlClaimToken,
        result: ControlResult,
    ) -> Result<(), FsError> {
        self.change_snapshot(claim.control())?;
        self.descriptors
            .complete_control(claim, result)
            .map_err(FsError::from)
    }

    pub fn ack_change_record(
        &mut self,
        token: ControlToken,
        owner: OwnerToken,
    ) -> Result<ControlResult, FsError> {
        self.change_snapshot(token)?;
        self.descriptors
            .ack_control(token, owner)
            .map_err(FsError::from)
    }

    /// Revoke the authority of the operation over the job: its Release is the
    /// debt that remains. Repeated calls return the same debt.
    pub fn begin_change_cleanup(
        &mut self,
        token: ControlToken,
    ) -> Result<ControlCleanup<Frame>, FsError> {
        self.change_snapshot(token)?;
        let cleanup = self
            .descriptors
            .control_begin_cleanup(token)
            .map_err(FsError::from)?;
        Ok(ControlCleanup {
            token: cleanup.token,
            recovery: cleanup.recovery.frame(),
        })
    }

    /// The Release was answered: the place goes when nobody owns the record.
    pub fn finish_change_cleanup(&mut self, token: ControlToken) -> Result<(), FsError> {
        self.change_snapshot(token)?;
        self.descriptors
            .control_finish_cleanup(token)
            .map_err(FsError::from)
    }

    /// A thread's lifetime ended: one of its records loses its owner, to be
    /// released by whoever collects. None when the thread owns no more.
    pub fn abandon_change_owner(&mut self, owner: OwnerToken) -> Option<ControlAbandoned<Frame>> {
        self.descriptors
            .abandon_control_owner_if(owner, |recovery| recovery.is_change())
            .map(|abandoned| match abandoned {
                ControlAbandoned::Recover { token, snapshot } => ControlAbandoned::Recover {
                    token,
                    snapshot: ControlSnapshot {
                        owner: snapshot.owner,
                        claimant: snapshot.claimant,
                        phase: snapshot.phase,
                        recovery: snapshot.recovery.frame(),
                        result: snapshot.result,
                    },
                },
                ControlAbandoned::ClaimReleased(token) => ControlAbandoned::ClaimReleased(token),
                ControlAbandoned::Discarded(token) => ControlAbandoned::Discarded(token),
            })
    }
}
