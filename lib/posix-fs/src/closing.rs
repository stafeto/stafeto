// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Frozen numeric close events and their exact physical cleanup receipts.

use super::{DescriptorFlags, FsError, PosixFs, Target};
use entries::Frame;
pub use posix_fd::{CloseAdmission, CloseSnapshot, CloseToken, JobPlace, OwnerToken, WaitValue};

pub type Snapshot = CloseSnapshot<Target, Frame>;
pub type Admission = CloseAdmission<Target, Frame>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseCommandFence {
    Control(super::change::ControlToken),
    Wait(super::wait::WaitToken),
}

impl PosixFs {
    /// Revoke both exact-source families and select one fair unlocked helper turn.
    pub fn close_command_fence(
        &mut self,
        token: CloseToken,
    ) -> Result<Option<CloseCommandFence>, FsError> {
        let snapshot = self.close_snapshot(token)?;
        if snapshot.complete {
            return Ok(None);
        }
        let control = self.fence_lock_for_close(snapshot.entry)?;
        let wait = self.fence_wait_for_close(snapshot.entry)?;
        match (control, wait) {
            (Some(c), Some(w)) => {
                let prefer_wait = self
                    .descriptors
                    .update_close_metadata(token, |r| r.next_close_fence())
                    .map_err(FsError::from)?;
                Ok(Some(if prefer_wait {
                    CloseCommandFence::Wait(w)
                } else {
                    CloseCommandFence::Control(c)
                }))
            }
            (Some(c), None) => Ok(Some(CloseCommandFence::Control(c))),
            (None, Some(w)) => Ok(Some(CloseCommandFence::Wait(w))),
            (None, None) => Ok(None),
        }
    }
    pub fn pending_open(&self, fd: u32) -> Option<posix_fd::OpenToken> {
        self.descriptors.pending(fd)
    }

    pub fn closing(&self, fd: u32) -> Option<CloseToken> {
        self.descriptors.closing(fd)
    }
    pub fn close_tokens(&self) -> impl Iterator<Item = CloseToken> + '_ {
        self.descriptors.close_tokens()
    }
    pub fn close_snapshot(&self, token: CloseToken) -> Result<Snapshot, FsError> {
        self.descriptors
            .close_snapshot(token)
            .map(snapshot_frame)
            .map_err(FsError::from)
    }
    pub fn close_place(&self, owner: OwnerToken) -> JobPlace {
        self.descriptors.close_place(owner)
    }
    pub fn close_wait_address(&self, token: CloseToken) -> Result<usize, FsError> {
        self.descriptors
            .close_wait_word(token)
            .map(|word| core::ptr::from_ref(word) as usize)
            .map_err(FsError::from)
    }
    pub fn begin_close_record(
        &mut self,
        owner: Option<OwnerToken>,
        fd: u32,
        frame: Frame,
    ) -> Result<Admission, FsError> {
        match owner {
            Some(owner) => {
                self.descriptors
                    .begin_close(owner, fd, super::control::Recovery::closing(frame))
            }
            None => self
                .descriptors
                .begin_close_unowned(fd, super::control::Recovery::closing(frame)),
        }
        .map(admission_frame)
        .map_err(FsError::from)
    }
    pub fn begin_replace_record(
        &mut self,
        owner: Option<OwnerToken>,
        source: u32,
        target: u32,
        flags: Option<DescriptorFlags>,
        frame: Frame,
    ) -> Result<Admission, FsError> {
        match owner {
            Some(owner) => self.descriptors.begin_replace(
                owner,
                source,
                target,
                flags,
                super::control::Recovery::closing(frame),
            ),
            None => self.descriptors.begin_replace_unowned(
                source,
                target,
                flags,
                super::control::Recovery::closing(frame),
            ),
        }
        .map(admission_frame)
        .map_err(FsError::from)
    }
    pub fn finish_close_record(&mut self, token: CloseToken) -> Result<Option<Target>, FsError> {
        self.descriptors.finish_close(token).map_err(FsError::from)
    }
    pub fn finish_close_release(
        &mut self,
        token: CloseToken,
        target: Target,
    ) -> Result<(), FsError> {
        self.descriptors
            .finish_close_release(token, target)
            .map_err(FsError::from)
    }
    pub fn ack_close_record(
        &mut self,
        token: CloseToken,
        owner: Option<OwnerToken>,
    ) -> Result<(), FsError> {
        self.descriptors
            .ack_close(token, owner)
            .map_err(FsError::from)
    }
    pub fn abandon_close_owner(&mut self, owner: OwnerToken) -> Option<(CloseToken, Snapshot)> {
        self.descriptors
            .abandon_close_owner(owner)
            .map(|(token, snapshot)| (token, snapshot_frame(snapshot)))
    }
}

fn snapshot_frame(snapshot: CloseSnapshot<Target, super::control::Recovery>) -> Snapshot {
    CloseSnapshot {
        owner: snapshot.owner,
        recovery: snapshot.recovery.frame(),
        entry: snapshot.entry,
        backend: snapshot.backend,
        last_alias: snapshot.last_alias,
        replacement: snapshot.replacement,
        complete: snapshot.complete,
        release: snapshot.release,
    }
}
fn admission_frame(admission: CloseAdmission<Target, super::control::Recovery>) -> Admission {
    match admission {
        CloseAdmission::Started { token, snapshot } => CloseAdmission::Started {
            token,
            snapshot: snapshot_frame(snapshot),
        },
        CloseAdmission::PendingOpen(token) => CloseAdmission::PendingOpen(token),
        CloseAdmission::PendingClose(token) => CloseAdmission::PendingClose(token),
        CloseAdmission::Replaced(number) => CloseAdmission::Replaced(number),
    }
}
