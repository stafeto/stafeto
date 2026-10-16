// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The recovery payload of resident control records: change, close and drain.

use super::{FsError, PosixFs};
use entries::{Frame, nested};
use posix_fd::{ControlSnapshot, ControlToken, OwnerToken};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Change,
    Closing,
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
            kind: Kind::Closing,
        }
    }
    pub fn frame(self) -> Frame {
        self.frame
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
}
