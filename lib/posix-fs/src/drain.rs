// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Prepaid terminal drain custody in the existing shared Control pool.
//! No RPC, capability creation, borrowed application pointer or channel Drop.

use super::{FsError, PosixFs, Target, control};
use entries::{Frame, nested};
use posix_fd::{
    ControlClaimToken, ControlPhase, ControlResult, ControlToken, EntryToken, OwnerToken,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Server {
    Unstarted,
    Waiting,
    Ready,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recovery {
    source: EntryToken,
    target: Target,
    session: u64,
    terminal: u32,
    key: u64,
    server: Server,
    held: bool,
    release: Option<Target>,
}
impl Recovery {
    pub fn source(self) -> EntryToken {
        self.source
    }
    pub fn session(self) -> u64 {
        self.session
    }
    pub fn terminal(self) -> u32 {
        self.terminal
    }
    pub fn key(self) -> u64 {
        self.key
    }
    pub fn server(self) -> Server {
        self.server
    }
    pub fn held(self) -> bool {
        self.held
    }
    pub fn release(self) -> Option<Target> {
        self.release
    }
}
impl PosixFs {
    /// None means the existing Control pool declined unpaid admission.
    pub fn begin_drain_record(
        &mut self,
        owner: OwnerToken,
        source: EntryToken,
        frame: Frame,
        session: u64,
        terminal: u32,
    ) -> Result<Option<(ControlToken, ControlClaimToken)>, FsError> {
        if session == 0 {
            return Err(FsError::InvalidArgument);
        }
        if self.descriptors.entry_token(source.fd).ok() != Some(source) {
            return Err(FsError::BadFileDescriptor);
        }
        let target = self.descriptors.get(source.fd).map_err(FsError::from)?;
        let number = match target {
            Target::Tty(number) => number,
            Target::Input | Target::Output | Target::Error => 0,
            _ => return Err(FsError::InvalidArgument),
        };
        if terminal != number {
            return Err(FsError::InvalidArgument);
        }
        let mut recovery = Recovery {
            source,
            target,
            session,
            terminal,
            key: 0,
            server: Server::Unstarted,
            held: false,
            release: None,
        };
        let frame = control::Recovery::from_drain(frame, recovery);
        let (token, claim) = match self.descriptors.begin_control(owner, frame) {
            Ok(paid) => paid,
            Err(posix_fd::Error::TooManyOpenFiles) => return Ok(None),
            Err(error) => return Err(FsError::from(error)),
        };
        if let Err(error) = self.descriptors.hold(source.fd) {
            // No START and no hold: dispose only this exact local reservation.
            self.descriptors
                .abandon_control(token)
                .map_err(FsError::from)?;
            self.descriptors
                .control_begin_cleanup(token)
                .map_err(FsError::from)?;
            self.descriptors
                .control_finish_cleanup(token)
                .map_err(FsError::from)?;
            return Err(FsError::from(error));
        }
        recovery.held = true;
        self.descriptors
            .update_control(claim, frame.update_drain(recovery).map_err(FsError::from)?)
            .map_err(FsError::from)?;
        Ok(Some((token, claim)))
    }
    pub fn drain_snapshot(&self, token: ControlToken) -> Result<control::Snapshot, FsError> {
        let snapshot = self.control_snapshot(token)?;
        if snapshot.recovery.drain().is_none() {
            return Err(FsError::InvalidArgument);
        }
        Ok(snapshot)
    }
    /// Called before opening delivery after the short accepted START reply.
    pub fn publish_drain_wait(
        &mut self,
        claim: ControlClaimToken,
        key: u64,
    ) -> Result<(), FsError> {
        let snapshot = self.drain_snapshot(claim.control())?;
        let mut recovery = snapshot.recovery.drain().ok_or(FsError::InvalidArgument)?;
        if key == 0
            || (recovery.server != Server::Unstarted
                && !(recovery.server == Server::Waiting && recovery.key == key))
        {
            return Err(FsError::InvalidArgument);
        }
        recovery.key = key;
        recovery.server = Server::Waiting;
        self.descriptors
            .update_control(
                claim,
                snapshot
                    .recovery
                    .update_drain(recovery)
                    .map_err(FsError::from)?,
            )
            .map_err(FsError::from)
    }
    pub fn publish_drain_terminal(
        &mut self,
        claim: ControlClaimToken,
        ready: bool,
    ) -> Result<(), FsError> {
        let snapshot = self.drain_snapshot(claim.control())?;
        let mut recovery = snapshot.recovery.drain().ok_or(FsError::InvalidArgument)?;
        if !ready && recovery.server != Server::Waiting {
            return Err(FsError::InvalidArgument);
        }
        recovery.server = if ready {
            Server::Ready
        } else {
            Server::Cancelled
        };
        let updated = snapshot
            .recovery
            .update_drain(recovery)
            .map_err(FsError::from)?;
        if ready {
            self.descriptors
                .complete_control_with(claim, ControlResult::Value(0), |_| Ok(updated))
                .map(|_| ())
                .map_err(FsError::from)
        } else {
            self.descriptors
                .update_control(claim, updated)
                .map_err(FsError::from)
        }
    }
    pub fn complete_drain_record(
        &mut self,
        claim: ControlClaimToken,
        result: ControlResult,
    ) -> Result<(), FsError> {
        let snapshot = self.drain_snapshot(claim.control())?;
        if let Some(saved) = snapshot.result {
            return if saved == result {
                Ok(())
            } else {
                Err(FsError::InvalidArgument)
            };
        }
        self.descriptors
            .complete_control(claim, result)
            .map_err(FsError::from)
    }
    pub fn begin_drain_cleanup(&mut self, token: ControlToken) -> Result<Recovery, FsError> {
        self.drain_snapshot(token)?;
        self.descriptors
            .control_begin_cleanup(token)
            .map_err(FsError::from)?
            .recovery
            .drain()
            .ok_or(FsError::InvalidArgument)
    }
    pub fn confirm_drain_gone(
        &mut self,
        token: ControlToken,
        session: u64,
        key: u64,
    ) -> Result<(), FsError> {
        self.descriptors
            .update_control_cleanup(token, |frame| {
                let mut recovery = frame.drain().ok_or(posix_fd::Error::InvalidArgument)?;
                if recovery.session != session || recovery.key != key {
                    return Err(posix_fd::Error::InvalidArgument);
                }
                if recovery.server == Server::Waiting {
                    recovery.server = Server::Cancelled;
                }
                frame.update_drain(recovery)
            })
            .map_err(FsError::from)
    }
    /// The files lock makes unhold and publication one indivisible local transition.
    pub fn release_drain_hold(&mut self, token: ControlToken) -> Result<Recovery, FsError> {
        let snapshot = self.drain_snapshot(token)?;
        let mut recovery = snapshot.recovery.drain().ok_or(FsError::InvalidArgument)?;
        if snapshot.phase != ControlPhase::Cleaning || recovery.server == Server::Waiting {
            return Err(FsError::InvalidArgument);
        }
        if recovery.held {
            recovery.release = self.descriptors.unhold(recovery.target);
            recovery.held = false;
            let updated = snapshot
                .recovery
                .update_drain(recovery)
                .map_err(FsError::from)?;
            self.descriptors
                .update_control_cleanup(token, |_| Ok(updated))
                .map_err(FsError::from)?;
        }
        Ok(recovery)
    }
    pub fn confirm_drain_release(
        &mut self,
        token: ControlToken,
        target: Target,
    ) -> Result<(), FsError> {
        self.descriptors
            .update_control_cleanup(token, |frame| {
                let mut recovery = frame.drain().ok_or(posix_fd::Error::InvalidArgument)?;
                if recovery.held || recovery.release != Some(target) {
                    return Err(posix_fd::Error::InvalidArgument);
                }
                recovery.release = None;
                frame.update_drain(recovery)
            })
            .map_err(FsError::from)
    }
    pub fn finish_drain_cleanup(&mut self, token: ControlToken) -> Result<(), FsError> {
        let recovery = self
            .drain_snapshot(token)?
            .recovery
            .drain()
            .ok_or(FsError::InvalidArgument)?;
        if recovery.held || recovery.release.is_some() || recovery.server == Server::Waiting {
            return Err(FsError::InvalidArgument);
        }
        self.descriptors
            .control_finish_cleanup(token)
            .map_err(FsError::from)
    }
    pub fn ack_drain_record(
        &mut self,
        token: ControlToken,
        owner: OwnerToken,
    ) -> Result<ControlResult, FsError> {
        if self.drain_snapshot(token)?.phase != ControlPhase::Cleaned {
            return Err(FsError::InvalidArgument);
        }
        self.descriptors
            .ack_control(token, owner)
            .map_err(FsError::from)
    }
    /// Return the caller's saved outcome while unpaid cleanup stays resident.
    pub fn handoff_drain_record(
        &mut self,
        token: ControlToken,
        owner: OwnerToken,
    ) -> Result<ControlResult, FsError> {
        self.drain_snapshot(token)?;
        self.descriptors
            .ack_control(token, owner)
            .map_err(FsError::from)
    }
    pub fn abandon_drain_owner(
        &mut self,
        owner: OwnerToken,
    ) -> Option<posix_fd::ControlAbandoned<control::Recovery>> {
        self.descriptors
            .abandon_control_owner_if(owner, |frame| frame.drain().is_some())
    }
    pub fn pick_drain_cleanup(
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
            if snapshot.recovery.drain().is_none() {
                continue;
            }
            let mine = snapshot.owner.is_some() && snapshot.owner == me;
            if snapshot.owner.is_some() && (!mine || nested(current, snapshot.recovery.frame())) {
                continue;
            }
            if snapshot.phase == ControlPhase::Cleaned {
                if let Some(owner) = snapshot.owner.filter(|_| mine) {
                    self.ack_drain_record(token, owner)?;
                }
                continue;
            }
            self.begin_drain_cleanup(token)?;
            return Ok(Some(token));
        }
        Ok(None)
    }
}
