// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Current-directory changes retain authentic path or description authority.
//! The surrounding paid job keeps its exact key and cached result through ACK.

use crate::{
    Fds, Ram,
    authority::Identity,
    io::Held,
    storage::{Pin, Root, Storage, Token},
};
use proto_fs::{ACCESS_DENIED, NOT_DIRECTORY, STALE_PROOF};

/// A retained resolver constructs the authentic path proof.
pub struct CwdProof {
    pub(crate) target: Token,
    pub(crate) identity: Identity,
    pub(crate) epoch: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CwdOutcome {
    Applied,
    Failed(u32),
}
enum Retained {
    Path(Token),
    Description(Held),
}
/// Admission and final retirement remain owned by the surrounding service job.
pub struct CwdJournal {
    target: Token,
    root: Root,
    charge: u16,
    identity: Identity,
    epoch: Option<u64>,
    retained: Option<Retained>,
    outcome: Option<CwdOutcome>,
    canceled: bool,
}
impl CwdJournal {
    pub fn path(
        storage: &mut Storage<'_>,
        root: Root,
        charge: u16,
        proof: CwdProof,
        identity: Identity,
    ) -> Result<Self, u32> {
        if proof.identity != identity || proof.epoch != storage.state.epoch {
            return Err(STALE_PROOF);
        }
        storage.namespace_charge(root, charge)?;
        if storage.node(proof.target)?.kind != crate::DIR {
            return Err(NOT_DIRECTORY);
        }
        storage.pin(proof.target, Pin::Pending)?;
        Ok(Self {
            target: proof.target,
            root,
            charge,
            identity,
            epoch: Some(proof.epoch),
            retained: Some(Retained::Path(proof.target)),
            outcome: None,
            canceled: false,
        })
    }
    pub fn outcome(&self) -> Option<CwdOutcome> {
        self.outcome
    }
    /// Current search permissions apply to both path and descriptor changes.
    /// The caller checks the original owner, image and stamp before publication.
    pub fn commit(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &mut Fds,
        identity: Identity,
        proof: Option<CwdProof>,
    ) -> Result<CwdOutcome, u32> {
        if let Some(outcome) = self.outcome {
            return Ok(outcome);
        }
        if self.canceled
            || self.retained.is_none()
            || identity != self.identity
            || fds.root != self.root
        {
            return Err(STALE_PROOF);
        }
        ram.storage.namespace_charge(self.root, self.charge)?;
        if let Some(epoch) = self.epoch {
            let proof = proof.ok_or(STALE_PROOF)?;
            if proof.target != self.target
                || proof.identity != identity
                || proof.epoch != epoch
                || epoch != ram.storage.state.epoch
            {
                return Err(STALE_PROOF);
            }
        }
        let node = ram.storage.node(self.target)?;
        if node.kind != crate::DIR {
            return Err(NOT_DIRECTORY);
        }
        let outcome = if identity.permits(node, 1) {
            ram.set_cwd_token(fds, self.target)?;
            CwdOutcome::Applied
        } else {
            CwdOutcome::Failed(ACCESS_DENIED)
        };
        self.outcome = Some(outcome);
        Ok(outcome)
    }
    /// Release one retained reference; the outer job releases its existing charge.
    pub fn cancel_step(&mut self, ram: &mut Ram<'_>) -> Result<bool, u32> {
        match self.retained.take() {
            Some(Retained::Path(token)) => ram.storage.unpin(token, Pin::Pending)?,
            Some(Retained::Description(held)) => ram.io_release(held),
            None => (),
        }
        self.canceled = true;
        Ok(true)
    }
}
impl Ram<'_> {
    /// The exact shared description survives fd Close, replacement and numeric reuse.
    pub fn prepare_fchdir(
        &mut self,
        fds: &Fds,
        fd: u32,
        charge: u16,
        identity: Identity,
    ) -> Result<CwdJournal, u32> {
        self.storage.namespace_charge(fds.root, charge)?;
        let open = self.get(fds, fd)?;
        if !open.file.is_directory() {
            return Err(NOT_DIRECTORY);
        }
        let target = self.token(open.file);
        self.storage.node(target)?;
        let held = self.io_retain(fds, fd)?;
        Ok(CwdJournal {
            target,
            root: fds.root,
            charge,
            identity,
            epoch: None,
            retained: Some(Retained::Description(held)),
            outcome: None,
            canceled: false,
        })
    }
}

#[path = "getcwd.rs"]
pub(crate) mod getcwd;
pub use getcwd::{GetcwdJournal, GetcwdOutcome};
