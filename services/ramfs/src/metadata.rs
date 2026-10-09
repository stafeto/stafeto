// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Paid metadata retains exact inode authority and one cached result.
//! The surrounding service owns admission, image/owner checks and trusted time.

use crate::{
    Fds, Ram,
    authority::Identity,
    io::Held,
    storage::{Pin, Root, Storage, Token},
};
use proto_fs::{
    ACCESS_DENIED, INVALID_ARGUMENT, NOT_SUPPORTED, PERMISSION, RESOLVING, STALE_PROOF, Timestamp,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeSetting {
    Exact(Timestamp),
    Now,
    Omit,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataIntent {
    Chmod(u32),
    Chown { uid: Option<u32>, gid: Option<u32> },
    Times([TimeSetting; 2]),
    Access { bits: u32, real: bool },
}
impl MetadataIntent {
    fn valid(self) -> bool {
        match self {
            Self::Times(settings) => settings.iter().all(|value| match value {
                TimeSetting::Exact(time) => time.valid(),
                _ => true,
            }),
            Self::Access { bits, .. } => bits & !7 == 0,
            _ => true,
        }
    }
    pub fn path(self, follow: bool) -> MetadataPath {
        MetadataPath {
            follow,
            real: matches!(self, Self::Access { real: true, .. }),
        }
    }
    fn needs_time(self) -> bool {
        !matches!(
            self,
            Self::Access { .. } | Self::Times([TimeSetting::Omit, TimeSetting::Omit])
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataPath {
    pub follow: bool,
    pub real: bool,
}
/// A retained Resolver creates this proof after authentic prefix traversal.
pub struct MetadataProof {
    pub(crate) target: Token,
    pub(crate) identity: Identity,
    pub(crate) epoch: u64,
    pub(crate) path: MetadataPath,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataOutcome {
    Applied,
    Unchanged,
    Failed(u32),
}
enum Retained {
    Path(Token),
    Description(Held),
}
/// The original paid job remains charged through commit and exact cancellation.
pub struct MetadataJournal {
    target: Token,
    root: Root,
    charge: u16,
    identity: Identity,
    path: Option<MetadataPath>,
    epoch: u64,
    intent: MetadataIntent,
    retained: Option<Retained>,
    outcome: Option<MetadataOutcome>,
    canceled: bool,
}
impl MetadataJournal {
    pub fn path(
        storage: &mut Storage<'_>,
        root: Root,
        charge: u16,
        proof: MetadataProof,
        identity: Identity,
        intent: MetadataIntent,
    ) -> Result<Self, u32> {
        if !intent.valid() {
            return Err(INVALID_ARGUMENT);
        }
        if proof.identity != identity
            || proof.epoch != storage.state.epoch
            || proof.path.real != intent.path(proof.path.follow).real
        {
            return Err(STALE_PROOF);
        }
        storage.namespace_charge(root, charge)?;
        storage.node(proof.target)?;
        storage.pin(proof.target, Pin::Pending)?;
        Ok(Self {
            target: proof.target,
            root,
            charge,
            identity,
            path: Some(proof.path),
            epoch: proof.epoch,
            intent,
            retained: Some(Retained::Path(proof.target)),
            outcome: None,
            canceled: false,
        })
    }
    pub fn outcome(&self) -> Option<MetadataOutcome> {
        self.outcome
    }
    /// Cached or read-only operations can complete without a Clock observation.
    pub fn needs_time(&self) -> bool {
        self.outcome.is_none() && self.intent.needs_time()
    }

    pub fn commit(
        &mut self,
        ram: &mut Ram<'_>,
        root: Root,
        identity: Identity,
        proof: Option<MetadataProof>,
        now: Option<Timestamp>,
    ) -> Result<MetadataOutcome, u32> {
        if let Some(outcome) = self.outcome {
            return Ok(outcome);
        }
        if self.canceled
            || self.retained.is_none()
            || self.root != root
            || self.identity != identity
        {
            return Err(STALE_PROOF);
        }
        ram.storage.namespace_charge(root, self.charge)?;
        if let Some(path) = self.path {
            let proof = proof.ok_or(STALE_PROOF)?;
            if proof.target != self.target
                || proof.identity != identity
                || proof.path != path
                || proof.epoch != self.epoch
                || proof.epoch != ram.storage.state.epoch
            {
                return Err(STALE_PROOF);
            }
        }
        let node = *ram.storage.node(self.target)?;
        // A link has no mode of its own to change.
        if matches!(self.intent, MetadataIntent::Chmod(_))
            && self.path.is_some_and(|path| !path.follow)
            && node.kind == crate::storage::SYMLINK
        {
            let outcome = MetadataOutcome::Failed(NOT_SUPPORTED);
            self.outcome = Some(outcome);
            return Ok(outcome);
        }
        let owner = identity.uid == 0 || identity.uid == node.uid;
        let mut mode = node.mode;
        let mut uid = node.uid;
        let mut gid = node.gid;
        let mut times = node.times;
        let allowed = match self.intent {
            MetadataIntent::Chmod(requested) => {
                mode = requested & 0o7777;
                if identity.uid != 0 && identity.gid != gid && !identity.groups.contains(gid) {
                    mode &= !0o2000;
                }
                owner
            }
            MetadataIntent::Chown {
                uid: requested_uid,
                gid: requested_gid,
            } => {
                uid = requested_uid.unwrap_or(uid);
                gid = requested_gid.unwrap_or(gid);
                mode &= !0o6000;
                identity.uid == 0
                    || (owner
                        && uid == node.uid
                        && (gid == node.gid
                            || gid == identity.gid
                            || identity.groups.contains(gid)))
            }
            MetadataIntent::Times(settings) => {
                // Only the owner sets a time of its own choosing; two "now"
                // need write permission as well; two omissions need nothing.
                owner
                    || settings == [TimeSetting::Omit; 2]
                    || (settings == [TimeSetting::Now; 2] && identity.permits(&node, 2))
            }
            MetadataIntent::Access { bits, .. } => identity.permits(&node, bits),
        };
        let outcome = if !allowed {
            MetadataOutcome::Failed(match self.intent {
                MetadataIntent::Access { .. } => ACCESS_DENIED,
                MetadataIntent::Times(settings) if settings == [TimeSetting::Now; 2] => {
                    ACCESS_DENIED
                }
                _ => PERMISSION,
            })
        } else if !self.intent.needs_time() {
            MetadataOutcome::Unchanged
        } else {
            let now = now.ok_or(RESOLVING)?;
            if !now.valid() {
                return Err(INVALID_ARGUMENT);
            }
            if let MetadataIntent::Times(settings) = self.intent {
                for (target, setting) in times[..2].iter_mut().zip(settings) {
                    *target = match setting {
                        TimeSetting::Exact(value) => value,
                        TimeSetting::Now => now,
                        TimeSetting::Omit => *target,
                    };
                }
            }
            times[2] = now;
            // All fallible authority and time checks precede this publication.
            // A change of the mode or owner of a directory raises its
            // generation (the walks in it check search permission again);
            // the times and the attributes of a file change nothing that
            // another operation has proved.
            let node = ram
                .storage
                .node_mut(self.target)
                .expect("retained metadata target");
            let access_changed = node.mode != mode || node.uid != uid || node.gid != gid;
            node.mode = mode;
            node.uid = uid;
            node.gid = gid;
            node.times = times;
            if node.kind == crate::DIR && access_changed {
                node.access_gen = node.access_gen.wrapping_add(1);
            }
            MetadataOutcome::Applied
        };
        self.outcome = Some(outcome);
        Ok(outcome)
    }
    /// Cleanup retains the originating root and releases one exact reference.
    /// The outer job releases its admission charge after this returns true.
    pub fn cancel_step(&mut self, ram: &mut Ram<'_>) -> Result<bool, u32> {
        if let Some(Retained::Path(token)) = self.retained.as_ref() {
            ram.storage.unpin(*token, Pin::Pending)?;
        }
        if let Some(Retained::Description(held)) = self.retained.take() {
            ram.io_release(held);
        }
        self.canceled = true;
        Ok(true)
    }
}
impl Ram<'_> {
    /// Retained descriptions preserve their inode/root independently of numeric reuse.
    pub fn prepare_metadata(
        &mut self,
        fds: &Fds,
        fd: u32,
        charge: u16,
        identity: Identity,
        intent: MetadataIntent,
    ) -> Result<MetadataJournal, u32> {
        if !intent.valid() {
            return Err(INVALID_ARGUMENT);
        }
        self.storage.namespace_charge(fds.root, charge)?;
        let held = self.io_retain(fds, fd)?;
        let target = self.token(held.open.file);
        Ok(MetadataJournal {
            target,
            root: fds.root,
            charge,
            identity,
            path: None,
            epoch: self.storage.state.epoch,
            intent,
            retained: Some(Retained::Description(held)),
            outcome: None,
            canceled: false,
        })
    }
}
