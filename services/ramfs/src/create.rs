// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Creation uses the existing paid reservation and retains one exact outcome.
//! Readlink keeps its byte result and one atime effect through retirement.

use super::*;
use proto_fs::{MAX_PATH, NAME_TOO_LONG, RESOLVING};

#[derive(Clone, Copy)]
enum Kind {
    Directory { mode: u32, umask: u32 },
    SymbolicLink,
}
#[derive(Clone, Copy)]
enum CreatePhase {
    Resolving,
    Reserved(Reservation),
    Ready(Reservation),
    Committed,
    Canceled,
}
/// The resident target is copied before any namespace or resource effect.
/// The surrounding job retains its owner, binding stamp and native recovery key.
pub struct CreateJournal {
    kind: Kind,
    target: [u8; MAX_PATH],
    target_len: u16,
    phase: CreatePhase,
    root: Option<Root>,
    identity: Option<Identity>,
    outcome: Option<NamespaceOutcome>,
}
impl CreateJournal {
    pub fn directory(mode: u32, umask: u32) -> Self {
        Self {
            kind: Kind::Directory { mode, umask },
            target: [0; MAX_PATH],
            target_len: 0,
            phase: CreatePhase::Resolving,
            root: None,
            identity: None,
            outcome: None,
        }
    }
    pub fn symlink(target: &[u8]) -> Result<Self, u32> {
        if target.len() > MAX_PATH {
            return Err(NAME_TOO_LONG);
        }
        if target.contains(&0) {
            return Err(INVALID_ARGUMENT);
        }
        let mut result = Self::directory(0, 0);
        result.kind = Kind::SymbolicLink;
        result.target[..target.len()].copy_from_slice(target);
        result.target_len = target.len() as u16;
        Ok(result)
    }
    pub fn role(&self) -> NamespacePath {
        match self.kind {
            Kind::Directory { .. } => NamespacePath::CreateDirectory,
            Kind::SymbolicLink => NamespacePath::CreateSymbolicLink,
        }
    }
    pub fn outcome(&self) -> Option<NamespaceOutcome> {
        self.outcome
    }
    fn check(
        &self,
        storage: &Storage<'_>,
        root: Root,
        proof: &NamespaceProof<'_>,
        identity: Identity,
    ) -> Result<(), u32> {
        if proof.role != self.role()
            || proof.epoch != storage.state.epoch
            || proof.identity != identity
            || self.identity.is_some_and(|captured| captured != identity)
            || self.root.is_some_and(|captured| captured != root)
        {
            return Err(STALE_PROOF);
        }
        if let CreatePhase::Reserved(r) | CreatePhase::Ready(r) = self.phase {
            storage.reserved_edge(r, root, proof.edge.parent, proof.leaf)?;
        }
        Ok(())
    }
    /// One reservation or one unpublished content page is prepared per call.
    /// A failed call leaves its existing resources attached until exact cancellation.
    pub fn step_paid(
        &mut self,
        storage: &mut Storage<'_>,
        root: Root,
        charge: &mut u16,
        proof: NamespaceProof<'_>,
        identity: Identity,
    ) -> Result<bool, u32> {
        if self.outcome.is_some() {
            return Ok(true);
        }
        if matches!(self.phase, CreatePhase::Canceled) {
            return Err(STALE_PROOF);
        }
        self.check(storage, root, &proof, identity)?;
        match self.phase {
            CreatePhase::Resolving => {
                storage.namespace_charge(root, *charge)?;
                if proof.edge.target.is_some() {
                    return Err(ALREADY_EXISTS);
                }
                let parent = storage.node(proof.edge.parent)?;
                if !identity.permits(parent, 3) {
                    return Err(ACCESS_DENIED);
                }
                let attributes = match self.kind {
                    Kind::Directory { mode, umask } => {
                        identity.creation(parent, crate::DIR, mode, umask)
                    }
                    Kind::SymbolicLink => identity.creation(parent, SYMLINK, 0o777, 0),
                };
                let r = storage.reserve_paid(
                    root,
                    proof.edge.parent,
                    proof.leaf,
                    attributes,
                    charge,
                )?;
                self.root = Some(root);
                self.identity = Some(identity);
                self.phase = CreatePhase::Reserved(r);
                Ok(false)
            }
            CreatePhase::Reserved(r) => {
                if matches!(self.kind, Kind::SymbolicLink) && self.target_len != 0 {
                    let token = storage.reserved_token(r, root)?;
                    let count =
                        storage.write(token, root, 0, &self.target[..self.target_len as usize])?;
                    debug_assert_eq!(count, self.target_len as usize);
                }
                self.phase = CreatePhase::Ready(r);
                Ok(true)
            }
            CreatePhase::Ready(_) => Ok(true),
            _ => Err(STALE_PROOF),
        }
    }
    /// The caller verifies exact owner, image and stamp before requesting publication.
    /// Charge returns to the surrounding job after its reservation is consumed.
    pub fn commit(
        &mut self,
        storage: &mut Storage<'_>,
        root: Root,
        charge: &mut u16,
        proof: Option<NamespaceProof<'_>>,
        identity: Identity,
        now: proto_fs::Timestamp,
    ) -> Result<NamespaceOutcome, u32> {
        if let Some(outcome) = self.outcome {
            return Ok(outcome);
        }
        if matches!(self.phase, CreatePhase::Canceled) {
            return Err(STALE_PROOF);
        }
        let CreatePhase::Ready(r) = self.phase else {
            return Err(RESOLVING);
        };
        let proof = proof.ok_or(STALE_PROOF)?;
        self.check(storage, root, &proof, identity)?;
        let parent = storage.node(proof.edge.parent)?;
        if !identity.permits(parent, 3) {
            return Err(ACCESS_DENIED);
        }
        storage.commit_keep_charge(r)?;
        // Exact reserved nodes and their retained parent remain valid through publication.
        storage.node_mut(r.token).expect("published creation").times = [now; 3];
        storage
            .node_mut(proof.edge.parent)
            .expect("retained creation parent")
            .times[1..]
            .fill(now);
        *charge = r.charge();
        self.outcome = Some(NamespaceOutcome::Applied);
        self.phase = CreatePhase::Committed;
        Ok(NamespaceOutcome::Applied)
    }
    /// Reservation cleanup is bounded; its data pages use the existing incremental GC.
    /// The restored admission remains paid until the surrounding job retires it.
    pub fn cancel_step(
        &mut self,
        storage: &mut Storage<'_>,
        charge: &mut u16,
    ) -> Result<bool, u32> {
        if let CreatePhase::Reserved(r) | CreatePhase::Ready(r) = self.phase {
            storage.cancel_keep_charge(r)?;
            *charge = r.charge();
        }
        if self.outcome.is_none() {
            self.phase = CreatePhase::Canceled;
        }
        Ok(true)
    }
}

/// Readlink bytes, count and atime effect survive namespace changes and repeated replies.
pub struct ReadLinkJournal {
    bytes: [u8; MAX_PATH],
    requested: u16,
    count: Option<u16>,
    held: Option<Token>,
    canceled: bool,
}
impl ReadLinkJournal {
    pub fn new(requested: usize) -> Self {
        Self {
            bytes: [0; MAX_PATH],
            requested: requested.min(MAX_PATH) as u16,
            count: None,
            held: None,
            canceled: false,
        }
    }
    pub fn result(&self) -> Option<&[u8]> {
        self.count.map(|count| &self.bytes[..count as usize])
    }
    /// All fallible proof, type, pin and copy checks precede the single atime effect.
    pub fn capture(
        &mut self,
        storage: &mut Storage<'_>,
        proof: Option<NamespaceProof<'_>>,
        identity: Identity,
        now: proto_fs::Timestamp,
    ) -> Result<usize, u32> {
        if let Some(count) = self.count {
            return Ok(count as usize);
        }
        if self.canceled {
            return Err(STALE_PROOF);
        }
        let proof = proof.ok_or(STALE_PROOF)?;
        if proof.role != NamespacePath::ReadLink
            || proof.epoch != storage.state.epoch
            || proof.identity != identity
        {
            return Err(STALE_PROOF);
        }
        let token = proof.edge.target.ok_or(NO_ENTRY)?;
        let node = storage.node(token)?;
        if node.kind != SYMLINK {
            return Err(INVALID_ARGUMENT);
        }
        if node.pins[Pin::Pending.index()] == u16::MAX {
            return Err(NO_SPACE);
        }
        let count = storage.read(token, 0, &mut self.bytes[..self.requested as usize])?;
        storage.pin(token, Pin::Pending)?;
        self.held = Some(token);
        storage
            .node_mut(token)
            .expect("retained readlink target")
            .times[0] = now;
        self.count = Some(count as u16);
        Ok(count)
    }
    pub fn cancel_step(&mut self, storage: &mut Storage<'_>) -> Result<bool, u32> {
        if let Some(token) = self.held {
            storage.unpin(token, Pin::Pending)?;
            self.held = None;
        }
        self.canceled = true;
        Ok(true)
    }
}
