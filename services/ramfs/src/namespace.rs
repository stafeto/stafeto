// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A paid namespace journal prepares exact edges and publishes one cached effect.
//! The service retains its admitted job, authentic owner and binding stamp.

use super::*;
use crate::authority::Identity;
#[path = "create.rs"]
mod create;
pub use create::{CreateJournal, ReadLinkJournal};
use proto_fs::{
    ACCESS_DENIED, ALREADY_EXISTS, INVALID_ARGUMENT, IS_DIRECTORY, NOT_DIRECTORY, PERMISSION,
    STALE_PROOF,
};

pub use proto_fs::{BUSY, NOT_EMPTY, TOO_MANY_LINKS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamespaceIntent {
    Unlink,
    Rmdir,
    Remove,
    Rename,
    Link { follow_source: bool },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamespacePath {
    Victim,
    Destination,
    LinkSource { follow: bool },
    CreateDirectory,
    CreateSymbolicLink,
    ReadLink,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalComponent {
    Root,
    Ordinary,
    Dot,
    DotDot,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawSyntax {
    pub final_component: FinalComponent,
    pub trailing_slash: bool,
}
impl RawSyntax {
    pub(crate) fn of(path: &[u8]) -> Self {
        let component = path.split(|&b| b == b'/').rfind(|part| !part.is_empty());
        Self {
            final_component: match component {
                None => FinalComponent::Root,
                Some(b".") => FinalComponent::Dot,
                Some(b"..") => FinalComponent::DotDot,
                Some(_) => FinalComponent::Ordinary,
            },
            trailing_slash: path.last() == Some(&b'/'),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Location {
    Missing,
    Original(u16),
    Dynamic(u16),
    ModelToken,
}
#[derive(Clone, Copy)]
pub(crate) struct Edge {
    pub parent: Token,
    pub target: Option<Token>,
    pub location: Location,
    pub syntax: RawSyntax,
}
/// Native construction is restricted to the retained resolver's verified result.
pub struct NamespaceProof<'a> {
    pub(crate) edge: Edge,
    pub(crate) leaf: &'a [u8],
    pub(crate) role: NamespacePath,
    pub(crate) identity: Identity,
    pub(crate) epoch: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamespaceOutcome {
    Applied,
    Unchanged,
    Failed(u32),
}
#[derive(Clone, Copy)]
struct LinkDelta {
    token: Token,
    previous: u32,
    next: u32,
}
#[derive(Clone, Copy)]
struct OverlayReserve {
    slot: u16,
    root: u16,
    initialized: bool,
}
struct Reserves {
    dentries: [Option<u16>; 3],
    overlays: [Option<OverlayReserve>; 2],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Empty,
    Ancestors,
    Prepay,
    Ready,
    Committed,
    Canceling,
    Canceled,
}
/// Each staged resource is retained until publication or exact bounded cancellation.
/// Admission belongs to the surrounding job throughout this record's lifetime.
pub struct Preparation {
    edges: [Edge; 2],
    destination_name: [u8; 255],
    destination_len: u8,
    root: Root,
    identity: Identity,
    charge: u16,
    intent: NamespaceIntent,
    epoch: u64,
    reserves: Reserves,
    links: [Option<LinkDelta>; 4],
    cursor: u16,
    ancestor: Option<Token>,
    ancestor_steps: u16,
    pins_held: u8,
    phase: Phase,
    outcome: Option<NamespaceOutcome>,
}
impl Preparation {
    pub fn outcome(&self) -> Option<NamespaceOutcome> {
        self.outcome
    }
    fn nodes(&self) -> [Option<Token>; 4] {
        [
            Some(self.edges[0].parent),
            self.edges[0].target,
            self.has_destination().then_some(self.edges[1].parent),
            if self.has_destination() {
                self.edges[1].target
            } else {
                None
            },
        ]
    }
    fn has_destination(&self) -> bool {
        matches!(
            self.intent,
            NamespaceIntent::Rename | NamespaceIntent::Link { .. }
        )
    }
    fn removes_source(&self) -> bool {
        !matches!(self.intent, NamespaceIntent::Link { .. })
    }
    fn empty_target(&self, storage: &Storage<'_>) -> Option<Token> {
        let token = if self.intent == NamespaceIntent::Rename {
            self.edges[1].target
        } else if self.removes_source() {
            self.edges[0].target
        } else {
            None
        };
        token.filter(|&t| storage.node(t).is_ok_and(|n| n.kind == crate::DIR))
    }
    fn check(&self, storage: &Storage<'_>, identity: Identity) -> Result<(), u32> {
        if storage.state.epoch != self.epoch || identity != self.identity {
            return Err(STALE_PROOF);
        }
        storage.namespace_charge(self.root, self.charge)?;
        storage.namespace_edge(self.edges[0])?;
        if self.has_destination() {
            storage.namespace_edge(self.edges[1])?;
        }
        let source = storage.node(self.edges[0].target.ok_or(NO_ENTRY)?)?;
        let parent = storage.node(self.edges[0].parent)?;
        if self.removes_source() {
            if !identity.permits(parent, 3) {
                return Err(ACCESS_DENIED);
            }
            if !identity.sticky(parent, source) {
                return Err(PERMISSION);
            }
        }
        if self.has_destination() {
            let parent = storage.node(self.edges[1].parent)?;
            if parent.links == 0 {
                return Err(NO_ENTRY);
            }
            if !identity.permits(parent, 3) {
                return Err(ACCESS_DENIED);
            }
            if let Some(victim) = self.edges[1].target
                && !identity.sticky(parent, storage.node(victim)?)
            {
                return Err(PERMISSION);
            }
        }
        Ok(())
    }
    fn add_links(&mut self, storage: &Storage<'_>, token: Token, delta: i64) -> Result<(), u32> {
        let i = self
            .links
            .iter()
            .position(|n| n.is_some_and(|n| n.token == token))
            .or_else(|| self.links.iter().position(Option::is_none))
            .ok_or(INVALID_ARGUMENT)?;
        let old = storage.node(token)?.links;
        let previous = self.links[i].map_or(old, |n| n.next);
        let next = if delta >= 0 {
            previous.checked_add(delta as u32).ok_or(TOO_MANY_LINKS)?
        } else {
            previous.checked_sub((-delta) as u32).ok_or(STALE_PROOF)?
        };
        self.links[i] = Some(LinkDelta {
            token,
            previous: old,
            next,
        });
        Ok(())
    }
    fn calculate_links(&mut self, storage: &Storage<'_>) -> Result<(), u32> {
        self.links.fill(None);
        let source = self.edges[0].target.ok_or(NO_ENTRY)?;
        let directory = storage.node(source)?.kind == crate::DIR;
        match self.intent {
            NamespaceIntent::Link { .. } => self.add_links(storage, source, 1)?,
            NamespaceIntent::Rename => {
                if let Some(victim) = self.edges[1].target {
                    if storage.node(victim)?.kind == crate::DIR {
                        self.add_links(storage, victim, -2)?;
                        self.add_links(storage, self.edges[1].parent, -1)?;
                    } else {
                        self.add_links(storage, victim, -1)?;
                    }
                }
                if directory && self.edges[0].parent != self.edges[1].parent {
                    self.add_links(storage, self.edges[0].parent, -1)?;
                    self.add_links(storage, self.edges[1].parent, 1)?;
                }
            }
            _ if directory => {
                self.add_links(storage, source, -2)?;
                self.add_links(storage, self.edges[0].parent, -1)?;
            }
            _ => self.add_links(storage, source, -1)?,
        }
        Ok(())
    }
    fn dentry_needed(&self, index: usize) -> bool {
        match index {
            0 => self.removes_source() && matches!(self.edges[0].location, Location::Original(_)),
            1 => {
                self.intent == NamespaceIntent::Rename
                    && matches!(self.edges[1].location, Location::Original(_))
            }
            2 => {
                matches!(self.intent, NamespaceIntent::Link { .. })
                    || self.intent == NamespaceIntent::Rename
                        && matches!(self.edges[0].location, Location::Original(_))
            }
            _ => false,
        }
    }
    fn overlay_token(&self, index: usize) -> Option<Token> {
        match index {
            0 => self.edges[0].target,
            1 if self.intent == NamespaceIntent::Rename => self.edges[1].target,
            _ => None,
        }
    }
    /// One empty-directory portion, ancestor hop, allocation or page-map initialization.
    pub fn step(&mut self, storage: &mut Storage<'_>, identity: Identity) -> Result<bool, u32> {
        if self.outcome.is_some() {
            return Ok(true);
        }
        if matches!(self.phase, Phase::Canceling | Phase::Canceled) {
            return Err(STALE_PROOF);
        }
        self.check(storage, identity)?;
        match self.phase {
            Phase::Empty => {
                if let Some(target) = self.empty_target(storage) {
                    for _ in 0..8 {
                        if self.cursor as usize == storage.entries() {
                            self.phase = Phase::Ancestors;
                            break;
                        }
                        if storage.entry(target, self.cursor as usize).is_some() {
                            return Err(NOT_EMPTY);
                        }
                        self.cursor += 1;
                    }
                } else {
                    self.phase = Phase::Ancestors;
                }
            }
            Phase::Ancestors => {
                if self.intent == NamespaceIntent::Rename
                    && storage.node(self.edges[0].target.unwrap())?.kind == crate::DIR
                {
                    let at = self.ancestor.unwrap_or(self.edges[1].parent);
                    if Some(at) == self.edges[0].target {
                        return Err(INVALID_ARGUMENT);
                    }
                    if at == ROOT {
                        self.phase = Phase::Prepay;
                    } else {
                        if self.ancestor_steps == NODES as u16 {
                            return Err(INVALID_ARGUMENT);
                        }
                        self.ancestor = Some(storage.node(at)?.parent);
                        self.ancestor_steps += 1;
                    }
                } else {
                    self.phase = Phase::Prepay;
                }
            }
            Phase::Prepay => {
                for i in 0..3 {
                    if self.dentry_needed(i) && self.reserves.dentries[i].is_none() {
                        self.reserves.dentries[i] =
                            Some(storage.namespace_reserve_dentry(self.charge, i == 2)?);
                        return Ok(false);
                    }
                }
                for i in 0..2 {
                    if let Some(held) = self.reserves.overlays[i] {
                        if !held.initialized {
                            storage.state.overlays[held.slot as usize]
                                .initialize(self.overlay_token(i).unwrap().slot, held.root);
                            self.reserves.overlays[i].as_mut().unwrap().initialized = true;
                            return Ok(false);
                        }
                    } else if let Some(token) = self.overlay_token(i)
                        && storage.node(token)?.overlay == NONE
                    {
                        self.reserves.overlays[i] =
                            Some(storage.namespace_reserve_overlay(self.charge)?);
                        return Ok(false);
                    }
                }
                self.calculate_links(storage)?;
                self.phase = Phase::Ready;
            }
            Phase::Ready => return Ok(true),
            _ => return Err(STALE_PROOF),
        }
        Ok(self.phase == Phase::Ready)
    }
    /// Cached outcomes precede new authority checks. The service checks the exact owner.
    pub fn commit(
        &mut self,
        storage: &mut Storage<'_>,
        identity: Identity,
        now: proto_fs::Timestamp,
    ) -> Result<NamespaceOutcome, u32> {
        if let Some(outcome) = self.outcome {
            return Ok(outcome);
        }
        if self.phase != Phase::Ready {
            return Err(STALE_PROOF);
        }
        self.check(storage, identity)?;
        let next_epoch = storage.state.epoch.checked_add(1).ok_or(NO_SPACE)?;
        for delta in self.links.iter().flatten() {
            if storage.node(delta.token)?.links != delta.previous {
                return Err(STALE_PROOF);
            }
        }
        if let Some(victim) = self.empty_target(storage) {
            if storage.node(victim)?.links != 2 {
                return Err(STALE_PROOF);
            }
            let parent = if self.intent == NamespaceIntent::Rename {
                self.edges[1].parent
            } else {
                self.edges[0].parent
            };
            if storage.node(parent)?.pins[Pin::Parent.index()] == u16::MAX {
                return Err(NO_SPACE);
            }
        }
        for i in 0..2 {
            if let Some(held) = self.reserves.overlays[i]
                && (!held.initialized
                    || storage.node(self.overlay_token(i).unwrap())?.overlay != NONE)
            {
                return Err(STALE_PROOF);
            }
        }
        // Every fallible check and resource payment precedes this publication.
        for i in 0..2 {
            if let Some(held) = self.reserves.overlays[i].take() {
                storage.state.nodes[self.overlay_token(i).unwrap().slot as usize].overlay =
                    held.slot;
            }
        }
        if let Some(victim) = self.empty_target(storage) {
            let parent = if self.intent == NamespaceIntent::Rename {
                self.edges[1].parent
            } else {
                self.edges[0].parent
            };
            storage.state.nodes[parent.slot as usize].pins[Pin::Parent.index()] += 1;
            storage.state.nodes[victim.slot as usize].orphan_parent = true;
        }
        let source = self.edges[0].target.unwrap();
        if self.removes_source() {
            storage.namespace_remove_edge(
                self.edges[0],
                self.reserves.dentries[0].take(),
                self.intent != NamespaceIntent::Rename,
            );
        }
        if self.intent == NamespaceIntent::Rename && self.edges[1].target.is_some() {
            storage.namespace_remove_edge(self.edges[1], self.reserves.dentries[1].take(), true);
        }
        if self.has_destination() {
            let slot = if self.intent == NamespaceIntent::Rename
                && let Location::Dynamic(slot) = self.edges[0].location
            {
                slot
            } else {
                self.reserves.dentries[2].take().expect("paid new name")
            };
            let d = &mut storage.state.dentries[slot as usize];
            d.parent = self.edges[1].parent;
            d.node = source;
            d.len = self.destination_len;
            d.name[..d.len as usize].copy_from_slice(&self.destination_name[..d.len as usize]);
            d.reserved = false;
            if storage.state.nodes[source.slot as usize].kind == crate::DIR {
                storage.state.nodes[source.slot as usize].parent = self.edges[1].parent;
            }
        }
        for delta in self.links.iter().flatten() {
            storage.state.nodes[delta.token.slot as usize].links = delta.next;
        }
        if self.removes_source() {
            storage.state.nodes[self.edges[0].parent.slot as usize].times[1..].fill(now);
        }
        if self.has_destination() {
            storage.state.nodes[self.edges[1].parent.slot as usize].times[1..].fill(now);
        }
        storage.state.nodes[source.slot as usize].times[2] = now;
        if self.intent == NamespaceIntent::Rename
            && let Some(victim) = self.edges[1].target
        {
            storage.state.nodes[victim.slot as usize].times[2] = now;
        }
        storage.state.epoch = next_epoch;
        self.outcome = Some(NamespaceOutcome::Applied);
        self.phase = Phase::Committed;
        Ok(NamespaceOutcome::Applied)
    }
    /// One reserved object or owned pin is released per call. Admission stays paid.
    pub fn cancel_step(&mut self, storage: &mut Storage<'_>) -> Result<bool, u32> {
        if self.phase == Phase::Canceled {
            return Ok(true);
        }
        self.phase = Phase::Canceling;
        for slot in &mut self.reserves.dentries {
            if let Some(index) = slot.take() {
                storage.drop_dentry(index as usize);
                return Ok(false);
            }
        }
        for held in &mut self.reserves.overlays {
            if let Some(held) = held.take() {
                storage.state.overlays[held.slot as usize] = Overlay::EMPTY;
                storage.state.inode_free[storage.state.inode_len] = held.slot;
                storage.state.inode_len += 1;
                storage.uncharge(held.root as usize, |u| &mut u.inodes);
                return Ok(false);
            }
        }
        let nodes = self.nodes();
        for (i, token) in nodes.into_iter().enumerate() {
            if self.pins_held & (1 << i) != 0 {
                self.pins_held &= !(1 << i);
                storage.unpin(token.expect("owned pending pin"), Pin::Pending)?;
                return Ok(false);
            }
        }
        self.phase = Phase::Canceled;
        Ok(true)
    }
}
impl Storage<'_> {
    pub(crate) fn namespace_charge(&self, root: Root, charge: u16) -> Result<(), u32> {
        if self
            .state
            .accounts
            .get(charge as usize)
            .and_then(Option::as_ref)
            .is_some_and(|a| a.key == root && a.pending != 0)
        {
            Ok(())
        } else {
            Err(INVALID_ARGUMENT)
        }
    }
    fn namespace_edge(&self, edge: Edge) -> Result<(), u32> {
        let parent = self.node(edge.parent)?;
        if parent.kind != crate::DIR {
            return Err(NOT_DIRECTORY);
        }
        if parent.links == 0 {
            return Err(NO_ENTRY);
        }
        if let Some(target) = edge.target {
            self.node(target)?;
        }
        let valid = match edge.location {
            Location::Missing => edge.target.is_none(),
            Location::ModelToken => edge.target.is_some(),
            Location::Original(i) => self.state.originals.get(i as usize).is_some_and(|d| {
                !d.hidden && d.parent == edge.parent && Some(d.node) == edge.target
            }),
            Location::Dynamic(i) => self.state.dentries.get(i as usize).is_some_and(|d| {
                d.len != 0 && !d.reserved && d.parent == edge.parent && Some(d.node) == edge.target
            }),
        };
        if valid { Ok(()) } else { Err(STALE_PROOF) }
    }
    pub(crate) fn namespace_location(&self, index: usize) -> Result<Location, u32> {
        if index < self.state.original_len {
            Ok(Location::Original(index as u16))
        } else if index < self.entries() {
            Ok(Location::Dynamic((index - self.state.original_len) as u16))
        } else {
            Err(STALE_PROOF)
        }
    }
    fn namespace_reserve_dentry(&mut self, charge: u16, visible: bool) -> Result<u16, u32> {
        let a = self.state.accounts[charge as usize]
            .as_ref()
            .ok_or(INVALID_ARGUMENT)?;
        if self.state.dentry_len == 0 || a.usage.dentries == DENTRY_SHARE {
            return Err(NO_SPACE);
        }
        let cookie = if visible {
            self.next_directory_cookie()?
        } else {
            0
        };
        self.state.dentry_len -= 1;
        let i = self.state.dentry_free[self.state.dentry_len];
        self.state.dentries[i as usize] = Dentry {
            root: charge,
            reserved: true,
            cookie,
            ..Dentry::EMPTY
        };
        self.state.accounts[charge as usize]
            .as_mut()
            .unwrap()
            .usage
            .dentries += 1;
        Ok(i)
    }
    fn namespace_reserve_overlay(&mut self, charge: u16) -> Result<OverlayReserve, u32> {
        let a = self.state.accounts[charge as usize]
            .as_ref()
            .ok_or(INVALID_ARGUMENT)?;
        if self.state.inode_len == 0 || a.usage.inodes == INODE_SHARE {
            return Err(NO_SPACE);
        }
        self.state.inode_len -= 1;
        let slot = self.state.inode_free[self.state.inode_len];
        self.state.accounts[charge as usize]
            .as_mut()
            .unwrap()
            .usage
            .inodes += 1;
        Ok(OverlayReserve {
            slot,
            root: charge,
            initialized: false,
        })
    }
    fn namespace_remove_edge(&mut self, edge: Edge, tombstone: Option<u16>, drop_dynamic: bool) {
        match edge.location {
            Location::Original(i) => {
                let slot = tombstone.expect("paid original tombstone");
                self.state.dentries[slot as usize].parent = edge.parent;
                self.state.dentries[slot as usize].node = edge.target.unwrap();
                self.state.originals[i as usize].hidden = true;
            }
            Location::Dynamic(i) if drop_dynamic => self.drop_dentry(i as usize),
            Location::Dynamic(_) => {}
            _ => unreachable!("existing naming edge"),
        }
    }
    /// The genuine surrounding job already owns this exact root admission.
    /// Native proofs come from both retained resolvers under their captured identity.
    pub fn prepare_namespace_paid(
        &mut self,
        root: Root,
        charge: u16,
        intent: NamespaceIntent,
        source: NamespaceProof<'_>,
        destination: Option<NamespaceProof<'_>>,
        identity: Identity,
    ) -> Result<Preparation, u32> {
        self.namespace_charge(root, charge)?;
        let expected = match intent {
            NamespaceIntent::Link { follow_source } => NamespacePath::LinkSource {
                follow: follow_source,
            },
            _ => NamespacePath::Victim,
        };
        if source.role != expected
            || source.epoch != self.state.epoch
            || source.identity != identity
        {
            return Err(STALE_PROOF);
        }
        let has_destination = matches!(
            intent,
            NamespaceIntent::Rename | NamespaceIntent::Link { .. }
        );
        if has_destination != destination.is_some() {
            return Err(INVALID_ARGUMENT);
        }
        let mut edges = [source.edge; 2];
        let mut destination_name = [0; 255];
        let mut destination_len = 0;
        if let Some(dest) = destination {
            if dest.role != NamespacePath::Destination
                || dest.epoch != self.state.epoch
                || dest.identity != identity
            {
                return Err(STALE_PROOF);
            }
            if dest.edge.syntax.final_component == FinalComponent::Root {
                return Err(BUSY);
            }
            if dest.leaf.is_empty()
                || dest.leaf.len() > 255
                || dest.leaf.contains(&0)
                || dest.leaf.contains(&b'/')
            {
                return Err(INVALID_ARGUMENT);
            }
            destination_name[..dest.leaf.len()].copy_from_slice(dest.leaf);
            destination_len = dest.leaf.len() as u8;
            edges[1] = dest.edge;
        }
        let source_kind = self.node(edges[0].target.ok_or(NO_ENTRY)?)?.kind;
        if matches!(intent, NamespaceIntent::Link { .. }) && source_kind == crate::DIR {
            return Err(PERMISSION);
        }
        for edge in &edges[..if has_destination { 2 } else { 1 }] {
            match edge.syntax.final_component {
                FinalComponent::Root => return Err(BUSY),
                FinalComponent::Dot | FinalComponent::DotDot => return Err(INVALID_ARGUMENT),
                FinalComponent::Ordinary => {}
            }
            if edge.target == Some(ROOT) {
                return Err(BUSY);
            }
            self.namespace_edge(*edge)?;
            if edge.syntax.trailing_slash {
                let token = edge.target.ok_or(NO_ENTRY)?;
                if self.node(token)?.kind != crate::DIR {
                    return Err(NOT_DIRECTORY);
                }
            }
        }
        let token = edges[0].target.ok_or(NO_ENTRY)?;
        let kind = self.node(token)?.kind;
        match intent {
            NamespaceIntent::Unlink if kind == crate::DIR => return Err(PERMISSION),
            NamespaceIntent::Rmdir if kind != crate::DIR => return Err(NOT_DIRECTORY),
            NamespaceIntent::Link { .. } if kind == crate::DIR => return Err(PERMISSION),
            NamespaceIntent::Link { .. } if edges[1].target.is_some() => {
                return Err(ALREADY_EXISTS);
            }
            NamespaceIntent::Rename => {
                if let Some(target) = edges[1].target {
                    let target_dir = self.node(target)?.kind == crate::DIR;
                    if kind == crate::DIR && !target_dir {
                        return Err(NOT_DIRECTORY);
                    }
                    if kind != crate::DIR && target_dir {
                        return Err(IS_DIRECTORY);
                    }
                }
            }
            _ => {}
        }
        let mut prep = Preparation {
            edges,
            destination_name,
            destination_len,
            root,
            identity,
            charge,
            intent,
            epoch: self.state.epoch,
            reserves: Reserves {
                dentries: [None; 3],
                overlays: [None; 2],
            },
            links: [None; 4],
            cursor: 0,
            ancestor: None,
            ancestor_steps: 0,
            pins_held: 0,
            phase: Phase::Empty,
            outcome: None,
        };
        prep.check(self, identity)?;
        if intent == NamespaceIntent::Rename && edges[1].target == Some(token) {
            prep.outcome = Some(NamespaceOutcome::Unchanged);
            prep.phase = Phase::Committed;
            return Ok(prep);
        }
        let nodes = prep.nodes();
        for (i, token) in nodes.iter().enumerate() {
            if let Some(token) = token
                && !nodes[..i].contains(&Some(*token))
                && self.node(*token)?.pins[Pin::Pending.index()] == u16::MAX
            {
                return Err(NO_SPACE);
            }
        }
        for (i, token) in nodes.iter().enumerate() {
            if let Some(token) = token
                && !nodes[..i].contains(&Some(*token))
            {
                self.pin(*token, Pin::Pending)
                    .expect("preflight pending pin");
                prep.pins_held |= 1 << i;
            }
        }
        Ok(prep)
    }
}
fn model_identity() -> Identity {
    Identity {
        uid: 0,
        gid: 0,
        groups: proto_process::Groups::EMPTY,
    }
}
fn model_edge<'a>(
    storage: &Storage<'_>,
    parent: Token,
    name: &'a [u8],
    role: NamespacePath,
) -> Result<NamespaceProof<'a>, u32> {
    let found = (0..storage.entries()).find_map(|i| {
        storage
            .entry(parent, i)
            .filter(|(n, _)| *n == name)
            .map(|(_, token)| (i, token))
    });
    Ok(NamespaceProof {
        edge: Edge {
            parent,
            target: found.map(|(_, t)| t),
            location: found.map_or(Ok(Location::Missing), |(i, _)| {
                storage.namespace_location(i)
            })?,
            syntax: RawSyntax::of(name),
        },
        leaf: name,
        role,
        identity: model_identity(),
        epoch: storage.state.epoch,
    })
}
fn model_finish(storage: &mut Storage<'_>, mut prep: Preparation, charge: u16) -> Result<(), u32> {
    let result = (|| {
        while !prep.step(storage, model_identity())? {}
        match prep.commit(storage, model_identity(), proto_fs::Timestamp::legacy_ns(0))? {
            NamespaceOutcome::Failed(code) => Err(code),
            _ => Ok(()),
        }
    })();
    while !prep.cancel_step(storage).expect("model namespace cleanup") {}
    storage.release_preparation(charge);
    result
}
pub(super) fn model_unlink(
    storage: &mut Storage<'_>,
    parent: Token,
    name: &[u8],
    root: Root,
) -> Result<Token, u32> {
    let charge = storage.charge_preparation(root)?;
    let prepared = (|| {
        let proof = model_edge(storage, parent, name, NamespacePath::Victim)?;
        let token = proof.edge.target.ok_or(NO_ENTRY)?;
        // The trusted storage model preserves its directory refusal status.
        if storage.node(token)?.kind == crate::DIR {
            return Err(IS_DIRECTORY);
        }
        Ok((
            token,
            storage.prepare_namespace_paid(
                root,
                charge,
                NamespaceIntent::Unlink,
                proof,
                None,
                model_identity(),
            )?,
        ))
    })();
    match prepared {
        Ok((token, prep)) => {
            model_finish(storage, prep, charge)?;
            Ok(token)
        }
        Err(code) => {
            storage.release_preparation(charge);
            Err(code)
        }
    }
}
pub(super) fn model_link(
    storage: &mut Storage<'_>,
    root: Root,
    parent: Token,
    name: &[u8],
    token: Token,
) -> Result<(), u32> {
    let charge = storage.charge_preparation(root)?;
    let prepared = (|| {
        let dest = model_edge(storage, parent, name, NamespacePath::Destination)?;
        let source = NamespaceProof {
            edge: Edge {
                parent: ROOT,
                target: Some(token),
                location: Location::ModelToken,
                syntax: RawSyntax {
                    final_component: FinalComponent::Ordinary,
                    trailing_slash: false,
                },
            },
            leaf: b"",
            role: NamespacePath::LinkSource { follow: false },
            identity: model_identity(),
            epoch: storage.state.epoch,
        };
        storage.prepare_namespace_paid(
            root,
            charge,
            NamespaceIntent::Link {
                follow_source: false,
            },
            source,
            Some(dest),
            model_identity(),
        )
    })();
    match prepared {
        Ok(prep) => model_finish(storage, prep, charge),
        Err(code) => {
            storage.release_preparation(charge);
            Err(if code == ALREADY_EXISTS {
                INVALID_ARGUMENT
            } else {
                code
            })
        }
    }
}
