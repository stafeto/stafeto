// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Retained byte paths. Every step handles one component, eight names or one link.

use crate::authority::Identity;
use crate::namespace::{Edge, Location, NamespacePath, NamespaceProof, RawSyntax};
use crate::storage::{Pin, ROOT, SYMLINK, Storage, Token};
use proto_fs::{LOOP, MAX_PATH, NAME_TOO_LONG, NO_ENTRY, NOT_DIRECTORY, STALE_PROOF};

pub struct Resolve {
    original: [u8; MAX_PATH],
    path: [u8; MAX_PATH],
    length: usize,
    original_len: usize,
    pub base: Token,
    current: Token,
    at: usize,
    end: usize,
    search: usize,
    looking: bool,
    link: Option<Token>,
    links: u8,
    epoch: u64,
    pub identity: Identity,
    follow: bool,
    intent: Intent,
    edge_parent: Option<Token>,
    edge_start: usize,
    edge_end: usize,
    missing: bool,
    result: Option<Token>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    Lookup { follow: bool },
    Open { flags: u32 },
    DirectoryCreate,
    Namespace { path: NamespacePath },
}
impl Intent {
    fn follows(self) -> bool {
        match self {
            Self::Lookup { follow } => follow,
            Self::Open { flags } => {
                flags & proto_fs::NO_FOLLOW == 0
                    && flags & (proto_fs::CREATE | proto_fs::EXCLUSIVE)
                        != proto_fs::CREATE | proto_fs::EXCLUSIVE
            }
            Self::DirectoryCreate => false,
            Self::Namespace { path } => matches!(path, NamespacePath::LinkSource { follow: true }),
        }
    }
    fn permits_missing(self) -> bool {
        matches!(
            self,
            Self::DirectoryCreate
                | Self::Namespace {
                    path: NamespacePath::Destination
                }
        ) || matches!(self, Self::Open { flags } if flags & proto_fs::CREATE != 0)
    }
}
/// The exact naming edge remains borrowed from the retained resolver path.
pub struct ResultProof<'a> {
    pub parent: Token,
    pub leaf: &'a [u8],
    pub target: Option<Token>,
    pub trailing_slash: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    More,
    Found(Token),
    Missing(Token),
}
impl Resolve {
    pub fn new(
        storage: &mut Storage<'_>,
        path: &[u8],
        base: Token,
        identity: Identity,
        follow: bool,
    ) -> Result<Self, u32> {
        Self::with_intent(storage, path, base, identity, Intent::Lookup { follow })
    }
    pub fn with_intent(
        storage: &mut Storage<'_>,
        path: &[u8],
        base: Token,
        identity: Identity,
        intent: Intent,
    ) -> Result<Self, u32> {
        if path.is_empty() {
            return Err(NO_ENTRY);
        }
        if path.len() > MAX_PATH {
            return Err(NAME_TOO_LONG);
        }
        if path.contains(&0) {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let base = if path[0] == b'/' { ROOT } else { base };
        storage.pin(base, Pin::Pending)?;
        let mut original = [0; MAX_PATH];
        original[..path.len()].copy_from_slice(path);
        Ok(Self {
            path: original,
            original,
            original_len: path.len(),
            length: path.len(),
            base,
            current: base,
            at: 0,
            end: 0,
            search: 0,
            looking: false,
            link: None,
            links: 0,
            epoch: storage.state.epoch,
            identity,
            follow: intent.follows(),
            intent,
            edge_parent: None,
            edge_start: 0,
            edge_end: 0,
            missing: false,
            result: None,
        })
    }
    fn restart(&mut self, storage: &mut Storage<'_>, identity: Identity) -> Result<(), u32> {
        if let Some(result) = self.result.take() {
            storage.unpin(result, Pin::Pending)?;
        }
        if let Some(parent) = self.edge_parent.take() {
            storage.unpin(parent, Pin::Pending)?;
        }
        self.missing = false;
        self.path = self.original;
        self.length = self.original_len;
        self.current = self.base;
        self.at = 0;
        self.end = 0;
        self.search = 0;
        self.looking = false;
        self.link = None;
        self.links = 0;
        self.epoch = storage.state.epoch;
        self.identity = identity;
        Ok(())
    }
    /// The admitted raw pathname survives link expansion and traversal restarts.
    pub fn original_path(&self) -> &[u8] {
        &self.original[..self.original_len]
    }
    /// A new authentic authority generation invalidates a proof even if IDs match.
    pub fn invalidate(&mut self) {
        self.epoch = 0;
    }
    pub fn step(&mut self, storage: &mut Storage<'_>, identity: Identity) -> Result<Progress, u32> {
        if self.epoch != storage.state.epoch || self.identity != identity {
            self.restart(storage, identity)?;
            return Ok(Progress::More);
        }
        if let Some(result) = self.result {
            return Ok(Progress::Found(result));
        }
        if self.missing {
            return Ok(Progress::Missing(
                self.edge_parent.expect("retained missing parent"),
            ));
        }
        if let Some(link) = self.link.take() {
            if self.links == 32 {
                return Err(LOOP);
            }
            self.links += 1;
            let len = storage.node(link)?.length as usize;
            let rest = self.length - self.end;
            if len == 0 {
                return Err(NO_ENTRY);
            }
            if len + rest > MAX_PATH {
                return Err(NAME_TOO_LONG);
            }
            let mut replacement = [0; MAX_PATH];
            storage.read(link, 0, &mut replacement[..len])?;
            replacement[len..len + rest].copy_from_slice(&self.path[self.end..self.length]);
            if replacement[0] == b'/' {
                self.current = ROOT;
            }
            self.path = replacement;
            self.length = len + rest;
            self.at = 0;
            self.looking = false;
            return Ok(Progress::More);
        }
        if !self.looking {
            while self.at < self.length && self.path[self.at] == b'/' {
                self.at += 1;
            }
            if self.at == self.length {
                if self.path[self.length - 1] == b'/'
                    && storage.node(self.current)?.kind != crate::DIR
                    && !matches!(self.intent, Intent::DirectoryCreate)
                    && !matches!(self.intent, Intent::Open { flags }
                        if flags & (proto_fs::CREATE | proto_fs::EXCLUSIVE) == proto_fs::CREATE | proto_fs::EXCLUSIVE)
                {
                    return Err(NOT_DIRECTORY);
                }
                storage.pin(self.current, Pin::Pending)?;
                self.result = Some(self.current);
                return Ok(Progress::Found(self.current));
            }
            let directory = storage.node(self.current)?;
            if directory.kind != crate::DIR {
                return Err(NOT_DIRECTORY);
            }
            if !identity.permits(directory, 1) {
                return Err(proto_fs::ACCESS_DENIED);
            }
            let directory_parent = directory.parent;
            self.end = self.at;
            while self.end < self.length && self.path[self.end] != b'/' {
                self.end += 1;
            }
            let name = &self.path[self.at..self.end];
            if name.len() > 255 {
                return Err(NAME_TOO_LONG);
            }
            if name == b"." || name == b".." {
                let parent_component = name == b"..";
                if self.final_component() {
                    self.capture_edge(storage)?;
                }
                if parent_component {
                    self.current = directory_parent;
                }
                self.at = self.end;
                return Ok(Progress::More);
            }
            self.search = 0;
            self.looking = true;
        }
        for _ in 0..8 {
            if self.search == storage.entries() {
                if self.final_component() && self.intent.permits_missing() {
                    if self.path[self.length - 1] == b'/'
                        && !matches!(self.intent, Intent::DirectoryCreate)
                    {
                        return Err(NO_ENTRY);
                    }
                    self.capture_edge(storage)?;
                    self.missing = true;
                    return Ok(Progress::Missing(self.current));
                }
                return Err(NO_ENTRY);
            }
            let i = self.search;
            self.search += 1;
            if let Some((name, token)) = storage.entry(self.current, i)
                && name == &self.path[self.at..self.end]
            {
                let node = storage.node(token)?;
                if node.kind == SYMLINK
                    && (self.follow
                        || !self.final_component()
                        || (self.end < self.length
                            && !matches!(self.intent, Intent::DirectoryCreate)
                            && !matches!(self.intent, Intent::Open { flags }
                                if flags & (proto_fs::CREATE | proto_fs::EXCLUSIVE)
                                    == proto_fs::CREATE | proto_fs::EXCLUSIVE)))
                {
                    self.link = Some(token);
                } else {
                    if self.final_component() {
                        self.capture_edge(storage)?;
                    }
                    self.current = token;
                    self.at = self.end;
                }
                self.looking = false;
                return Ok(Progress::More);
            }
        }
        Ok(Progress::More)
    }
    fn final_component(&self) -> bool {
        self.path[self.end..self.length]
            .iter()
            .all(|&byte| byte == b'/')
    }
    fn capture_edge(&mut self, storage: &mut Storage<'_>) -> Result<(), u32> {
        storage.pin(self.current, Pin::Pending)?;
        if let Some(parent) = self.edge_parent.replace(self.current) {
            storage.unpin(parent, Pin::Pending)?;
        }
        self.edge_start = self.at;
        self.edge_end = self.end;
        Ok(())
    }
    /// A namespace proof retains the original syntax and the authentic search identity.
    pub fn namespace_proof(
        &self,
        storage: &Storage<'_>,
        identity: Identity,
        path: NamespacePath,
    ) -> Result<NamespaceProof<'_>, u32> {
        let proof = self.result_proof(storage, identity, Intent::Namespace { path })?;
        let location = if proof.target.is_none() {
            Location::Missing
        } else {
            self.search
                .checked_sub(1)
                .map(|i| storage.namespace_location(i))
                .transpose()?
                .unwrap_or(Location::Missing)
        };
        Ok(NamespaceProof {
            edge: Edge {
                parent: proof.parent,
                target: proof.target,
                location,
                syntax: RawSyntax::of(self.original_path()),
            },
            leaf: proof.leaf,
            role: path,
            identity,
            epoch: self.epoch,
        })
    }
    /// Commit must supply the same operation intent captured at admission.
    pub fn result_proof(
        &self,
        storage: &Storage<'_>,
        identity: Identity,
        intent: Intent,
    ) -> Result<ResultProof<'_>, u32> {
        if self.epoch != storage.state.epoch || self.identity != identity || self.intent != intent {
            return Err(STALE_PROOF);
        }
        storage.node(self.base)?;
        let parent = self.edge_parent.or(self.result).ok_or(STALE_PROOF)?;
        storage.node(parent)?;
        if let Some(result) = self.result {
            storage.node(result)?;
        } else if !self.missing {
            return Err(STALE_PROOF);
        }
        Ok(ResultProof {
            parent,
            leaf: &self.path[self.edge_start..self.edge_end],
            target: self.result,
            trailing_slash: self.path[self.length - 1] == b'/',
        })
    }
    pub fn proof(&self, storage: &Storage<'_>, identity: Identity) -> Result<Token, u32> {
        if !matches!(self.intent, Intent::Lookup { .. }) {
            return Err(proto_fs::PERMISSION);
        }
        if self.epoch != storage.state.epoch || self.identity != identity {
            return Err(STALE_PROOF);
        }
        let token = self.result.ok_or(STALE_PROOF)?;
        storage.node(token)?;
        storage.node(self.base)?;
        Ok(token)
    }
    pub fn release(mut self, storage: &mut Storage<'_>) {
        if let Some(result) = self.result.take() {
            let _ = storage.unpin(result, Pin::Pending);
        }
        if let Some(parent) = self.edge_parent.take() {
            let _ = storage.unpin(parent, Pin::Pending);
        }
        let _ = storage.unpin(self.base, Pin::Pending);
    }
}
