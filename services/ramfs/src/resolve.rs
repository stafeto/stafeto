// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Retained byte paths. Every step handles one component, eight names or one link.

use crate::authority::Identity;
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
    result: Option<Token>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    More,
    Found(Token),
}
impl Resolve {
    pub fn new(
        storage: &mut Storage<'_>,
        path: &[u8],
        base: Token,
        identity: Identity,
        follow: bool,
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
            follow,
            result: None,
        })
    }
    fn restart(&mut self, storage: &mut Storage<'_>, identity: Identity) -> Result<(), u32> {
        if let Some(result) = self.result.take() {
            storage.unpin(result, Pin::Pending)?;
        }
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
    pub fn step(&mut self, storage: &mut Storage<'_>, identity: Identity) -> Result<Progress, u32> {
        if self.epoch != storage.state.epoch || self.identity != identity {
            self.restart(storage, identity)?;
            return Ok(Progress::More);
        }
        if let Some(result) = self.result {
            return Ok(Progress::Found(result));
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
            self.end = self.at;
            while self.end < self.length && self.path[self.end] != b'/' {
                self.end += 1;
            }
            let name = &self.path[self.at..self.end];
            if name.len() > 255 {
                return Err(NAME_TOO_LONG);
            }
            if name == b"." || name == b".." {
                if name == b".." {
                    self.current = directory.parent;
                }
                self.at = self.end;
                return Ok(Progress::More);
            }
            self.search = 0;
            self.looking = true;
        }
        for _ in 0..8 {
            if self.search == storage.entries() {
                return Err(NO_ENTRY);
            }
            let i = self.search;
            self.search += 1;
            if let Some((name, token)) = storage.entry(self.current, i)
                && name == &self.path[self.at..self.end]
            {
                let node = storage.node(token)?;
                if node.kind == SYMLINK && (self.follow || self.end < self.length) {
                    self.link = Some(token);
                } else {
                    self.current = token;
                    self.at = self.end;
                }
                self.looking = false;
                return Ok(Progress::More);
            }
        }
        Ok(Progress::More)
    }
    pub fn proof(&self, storage: &Storage<'_>, identity: Identity) -> Result<Token, u32> {
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
        let _ = storage.unpin(self.base, Pin::Pending);
    }
}
