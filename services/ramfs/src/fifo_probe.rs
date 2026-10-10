// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Lifetime-image-only scheduling barrier. It never supplies an Actor outcome.
#[cfg(test)]
use crate as ramfs;
use ramfs::{
    TentativeOpen,
    locks::{
        Owner, Range, actor::Command, jobs::Id, request::Captured, waiters::RegistrationToken,
    },
    storage::Token,
};
pub const PERIOD_NS: u64 = 100_000_000;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Phase {
    Idle,
    Armed,
    Frozen,
    Selecting,
    Selected,
    Expired,
    Invalidated,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    pub owner: u64,
    pub source: TentativeOpen,
    pub inode: Token,
    pub holder: u32,
}
pub struct Gate {
    pub scope: Option<Scope>,
    pub nonce: u64,
    pub deadline: u64,
    pub phase: Phase,
    pub control: Option<Id>,
    pub selected: Option<RegistrationToken>,
    pub visited: u32,
}
impl Gate {
    pub const fn new() -> Self {
        Self {
            scope: None,
            nonce: 0,
            deadline: 0,
            phase: Phase::Idle,
            control: None,
            selected: None,
            visited: 0,
        }
    }
    pub fn active(&self) -> bool {
        matches!(self.phase, Phase::Armed | Phase::Frozen | Phase::Selecting)
    }
    pub fn frozen(&self) -> bool {
        self.phase == Phase::Frozen
    }
    pub fn pause_wait(&self) -> bool {
        matches!(self.phase, Phase::Frozen | Phase::Selecting)
    }
    pub fn arm(&mut self, scope: Scope, nonce: u64, now: u64) -> Result<(), u32> {
        if nonce == 0
            || scope.owner == 0
            || scope.inode.generation == 0
            || scope.source.description.generation == 0
            || scope.holder == 0
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        if self.nonce == nonce && self.scope == Some(scope) {
            return Ok(());
        }
        if self.active() {
            return Err(proto_fs::JOBS_FULL);
        }
        self.scope = Some(scope);
        self.nonce = nonce;
        self.deadline = now.saturating_add(PERIOD_NS);
        self.phase = Phase::Armed;
        self.control = None;
        self.selected = None;
        self.visited = 0;
        Ok(())
    }
    pub fn expire(&mut self, now: u64) {
        if self.active() && now >= self.deadline {
            self.phase = Phase::Expired;
        }
    }
    pub fn invalidate(&mut self, owner: u64) {
        if self.active() && self.scope.is_some_and(|s| s.owner == owner) {
            self.phase = Phase::Invalidated;
        }
    }
    pub fn changed(&mut self, captured: Captured) {
        if self.phase == Phase::Armed
            && self.scope.is_some_and(|s| {
                captured.request.inode == s.inode
                    && captured.request.owner == Owner::Process(s.holder)
                    && captured.request.command == Command::Set(None)
                    && captured.request.range == Range::relative(0, 4, 4).expect("fixed range")
            })
        {
            self.phase = Phase::Frozen;
        }
    }
    pub fn accepted(&mut self, id: Id, captured: Captured) {
        if self.frozen()
            && self.scope.is_some_and(|s| {
                id.owner() == s.owner
                    && captured.request.inode == s.inode
                    && matches!(
                        captured.request.command,
                        Command::Set(Some(ramfs::locks::Kind::Write))
                    )
                    && captured.request.range == Range::relative(0, 4, 4).expect("fixed range")
            })
        {
            self.control = Some(id);
            self.phase = Phase::Selecting;
        }
    }
    pub fn visit(&mut self, id: Id, visited: usize) {
        if self.phase == Phase::Selecting && self.control == Some(id) {
            self.visited = self.visited.saturating_add(visited as u32);
        }
    }
    pub fn finish(&mut self, id: Id, selected: Option<RegistrationToken>) {
        if self.phase == Phase::Selecting && self.control == Some(id) {
            self.selected = selected;
            self.phase = Phase::Selected;
        }
    }
}

#[cfg(test)]
#[path = "fifo_probe_tests.rs"]
mod tests;
