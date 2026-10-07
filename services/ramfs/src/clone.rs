// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Atomic bounded descriptor capture with retained, one-reference rollback.

use crate::{
    Fds, OPEN_MAX, Ram,
    storage::{Pin, Root, Token},
};

pub struct Snapshot {
    slots: [Option<u8>; OPEN_MAX],
    cwd: Option<Token>,
    root: Root,
}
impl Snapshot {
    /// Complete preflight precedes every reference and CWD mutation.
    pub fn preflight(ram: &Ram<'_>, source: &Fds, list: &[u32]) -> Result<Self, u32> {
        if list.len() > OPEN_MAX {
            return Err(proto_wire::BAD_SIZE);
        }
        let mut slots = [None; OPEN_MAX];
        for &fd in list {
            let index = source.description(fd)?;
            slots[(fd - 3) as usize] = Some(index as u8);
        }
        let mut additions = [0u8; crate::DESCRIPTIONS];
        for &slot in slots.iter().flatten() {
            additions[usize::from(slot)] += 1;
        }
        for (index, &count) in additions.iter().enumerate() {
            if count != 0 {
                ram.descriptions[index]
                    .as_ref()
                    .ok_or(proto_fs::BAD_FD)?
                    .refs
                    .checked_add(u16::from(count))
                    .ok_or(proto_fs::TOO_MANY_OPEN_FILES)?;
            }
        }
        if let Some(cwd) = source.cwd {
            ram.storage.can_pin(cwd, Pin::Cwd)?;
        }
        Ok(Self {
            slots,
            cwd: source.cwd,
            root: source.root,
        })
    }
    /// Commit immediately after preflight on the sole service thread.
    pub fn retain(&self, ram: &mut Ram<'_>) {
        if let Some(cwd) = self.cwd {
            ram.storage.pin(cwd, Pin::Cwd).expect("preflight CWD pin");
        }
        for &slot in self.slots.iter().flatten() {
            ram.descriptions[usize::from(slot)]
                .as_mut()
                .expect("preflight description")
                .refs += 1;
        }
    }
    pub fn capture(ram: &mut Ram<'_>, source: &Fds, list: &[u32]) -> Result<Self, u32> {
        let snapshot = Self::preflight(ram, source, list)?;
        snapshot.retain(ram);
        Ok(snapshot)
    }
    /// Settle one retained owner; the child remains resident after an error.
    pub fn release_step(&mut self, ram: &mut Ram<'_>) -> Result<bool, u32> {
        if let Some(cwd) = self.cwd {
            ram.storage.unpin(cwd, Pin::Cwd)?;
            self.cwd = None;
            return Ok(true);
        }
        if let Some(index) = self.slots.iter().position(Option::is_some) {
            ram.release_shared(usize::from(self.slots[index].expect("retained reference")))?;
            self.slots[index] = None;
            return Ok(true);
        }
        Ok(false)
    }
    pub fn materialize(self) -> Fds {
        Fds {
            slots: self.slots,
            cwd: self.cwd,
            root: self.root,
            ..Fds::default()
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Session,
    Reply,
    ErrorReply,
    Rollback,
}

pub struct Journal<H, T> {
    pub owner: u64,
    pub snapshot: Option<Snapshot>,
    pub binding: crate::authority::Binding,
    pub authority_index: u16,
    pub session: Option<H>,
    pub token: Option<T>,
    pub phase: Phase,
    pub code: u32,
}

pub struct Refusal<H, T> {
    pub error: abi::Error,
    pub back: Option<H>,
    pub token: Option<T>,
}

/// Actual ABI adapter supplies each single kernel effect; the journal owns every retry.
pub trait Effects<H, T> {
    fn label(&mut self, label: u64) -> Result<H, abi::Error>;
    fn reply(&mut self, token: T, session: Option<H>, code: u32) -> Result<(), Refusal<H, T>>;
    fn close(&mut self, session: &mut Option<H>) -> Result<(), abi::Error>;
    fn close_identity(&mut self, index: u16, label: u64) -> Result<(), abi::Error>;
}

pub enum Outcome {
    Pending,
    Ready,
    Terminal,
}

impl<H, T> Journal<H, T> {
    pub fn revoke(&mut self, error: abi::Error) {
        self.code = proto_wire::Status::Kernel(error).code();
        self.phase = if self.token.is_some() {
            Phase::ErrorReply
        } else {
            Phase::Rollback
        };
    }
    /// One actual kernel effect or one retained CPU settlement, including failed attempts.
    pub fn step(
        &mut self,
        ram: &mut Ram<'_>,
        label: u64,
        effects: &mut impl Effects<H, T>,
    ) -> Outcome {
        let mut published = false;
        match self.phase {
            Phase::Session => match effects.label(label) {
                Ok(session) => {
                    self.session = Some(session);
                    self.phase = Phase::Reply;
                }
                Err(error) => self.revoke(error),
            },
            Phase::Reply => {
                let token = self.token.take().expect("unanswered clone token");
                let session = self.session.take().expect("retained session transfer");
                match effects.reply(token, Some(session), 0) {
                    Ok(()) => published = true,
                    Err(refusal) => {
                        assert_eq!(refusal.back.is_some(), refusal.error.keeps_handles());
                        self.session = refusal.back;
                        self.token = refusal.token;
                        if matches!(refusal.error, abi::Error::Unknown(_)) {
                            published = true;
                        } else {
                            self.revoke(refusal.error);
                        }
                    }
                }
            }
            Phase::ErrorReply => {
                if let Some(token) = self.token.take()
                    && let Err(refusal) = effects.reply(token, None, self.code)
                {
                    assert!(refusal.back.is_none());
                    self.token = refusal.token;
                }
                if self.token.is_none() {
                    self.phase = Phase::Rollback;
                }
            }
            Phase::Rollback => {
                if self
                    .snapshot
                    .as_mut()
                    .expect("retained snapshot")
                    .release_step(ram)
                    != Ok(false)
                {
                    return Outcome::Pending;
                }
                if self.session.is_some() {
                    let _ = effects.close(&mut self.session);
                    return Outcome::Pending;
                }
                if self.authority_index != crate::storage::NONE {
                    if effects.close_identity(self.authority_index, label).is_ok() {
                        self.authority_index = crate::storage::NONE;
                    }
                    return Outcome::Pending;
                }
                if self.token.is_none() {
                    return Outcome::Terminal;
                }
            }
        }
        if published {
            Outcome::Ready
        } else {
            Outcome::Pending
        }
    }
    /// Move the already published owner into its ordinary resident descriptor record.
    pub fn materialize(&mut self) -> Fds {
        let mut fds = self
            .snapshot
            .take()
            .expect("captured child owner")
            .materialize();
        fds.binding = self.binding;
        fds.authority_index = self.authority_index;
        fds
    }
}

/// Reserve the existing birth, Place and Clone budgets before any retained effect.
pub fn reserve<B, const N: usize>(
    births: &[Option<B>; N],
    given: &mut u64,
    places: &crate::places::Places,
    clones: &mut proto_wire::clones::Clones<N>,
    owner: u64,
) -> Result<(usize, u64), u32> {
    let full = proto_wire::Status::Kernel(abi::Error::LimitReached).code();
    let next = given.checked_add(1).filter(|&n| n < 1 << 46).ok_or(full)?;
    let free = births.iter().position(Option::is_none).ok_or(full)?;
    let label = places.issue(*given).ok_or(proto_fs::TOO_MANY_OPEN_FILES)?;
    if clones.add(label, owner).is_err() {
        places.release(label);
        return Err(full);
    }
    *given = next;
    Ok((free, label))
}
