// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Session authority originates in a Process Vouch or an explicit init profile.

use crate::storage::{Node, Root};
use proto_process::{Credentials, Groups, WhoReply};

/// A single paid receive advances one authentication phase.
pub enum Admission {
    Unvouched,
    Wire([u8; 252]),
    RetainedWire([u8; 260]),
    Vouched(WhoReply),
    RetainedVouched(proto_process::RetainedLoaderReply),
    Validated(WhoReply),
    RetainedValidated(proto_process::RetainedLoaderReply),
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BindingPurpose {
    Candidate,
    Refresh,
}
impl Admission {
    pub fn decode(&mut self) -> Result<(), u32> {
        if let Self::RetainedWire(wire) = self {
            let retained =
                proto_process::RetainedLoaderReply::read(wire).map_err(|_| proto_fs::PERMISSION)?;
            *self = Self::RetainedVouched(retained);
            return Ok(());
        }
        let Self::Wire(wire) = self else {
            return Err(proto_fs::PERMISSION);
        };
        let who = WhoReply::read(wire).map_err(|_| proto_fs::PERMISSION)?;
        *self = Self::Vouched(who);
        Ok(())
    }
    pub fn validate_retained(&mut self, original: Binding, generation: u64) -> Result<(), u32> {
        let Self::RetainedVouched(retained) = self else {
            return Err(proto_fs::PERMISSION);
        };
        if generation & proto_process::GENERATION_DEAD != 0 {
            return Err(proto_fs::PERMISSION);
        }
        if generation != retained.who.generation {
            *self = Self::Unvouched;
            return Ok(());
        }
        original.retained_refresh(retained)?;
        *self = Self::RetainedValidated(*retained);
        Ok(())
    }
    /// A stale reply restarts transport; validation never publishes a binding.
    pub fn validate(
        &mut self,
        original: Binding,
        purpose: BindingPurpose,
        pending: bool,
        generation: u64,
    ) -> Result<(), u32> {
        let Self::Vouched(who) = self else {
            return Err(proto_fs::PERMISSION);
        };
        if generation & proto_process::GENERATION_DEAD != 0 {
            return Err(proto_fs::PERMISSION);
        }
        if generation != who.generation {
            *self = Self::Unvouched;
            return Ok(());
        }
        match purpose {
            BindingPurpose::Refresh => {
                original.refreshed(who)?;
            }
            BindingPurpose::Candidate => {
                let mut bound = original;
                bound.bind_ref(Some(who), pending)?;
            }
        }
        *self = Self::Validated(*who);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub generation: u64,
    pub image: u32,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Binding {
    #[default]
    Unbound,
    Boot,
    Active(WhoReply),
    Pending(WhoReply),
    /// The exact successful target awaits its genuine startup identity.
    Handoff(WhoReply),
    /// Captured descriptions await a child identity, while the creator still owns cleanup.
    Inherited(WhoReply),
    Cleanup,
}
impl Binding {
    pub fn retained_refresh(
        self,
        retained: &proto_process::RetainedLoaderReply,
    ) -> Result<Self, u32> {
        let old = match self {
            Self::Pending(who) | Self::Handoff(who) => who,
            _ => return Err(proto_fs::PERMISSION),
        };
        let loader = old.loader.ok_or(proto_fs::PERMISSION)?;
        let expected = proto_process::RetainedLoader {
            pid: old.pid,
            index: old.index,
            image: old.image,
            ticket: loader.ticket,
            root: old.root,
        };
        if !expected.matches(&retained.who) {
            return Err(proto_fs::PERMISSION);
        }
        match retained.state {
            proto_process::RetainedLoaderState::Loading if matches!(self, Self::Pending(_)) => {
                self.refreshed(&retained.who)
            }
            proto_process::RetainedLoaderState::Handoff => Ok(Self::Handoff(retained.who)),
            _ => Err(proto_fs::PERMISSION),
        }
    }
    /// Refresh preserves the exact authority class and its captured owner.
    pub fn refreshed(self, who: &WhoReply) -> Result<Self, u32> {
        let old = self.snapshot_ref().ok_or(proto_fs::PERMISSION)?;
        if old.pid != who.pid
            || old.index != who.index
            || old.image != who.image
            || old.root != who.root
            || old.loader != who.loader
        {
            return Err(proto_fs::PERMISSION);
        }
        let mut checked = self;
        checked.bind_ref(Some(who), matches!(self, Self::Pending(_)))?;
        Ok(match self {
            Self::Active(_) => Self::Active(*who),
            Self::Pending(_) => Self::Pending(*who),
            Self::Inherited(_) => Self::Inherited(*who),
            _ => return Err(proto_fs::PERMISSION),
        })
    }
    pub fn bind(&mut self, vouched: Option<WhoReply>, pending: bool) -> Result<(), u32> {
        self.bind_ref(vouched.as_ref(), pending)
    }
    pub fn bind_ref(&mut self, vouched: Option<&WhoReply>, pending: bool) -> Result<(), u32> {
        let who = vouched.ok_or(proto_fs::PERMISSION)?;
        if who.generation == 0
            || who.generation & proto_process::GENERATION_DEAD != 0
            || who.root.pid == 0
            || who.root.generation == 0
            || who
                .limits
                .values
                .iter()
                .any(|l| l.soft > l.hard || l.hard == u64::MAX)
            || who.image == 0
            || who.index as usize >= proto_process::RECORDS
            || !who.groups.valid()
        {
            return Err(proto_fs::PERMISSION);
        }
        if pending != who.loader.is_some() {
            return Err(proto_fs::PERMISSION);
        }
        if let Self::Active(old) | Self::Pending(old) | Self::Handoff(old) = self {
            if old.pid != who.pid
                || old.index != who.index
                || old.image != who.image
                || old.root != who.root
            {
                return Err(proto_fs::PERMISSION);
            }
            if pending && old.loader != who.loader {
                return Err(proto_fs::PERMISSION);
            }
            if pending && matches!(self, Self::Handoff(_)) {
                return Err(proto_fs::PERMISSION);
            }
        }
        if let Self::Inherited(old) = self
            && old.root != who.root
        {
            return Err(proto_fs::PERMISSION);
        }
        if matches!(self, Self::Cleanup) {
            return Err(proto_fs::PERMISSION);
        }
        *self = if pending {
            Self::Pending(*who)
        } else {
            Self::Active(*who)
        };
        Ok(())
    }
    pub fn snapshot(&self) -> Option<WhoReply> {
        self.snapshot_ref().copied()
    }
    pub fn snapshot_ref(&self) -> Option<&WhoReply> {
        match self {
            Self::Active(w) | Self::Pending(w) | Self::Inherited(w) | Self::Handoff(w) => Some(w),
            _ => None,
        }
    }
    pub fn stamp(&self) -> Option<Stamp> {
        self.snapshot_ref().map(|who| Stamp {
            generation: who.generation,
            image: who.image,
        })
    }
    pub fn valid(&self, generation: u64) -> bool {
        matches!(*self, Self::Boot)
            || (!matches!(*self, Self::Inherited(_) | Self::Handoff(_))
                && self
                    .snapshot_ref()
                    .is_some_and(|who| who.generation == generation && generation != 0))
    }
    pub fn root(&self) -> Option<Root> {
        self.snapshot_ref().map(|who| Root {
            id: u64::from(who.root.pid),
            generation: u64::from(who.root.generation),
        })
    }
    pub fn identity(&self, real: bool) -> Result<Identity, u32> {
        if matches!(self, Self::Boot) {
            return Ok(Identity {
                uid: 0,
                gid: 0,
                groups: Groups::EMPTY,
            });
        }
        if matches!(self, Self::Inherited(_) | Self::Handoff(_)) {
            return Err(proto_fs::PERMISSION);
        }
        let who = self.snapshot_ref().ok_or(proto_fs::PERMISSION)?;
        Ok(Identity::of(who.credentials, who.groups, real))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    pub gid: u32,
    pub groups: Groups,
}
impl Identity {
    pub fn of(ids: Credentials, groups: Groups, real: bool) -> Self {
        Self {
            uid: if real { ids.uid } else { ids.euid },
            gid: if real { ids.gid } else { ids.egid },
            groups,
        }
    }
    pub fn permits(self, node: &Node, bits: u32) -> bool {
        if self.uid == 0 {
            return bits & 1 == 0 || node.kind == crate::DIR || node.mode & 0o111 != 0;
        }
        let class = if self.uid == node.uid {
            node.mode >> 6
        } else if self.gid == node.gid || self.groups.contains(node.gid) {
            node.mode >> 3
        } else {
            node.mode
        };
        class & bits == bits
    }
    pub fn sticky(self, parent: &Node, victim: &Node) -> bool {
        parent.mode & 0o1000 == 0
            || self.uid == 0
            || self.uid == parent.uid
            || self.uid == victim.uid
    }
    pub fn creation(self, parent: &Node, kind: u32, mode: u32, umask: u32) -> (u32, u32, u32, u32) {
        let gid = if parent.mode & 0o2000 != 0 {
            parent.gid
        } else {
            self.gid
        };
        let mode = (mode & 0o7777 & !(umask & 0o777))
            | if kind == crate::DIR {
                parent.mode & 0o2000
            } else {
                0
            };
        (kind, mode, self.uid, gid)
    }
}
