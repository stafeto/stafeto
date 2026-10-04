// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Session authority originates in a Process Vouch or an explicit init profile.

use crate::storage::{Node, Root};
use proto_process::{Credentials, Groups, WhoReply};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Binding {
    #[default]
    Unbound,
    Boot,
    Active(WhoReply),
    Pending(WhoReply),
    /// Captured descriptions await a child identity, while the creator still owns cleanup.
    Inherited(WhoReply),
    Cleanup,
}
impl Binding {
    pub fn bind(&mut self, vouched: Option<WhoReply>, pending: bool) -> Result<WhoReply, u32> {
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
        if let Self::Active(old) | Self::Pending(old) = *self {
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
        }
        if let Self::Inherited(old) = *self
            && old.root != who.root
        {
            return Err(proto_fs::PERMISSION);
        }
        if matches!(self, Self::Cleanup) {
            return Err(proto_fs::PERMISSION);
        }
        *self = if pending {
            Self::Pending(who)
        } else {
            Self::Active(who)
        };
        Ok(who)
    }
    pub fn snapshot(&self) -> Option<WhoReply> {
        match *self {
            Self::Active(w) | Self::Pending(w) | Self::Inherited(w) => Some(w),
            _ => None,
        }
    }
    pub fn valid(&self, generation: u64) -> bool {
        matches!(*self, Self::Boot)
            || (!matches!(*self, Self::Inherited(_))
                && self
                    .snapshot()
                    .is_some_and(|who| who.generation == generation && generation != 0))
    }
    pub fn root(&self) -> Option<Root> {
        self.snapshot().map(|who| Root {
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
        if matches!(self, Self::Inherited(_)) {
            return Err(proto_fs::PERMISSION);
        }
        let who = self.snapshot().ok_or(proto_fs::PERMISSION)?;
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
