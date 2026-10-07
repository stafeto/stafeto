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
    Audit,
}

/// A retained source advances its own refresh through maintenance.
#[derive(Debug, PartialEq, Eq)]
pub enum RetainedSourcePhase {
    WaitRefresh,
    Authenticate,
    Ready,
}
impl RetainedSourcePhase {
    /// Waiting destinations let maintenance reach the retained source.
    pub fn progresses(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// A reused label or an unrelated preparation cannot enter the refresh wait.
pub fn retained_source_phase(
    expected_label: u64,
    actual_label: u64,
    has_preparation: bool,
    purpose: Option<BindingPurpose>,
    current_generation: u64,
    creator_generation: u64,
) -> Result<RetainedSourcePhase, u32> {
    if expected_label != actual_label {
        return Err(proto_fs::PERMISSION);
    }
    if has_preparation {
        return if purpose == Some(BindingPurpose::Refresh) {
            Ok(RetainedSourcePhase::WaitRefresh)
        } else {
            Err(proto_fs::PERMISSION)
        };
    }
    if current_generation != creator_generation {
        Ok(RetainedSourcePhase::Authenticate)
    } else {
        Ok(RetainedSourcePhase::Ready)
    }
}

/// Only a canonical refusal from the genuine notary proves an invalid owner.
pub enum NotaryReply<const N: usize> {
    Wire([u8; N]),
    Denied,
    Retry,
}
impl<const N: usize> NotaryReply<N> {
    pub fn admit(
        self,
        admission: &mut Admission,
        wire: fn([u8; N]) -> Admission,
    ) -> Result<bool, u32> {
        match self {
            Self::Wire(bytes) => {
                *admission = wire(bytes);
                Ok(true)
            }
            Self::Denied => Err(proto_fs::PERMISSION),
            Self::Retry => Ok(false),
        }
    }
    pub fn read(bytes: &[u8], handles_empty: bool) -> Self {
        if !handles_empty {
            return Self::Retry;
        }
        if bytes == proto_wire::reply(proto_wire::Status::Unknown(proto_process::PERMISSION)) {
            return Self::Denied;
        }
        match bytes.try_into() {
            Ok(wire) => Self::Wire(wire),
            Err(_) => Self::Retry,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct CleanupAudit {
    target: u64,
    audited: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum AuditStep {
    Advance,
    Retry,
    Alive,
    Denied,
}
impl CleanupAudit {
    pub fn reset(&mut self) {
        *self = Self::default();
    }
    pub fn cached(&self, generation: u64) -> bool {
        generation != 0 && generation == self.audited
    }
    pub fn generations(&self) -> (u64, u64) {
        (self.target, self.audited)
    }
    pub fn start(&mut self, admission: &mut Admission, generation: u64) {
        self.target = generation;
        self.audited = 0;
        *admission = Admission::Unvouched;
    }
    /// A changed epoch discards the reply before another transport step.
    pub fn synchronize(&mut self, admission: &mut Admission, generation: u64) -> AuditStep {
        if generation == 0 || generation & proto_process::GENERATION_DEAD != 0 {
            return AuditStep::Denied;
        }
        if self.target != generation {
            self.start(admission, generation);
            return AuditStep::Retry;
        }
        AuditStep::Advance
    }
    /// Each call decodes, validates, or commits one read-only cleanup phase.
    pub fn step(
        &mut self,
        original: Binding,
        admission: &mut Admission,
        generation: u64,
    ) -> AuditStep {
        let synchronized = self.synchronize(admission, generation);
        if synchronized != AuditStep::Advance {
            return synchronized;
        }
        match admission {
            Admission::Wire(_) | Admission::RetainedWire(_) => {
                if admission.decode().is_err() {
                    self.start(admission, generation);
                    return AuditStep::Retry;
                }
                AuditStep::Advance
            }
            Admission::Vouched(who) => {
                if who.generation != generation {
                    self.start(admission, generation);
                    return AuditStep::Retry;
                }
                if admission
                    .validate(original, BindingPurpose::Audit, false, generation)
                    .is_err()
                {
                    return AuditStep::Denied;
                }
                AuditStep::Advance
            }
            Admission::RetainedVouched(reply) => {
                if reply.who.generation != generation {
                    self.start(admission, generation);
                    return AuditStep::Retry;
                }
                if admission.validate_retained(original, generation).is_err() {
                    return AuditStep::Denied;
                }
                AuditStep::Advance
            }
            Admission::Validated(who) => {
                if who.generation != generation || original.refreshed(who).is_err() {
                    return AuditStep::Denied;
                }
                self.audited = generation;
                AuditStep::Alive
            }
            Admission::RetainedValidated(reply) => {
                if reply.who.generation != generation || original.retained_refresh(reply).is_err() {
                    return AuditStep::Denied;
                }
                self.audited = generation;
                AuditStep::Alive
            }
            Admission::Unvouched => AuditStep::Retry,
        }
    }
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
            BindingPurpose::Refresh | BindingPurpose::Audit => {
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

#[cfg(test)]
mod retained_source_tests {
    use super::*;

    #[test]
    fn retained_wait_requires_the_exact_birth_and_refresh_authority() {
        for purpose in [
            None,
            Some(BindingPurpose::Candidate),
            Some(BindingPurpose::Audit),
        ] {
            assert_eq!(
                retained_source_phase(19, 19, true, purpose, 7, 7),
                Err(proto_fs::PERMISSION)
            );
        }
        assert_eq!(
            retained_source_phase(19, 20, true, Some(BindingPurpose::Refresh), 7, 7),
            Err(proto_fs::PERMISSION)
        );
        assert_eq!(
            retained_source_phase(19, 19, true, Some(BindingPurpose::Refresh), 7, 7),
            Ok(RetainedSourcePhase::WaitRefresh)
        );
    }

    #[test]
    fn a_changed_generation_reauthenticates_before_transfer() {
        assert_eq!(
            retained_source_phase(19, 19, false, None, 8, 7),
            Ok(RetainedSourcePhase::Authenticate)
        );
        assert_eq!(
            retained_source_phase(19, 19, false, None, proto_process::GENERATION_DEAD, 7),
            Ok(RetainedSourcePhase::Authenticate)
        );
        assert_eq!(
            retained_source_phase(19, 19, false, None, 7, 7),
            Ok(RetainedSourcePhase::Ready)
        );
    }
}
