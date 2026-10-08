// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Session authority originates in a Process Vouch or an explicit init profile.

use crate::storage::{Node, Root};
use proto_process::{Credentials, Groups, WhoReply};

/// A canonical failure stays queryable while its exact rollback owners settle.
pub fn capture_binding_failure(fds: &mut crate::Fds, code: u32) -> u32 {
    assert!(code != 0, "binding failure status");
    fds.binding_outcome = Some(code);
    code
}

/// A successful result is published only after the paid preparation is complete.
pub fn binding_reply(fds: &crate::Fds) -> Option<u32> {
    fds.binding_outcome
        .filter(|code| *code != 0 || fds.binding_preparation.is_none())
}

/// The old capability stays paid while a failed candidate's transport settles.
#[derive(Clone, Copy)]
pub struct FailedCandidate<'a> {
    pub label: u64,
    pub original: &'a Binding,
    pub original_root: Root,
    pub purpose: BindingPurpose,
    pub closing: bool,
    pub retained_failure: Option<u32>,
}

/// A captured refusal does not revoke an unchanged exact live original authority.
pub fn failed_candidate_allows(
    fds: &crate::Fds,
    label: u64,
    current: u64,
    candidate: FailedCandidate<'_>,
) -> bool {
    fds.binding_preparation.is_some()
        && !fds.closing
        && !candidate.closing
        && candidate.label == label
        && candidate.purpose == BindingPurpose::Candidate
        && *candidate.original == fds.binding
        && candidate.original_root == fds.root
        && candidate.original.root() == Some(fds.root)
        && matches!(candidate.original, Binding::Active(_) | Binding::Pending(_))
        && current != 0
        && current & proto_process::GENERATION_DEAD == 0
        && candidate.original.valid(current)
        && fds
            .binding_outcome
            .is_some_and(|code| code != 0 && candidate.retained_failure == Some(code))
}

/// Ordinary work retains its own downstream authority and ownership checks.
pub fn failed_candidate_method(method: u16) -> bool {
    use proto_fs::Method;
    matches!(
        Method::from_number(method),
        Some(
            Method::Open
                | Method::Read
                | Method::Write
                | Method::Seek
                | Method::Stat
                | Method::ReadDir
                | Method::Lookup
                | Method::SeekFrom
                | Method::InfoFd
                | Method::InfoPath
                | Method::ReadDirFd
                | Method::ReadAt
                | Method::Clone
                | Method::WriteAt
                | Method::ResolveStart
                | Method::ResolveStep
                | Method::ResolveSecond
                | Method::OpenStart
                | Method::OpenPrepare
                | Method::OpenCommit
                | Method::OpenFinish
                | Method::OpenQuery
                | Method::CaptureDescription
                | Method::CloneExact
                | Method::DataStart
                | Method::DataFeed
                | Method::DataStep
                | Method::DataCommit
                | Method::DataQuery
                | Method::DataReadResult
        )
    )
}

/// The request boundary blocks preparations before any ordinary dispatch effect.
pub fn preparation_rejects(
    method: u16,
    preparation: bool,
    can_replace_refresh: bool,
    failed_candidate: bool,
) -> bool {
    use proto_fs::Method;
    preparation
        && !(method == Method::Bind as u16 && can_replace_refresh)
        && !matches!(
            Method::from_number(method),
            Some(
                Method::Close
                    | Method::CloseExact
                    | Method::ResolveCancel
                    | Method::OpenCancel
                    | Method::DataCancel
                    | Method::DataAck
                    | Method::VerifySession
            )
        )
        && !(failed_candidate && failed_candidate_method(method))
}

/// A single paid receive advances one authentication phase.
pub type Admission = AdmissionState<()>;

pub enum AdmissionState<C> {
    Unvouched,
    Transport(C),
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

/// Captured child custody does not authenticate or refresh its ancestor.
pub fn inherited_source_phase(
    binding: Binding,
    expected_label: u64,
    actual_label: u64,
    has_preparation: bool,
    purpose: Option<BindingPurpose>,
    current_generation: u64,
    creator_generation: u64,
) -> Result<RetainedSourcePhase, u32> {
    if binding.awaits_child_identity() {
        if expected_label != actual_label {
            return Err(proto_fs::PERMISSION);
        }
        return Ok(if has_preparation {
            RetainedSourcePhase::WaitRefresh
        } else {
            RetainedSourcePhase::Ready
        });
    }
    retained_source_phase(
        expected_label,
        actual_label,
        has_preparation,
        purpose,
        current_generation,
        creator_generation,
    )
}

/// Only a canonical refusal from the genuine notary proves an invalid owner.
pub enum NotaryReply<const N: usize> {
    Wire([u8; N]),
    Denied,
    Retry,
}
impl<const N: usize> NotaryReply<N> {
    pub fn admit<C>(
        self,
        admission: &mut AdmissionState<C>,
        wire: fn([u8; N]) -> AdmissionState<C>,
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
    pub fn start<C>(&mut self, admission: &mut AdmissionState<C>, generation: u64) {
        assert!(
            !matches!(admission, AdmissionState::Transport(_)),
            "settled admission before epoch reset"
        );
        self.target = generation;
        self.audited = 0;
        *admission = AdmissionState::Unvouched;
    }
    /// A changed epoch discards the reply before another transport step.
    pub fn synchronize<C>(
        &mut self,
        admission: &mut AdmissionState<C>,
        generation: u64,
    ) -> AuditStep {
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
    pub fn step<C>(
        &mut self,
        original: Binding,
        admission: &mut AdmissionState<C>,
        generation: u64,
    ) -> AuditStep {
        let synchronized = self.synchronize(admission, generation);
        if synchronized != AuditStep::Advance {
            return synchronized;
        }
        match admission {
            AdmissionState::Wire(_) | AdmissionState::RetainedWire(_) => {
                if admission.decode().is_err() {
                    self.start(admission, generation);
                    return AuditStep::Retry;
                }
                AuditStep::Advance
            }
            AdmissionState::Vouched(who) => {
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
            AdmissionState::RetainedVouched(reply) => {
                if reply.who.generation != generation {
                    self.start(admission, generation);
                    return AuditStep::Retry;
                }
                if admission.validate_retained(original, generation).is_err() {
                    return AuditStep::Denied;
                }
                AuditStep::Advance
            }
            AdmissionState::Validated(who) => {
                if who.generation != generation || original.refreshed(who).is_err() {
                    return AuditStep::Denied;
                }
                self.audited = generation;
                AuditStep::Alive
            }
            AdmissionState::RetainedValidated(reply) => {
                if reply.who.generation != generation || original.retained_refresh(reply).is_err() {
                    return AuditStep::Denied;
                }
                self.audited = generation;
                AuditStep::Alive
            }
            AdmissionState::Unvouched | AdmissionState::Transport(_) => AuditStep::Retry,
        }
    }
}
impl<C> AdmissionState<C> {
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
#[derive(Debug, PartialEq, Eq)]
pub enum CustodyPhase {
    Ordinary,
    Hold,
    Candidate,
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
    /// Captured descriptions retain independent child custody until its genuine identity binds.
    Inherited(WhoReply),
    Cleanup,
}
impl Binding {
    /// The exact child custody advances only its own candidate or genuine revocation.
    pub fn custody_phase(&self, candidate: bool) -> CustodyPhase {
        if self.awaits_child_identity() {
            if candidate {
                CustodyPhase::Candidate
            } else {
                CustodyPhase::Hold
            }
        } else {
            CustodyPhase::Ordinary
        }
    }
    /// Captured ancestry never grants operations, including after parent epoch reuse.
    pub fn authenticate_epoch(&mut self, current: u64) -> Result<bool, u32> {
        if self.awaits_child_identity() {
            return Err(proto_fs::PERMISSION);
        }
        let who = self.snapshot_ref().ok_or(proto_fs::PERMISSION)?;
        if current == who.generation {
            return if matches!(self, Self::Handoff(_)) {
                Err(proto_fs::PERMISSION)
            } else {
                Ok(true)
            };
        }
        if current & proto_process::GENERATION_DEAD != 0 {
            *self = Self::Cleanup;
            return Err(proto_fs::PERMISSION);
        }
        Ok(false)
    }
    /// A captured ancestor supplies custody until a genuine child identity binds.
    pub fn awaits_child_identity(&self) -> bool {
        matches!(self, Self::Inherited(_))
    }

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

#[cfg(test)]
mod preparation_boundary_tests {
    use super::{failed_candidate_method, preparation_rejects};
    use proto_fs::Method;

    #[test]
    fn request_preparation_boundary_requires_exact_ordinary_recovery() {
        // The real Files fixture retries OpenStart while the refusal debt is paid.
        assert!(!preparation_rejects(
            Method::OpenStart as u16,
            true,
            false,
            true
        ));
        let ordinary = [
            1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 15, 16, 21, 22, 24, 26, 27, 28, 29, 31, 32, 34,
            35, 36, 37, 38, 39, 42,
        ];
        let cleanup = [6, 18, 23, 30, 33, 40, 41];
        for method in 0..=u16::MAX {
            assert_eq!(failed_candidate_method(method), ordinary.contains(&method));
            assert!(!preparation_rejects(method, false, false, false));
            assert_eq!(
                preparation_rejects(method, true, false, false),
                !cleanup.contains(&method)
            );
            assert_eq!(
                preparation_rejects(method, true, false, true),
                !(ordinary.contains(&method) || cleanup.contains(&method))
            );
        }
        assert!(!preparation_rejects(
            Method::OpenStart as u16,
            true,
            false,
            true
        ));
        assert!(preparation_rejects(Method::Bind as u16, true, false, true));
        assert!(!preparation_rejects(Method::Bind as u16, true, true, false));
        for method in [
            Method::BindPending,
            Method::FinishBinding,
            Method::OpenExec,
            Method::ReadInto,
        ] {
            assert!(preparation_rejects(method as u16, true, true, true));
        }
    }
}
