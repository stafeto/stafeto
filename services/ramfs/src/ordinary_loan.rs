// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Borrowed scalar journal for an ordinary request waiting for fresh authority.
use crate::{
    Fds, Ram,
    authority::{AdmissionState, Binding, BindingPurpose},
    storage::Root,
};
use proto_process::WhoReply;

/// All context is borrowed from the one paid identity row.
pub struct Lineage<'a, C> {
    pub label: u64,
    pub original: &'a Binding,
    pub original_root: Root,
    pub purpose: BindingPurpose,
    pub closing: bool,
    pub secondary_owners: bool,
    pub admission: &'a AdmissionState<C>,
}
/// Query preservation never proves a fresh generation or permission grant.
pub fn preserved_query<C>(fds: &Fds, label: u64, lineage: &Lineage<'_, C>) -> Option<u32> {
    let Binding::Active(who) = &fds.binding else {
        return None;
    };
    let Binding::Active(old) = lineage.original else {
        return None;
    };
    if usize::from(fds.authority_index) >= crate::storage::ROOTS
        || fds.closing
        || lineage.closing
        || lineage.secondary_owners
        || lineage.label != label
        || lineage.original_root != fds.root
        || fds.binding.root() != Some(fds.root)
        || old.pid != who.pid
        || old.index != who.index
        || old.image != who.image
        || old.root != who.root
        || old.loader.is_some()
        || who.loader.is_some()
    {
        return None;
    }
    let qualified = if fds.binding_preparation.is_some() {
        lineage.purpose == BindingPurpose::Refresh
            && matches!(
                lineage.admission,
                AdmissionState::Unvouched
                    | AdmissionState::Transport(_)
                    | AdmissionState::Wire(_)
                    | AdmissionState::Vouched(_)
                    | AdmissionState::Validated(_)
            )
    } else {
        match (lineage.purpose, lineage.admission) {
            (BindingPurpose::Candidate, AdmissionState::Unvouched) => {
                lineage.original == &fds.binding
            }
            (BindingPurpose::Refresh, AdmissionState::Validated(validated)) => validated == who,
            _ => false,
        }
    };
    qualified
        .then_some(fds.binding_outcome)
        .flatten()
        .filter(|code| *code != 0)
}
/// The same pure decision guards ordinary capture and the narrow quota fallback.
pub fn capture_phase<C>(
    fds: &Fds,
    label: u64,
    method: u16,
    current: u64,
    lineage: &Lineage<'_, C>,
    retained_failure: Option<u32>,
) -> Option<Phase> {
    if usize::from(fds.authority_index) >= crate::storage::ROOTS
        || !fds.claimed
        || !crate::authority::failed_candidate_method(method)
        || current == 0
        || current & proto_process::GENERATION_DEAD != 0
    {
        return None;
    }
    let Binding::Active(who) = &fds.binding else {
        return None;
    };
    if current == who.generation {
        return None;
    }
    if matches!(lineage.admission, AdmissionState::Transport(_))
        && crate::authority::failed_candidate_stale(
            fds,
            label,
            current,
            crate::authority::FailedCandidate {
                label: lineage.label,
                original: lineage.original,
                original_root: lineage.original_root,
                purpose: lineage.purpose,
                closing: lineage.closing,
                retained_failure,
            },
        )
    {
        return Some(Phase::DrainOld);
    }
    preserved_query(fds, label, lineage)?;
    Some(if fds.binding_preparation.is_some() {
        Phase::Fresh
    } else {
        Phase::BeginFresh
    })
}
pub fn begin_preserving(ram: &mut Ram<'_>, fds: &mut Fds, query: Option<u32>) -> Result<(), u32> {
    ram.begin_binding(fds)?;
    restore_query(fds, query);
    Ok(())
}
/// Return the actual phase result while preserving its independent captured query.
pub fn with_query<T>(
    fds: &mut Fds,
    query: Option<u32>,
    operation: impl FnOnce(&mut Fds) -> T,
) -> T {
    let result = operation(fds);
    restore_query(fds, query);
    result
}
pub fn restore_query(fds: &mut Fds, query: Option<u32>) {
    if let Some(code) = query {
        assert_ne!(code, 0);
        fds.binding_outcome = Some(code);
    }
}
/// Quota denial remains the result; only this exact settled lineage skips Audit fallback.
pub fn quota_deferred<C>(
    fds: &Fds,
    label: u64,
    result: Result<(), u32>,
    lineage: &Lineage<'_, C>,
) -> bool {
    result == Err(proto_fs::TOO_MANY_OPEN_FILES)
        && fds.binding_preparation.is_none()
        && preserved_query(fds, label, lineage).is_some()
}

fn live(current: u64) -> bool {
    current != 0 && current & proto_process::GENERATION_DEAD == 0
}

/// Both instance and retained-source initiators owe the same runnable wake.
pub fn refresh_started<C>(
    prepared_before: bool,
    fds: &Fds,
    label: u64,
    lineage: &Lineage<'_, C>,
) -> bool {
    !prepared_before
        && fds.binding_preparation.is_some()
        && preserved_query(fds, label, lineage).is_some()
}
/// A failed source charge rejects its destination; it cannot become WaitRefresh.
pub fn source_refresh_result(result: Result<(), u32>, valid: bool) -> Result<u32, u32> {
    if !valid {
        return Err(proto_fs::PERMISSION);
    }
    match result {
        Ok(()) | Err(proto_fs::AUTHENTICATING) => Ok(proto_fs::RESOLVING),
        Err(code) => Err(code),
    }
}

pub const TAG: u64 = 0x4f52_0000_0000_0000;
pub const MASK: u64 = 0xffff_ffff_ffff_ff00;
const _: () = assert!(core::mem::size_of::<[u64; 11]>() == 88);
const _: () = assert!(core::mem::align_of::<[u64; 11]>() == 8);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Phase {
    DrainOld = 1,
    BeginFresh,
    Fresh,
    CheckFresh,
    Replay,
    DrainFresh,
}
/// A phase borrows the paid row; only one effect method runs on a pending visit.
pub trait Effects {
    type Reply;
    fn fds(&self) -> &Fds;
    fn available(&self, loan: &Loan<'_>) -> bool;
    fn current(&self) -> u64;
    fn old_matches(&self, loan: &Loan<'_>) -> bool;
    fn old_step(&mut self);
    fn begin(&mut self, query: u32) -> Result<(), u32>;
    fn fresh_step(&mut self) -> u32;
    fn has_transport(&self) -> bool;
    fn drain_transport(&mut self);
    fn reset_fresh(&mut self);
    fn replay(&mut self) -> Self::Reply;
    fn authenticating(reply: &Self::Reply) -> bool;
    fn restore(&mut self, query: u32);
}
pub enum Progress<A> {
    Pending,
    Status(u32),
    Reply(A),
}
pub struct Loan<'a>(&'a mut [u64; 11]);
impl<'a> Loan<'a> {
    pub fn active(words: &[u64; 11]) -> bool {
        words[0] & MASK == TAG
    }
    pub fn new(words: &'a mut [u64; 11]) -> Self {
        Self(words)
    }
    pub fn begin(&mut self, fds: &Fds, label: u64, method: u16, current: u64) {
        assert_eq!(self.0[0], 0);
        let Binding::Active(who) = &fds.binding else {
            panic!("ordinary active authority")
        };
        assert!(crate::authority::failed_candidate_method(method));
        assert!(
            current != 0
                && current & proto_process::GENERATION_DEAD == 0
                && current != who.generation,
            "ordinary stale live epoch"
        );
        assert!(
            who.index < proto_process::RECORDS as u32
                && usize::from(fds.authority_index) < crate::storage::ROOTS,
            "ordinary captured indices"
        );
        assert_eq!(fds.binding.root(), Some(fds.root), "ordinary captured root");

        let failure = fds
            .binding_outcome
            .filter(|code| *code != 0)
            .expect("captured refusal");
        self.0[1] = label;
        self.0[2] = fds.root.id;
        self.0[3] = fds.root.generation;
        self.0[4] = u64::from(who.index)
            | (u64::from(fds.authority_index) << 32)
            | (u64::from(method) << 48);
        self.0[5] = u64::from(who.pid) | (u64::from(who.image) << 32);
        self.0[6] = who.generation;
        self.0[7] = current;
        self.0[8] = u64::from(failure);
        self.0[9] = u64::MAX;
        self.0[10] = 2;
        self.set_phase(Phase::DrainOld);
    }
    pub fn phase(&self) -> Phase {
        assert!(Self::active(self.0));
        assert_eq!(self.0[10] & !0x302, 0, "ordinary reserved flags");
        assert_eq!(self.0[10] & 0xff, 2, "ordinary active class");
        match self.0[0] & 0xff {
            1 => Phase::DrainOld,
            2 => Phase::BeginFresh,
            3 => Phase::Fresh,
            4 => Phase::CheckFresh,
            5 => Phase::Replay,
            6 => Phase::DrainFresh,
            _ => panic!("ordinary phase"),
        }
    }
    pub fn set_phase(&mut self, phase: Phase) {
        self.0[0] = TAG | phase as u64;
    }
    pub fn label(&self) -> u64 {
        self.0[1]
    }
    pub fn root(&self) -> Root {
        Root {
            id: self.0[2],
            generation: self.0[3],
        }
    }
    pub fn slot(&self) -> u16 {
        (self.0[4] >> 32) as u16
    }
    pub fn method(&self) -> u16 {
        (self.0[4] >> 48) as u16
    }
    pub fn old_epoch(&self) -> u64 {
        self.0[6]
    }
    pub fn target(&self) -> u64 {
        self.0[7]
    }
    pub fn target_next(&mut self, current: u64) {
        self.0[7] = current;
        self.0[10] &= !0x300;
        self.0[8] &= u64::from(u32::MAX);
    }
    pub fn refusal(&self) -> u32 {
        let code = self.0[8] as u32;
        assert_ne!(code, 0);
        code
    }
    pub fn result(&self) -> Option<u32> {
        (self.0[10] & 0x200 != 0).then_some((self.0[8] >> 32) as u32)
    }
    pub fn set_result(&mut self, code: u32) {
        self.0[8] = u64::from(self.refusal()) | (u64::from(code) << 32);
        self.0[10] |= 0x200;
    }
    pub fn same_who(&self, who: &WhoReply) -> bool {
        who.index == self.0[4] as u32
            && who.pid == self.0[5] as u32
            && who.image == (self.0[5] >> 32) as u32
            && u64::from(who.root.pid) == self.0[2]
            && u64::from(who.root.generation) == self.0[3]
    }
    pub fn matches(&self, fds: &Fds, label: u64, method: u16) -> bool {
        !fds.closing
            && label == self.label()
            && method == self.method()
            && fds.authority_index == self.slot()
            && fds.root == self.root()
            && matches!(&fds.binding, Binding::Active(who) if self.same_who(who))
    }
    pub fn fresh(&self, fds: &Fds, current: u64) -> bool {
        current != 0
            && current & proto_process::GENERATION_DEAD == 0
            && current == self.target()
            && matches!(&fds.binding, Binding::Active(who) if self.same_who(who) && who.generation == self.target())
    }
    /// The selector is CPU-only. A visit executes at most one adapter effect.
    pub fn step<E: Effects>(&mut self, effects: &mut E) -> Progress<E::Reply> {
        let phase = self.phase();
        if phase == Phase::CheckFresh
            && let Some(code) = self.result()
            && code != 0
        {
            return self.terminal(code);
        }
        if !effects.available(self) {
            return self.terminal(proto_fs::PERMISSION);
        }
        let current = effects.current();
        let query = self.refusal();
        match phase {
            Phase::DrainOld => {
                if !effects.old_matches(self) {
                    return self.terminal(proto_fs::PERMISSION);
                }
                if effects.fds().binding_preparation.is_none() {
                    self.set_phase(Phase::BeginFresh);
                } else {
                    effects.old_step();
                    effects.restore(query);
                }
            }
            Phase::BeginFresh => {
                if !live(current) {
                    return self.terminal(proto_fs::PERMISSION);
                }
                assert!(
                    effects.fds().binding_preparation.is_none() && !effects.has_transport(),
                    "ordinary old debt settled"
                );
                if let Err(code) = effects.begin(query) {
                    return self.terminal(code);
                }
                self.target_next(current);
                self.set_phase(Phase::Fresh);
            }
            Phase::Fresh if !live(current) || current != self.target() => {
                self.set_phase(Phase::DrainFresh)
            }
            Phase::Fresh => {
                let code = effects.fresh_step();
                effects.restore(query);
                if code != proto_fs::RESOLVING {
                    self.set_result(code);
                    self.set_phase(Phase::CheckFresh);
                }
            }
            Phase::CheckFresh => {
                assert_eq!(self.result(), Some(0), "ordinary fresh result");
                if self.fresh(effects.fds(), current) {
                    self.set_phase(Phase::Replay);
                } else if !live(current) {
                    return self.terminal(proto_fs::PERMISSION);
                } else {
                    self.set_phase(Phase::DrainFresh);
                }
            }
            Phase::DrainFresh => {
                if effects.has_transport() {
                    effects.drain_transport();
                    effects.restore(query);
                } else if !live(current) {
                    return self.terminal(proto_fs::PERMISSION);
                } else if effects.fds().binding_preparation.is_some() {
                    effects.reset_fresh();
                    self.target_next(current);
                    self.set_phase(Phase::Fresh);
                } else {
                    self.set_phase(Phase::BeginFresh);
                }
            }
            Phase::Replay => {
                if !self.fresh(effects.fds(), current) {
                    self.set_phase(Phase::DrainFresh);
                } else {
                    let reply = effects.replay();
                    effects.restore(query);
                    if E::authenticating(&reply) {
                        self.target_next(effects.current());
                        self.set_phase(if effects.fds().binding_preparation.is_some() {
                            Phase::Fresh
                        } else {
                            Phase::BeginFresh
                        });
                    } else {
                        self.finish();
                        return Progress::Reply(reply);
                    }
                }
            }
        }
        Progress::Pending
    }
    fn terminal<A>(&mut self, code: u32) -> Progress<A> {
        self.finish();
        Progress::Status(code)
    }
    pub fn finish(&mut self) {
        self.0.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ram, authority::binding_reply};
    fn who() -> WhoReply {
        WhoReply {
            pid: 300,
            credentials: proto_process::Credentials::ROOT,
            generation: 7,
            loader: None,
            index: 44,
            ctty: None,
            image: 1,
            groups: proto_process::Groups::EMPTY,
            limits: proto_process::ResourceLimits::initial(2 * 1024 * 1024),
            root: proto_process::ExpenditureRoot {
                pid: 300,
                generation: 1,
            },
        }
    }
    #[test]
    fn paid_old_preparation_settles_before_fresh_authority_and_cached_refusal_survives() {
        let old = who();
        let mut ram = Ram::default();
        let mut fds = Fds {
            binding: Binding::Active(old),
            root: Binding::Active(old).root().unwrap(),
            authority_index: 3,
            claimed: true,
            ..Fds::default()
        };
        let reservation = ram
            .storage
            .reserve(
                fds.root,
                crate::storage::ROOT,
                b"private",
                (crate::REG, 0o600, 0, 0),
            )
            .unwrap();
        let file = ram.storage.commit(reservation).unwrap();
        let identity = fds.binding.identity(false).unwrap();
        let fd = ram
            .open_token(&mut fds, file, proto_fs::READ_ONLY, identity)
            .unwrap();
        ram.close(&mut fds, fd).unwrap();
        ram.begin_binding(&mut fds).unwrap();
        fds.binding_outcome = Some(proto_fs::PERMISSION);
        let mut words = [0; 11];
        let mut loan = Loan::new(&mut words);
        loan.begin(&fds, 81, proto_fs::Method::OpenStart as u16, 8);
        assert_eq!(loan.phase(), Phase::DrainOld);
        assert_eq!(loan.old_epoch(), 7);
        assert!(!loan.fresh(&fds, 8));
        assert!(ram.begin_binding(&mut fds).is_err());
        assert_eq!(binding_reply(&fds), Some(proto_fs::PERMISSION));
        ram.complete_binding(&mut fds, proto_fs::PERMISSION);
        loan.set_phase(Phase::BeginFresh);
        ram.begin_binding(&mut fds).unwrap();
        fds.binding_outcome = Some(loan.refusal());
        loan.target_next(8);
        loan.set_phase(Phase::Fresh);
        let mut fresh = old;
        fresh.generation = 8;
        fresh.credentials.euid = 65533;
        fds.binding = fds.binding.refreshed(&fresh).unwrap();
        ram.complete_binding(&mut fds, 0);
        fds.binding_outcome = Some(loan.refusal());
        loan.set_result(0);
        loan.set_phase(Phase::CheckFresh);
        assert!(loan.fresh(&fds, 8));
        assert_eq!(loan.old_epoch(), 7);
        assert_eq!(loan.result(), Some(0));
        assert_eq!(binding_reply(&fds), Some(proto_fs::PERMISSION));
        assert_eq!(fds.binding.identity(false).unwrap().uid, 65533);
        let identity = fds.binding.identity(false).unwrap();
        assert_eq!(
            ram.open_token(&mut fds, file, proto_fs::READ_ONLY, identity),
            Err(proto_fs::ACCESS_DENIED)
        );

        for epoch in [0, 7, 9, proto_process::GENERATION_DEAD | 8] {
            assert!(!loan.fresh(&fds, epoch));
        }
        loan.set_phase(Phase::Replay);
        assert!(loan.matches(&fds, 81, proto_fs::Method::OpenStart as u16));
        assert!(!loan.matches(&fds, 82, proto_fs::Method::OpenStart as u16));
        assert!(!loan.matches(&fds, 81, proto_fs::Method::ReadInto as u16));
        fds.authority_index = 4;
        assert!(!loan.matches(&fds, 81, proto_fs::Method::OpenStart as u16));
        fds.authority_index = 3;
        fds.root.generation += 1;
        assert!(!loan.matches(&fds, 81, proto_fs::Method::OpenStart as u16));
        loan.finish();
        assert!(words.iter().all(|word| *word == 0));
        assert!(fds.binding_preparation.is_none());
        fresh.generation = 9;
        fresh.credentials.euid = 0;
        fds.binding = fds.binding.refreshed(&fresh).unwrap();
        let identity = fds.binding.identity(false).unwrap();
        let fd = ram
            .open_token(&mut fds, file, proto_fs::READ_ONLY, identity)
            .unwrap();
        ram.close(&mut fds, fd).unwrap();
        assert_eq!(binding_reply(&fds), Some(proto_fs::PERMISSION));
    }
}

#[cfg(test)]
mod engine_tests;
