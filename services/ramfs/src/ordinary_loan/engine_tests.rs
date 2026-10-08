// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;
use crate::{
    authority::binding_reply,
    notary_transport::{self as transport, Owners, State, Transport},
};
use std::{cell::RefCell, collections::VecDeque, vec, vec::Vec};

struct Cap(Option<u64>);
impl Cap {
    fn new(id: u64) -> Self {
        Self(Some(id))
    }
    fn consume(mut self) -> u64 {
        self.0.take().unwrap()
    }
}
impl Drop for Cap {
    fn drop(&mut self) {
        assert!(self.0.is_none(), "implicit cap disposal");
    }
}
std::thread_local! {
    static CALLS: RefCell<Vec<(&'static str,u64)>> = const { RefCell::new(Vec::new()) };
    static FAIL_CLOSE: RefCell<usize> = const { RefCell::new(0) };
}
struct Owned;
impl Owners for Owned {
    type Copy = Option<Cap>;
    type Back = Vec<Cap>;
    type Reply = Vec<Option<Cap>>;
    type Held = Cap;
    fn copy_live(owner: &Option<Cap>) -> bool {
        owner.is_some()
    }
    fn close_copy(owner: &mut Option<Cap>) {
        Self::close_held(owner);
    }
    fn pop_back(owners: &mut Vec<Cap>) -> Option<Cap> {
        owners.pop()
    }
    fn reply_len(owners: &Vec<Option<Cap>>) -> usize {
        owners.len()
    }
    fn take_reply(owners: &mut Vec<Option<Cap>>, index: usize) -> Option<Cap> {
        owners[index].take()
    }
    fn close_held(owner: &mut Option<Cap>) {
        let id = owner.as_ref().unwrap().0.unwrap();
        CALLS.with(|calls| calls.borrow_mut().push(("Close", id)));
        let failed = FAIL_CLOSE.with(|n| {
            let mut n = n.borrow_mut();
            let failed = *n != 0;
            *n = n.saturating_sub(1);
            failed
        });
        if !failed {
            assert_eq!(owner.take().unwrap().consume(), id);
        }
    }
}
type Admission = AdmissionState<Transport<Owned>>;
#[derive(Clone, Copy)]
enum ReplyMode {
    Wire,
    Back,
    Consumed,
    ExtraCaps,
}
struct Kernel {
    who: WhoReply,
    modes: VecDeque<ReplyMode>,
}
impl transport::Effects<Owned> for Kernel {
    fn duplicate(&mut self) -> Option<Option<Cap>> {
        CALLS.with(|calls| calls.borrow_mut().push(("Duplicate", 71)));
        Some(Some(Cap::new(90)))
    }
    fn send(&mut self, owner: &mut Option<Cap>) -> transport::Send<Vec<Cap>, Vec<Option<Cap>>> {
        let cap = owner.take().unwrap();
        CALLS.with(|calls| calls.borrow_mut().push(("Send", cap.0.unwrap())));
        match self.modes.pop_front().unwrap_or(ReplyMode::Wire) {
            ReplyMode::Back => transport::Send::Back(vec![cap]),
            ReplyMode::Consumed => {
                cap.consume();
                transport::Send::Retry
            }
            ReplyMode::ExtraCaps => {
                cap.consume();
                transport::Send::Reply(vec![Some(Cap::new(500)), Some(Cap::new(501))])
            }
            ReplyMode::Wire => {
                cap.consume();
                let mut writer = proto_wire::Writer::new();
                self.who.write(&mut writer).unwrap();
                transport::Send::Wire(writer.as_bytes().try_into().unwrap())
            }
        }
    }
}
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
struct Fixture {
    ram: Ram<'static>,
    fds: Fds,
    original: Binding,
    purpose: BindingPurpose,
    admission: Admission,
    previous: Option<Cap>,
    offered: Option<Cap>,
    primary: Option<Cap>,
    current: u64,
    uid: u32,
    file: crate::storage::Token,
    charges: usize,
    ordinary: usize,
    modes: VecDeque<ReplyMode>,
    fresh_error: Option<u32>,
    replay_race: bool,
    other: Option<Cap>,
    fair: usize,
}
impl Fixture {
    fn failed(phase: usize) -> Self {
        CALLS.with(|calls| calls.borrow_mut().clear());
        FAIL_CLOSE.with(|n| *n.borrow_mut() = 0);
        let original = Binding::Active(who());
        let root = original.root().unwrap();
        let mut ram = Ram::default();
        let mut fds = Fds {
            binding: original,
            root,
            authority_index: 3,
            claimed: true,
            ..Fds::default()
        };
        let r = ram
            .storage
            .reserve(
                root,
                crate::storage::ROOT,
                b"private",
                (crate::REG, 0o600, 0, 0),
            )
            .unwrap();
        let file = ram.storage.commit(r).unwrap();
        ram.begin_binding(&mut fds).unwrap();
        fds.binding_outcome = Some(proto_fs::PERMISSION);
        let state = match phase {
            0 => State::Copy {
                owner: Some(Cap::new(91)),
                outcome: proto_fs::PERMISSION,
            },
            1 => State::Back {
                owners: vec![Cap::new(91)],
                held: None,
                outcome: proto_fs::PERMISSION,
            },
            2 => State::Reply {
                owners: vec![Some(Cap::new(91))],
                held: None,
                cursor: 0,
                outcome: proto_fs::PERMISSION,
            },
            _ => State::Rollback {
                rejected: Some(Cap::new(72)),
                outcome: proto_fs::PERMISSION,
            },
        };
        Self {
            ram,
            fds,
            original,
            purpose: BindingPurpose::Candidate,
            admission: Admission::Transport(Transport {
                epoch: if phase == 3 { 0 } else { 7 },
                state,
            }),
            previous: (phase != 3).then(|| Cap::new(71)),
            offered: None,
            primary: Some(Cap::new(if phase == 3 { 71 } else { 72 })),
            current: 8,
            uid: 65533,
            file,
            charges: 1,
            ordinary: 0,
            modes: VecDeque::new(),
            fresh_error: None,
            replay_race: false,
            other: Some(Cap::new(600)),
            fair: 0,
        }
    }
    fn lineage(&self) -> Lineage<'_, Transport<Owned>> {
        Lineage {
            label: 81,
            original: &self.original,
            original_root: self.fds.root,
            purpose: self.purpose,
            closing: false,
            secondary_owners: self.previous.is_some() || self.offered.is_some(),
            admission: &self.admission,
        }
    }
    fn capture(&self, words: &mut [u64; 11]) {
        let failure = if let Admission::Transport(t) = &self.admission {
            t.failed_original_outcome(self.previous.is_some())
        } else {
            None
        };
        let phase = capture_phase(
            &self.fds,
            81,
            proto_fs::Method::OpenStart as u16,
            self.current,
            &self.lineage(),
            failure,
        )
        .unwrap();
        let mut loan = Loan::new(words);
        loan.begin(
            &self.fds,
            81,
            proto_fs::Method::OpenStart as u16,
            self.current,
        );
        loan.set_phase(phase);
        if phase == Phase::Fresh
            && let Admission::Transport(t) = &self.admission
            && t.epoch != self.current
        {
            loan.target_next(t.epoch);
            loan.set_phase(Phase::DrainFresh);
        }
    }
    fn finish_transport(&mut self) -> Option<u32> {
        let Admission::Transport(t) = &mut self.admission else {
            return None;
        };
        match transport::finish(t, &mut self.offered, &mut self.previous)? {
            transport::Finish::Pending => Some(proto_fs::RESOLVING),
            transport::Finish::Rollback(code) => {
                self.fds.binding = self.original;
                self.admission = Admission::Unvouched;
                self.ram.complete_binding(&mut self.fds, code);
                Some(code)
            }
            transport::Finish::Commit => {
                self.admission = Admission::Unvouched;
                self.ram.complete_binding(&mut self.fds, 0);
                Some(0)
            }
        }
    }
    fn drain(&mut self) {
        let Admission::Transport(t) = &mut self.admission else {
            panic!()
        };
        if let Some(Some(code)) = t.drain() {
            self.admission = Admission::Unvouched;
            if code != 0 {
                if let Some(previous) = self.previous.take() {
                    let rejected = self.primary.replace(previous);
                    self.admission = Admission::Transport(Transport {
                        epoch: 0,
                        state: State::Rollback {
                            rejected,
                            outcome: code,
                        },
                    });
                } else {
                    self.fds.closing = true;
                }
            }
        }
    }
    fn settle_old(&mut self) {
        for _ in 0..16 {
            if self.fds.binding_preparation.is_none() {
                return;
            }
            let before = CALLS.with(|c| c.borrow().len());
            self.old_step();
            self.restore(proto_fs::PERMISSION);
            assert!(CALLS.with(|c| c.borrow().len()) - before <= 1);
        }
        panic!("old preparation stranded");
    }
    fn background_start(&mut self) {
        let query = preserved_query(&self.fds, 81, &self.lineage()).unwrap();
        self.begin(query).unwrap();
        assert!(refresh_started(false, &self.fds, 81, &self.lineage()));
        assert!(!refresh_started(true, &self.fds, 81, &self.lineage()));
        let mut wake = false;
        let mut cursor = crate::maintenance::Cursor::default();
        cursor.wake_failure(&mut wake, 320);
        assert!(wake);
        assert_eq!(cursor.remaining, 320);
    }
    fn run(&mut self, words: &mut [u64; 11]) -> u32 {
        let query = self.fds.binding_outcome.unwrap();
        let ordinary_before = self.ordinary;
        for _ in 0..128 {
            let before = CALLS.with(|c| c.borrow().len());
            let progress = Loan::new(words).step(self);
            assert!(
                self.ordinary <= ordinary_before + 1,
                "repeated ordinary effect"
            );
            assert!(
                CALLS.with(|c| c.borrow().len()) - before <= 1,
                "combined visit effects"
            );
            assert_eq!(binding_reply(&self.fds), Some(query));
            match progress {
                Progress::Pending => {
                    self.fair += 1;
                    let before = CALLS.with(|c| c.borrow().len());
                    if self.other.is_some() {
                        Owned::close_copy(&mut self.other);
                    }
                    assert!(CALLS.with(|c| c.borrow().len()) - before <= 1);
                }
                Progress::Status(code) | Progress::Reply(code) => {
                    assert!(words.iter().all(|w| *w == 0));
                    return code;
                }
            }
        }
        panic!("ordinary request stranded");
    }
}
impl Effects for Fixture {
    type Reply = u32;
    fn fds(&self) -> &Fds {
        &self.fds
    }
    fn available(&self, loan: &Loan<'_>) -> bool {
        loan.matches(&self.fds, 81, proto_fs::Method::OpenStart as u16)
            && self
                .original
                .snapshot_ref()
                .is_some_and(|w| loan.same_who(w))
    }
    fn current(&self) -> u64 {
        self.current
    }
    fn old_matches(&self, loan: &Loan<'_>) -> bool {
        self.purpose == BindingPurpose::Candidate
            && self.original == self.fds.binding
            && self.original.snapshot_ref().unwrap().generation == loan.old_epoch()
    }
    fn old_step(&mut self) {
        if self.finish_transport().is_none() {
            self.drain();
        }
    }
    fn begin(&mut self, query: u32) -> Result<(), u32> {
        begin_preserving(&mut self.ram, &mut self.fds, Some(query))?;
        self.charges += 1;
        self.reset_fresh();
        Ok(())
    }
    fn fresh_step(&mut self) -> u32 {
        if let Some(code) = self.fresh_error.take() {
            return crate::authority::capture_binding_failure(&mut self.fds, code);
        }
        assert!(self.purpose == BindingPurpose::Refresh);
        match &mut self.admission {
            Admission::Unvouched | Admission::Transport(_) => {
                let mut fresh = *self.original.snapshot_ref().unwrap();
                fresh.generation = self.current;
                fresh.credentials.euid = self.uid;
                let mut kernel = Kernel {
                    who: fresh,
                    modes: core::mem::take(&mut self.modes),
                };
                let result = transport::advance(&mut self.admission, self.current, &mut kernel);
                self.modes = kernel.modes;
                match result {
                    Ok(_) => proto_fs::RESOLVING,
                    Err(code) => code,
                }
            }
            Admission::Wire(_) => {
                self.admission.decode().unwrap();
                proto_fs::RESOLVING
            }
            Admission::Vouched(_) => {
                self.admission
                    .validate(self.original, BindingPurpose::Refresh, false, self.current)
                    .unwrap();
                proto_fs::RESOLVING
            }
            Admission::Validated(who) => {
                self.fds.binding = self.original.refreshed(who).unwrap();
                self.ram.complete_binding(&mut self.fds, 0);
                0
            }
            _ => panic!(),
        }
    }
    fn has_transport(&self) -> bool {
        matches!(self.admission, Admission::Transport(_))
    }
    fn drain_transport(&mut self) {
        if self.finish_transport().is_none() {
            self.drain();
        }
    }
    fn reset_fresh(&mut self) {
        assert!(!self.has_transport());
        self.admission = Admission::Unvouched;
        self.purpose = BindingPurpose::Refresh;
        self.original = self.fds.binding;
    }
    fn replay(&mut self) -> u32 {
        if self.replay_race {
            self.replay_race = false;
            self.current += 1;
            self.background_start();
            return proto_fs::AUTHENTICATING;
        }
        self.ordinary += 1;
        let identity = self.fds.binding.identity(false).unwrap();
        match self
            .ram
            .open_token(&mut self.fds, self.file, proto_fs::READ_ONLY, identity)
        {
            Ok(fd) => {
                self.ram.close(&mut self.fds, fd).unwrap();
                0
            }
            Err(code) => code,
        }
    }
    fn authenticating(reply: &u32) -> bool {
        *reply == proto_fs::AUTHENTICATING
    }
    fn restore(&mut self, query: u32) {
        restore_query(&mut self.fds, Some(query));
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for _ in 0..16 {
            if !self.has_transport() {
                break;
            }
            self.drain_transport();
        }
        assert!(!self.has_transport());
        for cap in [
            &mut self.primary,
            &mut self.previous,
            &mut self.offered,
            &mut self.other,
        ] {
            if let Some(cap) = cap.take() {
                cap.consume();
            }
        }
        if self.fds.binding_preparation.is_some() {
            self.ram
                .complete_binding(&mut self.fds, proto_fs::PERMISSION);
        }
    }
}

#[test]
fn shared_driver_uid_chain_all_old_owner_phases_and_both_background_orders() {
    for phase in 0..4 {
        for background in [false, true] {
            let mut fixture = Fixture::failed(phase);
            FAIL_CLOSE.with(|n| *n.borrow_mut() = 1);
            if background {
                fixture.settle_old();
            }
            let mut words = [0; 11];
            fixture.capture(&mut words);
            assert_eq!(fixture.run(&mut words), proto_fs::ACCESS_DENIED);
            assert_eq!(fixture.ordinary, 1);
            assert_eq!(fixture.charges, 2);
            assert_eq!(fixture.primary.as_ref().unwrap().0, Some(71));
            assert!(fixture.previous.is_none());
            assert!(fixture.other.is_none());
            fixture.current = 9;
            fixture.uid = 0;
            if background {
                fixture.background_start();
                fixture.fresh_step();
                fixture.restore(proto_fs::PERMISSION);
            }
            fixture.capture(&mut words);
            assert_eq!(fixture.run(&mut words), 0);
            assert_eq!(fixture.ordinary, 2);
            assert_eq!(fixture.charges, 3);
            assert_eq!(fixture.ram.open_descriptions(), 0);
            assert!(fixture.fair > 0);
        }
    }
}
#[test]
fn paid_refresh_returned_caps_consumed_send_and_epoch_zero_drain_without_recharge() {
    for mode in [ReplyMode::Back, ReplyMode::Consumed, ReplyMode::ExtraCaps] {
        let mut fixture = Fixture::failed(3);
        fixture.settle_old();
        fixture.background_start();
        fixture.modes.push_back(mode);
        fixture.fresh_step();
        fixture.restore(proto_fs::PERMISSION);
        let mut words = [0; 11];
        fixture.capture(&mut words);
        FAIL_CLOSE.with(|n| *n.borrow_mut() = 2);
        assert_eq!(fixture.run(&mut words), proto_fs::ACCESS_DENIED);
        assert_eq!(fixture.charges, 2);
        assert_eq!(fixture.ordinary, 1);
    }
    for epoch in [0, 7] {
        let mut fixture = Fixture::failed(3);
        fixture.settle_old();
        fixture.background_start();
        fixture.admission = Admission::Transport(Transport {
            epoch,
            state: State::Copy {
                owner: Some(Cap::new(90)),
                outcome: 0,
            },
        });
        let mut words = [0; 11];
        fixture.capture(&mut words);
        assert_eq!(Loan::new(&mut words).phase(), Phase::DrainFresh);
        assert_eq!(fixture.run(&mut words), proto_fs::ACCESS_DENIED);
        assert_eq!(fixture.charges, 2);
        assert_eq!(fixture.ordinary, 1);
    }
}
#[test]
fn replay_epoch_race_revalidates_before_single_ordinary_effect() {
    let mut fixture = Fixture::failed(3);
    fixture.settle_old();
    fixture.replay_race = true;
    let mut words = [0; 11];
    fixture.capture(&mut words);
    assert_eq!(fixture.run(&mut words), proto_fs::ACCESS_DENIED);
    assert_eq!(fixture.ordinary, 1);
    assert_eq!(fixture.current, 9);
    assert_eq!(fixture.fds.binding.snapshot_ref().unwrap().generation, 9);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || Loan::new(&mut words).step(&mut fixture)
        ))
        .is_err()
    );
    assert_eq!(fixture.ordinary, 1);
}
#[test]
fn canonical_quota_failure_keeps_query_and_paid_owners_then_new_attempt_succeeds() {
    for refresh in [false, true] {
        let mut fixture = Fixture::failed(3);
        fixture.settle_old();
        if refresh {
            fixture.purpose = BindingPurpose::Refresh;
            fixture.admission = Admission::Validated(*fixture.fds.binding.snapshot_ref().unwrap());
        }
        let mut charges = [0; 16];
        for (i, charge) in charges.iter_mut().enumerate() {
            *charge = fixture
                .ram
                .storage
                .charge_preparation(fixture.fds.root)
                .unwrap();
            fixture.fds.resolvers[i] = (i + 1) as u64;
        }
        let query = preserved_query(&fixture.fds, 81, &fixture.lineage()).unwrap();
        let result = begin_preserving(&mut fixture.ram, &mut fixture.fds, Some(query));
        assert_eq!(result, Err(proto_fs::TOO_MANY_OPEN_FILES));
        assert!(quota_deferred(&fixture.fds, 81, result, &fixture.lineage()));
        assert!(!refresh_started(
            false,
            &fixture.fds,
            81,
            &fixture.lineage()
        ));
        assert_eq!(
            source_refresh_result(result, true),
            Err(proto_fs::TOO_MANY_OPEN_FILES)
        );
        let mut destination = Fds::default();
        assert_eq!(
            crate::authority::capture_binding_failure(
                &mut destination,
                source_refresh_result(result, true).unwrap_err()
            ),
            proto_fs::TOO_MANY_OPEN_FILES
        );
        assert_eq!(
            binding_reply(&destination),
            Some(proto_fs::TOO_MANY_OPEN_FILES)
        );
        assert!(fixture.fds.binding_preparation.is_none());
        assert_eq!(fixture.ram.storage.preparations_used(), 16);
        assert_eq!(fixture.primary.as_ref().unwrap().0, Some(71));
        assert_eq!(binding_reply(&fixture.fds), Some(proto_fs::PERMISSION));
        assert_eq!(
            crate::authority::inherited_source_phase(
                fixture.fds.binding,
                81,
                81,
                false,
                Some(fixture.purpose),
                8,
                7
            ),
            Ok(crate::authority::RetainedSourcePhase::Authenticate)
        );
        let mut words = [0; 11];
        fixture.capture(&mut words);
        assert_eq!(fixture.run(&mut words), proto_fs::TOO_MANY_OPEN_FILES);
        assert_eq!(fixture.ordinary, 0);
        fixture.ram.storage.release_preparation(charges[15]);
        fixture.fds.resolvers[15] = 0;
        fixture.current = 9;
        fixture.uid = 0;
        fixture.capture(&mut words);
        assert_eq!(fixture.run(&mut words), 0);
        assert_eq!(fixture.ordinary, 1);
        assert_eq!(fixture.ram.storage.preparations_used(), 15);
        for charge in &charges[..15] {
            fixture.ram.storage.release_preparation(*charge);
        }
        fixture.fds.resolvers.fill(0);
    }
}

#[test]
fn exact_lineage_boundary_rejects_foreign_dead_unknown_and_live_audit_states() {
    let original = Binding::Active(who());
    let root = original.root().unwrap();
    let unvouched = AdmissionState::<()>::Unvouched;
    let mut fds = Fds {
        binding: original,
        root,
        authority_index: 3,
        claimed: true,
        binding_outcome: Some(proto_fs::PERMISSION),
        ..Fds::default()
    };
    let context = Lineage {
        label: 81,
        original: &original,
        original_root: root,
        purpose: BindingPurpose::Candidate,
        closing: false,
        secondary_owners: false,
        admission: &unvouched,
    };
    assert_eq!(
        preserved_query(&fds, 81, &context),
        Some(proto_fs::PERMISSION)
    );
    assert_eq!(
        capture_phase(&fds, 81, 26, 8, &context, None),
        Some(Phase::BeginFresh)
    );
    for epoch in [0, 7, proto_process::GENERATION_DEAD | 8] {
        assert_eq!(capture_phase(&fds, 81, 26, epoch, &context, None), None);
    }
    for method in 0..=u16::MAX {
        assert_eq!(
            capture_phase(&fds, 81, method, 8, &context, None).is_some(),
            crate::authority::failed_candidate_method(method)
        );
    }
    assert_eq!(preserved_query(&fds, 82, &context), None);
    fds.closing = true;
    assert_eq!(preserved_query(&fds, 81, &context), None);
    fds.closing = false;
    fds.claimed = false;
    assert_eq!(capture_phase(&fds, 81, 26, 8, &context, None), None);
    fds.claimed = true;
    fds.authority_index = crate::storage::NONE;
    assert_eq!(capture_phase(&fds, 81, 26, 8, &context, None), None);
    fds.authority_index = 3;
    fds.root.generation += 1;
    assert_eq!(preserved_query(&fds, 81, &context), None);
    fds.root = root;
    fds.binding = Binding::Pending(who());
    assert_eq!(preserved_query(&fds, 81, &context), None);
    fds.binding = original;
    fds.binding_outcome = Some(0);
    assert_eq!(preserved_query(&fds, 81, &context), None);
    fds.binding_outcome = Some(proto_fs::PERMISSION);
    for purpose in [BindingPurpose::Audit, BindingPurpose::Refresh] {
        let c = Lineage { purpose, ..context };
        assert_eq!(preserved_query(&fds, 81, &c), None);
        assert!(!quota_deferred(
            &fds,
            81,
            Err(proto_fs::TOO_MANY_OPEN_FILES),
            &c
        ));
    }
    let validated = AdmissionState::<()>::Validated(who());
    let refreshed = Lineage {
        purpose: BindingPurpose::Refresh,
        admission: &validated,
        ..context
    };
    assert_eq!(
        capture_phase(&fds, 81, 26, 8, &refreshed, None),
        Some(Phase::BeginFresh)
    );
    let mut foreign = who();
    foreign.credentials.euid = 65533;
    let wrong = AdmissionState::<()>::Validated(foreign);
    assert_eq!(
        preserved_query(
            &fds,
            81,
            &Lineage {
                admission: &wrong,
                ..refreshed
            }
        ),
        None
    );
    for foreign in [
        WhoReply { pid: 301, ..who() },
        WhoReply { index: 45, ..who() },
        WhoReply { image: 2, ..who() },
    ] {
        let binding = Binding::Active(foreign);
        let c = Lineage {
            original: &binding,
            ..context
        };
        assert_eq!(preserved_query(&fds, 81, &c), None);
    }
    assert_eq!(
        preserved_query(
            &fds,
            81,
            &Lineage {
                secondary_owners: true,
                ..context
            }
        ),
        None
    );
    assert_eq!(
        preserved_query(
            &fds,
            81,
            &Lineage {
                closing: true,
                ..context
            }
        ),
        None
    );
    assert_eq!(
        source_refresh_result(Err(proto_fs::TOO_MANY_OPEN_FILES), true),
        Err(proto_fs::TOO_MANY_OPEN_FILES)
    );
    assert_eq!(
        source_refresh_result(Err(proto_fs::AUTHENTICATING), true),
        Ok(proto_fs::RESOLVING)
    );
    assert_eq!(
        source_refresh_result(Ok(()), false),
        Err(proto_fs::PERMISSION)
    );
}
#[test]
fn scoped_phase_result_is_independent_of_cached_query_and_explicit_bind_still_clears_it() {
    let mut fixture = Fixture::failed(3);
    fixture.settle_old();
    fixture.fds.binding_outcome = Some(proto_fs::TOO_MANY_OPEN_FILES);
    fixture.fresh_error = Some(proto_fs::PERMISSION);
    let mut words = [0; 11];
    fixture.capture(&mut words);
    assert_eq!(fixture.run(&mut words), proto_fs::PERMISSION);
    assert_eq!(
        binding_reply(&fixture.fds),
        Some(proto_fs::TOO_MANY_OPEN_FILES)
    );
    assert_eq!(fixture.ordinary, 0);
    let result = with_query(
        &mut fixture.fds,
        Some(proto_fs::TOO_MANY_OPEN_FILES),
        |fds| {
            fixture.ram.complete_binding(fds, 0);
            0
        },
    );
    assert_eq!(result, 0);
    assert_eq!(
        binding_reply(&fixture.fds),
        Some(proto_fs::TOO_MANY_OPEN_FILES)
    );
    // The genuine Bind caller supplies no implicit query preservation.
    begin_preserving(&mut fixture.ram, &mut fixture.fds, None).unwrap();
    assert_eq!(fixture.fds.binding_outcome, None);
    fixture.ram.complete_binding(&mut fixture.fds, 0);
}
