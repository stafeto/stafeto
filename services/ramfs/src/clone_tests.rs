// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::{
    Fds, Ram,
    authority::{Admission, Binding, BindingPurpose, CustodyPhase},
    clone::{Effects, Journal, Outcome, Phase, Refusal, Snapshot},
    storage::{NONE, Pin, ROOT, Root},
};
use posix_process_service::records::{Join, Records, State};
use proto_process::{Credentials, End, WhoReply};
use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

type Ledger = Rc<RefCell<BTreeSet<u64>>>;
struct Cap {
    id: u64,
    ledger: Ledger,
    live: bool,
}
impl Cap {
    fn new(id: u64, ledger: &Ledger) -> Self {
        assert!(ledger.borrow_mut().insert(id));
        Self {
            id,
            ledger: ledger.clone(),
            live: true,
        }
    }
    fn settle(mut self) {
        assert!(self.ledger.borrow_mut().remove(&self.id));
        self.live = false;
    }
}
impl Drop for Cap {
    fn drop(&mut self) {
        assert!(
            !self.live || std::thread::panicking(),
            "aggregate or lost capability drop {}",
            self.id
        );
    }
}
struct Kernel {
    ledger: Ledger,
    identity: Option<Cap>,
    delivered: Option<Cap>,
    reply_error: Option<abi::Error>,
    label_error: Option<abi::Error>,
    failed_closes: usize,
    effects: usize,
    next: u64,
}
impl Kernel {
    fn new() -> Self {
        let ledger = Ledger::default();
        Self {
            identity: Some(Cap::new(1, &ledger)),
            ledger,
            delivered: None,
            reply_error: None,
            label_error: None,
            failed_closes: 0,
            effects: 0,
            next: 2,
        }
    }
    fn gone(&mut self) {
        self.delivered
            .take()
            .expect("delivered child channel")
            .settle();
        self.identity
            .take()
            .expect("retained child identity")
            .settle();
        assert!(self.ledger.borrow().is_empty());
    }
}
impl Effects<Cap, u64> for Kernel {
    fn label(&mut self, _: u64) -> Result<Cap, abi::Error> {
        self.effects += 1;
        if let Some(error) = self.label_error.take() {
            return Err(error);
        }
        let cap = Cap::new(self.next, &self.ledger);
        self.next += 1;
        Ok(cap)
    }
    fn reply(&mut self, token: u64, session: Option<Cap>, _: u32) -> Result<(), Refusal<Cap, u64>> {
        self.effects += 1;
        if let Some(error) = self.reply_error.take() {
            if error.keeps_handles() {
                return Err(Refusal {
                    error,
                    back: session,
                    token: (error != abi::Error::BadState).then_some(token),
                });
            }
            if matches!(error, abi::Error::Unknown(_)) {
                // The ambiguous kernel outcome actually delivered this channel.
                self.delivered = session;
            } else if let Some(session) = session {
                session.settle();
            }
            return Err(Refusal {
                error,
                back: None,
                token: None,
            });
        }
        if let Some(session) = session {
            self.delivered = Some(session);
        }
        Ok(())
    }
    fn close(&mut self, session: &mut Option<Cap>) -> Result<(), abi::Error> {
        self.effects += 1;
        if self.failed_closes > 0 {
            self.failed_closes -= 1;
            return Err(abi::Error::WouldBlock);
        }
        session.take().expect("retained local channel").settle();
        Ok(())
    }
    fn close_identity(&mut self, index: u16, _: u64) -> Result<(), abi::Error> {
        assert_eq!(index, 0);
        self.effects += 1;
        if self.failed_closes > 0 {
            self.failed_closes -= 1;
            return Err(abi::Error::WouldBlock);
        }
        self.identity.take().expect("paid identity").settle();
        Ok(())
    }
}
fn step(j: &mut Journal<Cap, u64>, ram: &mut Ram<'_>, kernel: &mut Kernel) -> Outcome {
    let before = kernel.effects;
    let out = j.step(ram, 0x8000_0000_0000_0001, kernel);
    assert!(kernel.effects - before <= 1, "one kernel effect per STEP");
    out
}
fn journal(ram: &mut Ram<'_>, source: &Fds, list: &[u32]) -> Journal<Cap, u64> {
    Journal {
        owner: 17,
        snapshot: Some(Snapshot::capture(ram, source, list).unwrap()),
        binding: source.binding,
        authority_index: 0,
        session: None,
        token: Some(99),
        phase: Phase::Session,
        code: 0,
    }
}
fn who(records: &Records<u32>, index: usize) -> WhoReply {
    let r = records.get(index).unwrap();
    WhoReply {
        pid: r.label.pid(),
        credentials: r.credentials,
        generation: 1,
        loader: None,
        index: index as u32,
        ctty: r.ctty,
        image: r.image,
        groups: r.groups,
        limits: r.limits,
        root: r.root,
    }
}

#[test]
fn actual_parent_end_index_reuse_and_unknown_delivered_child_keep_custody_until_bind_and_gone() {
    for ambiguous in [false, true] {
        let mut records = Records::<u32>::new();
        let parent = records.next_label().unwrap();
        let parent_index =
            records.insert(parent, 11, None, Credentials::ROOT, 31, Join::NewSession);
        records.get_mut(parent_index).unwrap().state = State::Alive;
        let child = records.next_label().unwrap();
        let child_index = records.insert(
            child,
            22,
            Some(parent_index),
            Credentials::NOBODY,
            31,
            Join::NewSession,
        );
        records.get_mut(child_index).unwrap().state = State::Alive;
        let captured = who(&records, parent_index);
        let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
        let mut source = Fds {
            binding: Binding::Active(captured),
            root: Root {
                id: u64::from(captured.root.pid),
                generation: u64::from(captured.root.generation),
            },
            ..Fds::default()
        };
        let fd = ram
            .open(&mut source, "/etc/motd", proto_fs::READ_ONLY)
            .unwrap();
        ram.storage.pin(ROOT, Pin::Cwd).unwrap();
        source.cwd = Some(ROOT);
        let mut j = journal(&mut ram, &source, &[fd]);
        j.binding = Binding::Inherited(captured);
        let mut kernel = Kernel::new();
        assert!(matches!(
            step(&mut j, &mut ram, &mut kernel),
            Outcome::Pending
        ));
        if ambiguous {
            kernel.reply_error = Some(abi::Error::Unknown(89));
        }
        let Outcome::Ready = step(&mut j, &mut ram, &mut kernel) else {
            panic!("independent retained child");
        };
        let mut inherited = j.materialize();
        let (_, orphans) = records.exited(parent_index, End::Exited(0));
        assert_eq!(orphans.as_slice(), [child_index as u16]);
        assert_eq!(records.get(child_index).unwrap().state, State::Alive);
        assert_eq!(
            records.get(child_index).unwrap().parent,
            proto_process::INIT_PID
        );
        assert_eq!(records.get(child_index).unwrap().root, captured.root);
        let replacement = records.next_label().unwrap();
        assert_eq!(replacement.index, parent.index);
        assert_ne!(replacement.generation, parent.generation);
        records.insert(
            replacement,
            33,
            None,
            Credentials::ROOT,
            31,
            Join::NewSession,
        );
        while ram.release_step(&mut source) {}
        for epoch in [proto_process::GENERATION_DEAD | 1, 3, 0] {
            assert_eq!(inherited.binding.custody_phase(false), CustodyPhase::Hold);
            assert_eq!(
                inherited.binding.authenticate_epoch(epoch),
                Err(proto_fs::PERMISSION)
            );
            assert_eq!(inherited.binding, Binding::Inherited(captured));
        }
        assert_eq!(inherited.binding.identity(false), Err(proto_fs::PERMISSION));
        assert_eq!(ram.open_descriptions(), 1);
        let current_child = who(&records, child_index);
        let mut admission = Admission::Vouched(current_child);
        ram.begin_binding(&mut inherited).unwrap();
        assert_eq!(
            inherited.binding.custody_phase(true),
            CustodyPhase::Candidate
        );
        admission
            .validate(
                inherited.binding,
                BindingPurpose::Candidate,
                false,
                current_child.generation,
            )
            .unwrap();
        inherited
            .binding
            .bind_ref(Some(&current_child), false)
            .unwrap();
        ram.complete_binding(&mut inherited, 0);
        assert_eq!(
            inherited.binding.identity(false).unwrap().uid,
            Credentials::NOBODY.euid
        );
        assert_eq!(
            inherited
                .binding
                .authenticate_epoch(current_child.generation),
            Ok(true)
        );
        let mut byte = [0];
        assert_eq!(ram.read(&mut inherited, fd, &mut byte), Ok(1));
        assert_eq!(byte, *b"s");
        while ram.release_step(&mut inherited) {}
        inherited.authority_index = NONE;
        kernel.gone();
        assert!(Ram::released(&inherited));
        assert_eq!(ram.open_descriptions(), 0);
        assert_eq!(ram.storage.preparations_used(), 0);
    }
}

#[test]
fn genuine_candidate_refusals_preserve_inherited_resources_and_block_parent_authority() {
    let mut records = Records::<u32>::new();
    let label = records.next_label().unwrap();
    let index = records.insert(label, 0, None, Credentials::ROOT, 31, Join::NewSession);
    let captured = who(&records, index);
    let inherited = Binding::Inherited(captured);
    for mutation in 0..5 {
        let mut child = captured;
        match mutation {
            0 => child.root.generation += 1,
            1 => child.generation |= proto_process::GENERATION_DEAD,
            2 => {
                child.loader = Some(proto_process::LoaderOf {
                    image: 1,
                    ticket: 77,
                })
            }
            3 => child.limits.values[0].soft = child.limits.values[0].hard + 1,
            _ => child.image = 0,
        }
        let mut admission = Admission::Vouched(child);
        assert_eq!(
            admission.validate(
                inherited,
                BindingPurpose::Candidate,
                false,
                child.generation
            ),
            Err(proto_fs::PERMISSION)
        );
        assert_eq!(inherited.identity(false), Err(proto_fs::PERMISSION));
    }
    let mut stale = Admission::Vouched(captured);
    assert_eq!(
        stale.validate(
            inherited,
            BindingPurpose::Candidate,
            false,
            captured.generation + 1
        ),
        Ok(())
    );
    assert!(matches!(stale, Admission::Unvouched));
    assert_eq!(
        crate::authority::inherited_source_phase(
            inherited,
            7,
            7,
            false,
            None,
            proto_process::GENERATION_DEAD,
            1
        )
        .unwrap(),
        crate::authority::RetainedSourcePhase::Ready
    );
    assert_eq!(
        crate::authority::inherited_source_phase(
            inherited,
            7,
            8,
            false,
            None,
            proto_process::GENERATION_DEAD,
            1
        ),
        Err(proto_fs::PERMISSION)
    );
}

#[test]
fn thirty_two_shared_descriptors_survive_failed_label_and_each_rollback_visit() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let mut source = Fds::default();
    let numbers: Vec<_> = (0..32)
        .map(|_| {
            ram.open(&mut source, "/etc/motd", proto_fs::READ_ONLY)
                .unwrap()
        })
        .collect();
    let mut sibling = ram.clone_fds(&source, &numbers).unwrap();
    let mut j = journal(&mut ram, &source, &numbers);
    let mut kernel = Kernel::new();
    kernel.label_error = Some(abi::Error::NoMemory);
    assert!(matches!(
        step(&mut j, &mut ram, &mut kernel),
        Outcome::Pending
    ));
    assert!(matches!(
        step(&mut j, &mut ram, &mut kernel),
        Outcome::Pending
    ));
    while ram.release_step(&mut source) {}
    let mut visits = 0;
    loop {
        let terminal = matches!(step(&mut j, &mut ram, &mut kernel), Outcome::Terminal);
        visits += 1;
        assert_eq!(ram.open_descriptions(), 32);
        if terminal {
            break;
        }
        assert!(visits < 40);
    }
    assert_eq!(visits, 34);
    assert!(kernel.ledger.borrow().is_empty());
    assert_eq!(ram.read(&mut sibling, numbers[31], &mut [0]), Ok(1));
    while ram.release_step(&mut sibling) {}
    assert_eq!(ram.open_descriptions(), 0);
}

#[test]
fn returned_transfer_token_and_local_handle_remain_owned_across_failed_close() {
    for error in [
        abi::Error::WouldBlock,
        abi::Error::BadState,
        abi::Error::PeerClosed,
        abi::Error::LimitReached,
        abi::Error::NoMemory,
        abi::Error::Interrupted,
    ] {
        let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
        let source = Fds::default();
        let mut j = journal(&mut ram, &source, &[]);
        let mut kernel = Kernel::new();
        step(&mut j, &mut ram, &mut kernel);
        kernel.reply_error = Some(error);
        step(&mut j, &mut ram, &mut kernel);
        assert_eq!(j.session.is_some(), error.keeps_handles());
        assert_eq!(
            j.token.is_some(),
            error.keeps_handles() && error != abi::Error::BadState
        );
        kernel.failed_closes = 2;
        let mut terminal = false;
        for _ in 0..12 {
            if matches!(step(&mut j, &mut ram, &mut kernel), Outcome::Terminal) {
                terminal = true;
                break;
            }
        }
        assert!(terminal);
        assert!(kernel.ledger.borrow().is_empty());
    }
}

#[test]
fn aggregated_shared_preflight_and_bad_last_fd_have_zero_effect() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let mut source = Fds::default();
    let first = ram
        .open(&mut source, "/etc/motd", proto_fs::READ_ONLY)
        .unwrap();
    let second = ram
        .open(&mut source, "/etc/motd", proto_fs::READ_ONLY)
        .unwrap();
    let index = source.description(first).unwrap();
    let released = source.description(second).unwrap();
    ram.release_shared(released).unwrap();
    source.slots[(second - 3) as usize] = Some(index as u8);
    ram.descriptions[index].as_mut().unwrap().refs += 1;
    source.cwd = Some(ROOT);
    ram.storage.pin(ROOT, Pin::Cwd).unwrap();
    let pins = ram.storage.node(ROOT).unwrap().pins;
    ram.descriptions[index].as_mut().unwrap().refs = u16::MAX - 1;
    assert!(Snapshot::preflight(&ram, &source, &[first, second]).is_err());
    assert_eq!(ram.descriptions[index].as_ref().unwrap().refs, u16::MAX - 1);
    assert_eq!(ram.storage.node(ROOT).unwrap().pins, pins);
    assert!(Snapshot::preflight(&ram, &source, &[first, 35]).is_err());
    assert_eq!(ram.descriptions[index].as_ref().unwrap().refs, u16::MAX - 1);
    // Repeated numeric fd contributes one reference; two distinct aliases contribute two.
    let one = Snapshot::capture(&mut ram, &source, &[first, first]).unwrap();
    assert_eq!(ram.descriptions[index].as_ref().unwrap().refs, u16::MAX);
    let mut one = one;
    while one.release_step(&mut ram).unwrap() {}
    ram.descriptions[index].as_mut().unwrap().refs = 2;
    while ram.release_step(&mut source) {}
    assert_eq!(ram.open_descriptions(), 0);
}

#[test]
fn failed_cloning_close_rotates_while_another_clone_and_gc_progress() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let source = Fds::default();
    let mut first = journal(&mut ram, &source, &[]);
    first.revoke(abi::Error::PeerClosed);
    let mut second = journal(&mut ram, &source, &[]);
    let mut a = Kernel::new();
    let mut b = Kernel::new();
    a.failed_closes = 100;
    let mut cursor = crate::maintenance::Cursor {
        position: 1,
        remaining: 3,
    };
    let mut complete = None;
    let mut gc_visits = 0;
    for _ in 0..15 {
        match cursor.position {
            1 => {
                step(&mut first, &mut ram, &mut a);
            }
            2 if complete.is_none() => {
                if let Outcome::Ready = step(&mut second, &mut ram, &mut b) {
                    complete = Some(second.materialize());
                }
            }
            _ => {
                ram.storage.reclaim_step();
                gc_visits += 1;
            }
        }
        cursor.complete_clone(4);
    }
    assert!(complete.is_some());
    assert!(gc_visits > 0);
    assert_eq!(a.identity.as_ref().unwrap().id, 1);
    a.failed_closes = 0;
    while !matches!(step(&mut first, &mut ram, &mut a), Outcome::Terminal) {}
    let mut complete = complete.unwrap();
    while ram.release_step(&mut complete) {}
    b.gone();
    assert!(a.ledger.borrow().is_empty());
}

#[test]
fn last_paid_birth_place_clone_and_terminal_generation_preserve_exact_reuse() {
    let places = crate::places::Places::new();
    let mut clones = proto_wire::clones::Clones::<320>::new();
    let mut births = [None; 320];
    let mut given = 0;
    for owner in 0..319 {
        let (slot, label) =
            crate::clone::reserve(&births, &mut given, &places, &mut clones, owner).unwrap();
        births[slot] = Some(label);
        assert_eq!(clones.client_of(label), Some(owner));
    }
    let before = given;
    assert!(crate::clone::reserve(&births, &mut given, &places, &mut clones, 400).is_err());
    assert_eq!(given, before);
    let old = births[318].take().unwrap();
    places.release(old);
    clones.gone(old);
    let (slot, replacement) =
        crate::clone::reserve(&births, &mut given, &places, &mut clones, 401).unwrap();
    births[slot] = Some(replacement);
    assert_ne!(old, replacement);
    places.release(old);
    clones.gone(old);
    assert_eq!(clones.client_of(replacement), Some(401));
    assert!(places.place(replacement) < crate::places::COUNT);
    births.fill(Some(1));
    let before = given;
    assert!(crate::clone::reserve(&births, &mut given, &places, &mut clones, 402).is_err());
    assert_eq!(given, before);
    given = (1 << 46) - 1;
    births.fill(None);
    assert!(crate::clone::reserve(&births, &mut given, &places, &mut clones, 403).is_err());
    assert_eq!(given, (1 << 46) - 1);
    assert_eq!(clones.client_of(replacement), Some(401));
}

#[test]
fn snapshot_does_not_consume_saturated_global_and_root_preparation_budgets() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let a = Root {
        id: 11,
        generation: 1,
    };
    let b = Root {
        id: 12,
        generation: 1,
    };
    let charges: Vec<_> = (0..96)
        .map(|_| a)
        .chain((0..32).map(|_| b))
        .map(|root| ram.storage.charge_preparation(root).unwrap())
        .collect();
    let source = Fds {
        root: a,
        ..Fds::default()
    };
    let mut snapshot = Snapshot::capture(&mut ram, &source, &[]).unwrap();
    assert_eq!(ram.storage.preparations_used(), 128);
    #[cfg(feature = "auth-probe")]
    assert_eq!(ram.storage.preparations_for_root(a), 96);
    #[cfg(feature = "auth-probe")]
    assert_eq!(ram.storage.preparations_for_root(b), 32);
    assert_eq!(snapshot.release_step(&mut ram), Ok(false));
    for charge in charges {
        ram.storage.release_preparation(charge);
    }
    assert_eq!(ram.storage.preparations_used(), 0);
}

#[test]
fn repeated_revocation_and_failed_error_reply_keep_exact_snapshot_and_token() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let mut source = Fds::default();
    let fd = ram
        .open(&mut source, "/etc/motd", proto_fs::READ_ONLY)
        .unwrap();
    let mut j = journal(&mut ram, &source, &[fd]);
    let mut kernel = Kernel::new();
    step(&mut j, &mut ram, &mut kernel);
    j.revoke(abi::Error::PeerClosed);
    j.revoke(abi::Error::PeerClosed);
    kernel.reply_error = Some(abi::Error::WouldBlock);
    step(&mut j, &mut ram, &mut kernel);
    assert_eq!(j.token, Some(99));
    assert_eq!(j.phase, Phase::ErrorReply);
    assert!(j.session.is_some());
    let description = source.description(fd).unwrap();
    assert_eq!(ram.descriptions[description].as_ref().unwrap().refs, 2);
    step(&mut j, &mut ram, &mut kernel);
    assert_eq!(j.phase, Phase::Rollback);
    while !matches!(step(&mut j, &mut ram, &mut kernel), Outcome::Terminal) {}
    assert_eq!(ram.descriptions[description].as_ref().unwrap().refs, 1);
    assert_eq!(ram.read(&mut source, fd, &mut [0]), Ok(1));
    while ram.release_step(&mut source) {}
    assert!(kernel.ledger.borrow().is_empty());
}

#[test]
fn exhausted_cwd_pin_refuses_snapshot_before_descriptor_effects() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let mut source = Fds::default();
    let fd = ram
        .open(&mut source, "/etc/motd", proto_fs::READ_ONLY)
        .unwrap();
    source.cwd = Some(ROOT);
    ram.storage.pin(ROOT, Pin::Cwd).unwrap();
    let index = source.description(fd).unwrap();
    let before = ram.descriptions[index].as_ref().unwrap().refs;
    let pins = ram.storage.node(ROOT).unwrap().pins;
    ram.storage.node_mut(ROOT).unwrap().pins[Pin::Cwd as usize] = u16::MAX;
    assert!(Snapshot::preflight(&ram, &source, &[fd]).is_err());
    assert_eq!(ram.descriptions[index].as_ref().unwrap().refs, before);
    assert_eq!(
        ram.storage.node(ROOT).unwrap().pins[Pin::Cwd as usize],
        u16::MAX
    );
    ram.storage.node_mut(ROOT).unwrap().pins = pins;
    while ram.release_step(&mut source) {}
    assert_eq!(ram.open_descriptions(), 0);
}
