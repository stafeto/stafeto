// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One admission union retains every owner between notary transport visits.
use crate::authority::AdmissionState;

pub trait Owners {
    type Copy;
    type Back;
    type Reply;
    type Held;
    fn copy_live(owner: &Self::Copy) -> bool;
    fn close_copy(owner: &mut Self::Copy);
    fn pop_back(owners: &mut Self::Back) -> Option<Self::Held>;
    fn reply_len(owners: &Self::Reply) -> usize;
    fn take_reply(owners: &mut Self::Reply, index: usize) -> Option<Self::Held>;
    fn close_held(owner: &mut Option<Self::Held>);
}
pub enum State<O: Owners> {
    Copy {
        owner: O::Copy,
        outcome: u32,
    },
    Back {
        owners: O::Back,
        held: Option<O::Held>,
        outcome: u32,
    },
    Reply {
        owners: O::Reply,
        held: Option<O::Held>,
        cursor: u8,
        outcome: u32,
    },
    Rollback {
        rejected: O::Copy,
        outcome: u32,
    },
    Commit,
}
pub struct Transport<O: Owners> {
    pub epoch: u64,
    pub state: State<O>,
}
impl<O: Owners> Transport<O> {
    /// None is a finish phase; Some(None) retains debt; Some(Some(code)) is empty.
    pub fn drain(&mut self) -> Option<Option<u32>> {
        let outcome = match &mut self.state {
            State::Copy { owner, outcome } => {
                if O::copy_live(owner) {
                    O::close_copy(owner);
                    return Some(None);
                }
                *outcome
            }
            State::Back {
                owners,
                held,
                outcome,
            } => {
                if held.is_none() {
                    *held = O::pop_back(owners);
                }
                if held.is_some() {
                    O::close_held(held);
                    return Some(None);
                }
                *outcome
            }
            State::Reply {
                owners,
                held,
                cursor,
                outcome,
            } => {
                if held.is_none() {
                    while (*cursor as usize) < O::reply_len(owners) {
                        let index = *cursor as usize;
                        *cursor += 1;
                        if let Some(owner) = O::take_reply(owners, index) {
                            *held = Some(owner);
                            break;
                        }
                    }
                }
                if held.is_some() {
                    O::close_held(held);
                    return Some(None);
                }
                *outcome
            }
            State::Rollback { .. } | State::Commit => return None,
        };
        Some(Some(outcome))
    }
}
pub enum Finish {
    Pending,
    Rollback(u32),
    Commit,
}

/// Rejected primary, offered candidate and previous identity each get a separate close.
pub fn finish<O: Owners>(
    transport: &mut Transport<O>,
    offered: &mut O::Copy,
    previous: &mut O::Copy,
) -> Option<Finish> {
    match &mut transport.state {
        State::Rollback { rejected, outcome } => {
            if O::copy_live(offered) {
                O::close_copy(offered);
                return Some(Finish::Pending);
            }
            if O::copy_live(rejected) {
                O::close_copy(rejected);
                return Some(Finish::Pending);
            }
            Some(Finish::Rollback(*outcome))
        }
        State::Commit => {
            if O::copy_live(offered) {
                O::close_copy(offered);
                return Some(Finish::Pending);
            }
            if O::copy_live(previous) {
                O::close_copy(previous);
                return Some(Finish::Pending);
            }
            Some(Finish::Commit)
        }
        _ => None,
    }
}

pub enum Send<B, I> {
    Wire([u8; 252]),
    RetainedWire([u8; 260]),
    Denied,
    Retry,
    Back(B),
    Reply(I),
}
pub trait Effects<O: Owners> {
    fn duplicate(&mut self) -> Option<O::Copy>;
    fn send(&mut self, owner: &mut O::Copy) -> Send<O::Back, O::Reply>;
}

/// A visit duplicates, sends, or closes one owner; it never chains these effects.
pub fn advance<O: Owners, E: Effects<O>>(
    admission: &mut AdmissionState<Transport<O>>,
    current: u64,
    effects: &mut E,
) -> Result<bool, u32> {
    if matches!(admission, AdmissionState::Unvouched) {
        let Some(owner) = effects.duplicate() else {
            return Ok(false);
        };
        *admission = AdmissionState::Transport(Transport {
            epoch: current,
            state: State::Copy { owner, outcome: 0 },
        });
        return Ok(true);
    }
    let AdmissionState::Transport(transport) = admission else {
        return Ok(false);
    };
    let ready = matches!(transport.state, State::Copy { outcome: 0, .. })
        && transport.epoch == current
        && current & proto_process::GENERATION_DEAD == 0;
    if !ready {
        if let Some(Some(outcome)) = transport.drain() {
            *admission = AdmissionState::Unvouched;
            if outcome != 0 {
                return Err(outcome);
            }
        }
        return Ok(true);
    }
    let State::Copy { owner, .. } = &mut transport.state else {
        unreachable!()
    };
    let sent = effects.send(owner);
    assert!(
        matches!(sent, Send::Denied) || !O::copy_live(owner),
        "Send settles its exact offered owner"
    );
    match sent {
        Send::Wire(bytes) => *admission = AdmissionState::Wire(bytes),
        Send::RetainedWire(bytes) => *admission = AdmissionState::RetainedWire(bytes),
        Send::Denied => return Err(proto_fs::PERMISSION),
        Send::Retry => *admission = AdmissionState::Unvouched,
        Send::Back(owners) => {
            transport.state = State::Back {
                owners,
                held: None,
                outcome: 0,
            }
        }
        Send::Reply(owners) => {
            transport.state = State::Reply {
                owners,
                held: None,
                cursor: 0,
                outcome: 0,
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::CleanupAudit;
    use std::{cell::RefCell, collections::VecDeque};
    #[derive(Debug)]
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
            assert!(self.0.is_none(), "implicit owner drop");
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
        fn copy_live(owner: &Self::Copy) -> bool {
            owner.is_some()
        }
        fn close_copy(owner: &mut Self::Copy) {
            Self::close_held(owner);
        }
        fn pop_back(owners: &mut Self::Back) -> Option<Cap> {
            owners.pop()
        }
        fn reply_len(owners: &Self::Reply) -> usize {
            owners.len()
        }
        fn take_reply(owners: &mut Self::Reply, i: usize) -> Option<Cap> {
            owners[i].take()
        }
        fn close_held(owner: &mut Option<Cap>) {
            let id = owner.as_ref().unwrap().0.unwrap();
            CALLS.with(|calls| calls.borrow_mut().push(("Close", id)));
            let failed = FAIL_CLOSE.with(|count| {
                let mut count = count.borrow_mut();
                if *count == 0 {
                    false
                } else {
                    *count -= 1;
                    true
                }
            });
            if !failed {
                assert_eq!(owner.take().unwrap().consume(), id);
            }
        }
    }
    enum ResultKind {
        Wire,
        Retained,
        RefusedBack,
        Consumed,
        Reply(usize),
        Denied,
    }
    struct Kernel {
        id: u64,
        results: VecDeque<ResultKind>,
        fail_duplicate: bool,
    }
    impl Effects<Owned> for Kernel {
        fn duplicate(&mut self) -> Option<Option<Cap>> {
            CALLS.with(|calls| calls.borrow_mut().push(("Duplicate", self.id)));
            (!self.fail_duplicate).then(|| Some(Cap::new(self.id)))
        }
        fn send(&mut self, owner: &mut Option<Cap>) -> Send<Vec<Cap>, Vec<Option<Cap>>> {
            let cap = owner.take().unwrap();
            CALLS.with(|calls| calls.borrow_mut().push(("Send", cap.0.unwrap())));
            match self.results.pop_front().unwrap() {
                ResultKind::RefusedBack => Send::Back(vec![cap]),
                result => {
                    let _ = cap.consume();
                    match result {
                        ResultKind::Wire => Send::Wire([7; 252]),
                        ResultKind::Retained => Send::RetainedWire([8; 260]),
                        ResultKind::Consumed => Send::Retry,
                        ResultKind::Reply(n) => {
                            Send::Reply((0..n).map(|i| Some(Cap::new(500 + i as u64))).collect())
                        }
                        ResultKind::Denied => Send::Denied,
                        ResultKind::RefusedBack => unreachable!(),
                    }
                }
            }
        }
    }
    type Admission = AdmissionState<Transport<Owned>>;
    fn kernel(result: ResultKind) -> Kernel {
        CALLS.with(|calls| calls.borrow_mut().clear());
        FAIL_CLOSE.with(|count| *count.borrow_mut() = 0);
        Kernel {
            id: u64::MAX - 1,
            results: [result].into(),
            fail_duplicate: false,
        }
    }
    fn visit(admission: &mut Admission, current: u64, kernel: &mut Kernel) -> Result<bool, u32> {
        let before = CALLS.with(|calls| calls.borrow().len());
        let result = advance(admission, current, kernel);
        assert!(
            CALLS.with(|calls| calls.borrow().len()) - before <= 1,
            "combined transport effects"
        );
        result
    }
    fn settle(admission: &mut Admission, current: u64, kernel: &mut Kernel) {
        for _ in 0..8 {
            if matches!(admission, Admission::Unvouched) {
                return;
            }
            visit(admission, current, kernel).unwrap();
        }
        panic!("unsettled owner");
    }
    #[test]
    fn duplicate_and_both_wires_require_distinct_visits_without_owner_drop() {
        for retained in [false, true] {
            let mut kernel = kernel(if retained {
                ResultKind::Retained
            } else {
                ResultKind::Wire
            });
            let mut admission = Admission::Unvouched;
            visit(&mut admission, 31, &mut kernel).unwrap();
            assert!(matches!(
                admission,
                Admission::Transport(Transport {
                    state: State::Copy { owner: Some(_), .. },
                    ..
                })
            ));
            assert_eq!(CALLS.with(|calls| calls.borrow().len()), 1);
            visit(&mut admission, 31, &mut kernel).unwrap();
            assert!(matches!(
                (&admission, retained),
                (Admission::Wire(_), false) | (Admission::RetainedWire(_), true)
            ));
            assert_eq!(
                CALLS.with(|calls| calls.borrow().clone()),
                vec![("Duplicate", u64::MAX - 1), ("Send", u64::MAX - 1)]
            );
        }
    }
    #[test]
    fn refused_back_failed_close_preserves_exact_owner_while_another_admission_progresses() {
        let mut first = kernel(ResultKind::RefusedBack);
        let mut admission = Admission::Unvouched;
        visit(&mut admission, 31, &mut first).unwrap();
        visit(&mut admission, 31, &mut first).unwrap();
        FAIL_CLOSE.with(|count| *count.borrow_mut() = 2);
        visit(&mut admission, 31, &mut first).unwrap();
        let Admission::Transport(Transport {
            state: State::Back {
                held: Some(owner), ..
            },
            ..
        }) = &admission
        else {
            panic!()
        };
        assert_eq!(owner.0, Some(u64::MAX - 1));
        let mut other = Kernel {
            id: 42,
            results: [ResultKind::Wire].into(),
            fail_duplicate: false,
        };
        let mut other_admission = Admission::Unvouched;
        visit(&mut other_admission, 7, &mut other).unwrap();
        visit(&mut admission, 31, &mut first).unwrap();
        visit(&mut other_admission, 7, &mut other).unwrap();
        assert!(matches!(other_admission, Admission::Wire(_)));
        settle(&mut admission, 31, &mut first);
        assert_eq!(
            CALLS.with(|calls| calls
                .borrow()
                .iter()
                .filter(|(call, _)| *call == "Close")
                .map(|(_, id)| *id)
                .collect::<Vec<_>>()),
            vec![u64::MAX - 1; 3]
        );
    }
    #[test]
    fn consumed_send_never_resurrects_the_offer_and_unexpected_reply_drains_one_cap_each() {
        let mut kernel = kernel(ResultKind::Consumed);
        let mut admission = Admission::Unvouched;
        visit(&mut admission, 31, &mut kernel).unwrap();
        visit(&mut admission, 31, &mut kernel).unwrap();
        assert!(matches!(admission, Admission::Unvouched));
        assert_eq!(CALLS.with(|calls| calls.borrow().len()), 2);
        for n in 1..=4 {
            let mut kernel = self::kernel(ResultKind::Reply(n));
            let mut admission = Admission::Unvouched;
            visit(&mut admission, 31, &mut kernel).unwrap();
            visit(&mut admission, 31, &mut kernel).unwrap();
            settle(&mut admission, 31, &mut kernel);
            assert_eq!(
                CALLS.with(|calls| calls
                    .borrow()
                    .iter()
                    .filter(|(call, _)| *call == "Close")
                    .count()),
                n
            );
        }
    }
    #[test]
    fn generation_or_end_between_duplicate_and_send_drains_before_retry() {
        for current in [32, proto_process::GENERATION_DEAD | 31] {
            let mut kernel = kernel(ResultKind::Wire);
            let mut admission = Admission::Unvouched;
            visit(&mut admission, 31, &mut kernel).unwrap();
            settle(&mut admission, current, &mut kernel);
            assert_eq!(
                CALLS.with(|calls| calls.borrow().clone()),
                vec![("Duplicate", u64::MAX - 1), ("Close", u64::MAX - 1)]
            );
        }
    }
    #[test]
    fn admission_epoch_reset_rejects_live_transport_without_changing_audit_or_owner() {
        let mut kernel = kernel(ResultKind::Wire);
        let mut admission = Admission::Unvouched;
        visit(&mut admission, 31, &mut kernel).unwrap();
        let mut audit = CleanupAudit::default();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            audit.start(&mut admission, 32)
        }))
        .unwrap_err();
        let message = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
            .unwrap();
        assert!(message.contains("settled admission before epoch reset"));
        assert_eq!(audit.generations(), (0, 0));
        settle(&mut admission, 32, &mut kernel);
        audit.start(&mut admission, 32);
        assert_eq!(audit.generations(), (32, 0));
    }
    #[test]
    fn occupied_offered_rejected_and_previous_owners_settle_before_terminal_binding_result() {
        for rollback in [true, false] {
            let _kernel = kernel(ResultKind::Wire);
            let mut offered = Some(Cap::new(71));
            let mut previous = if rollback { None } else { Some(Cap::new(72)) };
            let mut transport = Transport::<Owned> {
                epoch: 0,
                state: if rollback {
                    State::Rollback {
                        rejected: Some(Cap::new(73)),
                        outcome: proto_fs::PERMISSION,
                    }
                } else {
                    State::Commit
                },
            };
            FAIL_CLOSE.with(|count| *count.borrow_mut() = 1);
            let mut terminal = false;
            for _ in 0..6 {
                let before = CALLS.with(|calls| calls.borrow().len());
                match finish(&mut transport, &mut offered, &mut previous).unwrap() {
                    Finish::Pending => {}
                    Finish::Rollback(code) => {
                        assert!(rollback);
                        assert_eq!(code, proto_fs::PERMISSION);
                        terminal = true;
                    }
                    Finish::Commit => {
                        assert!(!rollback);
                        terminal = true;
                    }
                }
                assert!(
                    CALLS.with(|calls| calls.borrow().len()) - before <= 1,
                    "combined binding cleanup effects"
                );
                if terminal {
                    break;
                }
            }
            assert!(terminal && offered.is_none() && previous.is_none());
            assert_eq!(
                CALLS.with(|calls| calls.borrow().clone()),
                vec![
                    ("Close", 71),
                    ("Close", 71),
                    ("Close", if rollback { 73 } else { 72 })
                ]
            );
        }
    }

    #[test]
    fn immediate_denial_repeats_during_failed_rollback_after_settlement_and_new_binding() {
        use crate::authority::{binding_reply, capture_binding_failure};
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let mut fds = crate::Fds {
            binding: crate::authority::Binding::Boot,
            root: crate::storage::Root {
                id: 900,
                generation: 2,
            },
            ..crate::Fds::default()
        };
        ram.begin_binding(&mut fds).unwrap();
        assert_eq!(ram.storage.preparations_used(), 1);
        assert_eq!(
            capture_binding_failure(&mut fds, proto_fs::PERMISSION),
            proto_fs::PERMISSION
        );
        assert_eq!(binding_reply(&fds), Some(proto_fs::PERMISSION));
        let _kernel = kernel(ResultKind::Wire);
        let mut offered = Some(Cap::new(72));
        let mut previous = None;
        let mut transport = Transport::<Owned> {
            epoch: 0,
            state: State::Rollback {
                rejected: Some(Cap::new(73)),
                outcome: proto_fs::PERMISSION,
            },
        };
        FAIL_CLOSE.with(|count| *count.borrow_mut() = 1);
        let mut settled = false;
        for _ in 0..6 {
            assert_eq!(binding_reply(&fds), Some(proto_fs::PERMISSION));
            assert_eq!(
                ram.begin_binding(&mut fds),
                Err(proto_fs::TOO_MANY_OPEN_FILES)
            );
            assert_eq!(binding_reply(&fds), Some(proto_fs::PERMISSION));
            assert_eq!(ram.storage.preparations_used(), 1);
            let before = CALLS.with(|calls| calls.borrow().len());
            match finish(&mut transport, &mut offered, &mut previous).unwrap() {
                Finish::Pending => {}
                Finish::Rollback(code) => {
                    ram.complete_binding(&mut fds, code);
                    settled = true;
                }
                Finish::Commit => panic!(),
            }
            assert!(CALLS.with(|calls| calls.borrow().len()) - before <= 1);
            if settled {
                break;
            }
        }
        assert!(settled);
        assert_eq!(fds.binding, crate::authority::Binding::Boot);
        assert_eq!(ram.storage.preparations_used(), 0);
        assert_eq!(binding_reply(&fds), Some(proto_fs::PERMISSION));
        ram.begin_binding(&mut fds).unwrap();
        assert_eq!(binding_reply(&fds), None);
        assert_eq!(ram.storage.preparations_used(), 1);
        ram.complete_binding(&mut fds, 0);
        assert_eq!(binding_reply(&fds), Some(0));
        assert_eq!(ram.storage.preparations_used(), 0);
    }

    #[test]
    fn canonical_denial_returns_permission_before_retained_admission_is_reset() {
        let mut kernel = kernel(ResultKind::Denied);
        let mut admission = Admission::Unvouched;
        visit(&mut admission, 31, &mut kernel).unwrap();
        assert_eq!(
            visit(&mut admission, 31, &mut kernel),
            Err(proto_fs::PERMISSION)
        );
        assert!(matches!(
            admission,
            Admission::Transport(Transport {
                state: State::Copy { owner: None, .. },
                ..
            })
        ));
        let Admission::Transport(transport) = &mut admission else {
            panic!()
        };
        let State::Copy { outcome, .. } = &mut transport.state else {
            panic!()
        };
        *outcome = proto_fs::PERMISSION;
        assert_eq!(
            visit(&mut admission, 31, &mut kernel),
            Err(proto_fs::PERMISSION)
        );
        assert!(matches!(admission, Admission::Unvouched));
        assert_eq!(
            CALLS.with(|calls| calls.borrow().clone()),
            vec![("Duplicate", u64::MAX - 1), ("Send", u64::MAX - 1)]
        );
    }

    #[test]
    fn cancellation_after_duplicate_retains_outcome_until_the_owner_is_closed() {
        let mut kernel = kernel(ResultKind::Denied);
        let mut admission = Admission::Unvouched;
        visit(&mut admission, 31, &mut kernel).unwrap();
        let Admission::Transport(transport) = &mut admission else {
            panic!()
        };
        let State::Copy { outcome, .. } = &mut transport.state else {
            panic!()
        };
        *outcome = proto_fs::PERMISSION;
        FAIL_CLOSE.with(|count| *count.borrow_mut() = 1);
        visit(&mut admission, 31, &mut kernel).unwrap();
        visit(&mut admission, 31, &mut kernel).unwrap();
        assert_eq!(
            visit(&mut admission, 31, &mut kernel),
            Err(proto_fs::PERMISSION)
        );
        assert!(matches!(admission, Admission::Unvouched));
        assert_eq!(
            CALLS.with(|calls| calls.borrow().clone()),
            vec![
                ("Duplicate", u64::MAX - 1),
                ("Close", u64::MAX - 1),
                ("Close", u64::MAX - 1)
            ]
        );
    }
}
