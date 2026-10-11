// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
extern crate std;
use super::*;
use crate::locks::{
    Kind,
    actor::{Command, Error, Response},
    wait_server,
};
use crate::{Fds, Ram, authority::Binding};
use proto_fs::{DataDescription, LockKind, WaitKey, WaitMode, WaitStart};
use proto_process::lifetimes::Page;
use std::boxed::Box;

struct Fixture {
    ram: Ram<'static>,
    locks: Box<LockService>,
    queue: Box<Queue>,
    pool: Pool,
    page: Page,
    fds: std::vec::Vec<Fds>,
    proof: Box<Proof>,
}
fn who(pid: u32) -> proto_process::WhoReply {
    proto_process::WhoReply {
        pid,
        credentials: proto_process::Credentials::NOBODY,
        generation: 1,
        loader: None,
        index: pid & 255,
        ctty: None,
        image: 1,
        groups: proto_process::Groups::EMPTY,
        limits: proto_process::ResourceLimits::initial(2 * 1024 * 1024),
        root: proto_process::ExpenditureRoot {
            pid: 10,
            generation: 1,
        },
    }
}
fn ram_fixture() -> Ram<'static> {
    let mut ram = Ram::default();
    let mut fds = Fds::default();
    let root = ram.storage.resolve(b"/").unwrap();
    for name in [b"a".as_slice(), b"b", b"c", b"unrelated"] {
        let reservation = ram
            .reserve_create(&mut fds, root, name, crate::REG)
            .unwrap();
        ram.commit_create(&mut fds, reservation).unwrap();
    }
    for index in 0..16 {
        let name = std::format!("ring{index}");
        let reservation = ram
            .reserve_create(&mut fds, root, name.as_bytes(), crate::REG)
            .unwrap();
        ram.commit_create(&mut fds, reservation).unwrap();
    }
    ram
}
impl Fixture {
    fn new() -> Self {
        let mut locks = Box::<LockService>::new_uninit();
        let mut queue = Box::<Queue>::new_uninit();
        let mut proof = Box::<Proof>::new_uninit();
        // SAFETY: complete exclusive aligned allocations initialized in place.
        let (locks, queue, proof) = unsafe {
            LockService::initialize_at(locks.as_mut_ptr());
            Queue::initialize_at(queue.as_mut_ptr());
            Proof::initialize_at(proof.as_mut_ptr());
            (
                locks.assume_init(),
                queue.assume_init(),
                proof.assume_init(),
            )
        };
        let page = Page::new();
        for pid in 256..272 {
            page.publish(pid).unwrap();
        }
        Self {
            ram: ram_fixture(),
            locks,
            queue,
            pool: Pool::new(),
            page,
            fds: std::vec::Vec::new(),
            proof,
        }
    }
    fn captured(
        &mut self,
        pid: u32,
        name: &str,
        kind: LockKind,
        slot: u32,
    ) -> (usize, WaitStart, Captured) {
        let mut fds = Fds {
            binding: Binding::Active(who(pid)),
            root: crate::storage::Root {
                id: u64::from(pid / 4),
                generation: 1,
            },
            ..Fds::default()
        };
        let fd = self.ram.open(&mut fds, name, proto_fs::READ_WRITE).unwrap();
        let (source, _) = self.ram.capture_description(&fds, fd).unwrap();
        let wire = WaitStart {
            key: WaitKey {
                slot,
                generation: 1,
            },
            description: DataDescription {
                packed: self.ram.marked_open(&fds, source).unwrap(),
                generation: source.description.generation,
            },
            mode: WaitMode::Pid,
            kind,
            whence: 0,
            start: 0,
            length: 10,
            pid: 0,
        };
        let captured = self.ram.capture_wait(&fds, wire).unwrap();
        let index = self.fds.len();
        self.fds.push(fds);
        (index, wire, captured)
    }
    fn drain(&mut self) {
        for _ in 0..4096 {
            if !self.locks.busy() {
                return;
            }
            let (storage, descriptions) = self.ram.lock_parts();
            assert!(
                self.locks
                    .step_with_owners(
                        storage,
                        |pid| self.page.live(pid),
                        |token| descriptions.live(token)
                    )
                    .visited
                    <= 8
            );
        }
        panic!("genuine actor did not drain");
    }
    fn actor(&mut self, captured: Captured) -> Result<Response, Error> {
        self.drain();
        self.locks
            .start(&mut self.ram.storage, captured.request, captured.root)
            .unwrap();
        for _ in 0..4096 {
            let (storage, descriptions) = self.ram.lock_parts();
            let progress = self.locks.step_with_owners(
                storage,
                |pid| self.page.live(pid),
                |token| descriptions.live(token),
            );
            assert!(progress.visited <= 8);
            if let Some(done) = progress.completed {
                return done;
            }
        }
        panic!("genuine actor did not finish");
    }
    fn hold(&mut self, pid: u32, name: &str, kind: LockKind) -> Captured {
        let (_, _, capture) = self.captured(pid, name, kind, 0);
        assert_eq!(self.actor(capture), Ok(Response::Changed));
        self.drain();
        capture
    }
    fn wait(&mut self, pid: u32, name: &str, slot: u32) -> RegistrationToken {
        self.wait_mode(pid, name, slot, WaitMode::Pid)
    }
    fn wait_mode(&mut self, pid: u32, name: &str, slot: u32, mode: WaitMode) -> RegistrationToken {
        let (index, mut wire, _) = self.captured(pid, name, LockKind::Write, slot);
        wire.mode = mode;
        let capture = self.ram.capture_wait(&self.fds[index], wire).unwrap();
        let id = self
            .queue
            .admit(
                index,
                index as u64 + 100,
                wire,
                capture,
                &mut self.ram.storage,
            )
            .unwrap();
        self.queue.activate(id).unwrap();
        let result = self.actor(capture);
        assert!(matches!(result, Err(Error::Conflict(_))));
        self.drain();
        let wait_server::Finish::Sleeping(token) = wait_server::finish(
            &mut self.queue,
            &mut self.pool,
            &mut self.ram,
            result,
            Some(&self.fds[index]),
            |pid| self.page.live(pid),
        )
        .unwrap() else {
            panic!("not parked")
        };
        token
    }
    fn start(&mut self, token: RegistrationToken, scan: u64) -> bool {
        let id = token.receipt();
        let captured = self.queue.snapshot(id).unwrap().0;
        self.proof.start(
            &self.queue,
            &self.pool,
            token,
            captured,
            Scope {
                owner: id.owner(),
                key: id.key(),
                scan,
            },
        )
    }
    fn step(&mut self) -> Progress {
        let (storage, descriptions) = self.ram.lock_parts();
        let mut checks = 0;
        let progress = self.proof.step(
            &self.queue,
            &self.pool,
            &self.locks,
            storage,
            |pid| {
                checks += 1;
                self.page.live(pid)
            },
            |token| descriptions.live(token),
        );
        assert!(progress.visited <= 8, "{} visits", progress.visited);
        assert!(checks <= 8);
        progress
    }
    fn finish(&mut self) -> Outcome {
        for _ in 0..8192 {
            if let Some(outcome) = self.step().outcome {
                return outcome;
            }
        }
        panic!("stable bounded proof did not finish");
    }
    fn cycle() -> (Self, RegistrationToken, RegistrationToken) {
        let mut f = Self::new();
        f.hold(256, "/a", LockKind::Write);
        f.hold(257, "/b", LockKind::Write);
        let a = f.wait(256, "/b", 0);
        let b = f.wait(257, "/a", 1);
        (f, a, b)
    }
}
#[test]
fn genuine_two_pid_cycle_and_paid_receipts_survive_read_only_proof() {
    let (mut f, a, _) = Fixture::cycle();
    let before = (
        f.queue.retained(),
        f.queue.has_work(),
        f.pool.count(),
        f.locks.counts(),
    );
    assert!(f.start(a, 1));
    let outcome = f.finish();
    assert_eq!(outcome.verdict, Verdict::Deadlock);
    assert_eq!(outcome.candidate, a.receipt());
    assert_eq!(outcome.captured, f.queue.snapshot(a.receipt()).unwrap().0);
    assert_eq!(
        (
            f.queue.retained(),
            f.queue.has_work(),
            f.pool.count(),
            f.locks.counts()
        ),
        before
    );
    assert!(!f.locks.busy());
    assert!(f.start(a, 2));
    assert_eq!(f.finish().verdict, Verdict::Deadlock);
    assert!(!f.start(a, 2));
    println!(
        "WAIT proof geometry Graph={} Pool={} Proof={} Reader={}",
        core::mem::size_of::<Graph>(),
        core::mem::size_of::<Pool>(),
        core::mem::size_of::<Proof>(),
        core::mem::size_of::<Reader>()
    );
}
#[test]
fn every_real_blocker_and_every_same_pid_registration_contribute_edges() {
    let mut f = Fixture::new();
    f.hold(256, "/a", LockKind::Write);
    // First published blocker is unrelated; the second creates the cycle.
    f.hold(257, "/b", LockKind::Read);
    f.hold(258, "/b", LockKind::Read);
    f.hold(259, "/c", LockKind::Write);
    let a = f.wait(256, "/b", 0);
    f.wait(257, "/c", 1); // first registration has no edge back
    f.wait(257, "/a", 2); // second registration closes the cycle
    assert!(f.start(a, 1));
    assert_eq!(f.finish().verdict, Verdict::Deadlock);
}
#[test]
fn unrelated_cycle_never_becomes_candidate_deadlock() {
    let mut f = Fixture::new();
    f.hold(257, "/b", LockKind::Write);
    f.hold(258, "/c", LockKind::Write);
    let a = f.wait(256, "/b", 0);
    f.wait(257, "/c", 1);
    f.wait(258, "/b", 2);
    assert!(f.start(a, 1));
    assert_eq!(f.finish().verdict, Verdict::NoCycle);
}
#[test]
fn candidate_actor_attempt_and_cancel_invalidate_pending_proof() {
    for cancel in [false, true] {
        let (mut f, a, _) = Fixture::cycle();
        assert!(f.start(a, 1));
        for _ in 0..5 {
            f.step();
        }
        if cancel {
            f.queue.request_cancel(a.receipt()).unwrap();
        } else {
            f.pool.ready(a).unwrap();
            f.pool.run(a).unwrap();
            f.queue.ready(a.receipt()).unwrap();
        }
        assert_eq!(f.finish().verdict, Verdict::Deferred);
        assert!(!f.start(a, 2));
    }
}
#[test]
fn positively_used_registration_cannot_leave_and_return_to_same_phase() {
    let (mut f, a, b) = Fixture::cycle();
    assert!(f.start(a, 1));
    for _ in 0..4096 {
        f.step();
        if matches!(f.proof.phase, Phase::Verify(_)) {
            break;
        }
    }
    assert!(matches!(f.proof.phase, Phase::Verify(_)));
    f.pool.ready(b).unwrap();
    f.pool.run(b).unwrap();
    f.pool.sleep(b).unwrap();
    assert_eq!(f.finish().verdict, Verdict::Deferred);
}
#[test]
fn full_page_lifetime_and_local_pid_revocation_both_prevent_stale_cycle() {
    for logical in [false, true] {
        let (mut f, a, _) = Fixture::cycle();
        assert!(f.start(a, 1));
        for _ in 0..4096 {
            f.step();
            if matches!(f.proof.phase, Phase::Graph) && f.proof.used.count_ones() == 2 {
                break;
            }
        }
        if logical {
            f.locks.depart_pid(257).unwrap();
            assert!(f.page.live(257));
        } else {
            assert!(f.page.retire(257));
            f.page.publish(513).unwrap();
        }
        assert_ne!(f.finish().verdict, Verdict::Deadlock);
    }
}
#[test]
fn genuine_inode_revision_changes_rebuild_twice_then_defer_without_global_reset() {
    let (mut f, a, _) = Fixture::cycle();
    assert!(f.start(a, 1));
    let mut mutations = 0;
    for _ in 0..8192 {
        if matches!(f.proof.phase, Phase::Read { .. }) && mutations < 3 {
            let index = match f.proof.phase {
                Phase::Read { seed, .. } => seed,
                _ => unreachable!(),
            };
            let mut capture = f.proof.seeds[index].unwrap().captured;
            capture.request.owner = Owner::Process(270);
            capture.request.range =
                crate::locks::Range::relative(0, 40 + mutations as i64, 1).unwrap();
            capture.request.command = Command::Set(Some(Kind::Read));
            assert_eq!(f.actor(capture), Ok(Response::Changed));
            f.drain();
            mutations += 1;
        }
        if let Some(outcome) = f.step().outcome {
            assert_eq!(mutations, 3);
            assert_eq!(outcome.verdict, Verdict::Deferred);
            assert!(f.start(a, 2));
            assert_eq!(f.finish().verdict, Verdict::Deadlock);
            return;
        }
    }
    panic!("dirty proof did not defer");
}
#[test]
fn unrelated_inode_and_arrival_do_not_reset_a_proven_candidate() {
    let (mut f, a, _) = Fixture::cycle();
    assert!(f.start(a, 1));
    for _ in 0..4096 {
        f.step();
        if matches!(f.proof.phase, Phase::Verify(_)) {
            break;
        }
    }
    f.hold(258, "/unrelated", LockKind::Write);
    f.wait(259, "/unrelated", 2);
    assert_eq!(f.finish().verdict, Verdict::Deadlock);
}
#[test]
fn completed_candidate_cannot_reuse_saved_deadlock_outcome() {
    let (mut f, a, _) = Fixture::cycle();
    assert!(f.start(a, 1));
    assert_eq!(f.finish().verdict, Verdict::Deadlock);
    f.queue.request_cancel(a.receipt()).unwrap();
    assert_eq!(f.step().outcome.unwrap().verdict, Verdict::Deferred);
}

#[test]
fn reused_used_registration_and_full_terminal_receipt_are_never_new_authority() {
    let (mut f, a, b) = Fixture::cycle();
    assert!(f.start(a, 1));
    for _ in 0..4096 {
        f.step();
        if matches!(f.proof.phase, Phase::Verify(_)) {
            break;
        }
    }
    assert!(matches!(f.proof.phase, Phase::Verify(_)));
    f.queue.request_cancel(b.receipt()).unwrap();
    f.pool.complete(b).unwrap();
    f.queue.release(b.receipt(), &mut f.ram.storage).unwrap();
    let new = f.wait(257, "/a", 2);
    assert_eq!(new.slot(), b.slot());
    assert_ne!(new, b);
    assert_eq!(f.finish().verdict, Verdict::Deferred);
}
#[test]
fn real_ofd_waiter_declines_optional_pid_cycle_and_saturated_stamp_is_not_an_errno() {
    let mut f = Fixture::new();
    f.hold(256, "/a", LockKind::Write);
    let ofd = f.wait_mode(257, "/a", 0, WaitMode::Ofd);
    assert!(!f.start(ofd, 1));
    assert_eq!(
        f.queue.snapshot(ofd.receipt()).unwrap().1,
        ReceiptPhase::Sleeping
    );
    assert_eq!(f.pool.count(), 1);
    let (mut f, a, _) = Fixture::cycle();
    f.pool.set_test_proof_revision(a, u64::MAX);
    assert!(!f.start(a, 1));
    assert_eq!(
        f.queue.snapshot(a.receipt()).unwrap().1,
        ReceiptPhase::Sleeping
    );
    assert_eq!(f.pool.count(), 2);
}
#[test]
fn final_positive_registration_checks_happen_after_all_reader_watch_barriers() {
    let (mut f, a, b) = Fixture::cycle();
    assert!(f.start(a, 1));
    for _ in 0..4096 {
        f.step();
        if matches!(f.proof.phase, Phase::Verify(_)) {
            break;
        }
    }
    assert!(matches!(f.proof.phase, Phase::Verify(_)));
    f.queue.request_cancel(b.receipt()).unwrap();
    assert_eq!(f.finish().verdict, Verdict::Deferred);
}

#[test]
fn sixteen_full_pid_cycle_and_scratch_reuse_keep_every_portion_bounded() {
    let mut f = Fixture::new();
    for index in 0..16 {
        f.hold(256 + index, &std::format!("/ring{index}"), LockKind::Write);
    }
    let tokens: std::vec::Vec<_> = (0..16)
        .map(|index| {
            f.wait(
                256 + index,
                &std::format!("/ring{}", (index + 1) % 16),
                index,
            )
        })
        .collect();
    assert_eq!(f.pool.count(), 16);
    for (scan, token) in [(1, tokens[0]), (2, tokens[15])] {
        assert!(f.start(token, scan));
        assert_eq!(f.finish().verdict, Verdict::Deadlock);
    }
}
#[test]
fn actual_ofd_lifetime_callback_observes_dead_description_despite_group_pin() {
    let mut f = Fixture::new();
    let (index, mut wire, _) = f.captured(256, "/a", LockKind::Write, 0);
    wire.mode = WaitMode::Ofd;
    let captured = f.ram.capture_wait(&f.fds[index], wire).unwrap();
    assert_eq!(f.actor(captured), Ok(Response::Changed));
    f.drain();
    let token = f.wait(257, "/a", 1);
    f.ram
        .close(&mut f.fds[index], wire.description.fd())
        .unwrap();
    assert!(f.locks.counts().published > 0);
    assert!(f.start(token, 1));
    let mut dead_checks = 0;
    for _ in 0..8192 {
        let (storage, descriptions) = f.ram.lock_parts();
        let progress = f.proof.step(
            &f.queue,
            &f.pool,
            &f.locks,
            storage,
            |pid| f.page.live(pid),
            |description| {
                assert_eq!(description, captured.source.description);
                let live = descriptions.live(description);
                if !live {
                    dead_checks += 1;
                }
                live
            },
        );
        assert!(progress.visited <= 8);
        if let Some(outcome) = progress.outcome {
            assert_eq!(outcome.verdict, Verdict::NoCycle);
            assert!(dead_checks > 0);
            return;
        }
    }
    panic!("OFD callback proof did not finish");
}

#[test]
fn final_exact_inode_barrier_rejects_edges_removed_after_genuine_readers() {
    let (mut f, a, _) = Fixture::cycle();
    let extra = f.hold(257, "/unrelated", LockKind::Write);
    assert!(f.start(a, 1));
    for _ in 0..4096 {
        f.step();
        if matches!(f.proof.phase, Phase::Graph) && f.proof.used.count_ones() == 2 {
            break;
        }
    }
    assert!(matches!(f.proof.phase, Phase::Graph));
    assert_eq!(f.proof.used.count_ones(), 2);
    let (_, _, mut unlocked) = f.captured(257, "/b", LockKind::Write, 3);
    unlocked.request.command = Command::Set(None);
    assert_eq!(f.actor(unlocked), Ok(Response::Changed));
    f.drain();
    assert!(f.page.live(257) && f.locks.pid_visible(257));
    assert!(f.ram.storage.node(extra.request.inode).is_ok());
    assert_eq!(f.finish().verdict, Verdict::NoCycle);
}

#[test]
fn positive_outcome_carries_direct_registration_and_never_other_receipt_or_reuse() {
    let (mut f, a, _) = Fixture::cycle();
    // Same payer, inode, range and kind; a different full PID and full receipt.
    let other = f.wait(258, "/b", 2);
    assert!(f.start(a, 1));
    let outcome = f.finish();
    assert_eq!(outcome.registration, a);
    assert_eq!(outcome.sleeping_registration(&f.queue, &f.pool), Some(a));
    let wrong = Outcome {
        registration: other,
        ..outcome
    };
    assert_eq!(wrong.sleeping_registration(&f.queue, &f.pool), None);
    f.pool.ready(a).unwrap();
    assert_eq!(outcome.sleeping_registration(&f.queue, &f.pool), None);
    f.pool.run(a).unwrap();
    f.pool.sleep(a).unwrap();
    f.queue.request_cancel(a.receipt()).unwrap();
    assert_eq!(outcome.sleeping_registration(&f.queue, &f.pool), None);
    f.pool.complete(a).unwrap();
    f.queue.release(a.receipt(), &mut f.ram.storage).unwrap();
    let reused = f.wait(256, "/b", 3);
    assert_eq!(reused.slot(), a.slot());
    assert_ne!(reused.receipt(), a.receipt());
    assert_eq!(outcome.sleeping_registration(&f.queue, &f.pool), None);
}
