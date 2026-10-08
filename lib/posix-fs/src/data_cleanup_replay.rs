// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

extern crate std;
use super::*;
use core::mem::ManuallyDrop;
use ramfs::{
    Fds, REG, Ram,
    data::Journal,
    storage::{NONE, ROOT, Root},
};
use rt::{
    Handle,
    fs::{Files, PreparedOpen},
    handle::Channel,
};
use std::vec::Vec;

struct Job {
    key: OpenKey,
    id: u64,
    charge: u16,
    journal: Journal,
}
struct Server {
    ram: Ram<'static>,
    fds: Fds,
    jobs: Vec<Job>,
    serial: u64,
    calls: usize,
    releases: usize,
    conflicts: usize,
}
impl Server {
    fn new() -> (Self, ManuallyDrop<PosixFs>, [u32; 2]) {
        let root = Root {
            id: 27,
            generation: 4,
        };
        // SAFETY: State contains integers, booleans and optional integer accounts,
        // matching the RAM library's own zeroed host fixture.
        let state = std::boxed::Box::leak(unsafe {
            std::boxed::Box::<ramfs::storage::State>::new_zeroed().assume_init()
        });
        state.initialize();
        let data = std::boxed::Box::leak(
            std::vec![0; ramfs::storage::PAGES * ramfs::storage::PAGE].into_boxed_slice(),
        );
        let mut ram = Ram::with_storage(proto_fs::Timestamp::ZERO, state, data, None);
        let reservation = ram
            .storage
            .reserve(root, ROOT, b"parallel-append", (REG, 0o600, 0, 0))
            .unwrap();
        let inode = ram.storage.commit(reservation).unwrap();
        let mut fds = Fds::default();
        fds.root = root;
        let mut client = ManuallyDrop::new(
            PosixFs::from_files(Files::from_sessions(
                Handle::<Channel>::from_raw(rt::abi::Handle::new(7, 9)),
                None,
            ))
            .unwrap(),
        );
        let mut local = [0; 2];
        for fd in &mut local {
            let held = ram
                .prepare_open_token(
                    &mut fds,
                    inode,
                    proto_fs::READ_WRITE | proto_fs::APPEND,
                    ramfs::authority::Identity {
                        uid: 0,
                        gid: 0,
                        groups: proto_process::Groups::EMPTY,
                    },
                    None,
                )
                .unwrap();
            let remote = ram.publish_open(&mut fds, held).unwrap();
            let (captured, _) = ram.capture_description(&fds, remote).unwrap();
            let target = Target::Ram(
                crate::RamTarget::from_prepared(PreparedOpen {
                    fd: remote,
                    slot: captured.description.slot as u32,
                    generation: captured.description.generation,
                    random: false,
                })
                .unwrap(),
            );
            *fd = client
                .insert(target, crate::DescriptorFlags::default())
                .unwrap();
        }
        (
            Self {
                ram,
                fds,
                jobs: Vec::new(),
                serial: 0,
                calls: 0,
                releases: 0,
                conflicts: 0,
            },
            client,
            local,
        )
    }
    fn admit(&mut self, request: DataStart, input: &[u8]) -> Result<u64, u32> {
        if !self.fds.preparation_available() {
            return Err(proto_fs::TOO_MANY_OPEN_FILES);
        }
        assert!(self.jobs.len() < ramfs::storage::PREPARATIONS);
        let charge = self.ram.storage.charge_preparation(self.fds.root)?;
        let mut journal = Journal::capture(&mut self.ram, &self.fds, request)?;
        journal.feed(0, input)?;
        self.serial += 1;
        let id = self.serial << 8;
        *self.fds.resolvers.iter_mut().find(|n| **n == 0).unwrap() = id;
        self.jobs.push(Job {
            key: request.key,
            id,
            charge,
            journal,
        });
        Ok(id)
    }
    fn complete(&mut self, id: u64) -> DataOutcome {
        let job = self.jobs.iter_mut().find(|j| j.id == id).unwrap();
        loop {
            while !job.journal.step(&mut self.ram).unwrap() {}
            match job
                .journal
                .commit(&mut self.ram, Some(proto_fs::Timestamp::ZERO))
            {
                Ok(_) => break,
                Err(proto_fs::RESOLVING) => {
                    self.conflicts += 1;
                    continue;
                }
                Err(code) => panic!("unexpected commit {code}"),
            }
        }
        job.journal.outcome(id)
    }
    // The exact ordered Data branch of main.rs cancel_job_mode is mirrored here:
    // cancel_step visit returns RESOLVING even if that visit completes the debt;
    // a completed Cancel retains the cache, ACK releases charge on a later visit.
    fn cleanup(&mut self, key: OpenKey, ack: bool) -> Result<(), Status> {
        self.calls += 1;
        let Some(i) = self.jobs.iter().position(|j| j.key == key) else {
            return if ack {
                Err(Status::Unknown(proto_fs::OPEN_RETIRED))
            } else {
                Ok(())
            };
        };
        let job = &mut self.jobs[i];
        if !job.journal.cleanup_done() {
            job.journal.cancel_step(&mut self.ram).unwrap();
            return Err(Status::Unknown(proto_fs::RESOLVING));
        }
        if !ack {
            return Ok(());
        }
        if job.charge != NONE {
            self.ram.storage.release_preparation(job.charge);
            job.charge = NONE;
            return Err(Status::Unknown(proto_fs::RESOLVING));
        }
        let job = self.jobs.remove(i);
        *self
            .fds
            .resolvers
            .iter_mut()
            .find(|n| **n == job.id)
            .unwrap() = 0;
        Ok(())
    }
}
impl CleanupEffects for Server {
    fn cancel(&mut self, key: OpenKey) -> Result<(), Status> {
        self.cleanup(key, false)
    }
    fn ack(&mut self, key: OpenKey) -> Result<(), Status> {
        self.cleanup(key, true)
    }
    fn release(&mut self, target: Option<Target>) -> Result<(), FsError> {
        // Both published descriptors remain live; operation pin release never closes them.
        assert!(target.is_none());
        self.releases += 1;
        Ok(())
    }
}
fn admitted(
    server: &mut Server,
    client: &mut PosixFs,
    fd: u32,
    owner: OwnerToken,
    input: &[u8],
) -> Result<(ScalarToken, ScalarClaimToken, u64), u32> {
    let (token, claim, _) = client
        .begin_data(owner, fd, DataKind::Write, input.len() as u32, 0, input)
        .unwrap();
    let request = snapshot_request(client, claim);
    let id = server.admit(request, input)?;
    client
        .set_data_progress(claim, Phase::Feeding, id, 0)
        .unwrap();
    client
        .set_data_progress(claim, Phase::Preparing, id, input.len() as u16)
        .unwrap();
    client
        .set_data_progress(claim, Phase::Ready, id, input.len() as u16)
        .unwrap();
    client
        .set_data_progress(claim, Phase::Committing, id, input.len() as u16)
        .unwrap();
    let job = server.jobs.iter_mut().find(|j| j.id == id).unwrap();
    while !job.journal.step(&mut server.ram).unwrap() {}
    Ok((token, claim, id))
}
fn completed(
    server: &mut Server,
    client: &mut PosixFs,
    fd: u32,
    owner: OwnerToken,
    input: &[u8],
) -> Result<ScalarToken, u32> {
    let (token, claim, id) = admitted(server, client, fd, owner, input)?;
    let outcome = server.complete(id);
    client
        .save_data_result(claim, outcome, &[], |_| 24)
        .unwrap();
    Ok(token)
}
fn snapshot_request(client: &PosixFs, claim: ScalarClaimToken) -> DataStart {
    client.data_start_context(claim).unwrap().0.request
}
#[test]
fn old_one_cancel_returns_emfile_from_remote_local16_with_two_append_descriptions() {
    let (mut server, mut client, fds) = Server::new();
    for n in 0..16 {
        let owner = OwnerToken::new(1 + n % 2).unwrap();
        let token = completed(
            &mut server,
            &mut client,
            fds[n as usize % 2],
            owner,
            &[b'A' + (n % 2) as u8],
        )
        .unwrap();
        let context = client.begin_data_cleanup(token).unwrap();
        assert!(context.send_with(&mut server).is_err());
        assert_eq!(
            client.acknowledge_data(token, owner, &mut []).unwrap(),
            ScalarResult::Bytes(1)
        );
    }
    assert_eq!(server.fds.preparation_count(), 16);
    assert_eq!(server.ram.storage.preparations_used(), 16);
    assert_eq!(client.data_tokens().count(), 16);
    let result = completed(
        &mut server,
        &mut client,
        fds[0],
        OwnerToken::new(1).unwrap(),
        b"A",
    );
    assert_eq!(result, Err(proto_fs::TOO_MANY_OPEN_FILES));
}
#[test]
fn exact_cleanup_replies_settle_twenty_overlapping_append_results() {
    let (mut server, mut client, fds) = Server::new();
    for _ in 0..10 {
        let first = admitted(
            &mut server,
            &mut client,
            fds[0],
            OwnerToken::new(1).unwrap(),
            b"A",
        )
        .unwrap();
        let second = admitted(
            &mut server,
            &mut client,
            fds[1],
            OwnerToken::new(2).unwrap(),
            b"B",
        )
        .unwrap();
        assert_eq!(server.fds.preparation_count(), 2);
        let pair = [
            (OwnerToken::new(1).unwrap(), first),
            (OwnerToken::new(2).unwrap(), second),
        ];
        for (_, (_, claim, id)) in pair {
            let outcome = server.complete(id);
            client
                .save_data_result(claim, outcome, &[], |_| 24)
                .unwrap();
        }
        let mut settled = [false; 2];
        let mut pending = [0; 2];
        for _ in 0..32 {
            for (i, (owner, (token, _, _))) in pair.iter().copied().enumerate() {
                if settled[i] {
                    continue;
                }
                let context = client.begin_data_cleanup(token).unwrap();
                client.validate_data_cleanup_context(&context).unwrap();
                match context.attempt_with(&mut server) {
                    Ok(proof) => {
                        client
                            .finish_data_cleanup_from_context(&context, proof)
                            .unwrap();
                        settled[i] = true;
                    }
                    Err(failure) => {
                        assert_eq!(failure.disposition(), CleanupDisposition::Retry);
                        pending[i] += 1;
                        assert_eq!(client.data_state(token).unwrap().owner, Some(owner));
                    }
                }
            }
            if settled.iter().all(|done| *done) {
                break;
            }
        }
        assert_eq!(settled, [true; 2]);
        assert!(pending[0] > 0 && pending[1] > 0);
        for (owner, (token, _, _)) in pair {
            assert_eq!(
                client.acknowledge_data(token, owner, &mut []).unwrap(),
                ScalarResult::Bytes(1)
            );
        }
        assert_eq!(server.jobs.len(), 0);
        assert_eq!(server.ram.storage.preparations_used(), 0);
        assert_eq!(client.data_tokens().count(), 0);
    }
    assert_eq!(server.conflicts, 10);
    let inode = server.ram.storage.lookup(ROOT, b"parallel-append").unwrap();
    let mut out = [0; 20];
    assert_eq!(server.ram.storage.read(inode, 0, &mut out).unwrap(), 20);
    assert_eq!(out.iter().filter(|b| **b == b'A').count(), 10);
    assert_eq!(out.iter().filter(|b| **b == b'B').count(), 10);
    assert_eq!(server.releases, 20);
    assert!(server.calls > 40);
}

#[test]
fn cached_failure_keeps_two_private_pages_until_separate_cleanup_visits() {
    let (mut server, mut client, fds) = Server::new();
    let owner = OwnerToken::new(1).unwrap();
    // Sparse EOF positions the actual append range across the 4096-byte boundary.
    let inode = server.ram.storage.lookup(ROOT, b"parallel-append").unwrap();
    server.ram.storage.node_mut(inode).unwrap().length = 4095;
    let before = server.ram.storage.usage(server.fds.root);
    let (token, claim, id) = admitted(&mut server, &mut client, fds[0], owner, b"AB").unwrap();
    assert_eq!(
        server.ram.storage.usage(server.fds.root).pages,
        before.pages + 2
    );
    server.jobs[0]
        .journal
        .fail_cleanup_replay(proto_fs::NO_SPACE);
    let outcome = server.jobs[0].journal.outcome(id);
    client
        .save_data_result(claim, outcome, &[], |_| 28)
        .unwrap();
    let mut previous = server.ram.storage.usage(server.fds.root).pages;
    let mut page_releases = 0;
    let mut settled = false;
    for _ in 0..32 {
        let context = client.begin_data_cleanup(token).unwrap();
        match context.send_with(&mut server) {
            Ok(proof) => {
                client
                    .finish_data_cleanup_from_context(&context, proof)
                    .unwrap();
                settled = true;
                break;
            }
            Err(_) => {
                let state = client.data_state(token).unwrap();
                assert_eq!(state.owner, Some(owner));
                assert_eq!(state.result, Some(ScalarResult::Failed(28)));
                let current = server.ram.storage.usage(server.fds.root).pages;
                assert!(previous - current <= 1);
                if current < previous {
                    page_releases += 1;
                }
                previous = current;
            }
        }
    }
    assert!(settled);
    assert_eq!(page_releases, 2);
    assert_eq!(
        server.ram.storage.usage(server.fds.root).pages,
        before.pages
    );
    assert_eq!(
        client.acknowledge_data(token, owner, &mut []).unwrap(),
        ScalarResult::Failed(28)
    );
    assert_eq!(client.data_tokens().count(), 0);
    assert!(server.jobs.is_empty());
    assert_eq!(server.ram.storage.preparations_used(), 0);
}

#[test]
fn cleanup_status_dispositions_never_turn_failure_into_done_or_new_effect() {
    assert_eq!(
        cleanup_disposition(CleanupStage::Cancel, Status::Unknown(proto_fs::RESOLVING)),
        CleanupDisposition::Retry
    );
    assert_eq!(
        cleanup_disposition(
            CleanupStage::Cancel,
            Status::Kernel(rt::abi::Error::Interrupted)
        ),
        CleanupDisposition::Retain
    );
    assert_eq!(
        cleanup_disposition(
            CleanupStage::Cancel,
            Status::Kernel(rt::abi::Error::Unknown(777))
        ),
        CleanupDisposition::Retain
    );
    assert_eq!(
        cleanup_disposition(CleanupStage::Cancel, Status::Unknown(9999)),
        CleanupDisposition::Retain
    );
    assert_eq!(
        cleanup_disposition(
            CleanupStage::Cancel,
            Status::Unknown(proto_fs::OPEN_RETIRED)
        ),
        CleanupDisposition::Retain
    );
    assert_eq!(
        cleanup_disposition(CleanupStage::Ack, Status::Unknown(proto_fs::OPEN_RETIRED)),
        CleanupDisposition::Continue
    );
    assert_eq!(
        cleanup_disposition(
            CleanupStage::Cancel,
            Status::Kernel(rt::abi::Error::PeerClosed)
        ),
        CleanupDisposition::Abandon
    );
}

struct Fault<'a> {
    server: &'a mut Server,
    stage: CleanupStage,
    error: Status,
    cancel_calls: usize,
    ack_calls: usize,
}
impl CleanupEffects for Fault<'_> {
    fn cancel(&mut self, key: OpenKey) -> Result<(), Status> {
        self.cancel_calls += 1;
        if self.stage == CleanupStage::Cancel {
            Err(self.error)
        } else {
            self.server.cancel(key)
        }
    }
    fn ack(&mut self, key: OpenKey) -> Result<(), Status> {
        self.ack_calls += 1;
        if self.stage == CleanupStage::Ack {
            Err(self.error)
        } else {
            self.server.ack(key)
        }
    }
    fn release(&mut self, target: Option<Target>) -> Result<(), FsError> {
        self.server.release(target)
    }
}
#[test]
fn native_pending_unknown_and_nonretryable_keep_exact_cached_result_and_debt() {
    for (status, disposition) in [
        (
            Status::Unknown(proto_fs::RESOLVING),
            CleanupDisposition::Retry,
        ),
        (Status::Unknown(9999), CleanupDisposition::Retain),
        (
            Status::Kernel(rt::abi::Error::Unknown(777)),
            CleanupDisposition::Retain,
        ),
        (
            Status::Kernel(rt::abi::Error::Interrupted),
            CleanupDisposition::Retain,
        ),
        (
            Status::Kernel(rt::abi::Error::PeerClosed),
            CleanupDisposition::Abandon,
        ),
        (
            Status::Unknown(proto_fs::OPEN_RETIRED),
            CleanupDisposition::Retain,
        ),
    ] {
        let (mut server, mut client, fds) = Server::new();
        let owner = OwnerToken::new(1).unwrap();
        let token = completed(&mut server, &mut client, fds[0], owner, b"A").unwrap();
        let context = client.begin_data_cleanup(token).unwrap();
        let mut fault = Fault {
            server: &mut server,
            stage: CleanupStage::Cancel,
            error: status,
            cancel_calls: 0,
            ack_calls: 0,
        };
        let Err(failure) = context.attempt_with(&mut fault) else {
            panic!("no proof on failed Cancel")
        };
        assert_eq!(failure.disposition(), disposition);
        assert_eq!(fault.cancel_calls, 1);
        assert_eq!(fault.ack_calls, 0);
        assert_eq!(fault.server.releases, 0);
        assert_eq!(
            client.data_state(token).unwrap().result,
            Some(ScalarResult::Bytes(1))
        );
        assert_eq!(client.data_state(token).unwrap().owner, Some(owner));
        assert_eq!(fault.server.ram.storage.preparations_used(), 1);
        if disposition == CleanupDisposition::Abandon {
            // Returning the original cached result detaches its owner without minting cleanup.
            assert_eq!(
                client.acknowledge_data(token, owner, &mut []).unwrap(),
                ScalarResult::Bytes(1)
            );
            assert_eq!(client.data_state(token).unwrap().owner, None);
            assert_eq!(client.data_tokens().count(), 1);
            assert_eq!(fault.server.jobs.len(), 1);
        }
    }
}
#[test]
fn local_stale_generation_foreign_key_and_session_reject_before_effects() {
    let (mut server, mut client, fds) = Server::new();
    let owner = OwnerToken::new(1).unwrap();
    let first = completed(&mut server, &mut client, fds[0], owner, b"A").unwrap();
    let second = completed(
        &mut server,
        &mut client,
        fds[1],
        OwnerToken::new(2).unwrap(),
        b"B",
    )
    .unwrap();
    let mut context = client.begin_data_cleanup(first).unwrap();
    let calls = server.calls;
    context.session ^= 1;
    assert!(client.validate_data_cleanup_context(&context).is_err());
    context.session ^= 1;
    context.cleanup.token = second;
    assert!(client.validate_data_cleanup_context(&context).is_err());
    context.cleanup.token = first;
    for _ in 0..32 {
        if let Ok(proof) = context.attempt_with(&mut server) {
            client
                .finish_data_cleanup_from_context(&context, proof)
                .unwrap();
            break;
        }
    }
    client.acknowledge_data(first, owner, &mut []).unwrap();
    let after = server.calls;
    assert!(client.validate_data_cleanup_context(&context).is_err());
    assert_eq!(server.calls, after);
    assert!(after > calls);
}

#[test]
fn ack_refusal_never_replays_commit_and_retired_ack_requires_canonical_absence() {
    for error in [
        Status::Unknown(proto_fs::RESOLVING),
        Status::Unknown(9999),
        Status::Kernel(rt::abi::Error::Unknown(777)),
        Status::Kernel(rt::abi::Error::Interrupted),
    ] {
        let (mut server, mut client, fds) = Server::new();
        let owner = OwnerToken::new(1).unwrap();
        let token = completed(&mut server, &mut client, fds[0], owner, b"A").unwrap();
        let context = client.begin_data_cleanup(token).unwrap();
        let key = key(token);
        while server.cancel(key).is_err() {}
        let mut fault = Fault {
            server: &mut server,
            stage: CleanupStage::Ack,
            error,
            cancel_calls: 0,
            ack_calls: 0,
        };
        let Err(failure) = context.attempt_with(&mut fault) else {
            panic!("no proof on refused ACK")
        };
        assert_eq!(
            failure,
            CleanupFailure::Native {
                stage: CleanupStage::Ack,
                status: error
            }
        );
        assert_eq!(fault.cancel_calls, 1);
        assert_eq!(fault.ack_calls, 1);
        assert_eq!(fault.server.jobs.len(), 1);
        assert_eq!(fault.server.releases, 0);
        assert_eq!(
            client.data_state(token).unwrap().result,
            Some(ScalarResult::Bytes(1))
        );
        assert_eq!(client.data_state(token).unwrap().owner, Some(owner));
    }
    let (mut server, mut client, fds) = Server::new();
    let owner = OwnerToken::new(1).unwrap();
    let token = completed(&mut server, &mut client, fds[0], owner, b"A").unwrap();
    let context = client.begin_data_cleanup(token).unwrap();
    while server.cancel(key(token)).is_err() {}
    while server.ack(key(token)).is_err() {}
    assert!(server.jobs.is_empty());
    let proof = context.attempt_with(&mut server).unwrap();
    client
        .finish_data_cleanup_from_context(&context, proof)
        .unwrap();
    assert_eq!(
        client.acknowledge_data(token, owner, &mut []).unwrap(),
        ScalarResult::Bytes(1)
    );
    assert_eq!(client.data_tokens().count(), 0);
    let inode = server.ram.storage.lookup(ROOT, b"parallel-append").unwrap();
    let mut bytes = [0; 2];
    assert_eq!(server.ram.storage.read(inode, 0, &mut bytes).unwrap(), 1);
    assert_eq!(bytes[0], b'A');
}

struct CachedDriver<'a, E> {
    client: &'a mut PosixFs,
    effects: &'a mut E,
    token: ScalarToken,
    requested: bool,
    cancel_after_pause: bool,
    visits: usize,
    pauses: usize,
}
impl<E: CleanupEffects> CachedCleanupEffects for CachedDriver<'_, E> {
    fn requested(&mut self) -> bool {
        self.requested
    }
    fn visit(&mut self) -> CleanupDisposition {
        self.visits += 1;
        let context = self.client.begin_data_cleanup(self.token).unwrap();
        self.client.validate_data_cleanup_context(&context).unwrap();
        match context.attempt_with(self.effects) {
            Ok(proof) => {
                self.client
                    .finish_data_cleanup_from_context(&context, proof)
                    .unwrap();
                CleanupDisposition::Continue
            }
            Err(failure) => failure.disposition(),
        }
    }
    fn pause(&mut self) -> bool {
        self.pauses += 1;
        self.requested |= self.cancel_after_pause;
        true
    }
}

#[test]
fn cached_driver_cancellation_preserves_original_result_and_paid_debt() {
    assert!(!cancel_before_result(true, true));
    assert!(cancel_before_result(false, true));
    for already_requested in [true, false] {
        let (mut server, mut client, fds) = Server::new();
        let owner = OwnerToken::new(1).unwrap();
        let token = completed(&mut server, &mut client, fds[0], owner, b"A").unwrap();
        let mut driver = CachedDriver {
            client: &mut client,
            effects: &mut server,
            token,
            requested: already_requested,
            cancel_after_pause: true,
            visits: 0,
            pauses: 0,
        };
        cleanup_cached(&mut driver);
        assert_eq!(driver.visits, usize::from(!already_requested));
        assert_eq!(driver.pauses, usize::from(!already_requested));
        assert_eq!(driver.client.data_state(token).unwrap().owner, Some(owner));
        assert_eq!(
            driver.client.data_state(token).unwrap().result,
            Some(ScalarResult::Bytes(1))
        );
        assert_eq!(
            driver
                .client
                .acknowledge_data(token, owner, &mut [])
                .unwrap(),
            ScalarResult::Bytes(1)
        );
        assert_eq!(driver.client.data_state(token).unwrap().owner, None);
        assert_eq!(server.ram.storage.preparations_used(), 1);
        assert_eq!(server.releases, 0);
    }
}

#[test]
fn cached_driver_retries_actual_cleanup_to_canonical_proof() {
    let (mut server, mut client, fds) = Server::new();
    let owner = OwnerToken::new(1).unwrap();
    let token = completed(&mut server, &mut client, fds[0], owner, b"A").unwrap();
    let mut driver = CachedDriver {
        client: &mut client,
        effects: &mut server,
        token,
        requested: false,
        cancel_after_pause: false,
        visits: 0,
        pauses: 0,
    };
    cleanup_cached(&mut driver);
    assert!(driver.visits > 1);
    assert_eq!(driver.pauses + 1, driver.visits);
    assert_eq!(
        driver
            .client
            .acknowledge_data(token, owner, &mut [])
            .unwrap(),
        ScalarResult::Bytes(1)
    );
    assert_eq!(driver.client.data_tokens().count(), 0);
    assert_eq!(server.ram.storage.preparations_used(), 0);
    assert!(server.jobs.is_empty());
}

#[test]
fn cached_driver_nonretryable_returns_cached_failure_without_proof_or_spin() {
    for status in [
        Status::Kernel(rt::abi::Error::Unknown(777)),
        Status::Kernel(rt::abi::Error::Interrupted),
        Status::Kernel(rt::abi::Error::PeerClosed),
        Status::Unknown(proto_fs::OPEN_RETIRED),
    ] {
        let (mut server, mut client, fds) = Server::new();
        let owner = OwnerToken::new(1).unwrap();
        let (token, claim, id) = admitted(&mut server, &mut client, fds[0], owner, b"A").unwrap();
        server.jobs[0]
            .journal
            .fail_cleanup_replay(proto_fs::NO_SPACE);
        let outcome = server.jobs[0].journal.outcome(id);
        client
            .save_data_result(claim, outcome, &[], |_| 28)
            .unwrap();
        let mut fault = Fault {
            server: &mut server,
            stage: CleanupStage::Cancel,
            error: status,
            cancel_calls: 0,
            ack_calls: 0,
        };
        let mut driver = CachedDriver {
            client: &mut client,
            effects: &mut fault,
            token,
            requested: false,
            cancel_after_pause: false,
            visits: 0,
            pauses: 0,
        };
        cleanup_cached(&mut driver);
        assert_eq!(driver.visits, 1);
        assert_eq!(driver.pauses, 0);
        assert_eq!(
            driver
                .client
                .acknowledge_data(token, owner, &mut [])
                .unwrap(),
            ScalarResult::Failed(28)
        );
        assert_eq!(driver.client.data_state(token).unwrap().owner, None);
        assert_eq!(fault.cancel_calls, 1);
        assert_eq!(fault.ack_calls, 0);
        assert_eq!(server.releases, 0);
        assert_eq!(server.ram.storage.preparations_used(), 1);
    }
}
