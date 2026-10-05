// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Paid data records retain immutable arguments and read bytes until local acknowledgment.
//! The caller serializes local transitions and sends requests after unlocking.

use super::{FsError, PosixFs, Target, Transport};
pub use posix_fd::{
    OwnerToken, ScalarAbandoned, ScalarClaim, ScalarClaimToken, ScalarCleanup, ScalarPhase,
    ScalarResult, ScalarSnapshot, ScalarToken, WaitValue,
};
use proto_fs::{DataDescription, DataStart, OpenKey};
pub use proto_fs::{DataKind, DataOutcome, DataPhase, DataResult};
use proto_wire::Status;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Phase {
    Starting,
    Feeding,
    Preparing,
    Ready,
    Committing,
    Completed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::ManuallyDrop;
    use rt::{
        Handle,
        fs::{Files, PreparedOpen},
        handle::Channel,
    };

    fn owner(n: u64) -> OwnerToken {
        OwnerToken::new(n).unwrap()
    }
    fn files() -> ManuallyDrop<PosixFs> {
        ManuallyDrop::new(
            PosixFs::from_files(Files::from_sessions(
                Handle::<Channel>::from_raw(rt::abi::Handle::new(7, 9)),
                None,
            ))
            .unwrap(),
        )
    }
    fn target(generation: u64) -> Target {
        Target::Ram(
            super::super::RamTarget::from_prepared(PreparedOpen {
                fd: 3,
                slot: 17,
                generation,
                random: false,
            })
            .unwrap(),
        )
    }
    fn begin(
        fs: &mut PosixFs,
        kind: DataKind,
        count: u32,
        input: &[u8],
    ) -> (ScalarToken, ScalarClaimToken) {
        let fd = fs
            .insert(target(43), super::super::DescriptorFlags::default())
            .unwrap();
        let (token, claim, _) = fs.begin_data(owner(1), fd, kind, count, 0, input).unwrap();
        (token, claim)
    }
    fn committing(fs: &mut PosixFs, token: ScalarToken, claim: ScalarClaimToken) {
        let mut r = fs.data_snapshot(token).unwrap().recovery;
        r.job = 256;
        r.feed_end = if r.kind().writes() { r.count as u16 } else { 0 };
        r.phase = Phase::Ready;
        fs.update_data(claim, r).unwrap();
        r.phase = Phase::Committing;
        fs.update_data(claim, r).unwrap();
    }
    fn done(job: u64, count: u64) -> DataOutcome {
        DataOutcome {
            job,
            phase: DataPhase::Completed,
            result: DataResult::Bytes(count),
        }
    }
    fn errno(error: FsError) -> i32 {
        match error {
            FsError::NoSpace => 28,
            _ => 5,
        }
    }
    fn cleanup_proof(context: CleanupContext) -> CleanupProof {
        // Local transition fixture supplies the exact successful native custody.
        // Real Cancel/ACK/CloseExact replies belong to the native driver gate.
        CleanupProof {
            token: context.cleanup.token,
            recovery: context.cleanup.recovery,
            last_target: context.cleanup.last_target,
            session: context.session,
        }
    }

    #[test]
    fn immutable_arguments_progress_and_exact_claim_preserve_wait_on_rejection() {
        let mut fs = files();
        let (token, claim) = begin(&mut fs, DataKind::PWrite, 3, b"abc");
        committing(&mut fs, token, claim);
        let before = fs.data_snapshot(token).unwrap();
        let wait = fs.data_wait_snapshot(token).unwrap();
        let r = before.recovery;
        for wrong in [
            Recovery { position: 1, ..r },
            Recovery { count: 4, ..r },
            Recovery {
                session_handle: rt::abi::Handle::new(7, 10).0,
                ..r
            },
            Recovery {
                kind: DataKind::Write as u8,
                ..r
            },
            Recovery { saved_len: 1, ..r },
        ] {
            assert!(fs.update_data(claim, wrong).is_err());
            assert_eq!(fs.data_snapshot(token).unwrap(), before);
            assert_eq!(fs.data_wait_snapshot(token).unwrap(), wait);
        }
        let mut wrong = r;
        wrong.bytes[1] = b'x';
        assert!(fs.update_data(claim, wrong).is_err());
        let r = fs.data_snapshot(token).unwrap().recovery;
        for phase in [
            Phase::Starting,
            Phase::Feeding,
            Phase::Preparing,
            Phase::Ready,
            Phase::Completed,
        ] {
            assert!(fs.update_data(claim, Recovery { phase, ..r }).is_err());
        }
        fs.release_data_claim(claim).unwrap();
        let ScalarClaim::Acquired { token: current, .. } = fs.claim_data(token, owner(2)).unwrap()
        else {
            panic!("helper claim");
        };
        let before = fs.data_snapshot(token).unwrap();
        assert!(fs.data_claim_snapshot(claim).is_err());
        assert!(
            fs.save_data_result(claim, done(256, 3), &[], errno)
                .is_err()
        );
        assert!(fs.update_data(claim, r).is_err());
        assert_eq!(fs.data_snapshot(token).unwrap(), before);
        assert_eq!(
            fs.data_claim_snapshot(current).unwrap().recovery.input(),
            b"abc"
        );
    }

    #[test]
    fn admission_validates_bounds_and_routes_before_spending_a_hold() {
        let mut fs = files();
        let fd = fs
            .insert(target(43), super::super::DescriptorFlags::default())
            .unwrap();
        for (kind, count, position, input) in [
            (DataKind::Write, 1013, 0, &[][..]),
            (DataKind::Read, 1017, 0, &[][..]),
            (DataKind::Read, 1, 1, &[][..]),
            (DataKind::Truncate, 1, 0, &[][..]),
            (DataKind::PRead, 0, i64::MAX as u64 + 1, &[][..]),
            (DataKind::Write, 2, 0, &b"a"[..]),
            (DataKind::Read, 1, 0, &b"a"[..]),
        ] {
            assert!(
                fs.begin_data(owner(1), fd, kind, count, position, input)
                    .is_err()
            );
        }
        let random = match target(43) {
            Target::Ram(r) => Target::Random(r),
            _ => unreachable!(),
        };
        let random_fd = fs
            .insert(random, super::super::DescriptorFlags::default())
            .unwrap();
        let pipe = fs
            .insert(Target::Pipe(4), super::super::DescriptorFlags::default())
            .unwrap();
        let tty = fs
            .insert(Target::Tty(4), super::super::DescriptorFlags::default())
            .unwrap();
        for fd in [random_fd, pipe, tty, 0] {
            assert!(
                fs.begin_data(owner(1), fd, DataKind::Read, 1, 0, &[])
                    .is_err()
            );
        }
        assert_eq!(fs.data_tokens().count(), 0);
        fs.begin_data(owner(1), random_fd, DataKind::Write, 1, 0, b"x")
            .unwrap();
        assert_eq!(fs.data_tokens().count(), 1);
    }

    #[test]
    fn read_cache_capacity_and_cleanup_order_preserve_original_result() {
        let mut fs = files();
        let (token, claim) = begin(&mut fs, DataKind::Read, 5, &[]);
        committing(&mut fs, token, claim);
        assert!(fs.begin_data_cleanup(token).is_err());
        let before = fs.data_snapshot(token).unwrap();
        for (outcome, bytes) in [
            (done(512, 3), &b"abc"[..]),
            (done(256, 6), &b"abcdef"[..]),
            (done(256, 3), &b"ab"[..]),
        ] {
            assert!(fs.save_data_result(claim, outcome, bytes, errno).is_err());
        }
        assert_eq!(fs.data_snapshot(token).unwrap(), before);
        fs.save_data_result(claim, done(256, 3), b"abc", errno)
            .unwrap();
        assert!(
            fs.save_data_result(claim, done(256, 2), b"xy", errno)
                .is_err()
        );
        let completed = fs.data_snapshot(token).unwrap();
        assert!(fs.acknowledge_data(token, owner(1), &mut [0; 2]).is_err());
        assert!(fs.acknowledge_data(token, owner(2), &mut [0; 3]).is_err());
        assert_eq!(fs.data_snapshot(token).unwrap(), completed);
        let cleanup = cleanup_proof(fs.begin_data_cleanup(token).unwrap());
        fs.finish_data_cleanup(cleanup).unwrap();
        assert_eq!(fs.data_snapshot(token).unwrap().owner, Some(owner(1)));
        let mut out = [0; 8];
        assert_eq!(
            fs.acknowledge_data(token, owner(1), &mut out).unwrap(),
            ScalarResult::Bytes(3)
        );
        assert_eq!(&out[..3], b"abc");
        assert!(fs.data_snapshot(token).is_err());
    }

    #[test]
    fn helper_end_requeries_cache_and_owner_end_revokes_effect_authority() {
        let mut fs = files();
        let (token, original) = begin(&mut fs, DataKind::PRead, 3, &[]);
        committing(&mut fs, token, original);
        fs.release_data_claim(original).unwrap();
        let ScalarClaim::Acquired { token: helper, .. } = fs.claim_data(token, owner(2)).unwrap()
        else {
            panic!("helper claim");
        };
        assert!(
            matches!(fs.abandon_data_owner(owner(2)), Some(ScalarAbandoned::ClaimReleased(t)) if t == token)
        );
        let ScalarClaim::Acquired { token: sibling, .. } = fs.claim_data(token, owner(3)).unwrap()
        else {
            panic!("sibling claim");
        };
        assert!(
            fs.save_data_result(helper, done(256, 3), b"old", errno)
                .is_err()
        );
        fs.save_data_result(sibling, done(256, 3), b"new", errno)
            .unwrap();
        let cleanup = cleanup_proof(fs.begin_data_cleanup(token).unwrap());
        let mut out = [0; 3];
        fs.acknowledge_data(token, owner(1), &mut out).unwrap();
        assert_eq!(&out, b"new");
        assert!(fs.data_snapshot(token).is_ok());
        fs.finish_data_cleanup(cleanup).unwrap();
        let (dead, claim) = begin(&mut fs, DataKind::Read, 3, &[]);
        committing(&mut fs, dead, claim);
        assert!(
            matches!(fs.abandon_data_owner(owner(1)), Some(ScalarAbandoned::Recover { token: t, .. }) if t == dead)
        );
        let ScalarClaim::Acquired { token: cleaner, .. } = fs.claim_data(dead, owner(3)).unwrap()
        else {
            panic!("cleanup claim");
        };
        assert!(fs.data_query_context(cleaner).is_ok());
        assert!(fs.data_commit_context(cleaner).is_err());
        let old = fs.data_snapshot(dead).unwrap();
        assert!(fs.update_data(cleaner, old.recovery).is_err());
        assert!(
            fs.save_data_result(cleaner, done(256, 3), b"new", errno)
                .is_err()
        );
        let cleanup = cleanup_proof(fs.begin_data_cleanup(dead).unwrap());
        fs.finish_data_cleanup(cleanup).unwrap();
        assert!(fs.data_snapshot(dead).is_err());
    }

    #[test]
    fn preparation_proof_binds_claim_target_job_and_full_session() {
        let mut fs = files();
        let (token, claim) = begin(&mut fs, DataKind::Write, 1, b"x");
        committing(&mut fs, token, claim);
        let snapshot = fs.data_snapshot(token).unwrap();
        let session = snapshot.recovery.session_handle;
        for (target, job, session) in [
            (target(44), 256, session),
            (target(43), 512, session),
            (target(43), 256, rt::abi::Handle::new(7, 10).0),
        ] {
            assert!(
                fs.restore_data_preparation(PreparedNoEffect {
                    claim,
                    target,
                    job,
                    session
                })
                .is_err()
            );
            assert_eq!(fs.data_snapshot(token).unwrap(), snapshot);
        }
        fs.restore_data_preparation(PreparedNoEffect {
            claim,
            target: target(43),
            job: 256,
            session,
        })
        .unwrap();
        let restored = fs.data_snapshot(token).unwrap();
        assert_eq!(restored.recovery.phase, Phase::Ready);
        assert_eq!(restored.claimant, None);
        assert_eq!(restored.recovery.input(), b"x");
        assert!(fs.data_commit_context(claim).is_err());
    }

    #[test]
    fn mixed_full32_and_last_target_debt_survive_numeric_reuse() {
        let mut fs = files();
        let fd = fs
            .insert(target(43), super::super::DescriptorFlags::default())
            .unwrap();
        let (token, claim, _) = fs
            .begin_data(owner(1), fd, DataKind::Write, 1, 0, b"x")
            .unwrap();
        for _ in 1..32 {
            fs.begin_open_record(owner(1), 0, super::super::DescriptorFlags::default())
                .unwrap();
        }
        assert_eq!(
            fs.begin_data(owner(1), fd, DataKind::Read, 1, 0, &[]).err(),
            Some(FsError::TooManyOpenFiles)
        );
        committing(&mut fs, token, claim);
        fs.save_data_result(claim, done(256, 1), &[], errno)
            .unwrap();
        assert_eq!(fs.take_close(fd).unwrap(), None);
        let replacement = target(44);
        assert_eq!(
            fs.insert(replacement, super::super::DescriptorFlags::default())
                .unwrap(),
            fd
        );
        let cleanup = fs.begin_data_cleanup(token).unwrap();
        assert_eq!(cleanup.cleanup.last_target, Some(target(43)));
        let exact_proof = cleanup_proof(cleanup);
        let before = fs.data_snapshot(token).unwrap();
        let wrong = CleanupProof {
            last_target: Some(replacement),
            ..exact_proof
        };
        assert!(fs.finish_data_cleanup(wrong).is_err());
        assert_eq!(fs.data_snapshot(token).unwrap(), before);
        let cleanup = cleanup_proof(fs.begin_data_cleanup(token).unwrap());
        fs.finish_data_cleanup(cleanup).unwrap();
        assert_eq!(fs.target(fd).unwrap(), replacement);
        fs.acknowledge_data(token, owner(1), &mut []).unwrap();
        assert!(fs.data_snapshot(token).is_err());
    }

    #[test]
    fn terminal_failure_and_zero_read_have_exact_cache_shape() {
        let mut fs = files();
        let (token, claim) = begin(&mut fs, DataKind::Read, 0, &[]);
        committing(&mut fs, token, claim);
        for code in [proto_fs::RESOLVING, proto_fs::TIME_DEFERRED] {
            let failure = DataOutcome {
                job: 256,
                phase: DataPhase::Completed,
                result: DataResult::FailedNoEffect(code),
            };
            assert!(fs.save_data_result(claim, failure, &[], errno).is_err());
        }
        fs.save_data_result(claim, done(256, 0), &[], errno)
            .unwrap();
        assert_eq!(
            fs.acknowledge_data(token, owner(1), &mut []).unwrap(),
            ScalarResult::Bytes(0)
        );
        let (token, claim) = begin(&mut fs, DataKind::Truncate, 0, &[]);
        committing(&mut fs, token, claim);
        let failure = DataOutcome {
            job: 256,
            phase: DataPhase::Completed,
            result: DataResult::FailedNoEffect(proto_fs::NO_SPACE),
        };
        fs.save_data_result(claim, failure, &[], errno).unwrap();
        assert_eq!(
            fs.acknowledge_data(token, owner(1), &mut []).unwrap(),
            ScalarResult::Failed(28)
        );
    }

    #[test]
    fn pinned_initializer_and_fork_discard_preserve_published_aliases() {
        let mut destination = core::mem::MaybeUninit::<PosixFs>::uninit();
        let startup = super::super::StartupFiles::from_sessions(
            Handle::<Channel>::from_raw(rt::abi::Handle::new(7, 9)),
            None,
            None,
            None,
        );
        // SAFETY: this fixture owns aligned destination storage before any access.
        unsafe {
            PosixFs::initialize_at(destination.as_mut_ptr(), startup, b"/", None, false).unwrap();
        }
        // SAFETY: initialize_at completed every field. Dummy transports remain undropped.
        let mut fs = ManuallyDrop::new(unsafe { destination.assume_init() });
        assert_eq!(fs.data_tokens().count(), 0);
        let fd = fs
            .insert(target(43), super::super::DescriptorFlags::default())
            .unwrap();
        let alias = fs.dup(fd).unwrap();
        let (token, _, _) = fs
            .begin_data(owner(1), fd, DataKind::PRead, 1, 0, &[])
            .unwrap();
        fs.after_fork(
            Handle::<Channel>::from_raw(rt::abi::Handle::new(8, 10)),
            None,
            None,
            None,
        );
        assert_eq!(fs.target(fd).unwrap(), target(43));
        assert_eq!(fs.target(alias).unwrap(), target(43));
        assert!(fs.data_snapshot(token).is_err());
        assert_eq!(fs.data_tokens().count(), 0);
        assert_eq!(core::mem::size_of::<Recovery>(), 1056);
        assert_eq!(core::mem::size_of::<PosixFs>(), 38984);
    }

    #[test]
    fn start_terminal_failure_retains_key_fence_and_rejects_stale_custody() {
        let mut fs = files();
        let (token, claim) = begin(&mut fs, DataKind::Read, 3, &[]);
        for status in [
            Status::Kernel(rt::abi::Error::Interrupted),
            Status::BadSize,
            Status::Unknown(proto_fs::RESOLVING),
            Status::Unknown(proto_fs::TIME_DEFERRED),
        ] {
            assert!(matches!(
                fs.data_start_context(claim).unwrap().classify(Err(status)),
                StartResult::Ambiguous(_)
            ));
        }
        let before = fs.data_snapshot(token).unwrap();
        let StartResult::Rejected(proof) = fs
            .data_start_context(claim)
            .unwrap()
            .classify(Err(Status::Unknown(proto_fs::NO_SPACE)))
        else {
            panic!("terminal reply");
        };
        assert!(fs.reject_data_start(proof, |_| 0).is_err());
        assert_eq!(fs.data_snapshot(token).unwrap(), before);
        let StartResult::Rejected(stale) = fs
            .data_start_context(claim)
            .unwrap()
            .classify(Err(Status::Unknown(proto_fs::NO_SPACE)))
        else {
            panic!("terminal reply");
        };
        fs.release_data_claim(claim).unwrap();
        let ScalarClaim::Acquired { token: current, .. } = fs.claim_data(token, owner(2)).unwrap()
        else {
            panic!("current claimant");
        };
        let before = fs.data_snapshot(token).unwrap();
        assert!(fs.reject_data_start(stale, errno).is_err());
        assert_eq!(fs.data_snapshot(token).unwrap(), before);
        let StartResult::Rejected(proof) = fs
            .data_start_context(current)
            .unwrap()
            .classify(Err(Status::Unknown(proto_fs::NO_SPACE)))
        else {
            panic!("terminal reply");
        };
        fs.reject_data_start(proof, errno).unwrap();
        let completed = fs.data_snapshot(token).unwrap();
        assert_eq!(completed.recovery.job, 0);
        assert_eq!(completed.result, Some(ScalarResult::Failed(28)));
        let cleanup = fs.begin_data_cleanup(token).unwrap();
        assert_eq!(cleanup.cleanup.token, token);
        // The native cleanup context always issues Cancel and ACK even at job0.
        let exact = cleanup_proof(cleanup);
        fs.finish_data_cleanup(exact).unwrap();
        assert_eq!(
            fs.acknowledge_data(token, owner(1), &mut []).unwrap(),
            ScalarResult::Failed(28)
        );
    }

    #[test]
    fn transport_replacement_preserves_incoming_custody_and_refuses_ownerless_debt() {
        fn incoming() -> super::super::StartupFiles {
            super::super::StartupFiles::from_sessions(
                Handle::<Channel>::from_raw(rt::abi::Handle::new(8, 10)),
                None,
                None,
                None,
            )
        }
        let mut fs = files();
        let fd = fs
            .insert(target(43), super::super::DescriptorFlags::default())
            .unwrap();
        let (token, _, _) = fs
            .begin_data(owner(1), fd, DataKind::Read, 3, 0, &[])
            .unwrap();
        fs.take_close(fd).unwrap();
        fs.abandon_data_owner(owner(1)).unwrap();
        assert_eq!(fs.descriptors().count(), 3);
        let before = fs.data_snapshot(token).unwrap();
        let session = fs.sessions().0.raw();
        let refused = ManuallyDrop::new(fs.replace_initial_transports(incoming()));
        let Err((_, retained)) = refused.as_ref() else {
            panic!("resident debt must block replacement");
        };
        assert_eq!(
            retained.files.sessions().0.raw(),
            rt::abi::Handle::new(8, 10)
        );
        assert_eq!(fs.sessions().0.raw(), session);
        assert_eq!(fs.data_snapshot(token).unwrap(), before);
        let cleanup = cleanup_proof(fs.begin_data_cleanup(token).unwrap());
        fs.finish_data_cleanup(cleanup).unwrap();
        let accepted = ManuallyDrop::new(fs.replace_initial_transports(incoming()));
        assert!(accepted.is_ok());
        assert_eq!(fs.sessions().0.raw(), rt::abi::Handle::new(8, 10));
        let Ok(old) = accepted.as_ref() else {
            panic!("idle initial transports");
        };
        assert_eq!(old.files.sessions().0.raw(), session);
        assert_eq!(fs.target(0).unwrap(), Target::Input);
        assert_eq!(fs.data_tokens().count(), 0);
    }
    #[test]
    fn canceling_retains_known_read_cache_and_rejects_missing_result() {
        let mut fs = files();
        let (token, claim) = begin(&mut fs, DataKind::Read, 3, &[]);
        committing(&mut fs, token, claim);
        let mut outcome = done(256, 3);
        outcome.phase = DataPhase::Canceling;
        outcome.result = DataResult::None;
        assert!(fs.save_data_result(claim, outcome, &[], |_| 5).is_err());
        assert_eq!(fs.data_snapshot(token).unwrap().result, None);
        outcome.result = DataResult::Bytes(3);
        fs.save_data_result(claim, outcome, b"abc", |_| 5).unwrap();
        let proof = cleanup_proof(fs.begin_data_cleanup(token).unwrap());
        fs.finish_data_cleanup(proof).unwrap();
        let mut bytes = [0; 3];
        assert_eq!(
            fs.acknowledge_data(token, owner(1), &mut bytes).unwrap(),
            ScalarResult::Bytes(3)
        );
        assert_eq!(&bytes, b"abc");
    }

    #[test]
    fn compact_progress_and_owned_feed_keep_input_and_exact_claim() {
        let mut fs = files();
        let mut input = [0; 1012];
        for (i, byte) in input.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let (token, claim) = begin(&mut fs, DataKind::Write, 1012, &input);
        fs.set_data_progress(claim, Phase::Feeding, 256, 0).unwrap();
        let feed = fs.data_feed_context(claim).unwrap();
        assert_eq!(feed.end(), 1004);
        assert_eq!(&feed.bytes[..1004], &input[..1004]);
        fs.set_data_progress(claim, Phase::Feeding, 256, feed.end())
            .unwrap();
        assert!(
            fs.set_data_progress(claim, Phase::Feeding, 512, 1012)
                .is_err()
        );
        assert!(
            fs.set_data_progress(claim, Phase::Feeding, 256, 1013)
                .is_err()
        );
        let last = fs.data_feed_context(claim).unwrap();
        assert_eq!(last.length, 8);
        assert_eq!(last.end(), 1012);
        assert_eq!(&last.bytes[..8], &input[1004..]);
        fs.release_data_claim(claim).unwrap();
        let ScalarClaimState::Acquired(current) = fs.claim_data_token(token, owner(1)).unwrap()
        else {
            panic!("small exact claim");
        };
        assert!(
            fs.set_data_progress(claim, Phase::Ready, 256, 1012)
                .is_err()
        );
        fs.set_data_progress(current, Phase::Ready, 256, 1012)
            .unwrap();
        let view = fs.descriptors.scalar_claim_view(current).unwrap();
        assert_eq!(view.recovery.input(), &input);
        let small = fs.data_claim_state(current).unwrap();
        assert_eq!(small.progress, Phase::Ready);
        assert_eq!(small.feed_end, 1012);
        assert_eq!(small.session_handle, fs.sessions().0.raw().0);
        assert!(core::mem::size_of::<DataState>() < 192);
        assert_eq!(core::mem::size_of::<PosixFs>(), 38984);
    }

    fn retired(fs: &PosixFs, claim: ScalarClaimToken) -> TerminalCleanupAuthority {
        let TerminalQueryResult::Retired(authority) = fs
            .data_terminal_query_context(claim)
            .unwrap()
            .classify(Err(Status::Unknown(proto_fs::OPEN_RETIRED)))
            .unwrap()
        else {
            panic!("canonical retired reply");
        };
        authority
    }

    #[test]
    fn terminal_fence_retains_original_until_confirmation_and_allows_retry() {
        let mut fs = files();
        let (token, claim) = begin(&mut fs, DataKind::Read, 3, &[]);
        assert!(
            fs.exhausted_data_cleanup_authority(token, owner(1))
                .is_err()
        );
        assert!(fs.begin_data_cleanup(token).is_err());
        let authority = retired(&fs, claim);
        let _uncertain = fs
            .begin_data_terminal_cleanup(token, owner(1), authority)
            .unwrap();
        assert!(fs.data_claim_snapshot(claim).is_err());
        assert!(fs.claim_data(token, owner(2)).is_ok());
        assert_eq!(
            fs.data_snapshot(token).unwrap().phase,
            ScalarPhase::Cleaning
        );
        assert_eq!(fs.data_snapshot(token).unwrap().result, None);
        assert!(fs.acknowledge_data(token, owner(1), &mut []).is_err());
        let proof = cleanup_proof(fs.begin_data_cleanup(token).unwrap());
        fs.finish_data_cleanup(proof).unwrap();
        assert_eq!(
            fs.acknowledge_data(token, owner(1), &mut []).unwrap(),
            ScalarResult::Failed(5)
        );
        assert!(fs.data_snapshot(token).is_err());
    }

    #[test]
    fn terminal_authority_cannot_replace_new_claim_or_completed_read_cache() {
        let mut fs = files();
        let (token, claim) = begin(&mut fs, DataKind::Read, 3, &[]);
        let authority = retired(&fs, claim);
        fs.release_data_claim(claim).unwrap();
        let ScalarClaim::Acquired { token: current, .. } = fs.claim_data(token, owner(1)).unwrap()
        else {
            panic!("new exact claim");
        };
        assert!(
            fs.begin_data_terminal_cleanup(token, owner(1), authority)
                .is_err()
        );
        assert_eq!(fs.data_snapshot(token).unwrap().phase, ScalarPhase::Working);
        committing(&mut fs, token, current);
        let authority = retired(&fs, current);
        fs.save_data_result(current, done(256, 3), b"abc", |_| 5)
            .unwrap();
        assert!(
            fs.begin_data_terminal_cleanup(token, owner(1), authority)
                .is_err()
        );
        let proof = cleanup_proof(fs.begin_data_cleanup(token).unwrap());
        fs.finish_data_cleanup(proof).unwrap();
        let mut bytes = [0; 3];
        assert_eq!(
            fs.acknowledge_data(token, owner(1), &mut bytes).unwrap(),
            ScalarResult::Bytes(3)
        );
        assert_eq!(&bytes, b"abc");
    }

    #[test]
    fn ambiguous_query_and_working_snapshot_cannot_mint_terminal_cleanup() {
        let mut fs = files();
        let (token, claim) = begin(&mut fs, DataKind::Read, 3, &[]);
        for status in [
            Status::Unknown(300),
            Status::BadSize,
            Status::Kernel(rt::abi::Error::Interrupted),
        ] {
            assert!(
                fs.data_terminal_query_context(claim)
                    .unwrap()
                    .classify(Err(status))
                    .is_err()
            );
        }
        let forged = TerminalCleanupAuthority {
            token,
            snapshot: fs.data_snapshot(token).unwrap(),
            claim: None,
        };
        assert!(
            fs.begin_data_terminal_cleanup(token, owner(1), forged)
                .is_err()
        );
        assert_eq!(
            fs.data_claim_snapshot(claim).unwrap().phase,
            ScalarPhase::Working
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Recovery {
    pub job: u64,
    position: u64,
    session_handle: u64,
    count: u32,
    saved_len: u16,
    pub feed_end: u16,
    kind: u8,
    pub phase: Phase,
    bytes: [u8; proto_fs::MAX_READ],
}

const _: () = assert!(core::mem::size_of::<Recovery>() == 1056);
const _: () = assert!(
    core::mem::size_of::<posix_fd::Table<Target, 32, super::open::Recovery, Recovery>>() == 38408
);

pub type Snapshot = ScalarSnapshot<Target, Recovery>;
pub use posix_fd::ScalarClaimState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataState {
    pub owner: Option<OwnerToken>,
    pub claimant: Option<OwnerToken>,
    pub phase: ScalarPhase,
    pub pin: Option<Target>,
    pub result: Option<ScalarResult>,
    pub last_target: Option<Target>,
    pub job: u64,
    pub position: u64,
    pub session_handle: u64,
    pub count: u32,
    pub feed_end: u16,
    pub kind: DataKind,
    pub progress: Phase,
}

fn state(view: posix_fd::ScalarView<'_, Target, Recovery>) -> DataState {
    DataState {
        owner: view.owner,
        claimant: view.claimant,
        phase: view.phase,
        pin: view.pin,
        result: view.result,
        last_target: view.last_target,
        job: view.recovery.job,
        position: view.recovery.position,
        session_handle: view.recovery.session_handle,
        count: view.recovery.count,
        feed_end: view.recovery.feed_end,
        kind: view.recovery.kind(),
        progress: view.recovery.phase,
    }
}

fn same_snapshot(view: &posix_fd::ScalarView<'_, Target, Recovery>, snapshot: &Snapshot) -> bool {
    view.owner == snapshot.owner
        && view.claimant == snapshot.claimant
        && view.phase == snapshot.phase
        && view.pin == snapshot.pin
        && view.result == snapshot.result
        && view.last_target == snapshot.last_target
        && view.recovery == &snapshot.recovery
}

#[inline(always)]
fn own_snapshot(view: posix_fd::ScalarView<'_, Target, Recovery>) -> Snapshot {
    Snapshot {
        owner: view.owner,
        claimant: view.claimant,
        phase: view.phase,
        recovery: *view.recovery,
        pin: view.pin,
        result: view.result,
        last_target: view.last_target,
    }
}

fn valid_job(job: u64) -> bool {
    job >> 8 != 0 && job & 255 < 128
}

fn key(token: ScalarToken) -> OpenKey {
    OpenKey {
        slot: token.slot() as u32,
        generation: token.generation(),
    }
}

fn description(target: Target, kind: DataKind) -> Result<DataDescription, FsError> {
    let exact = match target {
        Target::Ram(exact) => exact,
        Target::Random(exact) if kind.writes() => exact,
        _ => return Err(FsError::BadFileDescriptor),
    };
    Ok(DataDescription {
        packed: exact.fd() | (exact.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT),
        generation: exact.generation(),
    })
}

impl Recovery {
    pub fn kind(&self) -> DataKind {
        DataKind::from_number(self.kind as u32).expect("validated resident kind")
    }
    pub fn count(&self) -> u32 {
        self.count
    }
    pub fn position(&self) -> u64 {
        self.position
    }
    pub fn session_handle(&self) -> u64 {
        self.session_handle
    }
    pub fn input(&self) -> &[u8] {
        if self.kind().writes() {
            &self.bytes[..self.count as usize]
        } else {
            &[]
        }
    }
    pub fn request(&self, token: ScalarToken, target: Target) -> Result<DataStart, FsError> {
        let request = DataStart {
            key: key(token),
            kind: self.kind(),
            description: description(target, self.kind())?,
            count: self.count,
            position: self.position,
        };
        request.validate().map_err(FsError::from)?;
        Ok(request)
    }
    fn progresses_from(self, old: Self) -> bool {
        if self.position != old.position
            || self.session_handle != old.session_handle
            || self.count != old.count
            || self.kind != old.kind
            || self.saved_len != old.saved_len
            || self.bytes != old.bytes
            || self.feed_end < old.feed_end
            || self.feed_end as u32 > self.count
            || (!self.kind().writes() && self.feed_end != 0)
            || (old.job != 0 && self.job != old.job)
        {
            return false;
        }
        if self.phase == Phase::Starting {
            return self == old && self.job == 0;
        }
        if !valid_job(self.job) {
            return false;
        }
        self.phase == old.phase
            || matches!(
                (old.phase, self.phase),
                (
                    Phase::Starting,
                    Phase::Feeding | Phase::Preparing | Phase::Ready
                ) | (Phase::Feeding, Phase::Preparing | Phase::Ready)
                    | (Phase::Preparing, Phase::Ready)
                    | (Phase::Ready, Phase::Committing)
            )
    }
}

/// One exact native Query context. A caller-constructed outcome cannot mint its proof.
pub struct QueryContext {
    claim: ScalarClaimToken,
    job: u64,
    target: Target,
    session: u64,
    request: DataStart,
    transport: Transport,
}

pub struct StartContext(QueryContext);

/// A bounded owned copy survives unlocking; no resident borrow crosses IPC.
pub struct FeedContext {
    context: QueryContext,
    offset: u16,
    length: u16,
    bytes: [u8; proto_fs::FEED_MAX],
}

impl FeedContext {
    pub fn end(&self) -> u16 {
        self.offset + self.length
    }

    pub fn send_once(&self) -> Result<(), Status> {
        self.context.transport.files().data_feed_once(
            self.context.job,
            u32::from(self.offset),
            &self.bytes[..usize::from(self.length)],
        )
    }
}
pub struct StartRejected {
    context: QueryContext,
    status: Status,
}
pub enum StartResult {
    Started { phase: DataPhase, job: u64 },
    Rejected(StartRejected),
    Ambiguous(Status),
}
impl StartContext {
    pub fn send_once(self) -> StartResult {
        let result = self.0.transport.files().data_start_once(self.0.request);
        self.classify(result)
    }
    fn classify(self, result: Result<(DataPhase, u64), Status>) -> StartResult {
        match result {
            Ok((phase, job)) => StartResult::Started { phase, job },
            Err(Status::Unknown(code)) if proto_fs::terminal_failure(code) => {
                StartResult::Rejected(StartRejected {
                    context: self.0,
                    status: Status::Unknown(code),
                })
            }
            Err(error) => StartResult::Ambiguous(error),
        }
    }
}

pub struct PreparedNoEffect {
    claim: ScalarClaimToken,
    job: u64,
    target: Target,
    session: u64,
}

pub struct QueryResult {
    pub outcome: DataOutcome,
    pub prepared: Option<PreparedNoEffect>,
}

/// This context preserves complete history while querying terminal custody.
pub struct TerminalQueryContext {
    context: QueryContext,
    snapshot: Snapshot,
}

// The exact immutable snapshot remains value-owned without heap allocation.
#[allow(clippy::large_enum_variant)]
pub enum TerminalQueryResult {
    Outcome(QueryResult),
    Retired(TerminalCleanupAuthority),
}

/// An exact retired reply or irreversible claim exhaustion permits fencing.
/// Cleanup can report EIO after an earlier effect; this carries no no-effect proof.
pub struct TerminalCleanupAuthority {
    token: ScalarToken,
    snapshot: Snapshot,
    claim: Option<ScalarClaimToken>,
}

impl TerminalQueryContext {
    pub fn query_once(self) -> Result<TerminalQueryResult, Status> {
        let result = self
            .context
            .transport
            .files()
            .data_query_once(self.context.request);
        self.classify(result)
    }

    fn classify(self, result: Result<DataOutcome, Status>) -> Result<TerminalQueryResult, Status> {
        match result {
            Err(Status::Unknown(proto_fs::OPEN_RETIRED)) => {
                Ok(TerminalQueryResult::Retired(TerminalCleanupAuthority {
                    token: self.context.claim.scalar(),
                    snapshot: self.snapshot,
                    claim: Some(self.context.claim),
                }))
            }
            other => self
                .context
                .classify(other)
                .map(TerminalQueryResult::Outcome),
        }
    }
}

impl QueryContext {
    pub fn query_once(self) -> Result<QueryResult, Status> {
        let result = self.transport.files().data_query_once(self.request);
        self.classify(result)
    }

    fn classify(self, result: Result<DataOutcome, Status>) -> Result<QueryResult, Status> {
        let outcome = result?;
        if self.job != 0 && outcome.job != self.job {
            return Err(Status::BadSize);
        }
        let prepared = matches!(outcome.phase, DataPhase::Ready | DataPhase::TimeDeferred)
            .then_some(PreparedNoEffect {
                claim: self.claim,
                job: outcome.job,
                target: self.target,
                session: self.session,
            });
        Ok(QueryResult { outcome, prepared })
    }
}

/// Exactly one final call; ambiguity leaves the resident Committing phase intact.
pub struct CommitContext(QueryContext);
impl CommitContext {
    pub fn send_once(self) -> Result<DataOutcome, Status> {
        self.0
            .transport
            .files()
            .data_commit_once(self.0.job, self.0.request)
    }
}

/// Exact cleanup custody persists in the scalar hold until these calls succeed.
pub struct CleanupContext {
    cleanup: ScalarCleanup<Target, Recovery>,
    session: u64,
    transport: Transport,
}
pub struct CleanupProof {
    token: ScalarToken,
    recovery: Recovery,
    last_target: Option<Target>,
    session: u64,
}
impl CleanupContext {
    /// Cancel fences an uncertain Start; ACK retires any completed cache.
    /// CloseExact consumes only the captured description lifetime.
    pub fn send_once(self) -> Result<CleanupProof, FsError> {
        let files = self.transport.files();
        files
            .data_cancel_once(key(self.cleanup.token))
            .map_err(FsError::from)?;
        match files.data_ack_once(key(self.cleanup.token)) {
            Ok(()) | Err(Status::Unknown(proto_fs::OPEN_RETIRED)) => {}
            Err(error) => return Err(FsError::from(error)),
        }
        self.transport.release(self.cleanup.last_target)?;
        Ok(CleanupProof {
            token: self.cleanup.token,
            recovery: self.cleanup.recovery,
            last_target: self.cleanup.last_target,
            session: self.session,
        })
    }
}

impl PosixFs {
    pub fn data_state(&self, token: ScalarToken) -> Result<DataState, FsError> {
        Ok(state(self.descriptors.scalar_view(token)?))
    }

    pub fn data_claim_state(&self, claim: ScalarClaimToken) -> Result<DataState, FsError> {
        Ok(state(self.descriptors.scalar_claim_view(claim)?))
    }

    pub fn claim_data_token(
        &mut self,
        token: ScalarToken,
        helper: OwnerToken,
    ) -> Result<ScalarClaimState, FsError> {
        if self.descriptors.scalar_view(token)?.recovery.session_handle != self.sessions().0.raw().0
        {
            return Err(FsError::Io);
        }
        self.descriptors
            .claim_scalar_token(token, helper)
            .map_err(FsError::from)
    }

    pub fn set_data_progress(
        &mut self,
        claim: ScalarClaimToken,
        phase: Phase,
        job: u64,
        feed_end: u16,
    ) -> Result<(), FsError> {
        let view = self.descriptors.scalar_claim_view(claim)?;
        let old = view.recovery;
        if view.owner.is_none()
            || old.session_handle != self.sessions().0.raw().0
            || feed_end < old.feed_end
            || u32::from(feed_end) > old.count
            || (!old.kind().writes() && feed_end != 0)
            || (old.job != 0 && job != old.job)
        {
            return Err(FsError::Io);
        }
        if phase == Phase::Starting {
            if old.phase != phase || job != 0 || feed_end != old.feed_end {
                return Err(FsError::Io);
            }
        } else if !valid_job(job)
            || !(phase == old.phase
                || matches!(
                    (old.phase, phase),
                    (
                        Phase::Starting,
                        Phase::Feeding | Phase::Preparing | Phase::Ready
                    ) | (Phase::Feeding, Phase::Preparing | Phase::Ready)
                        | (Phase::Preparing, Phase::Ready)
                        | (Phase::Ready, Phase::Committing)
                ))
        {
            return Err(FsError::Io);
        }
        self.descriptors
            .update_scalar_with(claim, |recovery| {
                recovery.phase = phase;
                recovery.job = job;
                recovery.feed_end = feed_end;
            })
            .map_err(FsError::from)
    }

    pub fn begin_data(
        &mut self,
        owner: OwnerToken,
        fd: u32,
        kind: DataKind,
        count: u32,
        position: u64,
        input: &[u8],
    ) -> Result<(ScalarToken, ScalarClaimToken, Transport), FsError> {
        let target = self.target(fd)?;
        let request = DataStart {
            key: OpenKey {
                slot: 0,
                generation: 1,
            },
            kind,
            description: description(target, kind)?,
            count,
            position,
        };
        request.validate().map_err(FsError::from)?;
        if input.len() != if kind.writes() { count as usize } else { 0 } {
            return Err(FsError::InvalidArgument);
        }
        let mut recovery = Recovery {
            job: 0,
            position,
            session_handle: self.sessions().0.raw().0,
            count,
            saved_len: 0,
            feed_end: 0,
            kind: kind as u8,
            phase: Phase::Starting,
            bytes: [0; proto_fs::MAX_READ],
        };
        recovery.bytes[..input.len()].copy_from_slice(input);
        let (token, claim) = self.descriptors.begin_scalar(owner, fd, recovery)?;
        Ok((token, claim, self.transport()))
    }

    pub fn data_snapshot(&self, token: ScalarToken) -> Result<Snapshot, FsError> {
        self.descriptors
            .scalar_snapshot(token)
            .map_err(FsError::from)
    }
    pub fn data_claim_snapshot(&self, claim: ScalarClaimToken) -> Result<Snapshot, FsError> {
        self.descriptors
            .scalar_claim_snapshot(claim)
            .map_err(FsError::from)
    }
    pub fn data_tokens(&self) -> impl Iterator<Item = ScalarToken> + '_ {
        self.descriptors.scalar_tokens()
    }
    pub fn claim_data(
        &mut self,
        token: ScalarToken,
        helper: OwnerToken,
    ) -> Result<ScalarClaim<Target, Recovery>, FsError> {
        let snapshot = self.data_snapshot(token)?;
        if snapshot.recovery.session_handle != self.sessions().0.raw().0 {
            return Err(FsError::Io);
        }
        self.descriptors
            .claim_scalar(token, helper)
            .map_err(FsError::from)
    }
    pub fn release_data_claim(&mut self, claim: ScalarClaimToken) -> Result<(), FsError> {
        self.descriptors
            .release_scalar_claim(claim)
            .map_err(FsError::from)
    }
    pub fn update_data(
        &mut self,
        claim: ScalarClaimToken,
        recovery: Recovery,
    ) -> Result<(), FsError> {
        let old = self.data_claim_snapshot(claim)?;
        if old.owner.is_none()
            || recovery.session_handle != self.sessions().0.raw().0
            || !recovery.progresses_from(old.recovery)
        {
            return Err(FsError::Io);
        }
        self.descriptors
            .update_scalar(claim, recovery)
            .map_err(FsError::from)
    }
    pub fn data_query_context(&self, claim: ScalarClaimToken) -> Result<QueryContext, FsError> {
        let snapshot = self.descriptors.scalar_claim_view(claim)?;
        let target = snapshot.pin.ok_or(FsError::Io)?;
        let session = self.sessions().0.raw().0;
        if snapshot.recovery.session_handle != session {
            return Err(FsError::Io);
        }
        Ok(QueryContext {
            claim,
            job: snapshot.recovery.job,
            target,
            session,
            request: snapshot.recovery.request(claim.scalar(), target)?,
            transport: self.transport(),
        })
    }
    pub fn data_terminal_query_context(
        &self,
        claim: ScalarClaimToken,
    ) -> Result<TerminalQueryContext, FsError> {
        let snapshot = self.descriptors.scalar_claim_view(claim)?;
        if snapshot.owner.is_none() {
            return Err(FsError::BadFileDescriptor);
        }
        Ok(TerminalQueryContext {
            context: self.data_query_context(claim)?,
            snapshot: own_snapshot(snapshot),
        })
    }

    pub fn data_feed_context(&self, claim: ScalarClaimToken) -> Result<FeedContext, FsError> {
        let view = self.descriptors.scalar_claim_view(claim)?;
        let recovery = view.recovery;
        if view.owner.is_none()
            || !recovery.kind().writes()
            || !matches!(recovery.phase, Phase::Feeding)
            || !valid_job(recovery.job)
            || recovery.feed_end as u32 >= recovery.count
        {
            return Err(FsError::Io);
        }
        let offset = recovery.feed_end;
        let length = (recovery.count as usize - usize::from(offset)).min(proto_fs::FEED_MAX);
        let mut bytes = [0; proto_fs::FEED_MAX];
        bytes[..length]
            .copy_from_slice(&recovery.input()[usize::from(offset)..usize::from(offset) + length]);
        Ok(FeedContext {
            context: self.data_query_context(claim)?,
            offset,
            length: length as u16,
            bytes,
        })
    }

    /// Irreversible claim exhaustion permits cleanup without minting a new claim.
    pub fn exhausted_data_cleanup_authority(
        &self,
        token: ScalarToken,
        owner: OwnerToken,
    ) -> Result<TerminalCleanupAuthority, FsError> {
        let snapshot = self.descriptors.scalar_view(token)?;
        if snapshot.phase != ScalarPhase::CleanupRequired
            || snapshot.owner != Some(owner)
            || snapshot.recovery.session_handle != self.sessions().0.raw().0
        {
            return Err(FsError::BadFileDescriptor);
        }
        Ok(TerminalCleanupAuthority {
            token,
            snapshot: own_snapshot(snapshot),
            claim: None,
        })
    }

    /// Revoke effect authority before the exact-key native fence, retaining cache.
    pub fn begin_data_terminal_cleanup(
        &mut self,
        token: ScalarToken,
        owner: OwnerToken,
        authority: TerminalCleanupAuthority,
    ) -> Result<CleanupContext, FsError> {
        if token != authority.token || authority.snapshot.owner != Some(owner) {
            return Err(FsError::BadFileDescriptor);
        }
        let snapshot = if let Some(claim) = authority.claim {
            self.descriptors.scalar_claim_view(claim)?
        } else {
            let snapshot = self.descriptors.scalar_view(token)?;
            if snapshot.phase != ScalarPhase::CleanupRequired {
                return Err(FsError::BadFileDescriptor);
            }
            snapshot
        };
        let session = self.sessions().0.raw().0;
        if !same_snapshot(&snapshot, &authority.snapshot)
            || snapshot.recovery.session_handle != session
        {
            return Err(FsError::Io);
        }
        let cleanup = self.descriptors.scalar_begin_cleanup(token)?;
        Ok(CleanupContext {
            cleanup,
            session,
            transport: self.transport(),
        })
    }

    pub fn data_commit_context(&self, claim: ScalarClaimToken) -> Result<CommitContext, FsError> {
        let snapshot = self.descriptors.scalar_claim_view(claim)?;
        if snapshot.owner.is_none()
            || snapshot.recovery.phase != Phase::Committing
            || !valid_job(snapshot.recovery.job)
        {
            return Err(FsError::Io);
        }
        Ok(CommitContext(self.data_query_context(claim)?))
    }
    pub fn data_start_context(&self, claim: ScalarClaimToken) -> Result<StartContext, FsError> {
        let snapshot = self.descriptors.scalar_claim_view(claim)?;
        if snapshot.owner.is_none()
            || snapshot.recovery.phase != Phase::Starting
            || snapshot.recovery.job != 0
        {
            return Err(FsError::Io);
        }
        Ok(StartContext(self.data_query_context(claim)?))
    }
    /// A strict terminal Start reply becomes local failure. Exact-key cleanup
    /// remains mandatory because an earlier ambiguous Start may have admitted a job.
    pub fn reject_data_start(
        &mut self,
        proof: StartRejected,
        errno_of: fn(FsError) -> i32,
    ) -> Result<(), FsError> {
        let context = proof.context;
        let snapshot = self.data_claim_snapshot(context.claim)?;
        if snapshot.owner.is_none()
            || snapshot.recovery.phase != Phase::Starting
            || snapshot.recovery.job != 0
            || snapshot.pin != Some(context.target)
            || snapshot.recovery.session_handle != context.session
            || self.sessions().0.raw().0 != context.session
            || snapshot
                .recovery
                .request(context.claim.scalar(), context.target)?
                != context.request
        {
            return Err(FsError::Io);
        }
        let errno = errno_of(FsError::from(proof.status));
        if errno <= 0 {
            return Err(FsError::Io);
        }
        let mut recovery = snapshot.recovery;
        recovery.phase = Phase::Completed;
        self.descriptors.update_scalar(context.claim, recovery)?;
        self.descriptors
            .complete_scalar(context.claim, ScalarResult::Failed(errno))?;
        Ok(())
    }
    pub fn restore_data_preparation(&mut self, proof: PreparedNoEffect) -> Result<(), FsError> {
        let snapshot = self.descriptors.scalar_claim_view(proof.claim)?;
        if snapshot.owner.is_none()
            || snapshot.recovery.phase != Phase::Committing
            || snapshot.pin != Some(proof.target)
            || snapshot.recovery.job != proof.job
            || snapshot.recovery.session_handle != proof.session
            || self.sessions().0.raw().0 != proof.session
        {
            return Err(FsError::Io);
        }
        self.descriptors
            .update_scalar_with(proof.claim, |recovery| recovery.phase = Phase::Ready)?;
        self.descriptors.release_scalar_claim(proof.claim)?;
        Ok(())
    }

    /// No local cleanup starts before a living original's result and cache are complete.
    /// errno_of is the caller's pure, allocation-free conversion to a positive errno.
    pub fn save_data_result(
        &mut self,
        claim: ScalarClaimToken,
        outcome: DataOutcome,
        read_bytes: &[u8],
        errno_of: fn(FsError) -> i32,
    ) -> Result<(), FsError> {
        let snapshot = self.descriptors.scalar_claim_view(claim)?;
        if snapshot.owner.is_none()
            || snapshot.recovery.session_handle != self.sessions().0.raw().0
            || !matches!(outcome.phase, DataPhase::Completed | DataPhase::Canceling)
            || outcome.job != snapshot.recovery.job
        {
            return Err(FsError::Io);
        }
        outcome
            .validate(
                snapshot
                    .recovery
                    .request(claim.scalar(), snapshot.pin.ok_or(FsError::Io)?)?,
            )
            .map_err(FsError::from)?;
        let result = match outcome.result {
            DataResult::Bytes(count) => ScalarResult::Bytes(count),
            DataResult::FailedNoEffect(code) => {
                let errno = errno_of(FsError::from(Status::from_code(code)));
                if errno <= 0 {
                    return Err(FsError::Io);
                }
                ScalarResult::Failed(errno)
            }
            DataResult::None => return Err(FsError::Io),
        };
        let expected = match result {
            ScalarResult::Bytes(count) if snapshot.recovery.kind().reads() => count as usize,
            _ => 0,
        };
        if read_bytes.len() != expected {
            return Err(FsError::Io);
        }
        self.descriptors.update_scalar_with(claim, |recovery| {
            recovery.phase = Phase::Completed;
            recovery.saved_len = expected as u16;
            if expected != 0 {
                recovery.bytes[..expected].copy_from_slice(read_bytes);
            }
        })?;
        // The exact claim was validated under the same exclusive table borrow.
        self.descriptors.complete_scalar(claim, result)?;
        Ok(())
    }

    /// The caller supplies a short local signal defer around this copy and acknowledgment.
    pub fn acknowledge_data(
        &mut self,
        token: ScalarToken,
        owner: OwnerToken,
        out: &mut [u8],
    ) -> Result<ScalarResult, FsError> {
        let snapshot = self.descriptors.scalar_view(token)?;
        if snapshot.owner != Some(owner) {
            return Err(FsError::BadFileDescriptor);
        }
        let result = snapshot.result.ok_or(FsError::Io)?;
        let length = match result {
            ScalarResult::Bytes(n) if snapshot.recovery.kind().reads() => {
                if n > snapshot.recovery.count as u64
                    || n != snapshot.recovery.saved_len as u64
                    || n as usize > out.len()
                {
                    return Err(FsError::InvalidArgument);
                }
                n as usize
            }
            _ => 0,
        };
        out[..length].copy_from_slice(&snapshot.recovery.bytes[..length]);
        self.descriptors
            .ack_scalar(token, owner)
            .map_err(FsError::from)
    }

    pub fn begin_data_cleanup(&mut self, token: ScalarToken) -> Result<CleanupContext, FsError> {
        let snapshot = self.descriptors.scalar_view(token)?;
        let session = self.sessions().0.raw().0;
        if snapshot.recovery.session_handle != session
            || (snapshot.owner.is_some()
                && snapshot.result.is_none()
                && snapshot.phase != ScalarPhase::Cleaning)
        {
            return Err(FsError::Io);
        }
        let cleanup = self.descriptors.scalar_begin_cleanup(token)?;
        Ok(CleanupContext {
            cleanup,
            session,
            transport: self.transport(),
        })
    }
    pub fn finish_data_cleanup(&mut self, proof: CleanupProof) -> Result<(), FsError> {
        let snapshot = self.descriptors.scalar_view(proof.token)?;
        if snapshot.phase != ScalarPhase::Cleaning
            || snapshot.last_target != proof.last_target
            || snapshot.recovery != &proof.recovery
            || proof.session != self.sessions().0.raw().0
        {
            return Err(FsError::Io);
        }
        self.descriptors
            .scalar_finish_cleanup(proof.token)
            .map_err(FsError::from)
    }
    /// Detach exactly the original operation before its lifetime can be reused.
    pub fn abandon_data(
        &mut self,
        token: ScalarToken,
        owner: OwnerToken,
    ) -> Result<ScalarAbandoned<Target, Recovery>, FsError> {
        if self.descriptors.scalar_view(token)?.owner != Some(owner) {
            return Err(FsError::BadFileDescriptor);
        }
        self.descriptors
            .abandon_scalar(token)
            .map_err(FsError::from)
    }

    pub fn abandon_data_owner(
        &mut self,
        owner: OwnerToken,
    ) -> Option<ScalarAbandoned<Target, Recovery>> {
        self.descriptors.abandon_scalar_owner(owner)
    }
    pub fn data_wait_snapshot(&self, token: ScalarToken) -> Result<WaitValue, FsError> {
        self.descriptors
            .scalar_wait_snapshot(token)
            .map_err(FsError::from)
    }
    pub fn data_wait_word(
        &self,
        token: ScalarToken,
    ) -> Result<&core::sync::atomic::AtomicU32, FsError> {
        self.descriptors
            .scalar_wait_word(token)
            .map_err(FsError::from)
    }
}
