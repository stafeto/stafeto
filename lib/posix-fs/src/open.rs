// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Resident Open recovery survives native sender and helper lifetimes.
//! The shared layer serializes these transitions and performs RPC after unlocking.

use super::{DescriptorFlags, FsError, PosixFs, Target};
pub use posix_fd::{
    Abandoned, Claim, ClaimToken, Completion, EntryToken, OpenPhase, OpenSnapshot, OpenToken,
    OwnerToken, Replacement, WaitValue,
};
use proto_wire::Status;
use rt::fs::PreparedOpen;

/// The next backend phase; the local OpenToken always retains the client key.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum Phase {
    #[default]
    Starting,
    Traversing,
    Preparing,
    Committing,
    Finishing,
    Canceling,
}

/// Every expected backend result is saved before sending its final handoff.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct Recovery {
    pub job: u64,
    pub description_generation: u64,
    pub backend_fd: u32,
    pub phase: Phase,
    /// Captured before Start; writable-only Random uses the RAM route.
    pub access: u8,
    descriptor_flags: DescriptorFlags,
}

const _: () = assert!(core::mem::size_of::<Recovery>() == 24);

/// Validated remote preparation tied to one exact local final phase.
/// Its producer belongs to the trusted reply path once that protocol is connected.
pub struct PreparedNoEffect {
    claim: ClaimToken,
    entry: EntryToken,
    job: u64,
    session: rt::abi::Handle,
}

/// Captured from one exact reservation before its first final native request.
pub struct FinalizeContext {
    claim: ClaimToken,
    entry: EntryToken,
    job: u64,
    session: rt::abi::Handle,
    transport: super::Transport,
}

/// Only an actual uncertain final request creates this recovery continuation.
pub struct UnresolvedFinalize(FinalizeContext);

pub enum FinalizeResult {
    Finished(PreparedOpen),
    Deferred {
        proof: PreparedNoEffect,
        reason: Status,
    },
    Rejected(Status),
    Unresolved(UnresolvedFinalize),
}

pub enum FinalizeRecovery {
    Finished(PreparedOpen),
    Prepared(PreparedNoEffect),
    Failed(Status),
}

impl FinalizeContext {
    fn key(&self) -> proto_fs::OpenKey {
        proto_fs::OpenKey {
            slot: self.claim.open().slot() as u32,
            generation: self.claim.open().generation(),
        }
    }

    fn prepared(self) -> PreparedNoEffect {
        PreparedNoEffect {
            claim: self.claim,
            entry: self.entry,
            job: self.job,
            session: self.session,
        }
    }

    /// Exactly one native call; the proof comes from that call's canonical receipt.
    pub fn send_once(self) -> FinalizeResult {
        let attempt = self.transport.files().open_finalize_once(self.key());
        match attempt {
            rt::fs::OpenFinalizeAttempt::Finished(held) => FinalizeResult::Finished(held),
            rt::fs::OpenFinalizeAttempt::Deferred(receipt)
                if receipt.matches_request(self.key(), self.session) =>
            {
                let reason = receipt.status();
                FinalizeResult::Deferred {
                    proof: self.prepared(),
                    reason,
                }
            }
            rt::fs::OpenFinalizeAttempt::Rejected(error) => FinalizeResult::Rejected(error),
            rt::fs::OpenFinalizeAttempt::Deferred(_)
            | rt::fs::OpenFinalizeAttempt::Ambiguous(_) => {
                FinalizeResult::Unresolved(UnresolvedFinalize(self))
            }
        }
    }
}

impl UnresolvedFinalize {
    /// Recovery spends one Query call and never repeats the uncertain final request.
    pub fn query_once(self) -> FinalizeRecovery {
        let context = self.0;
        match context.transport.files().open_query_once(context.key()) {
            Ok(rt::fs::OpenOutcome::Active { job, phase: 2 }) if job == context.job => {
                FinalizeRecovery::Prepared(context.prepared())
            }
            Ok(rt::fs::OpenOutcome::Finished(held)) => FinalizeRecovery::Finished(held),
            Ok(rt::fs::OpenOutcome::Active { .. }) => FinalizeRecovery::Failed(Status::BadSize),
            Err(error) => FinalizeRecovery::Failed(error),
        }
    }
}

impl Recovery {
    pub fn starting(access: u32, descriptor_flags: DescriptorFlags) -> Result<Self, FsError> {
        if access > proto_fs::READ_WRITE {
            return Err(FsError::InvalidArgument);
        }
        Ok(Self {
            access: access as u8,
            descriptor_flags,
            ..Self::default()
        })
    }

    pub fn descriptor_flags(self) -> DescriptorFlags {
        self.descriptor_flags
    }

    pub fn expected(self) -> Option<PreparedOpen> {
        let fd = self.backend_fd & proto_fs::OPEN_FD_MASK;
        (self.backend_fd & !proto_fs::OPEN_RESULT_MASK == 0
            && self.description_generation != 0
            && (3..35).contains(&fd))
        .then_some(PreparedOpen {
            fd,
            slot: (self.backend_fd & proto_fs::OPEN_DESCRIPTION_MASK)
                >> proto_fs::OPEN_DESCRIPTION_SHIFT,
            generation: self.description_generation,
            random: self.backend_fd & proto_fs::OPEN_RANDOM != 0,
        })
    }

    fn progresses_from(self, previous: Self) -> bool {
        if self.access != previous.access
            || self.descriptor_flags != previous.descriptor_flags
            || (previous.job != 0 && self.job != previous.job)
            || (previous.backend_fd != 0 || previous.description_generation != 0)
                && (self.backend_fd != previous.backend_fd
                    || self.description_generation != previous.description_generation)
        {
            return false;
        }
        let forward = self.phase == previous.phase
            || matches!(
                (previous.phase, self.phase),
                (Phase::Starting, Phase::Traversing)
                    | (Phase::Traversing, Phase::Preparing)
                    | (Phase::Preparing, Phase::Committing)
                    | (Phase::Committing, Phase::Finishing)
            );
        if !forward {
            return false;
        }
        match self.phase {
            Phase::Starting => {
                self.job == 0 && self.backend_fd == 0 && self.description_generation == 0
            }
            Phase::Traversing | Phase::Preparing | Phase::Committing => {
                self.job >> 8 != 0
                    && self.job & 255 < 128
                    && self.backend_fd == 0
                    && self.description_generation == 0
            }
            Phase::Finishing => {
                self.job >> 8 != 0 && self.job & 255 < 128 && self.expected().is_some()
            }
            Phase::Canceling => false,
        }
    }
}

impl PosixFs {
    pub fn begin_open_record(
        &mut self,
        owner: OwnerToken,
        access: u32,
        descriptor_flags: DescriptorFlags,
    ) -> Result<(OpenToken, ClaimToken), FsError> {
        let recovery = Recovery::starting(access, descriptor_flags)?;
        self.descriptors
            .begin_open(owner, recovery)
            .map_err(FsError::from)
    }

    pub fn open_snapshot(&self, token: OpenToken) -> Result<OpenSnapshot<Recovery>, FsError> {
        self.descriptors.open_snapshot(token).map_err(FsError::from)
    }

    pub fn claim_open_record(
        &mut self,
        token: OpenToken,
        helper: OwnerToken,
    ) -> Result<Claim<Recovery>, FsError> {
        self.descriptors
            .claim_open(token, helper)
            .map_err(FsError::from)
    }

    pub fn release_open_claim(&mut self, claim: ClaimToken) -> Result<(), FsError> {
        self.descriptors.release_claim(claim).map_err(FsError::from)
    }

    pub fn update_open_record(
        &mut self,
        claim: ClaimToken,
        recovery: Recovery,
    ) -> Result<(), FsError> {
        let resident = self
            .descriptors
            .claim_snapshot(claim)?
            .recovery
            .ok_or(FsError::BadFileDescriptor)?;
        if !recovery.progresses_from(resident) {
            return Err(FsError::InvalidArgument);
        }
        self.descriptors
            .update_open(claim, recovery)
            .map_err(FsError::from)
    }

    pub fn reserve_open_record(&mut self, claim: ClaimToken) -> Result<EntryToken, FsError> {
        let resident = self
            .open_snapshot(claim.open())?
            .recovery
            .ok_or(FsError::BadFileDescriptor)?;
        self.descriptors
            .reserve_open(claim, 0, resident.descriptor_flags)
            .map_err(FsError::from)
    }

    /// Capture final request history and advance the resident phase under the file lock.
    pub fn begin_open_finalize(
        &mut self,
        claim: ClaimToken,
        entry: EntryToken,
    ) -> Result<FinalizeContext, FsError> {
        let snapshot = self.descriptors.claim_snapshot(claim)?;
        let mut recovery = snapshot.recovery.ok_or(FsError::BadFileDescriptor)?;
        if snapshot.owner.is_none()
            || snapshot.phase != OpenPhase::Reserved
            || snapshot.entry != Some(entry)
            || recovery.phase != Phase::Preparing
            || recovery.job >> 8 == 0
            || recovery.job & 255 >= 128
            || recovery.backend_fd != 0
            || recovery.description_generation != 0
        {
            return Err(FsError::BadFileDescriptor);
        }
        recovery.phase = Phase::Committing;
        self.update_open_record(claim, recovery)?;
        Ok(FinalizeContext {
            claim,
            entry,
            job: recovery.job,
            session: self.files.sessions().0.raw(),
            transport: self.transport(),
        })
    }

    /// Retain the paid operation while revoking a proven no-effect final-phase claim.
    pub fn unreserve_open_record(
        &mut self,
        claim: ClaimToken,
        entry: EntryToken,
        proof: PreparedNoEffect,
    ) -> Result<EntryToken, FsError> {
        if proof.claim != claim
            || proof.entry != entry
            || proof.session != self.files.sessions().0.raw()
        {
            return Err(FsError::BadFileDescriptor);
        }
        let snapshot = self.open_snapshot(claim.open())?;
        let mut recovery = snapshot.recovery.ok_or(FsError::BadFileDescriptor)?;
        if snapshot.phase != OpenPhase::Reserved
            || snapshot.owner.is_none()
            || snapshot.entry != Some(entry)
            || recovery.phase != Phase::Committing
            || recovery.job != proof.job
            || recovery.job >> 8 == 0
            || recovery.job & 255 >= 128
            || recovery.backend_fd != 0
            || recovery.description_generation != 0
        {
            return Err(FsError::BadFileDescriptor);
        }
        recovery.phase = Phase::Preparing;
        self.descriptors
            .unreserve_open(claim, entry, recovery)
            .map_err(FsError::from)
    }

    pub fn stage_open_record(&mut self, claim: ClaimToken, backend: Target) -> Result<(), FsError> {
        self.descriptors
            .stage_committed(claim, backend)
            .map_err(FsError::from)
    }

    pub fn publish_open_record(&mut self, claim: ClaimToken) -> Result<EntryToken, FsError> {
        self.descriptors.publish_open(claim).map_err(FsError::from)
    }

    pub fn ack_open_record(
        &mut self,
        token: OpenToken,
        owner: OwnerToken,
    ) -> Result<Completion, FsError> {
        self.descriptors
            .ack_open(token, owner)
            .map_err(FsError::from)
    }

    pub fn begin_open_cancel(
        &mut self,
        claim: ClaimToken,
    ) -> Result<OpenSnapshot<Recovery>, FsError> {
        self.descriptors.begin_cancel(claim).map_err(FsError::from)
    }

    /// A canonical backend Cancel has already consumed this snapshot's ownership.
    pub fn finish_open_cancel(
        &mut self,
        token: OpenToken,
        errno: i32,
    ) -> Result<Option<Target>, FsError> {
        self.descriptors
            .finish_cancel(token, errno)
            .map_err(FsError::from)
    }

    /// A surviving original acknowledges the first completion saved by either participant.
    /// A failed remote attempt can still observe the helper's canonical completion.
    pub fn acknowledge_open_cancel(
        &mut self,
        token: OpenToken,
        owner: OwnerToken,
        canonical: bool,
        errno: i32,
    ) -> Result<Option<Completion>, FsError> {
        let snapshot = self.open_snapshot(token)?;
        if snapshot.owner != Some(owner) {
            return Err(FsError::BadFileDescriptor);
        }
        if snapshot.completion.is_some() {
            return self.ack_open_record(token, owner).map(Some);
        }
        if canonical {
            let _snapshot = self.finish_open_cancel(token, errno)?;
            return self.ack_open_record(token, owner).map(Some);
        }
        Ok(None)
    }

    /// The same paid record owns canonical cleanup after an unreturned publication.
    pub fn abandon_open_record(
        &mut self,
        token: OpenToken,
        recovery: Recovery,
    ) -> Result<Abandoned<Target, Recovery>, FsError> {
        self.descriptors
            .abandon_open_with_recovery(token, recovery)
            .map_err(FsError::from)
    }

    /// Original records are detached individually with their preflight recovery payload.
    /// This final pass releases helper claims after every original has detached.
    pub fn detach_open_helper(&mut self, owner: OwnerToken) -> Option<Abandoned<Target, Recovery>> {
        self.descriptors.abandon_owner(owner)
    }

    pub fn open_tokens(&self) -> impl Iterator<Item = OpenToken> + '_ {
        self.descriptors.open_tokens()
    }

    /// Shared pins PosixFs before admission. The hold's wait header survives reuse.
    pub fn open_wait_address(&self, token: OpenToken) -> Result<usize, FsError> {
        self.descriptors
            .wait_word(token)
            .map(|word| core::ptr::from_ref(word) as usize)
            .map_err(FsError::from)
    }

    pub fn open_wait_snapshot(&self, token: OpenToken) -> Result<WaitValue, FsError> {
        self.descriptors.wait_snapshot(token).map_err(FsError::from)
    }

    pub fn try_take_dup3(
        &mut self,
        source: u32,
        target: u32,
        flags: Option<DescriptorFlags>,
    ) -> Result<Replacement<Target>, FsError> {
        match flags {
            None => self.descriptors.try_dup2(source, target),
            Some(flags) => self.descriptors.try_dup3(source, target, flags),
        }
        .map_err(FsError::from)
    }
}

impl Recovery {
    /// Capture the immutable full outcome before the final handoff request.
    pub fn remember(mut self, held: PreparedOpen) -> Self {
        self.backend_fd = held.fd
            | (held.slot << proto_fs::OPEN_DESCRIPTION_SHIFT)
            | if held.random {
                proto_fs::OPEN_RANDOM
            } else {
                0
            };
        self.description_generation = held.generation;
        self.phase = Phase::Finishing;
        self
    }
}

impl PosixFs {
    /// A native owner keeps exclusive access to this pinned table through the call.
    /// Public threaded callers use the shared adapter between each paid phase.
    pub fn open_policy(
        &mut self,
        path: &[u8],
        flags: u32,
        mode: u32,
        umask: u32,
        descriptor_flags: DescriptorFlags,
    ) -> Result<u32, FsError> {
        let resolved = self.resolve(path)?;
        let owner = OwnerToken::new(1)?;
        let (token, claim) = self.begin_open_record(owner, flags & 3, descriptor_flags)?;
        let key = proto_fs::OpenKey {
            slot: token.slot() as u32,
            generation: token.generation(),
        };
        let transport = self.transport();
        let files = transport.files();
        let mut recovery = Recovery::starting(flags & 3, descriptor_flags)?;
        let result = (|| {
            recovery.job = files.open_start(key, resolved.as_bytes(), flags, mode, umask)?;
            recovery.phase = Phase::Traversing;
            self.update_open_record(claim, recovery)?;
            while !files.open_advance(recovery.job, false)? {}
            recovery.phase = Phase::Preparing;
            self.update_open_record(claim, recovery)?;
            while !files.open_advance(recovery.job, true)? {}
            self.reserve_open_record(claim)?;
            recovery.phase = Phase::Committing;
            self.update_open_record(claim, recovery)?;
            let held = files.open_commit(recovery.job)?;
            recovery = recovery.remember(held);
            self.update_open_record(claim, recovery)?;
            let target = super::Transport::opened_target(held, recovery.access as u32)?;
            self.stage_open_record(claim, target)?;
            let finished = files.open_finish(key)?;
            if finished != held {
                return Err(FsError::Io);
            }
            self.publish_open_record(claim)?;
            self.ack_open_record(token, owner)?
                .into_result()
                .map_err(|_| FsError::Io)
        })();
        if result.is_err() && self.begin_open_cancel(claim).is_ok() {
            if files.open_cancel_key(key).is_ok() {
                // Native Cancel consumes the exact backend reference. Its snapshot
                // carries no further ordinary Close obligation.
                let _ = self.finish_open_cancel(token, 5);
                let _ = self.ack_open_record(token, owner);
            } else {
                // The same record retains cleanup until a later native owner phase.
                let _ = self.abandon_open_record(token, recovery);
            }
        }
        result
    }
}

impl PosixFs {
    /// Recover cleanup identity only from the still-current unreturned entry.
    pub fn published_open_recovery(&self, entry: Option<EntryToken>) -> Result<Recovery, i32> {
        let Some(entry) = entry else {
            return Ok(Recovery::default());
        };
        if self.descriptors.entry_token(entry.fd).ok() != Some(entry) {
            return Ok(Recovery::default());
        }
        let exact = match self.descriptors.get(entry.fd).map_err(|_| 5)? {
            Target::Ram(exact) | Target::Random(exact) => exact,
            _ => return Err(5),
        };
        let flags = self.descriptors.flags(entry.fd).map_err(|_| 5)?;
        Ok(Recovery::starting(proto_fs::READ_ONLY, flags)
            .map_err(|_| 5)?
            .remember(exact.prepared()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{ManuallyDrop, size_of};
    use rt::{
        fs::Files,
        handle::{Channel, Handle},
    };

    fn files() -> ManuallyDrop<PosixFs> {
        // These local transitions issue no system calls; the fixture never drops transports.
        ManuallyDrop::new(
            PosixFs::from_files(Files::from_sessions(
                Handle::<Channel>::from_raw(rt::abi::Handle::new(7, 9)),
                None,
            ))
            .unwrap(),
        )
    }
    fn flags() -> DescriptorFlags {
        DescriptorFlags {
            close_on_exec: true,
            close_on_fork: true,
        }
    }
    fn preparing(files: &mut PosixFs) -> (OpenToken, ClaimToken, EntryToken) {
        let (token, claim) = files
            .begin_open_record(OwnerToken::new(1).unwrap(), 0, flags())
            .unwrap();
        let mut recovery = files.open_snapshot(token).unwrap().recovery.unwrap();
        recovery.job = 256;
        recovery.phase = Phase::Traversing;
        files.update_open_record(claim, recovery).unwrap();
        recovery.phase = Phase::Preparing;
        files.update_open_record(claim, recovery).unwrap();
        let entry = files.reserve_open_record(claim).unwrap();
        (token, claim, entry)
    }
    fn reserved(files: &mut PosixFs) -> (OpenToken, ClaimToken, EntryToken) {
        let (token, claim, entry) = preparing(files);
        let mut recovery = files.open_snapshot(token).unwrap().recovery.unwrap();
        recovery.phase = Phase::Committing;
        files.update_open_record(claim, recovery).unwrap();
        (token, claim, entry)
    }

    #[test]
    fn ordinary_updates_cannot_restore_preparation_or_change_request_history() {
        let mut files = files();
        let (token, claim, _) = reserved(&mut files);
        let before = files.open_snapshot(token).unwrap();
        let wait = files.open_wait_snapshot(token).unwrap();
        for phase in [
            Phase::Starting,
            Phase::Traversing,
            Phase::Preparing,
            Phase::Canceling,
        ] {
            let mut wrong = before.recovery.unwrap();
            wrong.phase = phase;
            assert_eq!(
                files.update_open_record(claim, wrong),
                Err(FsError::InvalidArgument)
            );
            assert_eq!(files.open_snapshot(token).unwrap(), before);
            assert_eq!(files.open_wait_snapshot(token).unwrap(), wait);
        }
        for job in [0, 512, 384] {
            let mut wrong = before.recovery.unwrap();
            wrong.job = job;
            assert_eq!(
                files.update_open_record(claim, wrong),
                Err(FsError::InvalidArgument)
            );
        }
        let remembered = before.recovery.unwrap().remember(PreparedOpen {
            fd: 3,
            slot: 0,
            generation: 1,
            random: false,
        });
        files.update_open_record(claim, remembered).unwrap();
        let finished = files.open_snapshot(token).unwrap();
        let wrong = remembered.remember(PreparedOpen {
            fd: 4,
            slot: 1,
            generation: 2,
            random: true,
        });
        assert_eq!(
            files.update_open_record(claim, wrong),
            Err(FsError::InvalidArgument)
        );
        assert_eq!(files.open_snapshot(token).unwrap(), finished);
    }

    #[test]
    fn final_context_is_minted_once_from_the_exact_current_preparation() {
        let mut files = files();
        let (token, claim, entry) = preparing(&mut files);
        let (_, _, foreign_entry) = preparing(&mut files);
        let before = files.open_snapshot(token).unwrap();
        assert!(files.begin_open_finalize(claim, foreign_entry).is_err());
        assert_eq!(files.open_snapshot(token).unwrap(), before);
        files.release_open_claim(claim).unwrap();
        let Claim::Acquired { token: next, .. } = files
            .claim_open_record(token, OwnerToken::new(1).unwrap())
            .unwrap()
        else {
            panic!("claim");
        };
        let before = files.open_snapshot(token).unwrap();
        assert!(files.begin_open_finalize(claim, entry).is_err());
        assert_eq!(files.open_snapshot(token).unwrap(), before);
        let context = files.begin_open_finalize(next, entry).unwrap();
        assert_eq!(context.claim, next);
        assert_eq!(context.entry, entry);
        assert_eq!(context.job, 256);
        assert_eq!(context.session, files.sessions().0.raw());
        assert_eq!(context.key().slot, token.slot() as u32);
        assert_eq!(context.key().generation, token.generation());
        let committed = files.open_snapshot(token).unwrap();
        assert_eq!(committed.recovery.unwrap().phase, Phase::Committing);
        assert!(files.begin_open_finalize(next, entry).is_err());
        assert_eq!(files.open_snapshot(token).unwrap(), committed);
        // The unit fixture consumes the private proof boundary without issuing native RPC.
        files
            .unreserve_open_record(next, entry, context.prepared())
            .unwrap();
        let snapshot = files.open_snapshot(token).unwrap();
        assert_eq!(snapshot.claimant, None);
        assert_eq!(snapshot.recovery.unwrap().phase, Phase::Preparing);
        assert_eq!(snapshot.recovery.unwrap().descriptor_flags(), flags());
    }

    #[test]
    fn starting_history_requires_a_real_nonzero_job_and_forward_phase() {
        let mut files = files();
        let (token, claim) = files
            .begin_open_record(OwnerToken::new(1).unwrap(), 0, flags())
            .unwrap();
        let original = files.open_snapshot(token).unwrap().recovery.unwrap();
        for (phase, job) in [
            (Phase::Preparing, 256),
            (Phase::Traversing, 0),
            (Phase::Traversing, 384),
            (Phase::Finishing, 256),
        ] {
            let mut wrong = original;
            wrong.phase = phase;
            wrong.job = job;
            assert_eq!(
                files.update_open_record(claim, wrong),
                Err(FsError::InvalidArgument)
            );
        }
        assert_eq!(files.open_snapshot(token).unwrap().recovery, Some(original));
    }
    fn proof(files: &PosixFs, claim: ClaimToken, entry: EntryToken) -> PreparedNoEffect {
        PreparedNoEffect {
            claim,
            entry,
            job: 256,
            session: files.sessions().0.raw(),
        }
    }
    #[test]
    fn starting_flags_survive_owner_end_and_updates_preserve_capture() {
        let mut files = files();
        let owner = OwnerToken::new(1).unwrap();
        assert_eq!(
            files.begin_open_record(owner, 3, flags()),
            Err(FsError::InvalidArgument)
        );
        assert_eq!(files.open_tokens().count(), 0);
        let (token, claim) = files.begin_open_record(owner, 2, flags()).unwrap();
        let original = files.open_snapshot(token).unwrap().recovery.unwrap();
        assert_eq!(original.phase, Phase::Starting);
        assert_eq!(original.descriptor_flags(), flags());
        for wrong in [
            Recovery::starting(2, DescriptorFlags::default()).unwrap(),
            Recovery::starting(1, flags()).unwrap(),
        ] {
            assert_eq!(
                files.update_open_record(claim, wrong),
                Err(FsError::InvalidArgument)
            );
            assert_eq!(files.open_snapshot(token).unwrap().recovery, Some(original));
        }
        files.abandon_open_record(token, original).unwrap();
        let snapshot = files.open_snapshot(token).unwrap();
        assert_eq!(snapshot.owner, None);
        assert_eq!(snapshot.recovery.unwrap().descriptor_flags(), flags());
    }
    #[test]
    fn proof_releases_exact_pending_and_retains_flags_for_next_claim() {
        let mut files = files();
        let (token, claim, entry) = reserved(&mut files);
        let p = proof(&files, claim, entry);
        assert_eq!(files.unreserve_open_record(claim, entry, p), Ok(entry));
        let snapshot = files.open_snapshot(token).unwrap();
        assert_eq!(snapshot.claimant, None);
        assert_eq!(snapshot.phase, OpenPhase::Preparing);
        assert_eq!(snapshot.recovery.unwrap().phase, Phase::Preparing);
        assert_eq!(snapshot.recovery.unwrap().descriptor_flags(), flags());
        assert!(files.reserve_open_record(claim).is_err());
        let Claim::Acquired { token: next, .. } = files
            .claim_open_record(token, OwnerToken::new(1).unwrap())
            .unwrap()
        else {
            panic!("next claim");
        };
        let replacement = files.reserve_open_record(next).unwrap();
        assert_eq!(replacement.fd, entry.fd);
        assert!(replacement.generation() > entry.generation());
        assert_eq!(files.open_snapshot(token).unwrap().flags, Some(flags()));
        let mut recovery = files.open_snapshot(token).unwrap().recovery.unwrap();
        recovery.phase = Phase::Committing;
        files.update_open_record(next, recovery).unwrap();
        let before = files.open_snapshot(token).unwrap();
        let old = proof(&files, claim, entry);
        assert_eq!(
            files.unreserve_open_record(next, replacement, old),
            Err(FsError::BadFileDescriptor)
        );
        assert_eq!(files.open_snapshot(token).unwrap(), before);
        let wrong_entry = proof(&files, next, entry);
        assert_eq!(
            files.unreserve_open_record(next, replacement, wrong_entry),
            Err(FsError::BadFileDescriptor)
        );
        assert_eq!(files.open_snapshot(token).unwrap(), before);
    }
    #[test]
    fn foreign_session_job_and_remembered_backend_refuse_without_changes() {
        let mut files = files();
        let (token, claim, entry) = reserved(&mut files);
        let before = files.open_snapshot(token).unwrap();
        let mut bad = proof(&files, claim, entry);
        bad.session = rt::abi::Handle::new(7, 10);
        assert_eq!(
            files.unreserve_open_record(claim, entry, bad),
            Err(FsError::BadFileDescriptor)
        );
        let mut bad = proof(&files, claim, entry);
        bad.job = 512;
        assert_eq!(
            files.unreserve_open_record(claim, entry, bad),
            Err(FsError::BadFileDescriptor)
        );
        assert_eq!(files.open_snapshot(token).unwrap(), before);
        let remembered = before.recovery.unwrap().remember(PreparedOpen {
            fd: 3,
            slot: 0,
            generation: 1,
            random: false,
        });
        files.update_open_record(claim, remembered).unwrap();
        let p = proof(&files, claim, entry);
        assert_eq!(
            files.unreserve_open_record(claim, entry, p),
            Err(FsError::BadFileDescriptor)
        );
        assert_eq!(
            files.open_snapshot(token).unwrap().recovery,
            Some(remembered)
        );
    }
    #[test]
    fn full_paid_budget_keeps_recovery_and_helper_detach_revokes_claim() {
        let mut files = files();
        let (token, claim, entry) = reserved(&mut files);
        let owner = OwnerToken::new(1).unwrap();
        for _ in 1..32 {
            files
                .begin_open_record(owner, 0, DescriptorFlags::default())
                .unwrap();
        }
        let p = proof(&files, claim, entry);
        files.unreserve_open_record(claim, entry, p).unwrap();
        assert_eq!(
            files.begin_open_record(owner, 0, flags()),
            Err(FsError::TooManyOpenFiles)
        );
        let helper = OwnerToken::new(2).unwrap();
        let Claim::Acquired {
            token: helper_claim,
            ..
        } = files.claim_open_record(token, helper).unwrap()
        else {
            panic!("helper");
        };
        assert!(matches!(
            files.detach_open_helper(helper),
            Some(Abandoned::ClaimReleased(_))
        ));
        assert!(files.reserve_open_record(helper_claim).is_err());
        let snapshot = files.open_snapshot(token).unwrap();
        assert_eq!(snapshot.owner, Some(owner));
        assert_eq!(snapshot.claimant, None);
        assert_eq!(snapshot.recovery.unwrap().descriptor_flags(), flags());
        assert_eq!(files.open_tokens().count(), 32);
    }

    #[test]
    fn captured_flags_fill_existing_recovery_padding_and_table_union() {
        #[derive(Clone, Copy)]
        #[repr(C)]
        struct Legacy {
            job: u64,
            generation: u64,
            fd: u32,
            phase: Phase,
            access: u8,
        }
        #[allow(dead_code)]
        struct LegacyFs {
            files: Files,
            pipes: Option<Handle<Channel>>,
            terminal: Option<Handle<Channel>>,
            paths: crate::PathState,
            descriptors: posix_fd::Table<Target, 32, Legacy>,
        }
        assert_eq!(size_of::<Recovery>(), 24);
        assert_eq!(size_of::<PosixFs>(), size_of::<LegacyFs>());
        assert_eq!(
            core::mem::align_of::<PosixFs>(),
            core::mem::align_of::<LegacyFs>()
        );
        assert_eq!(size_of::<posix_fd::Table<Target, 32, Recovery>>(), 4880);
        assert_eq!(
            size_of::<posix_fd::Table<Target, 32, Recovery>>(),
            size_of::<posix_fd::Table<Target, 32, Legacy>>()
        );
        assert_eq!(
            size_of::<posix_fd::Table<Target, 32, Recovery, [u8; 1016]>>(),
            37136
        );
    }
}
