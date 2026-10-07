// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Resident Open recovery survives native sender and helper lifetimes.
//! The shared layer serializes these transitions and performs RPC after unlocking.

use super::{DescriptorFlags, FsError, PosixFs, Target};
pub use posix_fd::{
    Abandoned, Claim, ClaimToken, Completion, EntryToken, OpenSnapshot, OpenToken, OwnerToken,
    Replacement, WaitValue,
};
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
}

const _: () = assert!(core::mem::size_of::<Recovery>() == 24);

impl Recovery {
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
}

impl PosixFs {
    pub fn begin_open_record(
        &mut self,
        owner: OwnerToken,
        access: u32,
    ) -> Result<(OpenToken, ClaimToken), FsError> {
        if access > proto_fs::READ_WRITE {
            return Err(FsError::InvalidArgument);
        }
        self.descriptors
            .begin_open(
                owner,
                Recovery {
                    access: access as u8,
                    ..Recovery::default()
                },
            )
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
        self.descriptors
            .update_open(claim, recovery)
            .map_err(FsError::from)
    }

    pub fn reserve_open_record(
        &mut self,
        claim: ClaimToken,
        flags: DescriptorFlags,
    ) -> Result<EntryToken, FsError> {
        self.descriptors
            .reserve_open(claim, 0, flags)
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
