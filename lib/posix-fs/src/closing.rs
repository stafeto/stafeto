// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Frozen numeric close events and their exact physical cleanup receipts.

use super::{DescriptorFlags, FsError, PosixFs, Target};
use entries::Frame;
pub use posix_fd::{CloseAdmission, CloseSnapshot, CloseToken, JobPlace, OwnerToken, WaitValue};
use proto_fs::DataDescription;

pub type Snapshot = CloseSnapshot<Target, Frame>;
pub type Admission = CloseAdmission<Target, Frame>;
/// What the process knows about its record locks. A close of any descriptor
/// releases the locks of the process on the file, so the close of an alias
/// owes the service a message only while the process may hold one. The
/// service answers every close event with whether the process holds none.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecordLocks {
    none: bool,
    epoch: u64,
    /// Lock commands between their begin and their end.
    commands: u32,
}
impl RecordLocks {
    pub(crate) const fn new() -> Self {
        Self {
            none: false,
            epoch: 0,
            commands: 0,
        }
    }
}

/// A question about the record locks, put with a close event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asked(u64);

impl PosixFs {
    /// Whether closing `fd` only drops a name of a description that another
    /// descriptor keeps while the process is known to hold no record lock and
    /// no lock command is outstanding: the close then owes the service
    /// nothing and is as local as the close of a pipe.
    pub fn closes_alias_with_no_record_lock(&self, fd: u32) -> bool {
        self.record_locks.none && self.descriptors.has_open_alias(fd) && self.no_lock_command()
    }
    /// Whether the process is known to hold no record lock.
    pub fn knows_no_record_lock(&self) -> bool {
        self.record_locks.none
    }
    /// Whether no lock command of the files is outstanding.
    pub fn no_lock_command(&self) -> bool {
        self.record_locks.commands == 0
    }
    /// The question to put with a close event: the count of lock commands
    /// begun so far, or None while a lock command is outstanding, when no
    /// answer can settle it (the service may answer before a command that
    /// is under way reaches it).
    pub fn record_locks_question(&self) -> Option<Asked> {
        self.no_lock_command()
            .then_some(Asked(self.record_locks.epoch))
    }
    /// The service answered a close event that the process holds no record
    /// lock: kept only if no lock command is outstanding and none has begun
    /// since the question.
    pub fn record_locks_answered_none(&mut self, asked: Asked) {
        if self.record_locks.epoch == asked.0 && self.no_lock_command() {
            self.record_locks.none = true;
        }
    }
    /// A lock command begins: the process may hold a record lock from now
    /// until the service says otherwise. The result names the open file
    /// description the command acts on; `lock_ends` follows the reply.
    pub fn lock_begins(&mut self, fd: u32) -> Result<DataDescription, FsError> {
        let backend = match self.descriptors.get(fd).map_err(FsError::from)? {
            Target::Ram(backend) | Target::Random(backend) => backend,
            _ => return Err(FsError::InvalidArgument),
        };
        self.record_lock_command_begins();
        self.record_locks.commands += 1;
        Ok(DataDescription {
            packed: backend.fd() | backend.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT,
            generation: backend.generation(),
        })
    }
    /// A lock command begins: the process may hold a record lock from now
    /// until the service says otherwise.
    pub(crate) fn record_lock_command_begins(&mut self) {
        self.record_locks.none = false;
        self.record_locks.epoch = self.record_locks.epoch.wrapping_add(1);
    }
    pub(crate) fn lock_commands_forgotten(&mut self) {
        self.record_locks.commands = 0;
    }
    pub fn lock_ends(&mut self) {
        self.record_locks.commands = self.record_locks.commands.saturating_sub(1);
    }
    pub fn pending_open(&self, fd: u32) -> Option<posix_fd::OpenToken> {
        self.descriptors.pending(fd)
    }

    pub fn closing(&self, fd: u32) -> Option<CloseToken> {
        self.descriptors.closing(fd)
    }
    pub fn close_tokens(&self) -> impl Iterator<Item = CloseToken> + '_ {
        self.descriptors.close_tokens()
    }
    pub fn close_snapshot(&self, token: CloseToken) -> Result<Snapshot, FsError> {
        self.descriptors
            .close_snapshot(token)
            .map(snapshot_frame)
            .map_err(FsError::from)
    }
    pub fn close_place(&self, owner: OwnerToken) -> JobPlace {
        self.descriptors.close_place(owner)
    }
    pub fn close_wait_address(&self, token: CloseToken) -> Result<usize, FsError> {
        self.descriptors
            .close_wait_word(token)
            .map(|word| core::ptr::from_ref(word) as usize)
            .map_err(FsError::from)
    }
    pub fn begin_close_record(
        &mut self,
        owner: Option<OwnerToken>,
        fd: u32,
        frame: Frame,
    ) -> Result<Admission, FsError> {
        match owner {
            Some(owner) => {
                self.descriptors
                    .begin_close(owner, fd, super::control::Recovery::closing(frame))
            }
            None => self
                .descriptors
                .begin_close_unowned(fd, super::control::Recovery::closing(frame)),
        }
        .map(admission_frame)
        .map_err(FsError::from)
    }
    pub fn begin_replace_record(
        &mut self,
        owner: Option<OwnerToken>,
        source: u32,
        target: u32,
        flags: Option<DescriptorFlags>,
        frame: Frame,
    ) -> Result<Admission, FsError> {
        match owner {
            Some(owner) => self.descriptors.begin_replace(
                owner,
                source,
                target,
                flags,
                super::control::Recovery::closing(frame),
            ),
            None => self.descriptors.begin_replace_unowned(
                source,
                target,
                flags,
                super::control::Recovery::closing(frame),
            ),
        }
        .map(admission_frame)
        .map_err(FsError::from)
    }
    pub fn finish_close_record(&mut self, token: CloseToken) -> Result<Option<Target>, FsError> {
        self.descriptors.finish_close(token).map_err(FsError::from)
    }
    pub fn finish_close_release(
        &mut self,
        token: CloseToken,
        target: Target,
    ) -> Result<(), FsError> {
        self.descriptors
            .finish_close_release(token, target)
            .map_err(FsError::from)
    }
    pub fn ack_close_record(
        &mut self,
        token: CloseToken,
        owner: Option<OwnerToken>,
    ) -> Result<(), FsError> {
        self.descriptors
            .ack_close(token, owner)
            .map_err(FsError::from)
    }
    pub fn abandon_close_owner(&mut self, owner: OwnerToken) -> Option<(CloseToken, Snapshot)> {
        self.descriptors
            .abandon_close_owner(owner)
            .map(|(token, snapshot)| (token, snapshot_frame(snapshot)))
    }
}

fn snapshot_frame(snapshot: CloseSnapshot<Target, super::control::Recovery>) -> Snapshot {
    CloseSnapshot {
        owner: snapshot.owner,
        recovery: snapshot.recovery.frame(),
        entry: snapshot.entry,
        backend: snapshot.backend,
        last_alias: snapshot.last_alias,
        replacement: snapshot.replacement,
        complete: snapshot.complete,
        release: snapshot.release,
    }
}
fn admission_frame(admission: CloseAdmission<Target, super::control::Recovery>) -> Admission {
    match admission {
        CloseAdmission::Started { token, snapshot } => CloseAdmission::Started {
            token,
            snapshot: snapshot_frame(snapshot),
        },
        CloseAdmission::PendingOpen(token) => CloseAdmission::PendingOpen(token),
        CloseAdmission::PendingClose(token) => CloseAdmission::PendingClose(token),
        CloseAdmission::Replaced(number) => CloseAdmission::Replaced(number),
    }
}
