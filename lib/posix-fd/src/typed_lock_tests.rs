// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Run the production typed client transitions in a host-only descriptor container.

extern crate std;

use super::{ControlPhase, ControlResult, EntryToken, Flags, OwnerToken, Table};
use entries::Frame;
use proto_fs::{LockBlocker, LockCommand, LockKind, LockPhase, LockReply};
use proto_wire::{Status, Writer};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FsError {
    BadFileDescriptor,
    TooManyOpenFiles,
    InvalidArgument,
    Io,
}
impl From<super::Error> for FsError {
    fn from(error: super::Error) -> Self {
        match error {
            super::Error::BadFileDescriptor => Self::BadFileDescriptor,
            super::Error::TooManyOpenFiles => Self::TooManyOpenFiles,
            super::Error::InvalidArgument => Self::InvalidArgument,
            super::Error::Io => Self::Io,
        }
    }
}
impl From<Status> for FsError {
    fn from(_: Status) -> Self {
        Self::InvalidArgument
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RamTarget {
    fd: u32,
    slot: u32,
    generation: u64,
}
impl RamTarget {
    fn fd(self) -> u32 {
        self.fd
    }
    fn description_slot(self) -> u32 {
        self.slot
    }
    fn generation(self) -> u64 {
        self.generation
    }
}
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Target {
    Ram(RamTarget),
    Random(RamTarget),
    Other,
}
struct PosixFs {
    descriptors: Table<Target, 32, (), (), control::Recovery>,
}

#[allow(dead_code, unused_imports)]
#[path = "../../posix-fs/src/change.rs"]
mod change;
#[allow(dead_code)]
#[path = "../../posix-fs/src/control.rs"]
mod control;

fn fixture() -> (PosixFs, EntryToken, RamTarget, control::Input) {
    let mut files = PosixFs {
        descriptors: Table::default(),
    };
    let target = RamTarget {
        fd: 3,
        slot: 70,
        generation: 41,
    };
    let fd = files
        .descriptors
        .insert(Target::Ram(target), Flags::default())
        .unwrap();
    let entry = files.lock_source(fd).unwrap();
    let input = control::Input {
        command: LockCommand::GetOfd,
        kind: LockKind::Write,
        whence: 0,
        start: 3,
        length: 7,
        pid: 0,
    };
    (files, entry, target, input)
}
fn owner() -> OwnerToken {
    OwnerToken::new(1).unwrap()
}
fn terminal(reply: LockReply) -> control::TerminalReply {
    let mut wire = Writer::new();
    reply.write(&mut wire).unwrap();
    control::TerminalReply::read(wire.as_bytes()).unwrap()
}
fn blocker() -> LockReply {
    LockReply {
        phase: LockPhase::Complete,
        result: 0,
        blocker: Some(LockBlocker {
            kind: LockKind::Read,
            start: 8,
            length: 9,
            pid: -1,
        }),
    }
}
fn cancelled() -> LockReply {
    LockReply {
        phase: LockPhase::Complete,
        result: proto_fs::LOCK_CANCELLED,
        blocker: None,
    }
}

#[test]
fn typed_get_receipt_survives_close_helper_and_owner_ack_without_caller_storage() {
    let (mut files, entry, target, input) = fixture();
    let (token, claim) = files
        .begin_lock_record(owner(), entry, Frame::main(91), input)
        .unwrap();
    let captured = files.lock_snapshot(token).unwrap().recovery.lock().unwrap();
    assert_eq!(
        (captured.source(), captured.backend(), captured.input()),
        (entry, target, input)
    );
    assert_eq!(captured.request(token).key.generation, token.generation());
    files
        .begin_lock_cleanup(token, control::CancelReason::Close)
        .unwrap();
    assert!(!files.lock_is_live(claim));
    assert_eq!(
        files.finish_lock_cleanup(token),
        Err(FsError::InvalidArgument)
    );
    let saved = files
        .publish_lock_cleanup(token, ControlResult::Value(0), terminal(blocker()))
        .unwrap();
    assert_eq!(saved.recovery.lock().unwrap().outcome(), Some(blocker()));
    assert_eq!(saved.recovery.frame(), Frame::main(91));
    let exact = saved.recovery.lock().unwrap();
    assert_eq!(
        (exact.source(), exact.backend(), exact.input()),
        (entry, target, input)
    );
    assert_eq!(
        files.complete_lock_record(claim, ControlResult::Value(0), terminal(blocker())),
        Err(FsError::BadFileDescriptor)
    );
    assert_eq!(
        files.publish_lock_cleanup(token, ControlResult::Failed(9), terminal(cancelled())),
        Ok(saved)
    );
    files.finish_lock_cleanup(token).unwrap();
    let cleaned = files.lock_snapshot(token).unwrap();
    assert_eq!(
        (cleaned.phase, cleaned.owner),
        (ControlPhase::Cleaned, Some(owner()))
    );
    assert_eq!(
        files.ack_lock_record(token, OwnerToken::new(2).unwrap()),
        Err(FsError::BadFileDescriptor)
    );
    assert_eq!(
        files.ack_lock_record(token, owner()),
        Ok((ControlResult::Value(0), Some(blocker())))
    );
    assert_eq!(files.lock_snapshot(token), Err(FsError::BadFileDescriptor));
}

#[test]
fn typed_families_preserve_foreign_control_and_exact_source_generation() {
    let (mut files, entry, _, input) = fixture();
    let (lock, claim) = files
        .begin_lock_record(owner(), entry, Frame::main(91), input)
        .unwrap();
    let before = files.lock_snapshot(lock).unwrap();
    assert_eq!(files.change_tokens().count(), 0);
    assert_eq!(
        files.begin_change_cleanup(lock),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(
        files.finish_change_cleanup(lock),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(
        files.ack_change_record(lock, owner()),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(
        files.complete_change_record(claim, ControlResult::Value(0)),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(files.abandon_change_owner(owner()), None);
    assert_eq!(files.lock_snapshot(lock).unwrap(), before);
    let (change, _) = files.begin_change_record(owner(), Frame::main(92)).unwrap();
    assert_eq!(files.change_tokens().count(), 1);
    assert_eq!(files.lock_snapshot(change), Err(FsError::InvalidArgument));
    assert_eq!(
        files.publish_lock_cleanup(change, ControlResult::Value(0), terminal(blocker())),
        Err(FsError::InvalidArgument)
    );
    let retired = files.descriptors.close(entry.fd).unwrap();
    assert!(retired.is_some());
    let fresh_fd = files
        .descriptors
        .insert(
            Target::Ram(RamTarget {
                fd: 4,
                slot: 71,
                generation: 42,
            }),
            Flags::default(),
        )
        .unwrap();
    assert_eq!(fresh_fd, entry.fd);
    assert_ne!(files.lock_source(fresh_fd).unwrap(), entry);
    assert_eq!(
        files.begin_lock_record(owner(), entry, Frame::main(93), input),
        Err(FsError::BadFileDescriptor)
    );
    assert_eq!(
        files.lock_tokens_for(entry).collect::<std::vec::Vec<_>>(),
        [lock]
    );
    assert_eq!(
        files
            .lock_tokens_for(files.lock_source(fresh_fd).unwrap())
            .count(),
        0
    );
    assert_eq!(files.lock_snapshot(lock).unwrap(), before);
}

#[test]
fn typed_terminal_parser_and_scalar_pair_reject_pending_or_mismatched_outcomes() {
    let (mut files, entry, _, input) = fixture();
    let (token, claim) = files
        .begin_lock_record(owner(), entry, Frame::main(91), input)
        .unwrap();
    let before = files.lock_snapshot(token).unwrap();
    let mut wire = Writer::new();
    LockReply {
        phase: LockPhase::Pending,
        result: 0,
        blocker: None,
    }
    .write(&mut wire)
    .unwrap();
    assert_eq!(
        control::TerminalReply::read(wire.as_bytes()),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(
        files.complete_lock_record(claim, ControlResult::Failed(9), terminal(blocker())),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(
        files.complete_lock_record(claim, ControlResult::Value(0), terminal(cancelled())),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(files.lock_snapshot(token).unwrap(), before);
    assert!(files.lock_is_live(claim));
    let mut malformed = Writer::new();
    blocker().write(&mut malformed).unwrap();
    let mut bytes = malformed.as_bytes().to_vec();
    bytes.push(0);
    assert_eq!(
        control::TerminalReply::read(&bytes),
        Err(FsError::InvalidArgument)
    );
}

#[test]
fn typed_lock_owner_detach_keeps_change_custody_and_cleaned_owner_ack_is_local() {
    let (mut files, entry, _, input) = fixture();
    let (lock, _) = files
        .begin_lock_record(owner(), entry, Frame::main(91), input)
        .unwrap();
    let (change, change_claim) = files.begin_change_record(owner(), Frame::main(92)).unwrap();
    let before = files.change_snapshot(change).unwrap();
    assert!(
        matches!(files.abandon_lock_owner(owner()), Some(super::ControlAbandoned::Recover { token, .. }) if token == lock)
    );
    assert_eq!(files.change_snapshot(change).unwrap(), before);
    assert!(files.change_is_live(change_claim));
    assert_eq!(files.abandon_lock_owner(owner()), None);
    files
        .begin_lock_cleanup(lock, control::CancelReason::Abandoned)
        .unwrap();
    files
        .publish_lock_cleanup(lock, ControlResult::Value(0), terminal(blocker()))
        .unwrap();
    files.finish_lock_cleanup(lock).unwrap();
    assert_eq!(files.lock_snapshot(lock), Err(FsError::BadFileDescriptor));
}
