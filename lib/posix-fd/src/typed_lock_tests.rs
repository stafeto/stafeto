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
    Tty(u32),
    Input,
    Output,
    Error,
}
struct PosixFs {
    descriptors: Table<Target, 32, (), (), control::Recovery>,
    waits: super::WaitRecords<wait::Recovery>,
}

#[allow(dead_code, unused_imports)]
#[path = "../../posix-fs/src/change.rs"]
mod change;
#[allow(dead_code)]
#[path = "../../posix-fs/src/control.rs"]
mod control;
#[allow(dead_code)]
#[path = "../../posix-fs/src/drain.rs"]
mod drain;

fn fixture() -> (PosixFs, EntryToken, RamTarget, control::Input) {
    let mut files = PosixFs {
        descriptors: Table::default(),
        waits: super::WaitRecords::new(),
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

#[test]
fn exact_jump_marks_departing_frames_even_before_a_deeper_next_call() {
    let (mut files, entry, _, input) = fixture();
    let other = OwnerToken::new(2).unwrap();
    let (gone, claim) = files
        .begin_lock_record(owner(), entry, Frame::main(100), input)
        .unwrap();
    let (equal, equal_claim) = files
        .begin_lock_record(owner(), entry, Frame::main(200), input)
        .unwrap();
    let (outer, outer_claim) = files
        .begin_lock_record(owner(), entry, Frame::main(300), input)
        .unwrap();
    let (foreign, foreign_claim) = files
        .begin_lock_record(other, entry, Frame::main(100), input)
        .unwrap();
    let (change, change_claim) = files
        .begin_change_record(owner(), Frame::main(100))
        .unwrap();
    files.mark_control_jump(owner(), Frame::main(200));
    assert!(!files.lock_is_live(claim));
    assert!(!files.change_is_live(change_claim));
    assert_eq!(files.lock_snapshot(gone).unwrap().owner, None);
    assert_eq!(files.change_snapshot(change).unwrap().owner, None);
    assert!(files.lock_is_live(equal_claim));
    assert!(files.lock_is_live(outer_claim));
    assert!(files.lock_is_live(foreign_claim));
    assert_eq!(files.lock_snapshot(equal).unwrap().owner, Some(owner()));
    assert_eq!(files.lock_snapshot(outer).unwrap().owner, Some(owner()));
    assert_eq!(files.lock_snapshot(foreign).unwrap().owner, Some(other));
    // A deeper call cannot resurrect the departed frame after an explicit mark.
    assert_eq!(
        files.pick_lock_cleanup(Some(owner()), Frame::main(50), None),
        Ok(Some(gone))
    );
}

#[test]
fn jump_keeps_completed_receipt_and_close_reason_until_exact_release() {
    let (mut files, entry, _, input) = fixture();
    let (token, claim) = files
        .begin_lock_record(owner(), entry, Frame::main(100), input)
        .unwrap();
    files
        .complete_lock_record(claim, ControlResult::Value(0), terminal(blocker()))
        .unwrap();
    files
        .begin_lock_cleanup(token, control::CancelReason::Close)
        .unwrap();
    files.mark_control_jump(owner(), Frame::main(200));
    let saved = files.lock_snapshot(token).unwrap();
    assert_eq!(saved.result, Some(ControlResult::Value(0)));
    assert_eq!(saved.recovery.lock().unwrap().outcome(), Some(blocker()));
    assert_eq!(
        saved.recovery.lock().unwrap().cancel_reason(),
        control::CancelReason::Close
    );
    files.mark_control_jump(owner(), Frame::main(400));
    assert_eq!(files.lock_snapshot(token).unwrap().result, saved.result);
    files.finish_lock_cleanup(token).unwrap();
    assert_eq!(files.lock_snapshot(token), Err(FsError::BadFileDescriptor));
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

#[test]
fn typed_decoded_terminal_constructor_checks_phase_and_blocker_without_wire_buffer() {
    assert_eq!(
        control::TerminalReply::from_reply(blocker())
            .unwrap()
            .reply(),
        blocker()
    );
    assert_eq!(
        control::TerminalReply::from_reply(LockReply {
            phase: LockPhase::Pending,
            result: 0,
            blocker: None
        }),
        Err(FsError::InvalidArgument)
    );
    let mut invalid = blocker();
    invalid.blocker.as_mut().unwrap().start = -1;
    assert_eq!(
        control::TerminalReply::from_reply(invalid),
        Err(FsError::InvalidArgument)
    );
    let mut invalid = blocker();
    invalid.blocker.as_mut().unwrap().pid = 0;
    assert_eq!(
        control::TerminalReply::from_reply(invalid),
        Err(FsError::InvalidArgument)
    );
}

#[test]
fn close_fence_retains_working_cleaning_and_complete_debts_until_confirmation() {
    let (mut files, entry, _, input) = fixture();
    let (working, working_claim) = files
        .begin_lock_record(owner(), entry, Frame::main(91), input)
        .unwrap();
    let (cleaning, _) = files
        .begin_lock_record(owner(), entry, Frame::main(92), input)
        .unwrap();
    files
        .begin_lock_cleanup(cleaning, control::CancelReason::Abandoned)
        .unwrap();
    let (complete, complete_claim) = files
        .begin_lock_record(owner(), entry, Frame::main(93), input)
        .unwrap();
    files
        .complete_lock_record(complete_claim, ControlResult::Value(0), terminal(blocker()))
        .unwrap();
    let close = match files
        .descriptors
        .begin_close(
            owner(),
            entry.fd,
            control::Recovery::change(Frame::main(94)),
        )
        .unwrap()
    {
        super::CloseAdmission::Started { token, snapshot } => {
            assert_eq!(snapshot.entry, entry);
            token
        }
        _ => panic!("close admission"),
    };
    assert_eq!(files.fence_lock_for_close(entry), Ok(Some(working)));
    assert!(!files.lock_is_live(working_claim));
    assert_eq!(
        files
            .lock_snapshot(working)
            .unwrap()
            .recovery
            .lock()
            .unwrap()
            .cancel_reason(),
        control::CancelReason::Close
    );
    assert_eq!(files.fence_lock_for_close(entry), Ok(Some(working)));
    files
        .publish_lock_cleanup(working, ControlResult::Failed(9), terminal(cancelled()))
        .unwrap();
    files.finish_lock_cleanup(working).unwrap();
    assert_eq!(files.fence_lock_for_close(entry), Ok(Some(cleaning)));
    assert_eq!(
        files
            .lock_snapshot(cleaning)
            .unwrap()
            .recovery
            .lock()
            .unwrap()
            .cancel_reason(),
        control::CancelReason::Abandoned
    );
    files
        .publish_lock_cleanup(cleaning, ControlResult::Failed(5), terminal(cancelled()))
        .unwrap();
    files.finish_lock_cleanup(cleaning).unwrap();
    assert_eq!(files.fence_lock_for_close(entry), Ok(Some(complete)));
    let saved = files.lock_snapshot(complete).unwrap();
    assert_eq!(
        (saved.result, saved.recovery.lock().unwrap().outcome()),
        (Some(ControlResult::Value(0)), Some(blocker()))
    );
    assert_eq!(
        files.publish_lock_cleanup(complete, ControlResult::Failed(9), terminal(cancelled())),
        Ok(saved)
    );
    files.finish_lock_cleanup(complete).unwrap();
    assert_eq!(files.fence_lock_for_close(entry), Ok(None));
    assert_eq!(files.control_tokens().count(), 3);
    assert!(!files.descriptors.close_snapshot(close).unwrap().complete);
}

#[test]
fn close_fence_preserves_alias_reused_generation_and_change_family() {
    let (mut files, entry, target, input) = fixture();
    let (old, _) = files
        .begin_lock_record(owner(), entry, Frame::main(91), input)
        .unwrap();
    let alias_fd = files
        .descriptors
        .duplicate(entry.fd, 0, Flags::default())
        .unwrap();
    let alias_entry = files.lock_source(alias_fd).unwrap();
    let (alias, alias_claim) = files
        .begin_lock_record(owner(), alias_entry, Frame::main(92), input)
        .unwrap();
    let (change, change_claim) = files.begin_change_record(owner(), Frame::main(93)).unwrap();
    let change_before = files.change_snapshot(change).unwrap();
    files.descriptors.close(entry.fd).unwrap();
    let reused_fd = files
        .descriptors
        .insert(Target::Ram(target), Flags::default())
        .unwrap();
    assert_eq!(reused_fd, entry.fd);
    let reused_entry = files.lock_source(reused_fd).unwrap();
    assert_ne!(reused_entry, entry);
    let (reused, reused_claim) = files
        .begin_lock_record(owner(), reused_entry, Frame::main(94), input)
        .unwrap();
    let alias_before = files.lock_snapshot(alias).unwrap();
    let reused_before = files.lock_snapshot(reused).unwrap();
    assert_eq!(files.fence_lock_for_close(entry), Ok(Some(old)));
    files
        .publish_lock_cleanup(old, ControlResult::Failed(9), terminal(cancelled()))
        .unwrap();
    files.finish_lock_cleanup(old).unwrap();
    assert_eq!(files.fence_lock_for_close(entry), Ok(None));
    assert_eq!(files.lock_snapshot(alias).unwrap(), alias_before);
    assert_eq!(files.lock_snapshot(reused).unwrap(), reused_before);
    assert_eq!(files.change_snapshot(change).unwrap(), change_before);
    assert!(files.lock_is_live(alias_claim));
    assert!(files.lock_is_live(reused_claim));
    assert!(files.change_is_live(change_claim));
}

#[test]
fn full_sixteen_controls_preserve_close_admission_and_all_fence_debts() {
    let (mut files, entry, _, input) = fixture();
    let mut tokens = [None; super::JOBS_MAX];
    for (index, slot) in tokens.iter_mut().enumerate() {
        *slot = Some(
            files
                .begin_lock_record(owner(), entry, Frame::main(100 + index as u64), input)
                .unwrap()
                .0,
        );
    }
    assert_eq!(files.control_tokens().count(), 16);
    assert_eq!(
        files.begin_change_record(owner(), Frame::main(200)),
        Err(FsError::TooManyOpenFiles)
    );
    let close = match files
        .descriptors
        .begin_close(
            owner(),
            entry.fd,
            control::Recovery::change(Frame::main(201)),
        )
        .unwrap()
    {
        super::CloseAdmission::Started { token, snapshot } => {
            assert_eq!(snapshot.entry, entry);
            token
        }
        _ => panic!("full resident table retained close admission"),
    };
    for slot in tokens {
        let token = slot.unwrap();
        assert_eq!(files.fence_lock_for_close(entry), Ok(Some(token)));
        assert_eq!(files.control_tokens().count(), 16);
        files
            .publish_lock_cleanup(token, ControlResult::Failed(9), terminal(cancelled()))
            .unwrap();
        files.finish_lock_cleanup(token).unwrap();
    }
    assert_eq!(files.fence_lock_for_close(entry), Ok(None));
    assert_eq!(files.control_tokens().count(), 16);
    assert_eq!(
        files.descriptors.close_snapshot(close).unwrap().entry,
        entry
    );
    for slot in tokens {
        assert_eq!(
            files.ack_lock_record(slot.unwrap(), owner()),
            Ok((ControlResult::Failed(9), Some(cancelled())))
        );
    }
    assert_eq!(files.control_tokens().count(), 0);
}

#[test]
fn lock_collector_preserves_nested_foreign_skipped_and_change_records() {
    let (mut files, entry, _, input) = fixture();
    let current = Frame::main(200);
    let (nested, nested_claim) = files
        .begin_lock_record(owner(), entry, Frame::main(300), input)
        .unwrap();
    let foreign = OwnerToken::new(2).unwrap();
    let (foreign_token, foreign_claim) = files
        .begin_lock_record(foreign, entry, Frame::main(100), input)
        .unwrap();
    let (skipped, skipped_claim) = files
        .begin_lock_record(owner(), entry, Frame::main(100), input)
        .unwrap();
    let (change, change_claim) = files
        .begin_change_record(owner(), Frame::main(100))
        .unwrap();
    let (left, left_claim) = files
        .begin_lock_record(owner(), entry, Frame::main(100), input)
        .unwrap();
    assert_eq!(
        files.pick_lock_cleanup(Some(owner()), current, Some(skipped)),
        Ok(Some(left))
    );
    assert!(!files.lock_is_live(left_claim));
    assert!(files.lock_is_live(nested_claim));
    assert!(files.lock_is_live(foreign_claim));
    assert!(files.lock_is_live(skipped_claim));
    assert!(files.change_is_live(change_claim));
    assert_eq!(
        files
            .lock_snapshot(left)
            .unwrap()
            .recovery
            .lock()
            .unwrap()
            .cancel_reason(),
        control::CancelReason::Abandoned
    );
    assert_eq!(
        files.lock_snapshot(nested).unwrap().phase,
        ControlPhase::Working
    );
    assert_eq!(
        files.lock_snapshot(foreign_token).unwrap().owner,
        Some(foreign)
    );
    assert_eq!(
        files.change_snapshot(change).unwrap().phase,
        ControlPhase::Working
    );
    assert_eq!(files.pick_lock_cleanup(None, current, None), Ok(None));
}

#[test]
fn lock_collector_acknowledges_sixteen_cleaned_longjmp_frames_without_rpc() {
    let (mut files, entry, _, input) = fixture();
    let mut tokens = [None; super::JOBS_MAX];
    for slot in &mut tokens {
        let (token, claim) = files
            .begin_lock_record(owner(), entry, Frame::main(100), input)
            .unwrap();
        files
            .complete_lock_record(claim, ControlResult::Value(0), terminal(blocker()))
            .unwrap();
        files
            .begin_lock_cleanup(token, control::CancelReason::Close)
            .unwrap();
        files.finish_lock_cleanup(token).unwrap();
        *slot = Some(token);
    }
    assert_eq!(files.control_tokens().count(), 16);
    assert_eq!(
        files.pick_lock_cleanup(Some(owner()), Frame::main(90), None),
        Ok(None)
    );
    assert_eq!(files.control_tokens().count(), 16);
    assert_eq!(
        files.pick_lock_cleanup(Some(owner()), Frame::main(200), None),
        Ok(None)
    );
    assert_eq!(files.control_tokens().count(), 0);
    for token in tokens.into_iter().flatten() {
        assert_eq!(files.lock_snapshot(token), Err(FsError::BadFileDescriptor));
    }
    assert!(
        files
            .begin_lock_record(owner(), entry, Frame::main(200), input)
            .is_ok()
    );
}

#[test]
fn lock_collector_detached_owner_preserves_complete_receipt_until_remote_release() {
    let (mut files, entry, _, input) = fixture();
    let (completed, claim) = files
        .begin_lock_record(owner(), entry, Frame::main(100), input)
        .unwrap();
    files
        .complete_lock_record(claim, ControlResult::Value(0), terminal(blocker()))
        .unwrap();
    let (pending, pending_claim) = files
        .begin_lock_record(owner(), entry, Frame::main(100), input)
        .unwrap();
    let foreign = OwnerToken::new(2).unwrap();
    let (live, live_claim) = files
        .begin_lock_record(foreign, entry, Frame::main(100), input)
        .unwrap();
    let (change, change_claim) = files
        .begin_change_record(owner(), Frame::main(100))
        .unwrap();
    while files.abandon_lock_owner(owner()).is_some() {}
    assert_eq!(files.control_tokens().count(), 4);
    assert!(!files.lock_is_live(pending_claim));
    assert_eq!(
        files.pick_lock_cleanup(None, Frame::main(0), None),
        Ok(Some(completed))
    );
    let before = files.lock_snapshot(completed).unwrap();
    assert_eq!(before.owner, None);
    assert_eq!(before.result, Some(ControlResult::Value(0)));
    assert_eq!(before.recovery.lock().unwrap().outcome(), Some(blocker()));
    files
        .publish_lock_cleanup(completed, ControlResult::Failed(5), terminal(cancelled()))
        .unwrap();
    assert_eq!(
        files.lock_snapshot(completed).unwrap().result,
        Some(ControlResult::Value(0))
    );
    files.finish_lock_cleanup(completed).unwrap();
    assert_eq!(
        files.lock_snapshot(completed),
        Err(FsError::BadFileDescriptor)
    );
    assert_eq!(
        files.pick_lock_cleanup(None, Frame::main(0), None),
        Ok(Some(pending))
    );
    files
        .publish_lock_cleanup(pending, ControlResult::Failed(5), terminal(cancelled()))
        .unwrap();
    files.finish_lock_cleanup(pending).unwrap();
    assert_eq!(
        files.pick_lock_cleanup(None, Frame::main(0), None),
        Ok(None)
    );
    assert_eq!(files.lock_snapshot(live).unwrap().owner, Some(foreign));
    assert!(files.lock_is_live(live_claim));
    assert!(files.change_is_live(change_claim));
    assert_eq!(files.change_snapshot(change).unwrap().owner, Some(owner()));
}

#[path = "../../posix-abi/src/change/lock_collect.rs"]
mod lock_collect;

#[path = "typed_lock_helper_tests.rs"]
mod helper_retirement;

#[allow(dead_code)]
#[path = "../../posix-fs/src/wait.rs"]
mod wait;
#[path = "typed_wait_tests.rs"]
mod wait_tests;

fn drain_fixture(early: bool) -> (PosixFs, EntryToken) {
    let mut files = PosixFs {
        descriptors: if early {
            Table::with_early_release(|target| matches!(target, Target::Tty(_)))
        } else {
            Table::default()
        },
        waits: super::WaitRecords::new(),
    };
    let fd = files
        .descriptors
        .insert(Target::Tty(0x1a02), Flags::default())
        .unwrap();
    let source = files.descriptors.entry_token(fd).unwrap();
    (files, source)
}
fn paid_drain(
    files: &mut PosixFs,
    source: EntryToken,
) -> (super::ControlToken, super::ControlClaimToken) {
    files
        .begin_drain_record(owner(), source, Frame::main(100), 0x1234_0000_0081, 0x1a02)
        .unwrap()
        .unwrap()
}

#[test]
fn drain_pays_custody_before_wait_and_keeps_full_identity() {
    let (mut files, source) = drain_fixture(true);
    let (token, claim) = paid_drain(&mut files, source);
    let first = files
        .drain_snapshot(token)
        .unwrap()
        .recovery
        .drain()
        .unwrap();
    assert!(first.held());
    assert_eq!(first.source(), source);
    assert_eq!(first.session(), 0x1234_0000_0081);
    assert_eq!(first.terminal(), 0x1a02);
    assert_eq!(first.server(), drain::Server::Unstarted);
    assert_eq!(
        files.publish_drain_wait(claim, 0),
        Err(FsError::InvalidArgument)
    );
    let key = 0xabcd_0000_0000_0007;
    files.publish_drain_wait(claim, key).unwrap();
    files.publish_drain_wait(claim, key).unwrap();
    assert_eq!(
        files.publish_drain_wait(claim, key ^ (1 << 48)),
        Err(FsError::InvalidArgument)
    );
    let saved = files
        .drain_snapshot(token)
        .unwrap()
        .recovery
        .drain()
        .unwrap();
    assert_eq!(saved.key(), key);
    assert_eq!(saved.source(), source);
    assert_eq!(saved.session(), first.session());
    assert_eq!(saved.server(), drain::Server::Waiting);
}

#[test]
fn drain_unpaid_control_refusal_does_not_take_an_io_hold() {
    let (mut files, source) = drain_fixture(true);
    for _ in 0..16 {
        files
            .begin_change_record(owner(), Frame::main(100))
            .unwrap();
    }
    assert_eq!(
        files.begin_drain_record(owner(), source, Frame::main(100), 0x8100, 0x1a02),
        Ok(None)
    );
    assert!(
        !files
            .descriptors
            .holds
            .iter()
            .any(|slot| matches!(slot.held, super::Held::Io(_)))
    );
    assert_eq!(
        files.descriptors.close(source.fd),
        Ok(Some(Target::Tty(0x1a02)))
    );
    assert_eq!(files.descriptors.unhold(Target::Tty(0x1a02)), None);
    assert_eq!(files.control_tokens().count(), 16);
    assert!(
        !files
            .descriptors
            .holds
            .iter()
            .any(|slot| matches!(slot.held, super::Held::Io(_)))
    );
}

#[test]
fn drain_rejects_reused_source_and_wrong_terminal_before_payment() {
    let (mut files, old) = drain_fixture(true);
    files.descriptors.close(old.fd).unwrap();
    let fd = files
        .descriptors
        .insert(Target::Tty(0x1a02), Flags::default())
        .unwrap();
    assert_eq!(fd, old.fd);
    assert_eq!(
        files.begin_drain_record(owner(), old, Frame::main(100), 0x8100, 0x1a02),
        Err(FsError::BadFileDescriptor)
    );
    let fresh = files.descriptors.entry_token(fd).unwrap();
    assert_eq!(
        files.begin_drain_record(owner(), fresh, Frame::main(100), 0x8100, 0x2a02),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(
        files.begin_drain_record(owner(), fresh, Frame::main(100), 0, 0x1a02),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(files.control_tokens().count(), 0);
}

#[test]
fn drain_canonical_ready_survives_jump_and_reclaims_more_than_the_pool() {
    let (mut files, source) = drain_fixture(true);
    for _ in 0..40 {
        let (token, claim) = paid_drain(&mut files, source);
        files.publish_drain_wait(claim, 0x1234_0000_0007).unwrap();
        files.publish_drain_terminal(claim, true).unwrap();
        files.mark_control_jump(owner(), Frame::main(200));
        let saved = files.drain_snapshot(token).unwrap();
        assert_eq!(saved.owner, None);
        assert_eq!(saved.result, Some(ControlResult::Value(0)));
        assert_eq!(
            files.pick_drain_cleanup(Some(owner()), Frame::main(50), None),
            Ok(Some(token))
        );
        assert_eq!(files.release_drain_hold(token).unwrap().release(), None);
        files.finish_drain_cleanup(token).unwrap();
        assert_eq!(files.drain_snapshot(token), Err(FsError::BadFileDescriptor));
    }
    assert_eq!(files.descriptors.get(source.fd), Ok(Target::Tty(0x1a02)));
    assert_eq!(files.control_tokens().count(), 0);
}

#[test]
fn drain_cancel_confirmation_is_exact_and_never_double_unholds_a_sibling() {
    let (mut files, source) = drain_fixture(false);
    files.descriptors.hold(source.fd).unwrap();
    let (token, claim) = paid_drain(&mut files, source);
    files.publish_drain_wait(claim, 0xf123_0000_0007).unwrap();
    let saved = files.begin_drain_cleanup(token).unwrap();
    assert_eq!(
        files.release_drain_hold(token),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(
        files.confirm_drain_gone(token, saved.session() ^ (1 << 48), saved.key()),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(
        files.confirm_drain_gone(token, saved.session(), saved.key() ^ (1 << 48)),
        Err(FsError::InvalidArgument)
    );
    files
        .confirm_drain_gone(token, saved.session(), saved.key())
        .unwrap();
    files
        .confirm_drain_gone(token, saved.session(), saved.key())
        .unwrap();
    assert_eq!(files.descriptors.close(source.fd), Ok(None));
    assert_eq!(files.release_drain_hold(token).unwrap().release(), None);
    assert_eq!(files.release_drain_hold(token).unwrap().release(), None);
    assert_eq!(
        files.descriptors.unhold(Target::Tty(0x1a02)),
        Some(Target::Tty(0x1a02))
    );
    files.finish_drain_cleanup(token).unwrap();
    files.ack_drain_record(token, owner()).unwrap();
}

#[test]
fn drain_release_debt_survives_helper_jump_and_late_tokens() {
    let (mut files, source) = drain_fixture(false);
    let (token, claim) = paid_drain(&mut files, source);
    files.publish_drain_wait(claim, 0x1234_0000_0007).unwrap();
    files.publish_drain_terminal(claim, true).unwrap();
    files.begin_drain_cleanup(token).unwrap();
    files.descriptors.close(source.fd).unwrap();
    let debt = files.release_drain_hold(token).unwrap();
    assert_eq!(debt.release(), Some(Target::Tty(0x1a02)));
    assert_eq!(
        files.finish_drain_cleanup(token),
        Err(FsError::InvalidArgument)
    );
    files.mark_control_jump(owner(), Frame::main(200));
    assert_eq!(
        files
            .drain_snapshot(token)
            .unwrap()
            .recovery
            .drain()
            .unwrap(),
        debt
    );
    assert_eq!(
        files.confirm_drain_release(token, Target::Tty(0x2a02)),
        Err(FsError::InvalidArgument)
    );
    files
        .confirm_drain_release(token, Target::Tty(0x1a02))
        .unwrap();
    files.finish_drain_cleanup(token).unwrap();
    let fd = files
        .descriptors
        .insert(Target::Tty(0x1a02), Flags::default())
        .unwrap();
    let fresh = files.descriptors.entry_token(fd).unwrap();
    let (next, _) = paid_drain(&mut files, fresh);
    assert_ne!(next.generation(), token.generation());
    assert_eq!(
        files.confirm_drain_release(token, Target::Tty(0x1a02)),
        Err(FsError::BadFileDescriptor)
    );
    assert!(
        files
            .drain_snapshot(next)
            .unwrap()
            .recovery
            .drain()
            .unwrap()
            .held()
    );
}

#[test]
fn drain_early_release_preserves_alias_and_replacement_without_new_close_debt() {
    let (mut files, source) = drain_fixture(true);
    let alias = files
        .descriptors
        .insert(Target::Tty(0x1a02), Flags::default())
        .unwrap();
    let (token, claim) = paid_drain(&mut files, source);
    files.publish_drain_terminal(claim, true).unwrap();
    assert_eq!(files.descriptors.close(source.fd), Ok(None));
    let replacement = files
        .descriptors
        .insert(Target::Tty(0x2a02), Flags::default())
        .unwrap();
    assert_eq!(replacement, source.fd);
    assert_eq!(
        files.descriptors.close(alias),
        Ok(Some(Target::Tty(0x1a02)))
    );
    files.begin_drain_cleanup(token).unwrap();
    assert_eq!(files.release_drain_hold(token).unwrap().release(), None);
    files.finish_drain_cleanup(token).unwrap();
    assert_eq!(
        files.ack_drain_record(token, owner()),
        Ok(ControlResult::Value(0))
    );
    assert_eq!(files.descriptors.get(replacement), Ok(Target::Tty(0x2a02)));
}

#[test]
fn drain_genuine_end_detaches_only_the_exact_owner_and_keeps_paid_key() {
    let (mut files, source) = drain_fixture(true);
    let (token, claim) = paid_drain(&mut files, source);
    files.publish_drain_wait(claim, 0xffff_0000_0007).unwrap();
    assert_eq!(files.abandon_drain_owner(OwnerToken::new(2).unwrap()), None);
    assert!(files.abandon_drain_owner(owner()).is_some());
    let saved = files.drain_snapshot(token).unwrap();
    assert_eq!(saved.owner, None);
    assert_eq!(saved.recovery.drain().unwrap().key(), 0xffff_0000_0007);
    assert!(!files.descriptors.control_is_working(claim));
}

#[test]
fn drain_payload_fits_the_existing_largest_control_variant() {
    let bytes = core::mem::size_of::<drain::Recovery>();
    let largest = core::mem::size_of::<control::LockRecovery>();
    std::println!(
        "DrainRecovery {bytes}, LockRecovery {largest}, Recovery {}, Table {}",
        core::mem::size_of::<control::Recovery>(),
        core::mem::size_of_val(&drain_fixture(true).0.descriptors)
    );
    assert!(
        bytes <= largest,
        "drain must not enlarge the paid Control payload"
    );
}

#[test]
fn drain_fork_discards_copied_debt_without_releasing_original_descriptors() {
    let (mut files, source) = drain_fixture(false);
    let (token, claim) = paid_drain(&mut files, source);
    files.publish_drain_wait(claim, 0x1234_0000_0007).unwrap();
    files.descriptors.discard_open_after_fork();
    while files.descriptors.abandon_hold().is_some() {}
    assert_eq!(files.drain_snapshot(token), Err(FsError::BadFileDescriptor));
    assert_eq!(files.descriptors.get(source.fd), Ok(Target::Tty(0x1a02)));
    assert_eq!(
        files.descriptors.close(source.fd),
        Ok(Some(Target::Tty(0x1a02)))
    );
    assert_eq!(files.control_tokens().count(), 0);
}
