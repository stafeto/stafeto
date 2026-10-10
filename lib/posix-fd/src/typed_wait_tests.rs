// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
use super::*;
use crate::{WaitCancelReason, WaitRecordPhase, WaitRecords, WaitResult};
use proto_fs::{WaitMode, WaitPhase, WaitReply};
fn input() -> wait::Input {
    wait::Input {
        mode: WaitMode::Ofd,
        kind: LockKind::Read,
        whence: 1,
        start: 7,
        length: -3,
        pid: 0,
    }
}
fn done(code: u32) -> wait::TerminalReply {
    wait::TerminalReply::from_reply(WaitReply {
        phase: WaitPhase::Complete,
        result: code,
    })
    .unwrap()
}
fn saved_cleanup(files: &mut PosixFs, t: crate::WaitToken) {
    files
        .begin_wait_cleanup(t, WaitCancelReason::Abandoned)
        .unwrap();
    files
        .publish_wait_cleanup(t, WaitResult::Value(0), done(0))
        .unwrap();
    files.finish_wait_cleanup(t).unwrap();
}
#[test]
fn canonical_reply_reason_and_channel_debt_survive_exact_helper_publication() {
    let (mut files, entry, _, _) = fixture();
    let (t, c) = files
        .begin_wait_record(owner(), entry, Frame::main(100), input())
        .unwrap();
    let raw = 0x123456789abc0007;
    files.attach_wait_channel(c, raw).unwrap();
    files
        .begin_wait_cleanup(t, WaitCancelReason::Signal)
        .unwrap();
    assert!(!files.wait_is_live(c));
    files
        .begin_wait_cleanup(t, WaitCancelReason::Close)
        .unwrap();
    files
        .publish_wait_cleanup(t, WaitResult::Value(0), done(0))
        .unwrap();
    files
        .publish_wait_cleanup(t, WaitResult::Failed(9), done(proto_fs::LOCK_CANCELLED))
        .unwrap();
    let s = files.wait_snapshot(t).unwrap();
    assert_eq!(s.result, Some(WaitResult::Value(0)));
    assert_eq!(s.recovery.outcome(), Some(done(0).reply()));
    assert_eq!(s.reason, Some(WaitCancelReason::Signal));
    assert!(files.ack_wait_record(t, owner()).is_err());
    files.finish_wait_cleanup(t).unwrap();
    assert!(files.ack_wait_record(t, owner()).is_err());
    let debt = files.wait_channel_debt(t).unwrap().unwrap();
    assert_eq!(debt.raw(), raw);
    assert_eq!(files.wait_channel_debt(t).unwrap(), Some(debt));
    files.confirm_wait_channel_closed(debt).unwrap();
    files.confirm_wait_channel_closed(debt).unwrap();
    let (result, recovery) = files.ack_wait_record(t, owner()).unwrap();
    assert_eq!(result, WaitResult::Value(0));
    assert_eq!(recovery.outcome(), Some(done(0).reply()));
    let (next, claim) = files
        .begin_wait_record(owner(), entry, Frame::main(101), input())
        .unwrap();
    assert_eq!(next.slot(), t.slot());
    assert!(next.generation() > t.generation());
    assert!(files.confirm_wait_channel_closed(debt).is_err());
    assert!(
        files
            .publish_wait_cleanup(t, WaitResult::Value(0), done(0))
            .is_err()
    );
    assert!(files.attach_wait_channel(c, raw).is_err());
    assert!(files.wait_is_live(claim));
}
#[test]
fn paid_wait_capacity_is_independent_of_control_and_existing_close() {
    let (mut files, entry, _, control_input) = fixture();
    for i in 0..16 {
        files
            .begin_wait_record(owner(), entry, Frame::main(100 + i), input())
            .unwrap();
        files
            .begin_lock_record(owner(), entry, Frame::main(200 + i), control_input)
            .unwrap();
    }
    assert_eq!(files.wait_tokens().count(), 16);
    assert_eq!(files.control_tokens().count(), 16);
    assert!(
        files
            .begin_wait_record(owner(), entry, Frame::main(300), input())
            .is_err()
    );
    assert!(matches!(
        files
            .descriptors
            .begin_close(
                owner(),
                entry.fd,
                control::Recovery::change(Frame::main(400))
            )
            .unwrap(),
        crate::CloseAdmission::Started { .. }
    ));
    assert_eq!(files.wait_tokens().count(), 16);
    assert_eq!(files.control_tokens().count(), 16);
}
#[test]
fn close_fence_matches_source_generation_alias_and_terminal_debt() {
    let (mut files, entry, _, _) = fixture();
    let alias = files
        .descriptors
        .duplicate(entry.fd, 0, Flags::default())
        .unwrap();
    let aliasentry = files.lock_source(alias).unwrap();
    let (t, c) = files
        .begin_wait_record(owner(), entry, Frame::main(100), input())
        .unwrap();
    let (a, _) = files
        .begin_wait_record(owner(), aliasentry, Frame::main(101), input())
        .unwrap();
    files
        .complete_wait_record(c, WaitResult::Value(0), done(0))
        .unwrap();
    assert_eq!(files.fence_wait_for_close(entry), Ok(Some(t)));
    assert_eq!(
        files.wait_snapshot(a).unwrap().phase,
        WaitRecordPhase::Working
    );
    assert_eq!(
        files.wait_snapshot(t).unwrap().result,
        Some(WaitResult::Value(0))
    );
    files.finish_wait_cleanup(t).unwrap();
    assert_eq!(files.fence_wait_for_close(entry), Ok(None));
    let (stale, _) = files
        .begin_wait_record(owner(), entry, Frame::main(150), input())
        .unwrap();
    files.descriptors.close(entry.fd).unwrap();
    let fd = files
        .descriptors
        .insert(
            Target::Ram(RamTarget {
                fd: 3,
                slot: 71,
                generation: 42,
            }),
            Flags::default(),
        )
        .unwrap();
    assert_eq!(fd, entry.fd);
    let reused = files.lock_source(fd).unwrap();
    assert_ne!(entry, reused);
    assert_eq!(files.fence_wait_for_close(reused), Ok(None));
    assert_eq!(files.fence_wait_for_close(entry), Ok(Some(stale)));
    assert!(
        files
            .begin_wait_record(owner(), entry, Frame::main(200), input())
            .is_err()
    );
    assert_eq!(files.fence_wait_for_close(aliasentry), Ok(Some(a)));
}
#[test]
fn repeated_same_owner_longjmp_ack_does_not_leak_slots() {
    let (mut files, entry, _, _) = fixture();
    for i in 0..40 {
        let (t, _) = files
            .begin_wait_record(owner(), entry, Frame::main(100), input())
            .unwrap();
        saved_cleanup(&mut files, t);
        assert_eq!(
            files.pick_wait_cleanup(Some(owner()), Frame::main(200), None),
            Ok(None)
        );
        assert_eq!(files.wait_tokens().count(), 0, "turn{i}");
    }
    let (t, c) = files
        .begin_wait_record(owner(), entry, Frame::main(100), input())
        .unwrap();
    assert_eq!(
        files.pick_wait_cleanup(Some(owner()), Frame::main(90), None),
        Ok(None)
    );
    assert!(files.wait_is_live(c));
    assert_eq!(
        files.pick_wait_cleanup(Some(owner()), Frame::main(200), None),
        Ok(Some(t))
    );
    assert!(!files.wait_is_live(c));
}
#[test]
fn genuine_detach_keeps_receive_debt_then_ack_and_fork_never_closes_parent_ids() {
    let (mut files, entry, _, _) = fixture();
    let (t, c) = files
        .begin_wait_record(owner(), entry, Frame::main(100), input())
        .unwrap();
    files.attach_wait_channel(c, 0x90007).unwrap();
    assert_eq!(files.abandon_wait_owner(owner()), Some(t));
    assert_eq!(files.abandon_wait_owner(owner()), None);
    assert_eq!(files.wait_snapshot(t).unwrap().owner, None);
    saved_cleanup(&mut files, t);
    assert_eq!(
        files.pick_wait_cleanup(None, Frame::main(200), None),
        Ok(Some(t))
    );
    let debt = files.wait_channel_debt(t).unwrap().unwrap();
    files.confirm_wait_channel_closed(debt).unwrap();
    assert_eq!(
        files.pick_wait_cleanup(None, Frame::main(200), None),
        Ok(None)
    );
    assert_eq!(files.wait_tokens().count(), 0);
    let (parent, c) = files
        .begin_wait_record(owner(), entry, Frame::main(100), input())
        .unwrap();
    files.attach_wait_channel(c, 0x50007).unwrap();
    files.discard_wait_after_fork();
    assert_eq!(files.wait_tokens().count(), 0);
    let (child, _) = files
        .begin_wait_record(owner(), entry, Frame::main(100), input())
        .unwrap();
    assert!(child.generation() > parent.generation());
    assert!(files.wait_snapshot(parent).is_err());
    assert_eq!(files.wait_snapshot(child).unwrap().channel, None);
}
#[test]
fn strict_wait_terminal_and_raw_full_generation_are_required() {
    let (mut files, entry, _, _) = fixture();
    let (t, c) = files
        .begin_wait_record(owner(), entry, Frame::main(100), input())
        .unwrap();
    assert!(files.attach_wait_channel(c, 7).is_err());
    assert!(files.attach_wait_channel(c, 0).is_err());
    assert_eq!(files.wait_snapshot(t).unwrap().channel, None);
    assert!(
        wait::TerminalReply::from_reply(WaitReply {
            phase: WaitPhase::Sleeping,
            result: 0
        })
        .is_err()
    );
    assert!(
        wait::TerminalReply::from_reply(WaitReply {
            phase: WaitPhase::Complete,
            result: proto_fs::LOCK_CONFLICT
        })
        .is_err()
    );
    assert!(
        files
            .complete_wait_record(c, WaitResult::Failed(9), done(0))
            .is_err()
    );
    assert!(files.wait_is_live(c));
    let mut bytes = Writer::new();
    done(0).reply().write(&mut bytes).unwrap();
    let mut trailing = bytes.as_bytes().to_vec();
    trailing.push(0);
    assert!(wait::TerminalReply::read(&trailing).is_err());
    files
        .begin_wait_cleanup(t, WaitCancelReason::Abandoned)
        .unwrap();
    assert!(files.finish_wait_cleanup(t).is_err());
}
#[test]
fn initialized_wait_geometry_is_bounded() {
    let mut storage = std::boxed::Box::<WaitRecords<wait::Recovery>>::new_uninit();
    // SAFETY: exclusive aligned allocation initialized by production helper.
    let records = unsafe {
        WaitRecords::initialize_at(storage.as_mut_ptr());
        storage.assume_init()
    };
    assert_eq!(records.tokens().count(), 0);
    let size = core::mem::size_of::<WaitRecords<wait::Recovery>>();
    std::println!(
        "WAIT Recovery {} records{} slot{} hostPosixFs{}",
        core::mem::size_of::<wait::Recovery>(),
        size,
        size / 16,
        core::mem::size_of::<PosixFs>()
    );
    assert!(size <= 16 * 256);
    assert_eq!(
        core::mem::size_of::<Table<Target, 32, (), (), control::Recovery>>(),
        14096
    );
}

#[test]
fn wait_capacity_is_independent_and_protected_owner_cannot_wait_for_itself() {
    let (mut files, entry, _, control_input) = fixture();
    let me = owner();
    let other = OwnerToken::new(2).unwrap();
    let here = Frame::main(100);
    assert_eq!(
        files.wait_place(me, Frame::main(90)),
        crate::WaitPlace::Free
    );
    for _ in 0..crate::WAIT_RECORDS {
        files.begin_wait_record(me, entry, here, input()).unwrap();
    }
    assert_eq!(
        files.wait_place(me, Frame::main(90)),
        crate::WaitPlace::Full { own: true }
    );
    assert_eq!(
        files.wait_place(other, Frame::main(90)),
        crate::WaitPlace::Full { own: false }
    );
    assert!(
        files
            .begin_lock_record(other, entry, here, control_input)
            .is_ok()
    );
}

fn closing_token(files: &mut PosixFs, fd: u32) -> crate::CloseToken {
    match files
        .begin_close_record(Some(owner()), fd, Frame::main(777))
        .unwrap()
    {
        closing::Admission::Started { token, .. } => token,
        other => panic!("unexpected admission: {other:?}"),
    }
}
#[test]
fn close_selects_both_families_fairly_and_closes_cleaned_receiver_before_event() {
    use closing::CloseCommandFence::{Control, Wait};
    let (mut files, entry, _, control_input) = fixture();
    let (c, cc) = files
        .begin_lock_record(owner(), entry, Frame::main(100), control_input)
        .unwrap();
    let terminal = control::TerminalReply::from_reply(LockReply {
        phase: LockPhase::Complete,
        result: 0,
        blocker: None,
    })
    .unwrap();
    files
        .complete_lock_record(cc, ControlResult::Value(0), terminal)
        .unwrap();
    let (w, wc) = files
        .begin_wait_record(owner(), entry, Frame::main(101), input())
        .unwrap();
    files.attach_wait_channel(wc, 0x123456789abc0007).unwrap();
    files
        .begin_wait_cleanup(w, WaitCancelReason::Signal)
        .unwrap();
    files
        .publish_wait_cleanup(w, WaitResult::Value(0), done(0))
        .unwrap();
    let close = closing_token(&mut files, entry.fd);
    let before = files.close_snapshot(close).unwrap();
    let sequence: closing::WaitValue = files.descriptors.close_wait_value(close).unwrap();
    for expected in [Control(c), Wait(w), Control(c), Wait(w)] {
        assert_eq!(files.close_command_fence(close), Ok(Some(expected)));
    }
    assert_eq!(files.descriptors.close_wait_value(close).unwrap(), sequence);
    assert_eq!(files.close_snapshot(close).unwrap(), before);
    assert_eq!(
        files.lock_snapshot(c).unwrap().result,
        Some(ControlResult::Value(0))
    );
    assert_eq!(
        files.wait_snapshot(w).unwrap().reason,
        Some(WaitCancelReason::Signal)
    );
    assert_eq!(
        files.wait_snapshot(w).unwrap().result,
        Some(WaitResult::Value(0))
    );
    files.finish_lock_cleanup(c).unwrap();
    files.finish_wait_cleanup(w).unwrap();
    assert_eq!(
        files.close_command_fence(close),
        Ok(Some(Wait(w))),
        "Cleaned still owes exact receiver close"
    );
    let debt = files.wait_channel_debt(w).unwrap().unwrap();
    assert_eq!(debt.raw(), 0x123456789abc0007);
    files.confirm_wait_channel_closed(debt).unwrap();
    assert_eq!(files.close_command_fence(close), Ok(None));
    let (result, recovery) = files.ack_wait_record(w, owner()).unwrap();
    assert_eq!(result, WaitResult::Value(0));
    assert_eq!(recovery.outcome(), Some(done(0).reply()));
}
#[test]
fn full_wait_and_control_custody_leave_close_admission_and_other_alias_intact() {
    use closing::CloseCommandFence::{Control, Wait};
    let (mut files, entry, target, control_input) = fixture();
    let alias = files
        .descriptors
        .duplicate(entry.fd, 0, Flags::default())
        .unwrap();
    let alias_entry = files.lock_source(alias).unwrap();
    let mut control_token = None;
    let mut wait_token = None;
    for i in 0..16 {
        let source = if i == 0 { entry } else { alias_entry };
        let (c, _) = files
            .begin_lock_record(owner(), source, Frame::main(100 + i), control_input)
            .unwrap();
        let (w, _) = files
            .begin_wait_record(owner(), source, Frame::main(200 + i), input())
            .unwrap();
        if i == 0 {
            control_token = Some(c);
            wait_token = Some(w);
        }
    }
    let close = closing_token(&mut files, entry.fd);
    assert_eq!(
        files.close_command_fence(close),
        Ok(Some(Control(control_token.unwrap())))
    );
    assert_eq!(
        files.close_command_fence(close),
        Ok(Some(Wait(wait_token.unwrap())))
    );
    let alien = files
        .wait_tokens()
        .find(|&t| t != wait_token.unwrap())
        .unwrap();
    assert_eq!(
        files.wait_snapshot(alien).unwrap().phase,
        WaitRecordPhase::Working
    );
    assert_eq!(files.descriptors.get(alias), Ok(Target::Ram(target)));
}
#[test]
fn closing_recovery_is_not_change_and_local_preference_preserves_frame() {
    let recovery = control::Recovery::closing(Frame::main(901));
    assert!(!recovery.is_change());
    assert!(recovery.lock().is_none());
    let (recovery, first) = recovery.next_close_fence().unwrap();
    let (recovery, second) = recovery.next_close_fence().unwrap();
    assert!(!first);
    assert!(second);
    assert_eq!(recovery.frame(), Frame::main(901));
    assert!(
        control::Recovery::change(Frame::main(901))
            .next_close_fence()
            .is_err()
    );
    assert_eq!(core::mem::size_of::<control::Recovery>(), 120);
    assert_eq!(
        core::mem::size_of::<Table<Target, 32, (), (), control::Recovery>>(),
        14096
    );
}

#[test]
fn already_confirmed_close_receipt_does_not_repeat_fencing_or_mutate_outcomes() {
    let (mut files, entry, _, control_input) = fixture();
    let (c, _) = files
        .begin_lock_record(owner(), entry, Frame::main(100), control_input)
        .unwrap();
    let (w, _) = files
        .begin_wait_record(owner(), entry, Frame::main(101), input())
        .unwrap();
    let close = closing_token(&mut files, entry.fd);
    // Model the authoritative receipt observed by a delayed competing helper.
    files.finish_close_record(close).unwrap();
    let snapshot = files.close_snapshot(close).unwrap();
    assert!(snapshot.complete);
    assert_eq!(files.close_command_fence(close), Ok(None));
    assert_eq!(files.close_snapshot(close).unwrap(), snapshot);
    assert_eq!(
        files.control_snapshot(c).unwrap().phase,
        ControlPhase::Working
    );
    assert_eq!(
        files.wait_snapshot(w).unwrap().phase,
        WaitRecordPhase::Working
    );
}
