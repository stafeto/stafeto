// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Competing cleanup retires the real resident table at unlocked helper boundaries.

use super::*;
mod local_types {
    pub(super) use super::super::{FsError, PosixFs, control};
    pub(super) use crate::{
        ControlClaimToken, ControlPhase, ControlResult, ControlToken, OwnerToken,
    };
}
#[path = "../../posix-abi/src/lock_driver/local.rs"]
mod local;

fn record(files: &mut PosixFs, source: EntryToken, input: control::Input) -> crate::ControlToken {
    files
        .begin_lock_record(owner(), source, Frame::main(91), input)
        .unwrap()
        .0
}
fn retire(files: &mut PosixFs, token: crate::ControlToken) {
    files.abandon_lock_owner(owner()).unwrap();
    files
        .begin_lock_cleanup(token, control::CancelReason::Abandoned)
        .unwrap();
    files
        .publish_lock_cleanup(token, ControlResult::Value(0), terminal(blocker()))
        .unwrap();
    files.finish_lock_cleanup(token).unwrap();
    assert_eq!(
        files.control_snapshot(token),
        Err(FsError::BadFileDescriptor)
    );
}

#[test]
fn retirement_between_state_and_begin_preserves_recycled_generation() {
    let (mut files, source, _, input) = fixture();
    let old = record(&mut files, source, input);
    assert!(local::snapshot(&files, old, None).unwrap().is_some());
    retire(&mut files, old);
    let new = record(&mut files, source, input);
    assert_eq!(new.slot(), old.slot());
    assert_ne!(new.generation(), old.generation());
    let before = files.lock_snapshot(new).unwrap();
    local::begin(&mut files, old, None).unwrap();
    assert_eq!(local::snapshot(&files, old, None), Ok(None));
    assert_eq!(files.lock_snapshot(new).unwrap(), before);
}

#[test]
fn cancel_reply_after_other_helper_released_preserves_recycled_generation() {
    let (mut files, source, _, input) = fixture();
    let old = record(&mut files, source, input);
    files
        .begin_lock_cleanup(old, control::CancelReason::Abandoned)
        .unwrap();
    // First helper sent Cancel; the canonical reply is retained in its own value.
    let reply = terminal(cancelled());
    retire(&mut files, old);
    let new = record(&mut files, source, input);
    let before = files.lock_snapshot(new).unwrap();
    local::publish(&mut files, old, None, None, ControlResult::Failed(5), reply).unwrap();
    assert_eq!(files.lock_snapshot(new).unwrap(), before);
}

#[test]
fn release_reply_after_other_helper_released_preserves_recycled_generation() {
    let (mut files, source, _, input) = fixture();
    let old = record(&mut files, source, input);
    files
        .begin_lock_cleanup(old, control::CancelReason::Abandoned)
        .unwrap();
    files
        .publish_lock_cleanup(old, ControlResult::Value(0), terminal(blocker()))
        .unwrap();
    // First helper sent Release; another helper receives the reply first.
    retire(&mut files, old);
    let new = record(&mut files, source, input);
    let before = files.lock_snapshot(new).unwrap();
    local::finish(&mut files, old, None).unwrap();
    assert_eq!(files.lock_snapshot(new).unwrap(), before);
}

#[test]
fn vanished_owned_continuation_cannot_synthesize_outcome_or_touch_new_owner() {
    let (mut files, source, _, input) = fixture();
    let old = record(&mut files, source, input);
    retire(&mut files, old);
    let new = record(&mut files, source, input);
    let before = files.lock_snapshot(new).unwrap();
    assert_eq!(
        local::snapshot(&files, old, Some(owner())),
        Err(FsError::Io)
    );
    assert_eq!(
        local::begin(&mut files, old, Some(owner())),
        Err(FsError::Io)
    );
    assert_eq!(
        local::finish(&mut files, old, Some(owner())),
        Err(FsError::Io)
    );
    assert_eq!(
        local::publish(
            &mut files,
            old,
            None,
            Some(owner()),
            ControlResult::Value(0),
            terminal(blocker())
        ),
        Err(FsError::Io)
    );
    assert_eq!(
        files.ack_lock_record(old, owner()),
        Err(FsError::BadFileDescriptor)
    );
    assert_eq!(files.lock_snapshot(new).unwrap(), before);
}

#[test]
fn cleaned_owned_receipt_survives_late_begin_and_conflicting_helper_reply() {
    let (mut files, source, _, input) = fixture();
    let token = record(&mut files, source, input);
    files
        .begin_lock_cleanup(token, control::CancelReason::Close)
        .unwrap();
    files
        .publish_lock_cleanup(token, ControlResult::Value(0), terminal(blocker()))
        .unwrap();
    files.finish_lock_cleanup(token).unwrap();
    let before = files.lock_snapshot(token).unwrap();
    local::begin(&mut files, token, None).unwrap();
    local::publish(
        &mut files,
        token,
        None,
        None,
        ControlResult::Failed(9),
        terminal(cancelled()),
    )
    .unwrap();
    local::finish(&mut files, token, None).unwrap();
    assert_eq!(files.lock_snapshot(token).unwrap(), before);
    assert_eq!(
        files.ack_lock_record(token, owner()).unwrap(),
        (ControlResult::Value(0), Some(blocker()))
    );
}

#[test]
fn helper_cannot_finish_unpaid_or_unsaved_real_record() {
    let (mut files, source, _, input) = fixture();
    let token = record(&mut files, source, input);
    assert_eq!(
        local::finish(&mut files, token, None),
        Err(FsError::InvalidArgument)
    );
    local::begin(&mut files, token, None).unwrap();
    assert_eq!(
        local::finish(&mut files, token, None),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(
        files.lock_snapshot(token).unwrap().phase,
        ControlPhase::Cleaning
    );
    assert!(files.lock_snapshot(token).unwrap().result.is_none());
}

#[test]
fn actual_helper_saves_canonical_receipt_then_frees_abandoned_record() {
    let (mut files, source, _, input) = fixture();
    let token = record(&mut files, source, input);
    files.abandon_lock_owner(owner()).unwrap();
    local::begin(&mut files, token, None).unwrap();
    local::publish(
        &mut files,
        token,
        None,
        None,
        ControlResult::Value(0),
        terminal(blocker()),
    )
    .unwrap();
    let saved = files.lock_snapshot(token).unwrap();
    assert_eq!(saved.result, Some(ControlResult::Value(0)));
    assert_eq!(saved.recovery.lock().unwrap().outcome(), Some(blocker()));
    local::finish(&mut files, token, None).unwrap();
    assert_eq!(
        files.control_snapshot(token),
        Err(FsError::BadFileDescriptor)
    );
}

#[test]
fn existing_change_family_and_inconsistent_receipt_are_not_gone() {
    let (mut files, source, _, input) = fixture();
    let other = files
        .begin_change_record(owner(), Frame::main(1))
        .unwrap()
        .0;
    let before = files.control_snapshot(other).unwrap();
    assert_eq!(local::snapshot(&files, other, None), Err(FsError::Io));
    assert_eq!(local::begin(&mut files, other, None), Err(FsError::Io));
    assert_eq!(files.control_snapshot(other).unwrap(), before);
    let token = record(&mut files, source, input);
    files.descriptors.control_begin_cleanup(token).unwrap();
    // Generic table can hold a scalar without the typed terminal, which is invalid for Lock.
    files
        .descriptors
        .control_publish_cleanup(token, ControlResult::Value(0), Ok)
        .unwrap();
    assert_eq!(local::snapshot(&files, token, None), Err(FsError::Io));
    assert_eq!(local::finish(&mut files, token, None), Err(FsError::Io));
}

mod constants {
    pub const EIO: i32 = 5;
}
#[path = "../../posix-abi/src/lock_driver/core.rs"]
#[allow(dead_code)]
mod driver_core;

struct Competing<'a> {
    files: &'a mut PosixFs,
    token: crate::ControlToken,
    failure: driver_core::Failure,
    save_during_rpc: bool,
    retire_during_rpc: bool,
    requests: usize,
}
impl Competing<'_> {
    fn rpc(&mut self) -> driver_core::Failure {
        self.requests += 1;
        if self.save_during_rpc {
            local::publish(
                self.files,
                self.token,
                None,
                None,
                ControlResult::Value(0),
                terminal(blocker()),
            )
            .unwrap();
        }
        if self.retire_during_rpc {
            local::finish(self.files, self.token, None).unwrap();
        }
        self.failure
    }
}
impl driver_core::Session for Competing<'_> {
    type Completion = ();
    fn state(&mut self) -> Result<driver_core::State, i32> {
        let current = local::snapshot(self.files, self.token, None).map_err(|_| 5)?;
        Ok(match current {
            None => driver_core::State {
                phase: driver_core::Phase::Gone,
                claim_live: false,
                saved: false,
            },
            Some(current) => driver_core::State {
                phase: match current.phase {
                    ControlPhase::Working => driver_core::Phase::Live,
                    ControlPhase::Complete | ControlPhase::CleanupRequired => {
                        driver_core::Phase::Complete
                    }
                    ControlPhase::Cleaning => driver_core::Phase::Cleaning,
                    ControlPhase::Cleaned => driver_core::Phase::Cleaned,
                },
                claim_live: false,
                saved: current.result.is_some(),
            },
        })
    }
    fn cancel(&mut self) -> Result<LockReply, driver_core::Failure> {
        Err(self.rpc())
    }
    fn release(&mut self) -> Result<(), driver_core::Failure> {
        Err(self.rpc())
    }
    fn finish_cleanup(&mut self) -> Result<(), i32> {
        local::finish(self.files, self.token, None).map_err(|_| 5)
    }
    fn start(&mut self) -> Result<LockReply, driver_core::Failure> {
        panic!("helper starts fresh operation")
    }
    fn query(&mut self) -> Result<LockReply, driver_core::Failure> {
        panic!("helper queries")
    }
    fn authenticate(&mut self) -> Result<(), driver_core::Failure> {
        panic!("helper binds")
    }
    fn pause(&mut self, _: bool) {
        panic!("helper blocks")
    }
    fn publish(&mut self, _: LockReply) -> Result<(), i32> {
        panic!("error reply published")
    }
    fn begin_cleanup(&mut self) -> Result<(), i32> {
        panic!("already cleaning")
    }
    fn acknowledge(&mut self) -> Result<(), i32> {
        panic!("helper acknowledges owner")
    }
}
fn failures() -> [driver_core::Failure; 4] {
    [
        driver_core::Failure::Retired,
        driver_core::Failure::Rejected(proto_fs::BAD_FD),
        driver_core::Failure::Fatal(5),
        driver_core::Failure::Authenticating,
    ]
}
#[test]
fn delayed_cancel_error_recognizes_new_canonical_receipt_but_not_same_unpaid_debt() {
    for failure in failures() {
        for advance in [false, true] {
            let (mut files, source, _, input) = fixture();
            let token = record(&mut files, source, input);
            local::begin(&mut files, token, None).unwrap();
            let mut helper = Competing {
                files: &mut files,
                token,
                failure,
                save_during_rpc: advance,
                retire_during_rpc: false,
                requests: 0,
            };
            assert_eq!(
                driver_core::cleanup_step(&mut helper),
                if advance { Ok(false) } else { Err(5) }
            );
            assert_eq!(helper.requests, 1);
            assert_eq!(
                files.lock_snapshot(token).unwrap().result.is_some(),
                advance
            );
        }
    }
}
#[test]
fn delayed_cancel_and_release_errors_recognize_another_helpers_exact_retirement() {
    for failure in failures() {
        for already_saved in [false, true] {
            let (mut files, source, _, input) = fixture();
            let token = record(&mut files, source, input);
            files.abandon_lock_owner(owner()).unwrap();
            local::begin(&mut files, token, None).unwrap();
            if already_saved {
                local::publish(
                    &mut files,
                    token,
                    None,
                    None,
                    ControlResult::Value(0),
                    terminal(blocker()),
                )
                .unwrap();
            }
            let mut helper = Competing {
                files: &mut files,
                token,
                failure,
                save_during_rpc: !already_saved,
                retire_during_rpc: true,
                requests: 0,
            };
            assert_eq!(
                driver_core::cleanup_step(&mut helper),
                if already_saved && failure == driver_core::Failure::Retired {
                    Ok(false)
                } else {
                    Ok(true)
                }
            );
            assert_eq!(helper.requests, 1);
            assert_eq!(
                files.control_snapshot(token),
                Err(FsError::BadFileDescriptor)
            );
        }
    }
}
#[test]
fn release_error_with_only_previous_receipt_still_requires_canonical_release() {
    for failure in failures()
        .into_iter()
        .filter(|f| *f != driver_core::Failure::Retired)
    {
        let (mut files, source, _, input) = fixture();
        let token = record(&mut files, source, input);
        local::begin(&mut files, token, None).unwrap();
        local::publish(
            &mut files,
            token,
            None,
            None,
            ControlResult::Value(0),
            terminal(blocker()),
        )
        .unwrap();
        let mut helper = Competing {
            files: &mut files,
            token,
            failure,
            save_during_rpc: false,
            retire_during_rpc: false,
            requests: 0,
        };
        assert_eq!(driver_core::cleanup_step(&mut helper), Err(5));
        assert_eq!(
            files.lock_snapshot(token).unwrap().phase,
            ControlPhase::Cleaning
        );
    }
}
