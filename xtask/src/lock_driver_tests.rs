// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The production driver core with a service that can commit and lose a reply.

use super::lock_fields_tests::constants;
#[path = "../../lib/posix-abi/src/lock_driver/core.rs"]
mod core;

use core::{Failure, Phase, Session, State};
use proto_fs::{LockBlocker, LockKind, LockPhase, LockReply};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Start,
    Query,
    Cancel,
    Release,
    Authenticate,
    Publish,
    Clean,
    Finish,
    Ack,
}
struct Script {
    phase: Phase,
    claim: bool,
    local: Option<LockReply>,
    remote: Option<LockReply>,
    terminal: LockReply,
    events: Vec<Event>,
    loss: Vec<Event>,
    pending_start: bool,
    close_after_query: bool,
    finish_before_cancel: bool,
    bind_first: bool,
    room_first: bool,
    rejected: Option<u32>,
    query_failures: Vec<Failure>,
    release_failures: Vec<Failure>,
    cancel_pending_once: bool,
    effects: usize,
    releases: usize,
}
fn reply(result: u32) -> LockReply {
    LockReply {
        phase: LockPhase::Complete,
        result,
        blocker: None,
    }
}
impl Script {
    fn new() -> Self {
        Self {
            phase: Phase::Live,
            claim: true,
            local: None,
            remote: None,
            terminal: reply(0),
            events: Vec::new(),
            loss: Vec::new(),
            pending_start: false,
            close_after_query: false,
            finish_before_cancel: false,
            bind_first: false,
            room_first: false,
            rejected: None,
            query_failures: Vec::new(),
            release_failures: Vec::new(),
            cancel_pending_once: false,
            effects: 0,
            releases: 0,
        }
    }
    fn request(&mut self, event: Event) {
        self.events.push(event);
        assert!(self.events.len() < 100, "driver made no finite progress");
    }
    fn response<T>(&mut self, event: Event, value: T) -> Result<T, Failure> {
        if let Some(index) = self.loss.iter().position(|&lost| lost == event) {
            self.loss.remove(index);
            Err(Failure::Interrupted)
        } else {
            Ok(value)
        }
    }
}
impl Session for Script {
    type Completion = LockReply;
    fn state(&mut self) -> Result<State, i32> {
        Ok(State {
            phase: self.phase,
            claim_live: self.claim,
            saved: self.local.is_some(),
        })
    }
    fn start(&mut self) -> Result<LockReply, Failure> {
        assert!(self.claim, "a revoked continuation sent Start");
        self.request(Event::Start);
        if self.room_first {
            self.room_first = false;
            return Err(Failure::Room);
        }
        if self.bind_first {
            self.bind_first = false;
            return Err(Failure::Authenticating);
        }
        if let Some(code) = self.rejected {
            return Err(Failure::Rejected(code));
        }
        if self.remote.is_none() {
            self.effects += 1;
            self.remote = Some(if self.pending_start {
                LockReply {
                    phase: LockPhase::Pending,
                    ..reply(0)
                }
            } else {
                self.terminal
            });
        }
        self.response(Event::Start, self.remote.unwrap())
    }
    fn query(&mut self) -> Result<LockReply, Failure> {
        self.request(Event::Query);
        if !self.query_failures.is_empty() {
            return Err(self.query_failures.remove(0));
        }
        if self.close_after_query {
            self.close_after_query = false;
            self.phase = Phase::Cleaning;
            self.claim = false;
        } else {
            self.remote = Some(self.terminal);
        }
        self.response(Event::Query, self.remote.unwrap())
    }
    fn cancel(&mut self) -> Result<LockReply, Failure> {
        self.request(Event::Cancel);
        if self.cancel_pending_once {
            self.cancel_pending_once = false;
            return Ok(LockReply {
                phase: LockPhase::Pending,
                ..reply(0)
            });
        }
        let terminal = match self.remote {
            Some(outcome) if outcome.phase == LockPhase::Complete => outcome,
            _ if self.finish_before_cancel => self.terminal,
            _ => reply(proto_fs::LOCK_CANCELLED),
        };
        self.remote = Some(terminal);
        self.response(Event::Cancel, terminal)
    }
    fn release(&mut self) -> Result<(), Failure> {
        assert!(self.local.is_some(), "Release destroyed an unsaved reply");
        self.request(Event::Release);
        if !self.release_failures.is_empty() {
            return Err(self.release_failures.remove(0));
        }
        if self.remote.take().is_some() {
            self.releases += 1;
        }
        self.response(Event::Release, ())
    }
    fn authenticate(&mut self) -> Result<(), Failure> {
        self.events.push(Event::Authenticate);
        Ok(())
    }
    fn pause(&mut self, _: bool) {
        assert!(self.events.len() < 100);
    }
    fn publish(&mut self, outcome: LockReply) -> Result<(), i32> {
        assert_eq!(outcome.phase, LockPhase::Complete);
        outcome.validate().unwrap();
        self.events.push(Event::Publish);
        self.local.get_or_insert(outcome);
        if self.phase == Phase::Live {
            self.phase = Phase::Complete;
        }
        Ok(())
    }
    fn begin_cleanup(&mut self) -> Result<(), i32> {
        self.events.push(Event::Clean);
        self.claim = false;
        self.phase = Phase::Cleaning;
        Ok(())
    }
    fn finish_cleanup(&mut self) -> Result<(), i32> {
        assert_eq!(self.phase, Phase::Cleaning);
        assert!(self.local.is_some());
        self.events.push(Event::Finish);
        self.phase = Phase::Cleaned;
        Ok(())
    }
    fn acknowledge(&mut self) -> Result<LockReply, i32> {
        assert_eq!(self.phase, Phase::Cleaned);
        assert!(self.remote.is_none());
        self.events.push(Event::Ack);
        self.phase = Phase::Gone;
        Ok(self.local.unwrap())
    }
}

#[test]
fn lost_start_and_release_keep_one_effect_and_save_before_release() {
    let mut script = Script::new();
    script.loss = vec![Event::Start, Event::Release];
    assert_eq!(core::drive(&mut script), Ok(reply(0)));
    assert_eq!((script.effects, script.releases), (1, 1));
    assert_eq!(
        script.events.iter().filter(|&&e| e == Event::Start).count(),
        2
    );
    assert_eq!(
        script
            .events
            .iter()
            .filter(|&&e| e == Event::Release)
            .count(),
        2
    );
    let saved = script
        .events
        .iter()
        .position(|e| *e == Event::Publish)
        .unwrap();
    let released = script
        .events
        .iter()
        .position(|e| *e == Event::Release)
        .unwrap();
    assert!(saved < released);
}

#[test]
fn later_query_interruption_keeps_the_registered_operation_and_full_blocker() {
    let mut script = Script::new();
    script.pending_start = true;
    script.loss = vec![Event::Query];
    script.terminal.blocker = Some(LockBlocker {
        kind: LockKind::Write,
        start: 17,
        length: 0,
        pid: -1,
    });
    let expected = script.terminal;
    assert_eq!(core::drive(&mut script), Ok(expected));
    assert_eq!(script.effects, 1);
    assert_eq!(
        script.events.iter().filter(|&&e| e == Event::Query).count(),
        2
    );
}

#[test]
fn close_after_pending_query_keeps_published_success_and_lost_cancel_receipt() {
    let mut script = Script::new();
    script.pending_start = true;
    script.close_after_query = true;
    script.finish_before_cancel = true;
    script.loss = vec![Event::Cancel];
    assert_eq!(core::drive(&mut script), Ok(reply(0)));
    assert_eq!(
        script
            .events
            .iter()
            .filter(|&&e| e == Event::Cancel)
            .count(),
        2
    );
    assert_eq!(script.local, Some(reply(0)));
}

#[test]
fn revoked_before_start_uses_cancel_fence_and_never_starts() {
    let mut script = Script::new();
    script.claim = false;
    assert_eq!(
        core::drive(&mut script),
        Ok(reply(proto_fs::LOCK_CANCELLED))
    );
    assert_eq!(script.effects, 0);
    assert!(!script.events.contains(&Event::Start));
    assert!(script.events.contains(&Event::Cancel));
}

#[test]
fn helper_performs_one_request_and_pending_cancel_keeps_debt() {
    let mut script = Script::new();
    script.phase = Phase::Cleaning;
    script.loss = vec![Event::Cancel];
    assert_eq!(core::cleanup_step(&mut script), Ok(false));
    assert_eq!(script.local, None);
    assert_eq!(script.events, [Event::Cancel]);
    assert_eq!(core::cleanup_step(&mut script), Ok(false));
    assert_eq!(script.local, Some(reply(proto_fs::LOCK_CANCELLED)));
    assert!(!script.events.contains(&Event::Release));
    assert_eq!(core::cleanup_step(&mut script), Ok(false));
    assert_eq!(core::cleanup_step(&mut script), Ok(true));
}

#[test]
fn room_and_bind_retry_the_resident_operation_without_publishing_failure() {
    let mut script = Script::new();
    script.room_first = true;
    script.bind_first = true;
    assert_eq!(core::drive(&mut script), Ok(reply(0)));
    assert_eq!(script.effects, 1);
    assert_eq!(
        script
            .events
            .iter()
            .filter(|&&e| e == Event::Publish)
            .count(),
        1
    );
    assert_eq!(
        script
            .events
            .iter()
            .filter(|&&e| e == Event::Authenticate)
            .count(),
        1
    );
}

#[test]
fn unadmitted_rejection_is_saved_and_gone_child_sends_nothing() {
    let mut script = Script::new();
    script.rejected = Some(proto_fs::BAD_FD);
    assert_eq!(core::drive(&mut script), Ok(reply(proto_fs::BAD_FD)));
    assert_eq!(script.effects, 0);
    assert!(!script.events.contains(&Event::Cancel));
    let mut child = Script::new();
    child.phase = Phase::Gone;
    assert_eq!(core::drive(&mut child), Err(constants::EIO));
    assert!(child.events.is_empty());
    assert_eq!(core::cleanup_step(&mut child), Ok(true));
    assert!(child.events.is_empty());
}

#[test]
fn actual_pending_cancel_and_resolving_release_keep_the_saved_debt() {
    let mut script = Script::new();
    script.phase = Phase::Cleaning;
    script.cancel_pending_once = true;
    assert_eq!(core::cleanup_step(&mut script), Ok(false));
    assert_eq!(script.local, None);
    assert_eq!(script.phase, Phase::Cleaning);
    assert_eq!(core::cleanup_step(&mut script), Ok(false));
    let terminal = script.local;
    script.release_failures.push(Failure::Resolving);
    assert_eq!(core::cleanup_step(&mut script), Ok(false));
    assert_eq!(script.local, terminal);
    assert_eq!(script.phase, Phase::Cleaning);
    assert_eq!(core::cleanup_step(&mut script), Ok(false));
    assert_eq!(script.phase, Phase::Cleaned);
}

#[test]
fn completed_abandonment_begins_local_cleanup_before_release() {
    let mut script = Script::new();
    script.phase = Phase::Complete;
    script.local = Some(reply(0));
    script.remote = Some(reply(0));
    assert_eq!(core::cleanup_step(&mut script), Ok(false));
    assert_eq!(script.phase, Phase::Cleaning);
    assert_eq!(script.events, [Event::Clean]);
    assert_eq!(core::cleanup_step(&mut script), Ok(false));
    assert_eq!(script.phase, Phase::Cleaned);
    assert_eq!(script.releases, 1);
}

#[test]
fn ambiguous_query_failure_seeks_canonical_cancel_and_retired_release_is_confirmed() {
    for failure in [Failure::Fatal(constants::EIO), Failure::Retired] {
        let mut script = Script::new();
        script.pending_start = true;
        script.query_failures.push(failure);
        assert_eq!(
            core::drive(&mut script),
            Ok(reply(proto_fs::LOCK_CANCELLED))
        );
        assert!(script.events.contains(&Event::Cancel));
        assert_eq!(script.effects, 1);
    }
    let mut script = Script::new();
    script.phase = Phase::Cleaning;
    script.local = Some(reply(0));
    script.release_failures.push(Failure::Retired);
    assert_eq!(core::cleanup_step(&mut script), Ok(false));
    assert_eq!(script.phase, Phase::Cleaned);
}
#[path = "../../lib/posix-abi/src/lock_driver/status.rs"]
mod status;
