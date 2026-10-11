// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

extern crate std;
use std::{vec, vec::Vec};
#[allow(dead_code)]
#[path = "../../posix-abi/src/wait_lock_driver/core.rs"]
mod driver;
use driver::{Failure, Phase, Reason, Session, State};
use proto_fs::{WaitPhase, WaitReply};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Start,
    Query,
    Arm,
    Receive,
    Cancel,
    Release,
    Close,
    Publish,
    Ack,
}
fn reply(phase: WaitPhase, result: u32) -> WaitReply {
    WaitReply { phase, result }
}
struct Script {
    phase: Phase,
    channel: bool,
    claim: bool,
    local: Option<WaitReply>,
    remote: Option<WaitReply>,
    events: Vec<Event>,
    losses: Vec<Event>,
    queries: usize,
    signal_query: Option<usize>,
    ending: bool,
    armed: bool,
    cancel_success: bool,
    complete_after_wake: bool,
    reason: Option<Reason>,
    rejected: Option<u32>,
    fatal_query: bool,
    close_on_arm: bool,
    arm_copies: usize,
    starts: usize,
    effects: usize,
}
impl Script {
    fn new() -> Self {
        Self {
            phase: Phase::Working,
            channel: true,
            claim: true,
            local: None,
            remote: None,
            events: Vec::new(),
            losses: Vec::new(),
            queries: 0,
            signal_query: None,
            ending: false,
            armed: false,
            cancel_success: false,
            complete_after_wake: true,
            reason: None,
            rejected: None,
            fatal_query: false,
            close_on_arm: false,
            arm_copies: 0,
            starts: 0,
            effects: 0,
        }
    }
    fn event(&mut self, e: Event) {
        self.events.push(e);
        assert!(self.events.len() < 100, "unbounded driver retry");
    }
    fn response<T>(&mut self, e: Event, result: T) -> Result<T, Failure> {
        if let Some(i) = self.losses.iter().position(|&v| v == e) {
            self.losses.remove(i);
            Err(Failure::Interrupted)
        } else {
            Ok(result)
        }
    }
}
impl Session for Script {
    type Completion = WaitReply;
    fn state(&mut self) -> Result<State, i32> {
        Ok(State {
            phase: self.phase,
            claim_live: self.claim,
            saved: self.local.is_some(),
            channel: self.channel,
        })
    }
    fn ending(&mut self) -> bool {
        self.ending
    }
    fn start(&mut self) -> Result<WaitReply, Failure> {
        self.event(Event::Start);
        self.starts += 1;
        assert!(self.claim);
        if let Some(code) = self.rejected.take() {
            return Err(Failure::Rejected(code));
        }
        let pending = reply(WaitPhase::NeedsArm, 0);
        self.remote.get_or_insert(pending);
        self.response(Event::Start, self.remote.unwrap())
    }
    fn query(&mut self) -> Result<WaitReply, Failure> {
        self.event(Event::Query);
        self.queries += 1;
        if self.signal_query == Some(self.queries) {
            self.ending = true;
        }
        if self.fatal_query {
            self.fatal_query = false;
            return Err(Failure::Fatal(5));
        }
        let result = self.remote.unwrap();
        self.response(Event::Query, result)
    }
    fn arm(&mut self) -> Result<WaitReply, Failure> {
        self.event(Event::Arm);
        self.arm_copies += 1;
        if self.close_on_arm {
            self.phase = Phase::Cleaning;
            self.claim = false;
            return Err(Failure::Retired);
        }
        self.armed = true;
        if self.remote.unwrap().phase != WaitPhase::Complete {
            self.remote = Some(reply(WaitPhase::Sleeping, 0));
        }
        self.response(Event::Arm, self.remote.unwrap())
    }
    fn receive(&mut self) -> Result<(), Failure> {
        self.event(Event::Receive);
        assert!(self.armed);
        assert_eq!(
            self.events[self.events.len() - 2],
            Event::Query,
            "Arm must reconcile by Query before sleep"
        );
        if self.complete_after_wake {
            self.remote = Some(reply(WaitPhase::Complete, 0));
            self.effects += 1;
        }
        self.response(Event::Receive, ())
    }
    fn cancel(&mut self) -> Result<WaitReply, Failure> {
        self.event(Event::Cancel);
        if self.cancel_success {
            self.remote = Some(reply(WaitPhase::Complete, 0));
            self.effects += 1;
            self.cancel_success = false;
        }
        if !self.remote.is_some_and(|r| r.phase == WaitPhase::Complete) {
            self.remote = Some(reply(WaitPhase::Complete, proto_fs::LOCK_CANCELLED));
        }
        self.response(Event::Cancel, self.remote.unwrap())
    }
    fn release(&mut self) -> Result<(), Failure> {
        self.event(Event::Release);
        assert!(
            self.local.is_some(),
            "release before durable canonical publication"
        );
        // The remote Release fence also makes a lost acknowledgement repeatable.
        self.remote = None;
        self.response(Event::Release, ())
    }
    fn close_channel(&mut self) -> Result<(), i32> {
        self.event(Event::Close);
        assert_eq!(self.phase, Phase::Cleaned);
        self.channel = false;
        Ok(())
    }
    fn authenticate(&mut self) -> Result<(), Failure> {
        Ok(())
    }
    fn pause(&mut self, _: bool) {}
    fn publish(&mut self, r: WaitReply) -> Result<(), i32> {
        self.event(Event::Publish);
        assert_eq!(r.phase, WaitPhase::Complete);
        self.local.get_or_insert(r);
        self.claim = false;
        if self.phase == Phase::Working {
            self.phase = Phase::Complete;
        }
        Ok(())
    }
    fn begin_cleanup(&mut self, r: Reason) -> Result<(), i32> {
        self.reason.get_or_insert(r);
        self.claim = false;
        if self.phase != Phase::Cleaned {
            self.phase = Phase::Cleaning;
        }
        Ok(())
    }
    fn finish_cleanup(&mut self) -> Result<(), i32> {
        assert!(self.local.is_some());
        self.phase = Phase::Cleaned;
        Ok(())
    }
    fn acknowledge(&mut self) -> Result<WaitReply, i32> {
        self.event(Event::Ack);
        assert!(!self.channel);
        assert_eq!(self.phase, Phase::Cleaned);
        self.phase = Phase::Gone;
        Ok(self.local.unwrap())
    }
}
#[test]
fn arm_query_receive_and_channel_close_are_ordered_before_ack() {
    let mut s = Script::new();
    assert_eq!(driver::drive(&mut s), Ok(reply(WaitPhase::Complete, 0)));
    assert_eq!(s.effects, 1);
    assert_eq!(s.starts, 1);
    assert_eq!(
        s.events,
        vec![
            Event::Start,
            Event::Arm,
            Event::Query,
            Event::Receive,
            Event::Query,
            Event::Publish,
            Event::Release,
            Event::Close,
            Event::Ack
        ]
    );
}
#[test]
fn every_lost_reply_retains_one_effect_and_one_operation() {
    for lost in [
        Event::Start,
        Event::Arm,
        Event::Query,
        Event::Receive,
        Event::Release,
    ] {
        let mut s = Script::new();
        s.losses.push(lost);
        assert_eq!(
            driver::drive(&mut s),
            Ok(reply(WaitPhase::Complete, 0)),
            "{lost:?}"
        );
        assert_eq!(s.effects, 1);
        assert!(s.arm_copies <= 2);
        assert!(s.losses.is_empty());
    }
}
#[test]
fn signal_after_second_query_cancels_without_sleeping_again() {
    let mut s = Script::new();
    s.complete_after_wake = false;
    s.signal_query = Some(2);
    assert_eq!(
        driver::drive(&mut s),
        Ok(reply(WaitPhase::Complete, proto_fs::LOCK_CANCELLED))
    );
    assert_eq!(s.reason, Some(Reason::Signal));
    assert_eq!(s.effects, 0);
    assert_eq!(s.events.iter().filter(|&&e| e == Event::Receive).count(), 1);
}
#[test]
fn committed_success_wins_signal_and_lost_cancel_reply() {
    let mut s = Script::new();
    s.ending = true;
    s.cancel_success = true;
    s.losses.push(Event::Cancel);
    assert_eq!(driver::drive(&mut s), Ok(reply(WaitPhase::Complete, 0)));
    assert_eq!(s.reason, Some(Reason::Signal));
    assert_eq!(s.effects, 1);
    assert_eq!(s.starts, 0);
}
#[test]
fn cleanup_turn_never_combines_cancel_release_and_channel_close() {
    let mut s = Script::new();
    s.phase = Phase::Cleaning;
    assert!(!driver::cleanup_step(&mut s).unwrap());
    assert_eq!(s.events, vec![Event::Cancel, Event::Publish]);
    assert!(!driver::cleanup_step(&mut s).unwrap());
    assert_eq!(s.events[2], Event::Release);
    assert!(driver::cleanup_step(&mut s).unwrap());
    assert_eq!(s.events[3], Event::Close);
    assert_eq!(s.phase, Phase::Cleaned);
}
#[test]
fn helper_revocation_between_snapshot_and_arm_preserves_exact_debt() {
    let mut s = Script::new();
    s.close_on_arm = true;
    assert_eq!(
        driver::drive(&mut s),
        Ok(reply(WaitPhase::Complete, proto_fs::LOCK_CANCELLED))
    );
    assert_eq!(s.starts, 1);
    assert_eq!(s.effects, 0);
}
#[test]
fn fatal_decode_retains_unpaid_debt_instead_of_starting_another_job() {
    let mut s = Script::new();
    s.fatal_query = true;
    assert_eq!(driver::drive(&mut s), Err(5));
    assert_eq!(s.phase, Phase::Cleaning);
    assert!(s.channel);
    assert!(s.local.is_none());
    assert_eq!(s.starts, 1);
    assert!(!s.events.contains(&Event::Release));
    assert!(!s.events.contains(&Event::Ack));
}
#[test]
fn rejected_first_start_is_saved_before_its_release_fence() {
    let mut s = Script::new();
    s.rejected = Some(proto_fs::LOCK_DEADLOCK);
    assert_eq!(
        driver::drive(&mut s),
        Ok(reply(WaitPhase::Complete, proto_fs::LOCK_DEADLOCK))
    );
    assert_eq!(s.effects, 0);
    assert!(!s.events.contains(&Event::Cancel));
}

#[path = "../../posix-abi/src/wait_lock_driver/packet.rs"]
mod packet;
#[test]
fn fixed_inline_packets_match_the_real_protocol_and_strict_envelopes() {
    use proto_fs::{DataDescription, LockKind, Method, WaitKey, WaitMode, WaitStart};
    use proto_wire::{Header, Reader, Status, Writer};
    let key = WaitKey {
        slot: 15,
        generation: u64::MAX,
    };
    let wire = WaitStart {
        key,
        description: DataDescription {
            packed: 7,
            generation: 9,
        },
        mode: WaitMode::Ofd,
        kind: LockKind::Write,
        whence: 2,
        start: i64::MIN,
        length: i64::MAX,
        pid: 0,
    };
    let p = packet::Packet::start(wire).unwrap();
    let mut expected = Writer::new();
    wire.write(&mut expected).unwrap();
    assert_eq!(p.as_bytes(), expected.as_bytes());
    assert_eq!(p.as_bytes().len(), 64);
    let mut r = Reader::new(p.as_bytes());
    assert_eq!(Header::read(&mut r).unwrap(), Method::WaitStart.header());
    assert_eq!(WaitStart::read(r), Ok(wire));
    for method in [
        Method::WaitQuery,
        Method::WaitArm,
        Method::WaitCancel,
        Method::WaitRelease,
    ] {
        let p = packet::Packet::keyed(method, key).unwrap();
        let mut expected = Writer::new();
        proto_fs::write_wait_key(method, key, &mut expected).unwrap();
        assert_eq!(p.as_bytes(), expected.as_bytes());
    }
    assert!(packet::Packet::keyed(Method::LockQuery, key).is_err());
    let mut out = Writer::new();
    reply(WaitPhase::Sleeping, 0).write(&mut out).unwrap();
    assert_eq!(
        packet::reply(out.as_bytes()),
        Ok(reply(WaitPhase::Sleeping, 0))
    );
    let error = [proto_fs::NO_LOCKS.to_le_bytes(), 0u32.to_le_bytes()].concat();
    assert_eq!(
        packet::reply(&error),
        Err(Status::from_code(proto_fs::NO_LOCKS))
    );
    assert!(packet::reply(&error[..4]).is_err());
    let mut bad_reserved = error.clone();
    bad_reserved[4] = 1;
    assert_eq!(packet::reply(&bad_reserved), Err(Status::BadSize));
    let mut padded = error.clone();
    padded.extend_from_slice(&0u32.to_le_bytes());
    assert!(packet::reply(&padded).is_err());
    assert_eq!(packet::released(&[0; 8]), Ok(()));
    assert!(packet::released(&[0; 16]).is_err());
    let mut malformed = [0; 8];
    malformed[4] = 1;
    assert!(packet::released(&malformed).is_err());
}

#[test]
fn channel_capacity_failure_never_starts_and_pays_absent_release_before_ack() {
    let mut s = Script::new();
    s.channel = false;
    driver::prepared(&mut s, Err(Failure::Room)).unwrap();
    assert_eq!(
        driver::drive(&mut s),
        Ok(reply(WaitPhase::Complete, proto_fs::NO_LOCKS))
    );
    assert_eq!(s.events, vec![Event::Publish, Event::Release, Event::Ack]);
    assert_eq!(s.starts, 0);
    assert_eq!(s.effects, 0);
    assert!(!s.channel);
}
#[test]
fn fatal_channel_setup_revokes_claim_and_retains_cancel_cleanup() {
    let mut s = Script::new();
    s.channel = false;
    assert_eq!(driver::prepared(&mut s, Err(Failure::Fatal(5))), Err(5));
    assert_eq!(s.phase, Phase::Cleaning);
    assert!(!s.claim);
    assert!(s.local.is_none());
    assert!(!driver::cleanup_step(&mut s).unwrap());
    assert!(!driver::cleanup_step(&mut s).unwrap());
    assert!(driver::cleanup_step(&mut s).unwrap());
    assert_eq!(s.starts, 0);
    assert!(s.events.contains(&Event::Cancel));
}

use abi::{Error, Source};
#[path = "../../posix-abi/src/wait_lock_driver/raw_channel.rs"]
mod raw_channel;
#[test]
fn exact_raw_channel_decoders_accept_only_confirmed_gone_and_notifications() {
    assert_eq!(raw_channel::close_result(0), Ok(()));
    assert_eq!(raw_channel::close_result(Error::BadHandle.code()), Ok(()));
    for e in Error::KNOWN.into_iter().filter(|e| *e != Error::BadHandle) {
        assert_eq!(raw_channel::close_result(e.code()), Err(e));
    }
    let mut regs = [0; 10];
    regs[1] = 0x123456789abcd007;
    assert_eq!(raw_channel::duplicate_result(&regs), Ok(regs[1]));
    regs[0] = Error::BadHandle.code();
    assert_eq!(raw_channel::duplicate_result(&regs), Err(Error::BadHandle));
    assert_eq!(raw_channel::receive_result(&regs), Err(Error::BadHandle));
    regs[0] = 0;
    regs[1] = Source::Unlabeled.code() << abi::SOURCE_SHIFT;
    assert_eq!(raw_channel::receive_result(&regs), Ok(()));
    regs[1] = Source::Session.code() << abi::SOURCE_SHIFT;
    assert_eq!(raw_channel::receive_result(&regs), Ok(()));
    regs[1] = 0;
    assert_eq!(raw_channel::receive_result(&regs), Err(Error::BadState));
}
