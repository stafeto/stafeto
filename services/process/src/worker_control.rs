// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One existing worker's command and exact raw capability custody.
//! Only a retained kernel request proves that a live worker is parked.
//! The native controller must retain that Pending before rearming this slot.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};
use proto_wire::{Reader, Status, Writer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Idle,
    Refresh,
    InitialProof {
        index: u16,
        generation: u32,
        ticket: u64,
        epoch: u64,
    },
    Replace {
        index: u16,
        label: u64,
        image: u32,
        ticket: u64,
    },
}

const IDLE: u64 = 0;
const MAIN: u64 = 1;
const CLAIMED: u64 = 2;
const CANCELLED: u64 = 3;
const OUTCOME: u64 = 4;
const ACK: u64 = 1 << 8;
const KIND_SHIFT: u32 = 9;
const KIND_MASK: u64 = 3 << KIND_SHIFT;

/// InitialProof raw custody is distinct from the worker publication phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum RawKind {
    Empty = 0,
    Capability = 1,
    ProofPublishing = 2,
    ProofBuffer = 3,
}
impl RawKind {
    fn state(self) -> u64 {
        (self as u64) << KIND_SHIFT
    }
    fn read(state: u64) -> Self {
        match (state & KIND_MASK) >> KIND_SHIFT {
            0 => Self::Empty,
            1 => Self::Capability,
            2 => Self::ProofPublishing,
            _ => Self::ProofBuffer,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub raw: u64,
    pub status: u32,
    pub acknowledged: bool,
    pub reply_slots: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    Owned(Command, u64),
    Cancelled,
    Stale,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub worker: u64,
    pub serial: u64,
    pub status: u32,
}
impl Completion {
    pub fn read(mut reader: Reader<'_>, caps: usize) -> Result<Self, Status> {
        let value = Self {
            worker: reader.u64()?,
            serial: reader.u64()?,
            status: reader.u32()?,
        };
        if reader.u32()? != 0 || reader.finish().is_err() || caps != 0 {
            return Err(Status::BadSize);
        }
        Ok(value)
    }
    pub fn write(self, writer: &mut Writer) -> Result<(), Status> {
        writer.u64(self.worker)?;
        writer.u64(self.serial)?;
        writer.u32(self.status)?;
        writer.u32(0)
    }
}

/// Burn a fresh native admission serial. MAX is a terminal tombstone:
/// existing debt may observe it, but no fresh Send is admitted there.
pub fn prepay(counter: &mut u64) -> Option<u64> {
    *counter = counter.checked_add(1)?;
    (*counter != u64::MAX).then_some(*counter)
}

pub fn init_status(mut reader: Reader<'_>) -> Result<u32, Status> {
    let status = reader.u32()?;
    if reader.u32()? != 0 || reader.finish().is_err() {
        return Err(Status::BadSize);
    }
    Ok(status)
}

pub fn command_reply(command: Command, serial: u64) -> Writer {
    let mut writer = Writer::new();
    let (op, label) = match command {
        Command::Replace { label, .. } => (0, label),
        Command::Refresh => (1, 0),
        Command::Idle => unreachable!("idle has no command reply"),
        Command::InitialProof { .. } => {
            unreachable!("initial proof has its retained 120-byte reply")
        }
    };
    writer
        .u32(0)
        .and_then(|()| writer.u32(op))
        .and_then(|()| writer.u64(label))
        .and_then(|()| writer.u64(serial))
        .expect("a fixed command reply fits");
    writer
}

pub fn reply_serial(mut reader: Reader<'_>, caps: usize) -> Result<(u32, u64, u64), Status> {
    if reader.u32()? != 0 {
        return Err(Status::BadSize);
    }
    let value = (reader.u32()?, reader.u64()?, reader.u64()?);
    if reader.finish().is_err() || caps != 0 {
        return Err(Status::BadSize);
    }
    Ok(value)
}

pub struct Shared {
    command: UnsafeCell<Command>,
    serial: AtomicU64,
    raw: AtomicU64,
    state: AtomicU64,
    reply_slots: AtomicU64,
}

// SAFETY: publication and claim order access to command. Rearming is
// unsafe and requires the native controller's actual parked/Ended proof.
unsafe impl Sync for Shared {}

impl Shared {
    pub const fn new() -> Self {
        Self {
            command: UnsafeCell::new(Command::Idle),
            serial: AtomicU64::new(0),
            raw: AtomicU64::new(0),
            state: AtomicU64::new(IDLE),
            reply_slots: AtomicU64::new(0),
        }
    }

    pub fn serial(&self) -> u64 {
        self.serial.load(Ordering::Acquire)
    }
    pub fn raw(&self) -> u64 {
        self.raw.load(Ordering::Acquire)
    }
    pub fn idle(&self) -> bool {
        self.state.load(Ordering::Acquire) == IDLE
    }

    /// # Safety
    /// The main thread has the exact retained parked request (or Ended),
    /// and all previous owners have settled. The worker cannot read here.
    pub unsafe fn stage(&self, command: Command, serial: u64) {
        assert!(self.idle());
        assert_ne!(serial, 0);
        // SAFETY: the caller supplies the same proof as publish.
        unsafe {
            *self.command.get() = command;
        }
        self.serial.store(serial, Ordering::Release);
    }

    /// # Safety
    /// Only the native main thread reads this copy. The worker never
    /// writes command, and main does not concurrently rearm itself.
    pub unsafe fn command(&self) -> Command {
        // SAFETY: the caller's exclusive main-thread access above.
        unsafe { *self.command.get() }
    }

    /// # Safety
    /// Main owns this new duplicate while idle, or has settled the
    /// previous raw under actual parked/Ended proof. No live claim exists.
    pub unsafe fn main_raw(&self, raw: u64) {
        self.raw.store(raw, Ordering::Release);
    }

    /// # Safety
    /// The main thread retains the exact worker completion Pending with
    /// matching prior serial/Outcome, or has genuine ThreadEnded proof.
    /// All prior raw/reply slots are settled; no worker reads command.
    pub unsafe fn publish(&self, command: Command, serial: u64, raw: u64) {
        assert_ne!(serial, 0);
        assert_eq!(self.state.load(Ordering::Acquire), IDLE);
        // SAFETY: the caller provides the parked/Ended proof above.
        unsafe {
            *self.command.get() = command;
        }
        self.raw.store(raw, Ordering::Relaxed);
        self.reply_slots.store(0, Ordering::Relaxed);
        self.serial.store(serial, Ordering::Relaxed);
        let kind = if matches!(command, Command::InitialProof { .. }) && raw != 0 {
            RawKind::Capability.state()
        } else {
            0
        };
        self.state.store(MAIN | kind, Ordering::Release);
    }

    pub fn claim(&self, serial: u64) -> Claim {
        if self.serial() != serial {
            return Claim::Stale;
        }
        let state = self.state.load(Ordering::Acquire);
        let phase = state & 0xff;
        if phase == CANCELLED {
            return Claim::Cancelled;
        }
        if phase != MAIN {
            return Claim::Stale;
        }
        match self.state.compare_exchange(
            state,
            CLAIMED | (state & KIND_MASK),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // SAFETY: claim wins against cancel; command cannot be rearmed.
                let command = unsafe { *self.command.get() };
                Claim::Owned(command, self.raw.load(Ordering::Acquire))
            }
            Err(value) if value & 0xff == CANCELLED => Claim::Cancelled,
            Err(_) => Claim::Stale,
        }
    }

    pub fn cancel(&self, serial: u64) -> bool {
        if self.serial() != serial {
            return false;
        }
        let state = self.state.load(Ordering::Acquire);
        state & 0xff == MAIN
            && self
                .state
                .compare_exchange(
                    state,
                    CANCELLED | (state & KIND_MASK),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    /// Read custody even after genuine Ended interrupted Outcome publication.
    pub fn raw_kind(&self, serial: u64) -> Option<RawKind> {
        (self.serial() == serial).then(|| RawKind::read(self.state.load(Ordering::Acquire)))
    }

    /// Publish stable cap slots before the first InitialProof Send.
    pub fn initial_slots(&self, serial: u64, pointer: u64) -> bool {
        if self.serial() != serial
            || self.state.load(Ordering::Acquire) & 0xff != CLAIMED
            || pointer == 0
        {
            return false;
        }
        // SAFETY: a claimed command is immutable until parked/Ended reset.
        if !matches!(unsafe { *self.command.get() }, Command::InitialProof { .. }) {
            return false;
        }
        self.reply_slots.store(pointer, Ordering::Release);
        true
    }

    pub fn slots(&self, serial: u64) -> Option<u64> {
        (self.serial() == serial).then(|| self.reply_slots.load(Ordering::Acquire))
    }

    /// Disarm capability interpretation before any proof pointer store.
    /// The caller has validated the consumed Send and canonical proof.
    pub fn begin_proof(&self, serial: u64) -> bool {
        if self.serial() != serial {
            return false;
        }
        // SAFETY: the worker's claimed command remains immutable.
        if !matches!(unsafe { *self.command.get() }, Command::InitialProof { .. }) {
            return false;
        }
        let state = self.state.load(Ordering::Acquire);
        state & 0xff == CLAIMED
            && self
                .state
                .compare_exchange(
                    state,
                    CLAIMED | RawKind::ProofPublishing.state(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    pub fn complete_initial(&self, serial: u64, outcome: Outcome, kind: RawKind) -> bool {
        if self.serial() != serial {
            return false;
        }
        let state = self.state.load(Ordering::Acquire);
        let phase = state & 0xff;
        // SAFETY: command remains immutable throughout a claim.
        if !matches!(unsafe { *self.command.get() }, Command::InitialProof { .. }) {
            return false;
        }
        if phase != CLAIMED && phase != CANCELLED {
            return false;
        }
        if kind == RawKind::ProofPublishing {
            return false;
        }
        let success = kind == RawKind::ProofBuffer;
        if success {
            if phase != CLAIMED
                || RawKind::read(state) != RawKind::ProofPublishing
                || !outcome.acknowledged
                || outcome.status != 0
                || outcome.raw == 0
            {
                return false;
            }
        } else if outcome.acknowledged || (kind == RawKind::Empty) != (outcome.raw == 0) {
            return false;
        }
        if phase == CANCELLED && (kind != RawKind::read(state) || outcome.raw != self.raw()) {
            return false;
        }
        self.raw.store(outcome.raw, Ordering::Relaxed);
        self.reply_slots
            .store(outcome.reply_slots, Ordering::Relaxed);
        self.state.store(
            OUTCOME
                | kind.state()
                | (u64::from(outcome.status) << 32)
                | if success { ACK } else { 0 },
            Ordering::Release,
        );
        true
    }

    /// Called by the worker after Send, or after observing cancellation.
    /// Every unexpected reply cap is already in stable STACK slots.
    pub fn complete(&self, serial: u64, outcome: Outcome) -> bool {
        // SAFETY: only claimed immutable commands reach completion.
        if matches!(unsafe { *self.command.get() }, Command::InitialProof { .. }) {
            return false;
        }
        if self.serial() != serial || outcome.acknowledged && outcome.status != 0 {
            return false;
        }
        let state = self.state.load(Ordering::Acquire);
        if state != CLAIMED && state != CANCELLED {
            return false;
        }
        if state == CANCELLED && (outcome.raw != self.raw() || outcome.acknowledged) {
            return false;
        }
        self.raw.store(outcome.raw, Ordering::Relaxed);
        self.reply_slots
            .store(outcome.reply_slots, Ordering::Relaxed);
        self.state.store(
            OUTCOME
                | (u64::from(outcome.status) << 32)
                | if outcome.acknowledged { ACK } else { 0 },
            Ordering::Release,
        );
        true
    }

    pub fn outcome(&self, serial: u64) -> Option<Outcome> {
        if self.serial() != serial {
            return None;
        }
        let state = self.state.load(Ordering::Acquire);
        (state & 0xff == OUTCOME).then(|| Outcome {
            raw: self.raw.load(Ordering::Acquire),
            status: (state >> 32) as u32,
            acknowledged: state & ACK != 0,
            reply_slots: self.reply_slots.load(Ordering::Acquire),
        })
    }

    /// # Safety
    /// Main has exact parked completion or genuine Ended, and has closed
    /// or adopted every raw/reply slot. Cancellation alone is insufficient.
    pub unsafe fn reset(&self, serial: u64) -> bool {
        if self.serial() != serial {
            return false;
        }
        self.raw.store(0, Ordering::Relaxed);
        self.reply_slots.store(0, Ordering::Relaxed);
        self.state.store(IDLE, Ordering::Release);
        true
    }
}

impl Default for Shared {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn initial_command() -> Command {
        Command::InitialProof {
            index: 3,
            generation: u32::MAX,
            ticket: 29,
            epoch: 37,
        }
    }
    #[test]
    fn initial_raw_end_boundaries_preserve_discriminator_and_slots() {
        let shared = Shared::new();
        unsafe {
            shared.publish(initial_command(), 17, 0x1234);
        }
        assert_eq!(shared.raw_kind(17), Some(RawKind::Capability));
        assert_eq!(shared.claim(17), Claim::Owned(initial_command(), 0x1234));
        assert!(shared.initial_slots(17, 0x4000));
        assert_eq!(shared.slots(17), Some(0x4000));
        assert!(shared.begin_proof(17));
        assert_eq!(shared.raw_kind(17), Some(RawKind::ProofPublishing));
        assert!(shared.outcome(17).is_none());
        let outcome = Outcome {
            raw: 0x5000,
            status: 0,
            acknowledged: true,
            reply_slots: 0x4000,
        };
        assert!(!shared.complete(17, outcome));
        assert!(shared.complete_initial(17, outcome, RawKind::ProofBuffer));
        assert_eq!(shared.raw_kind(17), Some(RawKind::ProofBuffer));
        assert_eq!(shared.outcome(17), Some(outcome));
        assert!(shared.raw_kind(18).is_none());
    }
    #[test]
    fn initial_cancel_and_consumed_error_never_publish_proof() {
        let shared = Shared::new();
        unsafe {
            shared.publish(initial_command(), 17, 0x1234);
        }
        assert!(shared.cancel(17));
        assert_eq!(shared.claim(17), Claim::Cancelled);
        assert_eq!(shared.raw_kind(17), Some(RawKind::Capability));
        assert!(!shared.begin_proof(17));
        let canceled = Outcome {
            raw: 0x1234,
            status: 19,
            acknowledged: false,
            reply_slots: 0,
        };
        assert!(shared.complete_initial(17, canceled, RawKind::Capability));
        unsafe {
            assert!(shared.reset(17));
            shared.publish(initial_command(), 18, 0x5678);
        }
        assert!(matches!(shared.claim(18), Claim::Owned(..)));
        let consumed = Outcome {
            raw: 0,
            status: 19,
            acknowledged: false,
            reply_slots: 0x4000,
        };
        assert!(!shared.complete_initial(18, consumed, RawKind::ProofBuffer));
        assert!(shared.complete_initial(18, consumed, RawKind::Empty));
        assert_eq!(shared.raw_kind(18), Some(RawKind::Empty));
        assert!(!shared.outcome(18).unwrap().acknowledged);
    }

    fn command() -> Command {
        Command::Replace {
            index: 2,
            label: 0x1202,
            image: 3,
            ticket: 19,
        }
    }
    fn failed(raw: u64) -> Outcome {
        Outcome {
            raw,
            status: 17,
            acknowledged: false,
            reply_slots: 0,
        }
    }

    #[test]
    fn cancellation_and_claim_choose_one_owner_and_keep_same_serial() {
        let shared = Shared::new();
        unsafe {
            shared.publish(command(), 7, 99);
        }
        assert!(shared.cancel(7));
        assert_eq!(shared.claim(7), Claim::Cancelled);
        assert!(
            !shared.complete(7, failed(100)),
            "cancellation preserves the main-owned full raw"
        );
        assert!(shared.complete(7, failed(99)));
        assert_eq!(shared.outcome(7), Some(failed(99)));
        unsafe {
            assert!(shared.reset(7));
            shared.publish(command(), 8, 101);
        }
        assert_eq!(shared.claim(7), Claim::Stale);
        assert!(!shared.complete(7, failed(99)));
        assert_eq!(shared.claim(8), Claim::Owned(command(), 101));
        assert!(!shared.cancel(8));
        assert!(shared.complete(8, failed(0)));
        assert!(
            !shared.outcome(8).unwrap().acknowledged,
            "consumed on unknown loss is not ACK"
        );
    }

    #[test]
    fn outcome_carries_returned_generation_and_slots_before_parked_reuse() {
        assert_eq!(core::mem::size_of::<Shared>(), 56);
        let shared = Shared::new();
        unsafe {
            shared.publish(command(), u64::MAX, 99);
        }
        assert_eq!(shared.claim(u64::MAX), Claim::Owned(command(), 99));
        let outcome = Outcome {
            raw: 199,
            status: 0,
            acknowledged: false,
            reply_slots: 0x1000,
        };
        assert!(shared.complete(u64::MAX, outcome));
        assert_eq!(shared.outcome(u64::MAX), Some(outcome));
        assert_eq!(shared.claim(u64::MAX), Claim::Stale);
        assert!(!shared.cancel(u64::MAX));
        assert_eq!(shared.raw(), 199);
    }

    #[test]
    fn native_serial_admission_burns_max_without_admitting_or_wrapping() {
        let mut counter = u64::MAX - 2;
        assert_eq!(prepay(&mut counter), Some(u64::MAX - 1));
        assert_eq!(prepay(&mut counter), None);
        assert_eq!(counter, u64::MAX);
        assert_eq!(prepay(&mut counter), None);
        assert_eq!(counter, u64::MAX);
        let mut fresh = 0;
        assert_eq!(prepay(&mut fresh), Some(1));
    }

    #[test]
    fn init_ack_requires_exact_status_reserved_and_length() {
        assert_eq!(init_status(Reader::new(&[0; 8])), Ok(0));
        for len in 0..8 {
            assert!(init_status(Reader::new(&[0; 8][..len])).is_err());
        }
        assert!(init_status(Reader::new(&[0; 9])).is_err());
        let mut bad = [0; 8];
        bad[4] = 1;
        assert!(init_status(Reader::new(&bad)).is_err());
        let mut error = [0; 8];
        error[0] = 17;
        assert_eq!(init_status(Reader::new(&error)), Ok(17));
    }

    #[test]
    fn simultaneous_claim_and_cancel_never_publish_two_owners() {
        use std::sync::{Arc, Barrier};
        for serial in 1..=64 {
            let shared = Arc::new(Shared::new());
            unsafe {
                shared.publish(command(), serial, 99);
            }
            let barrier = Arc::new(Barrier::new(2));
            let other = shared.clone();
            let gate = barrier.clone();
            let worker = std::thread::spawn(move || {
                gate.wait();
                other.claim(serial)
            });
            barrier.wait();
            let cancelled = shared.cancel(serial);
            let claim = worker.join().unwrap();
            match (cancelled, claim) {
                (true, Claim::Cancelled) => assert!(shared.complete(serial, failed(99))),
                (false, Claim::Owned(_, 99)) => assert!(shared.complete(serial, failed(0))),
                shape => panic!("one custody winner required: {shape:?}"),
            }
            assert!(!shared.outcome(serial).unwrap().acknowledged);
        }
    }

    #[test]
    fn completion_and_command_reply_reject_trailing_bytes_reserved_and_caps() {
        let completion = Completion {
            worker: 99,
            serial: 7,
            status: 17,
        };
        let mut wire = Writer::new();
        completion.write(&mut wire).unwrap();
        assert_eq!(
            Completion::read(Reader::new(wire.as_bytes()), 0),
            Ok(completion)
        );
        assert!(Completion::read(Reader::new(wire.as_bytes()), 1).is_err());
        let mut bad = wire.as_bytes().to_vec();
        bad[20] = 1;
        assert!(Completion::read(Reader::new(&bad), 0).is_err());
        bad = wire.as_bytes().to_vec();
        bad.push(0);
        assert!(Completion::read(Reader::new(&bad), 0).is_err());
        let wire = command_reply(command(), 7);
        assert_eq!(
            reply_serial(Reader::new(wire.as_bytes()), 0),
            Ok((0, 0x1202, 7))
        );
        assert!(reply_serial(Reader::new(wire.as_bytes()), 1).is_err());
        let mut bad = wire.as_bytes().to_vec();
        bad.push(0);
        assert!(reply_serial(Reader::new(&bad), 0).is_err());
    }
}
