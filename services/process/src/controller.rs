// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Main-thread ownership beside the existing worker's atomic mailbox.

use posix_process_service::worker_control::Shared;

// Separate from OWNER: main's exclusive Processes/Controller references
// never cover the worker's shared atomic mailbox or command UnsafeCell.
pub(super) static SHARED: Shared = Shared::new();
use rt::handle::{Channel, Handle, Thread};
use rt::service::Pending;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Idle,
    Duplicate,
    Publish,
    Waiting,
    Drain,
    ReadInitialProof,
    CheckRaw,
    CloseRaw,
    CheckFiles,
    InstallFiles,
    CloseFiles,
    Finish,
    DiscardPending,
    Retire,
    Create,
    Start,
}

pub(super) struct Controller {
    pub pending: Option<Pending>,
    pub worker: Option<Handle<Thread>>,
    pub retired: Option<Handle<Thread>>,
    pub result: Option<Handle<Channel>>,
    pub next_serial: u64,
    pub phase: Phase,
    pub cursor: u8,
    pub refresh: bool,
    pub ended: bool,
    pub turn: bool,
    pub reap: bool,
    pub check_files: bool,
    pub bootstrap: bool,
}

impl Controller {
    pub const fn new() -> Self {
        Self {
            pending: None,
            worker: None,
            retired: None,
            result: None,
            next_serial: 0,
            phase: Phase::Idle,
            cursor: 0,
            refresh: false,
            ended: false,
            turn: false,
            reap: false,
            check_files: false,
            bootstrap: true,
        }
    }

    /// Admission burns its serial before any new Process/Thread effect.
    pub fn prepay(&mut self) -> Option<u64> {
        posix_process_service::worker_control::prepay(&mut self.next_serial)
    }

    pub fn busy(&self) -> bool {
        self.reap
            || self.phase != Phase::Waiting
                && (self.phase != Phase::Idle
                    || self.pending.is_some() && (self.refresh || self.check_files))
    }
}

/// Raw Info is intentional here: the exact transferred generational
/// handle may genuinely no longer be in this process after Send.
pub(super) fn raw_info(raw: u64, kind: u64) -> Result<[u64; 10], rt::abi::Error> {
    let mut args = [0; 10];
    args[0] = raw;
    args[1] = kind;
    // SAFETY: object_info only reads the full native handle and returns
    // registers. It cannot access caller-provided memory or run EL0 code.
    let values = unsafe { rt::sys::raw::<{ rt::abi::Call::ObjectInfo.number() }>(args) };
    match rt::abi::Error::from_code(values[0]) {
        None => Ok(values),
        Some(error) => Err(error),
    }
}

pub(super) fn raw_close(raw: u64) -> Result<(), rt::abi::Error> {
    let mut args = [0; 10];
    args[0] = raw;
    // SAFETY: the controller owns this exact full raw after parked/Ended
    // proof. Closing removes only its capability; no process-stop claim.
    let values = unsafe { rt::sys::raw::<{ rt::abi::Call::HandleClose.number() }>(args) };
    match rt::abi::Error::from_code(values[0]) {
        None => Ok(()),
        Some(error) => Err(error),
    }
}

use crate::{Processes, Work, make, replace};
use core::sync::atomic::{AtomicU64, Ordering};
use posix_process_service::worker_control::{Command, Completion, command_reply};
use proto_wire::Status;
use rt::service::{Answer, Request};
use rt::{abi, sys};

impl Processes {
    pub(super) fn controller_needed(&self) -> bool {
        self.replacer.busy()
            || self.replacer.phase == Phase::Idle
                && self.replacer.pending.is_some()
                && !self.replace_queue.is_empty()
    }

    pub(super) fn controller_request(&mut self, request: &mut Request<'_>) -> Answer {
        let Ok(completion) = Completion::read(request.body(), request.handles.len()) else {
            return Answer::Status(Status::BadSize);
        };
        let Some(worker) = self.replacer.worker.as_ref() else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        if completion.worker != worker.raw().0 || self.replacer.pending.is_some() {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        let serial = SHARED.serial();
        if completion.serial != serial {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        if self.replacer.bootstrap {
            if !SHARED.idle() || completion.status != 0 {
                return Answer::Status(Status::BadSize);
            }
        } else if !SHARED
            .outcome(serial)
            .is_some_and(|outcome| outcome.status == completion.status)
        {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        let Some(pending) = request.defer() else {
            return Answer::Status(Status::BadSize);
        };
        // Holding this exact request proves the worker is parked. No
        // AtomicParked store before its Send is used as such a proof.
        self.replacer.pending = Some(pending);
        let bootstrap = self.replacer.bootstrap;
        self.replacer.bootstrap = false;
        self.replacer.cursor = 0;
        self.replacer.phase = if bootstrap { Phase::Idle } else { Phase::Drain };
        self.kick();
        Answer::Deferred
    }

    pub(super) fn controller_step(&mut self) {
        if self.replacer.reap {
            let Some(worker) = self.replacer.worker.as_ref() else {
                self.replacer.reap = false;
                return;
            };
            if let Ok(info) = sys::thread_info(worker) {
                if info.state == abi::ThreadState::Ended {
                    if self.replacer.retired.is_some() {
                        return;
                    }
                    self.replacer.retired = self.replacer.worker.take();
                    self.replacer.ended = true;
                    self.replacer.cursor = 0;
                    self.replacer.phase = if self.replacer.pending.is_some() {
                        Phase::DiscardPending
                    } else {
                        Phase::Drain
                    };
                }
                self.replacer.reap = false;
            }
            return;
        }
        if matches!(self.replacer.phase, Phase::Duplicate | Phase::Publish)
            && let Command::InitialProof { index, .. } = unsafe { SHARED.command() }
            && self.replacing[usize::from(index)]
                .as_ref()
                .and_then(Work::initial)
                .and_then(|resident| resident.pending_stage())
                .is_none()
        {
            let serial = SHARED.serial();
            if SHARED.idle() {
                // SAFETY: the old genuine Pending still proves parking.
                unsafe {
                    SHARED.publish(SHARED.command(), serial, SHARED.raw());
                }
                assert!(SHARED.cancel(serial));
                self.replacer.cursor = 0;
                self.replacer.phase = Phase::Drain;
            } else {
                self.replacer.reap = true;
            }
            return;
        }
        match self.replacer.phase {
            Phase::Idle => {
                if self.replacer.pending.is_none() {
                    return;
                }
                if let Some(index) = self.replace_queue.pop() {
                    if let Some(resident) = self.replacing[index].as_ref().and_then(Work::initial) {
                        let Some((epoch, ..)) = resident.pending_stage() else {
                            return;
                        };
                        let Some((label, proto_process::Place::Work, 1)) =
                            proto_process::Label::parse_image(resident.key.label)
                        else {
                            return;
                        };
                        let command = Command::InitialProof {
                            index: label.index,
                            generation: label.generation,
                            ticket: resident.key.ticket,
                            epoch,
                        };
                        let Some(serial) = self.replacer.prepay() else {
                            return;
                        };
                        // SAFETY: the exact retained parked worker and settled prior owners.
                        unsafe {
                            SHARED.stage(command, serial);
                        }
                        self.replacer.phase = Phase::Duplicate;
                        return;
                    }
                    let Some(work) = self.replacing[index].as_ref().and_then(Work::replacing)
                    else {
                        return;
                    };
                    if work.old.cleanup_requested() {
                        return;
                    }
                    let command = Command::Replace {
                        index: index as u16,
                        label: work.key.label.raw_at(work.key.image),
                        image: work.key.image,
                        ticket: work.ticket,
                    };
                    // SAFETY: the actual worker Pending is retained; the
                    // previous raw and reply slots were settled before Idle.
                    unsafe {
                        SHARED.stage(command, work.serial);
                    }
                    self.replacer.phase = Phase::Duplicate;
                } else if self.replacer.refresh {
                    // An interrupted/failed refresh replays its existing
                    // serial, just as a replacement reuses its prepaid one.
                    let previous = unsafe { SHARED.command() };
                    let serial = if previous == Command::Refresh && SHARED.serial() != 0 {
                        SHARED.serial()
                    } else {
                        let Some(serial) = self.replacer.prepay() else {
                            return;
                        };
                        serial
                    };
                    unsafe {
                        SHARED.stage(Command::Refresh, serial);
                    }
                    self.replacer.phase = Phase::Publish;
                } else if self.replacer.check_files {
                    if let Some(files) = self.files.as_ref() {
                        if let Ok(info) = sys::channel_info(files) {
                            self.replacer.check_files = false;
                            self.replacer.refresh = info.closed;
                        }
                    } else {
                        self.replacer.check_files = false;
                        self.replacer.refresh = true;
                    }
                }
            }
            Phase::Duplicate => {
                if let Command::InitialProof {
                    index,
                    generation,
                    ticket,
                    epoch,
                } = unsafe { SHARED.command() }
                {
                    let label = proto_process::Label { index, generation };
                    let Some(resident) = self.replacing[usize::from(index)]
                        .as_ref()
                        .and_then(Work::initial)
                    else {
                        return;
                    };
                    if resident.key.label != label.raw_at(1)
                        || resident.key.ticket != ticket
                        || resident.pending_stage().map(|value| value.0) != Some(epoch)
                    {
                        return;
                    }
                    use posix_process_service::initial_resident::CleanupOwner;
                    let Some(CleanupOwner::Channel(candidate)) = resident.cleanup[0].as_ref()
                    else {
                        return;
                    };
                    if let Ok(copy) =
                        sys::handle_duplicate(candidate, abi::Rights::SEND | abi::Rights::TRANSFER)
                    {
                        unsafe {
                            SHARED.main_raw(copy.into_raw().0);
                        }
                        self.replacer.phase = Phase::Publish;
                    }
                    return;
                }
                let Command::Replace {
                    index,
                    label,
                    image,
                    ticket,
                } = (unsafe { SHARED.command() })
                else {
                    unreachable!("a replacement duplicate");
                };
                let Some(work) = self.replacing[usize::from(index)]
                    .as_ref()
                    .and_then(Work::replacing)
                else {
                    return;
                };
                if work.key.label.raw_at(work.key.image) != label
                    || work.key.image != image
                    || work.ticket != ticket
                    || work.serial != SHARED.serial()
                {
                    return;
                }
                let Some(anchor) = work.process.as_ref() else {
                    return;
                };
                if let Ok(transfer) =
                    sys::handle_duplicate(anchor, abi::Rights::DUPLICATE | abi::Rights::TRANSFER)
                {
                    // SAFETY: worker remains parked and this new duplicate
                    // is main-owned. There is no main-to-worker IPC cap hop.
                    unsafe {
                        SHARED.main_raw(transfer.into_raw().0);
                    }
                    self.replacer.phase = Phase::Publish;
                }
            }
            Phase::Publish => {
                if let Command::InitialProof { index, .. } = unsafe { SHARED.command() } {
                    let Some(resident) = self.replacing[usize::from(index)]
                        .as_ref()
                        .and_then(Work::initial)
                    else {
                        return;
                    };
                    let Some((epoch, uid, gid, mode)) = resident.pending_stage() else {
                        return;
                    };
                    let Some(files) = self.files.as_ref() else {
                        return;
                    };
                    let stage = proto_process::initial_stage::Stage {
                        epoch,
                        ticket: resident.key.ticket,
                        label: resident.key.label,
                        source: resident.publication.source,
                        query: proto_process::initial_identity::Query {
                            receipt: resident.publication.map.receipt,
                        },
                        uid,
                        gid,
                        mode,
                    };
                    let mut wire = proto_wire::Writer::new();
                    wire.bytes(&[0; 8])
                        .and_then(|()| stage.write(&mut wire))
                        .and_then(|()| wire.u64(SHARED.serial()))
                        .and_then(|()| wire.u64(files.raw().0))
                        .expect("fixed initial command reply");
                    let Some(pending) = self.replacer.pending.as_mut() else {
                        return;
                    };
                    let Some(token) = pending.take_token() else {
                        return;
                    };
                    // Publication happens once while the worker remains parked.
                    if SHARED.idle() {
                        unsafe {
                            SHARED.publish(SHARED.command(), SHARED.serial(), SHARED.raw());
                        }
                    }
                    match token.reply_handles(wire.as_bytes(), rt::handle::Outgoing::new()) {
                        Ok(()) => {
                            self.replacer.pending.take();
                            self.replacer.phase = Phase::Waiting;
                        }
                        Err(mut refused) => {
                            assert!(
                                refused
                                    .back
                                    .as_ref()
                                    .is_none_or(rt::handle::Outgoing::is_empty)
                            );
                            if let Some(token) = refused.token.take() {
                                assert!(pending.restore_token(token).is_ok());
                                self.replacer.reap = true;
                            } else {
                                self.replacer.pending.take();
                                self.replacer.phase = Phase::Waiting;
                                self.replacer.reap = true;
                            }
                        }
                    }
                    return;
                }
                let Some(pending) = self.replacer.pending.take() else {
                    return;
                };
                let command = unsafe { SHARED.command() };
                let serial = SHARED.serial();
                let raw = SHARED.raw();
                // SAFETY: this is the actual retained parked request. Its
                // command/serial and duplicate were paid before publication.
                unsafe {
                    SHARED.publish(command, serial, raw);
                }
                self.replacer.phase = Phase::Waiting;
                let wire = command_reply(command, serial);
                if pending
                    .answer(wire.as_bytes(), rt::handle::Outgoing::new())
                    .is_err()
                {
                    self.replacer.reap = true;
                }
            }
            Phase::Waiting => {}
            Phase::DiscardPending => {
                if matches!(unsafe { SHARED.command() }, Command::InitialProof { .. }) {
                    assert!(
                        self.replacer.ended,
                        "genuine worker Ended permits stale token discard"
                    );
                    if let Some(pending) = self.replacer.pending.as_mut() {
                        // The exact request's thread ended. Token has no Drop
                        // syscall; removing it disarms Pending's fallback reply.
                        pending.take_token();
                    }
                }
                drop(self.replacer.pending.take());
                self.replacer.phase = Phase::Drain;
            }
            Phase::Drain => {
                let serial = SHARED.serial();
                let outcome = SHARED.outcome(serial);
                let pointer = SHARED.slots(serial).unwrap_or(0);
                if pointer != 0 && self.replacer.cursor < abi::MESSAGE_HANDLES as u8 {
                    if !replace::owns_slots(pointer) {
                        return;
                    }
                    // SAFETY: either the exact worker request is retained,
                    // or genuine Ended protects its static STACK. Worker
                    // cannot mutate/reuse slots before the main reply.
                    let slot = unsafe {
                        &*((pointer as *const AtomicU64).add(usize::from(self.replacer.cursor)))
                    };
                    let raw = slot.load(Ordering::Acquire);
                    if raw == 0 || raw_close(raw).is_ok() {
                        slot.store(0, Ordering::Release);
                        self.replacer.cursor += 1;
                    }
                    return;
                }
                if matches!(unsafe { SHARED.command() }, Command::InitialProof { .. }) {
                    use posix_process_service::worker_control::RawKind;
                    match SHARED.raw_kind(serial).expect("the current initial serial") {
                        RawKind::ProofBuffer if !self.replacer.ended => {
                            self.replacer.phase = Phase::ReadInitialProof
                        }
                        RawKind::ProofBuffer | RawKind::ProofPublishing => {
                            // Genuine Ended forbids reading/closing a proof pointer.
                            unsafe {
                                SHARED.main_raw(0);
                            }
                            self.replacer.phase = Phase::Finish;
                        }
                        RawKind::Empty => self.replacer.phase = Phase::Finish,
                        RawKind::Capability => {
                            self.replacer.phase = if self.replacer.ended {
                                Phase::CheckRaw
                            } else {
                                Phase::CloseRaw
                            }
                        }
                    }
                    return;
                }
                self.replacer.phase = if SHARED.raw() != 0 {
                    match unsafe { SHARED.command() } {
                        Command::Refresh if outcome.is_some_and(|outcome| outcome.acknowledged) => {
                            Phase::CheckFiles
                        }
                        _ if self.replacer.ended => Phase::CheckRaw,
                        _ => Phase::CloseRaw,
                    }
                } else {
                    Phase::Finish
                };
            }
            Phase::ReadInitialProof => {
                let pointer = SHARED.raw();
                if self.replacer.pending.is_none()
                    || self.replacer.ended
                    || !replace::owns_proof(pointer)
                {
                    return;
                }
                // SAFETY: genuine retained Completion and checked STACK120
                // protect the worker buffer until this CPU-only read ends.
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        pointer as *const u8,
                        proto_process::initial_stage::PROOF,
                    )
                };
                let proof = proto_process::initial_stage::Proof::read(bytes, 0)
                    .expect("the published canonical source proof");
                let Command::InitialProof {
                    index,
                    generation,
                    ticket,
                    epoch,
                } = (unsafe { SHARED.command() })
                else {
                    unreachable!()
                };
                let label = proto_process::Label { index, generation };
                let index = usize::from(index);
                if let Some(resident) = self
                    .replacing
                    .get_mut(index)
                    .and_then(Option::as_mut)
                    .and_then(Work::initial_mut)
                {
                    let matches = resident.key.label == label.raw_at(1)
                        && resident.key.ticket == ticket
                        && resident.pending_stage()
                            == Some((epoch, proof.stage.uid, proof.stage.gid, proof.stage.mode))
                        && resident.publication.source == proof.stage.source
                        && resident.publication.map.receipt == proof.stage.query.receipt
                        && proof.stage.label == label.raw_at(1)
                        && proof.stage.ticket == ticket
                        && proof.stage.epoch == epoch;
                    if matches
                        && self.tickets[index] == ticket
                        && self.records.get(index).is_some_and(|record| {
                            record.label == label
                                && record.image == 1
                                && record.state == crate::State::Loading
                                && record.active_exec.is_none()
                                && record.initial_epoch(ticket) == Some(0)
                        })
                    {
                        use posix_process_service::initial_resident::{CleanupOwner, SeedKey};
                        if matches!(resident.cleanup[0], Some(CleanupOwner::Channel(_))) {
                            assert!(resident.authenticated_stage(
                                SeedKey {
                                    epoch,
                                    ticket,
                                    label: label.raw_at(1)
                                },
                                proof.source_label
                            ));
                            let Some(CleanupOwner::Channel(candidate)) = resident.cleanup[0].take()
                            else {
                                unreachable!()
                            };
                            let record = self
                                .records
                                .get_mut(index)
                                .expect("the exact initial record");
                            assert!(record.set_initial_epoch(ticket, epoch));
                            let mut origin = record.initial_origin(ticket).expect("initial source");
                            origin.flags |= posix_process_service::initial_origin::STAGE_COMMITTED;
                            assert!(record.set_initial_origin(ticket, origin));
                            record.active_exec = Some(candidate);
                            record.active_guard_label = proof.source_label;
                        }
                    }
                }
                // The proof is a byte view; no owned cap is created here.
                unsafe {
                    SHARED.main_raw(0);
                }
                self.replacer.phase = Phase::Finish;
            }
            Phase::CheckRaw => {
                let raw = SHARED.raw();
                let kind = if matches!(unsafe { SHARED.command() }, Command::InitialProof { .. }) {
                    abi::INFO_CHANNEL
                } else {
                    abi::INFO_PROCESS_STATE
                };
                match raw_info(raw, kind) {
                    Ok(_) => self.replacer.phase = Phase::CloseRaw,
                    Err(abi::Error::BadHandle) => {
                        // Genuine full-generation NotFound means consumed,
                        // never Init ACK. Other errors keep resident custody.
                        unsafe {
                            SHARED.main_raw(0);
                        }
                        self.replacer.phase = Phase::Finish;
                    }
                    Err(_) => {}
                }
            }
            Phase::CloseRaw => {
                if raw_close(SHARED.raw()).is_ok() {
                    unsafe {
                        SHARED.main_raw(0);
                    }
                    self.replacer.phase = Phase::Finish;
                }
            }
            Phase::CheckFiles => {
                let raw = SHARED.raw();
                match raw_info(raw, abi::INFO_CHANNEL) {
                    Ok(values) if values[4] == 0 => {
                        self.replacer.result = Some(Handle::<Channel>::from_raw(abi::Handle(raw)));
                        unsafe {
                            SHARED.main_raw(0);
                        }
                        self.replacer.phase = Phase::InstallFiles;
                    }
                    Ok(_) => self.replacer.phase = Phase::CloseRaw,
                    Err(_) => {}
                }
            }
            Phase::InstallFiles => {
                let Some(new) = self.replacer.result.take() else {
                    return;
                };
                self.replacer.result = self.files.replace(new);
                self.replacer.refresh = false;
                self.replacer.phase = Phase::CloseFiles;
            }
            Phase::CloseFiles => {
                if self.replacer.result.is_some() {
                    crate::close_owned(&mut self.replacer.result);
                    return;
                }
                self.replacer.phase = Phase::Finish;
            }
            Phase::Finish => {
                let serial = SHARED.serial();
                let outcome = SHARED.outcome(serial);
                match unsafe { SHARED.command() } {
                    Command::Replace {
                        index,
                        label,
                        image,
                        ticket,
                    } => {
                        let index = usize::from(index);
                        if self.replacing[index]
                            .as_ref()
                            .and_then(Work::replacing)
                            .is_some_and(|work| {
                                work.key.label.raw_at(work.key.image) == label
                                    && work.key.image == image
                                    && work.ticket == ticket
                                    && work.serial == serial
                                    && !work.old.cleanup_requested()
                            })
                        {
                            if outcome
                                .is_some_and(|outcome| outcome.acknowledged && outcome.status == 0)
                            {
                                self.finish_replace(index);
                            } else {
                                self.replace_queue.push(index);
                            }
                        }
                    }
                    Command::Refresh => {}
                    Command::Idle => {}
                    Command::InitialProof { .. } => {}
                }
                // SAFETY: actual parked completion or genuine Ended is
                // retained, and all slots/raw owners are settled above.
                unsafe {
                    SHARED.reset(serial);
                    // A successful refresh has finished its replay. A
                    // later reconnect must burn a fresh nonwrapping serial.
                    if serial != 0 && !self.replacer.refresh {
                        SHARED.stage(Command::Idle, serial);
                    }
                }
                self.replacer.cursor = 0;
                self.replacer.phase = if self.replacer.ended {
                    Phase::Retire
                } else {
                    Phase::Idle
                };
            }
            Phase::Retire => {
                let Some(retired) = self.replacer.retired.as_ref() else {
                    return;
                };
                if raw_close(retired.raw().0).is_ok() {
                    self.replacer
                        .retired
                        .take()
                        .expect("a retired owner")
                        .into_raw();
                    self.replacer.phase = Phase::Create;
                }
            }
            Phase::Create => {
                if self.replacer.retired.is_some() || self.replacer.worker.is_some() {
                    return;
                }
                let Some(exit) = self.step.as_ref() else {
                    return;
                };
                if let Ok(worker) = replace::create(&make::own(), self.level, exit) {
                    self.replacer.worker = Some(worker);
                    self.replacer.phase = Phase::Start;
                }
            }
            Phase::Start => {
                let Some(worker) = self.replacer.worker.as_ref() else {
                    return;
                };
                replace::publish_worker(worker.raw().0);
                if sys::thread_start(worker).is_ok() {
                    self.replacer.ended = false;
                    self.replacer.bootstrap = true;
                    self.replacer.phase = Phase::Idle;
                }
            }
        }
    }
}

const _: [(); 24] = [(); core::mem::size_of::<Command>()];
const _: [(); 56] = [(); core::mem::size_of::<Shared>()];
