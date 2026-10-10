// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Each prepaid genuine session retains sixteen exact lock outcomes and debts.

use super::{
    actor::{Error, Response},
    request::{Captured, reply},
};
use crate::storage::{LockAnchor, Pin, Storage};
use proto_fs::{LockPhase, LockReply, LockStart, OpenKey};

pub const SHARE: usize = 16;
pub const PLACES: usize = crate::places::COUNT * SHARE;
const PORTION: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Id {
    slot: u16,
    owner: u64,
    key: OpenKey,
}
impl Id {
    pub fn slot(self) -> u16 {
        self.slot
    }
    pub fn owner(self) -> u64 {
        self.owner
    }
    pub fn key(self) -> OpenKey {
        self.key
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Queued,
    Active,
    Complete,
}
struct Job {
    owner: u64,
    wire: LockStart,
    captured: Captured,
    anchor: Option<LockAnchor>,
    phase: Phase,
    result: LockReply,
    releasing: bool,
}
impl Job {
    fn id(&self, slot: usize) -> Id {
        Id {
            slot: slot as u16,
            owner: self.owner,
            key: self.wire.key,
        }
    }
}

pub struct Queue {
    jobs: [Option<Job>; PLACES],
    cursor: u16,
    cleanup: u16,
    active: Option<Id>,
    work: u16,
    held: u16,
}
impl Queue {
    pub const fn new() -> Self {
        Self {
            jobs: [const { None }; PLACES],
            cursor: 0,
            cleanup: 0,
            active: None,
            work: 0,
            held: 0,
        }
    }
    ///
    /// # Safety
    /// `destination` exclusively owns aligned writable uninitialized Self storage.
    pub unsafe fn initialize_at(destination: *mut Self) {
        // SAFETY: every field is written directly into the exclusive allocation.
        unsafe {
            let jobs = core::ptr::addr_of_mut!((*destination).jobs).cast::<Option<Job>>();
            for index in 0..PLACES {
                jobs.add(index).write(None);
            }
            core::ptr::addr_of_mut!((*destination).cursor).write(0);
            core::ptr::addr_of_mut!((*destination).cleanup).write(0);
            core::ptr::addr_of_mut!((*destination).active).write(None);
            core::ptr::addr_of_mut!((*destination).work).write(0);
            core::ptr::addr_of_mut!((*destination).held).write(0);
        }
    }
    fn job(&self, id: Id) -> Result<&Job, u32> {
        self.jobs
            .get(id.slot as usize)
            .and_then(Option::as_ref)
            .filter(|job| job.owner == id.owner && job.wire.key == id.key)
            .ok_or(proto_fs::OPEN_RETIRED)
    }
    fn job_mut(&mut self, id: Id) -> Result<&mut Job, u32> {
        self.jobs
            .get_mut(id.slot as usize)
            .and_then(Option::as_mut)
            .filter(|job| job.owner == id.owner && job.wire.key == id.key)
            .ok_or(proto_fs::OPEN_RETIRED)
    }
    /// A session's direct index is authenticated by both its complete label and key.
    pub fn find(&self, slot: u16, owner: u64, key: OpenKey) -> Result<Id, u32> {
        let id = Id { slot, owner, key };
        self.job(id)?;
        Ok(id)
    }
    /// A Control place has one family and one generation until its custody ends.
    pub fn occupied(&self, place: usize, owner: u64, key_slot: u32) -> Result<Option<Id>, u32> {
        if place >= crate::places::COUNT || !(32..48).contains(&key_slot) || owner == 0 {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let slot = place * SHARE + (key_slot - 32) as usize;
        match &self.jobs[slot] {
            Some(job) if job.owner == owner => Ok(Some(job.id(slot))),
            Some(_) => Err(proto_fs::OPEN_RETIRED),
            None => Ok(None),
        }
    }
    /// Sixteen prepaid cells retain the genuine session label during departure.
    pub fn retains(&self, place: usize, owner: u64) -> bool {
        assert!(place < crate::places::COUNT);
        self.jobs[place * SHARE..(place + 1) * SHARE]
            .iter()
            .flatten()
            .any(|job| job.owner == owner)
    }
    /// Mark one half of a departed session; active preparation cancels separately.
    pub fn depart(&mut self, place: usize, owner: u64, first: usize) -> bool {
        assert!(place < crate::places::COUNT && matches!(first, 0 | 8));
        let mut cancel_active = false;
        for local in first..first + PORTION {
            let slot = place * SHARE + local;
            if let Some(job) = &self.jobs[slot]
                && job.owner == owner
            {
                let id = job.id(slot);
                cancel_active |= self.request_release(id).expect("exact departed lock job");
            }
        }
        cancel_active
    }
    pub fn same_start(&self, id: Id, mut wire: LockStart) -> Result<(), u32> {
        wire.validate().map_err(|error| error.code())?;
        wire.pid = 0;
        if self.job(id)?.wire != wire {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        Ok(())
    }
    /// The caller checks the session's direct Control index and watermark first.
    pub fn admit(
        &mut self,
        place: usize,
        owner: u64,
        mut wire: LockStart,
        captured: Captured,
        storage: &mut Storage<'_>,
    ) -> Result<Id, u32> {
        wire.validate().map_err(|error| error.code())?;
        if owner == 0 {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        if place >= crate::places::COUNT {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let slot = place * SHARE + (wire.key.slot - 32) as usize;
        if let Some(previous) = &self.jobs[slot] {
            let id = previous.id(slot);
            if previous.owner == owner && previous.wire.key == wire.key {
                self.same_start(id, wire)?;
                return Ok(id);
            }
            return Err(
                if previous.owner != owner || wire.key.generation <= previous.wire.key.generation {
                    proto_fs::OPEN_RETIRED
                } else {
                    proto_fs::JOBS_FULL
                },
            );
        }
        let anchor = if matches!(
            captured.request.command,
            super::actor::Command::Set(Some(_))
        ) {
            Some(
                storage
                    .lock_anchor(captured.root)
                    .map_err(|_| proto_fs::NO_LOCKS)?,
            )
        } else {
            None
        };
        if storage.pin(captured.request.inode, Pin::Lock).is_err() {
            if let Some(anchor) = anchor {
                storage
                    .release_lock_anchor(anchor)
                    .expect("unadmitted job payer");
            }
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        wire.pid = 0;
        let job = Job {
            owner,
            wire,
            captured,
            anchor,
            phase: Phase::Queued,
            result: LockReply {
                phase: LockPhase::Pending,
                result: 0,
                blocker: None,
            },
            releasing: false,
        };
        let id = job.id(slot);
        assert!(self.jobs[slot].is_none());
        self.jobs[slot] = Some(job);
        self.work += 1;
        self.held += 1;
        Ok(id)
    }
    pub fn snapshot(&self, id: Id) -> Result<(Captured, Phase, bool), u32> {
        let job = self.job(id)?;
        Ok((job.captured, job.phase, job.releasing))
    }
    pub fn query(&self, id: Id) -> Result<LockReply, u32> {
        Ok(self.job(id)?.result)
    }
    pub fn active(&self) -> Option<Id> {
        self.active
    }
    pub fn retained(&self) -> usize {
        usize::from(self.held)
    }
    pub fn has_work(&self) -> bool {
        self.work != 0
    }
    /// One bounded service turn gives every occupied place a chance to start.
    pub fn next_ready(&mut self) -> Option<Id> {
        if self.active.is_some() {
            return None;
        }
        for _ in 0..PORTION {
            let slot = self.cursor as usize;
            self.cursor = ((slot + 1) % PLACES) as u16;
            if let Some(job) = &self.jobs[slot]
                && job.phase == Phase::Queued
                && !job.releasing
            {
                return Some(job.id(slot));
            }
        }
        None
    }
    pub fn activate(&mut self, id: Id) -> Result<(), u32> {
        if self.active.is_some() {
            return Err(proto_fs::RESOLVING);
        }
        let job = self.job_mut(id)?;
        if job.phase != Phase::Queued || job.releasing {
            return Err(proto_fs::OPEN_RETIRED);
        }
        job.phase = Phase::Active;
        self.active = Some(id);
        Ok(())
    }
    pub fn complete_queued(&mut self, id: Id, result: LockReply) -> Result<(), u32> {
        let job = self.job_mut(id)?;
        if job.phase != Phase::Queued || result.phase != LockPhase::Complete {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        job.phase = Phase::Complete;
        job.result = result;
        if !job.releasing {
            self.work -= 1;
        }
        Ok(())
    }
    pub fn complete_active(&mut self, result: Result<Response, Error>) -> Result<Id, u32> {
        let id = self.active.take().ok_or(proto_fs::INVALID_ARGUMENT)?;
        let job = self.job_mut(id)?;
        assert_eq!(job.phase, Phase::Active);
        job.phase = Phase::Complete;
        job.result = reply(result);
        if !job.releasing {
            self.work -= 1;
        }
        Ok(id)
    }
    /// Active preparation retains its custody until its own cancelled completion.
    /// The returned flag asks the service to cancel its single active actor.
    pub fn request_release(&mut self, id: Id) -> Result<bool, u32> {
        let job = self.job_mut(id)?;
        let active = job.phase == Phase::Active;
        let added = !job.releasing && job.phase == Phase::Complete;
        job.releasing = true;
        if added {
            self.work += 1;
        }
        Ok(active)
    }
    pub fn release(&mut self, id: Id, storage: &mut Storage<'_>) -> Result<bool, u32> {
        if self.job(id)?.phase == Phase::Active {
            return Ok(false);
        }
        let job = self.jobs[id.slot as usize].take().expect("exact release");
        self.held -= 1;
        if job.phase != Phase::Complete || job.releasing {
            self.work -= 1;
        }
        storage
            .unpin(job.captured.request.inode, Pin::Lock)
            .expect("exact job inode");
        if let Some(anchor) = job.anchor {
            storage
                .release_lock_anchor(anchor)
                .expect("exact job payer");
        }
        Ok(true)
    }
    /// Cleanup of departed or cancelled clients also advances with no further RPC.
    pub fn cleanup_released(&mut self, storage: &mut Storage<'_>) -> usize {
        let mut released = 0;
        for _ in 0..PORTION {
            let slot = self.cleanup as usize;
            self.cleanup = ((slot + 1) % PLACES) as u16;
            let candidate = self.jobs[slot]
                .as_ref()
                .filter(|job| job.releasing && job.phase != Phase::Active)
                .map(|job| job.id(slot));
            if let Some(id) = candidate {
                assert!(self.release(id, storage).expect("cleanup exact job"));
                released += 1;
            }
        }
        released
    }
}
impl Default for Queue {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{Fds, Ram, storage::Root};
    use proto_fs::{DataDescription, LockCommand, LockKind, READ_ONLY};

    fn queue() -> std::boxed::Box<Queue> {
        let mut allocation = std::boxed::Box::<Queue>::new_uninit();
        // SAFETY: exclusive aligned allocation initialized field by field.
        unsafe {
            Queue::initialize_at(allocation.as_mut_ptr());
            allocation.assume_init()
        }
    }
    fn fixture(ram: &mut Ram<'_>) -> (LockStart, Captured) {
        let mut fds = Fds::default();
        let fd = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
        let (source, _) = ram.capture_description(&fds, fd).unwrap();
        let wire = LockStart {
            key: OpenKey {
                slot: 32,
                generation: 1,
            },
            description: DataDescription {
                packed: ram.marked_open(&fds, source).unwrap(),
                generation: source.description.generation,
            },
            command: LockCommand::GetOfd,
            kind: LockKind::Write,
            whence: 0,
            start: 3,
            length: -2,
            pid: 0,
        };
        let captured = ram.capture_lock(&fds, wire).unwrap();
        (wire, captured)
    }
    fn complete() -> LockReply {
        LockReply {
            phase: LockPhase::Complete,
            result: 0,
            blocker: None,
        }
    }

    #[test]
    fn direct_control_family_lookup_retains_complete_label_and_current_generation() {
        let mut ram = Ram::default();
        let (wire, captured) = fixture(&mut ram);
        let mut queue = queue();
        assert_eq!(queue.occupied(19, 41, 32), Ok(None));
        let id = queue
            .admit(19, 41, wire, captured, &mut ram.storage)
            .unwrap();
        assert_eq!(queue.occupied(19, 41, 32), Ok(Some(id)));
        assert_eq!(queue.occupied(19, 42, 32), Err(proto_fs::OPEN_RETIRED));
        assert_eq!(queue.occupied(19, 41, 31), Err(proto_fs::INVALID_ARGUMENT));
        assert_eq!(
            queue.occupied(crate::places::COUNT, 41, 32),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        assert!(queue.retains(19, 41));
        assert!(!queue.retains(19, 42));
        queue.release(id, &mut ram.storage).unwrap();
        let next = LockStart {
            key: OpenKey {
                generation: 2,
                ..wire.key
            },
            ..wire
        };
        let next = queue
            .admit(19, 41, next, captured, &mut ram.storage)
            .unwrap();
        assert_eq!(queue.occupied(19, 41, 32), Ok(Some(next)));
        assert_eq!(queue.query(id), Err(proto_fs::OPEN_RETIRED));
    }

    #[test]
    fn departure_marks_eight_exact_jobs_and_retains_active_custody() {
        let mut ram = Ram::default();
        let (wire, captured) = fixture(&mut ram);
        let mut queue = queue();
        let mut ids = std::vec::Vec::new();
        for local in 0..SHARE {
            let wire = LockStart {
                key: OpenKey {
                    slot: 32 + local as u32,
                    ..wire.key
                },
                ..wire
            };
            ids.push(
                queue
                    .admit(3, 41, wire, captured, &mut ram.storage)
                    .unwrap(),
            );
        }
        queue.activate(ids[3]).unwrap();
        assert!(queue.depart(3, 41, 0));
        for (local, id) in ids.iter().copied().enumerate() {
            assert_eq!(queue.snapshot(id).unwrap().2, local < 8);
        }
        assert!(!queue.depart(3, 42, 8));
        assert!(!queue.snapshot(ids[8]).unwrap().2);
        assert!(!queue.depart(3, 41, 8));
        for _ in 0..PLACES.div_ceil(PORTION) {
            queue.cleanup_released(&mut ram.storage);
        }
        assert!(queue.retains(3, 41));
        assert_eq!(queue.snapshot(ids[3]).unwrap().1, Phase::Active);
        queue.complete_active(Err(Error::Cancelled)).unwrap();
        for _ in 0..PLACES.div_ceil(PORTION) {
            queue.cleanup_released(&mut ram.storage);
        }
        assert!(!queue.retains(3, 41));
        assert!(!queue.has_work());
    }

    #[test]
    fn every_prepaid_session_keeps_sixteen_places_without_an_active_root_limit() {
        let mut ram = Ram::default();
        let (wire, captured) = fixture(&mut ram);
        let mut queue = queue();
        let mut ids = std::vec::Vec::new();
        for place in 0..crate::places::COUNT {
            let captured = Captured {
                root: Root {
                    id: place as u64 + 17,
                    generation: 1,
                },
                ..captured
            };
            for local in 0..SHARE {
                let wire = LockStart {
                    key: OpenKey {
                        slot: 32 + local as u32,
                        ..wire.key
                    },
                    ..wire
                };
                let id = queue
                    .admit(place, place as u64 + 1, wire, captured, &mut ram.storage)
                    .unwrap();
                assert_eq!(usize::from(id.slot()), place * SHARE + local);
                ids.push(id);
            }
        }
        assert_eq!(ids.len(), PLACES);
        assert_eq!(queue.retained(), PLACES);
        assert_eq!(
            ram.storage.node(captured.request.inode).unwrap().pins[Pin::Lock as usize],
            PLACES as u16
        );
        assert_eq!(
            queue.admit(crate::places::COUNT, 999, wire, captured, &mut ram.storage),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        for id in ids {
            assert_eq!(queue.release(id, &mut ram.storage), Ok(true));
        }
        assert!(!queue.has_work());
        assert_eq!(queue.retained(), 0);
        assert_eq!(
            ram.storage.node(captured.request.inode).unwrap().pins[Pin::Lock as usize],
            0
        );
    }
    #[test]
    fn session_generation_key_generation_and_exact_body_guard_replay() {
        let mut ram = Ram::default();
        let (wire, captured) = fixture(&mut ram);
        let mut queue = queue();
        let id = queue
            .admit(0, 41, wire, captured, &mut ram.storage)
            .unwrap();
        assert_eq!(
            queue.find(id.slot(), 42, wire.key),
            Err(proto_fs::OPEN_RETIRED)
        );
        assert_eq!(
            queue.find(
                id.slot(),
                41,
                OpenKey {
                    generation: 2,
                    ..wire.key
                }
            ),
            Err(proto_fs::OPEN_RETIRED)
        );
        assert_eq!(queue.same_start(id, wire), Ok(()));
        assert_eq!(
            queue.same_start(id, LockStart { length: -3, ..wire }),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        queue.release(id, &mut ram.storage).unwrap();
        let next = queue
            .admit(0, 42, wire, captured, &mut ram.storage)
            .unwrap();
        assert_eq!(next.slot(), id.slot());
        assert_eq!(queue.query(id), Err(proto_fs::OPEN_RETIRED));
        assert_eq!(
            queue.release(id, &mut ram.storage),
            Err(proto_fs::OPEN_RETIRED)
        );
        assert_eq!(queue.query(next).unwrap().phase, LockPhase::Pending);
    }
    #[test]
    fn pid_input_is_ignored_for_replays_of_process_owned_commands() {
        let mut ram = Ram::default();
        let (wire, captured) = fixture(&mut ram);
        let mut queue = queue();
        let wire = LockStart {
            command: LockCommand::GetPid,
            pid: 377,
            ..wire
        };
        let id = queue
            .admit(0, 41, wire, captured, &mut ram.storage)
            .unwrap();
        assert_eq!(
            queue.same_start(id, LockStart { pid: -881, ..wire }),
            Ok(())
        );
        assert_eq!(
            queue.same_start(
                id,
                LockStart {
                    command: LockCommand::GetOfd,
                    pid: 0,
                    ..wire
                }
            ),
            Err(proto_fs::INVALID_ARGUMENT)
        );
    }
    #[test]
    fn retained_results_sleep_until_release_and_cleanup_progresses_without_client() {
        let mut ram = Ram::default();
        let (wire, captured) = fixture(&mut ram);
        let mut queue = queue();
        let id = queue
            .admit(0, 41, wire, captured, &mut ram.storage)
            .unwrap();
        assert!(queue.has_work());
        assert_eq!(queue.next_ready(), Some(id));
        queue.complete_queued(id, complete()).unwrap();
        assert!(!queue.has_work());
        assert_eq!(queue.query(id), Ok(complete()));
        assert_eq!(queue.query(id), Ok(complete()));
        assert_eq!(queue.request_release(id), Ok(false));
        assert_eq!(queue.request_release(id), Ok(false));
        assert_eq!(queue.work, 1);
        let mut released = 0;
        for _ in 0..PLACES / PORTION {
            released += queue.cleanup_released(&mut ram.storage);
        }
        assert_eq!(released, 1);
        assert!(!queue.has_work());
        assert_eq!(queue.query(id), Err(proto_fs::OPEN_RETIRED));
    }
    #[test]
    fn active_cancel_holds_custody_until_exact_actor_completion() {
        let mut ram = Ram::default();
        let (wire, captured) = fixture(&mut ram);
        let mut queue = queue();
        let id = queue
            .admit(0, 41, wire, captured, &mut ram.storage)
            .unwrap();
        queue.activate(id).unwrap();
        assert_eq!(queue.next_ready(), None);
        assert_eq!(queue.request_release(id), Ok(true));
        assert_eq!(queue.release(id, &mut ram.storage), Ok(false));
        assert_eq!(queue.cleanup_released(&mut ram.storage), 0);
        assert_eq!(
            ram.storage.node(captured.request.inode).unwrap().pins[Pin::Lock as usize],
            1
        );
        assert_eq!(queue.complete_active(Err(Error::Cancelled)), Ok(id));
        assert_eq!(queue.query(id).unwrap().result, proto_fs::LOCK_CANCELLED);
        assert!(queue.has_work());
        for _ in 0..PLACES / PORTION {
            queue.cleanup_released(&mut ram.storage);
        }
        assert!(!queue.has_work());
        assert_eq!(
            ram.storage.node(captured.request.inode).unwrap().pins[Pin::Lock as usize],
            0
        );
    }
    #[test]
    fn ready_cursor_is_bounded_and_visits_last_session_without_client_polling() {
        let mut ram = Ram::default();
        let (wire, captured) = fixture(&mut ram);
        let mut queue = queue();
        let wire = LockStart {
            key: OpenKey {
                slot: 47,
                ..wire.key
            },
            ..wire
        };
        let last = queue
            .admit(
                crate::places::COUNT - 1,
                41,
                wire,
                captured,
                &mut ram.storage,
            )
            .unwrap();
        for _ in 0..usize::from(last.slot()) / PORTION {
            let before = queue.cursor;
            assert_eq!(queue.next_ready(), None);
            assert_eq!(queue.cursor, before + PORTION as u16);
            assert!(queue.cursor - before <= 8);
        }
        assert_eq!(queue.next_ready(), Some(last));
        queue.activate(last).unwrap();
        assert_eq!(queue.complete_active(Ok(Response::Blocker(None))), Ok(last));
        assert!(!queue.has_work());
    }
    #[test]
    fn full_existing_preparation_charge_preserves_get_and_unlock_queue_admission() {
        let mut ram = Ram::default();
        let (wire, captured) = fixture(&mut ram);
        let mut queue = queue();
        let mut charges = std::vec::Vec::new();
        for _ in 0..crate::storage::PREPARATION_SHARE {
            charges.push(ram.storage.charge_preparation(captured.root).unwrap());
        }
        for (index, command) in [LockCommand::GetOfd, LockCommand::SetOfd]
            .into_iter()
            .enumerate()
        {
            let wire = LockStart {
                key: OpenKey {
                    slot: 32 + index as u32,
                    ..wire.key
                },
                command,
                kind: if command.get() {
                    LockKind::Read
                } else {
                    LockKind::Unlock
                },
                ..wire
            };
            let mut captured = captured;
            captured.request.command = if command.get() {
                super::super::actor::Command::Get(super::super::Kind::Read)
            } else {
                super::super::actor::Command::Set(None)
            };
            let id = queue
                .admit(0, 41, wire, captured, &mut ram.storage)
                .unwrap();
            assert!(queue.job(id).unwrap().anchor.is_none());
            queue.release(id, &mut ram.storage).unwrap();
        }
        for charge in charges {
            ram.storage.release_preparation(charge);
        }
        assert_eq!(ram.storage.preparations_used(), 0);
    }
    #[test]
    fn permanent_queue_geometry_and_empty_initialization_are_exact() {
        let queue = queue();
        assert_eq!(queue.work, 0);
        assert_eq!(queue.retained(), 0);
        assert!(queue.jobs.iter().all(Option::is_none));
        let bytes = core::mem::size_of::<Queue>();
        std::println!(
            "Lock request Queue: {bytes} bytes, Job {} bytes",
            core::mem::size_of::<Job>()
        );
        assert!(bytes <= 320 * 4096);
    }

    #[test]
    fn setting_job_holds_exact_payer_until_release_and_returns_every_account() {
        let mut ram = Ram::default();
        let (wire, captured) = fixture(&mut ram);
        let mut queue = queue();
        let root = Root {
            id: 999,
            generation: 77,
        };
        let wire = LockStart {
            command: LockCommand::SetOfd,
            kind: LockKind::Read,
            ..wire
        };
        let mut captured = Captured { root, ..captured };
        captured.request.command =
            super::super::actor::Command::Set(Some(super::super::Kind::Read));
        let id = queue
            .admit(0, 41, wire, captured, &mut ram.storage)
            .unwrap();
        assert_eq!(queue.job(id).unwrap().anchor.as_ref().unwrap().root(), root);
        queue.complete_queued(id, complete()).unwrap();
        assert!(!queue.has_work());
        assert!(queue.job(id).unwrap().anchor.is_some());
        queue.release(id, &mut ram.storage).unwrap();
        let mut anchors = std::vec::Vec::new();
        // The fixture's real descriptor retains one existing Boot payer.
        for id in 0..crate::storage::ROOTS - 1 {
            anchors.push(
                ram.storage
                    .lock_anchor(Root {
                        id: 2000 + id as u64,
                        generation: 1,
                    })
                    .expect("all released job accounts available"),
            );
        }
        for anchor in anchors {
            ram.storage.release_lock_anchor(anchor).unwrap();
        }
    }

    #[test]
    fn duplicate_start_keeps_one_custody_and_the_original_terminal_result() {
        let mut ram = Ram::default();
        let (wire, captured) = fixture(&mut ram);
        let mut queue = queue();
        let id = queue
            .admit(0, 41, wire, captured, &mut ram.storage)
            .unwrap();
        assert_eq!(queue.admit(0, 41, wire, captured, &mut ram.storage), Ok(id));
        assert_eq!(
            ram.storage.node(captured.request.inode).unwrap().pins[Pin::Lock as usize],
            1
        );
        queue.complete_queued(id, complete()).unwrap();
        assert_eq!(queue.admit(0, 41, wire, captured, &mut ram.storage), Ok(id));
        assert_eq!(queue.query(id), Ok(complete()));
        assert!(!queue.has_work());
        assert_eq!(
            queue.admit(
                0,
                41,
                LockStart { start: 4, ..wire },
                captured,
                &mut ram.storage
            ),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        assert_eq!(
            queue.admit(
                0,
                41,
                LockStart {
                    key: OpenKey {
                        generation: 2,
                        ..wire.key
                    },
                    ..wire
                },
                captured,
                &mut ram.storage
            ),
            Err(proto_fs::JOBS_FULL)
        );
        assert_eq!(queue.query(id), Ok(complete()));
    }
}
