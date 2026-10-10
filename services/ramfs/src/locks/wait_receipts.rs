// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Paid WAIT custody is independent of Control jobs and sleeping registrations.
//! Genuine Places/label authentication precedes every call from the service.

use super::{
    actor::{Error, Response},
    request::{Captured, reply},
};
use crate::storage::{LockAnchor, Pin, Storage};
use proto_fs::{WaitKey, WaitPhase, WaitReply, WaitStart};

pub const SHARE: usize = proto_fs::WAIT_KEY_PLACES;
pub const PLACES: usize = crate::places::COUNT * SHARE;
const PORTION: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Id {
    slot: u16,
    owner: u64,
    key: WaitKey,
}
impl Id {
    pub fn new(place: usize, owner: u64, key: WaitKey) -> Result<Self, u32> {
        Ok(Self {
            slot: Queue::slot(place, owner, key)? as u16,
            owner,
            key,
        })
    }
    pub fn slot(self) -> u16 {
        self.slot
    }
    pub fn owner(self) -> u64 {
        self.owner
    }
    pub fn key(self) -> WaitKey {
        self.key
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Ready,
    Active,
    Sleeping,
    Complete,
}
struct Job {
    owner: u64,
    wire: WaitStart,
    captured: Captured,
    anchor: LockAnchor,
    phase: Phase,
    result: WaitReply,
    cancel_requested: bool,
    armed: bool,
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
#[derive(Clone, Copy)]
struct Mark {
    owner: u64,
    generation: u64,
}
impl Mark {
    const EMPTY: Self = Self {
        owner: 0,
        generation: 0,
    };
}

pub struct Queue {
    jobs: [Option<Job>; PLACES],
    marks: [Mark; PLACES],
    cursor: u16,
    active: Option<Id>,
    work: u16,
    held: u16,
}
impl Queue {
    /// # Safety
    /// Destination exclusively owns aligned writable uninitialized Self storage.
    pub unsafe fn initialize_at(destination: *mut Self) {
        // SAFETY: exclusively owned fields and cells are initialized in place.
        unsafe {
            let jobs = core::ptr::addr_of_mut!((*destination).jobs).cast::<Option<Job>>();
            let marks = core::ptr::addr_of_mut!((*destination).marks).cast::<Mark>();
            for index in 0..PLACES {
                jobs.add(index).write(None);
                marks.add(index).write(Mark::EMPTY);
            }
            core::ptr::addr_of_mut!((*destination).cursor).write(0);
            core::ptr::addr_of_mut!((*destination).active).write(None);
            core::ptr::addr_of_mut!((*destination).work).write(0);
            core::ptr::addr_of_mut!((*destination).held).write(0);
        }
    }
    fn slot(place: usize, owner: u64, key: WaitKey) -> Result<usize, u32> {
        if place >= crate::places::COUNT || owner == 0 {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        Ok(place * SHARE + key.validate()?)
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
    pub fn find(&self, slot: u16, owner: u64, key: WaitKey) -> Result<Id, u32> {
        let id = Id { slot, owner, key };
        self.job(id)?;
        Ok(id)
    }
    pub fn occupied(&self, place: usize, owner: u64, key_slot: u32) -> Result<Option<Id>, u32> {
        let slot = Self::slot(
            place,
            owner,
            WaitKey {
                slot: key_slot,
                generation: 1,
            },
        )?;
        match &self.jobs[slot] {
            Some(job) if job.owner == owner => Ok(Some(job.id(slot))),
            Some(_) => Err(proto_fs::OPEN_RETIRED),
            None => Ok(None),
        }
    }
    pub fn retains(&self, place: usize, owner: u64) -> bool {
        assert!(place < crate::places::COUNT);
        self.jobs[place * SHARE..(place + 1) * SHARE]
            .iter()
            .flatten()
            .any(|job| job.owner == owner)
    }
    pub fn is_retired(&self, place: usize, owner: u64, key: WaitKey) -> Result<bool, u32> {
        let mark = &self.marks[Self::slot(place, owner, key)?];
        Ok(mark.owner == owner && key.generation <= mark.generation)
    }
    /// Fence an absent late Start/Arm. Never retire an occupied generation here.
    pub fn retire(&mut self, place: usize, owner: u64, key: WaitKey) -> Result<(), u32> {
        let slot = Self::slot(place, owner, key)?;
        if self.jobs[slot].is_some() {
            return Err(proto_fs::JOBS_FULL);
        }
        let mark = &mut self.marks[slot];
        if mark.owner == owner {
            mark.generation = mark.generation.max(key.generation);
        } else {
            *mark = Mark {
                owner,
                generation: key.generation,
            };
        }
        Ok(())
    }
    pub fn same_start(&self, id: Id, wire: WaitStart) -> Result<(), u32> {
        wire.validate().map_err(|e| e.code())?;
        if self.job(id)?.wire != wire {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        Ok(())
    }
    pub fn admit(
        &mut self,
        place: usize,
        owner: u64,
        wire: WaitStart,
        captured: Captured,
        storage: &mut Storage<'_>,
    ) -> Result<Id, u32> {
        wire.validate().map_err(|e| e.code())?;
        let slot = Self::slot(place, owner, wire.key)?;
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
        if self.is_retired(place, owner, wire.key)? {
            return Err(proto_fs::OPEN_RETIRED);
        }
        if !matches!(
            captured.request.command,
            super::actor::Command::Set(Some(_))
        ) || captured.unlocked_query
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let anchor = storage
            .lock_anchor(captured.root)
            .map_err(|_| proto_fs::NO_LOCKS)?;
        if storage.pin(captured.request.inode, Pin::Lock).is_err() {
            storage
                .release_lock_anchor(anchor)
                .expect("unadmitted WAIT payer");
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let job = Job {
            owner,
            wire,
            captured,
            anchor,
            phase: Phase::Ready,
            result: WaitReply {
                phase: WaitPhase::Queued,
                result: 0,
            },
            cancel_requested: false,
            armed: false,
        };
        let id = job.id(slot);
        self.jobs[slot] = Some(job);
        self.work += 1;
        self.held += 1;
        Ok(id)
    }
    pub fn snapshot(&self, id: Id) -> Result<(Captured, Phase, bool), u32> {
        let job = self.job(id)?;
        Ok((job.captured, job.phase, job.cancel_requested))
    }
    pub fn query(&self, id: Id) -> Result<WaitReply, u32> {
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
    pub fn next_ready(&mut self) -> Option<Id> {
        if self.active.is_some() {
            return None;
        }
        for _ in 0..PORTION {
            let slot = self.cursor as usize;
            self.cursor = ((slot + 1) % PLACES) as u16;
            if let Some(job) = &self.jobs[slot]
                && job.phase == Phase::Ready
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
        if job.phase != Phase::Ready {
            return Err(proto_fs::OPEN_RETIRED);
        }
        job.phase = Phase::Active;
        self.active = Some(id);
        Ok(())
    }
    /// Retry an internal actor cancellation without recapturing the seek origin.
    /// An explicit client cancellation always keeps its terminal cancellation path.
    pub fn retry_active(&mut self) -> Result<bool, u32> {
        let id = self.active.ok_or(proto_fs::INVALID_ARGUMENT)?;
        let job = self.job_mut(id)?;
        if job.cancel_requested {
            return Ok(false);
        }
        assert_eq!(job.phase, Phase::Active);
        job.phase = Phase::Ready;
        job.result = WaitReply {
            phase: WaitPhase::Queued,
            result: 0,
        };
        self.active = None;
        Ok(true)
    }
    /// Park a conflict without custody loss; the registration owns notification.
    pub fn sleep(&mut self, id: Id, armed: bool) -> Result<(), u32> {
        let job = self.job_mut(id)?;
        if !matches!(job.phase, Phase::Ready | Phase::Active) || job.cancel_requested {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let active = job.phase == Phase::Active;
        job.armed |= armed;
        job.phase = Phase::Sleeping;
        job.result = WaitReply {
            phase: if job.armed {
                WaitPhase::Sleeping
            } else {
                WaitPhase::NeedsArm
            },
            result: 0,
        };
        if active {
            self.active = None;
        }
        self.work -= 1;
        Ok(())
    }
    pub fn armed(&mut self, id: Id) -> Result<(), u32> {
        let job = self.job_mut(id)?;
        if job.phase != Phase::Sleeping {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        job.armed = true;
        job.result.phase = WaitPhase::Sleeping;
        Ok(())
    }
    pub fn ready(&mut self, id: Id) -> Result<(), u32> {
        let job = self.job_mut(id)?;
        if job.phase != Phase::Sleeping {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        job.phase = Phase::Ready;
        job.result = WaitReply {
            phase: WaitPhase::Queued,
            result: 0,
        };
        self.work += 1;
        Ok(())
    }
    pub fn request_cancel(&mut self, id: Id) -> Result<bool, u32> {
        match self.job(id)?.phase {
            Phase::Complete => Ok(false),
            Phase::Active => {
                self.job_mut(id)?.cancel_requested = true;
                Ok(true)
            }
            Phase::Ready | Phase::Sleeping => {
                self.complete(
                    id,
                    WaitReply {
                        phase: WaitPhase::Complete,
                        result: proto_fs::LOCK_CANCELLED,
                    },
                )?;
                Ok(false)
            }
        }
    }
    /// Publish only a terminal SET outcome. First publication wins.
    pub fn complete(&mut self, id: Id, result: WaitReply) -> Result<(), u32> {
        result.validate().map_err(|e| e.code())?;
        if result.phase != WaitPhase::Complete
            || matches!(
                result.result,
                proto_fs::LOCK_CONFLICT
                    | proto_fs::RESOLVING
                    | proto_fs::AUTHENTICATING
                    | proto_fs::JOBS_FULL
            )
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let job = self.job_mut(id)?;
        if job.phase == Phase::Complete {
            return Ok(());
        }
        let work = matches!(job.phase, Phase::Ready | Phase::Active);
        let active = job.phase == Phase::Active;
        job.phase = Phase::Complete;
        job.result = result;
        if work {
            self.work -= 1;
        }
        if active {
            self.active = None;
        }
        Ok(())
    }
    pub fn complete_active(&mut self, result: Result<Response, Error>) -> Result<Id, u32> {
        let id = self.active.ok_or(proto_fs::INVALID_ARGUMENT)?;
        let result = reply(result);
        if result.blocker.is_some() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        self.complete(
            id,
            WaitReply {
                phase: WaitPhase::Complete,
                result: result.result,
            },
        )?;
        Ok(id)
    }
    /// Durable canonical receipt acknowledgement, never an active discard.
    pub fn release(&mut self, id: Id, storage: &mut Storage<'_>) -> Result<(), u32> {
        if self.job(id)?.phase != Phase::Complete {
            return Err(proto_fs::JOBS_FULL);
        }
        let job = self.jobs[id.slot as usize]
            .take()
            .expect("exact WAIT release");
        self.held -= 1;
        let mark = &mut self.marks[id.slot as usize];
        *mark = Mark {
            owner: id.owner,
            generation: if mark.owner == id.owner {
                mark.generation.max(id.key.generation)
            } else {
                id.key.generation
            },
        };
        storage
            .unpin(job.captured.request.inode, Pin::Lock)
            .expect("exact WAIT inode");
        storage
            .release_lock_anchor(job.anchor)
            .expect("exact WAIT payer");
        Ok(())
    }
}

#[cfg(test)]
#[path = "wait_receipts_tests.rs"]
mod tests;
