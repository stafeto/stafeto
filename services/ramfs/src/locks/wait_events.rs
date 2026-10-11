// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact inode wake masks advance independently of optional proof snapshots.

use super::{
    actor::{Command, ReadState, Reader},
    request::Captured,
    service::LockService,
};
use super::{
    wait_receipts::{Phase as ReceiptPhase, Queue},
    waiters::{CAPACITY, Phase, Pool, RegistrationToken},
};
use crate::storage::{NODES, Storage, Token};

struct Recheck {
    registration: RegistrationToken,
    captured: Captured,
    reader: Reader,
}
fn sleeping(queue: &Queue, pool: &Pool, token: RegistrationToken) -> Option<Captured> {
    let (input, phase) = pool.snapshot(token).ok()?;
    let (captured, receipt_phase, cancelling) = queue.snapshot(token.receipt()).ok()?;
    if phase != Phase::Sleeping
        || receipt_phase != ReceiptPhase::Sleeping
        || cancelling
        || input.receipt != token.receipt()
        || input.root != captured.root
        || input.inode != captured.request.inode
        || input.range != captured.request.range
        || !matches!(captured.request.command, Command::Set(Some(kind)) if kind == input.kind)
    {
        return None;
    }
    Some(captured)
}

#[derive(Clone, Copy)]
struct Entry {
    generation: u64,
    registrations: u16,
}
impl Entry {
    const EMPTY: Self = Self {
        generation: 0,
        registrations: 0,
    };
}

pub struct Events {
    inodes: [Entry; NODES],
    registrations: [Option<(RegistrationToken, Token)>; CAPACITY],
    occupied: u16,
    pending: u16,
    rechecks: u16,
    recheck_next: u8,
    recheck: Option<Recheck>,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Progress {
    pub visited: usize,
    pub readied: usize,
}

impl Events {
    /// # Safety
    /// Exclusive aligned writable uninitialized storage for Self.
    pub unsafe fn initialize_at(destination: *mut Self) {
        // SAFETY: all cells and fields are initialized in the exclusive allocation.
        unsafe {
            let inodes = core::ptr::addr_of_mut!((*destination).inodes).cast::<Entry>();
            for i in 0..NODES {
                inodes.add(i).write(Entry::EMPTY);
            }
            let registrations = core::ptr::addr_of_mut!((*destination).registrations)
                .cast::<Option<(RegistrationToken, Token)>>();
            for i in 0..CAPACITY {
                registrations.add(i).write(None);
            }
            core::ptr::addr_of_mut!((*destination).occupied).write(0);
            core::ptr::addr_of_mut!((*destination).pending).write(0);
            core::ptr::addr_of_mut!((*destination).rechecks).write(0);
            core::ptr::addr_of_mut!((*destination).recheck_next).write(0);
            core::ptr::addr_of_mut!((*destination).recheck).write(None);
        }
    }
    pub fn attach(&mut self, pool: &Pool, registration: RegistrationToken) -> Result<(), u32> {
        let (input, _) = pool.snapshot(registration)?;
        if let Some((previous, _)) = self.registrations[registration.slot()]
            && previous != registration
            && pool.snapshot(previous).is_err()
        {
            self.detach(previous)?;
        }
        let old = &mut self.registrations[registration.slot()];
        if let Some(previous) = *old {
            return if previous == (registration, input.inode) {
                Ok(())
            } else {
                Err(proto_fs::OPEN_RETIRED)
            };
        }
        let entry = self
            .inodes
            .get_mut(usize::from(input.inode.slot))
            .filter(|entry| entry.registrations == 0 || entry.generation == input.inode.generation)
            .ok_or(proto_fs::INVALID_ARGUMENT)?;
        entry.generation = input.inode.generation;
        entry.registrations |= 1 << registration.slot();
        *old = Some((registration, input.inode));
        self.occupied |= 1 << registration.slot();
        Ok(())
    }
    pub fn detach(&mut self, registration: RegistrationToken) -> Result<(), u32> {
        let cell = &mut self.registrations[registration.slot()];
        let Some((current, inode)) = *cell else {
            return Ok(());
        };
        if current != registration {
            return Err(proto_fs::OPEN_RETIRED);
        }
        self.inodes[usize::from(inode.slot)].registrations &= !(1 << registration.slot());
        *cell = None;
        self.occupied &= !(1 << registration.slot());
        self.pending &= !(1 << registration.slot());
        self.rechecks &= !(1 << registration.slot());
        if self
            .recheck
            .as_ref()
            .is_some_and(|r| r.registration == registration)
        {
            self.recheck = None;
        }
        Ok(())
    }
    pub fn changed(&mut self, inode: Token) {
        if let Some(entry) = self.inodes.get(usize::from(inode.slot))
            && entry.generation == inode.generation
        {
            self.pending |= entry.registrations;
        }
    }
    /// Logical PID removal and the private life timer request real read-only checks.
    pub fn poll(&mut self) {
        // Read-only life/eligibility revalidation must not manufacture a new phase.
        self.rechecks |= self.occupied;
    }

    pub fn recheck_pending(&self) -> bool {
        self.rechecks != 0 || self.recheck.is_some()
    }

    fn ready_exact(
        queue: &mut Queue,
        pool: &mut Pool,
        token: RegistrationToken,
    ) -> Result<usize, u32> {
        if sleeping(queue, pool, token).is_none() {
            return Ok(0);
        }
        pool.ready(token)?;
        queue.ready(token.receipt())?;
        Ok(1)
    }
    /// One exact registration barrier and at most seven real Reader visits.
    /// Source checks use the actual session/FD/PID/OFD state supplied by the service.
    pub fn recheck_part(
        &mut self,
        queue: &mut Queue,
        pool: &mut Pool,
        locks: &LockService,
        storage: &Storage<'_>,
        mut source_live: impl FnMut(super::wait_receipts::Id, Captured) -> bool,
        life: (impl FnMut(u32) -> bool, impl FnMut(Token) -> bool),
    ) -> Result<Progress, u32> {
        let (pid_live, ofd_live) = life;
        if let Some(mut active) = self.recheck.take() {
            let mut progress = Progress {
                visited: 1,
                readied: 0,
            };
            let token = active.registration;
            if sleeping(queue, pool, token) != Some(active.captured) {
                return Ok(progress);
            }
            if !source_live(token.receipt(), active.captured) {
                progress.readied = Self::ready_exact(queue, pool, token)?;
                return Ok(progress);
            }
            let read = locks.reader_part_limit(storage, &mut active.reader, 7, pid_live, ofd_live);
            progress.visited += read.visited;
            if read.blockers.iter().any(Option::is_some) {
                // This proves only blocked WAIT. Proof still validates its own edges,
                // watched inode revisions, exact registrations and genuine owner life.
                return Ok(progress);
            }
            match read.state {
                ReadState::More => self.recheck = Some(active),
                ReadState::Done | ReadState::Invalidated => {
                    progress.readied = Self::ready_exact(queue, pool, token)?;
                }
            }
            return Ok(progress);
        }
        let rotated = self.rechecks.rotate_right(u32::from(self.recheck_next));
        if rotated == 0 {
            return Ok(Progress::default());
        }
        let slot = (rotated.trailing_zeros() as usize + usize::from(self.recheck_next)) % CAPACITY;
        self.recheck_next = ((slot + 1) % CAPACITY) as u8;
        self.rechecks &= !(1 << slot);
        let mut progress = Progress {
            visited: 1,
            readied: 0,
        };
        let Some((token, _)) = self.registrations[slot] else {
            return Ok(progress);
        };
        let Some(captured) = sleeping(queue, pool, token) else {
            return Ok(progress);
        };
        if !source_live(token.receipt(), captured) {
            progress.readied = Self::ready_exact(queue, pool, token)?;
            return Ok(progress);
        }
        match locks.reader(storage, captured.request) {
            Ok(Some(reader)) => {
                self.recheck = Some(Recheck {
                    registration: token,
                    captured,
                    reader,
                })
            }
            // Optional saturated snapshots and real invalidation use the ordinary
            // Actor admission/source checks, without any new canonical error.
            Ok(None) | Err(_) => progress.readied = Self::ready_exact(queue, pool, token)?,
        }
        Ok(progress)
    }
    pub fn pending(&self) -> bool {
        self.pending != 0
    }
    pub fn part(&mut self, queue: &mut Queue, pool: &mut Pool) -> Result<Progress, u32> {
        let mut progress = Progress::default();
        while self.pending != 0 && progress.visited < 8 {
            let slot = self.pending.trailing_zeros() as usize;
            self.pending &= !(1 << slot);
            progress.visited += 1;
            let Some((registration, inode)) = self.registrations[slot] else {
                continue;
            };
            let (input, phase) = match pool.snapshot(registration) {
                Ok(snapshot) => snapshot,
                Err(proto_fs::OPEN_RETIRED) => {
                    self.detach(registration)?;
                    continue;
                }
                Err(code) => return Err(code),
            };
            if input.inode != inode {
                return Err(proto_fs::OPEN_RETIRED);
            }
            if phase == Phase::Sleeping
                && queue.snapshot(registration.receipt())?.1 == ReceiptPhase::Sleeping
            {
                pool.ready(registration)?;
                queue.ready(registration.receipt())?;
                progress.readied += 1;
            }
        }
        Ok(progress)
    }
}

#[cfg(test)]
#[path = "wait_events_tests.rs"]
mod tests;

const _: () = assert!(core::mem::size_of::<Recheck>() < 1024);
