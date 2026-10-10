// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact inode wake masks advance independently of optional proof snapshots.

use super::{
    wait_receipts::{Phase as ReceiptPhase, Queue},
    waiters::{CAPACITY, Phase, Pool, RegistrationToken},
};
use crate::storage::{NODES, Token};

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
        Ok(())
    }
    pub fn changed(&mut self, inode: Token) {
        if let Some(entry) = self.inodes.get(usize::from(inode.slot))
            && entry.generation == inode.generation
        {
            self.pending |= entry.registrations;
        }
    }
    /// Logical PID removal and the private life timer can affect several inodes.
    pub fn poll(&mut self) {
        self.pending |= self.occupied;
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
