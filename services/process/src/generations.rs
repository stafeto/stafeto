// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The page of the credentials generations (proto_process::GENERATIONS_SIZE,
//! spec 2, 3.1): a u64 for each record index in one memory object, which
//! the service maps for writing at its own address and gives the services
//! that ask (Register) a read-only copy of. The service raises a record's
//! word with Release when it makes the record and before it answers a
//! change of its credentials; the second half holds the group and session
//! of each record (5f); a service that remembers the answer of Vouch reads
//! the word with Acquire, with no call, before each check. The words never
//! start over: a record made in a used index raises its word.

use core::sync::atomic::{AtomicU64, Ordering};
use proto_process::{GENERATIONS_SIZE, GROUPS_AT, RECORDS, groups_word};
use rt::abi::{Access, Error, Rights};
use rt::handle::{Handle, Memory, Process};
use rt::sys;

/// Where the service maps the page.
const BASE: usize = 0x42_0000_0000;
const PAGE: u64 = 4096;

pub struct Generations {
    object: Option<Handle<Memory>>,
}

impl Generations {
    pub const fn new() -> Self {
        Self { object: None }
    }

    /// Makes the object and maps it in `own`, the service's process.
    pub fn make(&mut self, own: &Handle<Process>) -> Result<(), Error> {
        const { assert!((GROUPS_AT + RECORDS * 8) as u64 <= PAGE) };
        const { assert!(GENERATIONS_SIZE <= GROUPS_AT) };
        let object = sys::mem_create(PAGE)?;
        sys::mem_map(own, &object, 0, PAGE, BASE, Access::ReadWrite)?;
        self.object = Some(object);
        Ok(())
    }

    fn word(&self, index: usize) -> Option<&'static AtomicU64> {
        self.object.as_ref()?;
        // SAFETY: the object is mapped read and write at BASE for as long
        // as the service lives (`make`); a word is aligned and lies in
        // the page for an index below RECORDS.
        (index < RECORDS).then(|| unsafe { &*((BASE + index * 8) as *const AtomicU64) })
    }

    /// The generation of the record in `index`.
    pub fn get(&self, index: usize) -> u64 {
        self.word(index).map_or(0, |w| w.load(Ordering::Acquire))
    }

    pub fn room(&self, index: usize, steps: u64) -> bool {
        proto_process::generation_room(self.get(index), steps)
    }

    pub fn live_room(&self, index: usize, steps: u64) -> bool {
        let old = self.get(index);
        old & proto_process::GENERATION_DEAD == 0 && proto_process::generation_room(old, steps)
    }

    /// Raises the generation of the record in `index`, with Release.
    pub fn raise(&self, index: usize) {
        if let Some(w) = self.word(index) {
            let old = w.load(Ordering::Relaxed);
            w.store(
                proto_process::next_generation(old, false),
                Ordering::Release,
            );
        }
    }

    /// Invalidate cached authority while retaining a retired record's death mark.
    pub fn invalidate(&self, index: usize) {
        if let Some(w) = self.word(index) {
            let old = w.load(Ordering::Relaxed);
            w.store(proto_process::next_generation(old, true), Ordering::Release);
        }
    }

    pub fn retire(&self, index: usize) {
        if let Some(w) = self.word(index) {
            w.fetch_or(proto_process::GENERATION_DEAD, Ordering::Release);
        }
    }

    /// The word of the group and session of the record in `index`, in the
    /// second half of the page (proto_process GROUPS_AT), with Release:
    /// `None` clears it.
    pub fn set_groups(&self, index: usize, groups: Option<(u32, u32)>) {
        if self.object.is_none() || index >= RECORDS {
            return;
        }
        // SAFETY: as in `word`: the second half of the page holds a word
        // for each index below RECORDS.
        let word = unsafe { &*((BASE + GROUPS_AT + index * 8) as *const AtomicU64) };
        let value = groups.map_or(0, |(pgid, sid)| groups_word(pgid, sid));
        word.store(value, Ordering::Release);
    }

    /// A copy of the object with MAP_READ and TRANSFER, for Register.
    pub fn copy(&self) -> Result<Handle<Memory>, Error> {
        let object = self.object.as_ref().ok_or(Error::BadState)?;
        sys::handle_duplicate(object, Rights::MAP_READ | Rights::TRANSFER)
    }
}
