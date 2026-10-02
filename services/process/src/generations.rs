// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The page of the credentials generations (proto_process::GENERATIONS_SIZE,
//! spec 2, 3.1): a u64 for each record index in one memory object, which
//! the service maps for writing at its own address and gives the services
//! that ask (Register) a read-only copy of. The service raises a record's
//! word with Release when it makes the record and before it answers a
//! change of its credentials; a service that remembers the answer of Vouch reads
//! the word with Acquire, with no call, before each check. The words never
//! start over: a record made in a used index raises its word.

use core::sync::atomic::{AtomicU64, Ordering};
use proto_process::{GENERATIONS_SIZE, RECORDS};
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
        const { assert!(GENERATIONS_SIZE as u64 <= PAGE) };
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

    /// Raises the generation of the record in `index`, with Release.
    pub fn raise(&self, index: usize) {
        if let Some(w) = self.word(index) {
            w.fetch_add(1, Ordering::Release);
        }
    }

    /// A copy of the object with MAP_READ and TRANSFER, for Register.
    pub fn copy(&self) -> Result<Handle<Memory>, Error> {
        let object = self.object.as_ref().ok_or(Error::BadState)?;
        sys::handle_duplicate(object, Rights::MAP_READ | Rights::TRANSFER)
    }
}
