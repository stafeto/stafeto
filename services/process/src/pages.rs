// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The pages of the records (proto_process::Page, spec 2, 3.1): one page
//! each, in memory objects of GROUP pages, OBJECTS of them, which the
//! service makes when a record of their indices first needs one and maps
//! at its own address for as long as it lives. A new record's page is
//! zeroed, gets its identity, and is mapped into its process at
//! PAGE_ADDRESS, read and write, through a copy of the object's handle
//! with those rights alone (rt::loader::map_narrowed). The service pays
//! for the objects; the process for the tables of its mapping.

use posix_process_service::preparing::{GroupClaim, Key, PageGroup};
use proto_process::{PAGE_ADDRESS, PAGE_VERSION, Page, RECORDS};
use rt::abi::{Access, Error};
use rt::handle::{Handle, Memory, Process};
use rt::{loader, sys};

const PAGE: usize = 4096;
/// The pages of one object.
const GROUP: usize = 4;
const OBJECTS: usize = RECORDS / GROUP;
/// Where the service maps its objects, GROUP pages each, one after the
/// other.
const BASE: usize = 0x40_0000_0000;

pub struct Pages {
    objects: [PageGroup<Handle<Memory>>; OBJECTS],
}

impl Pages {
    pub const fn new() -> Self {
        Self {
            objects: [const { PageGroup::Empty }; OBJECTS],
        }
    }

    pub fn claim(&mut self, index: usize, key: Key) -> GroupClaim {
        self.objects[index / GROUP].claim(key)
    }

    pub fn create_group() -> Result<Handle<Memory>, Error> {
        sys::mem_create((GROUP * PAGE) as u64)
    }

    /// The exact owner was prepaid before memory creation. No IPC changes it here.
    /// The memory stays in its resident preparation through the mapping syscall.
    pub fn map_group(
        &mut self,
        own: &Handle<Process>,
        index: usize,
        key: Key,
        object: &mut Option<Handle<Memory>>,
    ) -> Result<(), Error> {
        let group = index / GROUP;
        if !self.objects[group].reserved_by(key) {
            return Err(Error::BadState);
        }
        let memory = object.as_ref().ok_or(Error::BadState)?;
        let at = BASE + group * GROUP * PAGE;
        sys::mem_map(own, memory, 0, (GROUP * PAGE) as u64, at, Access::ReadWrite)?;
        // The main loop is the sole mutator. Successful mapping immediately
        // publishes ownership to the unchanged group, with no syscall suffix.
        let memory = object.take().expect("the resident mapped memory");
        if self.objects[group].publish(key, memory).is_err() {
            unreachable!("the preflighted group remains owned by its preparation");
        }
        Ok(())
    }

    pub fn cancel_group(&mut self, index: usize, key: Key) -> bool {
        self.objects[index / GROUP].cancel(key)
    }

    /// One zeroed page and four atomic fields, before its process can run.
    pub fn initialize(&self, index: usize, identity: [u32; 4]) -> Result<(), Error> {
        self.objects[index / GROUP]
            .mapped()
            .ok_or(Error::BadState)?;
        let at = BASE + index * PAGE;
        // SAFETY: the mapped group owns this reserved record's page; the target
        // process has no started thread while its preparation owns the record.
        unsafe { core::ptr::write_bytes(at as *mut u8, 0, PAGE) };
        let page = self.page(index).expect("a mapped group");
        let [pid, ppid, pgid, sid] = identity;
        page.pid.store(pid, core::sync::atomic::Ordering::Relaxed);
        page.ppid.store(ppid, core::sync::atomic::Ordering::Relaxed);
        page.pgid.store(pgid, core::sync::atomic::Ordering::Relaxed);
        page.sid.store(sid, core::sync::atomic::Ordering::Relaxed);
        page.version
            .store(PAGE_VERSION, core::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// The page of the record in `index`, once `prepare` made its object.
    pub fn page(&self, index: usize) -> Option<&'static Page> {
        self.objects[index / GROUP].mapped()?;
        // SAFETY: the object of the index is mapped at its place, read and
        // write, for as long as the service lives (`prepare`); a page holds
        // a Page, whose fields are atomics the process writes too.
        Some(unsafe { &*((BASE + index * PAGE) as *const Page) })
    }

    /// The page of the record in `index` mapped into `process` as it is,
    /// with the signals that wait on it: the new process of an exec (5c).
    pub fn map_again(&self, index: usize, process: &Handle<Process>) -> Result<(), Error> {
        let object = self.objects[index / GROUP]
            .mapped()
            .ok_or(Error::BadState)?;
        let offset = ((index % GROUP) * PAGE) as u64;
        loader::map_narrowed(
            process,
            object,
            offset,
            PAGE as u64,
            PAGE_ADDRESS,
            Access::ReadWrite,
        )
    }

    /// The page of a new record in `index` of process `pid`: its object
    /// made and mapped in `own`, the service's process, when it is the
    /// first; zeroed, with the identity, and mapped into `process`.
    pub fn give(
        &mut self,
        own: &Handle<Process>,
        index: usize,
        process: &Handle<Process>,
        identity: [u32; 4],
    ) -> Result<(), Error> {
        let group = index / GROUP;
        if matches!(self.objects[group], PageGroup::Empty) {
            let object = sys::mem_create((GROUP * PAGE) as u64)?;
            let at = BASE + group * GROUP * PAGE;
            sys::mem_map(
                own,
                &object,
                0,
                (GROUP * PAGE) as u64,
                at,
                Access::ReadWrite,
            )?;
            self.objects[group] = PageGroup::Mapped(object);
        }
        self.objects[group].mapped().ok_or(Error::BadState)?;
        let at = BASE + index * PAGE;
        // SAFETY: the page is the record's, mapped at `at` in the service,
        // and its process does not run yet: nothing else writes it.
        unsafe { core::ptr::write_bytes(at as *mut u8, 0, PAGE) };
        let page = self.page(index).expect("a page just made");
        let [pid, ppid, pgid, sid] = identity;
        page.pid.store(pid, core::sync::atomic::Ordering::Relaxed);
        page.ppid.store(ppid, core::sync::atomic::Ordering::Relaxed);
        page.pgid.store(pgid, core::sync::atomic::Ordering::Relaxed);
        page.sid.store(sid, core::sync::atomic::Ordering::Relaxed);
        page.version
            .store(PAGE_VERSION, core::sync::atomic::Ordering::Release);
        let object = self.objects[group].mapped().ok_or(Error::BadState)?;
        let offset = ((index % GROUP) * PAGE) as u64;
        loader::map_narrowed(
            process,
            object,
            offset,
            PAGE as u64,
            PAGE_ADDRESS,
            Access::ReadWrite,
        )
    }
}
