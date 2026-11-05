// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The jobs of the worker thread (pk3-design R1, R7, R9): the receipt of a package, whose
//! bytes the main thread copies into the object as they are fed and this thread hashes and
//! writes to the disk, one portion at a time; and the transactions of the store, each a
//! plan of `pkgd::commit` over the disk service and the file service. The main thread
//! gives one job at a time (`shared::JOB`) and tells the client when it is done; every
//! job that fails leaves the state as it was.

use crate::shared::*;
use crate::worker::{Disk, Worker, check_timed, settings_key, view};
use abi::Access;
use core::sync::atomic::Ordering::{AcqRel, Acquire, Release};
use pkgd::commit::{self, Change, Device, Kind, Opened, Refused};
use pkgd::receipts::{BeginArgs, GROUP_MAX};
use pkgd::settings::{self, Settings};
use pkgd::store::{self, BLOCK, Extent, PACKAGES, RECORDS, Table, field_bytes, find_free};
use pkgd::{plans, verify};
use pkgfmt::sha::sha256;
use proto_pkg::CELL_BYTES;
use rt::handle::Channel;
use rt::sys;

/// The receipt being fed: its number, the place of the table, its size and the first block
/// of its extent; the object is mapped at `window(slot)`.
#[derive(Clone, Copy)]
pub struct Open {
    pub number: u32,
    pub slot: usize,
    pub size: u64,
    pub first: u64,
}

fn table() -> &'static Table {
    // SAFETY: the worker reads the table it writes.
    unsafe { &*TABLE.get() }
}

fn next() -> &'static mut Table {
    // SAFETY: the worker's scratch table.
    unsafe { &mut (*NEXT.get()).next }
}

fn opened() -> Opened {
    // SAFETY: the worker's.
    unsafe { (*OPENED.get()).expect("a store is open when a job runs") }
}

/// Free blocks for `blocks` blocks, in the state `table` of `opened`, clear of `taken`.
fn extent_for(table: &Table, opened: &Opened, disk: &Disk, blocks: u64) -> Option<Extent> {
    let mut held = [Extent {
        first: 0,
        blocks: 0,
    }; RECORDS + 1];
    let n = table.occupied(opened.table_extent(), &mut held);
    find_free(&held[..n], &[], disk.blocks(), blocks).map(|first| Extent { first, blocks })
}

/// The zeros after the `len` bytes of a blob up to a whole block.
fn pad(bytes: &mut [u8], len: usize) {
    bytes[len..len.div_ceil(BLOCK) * BLOCK].fill(0);
}

/// What the process holds, for the line of the report: the pages of the objects of the
/// packages and the settings layer, and the pages of the service's own.
pub fn report_memory(process: &rt::Handle<rt::handle::Process>) {
    // SAFETY: the worker's.
    let objects = unsafe { &*OBJECTS.get() };
    let packages: u64 = objects
        .iter()
        .flatten()
        .filter_map(|m| sys::memory_info(m).ok())
        .map(|info| info.pages)
        .sum();
    if let Ok(m) = sys::process_memory(process) {
        rt::println!(
            "pkgd: memory own={} packages={packages} pages",
            (m.used / 4096).saturating_sub(packages)
        );
    }
}

impl Worker {
    /// The thread's life after the start: drop what the main thread cancelled, take the
    /// bytes that came, run the job that is given, and wait to be kicked.
    pub fn serve(&mut self) -> ! {
        let jobs = view::<Channel>(crate::worker::JOBS);
        loop {
            let mut busy = false;
            if CANCEL.swap(false, AcqRel) {
                self.drop_group();
                busy = true;
            }
            if self.pump_feed() {
                busy = true;
            }
            if JOB_STATE.load(Acquire) == PENDING {
                self.run_job();
                busy = true;
            }
            if !busy {
                let _ = sys::receive(&jobs);
            }
        }
    }

    fn run_job(&mut self) {
        // A group the main thread cancelled goes before the job that may have been given after it.
        if CANCEL.swap(false, AcqRel) {
            self.drop_group();
        }
        JOB_STATE.store(RUNNING, Release);
        // SAFETY: the main thread gives no other job and writes none while the state is not IDLE.
        let job = unsafe { &*JOB.get() };
        let (code, value) = match job.kind {
            JobKind::Begin => self.begin(job),
            JobKind::Commit => (self.commit(job), 0),
            JobKind::Remove => (self.remove(job), 0),
            JobKind::SettingsSet => (self.settings_set(job), 0),
            JobKind::SerialSet => (self.serial_set(job), 0),
            JobKind::RevokedSet => (self.revoked_set(job), 0),
            JobKind::WorldSet => (self.world_set(job), 0),
        };
        JOB_CODE.store(code, Release);
        JOB_VALUE.store(value, Release);
        JOB_SLOT.store(self.open.map_or(0, |o| o.slot as u32), Release);
        JOB_STATE.store(DONE, Release);
        let _ = sys::notify(&view::<Channel>(crate::worker::WAKE), 1);
    }

    /// The group is over without its changes: the objects close and the windows unmap, the
    /// staged entries and the extents go (the table holds none of them), and the store is free.
    pub fn drop_group(&mut self) {
        // SAFETY: the worker's.
        let (objects, staged, group) =
            unsafe { (&mut *OBJECTS.get(), &mut *STAGED.get(), &mut *GROUP.get()) };
        if let Some(open) = self.open.take() {
            // SAFETY: the window of the receipt is the thread's.
            let _ = unsafe { sys::mem_unmap(&self.process, window(open.slot), open.size) };
            objects[open.slot] = None;
        }
        for s in group.staged() {
            objects[s.slot] = None;
        }
        staged.fill(const { None });
        group.release();
        self.failed = None;
        self.first_write = true;
        FED.store(0, Release);
        GROUP_OWNER.store(0, Release);
    }

    /// INSTALL_BEGIN: a place, an extent and an object for the package, the receipt's number.
    fn begin(&mut self, a: &JobArgs) -> (u32, u32) {
        // The first receipt of a group opens it; the others join.
        let repo = table().find_repo(field_bytes(&a.repo));
        let Some(repo) = repo else {
            return (proto_pkg::INVALID, 0);
        };
        let args = BeginArgs {
            name: field_bytes(&a.name),
            version: field_bytes(&a.version),
            size: a.size,
            sha256: a.sha256,
            repo,
            world: a.world,
        };
        // SAFETY: the worker's.
        let group = unsafe { &mut *GROUP.get() };
        let opened = opened();
        let (number, slot, extent) = match group.begin(
            a.owner,
            table(),
            opened.table_extent(),
            self.disk.blocks(),
            &args,
            0,
        ) {
            Ok(got) => got,
            // The group of another session stays as it is.
            Err(proto_pkg::BUSY) => return (proto_pkg::BUSY, 0),
            Err(code) => {
                self.drop_group();
                return (code, 0);
            }
        };
        GROUP_OWNER.store(a.owner, Release);
        FED.store(0, Release);
        let at = window(slot);
        let made = sys::mem_create(a.size)
            .and_then(|memory| {
                sys::mem_map(&self.process, &memory, 0, a.size, at, Access::ReadWrite)
                    .map(|()| memory)
            })
            .map_err(|_| proto_pkg::NO_MEMORY);
        let memory = match made {
            Ok(memory) => memory,
            Err(code) => {
                self.drop_group();
                return (code, 0);
            }
        };
        // SAFETY: the worker's.
        unsafe { (*OBJECTS.get())[slot] = Some(memory) };
        self.open = Some(Open {
            number,
            slot,
            size: a.size,
            first: extent.first,
        });
        self.first_write = true;
        self.failed = None;
        self.disk.point(commit::Point::Begin);
        (0, number)
    }

    /// The bytes of the open receipt that came and were not hashed: hashed and written, a
    /// portion at a time, until none is left or the main thread cancels. True when it did
    /// something.
    fn pump_feed(&mut self) -> bool {
        let Some(open) = self.open else {
            return false;
        };
        if self.failed.is_some() {
            return false;
        }
        // SAFETY: the worker's.
        let group = unsafe { &mut *GROUP.get() };
        let Some(receipt) = group.receipt(open.number) else {
            return false;
        };
        receipt.set_fed(FED.load(Acquire));
        let mut did = false;
        while let Some((from, to)) = receipt.portion() {
            if CANCEL.load(Acquire) {
                return did;
            }
            // SAFETY: the main thread copied these bytes into the window before it
            // published the count that made them a portion; it writes none below it.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (window(open.slot) + from as usize) as *const u8,
                    (to - from) as usize,
                )
            };
            let hashing = Stopwatch::new();
            receipt.absorb(bytes);
            hashing.keep(&SHA_TICKS);
            while let Some((first, blocks)) = receipt.blocks_to_write() {
                let at = first as usize * BLOCK;
                let len = blocks as usize * BLOCK;
                // SAFETY: whole blocks below what was hashed, in the window.
                let data = unsafe {
                    core::slice::from_raw_parts((window(open.slot) + at) as *const u8, len)
                };
                debug_assert!(len <= CELL_BYTES as usize);
                if self.disk.write_blocks(open.first + first, data).is_err() {
                    self.failed = Some(proto_pkg::IO);
                    return true;
                }
                if core::mem::take(&mut self.first_write) {
                    self.disk.point(commit::Point::Data);
                }
                receipt.wrote(blocks);
            }
            did = true;
        }
        did
    }

    /// INSTALL_COMMIT: all of the package is in, hashed and on the disk; its checks; at the
    /// end of the group the transaction.
    fn commit(&mut self, a: &JobArgs) -> u32 {
        // SAFETY: the worker's.
        let group = unsafe { &mut *GROUP.get() };
        if group.owner() != Some(a.owner) {
            return proto_pkg::INVALID;
        }
        self.pump_feed();
        if let Some(code) = self.failed {
            self.drop_group();
            return code;
        }
        let Some(open) = self.open.filter(|o| o.number == a.number) else {
            return proto_pkg::INVALID;
        };
        let committed = match group.commit(open.number) {
            Ok(committed) => committed,
            Err(code) => {
                self.drop_group();
                return code;
            }
        };
        let record = committed.staged.record;
        // SAFETY: the window holds the whole file, and no one writes it now.
        let bytes = unsafe {
            core::slice::from_raw_parts(window(open.slot) as *const u8, open.size as usize)
        };
        let repo = table().repo(usize::from(record.repo)).map(|(name, _)| name);
        let official = matches!(repo, Some(b"stafeto"));
        let own = repo
            .filter(|_| !official)
            .and_then(|name| settings_key(SETTINGS_LEN.load(Acquire), name));
        let own_keys = own.map_or([].as_slice(), |k| core::slice::from_ref(k));
        let trust = verify::select(official, &self.roots.0[..self.roots.1], own_keys);
        let checked = check_timed(
            bytes,
            &committed.covered,
            &committed.whole,
            &record,
            &trust,
            self.revoked.as_ref(),
            true,
        );
        let checked = match checked {
            Ok(checked) => checked,
            Err(fault) => {
                self.drop_group();
                return fault.code();
            }
        };
        let mut entry = pkgd::packages::Entry {
            record,
            image: false,
            layer: 0,
            meta_len: 0,
            meta: [0; pkgd::packages::META_MAX],
            trailer: [0; pkgd::packages::TRAILER],
        };
        if !entry.keep(checked.meta, checked.trailer) {
            self.drop_group();
            return proto_pkg::BAD_PACKAGE;
        }
        let index = group.staged().count() - 1;
        debug_assert!(index < GROUP_MAX);
        // SAFETY: the worker's.
        unsafe { (*STAGED.get())[index] = Some(entry) };
        // The file is checked: the window is done with, the object goes on to be a layer.
        // SAFETY: the window of the receipt is the thread's.
        let _ = unsafe { sys::mem_unmap(&self.process, window(open.slot), open.size) };
        self.open = None;
        self.first_write = true;
        FED.store(0, Release);
        if !a.end {
            // The data of the package are on the medium before the next package comes.
            if self.disk.flush().is_err() {
                self.drop_group();
                return proto_pkg::IO;
            }
            return 0;
        }
        // SAFETY: the worker's.
        let plan = unsafe { &mut *NEXT.get() };
        group.table(table(), plan);
        let change = Change {
            kind: Kind::Install,
            detach: plan.detach(),
            attach: plan.attach(),
        };
        let done = commit::transact(&mut self.disk, &opened(), table(), &plan.next, &change);
        let code = self.after(done, |worker| {
            // SAFETY: inside `publish`: the main thread reads none of it.
            unsafe {
                let (entries, objects) = (&mut *DISK_ENTRIES.get(), &mut *OBJECTS.get());
                for &slot in (*NEXT.get()).detach() {
                    PUBLISHED[slot].store(false, Release);
                    entries[slot] = None;
                    objects[slot] = None;
                }
                for (i, &slot) in (*NEXT.get()).attach().iter().enumerate() {
                    let mut entry = (*STAGED.get())[i].take().expect("a staged entry");
                    entry.layer = (*LAYER_OF.get())[slot];
                    entries[slot] = Some(entry);
                    PUBLISHED[slot].store(true, Release);
                }
            }
            worker.release();
        });
        if code != 0 {
            self.drop_group();
        }
        code
    }

    /// The group is over and made: nothing of it is to be dropped, only forgotten.
    fn release(&mut self) {
        // SAFETY: the worker's.
        unsafe { (*GROUP.get()).release() };
        // SAFETY: as above.
        unsafe { (*STAGED.get()).fill(const { None }) };
        self.open = None;
        self.failed = None;
        self.first_write = true;
        FED.store(0, Release);
        GROUP_OWNER.store(0, Release);
    }

    /// The outcome of a transaction: the code, and for a state that was made, `apply` inside
    /// the change of the published state.
    fn after(&mut self, done: Result<Opened, Refused>, apply: impl FnOnce(&mut Worker)) -> u32 {
        match done {
            Ok(now) => {
                self.publish(now, apply);
                report_memory(&self.process);
                0
            }
            Err(Refused::Attach(code)) => code,
            Err(Refused::NoSpace) => proto_pkg::NO_SPACE,
            Err(Refused::Io) => {
                rt::println!("pkgd: store state unknown after a failed write");
                proto_pkg::IO
            }
        }
    }

    /// The state `now` is the store's: the main thread reads the table, the entries and the
    /// blobs again after `apply` changed them.
    fn publish(&mut self, now: Opened, apply: impl FnOnce(&mut Worker)) {
        let copy: &Table = next();
        let free = commit::free_of(copy, &now);
        SEQ.write(|| {
            // SAFETY: the count is odd: a read that overlaps is thrown away by its reader.
            unsafe {
                (*TABLE.get()).0 = copy.0;
                *OPENED.get() = Some(now);
            }
            GENERATION.store(now.superblock.generation, Release);
            FREE.store(free, Release);
            apply(self);
            let live = PUBLISHED.iter().filter(|p| p.load(Acquire)).count();
            DISK_PACKAGES.store(live as u32, Release);
        });
    }

    /// REMOVE of the names in the job.
    fn remove(&mut self, a: &JobArgs) -> u32 {
        if GROUP_OWNER.load(Acquire) != 0 {
            return proto_pkg::BUSY;
        }
        let mut names: [&[u8]; 8] = [&[]; 8];
        for (name, field) in names.iter_mut().zip(&a.names).take(a.count) {
            *name = field_bytes(field);
        }
        let mut slots = [0; plans::REMOVE_MAX];
        // SAFETY: the worker's reads of the entries it writes.
        let (entries, images) = unsafe { (&*DISK_ENTRIES.get(), &*IMAGE_ENTRIES.get()) };
        let n = match plans::remove(
            table(),
            next(),
            entries,
            images,
            &names[..a.count],
            &mut slots,
        ) {
            Ok(n) => n,
            Err(code) => return code,
        };
        let change = Change {
            kind: Kind::Remove,
            detach: &slots[..n],
            attach: &[],
        };
        let done = commit::transact(&mut self.disk, &opened(), table(), next(), &change);
        self.after(done, |_| {
            // SAFETY: inside `publish`.
            unsafe {
                let (entries, objects) = (&mut *DISK_ENTRIES.get(), &mut *OBJECTS.get());
                for &slot in &slots[..n] {
                    PUBLISHED[slot].store(false, Release);
                    entries[slot] = None;
                    objects[slot] = None;
                }
            }
        })
    }

    /// SERIAL_SET: the number of a repository.
    fn serial_set(&mut self, a: &JobArgs) -> u32 {
        if GROUP_OWNER.load(Acquire) != 0 {
            return proto_pkg::BUSY;
        }
        match plans::serial(table(), next(), field_bytes(&a.repo), a.serial) {
            Err(code) => code,
            Ok(false) => 0,
            Ok(true) => {
                let change = Change {
                    kind: Kind::Serial,
                    detach: &[],
                    attach: &[],
                };
                let done = commit::transact(&mut self.disk, &opened(), table(), next(), &change);
                self.after(done, |_| {})
            }
        }
    }

    /// WORLD_SET: the flag "world" of a package of the disk, the table alone.
    fn world_set(&mut self, a: &JobArgs) -> u32 {
        if GROUP_OWNER.load(Acquire) != 0 {
            return proto_pkg::BUSY;
        }
        // SAFETY: the worker's reads of the entries it writes.
        let images = unsafe { &*IMAGE_ENTRIES.get() };
        let slot = match plans::world(table(), next(), images, field_bytes(&a.name), a.world) {
            Err(code) => return code,
            Ok(None) => return 0,
            Ok(Some(slot)) => slot,
        };
        let change = Change {
            kind: Kind::World,
            detach: &[],
            attach: &[],
        };
        let done = commit::transact(&mut self.disk, &opened(), table(), next(), &change);
        self.after(done, |_| {
            // SAFETY: inside `publish`.
            let entries = unsafe { &mut *DISK_ENTRIES.get() };
            if let Some(entry) = entries[slot].as_mut() {
                entry.record = table().record(slot);
            }
        })
    }

    /// The bytes of a blob in the client's buffer into `out`, a copy of the worker's own
    /// that nothing the client does changes after it.
    fn copy_buffer(a: &JobArgs, out: &mut [u8]) {
        // SAFETY: the buffer is mapped for the life of the session, which the main thread
        // keeps mapped until this job is done; `out` is as long as the length it was
        // checked against.
        unsafe {
            core::ptr::copy_nonoverlapping(
                buffer_at(a.buffer) as *const u8,
                out.as_mut_ptr(),
                a.len,
            )
        };
    }

    /// The blob of `len` bytes at the start of `bytes`, which is padded with zeros to
    /// whole blocks (`pad`), into a free extent of the disk: the extent and the SHA-256
    /// of the blob.
    fn write_blob(&mut self, bytes: &[u8], len: usize) -> Result<(Extent, [u8; 32]), u32> {
        let blocks = len.div_ceil(BLOCK);
        let extent =
            extent_for(table(), &opened(), &self.disk, blocks as u64).ok_or(proto_pkg::NO_SPACE)?;
        for (i, part) in bytes[..blocks * BLOCK]
            .chunks(CELL_BYTES as usize)
            .enumerate()
        {
            let at = i as u64 * (CELL_BYTES as usize / BLOCK) as u64;
            self.disk
                .write_blocks(extent.first + at, part)
                .map_err(|_| proto_pkg::IO)?;
        }
        Ok((extent, sha256(&bytes[..len])))
    }

    /// SETTINGS_SET: the blob in the buffer of the client.
    fn settings_set(&mut self, a: &JobArgs) -> u32 {
        if GROUP_OWNER.load(Acquire) != 0 {
            return proto_pkg::BUSY;
        }
        // SAFETY: the worker's.
        let blob = unsafe { &mut *NEW_BLOB.get() };
        if a.len == 0 || a.len > blob.len() {
            return proto_pkg::INVALID;
        }
        Worker::copy_buffer(a, &mut blob[..a.len]);
        pad(&mut blob[..], a.len);
        let Ok(parsed) = Settings::parse(&blob[..a.len]) else {
            return proto_pkg::INVALID;
        };
        // A repository a package of the disk came from keeps its line and its key.
        let mut held: [&str; store::REPOS] = [""; store::REPOS];
        let mut n = 0;
        // SAFETY: the worker's reads of the entries it writes; the table is the state.
        let entries = unsafe { &*DISK_ENTRIES.get() };
        for entry in entries.iter().flatten() {
            let Some((name, _)) = table().repo(usize::from(entry.record.repo)) else {
                continue;
            };
            let Ok(name) = core::str::from_utf8(name) else {
                continue;
            };
            if name != settings::OFFICIAL && !held[..n].contains(&name) {
                held[n] = name;
                n += 1;
            }
        }
        // SAFETY: the worker's; the live blob changes only in `publish`, in this thread.
        let live: &[u8] = unsafe { &(&*SETTINGS.get()).0[..SETTINGS_LEN.load(Acquire)] };
        if !parsed.keeps(live, &held[..n]) {
            return proto_pkg::NEEDED_BY;
        }
        // The object of the new layer waits in its own place until its table is the state.
        let attached_before = SETTINGS_LEN.load(Acquire) != 0
            && unsafe { &*OBJECTS.get() }[store::SETTINGS_SLOT].is_some();
        let memory = match self.settings_object(&parsed) {
            Ok(memory) => memory,
            Err(_) => return proto_pkg::NO_MEMORY,
        };
        // SAFETY: the worker's.
        unsafe { (*OBJECTS.get())[store::SETTINGS_NEW] = Some(memory) };
        let code = self.settings_change(a, attached_before);
        if code != 0 {
            // SAFETY: as above.
            unsafe { (*OBJECTS.get())[store::SETTINGS_NEW] = None };
        }
        code
    }

    fn settings_change(&mut self, a: &JobArgs, attached_before: bool) -> u32 {
        // SAFETY: the worker's, and no reference to it is live.
        let blob = unsafe { &*NEW_BLOB.get() };
        let (extent, sha) = match self.write_blob(&blob[..], a.len) {
            Ok(written) => written,
            Err(code) => return code,
        };
        plans::settings(table(), next(), extent, a.len as u64, sha);
        let detach = [store::SETTINGS_SLOT];
        let change = Change {
            kind: Kind::Settings,
            detach: if attached_before { &detach } else { &[] },
            attach: &[store::SETTINGS_NEW],
        };
        let done = commit::transact(&mut self.disk, &opened(), table(), next(), &change);
        let len = a.len;
        self.after(done, |_| {
            // SAFETY: inside `publish`.
            unsafe {
                let (objects, layers) = (&mut *OBJECTS.get(), &mut *LAYER_OF.get());
                objects[store::SETTINGS_SLOT] = objects[store::SETTINGS_NEW].take();
                layers[store::SETTINGS_SLOT] = core::mem::take(&mut layers[store::SETTINGS_NEW]);
                let (live, new) = (&mut *SETTINGS.get(), &*NEW_BLOB.get());
                live[..len].copy_from_slice(&new[..len]);
            }
            SETTINGS_LEN.store(len, Release);
        })
    }

    /// REVOKED_SET: the list in the buffer of the client, signed by a root.
    fn revoked_set(&mut self, a: &JobArgs) -> u32 {
        if GROUP_OWNER.load(Acquire) != 0 {
            return proto_pkg::BUSY;
        }
        // SAFETY: the worker's.
        let buffer = unsafe { &mut *NEW_LIST.get() };
        if a.len <= pkgfmt::sig::BLOCK_SIZE || a.len > REVOKED_FILE_MAX {
            return proto_pkg::INVALID;
        }
        Worker::copy_buffer(a, &mut buffer[..a.len]);
        pad(buffer, a.len);
        // SAFETY: the list lives in the static `NEW_LIST` for the life of the process, and
        // nothing writes the bytes before `a.len` while this view lives.
        let bytes: &'static [u8] = unsafe { core::slice::from_raw_parts(buffer.as_ptr(), a.len) };
        let Ok(list) = crate::worker::list_of(bytes, &self.roots) else {
            return proto_pkg::BAD_SIGNATURE;
        };
        // The packages the list names (those that are not attached already stay out).
        let mut flags = [false; PACKAGES];
        let mut detach = [0usize; PACKAGES];
        let mut n = 0;
        // SAFETY: the worker's reads of the entries it writes.
        let entries = unsafe { &*DISK_ENTRIES.get() };
        for (slot, entry) in entries.iter().enumerate() {
            let Some(entry) = entry else { continue };
            flags[slot] = verify::revoked_by(&entry.trailer, &list);
            // SAFETY: the worker's.
            if flags[slot] && unsafe { (*LAYER_OF.get())[slot] } != 0 {
                detach[n] = slot;
                n += 1;
            }
        }
        let serial = list.serial;
        // SAFETY: `list` is a view of the first bytes of the list; the zeros after them
        // were put in before it was made.
        let whole = unsafe { &*NEW_LIST.get() };
        let (extent, sha) = match self.write_blob(whole, a.len) {
            Ok(written) => written,
            Err(code) => return code,
        };
        if let Err(code) =
            plans::revoked(table(), next(), extent, a.len as u64, sha, serial, &flags)
        {
            return code;
        }
        let change = Change {
            kind: Kind::Revoked,
            detach: &detach[..n],
            attach: &[],
        };
        let done = commit::transact(&mut self.disk, &opened(), table(), next(), &change);
        let len = a.len;
        self.after(done, |worker| {
            // The old list is not read again; the bytes of the new one take its place.
            worker.revoked = None;
            // SAFETY: inside `publish`.
            unsafe {
                let (entries, objects) = (&mut *DISK_ENTRIES.get(), &mut *OBJECTS.get());
                for (slot, entry) in entries.iter_mut().enumerate() {
                    if let Some(entry) = entry {
                        entry.record.flags = (*NEXT.get()).next.record(slot).flags;
                    }
                }
                for &slot in &detach[..n] {
                    objects[slot] = None;
                    let name = entries[slot].as_ref().map_or(&b"?"[..], |e| e.name());
                    rt::println!(
                        "pkgd: {}: key revoked, detached",
                        core::str::from_utf8(name).unwrap_or("?")
                    );
                }
                let (live, new) = (&mut *REVOKED_FILE.get(), &*NEW_LIST.get());
                live[..len].copy_from_slice(&new[..len]);
            }
            // The list of the state, parsed from the buffer that now holds it.
            worker.revoked = worker.parse_list(len).ok();
        })
    }
}
