// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The package service (pk3-design): two threads of one process. The main
//! thread (level 32) is the loop of a service (rt::service) and answers the
//! reads of its clients in steps that stay short: the list of packages, the
//! `meta` of one, the serial of a repository, the settings, the status, a
//! session of its own for a child (CLONE) and the buffer of a client. The
//! worker thread (`worker.rs`, level 30) reads the store from the disk,
//! checks and attaches the packages to the file service and takes all the
//! long calls, so the main thread never waits for them. The packages of the
//! boot image are read here, before the service registers.

#![no_std]
#![no_main]

mod shared;
mod worker;

use abi::{Access, Error, Rights, Source};
use core::sync::atomic::Ordering::{Acquire, Release};
use pkgd::packages::Entry;
use pkgd::store::{self, PACKAGES};
use proto_pkg::{
    BUFFER_SIZE, CELL_BYTES, INFO_MAX, LIST_MAX, Method, STATUS_DAMAGED, STATUS_READ_ONLY,
    STATUS_STARTING, Stat, VERSION, code, read_info, read_word,
};
use proto_wire::Status;
use proto_wire::clones::Clones;
use rt::handle::{Channel, Memory, Outgoing, Process};
use rt::service::{Answer, Config, Heartbeat, Notice, Request, Service, Session};
use rt::{Handle, sys};
use shared::*;

rt::entry!(main);

/// Where the service maps the boot image, and the buffers of its clients.
const IMAGE_AT: usize = 0x50_0000_0000;
const BUFFERS_AT: usize = 0x58_0000_0000;
/// The buffers at once, one for each session that gave one.
const BUFFERS: usize = 4;
/// The sessions the loop keeps, and the clones of them at most.
const SESSIONS: usize = 128;
const CLONES: usize = 64;
const OWN: u64 = 1 << 63;

/// The codes of a start that failed.
const NO_START_DATA: u64 = 1;
const NOT_CONNECTED: u64 = 2;
const NOT_REGISTERED: u64 = 3;
const STOPPED: u64 = 5;

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<rt::handle::Resource>("console") {
        rt::console::set(console);
    }
    let period_ns = proto_init::ServiceArgs::read(s.args()).map_or(0, |a| a.period_ns);
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    // The images' packages first: their `meta` is read before anything is served.
    // SAFETY: nothing else runs yet.
    unsafe {
        let n = image_packages(&mut s);
        IMAGE_PACKAGES.store(n, Release);
    }
    let (Ok(blk), Ok(layers)) = (
        rt::service::connect(&s.parent, "blk"),
        rt::service::connect(&s.parent, "ramfs/layers"),
    ) else {
        return NOT_CONNECTED;
    };
    let Ok(channel) = sys::channel_create(1) else {
        return NOT_REGISTERED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return NOT_REGISTERED;
    }
    let Ok(done) = sys::handle_label(
        &channel,
        Rights::NOTIFY | Rights::TRANSFER,
        LABEL_DONE,
        MAIN_LEVEL,
    ) else {
        return NOT_REGISTERED;
    };
    // The raw handles the worker uses stay alive for the life of the process.
    for (i, raw) in [
        (worker::PROCESS, s.process.raw()),
        (worker::BLK_SESSION, blk.into_raw()),
        (worker::LAYERS_SESSION, layers.into_raw()),
        (worker::MAIN_CHANNEL, channel.raw()),
        (worker::WAKE, done.into_raw()),
    ] {
        worker::RAW[i].store(raw.0, Release);
    }
    let Ok(_thread) = worker::start(&s.process) else {
        return NOT_REGISTERED;
    };
    #[cfg(feature = "steps")]
    rt::service::report_steps(16);
    let mut service = Pkgd {
        process: Handle::borrowed(s.process.raw()),
        clones: Clones::new(),
        channel: Handle::borrowed(channel.raw()),
        level,
        buffers: [None; BUFFERS],
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &s.parent,
            period_ns,
            priority: level,
        }),
    };
    let _ = rt::service::run::<Pkgd, SESSIONS, 0>(&channel, &mut service, config);
    STOPPED
}

/// The packages of the boot image: `meta` of each file named `*.stpkg`.
///
/// # Safety
/// Called once before the worker starts.
unsafe fn image_packages(s: &mut rt::startup::Startup) -> u32 {
    let Ok(image) = s.take::<Memory>("bootimage") else {
        return 0;
    };
    let Ok(info) = sys::memory_info(&image) else {
        return 0;
    };
    if sys::mem_map(&s.process, &image, 0, info.size, IMAGE_AT, Access::Read).is_err() {
        return 0;
    }
    // SAFETY: the image stays mapped, read-only, for the life of the process.
    let bytes = unsafe { core::slice::from_raw_parts(IMAGE_AT as *const u8, info.size as usize) };
    // SAFETY: the caller: no other thread yet.
    let entries = unsafe { &mut *IMAGE_ENTRIES.get() };
    let n = pkgd::packages::read_image(bytes, entries, |name, why| {
        rt::println!("pkgd: {name}: {why}, skipped");
    });
    n as u32
}

/// What a session keeps: the place of its buffer, if it gave one.
#[derive(Default)]
struct Sess {
    buffer: Option<u8>,
}

struct Pkgd {
    process: core::mem::ManuallyDrop<Handle<Process>>,
    channel: core::mem::ManuallyDrop<Handle<Channel>>,
    clones: Clones<CLONES>,
    level: u8,
    /// The label of the session whose buffer is mapped at each place.
    buffers: [Option<u64>; BUFFERS],
}

fn buffer_at(place: u8) -> usize {
    BUFFERS_AT + usize::from(place) * BUFFER_SIZE as usize
}

/// The entry at LIST position `i`: the disk's 64, then the image's.
fn listed(i: usize) -> Option<&'static Entry> {
    if i < PACKAGES {
        if !PUBLISHED[i].load(Acquire) {
            return None;
        }
        // SAFETY: published: whole and no longer written.
        unsafe { (*DISK_ENTRIES.get())[i].as_ref() }
    } else {
        // SAFETY: filled before the loop began.
        unsafe {
            (*IMAGE_ENTRIES.get())
                .get(i - PACKAGES)
                .and_then(Option::as_ref)
        }
    }
}

impl Pkgd {
    fn list(&self, r: &mut Request<'_>) -> Answer {
        let Ok(first) = read_word(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        let end = PACKAGES + IMAGE_MAX;
        let mut at = first as usize;
        let mut found = [None; LIST_MAX as usize];
        let mut count = 0;
        while at < end && count < found.len() {
            if let Some(e) = listed(at) {
                found[count] = Some(e);
                count += 1;
            }
            at += 1;
        }
        while at < end && listed(at).is_none() {
            at += 1;
        }
        let w = r.reply();
        let next = if at < end { at as u32 } else { 0 };
        let ok = w
            .u32(0)
            .and_then(|()| proto_pkg::write_list_head(count as u32, next, w));
        if ok.is_err() {
            return Answer::Status(Status::BadSize);
        }
        for e in found.iter().flatten() {
            let repo = repository_of(e);
            let wrote = proto_pkg::Entry {
                name: e.name(),
                version: e.record.version_bytes(),
                sha256: e.record.sha256,
                flags: e.flags(),
                repository: repo,
            }
            .write(w);
            if wrote.is_err() {
                return Answer::Status(Status::BadSize);
            }
        }
        Answer::Reply(Outgoing::new())
    }

    fn info(&self, r: &mut Request<'_>) -> Answer {
        let Ok((name, offset)) = read_info(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        let found = (0..PACKAGES + IMAGE_MAX)
            .filter_map(listed)
            .find(|e| e.name() == name);
        let Some(entry) = found else {
            return Answer::Status(code(proto_pkg::NOT_FOUND));
        };
        let meta = entry.meta();
        let from = (offset as usize).min(meta.len());
        let part = &meta[from..(from + INFO_MAX).min(meta.len())];
        let w = r.reply();
        if w.u32(0)
            .and_then(|()| w.u32(meta.len() as u32))
            .and_then(|()| w.bytes(part))
            .is_err()
        {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    fn serial(&self, r: &mut Request<'_>) -> Answer {
        let Ok((repo, _)) = proto_pkg::read_serial(r.body(), false) else {
            return Answer::Status(Status::BadSize);
        };
        if STARTING.load(Acquire) {
            return Answer::Status(code(proto_pkg::BUSY));
        }
        // SAFETY: the worker is done: the table is the main thread's.
        let table = unsafe { &*TABLE.get() };
        let serial = table
            .find_repo(repo)
            .and_then(|i| table.repo(i))
            .map_or(0, |(_, s)| s);
        let w = r.reply();
        if w.u32(0).and_then(|()| w.u64(serial)).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    fn status(&self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let mut flags = 0;
        for (on, bit) in [
            (DAMAGED.load(Acquire), STATUS_DAMAGED),
            (READ_ONLY.load(Acquire), STATUS_READ_ONLY),
            (STARTING.load(Acquire), STATUS_STARTING),
        ] {
            if on {
                flags |= bit;
            }
        }
        let stat = Stat {
            generation: GENERATION.load(Acquire),
            blocks: BLOCKS.load(Acquire),
            free: FREE.load(Acquire),
            disk: DISK_PACKAGES.load(Acquire),
            image: IMAGE_PACKAGES.load(Acquire),
            flags,
        };
        let w = r.reply();
        if w.u32(0).and_then(|()| stat.write(w)).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    /// BUFFER: the client's object, four cells, mapped for the session's life.
    fn give_buffer(&mut self, s: &mut Session<Sess, 0>, r: &mut Request<'_>) -> Answer {
        let Ok(size) = read_word(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        if size != BUFFER_SIZE || r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let needed = Rights::MAP_READ | Rights::MAP_WRITE;
        let rights = r.handles.info(0).map_or(Rights::NONE, |(_, rights)| rights);
        let Ok(object) = r.handles.take::<Memory>(0) else {
            return Answer::Status(code(proto_pkg::INVALID));
        };
        if rights.0 & needed.0 != needed.0 {
            return Answer::Status(code(proto_pkg::INVALID));
        }
        // An object of `mem_create`: as big as asked and every page its own.
        match sys::memory_info(&object) {
            Ok(info) if info.size >= u64::from(size) && info.pages * 4096 >= u64::from(size) => {}
            _ => return Answer::Status(code(proto_pkg::INVALID)),
        }
        if s.data.buffer.is_some() {
            return Answer::Status(code(proto_pkg::INVALID));
        }
        let Some(place) = self.buffers.iter().position(Option::is_none) else {
            return Answer::Status(code(proto_pkg::BUSY));
        };
        let mapped = sys::mem_map(
            &self.process,
            &object,
            0,
            u64::from(size),
            buffer_at(place as u8),
            Access::ReadWrite,
        );
        match mapped {
            Ok(()) => {
                self.buffers[place] = Some(r.label());
                s.data.buffer = Some(place as u8);
                Answer::Status(Status::Ok)
            }
            Err(error) => Answer::Status(Status::Kernel(error)),
        }
    }

    /// SETTINGS_GET: up to one cell of the blob from `offset` into cell 0.
    fn settings(&self, s: &Session<Sess, 0>, r: &mut Request<'_>) -> Answer {
        let Ok(offset) = read_word(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        let Some(place) = s.data.buffer else {
            return Answer::Status(code(proto_pkg::NO_BUFFER));
        };
        if STARTING.load(Acquire) {
            return Answer::Status(code(proto_pkg::BUSY));
        }
        let len = SETTINGS_LEN.load(Acquire);
        let from = (offset as usize).min(len);
        let n = (len - from).min(CELL_BYTES as usize);
        // SAFETY: the blob is the main thread's now; the cell is the client's, written raw.
        unsafe {
            let blob = (*SETTINGS.get()).as_ptr().add(from);
            core::ptr::copy_nonoverlapping(blob, buffer_at(place) as *mut u8, n);
        }
        let w = r.reply();
        let reply = proto_pkg::Settings {
            total: len as u32,
            copied: n as u32,
            generation: GENERATION.load(Acquire),
        };
        if w.u32(0).and_then(|()| reply.write(w)).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    /// CLONE: a session of its own for a child of the client.
    fn clone_session(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let Ok(label) = self.clones.give(OWN, r.label()) else {
            return Answer::Status(code(proto_pkg::BUSY));
        };
        let rights = Rights::SEND | Rights::DUPLICATE | Rights::TRANSFER;
        match sys::handle_label(&self.channel, rights, label, self.level) {
            Ok(session) => {
                if r.reply().u32(0).is_err() {
                    self.clones.gone(label);
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply([session.erase()].into())
            }
            Err(error) => {
                self.clones.gone(label);
                Answer::Status(Status::Kernel(error))
            }
        }
    }
}

/// The name of the repository of an entry: the table's, empty for the image.
fn repository_of(e: &Entry) -> &'static [u8] {
    if e.image || STARTING.load(Acquire) && e.record.repo == store::NO_REPO {
        return b"";
    }
    // SAFETY: a published entry's repository names are written before the
    // worker publishes any package.
    let table = unsafe { &*TABLE.get() };
    table
        .repo(usize::from(e.record.repo))
        .map_or(&b""[..], |(name, _)| name)
}

const METHODS: &[u16] = &[
    Method::List.number(),
    Method::Info.number(),
    Method::SettingsGet.number(),
    Method::Serial.number(),
    Method::Clone.number(),
    Method::Take.number(),
    Method::Buffer.number(),
    Method::Status.number(),
];

impl Service<0> for Pkgd {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = Sess;

    fn request(&mut self, s: &mut Session<Sess, 0>, r: &mut Request<'_>) -> Answer {
        match Method::from_number(r.method()) {
            Some(Method::List) => self.list(r),
            Some(Method::Info) => self.info(r),
            Some(Method::SettingsGet) => self.settings(s, r),
            Some(Method::Serial) => self.serial(r),
            Some(Method::Clone) => self.clone_session(r),
            Some(Method::Buffer) => self.give_buffer(s, r),
            Some(Method::Status) => self.status(r),
            // No operation of this part ever waits: every key is unknown.
            Some(Method::Take) => Answer::Status(Status::Kernel(Error::BadState)),
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    fn gone(&mut self, s: &mut Session<Sess, 0>) {
        if let Some(place) = s.data.buffer.take() {
            // SAFETY: nothing of the service's own lies in the buffer's range.
            let gone =
                unsafe { sys::mem_unmap(&self.process, buffer_at(place), u64::from(BUFFER_SIZE)) };
            if gone.is_ok() {
                self.buffers[usize::from(place)] = None;
            }
        }
    }

    /// The last copy of a session went: a clone's place is free again, whether or
    /// not it ever sent a request.
    fn closed(&mut self, label: u64) {
        if label & OWN != 0 {
            self.clones.gone(label);
        }
    }

    fn notification(&mut self, n: Notice) {
        // The step of a notification is measured apart from the heartbeat's.
        rt::service::step_own();
        if n.source == Source::Session && (LABEL_LAYER..=LABEL_DONE).contains(&n.label) {
            #[cfg(feature = "steps")]
            if n.label == LABEL_DONE {
                rt::println!(
                    "pkgd: work read_hash={} check={}",
                    HASH_TICKS.load(Acquire),
                    CHECK_TICKS.load(Acquire)
                );
                if let Ok(m) = sys::process_memory(&self.process) {
                    rt::println!("pkgd: memory used={} pages", m.used / 4096);
                }
            }
        }
    }
}
