// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The package service (pk3-design): two threads of one process. The main
//! thread (level 32) is the loop of a service (rt::service) and answers its
//! clients in steps that stay short: the reads (the list of packages, the
//! `meta` of one, the serial of a repository, the settings, the status), a
//! session of its own for a child (CLONE), the buffer of a client, the copy of
//! the bytes of a package that are fed, and the start and the result of the
//! changes of the store (INSTALL_BEGIN and the rest, which are long operations
//! with TAKE). The worker thread (`worker.rs`, `jobs.rs`, level 30) reads the store
//! from the disk, receives and checks the packages, makes the transactions, attaches
//! and detaches the layers of the file service and takes all the long calls, so the
//! main thread never waits for them. A change asks for UID 0 of the process service
//! (Vouch). The packages of the boot image are read here, before the service registers.

#![no_std]
#![no_main]

mod jobs;
mod shared;
mod worker;

use abi::{Access, Error, Rights, Source};
use core::sync::atomic::Ordering::{Acquire, Release};
use pkgd::packages::Entry;
use pkgd::receipts::{check_feed, orphan_drops_group};
use pkgd::store::{self, PACKAGES};
use proto_pkg::{
    BEGIN_WORLD, BUFFER_SIZE, CELL_BYTES, COMMIT_END, Feed, INFO_MAX, LIST_MAX, Method,
    STATUS_DAMAGED, STATUS_READ_ONLY, STATUS_STARTING, Stat, VERSION, code, read_begin,
    read_commit, read_info, read_remove, read_serial, read_take, read_word,
};
use proto_wire::clones::Clones;
use proto_wire::{Status, long};
use rt::handle::{Channel, Memory, Outgoing, Process};
use rt::service::{
    Answer, Config, Heartbeat, LongOps, LongSession, Notice, Request, Service, Session,
};
use rt::{Handle, sys};
use shared::*;

rt::entry!(main);

/// The sum of the longest times the last report named.
#[cfg(feature = "steps")]
static LAST_WORK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where the service maps the boot image.
const IMAGE_AT: usize = 0x50_0000_0000;
/// The sessions the loop keeps, and the clones of them at most.
/// A session for each of the 255 records of the process service, one more for each fork in
/// flight and the services beside it: the number the neighbours (`clock`, `entropy`, `pipe`,
/// `tty`) are sized to, since every process of the shell has a session here. A session holds
/// no handle of the service's own (the quota of 16,896 pages pays for its slot), so the
/// record's 512 handles hold the buffers, the layers and the objects of 64 packages with room
/// over.
const SESSIONS: usize = 320;
const _: () = assert!(
    SESSIONS >= 255 + 64 && CLONES >= 255,
    "a session for each process and its clone"
);
const CLONES: usize = 320;
/// The long operations at once: one change of the store at a time.
const OPERATIONS: usize = 4;
const OWN: u64 = 1 << 63;

/// The codes of a start that failed.
const NO_START_DATA: u64 = 1;
const NOT_CONNECTED: u64 = 2;
const NOT_REGISTERED: u64 = 3;
const STOPPED: u64 = 5;

fn main(_: u64) -> u64 {
    BEGAN.store(rt::time::now(), Release);
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
    // The channel the worker waits on for a job, and the copy that kicks it.
    let Ok(jobs) = sys::channel_create(worker::LEVEL) else {
        return NOT_REGISTERED;
    };
    let Ok(kick) = sys::handle_label(&jobs, Rights::NOTIFY, LABEL_KICK, worker::LEVEL) else {
        return NOT_REGISTERED;
    };
    // The raw handles the worker uses stay alive for the life of the process.
    for (i, raw) in [
        (worker::PROCESS, s.process.raw()),
        (worker::BLK_SESSION, blk.into_raw()),
        (worker::LAYERS_SESSION, layers.into_raw()),
        (worker::MAIN_CHANNEL, channel.raw()),
        (worker::WAKE, done.into_raw()),
        (worker::JOBS, jobs.into_raw()),
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
        parent: Handle::borrowed(s.parent.raw()),
        notary: None,
        clones: Clones::new(),
        channel: Handle::borrowed(channel.raw()),
        level,
        buffers: [None; BUFFERS],
        stale: [false; BUFFERS],
        kick,
        ops: LongOps::new(),
        pending: None,
        rx: None,
        ready: false,
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

/// What a session keeps: the place of its buffer, if it gave one, and its long operations.
#[derive(Default)]
struct Sess {
    buffer: Option<u8>,
    long: LongSession,
}

/// The receipt being fed, as the main thread knows it: the session that holds it, its
/// number, the place of its object and its size.
#[derive(Clone, Copy)]
struct Rx {
    owner: u64,
    number: u32,
    slot: usize,
    size: u64,
}

struct Pkgd {
    /// READY went to init (once the start of the worker is over, in the
    /// store's good state or not).
    ready: bool,
    process: core::mem::ManuallyDrop<Handle<Process>>,
    channel: core::mem::ManuallyDrop<Handle<Channel>>,
    parent: core::mem::ManuallyDrop<Handle<Channel>>,
    /// The notary session with the process service, asked of init at the first use.
    notary: Option<Handle<Channel>>,
    clones: Clones<CLONES>,
    level: u8,
    /// The label of the session whose buffer is mapped at each place.
    buffers: [Option<u64>; BUFFERS],
    /// The buffer of a session that went while a job might read it: unmapped when the job is done.
    stale: [bool; BUFFERS],
    /// A copy of the worker's channel that wakes it.
    kick: Handle<Channel>,
    ops: LongOps<OPERATIONS>,
    /// The session and key of the long operation whose job the worker has.
    pending: Option<(u64, u64)>,
    rx: Option<Rx>,
}

fn answer(status: Status) -> Answer {
    Answer::Status(status)
}

fn refuse(c: u32) -> Answer {
    Answer::Status(code(c))
}

/// The count a read starts from, or the BUSY it answers while the worker changes the state
/// (`pkgd::seq`): a read ends by checking the count again, and answers BUSY when it moved.
fn start_read() -> Result<u32, Answer> {
    SEQ.begin().ok_or_else(|| refuse(proto_pkg::BUSY))
}

fn end_read(start: u32, answer: Answer) -> Answer {
    if SEQ.unchanged(start) {
        answer
    } else {
        refuse(proto_pkg::BUSY)
    }
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
        let start = match start_read() {
            Ok(start) => start,
            Err(busy) => return busy,
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
        end_read(start, Answer::Reply(Outgoing::new()))
    }

    fn info(&self, r: &mut Request<'_>) -> Answer {
        let Ok((name, offset)) = read_info(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        let start = match start_read() {
            Ok(start) => start,
            Err(busy) => return busy,
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
        // The entry is not held past this step: the bytes are in the reply, and a change
        // that came meanwhile throws the reply away.
        end_read(start, Answer::Reply(Outgoing::new()))
    }

    fn serial(&self, r: &mut Request<'_>) -> Answer {
        let Ok((repo, _)) = proto_pkg::read_serial(r.body(), false) else {
            return Answer::Status(Status::BadSize);
        };
        if STARTING.load(Acquire) {
            return Answer::Status(code(proto_pkg::BUSY));
        }
        let start = match start_read() {
            Ok(start) => start,
            Err(busy) => return busy,
        };
        // SAFETY: the start is over; a change that comes while this reads is seen by the check
        // at the end, and the copy of the number is all that is kept.
        let table = unsafe { &*TABLE.get() };
        let serial = table
            .find_repo(repo)
            .and_then(|i| table.repo(i))
            .map_or(0, |(_, s)| s);
        let w = r.reply();
        if w.u32(0).and_then(|()| w.u64(serial)).is_err() {
            return Answer::Status(Status::BadSize);
        }
        end_read(start, Answer::Reply(Outgoing::new()))
    }

    fn status(&self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let start = match start_read() {
            Ok(start) => start,
            Err(busy) => return busy,
        };
        let mut flags = 0;
        for (on, bit) in [
            (DAMAGED.load(Acquire), STATUS_DAMAGED),
            (READ_ONLY.load(Acquire), STATUS_READ_ONLY),
            (STARTING.load(Acquire), STATUS_STARTING),
            (NO_STORE.load(Acquire), proto_pkg::STATUS_NO_STORE),
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
        end_read(start, Answer::Reply(Outgoing::new()))
    }

    /// BUFFER: the client's object, four cells, mapped for the session's life. A second handle,
    /// the identity session of the process, lets the service ask the process service who the
    /// caller is (Vouch): the superuser's session may take any place, any other the places
    /// after the `RESERVED` first ones (BUSY when they are all in use).
    fn give_buffer(&mut self, s: &mut Session<Sess, 0>, r: &mut Request<'_>) -> Answer {
        let Ok(size) = read_word(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        if size != BUFFER_SIZE || !(1..=2).contains(&r.handles.len()) {
            return Answer::Status(Status::BadSize);
        }
        let with_identity = r.handles.len() == 2;
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
        let identity = with_identity
            .then(|| r.handles.take::<Channel>(1).ok())
            .flatten();
        let superuser = identity.and_then(|channel| self.vouch(channel)) == Some(0);
        let from = if superuser { 0 } else { RESERVED };
        let Some(place) = (from..BUFFERS).find(|&p| self.buffers[p].is_none()) else {
            return Answer::Status(code(proto_pkg::BUSY));
        };
        let mapped = sys::mem_map(
            &self.process,
            &object,
            0,
            u64::from(size),
            buffer_at(place),
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
        let start = match start_read() {
            Ok(start) => start,
            Err(busy) => return busy,
        };
        let len = SETTINGS_LEN.load(Acquire);
        let from = (offset as usize).min(len);
        let n = (len - from).min(CELL_BYTES as usize);
        // SAFETY: a change that comes while this copies is seen by the check below, which
        // throws the copy away; the cell is the client's, written raw.
        unsafe {
            let blob = (*SETTINGS.get()).as_ptr().add(from);
            core::ptr::copy_nonoverlapping(blob, buffer_at(usize::from(place)) as *mut u8, n);
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
        end_read(start, Answer::Reply(Outgoing::new()))
    }

    /// Wakes the worker.
    fn wake(&self) {
        let _ = sys::notify(&self.kick, 1);
    }

    /// The effective user of the process whose identity session the request brought, as the
    /// process service vouches for it; None without a session or when the service refuses.
    fn vouch(&mut self, identity: Handle<Channel>) -> Option<u32> {
        if self.notary.is_none() {
            self.notary = rt::service::connect(&self.parent, "posix").ok();
        }
        let notary = self.notary.as_ref()?;
        let request = proto_process::Method::Vouch.header().bytes();
        let reply = sys::send_handles(notary, &request, [identity.erase()]).ok()?;
        let mut buffer = [0; abi::MESSAGE_MAX];
        proto_process::WhoReply::read(reply.bytes(&mut buffer))
            .ok()
            .map(|who| who.credentials.euid)
    }

    /// The gate of a change of the store: the identity session of the request is that of
    /// the superuser (NOT_ALLOWED otherwise, and without a session or when the process
    /// service refuses), the store is read, it can be written, and the device flushes.
    fn gate(&mut self, r: &mut Request<'_>) -> Result<(), Answer> {
        let identity = (r.handles.len() == 1)
            .then(|| r.handles.take::<Channel>(0).ok())
            .flatten();
        let allowed = identity.and_then(|channel| self.vouch(channel)) == Some(0);
        if !allowed {
            return Err(refuse(proto_pkg::NOT_ALLOWED));
        }
        if STARTING.load(Acquire) {
            return Err(refuse(proto_pkg::BUSY));
        }
        if NO_STORE.load(Acquire) {
            return Err(refuse(proto_pkg::IO));
        }
        if DAMAGED.load(Acquire) {
            return Err(refuse(proto_pkg::DAMAGED));
        }
        if READ_ONLY.load(Acquire) {
            return Err(refuse(proto_pkg::NO_FLUSH));
        }
        Ok(())
    }

    /// Whether the worker can take a job.
    fn job_free(&self) -> bool {
        JOB_STATE.load(Acquire) == IDLE && self.pending.is_none()
    }

    /// The job in `JOB` goes to the worker as a long operation of the session: WAIT k.
    fn give(&mut self, s: &mut Session<Sess, 0>, r: &mut Request<'_>) -> Answer {
        let label = r.label();
        let key = match self.ops.start(&mut s.data.long, label) {
            Ok(key) => key,
            Err(error) => return answer(Status::Kernel(error)),
        };
        self.pending = Some((label, key));
        JOB_STATE.store(PENDING, Release);
        self.wake();
        long_answer(r, long::Reply::Wait(key))
    }

    /// The job that is in `JOB`, made ready by `fill`, for a change of the store that is not
    /// an installation: no group of another session or of this one is open.
    fn change(
        &mut self,
        s: &mut Session<Sess, 0>,
        r: &mut Request<'_>,
        fill: impl FnOnce(&mut JobArgs) -> Result<(), Answer>,
    ) -> Answer {
        if let Err(refused) = self.gate(r) {
            return refused;
        }
        if !self.job_free() || GROUP_OWNER.load(Acquire) != 0 {
            return refuse(proto_pkg::BUSY);
        }
        // SAFETY: the job cell is the main thread's while the state is IDLE.
        let job = unsafe { &mut *JOB.get() };
        *job = JobArgs::EMPTY;
        job.owner = r.label();
        if let Err(refused) = fill(job) {
            return refused;
        }
        self.give(s, r)
    }

    /// INSTALL_BEGIN: the index's record, the repository and the flags; the number of the
    /// receipt comes with the result of the long operation.
    fn install_begin(&mut self, s: &mut Session<Sess, 0>, r: &mut Request<'_>) -> Answer {
        let begin = match read_begin(r.body()) {
            Ok(begin) => begin,
            Err(status) => return answer(status),
        };
        if let Err(refused) = self.gate(r) {
            return refused;
        }
        // A package of the boot image is the image's, whatever the index says.
        // SAFETY: the image entries were filled before the loop began.
        if pkgd::packages::in_image(unsafe { &*IMAGE_ENTRIES.get() }, begin.name) {
            return refuse(proto_pkg::IN_IMAGE);
        }
        let label = r.label();
        let owner = GROUP_OWNER.load(Acquire);
        if !self.job_free() || self.rx.is_some() || (owner != 0 && owner != label) {
            return refuse(proto_pkg::BUSY);
        }
        let (Some(name), Some(version), Some(repo)) = (
            store::to_field(begin.name),
            store::to_field(begin.version),
            store::to_field(begin.repository),
        ) else {
            return refuse(proto_pkg::INVALID);
        };
        // SAFETY: the job cell is the main thread's while the state is IDLE.
        let job = unsafe { &mut *JOB.get() };
        *job = JobArgs::EMPTY;
        job.kind = JobKind::Begin;
        job.owner = label;
        job.size = begin.size;
        job.sha256 = begin.sha256;
        job.world = begin.flags & BEGIN_WORLD != 0;
        job.name = name;
        job.version = version;
        job.repo = repo;
        self.give(s, r)
    }

    /// FEED: the bytes in a cell of the buffer are copied into the object of the receipt, at
    /// the end of what came, and the worker hashes and writes them. Past the size of the
    /// package the receipt goes (TOO_LONG).
    fn feed(&mut self, s: &mut Session<Sess, 0>, r: &mut Request<'_>) -> Answer {
        let feed = match Feed::read(r.body()) {
            Ok(feed) => feed,
            Err(status) => return answer(status),
        };
        let Some(rx) = self
            .rx
            .filter(|rx| rx.owner == r.label() && rx.number == feed.receipt)
        else {
            return refuse(proto_pkg::INVALID);
        };
        let Some(place) = s.data.buffer else {
            return refuse(proto_pkg::NO_BUFFER);
        };
        let fed = FED.load(Acquire);
        if check_feed(rx.size, fed, feed.len).is_err() {
            self.drop_receipt();
            return refuse(proto_pkg::TOO_LONG);
        }
        // SAFETY: the cell lies in the client's buffer, mapped for its session; the window
        // of the object is mapped for `size` bytes and `fed + len` is not past it.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (buffer_at(usize::from(place)) + feed.cell as usize * CELL_BYTES as usize)
                    as *const u8,
                (window(rx.slot) + fed as usize) as *mut u8,
                feed.len as usize,
            )
        };
        FED.store(fed + u64::from(feed.len), Release);
        self.wake();
        Answer::Status(Status::Ok)
    }

    /// The receipt, with its group, goes: the worker drops them.
    fn drop_receipt(&mut self) {
        self.rx = None;
        CANCEL.store(true, Release);
        self.wake();
    }

    /// INSTALL_COMMIT: all of the package came; the worker checks it and, at the end of the
    /// group, makes the transaction.
    fn install_commit(&mut self, s: &mut Session<Sess, 0>, r: &mut Request<'_>) -> Answer {
        let Ok((number, flags)) = read_commit(r.body()) else {
            return answer(Status::BadSize);
        };
        let label = r.label();
        let Some(rx) = self
            .rx
            .filter(|rx| rx.owner == label && rx.number == number)
        else {
            return refuse(proto_pkg::INVALID);
        };
        if FED.load(Acquire) != rx.size {
            return refuse(proto_pkg::INVALID);
        }
        if !self.job_free() {
            return refuse(proto_pkg::BUSY);
        }
        // SAFETY: the job cell is the main thread's while the state is IDLE.
        let job = unsafe { &mut *JOB.get() };
        *job = JobArgs::EMPTY;
        job.kind = JobKind::Commit;
        job.owner = label;
        job.number = number;
        job.end = flags & COMMIT_END != 0;
        self.rx = None;
        self.give(s, r)
    }

    /// INSTALL_CANCEL: the receipt and the group go; the store is free once the worker has dropped
    /// them.
    fn install_cancel(&mut self, r: &mut Request<'_>) -> Answer {
        let Ok(number) = read_word(r.body()) else {
            return answer(Status::BadSize);
        };
        let label = r.label();
        let held = GROUP_OWNER.load(Acquire) == label;
        let named = self.rx.is_none_or(|rx| rx.number == number);
        if !held || !named {
            return refuse(proto_pkg::INVALID);
        }
        self.drop_receipt();
        Answer::Status(Status::Ok)
    }

    fn remove(&mut self, s: &mut Session<Sess, 0>, r: &mut Request<'_>) -> Answer {
        let mut names: [&[u8]; 8] = [&[]; 8];
        let count = match read_remove(r.body(), &mut names) {
            Ok(count) => count,
            Err(status) => return answer(status),
        };
        let mut fields = [[0; 64]; 8];
        for (field, name) in fields.iter_mut().zip(&names).take(count) {
            let Some(made) = store::to_field(name) else {
                return refuse(proto_pkg::INVALID);
            };
            *field = made;
        }
        self.change(s, r, |job| {
            job.kind = JobKind::Remove;
            job.names = fields;
            job.count = count;
            Ok(())
        })
    }

    fn serial_set(&mut self, s: &mut Session<Sess, 0>, r: &mut Request<'_>) -> Answer {
        let (repository, serial) = match read_serial(r.body(), true) {
            Ok(got) => got,
            Err(status) => return answer(status),
        };
        let Some(field) = store::to_field(repository) else {
            return refuse(proto_pkg::INVALID);
        };
        self.change(s, r, |job| {
            job.kind = JobKind::SerialSet;
            job.repo = field;
            job.serial = serial;
            Ok(())
        })
    }

    /// SETTINGS_SET and REVOKED_SET: the blob or the list is `len` bytes in the buffer.
    fn blob_set(
        &mut self,
        s: &mut Session<Sess, 0>,
        r: &mut Request<'_>,
        kind: JobKind,
        most: usize,
    ) -> Answer {
        let Ok(len) = read_word(r.body()) else {
            return answer(Status::BadSize);
        };
        let Some(place) = s.data.buffer else {
            return refuse(proto_pkg::NO_BUFFER);
        };
        if len == 0 || len as usize > most {
            return refuse(proto_pkg::INVALID);
        }
        self.change(s, r, |job| {
            job.kind = kind;
            job.len = len as usize;
            job.buffer = usize::from(place);
            Ok(())
        })
    }

    /// The job the worker finished: the receipt of a package that began is the session's, and
    /// the client whose operation it was is told. A job whose session went is over.
    fn settle(&mut self) {
        if JOB_STATE.load(Acquire) != DONE {
            return;
        }
        // SAFETY: the worker is done with the cell until the state is IDLE again.
        let kind = unsafe { (*JOB.get()).kind };
        match self.pending {
            Some((label, key)) => {
                // SAFETY: as above.
                let (owner, size) = unsafe { ((*JOB.get()).owner, (*JOB.get()).size) };
                if kind == JobKind::Begin && JOB_CODE.load(Acquire) == 0 && self.rx.is_none() {
                    self.rx = Some(Rx {
                        owner,
                        number: JOB_VALUE.load(Acquire),
                        slot: JOB_SLOT.load(Acquire) as usize,
                        size,
                    });
                }
                self.ops.tell(label, key);
            }
            None => {
                // A begin that finished for a session that went opened a group no one owns.
                if orphan_drops_group(kind == JobKind::Begin, JOB_CODE.load(Acquire)) {
                    CANCEL.store(true, Release);
                    self.wake();
                }
                JOB_STATE.store(IDLE, Release);
                self.release_stale();
            }
        }
    }

    /// READY to init: the start is over (the probes of the wait change it: `no-ready` says
    /// nothing, `exit-before-ready` ends the process).
    fn say_ready(&mut self) {
        #[cfg(feature = "exit-before-ready")]
        sys::process_exit(7);
        #[cfg(not(any(feature = "no-ready", feature = "exit-before-ready")))]
        if let Err(why) = rt::service::ready(&self.parent) {
            rt::println!("pkgd: READY refused: {why:?}");
        }
    }

    /// The buffers of sessions that went while the worker might read them go now that it
    /// does not.
    fn release_stale(&mut self) {
        if JOB_STATE.load(Acquire) != IDLE {
            return;
        }
        for place in 0..BUFFERS {
            if self.stale[place] {
                // SAFETY: nothing of the service's own lies in the buffer's range.
                let gone = unsafe {
                    sys::mem_unmap(&self.process, buffer_at(place), u64::from(BUFFER_SIZE))
                };
                if gone.is_ok() {
                    self.buffers[place] = None;
                    self.stale[place] = false;
                }
            }
        }
    }

    /// TAKE: the result of the long operation once the worker has done it, or ARMED (keeping
    /// the handle with NOTIFY the first TAKE brings).
    fn take(&mut self, s: &mut Session<Sess, 0>, r: &mut Request<'_>) -> Answer {
        let Ok(key) = read_take(r.body()) else {
            return answer(Status::BadSize);
        };
        let label = r.label();
        if !self.ops.waits(label, key) {
            return answer(Status::Kernel(Error::BadState));
        }
        if self.pending == Some((label, key)) && JOB_STATE.load(Acquire) == DONE {
            // The receipt of a begin is the session's before the client has its number.
            self.settle();
            let c = JOB_CODE.load(Acquire);
            let value = JOB_VALUE.load(Acquire);
            // SAFETY: the worker is done with the cell.
            let kind = unsafe { (*JOB.get()).kind };
            JOB_STATE.store(IDLE, Release);
            self.pending = None;
            self.ops.finish(&mut s.data.long, label, key);
            self.release_stale();
            if c != 0 {
                return refuse(c);
            }
            let bytes = value.to_le_bytes();
            let result: &[u8] = if kind == JobKind::Begin { &bytes } else { &[] };
            return long_answer(r, long::Reply::Ready(result));
        }
        if !r.handles.is_empty() {
            match r.handles.take::<Channel>(0) {
                Ok(notify) => {
                    let _ = self.ops.arm(label, key, notify);
                }
                Err(error) => return answer(Status::Kernel(error)),
            }
        }
        long_answer(r, long::Reply::Armed)
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

/// The reply of a long operation, through the request's reply buffer.
fn long_answer(r: &mut Request<'_>, reply: long::Reply<'_>) -> Answer {
    match reply.write(r.reply()) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}

const METHODS: &[u16] = &[
    Method::List.number(),
    Method::Info.number(),
    Method::InstallBegin.number(),
    Method::Feed.number(),
    Method::InstallCommit.number(),
    Method::InstallCancel.number(),
    Method::Remove.number(),
    Method::SettingsGet.number(),
    Method::SettingsSet.number(),
    Method::Serial.number(),
    Method::SerialSet.number(),
    Method::Clone.number(),
    Method::RevokedSet.number(),
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
            Some(Method::InstallBegin) => self.install_begin(s, r),
            Some(Method::Feed) => self.feed(s, r),
            Some(Method::InstallCommit) => self.install_commit(s, r),
            Some(Method::InstallCancel) => self.install_cancel(r),
            Some(Method::Remove) => self.remove(s, r),
            Some(Method::SettingsGet) => self.settings(s, r),
            Some(Method::SettingsSet) => self.blob_set(s, r, JobKind::SettingsSet, 64 * 1024),
            Some(Method::Serial) => self.serial(r),
            Some(Method::SerialSet) => self.serial_set(s, r),
            Some(Method::Clone) => self.clone_session(r),
            Some(Method::RevokedSet) => self.blob_set(s, r, JobKind::RevokedSet, REVOKED_FILE_MAX),
            Some(Method::Take) => self.take(s, r),
            Some(Method::Buffer) => self.give_buffer(s, r),
            Some(Method::Status) => self.status(r),
            None => Answer::Status(Status::UnknownMethod),
        }
    }

    fn gone(&mut self, s: &mut Session<Sess, 0>) {
        let label = s.label();
        self.ops.gone(&mut s.data.long);
        let running = self.pending.is_some_and(|(l, _)| l == label);
        if running {
            // The job goes on; its result has no one to tell and its buffer stays until it ends.
            self.pending = None;
        }
        if self.rx.is_some_and(|rx| rx.owner == label) {
            self.rx = None;
        }
        // The group of the session, or the job that is to open one, is dropped.
        if GROUP_OWNER.load(Acquire) == label || running {
            CANCEL.store(true, Release);
            self.wake();
        }
        if let Some(place) = s.data.buffer.take() {
            self.stale[usize::from(place)] = true;
        }
        // A job that is done and has no one to take it is idle again.
        self.settle();
        self.release_stale();
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
        if n.source == Source::Session && n.label == LABEL_DONE {
            // The start is over (the worker cleared STARTING, whatever the
            // store is: a damaged disk or none is served as such): init may
            // start the records that wait for the service (spec 5, section 4).
            if !self.ready && !STARTING.load(Acquire) {
                self.ready = true;
                self.say_ready();
            }
            self.settle();
            #[cfg(feature = "steps")]
            {
                // The line again only when one of the longest times grew.
                let times = [&SHA_TICKS, &PARSE_TICKS, &SIGN_TICKS, &MANIFEST_TICKS]
                    .map(|t| t.load(Acquire));
                if times.iter().sum::<u64>() != LAST_WORK.swap(times.iter().sum(), Release) {
                    rt::println!(
                        "pkgd: work sha16k={} parse={} ed25519={} manifest16k={}",
                        times[0],
                        times[1],
                        times[2],
                        times[3]
                    );
                }
            }
        }
    }
}
