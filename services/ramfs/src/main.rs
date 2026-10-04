// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Single-threaded RAM file service. Each client session has its own fds.
//! The service opens a program's file for a loader (OPEN_EXEC, spec 2,
//! 3.2; 5c) through the session of the loaders alone, with the process
//! service vouching for the loader's identity through the service's
//! notary session, and gives a client a session for its child (CLONE).

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use proto_fs::{MAX_READ, MAX_WRITE, Method, VERSION};
use proto_init::ServiceArgs;
use proto_wire::Status;
use proto_wire::clones::Clones;
use ramfs::authority::{Binding, Identity};
use ramfs::resolve::{Progress, Resolve};
use ramfs::storage::{NONE, Root, Token};
use ramfs::tree::{self, Index};
use ramfs::{Exec, SET_GID, SET_UID};
use ramfs::{Fds, Ram};
use rt::abi::{Access, Rights};
use rt::handle::{Channel, Handle, Memory, Outgoing, Resource};
use rt::service::{Answer, Config, Heartbeat, Request, Service, Session};
use rt::sys;

rt::entry!(main);

const METHODS: &[u16] = proto_fs::METHODS;
/// The sessions: one place the image sessions share (they hold nothing),
/// then the clients', with room for the 255 records of the process
/// service and the services beside them. The table lies in `.bss`
/// (`SESSION_TABLE`).
const SESSIONS: usize = 320;
/// Where the service maps the boot image, read-only, for as long as it
/// lives: the files of its table are read from there.
const IMAGE: usize = 0x50_0000_0000;
/// Where the service maps the object of a READ_INTO while it fills it.
const INTO: usize = 0x58_0000_0000;

/// The index of the table of the boot image, in the service's `.bss`.
struct Table(UnsafeCell<Index>);
// SAFETY: only the main thread reaches it, once (`image_tree`).
unsafe impl Sync for Table {}
static TABLE: Table = Table(UnsafeCell::new(Index::new()));
struct StorageBss(UnsafeCell<core::mem::MaybeUninit<ramfs::storage::State>>);
// SAFETY: only the service thread accesses the storage tables.
unsafe impl Sync for StorageBss {}
static STORAGE: StorageBss = StorageBss(UnsafeCell::new(core::mem::MaybeUninit::uninit()));

/// The files of the boot image's table: the image is mapped from the
/// start data (`bootimage`, given to this record by init), and the table is
/// read. An image with no table, or no image, leaves the fixed tree alone.
fn image_tree(start: &mut rt::startup::Startup) -> Option<tree::Tree<'static>> {
    let image = start.take::<Memory>("bootimage").ok()?;
    let size = sys::memory_info(&image).ok()?.size;
    sys::mem_map(&start.process, &image, 0, size, IMAGE, Access::Read).ok()?;
    // SAFETY: the image stays mapped, read-only, for the life of the process.
    let bytes = unsafe { core::slice::from_raw_parts(IMAGE as *const u8, size as usize) };
    // SAFETY: only the main thread reaches TABLE, here once.
    let index = unsafe { &mut *TABLE.0.get() };
    match tree::load(bytes, index) {
        Ok(tree) => Some(tree),
        Err(tree::Error::Missing) => None,
        Err(error) => {
            rt::println!("ramfs: the table of the boot image is refused: {error:?}");
            None
        }
    }
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let now = rt::time::ticks_to_ns(rt::time::now());
    let tree = image_tree(&mut start);
    let Ok(backing) = sys::mem_create((ramfs::storage::PAGES * ramfs::storage::PAGE) as u64) else {
        return 5;
    };
    const DATA: usize = 0x54_0000_0000;
    let size = (ramfs::storage::PAGES * ramfs::storage::PAGE) as u64;
    if sys::mem_map(&start.process, &backing, 0, size, DATA, Access::ReadWrite).is_err() {
        return 6;
    }
    // SAFETY: the sole service thread owns this fixed data mapping and STORAGE.
    let data = unsafe { core::slice::from_raw_parts_mut(DATA as *mut u8, size as usize) };
    let state = unsafe {
        let pointer = (*STORAGE.0.get()).as_mut_ptr();
        // State's integer, boolean and Option<Account> fields admit zero values.
        pointer.write_bytes(0, 1);
        &mut *pointer
    };
    state.initialize();
    let ram = Ram::with_storage(now, state, data, tree);
    let args = ServiceArgs::read(start.args()).ok();
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return 2;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 3;
    }
    let heartbeat = Heartbeat {
        to: &start.parent,
        period_ns: args.map_or(0, |args| args.period_ns),
        priority: level,
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(heartbeat),
    };
    rt::println!(
        "ramfs: storage pages={} tables={} bytes",
        ramfs::storage::PAGES,
        core::mem::size_of::<ramfs::storage::State>()
            + core::mem::size_of::<Tables>()
            + core::mem::size_of::<Index>()
    );
    rt::println!("ramfs: ready");
    // SAFETY: only the main thread reaches TABLES, here once.
    let tables = unsafe { &mut *TABLES.0.get() };
    let mut fs = Fs {
        ram,
        process: Handle::borrowed(start.process.raw()),
        channel: Handle::borrowed(channel.raw()),
        parent: Handle::borrowed(start.parent.raw()),
        notary: None,
        given: 0,
        level,
        births: &mut tables.births,
        clones: &mut tables.clones,
        identities: &mut tables.identities,
        jobs: &mut tables.jobs,
        job_generations: &mut tables.job_generations,
        generations: None,
        maintenance_cursor: 1,
        job_cursor: 0,
        audit_remaining: 0,
        next_audit_ns: 0,
    };
    #[cfg(feature = "steps")]
    rt::service::report_steps(2);
    let _ = rt::service::run_in(&channel, &mut fs, config, &mut tables.sessions);
    4
}

struct Fs {
    ram: Ram<'static>,
    /// The service's own process, to map the object of a READ_INTO in.
    process: ManuallyDrop<Handle<rt::handle::Process>>,
    /// The service's channel, which its own sessions are copies of, and
    /// its connection to init, which gives the notary session.
    channel: ManuallyDrop<Handle<Channel>>,
    parent: ManuallyDrop<Handle<Channel>>,
    /// The notary session with the process service (init's VOUCHERS),
    /// asked for at the first OPEN_EXEC.
    notary: Option<Handle<Channel>>,
    /// The sessions the service gave itself so far.
    given: u64,
    level: u8,
    /// The descriptors of the sessions Clone made that sent nothing yet,
    /// by their labels: the session's first request takes them, and the
    /// end of its last copy closes them.
    births: &'static mut [Option<(u64, Fds)>; BIRTHS],
    /// The clones alive, bounded for each client and in all.
    clones: &'static mut Clones<CLONES>,
    identities: &'static mut [Option<IdentityChannel>; SESSIONS],
    jobs: &'static mut [Option<ResolveJob>; ramfs::storage::PREPARATIONS],
    job_generations: &'static mut [u64; ramfs::storage::PREPARATIONS],
    generations: Option<Handle<Memory>>,
    maintenance_cursor: usize,
    job_cursor: usize,
    audit_remaining: usize,
    next_audit_ns: u64,
}

/// The clones the service keeps alive at most: one for each record of the
/// process service and room beside them.
const CLONES: usize = 320;

/// Clones whose sessions sent nothing yet, at most: past them, Clone is
/// LIMIT_REACHED. A child that never touches a file keeps its birth, so
/// there is one for each record of the process service.
const BIRTHS: usize = 256;

/// The tables of the sessions and of the births, in `.bss`: too big for
/// the service's stack.
struct IdentityChannel {
    label: u64,
    channel: Handle<Channel>,
}
struct ResolveJob {
    id: u64,
    owner: u64,
    root: u16,
    real: bool,
    resolver: Resolve,
    second: Option<Resolve>,
    loader: Option<(proto_process::WhoReply, Handle<Channel>)>,
}
struct Tables {
    clones: Clones<CLONES>,
    sessions: [Option<Session<Fds, 0>>; SESSIONS],
    births: [Option<(u64, Fds)>; BIRTHS],
    identities: [Option<IdentityChannel>; SESSIONS],
    jobs: [Option<ResolveJob>; ramfs::storage::PREPARATIONS],
    job_generations: [u64; ramfs::storage::PREPARATIONS],
}
struct Bss(UnsafeCell<Tables>);
// SAFETY: only the main thread reaches it, once (`main`).
unsafe impl Sync for Bss {}
static TABLES: Bss = Bss(UnsafeCell::new(Tables {
    clones: Clones::new(),
    sessions: [const { None }; SESSIONS],
    births: [None; BIRTHS],
    identities: [const { None }; SESSIONS],
    jobs: [const { None }; ramfs::storage::PREPARATIONS],
    job_generations: [0; ramfs::storage::PREPARATIONS],
}));

impl Fs {
    /// A Loader that abandoned a job cannot keep its base or expenditure alive.
    fn cleanup_job_step(&mut self) -> bool {
        let i = self.job_cursor;
        self.job_cursor = (i + 1) % self.jobs.len();
        let Some(job) = self.jobs[i].take() else {
            return false;
        };
        let valid = if let Some((who, identity)) = &job.loader {
            self.vouch(identity).is_some_and(|fresh| {
                fresh.pid == who.pid
                    && fresh.index == who.index
                    && fresh.image == who.image
                    && fresh.root == who.root
                    && fresh.loader == who.loader
            })
        } else {
            true
        };
        let (id, owner) = (job.id, job.owner);
        self.jobs[i] = Some(job);
        if !valid {
            self.cancel_job(id, owner, None);
            return true;
        }
        false
    }
    /// A dead or superseded authority releases one retained reference per pass.
    fn cleanup_step(&mut self, fds: &mut Fds, label: u64) -> bool {
        if fds.binding.snapshot().is_some() {
            let _ = self.authenticate(fds, label);
        }
        if !matches!(fds.binding, Binding::Cleanup) {
            return false;
        }
        if let Some(id) = fds.resolvers.iter().copied().find(|&id| id != 0) {
            self.cancel_job(id, label, Some(fds));
            return true;
        }
        if self.ram.release_step(fds) {
            return true;
        }
        self.drop_identity(fds);
        false
    }
    fn notary(&mut self) -> Option<&Handle<Channel>> {
        if self.notary.is_none() {
            self.notary = rt::service::connect(&self.parent, "posix").ok();
        }
        self.notary.as_ref()
    }

    /// A session of the service's own with `label` for a client.
    fn session(&mut self, label: u64) -> Result<Handle<Channel>, rt::abi::Error> {
        self.given += 1;
        sys::handle_label(
            &self.channel,
            Rights::SEND | Rights::TRANSFER,
            label,
            self.level,
        )
    }

    /// OPEN_EXEC of `path` for the loader whose identity `r` brings, from
    /// the session of the loaders (condition O1, condition O3): the process service vouches
    /// for it, the path resolves for the effective IDs of the record it
    /// loads in this one step, the set-ID bits go to the process service
    /// before the reply, and the reply brings the image session.
    fn open_exec(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if !proto_fs::is_loaders(r.label()) || r.handles.len() != 1 {
            return status(proto_fs::PERMISSION);
        }
        let mut body = r.body();
        let (Ok(job), Ok(())) = (body.u64(), body.finish()) else {
            return Answer::Status(Status::BadSize);
        };
        if !self.loader_claim(job, r) {
            return status(proto_fs::PERMISSION);
        }
        let (token, who) = match self.proof(job, r.label(), None) {
            Ok((t, Some(w))) => (t, w),
            Ok(_) => return status(proto_fs::PERMISSION),
            Err(code) => return status(code),
        };
        let Some(loader) = who.loader else {
            return status(proto_fs::PERMISSION);
        };
        let pid = who.pid;
        let exec = match self
            .ram
            .exec_token(token, Identity::of(who.credentials, who.groups, false))
        {
            Ok(exec) => exec,
            Err(code) => {
                self.cancel_job(job, r.label(), Some(fds));
                return status(code);
            }
        };
        self.cancel_job(job, r.label(), Some(fds));
        if !self.tell_set_id(&exec, pid, loader) {
            return status(proto_fs::PERMISSION);
        }
        let label = proto_fs::image_label(self.given, exec.entry);
        match self.session(label) {
            Ok(session) => {
                if r.reply().u32(0).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply([session.erase()].into())
            }
            Err(e) => Answer::Status(Status::Kernel(e)),
        }
    }

    /// SetId for a file with a set-ID bit, through the notary session:
    /// whether the process service kept it, or the file has none.
    fn tell_set_id(&mut self, exec: &Exec, pid: u32, loader: proto_process::LoaderOf) -> bool {
        if exec.mode & (SET_UID | SET_GID) == 0 {
            return true;
        }
        let pick = |bit, id| {
            if exec.mode & bit != 0 {
                id
            } else {
                proto_process::NO_ID
            }
        };
        let set = proto_process::SetId {
            ticket: loader.ticket,
            pid,
            image: loader.image,
            uid: pick(SET_UID, exec.uid),
            gid: pick(SET_GID, exec.gid),
        };
        let mut w = proto_wire::Writer::new();
        if proto_process::Method::SetId.header().write(&mut w).is_err()
            || set.write(&mut w).is_err()
        {
            return false;
        }
        let Some(notary) = self.notary() else {
            return false;
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        sys::send(notary, w.as_bytes())
            .is_ok_and(|reply| reply.bytes(&mut buffer) == proto_wire::reply(Status::Ok))
    }

    /// A request through an image session for the file of `entry`:
    /// READ_AT, READ_INTO and INFO_FD of fd 0 alone.
    fn image(&mut self, entry: u16, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        match Method::from_number(r.method()) {
            Some(Method::ReadInto) => {
                let (Ok(fd), Ok(offset), Ok(count), Ok(at)) =
                    (body.u32(), body.u64(), body.u32(), body.u64())
                else {
                    return Answer::Status(Status::BadSize);
                };
                let rights = Rights::MAP_READ | Rights::MAP_WRITE;
                let writable = matches!(r.handles.info(0), Some((rt::abi::ObjectKind::Memory, got)) if got.contains(rights));
                let handles = r.handles.len();
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let Ok(memory) = r.handles.take::<Memory>(0) else {
                    return Answer::Status(Status::BadSize);
                };
                let size = sys::memory_info(&memory).map_or(0, |i| i.size);
                if !ramfs::read_into_valid(fd, count as usize, at, handles, writable, size) {
                    return Answer::Status(Status::BadSize);
                }
                match self.read_into(entry, offset, count as usize, &memory, at) {
                    Ok(n) => value(r, n as u32),
                    Err(answer) => answer,
                }
            }
            Some(Method::ReadAt) => {
                let (Ok(fd), Ok(offset), Ok(count)) = (body.u32(), body.u64(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() || fd != 0 || count as usize > MAX_READ {
                    return Answer::Status(Status::BadSize);
                }
                let mut bytes = [0; MAX_READ];
                match self
                    .ram
                    .image_read(entry, offset, &mut bytes[..count as usize])
                {
                    Ok(n) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(n as u32))
                            .and_then(|()| w.bytes(&bytes[..n]))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::InfoFd) => {
                if body.u32() != Ok(0) || body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.image_information(entry) {
                    Ok(info) => {
                        let w = r.reply();
                        if w.u32(0).and_then(|()| info.write(w)).is_err() {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            _ => status(proto_fs::PERMISSION),
        }
    }
}

impl Fs {
    /// READ_INTO: `count` bytes of the file of `entry` from `offset` into
    /// `memory` from `at`, through the window INTO of the service's own
    /// space, mapped for the copy alone: the count copied.
    fn read_into(
        &mut self,
        entry: u16,
        offset: u64,
        count: usize,
        memory: &Handle<Memory>,
        at: u64,
    ) -> Result<usize, Answer> {
        if count == 0 {
            return Ok(0);
        }
        let len = (count as u64).next_multiple_of(4096);
        sys::mem_map(&self.process, memory, at, len, INTO, Access::ReadWrite)
            .map_err(|e| Answer::Status(Status::Kernel(e)))?;
        // SAFETY: the window maps `len` bytes of the object, which only this
        // step touches until the unmap below.
        let out = unsafe { core::slice::from_raw_parts_mut(INTO as *mut u8, count) };
        let read = self.ram.image_read(entry, offset, out);
        // SAFETY: the mapping made above, which nothing uses now.
        let _ = unsafe { sys::mem_unmap(&self.process, INTO, len) };
        read.map_err(status)
    }
}

fn status(code: u32) -> Answer {
    Answer::Status(Status::from_code(code))
}

fn value(r: &mut Request<'_>, number: u32) -> Answer {
    let w = r.reply();
    if w.u32(0).and_then(|()| w.u32(number)).is_err() {
        return Answer::Status(Status::BadSize);
    }
    Answer::Reply(Outgoing::new())
}

impl Fs {
    /// CLONE with a list of descriptors of the session `fds` (count u32,
    /// then each u32): a session of the service's own label whose
    /// descriptors of the same numbers share their open descriptions;
    /// BAD_FD for a number of none, LIMIT_REACHED with BIRTHS clones that
    /// sent nothing yet.
    fn clone_session(&mut self, fds: &Fds, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let mut list = [0u32; 32];
        let count = body.u32().unwrap_or(0) as usize;
        if count > list.len() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        for fd in &mut list[..count] {
            let Ok(n) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            *fd = n;
        }
        if body.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let Some(free) = self.births.iter().position(Option::is_none) else {
            return Answer::Status(Status::Kernel(rt::abi::Error::LimitReached));
        };
        if self.clones.room(r.label()).is_err() {
            return Answer::Status(Status::Kernel(rt::abi::Error::LimitReached));
        }
        let mut child = match self.ram.clone_fds(fds, &list[..count]) {
            Ok(child) => child,
            Err(code) => return status(code),
        };
        if matches!(fds.binding, Binding::Boot) {
            child.binding = Binding::Boot;
        }
        let label = proto_fs::OWN | self.given;
        if let Some(who) = fds.binding.snapshot() {
            child.binding = Binding::Inherited(who);
            let identity = self.identities[fds.authority_index as usize]
                .as_ref()
                .and_then(|i| {
                    sys::handle_duplicate(
                        &i.channel,
                        Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER,
                    )
                    .ok()
                });
            let result = identity
                .ok_or(proto_fs::PERMISSION)
                .and_then(|identity| self.install_identity(&mut child, label, identity));
            if let Err(code) = result {
                self.ram.release(&mut child);
                return status(code);
            }
        }
        match self.session(label) {
            Ok(session) => {
                if r.reply().u32(0).is_err() {
                    self.drop_identity(&mut child);
                    self.ram.release(&mut child);
                    return Answer::Status(Status::BadSize);
                }
                self.births[free] = Some((label, child));
                let _ = self.clones.add(label, r.label());
                Answer::Reply([session.erase()].into())
            }
            Err(e) => {
                self.drop_identity(&mut child);
                self.ram.release(&mut child);
                Answer::Status(Status::Kernel(e))
            }
        }
    }
}

impl Service<0> for Fs {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    const PLACED: usize = 1;
    type Data = Fds;

    /// The client of `s` went: its descriptors close.
    fn gone(&mut self, s: &mut Session<Fds, 0>) {
        for id in s.data.resolvers {
            if id != 0 {
                self.cancel_job(id, s.label(), None);
            }
        }
        self.drop_identity(&mut s.data);
        self.ram.release(&mut s.data);
    }

    /// The last copy of a session Clone made went before it sent anything:
    /// the descriptors it was born with close.
    fn closed(&mut self, label: u64) {
        self.clones.gone(label);
        if let Some(birth) = self
            .births
            .iter_mut()
            .find(|b| b.is_some_and(|(l, _)| l == label))
            && let Some((_, mut fds)) = birth.take()
        {
            for id in fds.resolvers {
                if id != 0 {
                    self.cancel_job(id, label, None);
                }
            }
            self.drop_identity(&mut fds);
            self.ram.release(&mut fds);
        }
    }

    fn maintenance(&mut self, sessions: &mut [Option<Session<Fds, 0>>]) {
        let now = rt::time::ticks_to_ns(rt::time::now());
        if now >= self.next_audit_ns && self.audit_remaining == 0 {
            self.next_audit_ns = now.saturating_add(250_000_000);
            self.audit_remaining = SESSIONS + BIRTHS - 1;
        }
        let mut work = self.ram.storage.reclaim_step() | self.cleanup_job_step();
        let mut client_work = false;
        let i = self.maintenance_cursor;
        if i < SESSIONS {
            if let Some(s) = sessions.get_mut(i).and_then(Option::as_mut) {
                let label = s.label();
                client_work = self.cleanup_step(&mut s.data, label);
            }
        } else if let Some((label, mut fds)) = self.births[i - SESSIONS].take() {
            client_work = self.cleanup_step(&mut fds, label);
            self.births[i - SESSIONS] = Some((label, fds));
        }
        work |= client_work;
        if !client_work {
            self.maintenance_cursor = 1 + i % (SESSIONS + BIRTHS - 1);
            self.audit_remaining = self.audit_remaining.saturating_sub(1);
        }
        // A maintenance notification makes reclamation progress with no client request.
        if work || self.audit_remaining != 0 {
            let _ = sys::notify(&self.channel, 1);
        }
    }

    /// The image sessions share place 0: they hold nothing.
    fn place(&self, label: u64) -> Option<usize> {
        proto_fs::image_entry(label).map(|_| 0)
    }

    fn request(&mut self, s: &mut Session<Fds, 0>, r: &mut Request<'_>) -> Answer {
        if let Some(entry) = proto_fs::image_entry(r.label()) {
            return self.image(entry, r);
        }
        if !s.data.claimed {
            // The first request of a session Clone made takes its
            // descriptors.
            let label = r.label();
            if let Some(birth) = self
                .births
                .iter_mut()
                .find(|b| b.is_some_and(|(l, _)| l == label))
            {
                s.data = birth.take().expect("a birth").1;
            } else if r.label() & proto_fs::OWN != 0 && self.clones.client_of(r.label()).is_some() {
                // A Loader consumed this birth into a distinct label; surviving old copies
                // have cleanup authority only, regardless of a creator's retained handle.
                s.data.binding = Binding::Cleanup;
            }
            s.data.claimed = true;
        }
        if r.method() == Method::Bind as u16 {
            return self.bind(&mut s.data, r);
        }
        if r.method() == Method::BindPending as u16 {
            return self.bind_pending(r);
        }
        if matches!(
            Method::from_number(r.method()),
            Some(
                Method::ResolveStart
                    | Method::ResolveStep
                    | Method::ResolveCancel
                    | Method::ResolveSecond
            )
        ) {
            return self.resolve_request(&mut s.data, r);
        }
        if r.method() == Method::OpenExec as u16 {
            return self.open_exec(&mut s.data, r);
        }
        if r.method() == Method::VerifySession as u16 {
            return self.verify_clone(&mut s.data, r);
        }
        // The loader root also verifies the origin of inherited sessions.
        if proto_fs::is_loaders(r.label()) {
            return status(proto_fs::PERMISSION);
        }
        let cleanup = matches!(
            Method::from_number(r.method()),
            Some(Method::Close | Method::ResolveCancel)
        );
        if !self.authenticate(&mut s.data, r.label()) && !cleanup {
            return status(proto_fs::PERMISSION);
        }
        let mut body = r.body();
        match Method::from_number(r.method()) {
            Some(Method::Clone) => self.clone_session(&s.data, r),
            Some(
                Method::OpenExec
                | Method::ReadInto
                | Method::VerifySession
                | Method::Bind
                | Method::BindPending
                | Method::ResolveStart
                | Method::ResolveStep
                | Method::ResolveCancel
                | Method::ResolveSecond,
            ) => status(proto_fs::PERMISSION),
            Some(Method::Open) => {
                let Ok(flags) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                let (Ok(job), Ok(())) = (body.u64(), body.finish()) else {
                    return Answer::Status(Status::BadSize);
                };
                let token = match self.proof(job, r.label(), Some(&s.data)) {
                    Ok((t, _)) => t,
                    Err(code) => return status(code),
                };
                let identity = s
                    .data
                    .binding
                    .identity(false)
                    .expect("authenticated session");
                let opened = self.ram.open_token(&mut s.data, token, flags, identity);
                self.cancel_job(job, r.label(), Some(&mut s.data));
                match opened {
                    Ok(fd) if self.ram.is_random(&s.data, fd) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(fd))
                            .and_then(|()| w.u32(proto_fs::RANDOM_DEVICE))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Ok(fd) => value(r, fd),
                    Err(code) => status(code),
                }
            }
            Some(Method::Read) => {
                let (Ok(fd), Ok(count)) = (body.u32(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() || count as usize > MAX_READ {
                    return Answer::Status(Status::BadSize);
                }
                let mut bytes = [0; MAX_READ];
                match self.ram.read_at(
                    &mut s.data,
                    fd,
                    &mut bytes[..count as usize],
                    rt::time::ticks_to_ns(rt::time::now()),
                ) {
                    Ok(n) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(n as u32))
                            .and_then(|()| w.bytes(&bytes[..n]))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::ReadAt) => {
                let (Ok(fd), Ok(offset), Ok(count)) = (body.u32(), body.u64(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() || count as usize > MAX_READ {
                    return Answer::Status(Status::BadSize);
                }
                let mut bytes = [0; MAX_READ];
                match self.ram.pread(
                    &s.data,
                    fd,
                    offset,
                    &mut bytes[..count as usize],
                    rt::time::ticks_to_ns(rt::time::now()),
                ) {
                    Ok(n) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(n as u32))
                            .and_then(|()| w.bytes(&bytes[..n]))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::Write) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                let Ok(bytes) = body.bytes(body.left()) else {
                    return Answer::Status(Status::BadSize);
                };
                if bytes.len() > MAX_WRITE {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.write_at(
                    &mut s.data,
                    fd,
                    bytes,
                    rt::time::ticks_to_ns(rt::time::now()),
                ) {
                    Ok(n) => value(r, n as u32),
                    Err(code) => status(code),
                }
            }
            Some(Method::WriteAt) => {
                let (Ok(fd), Ok(offset)) = (body.u32(), body.u64()) else {
                    return Answer::Status(Status::BadSize);
                };
                let Ok(bytes) = body.bytes(body.left()) else {
                    return Answer::Status(Status::BadSize);
                };
                match self.ram.pwrite(
                    &mut s.data,
                    fd,
                    offset,
                    bytes,
                    rt::time::ticks_to_ns(rt::time::now()),
                ) {
                    Ok(n) => value(r, n as u32),
                    Err(code) => status(code),
                }
            }
            Some(Method::Seek) => {
                let (Ok(fd), Ok(offset)) = (body.u32(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.seek(&mut s.data, fd, offset) {
                    Ok(offset) => value(r, offset),
                    Err(code) => status(code),
                }
            }
            Some(Method::SeekFrom) => {
                let (Ok(fd), Ok(offset), Ok(origin)) = (body.u32(), body.u64(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let Some(origin) = proto_fs::SeekFrom::from_number(origin) else {
                    return status(proto_fs::INVALID_ARGUMENT);
                };
                match self.ram.seek_from(&mut s.data, fd, offset as i64, origin) {
                    Ok(offset) => {
                        let w = r.reply();
                        if w.u32(0).and_then(|()| w.u64(offset as u64)).is_err() {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::Stat) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.size(&s.data, fd) {
                    Ok(size) => value(r, size),
                    Err(code) => status(code),
                }
            }
            Some(Method::Close) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.close(&mut s.data, fd) {
                    Ok(()) => Answer::Status(Status::Ok),
                    Err(code) => status(code),
                }
            }
            Some(Method::ReadDir) => {
                let Ok(index) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                let (Ok(job), Ok(())) = (body.u64(), body.finish()) else {
                    return Answer::Status(Status::BadSize);
                };
                let token = match self.proof(job, r.label(), Some(&s.data)) {
                    Ok((t, _)) => t,
                    Err(code) => return status(code),
                };
                let identity = s
                    .data
                    .binding
                    .identity(false)
                    .expect("authenticated session");
                let found = self.ram.directory_read_token(
                    token,
                    index,
                    identity,
                    rt::time::ticks_to_ns(rt::time::now()),
                );
                self.cancel_job(job, r.label(), Some(&mut s.data));
                match found {
                    Ok(entry) => {
                        let (name, kind) = entry.map_or(("", 0), |entry| (entry.name, entry.kind));
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(kind))
                            .and_then(|()| w.bytes(name.as_bytes()))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::ReadDirFd) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.directory_read(
                    &mut s.data,
                    fd,
                    rt::time::ticks_to_ns(rt::time::now()),
                ) {
                    Ok(entry) => {
                        let entry = entry.map(|entry| proto_fs::DirectoryEntry {
                            name: entry.name.as_bytes(),
                            kind: entry.kind,
                            inode: entry.inode,
                        });
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| proto_fs::DirectoryEntry::write(entry, w))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::InfoFd | Method::InfoPath) => {
                let info = if r.method() == Method::InfoFd as u16 {
                    let Ok(fd) = body.u32() else {
                        return Answer::Status(Status::BadSize);
                    };
                    if body.finish().is_err() {
                        return Answer::Status(Status::BadSize);
                    }
                    self.ram.descriptor_information(&s.data, fd)
                } else {
                    let (Ok(job), Ok(())) = (body.u64(), body.finish()) else {
                        return Answer::Status(Status::BadSize);
                    };
                    let token = match self.proof(job, r.label(), Some(&s.data)) {
                        Ok((t, _)) => t,
                        Err(code) => return status(code),
                    };
                    let info = self.ram.token_information(token);
                    self.cancel_job(job, r.label(), Some(&mut s.data));
                    info
                };
                match info {
                    Ok(info) => {
                        let w = r.reply();
                        if w.u32(0).and_then(|()| info.write(w)).is_err() {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::Lookup) => {
                let (Ok(job), Ok(())) = (body.u64(), body.finish()) else {
                    return Answer::Status(Status::BadSize);
                };
                let token = match self.proof(job, r.label(), Some(&s.data)) {
                    Ok((t, _)) => t,
                    Err(code) => return status(code),
                };
                let found = self
                    .ram
                    .token_information(token)
                    .map(|i| proto_fs::Metadata {
                        kind: i.kind,
                        size: i.size as u32,
                    });
                self.cancel_job(job, r.label(), Some(&mut s.data));
                match found {
                    Ok(meta) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(meta.kind))
                            .and_then(|()| w.u32(meta.size))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            None => Answer::Status(Status::UnknownMethod),
        }
    }
}

const GENERATIONS: usize = 0x51_0000_0000;
fn generation(index: usize) -> u64 {
    if index >= proto_process::RECORDS {
        return proto_process::GENERATION_DEAD;
    }
    // SAFETY: notary_register maps the page read-only for the service's life.
    unsafe {
        (&*((GENERATIONS + index * 8) as *const core::sync::atomic::AtomicU64))
            .load(core::sync::atomic::Ordering::Acquire)
    }
}
impl Fs {
    fn notary_register(&mut self) -> bool {
        if self.generations.is_some() {
            return true;
        }
        let Some(notary) = self.notary() else {
            return false;
        };
        let request = proto_process::Method::Register.header().bytes();
        let Ok(mut reply) = sys::send(notary, &request) else {
            return false;
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
            return false;
        }
        let Ok(page) = reply.handles.take::<Memory>(0) else {
            return false;
        };
        if sys::mem_map(&self.process, &page, 0, 4096, GENERATIONS, Access::Read).is_err() {
            return false;
        }
        self.generations = Some(page);
        true
    }
    fn vouch(&mut self, identity: &Handle<Channel>) -> Option<proto_process::WhoReply> {
        if !self.notary_register() {
            return None;
        }
        let copy = sys::handle_duplicate(identity, Rights::NOTIFY | Rights::TRANSFER).ok()?;
        let notary = self.notary.as_ref()?;
        let request = proto_process::Method::Vouch.header().bytes();
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        let reply = sys::send_handles(notary, &request, [copy.erase()]).ok()?;
        proto_process::WhoReply::read(reply.bytes(&mut buffer)).ok()
    }
    fn install_identity(
        &mut self,
        fds: &mut Fds,
        label: u64,
        identity: Handle<Channel>,
    ) -> Result<(), u32> {
        let i = if fds.authority_index == NONE {
            self.identities
                .iter()
                .position(Option::is_none)
                .ok_or(proto_fs::TOO_MANY_OPEN_FILES)?
        } else {
            fds.authority_index as usize
        };
        self.identities[i] = Some(IdentityChannel {
            label,
            channel: identity,
        });
        fds.authority_index = i as u16;
        if let Some(root) = fds.binding.root() {
            fds.root = root;
        }
        Ok(())
    }
    fn drop_identity(&mut self, fds: &mut Fds) {
        if fds.authority_index != NONE {
            self.identities[fds.authority_index as usize] = None;
            fds.authority_index = NONE;
        }
    }
    fn bind(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || r.handles.len() != 1 || proto_fs::is_loaders(r.label()) {
            return status(proto_fs::PERMISSION);
        }
        let rights = r.handles.info(0).map(|(_, rights)| rights);
        if !rights
            .is_some_and(|r| r.contains(Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER))
        {
            return status(proto_fs::PERMISSION);
        }
        let Ok(identity) = r.handles.take::<Channel>(0) else {
            return status(proto_fs::PERMISSION);
        };
        let who = self.vouch(&identity);
        if fds.binding.bind(who, false).is_err() {
            return status(proto_fs::PERMISSION);
        }
        match self.install_identity(fds, r.label(), identity) {
            Ok(()) => Answer::Status(Status::Ok),
            Err(code) => status(code),
        }
    }
    fn authenticate(&mut self, fds: &mut Fds, label: u64) -> bool {
        if matches!(fds.binding, Binding::Unbound) && proto_fs::is_boot_profile(label) {
            fds.binding = Binding::Boot;
            fds.root = Root {
                id: label,
                generation: 1,
            };
        }
        if matches!(fds.binding, Binding::Boot) {
            return true;
        }
        let Some(who) = fds.binding.snapshot() else {
            return false;
        };
        let current = generation(who.index as usize);
        let inherited = matches!(fds.binding, Binding::Inherited(_));
        if current == who.generation {
            return !inherited;
        }
        if current & proto_process::GENERATION_DEAD != 0 {
            fds.binding = Binding::Cleanup;
            return false;
        }
        let i = fds.authority_index as usize;
        let Some(identity) = self.identities.get_mut(i).and_then(Option::take) else {
            return false;
        };
        let valid = identity.label == label;
        let refreshed = valid.then(|| self.vouch(&identity.channel)).flatten();
        self.identities[i] = Some(identity);
        let pending = matches!(fds.binding, Binding::Pending(_));
        if inherited {
            if let Some(fresh) = refreshed.filter(|fresh| {
                fresh.pid == who.pid
                    && fresh.index == who.index
                    && fresh.image == who.image
                    && fresh.root == who.root
            }) {
                fds.binding = Binding::Inherited(fresh);
            } else {
                fds.binding = Binding::Cleanup;
            }
            return false;
        }
        if fds.binding.bind(refreshed, pending).is_ok() {
            return true;
        }
        // A committed Pending image awaits its own authentic startup Bind.
        if !pending {
            fds.binding = Binding::Cleanup;
        }
        false
    }
    /// Compatibility verification only admits this authenticated caller's true clone.
    fn verify_clone(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if proto_fs::is_loaders(r.label()) || !self.authenticate(fds, r.label()) {
            return status(proto_fs::PERMISSION);
        }
        let mut body = r.body();
        if !matches!(body.u32(), Ok(0 | 1)) || body.finish().is_err() || r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let Ok(offered) = r.handles.take::<Channel>(0) else {
            return status(proto_fs::PERMISSION);
        };
        let Ok(label) = sys::copy_label(&self.channel, &offered) else {
            return status(proto_fs::PERMISSION);
        };
        if self.clones.client_of(label) != Some(r.label()) {
            return status(proto_fs::PERMISSION);
        }
        let Some(i) = self
            .births
            .iter()
            .position(|b| b.is_some_and(|(l, _)| l == label))
        else {
            return status(proto_fs::PERMISSION);
        };
        let (_, mut child) = self.births[i].take().expect("own clone");
        child.binding = fds.binding;
        let installed = if fds.authority_index == NONE {
            Ok(())
        } else {
            let identity = self.identities[fds.authority_index as usize]
                .as_ref()
                .and_then(|identity| {
                    sys::handle_duplicate(
                        &identity.channel,
                        Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER,
                    )
                    .ok()
                });
            identity
                .ok_or(proto_fs::PERMISSION)
                .and_then(|identity| self.install_identity(&mut child, label, identity))
        };
        self.births[i] = Some((label, child));
        if let Err(code) = installed {
            return status(code);
        }
        if r.reply().u32(0).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply([offered.erase()].into())
    }
    fn bind_pending(&mut self, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let require = body.u32();
        if !proto_fs::is_loaders(r.label())
            || !matches!(require, Ok(0 | 1))
            || body.finish().is_err()
            || r.handles.len() != 2
        {
            return status(proto_fs::PERMISSION);
        }
        if !r
            .handles
            .info(0)
            .is_some_and(|(_, rights)| rights.contains(Rights::SEND | Rights::TRANSFER))
            || !r.handles.info(1).is_some_and(|(_, rights)| {
                rights.contains(Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER)
            })
        {
            return status(proto_fs::PERMISSION);
        }
        let Ok(offered) = r.handles.take::<Channel>(0) else {
            return status(proto_fs::PERMISSION);
        };
        let Ok(identity) = r.handles.take::<Channel>(1) else {
            return status(proto_fs::PERMISSION);
        };
        let Some(who) = self.vouch(&identity).filter(|w| w.loader.is_some()) else {
            return status(proto_fs::PERMISSION);
        };
        let offered_label = sys::copy_label(&self.channel, &offered).ok();
        let original = offered_label.and_then(|label| {
            self.births
                .iter()
                .position(|b| b.is_some_and(|(l, _)| l == label))
        });
        if require == Ok(1) && original.is_none() {
            return status(proto_fs::PERMISSION);
        }
        let slot = match original.or_else(|| self.births.iter().position(Option::is_none)) {
            Some(slot) => slot,
            None => return status(proto_fs::TOO_MANY_OPEN_FILES),
        };
        if self.clones.room_within(r.label(), CLONES).is_err() {
            return status(proto_fs::TOO_MANY_OPEN_FILES);
        }
        let source = original.and_then(|i| self.births[i].take());
        if let Some((label, mut source)) = source {
            let mut binding = source.binding;
            if binding.bind(Some(who), true).is_err()
                || (source.root.id != 0 && source.root != binding.root().unwrap())
            {
                self.births[slot] = Some((label, source));
                return status(proto_fs::PERMISSION);
            }
            let mut kept = [0; 32];
            let mut count = 0;
            for fd in source.numbers() {
                kept[count] = fd;
                count += 1;
            }
            let mut child = match self.ram.clone_fds(&source, &kept[..count]) {
                Ok(child) => child,
                Err(code) => {
                    self.births[slot] = Some((label, source));
                    return status(code);
                }
            };
            let new_label = proto_fs::OWN | self.given;
            let new_session = match self.session(new_label) {
                Ok(session) => session,
                Err(error) => {
                    self.ram.release(&mut child);
                    self.births[slot] = Some((label, source));
                    return Answer::Status(Status::Kernel(error));
                }
            };
            child.binding = binding;
            // Commit the new authority on a new label. Old aliases retain no child resources.
            child.authority_index = source.authority_index;
            source.authority_index = NONE;
            if let Err(code) = self.install_identity(&mut child, new_label, identity) {
                source.authority_index = child.authority_index;
                child.authority_index = NONE;
                self.ram.release(&mut child);
                self.births[slot] = Some((label, source));
                return status(code);
            }
            self.ram.release(&mut source);
            self.births[slot] = Some((new_label, child));
            let _ = self.clones.add_within(new_label, r.label(), CLONES);
            drop(offered);
            if r.reply().u32(0).is_err() {
                return Answer::Status(Status::BadSize);
            }
            return Answer::Reply([new_session.erase()].into());
        }
        drop(offered);
        let label = proto_fs::OWN | self.given;
        let session = match self.session(label) {
            Ok(s) => s,
            Err(e) => return Answer::Status(Status::Kernel(e)),
        };
        let mut child = Fds::default();
        child.binding.bind(Some(who), true).expect("vouched loader");
        if let Err(code) = self.install_identity(&mut child, label, identity) {
            return status(code);
        }
        self.births[slot] = Some((label, child));
        let _ = self.clones.add_within(label, r.label(), CLONES);
        if r.reply().u32(0).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply([session.erase()].into())
    }
    /// The claimant must bring the same genuine pending Loader identity.
    fn loader_claim(&mut self, id: u64, r: &mut Request<'_>) -> bool {
        let Ok(i) = self.job_slot(id, r.label()) else {
            return false;
        };
        let Some((expected, _)) = self.jobs[i].as_ref().and_then(|j| j.loader.as_ref()) else {
            return false;
        };
        let expected = *expected;
        if r.handles.len() != 1 {
            return false;
        }
        let Ok(identity) = r.handles.take::<Channel>(0) else {
            return false;
        };
        let Some(who) = self.vouch(&identity).filter(|who| {
            who.pid == expected.pid
                && who.index == expected.index
                && who.image == expected.image
                && who.root == expected.root
                && who.loader == expected.loader
        }) else {
            return false;
        };
        let job = self.jobs[i].as_mut().expect("claimed job");
        if Identity::of(who.credentials, who.groups, false) == job.resolver.identity {
            job.loader.as_mut().expect("loader").0 = who;
        }
        true
    }
    fn job_slot(&self, id: u64, owner: u64) -> Result<usize, u32> {
        let i = (id & 255) as usize;
        if !self
            .jobs
            .get(i)
            .is_some_and(|j| j.as_ref().is_some_and(|j| j.id == id && j.owner == owner))
        {
            return Err(proto_fs::STALE_PROOF);
        }
        Ok(i)
    }
    fn cancel_job(&mut self, id: u64, owner: u64, fds: Option<&mut Fds>) {
        if let Ok(i) = self.job_slot(id, owner)
            && let Some(j) = self.jobs[i].take()
        {
            j.resolver.release(&mut self.ram.storage);
            if let Some(second) = j.second {
                second.release(&mut self.ram.storage);
            }
            self.ram.storage.release_preparation(j.root);
        }
        if let Some(fds) = fds
            && let Some(place) = fds.resolvers.iter_mut().find(|r| **r == id)
        {
            *place = 0;
        }
    }
    fn resolve_request(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if r.method() == Method::ResolveCancel as u16 {
            let mut body = r.body();
            let (Ok(id), Ok(())) = (body.u64(), body.finish()) else {
                return Answer::Status(Status::BadSize);
            };
            if proto_fs::is_loaders(r.label()) && !self.loader_claim(id, r) {
                return status(proto_fs::PERMISSION);
            }
            self.cancel_job(id, r.label(), Some(fds));
            return Answer::Status(Status::Ok);
        }
        let loaders = proto_fs::is_loaders(r.label());
        if !loaders && !self.authenticate(fds, r.label()) {
            return status(proto_fs::PERMISSION);
        }
        let mut body = r.body();
        if r.method() == Method::ResolveStart as u16 {
            let (Ok(slot), Ok(generation), Ok(real), Ok(follow)) =
                (body.u32(), body.u64(), body.u32(), body.u32())
            else {
                return Answer::Status(Status::BadSize);
            };
            if !matches!(real, 0 | 1) || !matches!(follow, 0 | 1) {
                return Answer::Status(Status::BadSize);
            }
            let Ok(path) = body.bytes(body.left()) else {
                return Answer::Status(Status::BadSize);
            };
            let mut loader = None;
            let (identity, root) = if loaders {
                if r.handles.len() != 1 || real != 0 {
                    return status(proto_fs::PERMISSION);
                }
                let Ok(channel) = r.handles.take::<Channel>(0) else {
                    return status(proto_fs::PERMISSION);
                };
                let Some(who) = self.vouch(&channel).filter(|w| w.loader.is_some()) else {
                    return status(proto_fs::PERMISSION);
                };
                let identity = Identity::of(who.credentials, who.groups, false);
                let root = Root {
                    id: u64::from(who.root.pid),
                    generation: u64::from(who.root.generation),
                };
                loader = Some((who, channel));
                (identity, root)
            } else {
                (
                    fds.binding.identity(real != 0).expect("authenticated"),
                    fds.root,
                )
            };
            for id in &mut fds.resolvers {
                if *id != 0
                    && !self.jobs[(*id & 255) as usize]
                        .as_ref()
                        .is_some_and(|j| j.id == *id && j.owner == r.label())
                {
                    *id = 0;
                }
            }
            let Some(place) = fds.resolvers.iter().position(|&id| id == 0) else {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            };
            let Some(i) = self.jobs.iter().position(Option::is_none) else {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            };
            let Some(next) = self.job_generations[i]
                .checked_add(1)
                .filter(|&n| n < 1 << 56)
            else {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            };
            let charge = match self.ram.storage.charge_preparation(root) {
                Ok(c) => c,
                Err(code) => return status(code),
            };
            let base = Token {
                slot: match u16::try_from(slot) {
                    Ok(s) => s,
                    Err(_) => NONE,
                },
                generation,
            };
            if path.first() != Some(&b'/') && (loaders || !self.ram.owns_directory_base(fds, base))
            {
                self.ram.storage.release_preparation(charge);
                return status(proto_fs::BAD_FD);
            }
            let resolver =
                match Resolve::new(&mut self.ram.storage, path, base, identity, follow != 0) {
                    Ok(r) => r,
                    Err(code) => {
                        self.ram.storage.release_preparation(charge);
                        return status(code);
                    }
                };
            let id = next << 8 | i as u64;
            self.job_generations[i] = next;
            self.jobs[i] = Some(ResolveJob {
                id,
                owner: r.label(),
                root: charge,
                real: real != 0,
                resolver,
                second: None,
                loader,
            });
            fds.resolvers[place] = id;
            if r.reply().u32(0).and_then(|()| r.reply().u64(id)).is_err() {
                self.cancel_job(id, r.label(), Some(fds));
                return Answer::Status(Status::BadSize);
            }
            return Answer::Reply(Outgoing::new());
        }
        if r.method() == Method::ResolveSecond as u16 {
            if loaders || !r.handles.is_empty() {
                return status(proto_fs::PERMISSION);
            }
            let (Ok(id), Ok(slot), Ok(generation), Ok(follow)) =
                (body.u64(), body.u32(), body.u64(), body.u32())
            else {
                return Answer::Status(Status::BadSize);
            };
            if !matches!(follow, 0 | 1) {
                return Answer::Status(Status::BadSize);
            }
            let path = match body.bytes(body.left()) {
                Ok(p) => p,
                Err(_) => return Answer::Status(Status::BadSize),
            };
            let i = match self.job_slot(id, r.label()) {
                Ok(i) => i,
                Err(code) => return status(code),
            };
            let j = self.jobs[i].as_mut().expect("owned job");
            if j.second.is_some() || j.real {
                return status(proto_fs::PERMISSION);
            }
            let base = Token {
                slot: u16::try_from(slot).unwrap_or(NONE),
                generation,
            };
            if path.first() != Some(&b'/') && !self.ram.owns_directory_base(fds, base) {
                return status(proto_fs::BAD_FD);
            }
            let identity = fds.binding.identity(false).expect("authenticated");
            match Resolve::new(&mut self.ram.storage, path, base, identity, follow != 0) {
                Ok(second) => {
                    j.second = Some(second);
                    return Answer::Status(Status::Ok);
                }
                Err(code) => return status(code),
            }
        }
        let (Ok(id), Ok(())) = (body.u64(), body.finish()) else {
            return Answer::Status(Status::BadSize);
        };
        if loaders && !self.loader_claim(id, r) {
            return status(proto_fs::PERMISSION);
        }
        if !loaders && !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let i = match self.job_slot(id, r.label()) {
            Ok(i) => i,
            Err(code) => return status(code),
        };
        let mut j = self.jobs[i].take().expect("resolve job");
        let identity = if let Some((who, channel)) = &mut j.loader {
            if generation(who.index as usize) != who.generation {
                let Some(fresh) = self
                    .vouch(channel)
                    .filter(|w| w.pid == who.pid && w.image == who.image && w.loader == who.loader)
                else {
                    self.jobs[i] = Some(j);
                    self.cancel_job(id, r.label(), Some(fds));
                    return status(proto_fs::PERMISSION);
                };
                *who = fresh;
            }
            Identity::of(who.credentials, who.groups, false)
        } else {
            fds.binding.identity(j.real).expect("authenticated")
        };
        let mut result = j.resolver.step(&mut self.ram.storage, identity);
        if matches!(result, Ok(Progress::Found(_)))
            && let Some(second) = j.second.as_mut()
        {
            result = second.step(&mut self.ram.storage, identity);
        }
        self.jobs[i] = Some(j);
        match result {
            Ok(Progress::More) => status(proto_fs::RESOLVING),
            Ok(Progress::Found(_)) => Answer::Status(Status::Ok),
            Err(code) => {
                self.cancel_job(id, r.label(), Some(fds));
                status(code)
            }
        }
    }
    fn proof(
        &mut self,
        id: u64,
        owner: u64,
        fds: Option<&Fds>,
    ) -> Result<(Token, Option<proto_process::WhoReply>), u32> {
        let i = self.job_slot(id, owner)?;
        let j = self.jobs[i].as_ref().expect("job");
        if j.real || j.second.is_some() {
            return Err(proto_fs::PERMISSION);
        }
        let (identity, who) = if let Some((who, _)) = &j.loader {
            if generation(who.index as usize) != who.generation {
                return Err(proto_fs::STALE_PROOF);
            }
            (Identity::of(who.credentials, who.groups, false), Some(*who))
        } else {
            (
                fds.ok_or(proto_fs::PERMISSION)?.binding.identity(j.real)?,
                None,
            )
        };
        Ok((j.resolver.proof(&self.ram.storage, identity)?, who))
    }
}
