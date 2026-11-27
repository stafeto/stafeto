// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The layer service: the names of the layered root over the live layer on the data volume (the
//! layered file system, step C3 part A). One thread serves the loop of a service (rt::service); the
//! library decides (`layerd::names::Core`), this program makes the calls and the wire.
//!
//! The start. The service reads COMPOSITION from the data file service (the first start makes
//! `/.layers` and the file), empties `work/`, registers its channel with init and its root with
//! the process service (a thread of its own makes that: the connection to the process service
//! waits in init until it has started), and builds the index of the names of the live layer in
//! steps, one in each notification the service sends itself, so that the heartbeat and the
//! requests go on; until the index is built the names answer STARTING. READY goes to init when it
//! is done.
//!
//! The root channel (label `proto_layer::ROOT`) takes SESSION (18 of proto_layer, 70 of the names)
//! and VERIFY_SESSION (71). A session is bound at birth to the process the copy of the identity
//! session names (Vouch), and serves LIST and STATUS of proto_layer and the names OPEN, STAT,
//! FSTAT, READ_DIR, REWIND, SEEK_DIR, CLOSE, BIND, ACCESS, READLINK and CHANGE (read only). The
//! other methods of proto_layer that carry a selector answer NOT_FOUND; the rest, CLONE, CLONE_MORE
//! and WAIT are not served (UNKNOWN_METHOD).

#![no_std]
#![no_main]

mod data;
mod lower;
mod notary;

use abi::Rights;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::Ordering::{Acquire, Release};
use layerd::identity::{Binding, Vouched, vouched_from};
use layerd::index::Index;
use layerd::names::{Client, Core, Done, State};
use layerd::scan::Scan;
use posix_fs::{PosixFs, StartupFiles};
use proto_fs::names::{self as n, NameMethod};
use proto_init::ServiceArgs;
use proto_layer as l;
use proto_wire::Status;
use rt::handle::{Channel, Process, Resource};
use rt::service::{Answer, Config, Heartbeat, Notice, Request, Service, Session};
use rt::{Handle, sys};

rt::entry!(main);

/// The codes of a start that failed.
const NO_START_DATA: u64 = 1;
const NOT_CONNECTED: u64 = 2;
const NOT_REGISTERED: u64 = 3;
const STOPPED: u64 = 5;

/// The sessions the loop and the table of identities keep: a session for each process that uses
/// the layered root, and the root's own. A session of a process that never sends a request holds
/// a place of the table of identities only.
const SESSIONS: usize = 192;

/// The label of the notification the service sends itself for the next step of the build.
const LABEL_STEP: u64 = 0x6c61_7967_0001;
/// Bit 63 marks the labels the service gives itself: a count of sessions that is never used twice.
const OWN: u64 = 1 << 63;

struct Cell<T>(UnsafeCell<T>);

// SAFETY: every cell is used from the one thread of the loop (the registrar thread only reads
// the atomics below).
unsafe impl<T> Sync for Cell<T> {}

static INDEX: Cell<Index> = Cell(UnsafeCell::new(Index::new()));
static SCAN: Cell<Scan> = Cell(UnsafeCell::new(Scan::new()));
static FILES: Cell<MaybeUninit<PosixFs>> = Cell(UnsafeCell::new(MaybeUninit::uninit()));

#[repr(C, align(4096))]
struct Pages([[u8; posix_fs::DESCRIPTOR_PAGE_BYTES]; posix_fs::DESCRIPTOR_PAGES]);
static PAGES: Cell<Pages> = Cell(UnsafeCell::new(Pages(
    [[0; posix_fs::DESCRIPTOR_PAGE_BYTES]; posix_fs::DESCRIPTOR_PAGES],
)));

/// The registrar thread: the root goes to the process service, tried until it is there.
static PARENT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static CHANNEL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static LEVEL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
static REGISTRAR: rt::Stack<{ 16 * 1024 }> = rt::Stack::new();
const REGISTRAR_BUFFER: usize = abi::INIT_MSGBUF as usize + 4096;

extern "C" fn register_root(_: u64) -> ! {
    let parent = Handle::<Channel>::borrowed(abi::Handle(PARENT.load(Acquire)));
    let channel = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Acquire)));
    let level = LEVEL.load(Acquire) as u8;
    rt::roots::keep(&parent, &channel, l::ROOT, level, "layerd")
}

/// The files of the RAM file service (the boot profile), made once.
fn connect_files(parent: &Handle<Channel>) -> Option<&'static mut PosixFs> {
    let startup = StartupFiles::connect(parent, false).ok()?;
    // SAFETY: FILES and PAGES are used by nobody else and this runs once, before the loop.
    unsafe {
        let fs = &mut *FILES.0.get();
        PosixFs::initialize_at(
            fs.as_mut_ptr(),
            startup,
            b"/",
            None,
            false,
            &mut posix_fs::Late::new(),
        )
        .ok()?;
        let fs = fs.assume_init_mut();
        let pages = &raw mut (*PAGES.0.get()).0;
        for k in 0..posix_fs::DESCRIPTOR_PAGES {
            let page = (&raw mut (*pages)[k]).cast::<u8>();
            fs.add_page(k, core::ptr::NonNull::new_unchecked(page));
        }
        Some(fs)
    }
}

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let args = ServiceArgs::read(s.args()).ok();
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Some(files) = connect_files(&s.parent) else {
        rt::println!("layerd: no file service");
        return NOT_CONNECTED;
    };
    let Ok(session) = rt::service::connect(&s.parent, "datafs") else {
        rt::println!("layerd: no data file service");
        return NOT_CONNECTED;
    };
    let Ok(channel) = sys::channel_create(1) else {
        return NOT_REGISTERED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return NOT_REGISTERED;
    }
    let Ok(step) = sys::handle_label(
        &channel,
        Rights::NOTIFY | Rights::TRANSFER,
        LABEL_STEP,
        level,
    ) else {
        return NOT_REGISTERED;
    };
    PARENT.store(s.parent.raw().0, Release);
    CHANNEL.store(channel.raw().0, Release);
    LEVEL.store(u64::from(level), Release);
    // SAFETY: REGISTRAR is the registrar's alone and the page after the main thread's message
    // buffer is free.
    let registrar = unsafe {
        sys::thread_create(
            &s.process,
            register_root,
            REGISTRAR.top(),
            0,
            level,
            abi::Policy::Fifo,
            REGISTRAR_BUFFER,
        )
    };
    match registrar {
        Ok(thread) if sys::thread_start(&thread).is_ok() => core::mem::forget(thread),
        _ => rt::println!(
            "layerd: no thread to register the root; programs get no session until it is registered"
        ),
    }
    #[cfg(feature = "steps")]
    {
        rt::service::report_steps(18);
        rt::service::table_steps_from(16);
    }
    // SAFETY: the statics are used by this thread alone from here on.
    let (index, scan) = unsafe { (&mut *INDEX.0.get(), &mut *SCAN.0.get()) };
    let epoch = (rt::time::now() as u16) | 1;
    let mut core = Core::new(
        index,
        scan,
        data::Data { session },
        lower::Ram { files },
        epoch,
    );
    core.prepare();
    match core.state {
        State::Starting => rt::println!(
            "layerd: live layer {:02}, building the index",
            core.live_number()
        ),
        other => rt::println!("layerd: not serving: {other:?}"),
    }
    let mut service = Layerd {
        core,
        parent: Handle::borrowed(s.parent.raw()),
        process: Handle::borrowed(s.process.raw()),
        channel: Handle::borrowed(channel.raw()),
        level,
        step,
        notary: notary::Notary::new(),
        next_label: 1,
        sessions: [const { None }; SESSIONS],
        ready: false,
    };
    // The first step of the build, or READY at once for a service that has nothing to build.
    let _ = sys::notify(&service.step, 1);
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &s.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    let _ = rt::service::run::<Layerd, SESSIONS, 0>(&channel, &mut service, config);
    STOPPED
}

/// What the service keeps for the session of one client: whom it is bound to and the copy of the
/// identity session it brought, which Vouch is asked about again when the process's record
/// changes.
struct Record {
    label: u64,
    binding: Binding,
    identity: Option<Handle<Channel>>,
}

struct Layerd {
    core: Core<'static, data::Data, lower::Ram>,
    parent: core::mem::ManuallyDrop<Handle<Channel>>,
    process: core::mem::ManuallyDrop<Handle<Process>>,
    /// The service's own channel, for the labelled copies it gives away.
    channel: core::mem::ManuallyDrop<Handle<Channel>>,
    level: u8,
    /// A notification of the service to itself: the next step of the build.
    step: Handle<Channel>,
    notary: notary::Notary,
    next_label: u64,
    sessions: [Option<Record>; SESSIONS],
    ready: bool,
}

/// The numbers of the methods the service takes: LIST, STATUS and the methods of proto_layer that
/// name a layer (NOT_FOUND), SESSION, and the names but CLONE, CLONE_MORE and WAIT.
const METHODS: &[u16] = &[
    l::Method::List as u16,
    l::Method::Status as u16,
    l::Method::Diff as u16,
    l::Method::Rollback as u16,
    l::Method::Squash as u16,
    l::Method::Check as u16,
    l::Method::Export as u16,
    l::Method::Remove as u16,
    l::Method::Session as u16,
    NameMethod::Session as u16,
    NameMethod::VerifySession as u16,
    NameMethod::Bind as u16,
    NameMethod::Open as u16,
    NameMethod::Stat as u16,
    NameMethod::Fstat as u16,
    NameMethod::ReadDir as u16,
    NameMethod::Rewind as u16,
    NameMethod::SeekDir as u16,
    NameMethod::Close as u16,
    NameMethod::Access as u16,
    NameMethod::Readlink as u16,
    NameMethod::Change as u16,
];

fn st(code: u32) -> Answer {
    Answer::Status(Status::Unknown(code))
}

impl Layerd {
    fn slot_of(&self, label: u64) -> Option<usize> {
        self.sessions
            .iter()
            .position(|r| r.as_ref().is_some_and(|r| r.label == label))
    }

    /// SESSION through the root: a new session of the service, bound to the process the copy of
    /// the identity session names.
    fn session(&mut self, r: &mut Request<'_>) -> Answer {
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let Ok(brought) = r.handles.take::<Channel>(0) else {
            return Answer::Status(Status::Kernel(abi::Error::WrongType));
        };
        if !self.notary.ready(&self.parent, &self.process) {
            return st(l::STARTING);
        }
        let Some(who) = self.notary.vouch(&brought).as_ref().and_then(vouched_from) else {
            return st(proto_fs::ACCESS_DENIED);
        };
        let Some(place) = self.sessions.iter().position(Option::is_none) else {
            return st(proto_fs::TOO_MANY_FILES_IN_SYSTEM);
        };
        let label = OWN | self.next_label;
        let Ok(copy) = sys::handle_label(
            &self.channel,
            Rights::SEND | Rights::TRANSFER,
            label,
            self.level,
        ) else {
            return st(proto_fs::TOO_MANY_FILES_IN_SYSTEM);
        };
        self.next_label += 1;
        self.sessions[place] = Some(Record {
            label,
            binding: Binding::Bound(who),
            identity: Some(brought),
        });
        if r.reply().u32(0).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply([copy.erase()].into())
    }

    /// VERIFY_SESSION (the root alone): the offered session itself comes back when it is a live
    /// session of this service, BAD_FD with no handle otherwise. The binding ends: the identity it
    /// was bound to is that of the holder before, and the program that gets the session binds it
    /// again (BIND).
    fn verify_session(&mut self, r: &mut Request<'_>) -> Answer {
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let Ok(offered) = r.handles.take::<Channel>(0) else {
            return st(proto_fs::BAD_FD);
        };
        let Ok(label) = sys::copy_label(&self.channel, &offered) else {
            return st(proto_fs::BAD_FD);
        };
        let Some(place) = self.slot_of(label).filter(|_| label != l::ROOT) else {
            return st(proto_fs::BAD_FD);
        };
        if let Some(rec) = self.sessions[place].as_mut() {
            rec.binding = Binding::Unbound;
            rec.identity = None;
        }
        if r.reply().u32(0).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply([offered.erase()].into())
    }

    /// BIND: the session takes the identity of the process the copy names, when it is unbound.
    fn bind(&mut self, place: usize, r: &mut Request<'_>) -> Answer {
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let Ok(brought) = r.handles.take::<Channel>(0) else {
            return Answer::Status(Status::Kernel(abi::Error::WrongType));
        };
        if self.sessions[place]
            .as_ref()
            .is_none_or(|rec| rec.binding != Binding::Unbound)
        {
            return st(proto_fs::INVALID_ARGUMENT);
        }
        if !self.notary.ready(&self.parent, &self.process) {
            return st(l::STARTING);
        }
        let Some(who) = self.notary.vouch(&brought).as_ref().and_then(vouched_from) else {
            return st(proto_fs::ACCESS_DENIED);
        };
        if let Some(rec) = self.sessions[place].as_mut() {
            rec.binding = Binding::Bound(who);
            rec.identity = Some(brought);
        }
        Answer::Status(Status::Ok)
    }

    /// The look at the binding of a session before a request: the generation of the process's
    /// record again, and Vouch with the stored copy when it moved.
    fn look(&mut self, place: usize) {
        let Some(rec) = self.sessions[place].as_mut() else {
            return;
        };
        let (notary, identity) = (&self.notary, rec.identity.as_ref());
        let looked = rec.binding.look(
            |index| notary.generation(index),
            || identity.and_then(|i| notary.vouch(i)),
        );
        if looked == layerd::identity::Looked::Lapsed {
            rec.identity = None;
        }
    }

    /// The names. `who` is None for an unbound session, which may use only what a description it
    /// holds allows.
    fn names(&mut self, method: NameMethod, label: u64, r: &mut Request<'_>) -> Answer {
        let Some(place) = self.slot_of(label) else {
            return st(proto_fs::AUTHENTICATING);
        };
        self.look(place);
        let who: Option<Vouched> = self.sessions[place]
            .as_ref()
            .and_then(|rec| rec.binding.bound().copied());
        let needs = |who: &Option<Vouched>| who.ok_or_else(|| Answer::Status(unbound()));
        let body = r.body();
        let bad = Answer::Status(Status::BadSize);
        match method {
            NameMethod::Bind => self.bind(place, r),
            NameMethod::Open => {
                let who = match needs(&who) {
                    Ok(w) => w,
                    Err(a) => return a,
                };
                let Ok((flags, path)) = n::read_open(body) else {
                    return bad;
                };
                let c = Client {
                    owner: label,
                    who: &who,
                };
                match self.core.open(&c, flags, path, r.reply()) {
                    Ok(Done::Written) => Answer::Reply(rt::handle::Outgoing::new()),
                    Ok(Done::Pass(pass)) => Answer::Reply([pass].into()),
                    Err(status) => Answer::Status(status),
                }
            }
            NameMethod::Stat => {
                let who = match needs(&who) {
                    Ok(w) => w,
                    Err(a) => return a,
                };
                let Ok((flags, path)) = n::read_stat(body) else {
                    return bad;
                };
                let c = Client {
                    owner: label,
                    who: &who,
                };
                reply_of(self.core.stat(&c, flags, path, r.reply()))
            }
            NameMethod::Access => {
                let who = match needs(&who) {
                    Ok(w) => w,
                    Err(a) => return a,
                };
                let Ok((bits, flags, path)) = n::read_access(body) else {
                    return bad;
                };
                let c = Client {
                    owner: label,
                    who: &who,
                };
                reply_of(self.core.access(&c, bits, flags, path, r.reply()))
            }
            NameMethod::Readlink => {
                let who = match needs(&who) {
                    Ok(w) => w,
                    Err(a) => return a,
                };
                let Ok(path) = n::read_readlink(body) else {
                    return bad;
                };
                let c = Client {
                    owner: label,
                    who: &who,
                };
                reply_of(self.core.readlink(&c, path, r.reply()))
            }
            NameMethod::Change => {
                if who.is_none() {
                    return Answer::Status(unbound());
                }
                if n::Change::read(body).is_err() {
                    return bad;
                }
                Answer::Status(self.core.change())
            }
            NameMethod::Fstat => {
                let Ok(handle) = n::read_handle(body) else {
                    return bad;
                };
                reply_of(self.core.fstat(label, handle, r.reply()))
            }
            NameMethod::ReadDir => {
                let Ok(handle) = n::read_handle(body) else {
                    return bad;
                };
                match self.core.read_dir(label, handle) {
                    Ok((bytes, len)) => {
                        if r.reply().bytes(&bytes[..len]).is_err() {
                            return bad;
                        }
                        Answer::Reply(rt::handle::Outgoing::new())
                    }
                    Err(status) => Answer::Status(status),
                }
            }
            NameMethod::Rewind => {
                let Ok(handle) = n::read_handle(body) else {
                    return bad;
                };
                status_of(self.core.rewind(label, handle))
            }
            NameMethod::SeekDir => {
                let Ok((handle, cursor)) = n::read_seek_dir(body) else {
                    return bad;
                };
                status_of(self.core.seek_dir(label, handle, cursor))
            }
            NameMethod::Close => {
                let Ok(handle) = n::read_handle(body) else {
                    return bad;
                };
                status_of(self.core.close(label, handle))
            }
            // Not served in this part (the list of methods keeps them from here).
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    /// LIST, STATUS and the methods of proto_layer that name a layer.
    fn layer(&mut self, method: l::Method, r: &mut Request<'_>) -> Answer {
        match method {
            l::Method::List => {
                let Ok(first) = l::read_word(r.body()) else {
                    return Answer::Status(Status::BadSize);
                };
                reply_of(self.core.list(first, r.reply()))
            }
            l::Method::Status => {
                if r.body().finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                reply_of(self.core.status(r.reply()))
            }
            // A layer is named by a selector; the live layer is the only one, and the others are
            // no layer of this volume in this part.
            l::Method::Diff => match l::read_diff(r.body()) {
                Ok(_) => st(l::NOT_FOUND),
                Err(e) => Answer::Status(e),
            },
            l::Method::Rollback | l::Method::Check | l::Method::Remove => {
                match l::read_select(r.body(), l::ALLOW_LIVE | l::ALLOW_STACK | l::ALLOW_ALL) {
                    Ok(_) => st(l::NOT_FOUND),
                    Err(e) => Answer::Status(e),
                }
            }
            l::Method::Squash => match l::read_squash(r.body()) {
                Ok(_) => st(l::NOT_FOUND),
                Err(e) => Answer::Status(e),
            },
            l::Method::Export => match l::read_export(r.body()) {
                Ok(_) => st(l::NOT_FOUND),
                Err(e) => Answer::Status(e),
            },
            _ => Answer::Status(Status::UnknownMethod),
        }
    }
}

/// The status of a session whose binding lapsed or never was: AUTHENTICATING until BIND.
fn unbound() -> Status {
    Status::Unknown(proto_fs::AUTHENTICATING)
}

/// The reply a handler wrote, or its status.
fn reply_of(result: Result<(), Status>) -> Answer {
    match result {
        Ok(()) => Answer::Reply(rt::handle::Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}

fn status_of(result: Result<(), Status>) -> Answer {
    Answer::Status(result.err().unwrap_or(Status::Ok))
}

impl Service<0> for Layerd {
    /// The version of the names; the methods of proto_layer have their own (`version_of`).
    const VERSION: u16 = proto_fs::VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = ();

    fn version_of(method: u16) -> u16 {
        if method < 64 {
            l::VERSION
        } else {
            proto_fs::VERSION
        }
    }

    fn request(&mut self, _: &mut Session<(), 0>, r: &mut Request<'_>) -> Answer {
        let method = r.method();
        if r.label() == l::ROOT {
            return if method == l::Method::Session as u16 || method == NameMethod::Session as u16 {
                self.session(r)
            } else if method == NameMethod::VerifySession as u16 {
                self.verify_session(r)
            } else {
                st(l::INVALID)
            };
        }
        if let Some(m) = l::Method::from_number(method) {
            return if m == l::Method::Session {
                st(proto_fs::INVALID_ARGUMENT)
            } else {
                self.layer(m, r)
            };
        }
        match NameMethod::from_number(method) {
            Some(NameMethod::Session | NameMethod::VerifySession) => st(proto_fs::INVALID_ARGUMENT),
            Some(m) => self.names(m, r.label(), r),
            None => Answer::Status(Status::UnknownMethod),
        }
    }

    /// The client of a label went (a session that never sent a request included): its
    /// descriptions close and its identity copy goes.
    fn closed(&mut self, label: u64) {
        self.core.gone(label);
        if let Some(place) = self.slot_of(label) {
            self.sessions[place] = None;
        }
    }

    fn notification(&mut self, notice: Notice) {
        if notice.label != LABEL_STEP {
            return;
        }
        if self.core.build_step() {
            if !self.ready {
                self.ready = true;
                let (added, deleted) = self.core.index.counts();
                match self.core.state {
                    State::Ready => rt::println!(
                        "layerd: index built: {added} names and {deleted} deletions in {} steps",
                        self.core.build_steps()
                    ),
                    other => rt::println!("layerd: not serving: {other:?}"),
                }
                if let Err(why) = rt::service::ready(&self.parent) {
                    rt::println!("layerd: READY refused: {why:?}");
                }
            }
        } else {
            let _ = sys::notify(&self.step, 1);
        }
    }
}
