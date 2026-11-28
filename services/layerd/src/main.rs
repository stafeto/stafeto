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
//! FSTAT, READ_DIR, REWIND, SEEK_DIR, CLOSE, BIND, ACCESS, READLINK and CHANGE. The
//! other methods of proto_layer that carry a selector answer NOT_FOUND. CLONE makes a session for
//! a child of a fork or a spawn that shares the descriptions it names (one position for the
//! holders, as POSIX shares an open file description), and CLONE_MORE adds descriptions to it
//! until the child sends its first request; the clone is unbound until the child's BIND.
//!
//! The copy up (step C4 part A). A request that writes a file of the lower set is a change job that
//! makes the directories of the path in the layer, takes a place in the table of copies
//! (`layerd::copy`) and answers COPYING with the ticket; the bytes are copied by the worker thread
//! (`worker`) with sessions of its own, so no step of the loop holds a copy. The loop's calls to the data
//! file service wait for at most one job of the copy ahead of them (that service has one worker thread of
//! synchronous calls: a part of 64 KiB, an FSYNC or one attribute call) and one tail step, besides the
//! jobs of other clients ahead of them and their own job. WAIT is answered at once
//! (COPYING while the copy goes on) and keeps the notification the request brings; when the worker
//! has ended a copy the loop walks the name again under the lock and either makes the copy visible
//! (the rename into the layer and the index entry in one step) or hands it to the reaper, and
//! notifies the waiters, who ask WAIT again for the outcome (0 or the failure).

#![no_std]
#![no_main]

mod data;
mod lower;
mod notary;
mod worker;

use abi::Rights;
use core::cell::UnsafeCell;
use core::sync::atomic::Ordering::{Acquire, Release};
use layerd::changejob::{ChangeJob, ChangeStep, CommitStart};
use layerd::copy::{self, Waiters};
use layerd::identity::{Binding, Vouched, vouched_from};
use layerd::index::Index;
use layerd::names::{Client, Core, Done, OpenCont, Prewalk, State};
use layerd::scan::Scan;
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
/// The budget the table gave the loop was refused by the kernel: the loop would run without a
/// limit, so the service does not start.
const BUDGET: u64 = 4;
const STOPPED: u64 = 5;
/// The data file service went (its session answered PEER_CLOSED): the live layer, the index and
/// every pass are of an instance that is gone, so the service ends and init starts a new one, which
/// connects to the new instance of the data file service and builds its index again.
pub const DATA_GONE: u64 = 6;

/// The sessions the loop and the table of identities keep: a session for each process that uses
/// the layered root, and the root's own. A session of a process that never sends a request holds
/// a place of the table of identities only.
const SESSIONS: usize = 192;
/// The sessions one process holds at most (one for the process and some for its clones).
const SESSIONS_PER_PROCESS: usize = 16;

/// The label of the notification the service sends itself for the next step of the build.
const LABEL_STEP: u64 = 0x6c61_7967_0001;
/// The label of the notification for the next step of a long walk (`Job`).
const LABEL_WALK: u64 = 0x6c61_7967_0002;
/// The label of the notification the worker thread gives when it has ended a copy.
const LABEL_COPY: u64 = 0x6c61_7967_0003;
/// The requests whose walk or calls go on in steps at once. A request that finds the table full, or
/// its session at its share, is answered busy (`layerd::jobs`).
const JOBS: usize = layerd::jobs::JOBS;
/// Bit 63 marks the labels the service gives itself: a count of sessions that is never used twice.
const OWN: u64 = 1 << 63;

/// The handle of the loop's own budget, kept for the steps build, and the time (ns) the loop began.
#[cfg(feature = "steps")]
static SERVE_BUDGET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "steps")]
static SERVE_START: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Under the feature `steps`, a line when the CPU the loop's budget has charged has grown by 1 ms
/// since the last line: `layerd: serve ran <us> us in <ms> ms since the start`. The share the loop
/// takes of CPU 0 is the first number over the second; its budget is 50 us in each 10 ms (0.5 %).
#[cfg(feature = "steps")]
fn serve_line() {
    use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let raw = SERVE_BUDGET.load(Acquire);
    if raw == 0 {
        return;
    }
    let budget = Handle::<rt::handle::Budget>::borrowed(abi::Handle(raw));
    let Ok(info) = sys::budget_info(&budget) else {
        return;
    };
    let now = rt::time::ticks_to_ns(rt::time::now());
    let ran = rt::time::ticks_to_ns(info.ran);
    if ran < LAST.load(Relaxed) + 1_000_000 {
        return;
    }
    LAST.store(ran, Relaxed);
    rt::println!(
        "layerd: serve ran {} us in {} ms since the start, {} overruns",
        ran / 1000,
        now.saturating_sub(SERVE_START.load(Relaxed)) / 1_000_000,
        info.overruns
    );
}

struct Cell<T>(UnsafeCell<T>);

// SAFETY: every cell is used from the one thread of the loop (the registrar thread only reads
// the atomics below).
unsafe impl<T> Sync for Cell<T> {}

static INDEX: Cell<Index> = Cell(UnsafeCell::new(Index::new()));
static SCAN: Cell<Scan> = Cell(UnsafeCell::new(Scan::new()));
static WORKERS: Cell<layerd::reaper::Workers> =
    Cell(UnsafeCell::new(layerd::reaper::Workers::new()));
/// The change jobs, one for each place of the table of jobs and one more: the commit job that
/// makes a finished copy visible (the place `JOBS`).
type Change = ChangeJob<data::Data, lower::Ram>;
static CHANGES: Cell<[Change; JOBS + 1]> =
    Cell(UnsafeCell::new([const { Change::new() }; JOBS + 1]));

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

/// Writes a zero into each page of the `len` bytes at `base`, so that every page is mapped: the
/// first touch of a page of a static is a fault the kernel serves, and it must not land in a step of
/// the loop. It runs before the loop, when nothing else uses the memory and its bytes are zeros.
fn touch(base: *mut u8, len: usize) {
    let mut at = 0;
    while at < len {
        // SAFETY: `at` is within the static, which holds zeros and is used by nobody yet.
        unsafe { base.add(at).write(0) };
        at += 4096;
    }
    core::hint::black_box(base);
}

/// The epoch of an instance: the counter in units of 2^20 ticks, 16 bits, never 0 (about 17 ms on
/// the 62.5 MHz counter of QEMU, about 1 ms on a 1 GHz counter, where it wraps in about 69 s). A
/// handle of an earlier instance carries another epoch unless the instances started a multiple of
/// 2^36 ticks apart to within a unit, and then its place and generation must match too
/// (`proto_fs::names::handle`); the POSIX client also counts the rebirths of its session and
/// answers EIO for a description of an earlier one, so the epoch is a second line.
const fn epoch_of(ticks: u64) -> u16 {
    let epoch = if cfg!(feature = "break-layerd-epoch") {
        1
    } else {
        (ticks >> 20) as u16
    };
    if epoch == 0 { 1 } else { epoch }
}

/// Maps the stack pages below the frame of `main`: the first touch of a page of the stack is a fault
/// the kernel serves, and a request that went deeper into the stack than any before it (a long path,
/// the open of a file) paid for it in its step. The array is the frame of this call alone.
#[inline(never)]
fn touch_stack() {
    let mut pad = [0u8; 64 * 1024];
    touch(pad.as_mut_ptr(), pad.len());
    core::hint::black_box(&mut pad);
}

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let serve = rt::budget::take(&mut s, rt::budget::SERVE);
    let args = ServiceArgs::read(s.args()).ok();
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(files) = rt::fs::Files::connect(&s.parent) else {
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
    let Ok(walk_step) = sys::handle_label(
        &channel,
        Rights::NOTIFY | Rights::TRANSFER,
        LABEL_WALK,
        level,
    ) else {
        return NOT_REGISTERED;
    };
    // The worker thread of the copies up: sessions of its own with the two file services, and the
    // notification it gives the loop when a copy has ended.
    let Ok(worker_files) = rt::fs::Files::connect(&s.parent) else {
        rt::println!("layerd: no second session with the file service for the copies");
        return NOT_CONNECTED;
    };
    let Ok(worker_data) = rt::service::connect(&s.parent, "datafs") else {
        rt::println!("layerd: no second session with the data file service for the copies");
        return NOT_CONNECTED;
    };
    let Ok(copied) = sys::handle_label(
        &channel,
        Rights::NOTIFY | Rights::TRANSFER,
        LABEL_COPY,
        level,
    ) else {
        return NOT_REGISTERED;
    };
    let kick = match worker::start(worker::Start {
        process: &s.process,
        files: worker_files,
        data: worker_data,
        done: copied,
    }) {
        Ok(kick) => kick,
        Err(why) => {
            rt::println!("layerd: no thread for the copies: {why}");
            return NOT_CONNECTED;
        }
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
    let (index, scan, workers, changes) = unsafe {
        (
            &mut *INDEX.0.get(),
            &mut *SCAN.0.get(),
            &mut *WORKERS.0.get(),
            &mut *CHANGES.0.get(),
        )
    };
    touch_stack();
    touch(INDEX.0.get().cast(), core::mem::size_of::<Index>());
    touch(SCAN.0.get().cast(), core::mem::size_of::<Scan>());
    index.reseed(
        (u64::from(rt::time::now() as u32) << 32)
            ^ rt::time::now().rotate_left(17)
            ^ 0x5bd1_e995_9e37_79b9,
    );
    let epoch = epoch_of(rt::time::now());
    let mut core = Core::new(
        index,
        scan,
        workers,
        data::Data { session },
        lower::Ram::new(files),
        epoch,
    );
    core.prepare();
    if core.cleared != 0 {
        rt::println!(
            "layerd: work/ held {} names an earlier instance left, removed",
            core.cleared
        );
    } else {
        rt::println!("layerd: work/ is empty at the start");
    }
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
        walk_step,
        jobs: [const { None }; JOBS],
        next_job: 0,
        changes,
        commit: false,
        kick,
        copy_seen: (0, 0, 0, 0),
        waiters: Waiters::new(),
        reap_turn: false,
        notary: notary::Notary::new(),
        next_label: 1,
        next_birth: 1,
        sessions: [const { None }; SESSIONS],
        ready: false,
    };
    // The loop is this thread: it works under its budget from here on, and a budget the kernel
    // refuses is a start error, since the thread would run without a limit.
    match rt::budget::bind("layerd", rt::budget::SERVE, serve, &s.thread) {
        Err(_) => return BUDGET,
        #[cfg(feature = "steps")]
        Ok(Some(kept)) => {
            SERVE_BUDGET.store(kept.raw().0, Release);
            SERVE_START.store(rt::time::ticks_to_ns(rt::time::now()), Release);
            core::mem::forget(kept);
        }
        Ok(_) => {}
    }
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
    /// The label of the session this one was cloned from (0 for none) and the birth number
    /// CLONE gave it: CLONE_MORE names the clone by them while the child has sent nothing.
    parent: u64,
    birth: u32,
    started: bool,
    /// The process the session was made for (Vouch's pid): the share of sessions it may hold.
    pid: u32,
    binding: Binding,
    identity: Option<Handle<Channel>>,
}

/// What a request that waits for its walk is: the reply it owes, who asked, and what it asked for.
struct Job {
    pending: rt::service::Pending,
    label: u64,
    who: Vouched,
    kind: JobKind,
    stage: Stage,
}

/// Where a job stands: its path is being walked, or the calls to the data file service that open
/// the file it found are going on, one in each step. The jobs live in a fixed table of the
/// service with no heap, so the variants are kept inline at the size of the larger one.
#[allow(clippy::large_enum_variant)]
enum Stage {
    Walking(Prewalk),
    Opening(OpenCont),
    /// A change of names: its state is `Layerd::changes[place]` (a change job runs in steps, one
    /// call to a service in each, and never in the step of its request).
    Changing,
}

enum JobKind {
    Open { flags: u32 },
    Stat { flags: u32 },
    Access { bits: u32, flags: u32 },
    Readlink,
    Change,
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
    /// A notification of the service to itself: the next step of a long walk.
    walk_step: Handle<Channel>,
    jobs: [Option<Job>; JOBS],
    next_job: usize,
    changes: &'static mut [Change; JOBS + 1],
    /// The commit job (the last of `changes`) has a copy to make visible.
    commit: bool,
    /// The kick of the worker thread.
    kick: Handle<Channel>,
    /// The counters of the copies at the last line the service printed.
    copy_seen: (u32, u32, u32, u32),
    /// The notifications of the programs that wait for a copy (WAIT with a handle).
    waiters: Waiters<Handle<Channel>, { copy::WAITERS }>,
    /// The next step of the loop goes to the reaper when it has work (the jobs and the reaper
    /// take turns).
    reap_turn: bool,
    notary: notary::Notary,
    next_label: u64,
    next_birth: u32,
    sessions: [Option<Record>; SESSIONS],
    ready: bool,
}

/// The numbers of the methods the service takes: LIST, STATUS and the methods of proto_layer that
/// name a layer (NOT_FOUND), SESSION, and the names but WAIT.
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
    NameMethod::Clone as u16,
    NameMethod::CloneMore as u16,
    NameMethod::Access as u16,
    NameMethod::Readlink as u16,
    NameMethod::Change as u16,
    NameMethod::Wait as u16,
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
        // A process takes `SESSIONS_PER_PROCESS` of the table and no more, so that none fills it.
        let held = self
            .sessions
            .iter()
            .flatten()
            .filter(|rec| rec.pid == who.pid)
            .count();
        let place = self.sessions.iter().position(Option::is_none);
        let (true, Some(place)) = (held < SESSIONS_PER_PROCESS, place) else {
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
            parent: 0,
            birth: 0,
            started: false,
            pid: who.pid,
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
            // A clone is counted for the process that made it until the child binds it: from then
            // on it is the child's.
            rec.pid = who.pid;
            rec.binding = Binding::Bound(who);
            rec.identity = Some(brought);
        }
        Answer::Status(Status::Ok)
    }

    /// CLONE: a session for a child of the caller, unbound, that holds a share of each description
    /// the request names. The caller's pid pays for the place until the child binds it.
    fn clone_session(&mut self, place: usize, r: &mut Request<'_>) -> Answer {
        let mut handles = [0u32; n::CLONE_MAX];
        let Ok(count) = n::read_clone(r.body(), &mut handles) else {
            return Answer::Status(Status::BadSize);
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let Some(parent) = self.sessions[place].as_ref() else {
            return st(proto_fs::AUTHENTICATING);
        };
        let (parent_label, pid) = (parent.label, parent.pid);
        let held = self
            .sessions
            .iter()
            .flatten()
            .filter(|rec| rec.pid == pid)
            .count();
        let free = self.sessions.iter().position(Option::is_none);
        let (true, Some(free)) = (held < SESSIONS_PER_PROCESS, free) else {
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
        if let Err(status) = self.core.share(parent_label, &handles[..count], label) {
            return Answer::Status(status);
        }
        self.next_label += 1;
        let birth = self.next_birth;
        self.next_birth = self.next_birth.wrapping_add(1).max(1);
        self.sessions[free] = Some(Record {
            label,
            parent: parent_label,
            birth,
            started: false,
            pid,
            binding: Binding::Unbound,
            identity: None,
        });
        if n::write_clone_reply(birth, r.reply()).is_err() {
            self.core.gone(label);
            self.sessions[free] = None;
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply([copy.erase()].into())
    }

    /// CLONE_MORE: more descriptions for the clone `birth` the caller made, while the child has
    /// sent nothing (INVALID_ARGUMENT after that, BAD_FD for a birth the caller did not make).
    fn clone_more(&mut self, place: usize, r: &mut Request<'_>) -> Answer {
        let mut handles = [0u32; n::CLONE_MAX];
        let Ok((birth, count)) = n::read_clone_more(r.body(), &mut handles) else {
            return Answer::Status(Status::BadSize);
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let Some(parent) = self.sessions[place].as_ref().map(|rec| rec.label) else {
            return st(proto_fs::AUTHENTICATING);
        };
        let Some(clone) = self
            .sessions
            .iter()
            .flatten()
            .find(|rec| rec.parent == parent && rec.birth == birth)
        else {
            return st(proto_fs::BAD_FD);
        };
        if clone.started {
            return st(proto_fs::INVALID_ARGUMENT);
        }
        let to = clone.label;
        status_of(self.core.share(parent, &handles[..count], to))
    }

    /// The place of the table of jobs for a job of the session `label`, or the answer the request
    /// gets: busy (`STARTING`) when the table is full or the session holds its share.
    fn place_for(&self, label: u64) -> Result<usize, Answer> {
        if !self.core.walkable() {
            return Err(st(l::STARTING));
        }
        let held: [Option<u64>; JOBS] =
            core::array::from_fn(|i| self.jobs[i].as_ref().map(|j| j.label));
        layerd::jobs::place(&held, label).map_err(|_| st(l::STARTING))
    }

    /// The request waits as the job in `place`.
    fn defer_at(
        &mut self,
        r: &mut Request<'_>,
        place: usize,
        who: Vouched,
        label: u64,
        kind: JobKind,
        stage: Stage,
    ) -> Answer {
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::BadSize);
        };
        self.jobs[place] = Some(Job {
            pending,
            label,
            who,
            kind,
            stage,
        });
        let _ = sys::notify(&self.walk_step, 1);
        Answer::Deferred
    }

    /// The request waits for its walk: a long path is walked `lookup::STEP` components in each step
    /// of the loop, and the step that finishes the walk finishes the request (`walk_job`). The
    /// answer is `Deferred`, or busy (`STARTING`, which the clients ask again) when the table of
    /// jobs has no place for the session (`jobs::place`): a long path is never walked inside the
    /// step of its request. None when the service does not answer yet (the request then gives its
    /// own refusal).
    fn defer_walk(
        &mut self,
        r: &mut Request<'_>,
        who: Vouched,
        label: u64,
        kind: JobKind,
        stage: Stage,
    ) -> Option<Answer> {
        if !self.core.walkable() {
            return None;
        }
        let held: [Option<u64>; JOBS] =
            core::array::from_fn(|i| self.jobs[i].as_ref().map(|j| j.label));
        let Ok(place) = layerd::jobs::place(&held, label) else {
            if let Stage::Opening(cont) = stage {
                self.core.open_abandon(cont);
            }
            return Some(st(l::STARTING));
        };
        let Some(pending) = r.defer() else {
            return Some(Answer::Status(Status::BadSize));
        };
        self.jobs[place] = Some(Job {
            pending,
            label,
            who,
            kind,
            stage,
        });
        let _ = sys::notify(&self.walk_step, 1);
        Some(Answer::Deferred)
    }

    /// One step of one job, the jobs in turn: the walk of its path, a part of it, or a call of
    /// the open of its file; a job that is done is answered. A job of a session that went is
    /// dropped (its reply goes to nobody, the description it holds closes).
    fn walk_job(&mut self) {
        // The jobs and the reaper take turns: a step is one or the other.
        if self.core.reaping() && (self.reap_turn || !self.has_jobs()) {
            self.reap_turn = false;
            #[cfg(feature = "steps")]
            rt::service::step_detail(1300);
            if self.core.reap_step() || self.has_jobs() {
                let _ = sys::notify(&self.walk_step, 1);
            }
            return;
        }
        self.reap_turn = true;
        // A change job that does not hold the lock waits while another one does. The commit job
        // of a finished copy is the place after the last of the table.
        let Some(place) = (0..=JOBS)
            .map(|k| (self.next_job + k) % (JOBS + 1))
            .find(|&i| self.runnable(i))
        else {
            return;
        };
        self.next_job = (place + 1) % (JOBS + 1);
        if place == JOBS {
            self.commit_job();
            if self.has_jobs() || self.core.reaping() {
                let _ = sys::notify(&self.walk_step, 1);
            }
            return;
        }
        let gone = self.jobs[place]
            .as_ref()
            .is_some_and(|job| self.slot_of(job.label).is_none());
        if matches!(
            self.jobs[place].as_ref().map(|j| &j.stage),
            Some(Stage::Changing)
        ) {
            // A change job whose session went before its first call is dropped; after it the
            // job runs to its end (its answer goes to nobody) and lets the lock go.
            if gone && !self.changes[place].committed() {
                self.core.change_abandon(&mut self.changes[place]);
                self.jobs[place] = None;
            } else {
                self.change_job(place);
            }
        } else if let Some(job) = self.jobs[place].take() {
            if gone {
                if let Stage::Opening(cont) = job.stage {
                    self.core.open_abandon(cont);
                }
            } else {
                self.jobs[place] = self.advance(place, job);
            }
        }
        if self.has_jobs() || self.core.reaping() {
            let _ = sys::notify(&self.walk_step, 1);
        }
    }

    /// A job of the table or the commit job has work.
    fn has_jobs(&self) -> bool {
        self.commit || self.jobs.iter().any(Option::is_some)
    }

    fn runnable(&self, place: usize) -> bool {
        if place == JOBS {
            return self.commit && (self.changes[JOBS].holds_lock() || !self.core.change_locked());
        }
        match self.jobs[place].as_ref().map(|j| &j.stage) {
            None => false,
            Some(Stage::Changing) => self.changes[place].holds_lock() || !self.core.change_locked(),
            Some(_) => true,
        }
    }

    /// One step of the change job in `place`; the job is answered when its last call is made.
    fn change_job(&mut self, place: usize) {
        let Some(job) = self.jobs[place].as_ref() else {
            return;
        };
        #[cfg(feature = "steps")]
        rt::service::step_detail(self.changes[place].detail());
        let c = Client {
            owner: job.label,
            who: &job.who,
        };
        let mut w = proto_wire::Writer::new();
        let stepped = self.core.change_step(&c, &mut self.changes[place], &mut w);
        let none = rt::handle::Outgoing::new;
        match stepped {
            ChangeStep::Wait | ChangeStep::More => {}
            ChangeStep::Done(result) => {
                let Some(job) = self.jobs[place].take() else {
                    return;
                };
                // A change that reserved a copy has a copy for the worker, and the line that says so
                // goes before the answer, so a program that has the answer has the line too.
                self.pump();
                let _ = match result {
                    Ok(Done::Written) => job.pending.answer(w.as_bytes(), none()),
                    Ok(Done::Pass(pass)) => job.pending.answer(w.as_bytes(), [pass]),
                    Ok(Done::Continue(_)) => unreachable!(),
                    Err(status) => job.pending.answer(&proto_wire::reply(status), none()),
                };
            }
        }
    }

    /// The copies the table has queued go to the worker thread, as many as it takes.
    fn pump(&mut self) {
        let mut sent = false;
        while let Some(order) = self.core.copies.next_order() {
            worker::publish(&order);
            sent = true;
        }
        self.note_copies("queued");
        if sent {
            let _ = sys::notify(&self.kick, 1);
            // The deliberate break `break-layerd-copy-in-loop`: the copy is made here, in this step.
            #[cfg(feature = "break-layerd-copy-in-loop")]
            {
                worker::inline();
                self.copies_ended();
            }
        }
    }

    /// The counters of the copies, a line when one of them moved: the probes read it (a read open
    /// makes no copy, two writers of one file make one).
    fn note_copies(&mut self, what: &str) {
        if !cfg!(feature = "probe-copies") {
            return;
        }
        let t = &self.core.copies;
        let seen = (t.reserved, t.committed, t.dropped, t.failed);
        if seen == self.copy_seen {
            return;
        }
        self.copy_seen = seen;
        rt::println!(
            "layerd: copies {what}: {} reserved, {} made visible, {} dropped, {} failed",
            seen.0,
            seen.1,
            seen.2,
            seen.3
        );
    }

    /// The worker has ended copies: the table is told, and the commit job starts for the first.
    fn copies_ended(&mut self) {
        while let Some(ended) = worker::collect() {
            if !self.core.copies.ended(ended) {
                rt::println!("layerd: a copy that is not in work ended");
            }
        }
        self.next_commit();
    }

    /// The commit job takes the next copy the worker ended, when it has none.
    fn next_commit(&mut self) {
        if self.commit {
            return;
        }
        match self.core.commit_start(&mut self.changes[JOBS], JOBS as u8) {
            CommitStart::None => {}
            CommitStart::Job => {
                self.commit = true;
                let _ = sys::notify(&self.walk_step, 1);
            }
            // The copy is over at once, failed: its waiters are told as for any copy that ends.
            CommitStart::Failed(ticket) => {
                self.note_copies("over");
                self.tell_waiters(ticket);
                self.next_commit();
            }
        }
    }

    /// The programs that wait for the copy are told, and ask WAIT once more for how it ended.
    fn tell_waiters(&mut self, ticket: u64) {
        while let Some(notify) = self.waiters.take(ticket) {
            let _ = sys::notify(&notify, 1);
        }
    }

    /// One step of the commit job.
    fn commit_job(&mut self) {
        let root = Vouched::root();
        let c = Client {
            owner: 0,
            who: &root,
        };
        #[cfg(feature = "steps")]
        rt::service::step_detail(self.changes[JOBS].detail());
        let mut w = proto_wire::Writer::new();
        match self.core.change_step(&c, &mut self.changes[JOBS], &mut w) {
            ChangeStep::Wait | ChangeStep::More => {}
            ChangeStep::Done(result) => {
                let of = self.changes[JOBS].commit_of();
                // A failure the waiters must hear (the volume is full, an I/O error); a name that
                // changed meanwhile is no failure of the copy: the program asks again.
                let failed = match result {
                    Ok(_) => None,
                    Err(Status::Unknown(
                        proto_fs::NO_ENTRY
                        | proto_fs::NOT_DIRECTORY
                        | proto_fs::ALREADY_EXISTS
                        | proto_fs::ACCESS_DENIED,
                    )) => None,
                    Err(Status::Unknown(code)) => Some(code),
                    Err(_) => Some(proto_layer::IO),
                };
                self.core.commit_done(&mut self.changes[JOBS], failed);
                self.commit = false;
                // The line goes before the answers, so a program that has its answer has it too.
                self.note_copies("over");
                if let Some((place, generation)) = of {
                    self.tell_waiters(copy::ticket_of(place, generation));
                }
                self.next_commit();
                self.pump();
            }
        }
    }

    /// One step of a job: the job again when it goes on, None when it has been answered.
    fn advance(&mut self, place: usize, job: Job) -> Option<Job> {
        let Job {
            pending,
            label,
            who,
            kind,
            stage,
        } = job;
        let c = Client {
            owner: label,
            who: &who,
        };
        let mut w = proto_wire::Writer::new();
        let done = match stage {
            Stage::Walking(mut walk) => {
                let Some(walked) = self.core.prewalk_step(&who, &mut walk) else {
                    return Some(Job {
                        pending,
                        label,
                        who,
                        kind,
                        stage: Stage::Walking(walk),
                    });
                };
                match kind {
                    JobKind::Open { flags } => {
                        // An OPEN that creates a name the layer does not hold is a change job, and so
                        // is one that writes a name of the lower set (it is copied up first).
                        if (flags & proto_fs::CREATE != 0 && walked.is_missing())
                            || (n::open_writes(flags) && walked.is_lower())
                        {
                            return match self.changes[place].start_create(
                                place as u8,
                                flags,
                                walked.path(),
                                walked.trailing(),
                            ) {
                                Ok(()) => Some(Job {
                                    pending,
                                    label,
                                    who,
                                    kind,
                                    stage: Stage::Changing,
                                }),
                                Err(status) => {
                                    let _ = pending.answer(
                                        &proto_wire::reply(status),
                                        rt::handle::Outgoing::new(),
                                    );
                                    None
                                }
                            };
                        }
                        self.core
                            .open_walked(&c, flags, Some(walked), true, b"", &mut w)
                    }
                    JobKind::Stat { flags } => self
                        .core
                        .stat_walked(&c, flags, Some(walked), b"", &mut w)
                        .map(|()| Done::Written),
                    JobKind::Access { bits, flags } => self
                        .core
                        .access_walked(&c, (bits, flags), Some(walked), b"", &mut w)
                        .map(|()| Done::Written),
                    JobKind::Readlink => self
                        .core
                        .readlink_walked(&c, Some(walked), b"", &mut w)
                        .map(|()| Done::Written),
                    JobKind::Change => Err(Status::BadSize),
                }
            }
            Stage::Changing => Err(Status::BadSize),
            Stage::Opening(cont) => self.core.open_continue(&c, cont, &mut w),
        };
        let none = rt::handle::Outgoing::new;
        let _ = match done {
            Ok(Done::Continue(cont)) => {
                return Some(Job {
                    pending,
                    label,
                    who,
                    kind,
                    stage: Stage::Opening(cont),
                });
            }
            Ok(Done::Written) => pending.answer(w.as_bytes(), none()),
            Ok(Done::Pass(pass)) => pending.answer(w.as_bytes(), [pass]),
            Err(status) => pending.answer(&proto_wire::reply(status), none()),
        };
        None
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
        if let Some(rec) = self.sessions[place].as_mut() {
            rec.started = true;
        }
        let who: Option<Vouched> = self.sessions[place]
            .as_ref()
            .and_then(|rec| rec.binding.bound().copied());
        let needs = |who: &Option<Vouched>| who.ok_or_else(|| Answer::Status(unbound()));
        let body = r.body();
        let bad = Answer::Status(Status::BadSize);
        match method {
            NameMethod::Bind => self.bind(place, r),
            NameMethod::Clone => self.clone_session(place, r),
            NameMethod::CloneMore => self.clone_more(place, r),
            NameMethod::Open => {
                let who = match needs(&who) {
                    Ok(w) => w,
                    Err(a) => return a,
                };
                let Ok((flags, path)) = n::read_open(body) else {
                    return bad;
                };
                #[cfg(feature = "probe-restart")]
                if path.ends_with(b"/.die") {
                    rt::println!("layerd: probe-restart: the service ends with the exit code 1");
                    sys::process_exit(1);
                }
                // An OPEN that creates or writes is a job whatever the path: its walk is in steps and
                // the change of the volume is the step that finishes it.
                let creates = flags & proto_fs::CREATE != 0;
                if self.core.partial && (creates || n::open_writes(flags)) {
                    return st(proto_fs::READ_ONLY_FILESYSTEM);
                }
                let follow = flags & proto_fs::NO_FOLLOW == 0
                    && !(creates && flags & proto_fs::EXCLUSIVE != 0);
                if (Prewalk::long(path) || creates || n::open_writes(flags))
                    && let Some(deferred) = self.defer_walk(
                        r,
                        who,
                        label,
                        JobKind::Open { flags },
                        Stage::Walking(Prewalk::new(path, false, follow)),
                    )
                {
                    return deferred;
                }
                let c = Client {
                    owner: label,
                    who: &who,
                };
                // The calls of the open of a file of the layer are steps of a job, whatever the
                // path: the largest step is one exchange with the data file service.
                let opened = self
                    .core
                    .open_walked(&c, flags, None, true, path, r.reply());
                #[cfg(feature = "steps")]
                rt::service::step_detail(match &opened {
                    Ok(Done::Continue(_)) => 7301,
                    Err(_) => 7302,
                    _ => 7300,
                });
                match opened {
                    Ok(Done::Written) => Answer::Reply(rt::handle::Outgoing::new()),
                    Ok(Done::Pass(pass)) => Answer::Reply([pass].into()),
                    Ok(Done::Continue(cont)) => self
                        .defer_walk(r, who, label, JobKind::Open { flags }, Stage::Opening(cont))
                        .unwrap_or(Answer::Status(Status::BadSize)),
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
                if Prewalk::long(path)
                    && let Some(deferred) = self.defer_walk(
                        r,
                        who,
                        label,
                        JobKind::Stat { flags },
                        Stage::Walking(Prewalk::new(path, false, flags & n::STAT_NO_FOLLOW == 0)),
                    )
                {
                    return deferred;
                }
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
                if Prewalk::long(path)
                    && let Some(deferred) = self.defer_walk(
                        r,
                        who,
                        label,
                        JobKind::Access { bits, flags },
                        Stage::Walking(Prewalk::new(
                            path,
                            flags & proto_data::ACCESS_REAL != 0,
                            true,
                        )),
                    )
                {
                    return deferred;
                }
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
                if Prewalk::long(path)
                    && let Some(deferred) = self.defer_walk(
                        r,
                        who,
                        label,
                        JobKind::Readlink,
                        Stage::Walking(Prewalk::new(path, false, false)),
                    )
                {
                    return deferred;
                }
                let c = Client {
                    owner: label,
                    who: &who,
                };
                reply_of(self.core.readlink(&c, path, r.reply()))
            }
            NameMethod::Change => {
                let who = match needs(&who) {
                    Ok(w) => w,
                    Err(a) => return a,
                };
                let mut body = body;
                let all = match body.bytes(body.left()) {
                    Ok(all) => all,
                    Err(_) => return bad,
                };
                if self.core.partial {
                    return st(proto_fs::READ_ONLY_FILESYSTEM);
                }
                if n::Change::read(proto_wire::Reader::new(all)).is_err() {
                    return bad;
                }
                // A change is a job: the table of jobs answers busy (STARTING) when it is full or
                // the session holds its share, and the walk and the calls are not in the step of
                // the request.
                let place = match self.place_for(label) {
                    Ok(place) => place,
                    Err(answer) => return answer,
                };
                if let Err(status) = self.changes[place].start_request(place as u8, all) {
                    return Answer::Status(status);
                }
                self.defer_at(r, place, who, label, JobKind::Change, Stage::Changing)
            }
            NameMethod::Wait => {
                if let Err(a) = needs(&who) {
                    return a;
                }
                let Ok(ticket) = n::read_wait(body) else {
                    return bad;
                };
                if r.handles.len() > 1 {
                    return bad;
                }
                // A ticket the table never gave (a bit above its place and generation) is refused:
                // the table would read it as another ticket, and the notification kept for it would
                // never be told.
                if !copy::ticket_valid(ticket) {
                    return st(proto_fs::INVALID_ARGUMENT);
                }
                // WAIT is answered at once: 0 or the failure when the copy is over, COPYING while it
                // goes on. The kernel gives no end to the wait of a thread for the reply of a request
                // that a service has taken, so a wait that a signal may end is the program's `receive`
                // on its own channel: the copy of that channel the request brings (NOTIFY, labelled
                // with the ticket) is kept here and notified when the copy ends.
                match self.core.copy_wait(ticket) {
                    copy::Wait::Over(0) => Answer::Status(Status::Ok),
                    copy::Wait::Over(code) => st(code),
                    copy::Wait::Pending => {
                        if r.handles.len() == 1 {
                            let Ok(handle) = r.handles.take::<Channel>(0) else {
                                return Answer::Status(Status::Kernel(abi::Error::WrongType));
                            };
                            // Up to `PER_OWNER` notifications of a session are kept, for one ticket or
                            // several (another thread of the program, or the same one after a
                            // signal); none is told before its copy ends. A session over its share
                            // is told STARTING, and its program backs off.
                            if let copy::Added::Full(_) = self.waiters.add(label, ticket, handle) {
                                return st(l::STARTING);
                            }
                        }
                        match n::write_copying(ticket, r.reply()) {
                            Ok(()) => Answer::Reply(rt::handle::Outgoing::new()),
                            Err(status) => Answer::Status(status),
                        }
                    }
                }
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
                match self.core.read_dir_into(label, handle, r.reply()) {
                    Ok(len) => {
                        #[cfg(feature = "steps")]
                        rt::service::step_detail(7600 + (len as u64 / 64));
                        #[cfg(not(feature = "steps"))]
                        let _ = len;
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
    fn layer(&mut self, method: l::Method, label: u64, r: &mut Request<'_>) -> Answer {
        // The methods that name a layer are the superuser's (NOT_ALLOWED for any other, as for the
        // ones this part serves later), whatever layer they name.
        if !matches!(method, l::Method::List | l::Method::Status) {
            if let Some(place) = self.slot_of(label) {
                self.look(place);
            }
            let root = self
                .slot_of(label)
                .and_then(|p| self.sessions[p].as_ref())
                .and_then(|rec| rec.binding.bound())
                .is_some_and(|v| v.ids.euid == 0);
            if !root {
                return st(l::NOT_ALLOWED);
            }
        }
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
        // The method is the detail of the longest step of its kind (the line of the steps).
        #[cfg(feature = "steps")]
        rt::service::step_detail(u64::from(method));
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
                self.layer(m, r.label(), r)
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
        #[cfg(feature = "steps")]
        serve_line();
        self.core.gone(label);
        self.waiters.drop_owner(label);
        if let Some(place) = self.slot_of(label) {
            self.sessions[place] = None;
        }
    }

    fn notification(&mut self, notice: Notice) {
        if notice.label == LABEL_WALK {
            #[cfg(feature = "steps")]
            rt::service::step_detail(1000);
            self.walk_job();
            return;
        }
        if notice.label == LABEL_COPY {
            #[cfg(feature = "steps")]
            rt::service::step_detail(1100);
            self.copies_ended();
            return;
        }
        #[cfg(feature = "steps")]
        rt::service::step_detail(2000);
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
                let (names, marks) = self.core.left_out();
                if names + marks != 0 {
                    rt::println!(
                        "layerd: {names} names and {marks} marks left out for the buckets of the index (directories among the names take their subtrees with them): the root is served read-only"
                    );
                }
                if self.core.skipped() != 0 {
                    rt::println!(
                        "layerd: {} directories left out: their path passes the volume's limit",
                        self.core.skipped()
                    );
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
