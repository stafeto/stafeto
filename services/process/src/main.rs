// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The POSIX process service (spec 2, section 3.1): it creates every POSIX
//! process itself and keeps its record, PID and credentials. The service
//! gives every session it serves through `handle_label` on its own
//! channel, the label naming the record (proto_process::Label), so the
//! label of a request finds its record in O(1) and no kernel call names a
//! process. Create, Loaded and Abandon come only through the channel
//! with no label, from the service's own receiving thread (adopt.rs),
//! which takes the records init's table starts with ADOPT and loads their
//! programs from the boot image (make.rs), and Replace from the thread
//! that tells init of an exec (replace.rs). Create makes the record, the place of its end, a copy of
//! the channel with NOTIFY and the record's exit label at the process's
//! ceiling, and the process with it, so that the kernel tells the service
//! of the end: the record ends with that notification alone, whoever
//! holds a copy of its session, and waits as a zombie for its parent's
//! wait (WaitStart, WaitTake, WaitCancel: a long operation in two steps,
//! rt::service::LongOps), or goes at once without a parent. Each record
//! has a page in its process (pages.rs) with its identity.
#![no_std]
#![no_main]
use core::cell::UnsafeCell;
#[cfg(feature = "image-probe")]
mod image_probe_main;
use posix_process_service::executable::{ExecCustody, ExecHolder, RetiredExec, Staged};
#[cfg(feature = "image-probe")]
use posix_process_service::image_probe::{self, Terminal};
use posix_process_service::loaders::{self, LOADERS, Loaders, Stage};
use posix_process_service::preparing::{
    self, GroupClaim, Kind as PrepareKind, Phase as PreparePhase, RecordWork,
};
type NativePreparation = preparing::StartPreparation<
    Handle<Process>,
    Handle<Channel>,
    Handle<Memory>,
    Handle<Thread>,
    Pending,
>;
type Work = RecordWork<Replacing, NativePreparation, ending::Ending>;
use posix_process_service::birthwalk::BirthWalk;
use posix_process_service::queue::Queue;
use posix_process_service::records::{self, Exit, GroupError, Join, Record, Records, State};
use posix_process_service::signals::{self, Info, PageStart, Posted};
use posix_process_service::terminals::Terminals;
use posix_process_service::waits::{WAITS_OF_RECORD, Wait, Waits};
use posix_process_service::walk::{self, Step, Target, Walk};
use proto_process::{
    CLD_EXITED, CLD_KILLED, Change, Create, Credentials, End, ForkStart, INIT_PID, Label, LoaderOf,
    Method, PAGE_CHLD_IGNORED, PAGE_NOCLDWAIT, Place, RECORDS, SI_KERNEL, SI_USER, SIGCHLD,
    SIGKILL, SIGNAL_MAX, SIGSTOP, SPAWN_FLAGS, Selector, SetId, SpawnStart, WCONTINUED, WEXITED,
    WNOHANG, WNOWAIT, WSTOPPED, WaitResult, WaitStart,
};
use proto_wire::{Status, Writer, long};
use rt::{
    abi::{self, Access, ObjectKind, Rights, Source},
    handle::{Channel, Handle, Memory, Outgoing, Process, Resource, Thread},
    service::{
        Answer, Config, Heartbeat, LongOps, LongSession, Notice, Pending, Request, Service, Session,
    },
    sys,
};
mod adopt;
mod controller;
mod ending;
mod ends;
mod generations;
mod jobs;
mod loader;
mod make;
mod pages;
mod replace;
mod start;
use core::mem::ManuallyDrop;
rt::entry!(main);
/// The sessions of the loop: those of the service's own threads through
/// the channel with no label at place 0, a record's at its index plus 1,
/// a loader's after them (`Service::place`), and a few for labels no
/// record has: the notary sessions init gives the vouchers, and a session
/// of a record that went, whose place a new record took, which asks there
/// and gets UNREGISTERED, or LIMIT_REACHED while the spare places are
/// taken.
const SESSIONS: usize = PLACED + 8;
/// The places `Service::place` gives.
const PLACED: usize = RECORDS + 1 + LOADERS;
/// Remove only a genuine resident capability. A refusal retains custody;
/// cap removal never proves that its process or thread has ended.
fn close_owned<K: rt::handle::Kind>(owner: &mut Option<Handle<K>>) -> bool {
    let Some(cap) = owner.as_ref() else {
        return true;
    };
    if controller::raw_close(cap.raw().0).is_err() {
        return false;
    }
    owner.take().expect("the removed owner").into_raw();
    true
}

/// Where the service maps the boot image, read-only, for as long as it
/// lives: the programs it loads are read from there.
const IMAGE: usize = 0x50_0000_0000;
/// The waits of the service at most (spec 2, 3.4): 16 of a record, 1024
/// in all; past them a wait is EAGAIN.
const WAITS: usize = 1024;
/// The ExecCommit of a record of init's table that waits until init took
/// the new process (replace.rs): the old image's request, the loader's
/// channel through which the new image hears the record is ready, the
/// copy of the new process for init, the old process, and init's ticket
/// of the record.
struct Replacing {
    pending: Option<Pending>,
    ready: Option<Handle<Channel>>,
    process: Option<Handle<Process>>,
    /// The old process, which the service kills once init took the new.
    old: RetiredExec<Option<Handle<Process>>, Handle<Channel>>,
    old_image: u32,
    ticket: u64,
    key: preparing::Key,
    serial: u64,
    cleanup_cursor: u8,
}
/// A walk of kill(0), kill(-pgid) or kill(-1) that waits (walk.rs): the
/// sender's request, what it sends, and what the steps found so far.
struct Walking {
    walk: Walk,
    pending: Pending,
    signal: u8,
    delivered: bool,
    refused: bool,
    canceled: bool,
    denied: bool,
}
/// The walks of the service that wait for an earlier walk of their sender
/// at most; past them kill is EAGAIN.
const LATER: usize = 64;
#[cfg(any(feature = "tty-probe", feature = "image-probe"))]
const PROBE_METHODS: [u16; proto_process::METHODS.len()
    + if cfg!(feature = "tty-probe") { 2 } else { 0 }
    + if cfg!(feature = "image-probe") { 3 } else { 0 }] = {
    let mut methods = [0; proto_process::METHODS.len()
        + if cfg!(feature = "tty-probe") { 2 } else { 0 }
        + if cfg!(feature = "image-probe") { 3 } else { 0 }];
    let mut i = 0;
    while i < proto_process::METHODS.len() {
        methods[i] = proto_process::METHODS[i];
        i += 1;
    }
    #[cfg(feature = "tty-probe")]
    {
        methods[i] = 42;
        methods[i + 1] = 44;
    }
    #[cfg(feature = "image-probe")]
    {
        let offset = i + if cfg!(feature = "tty-probe") { 2 } else { 0 };
        methods[offset] = image_probe::ARM;
        methods[offset + 1] = image_probe::TRACE;
        methods[offset + 2] = image_probe::CHILD_HANDOFF;
    }
    methods
};
/// The label of the service's own place for the notification that makes
/// the next step of a walk: a service label no record has (its index
/// is past RECORDS).
const STEP: u64 = 1 << 63 | 0xFFFF;
/// What the service holds for a loader (loaders.rs): its thread, the
/// router of the program's signals once the record lives; the copy of its
/// start channel C with NOTIFY, label 2, through which it hears that the
/// record is ready; the parent's SpawnStart, which waits for Boot.
struct Held {
    thread: Option<Handle<Thread>>,
    ready: Option<Handle<Channel>>,
    start: Option<Pending>,
    /// The new process of an exec, which ExecCommit gives the record.
    incoming: Option<Handle<Process>>,
    /// The load is a copy of ForkStart: only ForkCommit and ForkAbort
    /// take it.
    fork: bool,
    exec: ExecCustody<Handle<Channel>>,
    /// First abort reason remains resident across failed Kill attempts.
    outcome: LoaderOutcome,
    abort_ceiling: u8,
    abort_cursor: u8,
}
/// A prepaid serial stops being useful when this attempt aborts. Its
/// storage then retains the first abort reason and paid cleanup cursor.
enum LoaderOutcome {
    None,
    Serial(u64),
    Aborted(Status),
}
impl Held {
    fn abort(&mut self, status: Status) {
        if !matches!(self.outcome, LoaderOutcome::Aborted(_)) {
            self.outcome = LoaderOutcome::Aborted(status);
            self.abort_cursor = 0;
        }
    }
    fn serial(&self) -> u64 {
        match self.outcome {
            LoaderOutcome::Serial(serial) => serial,
            _ => 0,
        }
    }
}
impl ExecHolder for Held {
    type Cap = Handle<Channel>;
    fn exec_custody(&mut self) -> &mut ExecCustody<Self::Cap> {
        &mut self.exec
    }
    fn fork(&self) -> bool {
        self.fork
    }
}
/// What a child of SpawnStart or ForkStart starts with: its spawn-flags
/// and group, the level of its loader, its credentials and its page.
struct Birth {
    flags: u32,
    pgroup: u32,
    level: u8,
    credentials: Credentials,
    page: PageStart,
}
/// What one delivery of a signal to one process came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    Done,
    Denied,
    Refused,
}
struct Processes {
    /// The service's channel, which the sessions are copies of.
    channel: ManuallyDrop<Handle<Channel>>,
    /// The channel the identity sessions are copies of (`vouch`).
    identities: ManuallyDrop<Handle<Channel>>,
    /// The priority of the slot of a session: the loop's level.
    level: u8,
    records: Records<Handle<Process>, Handle<Channel>>,
    /// The ticket init gave each record of its table, 0 for the others.
    tickets: [u64; RECORDS],
    /// The ExecCommit of each record that waits for init, by the record's
    /// index, the records whose new process waits for the thread that
    /// tells init, and that thread's Replace that waits for one.
    replacing: [Option<Work>; RECORDS],
    replace_queue: Queue,
    replacer: controller::Controller,
    replace_cleanup: usize,
    abort_cleanup: usize,
    replace_cursor: usize,
    replace_turn: bool,
    preparing_count: u16,
    preparing_cursor: u16,
    preparing_turn: bool,
    window_owner: Option<(preparing::Key, u16)>,
    /// The pages of the records.
    pages: pages::Pages,
    /// The page of the credentials generations.
    generations: generations::Generations,
    /// The thread of each record's process whose entry the service asks
    /// for once it set a signal on the page (Router).
    routers: [Option<Handle<Thread>>; RECORDS],
    /// The witness of each record's process, which init gave with ADOPT:
    /// it closes once the process ended, and init hears of the end.
    witnesses: [Option<Handle<Channel>>; RECORDS],
    /// The waits that wait: LongOps, and what each takes.
    ops: LongOps<WAITS>,
    waits: Waits<WAITS>,
    /// The walks that wait, by their sender's index, and the order of
    /// their next steps.
    walks: [Option<Walking>; RECORDS],
    walking: Queue,
    /// The walks that wait for an earlier walk of their sender, with the
    /// sender's index.
    later: [Option<(usize, Walking)>; LATER],
    /// The walk of a TtySignal, one at a time: the terminal service waits
    /// for its reply (5f).
    tty_walk: Option<Walking>,
    tty_generation: u64,
    births: BirthWalk,
    orphan_walk: Option<(u32, Walk, bool)>,
    #[cfg(feature = "tty-probe")]
    tty_probe: Option<(usize, u32)>,
    terminal_notice: Option<Handle<Channel>>,
    loader_terminal: Option<Handle<Channel>>,
    /// The controlling terminals of the sessions (5f).
    terminals: Terminals,
    /// The place of the service's channel that tells it of the next step
    /// (STEP), and whether a step was told and not taken.
    step: Option<Handle<Channel>>,
    step_told: bool,
    /// The loaders that run (5c), the loader's program, the session of the
    /// loaders with the RAM file service (proto_fs LOADERS) and a console
    /// for the programs they start.
    loaders: Loaders<Held>,
    loader: Option<loader::Image>,
    files: Option<Handle<Channel>>,
    /// Trusted Clock root, obtained from init before the request loop.
    clock: Option<Handle<Channel>>,
    console: Option<Handle<Resource>>,
}
impl Processes {
    const fn new() -> Self {
        Self {
            channel: Handle::borrowed(abi::Handle::INVALID),
            identities: Handle::borrowed(abi::Handle::INVALID),
            level: 1,
            records: Records::with_exec_custody(),
            tickets: [0; RECORDS],
            replacing: [const { None }; RECORDS],
            replace_queue: Queue::new(),
            replacer: controller::Controller::new(),
            replace_cleanup: 0,
            abort_cleanup: 0,
            replace_cursor: 0,
            replace_turn: false,
            preparing_count: 0,
            preparing_cursor: 0,
            preparing_turn: false,
            window_owner: None,
            pages: pages::Pages::new(),
            generations: generations::Generations::new(),
            witnesses: [const { None }; RECORDS],
            routers: [const { None }; RECORDS],
            ops: LongOps::new(),
            waits: Waits::new(),
            walks: [const { None }; RECORDS],
            walking: Queue::new(),
            later: [const { None }; LATER],
            tty_walk: None,
            tty_generation: 0,
            births: BirthWalk::new(),
            orphan_walk: None,
            #[cfg(feature = "tty-probe")]
            tty_probe: None,
            terminal_notice: None,
            loader_terminal: None,
            terminals: Terminals::new(),
            step: None,
            step_told: false,
            loaders: Loaders::new(),
            loader: None,
            files: None,
            clock: None,
            console: None,
        }
    }
}
/// The loop's state, in .bss: the records are
/// too big for the main thread's stack.
struct Owner(UnsafeCell<Processes>);
// SAFETY: only the main thread reaches it (`main`), once.
unsafe impl Sync for Owner {}
static OWNER: Owner = Owner(UnsafeCell::new(Processes::new()));
fn worker_shared() -> &'static posix_process_service::worker_control::Shared {
    &controller::SHARED
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    // SAFETY: the main thread is the one that reaches OWNER, here once.
    let owner = unsafe { &mut *OWNER.0.get() };
    if let Ok(console) = start.take::<Resource>("console") {
        // A copy for the programs the loaders start, when init gave the
        // service a console it may copy.
        owner.console = sys::handle_duplicate(
            &console,
            Rights::DEBUG | Rights::TRANSFER | Rights::DUPLICATE,
        )
        .ok();
        rt::console::set(console);
    }
    if cfg!(feature = "exit-early") {
        return 9;
    }
    let Ok(image) = start.take::<Memory>("bootimage") else {
        return 2;
    };
    let size = sys::memory_info(&image).map_or(0, |info| info.size);
    if sys::mem_map(&start.process, &image, 0, size, IMAGE, Access::Read).is_err() {
        return 2;
    }
    make::set_image(IMAGE, size as usize);
    // SAFETY: the boot image stays mapped read-only at IMAGE for the
    // service's life.
    let boot: &'static [u8] =
        unsafe { core::slice::from_raw_parts(IMAGE as *const u8, size as usize) };
    owner.loader = bootimg::BootImage::parse(boot)
        .ok()
        .and_then(|boot| loader::Image::new(boot, &start.process));
    let Ok(channel) = sys::channel_create(1) else {
        return 3;
    };
    // The channel of the identity sessions: object_info LABEL of a copy
    // shows which record's it is (`vouch`), and the thread of ends.rs takes
    // what comes into it.
    let Ok(identities) = sys::channel_create(1) else {
        return 3;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 4;
    }
    let level = sys::thread_info(&start.thread).map_or(1, |i| i.base);
    make::set_handles(&channel, &start.process, &start.parent, level);
    // The session of the loaders with the RAM file service, when init's
    // table gives one (proto_fs LOADERS): every loader gets a copy.
    if owner.loader.is_some() {
        owner.files = rt::service::connect(&start.parent, "ramfs").ok();
        owner.clock = rt::service::connect(&start.parent, "clock").ok();
    }
    if adopt::start(&start.process, level).is_err()
        || ends::start(&start.process, &identities, level).is_err()
    {
        return 6;
    }
    let args = proto_init::ServiceArgs::read(start.args()).ok();
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &start.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    owner.channel = Handle::borrowed(channel.raw());
    owner.identities = Handle::borrowed(identities.raw());
    owner.level = level;
    if owner.generations.make(&start.process).is_err() {
        return 7;
    }
    // The notification of a step goes to the loop's own channel at its
    // level, so that a step waits in the queue with the requests.
    let Ok(step) = sys::handle_label(&channel, Rights::NOTIFY, STEP, level) else {
        return 7;
    };
    owner.step = Some(step);
    owner.replacer.refresh = owner.files.is_none();
    if replace::start(
        &start.process,
        level,
        owner.step.as_ref().expect("the step source"),
        &mut owner.replacer,
    )
    .is_err()
    {
        return 6;
    }
    #[cfg(feature = "steps")]
    rt::service::report_steps(1);
    rt::println!("posix-process: ready (records with their processes, root by init's table)");
    rt::println!(
        "posix-process: loader {}",
        if owner.loader.is_some() && owner.files.is_some() && owner.clock.is_some() {
            "ready"
        } else {
            "absent"
        }
    );
    let _ = rt::service::run::<Processes, SESSIONS, 0>(&channel, owner, config);
    5
}
fn snapshot(r: &mut Request<'_>, record: &Record<Handle<Process>, Handle<Channel>>) {
    let w = r.reply();
    w.u32(0)
        .and_then(|()| w.u32(record.label.pid()))
        .and_then(|()| w.u32(record.parent))
        .expect("process snapshot identity");
    for id in record.credentials.words() {
        w.u32(id).expect("process credentials");
    }
}
fn refuse(code: u32) -> Answer {
    Answer::Status(Status::from_code(code))
}
/// The status of a failed call of groups and sessions.
const fn group_error(e: GroupError) -> u32 {
    match e {
        GroupError::NoProcess => proto_process::NO_PROCESS,
        GroupError::Permission => proto_process::PERMISSION,
        GroupError::Access => proto_process::ACCESS,
    }
}
/// A reply of status 0 and the number `n`.
fn number(r: &mut Request<'_>, n: u32) -> Answer {
    let w = r.reply();
    if w.u32(0).and_then(|()| w.u32(n)).is_err() {
        return Answer::Status(Status::BadSize);
    }
    Answer::Reply(Outgoing::new())
}
impl Processes {
    /// Create (label 0): a record of init's table, LOADING, of a new
    /// process with the parameters of the body and the start channel the
    /// request brought, the process's end told through the record's exit
    /// place (O(1)). The reply: the PID and the label, a copy of the
    /// process for the load and the record's session. FULL with every
    /// record taken; a resident preparation retains native resources
    /// through bounded effects and exact cleanup before its final reply.
    fn create(&mut self, r: &mut Request<'_>) -> Answer {
        let Ok(create) = Create::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        if r.handles.len() != 2 {
            return Answer::Status(Status::BadSize);
        }
        let (Ok(start), Ok(witness)) = (r.handles.take::<Channel>(0), r.handles.take::<Channel>(1))
        else {
            return Answer::Status(Status::BadSize);
        };
        let Some(label) = self.records.next_label() else {
            return refuse(proto_process::FULL);
        };
        if self.replacing[usize::from(label.index)].is_some()
            || self.loaders.of(usize::from(label.index)).is_some()
        {
            return refuse(proto_process::FULL);
        }
        if !self.generations.room(usize::from(label.index), 1) {
            self.records.retire_next(label);
            return refuse(proto_process::FULL);
        }
        let Some(pending) = r.defer() else {
            return refuse(proto_process::FULL);
        };
        let reservation = self
            .records
            .reserve_next()
            .expect("the preflighted record slot");
        let key = preparing::Key { label, image: 1 };
        let mut work = NativePreparation::new(
            key,
            PrepareKind::Initial { create },
            preparing::Origin {
                parent: None,
                credentials_generation: 0,
            },
            create.priority,
            pending,
        );
        work.reservation = Some(reservation);
        work.identity = [label.pid(), INIT_PID, label.pid(), label.pid()];
        work.resources.start = Some(start);
        work.resources.witness = Some(witness);
        self.replacing[usize::from(label.index)] = Some(Work::Preparing(work));
        self.preparing_count += 1;
        self.kick();
        Answer::Deferred
    }

    /// Loaded (label 0) of the LOADING record the body names, with its
    /// first thread, the router of its signals: it is ALIVE. UNREGISTERED
    /// for a label of no such record.
    fn loaded(&mut self, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(label), Ok(thread)) = (body.u64(), r.handles.take::<Thread>(0)) else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let Some(index) = self.records.find(label) else {
            return refuse(proto_process::UNREGISTERED);
        };
        let Some(record) = self
            .records
            .get_mut(index)
            .filter(|r| r.state == State::Loading)
        else {
            return refuse(proto_process::UNREGISTERED);
        };
        record.state = State::Alive;
        // The first thread routes the process's signals (spec 2, 3.3).
        self.routers[index] = Some(thread);
        Answer::Status(Status::Ok)
    }

    /// Abandon (label 0): the LOADING record of the body's label, if any,
    /// is killed, and goes with the end of its process. UNREGISTERED for a
    /// label of no LOADING record.
    fn abandon(&mut self, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let Ok(label) = body.u64() else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if label == 0 {
            return Answer::Status(Status::Ok);
        }
        let Some(record) = self
            .records
            .find(label)
            .and_then(|i| self.records.get(i))
            .filter(|r| r.state == State::Loading)
        else {
            return refuse(proto_process::UNREGISTERED);
        };
        let _ = sys::process_kill(&record.process);
        Answer::Status(Status::Ok)
    }
}
/// A READY reply of a wait with `result`.
fn ready(r: &mut Request<'_>, result: WaitResult) -> Answer {
    let mut bytes = Writer::new();
    if result.write(&mut bytes).is_err()
        || long::Reply::Ready(bytes.as_bytes())
            .write(r.reply())
            .is_err()
    {
        return Answer::Status(Status::BadSize);
    }
    Answer::Reply(Outgoing::new())
}
/// A reply of a wait that is not READY.
fn long_reply(r: &mut Request<'_>, reply: long::Reply<'_>) -> Answer {
    match reply.write(r.reply()) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}
impl Processes {
    /// The wait of `key` while it waits.
    fn wait(&self, key: u64) -> Option<Wait> {
        self.waits.get(key, |w| self.ops.waits(w.label, w.key))
    }

    /// The child in `child` of the record in `parent` ended: the waits of
    /// the parent that take it are told, WAITS_OF_RECORD at most; the
    /// others, and the waits of other records, are not.
    fn tell(&mut self, parent: usize, child: usize) {
        let (records, ops) = (&self.records, &self.ops);
        let told = self.waits.told(
            parent,
            |selector| records.takes(child, selector),
            |w| ops.waits(w.label, w.key),
        );
        let told: [Option<Wait>; WAITS_OF_RECORD] = {
            let mut list = [None; WAITS_OF_RECORD];
            for (place, w) in list.iter_mut().zip(told) {
                *place = Some(w);
            }
            list
        };
        for w in told.into_iter().flatten() {
            self.ops.tell(w.label, w.key);
        }
    }

    /// A child of the record in `parent` moved between groups (the waits of its parent when it
    /// moved itself): the waits of `parent` for a
    /// group are told, for the child that left the group is none of
    /// theirs now (ECHILD when it was the last). WAITS_OF_RECORD tells at
    /// most, as the end of a child.
    fn tell_groups(&mut self, parent: usize) {
        let ops = &self.ops;
        let mut list = [None; WAITS_OF_RECORD];
        let found = self.waits.told(
            parent,
            |selector| matches!(selector, Selector::Group(_)),
            |w| ops.waits(w.label, w.key),
        );
        for (place, w) in list.iter_mut().zip(found) {
            *place = Some(w);
        }
        for w in list.into_iter().flatten() {
            self.ops.tell(w.label, w.key);
        }
    }

    /// The record in `index` moved between groups itself: its parent's
    /// waits for a group are told.
    fn tell_parent_groups(&mut self, index: usize) {
        if let Some(parent) = self.records.get(index).and_then(|r| r.parent_index) {
            self.tell_groups(usize::from(parent));
        }
    }

    /// What a wait of the record in `parent` with `selector` and `options`
    /// finds now: the first zombie child it takes, which goes unless
    /// WNOWAIT (the parent's other waits that take it are told); ECHILD
    /// with no child it takes; None while it waits. CHILDREN_MAX steps.
    fn found(&mut self, parent: usize, selector: Selector, options: u32) -> Option<WaitResult> {
        let Some((child, result)) = self.records.reported(parent, selector, options) else {
            let any = self
                .records
                .children(parent)
                .any(|c| self.records.takes(c, selector));
            return (!any).then_some(WaitResult::NoChild);
        };
        if options & WNOWAIT == 0 {
            if matches!(result, WaitResult::Ended { .. }) {
                self.reap_wait_retained(parent, child);
                self.kick();
            } else {
                self.tell(parent, child);
                self.records.consume_report(child, result);
            }
        }
        Some(result)
    }

    /// WaitStart of the record in `index`: READY with what the wait finds
    /// now (`found`), with nothing for WNOHANG, else WAIT k, its key
    /// kept for the record (LONG_SESSION_MAX of them; EAGAIN past them or
    /// past WAITS). INVALID without WEXITED, WSTOPPED or WCONTINUED.
    fn wait_start(
        &mut self,
        index: usize,
        s: &mut Session<LongSession, 0>,
        r: &mut Request<'_>,
    ) -> Answer {
        let Ok(start) = WaitStart::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        if start.options & (WEXITED | WSTOPPED | WCONTINUED) == 0 {
            return refuse(proto_process::INVALID);
        }
        if let Some(result) = self.found(index, start.selector, start.options) {
            return ready(r, result);
        }
        if start.options & WNOHANG != 0 {
            return ready(r, WaitResult::Nothing);
        }
        let key = match self.ops.start(&mut s.data, r.label()) {
            Ok(key) => key,
            Err(e) => return Answer::Status(Status::Kernel(e)),
        };
        let wait = Wait {
            label: r.label(),
            key,
            parent: index,
            selector: start.selector,
            options: start.options,
        };
        let ops = &self.ops;
        if !self.waits.add(wait, |w| ops.waits(w.label, w.key)) {
            self.ops.finish(&mut s.data, r.label(), key);
            return Answer::Status(Status::Kernel(abi::Error::LimitReached));
        }
        long_reply(r, long::Reply::Wait(key))
    }

    /// WaitTake of key k with the caller's labelled copy of its channel
    /// (NOTIFY), or without one after a tell: READY with what the wait
    /// finds now, the wait over; or ARMED, the copy kept to tell, again
    /// after a tell that found nothing. BAD_STATE for a key of no wait.
    fn wait_take(
        &mut self,
        index: usize,
        s: &mut Session<LongSession, 0>,
        r: &mut Request<'_>,
    ) -> Answer {
        let mut body = r.body();
        let Ok(key) = body.u64() else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() || r.handles.len() > 1 {
            return Answer::Status(Status::BadSize);
        }
        let Some(w) = self
            .wait(key)
            .filter(|w| w.label == r.label() && w.parent == index)
        else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        if let Some(result) = self.found(index, w.selector, w.options) {
            self.ops.finish(&mut s.data, r.label(), key);
            return ready(r, result);
        }
        if r.handles.len() == 1 {
            let notifies = matches!(r.handles.info(0), Some((ObjectKind::Channel, rights)) if rights.contains(Rights::NOTIFY));
            let Some(copy) = notifies
                .then(|| r.handles.take::<Channel>(0).ok())
                .flatten()
            else {
                return Answer::Status(Status::BadSize);
            };
            if let Err(e) = self.ops.arm(r.label(), key, copy) {
                return Answer::Status(Status::Kernel(e));
            }
        } else {
            // A take after a tell found nothing (another wait took the
            // zombie, or SA_NOCLDWAIT reaped it): the next end tells again.
            self.ops.untell(r.label(), key);
        }
        long_reply(r, long::Reply::Armed)
    }

    /// WaitCancel of key k: READY with what the wait finds now, else
    /// CANCELLED; the wait is over either way.
    fn wait_cancel(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let Ok(key) = body.u64() else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let found = self
            .wait(key)
            .filter(|w| w.label == r.label())
            .and_then(|w| self.found(w.parent, w.selector, w.options));
        self.ops.finish(&mut s.data, r.label(), key);
        match found {
            Some(result) => ready(r, result),
            None => long_reply(r, long::Reply::Cancelled),
        }
    }
}
impl Processes {
    /// A request through a notary session, which init gives the services
    /// of its VOUCHERS: Register, a copy of the page of the generations to
    /// read; Vouch, who brought the handle the request brings (`vouch`).
    /// Nothing else (PERMISSION).
    fn notary(&mut self, r: &mut Request<'_>) -> Answer {
        let method = r.method();
        #[cfg(feature = "tty-probe")]
        if method == 44 {
            if !proto_process::is_terminal(r.label()) {
                return refuse(proto_process::PERMISSION);
            }
            let mut body = r.body();
            let (Ok(group), Ok(sid), Ok(())) = (body.u32(), body.u32(), body.finish()) else {
                return Answer::Status(Status::BadSize);
            };
            if self.records.get(RECORDS - 1).is_some() || self.terminals.session(0) != Some(sid) {
                return refuse(proto_process::PERMISSION);
            }
            self.generations
                .set_groups(RECORDS - 1, (group != 0).then_some((group, sid)));
            return Answer::Status(Status::Ok);
        }
        #[cfg(feature = "tty-probe")]
        if method == 42 {
            return if proto_process::is_terminal(r.label()) {
                self.probe_newborn(r)
            } else {
                refuse(proto_process::PERMISSION)
            };
        }
        if method == Method::SetId as u16 {
            return self.set_id(r);
        }
        if method == Method::StageExec as u16 {
            return self.stage_exec(r);
        }
        let terminal = [
            Method::TtySignal,
            Method::SetCtty,
            Method::DropCtty,
            Method::DetachCtty,
            Method::TtyEvents,
            Method::AckCtty,
            Method::DisconnectCtty,
        ];
        if terminal.map(|m| m as u16).contains(&method) {
            if !proto_process::is_terminal(r.label()) {
                return refuse(proto_process::PERMISSION);
            }
            return self.terminal_request(method, r);
        }
        if method == Method::RetainedLoader as u16 {
            return self.retained_loader(r);
        }
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        if method == Method::Register as u16
            && (r.handles.is_empty()
                || proto_process::is_terminal(r.label()) && r.handles.len() == 2)
        {
            if !r.handles.is_empty() {
                let notice = matches!(r.handles.info(0), Some((ObjectKind::Channel, rights)) if rights.contains(Rights::NOTIFY));
                let loader = matches!(r.handles.info(1), Some((ObjectKind::Channel, rights)) if rights.contains(Rights::SEND | Rights::DUPLICATE));
                if !notice || !loader {
                    return Answer::Status(Status::BadSize);
                }
            }
            let Ok(copy) = self.generations.copy() else {
                return Answer::Status(Status::Kernel(abi::Error::NoMemory));
            };
            if r.reply().u32(0).is_err() {
                return Answer::Status(Status::BadSize);
            }
            if proto_process::is_terminal(r.label()) && r.handles.len() == 2 {
                self.terminal_notice = r.handles.take::<Channel>(0).ok();
                self.loader_terminal = r.handles.take::<Channel>(1).ok();
            }
            return Answer::Reply([copy.erase()].into());
        }
        if method != Method::Vouch as u16 {
            return refuse(proto_process::PERMISSION);
        }
        let Some((index, loader)) = self.vouch(r) else {
            return refuse(proto_process::PERMISSION);
        };
        let record = self.records.get(index).expect("a vouched record");
        let who = proto_process::Vouch {
            pid: record.label.pid(),
            credentials: record.credentials,
            generation: self.generations.get(index),
            loader,
            index: index as u32,
            ctty: record.ctty,
            image: loader.map_or(record.image, |l| l.image),
            groups: &record.groups,
            limits: &record.limits,
            root: record.root,
        };
        if who.write(r.reply()).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    /// The record whose identity session the one handle of `r` is a copy
    /// of: the kernel gives the copy's label to the service, which receives
    /// on the identity channel (object_info LABEL, O(1)); a channel of
    /// anyone else, or one without a label, proves nothing. Nothing goes
    /// through the copy and nothing is taken off the channel, so the step
    /// is the same with any number of processes, and on any number of
    /// processors.
    ///
    /// A copy of a loader's identity names its record only while the
    /// loader loads (loaders.rs `vouches`), with the image and the ticket
    /// of its place.
    fn vouch(&mut self, r: &mut Request<'_>) -> Option<(usize, Option<LoaderOf>)> {
        if r.handles.len() != 1 {
            return None;
        }
        let handle = r.handles.take::<Channel>(0).ok()?;
        let label = sys::copy_label(&self.identities, &handle).ok()?;
        match Label::parse(label) {
            Some((_, Place::Loader)) => {
                let index = self.records.find_loader(label)?;
                let ticket = self.loaders.vouches(index)?;
                let place = self.loaders.get(self.loaders.of(index)?)?;
                let image = place.image;
                // A loader of another attempt of the record names nothing.
                let (_, _, named) = Label::parse_image(label)?;
                (named == image).then_some((index, Some(LoaderOf { image, ticket })))
            }
            _ => {
                let index = self.records.find_identity(label)?;
                self.records
                    .get(index)?
                    .state
                    .live()
                    .then_some((index, None))
            }
        }
    }

    fn retained_loader(&mut self, r: &mut Request<'_>) -> Answer {
        let Ok(expected) = proto_process::RetainedLoader::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let Ok(identity) = r.handles.take::<Channel>(0) else {
            return refuse(proto_process::PERMISSION);
        };
        let Ok(label) = sys::copy_label(&self.identities, &identity) else {
            return refuse(proto_process::PERMISSION);
        };
        let Some((named, Place::Loader, image)) = Label::parse_image(label) else {
            return refuse(proto_process::PERMISSION);
        };
        let Some(index) = self.records.find_loader(label) else {
            return refuse(proto_process::PERMISSION);
        };
        let record = self.records.get(index).expect("an exact retained record");
        if expected.pid != named.pid()
            || expected.index as usize != index
            || expected.image != image
            || expected.root != record.root
            || !record.state.live()
            || self.generations.get(index) & proto_process::GENERATION_DEAD != 0
        {
            return refuse(proto_process::PERMISSION);
        }
        let Some(state) = self.loaders.retained(
            index,
            image,
            expected.ticket,
            record.image,
            record.committed_loader_ticket,
            record.state == State::Alive,
        ) else {
            return refuse(proto_process::PERMISSION);
        };
        let who = proto_process::Vouch {
            pid: record.label.pid(),
            credentials: record.credentials,
            generation: self.generations.get(index),
            loader: Some(LoaderOf {
                image,
                ticket: expected.ticket,
            }),
            index: index as u32,
            ctty: record.ctty,
            image,
            groups: &record.groups,
            limits: &record.limits,
            root: record.root,
        };
        if r.reply()
            .u32(0)
            .and_then(|()| r.reply().u32(state as u32))
            .and_then(|()| who.write(r.reply()))
            .is_err()
        {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    /// Router of the record in `index`: one thread handle with MANAGE, the
    /// thread whose entry routes the process's signals (spec 2, 3.3); a
    /// signal that waits on the page already asks for its entry at once.
    fn router(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let manages = matches!(r.handles.info(0), Some((ObjectKind::Thread, rights)) if rights.contains(Rights::MANAGE));
        let Some(thread) = manages.then(|| r.handles.take::<Thread>(0).ok()).flatten() else {
            return refuse(proto_process::PERMISSION);
        };
        let waiting = self.pages.page(index).is_some_and(|p| {
            p.pending.load(core::sync::atomic::Ordering::Acquire)
                | proto_process::job::bits(
                    p.stop_word.load(core::sync::atomic::Ordering::Acquire),
                    p.cont_word.load(core::sync::atomic::Ordering::Acquire),
                )
                != 0
        });
        if waiting {
            let _ = sys::thread_upcall_request(&thread);
        }
        self.routers[index] = Some(thread);
        Answer::Status(Status::Ok)
    }

    /// Posts `signal` with `info` to the process of the record in `target`
    /// and asks for its router's entry when it waits now (O(1)).
    fn signal(&mut self, target: usize, signal: u8, info: Info) {
        if !self.records.get(target).is_some_and(|r| r.state.live()) {
            return;
        }
        if proto_process::job::class(signal).is_some() || signal == SIGSTOP {
            if self.generate_job(target, signal).is_none() {
                return;
            }
            if signal == SIGSTOP {
                return;
            }
        }
        let Some(page) = self.pages.page(target) else {
            return;
        };
        if signals::post(page, signal, info) == Posted::Pending
            && let Some(router) = self.routers[target].as_ref()
        {
            // A router that ended asks nothing; the signal waits on the
            // page for a thread that unblocks or waits for it.
            let _ = sys::thread_upcall_request(router);
        }
    }

    /// Delivers `signal` from the record in `sender` to the process of the
    /// record in `target`: Denied past kill's rule (`signals::may_signal`),
    /// Refused for a signal outside the supported range; signal 0 and a
    /// zombie take nothing; SIGKILL
    /// ends the process from the service at the target's ceiling
    /// (process_kill_at); any other is posted on the target's page
    /// (`signal`). O(1).
    fn deliver(&mut self, sender: usize, target: usize, signal: u8) -> Delivery {
        let from = self.records.get(sender).expect("the sender");
        if !from.state.live() {
            return Delivery::Denied;
        }
        let (from_pid, creds, from_session) = (from.label.pid(), from.credentials, from.sid);
        let record = self.records.get(target).expect("a target");
        if !signals::may_signal(
            creds,
            record.credentials,
            signal,
            from_session == record.sid,
        ) {
            return Delivery::Denied;
        }
        let zombie = !record.state.live();
        if signal == 0 || zombie {
            return Delivery::Done;
        }
        if signal == SIGKILL {
            let _ = sys::process_kill_at(&record.process, record.ceiling);
            return Delivery::Done;
        }
        let Some(page) = self.pages.page(target) else {
            return Delivery::Refused;
        };
        if signals::refused(signal, page) || !self.can_generate_job(target, signal) {
            return Delivery::Refused;
        }
        let info = Info {
            code: SI_USER,
            pid: from_pid,
            uid: creds.uid,
            status: 0,
        };
        self.signal(target, signal, info);
        Delivery::Done
    }

    /// Kill of the record in `index`: pid (an i32 as a u32) and signal
    /// u32. A pid above 0 names one process: NO_PROCESS for no live or
    /// zombie process of that PID (a LOADING one is none yet), PERMISSION
    /// and INVALID as `deliver` says, and the reply comes once the signal
    /// is there: the caller's layer looks at its own page before its
    /// return. 0 is the sender's group, -1 every process but the sender's,
    /// below -1 the group -pid: a walk over the records, one step at a
    /// time, whose reply comes at its end (`walk_start`).
    fn kill(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(pid), Ok(signal)) = (body.u32(), body.u32()) else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let Ok(signal) = u8::try_from(signal) else {
            return refuse(proto_process::INVALID);
        };
        let pid = pid as i32;
        if pid <= 0 {
            return self.walk_start(index, pid, signal, r);
        }
        let Some(target) = self.records.find_pid(pid as u32).filter(|&t| {
            self.records.get(t).is_some_and(|r| {
                !r.state.end_pending()
                    && (r.state != State::Loading
                        || signal == SIGKILL
                        || signal == SIGSTOP
                        || proto_process::job::class(signal).is_some())
            })
        }) else {
            return refuse(proto_process::NO_PROCESS);
        };
        match self.deliver(index, target, signal) {
            Delivery::Done => Answer::Status(Status::Ok),
            Delivery::Denied => refuse(proto_process::PERMISSION),
            Delivery::Refused => refuse(proto_process::INVALID),
        }
    }

    /// The start of a walk of `index` for `pid` of 0 or below: INVALID for
    /// a signal past SIGNAL_MAX; NO_PROCESS at once for a
    /// group nobody is in; AGAIN while the sender's other walk is on; else
    /// the request waits for the steps (`walk_step`).
    fn walk_start(&mut self, index: usize, pid: i32, signal: u8, r: &mut Request<'_>) -> Answer {
        if signal > SIGNAL_MAX {
            return refuse(proto_process::INVALID);
        }
        let own = self.records.get(index).expect("the sender").pgid;
        let target = match pid {
            0 => Target::Group(own),
            -1 => Target::All,
            p => Target::Group(p.unsigned_abs()),
        };
        if matches!(target, Target::Group(g) if self.records.members(g) == 0) {
            return refuse(proto_process::NO_PROCESS);
        }
        let busy = self.walks[index].is_some();
        let free = self.later.iter().position(Option::is_none);
        if busy && free.is_none() {
            return refuse(proto_process::AGAIN);
        }
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::BadSize);
        };
        let walking = Walking {
            walk: Walk::new(target, index),
            pending,
            signal,
            delivered: false,
            refused: false,
            canceled: false,
            denied: false,
        };
        if busy {
            // A second walk of the sender waits for the first (no EAGAIN
            // in kill): LATER of them in the service.
            self.later[free.expect("a free place")] = Some((index, walking));
            return Answer::Deferred;
        }
        self.walks[index] = Some(walking);
        self.walking.push(index);
        self.kick();
        Answer::Deferred
    }

    /// Tells the loop of a step of the walks that wait, unless one is
    /// told already: a notification to the loop's own channel, which comes
    /// in its turn between the requests. When the call fails the walks
    /// that wait are answered AGAIN, none is left waiting for a step that
    /// never comes.
    fn kick(&mut self) {
        if !self.step_told
            && (self.tty_walk.is_some()
                || self.orphan_walk.is_some()
                || self.records.has_orphans()
                || self.replace_cleanup != 0
                || self.abort_cleanup != 0
                || self.controller_needed()
                || self.preparing_count != 0)
        {
            if self
                .step
                .as_ref()
                .is_some_and(|s| sys::notify(s, 1).is_ok())
            {
                self.step_told = true;
            } else if let Some(w) = self.tty_walk.take() {
                self.births.clear_tty();
                self.tty_generation = 0;
                let status = Status::from_code(proto_process::AGAIN);
                let _ = w
                    .pending
                    .answer(&proto_wire::reply(status), Outgoing::new());
            }
        }
        while !self.step_told && !self.walking.is_empty() {
            if self
                .step
                .as_ref()
                .is_some_and(|s| sys::notify(s, 1).is_ok())
            {
                self.step_told = true;
                return;
            }
            let Some(index) = self.walking.pop() else {
                return;
            };
            if let Some(w) = self.walks[index].take() {
                self.births.clear(index);
                let status = Status::from_code(proto_process::AGAIN);
                let _ = w
                    .pending
                    .answer(&proto_wire::reply(status), Outgoing::new());
            }
        }
    }

    /// One step of the walk at the head of the queue (walk.rs): one
    /// delivery, or a look at up to LOOKS places; the walk goes to the
    /// tail unless it is done, and its sender's request is answered with
    /// what the steps found: Ok when a process took the signal, else
    /// INVALID for one it refuses, PERMISSION when processes were there
    /// and none could be signalled, NO_PROCESS for none.
    fn walk_step(&mut self) {
        self.step_told = false;
        if self.preparing_count != 0 {
            self.preparing_turn = !self.preparing_turn;
            let other = self.replace_cleanup != 0
                || self.abort_cleanup != 0
                || self.tty_walk.is_some()
                || self.orphan_walk.is_some()
                || self.records.has_orphans()
                || !self.walking.is_empty();
            let other = other || self.controller_needed();
            if self.preparing_turn || !other {
                rt::service::step_own();
                self.prepare_step();
                self.kick();
                return;
            }
        }
        if self.controller_needed() {
            self.replacer.turn = !self.replacer.turn;
            if self.replacer.turn
                || self.replace_cleanup == 0
                    && self.abort_cleanup == 0
                    && self.tty_walk.is_none()
                    && self.orphan_walk.is_none()
                    && !self.records.has_orphans()
                    && self.walking.is_empty()
            {
                rt::service::step_own();
                self.controller_step();
                self.kick();
                return;
            }
        }
        if self.replace_cleanup != 0 || self.abort_cleanup != 0 {
            self.replace_turn = !self.replace_turn;
            if self.replace_turn {
                rt::service::step_own();
                self.replace_cleanup_step();
                self.kick();
                return;
            }
        }
        // A walk of the terminal goes first: the terminal service waits
        // for it, and its input with it.
        if self.tty_walk.is_some() {
            rt::service::step_own();
            self.tty_walk_step();
            self.kick();
            return;
        }
        if self.orphan_walk.is_some() || self.records.has_orphans() {
            rt::service::step_own();
            self.orphan_step();
            self.kick();
            return;
        }
        let Some(index) = self.walking.pop() else {
            self.kick();
            return;
        };
        let Some(mut w) = self.walks[index].take() else {
            self.kick();
            return;
        };
        let step = if w.canceled {
            Step::Done
        } else {
            w.walk.step(&self.records)
        };
        match step {
            Step::Found(target) => match self.deliver(index, target, w.signal) {
                Delivery::Done => w.delivered = true,
                Delivery::Denied => w.denied = true,
                Delivery::Refused => w.refused = true,
            },
            Step::Looked => {}
            Step::Done => {
                if self.births.holds(index) {
                    self.walks[index] = Some(w);
                    self.walking.push(index);
                    self.kick();
                    return;
                }
                let code = walk::outcome(w.delivered, w.refused, w.denied);
                let status = if w.canceled {
                    Status::Kernel(abi::Error::PeerClosed)
                } else {
                    Status::from_code(code)
                };
                let _ = w
                    .pending
                    .answer(&proto_wire::reply(status), Outgoing::new());
                // The sender's next walk, which waited, starts.
                let next = self
                    .later
                    .iter()
                    .position(|l| l.as_ref().is_some_and(|(s, _)| *s == index));
                if let Some((_, next)) = next.and_then(|n| self.later[n].take()) {
                    self.walks[index] = Some(next);
                    self.walking.push(index);
                }
                self.kick();
                return;
            }
        }
        self.walks[index] = Some(w);
        self.walking.push(index);
        self.kick();
    }

    /// A child just made in `index` whose group a walk passed already gets
    /// that walk's signal at its birth (walk.rs `takes_newborn`): a member
    /// that spawns while kill(-pgid) or kill(-1) is on leaves no child
    /// behind the cursor. Only while walks are on: RECORDS looks then.
    #[cfg(feature = "tty-probe")]
    fn signal_newborn(&mut self, index: usize) {
        let pgid = self.records.get(index).map_or(0, |r| r.pgid);
        if let Some(w) = self.tty_walk.as_ref()
            && w.walk.takes_newborn(index, pgid)
        {
            let signal = w.signal;
            let delivery = self.deliver_terminal(index, signal);
            if let Some(w) = self.tty_walk.as_mut() {
                match delivery {
                    Delivery::Done => w.delivered = true,
                    Delivery::Denied => w.denied = true,
                    Delivery::Refused => w.refused = true,
                }
            }
        }
        if self.walking.is_empty() {
            return;
        }
        let pgid = self.records.get(index).map_or(0, |r| r.pgid);
        for sender in 0..RECORDS {
            let Some(w) = self.walks[sender].as_ref() else {
                continue;
            };
            if !w.walk.takes_newborn(index, pgid) {
                continue;
            }
            let signal = w.signal;
            let delivery = self.deliver(sender, index, signal);
            if let Some(w) = self.walks[sender].as_mut() {
                match delivery {
                    Delivery::Done => w.delivered = true,
                    Delivery::Denied => w.denied = true,
                    Delivery::Refused => w.refused = true,
                }
            }
        }
    }

    fn capture_newborn(&mut self, key: preparing::Key) {
        let index = usize::from(key.label.index);
        let pgid = self.records.get(index).expect("a published newborn").pgid;
        let tty = self
            .tty_walk
            .as_ref()
            .filter(|w| !w.canceled && w.walk.takes_newborn(index, pgid))
            .map(|_| self.tty_generation);
        let walks = &self.walks;
        let records = &self.records;
        self.births.capture(key, tty, |sender| {
            walks[sender].as_ref().is_some_and(|w| {
                !w.canceled
                    && posix_process_service::birthwalk::eligible(
                        &w.walk,
                        records,
                        w.pending.label(),
                        sender,
                        index,
                        pgid,
                    )
            })
        });
    }

    /// One captured walk delivery; neither other walk cursors nor ahead
    /// walks are held. The caller keeps its Work and thread unborn.
    fn newborn_step(&mut self, key: preparing::Key) -> Result<bool, abi::Error> {
        if self.births.key() != Some(key) {
            return Err(abi::Error::BadState);
        }
        let index = usize::from(key.label.index);
        let record = self
            .records
            .get(index)
            .filter(|r| r.label == key.label && r.image == key.image);
        let Some(record) = record else {
            self.births.removed(key);
            return Err(abi::Error::PeerClosed);
        };
        if record.state.end_pending() {
            self.births.removed(key);
            return Err(abi::Error::PeerClosed);
        }
        if !matches!(record.state, State::Loading | State::Zombie(_)) {
            return Err(abi::Error::BadState);
        }
        if let Some(generation) = self.births.tty() {
            let signal = self
                .tty_walk
                .as_ref()
                .filter(|w| !w.canceled && generation == self.tty_generation)
                .map(|w| w.signal);
            if let Some(signal) = signal {
                let result = self.deliver_terminal(index, signal);
                let w = self.tty_walk.as_mut().expect("the same terminal walk");
                match result {
                    Delivery::Done => w.delivered = true,
                    Delivery::Denied => w.denied = true,
                    Delivery::Refused => w.refused = true,
                }
            }
            self.births.clear_tty();
            return Ok(false);
        }
        if let Some(sender) = self.births.next() {
            let signal = self.walks[sender]
                .as_ref()
                .filter(|w| !w.canceled && self.records.find(w.pending.label()) == Some(sender))
                .map(|w| w.signal);
            if let Some(signal) = signal {
                let result = self.deliver(sender, index, signal);
                let w = self.walks[sender].as_mut().expect("the same sender walk");
                match result {
                    Delivery::Done => w.delivered = true,
                    Delivery::Denied => w.denied = true,
                    Delivery::Refused => w.refused = true,
                }
            } else if let Some(w) = self.walks[sender].as_mut() {
                w.canceled = true;
            }
            self.births.clear(sender);
            return Ok(false);
        }
        assert!(self.births.release(key));
        Ok(true)
    }

    /// Keep canceled replies resident until their ordinary paid walk visit.
    fn cancel_walks(&mut self, label: u64) {
        for sender in 0..RECORDS {
            if let Some(w) = self.walks[sender].as_mut()
                && w.pending.label() == label
            {
                self.births.clear(sender);
                w.canceled = true;
            }
        }
        for (_, w) in self.later.iter_mut().flatten() {
            if w.pending.label() == label {
                w.canceled = true;
            }
        }
        if let Some(w) = self.tty_walk.as_mut()
            && w.pending.label() == label
        {
            self.births.clear_tty();
            w.canceled = true;
        }
        self.kick();
    }

    /// The group and session of the record in `index` in the second half
    /// of the page of the generations, where the terminal service reads
    /// them (5f).
    fn publish_groups(&self, index: usize) {
        let groups = self.records.get(index).map(|r| (r.pgid, r.sid));
        self.generations.set_groups(index, groups);
    }

    /// TtySignal, SetCtty or DropCtty of the terminal service (5f).
    fn terminal_request(&mut self, method: u16, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let Ok(terminal) = body.u32() else {
            return Answer::Status(Status::BadSize);
        };
        let terminal = terminal as usize;
        if terminal >= proto_process::TERMINALS {
            return refuse(proto_process::PERMISSION);
        }
        if method == Method::TtyEvents as u16 {
            if body.finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            let w = r.reply();
            let e = self.terminals.event(terminal);
            if w.u32(0)
                .and_then(|()| w.u32(e.map_or(0, |e| e.sid)))
                .and_then(|()| w.u64(e.map_or(0, |e| e.generation)))
                .and_then(|()| w.u32(u32::from(e.is_some_and(|e| e.disconnect))))
                .is_err()
            {
                return Answer::Status(Status::BadSize);
            }
            return Answer::Reply(Outgoing::new());
        }
        if method == Method::DisconnectCtty as u16 {
            let (Ok(sid), Ok(generation), Ok(hup), Ok(())) =
                (body.u32(), body.u64(), body.u32(), body.finish())
            else {
                return Answer::Status(Status::BadSize);
            };
            if hup > 1 {
                return refuse(proto_process::INVALID);
            }
            #[cfg(feature = "tty-probe")]
            let link = self.terminals.link(terminal);
            let disconnected = self.terminals.disconnect(terminal, sid, generation);
            #[cfg(feature = "tty-probe")]
            rt::println!(
                "process: PTY disconnect terminal={terminal} sid={sid} generation={generation} hup={hup} link={link:?} accepted={disconnected}"
            );
            if disconnected {
                if hup != 0
                    && let Some(index) = self
                        .records
                        .find_pid(sid)
                        .filter(|&i| self.records.get(i).is_some_and(|r| r.state.live()))
                {
                    let delivered = self.deliver_terminal(index, proto_process::SIGHUP);
                    #[cfg(feature = "tty-probe")]
                    rt::println!("process: PTY HUP pid={sid} result={delivered:?}");
                    #[cfg(not(feature = "tty-probe"))]
                    let _ = delivered;
                }
                if let Some(notice) = self.terminal_notice.as_ref() {
                    let _ = sys::notify(notice, 1);
                }
            }
            return Answer::Status(Status::Ok);
        }
        if method == Method::AckCtty as u16 {
            let (Ok(generation), Ok(())) = (body.u64(), body.finish()) else {
                return Answer::Status(Status::BadSize);
            };
            self.terminals.ack(terminal, generation);
            return Answer::Status(Status::Ok);
        }
        if method == Method::DetachCtty as u16 {
            let (Ok(pid), Ok(generation), Ok(())) = (body.u32(), body.u64(), body.finish()) else {
                return Answer::Status(Status::BadSize);
            };
            let Some(index) = self
                .records
                .find_pid(pid)
                .filter(|&i| self.records.get(i).is_some_and(|r| r.state.live()))
            else {
                return refuse(proto_process::NO_PROCESS);
            };
            let record = self.records.get(index).expect("detaching caller");
            if record.ctty != Some((terminal as u32, generation))
                || !self
                    .terminals
                    .link(terminal)
                    .is_some_and(|link| link.sid == record.sid && link.generation == generation)
            {
                return refuse(proto_process::PERMISSION);
            }
            let leader = pid == record.sid;
            if !self.generations.live_room(index, 1) {
                return refuse(proto_process::AGAIN);
            }
            self.records.get_mut(index).expect("caller").ctty = None;
            self.generations.raise(index);
            if leader {
                self.terminals.drop_terminal(terminal);
                if let Some(notice) = self.terminal_notice.as_ref() {
                    let _ = sys::notify(notice, 1);
                }
            }
            return Answer::Status(Status::Ok);
        }
        if method == Method::DropCtty as u16 {
            if body.finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            self.terminals.drop_terminal(terminal);
            if let Some(notice) = self.terminal_notice.as_ref() {
                let _ = sys::notify(notice, 1);
            }
            return Answer::Status(Status::Ok);
        }
        if method == Method::SetCtty as u16 {
            let (Ok(sid), Ok(())) = (body.u32(), body.finish()) else {
                return Answer::Status(Status::BadSize);
            };
            let records = &self.records;
            if let Some(index) = records.find_pid(sid)
                && !self.generations.live_room(index, 1)
            {
                return refuse(proto_process::AGAIN);
            }
            let lives = |sid: u32| {
                records.find_pid(sid).is_some_and(|i| {
                    records.get(i).is_some_and(|r| {
                        r.sid == sid && matches!(r.state, State::Alive | State::Loading)
                    })
                })
            };
            return match self.terminals.set(terminal, sid, lives) {
                Ok(generation) => {
                    let index = self.records.find_pid(sid).expect("live session leader");
                    self.records.get_mut(index).expect("leader").ctty =
                        Some((terminal as u32, generation));
                    self.generations.raise(index);
                    if r.reply()
                        .u32(0)
                        .and_then(|()| r.reply().u64(generation))
                        .is_err()
                    {
                        return Answer::Status(Status::BadSize);
                    }
                    Answer::Reply(Outgoing::new())
                }
                Err(code) => refuse(code),
            };
        }
        let (Ok(pgid), Ok(signal), Ok(generation), Ok(())) =
            (body.u32(), body.u32(), body.u64(), body.finish())
        else {
            return Answer::Status(Status::BadSize);
        };
        self.tty_signal(terminal, pgid, signal, generation, r)
    }

    /// TtySignal: the walk of group `pgid` with `signal`, from the terminal
    /// whose session the group lies in, with no check of permission.
    fn tty_signal(
        &mut self,
        terminal: usize,
        pgid: u32,
        signal: u32,
        generation: u64,
        r: &mut Request<'_>,
    ) -> Answer {
        let Ok(signal) = u8::try_from(signal) else {
            return refuse(proto_process::INVALID);
        };
        if signal == 0 || signal > SIGNAL_MAX || signal == SIGSTOP {
            return refuse(proto_process::INVALID);
        }
        let Some(session) = self.records.session_of(pgid) else {
            return refuse(proto_process::NO_PROCESS);
        };
        if !self
            .terminals
            .permits_exact(terminal, session, generation, signal)
        {
            return refuse(proto_process::PERMISSION);
        }
        if matches!(signal, proto_process::SIGTTIN | proto_process::SIGTTOU)
            && self.records.orphaned(pgid) == Some(true)
        {
            return refuse(proto_process::ORPHAN);
        }
        if self.tty_walk.is_some() {
            return refuse(proto_process::AGAIN);
        }
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::BadSize);
        };
        self.tty_generation = generation;
        self.tty_walk = Some(Walking {
            walk: Walk::new(Target::Group(pgid), RECORDS),
            pending,
            signal,
            delivered: false,
            refused: false,
            canceled: false,
            denied: false,
        });
        self.kick();
        Answer::Deferred
    }

    /// A signal of the terminal to the record in `target` (XBD 11.1.9):
    /// as `deliver`, with no check of permission and the code SI_KERNEL.
    fn deliver_terminal(&mut self, target: usize, signal: u8) -> Delivery {
        #[cfg(feature = "tty-probe")]
        if let Some((index, count)) = self.tty_probe.as_mut()
            && *index == target
        {
            *count += 1;
        }
        let record = self.records.get(target).expect("a target");
        if !record.state.live() {
            return Delivery::Done;
        }
        if signal == SIGKILL {
            let _ = sys::process_kill_at(&record.process, record.ceiling);
            return Delivery::Done;
        }
        let Some(page) = self.pages.page(target) else {
            return Delivery::Refused;
        };
        if signals::refused(signal, page) || !self.can_generate_job(target, signal) {
            return Delivery::Refused;
        }
        let info = Info {
            code: SI_KERNEL,
            pid: 0,
            uid: 0,
            status: 0,
        };
        self.signal(target, signal, info);
        Delivery::Done
    }

    /// One step of the walk of a TtySignal; its reply at its end.
    fn tty_walk_step(&mut self) {
        let Some(mut w) = self.tty_walk.take() else {
            return;
        };
        let step = if w.canceled {
            Step::Done
        } else {
            w.walk.step(&self.records)
        };
        match step {
            Step::Found(target) => match self.deliver_terminal(target, w.signal) {
                Delivery::Done => w.delivered = true,
                Delivery::Denied => w.denied = true,
                Delivery::Refused => w.refused = true,
            },
            Step::Looked => {}
            Step::Done => {
                if self.births.tty() == Some(self.tty_generation) {
                    self.tty_walk = Some(w);
                    return;
                }
                let code = walk::outcome(w.delivered, w.refused, w.denied);
                self.tty_generation = 0;
                #[cfg(feature = "tty-probe")]
                if let Some((_, count)) = self.tty_probe.take() {
                    let mut reply = Writer::new();
                    let _ = reply.u32(code);
                    let _ = reply.u32(count);
                    let _ = w.pending.answer(reply.as_bytes(), Outgoing::new());
                    return;
                }
                let _ = w.pending.answer(
                    &proto_wire::reply(if w.canceled {
                        Status::Kernel(abi::Error::PeerClosed)
                    } else {
                        Status::from_code(code)
                    }),
                    Outgoing::new(),
                );
                return;
            }
        }
        self.tty_walk = Some(w);
    }

    #[cfg(feature = "tty-probe")]
    fn probe_newborn(&mut self, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(pid), Ok(())) = (body.u32(), body.finish()) else {
            return Answer::Status(Status::BadSize);
        };
        let Some(index) = self
            .records
            .find_pid(pid)
            .filter(|&i| self.records.get(i).is_some_and(|r| r.state.live()))
        else {
            return refuse(proto_process::NO_PROCESS);
        };
        let record = self.records.get(index).expect("the probe's target");
        let pgid = record.pgid;
        if self.terminals.session(0) != Some(record.sid) {
            return refuse(proto_process::PERMISSION);
        }
        if self.tty_walk.is_some() {
            return refuse(proto_process::AGAIN);
        }
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::BadSize);
        };
        self.tty_walk = Some(Walking {
            walk: Walk::passed(Target::Group(pgid), index),
            pending,
            signal: 28,
            delivered: false,
            refused: false,
            canceled: false,
            denied: false,
        });
        self.tty_probe = Some((index, 0));
        self.signal_newborn(index);
        self.kick();
        Answer::Deferred
    }

    /// Publishes the group and session of the record in `index` on its
    /// page, where `getpgrp`, `getsid(0)` and waitpid(0) read them.
    fn publish_group(&self, index: usize) {
        let (Some(record), Some(page)) = (self.records.get(index), self.pages.page(index)) else {
            return;
        };
        page.pgid
            .store(record.pgid, core::sync::atomic::Ordering::Release);
        page.sid
            .store(record.sid, core::sync::atomic::Ordering::Release);
    }

    /// SetPgid of the record in `index`: pid u32 and pgid u32 (records.rs
    /// `set_pgid`); the status alone: NO_PROCESS, PERMISSION, ACCESS.
    fn set_pgid(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(pid), Ok(pgid)) = (body.u32(), body.u32()) else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() || pid > i32::MAX as u32 || pgid > i32::MAX as u32 {
            return Answer::Status(Status::BadSize);
        }
        match self.records.set_pgid(index, pid, pgid) {
            Ok(()) => {
                let target = if pid == 0 {
                    Some(index)
                } else {
                    self.records.find_pid(pid)
                };
                if let Some(target) = target {
                    self.publish_group(target);
                    self.publish_groups(target);
                }
                // A child moved: the caller's waits; the caller itself: its
                // parent's.
                if pid != 0 && Some(pid) != self.records.get(index).map(|r| r.label.pid()) {
                    self.tell_groups(index);
                } else {
                    self.tell_parent_groups(index);
                }
                self.kick();
                Answer::Status(Status::Ok)
            }
            Err(e) => refuse(group_error(e)),
        }
    }

    /// SetSid of the record in `index`: the status and the new number.
    fn set_sid(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        if !self.generations.live_room(index, 1) {
            return refuse(proto_process::AGAIN);
        }
        match self.records.set_sid(index) {
            Ok(sid) => {
                self.generations.raise(index);
                self.publish_group(index);
                self.publish_groups(index);
                self.tell_parent_groups(index);
                self.kick();
                number(r, sid)
            }
            Err(e) => refuse(group_error(e)),
        }
    }

    /// GetPgid or GetSid of `pid` (0 for the record in `index`): the
    /// status and the number, NO_PROCESS for no such record.
    fn get_group(&self, index: usize, session: bool, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let Ok(pid) = body.u32() else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let found = if session {
            self.records.sid_of(index, pid)
        } else {
            self.records.pgid_of(index, pid)
        };
        match found {
            Some(n) => number(r, n),
            None => refuse(proto_process::NO_PROCESS),
        }
    }
}
/// The status of a failed call of the kernel.
fn kernel(e: abi::Error) -> Answer {
    Answer::Status(Status::Kernel(e))
}

/// The service's quota left, of which the children's quotas come past
/// its reserve (loaders::pool_allows).
fn free_quota() -> u64 {
    sys::process_memory(&make::own()).map_or(0, |m| m.quota.saturating_sub(m.used))
}
impl Processes {
    /// SpawnStart of the record in `index` (5c, spec 2, 3.2): a child from
    /// a file (`start_child`), with the credentials of an exec and the
    /// mask and signals SpawnStart names.
    fn spawn_start(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let Ok(start) = SpawnStart::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if start.flags & !SPAWN_FLAGS != 0 {
            return refuse(proto_process::INVALID);
        }
        let parent = self.records.get(index).expect("the caller");
        let birth = Birth {
            flags: start.flags,
            pgroup: start.pgroup,
            level: start.level,
            credentials: loaders::child_credentials(parent.credentials, start.flags),
            page: PageStart::Spawn {
                mask: start.mask,
                default: start.default,
            },
        };
        self.start_child(index, birth, r)
    }

    /// ForkStart of the record in `index` (5d, spec 2, 3.2): a child whose
    /// loader copies the caller's memory (`start_child`), in the caller's
    /// group and session with the caller's credentials, its page with the
    /// classes of the caller's actions before any walk may find it.
    fn fork_start(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let Ok(start) = ForkStart::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let parent = self.records.get(index).expect("the caller");
        let birth = Birth {
            flags: 0,
            pgroup: 0,
            level: start.level,
            credentials: parent.credentials,
            page: PageStart::Fork {
                ignored: start.ignored,
                caught: start.caught,
                flags: start.flags,
            },
        };
        self.start_child(index, birth, r)
    }

    /// The child of SpawnStart or ForkStart of the record in `index`: its
    /// record (LOADING, as Create makes it), its process with the parent's
    /// quota, room for handles and ceiling, the loader's session in its
    /// entry 0, its page as `birth` says before the record is a target of
    /// a walk, the loader mapped and its thread started at the caller's
    /// level; the reply waits for Boot. AGAIN while a load of the record
    /// waits, past CHILDREN_MAX children or the 16 places of loaders;
    /// PERMISSION for a group setpgid would refuse; NOT_FOUND without a
    /// loader or a session of the loaders; NO_MEMORY past the pool. O(1)
    /// but for the copy of the loader's data, a page.
    fn start_child(&mut self, index: usize, birth: Birth, r: &mut Request<'_>) -> Answer {
        self.prepare_child(index, birth, r)
    }

    /// ExecStart of the record in `index` (5c, spec 2, 3.2 step 2): a new
    /// process for the record, image one past its own, with the record's
    /// quota, room for handles and ceiling, its page as it is, the loader
    /// mapped and started at the caller's level; the reply waits for Boot.
    /// AGAIN while an exec or two loads of the record are on, or past
    /// IMAGE_MAX; INVALID for flags or a group.
    fn exec_start(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let Ok(start) = SpawnStart::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if start.flags != 0 || start.pgroup != 0 {
            return refuse(proto_process::INVALID);
        }
        if self.loader.is_none() || self.files.is_none() {
            return refuse(proto_process::NOT_FOUND);
        }
        self.prepare_exec(index, start, r)
    }

    /// ExecCommit of the record in `index` (step 5): the record moves to
    /// the new process in one step of the loop: its image number is the
    /// new one (its old session, exit place and identity name nothing
    /// from here on), the set-ID its loader's place kept applies (the
    /// saved IDs follow the effective ones), the generation of its
    /// credentials grows before the reply, its caught signals are the
    /// default on the page, the new main thread routes its
    /// signals, the loads of children the old image started and did not
    /// commit stop (their parent's copy of C goes with it), the service
    /// kills the old process (process_kill_at, O(1) for the caller)
    /// and the loader hears that the record is ready. For a record of
    /// init's table the loader's notification and the kill wait until init
    /// took the new process for the record's end line (`replace`).
    /// BAD_STATE without an exec whose image is ready.
    fn exec_commit(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if !self.generations.live_room(index, 2) {
            return refuse(proto_process::AGAIN);
        }
        let exec = self
            .loaders
            .of(index)
            .and_then(|slot| self.loaders.get(slot))
            .is_some_and(|p| p.parent == index && p.held.incoming.is_some());
        if !exec {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        // The existing per-record replacement slot and reply are paid before Commit.
        if self.replacing[index].is_some() {
            return refuse(proto_process::AGAIN);
        }
        let slot = self.loaders.of(index).expect("an exec's place");
        let place = self.loaders.get(slot).expect("a place");
        if place.stage != Stage::Loaded
            || self
                .records
                .get(index)
                .is_some_and(|r| r.active_exec.is_some())
                && place.held.exec.pending_exec.is_none()
        {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        let ticket = self.tickets[index];
        let serial = place.held.serial();
        if ticket != 0 && serial == 0 {
            return refuse(proto_process::AGAIN);
        }
        let copy = if ticket != 0 {
            match sys::handle_duplicate(
                place.held.incoming.as_ref().expect("the new process"),
                Rights::DUPLICATE | Rights::TRANSFER,
            ) {
                Ok(copy) => Some(copy),
                Err(error) => return kernel(error),
            }
        } else {
            None
        };
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::BadSize);
        };
        let Ok(set_id) = self.loaders.commit(index) else {
            let _ = pending.answer(
                &proto_wire::reply(Status::Kernel(abi::Error::BadState)),
                Outgoing::new(),
            );
            return Answer::Deferred;
        };
        let committed_ticket = self.loaders.ticket(slot);
        let new_exec = self.loaders.take_pending_exec(index);
        let place = self.loaders.get_mut(slot).expect("a place");
        let image = place.image;
        let incoming = place.held.incoming.take().expect("the new process");
        self.routers[index] = place.held.thread.take();
        let ready = place.held.ready.take();
        let record = self.records.get_mut(index).expect("the caller");
        let old = core::mem::replace(&mut record.process, incoming);
        let old_exec = core::mem::replace(&mut record.active_exec, new_exec);
        let old_image = record.image;
        let ceiling = record.ceiling;
        record.image = image;
        record.committed_loader_ticket = committed_ticket;
        record.execed = true;
        let mut credentials = loaders::child_credentials(record.credentials, 0);
        if let Some(ids) = set_id {
            credentials = loaders::set_ids(credentials, ids);
        }
        record.credentials = credentials;
        let key = preparing::Key {
            label: record.label,
            image,
        };
        self.generations.raise(index);
        if let Some(page) = self.pages.page(index) {
            page.caught.store(0, core::sync::atomic::Ordering::Release);
        }
        if self.records.get(index).is_some_and(|r| r.stopped.is_some()) {
            let r = self.records.get(index).expect("a stopped record");
            let _ = sys::process_control(&r.process, true, r.ceiling);
        }
        // The loads the old image started: nobody gives their loaders a
        // block once it is gone.
        let mut children = [0u16; loaders::LOADERS];
        let mut count = 0;
        for child in self.loaders.uncommitted_of(index) {
            children[count] = child as u16;
            count += 1;
        }
        for &child in &children[..count] {
            self.abort_load(usize::from(child), Status::Kernel(abi::Error::PeerClosed));
        }
        self.replacing[index] = Some(Work::Replacing(Replacing {
            pending: Some(pending),
            ready,
            process: copy,
            old: RetiredExec::new(Some(old), old_exec, ceiling),
            old_image,
            ticket,
            key,
            serial,
            cleanup_cursor: 0,
        }));
        if ticket != 0 {
            self.replace_queue.push(index);
            self.dispatch_replace();
        } else {
            self.finish_replace(index);
        }
        Answer::Deferred
    }

    /// Replace (label 0): the thread that tells init of an exec names the
    /// record whose exec init heard of (`finish_replace`), then waits for
    /// the next ExecCommit of a record of init's table; AGAIN for a second
    /// Replace that waits.
    fn replace(&mut self, r: &mut Request<'_>) -> Answer {
        self.controller_request(r)
    }

    /// Queue ownership remains resident; the next paid controller visit
    /// prepares one immutable command and its transfer duplicate.
    fn dispatch_replace(&mut self) {
        self.kick();
    }

    /// The exec of the record in `index` that waited for init goes on: the
    /// service kills the old process and the loader tells the new image
    /// the record is ready.
    fn finish_replace(&mut self, index: usize) {
        let Some(replacing) = self.replacing[index].as_mut().and_then(Work::replacing_mut) else {
            return;
        };
        if replacing.old.request_cleanup() {
            self.replace_cleanup += 1;
        }
        self.kick();
    }

    fn try_finish_replace(&mut self, index: usize) {
        let Some(work) = self.replacing[index].as_mut().and_then(Work::replacing_mut) else {
            return;
        };
        match work.cleanup_cursor {
            0 => {
                if work.old.try_stop(self.level, |old, level| {
                    sys::process_kill_at(old.as_ref().expect("the old image owner"), level)
                }) != Ok(true)
                {
                    return;
                }
            }
            1 => {
                if !close_owned(&mut work.old.executable) {
                    return;
                }
            }
            2 => {
                if !close_owned(&mut work.old.process) {
                    return;
                }
            }
            3 => {
                if !close_owned(&mut work.process) {
                    return;
                }
            }
            4 => {
                if !self
                    .records
                    .get(index)
                    .is_some_and(|r| r.state.end_pending())
                    && let Some(ready) = work.ready.as_ref()
                {
                    let _ = sys::notify(ready, 1);
                }
            }
            5 => {
                if !close_owned(&mut work.ready) {
                    return;
                }
            }
            6 => {
                if self
                    .records
                    .get(index)
                    .is_some_and(|r| r.state.end_pending())
                {
                    let pending = work.pending.take();
                    let empty = Work::take_replacing(&mut self.replacing[index])
                        .expect("an empty ended replacement");
                    assert!(
                        empty.ready.is_none()
                            && empty.process.is_none()
                            && empty.old.process.is_none()
                            && empty.old.executable.is_none()
                    );
                    self.replace_cleanup -= 1;
                    self.start_ending(index, pending);
                    return;
                }
                if let Some(pending) = work.pending.take() {
                    let _ = pending.answer(&proto_wire::reply(Status::Ok), Outgoing::new());
                }
                // Every capability is already settled. Reply has no
                // fallible or cap-dropping suffix that can keep Work busy.
                let empty =
                    Work::take_replacing(&mut self.replacing[index]).expect("an empty replacement");
                assert!(
                    empty.pending.is_none()
                        && empty.ready.is_none()
                        && empty.process.is_none()
                        && empty.old.process.is_none()
                        && empty.old.executable.is_none()
                );
                self.replace_cleanup -= 1;
                return;
            }
            _ => unreachable!("a finite replacement cleanup cursor"),
        }
        work.cleanup_cursor += 1;
    }

    /// At most one existing replacement row and one Kill in this STEP.
    fn replace_cleanup_step(&mut self) {
        let index = self.replace_cursor;
        self.replace_cursor = (index + 1) % (RECORDS + LOADERS);
        if index >= RECORDS {
            if let Some(place) = self.loaders.get(index - RECORDS)
                && place.stage == Stage::Aborting
            {
                self.try_abort_load(place.record);
            }
            return;
        }
        if matches!(self.replacing[index], Some(Work::Ending(_))) {
            self.try_end_step(index);
            return;
        }
        if self.replacing[index]
            .as_ref()
            .and_then(Work::replacing)
            .is_some_and(|r| r.old.cleanup_requested())
        {
            self.try_finish_replace(index);
        }
    }

    /// ExecAbort of the record in `index`: the new process of its exec is
    /// killed, the place and its SetId go, and the old image goes on.
    fn exec_abort(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let exec = self
            .loaders
            .of(index)
            .and_then(|slot| self.loaders.get(slot))
            .is_some_and(|p| p.parent == index && p.held.incoming.is_some());
        if exec {
            self.abort_load(index, Status::from_code(proto_process::AGAIN));
        }
        Answer::Status(Status::Ok)
    }

    #[cfg(feature = "image-probe")]
    fn free_observed_loader(
        &mut self,
        child: usize,
        terminal: Terminal,
    ) -> Option<loaders::Place<Held>> {
        let Some(record) = self.records.get_mut(child) else {
            return self.loaders.free(child);
        };
        image_probe::free(&mut self.loaders, &mut record.image_probe, child, terminal)
    }

    /// The load of the record in `child` stops: its process is killed, its
    /// loader's place and SetId go, and a SpawnStart that waits gets
    /// `status`. The record goes with the end of its process.
    fn abort_load(&mut self, child: usize, status: Status) {
        let Some(slot) = self.loaders.of(child) else {
            return;
        };
        let place = self.loaders.get_mut(slot).expect("a loader place");
        if place.stage != Stage::Aborting {
            let committed = place.stage == Stage::Ready;
            place.stage = Stage::Aborting;
            place.held.abort(status);
            if committed {
                place.held.outcome = LoaderOutcome::Aborted(status);
                place.held.abort_cursor = 1;
            }
            self.abort_cleanup += 1;
        } else {
            place.held.abort(status);
        }
        self.kick();
    }

    fn try_abort_load(&mut self, child: usize) {
        let Some(slot) = self.loaders.of(child) else {
            return;
        };
        let place = self.loaders.get_mut(slot).expect("an aborting place");
        if place.stage != Stage::Aborting {
            return;
        }
        let LoaderOutcome::Aborted(status) = place.held.outcome else {
            unreachable!("the first abort reason");
        };
        let cursor = place.held.abort_cursor;
        match cursor {
            0 => {
                let target = match place.held.incoming.as_ref() {
                    Some(target) => target,
                    None => match self.records.get(child) {
                        Some(record) => &record.process,
                        None => return,
                    },
                };
                if sys::process_kill_at(target, place.held.abort_ceiling.min(self.level)).is_err() {
                    return;
                }
            }
            1 => {
                if !close_owned(&mut place.held.thread) {
                    return;
                }
            }
            2 => {
                if !close_owned(&mut place.held.ready) {
                    return;
                }
            }
            3 => {
                if !close_owned(&mut place.held.incoming) {
                    return;
                }
            }
            4 => {
                if !close_owned(&mut place.held.exec.pending_exec) {
                    return;
                }
            }
            5 => {
                if !close_owned(&mut place.held.exec.fork_source) {
                    return;
                }
            }
            6 => {
                if let Some(start) = place.held.start.take() {
                    let _ = start.answer(&proto_wire::reply(status), Outgoing::new());
                }
                self.abort_cleanup -= 1;
                self.free_aborted_load(child, status);
                return;
            }
            _ => unreachable!("a finite abort cleanup cursor"),
        }
        place.held.abort_cursor = cursor + 1;
    }

    fn free_aborted_load(&mut self, child: usize, status: Status) {
        #[cfg(feature = "image-probe")]
        let place = self.free_observed_loader(child, Terminal::Aborted);
        #[cfg(not(feature = "image-probe"))]
        let place = self.loaders.free(child);
        if let Some(mut place) = place {
            assert!(
                place.held.thread.is_none()
                    && place.held.ready.is_none()
                    && place.held.incoming.is_none()
                    && place.held.exec.pending_exec.is_none()
                    && place.held.exec.fork_source.is_none()
            );
            self.generations.invalidate(child);
            // Stop is confirmed before any pending guard or fork source is closed.
            if let Some(start) = place.held.start.take() {
                let _ = start.answer(&proto_wire::reply(status), Outgoing::new());
            }
        }
    }

    /// A request through the session of the loader of the record in
    /// `child`: startup, readiness, final transfer and the trusted loader roots.
    fn loader_request(&mut self, child: usize, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let Some(slot) = self.loaders.of(child) else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        match r.method() {
            m if m == Method::LoaderTerminal as u16 || m == Method::LoaderClock as u16 => {
                if self.loaders.get(slot).map(|p| p.stage) != Some(Stage::Loading)
                    || !r.handles.is_empty()
                {
                    return refuse(proto_process::PERMISSION);
                }
                let root = if m == Method::LoaderClock as u16 {
                    self.clock.as_ref()
                } else {
                    self.loader_terminal.as_ref()
                };
                let Some(terminal) = root else {
                    return refuse(proto_process::UNREGISTERED);
                };
                let copy = match sys::handle_duplicate(terminal, Rights::SEND | Rights::TRANSFER) {
                    Ok(copy) => copy,
                    Err(e) => return kernel(e),
                };
                if r.reply().u32(0).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply([copy.erase()].into())
            }
            m if m == Method::Boot as u16 => self.boot(child, slot, r),
            m if m == Method::Ready as u16 => self.ready(child, r),
            m if m == Method::LoaderForkImage as u16 => {
                if !r.handles.is_empty() {
                    return Answer::Status(Status::BadSize);
                }
                let place = self.loaders.get(slot).expect("an exact loader");
                if place.stage != Stage::Loading || !place.held.fork {
                    return refuse(proto_process::PERMISSION);
                }
                let Some(source) = place.held.exec.fork_source.as_ref() else {
                    return refuse(proto_process::NOT_FOUND);
                };
                let copy = match sys::handle_duplicate(
                    source,
                    Rights::SEND | Rights::DUPLICATE | Rights::TRANSFER,
                ) {
                    Ok(copy) => copy,
                    Err(error) => return kernel(error),
                };
                if r.reply().u32(0).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply([copy.erase()].into())
            }
            m if m == Method::Take as u16 => self.take(child, slot, r),
            _ => refuse(proto_process::PERMISSION),
        }
    }

    /// Boot of the loader in place `slot`, which loads the record in
    /// `child`: two handles, the copies of its start channel C for the
    /// parent (SEND) and for the service (NOTIFY). The reply: the process
    /// and the loader's thread, the session of the loaders and the
    /// loader's identity; the parent's SpawnStart gets the PID and its
    /// copy of C.
    fn boot(&mut self, child: usize, slot: usize, r: &mut Request<'_>) -> Answer {
        self.replacer.check_files = true;
        self.kick();
        if self.loaders.get(slot).map(|p| p.stage) != Some(Stage::Booting) {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        let sends = matches!(r.handles.info(0), Some((ObjectKind::Channel, rights)) if rights.contains(Rights::SEND));
        let notifies = matches!(r.handles.info(1), Some((ObjectKind::Channel, rights)) if rights.contains(Rights::NOTIFY));
        if r.handles.len() != 2 || !sends || !notifies {
            return Answer::Status(Status::BadSize);
        }
        let (Ok(parents), Ok(ready)) = (r.handles.take::<Channel>(0), r.handles.take::<Channel>(1))
        else {
            return Answer::Status(Status::BadSize);
        };
        let record = self.records.get(child).expect("a loading record");
        let (label, pid) = (record.label, record.label.pid());
        let place = self.loaders.get(slot).expect("a place");
        let image = place.image;
        // The process the loader loads: an exec's new one, or the child's.
        let target = place.held.incoming.as_ref().unwrap_or(&record.process);
        let owner = Rights::MANAGE | Rights::DUPLICATE | Rights::TRANSFER;
        let made = (|| {
            let process = sys::handle_duplicate(target, owner)?;
            let thread = place.held.thread.as_ref().ok_or(abi::Error::BadState)?;
            let thread = sys::handle_duplicate(thread, owner)?;
            let files = self.files.as_ref().ok_or(abi::Error::BadState)?;
            let files = sys::handle_duplicate(files, Rights::SEND | Rights::TRANSFER)?;
            let identity = sys::handle_label(
                &self.identities,
                Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER,
                label.loader_at(image),
                self.level,
            )?;
            Ok::<_, abi::Error>([
                process.erase(),
                thread.erase(),
                files.erase(),
                identity.erase(),
            ])
        })();
        let handles = match made {
            Ok(handles) => handles,
            Err(e) => {
                self.abort_load(child, Status::Kernel(e));
                return kernel(e);
            }
        };
        let place = self.loaders.get_mut(slot).expect("a place");
        place.stage = Stage::Loading;
        place.held.ready = Some(ready);
        let start = place
            .held
            .start
            .take()
            .expect("the SpawnStart of a booting loader");
        let mut w = Writer::new();
        let answered = w.u32(0).and_then(|()| w.u32(pid)).is_ok()
            && start.answer(w.as_bytes(), [parents.erase()]).is_ok();
        if !answered {
            // The parent went, or its thread: nobody gives the loader its
            // block, and the child goes.
            self.abort_load(child, Status::Kernel(abi::Error::PeerClosed));
            return Answer::Status(Status::Kernel(abi::Error::PeerClosed));
        }
        let (data_at, data_len) = self.loader.as_ref().map_or((0, 0), loader::Image::data);
        let w = r.reply();
        if w.u32(0)
            .and_then(|()| w.u64(data_at))
            .and_then(|()| w.u64(data_len))
            .is_err()
        {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(handles.into())
    }

    /// Ready of the loader of the record in `child`: its image is loaded,
    /// and the parent may commit the place from now on.
    fn ready(&mut self, child: usize, r: &mut Request<'_>) -> Answer {
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if !self.generations.live_room(child, 3) {
            return refuse(proto_process::AGAIN);
        }
        match self.loaders.loaded(child) {
            Ok(()) => {
                self.generations.invalidate(child);
                Answer::Status(Status::Ok)
            }
            Err(loaders::Refused) => Answer::Status(Status::Kernel(abi::Error::BadState)),
        }
    }

    /// Take of the loader in place `slot`, once the record in `child` is
    /// ready: its credentials, the program's session and identity session,
    /// and a console; the place goes.
    fn take(&mut self, child: usize, slot: usize, r: &mut Request<'_>) -> Answer {
        if self.loaders.get(slot).map(|p| p.stage) != Some(Stage::Ready) {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        if !self.generations.live_room(child, 1) {
            return refuse(proto_process::AGAIN);
        }
        let record = self.records.get(child).expect("a ready record");
        let (label, credentials, image) = (record.label, record.credentials, record.image);
        let work = record.label.raw_at(record.image);
        let made = (|| {
            let session = sys::handle_label(
                &self.channel,
                Rights::SEND | Rights::TRANSFER,
                work,
                self.level,
            )?;
            let identity = sys::handle_label(
                &self.identities,
                Rights::NOTIFY | Rights::TRANSFER | Rights::DUPLICATE,
                label.identity_at(image),
                self.level,
            )?;
            let mut handles = Outgoing::new();
            let _ = handles.push(session.erase());
            let _ = handles.push(identity.erase());
            if let Some(console) = self.console.as_ref() {
                let copy = sys::handle_duplicate(console, Rights::DEBUG | Rights::TRANSFER)?;
                let _ = handles.push(copy.erase());
            }
            Ok::<_, abi::Error>(handles)
        })();
        let handles = match made {
            Ok(handles) => handles,
            Err(e) => return kernel(e),
        };
        let w = r.reply();
        if w.u32(0).is_err() || credentials.words().iter().any(|&id| w.u32(id).is_err()) {
            return Answer::Status(Status::BadSize);
        }
        #[cfg(feature = "image-probe")]
        self.free_observed_loader(child, Terminal::Taken);
        #[cfg(not(feature = "image-probe"))]
        self.loaders.free(child);
        self.generations.invalidate(child);
        Answer::Reply(handles)
    }

    /// The LOADING child of the record in `parent` whose PID the body
    /// names, a child of ForkStart for `fork` and of SpawnStart otherwise.
    fn loading_child(&self, parent: usize, r: &Request<'_>, fork: bool) -> Option<usize> {
        let mut body = r.body();
        let pid = body.u32().ok()?;
        body.finish().ok()?;
        self.records.find_pid(pid).filter(|&c| {
            self.records
                .get(c)
                .is_some_and(|c| c.state == State::Loading && c.parent_index == Some(parent as u16))
                && self
                    .loaders
                    .of(c)
                    .and_then(|slot| self.loaders.get(slot))
                    .is_some_and(|p| p.held.fork == fork)
        })
    }

    /// SpawnCommit of the record in `index`: its LOADING child lives, with
    /// the IDs SetId kept for its loader's place, and the loader hears that
    /// the record is ready. BAD_STATE until the loader said its image is
    /// ready (Ready): a parent that commits before, or after a failed
    /// load, gets no child that waits for a block.
    /// ForkCommit (`fork`) takes a child of ForkStart alone, SpawnCommit
    /// one of SpawnStart.
    fn spawn_commit(&mut self, index: usize, r: &mut Request<'_>, fork: bool) -> Answer {
        let Some(child) = self.loading_child(index, r, fork) else {
            return refuse(proto_process::NO_PROCESS);
        };
        if !self.generations.live_room(child, 2) {
            return refuse(proto_process::AGAIN);
        }
        let slot = self.loaders.of(child).expect("a loading place");
        if self.loaders.get(slot).is_some_and(|p| {
            p.held.exec.fork_source.is_some() && p.held.exec.pending_exec.is_none()
        }) {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        let Ok(set_id) = self.loaders.commit(child) else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        let committed_slot = self.loaders.of(child).expect("a committed place");
        let committed_ticket = self.loaders.ticket(committed_slot);
        let new_exec = self.loaders.take_pending_exec(child);
        let record = self.records.get_mut(child).expect("a loading record");
        record.active_exec = new_exec;
        record.state = State::Alive;
        record.committed_loader_ticket = committed_ticket;
        // A child of posix_spawn runs its own program from the start; one
        // of fork runs its parent's copy until it execs.
        record.execed = !fork;
        if let Some(ids) = set_id {
            record.credentials = loaders::set_ids(record.credentials, ids);
        }
        // The services that remember credentials see the new ones before
        // the child runs a request.
        self.generations.raise(child);
        if let Some(signal) = self.records.get(child).and_then(|r| r.stopped) {
            let r = self.records.get(child).expect("a committed child");
            let _ = sys::process_control(&r.process, true, r.ceiling);
            self.child_report(child, Some(signal));
        }
        let slot = self.loaders.of(child).expect("a committed place");
        let place = self.loaders.get_mut(slot).expect("a place");
        self.routers[child] = place.held.thread.take();
        if let Some(ready) = place.held.ready.as_ref() {
            // A loader that went hears nothing; its end follows.
            let _ = sys::notify(ready, 1);
        }
        Answer::Status(Status::Ok)
    }

    /// SpawnAbort of the record in `index`: its LOADING child is killed,
    /// and the SetId of its loader's place goes with the place at once.
    /// ForkAbort (`fork`) takes a child of ForkStart alone, SpawnAbort one
    /// of SpawnStart.
    fn spawn_abort(&mut self, index: usize, r: &mut Request<'_>, fork: bool) -> Answer {
        let Some(child) = self.loading_child(index, r, fork) else {
            return refuse(proto_process::NO_PROCESS);
        };
        self.abort_load(child, Status::from_code(proto_process::AGAIN));
        Answer::Status(Status::Ok)
    }

    /// SetId through a notary session with SET_ID: kept for the loader's
    /// place the ticket names, while it loads the record and image the
    /// body names (loaders.rs); PERMISSION otherwise.
    /// Trusted RAM installs one exact prepaid executable cap and its captured IDs.
    fn stage_exec(&mut self, r: &mut Request<'_>) -> Answer {
        if !proto_process::may_set_id(r.label()) {
            return refuse(proto_process::PERMISSION);
        }
        let Ok(args) = proto_process::StageExec::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        let rights = Rights::SEND | Rights::DUPLICATE | Rights::TRANSFER;
        if r.handles.len() != 1 || r.handles.info(0) != Some((ObjectKind::Channel, rights)) {
            return Answer::Status(Status::BadSize);
        }
        let Some(record) = self
            .records
            .find_pid(args.pid)
            .filter(|&i| self.records.get(i).is_some_and(|r| r.state.live()))
        else {
            return refuse(proto_process::STAGE_RETIRED);
        };
        if self.loaders.of(record).is_none() {
            let current = self.records.get(record).expect("a stage target");
            return if current.image == args.image && current.committed_loader_ticket == args.ticket
            {
                refuse(proto_process::STAGE_RETIRED)
            } else {
                refuse(proto_process::PERMISSION)
            };
        }
        let cap = match r.handles.take::<Channel>(0) {
            Ok(cap) => cap,
            Err(error) => return kernel(error),
        };
        #[cfg(feature = "image-probe")]
        let staged = image_probe::stage_exec(
            &mut self.loaders,
            &mut self
                .records
                .get_mut(record)
                .expect("a stage target")
                .image_probe,
            record,
            args,
            cap,
        );
        #[cfg(not(feature = "image-probe"))]
        let staged = self
            .loaders
            .stage_exec(record, args, cap)
            .map(|result| (result, false));
        match staged {
            Ok((Staged::Installed, true)) => {
                let w = r.reply();
                if w.u32(0).and_then(|()| w.u32(1)).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply(Outgoing::new())
            }
            Ok((Staged::Installed, false)) => Answer::Status(Status::Ok),
            Ok((Staged::Replay(extra), _)) => {
                drop(extra);
                Answer::Status(Status::Ok)
            }
            Err(posix_process_service::executable::Refused(cap)) => {
                drop(cap);
                refuse(proto_process::PERMISSION)
            }
        }
    }

    fn set_id(&mut self, r: &mut Request<'_>) -> Answer {
        if !proto_process::may_set_id(r.label()) || !r.handles.is_empty() {
            return refuse(proto_process::PERMISSION);
        }
        let Ok(set) = SetId::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        let Some(child) = self
            .records
            .find_pid(set.pid)
            .filter(|&i| self.records.get(i).is_some_and(|r| r.state.live()))
        else {
            return refuse(proto_process::PERMISSION);
        };
        #[cfg(feature = "image-probe")]
        {
            let observation = &mut self
                .records
                .get_mut(child)
                .expect("a live record")
                .image_probe;
            match image_probe::set_id(
                &mut self.loaders,
                observation,
                set.ticket,
                child,
                set.image,
                (set.uid, set.gid),
            ) {
                Ok(true) => {
                    let w = r.reply();
                    if w.u32(0).and_then(|()| w.u32(1)).is_err() {
                        return Answer::Status(Status::BadSize);
                    }
                    Answer::Reply(Outgoing::new())
                }
                Ok(false) => Answer::Status(Status::Ok),
                Err(loaders::Refused) => refuse(proto_process::PERMISSION),
            }
        }
        #[cfg(not(feature = "image-probe"))]
        match self
            .loaders
            .set_id(set.ticket, child, set.image, (set.uid, set.gid))
        {
            Ok(()) => Answer::Status(Status::Ok),
            Err(loaders::Refused) => refuse(proto_process::PERMISSION),
        }
    }
}
impl Service<0> for Processes {
    const VERSION: u16 = proto_process::VERSION;
    const METHODS: &'static [u16] = {
        #[cfg(any(feature = "tty-probe", feature = "image-probe"))]
        {
            &PROBE_METHODS
        }
        #[cfg(not(any(feature = "tty-probe", feature = "image-probe")))]
        {
            proto_process::METHODS
        }
    };
    const PLACED: usize = PLACED;
    type Data = LongSession;
    fn place(&self, label: u64) -> Option<usize> {
        if label == 0 {
            return Some(0);
        }
        if let Some(record) = self.records.find_loader(label) {
            return self.loaders.of(record).map(|slot| RECORDS + 1 + slot);
        }
        self.records.find(label).map(|i| i + 1)
    }
    fn request(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
        let method = r.method();
        let own = [
            Method::Create,
            Method::Loaded,
            Method::Abandon,
            Method::Replace,
        ];
        if own.map(|m| m as u16).contains(&method) {
            // Only the service's own threads and init hold the channel with
            // no label.
            if r.label() != 0 {
                return refuse(proto_process::PERMISSION);
            }
            return match method {
                n if n == Method::Create as u16 => self.create(r),
                n if n == Method::Loaded as u16 => self.loaded(r),
                n if n == Method::Replace as u16 => self.replace(r),
                _ => self.abandon(r),
            };
        }
        if proto_process::is_notary(r.label()) {
            return self.notary(r);
        }
        // The signals and controlling terminals of the terminal service
        // come through its notary session alone (5f).
        let terminal = [
            Method::TtySignal,
            Method::SetCtty,
            Method::DropCtty,
            Method::DetachCtty,
            Method::TtyEvents,
            Method::AckCtty,
            Method::DisconnectCtty,
        ];
        if terminal.map(|m| m as u16).contains(&method) {
            return refuse(proto_process::PERMISSION);
        }
        if let Some(child) = self.records.find_loader(r.label()) {
            return self.loader_request(child, r);
        }
        let loaders_own = [
            Method::Boot,
            Method::Ready,
            Method::Take,
            Method::SetId,
            Method::LoaderTerminal,
            Method::LoaderClock,
        ];
        if loaders_own.map(|m| m as u16).contains(&method) {
            return refuse(proto_process::PERMISSION);
        }
        let Some(index) = self.records.find(r.label()) else {
            return refuse(proto_process::UNREGISTERED);
        };
        #[cfg(feature = "image-probe")]
        if [
            image_probe::ARM,
            image_probe::TRACE,
            image_probe::CHILD_HANDOFF,
        ]
        .contains(&method)
        {
            return self.image_probe_request(index, r);
        }
        if method == Method::WaitTake as u16 {
            return self.wait_take(index, s, r);
        }
        if method == Method::Router as u16 {
            return self.router(index, r);
        }
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let mut body = r.body();
        match method {
            n if n == Method::Query as u16 => {
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                snapshot(r, self.records.get(index).expect("query process"));
                Answer::Reply(Outgoing::new())
            }
            n if n == Method::Change as u16 => {
                let (Ok(operation), Ok(id)) = (body.u32(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let Some(operation) = Change::from_number(operation) else {
                    return refuse(proto_process::INVALID);
                };
                let result = self.records.change_credentials(
                    index,
                    operation,
                    id,
                    self.generations.get(index),
                );
                // The services that remember the credentials see the
                // generation move before the caller's reply, so that
                // whatever the caller sends after it returns is checked by
                // the new ones.
                if result.is_ok() {
                    self.generations.raise(index);
                }
                Answer::Status(Status::from_code(result.err().unwrap_or(0)))
            }
            n if n == Method::SpawnStart as u16 => self.spawn_start(index, r),
            n if n == Method::SpawnCommit as u16 => self.spawn_commit(index, r, false),
            n if n == Method::SpawnAbort as u16 => self.spawn_abort(index, r, false),
            n if n == Method::ForkStart as u16 => self.fork_start(index, r),
            n if n == Method::ForkCommit as u16 => self.spawn_commit(index, r, true),
            n if n == Method::ForkAbort as u16 => self.spawn_abort(index, r, true),
            n if n == Method::ExecStart as u16 => self.exec_start(index, r),
            n if n == Method::ExecCommit as u16 => self.exec_commit(index, r),
            n if n == Method::ExecAbort as u16 => self.exec_abort(index, r),
            n if n == Method::WaitStart as u16 => self.wait_start(index, s, r),
            n if n == Method::WaitCancel as u16 => self.wait_cancel(s, r),
            n if n == Method::Kill as u16 => self.kill(index, r),
            n if n == Method::SignalGeneration as u16 => self.signal_generation(index, r),
            n if n == Method::StopSelf as u16 => self.stop_self(index, r),
            n if n == Method::ReturnSignal as u16 => self.return_signal(index, r),
            n if n == Method::SetPgid as u16 => self.set_pgid(index, r),
            n if n == Method::SetSid as u16 => self.set_sid(index, r),
            n if n == Method::GetPgid as u16 => self.get_group(index, false, r),
            n if n == Method::GetSid as u16 => self.get_group(index, true, r),
            n if n == Method::Pool as u16 => {
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let pool = free_quota().saturating_sub(loaders::RESERVE);
                let w = r.reply();
                if w.u32(0).and_then(|()| w.u64(pool)).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply(Outgoing::new())
            }
            _ => Answer::Status(Status::UnknownMethod),
        }
    }
    /// The client of `s` went: its waits go.
    fn gone(&mut self, s: &mut Session<LongSession, 0>) {
        self.cancel_walks(s.label());
        self.ops.gone(&mut s.data);
    }
    /// The telling of a step of the walks (STEP): one step of the walk at
    /// the head of the queue (`walk_step`).
    ///
    /// The end of a process, through its record's exit place: the record
    /// ends with its reason (proto_process::End), its live children get
    /// PID 1 in their records and pages, and it waits as a zombie for its
    /// parent's wait, whose waits that take it are told, or goes at once
    /// without a parent. An end of an older generation takes nothing.
    fn notification(&mut self, n: Notice) {
        if n.source == Source::Exit && n.label == STEP {
            self.replacer.reap = true;
            self.kick();
            return;
        }
        if n.source == Source::Session && n.label == STEP {
            self.walk_step();
            return;
        }
        if n.source != Source::Exit {
            return;
        }
        if let Some((label, Place::Exit, image)) = Label::parse_image(n.label)
            && let Some(work) = self.replacing[usize::from(label.index)]
                .as_mut()
                .and_then(Work::preparing_mut)
        {
            work.ended(label, image);
        }
        let Some((index, image)) = self.records.find_exit_any(n.label) else {
            return;
        };
        let record = self.records.get(index).expect("an ended record");
        if image != record.image {
            if self.replacing[index]
                .as_ref()
                .and_then(Work::replacing)
                .is_some_and(|r| r.old_image == image)
            {
                self.replacing[index]
                    .as_mut()
                    .and_then(Work::replacing_mut)
                    .expect("an exact old image")
                    .old
                    .ended();
                self.kick();
                return;
            }
            // The new process of an exec ended before ExecCommit: the place
            // goes, and the old image goes on. The end of an old image
            // after ExecCommit names nothing.
            let incoming = self
                .loaders
                .of(index)
                .and_then(|slot| self.loaders.get(slot))
                .is_some_and(|p| p.image == image && p.held.incoming.is_some());
            if incoming {
                #[cfg(feature = "image-probe")]
                self.abort_ended_load(index, Status::from_code(proto_process::AGAIN));
                #[cfg(not(feature = "image-probe"))]
                self.abort_load(index, Status::from_code(proto_process::AGAIN));
            }
            return;
        }
        let key = preparing::Key {
            label: record.label,
            image: record.image,
        };
        let first = self.records.mark_end_pending(key, None);
        self.generations.retire(index);
        if first {
            self.cancel_walks(key.label.raw_at(key.image));
        }
        if let Some(work) = self.replacing[index].as_mut().and_then(Work::preparing_mut) {
            let attempted = work.key();
            let requires_stop = work.resources.process.is_some();
            work.cancel(
                attempted,
                Status::from_code(proto_process::AGAIN).code(),
                requires_stop,
            );
            // Only the exact ended target can skip its paid Kill.
            work.ended(key.label, key.image);
        } else if self.replacing[index].is_none() {
            self.start_ending(index, None);
        }
        self.kick();
    }
}
