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
use posix_process_service::loaders::{self, LOADERS, Loaders, Stage};
use posix_process_service::queue::Queue;
use posix_process_service::records::{self, Exit, GroupError, Join, Record, Records, State};
use posix_process_service::signals::{self, Info, Posted};
use posix_process_service::waits::{WAITS_OF_RECORD, Wait, Waits};
use posix_process_service::walk::{self, Step, Target, Walk};
use proto_process::{
    CLD_EXITED, CLD_KILLED, Change, Create, Credentials, End, INIT_PID, Label, LoaderOf, Method,
    PAGE_CHLD_IGNORED, PAGE_NOCLDWAIT, Place, RECORDS, SI_USER, SIGCHLD, SIGKILL, SIGNAL_MAX,
    SIGSTOP, SPAWN_FLAGS, Selector, SetId, SpawnStart, WCONTINUED, WEXITED, WNOHANG, WNOWAIT,
    WSTOPPED, WaitResult, WaitStart,
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
mod ends;
mod generations;
mod loader;
mod make;
mod pages;
mod replace;
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
    pending: Pending,
    ready: Option<Handle<Channel>>,
    process: Option<Handle<Process>>,
    /// The old process, which the service kills once init took the new.
    old: Option<Handle<Process>>,
    ticket: u64,
}
/// A walk of kill(0), kill(-pgid) or kill(-1) that waits (walk.rs): the
/// sender's request, what it sends, and what the steps found so far.
struct Walking {
    walk: Walk,
    pending: Pending,
    signal: u8,
    delivered: bool,
    refused: bool,
    denied: bool,
}
/// The walks of the service that wait for an earlier walk of their sender
/// at most; past them kill is EAGAIN.
const LATER: usize = 64;
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
    records: Records<Handle<Process>>,
    /// The ticket init gave each record of its table, 0 for the others.
    tickets: [u64; RECORDS],
    /// The ExecCommit of each record that waits for init, by the record's
    /// index, the records whose new process waits for the thread that
    /// tells init, and that thread's Replace that waits for one.
    replacing: [Option<Replacing>; RECORDS],
    replace_queue: Queue,
    replacer: Option<Pending>,
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
    console: Option<Handle<Resource>>,
}
impl Processes {
    const fn new() -> Self {
        Self {
            channel: Handle::borrowed(abi::Handle::INVALID),
            identities: Handle::borrowed(abi::Handle::INVALID),
            level: 1,
            records: Records::new(),
            tickets: [0; RECORDS],
            replacing: [const { None }; RECORDS],
            replace_queue: Queue::new(),
            replacer: None,
            pages: pages::Pages::new(),
            generations: generations::Generations::new(),
            witnesses: [const { None }; RECORDS],
            routers: [const { None }; RECORDS],
            ops: LongOps::new(),
            waits: Waits::new(),
            walks: [const { None }; RECORDS],
            walking: Queue::new(),
            later: [const { None }; LATER],
            step: None,
            step_told: false,
            loaders: Loaders::new(),
            loader: None,
            files: None,
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
    }
    if adopt::start(&start.process, level).is_err()
        || replace::start(&start.process, level).is_err()
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
    #[cfg(feature = "steps")]
    rt::service::report_steps();
    rt::println!("posix-process: ready (records with their processes, root by init's table)");
    rt::println!(
        "posix-process: loader {}",
        if owner.loader.is_some() && owner.files.is_some() {
            "ready"
        } else {
            "absent"
        }
    );
    let _ = rt::service::run::<Processes, SESSIONS, 0>(&channel, owner, config);
    5
}
fn status(result: Result<(), posix_credentials::Error>) -> Status {
    Status::from_code(match result {
        Ok(()) => 0,
        Err(posix_credentials::Error::Invalid) => proto_process::INVALID,
        Err(posix_credentials::Error::Permission) => proto_process::PERMISSION,
    })
}
fn snapshot(r: &mut Request<'_>, record: &Record<Handle<Process>>) {
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
    /// record taken; the errors of the calls as the status, and nothing
    /// stays.
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
        let place = records::exit_place(label, &create, self.level);
        let made = sys::handle_label(&self.channel, Rights::NOTIFY, place.label, place.slot)
            .and_then(|exit| {
                sys::process_create_with(
                    create.quota,
                    create.handle_limit,
                    create.ceiling,
                    Some((&exit, place.notice)),
                    Some(start),
                )
                .map_err(|(e, _)| e)
            });
        let process = match made {
            Ok(process) => process,
            Err(e) => return Answer::Status(Status::Kernel(e)),
        };
        // From here on the record is in the table, and only the end of its
        // process takes it out, so that the exit label is never given twice.
        let rights = Rights::MANAGE | Rights::DUPLICATE | Rights::TRANSFER;
        let copy = sys::handle_duplicate(&process, rights);
        let credentials = if create.root {
            Credentials::ROOT
        } else {
            Credentials::NOBODY
        };
        let index = self.records.insert(
            label,
            process,
            None,
            credentials,
            create.ceiling,
            Join::Inherit,
        );
        if let Some(record) = self.records.get_mut(index) {
            record.quota = create.quota;
            record.handle_limit = create.handle_limit;
        }
        self.witnesses[index] = Some(witness);
        self.tickets[index] = create.ticket;
        // A record made in a used index never starts its generation over.
        self.generations.raise(index);
        let record = self.records.get(index).expect("a new record");
        let identity = [label.pid(), record.parent, record.pgid, record.sid];
        let paged = self
            .pages
            .give(&make::own(), index, &record.process, identity);
        let session = paged.and_then(|()| {
            sys::handle_label(
                &self.channel,
                Rights::SEND | Rights::TRANSFER,
                label.raw(),
                self.level,
            )
        });
        // The identity session: the process gives copies of it (DUPLICATE)
        // to the services it asks something of, which have it vouched for.
        let who = sys::handle_label(
            &self.identities,
            Rights::NOTIFY | Rights::TRANSFER | Rights::DUPLICATE,
            label.identity(),
            self.level,
        );
        let (copy, session, who) = match (copy, session, who) {
            (Ok(copy), Ok(session), Ok(who)) => (copy, session, who),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                let record = self.records.get(index).expect("a new record");
                let _ = sys::process_kill(&record.process);
                return Answer::Status(Status::Kernel(e));
            }
        };
        let w = r.reply();
        let written = w
            .u32(0)
            .and_then(|()| w.u32(label.pid()))
            .and_then(|()| w.u64(label.raw()));
        match written {
            Ok(()) => Answer::Reply([copy.erase(), session.erase(), who.erase()].into()),
            Err(status) => {
                let _ = sys::process_kill(&copy);
                Answer::Status(status)
            }
        }
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

    /// What a wait of the record in `parent` with `selector` and `options`
    /// finds now: the first zombie child it takes, which goes unless
    /// WNOWAIT (the parent's other waits that take it are told); ECHILD
    /// with no child it takes; None while it waits. CHILDREN_MAX steps.
    fn found(&mut self, parent: usize, selector: Selector, options: u32) -> Option<WaitResult> {
        let (zombie, any) = self.records.zombie(parent, selector);
        let Some(child) = zombie else {
            return (!any).then_some(WaitResult::NoChild);
        };
        if options & WEXITED == 0 {
            return None;
        }
        let record = self.records.get(child).expect("a zombie");
        let State::Zombie(end) = record.state else {
            return None;
        };
        let result = WaitResult::Ended {
            pid: record.label.pid(),
            end,
            uid: record.credentials.uid,
        };
        if options & WNOWAIT == 0 {
            self.tell(parent, child);
            self.records.reap(child);
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
        if method == Method::SetId as u16 {
            return self.set_id(r);
        }
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        if method == Method::Register as u16 && r.handles.is_empty() {
            let Ok(copy) = self.generations.copy() else {
                return Answer::Status(Status::Kernel(abi::Error::NoMemory));
            };
            if r.reply().u32(0).is_err() {
                return Answer::Status(Status::BadSize);
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
        let who = proto_process::WhoReply {
            pid: record.label.pid(),
            credentials: record.credentials,
            generation: self.generations.get(index),
            loader,
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
            _ => Some((self.records.find_identity(label)?, None)),
        }
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
        let waiting = self
            .pages
            .page(index)
            .is_some_and(|p| p.pending.load(core::sync::atomic::Ordering::Acquire) != 0);
        if waiting {
            let _ = sys::thread_upcall_request(&thread);
        }
        self.routers[index] = Some(thread);
        Answer::Status(Status::Ok)
    }

    /// Posts `signal` with `info` to the process of the record in `target`
    /// and asks for its router's entry when it waits now (O(1)).
    fn signal(&mut self, target: usize, signal: u8, info: Info) {
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
    /// Refused for a signal the service refuses until stops come
    /// (`signals::refused`); signal 0 and a zombie take nothing; SIGKILL
    /// ends the process from the service at the target's ceiling
    /// (process_kill_at); any other is posted on the target's page
    /// (`signal`). O(1).
    fn deliver(&mut self, sender: usize, target: usize, signal: u8) -> Delivery {
        let from = self.records.get(sender).expect("the sender");
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
        let zombie = matches!(record.state, State::Zombie(_));
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
        if signals::refused(signal, page) {
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
            self.records
                .get(t)
                .is_some_and(|r| r.state != State::Loading)
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
    /// a signal past SIGNAL_MAX and SIGSTOP (until stops come, as
    /// `signals::refused` says for one process); NO_PROCESS at once for a
    /// group nobody is in; AGAIN while the sender's other walk is on; else
    /// the request waits for the steps (`walk_step`).
    fn walk_start(&mut self, index: usize, pid: i32, signal: u8, r: &mut Request<'_>) -> Answer {
        if signal > SIGNAL_MAX || signal == SIGSTOP {
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
        let Some(index) = self.walking.pop() else {
            return;
        };
        let Some(mut w) = self.walks[index].take() else {
            self.kick();
            return;
        };
        match w.walk.step(&self.records) {
            Step::Found(target) => match self.deliver(index, target, w.signal) {
                Delivery::Done => w.delivered = true,
                Delivery::Denied => w.denied = true,
                Delivery::Refused => w.refused = true,
            },
            Step::Looked => {}
            Step::Done => {
                let code = walk::outcome(w.delivered, w.refused, w.denied);
                let status = Status::from_code(code);
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
    fn signal_newborn(&mut self, index: usize) {
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
                self.publish_group(index);
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
        match self.records.set_sid(index) {
            Ok(sid) => {
                self.publish_group(index);
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

    /// The child in `child` of the record in `parent` ended with `end`: a
    /// parent whose page says SA_NOCLDWAIT or SIGCHLD ignored takes no
    /// zombie, which goes at once; SIGCHLD goes to the parent (CLD_EXITED
    /// or CLD_KILLED with the child's PID, real UID and status); the
    /// parent's waits that take the child are told.
    fn child_ended(&mut self, parent: usize, child: usize, end: End) {
        let record = self.records.get(child).expect("a zombie");
        let (pid, uid) = (record.label.pid(), record.credentials.uid);
        let (code, status) = match end {
            End::Exited(code) => (CLD_EXITED, i32::from(code)),
            End::Signaled(n) => (CLD_KILLED, i32::from(n)),
        };
        let flags = self
            .pages
            .page(parent)
            .map_or(0, |p| p.flags.load(core::sync::atomic::Ordering::Acquire));
        self.tell(parent, child);
        if flags & (PAGE_NOCLDWAIT | PAGE_CHLD_IGNORED) != 0 {
            self.records.reap(child);
        }
        let info = Info {
            code,
            pid,
            uid,
            status,
        };
        self.signal(parent, SIGCHLD, info);
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
    /// a file. The record of the child (LOADING, as Create makes it), its
    /// process with the parent's quota, room for handles and ceiling, the
    /// loader's session in its entry 0, the loader mapped and its thread
    /// started at the caller's level; the reply waits for Boot. O(1) but
    /// for the copy of the loader's data, a page.
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
        // A RAM file service that started again closed the session of
        // the loaders: the service asks init for the new one (init answers
        // once the service registered).
        if self.loader.is_some()
            && self
                .files
                .as_ref()
                .is_none_or(|f| sys::channel_info(f).is_ok_and(|i| i.closed))
        {
            self.files = rt::service::connect(&make::init(), "ramfs").ok();
        }
        if self.loader.is_none() || self.files.is_none() {
            return refuse(proto_process::NOT_FOUND);
        }
        if !self.records.may_spawn(index) || !self.loaders.room_for(index) {
            return refuse(proto_process::AGAIN);
        }
        let Some(label) = self.records.next_label() else {
            return refuse(proto_process::AGAIN);
        };
        let Some(join) = self
            .records
            .joining(index, start.flags, start.pgroup, label.pid())
        else {
            return refuse(proto_process::PERMISSION);
        };
        let parent = self.records.get(index).expect("the caller");
        let create = Create {
            quota: parent.quota,
            handle_limit: parent.handle_limit,
            ceiling: parent.ceiling,
            priority: start.level.clamp(1, parent.ceiling),
            root: false,
            ticket: 0,
        };
        let credentials = loaders::child_credentials(parent.credentials, start.flags);
        // The child's quota comes from the service's: the pool, past which
        // the service keeps a reserve for its own records and loaders.
        if !loaders::pool_allows(free_quota(), create.quota) {
            return kernel(abi::Error::NoMemory);
        }
        let place = records::exit_place(label, &create, self.level);
        // TRANSFER: the session moves into the process's entry 0.
        let rights = Rights::SEND | Rights::TRANSFER;
        let made = sys::handle_label(&self.channel, rights, label.loader(), self.level).and_then(
            |session| {
                let exit =
                    sys::handle_label(&self.channel, Rights::NOTIFY, place.label, place.slot)?;
                sys::process_create_with(
                    create.quota,
                    create.handle_limit,
                    create.ceiling,
                    Some((&exit, place.notice)),
                    Some(session),
                )
                .map_err(|(e, _)| e)
            },
        );
        let process = match made {
            Ok(process) => process,
            Err(e) => return kernel(e),
        };
        // From here on the record is in the table, and only the end of its
        // process takes it out.
        let child = self.records.insert(
            label,
            process,
            Some(index),
            credentials,
            create.ceiling,
            join,
        );
        if let Some(record) = self.records.get_mut(child) {
            record.quota = create.quota;
            record.handle_limit = create.handle_limit;
        }
        self.generations.raise(child);
        let record = self.records.get(child).expect("a new record");
        let identity = [label.pid(), record.parent, record.pgid, record.sid];
        let paged = self
            .pages
            .give(&make::own(), child, &record.process, identity);
        // The child's main thread starts with the mask SpawnStart names;
        // the parent's SIG_IGN pass but those POSIX_SPAWN_SETSIGDEF sets
        // to the default ([P24-SPAWN]).
        if let (Ok(()), Some(page), Some(from)) =
            (&paged, self.pages.page(child), self.pages.page(index))
        {
            use core::sync::atomic::Ordering::{Acquire, Release};
            page.start_mask.store(start.mask, Release);
            let ignored = from.ignored.load(Acquire) & !start.default;
            page.ignored.store(ignored, Release);
        }
        if paged.is_ok() {
            self.signal_newborn(child);
        }
        let image = self.loader.as_ref().expect("a loader");
        let record = self.records.get(child).expect("a new record");
        let placed =
            paged.and_then(|()| image.place(&make::own(), &record.process, create.priority));
        let thread = match placed {
            Ok(thread) => thread,
            Err(e) => {
                let _ = sys::process_kill(&record.process);
                return kernel(e);
            }
        };
        let Some(pending) = r.defer() else {
            let _ = sys::process_kill(&record.process);
            return Answer::Status(Status::BadSize);
        };
        let held = Held {
            thread: None,
            ready: None,
            start: Some(pending),
            incoming: None,
        };
        let Some(slot) = self.loaders.take(child, index, proto_process::IMAGE, held) else {
            let _ = sys::process_kill(&record.process);
            return Answer::Deferred;
        };
        let started = sys::thread_start(&thread);
        self.loaders.get_mut(slot).expect("a new place").held.thread = Some(thread);
        if let Err(e) = started {
            self.abort_load(child, Status::Kernel(e));
        }
        Answer::Deferred
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
        let record = self.records.get(index).expect("the caller");
        if self.loaders.of(index).is_some()
            || !self.loaders.room_for(index)
            || record.tried >= proto_process::IMAGE_MAX
        {
            return refuse(proto_process::AGAIN);
        }
        if !loaders::pool_allows(free_quota(), record.quota) {
            return kernel(abi::Error::NoMemory);
        }
        let (label, image, ceiling) = (record.label, record.tried + 1, record.ceiling);
        let (quota, handle_limit) = (record.quota, record.handle_limit);
        // The number goes to this attempt whatever comes of it (sp5.M1).
        self.records.get_mut(index).expect("the caller").tried = image;
        let priority = start.level.clamp(1, ceiling);
        let rights = Rights::SEND | Rights::TRANSFER;
        let made = sys::handle_label(&self.channel, rights, label.loader_at(image), self.level)
            .and_then(|session| {
                let exit = sys::handle_label(
                    &self.channel,
                    Rights::NOTIFY,
                    label.exit_at(image),
                    ceiling,
                )?;
                sys::process_create_with(
                    quota,
                    handle_limit,
                    ceiling,
                    Some((&exit, ceiling)),
                    Some(session),
                )
                .map_err(|(e, _)| e)
            });
        let process = match made {
            Ok(process) => process,
            Err(e) => return kernel(e),
        };
        let placed = self.pages.map_again(index, &process).and_then(|()| {
            let image = self.loader.as_ref().expect("a loader");
            image.place(&make::own(), &process, priority)
        });
        let thread = match placed {
            Ok(thread) => thread,
            Err(e) => {
                let _ = sys::process_kill(&process);
                return kernel(e);
            }
        };
        // The new image's main thread starts with the caller's mask.
        if let Some(page) = self.pages.page(index) {
            page.start_mask
                .store(start.mask, core::sync::atomic::Ordering::Release);
        }
        let Some(pending) = r.defer() else {
            let _ = sys::process_kill(&process);
            return Answer::Status(Status::BadSize);
        };
        let started = sys::thread_start(&thread);
        let held = Held {
            thread: Some(thread),
            ready: None,
            start: Some(pending),
            incoming: Some(process),
        };
        if self.loaders.take(index, index, image, held).is_none() {
            return Answer::Deferred;
        }
        if let Err(e) = started {
            self.abort_load(index, Status::Kernel(e));
        }
        Answer::Deferred
    }

    /// ExecCommit of the record in `index` (step 5): the record moves to
    /// the new process in one step of the loop: its image number is the
    /// new one (its old session, exit place and identity name nothing
    /// from here on), the set-ID its loader's place kept applies (the
    /// saved IDs follow the effective ones), the generation of its
    /// credentials grows before the reply, its caught signals are the
    /// default on the page (sp4.M3), the new main thread routes its
    /// signals, the loads of children the old image started and did not
    /// commit stop (their parent's copy of C goes with it), the service
    /// kills the old process (process_kill_at, O(1) for the caller, sp5.K1)
    /// and the loader hears that the record is ready. For a record of
    /// init's table the loader's notification and the kill wait until init
    /// took the new process for the record's end line (`replace`).
    /// BAD_STATE without an exec whose image is ready.
    fn exec_commit(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let exec = self
            .loaders
            .of(index)
            .and_then(|slot| self.loaders.get(slot))
            .is_some_and(|p| p.parent == index && p.held.incoming.is_some());
        if !exec {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        let Ok(set_id) = self.loaders.commit(index) else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        let slot = self.loaders.of(index).expect("an exec's place");
        let place = self.loaders.get_mut(slot).expect("a place");
        let image = place.image;
        let incoming = place.held.incoming.take().expect("the new process");
        self.routers[index] = place.held.thread.take();
        let ready = place.held.ready.take();
        let ticket = self.tickets[index];
        let copy = (ticket != 0)
            .then(|| sys::handle_duplicate(&incoming, Rights::DUPLICATE | Rights::TRANSFER).ok())
            .flatten();
        let record = self.records.get_mut(index).expect("the caller");
        let old = core::mem::replace(&mut record.process, incoming);
        let ceiling = record.ceiling;
        record.image = image;
        let mut credentials = loaders::child_credentials(record.credentials, 0);
        if let Some(ids) = set_id {
            credentials = loaders::set_ids(credentials, ids);
        }
        record.credentials = credentials;
        self.generations.raise(index);
        if let Some(page) = self.pages.page(index) {
            page.caught.store(0, core::sync::atomic::Ordering::Release);
        }
        // The loads the old image started: nobody gives their loaders a
        // block once it is gone (sp5.V2).
        let mut children = [0u16; loaders::LOADERS];
        let mut count = 0;
        for child in self.loaders.uncommitted_of(index) {
            children[count] = child as u16;
            count += 1;
        }
        for &child in &children[..count] {
            self.abort_load(usize::from(child), Status::Kernel(abi::Error::PeerClosed));
        }
        if let Some(process) = copy
            && let Some(pending) = r.defer()
        {
            self.replacing[index] = Some(Replacing {
                pending,
                ready,
                process: Some(process),
                old: Some(old),
                ticket,
            });
            self.replace_queue.push(index);
            self.dispatch_replace();
            return Answer::Deferred;
        }
        let _ = sys::process_kill_at(&old, ceiling);
        if let Some(ready) = ready.as_ref() {
            let _ = sys::notify(ready, 1);
        }
        Answer::Status(Status::Ok)
    }

    /// Replace (label 0): the thread that tells init of an exec names the
    /// record whose exec init heard of (`finish_replace`), then waits for
    /// the next ExecCommit of a record of init's table; AGAIN for a second
    /// Replace that waits.
    fn replace(&mut self, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let Ok(done) = body.u64() else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if let Some(index) = self.records.find(done) {
            self.finish_replace(index);
        }
        if self.replacer.is_some() {
            return refuse(proto_process::AGAIN);
        }
        self.replacer = r.defer();
        self.dispatch_replace();
        Answer::Deferred
    }

    /// Gives the waiting Replace the new process of the exec at the head
    /// of the queue, if both wait: the record's label at its new image,
    /// init's ticket and the process. A thread that went leaves the exec to go on at once.
    fn dispatch_replace(&mut self) {
        while self.replacer.is_some() {
            let Some(index) = self.replace_queue.pop() else {
                return;
            };
            let (Some(replacing), Some(record)) =
                (self.replacing[index].as_mut(), self.records.get(index))
            else {
                continue;
            };
            let Some(process) = replacing.process.take() else {
                continue;
            };
            let mut w = Writer::new();
            let written = w
                .u32(0)
                .and_then(|()| w.u32(0))
                .and_then(|()| w.u64(record.label.raw_at(record.image)))
                .and_then(|()| w.u64(replacing.ticket));
            let pending = self.replacer.take().expect("a waiting Replace");
            if written.is_err() || pending.answer(w.as_bytes(), [process.erase()]).is_err() {
                self.finish_replace(index);
            }
        }
    }

    /// The exec of the record in `index` that waited for init goes on: the
    /// service kills the old process and the loader tells the new image
    /// the record is ready.
    fn finish_replace(&mut self, index: usize) {
        let Some(replacing) = self.replacing[index].take() else {
            return;
        };
        if let Some(old) = replacing.old.as_ref() {
            let ceiling = self.records.get(index).map_or(0, |r| r.ceiling);
            let _ = sys::process_kill_at(old, ceiling);
        }
        if let Some(ready) = replacing.ready.as_ref() {
            let _ = sys::notify(ready, 1);
        }
        let _ = replacing
            .pending
            .answer(&proto_wire::reply(Status::Ok), Outgoing::new());
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

    /// The load of the record in `child` stops: its process is killed, its
    /// loader's place and SetId go, and a SpawnStart that waits gets
    /// `status`. The record goes with the end of its process.
    fn abort_load(&mut self, child: usize, status: Status) {
        if let Some(place) = self.loaders.free(child) {
            if let Some(start) = place.held.start {
                let _ = start.answer(&proto_wire::reply(status), Outgoing::new());
            }
            // An exec's new process goes; the record keeps its old one.
            if let Some(incoming) = place.held.incoming {
                let ceiling = self.records.get(child).map_or(0, |r| r.ceiling);
                let _ = sys::process_kill_at(&incoming, ceiling);
                return;
            }
        }
        if let Some(record) = self.records.get(child)
            && record.state == State::Loading
        {
            let _ = sys::process_kill(&record.process);
        }
    }

    /// A request through the session of the loader of the record in
    /// `child`: Boot or Take; PERMISSION for any other.
    fn loader_request(&mut self, child: usize, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let Some(slot) = self.loaders.of(child) else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        match r.method() {
            m if m == Method::Boot as u16 => self.boot(child, slot, r),
            m if m == Method::Ready as u16 => self.ready(child, r),
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
    /// and the parent may commit the place from now on (sp5.V1).
    fn ready(&mut self, child: usize, r: &mut Request<'_>) -> Answer {
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        match self.loaders.loaded(child) {
            Ok(()) => Answer::Status(Status::Ok),
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
        self.loaders.free(child);
        Answer::Reply(handles)
    }

    /// The LOADING child of the record in `parent` whose PID the body
    /// names.
    fn loading_child(&self, parent: usize, r: &Request<'_>) -> Option<usize> {
        let mut body = r.body();
        let pid = body.u32().ok()?;
        body.finish().ok()?;
        self.records.find_pid(pid).filter(|&c| {
            self.records
                .get(c)
                .is_some_and(|c| c.state == State::Loading && c.parent_index == Some(parent as u16))
        })
    }

    /// SpawnCommit of the record in `index`: its LOADING child lives, with
    /// the IDs SetId kept for its loader's place, and the loader hears that
    /// the record is ready. BAD_STATE until the loader said its image is
    /// ready (Ready): a parent that commits before, or after a failed
    /// load, gets no child that waits for a block (sp5.V1).
    fn spawn_commit(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let Some(child) = self.loading_child(index, r) else {
            return refuse(proto_process::NO_PROCESS);
        };
        let Ok(set_id) = self.loaders.commit(child) else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        let record = self.records.get_mut(child).expect("a loading record");
        record.state = State::Alive;
        if let Some(ids) = set_id {
            record.credentials = loaders::set_ids(record.credentials, ids);
        }
        // The services that remember credentials see the new ones before
        // the child runs a request.
        self.generations.raise(child);
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
    fn spawn_abort(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let Some(child) = self.loading_child(index, r) else {
            return refuse(proto_process::NO_PROCESS);
        };
        self.abort_load(child, Status::from_code(proto_process::AGAIN));
        Answer::Status(Status::Ok)
    }

    /// SetId through a notary session with SET_ID: kept for the loader's
    /// place the ticket names, while it loads the record and image the
    /// body names (loaders.rs); PERMISSION otherwise.
    fn set_id(&mut self, r: &mut Request<'_>) -> Answer {
        if !proto_process::may_set_id(r.label()) || !r.handles.is_empty() {
            return refuse(proto_process::PERMISSION);
        }
        let Ok(set) = SetId::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        let Some(child) = self.records.find_pid(set.pid) else {
            return refuse(proto_process::PERMISSION);
        };
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
    const METHODS: &'static [u16] = proto_process::METHODS;
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
        if let Some(child) = self.records.find_loader(r.label()) {
            return self.loader_request(child, r);
        }
        let loaders_own = [Method::Boot, Method::Ready, Method::Take, Method::SetId];
        if loaders_own.map(|m| m as u16).contains(&method) {
            return refuse(proto_process::PERMISSION);
        }
        let Some(index) = self.records.find(r.label()) else {
            return refuse(proto_process::UNREGISTERED);
        };
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
                let record = self.records.get_mut(index).expect("change process");
                let result = posix_credentials::change(record.credentials, operation, id)
                    .map(|next| record.credentials = next);
                // The services that remember the credentials see the
                // generation move before the caller's reply, so that
                // whatever the caller sends after it returns is checked by
                // the new ones.
                if result.is_ok() {
                    self.generations.raise(index);
                }
                Answer::Status(status(result))
            }
            n if n == Method::SpawnStart as u16 => self.spawn_start(index, r),
            n if n == Method::SpawnCommit as u16 => self.spawn_commit(index, r),
            n if n == Method::SpawnAbort as u16 => self.spawn_abort(index, r),
            n if n == Method::ExecStart as u16 => self.exec_start(index, r),
            n if n == Method::ExecCommit as u16 => self.exec_commit(index, r),
            n if n == Method::ExecAbort as u16 => self.exec_abort(index, r),
            n if n == Method::WaitStart as u16 => self.wait_start(index, s, r),
            n if n == Method::WaitCancel as u16 => self.wait_cancel(s, r),
            n if n == Method::Kill as u16 => self.kill(index, r),
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
        if n.source == Source::Session && n.label == STEP {
            self.walk_step();
            return;
        }
        if n.source != Source::Exit {
            return;
        }
        let Some((index, image)) = self.records.find_exit_any(n.label) else {
            return;
        };
        let record = self.records.get(index).expect("an ended record");
        if image != record.image {
            // The new process of an exec ended before ExecCommit: the place
            // goes, and the old image goes on. The end of an old image
            // after ExecCommit names nothing.
            let incoming = self
                .loaders
                .of(index)
                .and_then(|slot| self.loaders.get(slot))
                .is_some_and(|p| p.image == image && p.held.incoming.is_some());
            if incoming {
                self.abort_load(index, Status::from_code(proto_process::AGAIN));
            }
            return;
        }
        let end = End::of(sys::process_state(&record.process).unwrap_or(abi::ProcessState::Killed))
            .unwrap_or(End::Signaled(SIGKILL));
        // A walk of the ended sender stops, and those it queued: their
        // replies have no taker.
        self.walking.remove(index);
        self.walks[index] = None;
        for slot in &mut self.later {
            if slot.as_ref().is_some_and(|(s, _)| *s == index) {
                *slot = None;
            }
        }
        // A loader that ended: its place and SetId go, and a SpawnStart
        // that waited for its Boot gets AGAIN. An old image that ended
        // before its ExecCommit, by itself or by SIGKILL, takes the new
        // process with it, whose quota comes back to the pool (sp5.K2).
        self.abort_load(index, Status::from_code(proto_process::AGAIN));
        let (exit, orphans) = self.records.exited(index, end);
        // An exec that waited for init goes on: its new image is dead.
        self.replace_queue.remove(index);
        self.finish_replace(index);
        self.tickets[index] = 0;
        // Init reads the end once the witness closed.
        self.witnesses[index] = None;
        for &orphan in orphans.as_slice() {
            let orphan = usize::from(orphan);
            if let Some(page) = self.pages.page(orphan) {
                page.ppid
                    .store(INIT_PID, core::sync::atomic::Ordering::Release);
            }
            // A child whose parent ended before its SpawnCommit goes.
            if self
                .records
                .get(orphan)
                .is_some_and(|r| r.state == State::Loading)
                && self.loaders.of(orphan).is_some()
            {
                self.abort_load(orphan, Status::Kernel(abi::Error::PeerClosed));
            }
        }
        self.routers[index] = None;
        if let Exit::Zombie { parent } = exit {
            self.child_ended(parent, index, end);
        }
    }
}
