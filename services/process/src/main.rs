// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The POSIX process service (spec 2, section 3.1): it creates every POSIX
//! process itself and keeps its record, PID and credentials. The service
//! gives every session it serves through `handle_label` on its own
//! channel, the label naming the record (proto_process::Label), so the
//! label of a request finds its record in O(1) and no kernel call names a
//! process. Create, Loaded, Abandon and Next come only through the channel
//! with no label, from the service's own threads: the receiving thread
//! (adopt.rs) takes the records init's table starts with ADOPT, the
//! spawning thread (spawn.rs) the children Spawn asks for, which init
//! gives with SPAWN, and both load the programs from the boot image
//! (make.rs). Create makes the record, the place of its end, a copy of
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
use posix_process_service::queue::Queue;
use posix_process_service::records::{self, Exit, GroupError, Join, Record, Records, State};
use posix_process_service::signals::{self, Info, Posted};
use posix_process_service::waits::{WAITS_OF_RECORD, Wait, Waits};
use posix_process_service::walk::{self, Step, Target, Walk};
use proto_process::{
    CLD_EXITED, CLD_KILLED, Change, Create, Credentials, End, INIT_PID, Method, Next,
    PAGE_CHLD_IGNORED, PAGE_NOCLDWAIT, RECORDS, SI_USER, SIGCHLD, SIGKILL, SIGNAL_MAX, SIGSTOP,
    SPAWN_SETPGROUP, SPAWN_SETSID, Selector, Spawn, WCONTINUED, WEXITED, WNOHANG, WNOWAIT,
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
mod generations;
mod make;
mod pages;
mod spawn;
use core::mem::ManuallyDrop;
rt::entry!(main);
/// The sessions of the loop: those of the service's own threads through
/// the channel with no label at place 0, a record's at its index plus 1
/// (`Service::place`), and a few for labels no record has: the notary
/// sessions init gives the vouchers, and a session of a record that went,
/// whose place a new record took, which asks there and gets UNREGISTERED,
/// or LIMIT_REACHED while the spare places are taken.
const SESSIONS: usize = RECORDS + 1 + 8;
/// Where the service maps the boot image, read-only, for as long as it
/// lives: the programs it loads are read from there.
const IMAGE: usize = 0x50_0000_0000;
/// The waits of the service at most (spec 2, 3.4): 16 of a record, 1024
/// in all; past them a wait is EAGAIN.
const WAITS: usize = 1024;
/// A Spawn that waits: its deferred reply and its request. A record has
/// one at a time, so Loaded and Abandon of its child find it by the
/// parent alone.
struct Spawning {
    pending: Pending,
    request: Spawn,
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
    /// The Spawn of each record that waits, by the record's index.
    spawns: [Option<Spawning>; RECORDS],
    /// The records whose Spawn waits for the spawning thread.
    queue: Queue,
    /// The spawning thread's Next that waits for a Spawn.
    next: Option<Pending>,
    /// The pages of the records.
    pages: pages::Pages,
    /// The page of the credentials generations.
    generations: generations::Generations,
    /// The thread of each record's process whose entry the service asks
    /// for once it set a signal on the page (Router).
    routers: [Option<Handle<Thread>>; RECORDS],
    /// The witness of each record's process, which init gave with ADOPT or
    /// SPAWN: it closes once the process ended, and init hears of the end.
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
}
impl Processes {
    const fn new() -> Self {
        Self {
            channel: Handle::borrowed(abi::Handle::INVALID),
            identities: Handle::borrowed(abi::Handle::INVALID),
            level: 1,
            records: Records::new(),
            spawns: [const { None }; RECORDS],
            queue: Queue::new(),
            next: None,
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
        }
    }
}
/// The loop's state, in .bss: the records and the spawns that wait are
/// too big for the main thread's stack.
struct Owner(UnsafeCell<Processes>);
// SAFETY: only the main thread reaches it (`main`), once.
unsafe impl Sync for Owner {}
static OWNER: Owner = Owner(UnsafeCell::new(Processes::new()));
fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
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
    let Ok(channel) = sys::channel_create(1) else {
        return 3;
    };
    // The channel of the identity sessions, which no loop receives on:
    // a notification through a copy shows which record's it is (`vouch`).
    let Ok(identities) = sys::channel_create(1) else {
        return 3;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 4;
    }
    let level = sys::thread_info(&start.thread).map_or(1, |i| i.base);
    make::set_handles(&channel, &start.process, &start.parent, level);
    if adopt::start(&start.process, level).is_err() || spawn::start(&start.process, level).is_err()
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
    // SAFETY: the main thread is the one that reaches OWNER, here once.
    let owner = unsafe { &mut *OWNER.0.get() };
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
    rt::println!("posix-process: ready (records with their processes, root by init's table)");
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
    /// Create (label 0): a record, LOADING, of a new process with the
    /// parameters of the body and the start channel the request brought,
    /// the process's end told through the record's exit place (O(1)): a
    /// record of init's table, or a child of the live record of the body's
    /// parent with its credentials (UNREGISTERED for none, AGAIN for one
    /// with CHILDREN_MAX children), in the group and session its Spawn
    /// asks for (PERMISSION where setpgid would be EPERM). The reply: the PID and the label, a
    /// copy of the process for the load and the record's session. FULL
    /// with every record taken; the errors of the calls as the status, and
    /// nothing stays.
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
        let parent = match create.parent {
            0 => None,
            label => match self.records.find(label) {
                None => return refuse(proto_process::UNREGISTERED),
                Some(p) if !self.records.may_spawn(p) => return refuse(proto_process::AGAIN),
                Some(p) => Some(p),
            },
        };
        let Some(label) = self.records.next_label() else {
            return refuse(proto_process::FULL);
        };
        // The group and session the parent's Spawn asks for, before any
        // call: PERMISSION where setpgid would say EPERM.
        let join = match parent {
            Some(p) => {
                let (flags, pgroup) = self.spawns[p]
                    .as_ref()
                    .map_or((0, 0), |s| (s.request.flags, s.request.pgroup));
                match self.records.joining(p, flags, pgroup, label.pid()) {
                    Some(join) => join,
                    None => return refuse(proto_process::PERMISSION),
                }
            }
            None => Join::Inherit,
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
        let credentials = match parent {
            Some(p) => self.records.get(p).expect("a live parent").credentials,
            None if create.root => Credentials::ROOT,
            None => Credentials::NOBODY,
        };
        let index = self
            .records
            .insert(label, process, parent, credentials, create.ceiling, join);
        self.witnesses[index] = Some(witness);
        // A record made in a used index never starts its generation over.
        self.generations.raise(index);
        let record = self.records.get(index).expect("a new record");
        let identity = [label.pid(), record.parent, record.pgid, record.sid];
        let paged = self
            .pages
            .give(&make::own(), index, &record.process, identity);
        // A spawned child starts with the caller's mask and the parent's
        // SIG_IGN ([P24-SPAWN]); the layer reads them at its start.
        if let (Ok(()), Some(p)) = (&paged, parent)
            && let (Some(child), Some(from)) = (self.pages.page(index), self.pages.page(p))
        {
            use core::sync::atomic::Ordering::{Acquire, Release};
            let mask = self.spawns[p].as_ref().map_or(0, |s| s.request.mask);
            child.start_mask.store(mask, Release);
            child.ignored.store(from.ignored.load(Acquire), Release);
        }
        if paged.is_ok() && parent.is_some() {
            self.signal_newborn(index);
        }
        let session = paged.and_then(|()| {
            sys::handle_label(
                &self.channel,
                Rights::SEND | Rights::TRANSFER,
                label.raw(),
                self.level,
            )
        });
        // The end of an identity session waits in its channel, which no
        // loop receives on, and the session stays until it is received:
        // empty the channel, the earlier ends of a record each once, so
        // that the sessions of the processes that went do not fill it.
        while sys::try_receive(&self.identities).is_ok() {}
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
    /// first thread, the router of its signals: it is ALIVE, and the Spawn
    /// that asked for it gets its PID. UNREGISTERED for a
    /// label of no such record. A child that ended between thread_start
    /// and Loaded would leave its parent's Spawn waiting; it does not come
    /// to pass on one processor, where the spawning thread runs at the
    /// loop's level, above the child's ceiling, from its start to Loaded.
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
        let pid = record.label.pid();
        let parent = record.parent_index.map(usize::from);
        if let Some(spawning) = parent.and_then(|p| self.spawns[p].take()) {
            let mut w = Writer::new();
            if w.u32(0).and_then(|()| w.u32(pid)).is_ok() {
                // A parent that went meanwhile takes no reply.
                let _ = spawning.pending.answer(w.as_bytes(), Outgoing::new());
            }
        }
        Answer::Status(Status::Ok)
    }

    /// Abandon (label 0): the LOADING record of the body's label, if any,
    /// is killed, and goes with the end of its process; the Spawn of the
    /// body's parent, if any, gets the body's status. UNREGISTERED for a
    /// label of no LOADING record.
    fn abandon(&mut self, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(label), Ok(parent), Ok(code)) = (body.u64(), body.u64(), body.u32()) else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if let Some(spawning) = self
            .records
            .find(parent)
            .and_then(|p| self.spawns[p].take())
        {
            let status = Status::from_code(code.max(1));
            let _ = spawning
                .pending
                .answer(&proto_wire::reply(status), Outgoing::new());
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

    /// Spawn of the record in `index`: the request waits for the spawning
    /// thread, which makes the child (spawn.rs), and its reply comes with
    /// Loaded or Abandon. AGAIN while a Spawn of the record waits or it
    /// has CHILDREN_MAX children; INVALID for a spawn-flag other than
    /// SETPGROUP and SETSID, PERMISSION for the group they ask for when
    /// setpgid would be EPERM (Create asks again: the groups may change).
    fn spawn(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let Ok(mut request) = Spawn::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        // The caller's level, as it says, within the ceiling of its record:
        // the copy of the child's program never runs above the caller.
        let ceiling = self.records.get(index).map_or(1, |r| r.ceiling);
        request.level = request.level.min(ceiling);
        if request.flags & !(SPAWN_SETPGROUP | SPAWN_SETSID) != 0 {
            return refuse(proto_process::INVALID);
        }
        if self
            .records
            .joining(index, request.flags, request.pgroup, 0)
            .is_none()
        {
            return refuse(proto_process::PERMISSION);
        }
        if self.spawns[index].is_some() || !self.records.may_spawn(index) {
            return refuse(proto_process::AGAIN);
        }
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::BadSize);
        };
        self.spawns[index] = Some(Spawning { pending, request });
        self.queue.push(index);
        self.dispatch();
        Answer::Deferred
    }

    /// Next (label 0): the spawning thread waits for the next Spawn; AGAIN
    /// for a second Next.
    fn next(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if self.next.is_some() {
            return refuse(proto_process::AGAIN);
        }
        self.next = r.defer();
        self.dispatch();
        Answer::Deferred
    }

    /// Gives the waiting Next the Spawn at the head of the queue, if both
    /// wait: the parent's label and the record's name.
    fn dispatch(&mut self) {
        while self.next.is_some() {
            let Some(index) = self.queue.pop() else {
                return;
            };
            let (Some(spawning), Some(record)) = (&self.spawns[index], self.records.get(index))
            else {
                continue;
            };
            let next = Next {
                parent: record.label.raw(),
                name: spawning.request.name,
                level: spawning.request.level,
            };
            let mut w = Writer::new();
            if next.write(&mut w).is_err() {
                continue;
            }
            let pending = self.next.take().expect("a waiting Next");
            if pending.answer(w.as_bytes(), Outgoing::new()).is_err() {
                // The thread went; the Spawn waits for it again.
                self.queue.push(index);
            }
        }
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
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let method = r.method();
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
        let Some(index) = self.vouch(r) else {
            return refuse(proto_process::PERMISSION);
        };
        let record = self.records.get(index).expect("a vouched record");
        let who = proto_process::WhoReply {
            pid: record.label.pid(),
            credentials: record.credentials,
            generation: self.generations.get(index),
        };
        if who.write(r.reply()).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    /// The record whose identity session the one handle of `r` is a copy
    /// of: the service empties the identity channel, notifies through the
    /// handle and takes what came there. A copy of an identity session
    /// lands in its record's place (its label, which the kernel set); a
    /// channel of anyone else lands elsewhere, and none came. On one
    /// processor nothing runs between, the loop being above every client.
    fn vouch(&mut self, r: &mut Request<'_>) -> Option<usize> {
        if r.handles.len() != 1 {
            return None;
        }
        let handle = r.handles.take::<Channel>(0).ok()?;
        let drain = |c: &Handle<Channel>| while sys::try_receive(c).is_ok() {};
        drain(&self.identities);
        sys::notify(&handle, 1).ok()?;
        let got = sys::try_receive(&self.identities);
        drain(&self.identities);
        match got {
            Ok(sys::Received::Notification {
                source: Source::Session,
                label,
                bits,
                ..
            }) if bits & 1 != 0 => self.records.find_identity(label),
            _ => None,
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
impl Service<0> for Processes {
    const VERSION: u16 = proto_process::VERSION;
    const METHODS: &'static [u16] = proto_process::METHODS;
    const PLACED: usize = RECORDS + 1;
    type Data = LongSession;
    fn place(&self, label: u64) -> Option<usize> {
        if label == 0 {
            return Some(0);
        }
        self.records.find(label).map(|i| i + 1)
    }
    fn request(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
        let method = r.method();
        let own = [
            Method::Create,
            Method::Loaded,
            Method::Abandon,
            Method::Next,
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
                n if n == Method::Abandon as u16 => self.abandon(r),
                _ => self.next(r),
            };
        }
        if proto_process::is_notary(r.label()) {
            return self.notary(r);
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
            n if n == Method::Spawn as u16 => self.spawn(index, r),
            n if n == Method::WaitStart as u16 => self.wait_start(index, s, r),
            n if n == Method::WaitCancel as u16 => self.wait_cancel(s, r),
            n if n == Method::Kill as u16 => self.kill(index, r),
            n if n == Method::SetPgid as u16 => self.set_pgid(index, r),
            n if n == Method::SetSid as u16 => self.set_sid(index, r),
            n if n == Method::GetPgid as u16 => self.get_group(index, false, r),
            n if n == Method::GetSid as u16 => self.get_group(index, true, r),
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
        let Some(index) = self.records.find_exit(n.label) else {
            return;
        };
        let record = self.records.get(index).expect("an ended record");
        let end = End::of(sys::process_state(&record.process).unwrap_or(abi::ProcessState::Killed))
            .unwrap_or(End::Signaled(SIGKILL));
        self.queue.remove(index);
        self.spawns[index] = None;
        // A walk of the ended sender stops, and those it queued: their
        // replies have no taker.
        self.walking.remove(index);
        self.walks[index] = None;
        for slot in &mut self.later {
            if slot.as_ref().is_some_and(|(s, _)| *s == index) {
                *slot = None;
            }
        }
        let (exit, orphans) = self.records.exited(index, end);
        // Init reads the end once the witness closed.
        self.witnesses[index] = None;
        for &orphan in orphans.as_slice() {
            if let Some(page) = self.pages.page(usize::from(orphan)) {
                page.ppid
                    .store(INIT_PID, core::sync::atomic::Ordering::Release);
            }
        }
        self.routers[index] = None;
        if let Exit::Zombie { parent } = exit {
            self.child_ended(parent, index, end);
        }
    }
}
