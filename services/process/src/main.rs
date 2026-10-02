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
use posix_process_service::records::{self, Exit, Record, Records, State};
use posix_process_service::signals::{self, Info, Posted};
use posix_process_service::waits::{WAITS_OF_RECORD, Wait, Waits};
use proto_process::{
    CLD_EXITED, CLD_KILLED, Change, Create, Credentials, End, INIT_PID, Method, Next,
    PAGE_CHLD_IGNORED, PAGE_NOCLDWAIT, RECORDS, SI_USER, SIGCHLD, SIGKILL, Selector, Spawn,
    WCONTINUED, WEXITED, WNOHANG, WNOWAIT, WSTOPPED, WaitResult, WaitStart,
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
mod make;
mod pages;
mod spawn;
use core::mem::ManuallyDrop;
rt::entry!(main);
/// The sessions of the loop: those of the service's own threads through
/// the channel with no label at place 0, a record's at its index plus 1
/// (`Service::place`), and a few for labels no record has: a session of a
/// record that went, whose place a new record took, asks there and gets
/// UNREGISTERED, or LIMIT_REACHED while five such hold the spare places.
const SESSIONS: usize = RECORDS + 1 + 4;
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
struct Processes {
    /// The service's channel, which the sessions are copies of.
    channel: ManuallyDrop<Handle<Channel>>,
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
    /// The thread of each record's process whose entry the service asks
    /// for once it set a signal on the page (Router).
    routers: [Option<Handle<Thread>>; RECORDS],
    /// The witness of each record's process, which init gave with ADOPT or
    /// SPAWN: it closes once the process ended, and init hears of the end.
    witnesses: [Option<Handle<Channel>>; RECORDS],
    /// The waits that wait: LongOps, and what each takes.
    ops: LongOps<WAITS>,
    waits: Waits<WAITS>,
}
impl Processes {
    const fn new() -> Self {
        Self {
            channel: Handle::borrowed(abi::Handle::INVALID),
            level: 1,
            records: Records::new(),
            spawns: [const { None }; RECORDS],
            queue: Queue::new(),
            next: None,
            pages: pages::Pages::new(),
            witnesses: [const { None }; RECORDS],
            routers: [const { None }; RECORDS],
            ops: LongOps::new(),
            waits: Waits::new(),
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
    owner.level = level;
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
impl Processes {
    /// Create (label 0): a record, LOADING, of a new process with the
    /// parameters of the body and the start channel the request brought,
    /// the process's end told through the record's exit place (O(1)): a
    /// record of init's table, or a child of the live record of the body's
    /// parent with its credentials (UNREGISTERED for none, AGAIN for one
    /// with CHILDREN_MAX children). The reply: the PID and the label, a
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
            .insert(label, process, parent, credentials, create.ceiling);
        self.witnesses[index] = Some(witness);
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
        let (copy, session) = match (copy, session) {
            (Ok(copy), Ok(session)) => (copy, session),
            (Err(e), _) | (_, Err(e)) => {
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
            Ok(()) => Answer::Reply([copy.erase(), session.erase()].into()),
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
    /// has CHILDREN_MAX children; INVALID for any spawn-flag until process
    /// groups come (5b T5).
    fn spawn(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let Ok(request) = Spawn::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        if request.flags != 0 {
            return refuse(proto_process::INVALID);
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
    /// (NOTIFY): READY with what the wait finds now, the wait over; or
    /// ARMED, the copy kept to tell. BAD_STATE for a key of no wait.
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

    /// Kill of the record in `index`: pid u32 and signal u32. NO_PROCESS
    /// for no live or zombie process of that PID (a LOADING one is none
    /// yet); PERMISSION past kill's rule (`signals::may_signal`); signal 0
    /// checks alone; SIGKILL ends the process from the service at the
    /// target's ceiling (process_kill_at); INVALID for a signal the service
    /// refuses until stops come (`signals::refused`); any other is posted
    /// on the target's page (`signal`). The reply comes once the signal is
    /// there: the caller's layer looks at its own page before its return.
    fn kill(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(pid), Ok(signal)) = (body.u32(), body.u32()) else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() || pid == 0 {
            return Answer::Status(Status::BadSize);
        }
        let Ok(signal) = u8::try_from(signal) else {
            return refuse(proto_process::INVALID);
        };
        let sender = self.records.get(index).expect("the sender");
        let (from_pid, from, from_session) = (sender.label.pid(), sender.credentials, sender.sid);
        let Some(target) = self.records.find_pid(pid).filter(|&t| {
            self.records
                .get(t)
                .is_some_and(|r| r.state != State::Loading)
        }) else {
            return refuse(proto_process::NO_PROCESS);
        };
        let record = self.records.get(target).expect("a target");
        if !signals::may_signal(from, record.credentials, signal, from_session == record.sid) {
            return refuse(proto_process::PERMISSION);
        }
        let zombie = matches!(record.state, State::Zombie(_));
        if signal == 0 || zombie {
            return Answer::Status(Status::Ok);
        }
        if signal == SIGKILL {
            let _ = sys::process_kill_at(&record.process, record.ceiling);
            return Answer::Status(Status::Ok);
        }
        let Some(page) = self.pages.page(target) else {
            return refuse(proto_process::NO_PROCESS);
        };
        if signals::refused(signal, page) {
            return refuse(proto_process::INVALID);
        }
        let info = Info {
            code: SI_USER,
            pid: from_pid,
            uid: from.uid,
            status: 0,
        };
        self.signal(target, signal, info);
        Answer::Status(Status::Ok)
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
                Answer::Status(status(result))
            }
            n if n == Method::Spawn as u16 => self.spawn(index, r),
            n if n == Method::WaitStart as u16 => self.wait_start(index, s, r),
            n if n == Method::WaitCancel as u16 => self.wait_cancel(s, r),
            n if n == Method::Kill as u16 => self.kill(index, r),
            _ => Answer::Status(Status::UnknownMethod),
        }
    }
    /// The client of `s` went: its waits go.
    fn gone(&mut self, s: &mut Session<LongSession, 0>) {
        self.ops.gone(&mut s.data);
    }
    /// The end of a process, through its record's exit place: the record
    /// ends with its reason (proto_process::End), its live children get
    /// PID 1 in their records and pages, and it waits as a zombie for its
    /// parent's wait, whose waits that take it are told, or goes at once
    /// without a parent. An end of an older generation takes nothing.
    fn notification(&mut self, n: Notice) {
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
