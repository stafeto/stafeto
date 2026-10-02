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
//! of the end: the record goes with that notification alone, whoever
//! holds a copy of its session.
#![no_std]
#![no_main]
use core::cell::UnsafeCell;
use posix_process_service::queue::Queue;
use posix_process_service::records::{self, Record, Records, State};
use proto_process::{Change, Create, Credentials, Method, Next, RECORDS, Spawn};
use proto_wire::{Status, Writer};
use rt::{
    abi::{self, Access, Rights, Source},
    handle::{Channel, Handle, Memory, Outgoing, Process, Resource},
    service::{Answer, Config, Heartbeat, Notice, Pending, Request, Service, Session},
    sys,
};
mod adopt;
mod make;
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
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let Ok(start) = r.handles.take::<Channel>(0) else {
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
        let index = self.records.insert(label, process, parent, credentials);
        let session = sys::handle_label(
            &self.channel,
            Rights::SEND | Rights::TRANSFER,
            label.raw(),
            self.level,
        );
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

    /// Loaded (label 0) of the LOADING record the body names: it is ALIVE,
    /// and the Spawn that asked for it gets its PID. UNREGISTERED for a
    /// label of no such record. A child that ended between thread_start
    /// and Loaded would leave its parent's Spawn waiting; it does not come
    /// to pass on one processor, where the spawning thread runs at the
    /// loop's level, above the child's ceiling, from its start to Loaded.
    fn loaded(&mut self, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(label), true) = (body.u64(), r.handles.is_empty()) else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let Some(record) = self
            .records
            .find(label)
            .and_then(|i| self.records.get_mut(i))
            .filter(|r| r.state == State::Loading)
        else {
            return refuse(proto_process::UNREGISTERED);
        };
        record.state = State::Alive;
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
impl Service<0> for Processes {
    const VERSION: u16 = proto_process::VERSION;
    const METHODS: &'static [u16] = proto_process::METHODS;
    const PLACED: usize = RECORDS + 1;
    type Data = ();
    fn place(&self, label: u64) -> Option<usize> {
        if label == 0 {
            return Some(0);
        }
        self.records.find(label).map(|i| i + 1)
    }
    fn request(&mut self, _: &mut Session<(), 0>, r: &mut Request<'_>) -> Answer {
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
            _ => Answer::Status(Status::UnknownMethod),
        }
    }
    /// The end of a process, through its record's exit place: the record
    /// goes with the Spawn it waits for, its children get PID 1, its index
    /// waits on top of the free ones, its next PID one generation on. An
    /// end of an older generation takes nothing.
    fn notification(&mut self, n: Notice) {
        if n.source != Source::Exit {
            return;
        }
        if let Some(record) = self.records.ended(n.label) {
            let index = usize::from(record.label.index);
            self.queue.remove(index);
            self.spawns[index] = None;
        }
    }
}
