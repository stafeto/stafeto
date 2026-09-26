// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Init's main thread (spec 13.4): the loop of rt::service on init's
//! channel at 63, with `Init` as its service. The label of a request names
//! the instance of a record that sent it, the label of the instance's start
//! channel (rt::loader::spawn); any other label gets ACCESS_DENIED. START
//! gives an instance its start data (rt::startup::Giver); REGISTER takes
//! the channel of a service and gives it its windows and bindings; CONNECT
//! gives a copy of a registered channel with SEND, TRANSFER and a label of
//! its own, or holds the request until the service registers; HEARTBEAT
//! answers a registered service; LIST gives a page of the records, init
//! first; STATS what the kernel, the worker and init's quota show; PING
//! anyone. The notification of the worker thread brings the outcome of
//! its job: the main thread starts the thread of the instance it loaded,
//! and gives the worker the next job of the queue at the level
//! init::work::worker_level sets. Each handler is bounded by the records
//! of the table; the main thread loads, maps and kills nothing itself
//! (worker.rs).

use crate::worker::{Order, Outcome, Worker};
use abi::{Error, ObjectKind, Rights, Source};
use bootimg::Program;
use init::PAGE;
use init::labels::Labels;
use init::table::{self, MAX_RECORDS, Record, TABLE};
use init::work::{Job, Queue, WORKER_IDLE, worker_level};
use proto_init::{
    Connect, LIST_PAGE, ListReply, ListRequest, Method, Record as Listed, RegisterReply,
    START_NAMES, State, Stats, VERSION, Work,
};
use proto_wire::{Name, Status};
use rt::handle::{Channel, Outgoing, Process, Resource};
use rt::loader::Spawned;
use rt::service::{Answer, Notice, Pending, Request, Service, Session};
use rt::{Handle, println, sys};

/// The CONNECT requests that wait for one service at most.
pub const WAITING_MAX: usize = 4;
/// The line init prints once the first start of each record is done.
const STARTED: &str = "init: services started";
/// The priority and the ceiling of init's main thread (spec 8, 13.3).
const MAIN: u8 = 63;

/// An instance of a record: what the worker loaded (its process and first
/// thread, the label of its start channel, what is left of its start
/// data), and the channel a service registered.
struct Instance {
    spawned: Spawned,
    channel: Option<Handle<Channel>>,
}

/// What the main thread keeps for a record of the table: its state, its
/// instance, and the CONNECT requests that wait for it to register, each
/// with the base priority of its client.
struct Entry {
    state: State,
    instance: Option<Instance>,
    waiting: [Option<(Pending, u8)>; WAITING_MAX],
}

impl Entry {
    const NEW: Entry = Entry {
        state: State::Loading,
        instance: None,
        waiting: [const { None }; WAITING_MAX],
    };
}

/// Init as the service of its channel.
pub struct Init {
    own: Handle<Process>,
    resource: Handle<Resource>,
    worker: Worker,
    labels: Labels,
    programs: [Option<Program<'static>>; MAX_RECORDS],
    entries: [Entry; MAX_RECORDS],
    queue: Queue,
    /// The job the worker does.
    current: Option<Job>,
    /// The records whose first instance started.
    started: usize,
}

impl Init {
    /// Init with its own process, the system resource, its worker, the
    /// count of labels the worker's own came from, and the program of each
    /// record of the table.
    pub fn new(
        own: Handle<Process>,
        resource: Handle<Resource>,
        worker: Worker,
        labels: Labels,
        programs: [Option<Program<'static>>; MAX_RECORDS],
    ) -> Init {
        Init {
            own,
            resource,
            worker,
            labels,
            programs,
            entries: [Entry::NEW; MAX_RECORDS],
            queue: Queue::new(),
            current: None,
            started: 0,
        }
    }

    /// Starts the records of the table in `order` (table::check): a job to
    /// load each, which the queue gives the worker by the ceiling of its
    /// record, and in the order of the table within a level. With an empty
    /// table the services started at once.
    pub fn start(&mut self, order: &table::Order) {
        for &place in order.as_slice() {
            // The queue has a place for each record of a checked table.
            let _ = self.queue.push(Job::new(Work::Load, place, &TABLE[place]));
        }
        if TABLE.is_empty() {
            println!("{STARTED}");
        }
        self.next();
    }

    /// Gives the worker the next job of the queue, when it has none, at
    /// the level of that job and of those that wait; with no job left the
    /// worker waits at WORKER_IDLE.
    fn next(&mut self) {
        if self.current.is_some() {
            return;
        }
        let Some(job) = self.queue.pop() else {
            let _ = self.worker.set_level(WORKER_IDLE);
            return;
        };
        self.current = Some(job);
        let _ = self
            .worker
            .set_level(worker_level(self.current, &self.queue));
        let order = Order::Load {
            place: job.record,
            label: self.labels.next().expect("init gave every label"),
            program: self.programs[job.record].expect("init found each program at its start"),
        };
        // The worker's channel lives as long as init.
        let _ = self.worker.give(order);
    }

    /// The outcome of the worker's job: an instance it loaded starts, and
    /// the worker gets the next job.
    fn accept(&mut self) {
        let Some(outcome) = self.worker.take() else {
            return;
        };
        let Some(job) = self.current.take() else {
            return;
        };
        match outcome {
            Outcome::Loaded(result) => self.loaded(job.record, result),
        }
        self.next();
    }

    /// The first instance of the record at `place` loaded, or why not: its
    /// thread starts here, once its start data wait in the entry. A client
    /// runs from its start, a service is STARTING until it registers.
    fn loaded(&mut self, place: usize, result: Result<Spawned, Error>) {
        let record = &TABLE[place];
        let entry = &mut self.entries[place];
        match result {
            Ok(spawned) => {
                if let Err(e) = spawned.start() {
                    println!("init: {} did not start: {e:?}", record.name);
                }
                entry.instance = Some(Instance {
                    spawned,
                    channel: None,
                });
                entry.state = if record.is_client() {
                    State::Running
                } else {
                    State::Starting
                };
            }
            Err(e) => {
                println!("init: {} did not load: {e:?}", record.name);
                entry.state = State::Ended;
                // The requests that wait for it get PEER_CLOSED.
                entry.waiting = [const { None }; WAITING_MAX];
            }
        }
        self.started += 1;
        if self.started == TABLE.len() {
            println!("{STARTED}");
        }
    }

    /// The place of the record whose instance has `label`.
    fn caller(&self, label: u64) -> Option<usize> {
        let named = |e: &Entry| {
            e.instance
                .as_ref()
                .is_some_and(|i| i.spawned.label == label)
        };
        self.entries[..TABLE.len()].iter().position(named)
    }

    /// START: the next piece of the start data of the instance at `place`.
    /// A reply that failed changes nothing here: the end of the instance
    /// comes as its exit notification.
    fn start_data(&mut self, place: usize, r: &mut Request<'_>) -> Answer {
        let instance = self.entries[place].instance.as_mut();
        if let (Some(instance), Some(token)) = (instance, r.token()) {
            // A request of this method: Giver never gives it back.
            let _ = instance.spawned.giver.answer(r.bytes(), token);
        }
        Answer::Deferred
    }

    /// REGISTER from the instance at `place`: BAD_STATE unless it is a
    /// service that has not registered; BAD_SIZE for bytes after the
    /// header; ACCESS_DENIED unless it brought one handle, a channel with
    /// SEND, NOTIFY, DUPLICATE and TRANSFER and without RECEIVE, whose copy
    /// would keep the service's channel open after it ended (spec 13.4).
    /// The reply names the windows and bindings of the record (`objects`);
    /// the service runs from then on, and the CONNECT requests that wait
    /// for it get their sessions.
    fn register(&mut self, place: usize, r: &mut Request<'_>) -> Answer {
        let record = &TABLE[place];
        if record.is_client() || self.entries[place].state != State::Starting {
            return refuse(Error::BadState);
        }
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let rights = Rights::SEND | Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER;
        let fits = r.handles.len() == 1
            && matches!(r.handles.info(0), Some((ObjectKind::Channel, got))
                if got.contains(rights) && !got.contains(Rights::RECEIVE));
        let Some(channel) = fits.then(|| r.handles.take::<Channel>(0).ok()).flatten() else {
            return refuse(Error::AccessDenied);
        };
        let mut reply = RegisterReply {
            names: [None; START_NAMES],
        };
        let mut handles = Outgoing::new();
        if let Err(e) = self.objects(record, &channel, &mut reply, &mut handles) {
            return refuse(e);
        }
        if let Err(status) = reply.write(r.reply()) {
            return Answer::Status(status);
        }
        let Init {
            entries, labels, ..
        } = self;
        let entry = &mut entries[place];
        for (p, priority) in entry.waiting.iter_mut().filter_map(Option::take) {
            let _ = match session(labels, &channel, priority) {
                Ok(copy) => p.answer(&proto_wire::reply(Status::Ok), [copy.erase()]),
                Err(e) => p.answer(&proto_wire::reply(Status::Kernel(e)), Outgoing::new()),
            };
        }
        if let Some(instance) = entry.instance.as_mut() {
            instance.channel = Some(channel);
        }
        entry.state = State::Running;
        Answer::Reply(handles)
    }

    /// The windows and the bindings of `record`, the windows first, for the
    /// service whose registered channel is `channel`: their names in
    /// `reply` and their handles in `handles`, in one order (spec 13.4). A
    /// binding goes through `channel` with a slot at the service's base
    /// priority. A window carries MAP_READ, MAP_WRITE and TRANSFER, a
    /// binding MANAGE and TRANSFER: init keeps no copy, and each lives as
    /// long as its one handle. The errors are those of the calls.
    fn objects(
        &self,
        record: &Record,
        channel: &Handle<Channel>,
        reply: &mut RegisterReply,
        handles: &mut Outgoing,
    ) -> Result<(), Error> {
        let windows = record.windows.iter().map(|w| w.name);
        let names = windows.chain(record.bindings.iter().map(|b| b.name));
        for (slot, name) in reply.names.iter_mut().zip(names) {
            *slot = Name::new(name.as_bytes()).ok();
        }
        // The checks of the table keep them within one reply.
        for w in record.windows {
            let window = sys::device_window_create(&self.resource, w.base, w.len)?;
            let rights = Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER;
            let only = sys::handle_duplicate(&window, rights)?;
            drop(window);
            let _ = handles.push(only.erase());
        }
        for b in record.bindings {
            let bound = sys::irq_bind(&self.resource, b.line, channel, record.priority, b.edge)?;
            let only = sys::handle_duplicate(&bound, Rights::MANAGE | Rights::TRANSFER)?;
            drop(bound);
            let _ = handles.push(only.erase());
        }
        Ok(())
    }

    /// CONNECT from the instance at `place` (spec 13.4): BAD_SIZE for a
    /// request that is no name; ACCESS_DENIED for a name its record may not
    /// connect to; PEER_CLOSED for a service that ended; a session with the
    /// service when its registered channel is open (`session`); otherwise
    /// the request waits for the service to register, at most WAITING_MAX
    /// for one service, and LIMIT_REACHED past them.
    fn connect(&mut self, place: usize, r: &mut Request<'_>) -> Answer {
        let Ok(Connect { name }) = Connect::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        let client = &TABLE[place];
        let allowed = client
            .connects
            .iter()
            .any(|to| to.as_bytes() == name.as_bytes());
        let Some(to) = allowed
            .then(|| table::find(TABLE, name.as_bytes()))
            .flatten()
        else {
            return refuse(Error::AccessDenied);
        };
        let Init {
            entries, labels, ..
        } = self;
        let service = &mut entries[to];
        if service.state == State::Ended {
            return refuse(Error::PeerClosed);
        }
        if let Some(channel) = open(service) {
            return match session(labels, channel, client.priority) {
                Ok(copy) => {
                    let _ = r.reply().bytes(&proto_wire::reply(Status::Ok));
                    Answer::Reply([copy.erase()].into())
                }
                Err(e) => refuse(e),
            };
        }
        let Some(free) = service.waiting.iter_mut().find(|w| w.is_none()) else {
            return refuse(Error::LimitReached);
        };
        if let Some(pending) = r.defer() {
            *free = Some((pending, client.priority));
        }
        Answer::Deferred
    }

    /// HEARTBEAT from the instance at `place`: 0 for a service that
    /// registered, BAD_STATE for any other (spec 13.4).
    fn heartbeat(&self, place: usize, r: &Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let registered = !TABLE[place].is_client() && self.entries[place].state == State::Running;
        if registered {
            Answer::Status(Status::Ok)
        } else {
            refuse(Error::BadState)
        }
    }

    /// LIST (spec 13.4): BAD_SIZE for a request out of its layout; the
    /// records from `first` on, at most LIST_PAGE, of the records in all:
    /// init itself, then the records of the table in its order. A first
    /// record past them gives an empty page.
    fn list(&self, r: &mut Request<'_>) -> Answer {
        let Ok(ListRequest { first }) = ListRequest::read(r.body()) else {
            return Answer::Status(Status::BadSize);
        };
        let total = TABLE.len() + 1;
        let mut page = ListReply::new(total as u16);
        let first = usize::from(first);
        for n in first..total.min(first.saturating_add(LIST_PAGE)) {
            // The page has room for LIST_PAGE records.
            let _ = page.push(self.listed(n));
        }
        match page.write(r.reply()) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }

    /// Record `n` of LIST: 0 is init, n the record at place n - 1 of the
    /// table. The handles and the memory are those of the process of its
    /// instance, and 0 without one.
    fn listed(&self, n: usize) -> Listed {
        let (name, state, priority, ceiling, client, process) = match n.checked_sub(1) {
            None => ("init", State::Running, MAIN, MAIN, false, Some(&self.own)),
            Some(place) => {
                let (record, entry) = (&TABLE[place], &self.entries[place]);
                let process = entry.instance.as_ref().map(|i| &i.spawned.process);
                let (p, c) = (record.priority, record.ceiling);
                (record.name, entry.state, p, c, record.is_client(), process)
            }
        };
        let handles = process.and_then(|p| sys::process_handles(p).ok());
        let memory = process.and_then(|p| sys::process_memory(p).ok());
        let pages = |bytes: u64| u32::try_from(bytes / PAGE).unwrap_or(u32::MAX);
        let count = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
        Listed {
            name: Name::new(name.as_bytes()).expect("a checked table has names"),
            state,
            priority,
            ceiling,
            client,
            failures: 0,
            restarts: 0,
            live: handles.map_or(0, |h| count(h.live)),
            retired: handles.map_or(0, |h| count(h.retired)),
            limit: handles.map_or(0, |h| count(h.limit)),
            quota_pages: memory.map_or(0, |m| pages(m.quota)),
            used_pages: memory.map_or(0, |m| pages(m.used)),
        }
    }

    /// STATS (spec 13.4): the counts of the kernel (KERNEL_STATS), the job
    /// of the worker with the place of its record, the worker's priorities
    /// and state (THREAD_STATE), the jobs that wait, the free pages of
    /// init's quota and the labels init gave. The errors are those of the
    /// calls.
    fn stats(&self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let facts = sys::kernel_stats(&self.resource).and_then(|kernel| {
            let worker = sys::thread_info(self.worker.thread())?;
            let memory = sys::process_memory(&self.own)?;
            Ok(Stats {
                kernel,
                job: self.current.map(|j| (j.work, j.record as u8)),
                worker_priority: worker.base,
                worker_effective: worker.priority,
                worker_state: worker.state.code() as u8,
                pending: self.queue.len() as u8,
                free_pages: memory.quota.saturating_sub(memory.used) / PAGE,
                labels: self.labels.given(),
            })
        });
        match facts.map(|stats| stats.write(r.reply())) {
            Ok(Ok(())) => Answer::Reply(Outgoing::new()),
            Ok(Err(status)) => Answer::Status(status),
            Err(e) => refuse(e),
        }
    }
}

/// The registered channel of the service of `entry`, when it is open:
/// a CONNECT gets a session with it at once. A channel that closed before
/// init heard of the end of its service counts as none, and the request
/// waits for the next instance.
fn open(entry: &Entry) -> Option<&Handle<Channel>> {
    let channel = entry.instance.as_ref()?.channel.as_ref()?;
    matches!(sys::channel_info(channel), Ok(info) if !info.closed).then_some(channel)
}

/// A session of a client with a service (spec 13.4): a copy of the
/// service's registered `channel` with SEND and TRANSFER and no DUPLICATE,
/// the next of `labels`, and a slot at `priority`, the client's base
/// priority. The errors are those of handle_label.
fn session(
    labels: &mut Labels,
    channel: &Handle<Channel>,
    priority: u8,
) -> Result<Handle<Channel>, Error> {
    let label = labels.next().expect("init gave every label");
    sys::handle_label(channel, Rights::SEND | Rights::TRANSFER, label, priority)
}

/// A refusal with the error `e` as its status.
fn refuse(e: Error) -> Answer {
    Answer::Status(Status::Kernel(e))
}

impl Service<1> for Init {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = &[
        Method::Start.number(),
        Method::Register.number(),
        Method::Connect.number(),
        Method::Heartbeat.number(),
        Method::List.number(),
        Method::Stats.number(),
        Method::Ping.number(),
    ];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, r: &mut Request<'_>) -> Answer {
        let Some(place) = self.caller(r.label()) else {
            return refuse(Error::AccessDenied);
        };
        match Method::from_number(r.method()) {
            Some(Method::Start) => self.start_data(place, r),
            Some(Method::Register) => self.register(place, r),
            Some(Method::Connect) => self.connect(place, r),
            Some(Method::Heartbeat) => self.heartbeat(place, r),
            Some(Method::List) => self.list(r),
            Some(Method::Stats) => self.stats(r),
            Some(Method::Ping) if r.body().finish().is_ok() => Answer::Status(Status::Ok),
            Some(Method::Ping) => Answer::Status(Status::BadSize),
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    /// The worker's notification: the outcome of its job.
    fn notification(&mut self, n: Notice) {
        if n.source == Source::Session && n.label == self.worker.label {
            self.accept();
        }
    }
}
