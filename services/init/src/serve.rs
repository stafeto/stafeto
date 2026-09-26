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
//! init::work::worker_level sets. The notification of the end of an
//! instance is a failure of its record: init prints its reason and what it
//! decided (init::restart), the worker tears the instance down, and the
//! record's timer, whose slot is at the record's ceiling, ends the pause
//! before its restart; each start waits while init's quota falls short of
//! what the instance needs (init::quota). Each handler is bounded by the
//! records of the table; the main thread loads, maps and kills nothing
//! itself, and lets go of no last handle of an instance (worker.rs).

use crate::worker::{Gone, Loaded, Worker};
use abi::{Error, ObjectKind, ProcessState, Rights, Source};
use bootimg::Program;
use core::fmt;
use init::PAGE;
use init::labels::Labels;
use init::quota::{self, Start};
use init::restart::{BREAK_AFTER, Failures, Verdict, WINDOW_NS};
use init::table::{self, MAX_RECORDS, Record, Restart, TABLE};
use init::work::{Job, Queue, WORKER_IDLE, worker_level};
use proto_init::{
    Connect, LIST_PAGE, ListReply, ListRequest, Method, Record as Listed, RegisterReply,
    START_NAMES, State, Stats, VERSION, Work,
};
use proto_wire::{Name, Status};
use rt::handle::{Channel, Outgoing, Process, Resource, Timer};
use rt::loader::Spawned;
use rt::service::{Answer, Notice, Pending, Request, Service, Session};
use rt::{Handle, println, sys, time};

/// The CONNECT requests that wait for one service at most.
pub const WAITING_MAX: usize = 4;
/// The line init prints once the first start of each record is done.
const STARTED: &str = "init: services started";
/// The priority and the ceiling of init's main thread (spec 8, 13.3).
const MAIN: u8 = 63;
const MS: u64 = 1_000_000;
const S: u64 = 1_000 * MS;

/// An instance of a record: what the worker loaded (its process and first
/// thread, the label of its start channel, what is left of its start
/// data), the channel a service registered, and when its thread started,
/// in nanoseconds on the one scale of the system.
struct Instance {
    spawned: Spawned,
    channel: Option<Handle<Channel>>,
    started: u64,
}

impl Instance {
    /// What the worker tears down of the instance once it ended: what is
    /// left of its start data closes here, copies of objects whose own
    /// handles go to the worker.
    fn gone(self) -> Gone {
        Gone {
            process: self.spawned.process,
            thread: self.spawned.thread,
            channel: self.channel,
        }
    }
}

/// What the main thread keeps for a record of the table: its state, its
/// instance, what is left of the instance that ended until the worker
/// takes it for its teardown, the CONNECT requests that wait for it to
/// register, each with the base priority of its client, and its restarts
/// (init::restart).
struct Entry {
    state: State,
    instance: Option<Instance>,
    gone: Option<Gone>,
    waiting: [Option<(Pending, u8)>; WAITING_MAX],
    /// The record's timer on init's channel, its slot at the record's
    /// ceiling, and its deadline: the end of the pause before a restart
    /// (STOPPING, PAUSED) or of a wait for quota (QUOTA).
    timer: Option<Handle<Timer>>,
    deadline: Option<u64>,
    failures: Failures,
    restarts: u32,
    /// The pause the record waited last, before a restart or for quota
    /// (quota::start); 0 before its first start.
    waited: u64,
    /// Its start waits for quota since its last start: the line of the
    /// wait comes once.
    short: bool,
    /// Its first start is done, or waits for quota.
    begun: bool,
}

impl Entry {
    const NEW: Entry = Entry {
        state: State::Loading,
        instance: None,
        gone: None,
        waiting: [const { None }; WAITING_MAX],
        timer: None,
        deadline: None,
        failures: Failures::new(),
        restarts: 0,
        waited: 0,
        short: false,
        begun: false,
    };
}

/// How an instance ended (PROCESS_STATE), as the line of its failure says
/// it (spec 16.2).
struct End(Result<ProcessState, Error>);

impl fmt::Display for End {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Ok(ProcessState::Exited { code }) => write!(f, "exit code {code}"),
            Ok(ProcessState::Killed) => write!(f, "killed"),
            Ok(ProcessState::Fault { esr, far, elr }) => {
                write!(f, "fault ESR={esr:#x} FAR={far:#x} ELR={elr:#x}")
            }
            Ok(other) => write!(f, "{other:?}"),
            Err(e) => write!(f, "no state ({e:?})"),
        }
    }
}

/// Now, in nanoseconds on the one scale of the system (spec 10).
fn now() -> u64 {
    time::ticks_to_ns(time::now())
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
    /// The records whose first start is done or waits for quota.
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

    /// Starts the records of the table in `order` (table::check): the
    /// timer of each on `channel`, init's channel, through its handle
    /// without a label, with its slot at the record's ceiling; a job to
    /// load each, which the queue gives the worker by the ceiling of its
    /// record, and in the order of the table within a level. With an empty
    /// table the services started at once.
    pub fn start(&mut self, channel: &Handle<Channel>, order: &table::Order) {
        for (entry, record) in self.entries.iter_mut().zip(TABLE) {
            let timer = sys::timer_create(channel, record.ceiling);
            entry.timer = Some(timer.expect("init makes the timer of each record"));
        }
        for &place in order.as_slice() {
            self.launch(place);
        }
        if TABLE.is_empty() {
            println!("{STARTED}");
        }
    }

    /// Puts the load of the record at `place` in the queue: LOADING.
    fn launch(&mut self, place: usize) {
        self.entries[place].state = State::Loading;
        self.push(Job::new(Work::Load, place, &TABLE[place]));
    }

    /// Puts `job` in the queue. With the worker at a job, its level goes
    /// up to that of the jobs that wait at once (init::work::worker_level);
    /// an idle worker gets the next job.
    fn push(&mut self, job: Job) {
        // The queue has a place for each record, and a record has one job
        // at a time: its load comes after the teardown of its instance.
        let _ = self.queue.push(job);
        if self.current.is_some() {
            let _ = self
                .worker
                .set_level(worker_level(self.current, &self.queue));
        } else {
            self.next();
        }
    }

    /// Gives the worker the next job of the queue, when it has none, at
    /// the level of that job and of those that wait; with no job left the
    /// worker waits at WORKER_IDLE. A load for which init's quota falls
    /// short waits (`quota_fits`), and the next job goes.
    fn next(&mut self) {
        if self.current.is_some() {
            return;
        }
        while let Some(job) = self.queue.pop() {
            let place = job.record;
            let gone = match job.work {
                Work::Load if !self.quota_fits(place) => continue,
                Work::Load => None,
                _ => match self.entries[place].gone.take() {
                    Some(gone) => Some(gone),
                    None => continue,
                },
            };
            self.current = Some(job);
            let _ = self
                .worker
                .set_level(worker_level(self.current, &self.queue));
            // The worker's channel lives as long as init.
            let _ = match gone {
                Some(gone) => self.worker.teardown(gone),
                None => {
                    let label = self.labels.next().expect("init gave every label");
                    let program =
                        self.programs[place].expect("init found each program at its start");
                    self.worker.load(place, label, program)
                }
            };
            return;
        }
        let _ = self.worker.set_level(WORKER_IDLE);
    }

    /// Whether init's quota covers an instance of the record at `place`
    /// (init::quota), which it then loads. Otherwise the start waits:
    /// QUOTA, the record's timer at twice the pause it waited last, from
    /// 100 ms up to 5 s, no failure; the first wait in a row prints a line.
    fn quota_fits(&mut self, place: usize) -> bool {
        let record = &TABLE[place];
        let need = self.programs[place].map_or(u64::MAX, |p| quota::need_pages(record.quota, &p));
        let memory = sys::process_memory(&self.own);
        let free = memory.map_or(0, |m| m.quota.saturating_sub(m.used) / PAGE);
        let entry = &mut self.entries[place];
        match quota::start(free, need, entry.waited) {
            Start::Now => {
                entry.short = false;
                true
            }
            Start::Wait { pause_ns } => {
                if !entry.short {
                    println!(
                        "init: {} waits for quota: needs {need} pages, {free} free",
                        record.name
                    );
                }
                entry.short = true;
                entry.waited = pause_ns;
                entry.state = State::Quota;
                self.set_deadline(place, now().saturating_add(pause_ns));
                self.begin(place);
                false
            }
        }
    }

    /// Arms the timer of the record at `place` for `at`.
    fn set_deadline(&mut self, place: usize, at: u64) {
        let entry = &mut self.entries[place];
        entry.deadline = Some(at);
        if let Some(timer) = entry.timer.as_ref() {
            // Init's own timer: timer_set has no error to give.
            let _ = sys::timer_set(timer, at);
        }
    }

    /// The first start of the record at `place` is done or waits for
    /// quota; once that holds for each record, init says the services
    /// started.
    fn begin(&mut self, place: usize) {
        let entry = &mut self.entries[place];
        if entry.begun {
            return;
        }
        entry.begun = true;
        self.started += 1;
        if self.started == TABLE.len() {
            println!("{STARTED}");
        }
    }

    /// The outcome of the worker's job: an instance it loaded starts, one
    /// it tore down may start again, and the worker gets the next job.
    fn accept(&mut self) {
        let Some(loaded) = self.worker.take() else {
            return;
        };
        let Some(job) = self.current.take() else {
            return;
        };
        match loaded {
            Some(result) => self.loaded(job.record, result),
            None => self.torn_down(job.record),
        }
        self.next();
    }

    /// An instance of the record at `place` loaded, or why not, which is a
    /// failure: its thread starts here, once its start data wait in the
    /// entry. A client runs from its start, a service is STARTING until it
    /// registers.
    fn loaded(&mut self, place: usize, result: Loaded) {
        let record = &TABLE[place];
        match result {
            Ok(spawned) => {
                if let Err(e) = spawned.start() {
                    println!("init: {} did not start: {e:?}", record.name);
                }
                let entry = &mut self.entries[place];
                entry.instance = Some(Instance {
                    spawned,
                    channel: None,
                    started: now(),
                });
                entry.state = if record.is_client() {
                    State::Running
                } else {
                    State::Starting
                };
            }
            Err(e) => self.failed(place, None, 0, format_args!("did not load: {e:?}")),
        }
        self.begin(place);
    }

    /// The end of the instance whose label is `label` (its exit
    /// notification): a failure of its record, with the reason of
    /// PROCESS_STATE.
    fn ended(&mut self, label: u64) {
        let Some(place) = self.caller(label) else {
            return;
        };
        let Some(instance) = self.entries[place].instance.take() else {
            return;
        };
        let lived = now().saturating_sub(instance.started);
        let end = End(sys::process_state(&instance.spawned.process));
        self.failed(
            place,
            Some(instance.gone()),
            lived,
            format_args!("ended: {end}"),
        );
    }

    /// A failure of the record at `place` (spec 13.4, 16.2): `gone`, what
    /// is left of its instance that lived `lived` ns, if any, goes to the
    /// worker for its teardown; `what` says what happened. Init prints one
    /// line with it and its decision: a record whose policy is never ends,
    /// one that failed BREAK_AFTER times within WINDOW_NS is broken, and
    /// the CONNECT requests that wait for either get PEER_CLOSED; any other
    /// starts again after the pause of init::restart, on its timer, and
    /// once its teardown is done.
    fn failed(&mut self, place: usize, gone: Option<Gone>, lived: u64, what: fmt::Arguments) {
        let record = &TABLE[place];
        let now = now();
        let entry = &mut self.entries[place];
        let teardown = gone.is_some();
        entry.gone = gone;
        let verdict = match record.restart {
            Restart::Always => Some(entry.failures.failed(now, lived)),
            Restart::Never => None,
        };
        match verdict {
            None => {
                println!("init: {} {what}, not restarted", record.name);
                entry.state = State::Ended;
                entry.waiting = [const { None }; WAITING_MAX];
            }
            Some(Verdict::Broken) => {
                println!(
                    "init: {} {what}; broken: {BREAK_AFTER} failures in {} s",
                    record.name,
                    WINDOW_NS / S
                );
                entry.state = State::Broken;
                entry.waiting = [const { None }; WAITING_MAX];
            }
            Some(Verdict::Restart { pause_ns }) => {
                println!(
                    "init: {} {what}; restarts in {} ms",
                    record.name,
                    pause_ns / MS
                );
                entry.restarts = entry.restarts.saturating_add(1);
                entry.waited = pause_ns;
                entry.state = if teardown {
                    State::Stopping
                } else {
                    State::Paused
                };
                self.set_deadline(place, now.saturating_add(pause_ns));
            }
        }
        if teardown {
            self.push(Job::new(Work::Teardown, place, record));
        }
    }

    /// The teardown of the instance of the record at `place` is done: a
    /// record that restarts loads once its pause is over, and waits for it
    /// otherwise.
    fn torn_down(&mut self, place: usize) {
        let entry = &mut self.entries[place];
        if entry.state != State::Stopping {
            return;
        }
        if entry.deadline.is_some_and(|at| !time::reached(at)) {
            entry.state = State::Paused;
        } else {
            entry.deadline = None;
            self.launch(place);
        }
    }

    /// An expiry of a timer of the records: each record whose deadline the
    /// counter reached (rt::time::reached) and which waits for its pause or
    /// for quota starts; the other expiries are stale (spec 10).
    fn expired(&mut self) {
        for place in 0..TABLE.len() {
            let entry = &mut self.entries[place];
            let due = entry.deadline.is_some_and(time::reached);
            if due && matches!(entry.state, State::Paused | State::Quota) {
                entry.deadline = None;
                self.launch(place);
            }
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
    /// connect to; PEER_CLOSED for a service that is broken or ended; a
    /// session with the service when its registered channel is open
    /// (`session`); otherwise the request waits for the service to
    /// register, at most WAITING_MAX for one service, and LIMIT_REACHED
    /// past them.
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
        if matches!(service.state, State::Broken | State::Ended) {
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
    /// table, with its failures within WINDOW_NS and its restarts. The
    /// handles and the memory are those of the process of its instance, and
    /// 0 without one.
    fn listed(&self, n: usize) -> Listed {
        let (mut failures, mut restarts) = (0, 0);
        let (name, state, priority, ceiling, client, process) = match n.checked_sub(1) {
            None => ("init", State::Running, MAIN, MAIN, false, Some(&self.own)),
            Some(place) => {
                let (record, entry) = (&TABLE[place], &self.entries[place]);
                (failures, restarts) = (entry.failures.recent(now()), entry.restarts);
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
            failures,
            restarts,
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

    /// The worker's notification: the outcome of its job; the end of an
    /// instance (`ended`); an expiry of a timer of the records (`expired`).
    fn notification(&mut self, n: Notice) {
        match n.source {
            Source::Session if n.label == self.worker.label => self.accept(),
            Source::Exit => self.ended(n.label),
            Source::Timer if n.label == 0 => self.expired(),
            _ => {}
        }
    }
}
