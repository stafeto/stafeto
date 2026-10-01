// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Init's main thread (spec 13.4): the loop of rt::service on init's
//! channel at 63, with `Init` as its service. The label of a request names
//! the instance of a record that sent it, the label of the instance's start
//! channel (rt::loader::spawn); any other label gets ACCESS_DENIED. START
//! gives an instance its start data (rt::startup::Giver); REGISTER takes
//! the channel of a service and gives it its windows and bindings; CONNECT
//! gives a copy of a registered channel with SEND, TRANSFER and a label of
//! its own, or holds the request until the service registers, but for the
//! process service (table::PROCESS_SERVICE); ADOPT from the process service
//! takes the next POSIX process init loaded, whose thread waits until
//! ADOPTED brings the session of its record (spec 2, section 3.1): init
//! holds the request and never sends one to a service (spec 6.7); HEARTBEAT
//! answers a registered service and moves its watchdog deadline; LIST gives
//! a page of the records, init first; STATS what the kernel, the worker and
//! init's quota show; PING anyone. The notification of the worker thread
//! brings the outcome of its job: the main thread starts the thread of the
//! instance it loaded, and gives the worker the next job of the queue at
//! the level init::work::Jobs sets. The notification of the end of
//! an instance is a failure of its record: init prints its reason and what
//! it decided (init::restart), the worker tears the instance down, and the
//! record's timer, whose slot is at the record's ceiling and whose expiries
//! carry a label of its own, ends the pause before its restart; a service
//! whose watchdog finds it silent twice in a row is killed by the worker
//! from above its ceiling, which is a failure too (init::watch); each start
//! waits while init's quota falls short of what the instance needs
//! (init::quota). Each handler is bounded by the records of the table; the
//! main thread loads, maps and kills nothing itself, and lets go of no last
//! handle of an instance (worker.rs).

use crate::worker::{Kept, Loaded, Worker};
use abi::{Error, ObjectKind, ProcessState, Rights, Source};
use bootimg::Program;
use core::fmt;
use core::mem;
use init::PAGE;
use init::labels::Labels;
use init::quota::{self, Start};
use init::restart::{BREAK_AFTER, Failures, Verdict, WINDOW_NS};
use init::table::{self, MAX_RECORDS, Record, Restart, TABLE};
use init::watch::{Action, Watched};
use init::work::{Job, Jobs, WORKER_IDLE, worker_level};
use proto_init::{
    Connect, LIST_PAGE, ListReply, ListRequest, Method, Record as Listed, RegisterReply,
    START_NAMES, State, Stats, VERSION, Work,
};
use proto_wire::{Name, Status};
#[cfg(feature = "dma-watch")]
use rt::handle::Memory;
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
/// in nanoseconds on the one scale of the system. Its handles close in the
/// worker thread: the main thread lets go of no Instance (spec 7.7).
pub struct Instance {
    spawned: Spawned,
    /// Init's own handles to its DMA objects, which go with it, after its
    /// device stopped (worker.rs).
    dma: Kept,
    channel: Option<Handle<Channel>>,
    started: u64,
    /// Set by the worker right before it lets go of the instance (`release`).
    released: bool,
}

impl Instance {
    /// Lets go of the instance: its handles close. Only init's worker
    /// thread calls it (worker.rs).
    pub fn release(mut self) {
        self.released = true;
    }

    /// The instance's process, which the worker kills before it tears the
    /// instance down (worker.rs).
    pub fn process(&self) -> &Handle<Process> {
        &self.spawned.process
    }

    /// Init's handle to the instance's first DMA object, if any, which
    /// the probe of a stop reads (feature `dma-watch`).
    #[cfg(feature = "dma-watch")]
    pub fn dma(&self) -> Option<&Handle<Memory>> {
        self.dma.first().and_then(Option::as_ref)
    }

    /// Init keeps the instance's DMA objects for good: their handles are
    /// forgotten, so their frames never go back while a device that did
    /// not stop may write them (worker.rs).
    pub fn keep_dma(&mut self) {
        for d in &mut self.dma {
            if let Some(handle) = d.take() {
                core::mem::forget(handle);
            }
        }
    }
}

/// The strict build (debug assertions) panics when an instance goes
/// another way than `release`, such as a drop on the main thread.
impl Drop for Instance {
    fn drop(&mut self) {
        if cfg!(debug_assertions) && !self.released {
            panic!("an instance dropped outside init's worker");
        }
    }
}

/// What a record holds: no instance, the one that runs, or the one that
/// ended and waits for the worker to take it for its teardown or kill.
/// Only one instance's storage, never two at once (the load of a record
/// comes after the teardown of its instance).
enum Held {
    Empty,
    Running(Instance),
    Gone(Instance),
}

impl Held {
    /// The instance that runs, if any.
    fn running(&self) -> Option<&Instance> {
        match self {
            Held::Running(instance) => Some(instance),
            _ => None,
        }
    }

    fn running_mut(&mut self) -> Option<&mut Instance> {
        match self {
            Held::Running(instance) => Some(instance),
            _ => None,
        }
    }

    /// Takes the instance that runs out, leaving the record with none.
    fn take_running(&mut self) -> Option<Instance> {
        match mem::replace(self, Held::Empty) {
            Held::Running(instance) => Some(instance),
            other => {
                *self = other;
                None
            }
        }
    }

    /// Takes the instance that waits for its teardown or kill out.
    fn take_gone(&mut self) -> Option<Instance> {
        match mem::replace(self, Held::Empty) {
            Held::Gone(instance) => Some(instance),
            other => {
                *self = other;
                None
            }
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
    held: Held,
    /// The watchdog of the current instance of a service: its deadline and
    /// its mark of suspicion (init::watch). None for a client, and between
    /// instances.
    watch: Option<Watched>,
    waiting: [Option<(Pending, u8)>; WAITING_MAX],
    /// The record's timer on init's channel, its slot at the record's
    /// ceiling, and its deadline: the watchdog deadline (STARTING,
    /// RUNNING), the end of the pause before a restart (STOPPING, PAUSED)
    /// or the end of a wait for quota (QUOTA). The timer is made through
    /// `timer_view`, a copy of init's channel with RECEIVE and
    /// `timer_label`, a label of init's count, which its expiries carry.
    timer: Option<Handle<Timer>>,
    timer_view: Option<Handle<Channel>>,
    timer_label: u64,
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
    /// A POSIX process loaded whose thread waits for the session of its
    /// record (ADOPTED); `offered` once ADOPT took it.
    adopting: bool,
    offered: bool,
}

impl Entry {
    const NEW: Entry = Entry {
        state: State::Loading,
        held: Held::Empty,
        watch: None,
        waiting: [const { None }; WAITING_MAX],
        timer: None,
        timer_view: None,
        timer_label: 0,
        deadline: None,
        failures: Failures::new(),
        restarts: 0,
        waited: 0,
        short: false,
        begun: false,
        adopting: false,
        offered: false,
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
    /// The job the worker does and those that wait.
    jobs: Jobs,
    /// The process service's ADOPT that waits for a POSIX process.
    adoption: Option<Pending>,
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
            jobs: Jobs::new(),
            adoption: None,
            started: 0,
        }
    }

    /// Starts the records of the table in `order` (table::check): the
    /// timer of each on `channel`, init's channel, through a copy of it
    /// with a label of its own, with its slot at the record's ceiling; a
    /// job to load each, which the queue gives the worker by the ceiling of
    /// its record, and in the order of the table within a level. With an
    /// empty table the services started at once.
    pub fn start(&mut self, channel: &Handle<Channel>, order: &table::Order) {
        for (place, entry) in self.entries.iter_mut().enumerate().take(TABLE.len()) {
            let ceiling = TABLE[place].ceiling;
            let label = self.labels.next().expect("init gave every label");
            let view = sys::handle_label(channel, Rights::RECEIVE, label, ceiling)
                .expect("init labels a channel view for each timer");
            let timer =
                sys::timer_create(&view, ceiling).expect("init makes the timer of each record");
            entry.timer = Some(timer);
            entry.timer_view = Some(view);
            entry.timer_label = label;
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
    /// up to that of the jobs that wait at once (init::work::Jobs::push);
    /// an idle worker gets the next job.
    fn push(&mut self, job: Job) {
        // The queue has a place for each record, and a record has one job
        // at a time: its load comes after the teardown of its instance.
        match self.jobs.push(job) {
            Ok(Some(level)) => {
                let _ = self.worker.set_level(level);
            }
            _ => self.next(),
        }
    }

    /// Gives the worker the next job of the queue, when it has none, at
    /// the level of that job and of those that wait; with no job left the
    /// worker waits at WORKER_IDLE. A load for which init's quota falls
    /// short waits (`quota_fits`), and the next job goes.
    fn next(&mut self) {
        if self.jobs.current().is_some() {
            return;
        }
        while let Some(job) = self.jobs.pop() {
            let place = job.record;
            let gone = match job.work {
                Work::Load if !self.quota_fits(place) => continue,
                Work::Load | Work::ShowLog => None,
                _ => match self.entries[place].held.take_gone() {
                    Some(gone) => Some(gone),
                    None => continue,
                },
            };
            let level = self.jobs.start(job);
            let _ = self.worker.set_level(level);
            // The worker's channel lives as long as init.
            let _ = match job.work {
                Work::Load => {
                    let label = self.labels.next().expect("init gave every label");
                    let program =
                        self.programs[place].expect("init found each program at its start");
                    self.worker.load(place, label, program)
                }
                Work::Teardown => self
                    .worker
                    .teardown(place, gone.expect("a teardown carries its instance")),
                Work::Kill => self
                    .worker
                    .kill(place, gone.expect("a kill carries its instance")),
                Work::ShowLog => self.worker.show_log(),
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
        let Some(job) = self.jobs.done() else {
            return;
        };
        match loaded {
            Some(result) => self.loaded(job.record, result),
            // The log it showed is the last job of its record.
            None if job.work == Work::ShowLog => {}
            None => self.torn_down(job.record),
        }
        self.next();
    }

    /// An instance of the record at `place` loaded, or why not, which is a
    /// failure: its thread starts here, once its start data wait in the
    /// entry (`run`); that of a POSIX process once the process service gave
    /// the session of its record (`offer`, `adopted`).
    fn loaded(&mut self, place: usize, result: Loaded) {
        let record = &TABLE[place];
        match result {
            Ok((spawned, dma)) => {
                let entry = &mut self.entries[place];
                entry.held = Held::Running(Instance {
                    spawned,
                    dma,
                    channel: None,
                    started: 0,
                    released: false,
                });
                if record.is_posix() {
                    // Its thread starts once the process service gave the
                    // session of its record (`adopted`).
                    entry.adopting = true;
                    entry.offered = false;
                    self.offer();
                } else {
                    self.run(place);
                }
            }
            Err(e) => {
                let what = format_args!("did not load: {e:?}");
                self.failed(place, None, 0, what, Work::Teardown)
            }
        }
        self.begin(place);
    }

    /// The thread of the instance of the record at `place` starts: a
    /// client runs from then on, a service is STARTING until it registers.
    fn run(&mut self, place: usize) {
        let record = &TABLE[place];
        let Some(instance) = self.entries[place].held.running_mut() else {
            return;
        };
        if let Err(e) = instance.spawned.start() {
            println!("init: {} did not start: {e:?}", record.name);
        }
        let started = now();
        instance.started = started;
        // The watchdog of a service counts from its start until its
        // REGISTER (spec 13.4); a client has none.
        let watch = record.watch().map(|w| w.arm(started));
        let deadline = watch.map(|w| w.deadline());
        let entry = &mut self.entries[place];
        entry.watch = watch;
        entry.state = if record.is_client() {
            State::Running
        } else {
            State::Starting
        };
        if let Some(at) = deadline {
            self.set_deadline(place, at);
        }
    }

    /// Answers the process service's ADOPT, when one waits, with the first
    /// POSIX process that waits for its session and was not offered yet:
    /// its ticket (the label of its instance), root, and a copy of its
    /// process with MANAGE, DUPLICATE and TRANSFER. A copy that cannot be
    /// made fails the load.
    fn offer(&mut self) {
        if self.adoption.is_none() {
            return;
        }
        let waiting = (0..TABLE.len()).find(|&p| {
            let e = &self.entries[p];
            e.adopting && !e.offered && e.held.running().is_some()
        });
        let Some(place) = waiting else {
            return;
        };
        let instance = self.entries[place]
            .held
            .running()
            .expect("an adopted instance");
        let rights = Rights::MANAGE | Rights::DUPLICATE | Rights::TRANSFER;
        let copy = sys::handle_duplicate(instance.process(), rights);
        let ticket = instance.spawned.label;
        let Ok(copy) = copy else {
            self.adoption_failed(place, "no copy of its process");
            return;
        };
        let mut w = proto_wire::Writer::new();
        let written = w
            .bytes(&proto_wire::reply(Status::Ok))
            .and_then(|()| w.u64(ticket))
            .and_then(|()| w.u32(u32::from(TABLE[place].root)));
        let pending = self.adoption.take().expect("a waiting ADOPT");
        if written.is_err() || pending.answer(w.as_bytes(), [copy.erase()]).is_err() {
            // The service went: the next ADOPT offers the process again.
            return;
        }
        self.entries[place].offered = true;
    }

    /// The POSIX process at `place` gets no session of its record: a
    /// failure of its record; its thread never ran.
    fn adoption_failed(&mut self, place: usize, why: &str) {
        let entry = &mut self.entries[place];
        entry.adopting = false;
        entry.offered = false;
        let Some(instance) = entry.held.take_running() else {
            return;
        };
        let what = format_args!("did not load: {why}");
        self.failed(place, Some(instance), 0, what, Work::Kill);
    }

    /// ADOPT from the instance at `place`: only the process service's, at
    /// most one at a time (BAD_STATE for any other caller, LIMIT_REACHED
    /// for a second); BAD_SIZE for bytes after the header. Init holds it
    /// until a POSIX process waits for its session (`offer`).
    fn adopt(&mut self, place: usize, r: &mut Request<'_>) -> Answer {
        if TABLE[place].name != table::PROCESS_SERVICE {
            return refuse(Error::BadState);
        }
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        if self.adoption.is_some() {
            return refuse(Error::LimitReached);
        }
        self.adoption = r.defer();
        self.offer();
        Answer::Deferred
    }

    /// ADOPTED from the process service: the ticket of a process it took
    /// and its status. With status 0 and the session, init gives the
    /// session in the start data under `posix` and starts the thread; any
    /// other status, or no session, fails the load. BAD_STATE for another
    /// caller, BAD_SIZE out of the layout, INVALID_ARGS for
    /// a ticket no waiting process has.
    fn adopted(&mut self, place: usize, r: &mut Request<'_>) -> Answer {
        if TABLE[place].name != table::PROCESS_SERVICE {
            return refuse(Error::BadState);
        }
        let mut body = r.body();
        let (Ok(ticket), Ok(status)) = (body.u64(), body.u32()) else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() || r.handles.len() > 1 {
            return Answer::Status(Status::BadSize);
        }
        let waiting = (0..TABLE.len()).find(|&p| {
            let e = &self.entries[p];
            e.adopting && e.offered && e.held.running().is_some_and(|i| i.spawned.label == ticket)
        });
        let Some(place) = waiting else {
            return refuse(Error::InvalidArgs);
        };
        let session = (status == 0)
            .then(|| r.handles.take::<Channel>(0).ok())
            .flatten();
        let Some(session) = session else {
            println!(
                "init: the process service made no record for {}: status {status}",
                TABLE[place].name
            );
            self.adoption_failed(place, "no record of the process service");
            return Answer::Status(Status::Ok);
        };
        let entry = &mut self.entries[place];
        let instance = entry.held.running_mut().expect("an adopted instance");
        // The checks of the table keep the name apart from the others of
        // the start data.
        let given = instance
            .spawned
            .giver
            .give(table::PROCESS_SERVICE, session.erase());
        entry.adopting = false;
        entry.offered = false;
        if given.is_err() {
            self.adoption_failed(place, "no room for its session");
        } else {
            self.run(place);
        }
        Answer::Status(Status::Ok)
    }

    /// The end of the instance whose label is `label` (its exit
    /// notification): a failure of its record, with the reason of
    /// PROCESS_STATE.
    fn ended(&mut self, label: u64) {
        // An instance the watchdog took to kill is no current one: its later
        // exit notification stops at `caller`.
        let Some(place) = self.caller(label) else {
            return;
        };
        let Some(instance) = self.entries[place].held.take_running() else {
            return;
        };
        let lived = now().saturating_sub(instance.started);
        let end = End(sys::process_state(instance.process()));
        let what = format_args!("ended: {end}");
        self.failed(place, Some(instance), lived, what, Work::Teardown);
    }

    /// The watchdog of the service at `place` found it silent (init::watch):
    /// a failure (`failed`) whose line names the level the worker kills its
    /// instance from, above its ceiling and below its clients (init::work).
    /// Its later exit notification is skipped (`ended`).
    fn silent(&mut self, place: usize) {
        let job = Job::new(Work::Kill, place, &TABLE[place]);
        let level = worker_level(Some(job), self.jobs.queue());
        let Some(instance) = self.entries[place].held.take_running() else {
            return;
        };
        let lived = now().saturating_sub(instance.started);
        let what = format_args!("went silent, killed from level {level}");
        self.failed(place, Some(instance), lived, what, Work::Kill);
    }

    /// A failure of the record at `place` (spec 13.4, 16.2): `gone`, what
    /// is left of its instance that lived `lived` ns, if any, goes to the
    /// worker for `work`, its teardown or kill; `what` says what happened.
    /// Init prints one line with it and its decision: a record whose
    /// policy is never ends, one that failed BREAK_AFTER times within
    /// WINDOW_NS is broken, and the CONNECT requests that wait for either
    /// get PEER_CLOSED; any other starts again after the pause of
    /// init::restart, on its timer, and once its teardown or kill is done.
    fn failed(
        &mut self,
        place: usize,
        gone: Option<Instance>,
        lived: u64,
        what: fmt::Arguments,
        work: Work,
    ) {
        let name = TABLE[place].name;
        let now = now();
        let verdict = self.accrue(place, now, lived);
        match verdict {
            None => println!("init: {name} {what}, not restarted"),
            Some(Verdict::Broken) => println!(
                "init: {name} {what}; broken: {BREAK_AFTER} failures in {} s",
                WINDOW_NS / S
            ),
            Some(Verdict::Restart { pause_ns }) => {
                println!("init: {name} {what}; restarts in {} ms", pause_ns / MS)
            }
        }
        self.settle(place, gone, verdict, work);
    }

    /// Records a failure of the record at `place` at `now`, of an instance
    /// that lived `lived` ns: a verdict for a record that restarts, None
    /// for one whose policy is never (init::restart).
    fn accrue(&mut self, place: usize, now: u64, lived: u64) -> Option<Verdict> {
        match TABLE[place].restart {
            Restart::Always => Some(self.entries[place].failures.failed(now, lived)),
            Restart::Never => None,
        }
    }

    /// Settles a failure of the record at `place`: `gone`, its instance if
    /// any, waits for the worker's `work` (teardown or kill); the record
    /// ends or is marked broken, its waiting CONNECT requests getting
    /// PEER_CLOSED, or it starts again after `verdict`'s pause on its timer,
    /// once the work is done (`torn_down`).
    fn settle(
        &mut self,
        place: usize,
        gone: Option<Instance>,
        verdict: Option<Verdict>,
        work: Work,
    ) {
        let now = now();
        let record = &TABLE[place];
        let entry = &mut self.entries[place];
        let teardown = gone.is_some();
        if let Some(instance) = gone {
            entry.held = Held::Gone(instance);
        }
        entry.watch = None;
        entry.adopting = false;
        entry.offered = false;
        let deadline = match verdict {
            None => {
                entry.state = State::Ended;
                entry.waiting = [const { None }; WAITING_MAX];
                None
            }
            Some(Verdict::Broken) => {
                entry.state = State::Broken;
                entry.waiting = [const { None }; WAITING_MAX];
                None
            }
            Some(Verdict::Restart { pause_ns }) => {
                entry.restarts = entry.restarts.saturating_add(1);
                entry.waited = pause_ns;
                entry.state = if teardown {
                    State::Stopping
                } else {
                    State::Paused
                };
                Some(now.saturating_add(pause_ns))
            }
        };
        if let Some(at) = deadline {
            self.set_deadline(place, at);
        }
        if teardown {
            self.push(Job::new(work, place, record));
        }
        // With the process service ended or broken for good, the POSIX
        // processes that wait for their sessions get none; a service that
        // restarts asks for them again.
        let over = matches!(self.entries[place].state, State::Ended | State::Broken);
        if record.name == table::PROCESS_SERVICE {
            self.adoption = None;
            for p in 0..TABLE.len() {
                if over && self.entries[p].adopting {
                    self.adoption_failed(p, "the process service ended");
                } else {
                    self.entries[p].offered = false;
                }
            }
        }
    }

    /// The teardown of the instance of the record at `place` is done: a
    /// record that restarts loads once its pause is over, and waits for it
    /// otherwise; the console's driver, the record with `log`, that is
    /// broken or ended gets what is left of the kernel log shown by the
    /// worker at WORKER_IDLE (spec 13.4, 16.3).
    fn torn_down(&mut self, place: usize) {
        if crate::worker::take_stuck(place) {
            let entry = &mut self.entries[place];
            entry.state = State::Broken;
            entry.waiting = [const { None }; WAITING_MAX];
            entry.deadline = None;
            println!(
                "init: {} did not stop; broken, its DMA memory stays with init",
                TABLE[place].name
            );
        }
        let entry = &mut self.entries[place];
        if matches!(entry.state, State::Broken | State::Ended) && TABLE[place].log {
            // Ceiling 0: the worker goes to WORKER_IDLE for it (init::work).
            let job = Job {
                work: Work::ShowLog,
                record: place,
                ceiling: 0,
            };
            self.push(job);
            return;
        }
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

    /// An expiry of the timer of the record at `place` (its label names it,
    /// `timed`): a record that waits for its pause or its quota starts; a
    /// service whose watchdog deadline came is marked suspect, then silent
    /// one period later (init::watch). An expiry before the deadline is
    /// stale (spec 10). Init acts on this record alone: a record whose
    /// timer is masked by a higher service does not come here until that
    /// service lets the processor down to its slot.
    fn expired(&mut self, place: usize) {
        let now = now();
        let entry = &mut self.entries[place];
        if !entry.deadline.is_some_and(time::reached) {
            return;
        }
        match entry.state {
            State::Paused | State::Quota => {
                entry.deadline = None;
                self.launch(place);
            }
            State::Starting | State::Running => {
                match entry.watch.as_mut().map(|w| w.expired(now)) {
                    Some(Action::Suspect { deadline }) => self.set_deadline(place, deadline),
                    Some(Action::Silent) => self.silent(place),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// The place of the record whose timer carries `label` (spec 13.4).
    fn timed(&self, label: u64) -> Option<usize> {
        let timed = |e: &Entry| e.timer_label == label;
        self.entries[..TABLE.len()].iter().position(timed)
    }

    /// The place of the record whose instance has `label`.
    fn caller(&self, label: u64) -> Option<usize> {
        let named = |e: &Entry| e.held.running().is_some_and(|i| i.spawned.label == label);
        self.entries[..TABLE.len()].iter().position(named)
    }

    /// START: the next piece of the start data of the instance at `place`.
    /// A reply that failed changes nothing here: the end of the instance
    /// comes as its exit notification.
    fn start_data(&mut self, place: usize, r: &mut Request<'_>) -> Answer {
        let instance = self.entries[place].held.running_mut();
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
        if let Some(instance) = entry.held.running_mut() {
            instance.channel = Some(channel);
        }
        entry.state = State::Running;
        // From REGISTER on, the watchdog counts the heartbeats (spec 13.4).
        let deadline = record.watch().map(|w| {
            let armed = w.arm(now());
            entry.watch = Some(armed);
            armed.deadline()
        });
        if let Some(at) = deadline {
            self.set_deadline(place, at);
        }
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
        // The sessions of the process service come in start data.
        let allowed = name.as_bytes() != table::PROCESS_SERVICE.as_bytes()
            && client
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
    /// registered, its watchdog deadline moving to now plus its record's
    /// deadline; BAD_STATE for any other (spec 13.4).
    fn heartbeat(&mut self, place: usize, r: &Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let entry = &mut self.entries[place];
        let registered = !TABLE[place].is_client() && entry.state == State::Running;
        if !registered {
            return refuse(Error::BadState);
        }
        if let Some(at) = entry.watch.as_mut().map(|w| w.beat(now())) {
            self.set_deadline(place, at);
        }
        Answer::Status(Status::Ok)
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
                let process = entry.held.running().map(Instance::process);
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
    /// of the worker with the place of its record and whether the worker
    /// took it, the worker's priorities and state (THREAD_STATE), the jobs
    /// that wait, the free pages of init's quota and the labels init gave.
    /// The errors are those of the calls.
    fn stats(&self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let facts = sys::kernel_stats(&self.resource).and_then(|kernel| {
            let worker = sys::thread_info(self.worker.thread())?;
            let memory = sys::process_memory(&self.own)?;
            Ok(Stats {
                kernel,
                job: self.jobs.current().map(|j| (j.work, j.record as u8)),
                worker_priority: worker.base,
                worker_effective: worker.priority,
                worker_state: worker.state.code() as u8,
                pending: self.jobs.queue().len() as u8,
                begun: self.worker.begun(),
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
    let channel = entry.held.running()?.channel.as_ref()?;
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
        Method::Adopt.number(),
        Method::Adopted.number(),
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
            Some(Method::Adopt) => self.adopt(place, r),
            Some(Method::Adopted) => self.adopted(place, r),
            Some(Method::Ping) if r.body().finish().is_ok() => Answer::Status(Status::Ok),
            Some(Method::Ping) => Answer::Status(Status::BadSize),
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    /// The client of `s` went (CLIENT_GONE): its waiting CONNECT requests
    /// leave the records they wait in (spec 13.4). Its instance, if it was
    /// a service, ends through its exit notification (`ended`).
    fn gone(&mut self, s: &mut Session<(), 1>) {
        let label = s.label();
        if self.adoption.as_ref().is_some_and(|p| p.label() == label) {
            self.adoption = None;
        }
        for entry in &mut self.entries {
            for slot in &mut entry.waiting {
                if slot.as_ref().is_some_and(|(p, _)| p.label() == label) {
                    *slot = None;
                }
            }
        }
    }

    /// The worker's notification: the outcome of its job; the end of an
    /// instance (`ended`); an expiry of the timer of a record, which its
    /// label names (`expired`).
    fn notification(&mut self, n: Notice) {
        match n.source {
            Source::Session if n.label == self.worker.label => self.accept(),
            Source::Exit => self.ended(n.label),
            Source::Timer => {
                if let Some(place) = self.timed(n.label) {
                    self.expired(place);
                }
            }
            _ => {}
        }
    }
}
