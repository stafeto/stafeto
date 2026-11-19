// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The data file service: the files of the volume mounted at `/data` (proto_data), two threads of one
//! process. The main thread is the loop of a service (rt::service): it takes a request, copies it into
//! a job and defers the reply, so a step is a copy of at most 1 KiB and stays short whatever the disk
//! does; it answers the heartbeat and sends the reply of each job the worker has finished. The worker
//! thread (`worker.rs`, level 30) picks the data partition, mounts littlefs on it and runs the jobs in
//! the order they came, waiting in calls to the disk service. A session that goes has what it held
//! closed by a job of the worker.

#![no_std]
#![no_main]

mod shared;
mod worker;

use abi::{Rights, Source};
use core::sync::atomic::Ordering::{Acquire, Release};
use datafs::admit::{self, Adopt, Forgotten, Held};
use proto_data::{METHODS as DATA_METHODS, Method, VERSION};
use proto_init::ServiceArgs;
use proto_wire::Status;
use rt::handle::{Any, Channel, Outgoing, Process};
use rt::service::{Answer, Config, Heartbeat, Notice, Pending, Request, Service, Session};
use rt::{Handle, sys};
use shared::*;

rt::entry!(main);

/// The sessions the loop keeps: the processes of POSIX that use `/data`, and the services beside.
const SESSIONS: usize = 64;

/// The codes of a start that failed.
const NO_START_DATA: u64 = 1;
const NOT_REGISTERED: u64 = 3;
const BUDGET: u64 = 4;
const STOPPED: u64 = 5;
const STUCK: u64 = 6;

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<rt::handle::Resource>("console") {
        rt::console::set(console);
    }
    let serve = rt::budget::take(&mut s, rt::budget::SERVE);
    let args = ServiceArgs::read(s.args()).ok();
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    // The record `datadisk` is optional: a machine without a data volume has none, and the service
    // answers every request with "not mounted" (the worker finds no session of a disk).
    let blk = rt::service::connect(&s.parent, "datadisk").ok();
    let Ok(channel) = sys::channel_create(1) else {
        return NOT_REGISTERED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return NOT_REGISTERED;
    }
    // The notification the worker gives when a job is done, and the channel it waits on for a kick.
    let Ok(done) = sys::handle_label(
        &channel,
        Rights::NOTIFY | Rights::TRANSFER,
        LABEL_DONE,
        level,
    ) else {
        return NOT_REGISTERED;
    };
    // The same notification for the service itself, when it leaves finished jobs for a later step.
    let Ok(again) = sys::handle_label(
        &channel,
        Rights::NOTIFY | Rights::TRANSFER,
        LABEL_DONE,
        level,
    ) else {
        return NOT_REGISTERED;
    };
    let Ok(jobs) = sys::channel_create(worker::LEVEL) else {
        return NOT_REGISTERED;
    };
    let Ok(kick) = sys::handle_label(&jobs, Rights::NOTIFY, LABEL_KICK, worker::LEVEL) else {
        return NOT_REGISTERED;
    };
    for (i, raw) in [
        (worker::PROCESS, s.process.raw()),
        (
            worker::BLK_SESSION,
            blk.map_or(abi::Handle(0), |h| h.into_raw()),
        ),
        (worker::WAKE, done.into_raw()),
    ] {
        worker::RAW[i].store(raw.0, Release);
    }
    worker::JOBS_CHANNEL.store(jobs.into_raw().0, Release);
    // The loop works under a budget from here on: the first touch of a page of the table of jobs
    // or of the volume's memory is a fault the kernel serves, and it must not land in a step.
    touch(
        TABLE.get().cast::<u8>(),
        core::mem::size_of::<[Job; JOBS]>(),
    );
    touch(
        STORAGE.get().cast::<u8>(),
        core::mem::size_of::<datafs::Storage>(),
    );
    let Ok(_thread) = worker::start(&s.process) else {
        return NOT_REGISTERED;
    };
    #[cfg(feature = "steps")]
    {
        rt::service::report_steps(17);
        rt::service::table_steps_from(16);
    }
    let mut service = Datafs {
        parent: Handle::borrowed(s.parent.raw()),
        channel: Handle::borrowed(channel.raw()),
        level,
        next_label: 1,
        kick,
        again,
        pending: [const { None }; JOBS],
        outgoing: [const { None }; JOBS],
        forgotten: Forgotten::new(),
        ready: false,
        since: 0,
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &s.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    // The loop is this thread: it works under its budget from here on, and a budget the kernel
    // refuses is a start error, since the thread would run without a limit.
    if rt::budget::bind("datafs", rt::budget::SERVE, serve, &s.thread).is_err() {
        return BUDGET;
    }
    let _ = rt::service::run::<Datafs, SESSIONS, 0>(&channel, &mut service, config);
    STOPPED
}

/// Writes a zero into each page of the `len` bytes at `base`, so that every page is mapped. It runs
/// before the worker thread starts: no one else uses the memory yet, and the bytes are zeros.
fn touch(base: *mut u8, len: usize) {
    let mut at = 0;
    while at < len {
        // SAFETY: `at` is within the static; the bytes are zeros and no other thread runs yet.
        unsafe { base.add(at).write(0) };
        at += PAGE;
    }
    // The memory may be read through the pointer from here on: the writes stay.
    core::hint::black_box(base);
}

const PAGE: usize = 4096;

/// The labels whose close waits for a free job: everything that can close while the table is full
/// (`admit::closers`). A label that does not fit is lost, and with it a session's descriptions.
const FORGOTTEN: usize = admit::closers(SESSIONS, datafs::server::PASSES, JOBS);
const _: () = assert!(SESSIONS == datafs::server::SESSIONS);
const _: () = assert!(FORGOTTEN >= SESSIONS + datafs::server::PASSES + 3 * JOBS);

/// Bit 63 marks the labels the service gives itself (the clones of CLONE and the passes of
/// EXPORT), which no label of init has; the rest is a count that is never used twice.
const OWN: u64 = 1 << 63;

/// The finished jobs the main thread answers in one step; the rest follow in later steps.
const SETTLE_AT_ONCE: usize = 4;

struct Datafs {
    parent: core::mem::ManuallyDrop<Handle<Channel>>,
    /// The service's own channel, for the labelled copies it gives away.
    channel: core::mem::ManuallyDrop<Handle<Channel>>,
    /// The priority of the slots of those copies: the thread's base priority.
    level: u8,
    next_label: u64,
    kick: Handle<Channel>,
    /// A notification of the service to itself with the label of the worker's.
    again: Handle<Channel>,
    /// The deferred reply of each job in flight.
    pending: [Option<Pending>; JOBS],
    /// The handle a job's reply carries when the worker says yes: the session of CLONE, the pass of
    /// EXPORT. A job the worker refuses lets it go.
    outgoing: [Option<(Held, Handle<Any>)>; JOBS],
    /// The labels that went while every job was in use: what they held closes when a job is free.
    forgotten: Forgotten<FORGOTTEN>,
    /// READY went to init (once the worker's start is over, the volume mounted or not).
    ready: bool,
    /// The instant the worker's start was over (0 while it is not), for the look at the oldest job.
    since: u64,
}

/// The clock in nanoseconds.
fn now_ns() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}

impl Datafs {
    /// The heartbeat proves the worker as well as the request thread: while a job is in the table
    /// and no disk call has completed for `STUCK_NS`, the service ends, and init starts a new one.
    fn watch_worker(&mut self) {
        if STARTING.load(Acquire) {
            return;
        }
        let now = now_ns();
        if self.since == 0 {
            self.since = now;
        }
        let queued = (0..JOBS)
            .filter(|&i| state(i).load(Acquire) == QUEUED)
            // SAFETY: the instant is written before the job is QUEUED; it is read through the atomic.
            .map(|i| unsafe { (*job(i)).queued_at.load(Acquire) });
        let progress = PROGRESS.load(Acquire);
        // While the service stops the check is off: the drain waits on the disk, and init's deadline
        // of 3 s bounds it (a stuck exit outside a stop is unchanged).
        let stopping = STOPPING.load(Acquire);
        if datafs::watch::must_exit(
            stopping,
            now,
            self.since,
            progress,
            queued,
            datafs::watch::STUCK_NS,
        ) {
            rt::println!(
                "datafs: no disk call completed in 20 s with a job waiting, the service ends"
            );
            sys::process_exit(STUCK);
        }
    }

    fn free_job(&self) -> Option<usize> {
        (0..JOBS).find(|&i| state(i).load(Acquire) == FREE && self.pending[i].is_none())
    }

    /// Fills job `i` and hands it to the worker.
    fn queue(&mut self, i: usize, kind: u8, owner: u64, aux: u64, bytes: &[u8]) {
        // SAFETY: the job is FREE: the worker does not touch it until it is QUEUED.
        let job = unsafe { &mut *job(i) };
        job.kind = kind;
        job.owner = owner;
        job.aux = aux;
        job.request_len = bytes.len();
        job.request[..bytes.len()].copy_from_slice(bytes);
        job.ticket.store(next_ticket(), Release);
        job.queued_at.store(now_ns(), Release);
        state(i).store(QUEUED, Release);
        let _ = sys::notify(&self.kick, 1);
    }

    /// The closes of the sessions that went and found no job free. At most `SETTLE_AT_ONCE` go in one
    /// step; when more wait and jobs are free, the service tells itself again and the rest follow.
    fn close_forgotten(&mut self) {
        let mut queued = 0;
        while !self.forgotten.is_empty() {
            let Some(i) = self.free_job() else { return };
            if queued == SETTLE_AT_ONCE {
                let _ = sys::notify(&self.again, 1);
                return;
            }
            queued += 1;
            if let Some(owner) = self.forgotten.pop() {
                self.queue(i, GONE, owner, 0, &[]);
            }
        }
    }

    /// A new label of the service's own and a copy of its channel that carries it, with `rights`.
    fn make(&mut self, rights: Rights) -> Result<(u64, Handle<Any>), abi::Error> {
        let label = OWN | self.next_label;
        let copy = sys::handle_label(&self.channel, rights, label, self.level)?;
        self.next_label += 1;
        Ok((label, copy.erase()))
    }

    /// A free job for a request of `owner`: None when the table is full or the session has its share
    /// in flight (no session fills the table alone).
    fn job_for(&self, owner: u64) -> Option<usize> {
        let mine = (0..JOBS)
            .filter(|&j| state(j).load(Acquire) != FREE)
            // SAFETY: the owner is written before the job is QUEUED and stays until it is FREE.
            .filter(|&j| unsafe { (*job(j)).owner } == owner)
            .count();
        admit::job_for(self.free_job(), mine, SESSION_JOBS)
    }

    /// ADOPT: the handle of the request is a pass of the service; its label goes to the worker, which
    /// knows the description. The thread keeps the pass until the worker answers: a refusal for a
    /// limit leaves the pass unspent and it goes back in the reply (`admit::carries`), and so does
    /// the pass of a request that found no job free.
    fn adopt(&mut self, r: &mut Request<'_>) -> Answer {
        let owner = r.label();
        let job = self.job_for(owner);
        match admit::adopt_plan(r.handles.len(), job.is_some()) {
            Adopt::BadSize => return Answer::Status(Status::BadSize),
            Adopt::GiveBack | Adopt::Queue => {}
        }
        let Ok(pass) = r.handles.take::<Channel>(0) else {
            return Answer::Status(Status::Kernel(abi::Error::WrongType));
        };
        let Ok(label) = sys::copy_label(&self.channel, &pass) else {
            return Answer::Status(proto_data::code(proto_data::BAD_HANDLE));
        };
        let Some(i) = job else {
            if r.reply().u32(busy().code()).is_err() {
                return Answer::Status(busy());
            }
            return Answer::Reply([pass.erase()].into());
        };
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        self.pending[i] = Some(pending);
        self.outgoing[i] = Some((Held::Spent, pass.erase()));
        self.queue(i, REQUEST, owner, label, r.bytes());
        Answer::Deferred
    }

    /// Sends the reply of every finished job and frees it.
    /// At most `SETTLE_AT_ONCE` replies go in one step, so that a step stays short whatever the worker
    /// has finished; when more are done, the service tells itself again and the rest follow.
    fn settle(&mut self) {
        let mut sent = 0;
        let mut more = false;
        for i in 0..JOBS {
            if state(i).load(Acquire) != DONE {
                continue;
            }
            if sent == SETTLE_AT_ONCE {
                more = true;
                break;
            }
            sent += 1;
            // SAFETY: the job is DONE: the worker has finished with it.
            let job = unsafe { &*job(i) };
            let held = self.outgoing[i].take();
            if let Some(pending) = self.pending[i].take() {
                // `admit::carries` says whether the handle goes with the reply or closes.
                let reply = &job.reply[..job.reply_len];
                let handles = match held {
                    Some((how, h)) if admit::carries(how, reply) => [h].into(),
                    _ => Outgoing::new(),
                };
                let _ = pending.answer(reply, handles);
            }
            state(i).store(FREE, Release);
        }
        if more {
            let _ = sys::notify(&self.again, 1);
        }
        self.close_forgotten();
    }
}

impl Service<0> for Datafs {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = &DATA_METHODS;
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 0>, r: &mut Request<'_>) -> Answer {
        if STOPPING.load(Acquire) {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        // ADOPT first: a refusal for want of a job gives the pass back.
        if Method::from_number(r.method()) == Some(Method::Adopt) {
            return self.adopt(r);
        }
        let owner = r.label();
        let Some(i) = self.job_for(owner) else {
            return Answer::Status(busy());
        };
        // The calls that bring or make a handle are the request thread's: a kernel call each, no disk.
        let (aux, handle) = match Method::from_number(r.method()) {
            Some(Method::Clone) => match self.make(Rights::SEND | Rights::TRANSFER) {
                Ok(made) => (made.0, Some((Held::Made, made.1))),
                Err(e) => return Answer::Status(Status::Kernel(e)),
            },
            Some(Method::Export) => match self.make(Rights::TRANSFER) {
                Ok(made) => (made.0, Some((Held::Made, made.1))),
                Err(e) => return Answer::Status(Status::Kernel(e)),
            },
            _ => (0, None),
        };
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        self.pending[i] = Some(pending);
        self.outgoing[i] = handle;
        self.queue(i, REQUEST, owner, aux, r.bytes());
        Answer::Deferred
    }

    fn gone(&mut self, s: &mut Session<(), 0>) {
        let label = s.label();
        // A job of the session still in flight finishes with no one to tell.
        for i in 0..JOBS {
            let mine = state(i).load(Acquire) != FREE
                // SAFETY: the owner is written before the job is QUEUED and stays until it is FREE.
                && unsafe { (*job(i)).owner } == label;
            if mine {
                self.pending[i] = None;
                self.outgoing[i] = None;
            }
        }
    }

    /// The last copy of the handle of `label` went, whether it had a session or not (a session, a
    /// clone's or a client's, or a pass): what it held closes in a job of the worker.
    fn closed(&mut self, label: u64) {
        match self.free_job() {
            Some(i) => self.queue(i, GONE, label, 0, &[]),
            None => {
                // The size of the list covers every label that can close at once.
                let kept = self.forgotten.push(label);
                debug_assert!(kept);
            }
        }
    }

    fn maintenance(&mut self, _: &mut [Option<Session<(), 0>>], notice: Notice) {
        if notice.source == Source::Timer && notice.label == 0 {
            self.watch_worker();
        }
    }

    fn notification(&mut self, n: Notice) {
        rt::service::step_own();
        if n.source == Source::Session && n.label == LABEL_DONE {
            if !self.ready && !STARTING.load(Acquire) {
                self.ready = true;
                if let Err(why) = rt::service::ready(&self.parent) {
                    rt::println!("datafs: READY refused: {why:?}");
                }
            }
            self.settle();
            // The worker put the volume away and every reply it made has gone: the service ends.
            if UNMOUNTED.load(Acquire) && (0..JOBS).all(|i| state(i).load(Acquire) != DONE) {
                rt::println!("datafs: stopped, {} jobs finished", STOP_JOBS.load(Acquire));
                sys::process_exit(0);
            }
        }
    }

    /// The stop notice of init: no new request, the worker runs the queued jobs and puts the volume
    /// away, and `notification` ends the process when that is done. Init kills the service at its
    /// deadline should the disk not answer.
    fn stop(&mut self) {
        // The break image exits at once, as the default handler of rt::service does: the probe of
        // the stop handlers (xtask nvme-persist stop-handlers breaks) must catch it.
        #[cfg(feature = "break-datafs-stop")]
        sys::process_exit(0);
        // The time first: the worker reads it as soon as it sees the flag.
        #[cfg(not(feature = "break-datafs-stop"))]
        {
            if STOPPING.load(Acquire) {
                return;
            }
            STOP_AT.store(rt::time::now().max(1), Release);
            STOPPING.store(true, Release);
            let _ = sys::notify(&self.kick, 1);
        }
    }
}

const _: fn() = || {
    let _: Option<Handle<Process>> = None;
};
