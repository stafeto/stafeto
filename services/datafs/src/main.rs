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

mod clock;
mod identity;
mod shared;
mod window;
mod worker;

use abi::{Rights, Source};
use core::sync::atomic::Ordering::{Acquire, Release};
use datafs::admit::{self, Adopt, Fifo, Forgotten, Held, Wait};
use proto_data::{METHODS as DATA_METHODS, Method, VERSION};
use proto_init::ServiceArgs;
use proto_wire::Status;
use rt::handle::{Any, Channel, Memory, Outgoing, Process};
use rt::service::{Answer, Config, Heartbeat, Notice, Pending, Request, Service, Session};
use rt::{Handle, sys};
use shared::*;

rt::entry!(main);

/// The sessions the loop keeps: the processes of POSIX that use `/data`, and the services beside,
/// and the root channel, which holds a session of its own like any label that sends.
const SESSIONS: usize = datafs::server::SESSIONS + 1;

/// The codes of a start that failed.
const NO_START_DATA: u64 = 1;
const NOT_REGISTERED: u64 = 3;
const BUDGET: u64 = 4;
const STOPPED: u64 = 5;
const STUCK: u64 = 6;

/// The handle of the loop's own budget, kept for the steps build.
#[cfg(feature = "steps")]
static SERVE_BUDGET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Under the feature `steps`, at each heartbeat in which the loop's budget overran again: the CPU
/// the loop's budget has charged since the last line, the time since it, and the overruns the kernel
/// counted, `datafs: serve ran <us> us in <ms> ms, <n> overruns, <m> in this span`. The share the
/// loop takes of its CPU is `ran` over the span; the budget is 100 us in each 10 ms (1 %).
#[cfg(feature = "steps")]
fn serve_line() {
    use core::sync::atomic::AtomicU64;
    static LAST: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
    let raw = SERVE_BUDGET.load(Acquire);
    if raw == 0 {
        return;
    }
    let budget = Handle::<rt::handle::Budget>::borrowed(abi::Handle(raw));
    let Ok(info) = sys::budget_info(&budget) else {
        return;
    };
    let now = rt::time::ticks_to_ns(rt::time::now());
    let before = LAST[2].load(Acquire);
    if info.overruns == before {
        return;
    }
    let (ran, at) = (LAST[0].load(Acquire), LAST[1].load(Acquire));
    LAST[0].store(info.ran, Release);
    LAST[1].store(now, Release);
    LAST[2].store(info.overruns, Release);
    rt::println!(
        "datafs: serve ran {} us in {} ms, {} overruns, {} in this span",
        rt::time::ticks_to_ns(info.ran.saturating_sub(ran)) / 1000,
        now.saturating_sub(at) / 1_000_000,
        info.overruns,
        info.overruns - before
    );
}

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<rt::handle::Resource>("console") {
        rt::console::set(console);
    }
    let serve = rt::budget::take(&mut s, rt::budget::SERVE);
    let work = rt::budget::take(&mut s, worker::WORK);
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
        (worker::PARENT, s.parent.raw()),
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
    let Ok(_thread) = worker::start(&s.process, work) else {
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
        carried: [const { None }; JOBS],
        forgotten: Forgotten::new(),
        waiting: Fifo::new(),
        made: 0,
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
    match rt::budget::bind("datafs", rt::budget::SERVE, serve, &s.thread) {
        Err(_) => return BUDGET,
        #[cfg(feature = "steps")]
        Ok(Some(kept)) => {
            SERVE_BUDGET.store(kept.raw().0, Release);
            core::mem::forget(kept);
        }
        Ok(_) => {}
    }
    // The root of the service goes to the process service, which gives a copy of it to every
    // process that asks (TakeRoot) and to the loader of a set-ID program (LoaderRoot). A thread
    // registers it: the connection to the process service waits in init until it has started, and
    // the loop must not wait for it.
    PARENT.store(s.parent.raw().0, core::sync::atomic::Ordering::Release);
    CHANNEL.store(channel.raw().0, core::sync::atomic::Ordering::Release);
    LEVEL.store(u64::from(level), core::sync::atomic::Ordering::Release);
    // SAFETY: REGISTRAR is the registrar's alone, and the page after the worker's message buffer
    // is free.
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
            "datafs: no thread to register the root; programs get no session until it is registered"
        ),
    }
    let _ = rt::service::run::<Datafs, SESSIONS, 0>(&channel, &mut service, config);
    STOPPED
}

/// The registrar thread: the connection to init, the loop's channel and its level, which the root
/// is made from, and the thread's stack and message buffer (the page after the worker's).
static PARENT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static CHANNEL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static LEVEL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
static REGISTRAR: rt::Stack<{ 16 * 1024 }> = rt::Stack::new();
const REGISTRAR_BUFFER: usize = abi::INIT_MSGBUF as usize + 2 * 4096;

extern "C" fn register_root(_: u64) -> ! {
    let parent = Handle::<Channel>::borrowed(abi::Handle(
        PARENT.load(core::sync::atomic::Ordering::Acquire),
    ));
    let channel = Handle::<Channel>::borrowed(abi::Handle(
        CHANNEL.load(core::sync::atomic::Ordering::Acquire),
    ));
    let level = LEVEL.load(core::sync::atomic::Ordering::Acquire) as u8;
    rt::roots::keep(&parent, &channel, proto_data::ROOT, level, "datafs")
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
const _: () = assert!(SESSIONS == datafs::server::SESSIONS + 1);
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
    /// The handle a request brought for its job to use (the identity session of BIND and SESSION),
    /// open until the job is done: the worker works on the raw handle, so the thread keeps it.
    carried: [Option<Handle<Channel>>; JOBS],
    /// The labels that went while every job was in use: what they held closes when a job is free.
    forgotten: Forgotten<FORGOTTEN>,
    /// The SESSION requests of the root channel that wait for a job, first in, first out.
    waiting: Fifo<Waiting, { admit::WAITING_MAX }>,
    /// The sessions and clones of process trees made and not yet closed: the last places of the
    /// table stay for the native clients (`admit::may_make`).
    made: usize,
    /// READY went to init (once the worker's start is over, the volume mounted or not).
    ready: bool,
    /// The instant the worker's start was over (0 while it is not), for the look at the oldest job.
    since: u64,
}

/// A SESSION request of the root channel that waits for a job: the answer to give, the identity
/// session it brought, and the request as it came (a header, `WAITING_BYTES` at most).
struct Waiting {
    pending: Pending,
    brought: Handle<Channel>,
    owner: u64,
    request: [u8; WAITING_BYTES],
    len: usize,
}

const WAITING_BYTES: usize = 16;

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
            .filter(|&i| waiting_job(i))
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
        (job.root, job.expense) = ROOTS.root_of(owner);
        job.aux = aux;
        job.carried = self.carried[i].as_ref().map_or(0, |h| h.raw().0);
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
    fn make(&mut self, rights: Rights, pass: bool) -> Result<(u64, Handle<Any>), Status> {
        if !pass && !admit::may_make(self.made, SESSIONS) {
            // The last places of the table are the native clients': the answer is the service's
            // own TABLE_FULL, which the layer maps like a full table.
            return Err(proto_data::code(proto_data::TABLE_FULL));
        }
        let label = if pass {
            proto_data::PASS | self.next_label
        } else {
            OWN | self.next_label
        };
        let copy =
            sys::handle_label(&self.channel, rights, label, self.level).map_err(Status::Kernel)?;
        self.next_label += 1;
        self.made += usize::from(!pass);
        Ok((label, copy.erase()))
    }

    /// A free job for a request of `owner`: None when the table is full, the session has its share
    /// in flight, or its root has (the sessions of one process tree share `ROOT_JOBS`: no session
    /// and no tree fills the table alone).
    fn job_for(&self, owner: u64, holder: bool) -> Option<usize> {
        let (root, expense) = ROOTS.root_of(owner);
        let (mut mine, mut tree) = (0, 0);
        for j in (0..JOBS).filter(|&j| state(j).load(Acquire) != FREE) {
            // SAFETY: the owner and the root are written before the job is QUEUED and stay until
            // it is FREE.
            let (o, r, e) = unsafe { ((*job(j)).owner, (*job(j)).root, (*job(j)).expense) };
            mine += usize::from(o == owner);
            tree += usize::from(r == root && e == expense);
        }
        let free = (0..JOBS)
            .filter(|&j| state(j).load(Acquire) == FREE && self.pending[j].is_none())
            .count();
        admit::admit(admit::Load {
            free_job: self.free_job(),
            free,
            mine,
            tree,
            native: proto_data::is_service(owner),
            holder,
        })
    }

    /// ADOPT: the handle of the request is a pass of the service; its label goes to the worker, which
    /// knows the description. The thread keeps the pass until the worker answers: a refusal for a
    /// limit leaves the pass unspent and it goes back in the reply (`admit::carries`), and so does
    /// the pass of a request that found no job free.
    fn adopt(&mut self, r: &mut Request<'_>) -> Answer {
        let owner = r.label();
        let job = self.job_for(owner, false);
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

    /// WINDOW: the one handle of the request is a memory object. The root channel has no window.
    /// The handle goes to the worker in the job's `aux` (raw), which keeps it or closes it; a
    /// request that finds no job free is busy and the handle stays with the request.
    fn window(&mut self, r: &mut Request<'_>, owner: u64) -> Answer {
        if proto_data::is_root(owner) {
            return Answer::Status(proto_data::code(proto_data::IS_ROOT));
        }
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        // The kind and the rights come with the message: a device window (the kernel's `Memory`
        // accepts one) or a handle that cannot be mapped both ways is no window.
        match r.handles.info(0) {
            Some((kind, rights)) if admit::window_offered(kind, rights) => {}
            _ => return Answer::Status(proto_data::code(proto_data::INVALID)),
        }
        let Some(i) = self.job_for(owner, false) else {
            return Answer::Status(busy());
        };
        let Ok(memory) = r.handles.take::<Memory>(0) else {
            return Answer::Status(Status::Kernel(abi::Error::WrongType));
        };
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        self.pending[i] = Some(pending);
        self.outgoing[i] = None;
        self.carried[i] = None;
        self.queue(i, REQUEST, owner, memory.into_raw().0, r.bytes());
        Answer::Deferred
    }

    /// BIND, SESSION and VERIFY_SESSION: the one handle of the request. For BIND it is the caller's
    /// identity session (kept for the job); for SESSION it is that too, and the reply carries a new
    /// session of the service (a label of its own and a copy of the channel); for VERIFY_SESSION it
    /// is the session offered, which goes back in the reply when the worker says it is live. The
    /// result is what `request` takes: the label for the worker, the handle the reply may carry, and
    /// the handle the job uses.
    #[allow(clippy::type_complexity)]
    fn identity_call(
        &mut self,
        r: &mut Request<'_>,
    ) -> Result<(u64, (Option<(Held, Handle<Any>)>, Option<Handle<Channel>>)), Answer> {
        if r.handles.len() != 1 {
            return Err(Answer::Status(Status::BadSize));
        }
        let Ok(brought) = r.handles.take::<Channel>(0) else {
            return Err(Answer::Status(Status::Kernel(abi::Error::WrongType)));
        };
        match Method::from_number(r.method()) {
            Some(Method::Bind) => Ok((0, (None, Some(brought)))),
            Some(Method::Session) => match self.make(Rights::SEND | Rights::TRANSFER, false) {
                Ok(made) => Ok((made.0, (Some((Held::Made, made.1)), Some(brought)))),
                Err(e) => Err(Answer::Status(e)),
            },
            _ => Err(Answer::Status(proto_data::code(proto_data::INVALID))),
        }
    }

    /// VERIFY_SESSION (rule 15, root channel only): the offered session itself comes back when it is
    /// a live session of this service, BAD_HANDLE with no handle otherwise. A handle of this
    /// service's channel has a label here (`copy_label` fails for any other channel), and a handle
    /// held is a channel that lives; the root channel is not a session.
    fn verify_session(&mut self, r: &mut Request<'_>) -> Answer {
        if !proto_data::is_root(r.label()) {
            return Answer::Status(proto_data::code(proto_data::IS_ROOT));
        }
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let Ok(offered) = r.handles.take::<Channel>(0) else {
            return Answer::Status(proto_data::code(proto_data::BAD_HANDLE));
        };
        match sys::copy_label(&self.channel, &offered) {
            // A pass and the session of a native client are not sessions a POSIX client holds.
            Ok(label) if admit::verifiable(label) => {
                // The session came from a loader, for a set-ID program: the identity it was
                // bound to is the parent's, so the worker ends the binding before the program's
                // first request (the queue keeps the order). With no job admitted the session is not
                // vouched for: the loader leaves the slot empty.
                // The job is admitted under the rules of every request, for the label of the
                // session verified: a loop of VERIFY_SESSION on one session takes its share and no
                // more, and leaves the native places and the other roots' alone.
                let Some(i) = self.job_for(label, false) else {
                    return Answer::Status(proto_data::code(proto_data::BAD_HANDLE));
                };
                if r.reply().u32(0).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                self.queue(i, UNBIND, label, 0, &[]);
                Answer::Reply([offered.erase()].into())
            }
            _ => Answer::Status(proto_data::code(proto_data::BAD_HANDLE)),
        }
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
            // The identity session the request brought closes with the job (the worker kept a copy
            // of it for a session that stays bound).
            self.carried[i] = None;
            state(i).store(FREE, Release);
        }
        if more {
            let _ = sys::notify(&self.again, 1);
        }
        self.release_waiting();
        self.close_forgotten();
    }

    /// Keeps a SESSION request of the root channel until a job is admitted: the answer is deferred
    /// and the identity session it brought is held with it. A request that does not fit the queue
    /// gets busy.
    fn wait(&mut self, r: &mut Request<'_>, owner: u64) -> Answer {
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let bytes = r.bytes();
        if bytes.len() > WAITING_BYTES {
            return Answer::Status(busy());
        }
        let Ok(brought) = r.handles.take::<Channel>(0) else {
            return Answer::Status(Status::Kernel(abi::Error::WrongType));
        };
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        let mut request = [0; WAITING_BYTES];
        request[..bytes.len()].copy_from_slice(bytes);
        let waiting = Waiting {
            pending,
            brought,
            owner,
            request,
            len: bytes.len(),
        };
        if let Err(back) = self.waiting.push(waiting) {
            let _ = back
                .pending
                .answer(&busy().code().to_le_bytes(), Outgoing::new());
        }
        Answer::Deferred
    }

    /// The waiting requests go to the worker in the order they came, while jobs are admitted.
    fn release_waiting(&mut self) {
        while let Some(front) = self.waiting.front() {
            let Some(i) = self.job_for(front.owner, false) else {
                break;
            };
            let Some(waiting) = self.waiting.pop() else {
                break;
            };
            match self.make(Rights::SEND | Rights::TRANSFER, false) {
                Ok((label, copy)) => {
                    self.pending[i] = Some(waiting.pending);
                    self.outgoing[i] = Some((Held::Made, copy));
                    self.carried[i] = Some(waiting.brought);
                    self.queue(
                        i,
                        REQUEST,
                        waiting.owner,
                        label,
                        &waiting.request[..waiting.len],
                    );
                }
                Err(e) => {
                    let code = e.code().to_le_bytes();
                    let _ = waiting.pending.answer(&code, Outgoing::new());
                }
            }
        }
    }

    /// The service stops: nothing waits for a job any more.
    fn refuse_waiting(&mut self) {
        let code = Status::Kernel(abi::Error::BadState).code().to_le_bytes();
        while let Some(waiting) = self.waiting.pop() {
            let _ = waiting.pending.answer(&code, Outgoing::new());
        }
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
        // VERIFY_SESSION needs no disk and no table of the volume: the kernel says whether the
        // offered handle is a session of this service.
        if Method::from_number(r.method()) == Some(Method::VerifySession) {
            return self.verify_session(r);
        }
        let owner = r.label();
        // A part of a call that holds a lease takes a job outside the shares.
        let holder = admit::holder_part(r.bytes(), |number| {
            LIVE_LEASES.iter().any(|l| l.load(Acquire) == number)
        });
        // WINDOW brings the memory object of the session's cells. It goes to the worker, which owns
        // it from here (it keeps it or closes it), in the `aux` of the job.
        if Method::from_number(r.method()) == Some(Method::Window) {
            return self.window(r, owner);
        }
        let job = self.job_for(owner, holder);
        // Every SESSION arrives with the one root label and shares its jobs: over the share the
        // request waits its turn, and busy answers only a full queue.
        if Method::from_number(r.method()) == Some(Method::Session) && proto_data::is_root(owner) {
            match admit::wait_plan(job.is_some(), self.waiting.len()) {
                Wait::Run => {}
                Wait::Defer => return self.wait(r, owner),
                Wait::Busy => return Answer::Status(busy()),
            }
        }
        let Some(i) = job else {
            return Answer::Status(busy());
        };
        // The calls that bring or make a handle are the request thread's: a kernel call each, no disk.
        let (aux, handle) = match Method::from_number(r.method()) {
            Some(Method::Clone) => match self.make(Rights::SEND | Rights::TRANSFER, false) {
                Ok(made) => (made.0, (Some((Held::Made, made.1)), None)),
                Err(e) => return Answer::Status(e),
            },
            Some(Method::Export) => match self.make(Rights::TRANSFER, true) {
                Ok(made) => (made.0, (Some((Held::Made, made.1)), None)),
                Err(e) => return Answer::Status(e),
            },
            // BIND, SESSION and VERIFY_SESSION bring one handle: the identity session of the caller
            // (a copy for the worker to vouch for) or the session offered for verification.
            Some(Method::Bind | Method::Session) => match self.identity_call(r) {
                Ok(made) => made,
                Err(answer) => return answer,
            },
            _ => (0, (None, None)),
        };
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        self.pending[i] = Some(pending);
        self.outgoing[i] = handle.0;
        self.carried[i] = handle.1;
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
        // A session or clone made for a process tree: its place of the count is free again.
        if label & OWN != 0 && !proto_data::is_pass(label) && !proto_data::is_root(label) {
            self.made = self.made.saturating_sub(1);
        }
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
            // A job that waits for a lease is looked at again each beat, whatever the worker's own
            // timer did: no wake is lost for good.
            if (0..JOBS).any(|i| state(i).load(Acquire) == PARKED) {
                let _ = sys::notify(&self.kick, 1);
            }
            #[cfg(feature = "steps")]
            serve_line();
        }
    }

    fn notification(&mut self, n: Notice) {
        rt::service::step_own();
        if n.source == Source::Session && n.label == LABEL_DONE {
            if !self.ready && !STARTING.load(Acquire) {
                self.ready = true;
                // The time of the machine at READY, to be read against the one of the layer
                // service (`layerd: index of ...`): the build of its index starts after this.
                rt::println!(
                    "datafs: READY at {} ms of uptime",
                    rt::time::ticks_to_ns(rt::time::now()) / 1_000_000
                );
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
            self.refuse_waiting();
            let _ = sys::notify(&self.kick, 1);
        }
    }
}

const _: fn() = || {
    let _: Option<Handle<Process>> = None;
};
