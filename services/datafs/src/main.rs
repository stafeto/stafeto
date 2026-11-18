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
use proto_data::{METHODS as DATA_METHODS, VERSION};
use proto_init::ServiceArgs;
use proto_wire::Status;
use rt::handle::{Channel, Outgoing, Process};
use rt::service::{Answer, Config, Heartbeat, Notice, Pending, Request, Service, Session};
use rt::{Handle, sys};
use shared::*;

rt::entry!(main);

/// The sessions the loop keeps: the processes of POSIX that use `/data`, and the services beside.
const SESSIONS: usize = 32;

/// The codes of a start that failed.
const NO_START_DATA: u64 = 1;
const NOT_REGISTERED: u64 = 3;
const BUDGET: u64 = 4;
const STOPPED: u64 = 5;

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
    rt::service::report_steps(17);
    let mut service = Datafs {
        parent: Handle::borrowed(s.parent.raw()),
        kick,
        again,
        pending: [const { None }; JOBS],
        forgotten: [0; SESSIONS],
        forgotten_count: 0,
        ready: false,
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

/// The finished jobs the main thread answers in one step; the rest follow in later steps.
const SETTLE_AT_ONCE: usize = 4;

struct Datafs {
    parent: core::mem::ManuallyDrop<Handle<Channel>>,
    kick: Handle<Channel>,
    /// A notification of the service to itself with the label of the worker's.
    again: Handle<Channel>,
    /// The deferred reply of each job in flight.
    pending: [Option<Pending>; JOBS],
    /// The sessions that went while every job was in use: their files close when a job is free.
    forgotten: [u64; SESSIONS],
    forgotten_count: usize,
    /// READY went to init (once the worker's start is over, the volume mounted or not).
    ready: bool,
}

impl Datafs {
    fn free_job(&self) -> Option<usize> {
        (0..JOBS).find(|&i| state(i).load(Acquire) == FREE && self.pending[i].is_none())
    }

    /// Fills job `i` and hands it to the worker.
    fn queue(&mut self, i: usize, kind: u8, owner: u64, bytes: &[u8]) {
        // SAFETY: the job is FREE: the worker does not touch it until it is QUEUED.
        let job = unsafe { &mut *job(i) };
        job.kind = kind;
        job.owner = owner;
        job.request_len = bytes.len();
        job.request[..bytes.len()].copy_from_slice(bytes);
        job.ticket.store(next_ticket(), Release);
        state(i).store(QUEUED, Release);
        let _ = sys::notify(&self.kick, 1);
    }

    /// The closes of the sessions that went and found no job free. At most `SETTLE_AT_ONCE` go in one
    /// step; when more wait and jobs are free, the service tells itself again and the rest follow.
    fn close_forgotten(&mut self) {
        let mut queued = 0;
        while self.forgotten_count > 0 {
            let Some(i) = self.free_job() else { return };
            if queued == SETTLE_AT_ONCE {
                let _ = sys::notify(&self.again, 1);
                return;
            }
            queued += 1;
            self.forgotten_count -= 1;
            let owner = self.forgotten[self.forgotten_count];
            self.queue(i, GONE, owner, &[]);
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
            if let Some(pending) = self.pending[i].take() {
                let _ = pending.answer(&job.reply[..job.reply_len], Outgoing::new());
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
        let Some(i) = self.free_job() else {
            return Answer::Status(busy());
        };
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        self.pending[i] = Some(pending);
        self.queue(i, REQUEST, r.label(), r.bytes());
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
            }
        }
        match self.free_job() {
            Some(i) => self.queue(i, GONE, label, &[]),
            None if self.forgotten_count < SESSIONS => {
                self.forgotten[self.forgotten_count] = label;
                self.forgotten_count += 1;
            }
            None => {}
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
