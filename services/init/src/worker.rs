// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Init's worker thread (spec 8, 13.4): it loads the instances of the
//! records of the table (rt::loader::spawn), one job at a time, so that
//! init's main thread at 63 never waits for work that grows with the size
//! of a service. The main thread puts a job into the cell (`Worker::give`),
//! sets the worker's level (init::work::worker_level) and wakes it through
//! the worker's channel; the worker does the job, leaves its outcome in
//! the cell and tells the main thread through its copy of init's channel
//! with NOTIFY and a label of its own, whose slot is at WORKER_MAX.

use abi::{Error, Policy, Rights};
use bootimg::Program;
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use init::table::{Record, TABLE};
use init::work::{WORKER_IDLE, WORKER_MAX};
use proto_init::ServiceArgs;
use proto_wire::Writer;
use rt::handle::{Channel, Process, Resource, Thread};
use rt::loader::{self, SpawnParams, Spawned};
use rt::{Handle, Stack, sys};

/// Where the worker maps the objects of a program it loads, in init's
/// space: a window only the loader uses (rt::loader::load).
const LOADER_WINDOW: usize = 0x60_0000_0000;
/// The worker's message buffer, the page after that of init's main thread.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 4096;
const STACK_SIZE: usize = 32 * 1024;

static STACK: Stack<STACK_SIZE> = Stack::new();

/// A job the main thread gives the worker.
pub enum Order {
    /// Load an instance of the record at `place` of the table from
    /// `program`, named by `label` on init's channel.
    Load {
        place: usize,
        label: u64,
        program: Program<'static>,
    },
}

/// What the worker leaves the main thread.
pub enum Outcome {
    /// The instance, its thread not started yet: its start data hold its
    /// process, its thread, the console when its record has one, and its
    /// arguments.
    Loaded(Result<Spawned, Error>),
}

/// The states of the cell: FREE, the main thread's to fill; GIVEN, the
/// worker's; DONE, the main thread's to empty.
const FREE: u8 = 0;
const GIVEN: u8 = 1;
const DONE: u8 = 2;

/// The cell of the one job between the two threads: its order and its
/// outcome. Only the thread its state names reaches them; the store that
/// hands them over has Release order, the load that takes them Acquire.
struct Cell {
    state: AtomicU8,
    order: UnsafeCell<Option<Order>>,
    outcome: UnsafeCell<Option<Outcome>>,
}

// SAFETY: the state gives the cell to one thread at a time (`Cell`), and
// one worker uses it (`Worker::start`).
unsafe impl Sync for Cell {}

/// Whether the one worker started (`Worker::start`).
static STARTED: AtomicBool = AtomicBool::new(false);

static CELL: Cell = Cell {
    state: AtomicU8::new(FREE),
    order: UnsafeCell::new(None),
    outcome: UnsafeCell::new(None),
};

/// The values of the handles the worker uses: init's process, init's
/// channel, the system resource, the worker's channel and its copy of
/// init's channel. The main thread keeps the first four for good; the
/// worker owns the last.
static HANDLES: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
const OWN: usize = 0;
const CHANNEL: usize = 1;
const RESOURCE: usize = 2;
const WAKE: usize = 3;
const TELL: usize = 4;

fn view<K>(i: usize) -> ManuallyDrop<Handle<K>> {
    Handle::borrowed(abi::Handle(HANDLES[i].load(Ordering::Relaxed)))
}

/// The main thread's side of the worker: its thread, its channel and the
/// label of its notifications on init's channel.
pub struct Worker {
    thread: Handle<Thread>,
    wake: Handle<Channel>,
    pub label: u64,
}

impl Worker {
    /// Starts the worker at WORKER_IDLE in init's process `own` (spec
    /// 13.4): it loads through `channel`, init's channel, gives copies of
    /// `resource` as consoles, waits on a channel of its own whose slot of
    /// label 0 is at WORKER_IDLE, so a wake lifts it no higher, and tells
    /// the main thread through a copy of `channel` with NOTIFY and `label`.
    /// BAD_STATE once a worker started: the cell is one; the other errors
    /// are those of the calls.
    pub fn start(
        own: &Handle<Process>,
        channel: &Handle<Channel>,
        resource: &Handle<Resource>,
        label: u64,
    ) -> Result<Worker, Error> {
        if STARTED.swap(true, Ordering::AcqRel) {
            return Err(Error::BadState);
        }
        let wake = sys::channel_create(WORKER_IDLE)?;
        let tell = sys::handle_label(channel, Rights::NOTIFY, label, WORKER_MAX)?;
        for (i, raw) in [
            (OWN, own.raw()),
            (CHANNEL, channel.raw()),
            (RESOURCE, resource.raw()),
            (WAKE, wake.raw()),
            (TELL, tell.into_raw()),
        ] {
            HANDLES[i].store(raw.0, Ordering::Relaxed);
        }
        // SAFETY: STACK is the worker's alone.
        let thread = unsafe {
            sys::thread_create(own, work, STACK.top(), 0, WORKER_IDLE, Policy::Fifo, BUFFER)
        }?;
        sys::thread_start(&thread)?;
        Ok(Worker {
            thread,
            wake,
            label,
        })
    }

    /// Sets the worker's base priority to `level` (init::work).
    pub fn set_level(&self, level: u8) -> Result<(), Error> {
        sys::thread_set_priority(&self.thread, level, Policy::Fifo)
    }

    /// Gives the worker `order` and wakes it. The main thread gives a job
    /// only once it took the outcome of the one before (`take`).
    pub fn give(&self, order: Order) -> Result<(), Error> {
        assert_eq!(
            CELL.state.load(Ordering::Acquire),
            FREE,
            "one job at a time"
        );
        // SAFETY: FREE: the cell is the main thread's.
        unsafe { *CELL.order.get() = Some(order) };
        CELL.state.store(GIVEN, Ordering::Release);
        sys::notify(&self.wake, 1)
    }

    /// The outcome of the job the worker did, once it is done.
    pub fn take(&self) -> Option<Outcome> {
        if CELL.state.load(Ordering::Acquire) != DONE {
            return None;
        }
        // SAFETY: DONE: the cell is the main thread's.
        let outcome = unsafe { (*CELL.outcome.get()).take() };
        CELL.state.store(FREE, Ordering::Release);
        outcome
    }
}

/// The worker's thread: waits on its channel, does the job it finds in
/// the cell, and tells the main thread.
extern "C" fn work(_: u64) -> ! {
    let (wake, tell) = (view::<Channel>(WAKE), view::<Channel>(TELL));
    loop {
        sys::receive(&wake).expect("the worker's channel lives as long as init");
        if CELL.state.load(Ordering::Acquire) != GIVEN {
            continue;
        }
        // SAFETY: GIVEN: the cell is the worker's.
        let Some(order) = (unsafe { (*CELL.order.get()).take() }) else {
            continue;
        };
        let outcome = match order {
            Order::Load {
                place,
                label,
                program,
            } => Outcome::Loaded(load(&TABLE[place], label, &program)),
        };
        // SAFETY: still GIVEN: the cell is the worker's until the store.
        unsafe { *CELL.outcome.get() = Some(outcome) };
        CELL.state.store(DONE, Ordering::Release);
        // The main thread lives as long as init's channel.
        let _ = sys::notify(&tell, 1);
    }
}

/// Loads an instance of `record` from `program` with the label `label` on
/// init's channel (rt::loader::spawn): its quota, room for handles,
/// ceiling and priority from the record, the notification of its end at
/// its base priority (spec 13.4), and its start data (`start_data`). An
/// instance whose start data could not be made is killed; its thread never
/// ran.
fn load(record: &Record, label: u64, program: &Program<'static>) -> Result<Spawned, Error> {
    let channel = view::<Channel>(CHANNEL);
    let params = SpawnParams {
        channel: &channel,
        label,
        notice: record.priority,
        quota: record.quota,
        handle_limit: record.handle_limit,
        ceiling: record.ceiling,
        priority: record.priority,
        policy: Policy::Fifo,
    };
    // SAFETY: only the worker maps and uses LOADER_WINDOW.
    let mut spawned = unsafe { loader::spawn(&view(OWN), program, LOADER_WINDOW, params) }?;
    if let Err(e) = start_data(record, &mut spawned) {
        let _ = sys::process_kill(&spawned.process);
        return Err(e);
    }
    Ok(spawned)
}

/// The start data of an instance of `record` besides its process and
/// thread (spec 13.3): a copy of the system resource with DEBUG and
/// TRANSFER under the name `console` when the record has one, and the
/// arguments, ServiceArgs with the heartbeat and watchdog of a service (0
/// for a client) and the record's own arguments.
fn start_data(record: &Record, spawned: &mut Spawned) -> Result<(), Error> {
    if record.console {
        let rights = Rights::DEBUG | Rights::TRANSFER;
        let console = sys::handle_duplicate(&view::<Resource>(RESOURCE), rights)?;
        // The third name of the start data fits.
        let _ = spawned.giver.give("console", console.erase());
    }
    let watch = record.watch();
    let args = ServiceArgs {
        period_ns: watch.map_or(0, |w| w.period_ns),
        deadline_ns: watch.map_or(0, |w| w.deadline_ns),
        own: record.args,
    };
    let mut w = Writer::new();
    // The checks of the table keep the own arguments within OWN_ARGS_MAX.
    args.write(&mut w).map_err(|_| Error::InvalidArgs)?;
    spawned.giver.set_args(w.as_bytes())
}
