// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Init's worker thread (spec 8, 13.4): it loads the instances of the
//! records of the table (rt::loader::spawn), tears down those that ended
//! and kills those that went silent, one job at a time, so that init's
//! main thread at 63 never waits for work that grows with the size of a
//! service, and never lets go of the last handles of an instance. The main
//! thread puts a job into the cell (`Worker::load`, `Worker::teardown`,
//! `Worker::kill`), sets the worker's level (init::work::worker_level) and
//! wakes it through the worker's channel; the worker does the job, leaves
//! its outcome in the cell and tells the main thread through its copy of
//! init's channel with NOTIFY and a label of its own, whose slot is at
//! WORKER_MAX. An instance's handles close here, so the cleanup of their
//! objects runs at the worker's level, below init (spec 7.7).

use crate::serve::Instance;
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
enum Order {
    /// Load an instance of the record at `place` of the table from
    /// `program`, named by `label` on init's channel.
    Load {
        place: usize,
        label: u64,
        program: Program<'static>,
    },
    /// Close the handles of the instance in the cell's `gone`.
    Teardown,
    /// Kill the process of the instance in the cell's `gone`, then close
    /// its handles.
    Kill,
}

/// What a load leaves the main thread: the instance, its thread not
/// started yet, whose start data hold its process, its thread, the console
/// when its record has one, and its arguments; or why not.
pub type Loaded = Result<Spawned, Error>;

/// The states of the cell: FREE, the main thread's to fill; GIVEN, the
/// worker's; DONE, the main thread's to empty.
const FREE: u8 = 0;
const GIVEN: u8 = 1;
const DONE: u8 = 2;

/// The cell of the one job between the two threads: its order, the
/// instance a teardown takes, and the outcome of a load. Only the thread
/// its state names reaches them; the store that hands them over has
/// Release order, the load that takes them Acquire.
struct Cell {
    state: AtomicU8,
    order: UnsafeCell<Option<Order>>,
    gone: UnsafeCell<Option<Instance>>,
    loaded: UnsafeCell<Option<Loaded>>,
}

// SAFETY: the state gives the cell to one thread at a time (`Cell`), and
// one worker uses it (`Worker::start`).
unsafe impl Sync for Cell {}

/// Whether the one worker started (`Worker::start`).
static STARTED: AtomicBool = AtomicBool::new(false);

static CELL: Cell = Cell {
    state: AtomicU8::new(FREE),
    order: UnsafeCell::new(None),
    gone: UnsafeCell::new(None),
    loaded: UnsafeCell::new(None),
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

    /// The worker's thread, for its state (STATS).
    pub fn thread(&self) -> &Handle<Thread> {
        &self.thread
    }

    /// Sets the worker's base priority to `level` (init::work).
    pub fn set_level(&self, level: u8) -> Result<(), Error> {
        sys::thread_set_priority(&self.thread, level, Policy::Fifo)
    }

    /// Gives the worker the load of an instance of the record at `place`
    /// from `program`, named by `label` on init's channel (`give`).
    pub fn load(&self, place: usize, label: u64, program: Program<'static>) -> Result<(), Error> {
        let order = Order::Load {
            place,
            label,
            program,
        };
        self.give(order, None)
    }

    /// Gives the worker the teardown of `gone`, an instance that ended:
    /// its handles close in the worker (`give`).
    pub fn teardown(&self, gone: Instance) -> Result<(), Error> {
        self.give(Order::Teardown, Some(gone))
    }

    /// Gives the worker the kill of `gone`, an instance that went silent:
    /// the worker kills its process, then its handles close (`give`).
    pub fn kill(&self, gone: Instance) -> Result<(), Error> {
        self.give(Order::Kill, Some(gone))
    }

    /// Puts `order` and `gone` into the cell and wakes the worker. The
    /// main thread gives a job only once it took the outcome of the one
    /// before (`take`).
    fn give(&self, order: Order, gone: Option<Instance>) -> Result<(), Error> {
        assert_eq!(
            CELL.state.load(Ordering::Acquire),
            FREE,
            "one job at a time"
        );
        // SAFETY: FREE: the cell is the main thread's.
        unsafe {
            *CELL.order.get() = Some(order);
            *CELL.gone.get() = gone;
        }
        CELL.state.store(GIVEN, Ordering::Release);
        sys::notify(&self.wake, 1)
    }

    /// Once the worker did its job: the outcome of a load, None after a
    /// teardown.
    pub fn take(&self) -> Option<Option<Loaded>> {
        if CELL.state.load(Ordering::Acquire) != DONE {
            return None;
        }
        // SAFETY: DONE: the cell is the main thread's.
        let loaded = unsafe { (*CELL.loaded.get()).take() };
        CELL.state.store(FREE, Ordering::Release);
        Some(loaded)
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
        // SAFETY: still GIVEN: the cell is the worker's.
        let gone = unsafe { (*CELL.gone.get()).take() };
        let loaded = match order {
            Order::Load {
                place,
                label,
                program,
            } => Some(load(&TABLE[place], label, &program)),
            Order::Teardown => {
                // The handles close here, the cleanup at the worker's level.
                drop(gone);
                None
            }
            Order::Kill => {
                if let Some(gone) = gone {
                    // The process goes, then its handles (spec 7.7).
                    let _ = sys::process_kill(gone.process());
                    drop(gone);
                }
                None
            }
        };
        // SAFETY: still GIVEN: the cell is the worker's until the store.
        unsafe { *CELL.loaded.get() = loaded };
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
