// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Init's worker thread (spec 8, 13.4): it loads the instances of the
//! records of the table (rt::loader::spawn), tears down those that ended
//! and kills those that went silent, one job at a time, so that init's
//! main thread at 63 never waits for work that grows with the size of a
//! service, and never lets go of the last handles of an instance; once the
//! console's driver ended for good, it shows what is left of the kernel
//! log (`show_log`). For a driver with DMA objects it makes them at each
//! load and keeps a handle of its own to each, and at the teardown or
//! kill of an instance it first stops the device through windows of its
//! own (`quiesce`), then lets the objects go with the instance: the device
//! never writes frames the allocator gave back (spec 2, section 4). The
//! main thread puts a job into the cell
//! (`Worker::load`, `Worker::teardown`, `Worker::kill`,
//! `Worker::show_log`), sets the worker's level (init::work::Jobs) and
//! wakes it through the worker's channel; the worker does the job, leaves
//! its outcome in the cell and tells the main thread through its copy of
//! init's channel with NOTIFY and a label of its own, whose slot is at
//! WORKER_MAX. An instance's handles close here, so the cleanup of their
//! objects runs at the worker's level, below init (spec 7.7).

use crate::serve::Instance;
use abi::{Access, Error, Policy, Rights};
use bootimg::Program;
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use init::table::{Gate, MAX_DMA, Record, TABLE};
use init::work::{WORKER_IDLE, WORKER_MAX};
use proto_init::{OWN_ARGS_MAX, ServiceArgs};
use proto_wire::Writer;
use rt::handle::{Channel, Memory, Process, Resource, Thread};
use rt::loader::{self, SpawnParams, Spawned};
use rt::{Handle, Stack, mmio, sys};

/// Where the worker maps the objects of a program it loads, in init's
/// space: a window only the loader uses (rt::loader::load).
const LOADER_WINDOW: usize = 0x60_0000_0000;
/// Where the worker maps the page of a device it writes to stop the
/// device (`quiesce`).
const QUIESCE_WINDOW: usize = 0x61_0000_0000;
const PAGE: u64 = 4096;
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
    /// Stop the device of the record at `place`, then close the handles
    /// of the instance in the cell's `gone`.
    Teardown { place: usize },
    /// Kill the process of the instance in the cell's `gone`, stop the
    /// device of the record at `place`, then close its handles.
    Kill { place: usize },
    /// Show what is left of the kernel log (`show_log`).
    ShowLog,
}

/// What a load leaves the main thread: the instance, its thread not
/// started yet, whose start data hold its process, its thread, the console
/// when its record has one, its DMA objects and its arguments, with init's
/// own handles to the DMA objects; or why not.
pub type Loaded = Result<(Spawned, Kept), Error>;

/// Init's own handles to the DMA objects of an instance (Record::dma),
/// which go only after its device stopped.
pub type Kept = [Option<Handle<Memory>>; MAX_DMA];

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

/// Whether the worker took the job in the cell and does it (STATS).
static BEGUN: AtomicBool = AtomicBool::new(false);

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

    /// Gives the worker the teardown of `gone`, an instance of the record
    /// at `place` that ended: its device stops, then its handles close in
    /// the worker (`give`).
    pub fn teardown(&self, place: usize, gone: Instance) -> Result<(), Error> {
        self.give(Order::Teardown { place }, Some(gone))
    }

    /// Gives the worker the kill of `gone`, an instance of the record at
    /// `place` that went silent: the worker kills its process, stops its
    /// device, then its handles close (`give`).
    pub fn kill(&self, place: usize, gone: Instance) -> Result<(), Error> {
        self.give(Order::Kill { place }, Some(gone))
    }

    /// Gives the worker what is left of the kernel log to show, once the
    /// console's driver ended for good (`give`, spec 13.4).
    pub fn show_log(&self) -> Result<(), Error> {
        self.give(Order::ShowLog, None)
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
        BEGUN.store(false, Ordering::Relaxed);
        CELL.state.store(GIVEN, Ordering::Release);
        sys::notify(&self.wake, 1)
    }

    /// Whether the worker took the job it was given and does it.
    pub fn begun(&self) -> bool {
        BEGUN.load(Ordering::Relaxed)
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
        BEGUN.store(true, Ordering::Relaxed);
        let loaded = match order {
            Order::Load {
                place,
                label,
                program,
            } => Some(load(&TABLE[place], label, &program)),
            Order::Teardown { place } => {
                // The handles close here, the cleanup at the worker's level,
                // once the device stopped.
                if let Some(gone) = gone {
                    stop(place, gone);
                }
                None
            }
            Order::ShowLog => {
                show_log();
                None
            }
            Order::Kill { place } => {
                if let Some(gone) = gone {
                    // The process goes, its device stops, then its handles
                    // (spec 7.7).
                    let _ = sys::process_kill(gone.process());
                    stop(place, gone);
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
fn load(record: &Record, label: u64, program: &Program<'static>) -> Loaded {
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
    match start_data(record, &mut spawned) {
        Ok(kept) => Ok((spawned, kept)),
        Err(e) => {
            let _ = sys::process_kill(&spawned.process);
            Err(e)
        }
    }
}

/// The start data of an instance of `record` besides its process and
/// thread (spec 13.3): copies of the system resource with DEBUG and
/// TRANSFER under the name `console` and with KSTATS and TRANSFER under
/// the name `log` when the record has them; a copy of each of its DMA
/// objects, made here (`dma`), under its name; and the arguments,
/// ServiceArgs with the heartbeat and watchdog of a service (0 for a
/// client) and the own arguments: the physical address of each DMA
/// object, 8 bytes little-endian, then the record's. Returns init's own
/// handles to the DMA objects.
fn start_data(record: &Record, spawned: &mut Spawned) -> Result<Kept, Error> {
    for (wanted, name, right) in [
        (record.console, "console", Rights::DEBUG),
        (record.log, "log", Rights::KSTATS),
        (record.trace, "trace", Rights::KSTATS),
    ] {
        if wanted {
            let copy =
                sys::handle_duplicate(&view::<Resource>(RESOURCE), right | Rights::TRANSFER)?;
            // The third and fourth names of the start data fit.
            let _ = spawned.giver.give(name, copy.erase());
        }
    }
    let mut own = [0; OWN_ARGS_MAX];
    let mut kept: Kept = [const { None }; MAX_DMA];
    let resource = view::<Resource>(RESOURCE);
    for (i, d) in record.dma.iter().enumerate() {
        let (object, pa) = sys::mem_create_contiguous(d.size, d.uncached, &resource)?;
        let rights = Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER;
        let copy = sys::handle_duplicate(&object, rights)?;
        // The checks of the table keep the names apart from the others of
        // the start data, and MAX_DMA keeps them within its room.
        let _ = spawned.giver.give(d.name, copy.erase());
        own[8 * i..8 * i + 8].copy_from_slice(&pa.to_le_bytes());
        kept[i] = Some(object);
    }
    // The checks of the table keep the own arguments within OWN_ARGS_MAX.
    let len = 8 * record.dma.len() + record.args.len();
    own[8 * record.dma.len()..len].copy_from_slice(record.args);
    let watch = record.watch();
    let args = ServiceArgs {
        period_ns: watch.map_or(0, |w| w.period_ns),
        deadline_ns: watch.map_or(0, |w| w.deadline_ns),
        own: &own[..len],
    };
    let mut w = Writer::new();
    args.write(&mut w).map_err(|_| Error::InvalidArgs)?;
    spawned.giver.set_args(w.as_bytes())?;
    Ok(kept)
}

/// Reads of a register a stopping write wrote, at most, until it shows
/// the value written (Record::quiesce).
pub const SETTLE_READS: u32 = 1_000_000;

/// The records whose device did not stop, a bit each by place: their DMA
/// objects stay with init for good, and the main thread marks them broken
/// (`take_stuck`).
static STUCK: AtomicU64 = AtomicU64::new(0);

/// Whether the device of the record at `place` did not stop at the last
/// teardown or kill; the mark goes.
pub fn take_stuck(place: usize) -> bool {
    STUCK.fetch_and(!(1 << place), Ordering::AcqRel) & (1 << place) != 0
}

/// The end of `gone`, an instance of the record at `place` (spec 2,
/// section 4): its device stops (`quiesce`), then its handles close,
/// init's to its DMA objects among them. A device that did not stop keeps
/// the objects: init forgets its handles, so their frames never go back
/// to the allocator while the device may still write them, and the record
/// is marked broken (`take_stuck`).
fn stop(place: usize, mut gone: Instance) {
    let record = &TABLE[place];
    if quiesce(record) {
        #[cfg(feature = "dma-watch")]
        watch(record, &gone);
    } else {
        gone.keep_dma();
        STUCK.fetch_or(1 << place, Ordering::AcqRel);
    }
    gone.release();
}

/// Stops the device of `record` once an instance ended (Record::quiesce,
/// spec 2 section 4): each write, in its order, goes through a window init
/// makes over the page of the record's window that holds it, mapped at
/// QUIESCE_WINDOW, and is read back until its settled bits show its value,
/// so that it
/// reached the device and the device finished it [G34]; a write whose
/// register of Write::only_if shows none of its bits is skipped. False
/// when a window does not come or a write does not settle.
fn quiesce(record: &Record) -> bool {
    let resource = view::<Resource>(RESOURCE);
    let own = view::<Process>(OWN);
    for q in record.quiesce {
        if let Some(g) = q.only_if
            && !gate_open(record, g)
        {
            continue;
        }
        let Some(w) = record.windows.iter().find(|w| w.name == q.window) else {
            return false;
        };
        let page = q.offset & !(PAGE - 1);
        let Ok(window) = sys::device_window_create(&resource, w.base + page, PAGE) else {
            return false;
        };
        if sys::mem_map(&own, &window, 0, PAGE, QUIESCE_WINDOW, Access::ReadWrite).is_err() {
            return false;
        }
        let at = QUIESCE_WINDOW + (q.offset - page) as usize;
        // SAFETY: the window maps the device's page at QUIESCE_WINDOW as
        // device memory, read and write; `at` is a register of q.bits bits
        // within it, aligned to them (the checks of the table).
        let settled = unsafe {
            if q.bits == 8 {
                mmio::write8(at, q.value as u8);
                (0..SETTLE_READS).any(|_| u32::from(mmio::read8(at)) & q.settled == q.value)
            } else {
                mmio::write32(at, q.value);
                (0..SETTLE_READS).any(|_| mmio::read32(at) & q.settled == q.value)
            }
        };
        // SAFETY: only the worker maps and uses QUIESCE_WINDOW.
        let _ = unsafe { sys::mem_unmap(&own, QUIESCE_WINDOW, PAGE) };
        if !settled {
            return false;
        }
    }
    true
}

/// Whether the register of `g` shows one of its bits (Write::only_if),
/// read through a window of init's own at QUIESCE_WINDOW; a register that
/// cannot be read counts as open, so the write goes and must settle.
fn gate_open(record: &Record, g: Gate) -> bool {
    let Some(w) = record.windows.iter().find(|w| w.name == g.window) else {
        return true;
    };
    let page = g.offset & !(PAGE - 1);
    let resource = view::<Resource>(RESOURCE);
    let own = view::<Process>(OWN);
    let Ok(window) = sys::device_window_create(&resource, w.base + page, PAGE) else {
        return true;
    };
    if sys::mem_map(&own, &window, 0, PAGE, QUIESCE_WINDOW, Access::Read).is_err() {
        return true;
    }
    // SAFETY: the window maps the register's page at QUIESCE_WINDOW as
    // device memory; the register is a word within it (the checks of the
    // table).
    let value = unsafe { mmio::read32(QUIESCE_WINDOW + (g.offset - page) as usize) };
    // SAFETY: only the worker maps and uses QUIESCE_WINDOW.
    let _ = unsafe { sys::mem_unmap(&own, QUIESCE_WINDOW, PAGE) };
    value & g.bits != 0
}

/// Where the worker maps a DMA object it watches (`watch`).
#[cfg(feature = "dma-watch")]
const WATCH_WINDOW: usize = 0x62_0000_0000;
/// How long `watch` watches.
#[cfg(feature = "dma-watch")]
const WATCH_NS: u64 = 300_000_000;

/// The probe of a stop (feature `dma-watch`, console-restart-vz): with the
/// device stopped, the first DMA object of `gone` is read whole, then again
/// WATCH_NS later, while xtask types into the console; init says whether
/// the device wrote it meanwhile. Init only reads the object.
#[cfg(feature = "dma-watch")]
fn watch(record: &Record, gone: &Instance) {
    let (Some(object), Some(d)) = (gone.dma(), record.dma.first()) else {
        return;
    };
    let own = view::<Process>(OWN);
    if sys::mem_map(&own, object, 0, d.size, WATCH_WINDOW, Access::Read).is_err() {
        return;
    }
    let sum = || {
        (0..d.size as usize / 4).fold(0xcbf2_9ce4_8422_2325u64, |h, i| {
            // SAFETY: the object is mapped read-only at WATCH_WINDOW, d.size
            // bytes; the read is a word within it. The wait between the two
            // sums is a system call, which the compiler moves no load over.
            let word = unsafe { ((WATCH_WINDOW + 4 * i) as *const u32).read() };
            (h ^ u64::from(word)).wrapping_mul(0x100_0000_01b3)
        })
    };
    let before = sum();
    let deadline = rt::time::ticks_to_ns(rt::time::now()).saturating_add(WATCH_NS);
    if let Ok(channel) = sys::channel_create(1)
        && let Ok(waiter) = rt::wait::Waiter::new(&channel, 0, 1)
    {
        let _ = waiter.receive_until(&channel, deadline);
    }
    let after = sum();
    // SAFETY: only the worker maps and uses WATCH_WINDOW.
    let _ = unsafe { sys::mem_unmap(&own, WATCH_WINDOW, d.size) };
    let what = if before == after {
        "unchanged"
    } else {
        "written"
    };
    rt::println!(
        "init: {} DMA memory {what} for 300 ms after its stop",
        record.name
    );
}

/// Shows what is left of the kernel log once its reader, the console's
/// driver, ended for good (spec 13.4, 16.3): batches of LOG through the
/// system resource, then the line of the records lost and the text of each
/// record (uart::log::text) through debug_write, a call each, while the
/// kernel says records are left, a ring's worth at most. The main thread
/// gives it at WORKER_IDLE, below every cleanup of the driver's instance,
/// so the port is the kernel's and the texts go out at once (spec 3.2).
fn show_log() {
    let resource = view::<Resource>(RESOURCE);
    let mut records = [[0; abi::LOG_RECORD]; abi::LOG_BATCH];
    for _ in 0..64 / abi::LOG_BATCH + 1 {
        let Ok(batch) = sys::log_take(&resource, &mut records) else {
            return;
        };
        uart::log::text(&records, batch, |bytes| {
            let _ = sys::debug_write(&resource, bytes);
        });
        if batch.left == 0 {
            return;
        }
    }
}
