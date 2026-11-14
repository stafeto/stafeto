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
use init::table::{
    self, BOOT_IMAGE, CLOCK_SERVICE, Confirm, ENTROPY_SERVICE, Gate, MAX_DMA, PACKAGE_SERVICE,
    PROCESS_SERVICE, RAM_SERVICE, Record, SEED, Write,
};
use init::work::{WORKER_IDLE, WORKER_MAX};
use proto_init::{OWN_ARGS_MAX, ServiceArgs};
use proto_wire::Writer;
use rt::handle::{Channel, Memory, Process, Resource, Thread};
use rt::loader::{self, SpawnParams, Spawned};
use rt::startup::Giver;
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
        quota: u64,
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

// The check of the table counts the names of the start data against the
// room of the giver.
const _: () = assert!(init::table::START_DATA_MAX == rt::startup::NAMES_MAX);

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
/// channel, the system resource, the worker's channel, its copy of init's
/// channel, the boot image and the page of the boot seed. The main thread
/// keeps the first four for good; the worker owns the last three.
static HANDLES: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];
const OWN: usize = 0;
const CHANNEL: usize = 1;
const RESOURCE: usize = 2;
const WAKE: usize = 3;
const TELL: usize = 4;
const BOOT: usize = 5;
const SEED_PAGE: usize = 6;

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
    /// the main thread through a copy of `channel` with NOTIFY and `label`;
    /// it keeps `boot`, the boot image, for the start data of the process
    /// service, and `seed`, the page of the boot seed, for that of the
    /// entropy service. BAD_STATE once a worker started: the cell is one; the
    /// other errors are those of the calls.
    pub fn start(
        own: &Handle<Process>,
        channel: &Handle<Channel>,
        resource: &Handle<Resource>,
        label: u64,
        boot: Handle<Memory>,
        seed: Option<Handle<Memory>>,
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
            (BOOT, boot.into_raw()),
            (SEED_PAGE, seed.map_or(abi::Handle(0), Handle::into_raw)),
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
    /// from `program` with `quota` bytes, named by `label` on init's
    /// channel (`give`).
    pub fn load(
        &self,
        place: usize,
        label: u64,
        program: Program<'static>,
        quota: u64,
    ) -> Result<(), Error> {
        let order = Order::Load {
            place,
            label,
            program,
            quota,
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
                quota,
            } => Some(load(&table::table()[place], label, &program, quota)),
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

/// The CPU mask of an instance of `record` (process_create x8, kernel spec
/// 13.4): the mask of the record cut to the CPUs that are up. A record none
/// of whose CPUs is up gets all that are, and a line says so.
pub fn cpus_of(record: &Record) -> u8 {
    let up = sys::cpu_info(0).map_or(1, |info| (1u32 << info.cpus.clamp(1, 8)) - 1);
    let (mask, kept) = init::table::on_cpus(record.cpus, up as u8);
    if !kept {
        rt::println!(
            "init: {} names no CPU that is up: it runs on all of them",
            record.name
        );
    }
    mask
}

/// Loads an instance of `record` from `program` with the label `label` on
/// init's channel (rt::loader::spawn): `quota` (the record's, and more for
/// the process service, serve.rs), room for handles, ceiling and priority
/// from the record, the notification of its end at its base priority
/// (spec 13.4), and its start data (`start_data`). An instance whose start
/// data could not be made is killed; its thread never ran.
fn load(record: &Record, label: u64, program: &Program<'static>, quota: u64) -> Loaded {
    // A device a stop turned off comes back before its next instance runs.
    if !init::device::start(record, &mut Hw) {
        return Err(Error::BadState);
    }
    if !record.start.is_empty() {
        rt::println!("init: {} device command word written", record.name);
    }
    let channel = view::<Channel>(CHANNEL);
    let cpus = cpus_of(record);
    let params = SpawnParams {
        channel: &channel,
        label,
        notice: record.priority,
        quota,
        handle_limit: record.handle_limit,
        ceiling: record.ceiling,
        priority: record.priority,
        policy: Policy::Fifo,
        // The driver of the console and its log (the record that has `log`)
        // runs on CPU 1 when the machine has one and its mask allows it: its
        // requests come from the shell on CPU 0 across CPUs (SMP stage 4);
        // with one CPU, or a mask without CPU 1 (the image `cpu0`), the
        // loader leaves it on the CPU of its mask.
        cpu: init::table::first_cpu(record.log, cpus),
        shares: sys::Shares {
            threads: record.shares.threads,
            timers: record.shares.timers,
        },
        cpus,
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
/// thread (spec 13.3): the copies of the system resource of `resources`;
/// a copy of each of its DMA objects, made here (`dma`), under its name;
/// the boot image, read-only, for the process service, the RAM file
/// service, the clock service and the package service (BOOT_IMAGE); the
/// page of the boot seed for the entropy service (SEED); and
/// the arguments (`set_args`) with the physical address of each DMA
/// object, 8 bytes little-endian, before the record's. Returns init's own
/// handles to the DMA objects.
fn start_data(record: &Record, spawned: &mut Spawned) -> Result<Kept, Error> {
    let resource = view::<Resource>(RESOURCE);
    resources(record, &mut spawned.giver, &resource)?;
    if record.name == PROCESS_SERVICE
        || record.name == RAM_SERVICE
        || record.name == CLOCK_SERVICE
        || record.name == PACKAGE_SERVICE
    {
        let image =
            sys::handle_duplicate(&view::<Memory>(BOOT), Rights::MAP_READ | Rights::TRANSFER)?;
        // The checks of the table keep the name apart from the others.
        let _ = spawned.giver.give(BOOT_IMAGE, image.erase());
    }
    if record.name == ENTROPY_SERVICE && HANDLES[SEED_PAGE].load(Ordering::Relaxed) != 0 {
        let rights = Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER;
        let page = sys::handle_duplicate(&view::<Memory>(SEED_PAGE), rights)?;
        // The checks of the table keep the name apart from the others.
        let _ = spawned.giver.give(SEED, page.erase());
    }
    let mut own = [0; OWN_ARGS_MAX];
    let mut kept: Kept = [const { None }; MAX_DMA];
    for (i, d) in record.dma.iter().enumerate() {
        let (object, pa) = sys::mem_create_contiguous(d.size, d.uncached, &resource)?;
        let mut rights = Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER;
        if d.duplicate {
            rights = rights | Rights::DUPLICATE;
        }
        let copy = sys::handle_duplicate(&object, rights)?;
        // The checks of the table keep the names apart from the others of
        // the start data, MAX_DMA keeps them within its room, and
        // START_DATA_MAX keeps all of them within the giver's.
        let _ = spawned.giver.give(d.name, copy.erase());
        own[8 * i..8 * i + 8].copy_from_slice(&pa.to_le_bytes());
        kept[i] = Some(object);
    }
    set_args(record, &mut spawned.giver, &own[..8 * record.dma.len()])?;
    Ok(kept)
}

/// Copies of `resource`, the system resource, in `giver` for `record`:
/// with DEBUG and TRANSFER under the name `console`, with KSTATS and
/// TRANSFER under `log` and `trace`, when the record has them. The main
/// thread makes them for a POSIX process (serve.rs), the worker for the
/// others.
pub fn resources(
    record: &Record,
    giver: &mut Giver,
    resource: &Handle<Resource>,
) -> Result<(), Error> {
    for (wanted, name, right) in [
        (record.console, "console", Rights::DEBUG),
        (record.log, "log", Rights::KSTATS),
        (record.trace, "trace", Rights::KSTATS),
    ] {
        if wanted {
            // The process service gives the programs its loaders start a
            // console of their own (5c): its copy may be copied.
            let copy_right = if name == "console" && record.name == PROCESS_SERVICE {
                Rights::DUPLICATE
            } else {
                Rights::NONE
            };
            let copy = sys::handle_duplicate(resource, right | Rights::TRANSFER | copy_right)?;
            // The names of the start data fit the giver (NAMES_MAX).
            let _ = giver.give(name, copy.erase());
        }
    }
    Ok(())
}

/// The arguments of `record` in `giver`: ServiceArgs with the heartbeat
/// and watchdog of a service (0 for a client) and the own arguments,
/// `first` and then the record's.
pub fn set_args(record: &Record, giver: &mut Giver, first: &[u8]) -> Result<(), Error> {
    let mut own = [0; OWN_ARGS_MAX];
    // The checks of the table keep the own arguments within OWN_ARGS_MAX.
    let len = first.len() + record.args.len();
    own[..first.len()].copy_from_slice(first);
    own[first.len()..len].copy_from_slice(record.args);
    let watch = record.watch();
    let args = ServiceArgs {
        period_ns: watch.map_or(0, |w| w.period_ns),
        deadline_ns: watch.map_or(0, |w| w.deadline_ns),
        own: &own[..len],
    };
    let mut w = Writer::new();
    args.write(&mut w).map_err(|_| Error::InvalidArgs)?;
    giver.set_args(w.as_bytes())
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
    let record = &table::table()[place];
    let stopped = init::device::stop(record, &mut Hw);
    if !record.release.is_empty() {
        let what = if stopped {
            "stopped and confirmed"
        } else {
            "did not stop, its DMA memory stays kept"
        };
        rt::println!("init: {} device {what}", record.name);
    }
    if stopped {
        #[cfg(feature = "dma-watch")]
        watch(record, &gone);
    } else {
        gone.keep_dma();
        STUCK.fetch_or(1 << place, Ordering::AcqRel);
    }
    gone.release();
}

/// The longest the worker waits for the register of a confirmation
/// (Write::confirm): above the 2000 ms reset timeout an ENA reports in its
/// capabilities (t4g), so a device that is slow but alive confirms, and a dead
/// one lets the stop go on after a bounded wait. The wait is the worker's: init's
/// main thread does not wait for it.
const CONFIRM_NS: u64 = 2_500_000_000;

/// The register access of the worker (init::device::Regs): each access maps the
/// page of the record's window that holds the register at QUIESCE_WINDOW.
struct Hw;

impl init::device::Regs for Hw {
    fn write(&mut self, record: &Record, q: &Write) -> bool {
        let resource = view::<Resource>(RESOURCE);
        let own = view::<Process>(OWN);
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
                q.settled == 0 || (0..SETTLE_READS).any(|_| mmio::read32(at) & q.settled == q.value)
            }
        };
        // SAFETY: only the worker maps and uses QUIESCE_WINDOW.
        let _ = unsafe { sys::mem_unmap(&own, QUIESCE_WINDOW, PAGE) };
        settled
    }

    /// Reads the register of `c` through a window of init's own at QUIESCE_WINDOW
    /// until it shows its state or CONFIRM_NS passed.
    fn confirmed(&mut self, record: &Record, c: Confirm) -> bool {
        let Some(w) = record.windows.iter().find(|w| w.name == c.window) else {
            return false;
        };
        let page = c.offset & !(PAGE - 1);
        let resource = view::<Resource>(RESOURCE);
        let own = view::<Process>(OWN);
        let Ok(window) = sys::device_window_create(&resource, w.base + page, PAGE) else {
            return false;
        };
        if sys::mem_map(&own, &window, 0, PAGE, QUIESCE_WINDOW, Access::Read).is_err() {
            return false;
        }
        let at = QUIESCE_WINDOW + (c.offset - page) as usize;
        let began = rt::time::now();
        let shown = loop {
            // SAFETY: the window maps the register's page at QUIESCE_WINDOW as
            // device memory, read; the register is a word within it (the checks
            // of the table).
            if unsafe { mmio::read32(at) } & c.mask == c.value {
                break true;
            }
            if rt::time::ticks_to_ns(rt::time::now().wrapping_sub(began)) >= CONFIRM_NS {
                break false;
            }
        };
        // SAFETY: only the worker maps and uses QUIESCE_WINDOW.
        let _ = unsafe { sys::mem_unmap(&own, QUIESCE_WINDOW, PAGE) };
        shown
    }

    /// Reads the register of `g` through a window of init's own at
    /// QUIESCE_WINDOW; a register that cannot be read counts as open, so the
    /// write goes and must settle.
    fn gate_open(&mut self, record: &Record, g: Gate) -> bool {
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
/// record (uart::log::text) through debug_write, in calls of 64 bytes at most, while the
/// kernel says records are left, a ring's worth at most. The main thread
/// gives it at WORKER_IDLE, below every cleanup of the driver's instance,
/// so the port is the kernel's and the texts go out at once (spec 3.2).
fn show_log() {
    let resource = view::<Resource>(RESOURCE);
    let mut records = [[0; abi::LOG_RECORD]; abi::LOG_BATCH];
    let mut lines = console_line::Lines::new();
    // What could not be shown: the calls that debug_write refused, and a
    // batch that LOG did not give.
    let lost = core::cell::Cell::new(0u32);
    // An assembled line is up to console_line::LINE_MAX bytes, a call takes
    // 64: the pieces go in calls of their own.
    let mut put = |bytes: &[u8]| {
        for piece in console_line::calls(bytes) {
            if sys::debug_write(&resource, piece).is_err() {
                lost.set(lost.get() + 1);
            }
        }
    };
    for _ in 0..64 / abi::LOG_BATCH + 1 {
        let Ok(batch) = sys::log_take(&resource, &mut records) else {
            lost.set(lost.get() + 1);
            break;
        };
        uart::log::text(&records, batch, &mut lines, &mut put);
        if batch.left == 0 {
            break;
        }
    }
    lines.finish(&mut put);
    if lost.get() > 0 {
        rt::println!("init: the log show lost {} calls", lost.get());
    }
}
