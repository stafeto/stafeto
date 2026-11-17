// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The disk service over an NVMe controller (a PCI function of class 0x010802): the protocol
//! of the Virtio driver (proto_blk, services/virtio-blk) over the library `lib/nvme`, so the
//! package service (services/pkgd) keeps its store on an NVMe disk, an EBS volume on EC2 or a
//! drive of QEMU, and finds the packages after a reboot.
//!
//! Init finds the function by its PCI id and index when it starts (table `At::Bar`,
//! `At::Config`) and gives the service the windows `bar` (BAR 0, 4 pages) and `ecam` (the
//! function's page of configuration), the bindings `irq0` and `irq1` of the two MSI-X
//! vectors, and two contiguous DMA objects: `nvme` (uncached, 32 KiB: the queues, the PRP
//! lists, the Identify buffer) and `cells` (cached, 64 KiB: four cells of 16 KiB), their
//! physical addresses the first two words of the own arguments. The DMA of the device is
//! coherent on EC2 (no SMMU in the IORT, the Nitro PCIe is I/O-coherent) and under QEMU's
//! TCG, so the cells need no cache maintenance, only the barriers of the library.
//!
//! The service has one thread. The library does the controller's work in steps of one
//! register access (`Nvme::poll`); a request goes to the queue in the call that takes it, and
//! the completion is found by the step that an interrupt of vector 1 (or of vector 0), the
//! timer or the heartbeat starts. While any command is with the controller, the timer looks at
//! the queue every 500 us (the way the ENA service polls a silent vector), and after a reset in
//! place it runs the bring-up the same way until the queues are up; with no command out and the
//! controller up the service sleeps until a request, an interrupt or the heartbeat comes. Without MSI-X (no capability, no LPI for a binding, a table not in BAR 0) the
//! controller runs without vectors and the timer is the only way a completion is found.
//!
//! The data of a write are copied from the client's cell of the shared buffer into the cell of
//! the DMA object before the command goes, and the data of a read from there into the
//! client's cell in the step of TAKE, one copy of 16 KiB at most in a step, through raw
//! pointers: a client that changes its cell meanwhile spoils only its own bytes. The
//! controller addresses physical memory with no SMMU (spec 9): the driver is in the trusted
//! base, and the PRP lists are those the library made once from the object's own address.
//! Init stops the controller (a normal shutdown, then CC = 0) before it lets the DMA objects of
//! an instance that ended go.
//!
//! A disk whose blocks are 4 KiB reports `block` 4096, and a request that does not begin and
//! end on a block (a sector and a count that are multiples of 8) is INVALID.

#![no_std]
#![no_main]

use abi::{Access, Error, Rights, Source};
use core::alloc::{GlobalAlloc, Layout};
use core::fmt;
use nvme::mmio::Bar;
use nvme::{Cause, Completion, Event, Nvme, Outcome as NvmeOutcome, Platform, Region, Reject};
use proto_blk::{
    BUFFER_SIZE, CELL_BYTES, FLAG_FLUSH, Info, Io, Key, Method, SECTOR, VERSION, code, read_buffer,
};
use proto_init::ServiceArgs;
use proto_wire::{Status, long};
use rt::handle::{Channel, Interrupt, Memory, Outgoing, Process, Resource, Timer};
use rt::service::{
    Answer, Config, Heartbeat, LongOps, LongSession, Notice, Request, Service, Session,
};
use rt::{Handle, sys, time};
use virtio_blk::{Cells, Completion as Told, Kind, Outcome, Refusal, Taken, dma::FLUSH_PLACE};

rt::entry!(main);

/// The library of the driver's decisions links the Virtio crate, which may ask for a heap this
/// service never uses: every allocation fails.
struct NoHeap;

#[global_allocator]
static ALLOCATOR: NoHeap = NoHeap;

// SAFETY: every allocation fails with a null pointer, which the contract allows; nothing is
// ever handed out to come back.
unsafe impl GlobalAlloc for NoHeap {
    unsafe fn alloc(&self, _: Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

/// Where the service maps its DMA objects, the function's page of configuration, BAR 0 and
/// the client's shared buffer.
const NVME_AT: usize = 0x10_0000_0000;
const CELLS_AT: usize = 0x10_0100_0000;
const ECAM_AT: usize = 0x10_2000_0000;
const BAR_AT: usize = 0x10_3000_0000;
const BUFFER_AT: usize = 0x10_4000_0000;
const PAGE: u64 = 4096;
/// The pages of BAR 0 the window holds: the registers and the doorbells, the MSI-X table and
/// its pending bits (16 KiB on EBS and on QEMU).
const BAR_PAGES: u64 = 4;
/// The sessions of the service's channel and the operations that wait at once.
const SESSIONS: usize = 2;
const OPERATIONS: usize = 8;
/// The label of the service's timer on its channel (a timer's notification names its source,
/// so it never meets a session's label).
const TIMER_LABEL: u64 = 1;
/// The look at the queue while a command is out and nothing has come: 500 us.
const POLL_NS: u64 = 500_000;
/// The tick of the bring-up, which has no request to take and sleeps on a channel of its own.
const BRINGUP_TICK_NS: u64 = 200_000;
/// The bring-up may take this long (the controller's own limits are inside it), and init is
/// told the service lives at least every `BEAT_NS` on the way.
const BRINGUP_LIMIT_NS: u64 = 60_000_000_000;
const BEAT_NS: u64 = 200_000_000;
/// How long the ITS may take to run the commands of an event before the table is written.
const MAPPED_LIMIT_NS: u64 = 2_000_000_000;
/// The steps one wake of the service makes at most: each is one register access or a bounded
/// number of stores, and a wake that has more to do arms the timer to go on at once.
const STEPS: usize = 8;
/// The vectors: 0 for the admin queue, 1 for the pair.
const VECTORS: usize = 2;
const IO_VECTOR: u16 = 1;

/// The name of the record the identity is checked for, in the line of a refusal.
const DATA_NAME: &str = "datadisk";

/// The codes of a start that failed.
const NO_START_DATA: u64 = 1;
const NOT_REGISTERED: u64 = 3;
const NOT_MAPPED: u64 = 4;
const STOPPED: u64 = 5;
const NO_DEVICE: u64 = 6;
const BUDGET: u64 = 10;
/// The controller is down for good (the library's `Failed`): init starts the service again.
const FAILED: u64 = 8;

fn word(own: &[u8], at: usize) -> u64 {
    own.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

/// The platform of the library: BAR 0, the clock, the barriers, the console.
#[derive(Clone, Copy)]
struct Hw {
    bar: Bar,
}

impl Platform for Hw {
    fn read32(&self, offset: u32) -> u32 {
        self.bar.read32(offset)
    }

    fn write32(&self, offset: u32, value: u32) {
        self.bar.write32(offset, value);
    }

    fn now_ns(&self) -> u64 {
        time::ticks_to_ns(time::now())
    }

    fn wmb(&self) {
        rt::dma::wmb();
    }

    fn rmb(&self) {
        rt::dma::rmb();
    }

    fn log(&self, line: fmt::Arguments<'_>) {
        rt::println!("{line}");
    }
}

fn heartbeat(parent: &Handle<Channel>) {
    let _ = sys::send(parent, &proto_init::Method::Heartbeat.header().bytes());
}

fn now_ns() -> u64 {
    time::ticks_to_ns(time::now())
}

/// The messages of the two vectors from the bindings, and the capability of the function when
/// the table can be used: it must lie in BAR 0 inside the window and hold both vectors.
fn msi_plan(
    irq: &[Option<Handle<Interrupt>>; VECTORS],
) -> Option<(pci::Msix, [(u64, u32); VECTORS])> {
    // SAFETY: the page of the function is mapped at ECAM_AT as device memory; the offsets the
    // capability list gives are inside it (`pci::msix` stops at 48 capabilities).
    let found = pci::msix(|offset| unsafe { rt::mmio::read32(ECAM_AT + offset) });
    let Some(msix) = found else {
        rt::println!("nvme: no MSI-X capability: polling");
        return None;
    };
    let room = u64::from(msix.offset) + (VECTORS * pci::MSIX_ENTRY) as u64;
    if msix.bar != 0 || usize::from(msix.vectors) < VECTORS || room > BAR_PAGES * PAGE {
        rt::println!(
            "nvme: the MSI-X table is not where the window holds it (BAR {}, offset {:#x}, {} vectors): polling",
            msix.bar,
            msix.offset,
            msix.vectors
        );
        return None;
    }
    let mut messages = [(0, 0); VECTORS];
    for (v, binding) in irq.iter().enumerate() {
        let Some(binding) = binding else {
            rt::println!("nvme: no binding for vector {v}: polling");
            return None;
        };
        match sys::irq_info(binding) {
            Ok(info) if info.lpi => messages[v] = (info.msi_address, info.msi_data as u32),
            _ => {
                rt::println!("nvme: the binding of vector {v} is no LPI: polling");
                return None;
            }
        }
    }
    Some((msix, messages))
}

/// Waits (at most `MAPPED_LIMIT_NS`, with a heartbeat on the way) until the ITS has run the
/// commands of each binding's event: `irq_ack` says WOULD_BLOCK until it has. A message the
/// device writes before that is lost, so the table is written once it is done.
fn wait_mapped(
    irq: &[Option<Handle<Interrupt>>; VECTORS],
    parent: &Handle<Channel>,
    sleeper: &Sleeper,
) -> bool {
    let began = now_ns();
    for binding in irq.iter().flatten() {
        while let Err(Error::WouldBlock) = sys::irq_ack(binding) {
            let now = now_ns();
            if now - began > MAPPED_LIMIT_NS {
                rt::println!("nvme: the mapping of a vector is not done after 2 s: polling");
                return false;
            }
            heartbeat(parent);
            sleeper.sleep(BRINGUP_TICK_NS);
        }
    }
    true
}

/// The MSI-X table in the order a driver that leaves nothing to the device's guess writes it:
/// Enable with Function Mask, each entry masked, its address and data written and the data
/// read back, then each entry unmasked and Function Mask cleared. The function's first
/// capability word is read and written whole: the ID and next pointer are read-only.
fn write_table(bar: Bar, msix: &pci::Msix, messages: [(u64, u32); VECTORS]) {
    let control = |mask: bool| {
        // SAFETY: the page of the function is mapped at ECAM_AT, read and write, as device
        // memory; `msix.at` is the first word of its MSI-X capability.
        unsafe {
            let mut head = rt::mmio::read32(ECAM_AT + msix.at);
            head &= !(pci::MSIX_ENABLE | pci::MSIX_FUNCTION_MASK);
            head |= pci::MSIX_ENABLE;
            if mask {
                head |= pci::MSIX_FUNCTION_MASK;
            }
            rt::mmio::write32(ECAM_AT + msix.at, head);
        }
    };
    let entry = |v: usize, word: u32| msix.offset + (v * pci::MSIX_ENTRY) as u32 + 4 * word;
    control(true);
    for (v, (address, data)) in messages.into_iter().enumerate() {
        bar.write32(entry(v, 3), pci::MSIX_MASKED);
        bar.write32(entry(v, 0), address as u32);
        bar.write32(entry(v, 1), (address >> 32) as u32);
        bar.write32(entry(v, 2), data);
        let back = bar.read32(entry(v, 2));
        if back != data {
            rt::println!("nvme: msix vector {v} data reads back {back:#x}, wrote {data:#x}");
        }
    }
    for v in 0..VECTORS {
        bar.write32(entry(v, 3), 0);
    }
    control(false);
}

/// A channel of the bring-up's own with a timer on it: the service sleeps there while the
/// controller works, so the requests that come wait on the service's channel untouched.
struct Sleeper {
    channel: Handle<Channel>,
    timer: Handle<Timer>,
}

impl Sleeper {
    fn new(level: u8) -> Option<Sleeper> {
        let channel = sys::channel_create(level).ok()?;
        let view = sys::handle_label(&channel, Rights::RECEIVE, TIMER_LABEL, level).ok()?;
        let timer = sys::timer_create(&view, level).ok()?;
        Some(Sleeper { channel, timer })
    }

    fn sleep(&self, ns: u64) {
        let _ = sys::timer_set(&self.timer, now_ns() + ns);
        let _ = sys::receive(&self.channel);
    }
}

/// The text of a field of Identify (ASCII padded with spaces or zeros).
struct Field<'a>(&'a [u8]);

impl fmt::Display for Field<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let end = self
            .0
            .iter()
            .rposition(|&b| b != b' ' && b != 0)
            .map_or(0, |i| i + 1);
        for &b in &self.0[..end] {
            let c = if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '?'
            };
            write!(f, "{c}")?;
        }
        Ok(())
    }
}

/// Runs the library to `Up`, with a heartbeat to init on the way; false when the controller
/// failed or took too long.
fn bring_up(nvme: &mut Nvme<Hw>, parent: &Handle<Channel>, sleeper: &Sleeper) -> bool {
    let began = now_ns();
    let mut beat = began;
    loop {
        let now = now_ns();
        if now - began > BRINGUP_LIMIT_NS {
            rt::println!("nvme: the bring-up took too long");
            return false;
        }
        if now - beat > BEAT_NS {
            beat = now;
            heartbeat(parent);
        }
        match nvme.poll() {
            Event::Up => return true,
            Event::Failed(why) => {
                rt::println!("nvme: the controller failed to come up: {why:?}");
                return false;
            }
            Event::Idle => sleeper.sleep(BRINGUP_TICK_NS),
            _ => {}
        }
    }
}

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let (Ok(queues), Ok(cell_object)) = (s.take::<Memory>("nvme"), s.take::<Memory>("cells"))
    else {
        return NO_START_DATA;
    };
    let serve = rt::budget::take(&mut s, rt::budget::SERVE);
    let args = ServiceArgs::read(s.args()).ok();
    let own = args.map_or(&[][..], |a| a.own);
    let (queues_pa, cells_pa) = (word(own, 0), word(own, 8));
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return NOT_REGISTERED;
    };
    let Ok(mut got) = rt::service::register(&s.parent, &channel) else {
        return NOT_REGISTERED;
    };
    let (Ok(bar), Ok(ecam)) = (got.take::<Memory>("bar"), got.take::<Memory>("ecam")) else {
        return NO_DEVICE;
    };
    let irq = [
        got.take::<Interrupt>("irq0").ok(),
        got.take::<Interrupt>("irq1").ok(),
    ];
    let rw = Access::ReadWrite;
    let queues_len = sys::memory_info(&queues).map_or(0, |info| info.size);
    let cells_len = sys::memory_info(&cell_object).map_or(0, |info| info.size);
    let mapped = sys::mem_map(&s.process, &queues, 0, queues_len, NVME_AT, rw)
        .and_then(|()| sys::mem_map(&s.process, &cell_object, 0, cells_len, CELLS_AT, rw))
        .and_then(|()| sys::mem_map(&s.process, &ecam, 0, PAGE, ECAM_AT, rw))
        .and_then(|()| sys::mem_map(&s.process, &bar, 0, BAR_PAGES * PAGE, BAR_AT, rw));
    if queues_pa == 0 || cells_pa == 0 || mapped.is_err() {
        return NOT_MAPPED;
    }
    rt::println!("nvme: dma queues {queues_pa:#x} cells {cells_pa:#x}");
    // SAFETY: the window `bar` maps BAR 0 at BAR_AT for BAR_PAGES pages (init's table).
    let hw = Hw {
        bar: unsafe { Bar::new(BAR_AT, (BAR_PAGES * PAGE) as usize) },
    };
    let Some(sleeper) = Sleeper::new(level) else {
        return NOT_REGISTERED;
    };
    // MSI-X first: the table is written before the controller may raise a vector.
    let plan = msi_plan(&irq).filter(|_| wait_mapped(&irq, &s.parent, &sleeper));
    if let Some((msix, messages)) = &plan {
        write_table(hw.bar, msix, *messages);
    }
    let config = nvme::Config {
        vector: plan.as_ref().map(|_| IO_VECTOR),
        ..nvme::Config::default()
    };
    // SAFETY: the objects are mapped at NVME_AT and CELLS_AT for their whole length, uncached
    // and cached as init made them, and this service alone uses them; the controller addresses
    // them at the physical addresses init gave in the own arguments, and the DMA is coherent.
    let opened = unsafe {
        Nvme::open(
            hw,
            Region {
                va: NVME_AT,
                pa: queues_pa,
                len: queues_len as usize,
            },
            Region {
                va: CELLS_AT,
                pa: cells_pa,
                len: cells_len as usize,
            },
            config,
        )
    };
    let Ok(mut controller) = opened else {
        rt::println!("nvme: the objects do not fit the driver");
        return NO_DEVICE;
    };
    if !bring_up(&mut controller, &s.parent, &sleeper) {
        return NO_DEVICE;
    }
    let Some(found) = controller.info().copied() else {
        return NO_DEVICE;
    };
    let block = 1u32 << found.block_shift;
    let sectors = found.blocks << (found.block_shift - 9);
    rt::println!(
        "nvme: {} fw {} sn {}, {} blocks of {} bytes ({} sectors), mdts {} ({} bytes), vwc {}, nn {}, msi {}, mqes {}, to {}, dstrd {}",
        Field(&found.model),
        Field(&found.firmware),
        Field(&found.serial),
        found.blocks,
        block,
        sectors,
        found.mdts,
        found.max_transfer,
        u8::from(found.vwc),
        found.nn,
        if plan.is_some() { "yes" } else { "no" },
        found.cap.mqes,
        found.cap.to,
        found.cap.dstrd
    );
    // The identity of the volume, before any request: a controller that is not the one the record
    // names (the ESP of a machine, the root volume of an instance) is registered and refuses every
    // operation, so no client reads it, writes it or formats it.
    let want = nvme_blk::Want::parse(own);
    let refused = !nvme_blk::matches(&found.serial, &found.vendor_name, &want);
    if refused {
        rt::println!("nvme: {DATA_NAME} is not the data volume, left alone");
    }
    let Ok(view) = sys::handle_label(&channel, Rights::RECEIVE, TIMER_LABEL, level) else {
        return NOT_REGISTERED;
    };
    let Ok(timer) = sys::timer_create(&view, level) else {
        return NOT_REGISTERED;
    };
    let mut disk = Disk {
        nvme: controller,
        refused,
        cells: Cells::new(sectors, FLAG_FLUSH),
        ops: LongOps::new(),
        info: Info {
            sectors,
            block,
            flags: FLAG_FLUSH,
        },
        shift: found.block_shift,
        inflight: 0,
        up: true,
        said: [false; VECTORS],
        timer,
        deadline: 0,
        armed: false,
        irq,
        buffer: None,
        process: Handle::borrowed(s.process.raw()),
        _objects: [queues, cell_object],
        _windows: [ecam, bar],
        slba: [0; CELLS_N],
        errors: ERRORS_SHOWN,
        #[cfg(feature = "diag")]
        diag: Diag::default(),
    };
    #[cfg(feature = "steps")]
    rt::service::report_steps(15);
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
    if rt::budget::bind("nvme", rt::budget::SERVE, serve, &s.thread).is_err() {
        return BUDGET;
    }
    let _ = rt::service::run::<Disk, SESSIONS, 0>(&channel, &mut disk, config);
    STOPPED
}

/// The service: the controller, the places of the requests, the operations that wait, the
/// session that holds the shared buffer and the timer that looks at the queue.
struct Disk {
    nvme: Nvme<Hw>,
    /// The controller is not the volume the record names: every operation is refused.
    refused: bool,
    cells: Cells,
    ops: LongOps<OPERATIONS>,
    info: Info,
    /// The log2 of the bytes of a block: 9, or 12 for a disk of 4 KiB blocks.
    shift: u8,
    /// The commands with the controller whose completion has not come.
    inflight: u32,
    /// False from a reset in place until the queues are up again.
    up: bool,
    /// The vectors that have raised an interrupt, for the line that says so once.
    said: [bool; VECTORS],
    timer: Handle<Timer>,
    deadline: u64,
    armed: bool,
    irq: [Option<Handle<Interrupt>>; VECTORS],
    /// The label of the session whose buffer is mapped at BUFFER_AT.
    buffer: Option<u64>,
    /// The service's own process, borrowed from the start data, which outlives the loop.
    process: core::mem::ManuallyDrop<Handle<Process>>,
    /// The DMA objects and the windows, mapped for the service's life.
    _objects: [Handle<Memory>; 2],
    _windows: [Handle<Memory>; 2],
    /// The first block of the command in each place, for the line of an I/O error.
    slba: [u64; CELLS_N],
    /// The I/O errors that may still print a line.
    errors: u8,
    #[cfg(feature = "diag")]
    diag: Diag,
}

/// The places of the staging cells.
const CELLS_N: usize = proto_blk::CELLS as usize;
/// The I/O errors that print a line.
const ERRORS_SHOWN: u8 = 4;

/// The state of the diagnostic build: the reads that are still watched, and for each place the
/// sectors of the pattern its read started with (0 for none).
#[cfg(feature = "diag")]
#[derive(Default)]
struct Diag {
    reads: u8,
    takes: u8,
    pattern: [u32; CELLS_N],
}

/// The byte the staging cell is filled with before a read in the diagnostic build.
#[cfg(feature = "diag")]
const PATTERN: u8 = 0x5A;
/// The reads the diagnostic build watches.
#[cfg(feature = "diag")]
const WATCHED: u8 = 4;

/// The first `count` sectors of the staging cell of `place` as bytes.
#[cfg(feature = "diag")]
fn staging(nvme: &Nvme<Hw>, place: usize, count: u32) -> &[u8] {
    // SAFETY: the cell lies in the mapped DMA object for its 16 KiB, `count` sectors within it
    // (the request was admitted); the command that wrote it has completed.
    unsafe {
        core::slice::from_raw_parts(
            nvme.cell_va(place as u8) as *const u8,
            count as usize * SECTOR,
        )
    }
}

/// `count` sectors between cell `place` of the DMA object and the client's cell of the same
/// number: to the client for a read, from it for a write.
fn copy_cell(nvme: &Nvme<Hw>, place: usize, count: u32, to_client: bool) {
    let staging = nvme.cell_va(place as u8) as *mut u8;
    let client = (BUFFER_AT + place * CELL_BYTES as usize) as *mut u8;
    let (from, to) = if to_client {
        (staging, client)
    } else {
        (client, staging)
    };
    // SAFETY: both cells lie in mapped memory, `count` sectors within the cell's 16 KiB (the
    // request was admitted); a raw copy, since the client may write its cell meanwhile.
    unsafe { core::ptr::copy_nonoverlapping(from, to, count as usize * SECTOR) };
}

/// What a refusal of the library is for the client.
fn rejected(reject: Reject) -> Answer {
    Answer::Status(match reject {
        Reject::NotUp => code(proto_blk::IO),
        Reject::Busy => code(proto_blk::BUSY),
        Reject::Invalid => code(proto_blk::INVALID),
        Reject::Range => code(proto_blk::RANGE),
    })
}

impl Disk {
    /// The steps the library has for now, up to `STEPS`: the completions found tell their
    /// clients; the timer is armed again while a command is out.
    fn pump(&mut self) {
        let mut idle = false;
        for _ in 0..STEPS {
            match self.nvme.poll() {
                Event::Idle => {
                    idle = true;
                    break;
                }
                Event::Done(done) => self.finish(done),
                Event::Reset(cause) => {
                    let why = match cause {
                        Cause::Fatal => "CSTS.CFS",
                        Cause::Gone => "the function is gone",
                        Cause::AdminTimeout => "an admin command timed out",
                        Cause::NotReady | Cause::NotCleared => "CSTS.RDY did not change",
                    };
                    self.up = false;
                    rt::println!("nvme: reset in place: {why}");
                }
                Event::Failed(why) => {
                    rt::println!("nvme: the controller is down: {why:?}");
                    sys::process_exit(FAILED)
                }
                Event::Stopped => sys::process_exit(FAILED),
                Event::Up => {
                    self.up = true;
                    rt::println!("nvme: the queues are up again");
                }
                Event::Working => {}
            }
        }
        // More steps than a wake may make: the timer goes on at once.
        let next = if idle { POLL_NS } else { 0 };
        self.arm(next);
    }

    /// The command that ended: its place tells the waiting client, or goes free.
    fn finish(&mut self, done: Completion) {
        let place = usize::from(done.tag);
        self.inflight = self.inflight.saturating_sub(1);
        if let NvmeOutcome::Error { sct, sc, dnr } = done.outcome
            && self.errors > 0
        {
            self.errors -= 1;
            rt::println!(
                "nvme: io error cid {} sct/sc {:#x}/{:#x} dnr {} slba {}",
                u16::from(done.tag) << 2,
                sct,
                sc,
                u8::from(dnr),
                self.slba.get(place).copied().unwrap_or(0)
            );
        }
        #[cfg(feature = "diag")]
        if let (NvmeOutcome::Ok, Some(sectors)) = (done.outcome, self.diag.pattern.get_mut(place))
            && *sectors > 0
        {
            let kept = staging(&self.nvme, place, *sectors)
                .iter()
                .all(|&b| b == PATTERN);
            *sectors = 0;
            rt::println!(
                "nvme: pattern {}",
                if kept { "survived" } else { "overwritten" }
            );
        }
        let outcome = match done.outcome {
            NvmeOutcome::Ok => Outcome::Ok,
            NvmeOutcome::Error { .. } | NvmeOutcome::Aborted => Outcome::Io,
        };
        if let Told::Tell { label, key } = self.cells.complete(place, outcome) {
            self.ops.tell(label, key);
        }
    }

    /// Looks at the queue again `after` ns from now while a command is out or the controller is
    /// coming up after a reset. The timer is
    /// armed once: a later deadline never replaces an earlier one.
    fn arm(&mut self, after: u64) {
        if !nvme_blk::timer_wanted(self.inflight, self.up) {
            return;
        }
        let at = now_ns() + after;
        if self.armed && self.deadline <= at {
            return;
        }
        self.deadline = at;
        self.armed = sys::timer_set(&self.timer, at).is_ok();
    }

    fn refuse(&self, refusal: Refusal) -> Answer {
        Answer::Status(refusal.status())
    }

    /// READ and WRITE: a command for the controller, WAIT k.
    fn io(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>, kind: Kind) -> Answer {
        let io = match Io::read(r.body()) {
            Ok(io) => io,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        let buffered = self.buffer == Some(label);
        let place = match self
            .cells
            .admit_io(kind, io.cell, io.count, io.sector, buffered)
        {
            Ok(place) => place,
            Err(refusal) => return self.refuse(refusal),
        };
        // The blocks of the disk: a request that cuts one is refused.
        let per_block = 1u64 << (self.shift - 9);
        if !io.sector.is_multiple_of(per_block) || !u64::from(io.count).is_multiple_of(per_block) {
            return Answer::Status(code(proto_blk::INVALID));
        }
        let lba = io.sector >> (self.shift - 9);
        let blocks = io.count >> (self.shift - 9);
        let key = match self.ops.start(&mut s.data, label) {
            Ok(key) => key,
            Err(error) => return Answer::Status(Status::Kernel(error)),
        };
        if kind == Kind::Write {
            copy_cell(&self.nvme, place, io.count, false);
        }
        if let Some(at) = self.slba.get_mut(place) {
            *at = lba;
        }
        #[cfg(feature = "diag")]
        if kind == Kind::Read && self.diag.reads < WATCHED {
            self.diag.reads += 1;
            // SAFETY: the staging cell of the place, in the mapped DMA object, 16 KiB, with no
            // command on it (the place was admitted).
            unsafe {
                core::ptr::write_bytes(
                    self.nvme.cell_va(place as u8) as *mut u8,
                    PATTERN,
                    io.count as usize * SECTOR,
                )
            };
            self.diag.pattern[place] = io.count;
        }
        let sent = match kind {
            Kind::Read => self.nvme.read(place as u8, lba, blocks),
            Kind::Write => {
                let lba = if cfg!(feature = "break-nvme-write-offset") {
                    lba + 1
                } else {
                    lba
                };
                self.nvme.write(place as u8, lba, blocks)
            }
            Kind::Flush => Err(Reject::Invalid),
        };
        if let Err(reject) = sent {
            self.ops.finish(&mut s.data, label, key);
            return rejected(reject);
        }
        self.cells.begin(place, kind, label, key, 0, io.count);
        self.inflight += 1;
        self.pump();
        long_answer(r, long::Reply::Wait(key))
    }

    fn flush(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let place = match self.cells.admit_flush() {
            Ok(place) => place,
            Err(refusal) => return self.refuse(refusal),
        };
        debug_assert_eq!(place, FLUSH_PLACE);
        let label = r.label();
        let key = match self.ops.start(&mut s.data, label) {
            Ok(key) => key,
            Err(error) => return Answer::Status(Status::Kernel(error)),
        };
        if let Err(reject) = self.nvme.flush() {
            self.ops.finish(&mut s.data, label, key);
            return rejected(reject);
        }
        self.cells.begin(place, Kind::Flush, label, key, 0, 0);
        self.inflight += 1;
        self.pump();
        long_answer(r, long::Reply::Wait(key))
    }

    /// BUFFER: the object the request carries becomes the session's shared buffer, mapped for
    /// the session's life.
    fn give_buffer(&mut self, r: &mut Request<'_>) -> Answer {
        let size = match read_buffer(r.body()) {
            Ok(size) => size,
            Err(status) => return Answer::Status(status),
        };
        if size != BUFFER_SIZE || r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let needed = Rights::MAP_READ | Rights::MAP_WRITE;
        let rights = r.handles.info(0).map_or(Rights::NONE, |(_, rights)| rights);
        let Ok(object) = r.handles.take::<Memory>(0) else {
            return Answer::Status(code(proto_blk::INVALID));
        };
        if rights.0 & needed.0 != needed.0 {
            return Answer::Status(code(proto_blk::INVALID));
        }
        // An object of `mem_create`: as big as asked and with every page its own (a device
        // window owns none).
        match sys::memory_info(&object) {
            Ok(info)
                if info.size >= u64::from(BUFFER_SIZE)
                    && info.pages * PAGE >= u64::from(BUFFER_SIZE) => {}
            _ => return Answer::Status(code(proto_blk::INVALID)),
        }
        match self.buffer {
            Some(label) if label == r.label() => return Answer::Status(code(proto_blk::EXISTS)),
            Some(_) => return Answer::Status(code(proto_blk::BUSY)),
            None => {}
        }
        let mapped = sys::mem_map(
            &self.process,
            &object,
            0,
            u64::from(BUFFER_SIZE),
            BUFFER_AT,
            Access::ReadWrite,
        );
        match mapped {
            Ok(()) => {
                self.buffer = Some(r.label());
                Answer::Status(Status::Ok)
            }
            Err(Error::NoMemory | Error::LimitReached) => {
                Answer::Status(Status::Kernel(Error::LimitReached))
            }
            Err(error) => Answer::Status(Status::Kernel(error)),
        }
    }

    /// TAKE: the result once the controller answered, or ARMED (keeping the handle with NOTIFY
    /// the first TAKE brings).
    fn take(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
        let key = match Key::read(r.body()) {
            Ok(key) => key.key,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        match self.cells.take(label, key) {
            Taken::Done(done) => {
                self.ops.finish(&mut s.data, label, key);
                if let Some(refusal) = done.outcome.refusal() {
                    return Answer::Status(refusal);
                }
                #[cfg(feature = "diag")]
                if done.kind == Kind::Read && self.diag.takes < WATCHED {
                    self.diag.takes += 1;
                    match staging(&self.nvme, done.place, done.count)
                        .iter()
                        .position(|&b| b != 0)
                    {
                        Some(at) => rt::println!("nvme: staging nonzero at {at}"),
                        None => rt::println!("nvme: staging zero"),
                    }
                }
                if done.kind == Kind::Read {
                    copy_cell(&self.nvme, done.place, done.count, true);
                }
                long_answer(r, long::Reply::Ready(&[]))
            }
            Taken::Waits => {
                if !r.handles.is_empty() {
                    match r.handles.take::<Channel>(0) {
                        Ok(notify) => {
                            let _ = self.ops.arm(label, key, notify);
                        }
                        Err(error) => return Answer::Status(Status::Kernel(error)),
                    }
                }
                long_answer(r, long::Reply::Armed)
            }
            Taken::Unknown => Answer::Status(Status::Kernel(Error::BadState)),
        }
    }

    fn cancel(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
        let key = match Key::read(r.body()) {
            Ok(key) => key.key,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        if !self.cells.cancel(label, key) {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        self.ops.finish(&mut s.data, label, key);
        long_answer(r, long::Reply::Cancelled)
    }

    fn info(&self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let w = r.reply();
        if w.u32(Status::Ok.code())
            .and_then(|()| self.info.write(w))
            .is_err()
        {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    /// An interrupt of a vector: the completions are found, and the binding is acknowledged
    /// (an LPI has no mask in the kernel; the acknowledgement says the ITS is done with it).
    fn interrupt(&mut self, label: u64) {
        rt::service::step_own();
        let vector = usize::from(label == proto_init::binding_label(1));
        self.pump();
        if !core::mem::replace(&mut self.said[vector], true) {
            rt::println!("nvme: first interrupt of vector {vector}");
        }
        if let Some(binding) = &self.irq[vector] {
            let _ = sys::irq_ack(binding);
        }
    }
}

/// The methods of the service: CRASH only with the feature `crash`.
#[cfg(feature = "crash")]
const METHODS: &[u16] = &[
    Method::Info.number(),
    Method::Read.number(),
    Method::Write.number(),
    Method::Flush.number(),
    Method::Buffer.number(),
    Method::Take.number(),
    Method::Cancel.number(),
    Method::Crash.number(),
];
#[cfg(not(feature = "crash"))]
const METHODS: &[u16] = &[
    Method::Info.number(),
    Method::Read.number(),
    Method::Write.number(),
    Method::Flush.number(),
    Method::Buffer.number(),
    Method::Take.number(),
    Method::Cancel.number(),
];

/// CRASH: a load from page 0 ends the service with a fault while the controller still has its
/// queues; init stops the controller before it lets the DMA objects go, and starts the service
/// again.
#[cfg(feature = "crash")]
fn crash(r: &Request<'_>) -> Answer {
    if r.body().finish().is_err() {
        return Answer::Status(Status::BadSize);
    }
    // SAFETY: the load is the fault the method exists for; the thread never runs after it.
    unsafe {
        core::arch::asm!(
            "ldr {t}, [{a}]",
            t = out(reg) _,
            a = in(reg) 0_usize,
            options(nostack, readonly),
        )
    };
    Answer::Status(Status::Kernel(Error::BadState))
}

impl Service<0> for Disk {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = LongSession;

    fn request(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
        if self.refused {
            return Answer::Status(code(proto_blk::IO));
        }
        match Method::from_number(r.method()) {
            Some(Method::Info) => self.info(r),
            Some(Method::Read) => self.io(s, r, Kind::Read),
            Some(Method::Write) => self.io(s, r, Kind::Write),
            Some(Method::Flush) => self.flush(s, r),
            Some(Method::Buffer) => self.give_buffer(r),
            Some(Method::Take) => self.take(s, r),
            Some(Method::Cancel) => self.cancel(s, r),
            #[cfg(feature = "crash")]
            Some(Method::Crash) => crash(r),
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    fn gone(&mut self, s: &mut Session<LongSession, 0>) {
        let label = s.label();
        self.cells.gone(label);
        self.ops.gone(&mut s.data);
        if self.buffer == Some(label) {
            // SAFETY: nothing of the service's own lies in the buffer's range; the bytes
            // there are the client's.
            let gone = unsafe { sys::mem_unmap(&self.process, BUFFER_AT, u64::from(BUFFER_SIZE)) };
            if gone.is_ok() {
                self.buffer = None;
            }
        }
    }

    fn notification(&mut self, n: Notice) {
        match n.source {
            Source::Interrupt => self.interrupt(n.label),
            Source::Timer if n.label == TIMER_LABEL && time::reached(self.deadline) => {
                self.armed = false;
                self.pump();
            }
            _ => {}
        }
    }

    /// The heartbeat wakes the service every period: the library reads CSTS once in 100 ms
    /// to see a controller that failed or a function that is gone.
    fn between_notifications(&mut self, n: Notice) {
        if n.source == Source::Timer && n.label == 0 {
            self.pump();
        }
    }
}

/// The reply of a long operation, through the request's reply buffer.
fn long_answer(r: &mut Request<'_>, reply: long::Reply<'_>) -> Answer {
    match reply.write(r.reply()) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}
