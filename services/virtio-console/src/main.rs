// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The driver of the Virtio PCI console of Apple VZ (spec 13.5): a
//! service in one thread (rt::service), with the protocol of the PL011's
//! driver (proto_uart), so that the shell and the POSIX layer read and
//! write the console on VZ as on QEMU. Init gives it `console`, `log` and
//! `dma`, a contiguous uncached object, with the object's physical address
//! and the base of the function's configuration in its own arguments, and
//! in the reply to its REGISTER the windows `ecam`, over the function's
//! page of configuration, and `bar`, over its Virtio structures, and the
//! binding `irq` of its level-triggered INTx line. It resets the device
//! before it turns bus mastering on. The queues of the device's crate
//! (virtio-drivers) run port 0 (`port`) on the DMA object (`Host`); the
//! driver never waits for the host: a transmission ends at the interrupt
//! that shows its buffer used, input comes at the interrupt, and a receive
//! of no bytes, the end of the host's input, leaves output going. It shows
//! the kernel log as the PL011's driver does: at its start, every
//! LOG_PERIOD_NS and again while records are left. A buffer goes through a
//! bounce page, copied whole: up to port::RX_BYTES in, port::TX_BYTES out.
//! The driver is in the trusted base: the device writes where the
//! driver's queues tell it (spec 9, no SMMU on VZ). The program ends with
//! a code of its own when its start fails; init restarts it.

#![no_std]
#![no_main]

extern crate alloc;

use abi::time::next_release;
use abi::{Access, Error, LOG_BATCH, LOG_RECORD, Source};
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::fmt::{self, Write};
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use proto_init::ServiceArgs;
use proto_uart::{
    CancelRead, CancelableRead, Method, ReadReply, ReadRequest, VERSION, WriteReply, WriteRequest,
};
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Interrupt, Memory, Outgoing, Resource, Timer};
use rt::service::{Answer, Config, Heartbeat, Notice, Pending, Request, Service, Session};
use rt::{Handle, mmio, sys, time};
use uart::input::{self, Input, RX_RING};
use uart::output::Output;
use uart::writes::{self, Writes};
use virtio_console::dma::{Bounce, DMA_PAGES, PAGE, Queues};
use virtio_console::pci;
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::transport::pci::bus::{ConfigurationAccess, DeviceFunction, PciRoot};
use virtio_drivers::transport::{DeviceStatus, Transport};
use virtio_drivers::{BufferDirection, Hal, PhysAddr};

mod port;

use port::Port;

rt::entry!(main);

/// Where the driver maps its DMA object, the function's page of
/// configuration and its Virtio structures.
const DMA_AT: usize = 0x10_0000_0000;
const ECAM_AT: usize = 0x10_1000_0000;
const BAR_AT: usize = 0x10_2000_0000;
/// The period of the reads of the kernel log.
const LOG_PERIOD_NS: u64 = 50_000_000;
/// The label of the copy of the driver's channel its timer posts through.
const TIMER_LABEL: u64 = 1;
/// The priority of the slot of label 0 of the driver's channel.
const CHANNEL_PRIORITY: u8 = 1;
/// The sessions of the driver's channel, and what each holds at most.
const SESSIONS: usize = 8;
const HELD: usize = 2;
/// Batches of the kernel log one read takes in a row at most.
const LOG_BATCHES: usize = 64 / LOG_BATCH + 1;
/// Reads of the device's status after its reset, at most, before the
/// driver gives up: Virtio 1.2, 2.4.1, the reset is done once it reads 0.
const RESET_READS: u32 = 1_000_000;

/// The codes of a start that failed: the start data, `log` or `dma` among
/// them; REGISTER, the windows or the binding; a map; no Virtio console
/// at the function; the device refused the driver; the loop.
const NO_START_DATA: u64 = 1;
const NO_LOG: u64 = 2;
const NOT_REGISTERED: u64 = 3;
const NOT_MAPPED: u64 = 4;
const STOPPED: u64 = 5;
const NO_DEVICE: u64 = 6;
const NO_CONSOLE: u64 = 7;

/// The heap of the device's crate: its queues' bookkeeping and the
/// console's input buffer, made once; nothing goes back.
const HEAP_SIZE: usize = 32 * 1024;

#[repr(align(16))]
struct Heap(UnsafeCell<[u8; HEAP_SIZE]>);

// SAFETY: `Bump` hands out disjoint pieces, one at a time.
unsafe impl Sync for Heap {}

static HEAP: Heap = Heap(UnsafeCell::new([0; HEAP_SIZE]));
static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);

struct Bump;

#[global_allocator]
static ALLOCATOR: Bump = Bump;

// SAFETY: each allocation is a fresh piece of HEAP, aligned as asked and
// never handed out twice.
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = HEAP.0.get() as usize;
        let start = HEAP_NEXT.load(Ordering::Relaxed);
        let at = (base + start).next_multiple_of(layout.align()) - base;
        match at.checked_add(layout.size()) {
            Some(end) if end <= HEAP_SIZE => {
                HEAP_NEXT.store(end, Ordering::Relaxed);
                (base + at) as *mut u8
            }
            _ => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

/// The physical address of the DMA object and of the Virtio structures,
/// for `Host`, set once at the start.
static DMA_PA: AtomicU64 = AtomicU64::new(0);

/// The bookkeeping of the DMA object (virtio_console::dma).
struct Pages {
    queues: Queues,
    bounce: Bounce,
}

struct PagesCell(UnsafeCell<Pages>);

// SAFETY: the driver's one thread reaches it, through `pages`.
unsafe impl Sync for PagesCell {}

static PAGES: PagesCell = PagesCell(UnsafeCell::new(Pages {
    queues: Queues::new(),
    bounce: Bounce::new(),
}));

/// The bookkeeping of the DMA object.
///
/// # Safety
/// The caller is the driver's one thread, and holds no other borrow.
unsafe fn book<'a>() -> &'a mut Pages {
    // SAFETY: the caller's promise.
    unsafe { &mut *PAGES.0.get() }
}

/// The address in the driver and the physical address of page `page` of
/// the DMA object.
fn page_at(page: usize) -> (usize, PhysAddr) {
    let offset = page * PAGE;
    (
        DMA_AT + offset,
        DMA_PA.load(Ordering::Relaxed) + offset as u64,
    )
}

/// The DMA of the device's crate on the driver's object: the queues take
/// its first pages, and a buffer goes through a bounce page while the
/// device has it. The object is uncached, so no line of a cache stands
/// between the driver and the device; the queues order their stores
/// with barriers of their own.
struct Host;

// SAFETY: `dma_alloc` gives zeroed pages of the DMA object, never twice;
// `share` gives the physical address of a bounce page that holds the
// buffer until `unshare`; `mmio_phys_to_virt` maps only the BAR window.
unsafe impl Hal for Host {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        // SAFETY: the driver's one thread.
        let first = unsafe { book() }.queues.take(pages);
        let Some(first) = first else {
            // The crate takes a physical address of 0 for a failure.
            return (0, NonNull::dangling());
        };
        let (va, pa) = page_at(first);
        // SAFETY: the pages are the DMA object's, mapped read and write at
        // DMA_AT, and no one else has them; the kernel zeroed them, and the
        // crate expects zeroes again.
        unsafe { core::ptr::write_bytes(va as *mut u8, 0, pages * PAGE) };
        (pa, NonNull::new(va as *mut u8).expect("DMA_AT is no null"))
    }

    unsafe fn dma_dealloc(_paddr: PhysAddr, _vaddr: NonNull<u8>, _pages: usize) -> i32 {
        // The queues live as long as the driver.
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, size: usize) -> NonNull<u8> {
        let offset = paddr.wrapping_sub(pci::BAR_BASE);
        assert!(
            offset.saturating_add(size as u64) <= pci::BAR_LEN,
            "a Virtio structure outside BAR 0"
        );
        NonNull::new((BAR_AT + offset as usize) as *mut u8).expect("BAR_AT is no null")
    }

    unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> PhysAddr {
        let len = buffer.len();
        // SAFETY: the driver's one thread.
        let page = unsafe { book() }.bounce.lend(len);
        let page = page.expect("a free bounce page for a buffer of a page at most");
        let (va, pa) = page_at(page);
        if direction != BufferDirection::DeviceToDriver {
            // SAFETY: the crate's buffer is valid for `len` bytes; the
            // bounce page is the driver's until `unshare`.
            unsafe {
                core::ptr::copy_nonoverlapping(buffer.as_ptr().cast::<u8>(), va as *mut u8, len)
            };
        }
        pa
    }

    unsafe fn unshare(paddr: PhysAddr, buffer: NonNull<[u8]>, direction: BufferDirection) {
        let page = ((paddr - DMA_PA.load(Ordering::Relaxed)) as usize) / PAGE;
        if direction != BufferDirection::DriverToDevice {
            let (va, _) = page_at(page);
            // SAFETY: as in `share`; the device is done with the page.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    va as *const u8,
                    buffer.as_ptr().cast::<u8>(),
                    buffer.len(),
                )
            };
        }
        // SAFETY: the driver's one thread.
        let back = unsafe { book() }.bounce.give_back(page);
        assert!(back, "a bounce page came back that was not lent");
    }
}

/// What the driver keeps in its data segment: the rings of output and
/// input, the writes that wait, a batch of the kernel log and the bytes of
/// a reply to READ, as the PL011's driver keeps them (spec 13.5).
struct State {
    output: Output,
    writes: Writes<Pending>,
    input: Input<Pending>,
    records: [[u8; LOG_RECORD]; LOG_BATCH],
    read: [u8; RX_RING],
}

struct Cell(UnsafeCell<MaybeUninit<State>>);

// SAFETY: `state` gives the state out once, to the driver's one thread.
unsafe impl Sync for Cell {}

static STATE: Cell = Cell(UnsafeCell::new(MaybeUninit::uninit()));
static TAKEN: AtomicBool = AtomicBool::new(false);

/// The state, empty, at the first call only.
fn state() -> Option<&'static mut State> {
    if TAKEN.swap(true, Ordering::Relaxed) {
        return None;
    }
    // SAFETY: TAKEN lets one call through, and nothing else reaches STATE.
    let place = unsafe { &mut *STATE.0.get() };
    Some(place.write(State {
        output: Output::new(),
        writes: Writes::new(),
        input: Input::new(),
        records: [[0; LOG_RECORD]; LOG_BATCH],
        read: [0; RX_RING],
    }))
}

/// A 32-bit register of the function's configuration through the window
/// at ECAM_AT [G34].
fn config_read(offset: usize) -> u32 {
    // SAFETY: the window maps the function's page of configuration at
    // ECAM_AT, read and write, as device memory; `offset` is a register of
    // virtio_console::pci within it.
    unsafe { mmio::read32(ECAM_AT + offset) }
}

fn config_write(offset: usize, value: u32) {
    // SAFETY: as for `config_read`.
    unsafe { mmio::write32(ECAM_AT + offset, value) }
}

/// The function's configuration as the device's crate reads it: the
/// window holds the one function, whichever device and function the crate
/// names, each access a 32-bit `ldr` or `str` [G34].
struct Function;

impl ConfigurationAccess for Function {
    fn read_word(&self, _: DeviceFunction, register_offset: u8) -> u32 {
        config_read(usize::from(register_offset & !3))
    }

    fn write_word(&mut self, _: DeviceFunction, register_offset: u8, data: u32) {
        config_write(usize::from(register_offset & !3), data)
    }

    unsafe fn unsafe_clone(&self) -> Self {
        Function
    }
}

/// The first 8 bytes of `own` from `at`, little-endian; 0 without them.
fn word(own: &[u8], at: usize) -> u64 {
    own.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let Ok(log) = s.take::<Resource>("log") else {
        return NO_LOG;
    };
    let Ok(dma) = s.take::<Memory>("dma") else {
        return NO_START_DATA;
    };
    let Some(state) = state() else {
        return NO_START_DATA;
    };
    let args = ServiceArgs::read(s.args()).ok();
    // The own arguments: the DMA object's physical address, which init
    // puts first, then the record's, the base of the function's page.
    let own = args.map_or(&[][..], |a| a.own);
    let (dma_pa, function) = (word(own, 0), word(own, 8));
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(CHANNEL_PRIORITY) else {
        return NOT_REGISTERED;
    };
    let Ok(mut got) = rt::service::register(&s.parent, &channel) else {
        return NOT_REGISTERED;
    };
    let (Ok(ecam), Ok(bar), Ok(irq)) = (
        got.take::<Memory>("ecam"),
        got.take::<Memory>("bar"),
        got.take::<Interrupt>("irq"),
    ) else {
        return NOT_REGISTERED;
    };
    let rw = Access::ReadWrite;
    let mapped = sys::mem_map(&s.process, &dma, 0, (DMA_PAGES * PAGE) as u64, DMA_AT, rw)
        .and_then(|()| sys::mem_map(&s.process, &ecam, 0, PAGE as u64, ECAM_AT, rw))
        .and_then(|()| sys::mem_map(&s.process, &bar, 0, pci::BAR_LEN, BAR_AT, rw));
    if mapped.is_err() || dma_pa == 0 {
        return NOT_MAPPED;
    }
    DMA_PA.store(dma_pa, Ordering::Relaxed);
    // The table names the console's function; one that holds something
    // else ends the driver before it writes there (VZ puts the console at
    // device 5 of bus 0 whatever else the machine has).
    if config_read(pci::ID) != pci::CONSOLE_ID {
        return NO_DEVICE;
    }
    // The command word as the driver finds it: 0 at the machine's start,
    // and 0 again after init stopped the function of an instance that
    // ended (Record::quiesce); the line below shows it.
    let found = config_read(pci::COMMAND) & 0xFFFF;
    for (offset, value) in pci::set_up(found) {
        config_write(offset, value);
    }
    let mut root = PciRoot::new(Function);
    let at = DeviceFunction {
        bus: 0,
        device: 0,
        function: 0,
    };
    let Ok(mut transport) = PciTransport::new::<Host, _>(&mut root, at) else {
        return NO_CONSOLE;
    };
    // The device forgets every queue before it may master the bus again
    // (Virtio 1.2, 2.4.1): a reset of an instance that ended may not have
    // run, and VZ keeps a device's DMA going with bus mastering off.
    transport.set_status(DeviceStatus::empty());
    if !(0..RESET_READS).any(|_| transport.get_status().is_empty()) {
        return NO_CONSOLE;
    }
    config_write(pci::COMMAND, pci::bus_master(found));
    let Ok(port) = Port::new(transport) else {
        return NO_CONSOLE;
    };
    let Ok(view) = sys::handle_label(&channel, abi::Rights::RECEIVE, TIMER_LABEL, level) else {
        return NOT_REGISTERED;
    };
    let Ok(timer) = sys::timer_create(&view, level) else {
        return NOT_REGISTERED;
    };
    let mut driver = Driver {
        port,
        ended_said: false,
        irq,
        log,
        timer,
        _view: view,
        _windows: [dma, ecam, bar],
        t0: time::ticks_to_ns(time::now()),
        deadline: 0,
        left: 0,
        state,
    };
    driver.take_log();
    driver.arm();
    let line = sys::irq_info(&driver.irq).map_or(0, |info| info.line);
    driver.say(format_args!(
        "virtio-console: 1af4:1043 at {function:#x}, line {line}, command {found:#x}\n"
    ));
    // The line opens once the queues are up: an input that came before
    // is read at the first interrupt.
    let _ = sys::irq_ack(&driver.irq);
    let heartbeat = Heartbeat {
        to: &s.parent,
        period_ns: args.map_or(0, |a| a.period_ns),
        priority: level,
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(heartbeat),
    };
    let _ = rt::service::run::<Driver, SESSIONS, HELD>(&channel, &mut driver, config);
    STOPPED
}

/// The driver: the device, the binding of the line, `log`, the timer of
/// the reads of the log, the objects it maps and the state.
struct Driver {
    port: Port,
    /// The line of the end of the host's input went out.
    ended_said: bool,
    irq: Handle<Interrupt>,
    log: Handle<Resource>,
    timer: Handle<Timer>,
    /// The copy of the channel with RECEIVE the timer posts through.
    _view: Handle<Channel>,
    /// The DMA object and the two windows, mapped for the driver's life.
    _windows: [Handle<Memory>; 3],
    /// The timer fires at t0 + k * LOG_PERIOD_NS; `deadline` is the next.
    t0: u64,
    deadline: u64,
    /// The records of the kernel log left after the last batch.
    left: u64,
    state: &'static mut State,
}

impl Driver {
    /// Formats a line of the driver into its output and sends it.
    fn say(&mut self, args: fmt::Arguments<'_>) {
        let mut line = Line {
            bytes: [0; LINE_MAX],
            len: 0,
        };
        let _ = line.write_fmt(args);
        let _ = self.state.output.put(&line.bytes[..line.len]);
        self.kick();
    }

    /// Starts output: the writes that wait go into the ring as room
    /// allows, and, when no transmission is with the device, the next
    /// bytes of the ring, up to port::TX_BYTES, go to it. The driver never
    /// waits for the host: the interrupt that shows the buffer used starts
    /// the next transmission (`interrupt`).
    fn kick(&mut self) {
        let State { output, writes, .. } = &mut *self.state;
        writes.flush(output, answer_write);
        self.port.send(|buf| {
            let mut n = 0;
            while n < buf.len() {
                let Some(b) = output.next_byte() else { break };
                buf[n] = b;
                n += 1;
            }
            n
        });
        writes.flush(output, answer_write);
    }

    /// Takes the input the device holds into the ring while it has room,
    /// and answers a read that waits. Once the host's input ended the
    /// driver says so once and goes on with output.
    fn pull(&mut self) {
        let input = &mut self.state.input;
        while input.room() > 0 {
            let Some(b) = self.port.next_byte() else {
                break;
            };
            input.push(u32::from(b));
        }
        self.answer_read();
        if self.port.input_ended() && !self.ended_said {
            self.ended_said = true;
            self.say(format_args!("virtio-console: the host's input ended\n"));
        }
    }

    /// An interrupt of the line (spec 9, 13.5): the kernel masked it at
    /// delivery. Reading the ISR clears the level of INTx and completes a
    /// receive and a transmission the device finished; the input goes into
    /// the ring, the next transmission starts and the next batch of the
    /// log comes once the last went out, then the line opens again
    /// (irq_ack), source cleared first [G26].
    fn interrupt(&mut self) {
        if self.port.interrupt() {
            self.kick();
            if self.left > 0 {
                self.take_log();
            }
        }
        self.pull();
        // The binding lives as long as the driver.
        let _ = sys::irq_ack(&self.irq);
    }

    /// The read that waits gets what came.
    fn answer_read(&mut self) {
        let State { input, read, .. } = &mut *self.state;
        if let Some((pending, n)) = input.answer(read)
            && !answer_read(pending, &read[..n])
        {
            input.restore(&read[..n]);
        }
    }

    /// Takes batches of the kernel log into the output (spec 13.5, 16.3)
    /// once the last went out whole, and sends them; LOG_BATCHES at most.
    fn take_log(&mut self) {
        for _ in 0..LOG_BATCHES {
            let State {
                output, records, ..
            } = &mut *self.state;
            if !output.log_done() {
                return;
            }
            let Ok(batch) = sys::log_take(&self.log, records) else {
                return;
            };
            self.left = batch.left;
            uart::log::text(records, batch, |bytes| {
                // A batch fits: twelve records and the line of those lost.
                let _ = output.put_log(bytes);
            });
            self.kick();
            if self.left == 0 {
                return;
            }
        }
    }

    /// Arms the timer at the first deadline t0 + k * LOG_PERIOD_NS after
    /// now (spec 10).
    fn arm(&mut self) {
        let now = time::ticks_to_ns(time::now());
        self.deadline = next_release(self.t0, LOG_PERIOD_NS, now);
        // The driver's own timer: timer_set has no error to give.
        let _ = sys::timer_set(&self.timer, self.deadline);
    }

    /// WRITE (spec 13.5, 13.8), as the PL011's driver answers it.
    fn write(&mut self, r: &mut Request<'_>) -> Answer {
        let bytes = match WriteRequest::read(r.body()) {
            Ok(request) => request.bytes,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        let Some(pending) = r.defer() else {
            return Answer::Deferred;
        };
        let State { output, writes, .. } = &mut *self.state;
        match writes.write(output, label, bytes, pending) {
            writes::Taken::Now(n, pending) => answer_write(pending, n),
            writes::Taken::Waits => {}
            writes::Taken::Full(pending) => refuse(pending, Error::LimitReached),
        }
        self.kick();
        Answer::Deferred
    }

    /// READ (spec 13.5, 13.8), as the PL011's driver answers it; input the
    /// device kept while the ring was full comes in once bytes went.
    fn read(&mut self, r: &mut Request<'_>) -> Answer {
        let (max, id) = if r.method() == Method::ReadCancelable.number() {
            match CancelableRead::read(r.body()) {
                Ok(request) => (request.max as usize, request.id),
                Err(status) => return Answer::Status(status),
            }
        } else {
            match ReadRequest::read(r.body()) {
                Ok(request) => (request.max as usize, 0),
                Err(status) => return Answer::Status(status),
            }
        };
        let label = r.label();
        let Some(pending) = r.defer() else {
            return Answer::Deferred;
        };
        let State { input, read, .. } = &mut *self.state;
        let taken = if id == 0 {
            input.read(label, max, pending, read)
        } else {
            input.read_cancelable(label, max, id, pending, read)
        };
        match taken {
            input::Taken::Now(n, pending) => {
                if !answer_read(pending, &read[..n]) {
                    input.restore(&read[..n]);
                }
            }
            input::Taken::Waits => {}
            input::Taken::Refused(pending) => refuse(pending, Error::BadState),
        }
        self.pull();
        Answer::Deferred
    }

    fn cancel_read(&mut self, r: &Request<'_>) -> Answer {
        let cancel = match CancelRead::read(r.body()) {
            Ok(cancel) => cancel,
            Err(status) => return Answer::Status(status),
        };
        if let Some(pending) = self.state.input.cancel(r.label(), cancel.id) {
            refuse(pending, Error::Interrupted);
        }
        Answer::Status(Status::Ok)
    }
}

/// The methods of the driver: CRASH only with the feature `crash`.
#[cfg(feature = "crash")]
const METHODS: &[u16] = &[
    Method::Write.number(),
    Method::Read.number(),
    Method::ReadCancelable.number(),
    Method::CancelRead.number(),
    Method::Crash.number(),
];
#[cfg(not(feature = "crash"))]
const METHODS: &[u16] = &[
    Method::Write.number(),
    Method::Read.number(),
    Method::ReadCancelable.number(),
    Method::CancelRead.number(),
];

#[cfg(feature = "crash")]
impl Driver {
    /// What the output holds goes out before CRASH faults, as the
    /// PL011's FIFO takes a short line at once: the client's last line
    /// shows. Waits for each transmission by reading the ISR, up to
    /// DRAIN_NS; only the method of the tests waits so.
    fn drain(&mut self) {
        const DRAIN_NS: u64 = 100_000_000;
        let until = time::ticks_to_ns(time::now()).saturating_add(DRAIN_NS);
        loop {
            self.kick();
            if !self.port.sending() || time::reached(until) {
                return;
            }
            while self.port.sending() && !time::reached(until) {
                self.port.interrupt();
            }
        }
    }
}

impl Service<HELD> for Driver {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = ();

    fn request(&mut self, _: &mut Session<(), HELD>, r: &mut Request<'_>) -> Answer {
        match Method::from_number(r.method()) {
            Some(Method::Write) => self.write(r),
            Some(Method::Read | Method::ReadCancelable) => self.read(r),
            Some(Method::CancelRead) => self.cancel_read(r),
            #[cfg(feature = "crash")]
            Some(Method::Crash) => {
                self.drain();
                crash(r)
            }
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    fn gone(&mut self, s: &mut Session<(), HELD>) {
        let label = s.label();
        let State { writes, input, .. } = &mut *self.state;
        writes.gone(label, drop);
        drop(input.gone(label));
    }

    fn notification(&mut self, n: Notice) {
        match (n.source, n.label) {
            (Source::Interrupt, _) => self.interrupt(),
            (Source::Timer, TIMER_LABEL) if time::reached(self.deadline) => {
                self.take_log();
                self.arm();
            }
            _ => {}
        }
    }
}

/// CRASH (spec 13.5): a load from page 0 ends the driver with a fault
/// while the device still has its queues; init stops the function's DMA
/// before it lets the DMA object go, and starts the driver again.
#[cfg(feature = "crash")]
fn crash(r: &Request<'_>) -> Answer {
    if r.body().finish().is_err() {
        return Answer::Status(Status::BadSize);
    }
    // SAFETY: the load is the fault the method exists for; the thread
    // never runs after it.
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

/// The reply to a WRITE of `n` bytes that all went into the ring.
fn answer_write(pending: Pending, n: u32) {
    let mut w = Writer::new();
    let _ = WriteReply { written: n }.write(&mut w);
    let _ = pending.answer(w.as_bytes(), Outgoing::new());
}

/// The reply to a READ with `bytes`, 1 to RX_RING of them.
fn answer_read(pending: Pending, bytes: &[u8]) -> bool {
    let mut w = Writer::new();
    let _ = ReadReply { bytes }.write(&mut w);
    pending.answer(w.as_bytes(), Outgoing::new()).is_ok()
}

/// A reply that is the status of `error` alone.
fn refuse(pending: Pending, error: Error) {
    let _ = pending.answer(&proto_wire::reply(Status::Kernel(error)), Outgoing::new());
}

/// The longest line the driver says of itself.
const LINE_MAX: usize = 96;

struct Line {
    bytes: [u8; LINE_MAX],
    len: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        let room = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        room.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}
