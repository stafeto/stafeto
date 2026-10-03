// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The driver of the Virtio entropy device (Virtio 1.2, 5.4): a service in
//! one thread (rt::service) that gives its clients bytes of the device in
//! fills of two steps (proto_entropy). On QEMU the device sits on a
//! virtio-mmio transport, whose window `mmio` init gives it; on Apple VZ it
//! is a Virtio PCI function, with the windows `ecam` and `bar` as the
//! console's driver has them (virtio_pci), which the driver sets up and
//! resets before it turns bus mastering on. Init gives it `dma`, a
//! contiguous uncached object, with the object's physical address and the
//! transport's in its own arguments, and the binding `irq` of the device's
//! level-triggered line.
//!
//! The driver never waits for the device: a fill goes to the device as a
//! request of the queue (`add`, the barrier and the doorbell) and the
//! interrupt brings its bytes, read through the ISR and `pop_used`, which
//! copies them out of the bounce page; the line opens again after the
//! source is cleared (irq_ack, [G26]). The crate's `request_entropy`
//! waits for the device by spinning, so the driver keeps the queue itself.
//! The driver is in the trusted base: the device writes where the queue
//! tells it (spec 9, no SMMU on QEMU's virt or on VZ). Init stops the
//! device (Status 0 or the Virtio reset and the command word 0) before it
//! lets the DMA object of an instance go. The program ends with a code of
//! its own when its start fails; init restarts it.

#![no_std]
#![no_main]

use abi::{Access, Error, Source};
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use proto_entropy::{Fill, Key, Method, VERSION};
use proto_init::ServiceArgs;
use proto_wire::{Status, long};
use rt::handle::{Channel, Interrupt, Memory, Outgoing, Resource};
use rt::service::{
    Answer, Config, Heartbeat, LongOps, LongSession, Notice, Request, Service, Session,
};
use rt::{Handle, mmio, sys};
use virtio_drivers::device::common::Feature;
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::transport::pci::bus::{ConfigurationAccess, DeviceFunction, PciRoot};
use virtio_drivers::transport::{DeviceStatus, SomeTransport, Transport};
use virtio_drivers::{BufferDirection, Hal, PhysAddr};
use virtio_rng::dma::{BOUNCE_PAGE, DMA_PAGES, PAGE, QUEUE_PAGES};
use virtio_rng::fills::{FILLS, Fills, Taken};
use virtio_rng::{PLACE, is_mmio_entropy};

rt::entry!(main);

/// Where the driver maps its DMA object, the transport's page on QEMU,
/// and the function's page of configuration and its Virtio structures on
/// VZ.
const DMA_AT: usize = 0x10_0000_0000;
const MMIO_AT: usize = 0x10_1000_0000;
const ECAM_AT: usize = 0x10_2000_0000;
const BAR_AT: usize = 0x10_3000_0000;
/// The sessions of the driver's channel.
const SESSIONS: usize = 4;
/// The entries of the queue: the device takes one request at a time.
const QUEUE_SIZE: usize = 8;
/// The device's one queue, `requestq`.
const REQUESTQ: u16 = 0;
/// Reads of the device's status after its reset, at most, before the
/// driver gives up: Virtio 1.2, 2.4.1, the reset is done once it reads 0.
const RESET_READS: u32 = 1_000_000;

/// The codes of a start that failed: the start data or `dma`; REGISTER,
/// the windows or the binding; a map; no entropy device at the transport
/// or the function; the device refused the driver; the loop; the common
/// configuration of a PCI device lies elsewhere than at the start of BAR 0.
const NO_START_DATA: u64 = 1;
const NOT_REGISTERED: u64 = 3;
const NOT_MAPPED: u64 = 4;
const STOPPED: u64 = 5;
const NO_DEVICE: u64 = 6;
const NOT_STARTED: u64 = 7;
const CONFIG_ELSEWHERE: u64 = 9;

/// The heap the device's crate may ask for: none. The queue has no
/// indirect entries, the only thing of the crate that allocates, so an
/// allocation is a fault of the driver's, and fails.
struct NoHeap;

#[global_allocator]
static ALLOCATOR: NoHeap = NoHeap;

// SAFETY: every allocation fails with a null pointer, which the contract
// allows; nothing is ever handed out to come back.
unsafe impl GlobalAlloc for NoHeap {
    unsafe fn alloc(&self, _: Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

/// The physical address of the DMA object, for `Host`, set once.
static DMA_PA: AtomicU64 = AtomicU64::new(0);
/// The queue's pages handed out so far.
static QUEUE_TAKEN: AtomicUsize = AtomicUsize::new(0);

/// The address in the driver and the physical address of page `page` of
/// the DMA object.
fn page_at(page: usize) -> (usize, PhysAddr) {
    let offset = page * PAGE;
    (
        DMA_AT + offset,
        DMA_PA.load(Ordering::Relaxed) + offset as u64,
    )
}

/// The DMA of the device's crate on the driver's object: the queue takes
/// its first pages, and the buffer of a request goes through the bounce
/// page while the device has it. The object is uncached; the queue orders
/// its stores with barriers of its own.
struct Host;

// SAFETY: `dma_alloc` gives zeroed pages of the DMA object, never twice;
// `share` gives the physical address of the bounce page, which holds the
// one buffer the device has until `unshare`; `mmio_phys_to_virt` maps only
// the BAR window.
unsafe impl Hal for Host {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        let first = QUEUE_TAKEN.load(Ordering::Relaxed);
        if first + pages > QUEUE_PAGES {
            // The crate takes a physical address of 0 for a failure.
            return (0, NonNull::dangling());
        }
        QUEUE_TAKEN.store(first + pages, Ordering::Relaxed);
        let (va, pa) = page_at(first);
        // SAFETY: the pages are the DMA object's, mapped read and write at
        // DMA_AT, and no one else has them; the crate expects zeroes.
        unsafe { core::ptr::write_bytes(va as *mut u8, 0, pages * PAGE) };
        (pa, NonNull::new(va as *mut u8).expect("DMA_AT is no null"))
    }

    unsafe fn dma_dealloc(_paddr: PhysAddr, _vaddr: NonNull<u8>, _pages: usize) -> i32 {
        // The queue lives as long as the driver.
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, size: usize) -> NonNull<u8> {
        let offset = paddr.wrapping_sub(PLACE.bar);
        assert!(
            offset.saturating_add(size as u64) <= PLACE.bar_len,
            "a Virtio structure outside BAR 0"
        );
        NonNull::new((BAR_AT + offset as usize) as *mut u8).expect("BAR_AT is no null")
    }

    unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> PhysAddr {
        assert!(buffer.len() <= PAGE, "a request of a page at most");
        let (va, pa) = page_at(BOUNCE_PAGE);
        if direction != BufferDirection::DeviceToDriver {
            // SAFETY: the crate's buffer is valid for its length; the
            // bounce page is the driver's until `unshare`.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buffer.as_ptr().cast::<u8>(),
                    va as *mut u8,
                    buffer.len(),
                )
            };
        }
        pa
    }

    unsafe fn unshare(_paddr: PhysAddr, buffer: NonNull<[u8]>, direction: BufferDirection) {
        if direction != BufferDirection::DriverToDevice {
            let (va, _) = page_at(BOUNCE_PAGE);
            // SAFETY: as in `share`; the device is done with the page.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    va as *const u8,
                    buffer.as_ptr().cast::<u8>(),
                    buffer.len(),
                )
            };
        }
    }
}

/// A 32-bit register of the function's configuration through the window
/// at ECAM_AT [G34].
fn config_read(offset: usize) -> u32 {
    // SAFETY: the window maps the function's page of configuration at
    // ECAM_AT, read and write, as device memory; `offset` is a register of
    // virtio_pci within it.
    unsafe { mmio::read32(ECAM_AT + offset) }
}

fn config_write(offset: usize, value: u32) {
    // SAFETY: as for `config_read`.
    unsafe { mmio::write32(ECAM_AT + offset, value) }
}

/// The function's configuration as the device's crate reads it: the
/// window holds the one function, each access a 32-bit `ldr` or `str`.
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

/// The transport of the device, where it is, and the device's status as
/// the driver found it, before its reset: 0 at the machine's start and
/// after init stopped the device of an instance that ended.
struct Found {
    transport: SomeTransport<'static>,
    at: u64,
    status: u32,
    pci: bool,
}

/// The virtio-mmio transport of QEMU at `at`, whose page the window maps
/// at MMIO_AT.
fn mmio_transport(at: u64) -> Result<Found, u64> {
    let base = MMIO_AT + (at as usize & (PAGE - 1));
    if base + virtio_rng::mmio::LEN > MMIO_AT + PAGE {
        return Err(NO_DEVICE);
    }
    // SAFETY: the window maps the transport's page at MMIO_AT as device
    // memory, read and write; the registers lie within the transport.
    let read = |offset: usize| unsafe { mmio::read32(base + offset) };
    if !is_mmio_entropy(read) {
        return Err(NO_DEVICE);
    }
    let status = read(virtio_rng::mmio::STATUS);
    let header = NonNull::new(base as *mut VirtIOHeader).ok_or(NO_DEVICE)?;
    // SAFETY: the transport's registers stay mapped for the driver's life,
    // and only the transport reaches them from here on.
    let transport = unsafe { MmioTransport::new(header, virtio_rng::mmio::LEN) };
    let transport = transport.map_err(|_| NO_DEVICE)?;
    Ok(Found {
        transport: transport.into(),
        at,
        status,
        pci: false,
    })
}

/// The Virtio PCI function of VZ at `function`, whose page of
/// configuration the window maps at ECAM_AT: checked, set up with
/// decoding on and bus mastering off.
fn pci_transport(function: u64) -> Result<Found, u64> {
    // The table names the entropy device's function; one that holds
    // something else ends the driver before it writes there.
    if config_read(virtio_pci::ID) != PLACE.id {
        return Err(NO_DEVICE);
    }
    // init resets the device of an instance that ended through BAR 0 at
    // the offset of `device_status`, so the common configuration must lie
    // at the start of BAR 0.
    if virtio_pci::common_config(config_read) != Some((0, 0)) {
        return Err(CONFIG_ELSEWHERE);
    }
    let found = config_read(virtio_pci::COMMAND) & 0xFFFF;
    for (offset, value) in PLACE.set_up(found) {
        config_write(offset, value);
    }
    let mut root = PciRoot::new(Function);
    let at = DeviceFunction {
        bus: 0,
        device: 0,
        function: 0,
    };
    let transport = PciTransport::new::<Host, _>(&mut root, at).map_err(|_| NO_DEVICE)?;
    let status = transport.get_status().bits();
    Ok(Found {
        transport: transport.into(),
        at: function,
        status,
        pci: true,
    })
}

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let Ok(dma) = s.take::<Memory>("dma") else {
        return NO_START_DATA;
    };
    let args = ServiceArgs::read(s.args()).ok();
    // The own arguments: the DMA object's physical address, which init
    // puts first, then the record's, where the transport is.
    let own = args.map_or(&[][..], |a| a.own);
    let (dma_pa, at) = (word(own, 0), word(own, 8));
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return NOT_REGISTERED;
    };
    let Ok(mut got) = rt::service::register(&s.parent, &channel) else {
        return NOT_REGISTERED;
    };
    let Ok(irq) = got.take::<Interrupt>("irq") else {
        return NOT_REGISTERED;
    };
    let rw = Access::ReadWrite;
    if dma_pa == 0
        || sys::mem_map(&s.process, &dma, 0, (DMA_PAGES * PAGE) as u64, DMA_AT, rw).is_err()
    {
        return NOT_MAPPED;
    }
    DMA_PA.store(dma_pa, Ordering::Relaxed);
    // QEMU's transport, or VZ's function and its structures.
    let mut windows = [None, None];
    let found = if let Ok(window) = got.take::<Memory>("mmio") {
        if sys::mem_map(&s.process, &window, 0, PAGE as u64, MMIO_AT, rw).is_err() {
            return NOT_MAPPED;
        }
        windows[0] = Some(window);
        mmio_transport(at)
    } else {
        let (Ok(ecam), Ok(bar)) = (got.take::<Memory>("ecam"), got.take::<Memory>("bar")) else {
            return NOT_REGISTERED;
        };
        let mapped = sys::mem_map(&s.process, &ecam, 0, PAGE as u64, ECAM_AT, rw)
            .and_then(|()| sys::mem_map(&s.process, &bar, 0, PLACE.bar_len, BAR_AT, rw));
        if mapped.is_err() {
            return NOT_MAPPED;
        }
        windows = [Some(ecam), Some(bar)];
        pci_transport(at)
    };
    let Found {
        mut transport,
        at,
        status,
        pci,
    } = match found {
        Ok(found) => found,
        Err(code) => return code,
    };
    // The device forgets every queue before it may master the bus again
    // (Virtio 1.2, 2.4.1): a stop of an instance that ended may not have
    // run.
    transport.set_status(DeviceStatus::empty());
    if !(0..RESET_READS).any(|_| transport.get_status().is_empty()) {
        return NOT_STARTED;
    }
    if pci {
        let command = config_read(virtio_pci::COMMAND) & 0xFFFF;
        config_write(virtio_pci::COMMAND, virtio_pci::bus_master(command));
    }
    let _: Feature = transport.begin_init(Feature::VERSION_1);
    let Ok(queue) = VirtQueue::<Host, QUEUE_SIZE>::new(&mut transport, REQUESTQ, false, false)
    else {
        return NOT_STARTED;
    };
    transport.finish_init();
    let line = sys::irq_info(&irq).map_or(0, |info| info.line);
    if pci {
        rt::println!("virtio-rng: 1af4:1044 at {at:#x}, line {line}, status {status:#x}");
    } else {
        rt::println!("virtio-rng: virtio-mmio at {at:#x}, line {line}, status {status:#x}");
    }
    let mut driver = Driver {
        transport,
        queue,
        irq,
        flight: None,
        buffer: [0; proto_entropy::FILL_MAX as usize],
        fills: Fills::new(),
        ops: LongOps::new(),
        _dma: dma,
        _windows: windows,
    };
    // The line opens once the queue is up.
    let _ = sys::irq_ack(&driver.irq);
    #[cfg(feature = "steps")]
    rt::service::report_steps(10);
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &s.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    let _ = rt::service::run::<Driver, SESSIONS, 1>(&channel, &mut driver, config);
    STOPPED
}

/// The request the device holds: its token in the queue, the fill it is
/// for, and its length.
#[derive(Clone, Copy)]
struct Flight {
    token: u16,
    label: u64,
    key: u64,
    len: usize,
}

/// The driver: the device and its queue, the binding of its line, the
/// request with the device and the fills that wait.
struct Driver {
    transport: SomeTransport<'static>,
    queue: VirtQueue<Host, QUEUE_SIZE>,
    irq: Handle<Interrupt>,
    flight: Option<Flight>,
    /// The buffer of the request with the device, which the bounce page
    /// is copied into.
    buffer: [u8; proto_entropy::FILL_MAX as usize],
    fills: Fills,
    ops: LongOps<FILLS>,
    /// The DMA object and the windows, mapped for the driver's life.
    _dma: Handle<Memory>,
    _windows: [Option<Handle<Memory>>; 2],
}

impl Driver {
    /// Gives the device a request for the oldest fill that lacks bytes,
    /// when it holds none: the buffer, the barrier and the doorbell
    /// [G34]. The call returns at once: the interrupt brings the bytes.
    fn kick(&mut self) {
        if self.flight.is_some() {
            return;
        }
        let Some((label, key, len)) = self.fills.wanted() else {
            return;
        };
        let len = len.min(self.buffer.len());
        // SAFETY: the buffer lives in the driver, which the queue does not
        // outlive, and nothing touches it until `pop_used` gives it back.
        let token = unsafe { self.queue.add(&[], &mut [&mut self.buffer[..len]]) };
        let Ok(token) = token else {
            return;
        };
        self.flight = Some(Flight {
            token,
            label,
            key,
            len,
        });
        if self.queue.should_notify() {
            rt::dma::wmb();
            self.transport.notify(REQUESTQ);
        }
    }

    /// An interrupt of the line (spec 9): the kernel masked it at
    /// delivery. Reading the ISR (or the interrupt status and its
    /// acknowledgement on virtio-mmio) drops the level; the bytes of the
    /// request go into its fill, whose client hears of it once the fill is
    /// whole; the next request goes; then the line opens again (irq_ack),
    /// source cleared first [G26].
    fn interrupt(&mut self) {
        // The driver's own work, measured apart from the heartbeat.
        rt::service::step_own();
        let _ = self.transport.ack_interrupt();
        if let Some(f) = self.flight
            && self.queue.peek_used() == Some(f.token)
        {
            // SAFETY: the same buffer `kick` added with this token.
            let got = unsafe {
                self.queue
                    .pop_used(f.token, &[], &mut [&mut self.buffer[..f.len]])
            };
            self.flight = None;
            let n = got.map_or(0, |n| (n as usize).min(f.len));
            if self.fills.put(f.label, f.key, &self.buffer[..n]) {
                self.ops.tell(f.label, f.key);
            }
            self.buffer = [0; proto_entropy::FILL_MAX as usize];
        }
        self.kick();
        // The binding lives as long as the driver.
        let _ = sys::irq_ack(&self.irq);
    }

    /// FILL_START: a fill of `n` bytes under a new key; WAIT k, since the
    /// bytes come at the interrupt.
    fn fill_start(&mut self, s: &mut Session<LongSession, 1>, r: &mut Request<'_>) -> Answer {
        let fill = match Fill::read(r.body()) {
            Ok(fill) => fill,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        let key = match self.ops.start(&mut s.data, label) {
            Ok(key) => key,
            Err(error) => return Answer::Status(Status::Kernel(error)),
        };
        if !self.fills.add(label, key, fill.n as usize) {
            self.ops.finish(&mut s.data, label, key);
            return Answer::Status(Status::Kernel(Error::LimitReached));
        }
        self.kick();
        long_answer(r, long::Reply::Wait(key))
    }

    /// FILL_TAKE and FILL_CANCEL: the bytes once they all came, or ARMED
    /// (keeping the handle with NOTIFY the first FILL_TAKE brings), or
    /// CANCELLED.
    fn fill_take(
        &mut self,
        s: &mut Session<LongSession, 1>,
        r: &mut Request<'_>,
        cancel: bool,
    ) -> Answer {
        let key = match Key::read(r.body()) {
            Ok(key) => key.key,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        if !self.ops.waits(label, key) {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let mut bytes = [0; proto_entropy::FILL_MAX as usize];
        match self.fills.take(label, key, &mut bytes) {
            Taken::Ready(n) => {
                self.ops.finish(&mut s.data, label, key);
                long_answer(r, long::Reply::Ready(&bytes[..n]))
            }
            Taken::Waits if cancel => {
                self.fills.cancel(label, key);
                self.ops.finish(&mut s.data, label, key);
                long_answer(r, long::Reply::Cancelled)
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
}

/// The methods of the driver: CRASH only with the feature `crash`.
#[cfg(feature = "crash")]
const METHODS: &[u16] = &[
    Method::FillStart.number(),
    Method::FillTake.number(),
    Method::FillCancel.number(),
    Method::Crash.number(),
];
#[cfg(not(feature = "crash"))]
const METHODS: &[u16] = &[
    Method::FillStart.number(),
    Method::FillTake.number(),
    Method::FillCancel.number(),
];

impl Service<1> for Driver {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = LongSession;

    fn request(&mut self, s: &mut Session<LongSession, 1>, r: &mut Request<'_>) -> Answer {
        match Method::from_number(r.method()) {
            Some(Method::FillStart) => self.fill_start(s, r),
            Some(Method::FillTake) => self.fill_take(s, r, false),
            Some(Method::FillCancel) => self.fill_take(s, r, true),
            #[cfg(feature = "crash")]
            Some(Method::Crash) => crash(r),
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    fn gone(&mut self, s: &mut Session<LongSession, 1>) {
        self.fills.gone(s.label());
        self.ops.gone(&mut s.data);
    }

    fn notification(&mut self, n: Notice) {
        if n.source == Source::Interrupt {
            self.interrupt();
        }
    }
}

/// CRASH: a load from page 0 ends the driver with a fault while the device
/// still has its queue; init stops the device before it lets the DMA
/// object go, and starts the driver again.
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

/// The reply of a long operation, through the request's reply buffer.
fn long_answer(r: &mut Request<'_>, reply: long::Reply<'_>) -> Answer {
    match reply.write(r.reply()) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}
