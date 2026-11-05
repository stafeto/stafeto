// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The driver of the Virtio block device (Virtio 1.2, 5.2) on QEMU's `virt`
//! machine: a service in one thread (rt::service) that reads, writes and
//! flushes the disk for its clients, through the cells of a shared buffer
//! (proto_blk). The device is a Virtio PCI function at device 1 of bus 0
//! (virtio_pci::qemu): init gives the driver the windows `ecam` (the
//! function's page of configuration) and `bar` (BAR 4), `dma`, a contiguous
//! uncached object, with its physical address and the function's in its own
//! arguments, and the binding `irq` of the level-triggered INTx line. The
//! firmware-less machine leaves the BAR at zero: the driver measures it and
//! puts it where the table says (virtio_pci::Bar64), then resets the device
//! and only then turns bus mastering on.
//!
//! The driver never waits for the device: a request goes to the queue (the
//! chain, the barrier and the doorbell), the interrupt brings its answer
//! (the ISR is read to drop the level, `pop_used` for each answer) and
//! tells the client whose operation it was; the line opens again after the
//! source is cleared (irq_ack, [G26]). Data of a write are copied from the
//! client's cell of the shared buffer into a cell of the DMA object before
//! the doorbell, and the data of a read from the DMA object into the
//! client's cell in the step of TAKE, one copy of 16 KiB at most in a step.
//! The copies go through raw pointers: a client that changes its cell while
//! the service copies spoils only its own bytes. The driver is in the
//! trusted base: the device writes where the queue tells it (spec 9, no
//! SMMU on QEMU's virt). Init stops the device before it lets the DMA
//! object of an instance go. The program ends with a code of its own when
//! its start fails; init restarts it.

#![no_std]
#![no_main]

use abi::{Access, Error, Rights, Source};
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use proto_blk::{
    BUFFER_SIZE, CELL_BYTES, Info, Io, Key, Method, SECTOR, VERSION, code, read_buffer,
};
use proto_init::ServiceArgs;
use proto_wire::{Status, long};
use rt::handle::{Channel, Interrupt, Memory, Outgoing, Process, Resource};
use rt::service::{
    Answer, Config, Heartbeat, LongOps, LongSession, Notice, Request, Service, Session,
};
use rt::{Handle, mmio, sys};
use virtio_blk::{
    Cells, Completion, Kind, Outcome, Refusal, Taken, block_size, dma, feature, flags, negotiate,
    request,
};
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::transport::pci::bus::{ConfigurationAccess, DeviceFunction, PciRoot};
use virtio_drivers::transport::{DeviceStatus, Transport};
use virtio_drivers::{BufferDirection, Hal, PhysAddr};
use virtio_mmio::DmaHal;
use virtio_pci::qemu::{DISK, DISK_FUNCTION};

rt::entry!(main);

/// Where the driver maps its DMA object, the function's page of
/// configuration, BAR 4 and the client's shared buffer.
const DMA_AT: usize = 0x10_0000_0000;
const ECAM_AT: usize = 0x10_2000_0000;
const BAR_AT: usize = 0x10_3000_0000;
const BUFFER_AT: usize = 0x10_4000_0000;
/// The sessions of the driver's channel and the operations that wait at once.
const SESSIONS: usize = 2;
const OPERATIONS: usize = 8;
/// The device's one queue, `requestq`.
const REQUESTQ: u16 = 0;
/// The machine kind of the record's arguments: QEMU's `virt`.
const MACHINE_QEMU: u64 = 1;

/// The codes of a start that failed: the start data or `dma`; REGISTER,
/// the windows or the binding; a map; the loop; no disk at the function;
/// the device refused the driver; the common configuration lies elsewhere
/// than at the start of BAR 4; BAR 4 has another size than the table's.
const NO_START_DATA: u64 = 1;
const NOT_REGISTERED: u64 = 3;
const NOT_MAPPED: u64 = 4;
const STOPPED: u64 = 5;
const NO_DEVICE: u64 = 6;
const NOT_STARTED: u64 = 7;
const CONFIG_ELSEWHERE: u64 = 9;
const BAR_SIZE: u64 = 10;

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

/// The DMA of the device's crate: the queue and the buffers of a request
/// lie in the driver's object (virtio_mmio::DmaHal), and BAR 4 is the one
/// window the crate reaches the device's structures through.
struct Host;

// SAFETY: `dma_alloc`, `share` and `unshare` are DmaHal's, which gives
// zeroed pages of the object and the physical address of a buffer inside
// it; `mmio_phys_to_virt` maps only the BAR window.
unsafe impl Hal for Host {
    fn dma_alloc(pages: usize, direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        DmaHal::dma_alloc(pages, direction)
    }

    unsafe fn dma_dealloc(paddr: PhysAddr, vaddr: NonNull<u8>, pages: usize) -> i32 {
        // SAFETY: the crate's own arguments.
        unsafe { DmaHal::dma_dealloc(paddr, vaddr, pages) }
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, size: usize) -> NonNull<u8> {
        let offset = paddr.wrapping_sub(DISK.bar);
        assert!(
            offset.saturating_add(size as u64) <= DISK.len,
            "a Virtio structure outside BAR 4"
        );
        NonNull::new((BAR_AT + offset as usize) as *mut u8).expect("BAR_AT is no null")
    }

    unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> PhysAddr {
        // SAFETY: the crate's own arguments.
        unsafe { DmaHal::share(buffer, direction) }
    }

    unsafe fn unshare(paddr: PhysAddr, buffer: NonNull<[u8]>, direction: BufferDirection) {
        // SAFETY: the crate's own arguments.
        unsafe { DmaHal::unshare(paddr, buffer, direction) }
    }
}

/// A 32-bit register of the function's configuration through the window
/// at ECAM_AT [G34].
fn config_read(offset: usize) -> u32 {
    // SAFETY: the window maps the function's page of configuration at
    // ECAM_AT, read and write, as device memory; `offset` is a register of
    // the function within it.
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

/// The size of BAR 4 of the function, measured with decoding off: all
/// ones into the two registers, the words read back, the old words
/// returned and the command word as it was.
fn measure_bar() -> u64 {
    let command = config_read(virtio_pci::COMMAND) & 0xFFFF;
    config_write(
        virtio_pci::COMMAND,
        command & !(virtio_pci::MEMORY | virtio_pci::IO),
    );
    let (low, high) = (DISK.register(), DISK.register() + 4);
    let (old_low, old_high) = (config_read(low), config_read(high));
    config_write(low, !0);
    config_write(high, !0);
    let size = virtio_blk::bar_size(config_read(low), config_read(high));
    config_write(low, old_low);
    config_write(high, old_high);
    config_write(virtio_pci::COMMAND, command);
    size
}

/// The bytes of the DMA object at `offset`, for the queue's buffers.
///
/// # Safety
/// The range lies in the object, and the caller holds no other slice of
/// it; the device writes the range only while a request has it.
unsafe fn dma_bytes(offset: usize, len: usize) -> &'static mut [u8] {
    // SAFETY: the caller's promise; the object is mapped read and write at
    // DMA_AT.
    unsafe { core::slice::from_raw_parts_mut((DMA_AT + offset) as *mut u8, len) }
}

/// `count` sectors from the staging cell `cell` of the DMA object to the
/// client's cell of the same number (`to_client`), or the other way.
fn copy_cell(cell: usize, count: u32, to_client: bool) {
    let staging = (DMA_AT + dma::cell(cell)) as *mut u8;
    let client = (BUFFER_AT + cell * CELL_BYTES as usize) as *mut u8;
    let (from, to) = if to_client {
        (staging, client)
    } else {
        (client, staging)
    };
    // SAFETY: both cells lie in mapped memory, `count` sectors within the
    // cell's 16 KiB (the request was admitted); a raw copy, since the
    // client may write its cell meanwhile.
    unsafe { core::ptr::copy_nonoverlapping(from, to, count as usize * SECTOR) };
}

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let Ok(dma_object) = s.take::<Memory>("dma") else {
        return NO_START_DATA;
    };
    let args = ServiceArgs::read(s.args()).ok();
    // The own arguments: the DMA object's physical address, which init
    // puts first, then the record's: the function's page and the machine.
    let own = args.map_or(&[][..], |a| a.own);
    let (dma_pa, function, machine) = (word(own, 0), word(own, 8), word(own, 16));
    if machine != MACHINE_QEMU {
        return NO_START_DATA;
    }
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
    let (Ok(ecam), Ok(bar)) = (got.take::<Memory>("ecam"), got.take::<Memory>("bar")) else {
        return NOT_REGISTERED;
    };
    let rw = Access::ReadWrite;
    let mapped = sys::mem_map(
        &s.process,
        &dma_object,
        0,
        (dma::PAGES * dma::PAGE) as u64,
        DMA_AT,
        rw,
    )
    .and_then(|()| sys::mem_map(&s.process, &ecam, 0, dma::PAGE as u64, ECAM_AT, rw))
    .and_then(|()| sys::mem_map(&s.process, &bar, 0, DISK.len, BAR_AT, rw));
    if dma_pa == 0
        || mapped.is_err()
        || !virtio_mmio::attach(DMA_AT, dma_pa, dma::PAGES, dma::QUEUE_PAGES)
    {
        return NOT_MAPPED;
    }
    // The table names the disk's function; one that holds something else
    // ends the driver before it writes there.
    if function != DISK_FUNCTION || config_read(virtio_pci::ID) != DISK.id {
        rt::println!("virtio-blk: no disk device at {function:#x}");
        return NO_DEVICE;
    }
    // init resets the device of an instance that ended through BAR 4 at
    // the offset of `device_status`, so the common configuration must lie
    // at the start of BAR 4.
    if virtio_pci::common_config(config_read) != Some((DISK.index as u8, 0)) {
        return CONFIG_ELSEWHERE;
    }
    let size = measure_bar();
    if size != DISK.len {
        rt::println!(
            "virtio-blk: BAR 4 of {size:#x} bytes, {:#x} expected",
            DISK.len
        );
        return BAR_SIZE;
    }
    let found = config_read(virtio_pci::COMMAND) & 0xFFFF;
    for (offset, value) in DISK.set_up(found) {
        config_write(offset, value);
    }
    let mut root = PciRoot::new(Function);
    let at = DeviceFunction {
        bus: 0,
        device: 0,
        function: 0,
    };
    let Ok(mut transport) = PciTransport::new::<Host, _>(&mut root, at) else {
        return NO_DEVICE;
    };
    // The crate turned bus mastering on with the decoding; the device must
    // be reset before it may master the bus.
    let command = config_read(virtio_pci::COMMAND) & 0xFFFF & !virtio_pci::BUS_MASTER;
    config_write(virtio_pci::COMMAND, command);
    let status = transport.get_status().bits();
    // The device forgets every queue before it may master the bus again
    // (Virtio 1.2, 2.4.1): a stop of an instance that ended may not have
    // run.
    transport.set_status(DeviceStatus::empty());
    if !(0..virtio_mmio::RESET_READS).any(|_| transport.get_status().is_empty()) {
        return NOT_STARTED;
    }
    let command = config_read(virtio_pci::COMMAND) & 0xFFFF;
    config_write(virtio_pci::COMMAND, virtio_pci::bus_master(command));
    // QEMU lets the device master the bus without the bit, and VZ ignores a
    // reset of it, so the machine does not show a driver that lost it: the
    // driver reads the word back.
    if config_read(virtio_pci::COMMAND) & virtio_pci::BUS_MASTER == 0 {
        rt::println!("virtio-blk: bus mastering is off");
        return NOT_STARTED;
    }
    let negotiated = virtio_mmio::start_with(&mut transport, feature::WANTED)
        .ok()
        .and_then(negotiate);
    let Some(features) = negotiated else {
        rt::println!("virtio-blk: features refused");
        return NOT_STARTED;
    };
    let Ok(queue) =
        VirtQueue::<Host, { dma::QUEUE_SIZE }>::new(&mut transport, REQUESTQ, false, false)
    else {
        return NOT_STARTED;
    };
    transport.finish_init();
    let capacity = {
        let low = transport.read_config_space::<u32>(0).unwrap_or(0);
        let high = transport.read_config_space::<u32>(4).unwrap_or(0);
        u64::from(high) << 32 | u64::from(low)
    };
    let block = block_size(
        features,
        transport.read_config_space::<u32>(20).unwrap_or(0),
    );
    let line = sys::irq_info(&irq).map_or(0, |info| info.line);
    rt::println!(
        "virtio-blk: 1af4:1042 at {function:#x}, line {line}, status {status:#x}, {capacity} sectors"
    );
    let mut driver = Driver {
        transport,
        queue,
        irq,
        cells: Cells::new(capacity, flags(features)),
        ops: LongOps::new(),
        id_token: None,
        info: Info {
            sectors: capacity,
            block,
            flags: flags(features),
        },
        buffer: None,
        process: Handle::borrowed(s.process.raw()),
        _dma: dma_object,
        _windows: [ecam, bar],
    };
    // The line opens once the queue is up.
    let _ = sys::irq_ack(&driver.irq);
    driver.ask_for_id();
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
    let _ = rt::service::run::<Driver, SESSIONS, 0>(&channel, &mut driver, config);
    STOPPED
}

/// The driver: the device and its queue, the binding of its line, the
/// places of the requests with the device, the operations that wait and
/// the session that holds the shared buffer.
struct Driver {
    transport: PciTransport,
    queue: VirtQueue<Host, { dma::QUEUE_SIZE }>,
    irq: Handle<Interrupt>,
    cells: Cells,
    ops: LongOps<OPERATIONS>,
    /// The token of the GET_ID the start asked for, until it is answered.
    id_token: Option<u16>,
    info: Info,
    /// The label of the session whose buffer is mapped at BUFFER_AT.
    buffer: Option<u64>,
    /// The driver's own process, borrowed from the start data, which
    /// outlives the loop.
    process: core::mem::ManuallyDrop<Handle<Process>>,
    /// The DMA object and the windows, mapped for the driver's life.
    _dma: Handle<Memory>,
    _windows: [Handle<Memory>; 2],
}

impl Driver {
    /// The device's request with the chain of `place`: the header and, by
    /// the kind, the data and the status byte. Gives the token, or None
    /// when the queue refused the chain.
    fn submit(&mut self, place: usize, kind: Kind, sector: u64, count: u32) -> Option<u16> {
        let (hdr, status) = (dma::header(place), dma::status(place));
        let len = count as usize * SECTOR;
        let kind_word = match kind {
            Kind::Read => request::IN,
            Kind::Write => request::OUT,
            Kind::Flush => request::FLUSH,
        };
        // SAFETY (all of the slices below): the ranges are those of
        // `place` in the object, which no other request uses, and only
        // this function and `reap` make slices of them.
        unsafe {
            dma_bytes(hdr, request::HEADER_LEN)
                .copy_from_slice(&request::header(kind_word, sector));
            dma_bytes(status, 1)[0] = request::PENDING;
        }
        let header = unsafe { &*dma_bytes(hdr, request::HEADER_LEN) };
        let status = unsafe { dma_bytes(status, 1) };
        let token = match kind {
            Kind::Read => unsafe {
                let data = dma_bytes(dma::cell(place), len);
                self.queue.add(&[header], &mut [data, status])
            },
            Kind::Write => unsafe {
                let data = &*dma_bytes(dma::cell(place), len);
                self.queue.add(&[header, data], &mut [status])
            },
            Kind::Flush => unsafe { self.queue.add(&[header], &mut [status]) },
        };
        token.ok()
    }

    /// Rings the doorbell once the requests are in the queue: the stores of
    /// the descriptors and the ring reach the device first.
    fn ring(&mut self) {
        if self.queue.should_notify() {
            rt::dma::wmb();
            self.transport.notify(REQUESTQ);
        }
    }

    /// GET_ID, the first request: its answer comes only by the interrupt,
    /// which shows that the line and the bus mastering work.
    fn ask_for_id(&mut self) {
        let (hdr, status) = (dma::header(dma::ID_PLACE), dma::status(dma::ID_PLACE));
        // SAFETY: the ranges belong to the place of GET_ID alone.
        let token = unsafe {
            dma_bytes(hdr, request::HEADER_LEN)
                .copy_from_slice(&request::header(request::GET_ID, 0));
            dma_bytes(status, 1)[0] = request::PENDING;
            let header = &*dma_bytes(hdr, request::HEADER_LEN);
            self.queue.add(
                &[header],
                &mut [dma_bytes(dma::id(), dma::ID_LEN), dma_bytes(status, 1)],
            )
        };
        self.id_token = token.ok();
        self.ring();
    }

    /// The answer of the device to the request `token` is taken from the
    /// queue: its status byte, or IOERR for an answer the queue refuses.
    fn reap(&mut self, token: u16, place: usize, kind: Kind, count: u32) -> Outcome {
        let (hdr, status) = (dma::header(place), dma::status(place));
        let len = count as usize * SECTOR;
        // SAFETY: the same ranges `submit` gave this token.
        let popped = unsafe {
            let header = &*dma_bytes(hdr, request::HEADER_LEN);
            let status = dma_bytes(status, 1);
            match kind {
                Kind::Read => self.queue.pop_used(
                    token,
                    &[header],
                    &mut [dma_bytes(dma::cell(place), len), status],
                ),
                Kind::Write => {
                    let data = &*dma_bytes(dma::cell(place), len);
                    self.queue.pop_used(token, &[header, data], &mut [status])
                }
                Kind::Flush => self.queue.pop_used(token, &[header], &mut [status]),
            }
        };
        if popped.is_err() {
            return Outcome::Io;
        }
        // SAFETY: the byte the device wrote; read once, volatile.
        let byte = unsafe { core::ptr::read_volatile((DMA_AT + dma::status(place)) as *const u8) };
        Outcome::from_byte(byte)
    }

    /// The answer to GET_ID: the device's ID, a line.
    fn got_id(&mut self, token: u16) {
        let (hdr, status) = (dma::header(dma::ID_PLACE), dma::status(dma::ID_PLACE));
        // SAFETY: the ranges `ask_for_id` gave this token.
        let popped = unsafe {
            let header = &*dma_bytes(hdr, request::HEADER_LEN);
            self.queue.pop_used(
                token,
                &[header],
                &mut [dma_bytes(dma::id(), dma::ID_LEN), dma_bytes(status, 1)],
            )
        };
        self.id_token = None;
        // SAFETY: as above.
        let id = unsafe { &*dma_bytes(dma::id(), dma::ID_LEN) };
        let end = id.iter().position(|&b| b == 0).unwrap_or(id.len());
        let name = core::str::from_utf8(&id[..end]).unwrap_or("?");
        if popped.is_ok() {
            rt::println!(
                "virtio-blk: id {name}, {}",
                virtio_blk::describe(self.info.flags)
            );
        }
    }

    /// An interrupt of the line (spec 9): the kernel masked it at
    /// delivery. Reading the ISR drops the level; every answer in the queue
    /// changes the state of its place and tells the client that waits; then
    /// the line opens again (irq_ack), source cleared first [G26].
    fn interrupt(&mut self) {
        // The driver's own work, measured apart from the heartbeat.
        rt::service::step_own();
        let isr = virtio_mmio::Isr::read(&mut self.transport);
        if isr.config() {
            rt::println!("virtio-blk: the configuration changed");
        }
        while let Some(token) = self.queue.peek_used() {
            if self.id_token == Some(token) {
                self.got_id(token);
                continue;
            }
            let Some(place) = self.cells.find(token) else {
                // An answer for a request the driver does not know; it
                // cannot be taken back without its buffers.
                rt::println!("virtio-blk: an answer to the unknown request {token}");
                break;
            };
            let (kind, count) = self.cells.request(place);
            let outcome = self.reap(token, place, kind, count);
            if let Completion::Tell { label, key } = self.cells.complete(place, outcome) {
                self.ops.tell(label, key);
            }
        }
        // The binding lives as long as the driver.
        let _ = sys::irq_ack(&self.irq);
    }

    fn refuse(&self, refusal: Refusal) -> Answer {
        Answer::Status(refusal.status())
    }

    /// READ and WRITE: a request for the device, WAIT k.
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
        if kind == Kind::Write {
            copy_cell(place, io.count, false);
        }
        self.start(s, r, place, kind, io.sector, io.count)
    }

    fn flush(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        match self.cells.admit_flush() {
            Ok(place) => self.start(s, r, place, Kind::Flush, 0, 0),
            Err(refusal) => self.refuse(refusal),
        }
    }

    /// The request of `kind` in `place` goes to the device under a new key.
    fn start(
        &mut self,
        s: &mut Session<LongSession, 0>,
        r: &mut Request<'_>,
        place: usize,
        kind: Kind,
        sector: u64,
        count: u32,
    ) -> Answer {
        let label = r.label();
        let key = match self.ops.start(&mut s.data, label) {
            Ok(key) => key,
            Err(error) => return Answer::Status(Status::Kernel(error)),
        };
        let Some(token) = self.submit(place, kind, sector, count) else {
            self.ops.finish(&mut s.data, label, key);
            return Answer::Status(code(proto_blk::IO));
        };
        self.cells.begin(place, kind, label, key, token, count);
        self.ring();
        long_answer(r, long::Reply::Wait(key))
    }

    /// BUFFER: the object the request carries becomes the session's shared
    /// buffer, mapped for the session's life.
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
        // An object of `mem_create`: as big as asked and with every page
        // its own (a device window owns none).
        match sys::memory_info(&object) {
            Ok(info)
                if info.size >= u64::from(BUFFER_SIZE)
                    && info.pages * dma::PAGE as u64 >= u64::from(BUFFER_SIZE) => {}
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
                // The mapping keeps the object; the handle goes.
                Answer::Status(Status::Ok)
            }
            Err(Error::NoMemory | Error::LimitReached) => {
                Answer::Status(Status::Kernel(Error::LimitReached))
            }
            Err(error) => Answer::Status(Status::Kernel(error)),
        }
    }

    /// TAKE: the result once the device answered, or ARMED (keeping the
    /// handle with NOTIFY the first TAKE brings).
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
                if done.kind == Kind::Read {
                    copy_cell(done.place, done.count, true);
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
}

/// The methods of the driver: CRASH only with the feature `crash`.
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

impl Service<0> for Driver {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = LongSession;

    fn request(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
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
            // SAFETY: nothing of the service's own lies in the buffer's
            // range; the bytes there are the client's.
            let gone = unsafe { sys::mem_unmap(&self.process, BUFFER_AT, u64::from(BUFFER_SIZE)) };
            if gone.is_ok() {
                self.buffer = None;
            }
        }
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
