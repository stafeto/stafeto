// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The driver of the Virtio input device (Virtio 1.2, 5.8) on a
//! virtio-mmio transport, the keyboard: the input service of stafeto
//! (spec 3, 3.6). It keeps the event queue full of buffers of 8 bytes in
//! the page of its DMA object, and each event the device writes is read
//! at the interrupt, returned to the queue, and put in the ring of the
//! focus (`focus`) when someone holds it. At most one session holds the
//! focus: the display service asks for it (GRANT) when the screen gets an
//! owner and takes it back (REVOKE) when the screen goes back; the owner
//! reads its events without waiting (READ). Only key presses and releases
//! pass (`proto_input::Event::passes`).
//!
//! The driver never waits for the device: the queue is full of buffers, the
//! interrupt brings the events, read through the ISR and `pop_used`; the
//! line opens again after the source is cleared (irq_ack, [G26]).
//!
//! Init gives the driver `dma` (4 pages, contiguous and uncached) with its
//! physical address first in the own arguments, the transport's address
//! after it, the window `mmio` and the binding `irq`. The driver is in
//! the trusted base: the device writes where the queue tells it (spec 9,
//! no SMMU on QEMU's virt). Init stops the device (Status 0) before it
//! lets the object of an instance go. The program ends with a code of its
//! own when its start fails; init starts it again.

#![no_std]
#![no_main]

use abi::{Access, Rights, Source};
use core::alloc::{GlobalAlloc, Layout};
use core::mem::ManuallyDrop;
use core::slice;
use proto_init::ServiceArgs;
use proto_input::{
    EVENT_LEN, Event, MAX_READ, Method, NOT_ALLOWED, REVOKED, VERSION, code, read_max, write_events,
};
use proto_wire::Status;
use rt::handle::{Channel, Interrupt, Memory, Outgoing, Resource};
use rt::service::{Answer, Config, Heartbeat, Notice, Request, Service, Session};
use rt::{Handle, sys};
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::Transport;
use virtio_drivers::transport::mmio::MmioTransport;
use virtio_input::config;
use virtio_input::dma::{BUFFER_PAGE, PAGE, PAGES, QUEUE_PAGES, QUEUE_SIZE, buffer_at};
use virtio_input::focus::{self, Focus, Refusal};
use virtio_mmio::{DmaHal, Isr, OpenError, StartError};

rt::entry!(main);

/// Where the driver maps its DMA object and the transport's page.
const DMA_AT: usize = 0x10_0000_0000;
const MMIO_AT: usize = 0x10_1000_0000;
/// The sessions of the driver's channel: init's for the display service,
/// the focus, and the revoked ones whose holders have not ended yet.
const SESSIONS: usize = 16;
/// The device's one queue that carries events, `eventq`.
const EVENTQ: u16 = 0;
/// The most events one step takes from the queue: the rest wait for the
/// driver's notification to itself, between which the requests of the
/// clients are served. A step of 16 stays under 0.9 of term B (xtask).
const PER_STEP: u64 = 16;
/// The bit of the driver's notification to its own channel: more events
/// wait in the queue.
const MORE: u64 = 1;

/// The codes of a start that failed: the start data or `dma`; REGISTER, the
/// window or the binding; a map; the loop; no input device at the
/// transport; the device refused the driver or the queue.
const NO_START_DATA: u64 = 1;
const NOT_REGISTERED: u64 = 3;
const NOT_MAPPED: u64 = 4;
const STOPPED: u64 = 5;
const NO_INPUT: u64 = 6;
const NOT_STARTED: u64 = 7;

/// The heap the device's crate may ask for: none (the queue has no
/// indirect entries, the only thing of the crate that allocates).
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

/// The first 8 bytes of `own` from `at`, little-endian; 0 without them.
fn word(own: &[u8], at: usize) -> u64 {
    own.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

/// The address in the driver of buffer `slot` of the events.
fn buffer(slot: usize) -> usize {
    DMA_AT + BUFFER_PAGE * PAGE + buffer_at(slot)
}

/// What the device says for the config selection (`select`, `subsel`):
/// its bytes in `out`, how many.
fn selected(
    transport: &mut MmioTransport<'static>,
    select: u8,
    subsel: u8,
    out: &mut [u8; config::DATA_MAX],
) -> usize {
    let _ = transport.write_config_space::<u8>(config::SELECT, select);
    let _ = transport.write_config_space::<u8>(config::SUBSEL, subsel);
    let size = transport
        .read_config_space::<u8>(config::SIZE)
        .map_or(0, usize::from)
        .min(config::DATA_MAX);
    for (i, byte) in out.iter_mut().enumerate().take(size) {
        *byte = transport
            .read_config_space::<u8>(config::DATA + i)
            .unwrap_or(0);
    }
    size
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
    // The own arguments: the physical address of `dma`, which init puts
    // first, then the record's, where the transport is.
    let own = args.map_or(&[][..], |a| a.own);
    let (dma_pa, at) = (word(own, 0), word(own, 8));
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return NOT_REGISTERED;
    };
    let Ok(mut got) = rt::service::register(&s.parent, &channel) else {
        return NOT_REGISTERED;
    };
    let (Ok(irq), Ok(window)) = (got.take::<Interrupt>("irq"), got.take::<Memory>("mmio")) else {
        return NOT_REGISTERED;
    };
    let rw = Access::ReadWrite;
    let page = PAGE as u64;
    if dma_pa == 0
        || sys::mem_map(&s.process, &dma, 0, PAGES as u64 * page, DMA_AT, rw).is_err()
        || sys::mem_map(&s.process, &window, 0, page, MMIO_AT, rw).is_err()
        || !virtio_mmio::attach(DMA_AT, dma_pa, PAGES, QUEUE_PAGES)
    {
        return NOT_MAPPED;
    }
    let base = MMIO_AT + (at as usize & (PAGE - 1));
    // SAFETY: the window maps the transport's page at MMIO_AT as device
    // memory, read and write; `base` is the transport within it, and only
    // the transport reaches the registers from here on.
    let opened = unsafe { virtio_mmio::transport(base, virtio_mmio::device::INPUT) };
    let (mut transport, status) = match opened {
        Ok(found) => found,
        Err(error) => {
            match error {
                OpenError::Rejected(why) => {
                    rt::println!("virtio-input: no input device at {at:#x}: {why:?}")
                }
                OpenError::Unusable => {
                    rt::println!("virtio-input: no usable transport at {at:#x}")
                }
            }
            return NO_INPUT;
        }
    };
    if let Err(StartError::Reset | StartError::Features) = virtio_mmio::start(&mut transport) {
        return NOT_STARTED;
    }
    let Ok(queue) = VirtQueue::<DmaHal, QUEUE_SIZE>::new(&mut transport, EVENTQ, false, false)
    else {
        return NOT_STARTED;
    };
    let Ok(notify) = sys::handle_duplicate(&channel, Rights::NOTIFY) else {
        return NOT_REGISTERED;
    };
    let mut driver = Driver {
        transport,
        queue,
        irq,
        channel: Handle::borrowed(channel.raw()),
        level,
        notify,
        focus: Focus::new(),
        slot_of: [0; QUEUE_SIZE],
        _maps: (dma, window),
    };
    // Every buffer is the device's before it is turned on.
    for slot in 0..QUEUE_SIZE {
        if !driver.offer(slot) {
            return NOT_STARTED;
        }
    }
    driver.transport.finish_init();
    let line = sys::irq_info(&driver.irq).map_or(0, |info| info.line);
    rt::println!("virtio-input: virtio-mmio at {at:#x}, line {line}, status {status:#x}");
    driver.describe();
    // The doorbell for the buffers, and the line opens.
    if driver.queue.should_notify() {
        virtio_mmio::ring(&mut driver.transport, EVENTQ);
    }
    virtio_mmio::reopen(&driver.irq);
    #[cfg(feature = "steps")]
    rt::service::report_steps(13);
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

/// The driver: the device and its queue, the binding of its line, and the
/// focus.
struct Driver {
    transport: MmioTransport<'static>,
    queue: VirtQueue<DmaHal, QUEUE_SIZE>,
    irq: Handle<Interrupt>,
    /// The loop's channel, to make sessions of focus from.
    channel: ManuallyDrop<Handle<Channel>>,
    /// A copy of the channel with NOTIFY, for the notifications to itself.
    notify: Handle<Channel>,
    level: u8,
    focus: Focus,
    /// The buffer each token of the queue stands for.
    slot_of: [u8; QUEUE_SIZE],
    /// The object and the window, mapped for the driver's life.
    _maps: (Handle<Memory>, Handle<Memory>),
}

impl Driver {
    /// Puts buffer `slot` in the queue for the device to write an event
    /// into; false when the queue refuses.
    fn offer(&mut self, slot: usize) -> bool {
        // SAFETY: the buffer is 8 bytes of the DMA object's page of
        // buffers, mapped read and write at DMA_AT; no one else touches it
        // while the device has it (`reap` gives it back after reading).
        let bytes = unsafe { slice::from_raw_parts_mut(buffer(slot) as *mut u8, EVENT_LEN) };
        // SAFETY: the buffer stays valid and untouched until `pop_used`
        // returns it.
        let sent = unsafe { self.queue.add(&[], &mut [bytes]) };
        match sent {
            Ok(token) => {
                if let Some(entry) = self.slot_of.get_mut(usize::from(token)) {
                    *entry = slot as u8;
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    /// The device's name and the keys it has, once in the log.
    fn describe(&mut self) {
        let mut name = [0u8; config::DATA_MAX];
        let n = selected(&mut self.transport, config::ID_NAME, 0, &mut name);
        // The device may count the string's end among its bytes.
        let name = core::str::from_utf8(&name[..n])
            .unwrap_or("?")
            .trim_end_matches('\0');
        let mut keys = [0u8; config::DATA_MAX];
        let n = selected(
            &mut self.transport,
            config::EV_BITS,
            proto_input::EV_KEY as u8,
            &mut keys,
        );
        let (count, first) = config::key_summary(&keys[..n]);
        rt::println!("input: {name}, keys {first:#x} ({count} codes)");
    }

    /// An interrupt of the line (spec 9): the kernel masked it at
    /// delivery. Reading the ISR drops the level; the events the device
    /// wrote are taken, their buffers go back to it (`drain`).
    fn interrupt(&mut self) {
        // The driver's own work, measured apart from the heartbeat.
        rt::service::step_own();
        let isr = Isr::read(&mut self.transport);
        if isr.queue() {
            self.drain();
        } else {
            virtio_mmio::reopen(&self.irq);
        }
    }

    /// Takes up to PER_STEP events; when the queue holds more, the driver
    /// notifies itself for the next step and the line stays closed. With
    /// the queue empty the line opens again (irq_ack), source cleared
    /// first [G26].
    fn drain(&mut self) {
        let (taken, sound) = self.reap(PER_STEP);
        // The events of the step, for the line of the longest.
        rt::service::step_detail(taken);
        // A buffer that could not be taken back stays in the ring: no step
        // is asked for it again and again.
        if sound && self.queue.peek_used().is_some() && sys::notify(&self.notify, MORE).is_ok() {
            return;
        }
        virtio_mmio::reopen(&self.irq);
    }

    /// Takes up to `most` events the device returned to the focus, and
    /// gives their buffers back; how many, and whether no buffer failed.
    fn reap(&mut self, most: u64) -> (u64, bool) {
        let mut taken = 0u64;
        let mut sound = true;
        while taken < most
            && let Some(token) = self.queue.peek_used()
        {
            let Some(&slot) = self.slot_of.get(usize::from(token)) else {
                rt::println!("virtio-input: a used buffer {token} out of the queue");
                sound = false;
                break;
            };
            let slot = usize::from(slot);
            // SAFETY: the same buffer `offer` added with this token; the
            // device is done with it.
            let popped = unsafe {
                let bytes = slice::from_raw_parts_mut(buffer(slot) as *mut u8, EVENT_LEN);
                self.queue.pop_used(token, &[], &mut [&mut *bytes])
            };
            let Ok(len) = popped else {
                rt::println!("virtio-input: the used buffer {token} could not be taken back");
                sound = false;
                break;
            };
            if len as usize >= EVENT_LEN {
                // SAFETY: as above; read before the buffer goes back.
                let bytes = unsafe { *(buffer(slot) as *const [u8; EVENT_LEN]) };
                self.focus.event(Event::from_bytes(bytes));
            }
            if !self.offer(slot) {
                rt::println!("virtio-input: buffer {slot} could not go back to the queue");
                sound = false;
                break;
            }
            taken += 1;
        }
        if taken > 0 && self.queue.should_notify() {
            virtio_mmio::ring(&mut self.transport, EVENTQ);
        }
        (taken, sound)
    }

    /// GRANT: a new session of focus, which revokes the one before.
    fn grant(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let label = self.focus.grant();
        // A handle in a reply must carry TRANSFER (spec 6.1), and the
        // display service passes this one on to the owner of the screen.
        let rights = Rights::SEND | Rights::TRANSFER;
        match sys::handle_label(&self.channel, rights, label, self.level) {
            Ok(session) => {
                if r.reply().u32(Status::Ok.code()).is_err() {
                    self.focus.revoke();
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply([session.erase()].into())
            }
            Err(error) => {
                self.focus.revoke();
                Answer::Status(Status::Kernel(error))
            }
        }
    }

    /// REVOKE: the focus ends.
    fn revoke(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        self.focus.revoke();
        Answer::Status(Status::Ok)
    }

    /// READ by the focus: the events there are, none included.
    fn read(&mut self, r: &mut Request<'_>) -> Answer {
        let max = match read_max(r.body()) {
            Ok(max) => max as usize,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let mut out = [Event::default(); MAX_READ as usize];
        match self.focus.read(r.label(), &mut out[..max]) {
            Ok((count, lost)) => {
                if write_events(&out[..count], lost, r.reply()).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply(Outgoing::new())
            }
            Err(Refusal::Revoked) => Answer::Status(code(REVOKED)),
        }
    }
}

impl Service<1> for Driver {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = &[
        Method::Grant.number(),
        Method::Revoke.number(),
        Method::Read.number(),
    ];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, r: &mut Request<'_>) -> Answer {
        let Some(method) = Method::from_number(r.method()) else {
            return Answer::Status(Status::UnknownMethod);
        };
        // The display service's session grants and revokes; the focus
        // reads: the other method is not theirs.
        if !focus::allowed(r.label(), method) {
            return Answer::Status(code(NOT_ALLOWED));
        }
        match method {
            Method::Grant => self.grant(r),
            Method::Revoke => self.revoke(r),
            Method::Read => self.read(r),
        }
    }

    /// The last copy of a session went: the focus's ends the focus.
    fn closed(&mut self, label: u64) {
        self.focus.closed(label);
    }

    fn notification(&mut self, n: Notice) {
        match n.source {
            Source::Interrupt => self.interrupt(),
            Source::Unlabeled if n.bits & MORE != 0 => {
                rt::service::step_own();
                self.drain();
            }
            _ => {}
        }
    }
}
