// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The driver of the Virtio GPU in 2D mode (Virtio 1.2, 5.7) on a
//! virtio-mmio transport: the display service of stafeto (spec 3). One
//! screen of 640 by 400 points, one owner at a time (`owner`), who draws in
//! the buffer init made (the object `fb`, a megabyte of cached memory, the
//! device's resource 1 over it) and shows what it drew with FLUSH: a
//! TRANSFER_TO_HOST_2D and a RESOURCE_FLUSH of the rectangle. The commands
//! are the driver's own (`commands`); of the device's crate it takes the
//! transport and the queue, as the entropy device's driver does, because
//! its GPU driver waits for the device by spinning and allocates the
//! framebuffer itself.
//!
//! The driver never waits for the device: a command goes into the control
//! queue as a request (`add`, the barrier, the doorbell) and the interrupt
//! brings its answer, read through the ISR and `pop_used`; the line opens
//! again after the source is cleared (irq_ack, [G26]). The setup commands
//! (display info, the resource, its backing) go the same way, one after
//! another from the interrupts, and OPEN answers CLEARING until they are
//! done. A FLUSH and an OPEN are deferred replies the interrupt answers.
//! The screen's return to free (the scanout off, then 64 portions of 16
//! KiB cleared, each one a step) is driven by the owner's machine
//! (`owner`) and the driver's notifications to its own channel.
//!
//! The input service (spec 3, 3.6) is the driver's own client: an OPEN asks
//! it for a session of focus (GRANT) and passes it on to the owner with
//! the buffer and the owner's session; the screen's return asks it to end
//! the focus (REVOKE). The driver connects to it by init's table
//! (`connects`) when it starts. An image with no input service in the
//! table is refused the connection, and OPEN's status is NO_INPUT, the
//! screen the client's all the same; so it is when GRANT fails.
//!
//! Init gives the driver `dma` (16 pages, contiguous and uncached: the
//! queue, then the commands and their answers) and `fb` (256 pages,
//! contiguous and cached) with their physical addresses first in the own
//! arguments, the transport's address after them, the window `mmio` and
//! the binding `irq`. The driver is in the trusted base: the device writes
//! where the queue tells it (spec 9, no SMMU on QEMU's virt). Init stops
//! the device (Status 0) before it lets the objects of an instance go. The
//! program ends with a code of its own when its start fails; init starts
//! it again.

#![no_std]
#![no_main]

use abi::{Access, Error, Rights, Source};
use core::alloc::{GlobalAlloc, Layout};
use core::mem::ManuallyDrop;
use core::slice;
use proto_gpu::{
    BUSY, CLEARING, IO, Method, NO_DEVICE, NO_INPUT, NOT_ALLOWED, REVOKED, Rect, STRIDE, Screen,
    VERSION, code,
};
use proto_init::ServiceArgs;
use proto_input::{self, Method as InputMethod};
use proto_wire::clones::Clones;
use proto_wire::{Status, Writer};
use rt::handle::{Any, Channel, Interrupt, Memory, Outgoing, Resource};
use rt::service::{Answer, Config, Heartbeat, Notice, Pending, Request, Service, Session};
use rt::{Handle, sys};
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::Transport;
use virtio_drivers::transport::mmio::MmioTransport;
use virtio_gpu::commands::{self, COMMAND_MAX, HEADER, INFO_REPLY};
use virtio_gpu::dma::{
    ANSWER_AT, COMMAND_AT, INFO_AT, PAGE, PAGES, QUEUE_PAGES, QUEUE_SIZE, STAGE_PAGE,
};
use virtio_gpu::owner::{self, Owner, Refusal};
use virtio_mmio::{DmaHal, Isr, OpenError, StartError};

rt::entry!(main);

/// Where the driver maps its DMA object, the screen's buffer and the
/// transport's page.
const DMA_AT: usize = 0x10_0000_0000;
const FB_AT: usize = 0x10_0100_0000;
const MMIO_AT: usize = 0x10_1000_0000;
/// The sessions of the driver's channel: every POSIX process may hold one
/// `Display` session, init's or a clone, and the owner's session is one
/// more; room beside them.
const SESSIONS: usize = 96;
/// The clones the driver keeps alive at most, for all its clients.
const CLONES: usize = 64;
/// The mark of the labels CLONE gives (bit 63, as the entropy service has
/// it); the owner's labels carry bit 62 (`owner::TAG`).
const OWN: u64 = 1 << 63;
/// The bit of the driver's notification to its own channel: a portion of
/// clearing is due.
const CLEAR: u64 = 1;
/// The device's one queue that carries the commands, `controlq`.
const CONTROLQ: u16 = 0;

/// The codes of a start that failed: the start data or `dma`; REGISTER, the
/// window or the binding; a map; no GPU at the transport; the device
/// refused the driver; the queue; the loop.
const NO_START_DATA: u64 = 1;
const NOT_REGISTERED: u64 = 3;
const NOT_MAPPED: u64 = 4;
const STOPPED: u64 = 5;
const NO_GPU: u64 = 6;
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

/// The address in the driver of byte `offset` of the page of the commands.
fn stage(offset: usize) -> usize {
    DMA_AT + STAGE_PAGE * PAGE + offset
}

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let (Ok(dma), Ok(fb)) = (s.take::<Memory>("dma"), s.take::<Memory>("fb")) else {
        return NO_START_DATA;
    };
    let args = ServiceArgs::read(s.args()).ok();
    // The own arguments: the physical addresses of `dma` and `fb`, which
    // init puts first, then the record's, where the transport is.
    let own = args.map_or(&[][..], |a| a.own);
    let (dma_pa, fb_pa, at) = (word(own, 0), word(own, 8), word(own, 16));
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
    let fb_len = u64::from(proto_gpu::BUFFER_BYTES);
    if dma_pa == 0
        || fb_pa == 0
        || sys::mem_map(&s.process, &dma, 0, PAGES as u64 * page, DMA_AT, rw).is_err()
        || sys::mem_map(&s.process, &fb, 0, fb_len, FB_AT, rw).is_err()
        || sys::mem_map(&s.process, &window, 0, page, MMIO_AT, rw).is_err()
        || !virtio_mmio::attach(DMA_AT, dma_pa, PAGES, QUEUE_PAGES)
    {
        return NOT_MAPPED;
    }
    let base = MMIO_AT + (at as usize & (PAGE - 1));
    // SAFETY: the window maps the transport's page at MMIO_AT as device
    // memory, read and write; `base` is the transport within it, and only
    // the transport reaches the registers from here on.
    let opened = unsafe { virtio_mmio::transport(base, virtio_mmio::device::GPU) };
    let (mut transport, status) = match opened {
        Ok(found) => found,
        Err(error) => {
            match error {
                OpenError::Rejected(why) => {
                    rt::println!("virtio-gpu: no GPU device at {at:#x}: {why:?}")
                }
                OpenError::Unusable => rt::println!("virtio-gpu: no usable transport at {at:#x}"),
            }
            return NO_GPU;
        }
    };
    match virtio_mmio::start(&mut transport) {
        Ok(()) => {}
        Err(StartError::Reset | StartError::Features) => return NOT_STARTED,
    }
    let Ok(queue) = VirtQueue::<DmaHal, QUEUE_SIZE>::new(&mut transport, CONTROLQ, false, false)
    else {
        return NOT_STARTED;
    };
    transport.finish_init();
    let line = sys::irq_info(&irq).map_or(0, |info| info.line);
    rt::println!("virtio-gpu: virtio-mmio at {at:#x}, line {line}, status {status:#x}");
    let (Ok(notify), Ok(copy)) = (
        sys::handle_duplicate(&channel, Rights::NOTIFY),
        sys::handle_duplicate(
            &fb,
            Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER | Rights::DUPLICATE,
        ),
    ) else {
        return NOT_REGISTERED;
    };
    let mut driver = Driver {
        transport,
        queue,
        irq,
        channel: Handle::borrowed(channel.raw()),
        notify,
        level,
        fb_pa,
        owner: Owner::new(),
        clones: Clones::new(),
        setup: Setup::Info,
        flight: None,
        opening: None,
        parent: Handle::borrowed(s.parent.raw()),
        input: Link::Absent,
        focus_on: false,
        showing: None,
        queued: None,
        fb: copy,
        _maps: (dma, fb, window),
    };
    driver.input = driver.connect_input();
    // The line opens once the queue is up, and the setup commands begin.
    virtio_mmio::reopen(&driver.irq);
    driver.pump();
    #[cfg(feature = "steps")]
    rt::service::report_steps(12);
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

/// Where the device's setup stands: the commands go in this order, each
/// from the answer to the one before.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Setup {
    Info,
    Create,
    Attach,
    Ready,
    /// A command of the setup failed, or could not be sent: no screen to
    /// give.
    Failed,
}

/// What the commands in the queue are for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Job {
    Info,
    Create,
    Attach,
    /// SET_SCANOUT with the resource, for an OPEN.
    ScanoutOn,
    /// SET_SCANOUT with resource 0, on the way back.
    ScanoutOff,
    /// TRANSFER_TO_HOST_2D and RESOURCE_FLUSH, for a FLUSH.
    Show,
}

/// One command in the queue: its token, where its bytes and its answer
/// lie (offsets in the page of commands) and how long they are.
#[derive(Clone, Copy)]
struct Chain {
    token: u16,
    command: usize,
    command_len: usize,
    answer: usize,
    answer_len: usize,
}

/// The commands the device holds for one job (one or two chains), and how
/// many came back; `bad` once one answered with an error.
struct Flight {
    job: Job,
    chains: [Option<Chain>; 2],
    done: u8,
    bad: bool,
}

/// An OPEN waiting for its SET_SCANOUT: the reply, the owner's label, the
/// handles the reply carries (the buffer, the owner's session, and the
/// focus when the input service gave one).
struct Opening {
    pending: Pending,
    label: u64,
    handles: Outgoing,
    focus: bool,
}

/// The driver's link to the input service.
enum Link {
    /// The image has none: init's table gives the driver no connection.
    Absent,
    /// A session of the service.
    Linked(Handle<Channel>),
    /// The service ended or could not be reached: connect again at the
    /// next OPEN.
    Lost,
}

/// The driver: the device and its queue, the binding of its line, the
/// owner of the screen, and what waits for the device.
struct Driver {
    transport: MmioTransport<'static>,
    queue: VirtQueue<DmaHal, QUEUE_SIZE>,
    irq: Handle<Interrupt>,
    /// The loop's channel, to make sessions from, and a copy with NOTIFY
    /// for the portions of clearing.
    channel: ManuallyDrop<Handle<Channel>>,
    notify: Handle<Channel>,
    level: u8,
    fb_pa: u64,
    owner: Owner,
    /// The `Display` sessions CLONE gave that live, bounded for each
    /// client.
    clones: Clones<CLONES>,
    setup: Setup,
    flight: Option<Flight>,
    opening: Option<Opening>,
    /// Init's channel, to connect to the input service by, and the link to
    /// that service.
    parent: ManuallyDrop<Handle<Channel>>,
    input: Link,
    /// Whether the focus of the screen's owner was granted and not yet
    /// revoked.
    focus_on: bool,
    /// The FLUSH with the device, and the one that waits for it.
    showing: Option<Pending>,
    queued: Option<(Pending, Rect)>,
    /// A copy of the buffer's object that the owners' copies come from, and
    /// the objects and the window, mapped for the driver's life.
    fb: Handle<Memory>,
    _maps: (Handle<Memory>, Handle<Memory>, Handle<Memory>),
}

impl Driver {
    /// The service's next command, when the device holds none: the setup
    /// from where it stands, then the scanout off of a screen on its way
    /// back, then a FLUSH that waits.
    fn pump(&mut self) {
        if self.flight.is_some() {
            return;
        }
        match self.setup {
            Setup::Info => self.issue_info(),
            Setup::Create => self.issue_create(),
            Setup::Attach => self.issue_attach(),
            Setup::Failed => {}
            Setup::Ready => {
                if self.owner.wants_scanout_off() {
                    self.issue_scanout(Job::ScanoutOff);
                } else if let Some((pending, rect)) = self.queued.take() {
                    self.show(pending, rect);
                }
            }
        }
    }

    /// Puts a command, written by `write` into slot `slot` of the page of
    /// commands, into the queue with an answer of `answer_len` bytes at
    /// `answer`; the chain, or None when the queue refuses.
    fn submit(
        &mut self,
        slot: usize,
        answer: usize,
        answer_len: usize,
        write: impl FnOnce(&mut [u8]) -> usize,
    ) -> Option<Chain> {
        let command = COMMAND_AT[slot];
        // SAFETY: the page of commands is the DMA object's, mapped read and
        // write at DMA_AT; no one else touches the slot, which the device
        // does not hold (a job begins with its chains back).
        let buffer = unsafe { slice::from_raw_parts_mut(stage(command) as *mut u8, COMMAND_MAX) };
        let command_len = write(buffer);
        // SAFETY: as above, for the answer's bytes, which the device
        // writes once the command is added.
        let reply = unsafe { slice::from_raw_parts_mut(stage(answer) as *mut u8, answer_len) };
        reply[..HEADER].fill(0);
        // SAFETY: the command and the answer lie in the page of commands,
        // and nothing touches them until `pop_used` gives them back.
        let sent = unsafe {
            let command_bytes = slice::from_raw_parts(stage(command) as *const u8, command_len);
            self.queue.add(&[command_bytes], &mut [reply])
        };
        let token = sent.ok()?;
        Some(Chain {
            token,
            command,
            command_len,
            answer,
            answer_len,
        })
    }

    /// Rings the doorbell, once the chains of a job are in.
    fn ring(&mut self) {
        if self.queue.should_notify() {
            virtio_mmio::ring(&mut self.transport, CONTROLQ);
        }
    }

    /// Starts a job of one chain; false when the queue refused.
    fn one(
        &mut self,
        job: Job,
        answer: usize,
        answer_len: usize,
        write: impl FnOnce(&mut [u8]) -> usize,
    ) -> bool {
        let Some(chain) = self.submit(0, answer, answer_len, write) else {
            return false;
        };
        self.flight = Some(Flight {
            job,
            chains: [Some(chain), None],
            done: 0,
            bad: false,
        });
        self.ring();
        true
    }

    fn fail_setup(&mut self, what: &str) {
        rt::println!("virtio-gpu: {what} could not be sent");
        self.setup = Setup::Failed;
    }

    fn issue_info(&mut self) {
        if !self.one(Job::Info, INFO_AT, INFO_REPLY, commands::get_display_info) {
            self.fail_setup("GET_DISPLAY_INFO");
        }
    }

    fn issue_create(&mut self) {
        let sent = self.one(Job::Create, ANSWER_AT[0], HEADER, |b| {
            commands::resource_create_2d(
                b,
                commands::RESOURCE,
                commands::FORMAT_B8G8R8X8,
                proto_gpu::WIDTH,
                proto_gpu::HEIGHT,
            )
        });
        if !sent {
            self.fail_setup("RESOURCE_CREATE_2D");
        }
    }

    fn issue_attach(&mut self) {
        let pa = self.fb_pa;
        let sent = self.one(Job::Attach, ANSWER_AT[0], HEADER, |b| {
            commands::attach_backing(b, commands::RESOURCE, pa, proto_gpu::SCREEN_BYTES)
        });
        if !sent {
            self.fail_setup("RESOURCE_ATTACH_BACKING");
        }
    }

    /// SET_SCANOUT: the resource for an OPEN, none to take the screen off.
    /// False when the queue refused.
    fn issue_scanout(&mut self, job: Job) -> bool {
        let resource = if job == Job::ScanoutOn {
            commands::RESOURCE
        } else {
            commands::NO_RESOURCE
        };
        let sent = self.one(job, ANSWER_AT[0], HEADER, |b| {
            commands::set_scanout(b, &Rect::SCREEN, commands::SCANOUT, resource)
        });
        if !sent && job == Job::ScanoutOff {
            // Nothing to wait for: clear the buffer all the same.
            self.owner.scanout_off();
            let _ = sys::notify(&self.notify, CLEAR);
        }
        sent
    }

    /// Starts a FLUSH: the transfer and the flush of the rectangle, two
    /// chains. The device is idle. A refusal of the queue answers the
    /// client at once.
    fn show(&mut self, pending: Pending, rect: Rect) {
        let transfer = self.submit(0, ANSWER_AT[0], HEADER, |b| {
            commands::transfer_to_host_2d(b, &rect, commands::RESOURCE)
        });
        let flush = transfer.and_then(|_| {
            self.submit(1, ANSWER_AT[1], HEADER, |b| {
                commands::resource_flush(b, &rect, commands::RESOURCE)
            })
        });
        let Some(first) = transfer else {
            let _ = pending.answer(&proto_wire::reply(code(IO)), Outgoing::new());
            return;
        };
        // A transfer in the queue with no flush after it is taken back by
        // the interrupt that brings it, and nothing waits on it.
        self.flight = Some(Flight {
            job: Job::Show,
            chains: [Some(first), flush],
            done: 0,
            bad: flush.is_none(),
        });
        self.ring();
        if flush.is_some() {
            self.showing = Some(pending);
        } else {
            let _ = pending.answer(&proto_wire::reply(code(IO)), Outgoing::new());
        }
    }

    /// An interrupt of the line (spec 9): the kernel masked it at
    /// delivery. Reading the ISR drops the level; the chains the device
    /// returned are taken back and their job goes on; the line opens again
    /// (irq_ack), source cleared first [G26].
    fn interrupt(&mut self) {
        // The driver's own work, measured apart from the heartbeat.
        rt::service::step_own();
        let isr = Isr::read(&mut self.transport);
        if isr.config() {
            self.config_changed();
        }
        self.reap();
        virtio_mmio::reopen(&self.irq);
    }

    /// The display changed (the host's window): said once in the log and
    /// cleared with `events_clear`; the screen stays 640 by 400.
    fn config_changed(&mut self) {
        let events = self.transport.read_config_space::<u32>(0).unwrap_or(0);
        let _ = self.transport.write_config_space::<u32>(4, events);
        rt::println!("virtio-gpu: the display changed ({events:#x}); the screen stays 640 by 400");
    }

    /// Takes back every chain the device returned, and finishes the job
    /// when its last chain is back.
    fn reap(&mut self) {
        while let Some(token) = self.queue.peek_used() {
            let chain = self
                .flight
                .as_ref()
                .and_then(|f| f.chains.iter().flatten().find(|c| c.token == token))
                .copied();
            let Some(chain) = chain else {
                // A chain no job holds: the device answered what the driver
                // did not ask. Left in the ring it would repeat forever, so
                // the screen is given up.
                rt::println!("virtio-gpu: a used chain {token} with no job");
                self.setup = Setup::Failed;
                return;
            };
            // SAFETY: the same command and answer `submit` added with this
            // token; the device is done with them.
            let (popped, kind) = unsafe {
                let command =
                    slice::from_raw_parts(stage(chain.command) as *const u8, chain.command_len);
                let answer =
                    slice::from_raw_parts_mut(stage(chain.answer) as *mut u8, chain.answer_len);
                let popped = self.queue.pop_used(token, &[command], &mut [&mut *answer]);
                (popped, commands::answer_type(answer))
            };
            if popped.is_err() {
                rt::println!("virtio-gpu: the used chain {token} could not be taken back");
                self.setup = Setup::Failed;
                return;
            }
            if let Some(flight) = self.flight.as_mut() {
                if !commands::succeeded(kind) {
                    flight.bad = true;
                    rt::println!("virtio-gpu: {:?} answered {kind:#x}", flight.job);
                }
                flight.done += 1;
            }
        }
        let finished = self
            .flight
            .as_ref()
            .is_some_and(|f| usize::from(f.done) == f.chains.iter().flatten().count());
        if finished && let Some(flight) = self.flight.take() {
            self.finish(flight);
            self.pump();
        }
    }

    /// The job is back: what comes of it.
    fn finish(&mut self, flight: Flight) {
        match flight.job {
            Job::Info => {
                // SAFETY: the answer lies in the page of commands; the
                // device wrote it before the chain came back.
                let bytes =
                    unsafe { slice::from_raw_parts(stage(INFO_AT) as *const u8, INFO_REPLY) };
                match commands::first_mode(bytes) {
                    Some((w, h, on)) => rt::println!(
                        "virtio-gpu: the device's display is {w}x{h}, {}",
                        if on { "enabled" } else { "disabled" }
                    ),
                    None => rt::println!("virtio-gpu: no display info"),
                }
                // The info is for the log: a failure does not stop the setup.
                self.setup = Setup::Create;
            }
            Job::Create | Job::Attach if flight.bad => {
                rt::println!("virtio-gpu: the setup of the screen failed");
                self.setup = Setup::Failed;
            }
            Job::Create => self.setup = Setup::Attach,
            Job::Attach => {
                self.setup = Setup::Ready;
                rt::println!(
                    "virtio-gpu: screen ready, {}x{}, stride {}",
                    proto_gpu::WIDTH,
                    proto_gpu::HEIGHT,
                    STRIDE
                );
            }
            Job::ScanoutOn => self.opened(!flight.bad),
            Job::ScanoutOff => {
                // On the way back whatever the device said.
                self.owner.scanout_off();
                let _ = sys::notify(&self.notify, CLEAR);
            }
            Job::Show => {
                let status = if flight.bad { code(IO) } else { Status::Ok };
                if let Some(pending) = self.showing.take() {
                    let _ = pending.answer(&proto_wire::reply(status), Outgoing::new());
                }
            }
        }
    }

    /// The scanout of an OPEN is on (`shown`) or the device refused it.
    fn opened(&mut self, shown: bool) {
        let Some(opening) = self.opening.take() else {
            return;
        };
        if !shown {
            let _ = opening
                .pending
                .answer(&proto_wire::reply(code(IO)), Outgoing::new());
            self.release(opening.label);
            return;
        }
        // With a session of focus the status is 0, without one NO_INPUT:
        // the screen is the client's all the same (proto_gpu).
        let status = if opening.focus {
            Status::Ok
        } else {
            code(NO_INPUT)
        };
        let mut w = Writer::new();
        if Screen::FIXED.write(status, &mut w).is_err() {
            self.release(opening.label);
            return;
        }
        if let Err(refused) = opening.pending.answer(w.as_bytes(), opening.handles) {
            rt::println!("virtio-gpu: OPEN's reply refused: {:?}", refused.error);
        }
    }

    /// The screen's owner `label` is gone, or closed it: the screen starts
    /// back, and a FLUSH that waited is refused.
    fn release(&mut self, label: u64) {
        if !self.owner.release(label) {
            return;
        }
        self.revoke_focus();
        if let Some((pending, _)) = self.queued.take() {
            let _ = pending.answer(&proto_wire::reply(code(REVOKED)), Outgoing::new());
        }
        self.pump();
    }

    /// A portion of clearing is due (the driver notified itself): a step
    /// of 16 KiB zeroed. The last one frees the screen.
    fn clear_step(&mut self) {
        rt::service::step_own();
        let Some(portion) = self.owner.portion() else {
            return;
        };
        // SAFETY: the buffer is the driver's mapping of `fb`, read and
        // write, 256 pages; the portion lies within it (owner::Owner).
        unsafe {
            core::ptr::write_bytes(
                (FB_AT + portion.offset as usize) as *mut u8,
                0,
                portion.len as usize,
            )
        };
        if portion.last {
            rt::println!("gpu: screen released");
        } else {
            let _ = sys::notify(&self.notify, CLEAR);
        }
    }

    /// The session with the input service, from init's table: Absent when
    /// the table gives none, Lost when the service is not there.
    fn connect_input(&self) -> Link {
        match rt::service::connect(&self.parent, "input") {
            Ok(session) => Link::Linked(session),
            Err(Status::Kernel(Error::AccessDenied)) => Link::Absent,
            Err(_) => Link::Lost,
        }
    }

    /// GRANT: the session of focus for the owner just made, or None (the
    /// OPEN's status is NO_INPUT). A service that ended since the last
    /// call (PEER_CLOSED) is connected to again once.
    fn grant_focus(&mut self) -> Option<Handle<Any>> {
        for _ in 0..2 {
            if matches!(self.input, Link::Lost) {
                self.input = self.connect_input();
            }
            let Link::Linked(session) = &self.input else {
                return None;
            };
            match sys::send(session, &InputMethod::Grant.header().bytes()) {
                Ok(mut reply) => {
                    let mut buffer = [0; abi::MESSAGE_MAX];
                    let status = reply
                        .bytes(&mut buffer)
                        .get(..4)
                        .map(|b| Status::from_code(u32::from_le_bytes([b[0], b[1], b[2], b[3]])));
                    if status != Some(Status::Ok) || reply.handles.len() != 1 {
                        rt::println!("virtio-gpu: GRANT refused: {status:?}");
                        return None;
                    }
                    let focus = reply.handles.take::<Any>(0).ok()?;
                    self.focus_on = true;
                    return Some(focus);
                }
                Err(Error::PeerClosed) => self.input = Link::Lost,
                Err(_) => return None,
            }
        }
        None
    }

    /// REVOKE: the focus of the owner that left ends. Nothing when none
    /// was granted; a service that cannot be reached has lost it anyway.
    fn revoke_focus(&mut self) {
        if !core::mem::take(&mut self.focus_on) {
            return;
        }
        let Link::Linked(session) = &self.input else {
            return;
        };
        if let Err(Error::PeerClosed) = sys::send(session, &InputMethod::Revoke.header().bytes()) {
            self.input = Link::Lost;
        }
    }

    /// OPEN of a `Display` session.
    fn open(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        match self.setup {
            Setup::Ready => {}
            Setup::Failed => return Answer::Status(code(NO_DEVICE)),
            // The device is being set up: ask again.
            _ => return Answer::Status(code(CLEARING)),
        }
        // A free screen has no job with the device; one that does is not
        // ready to be given.
        if self.flight.is_some() {
            return Answer::Status(code(CLEARING));
        }
        let label = match self.owner.open() {
            Ok(label) => label,
            Err(Refusal::Busy) => return Answer::Status(code(BUSY)),
            Err(Refusal::Clearing) => return Answer::Status(code(CLEARING)),
        };
        // A handle in a reply must carry TRANSFER (spec 6.1), so the owner
        // gets TRANSFER on both, and no DUPLICATE.
        let rights = Rights::SEND | Rights::TRANSFER;
        let session = sys::handle_label(&self.channel, rights, label, self.level);
        let buffer = sys::handle_duplicate(
            &self.fb,
            Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER,
        );
        let (Ok(session), Ok(buffer)) = (session, buffer) else {
            self.release(label);
            return Answer::Status(Status::Kernel(Error::NoMemory));
        };
        let mut handles: Outgoing = [buffer.erase(), session.erase()].into();
        let focus = self.grant_focus();
        let focused = focus.is_some();
        if let Some(focus) = focus {
            // Room for three handles: the buffer and the owner's session
            // are two.
            let _ = handles.push(focus);
        }
        let Some(pending) = r.defer() else {
            self.release(label);
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        self.opening = Some(Opening {
            pending,
            label,
            handles,
            focus: focused,
        });
        if !self.issue_scanout(Job::ScanoutOn) {
            self.opened(false);
        }
        Answer::Deferred
    }

    /// FLUSH of the owner's session.
    fn flush(&mut self, r: &mut Request<'_>) -> Answer {
        let rect = match Rect::read(r.body()) {
            Ok(rect) => rect,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if !self.owner.owns(r.label()) || self.setup != Setup::Ready {
            return Answer::Status(code(REVOKED));
        }
        let busy = self.flight.is_some();
        if busy && self.queued.is_some() {
            return Answer::Status(proto_gpu::LIMIT);
        }
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        if busy {
            self.queued = Some((pending, rect));
        } else {
            self.show(pending, rect);
        }
        Answer::Deferred
    }

    /// CLOSE of the owner's session.
    fn close(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        self.release(r.label());
        Answer::Status(Status::Ok)
    }

    /// CLONE: a new `Display` session for a child of the client, a copy of
    /// the driver's channel with SEND, DUPLICATE, TRANSFER and a label of
    /// the driver's own; LIMIT_REACHED past the clones of the client or of
    /// the driver.
    fn clone_session(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let Ok(label) = self.clones.give(OWN, r.label()) else {
            return Answer::Status(proto_gpu::LIMIT);
        };
        let rights = Rights::SEND | Rights::DUPLICATE | Rights::TRANSFER;
        match sys::handle_label(&self.channel, rights, label, self.level) {
            Ok(session) => {
                if r.reply().u32(Status::Ok.code()).is_err() {
                    self.clones.gone(label);
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply([session.erase()].into())
            }
            Err(error) => {
                self.clones.gone(label);
                Answer::Status(Status::Kernel(error))
            }
        }
    }
}

/// The methods of the driver: CRASH only with the feature `crash`.
#[cfg(feature = "crash")]
const METHODS: &[u16] = &[
    Method::Open.number(),
    Method::Flush.number(),
    Method::Close.number(),
    Method::Clone.number(),
    Method::Crash.number(),
];
#[cfg(not(feature = "crash"))]
const METHODS: &[u16] = &[
    Method::Open.number(),
    Method::Flush.number(),
    Method::Close.number(),
    Method::Clone.number(),
];

impl Service<1> for Driver {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, r: &mut Request<'_>) -> Answer {
        let method = Method::from_number(r.method());
        // The owner's sessions show and close; the `Display` sessions open
        // and clone: the other method is not theirs.
        let owner_session = owner::is_owner_label(r.label());
        match method {
            Some(Method::Flush | Method::Close) if !owner_session => {
                return Answer::Status(code(NOT_ALLOWED));
            }
            Some(Method::Open | Method::Clone) if owner_session => {
                return Answer::Status(code(NOT_ALLOWED));
            }
            _ => {}
        }
        match method {
            Some(Method::Open) => self.open(r),
            Some(Method::Flush) => self.flush(r),
            Some(Method::Close) => self.close(r),
            Some(Method::Clone) => self.clone_session(r),
            #[cfg(feature = "crash")]
            Some(Method::Crash) => crash(r),
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    /// The last copy of a session went: an owner's ends the ownership (the
    /// process ended, `exec` closed it, or it died), a clone's frees its
    /// place.
    fn closed(&mut self, label: u64) {
        if owner::is_owner_label(label) {
            self.release(label);
        } else {
            self.clones.gone(label);
        }
    }

    fn notification(&mut self, n: Notice) {
        match n.source {
            Source::Interrupt => self.interrupt(),
            Source::Unlabeled if n.bits & CLEAR != 0 => self.clear_step(),
            _ => {}
        }
    }
}

/// CRASH: a load from page 0 ends the driver with a fault while the device
/// still has its queue; init stops the device before it lets the DMA
/// objects go, and starts the driver again.
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
