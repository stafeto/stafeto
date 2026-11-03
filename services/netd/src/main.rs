// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The network service of stafeto (spec 6): its own driver of the Virtio
//! network device on a virtio-mmio transport (Virtio 1.2, 5.1) and the
//! smoltcp stack over it, with DHCP (or the static address of
//! `/etc/netd.conf`), ARP and the answer to ICMP echo. The first stage has
//! one client method, CONFIG, which tells the interface's address; a build
//! with the feature `probe` adds PING (an echo request to an address, for
//! the network probe) and CRASH.
//!
//! The device is `net` of init's table: two DMA objects (`dma`, the pages
//! of the two queues, and `net`, 512 buffers of 2 KiB for the frames), the
//! window `mmio` and the binding `irq`. The service is in the trusted base:
//! the device writes where the queues tell it (spec 9, no SMMU). Init
//! stops the device (Status 0) before it lets the objects of an instance
//! go.
//!
//! The service never waits for the device. An interrupt (or the service's
//! own notification STEP, or its timer) starts a step: the used buffers of
//! sending come back, the stack takes at most 16 received frames and sends
//! at most 16, the buffers of receiving go back to the queue, the doorbells
//! ring, and the timer is set for the stack's next deadline. A step that
//! left received frames behind notifies the service again and keeps the
//! line closed; otherwise the line opens again (irq_ack) with the source
//! cleared.
//!
//! The key of the stack comes from the entropy service and the address
//! settings from the file service, both before the service registers with
//! init, so that a wait for either is not counted against the heartbeat.
//! The program ends with a code of its own when its start fails, and init
//! starts it again.

#![no_std]
#![no_main]

mod conf;
mod device;
mod dma;
mod seed;
mod stack;

use abi::{Access, Rights, Source};
use core::alloc::{GlobalAlloc, Layout};
use device::{DEVICE, NetDevice, RxRing, TxRing};
use netd::config::Settings;
use netd::lines::Mac;
use netd::ring::{NET_PAGES, QUEUE_SIZE};
use proto_init::ServiceArgs;
use proto_net::{Method, VERSION, code};
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Interrupt, Memory, Outgoing, Resource, Timer};
use rt::service::{Answer, Config, Heartbeat, Notice, Pending, Request, Service, Session};
use rt::{Handle, sys, time};
use stack::{Event, PingEnd, Stack, Storage};
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::Transport;
use virtio_drivers::transport::mmio::MmioTransport;
use virtio_mmio::{Isr, OpenError, PAGE, StartError};

rt::entry!(main);

/// The sessions of the service's channel.
const SESSIONS: usize = 8;
/// The bit of the service's notification to itself: a step is due.
const STEP: u64 = 1;
/// The label of the service's timer.
const TIMER_LABEL: u64 = 1;
/// The device's queues: `receiveq` and `transmitq` (Virtio 1.2, 5.1.2).
const RECEIVEQ: u16 = 0;
const TRANSMITQ: u16 = 1;
/// The features the service asks for: `VIRTIO_F_VERSION_1` (added by
/// `start_with`), `VIRTIO_NET_F_MAC` and `VIRTIO_NET_F_STATUS`. No
/// checksum offload, no segmentation offload, no merged buffers, no control
/// queue (Virtio 1.2, 5.1.3).
const MAC: u64 = 1 << 5;
const STATUS: u64 = 1 << 16;
/// The registers of the device's configuration space (Virtio 1.2, 4.2.2
/// and 5.1.4): the generation, then the MAC and the status.
const CONFIG_GENERATION: usize = 0xfc;
const CONFIG_SPACE: usize = 0x100;
const LINK_UP: u32 = 1;

/// The codes of a start that failed: the start data or an object; the
/// entropy service; REGISTER, the window or the binding; a map; no network
/// device at the transport; the device refused the driver; the file
/// `netd.conf`.
const NO_START_DATA: u64 = 1;
const NO_ENTROPY: u64 = 2;
const NOT_REGISTERED: u64 = 3;
const NOT_MAPPED: u64 = 4;
const STOPPED: u64 = 5;
const NO_DEVICE: u64 = 6;
const NOT_STARTED: u64 = 7;
const NO_CONFIG: u64 = 9;

/// The heap the device's crate may ask for: none (the queues have no
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

fn now_ns() -> u64 {
    time::ticks_to_ns(time::now())
}

/// The MAC address and the link status the configuration space of the
/// device at `base` holds, read between two equal generations (Virtio 1.2,
/// 2.5.1).
fn read_config(base: usize) -> ([u8; 6], bool) {
    loop {
        // SAFETY: the registers lie within the transport the window maps
        // at `base`, as device memory, aligned to 4 bytes.
        let (before, low, high, after) = unsafe {
            (
                rt::mmio::read32(base + CONFIG_GENERATION),
                rt::mmio::read32(base + CONFIG_SPACE),
                rt::mmio::read32(base + CONFIG_SPACE + 4),
                rt::mmio::read32(base + CONFIG_GENERATION),
            )
        };
        if before == after {
            let [m0, m1, m2, m3] = low.to_le_bytes();
            let [m4, m5, s0, s1] = high.to_le_bytes();
            let status = u32::from(u16::from_le_bytes([s0, s1]));
            return ([m0, m1, m2, m3, m4, m5], status & LINK_UP != 0);
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
    let (Ok(dma_object), Ok(net_object)) = (s.take::<Memory>("dma"), s.take::<Memory>("net"))
    else {
        return NO_START_DATA;
    };
    let args = ServiceArgs::read(s.args()).ok();
    // The own arguments: the physical addresses of `dma` and `net`, which
    // init puts first, then the record's, where the transport is.
    let own = args.map_or(&[][..], |a| a.own);
    let (dma_pa, net_pa, at) = (word(own, 0), word(own, 8), word(own, 16));
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(level) else {
        return NOT_REGISTERED;
    };

    // The key of the stack: its first 8 bytes seed the stack, and the rest
    // is erased (the ports of the next stage take their secret from the
    // service that has it).
    let Ok(entropy) = rt::service::connect(&s.parent, "entropy") else {
        return NO_ENTROPY;
    };
    let Ok(mut key) = seed::take(&entropy, &channel, level) else {
        return NO_ENTROPY;
    };
    let mut first = [0; 8];
    first.copy_from_slice(&key[..8]);
    let random_seed = u64::from_le_bytes(first);
    posix_random::erase(&mut key);
    drop(entropy);

    let settings = match conf::read(&s.parent) {
        Ok(settings) => settings,
        Err(conf::Failure::Refused(error)) => {
            rt::println!(
                "net: netd.conf line {}: {}",
                error.line,
                error.reason.text()
            );
            return NO_CONFIG;
        }
        Err(conf::Failure::Unreadable(error)) => {
            rt::println!("net: netd.conf unreadable: {error:?}");
            return NO_CONFIG;
        }
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
        || net_pa == 0
        || sys::mem_map(
            &s.process,
            &dma_object,
            0,
            dma::DMA_PAGES as u64 * page,
            dma::dma_at(DEVICE),
            rw,
        )
        .is_err()
        || sys::mem_map(
            &s.process,
            &net_object,
            0,
            NET_PAGES as u64 * page,
            dma::net_at(DEVICE),
            rw,
        )
        .is_err()
        || sys::mem_map(&s.process, &window, 0, page, dma::mmio_at(DEVICE), rw).is_err()
    {
        return NOT_MAPPED;
    }
    dma::attach(DEVICE, dma_pa, net_pa);
    let base = dma::mmio_at(DEVICE) + (at as usize & (PAGE - 1));
    // SAFETY: the window maps the transport's page at mmio_at as device
    // memory, read and write; `base` is the transport within it, and only
    // the transport and `read_config` reach the registers from here on.
    let opened = unsafe { virtio_mmio::transport(base, virtio_mmio::device::NET) };
    let (mut transport, status) = match opened {
        Ok(found) => found,
        Err(error) => {
            match error {
                OpenError::Rejected(why) => {
                    rt::println!("virtio-net: no network device at {at:#x}: {why:?}")
                }
                OpenError::Unusable => rt::println!("virtio-net: no usable transport at {at:#x}"),
            }
            return NO_DEVICE;
        }
    };
    let features = match virtio_mmio::start_with(&mut transport, MAC | STATUS) {
        Ok(bits) => bits,
        Err(StartError::Reset | StartError::Features) => return NOT_STARTED,
    };
    if features & MAC == 0 {
        rt::println!("virtio-net: the device offers no MAC address");
        return NO_DEVICE;
    }
    let (mac, link) = read_config(base);
    let link = link || features & STATUS == 0;
    type Q = VirtQueue<dma::Host<DEVICE>, QUEUE_SIZE>;
    let queues = (
        Q::new(&mut transport, RECEIVEQ, false, false),
        Q::new(&mut transport, TRANSMITQ, false, false),
    );
    let (Ok(rx_queue), Ok(tx_queue)) = queues else {
        return NOT_STARTED;
    };
    let mut device = NetDevice {
        rx: RxRing::new(rx_queue),
        tx: TxRing::new(tx_queue),
    };
    device.rx.fill();
    transport.finish_init();
    virtio_mmio::ring(&mut transport, RECEIVEQ);
    device.rx.dirty = false;
    let line = sys::irq_info(&irq).map_or(0, |info| info.line);
    rt::println!(
        "virtio-net: virtio-mmio at {at:#x}, line {line}, status {status:#x}, mac {}",
        Mac(mac)
    );
    if !link {
        rt::println!("virtio-net: link down");
    }

    let Ok(notify) = sys::handle_duplicate(&channel, Rights::NOTIFY) else {
        return NOT_REGISTERED;
    };
    let Ok(view) = sys::handle_label(&channel, Rights::RECEIVE, TIMER_LABEL, level) else {
        return NOT_REGISTERED;
    };
    let Ok(timer) = sys::timer_create(&view, level) else {
        return NOT_REGISTERED;
    };
    let mut storage = Storage::new();
    let now = now_ns();
    let mut stack = Stack::new(
        &mut storage,
        &mut device,
        mac,
        random_seed,
        now,
        settings.address.is_none(),
    );
    announce_static(&mut stack, &settings);
    let mut driver = Driver {
        transport,
        device,
        stack,
        irq,
        notify,
        timer,
        _view: view,
        ping: None,
        base,
        mac,
        link,
        line_closed: false,
        step_told: false,
        _maps: (dma_object, net_object, window),
    };
    // The line opens once the queues are up; the first step starts the
    // DHCP client.
    virtio_mmio::reopen(&driver.irq);
    driver.step(false);
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

/// The static address of the file, when it names one.
fn announce_static(stack: &mut Stack<'_>, settings: &Settings) {
    if let Some(address) = settings.address {
        stack.set_static(address, settings.gateway, settings.dns);
        if let Some(lease) = stack.lease {
            rt::println!("net: static {}", lease.summary());
        }
    }
}

/// The service: the device and the stack, the binding of its line, the
/// timer, and the PING that waits for its reply.
struct Driver<'a> {
    transport: MmioTransport<'static>,
    device: NetDevice,
    stack: Stack<'a>,
    irq: Handle<Interrupt>,
    /// A copy of the service's channel with NOTIFY: the service tells
    /// itself a step is due.
    notify: Handle<Channel>,
    timer: Handle<Timer>,
    _view: Handle<Channel>,
    ping: Option<Pending>,
    /// The transport's registers.
    base: usize,
    mac: [u8; 6],
    link: bool,
    /// The line is closed (the kernel masked it at delivery and the step
    /// has not opened it yet).
    line_closed: bool,
    /// A STEP notification is on its way.
    step_told: bool,
    _maps: (Handle<Memory>, Handle<Memory>, Handle<Memory>),
}

impl Driver<'_> {
    /// Asks the loop for a step, unless one is asked for.
    fn want_step(&mut self) {
        if !self.step_told && sys::notify(&self.notify, STEP).is_ok() {
            self.step_told = true;
        }
    }

    /// One step of the service: from the interrupt (`interrupt`: read the
    /// status first), the service's own notification, or the timer.
    fn step(&mut self, interrupt: bool) {
        rt::service::step_own();
        if interrupt {
            self.line_closed = true;
            let isr = Isr::read(&mut self.transport);
            if isr.config() {
                self.link_changed();
            }
        }
        let now = now_ns();
        self.device.rx.begin_step();
        self.device.tx.begin_step();
        self.stack.ingress(now, &mut self.device);
        self.stack.egress(now, &mut self.device);
        self.events(now);
        self.doorbells();
        rt::service::step_detail(self.device.step_frames() as u64);
        // Frames the share of the step left in the queue: another step,
        // with the line closed.
        if self.device.rx.queue.can_pop() {
            self.want_step();
        } else if core::mem::take(&mut self.line_closed) {
            virtio_mmio::reopen(&self.irq);
        }
        self.arm(now);
    }

    /// The change of the link (the interrupt's configuration bit).
    fn link_changed(&mut self) {
        let (_, up) = read_config(self.base);
        if up != self.link {
            self.link = up;
            rt::println!("virtio-net: link {}", if up { "up" } else { "down" });
        }
    }

    /// What the DHCP client and the PING made of the step.
    fn events(&mut self, now: u64) {
        match self.stack.dhcp_event() {
            Some(Event::Leased(lease)) => rt::println!("net: lease {}", lease.summary()),
            Some(Event::Lost) => rt::println!("net: lease lost"),
            None => {}
        }
        if self.ping.is_some()
            && let Some(end) = self.stack.ping_end(now)
        {
            self.finish_ping(end);
        }
    }

    fn finish_ping(&mut self, end: PingEnd) {
        let Some(pending) = self.ping.take() else {
            return;
        };
        let mut w = Writer::new();
        let answered = match end {
            PingEnd::Reply(nanos) => proto_net::write_ping_reply(nanos, &mut w)
                .map(|()| pending.answer(w.as_bytes(), Outgoing::new())),
            PingEnd::TimedOut => Ok(pending.answer(
                &proto_wire::reply(code(proto_net::TIMEOUT)),
                Outgoing::new(),
            )),
        };
        if answered.is_err() {
            rt::println!("net: a reply of PING could not be written");
        }
    }

    /// Rings the doorbell of each queue that got buffers in the step.
    fn doorbells(&mut self) {
        if core::mem::take(&mut self.device.rx.dirty) && self.device.rx.queue.should_notify() {
            virtio_mmio::ring(&mut self.transport, RECEIVEQ);
        }
        if core::mem::take(&mut self.device.tx.dirty) && self.device.tx.queue.should_notify() {
            virtio_mmio::ring(&mut self.transport, TRANSMITQ);
        }
    }

    /// Sets the timer for the stack's next work or the PING's deadline,
    /// never in the past.
    fn arm(&mut self, now: u64) {
        let next = [
            self.stack.poll_at_ns(now),
            self.stack.ping.as_ref().map(|p| p.deadline_ns),
        ]
        .into_iter()
        .flatten()
        .min();
        if let Some(at) = next {
            let _ = sys::timer_set(&self.timer, at.max(now + 1_000_000));
        }
    }

    /// CONFIG: the interface's address, or NET_DOWN while it has none.
    fn config(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        #[cfg(feature = "probe")]
        self.report_frames();
        let Some(lease) = self.stack.lease else {
            return Answer::Status(code(proto_net::NET_DOWN));
        };
        let config = proto_net::Config {
            address: lease.address,
            prefix: u32::from(lease.prefix),
            gateway: lease.gateway,
            dns: lease.dns,
            mac: self.mac,
        };
        if config.write(r.reply()).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    /// The counters of the probe's line.
    #[cfg(feature = "probe")]
    fn report_frames(&self) {
        let (rx, rx_dropped) = self.device.rx.counters();
        let tx = self.device.tx.counters();
        rt::println!(
            "net: frames rx {} tx {} dhcp {} dropped {}",
            rx,
            tx.tx,
            tx.dhcp,
            rx_dropped + tx.dropped
        );
    }

    /// PING: an echo request to the address; the reply comes from the step
    /// that sees the answer, or TIMEOUT after a second.
    #[cfg(feature = "probe")]
    fn ping(&mut self, r: &mut Request<'_>) -> Answer {
        let target = match proto_net::read_ping(r.body()) {
            Ok(address) => address.ipv4(),
            Err(status) => return Answer::Status(status),
        };
        let Some(target) = target else {
            return Answer::Status(Status::BadSize);
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if self.ping.is_some() {
            return Answer::Status(proto_net::LIMIT);
        }
        if self.stack.lease.is_none() {
            return Answer::Status(code(proto_net::NET_DOWN));
        }
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        if !self.stack.ping_start(target, now_ns()) {
            let status = code(proto_net::NO_BUFFERS);
            let _ = pending.answer(&proto_wire::reply(status), Outgoing::new());
            return Answer::Deferred;
        }
        self.ping = Some(pending);
        self.want_step();
        Answer::Deferred
    }
}

/// The methods of the service: PING and CRASH only with the feature
/// `probe`.
#[cfg(feature = "probe")]
const METHODS: &[u16] = &[
    Method::Config.number(),
    Method::Ping.number(),
    Method::Crash.number(),
];
#[cfg(not(feature = "probe"))]
const METHODS: &[u16] = &[Method::Config.number()];

impl Service<1> for Driver<'_> {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, r: &mut Request<'_>) -> Answer {
        match Method::from_number(r.method()) {
            Some(Method::Config) => self.config(r),
            #[cfg(feature = "probe")]
            Some(Method::Ping) => self.ping(r),
            #[cfg(feature = "probe")]
            Some(Method::Crash) => crash(r),
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    fn notification(&mut self, n: Notice) {
        match n.source {
            Source::Interrupt => self.step(true),
            Source::Unlabeled if n.bits & STEP != 0 => {
                self.step_told = false;
                self.step(false);
            }
            Source::Timer if n.label == TIMER_LABEL => self.step(false),
            _ => {}
        }
    }
}

/// CRASH: a load from page 0 ends the service with a fault while the
/// device still has its queues; init stops the device before it lets the
/// DMA objects go, and starts the service again.
#[cfg(feature = "probe")]
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
    Answer::Status(Status::Kernel(abi::Error::BadState))
}
