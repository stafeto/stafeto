// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The network service of stafeto (spec 6): its own driver of the Virtio
//! network device on a virtio-mmio transport (Virtio 1.2, 5.1) and the
//! smoltcp stack over it, with DHCP (or the static address of
//! `/etc/netd.conf`), ARP and the answer to ICMP echo. CONFIG tells the
//! interface's address; the sockets' methods of proto_net serve TCP and UDP
//! over IPv4, with a loopback inside the one interface (`net.rs`,
//! `calls.rs`); a build with the feature `probe` adds PING (an echo request
//! to an address, for the network probe) and CRASH.
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
//! sending come back, the stack takes the frames of the loopback and then of
//! the wire (`ring::STEP_RX` at most) and sends in one pass over its
//! sockets (`ring::STEP_TX` frames at most), the operations that wait are
//! told, the buffers of receiving go back to the queue, the doorbells ring,
//! and the timer is set for the stack's next deadline. A step that left
//! frames behind notifies the service again and keeps the line closed;
//! otherwise the line opens again (irq_ack) with the source cleared. A
//! call of a socket never runs the stack: it changes the buffers of one
//! socket and asks for a step.
//!
//! The key of the stack comes from the entropy service and the address
//! settings from the file service, both before the service registers with
//! init, so that a wait for either is not counted against the heartbeat.
//! The program ends with a code of its own when its start fails, and init
//! starts it again.

#![no_std]
#![no_main]

mod calls;
mod conf;
mod device;
mod dma;
mod net;
mod seed;
mod split;
mod stack;

use abi::{Access, Rights, Source};
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use device::{DEVICE, NetDevice, RxRing, TxRing};
use net::{Client, Net, SESSIONS, now_ns};
use netd::config::Settings;
use netd::lines::Mac;
use netd::ring::{Budget, NET_PAGES, QUEUE_SIZE};
use proto_init::ServiceArgs;
use proto_net::sockets;
use proto_net::{Method, VERSION, code};
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Interrupt, Memory, Outgoing, Resource, Timer};
use rt::service::{Answer, Config, Heartbeat, Notice, Pending, Request, Service, Session};
use rt::{Handle, sys};
use stack::{Event, PingEnd, Stack, Storage};
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::Transport;
use virtio_drivers::transport::mmio::MmioTransport;
use virtio_mmio::{Isr, OpenError, PAGE, StartError};

rt::entry!(main);

/// The bits of the service's notification to itself, each a step of its own:
/// receiving, sending (also asked by a request), the departure of a session,
/// the waking of operations, and the sweep of the streams that close.
const RX: u64 = 16;
const TX: u64 = 1;
const CLEANUP: u64 = 2;
const WAKE: u64 = 4;
const SWEEP: u64 = 8;
const STEP_BITS: u64 = RX | TX | CLEANUP | WAKE | SWEEP;
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
/// The offset of the link status in the configuration space (Virtio 1.2,
/// 5.1.4), after the six bytes of the MAC.
const STATUS_AT: usize = 6;
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

/// The tables of the service in `.bss`, too big for the stack: the sockets
/// with their buffers (`net`), the storage of the smoltcp sockets, the table
/// of sessions and the frames of the loopback. They are filled in place at
/// the start (`Net::initialize_at`); nothing in them is touched before a
/// socket needs it.
struct Tables {
    net: Net,
    storage: Storage<'static>,
    sessions: [Option<Session<Client, 0>>; SESSIONS],
}
struct Bss(UnsafeCell<core::mem::MaybeUninit<Tables>>);
// SAFETY: only the main thread reaches it, once (`main`).
unsafe impl Sync for Bss {}
static TABLES: Bss = Bss(UnsafeCell::new(core::mem::MaybeUninit::zeroed()));

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

/// The MAC address and the link status the configuration space of the
/// device holds, read at the width of each field (Virtio 1.2, 4.2.2.2: the
/// bytes of the MAC one at a time, the status as 16 bits) between two equal
/// generations (Virtio 1.2, 2.5.1).
fn read_config(transport: &MmioTransport<'static>) -> Result<([u8; 6], bool), ()> {
    transport
        .read_consistent(|| {
            let mut mac = [0u8; 6];
            for (at, byte) in mac.iter_mut().enumerate() {
                *byte = transport.read_config_space::<u8>(at)?;
            }
            let status = transport.read_config_space::<u16>(STATUS_AT)?;
            Ok((mac, u32::from(status) & LINK_UP != 0))
        })
        .map_err(|_| ())
}

/// 16 bytes for the table of destinations from the key of the ports and 8
/// bytes more of the entropy service's key: two SipHash-2-4 values of them.
#[allow(deprecated)] // SipHasher is in core and has no replacement there.
fn demux_secret(ports_key: &[u8; 16], tail: &[u8]) -> [u8; 16] {
    use core::hash::{Hasher, SipHasher};
    let k0 = u64::from_le_bytes(ports_key[..8].try_into().expect("8 bytes"));
    let k1 = u64::from_le_bytes(ports_key[8..].try_into().expect("8 bytes"));
    let mut out = [0u8; 16];
    for (n, half) in out.chunks_mut(8).enumerate() {
        let mut hash = SipHasher::new_with_keys(k0, k1);
        hash.write(b"demux");
        hash.write(&[n as u8]);
        hash.write(tail);
        half.copy_from_slice(&hash.finish().to_le_bytes());
    }
    out
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

    // The timer of the service, made before anything is waited for: it ends
    // the wait for the key, and after REGISTER it serves the deadlines of the
    // stack.
    let Ok(notify) = sys::handle_duplicate(&channel, Rights::NOTIFY) else {
        return NOT_REGISTERED;
    };
    let Ok(view) = sys::handle_label(&channel, Rights::RECEIVE, TIMER_LABEL, level) else {
        return NOT_REGISTERED;
    };
    let Ok(timer) = sys::timer_create(&view, level) else {
        return NOT_REGISTERED;
    };

    // The key of the stack: its first 8 bytes seed the stack, the next 16
    // are the secret of the choice of ports (RFC 6056), and the rest is
    // erased.
    let Ok(entropy) = rt::service::connect(&s.parent, "entropy") else {
        return NO_ENTROPY;
    };
    let mut key = match seed::take(&entropy, &channel, level, (&timer, TIMER_LABEL)) {
        Ok(key) => key,
        Err(failure) => {
            match failure {
                seed::Failure::Gone => {
                    rt::println!("net: no key from the entropy service (gone)")
                }
                seed::Failure::Timeout => {
                    rt::println!("net: no key from the entropy service (timeout)")
                }
                seed::Failure::Refused(status) => {
                    rt::println!("net: no key from the entropy service ({status:?})")
                }
            }
            return NO_ENTROPY;
        }
    };
    let mut first = [0; 8];
    first.copy_from_slice(&key[..8]);
    let random_seed = u64::from_le_bytes(first);
    let mut ports_key = [0; 16];
    ports_key.copy_from_slice(&key[8..24]);
    // The secret of the table of destinations: a hash of the key of the ports
    // and the rest of the key.
    let demux_key = demux_secret(&ports_key, &key[24..32]);
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
    let Ok((mac, link)) = read_config(&transport) else {
        return NOT_STARTED;
    };
    let link = link || features & STATUS == 0;
    type Q = VirtQueue<dma::Host<DEVICE>, QUEUE_SIZE>;
    let Ok(rx_queue) = Q::new(&mut transport, RECEIVEQ, false, false) else {
        return NOT_STARTED;
    };
    let Ok(tx_queue) = Q::new(&mut transport, TRANSMITQ, false, false) else {
        return NOT_STARTED;
    };
    // SAFETY: only this thread reaches TABLES, here once; the pointer is to
    // zeroed memory of the static.
    let tables = unsafe {
        let pointer = (*TABLES.0.get()).as_mut_ptr();
        Tables::initialize_at(pointer, ports_key, demux_key, &s.parent, &channel, level);
        &mut *pointer
    };
    posix_random::erase(&mut ports_key);
    let Tables {
        net,
        storage,
        sessions,
    } = tables;
    let mut device = NetDevice::new(RxRing::new(rx_queue), TxRing::new(tx_queue), mac);
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

    let now = now_ns();
    let mut stack = Stack::new(
        storage,
        &mut device,
        mac,
        random_seed,
        now,
        settings.address.is_none(),
    );
    announce_static(&mut stack, &settings);
    net.external = stack.lease.map(|lease| lease.address);
    let (own, count) = stack.addresses();
    device.set_addresses(&own[..count]);
    device.seed_neighbours();
    let mut driver = Driver {
        transport,
        device,
        stack,
        net,
        irq,
        notify,
        timer,
        _view: view,
        ping: None,
        mac,
        link,
        line_closed: false,
        told: 0,
        cleanup_due: false,
        armed: None,
        last_step: 0,
        neighbours_at: 0,
        #[cfg(feature = "probe")]
        hold: false,
        #[cfg(feature = "probe")]
        held_irq: false,
        #[cfg(feature = "probe")]
        held_rx: false,
        #[cfg(feature = "probe")]
        held_tx: false,
        _maps: (dma_object, net_object, window),
    };
    // The line opens once the queues are up; the first step starts the
    // DHCP client.
    virtio_mmio::reopen(&driver.irq);
    driver.rx_step(false);
    driver.tx_step(false);
    #[cfg(feature = "steps")]
    rt::service::report_steps(14);
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &s.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    let _ = rt::service::run_in(&channel, &mut driver, config, sessions);
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

impl Tables {
    /// The tables as they start, in place.
    ///
    /// # Safety
    /// `tables` is valid for writes, exclusive and zeroed.
    #[inline(never)]
    unsafe fn initialize_at(
        tables: *mut Tables,
        key: [u8; 16],
        demux_key: [u8; 16],
        parent: &Handle<Channel>,
        channel: &Handle<Channel>,
        level: u8,
    ) {
        use core::ptr::addr_of_mut;
        // SAFETY: each field is in bounds and written once.
        unsafe {
            Net::initialize_at(
                addr_of_mut!((*tables).net),
                key,
                demux_key,
                parent,
                channel,
                level,
            );
            Storage::initialize_at(addr_of_mut!((*tables).storage));
            rt::bss::fill_none(addr_of_mut!((*tables).sessions));
        }
    }
}

/// The service: the device and the stack, the binding of its line, the
/// timer, the sockets, and the PING that waits for its reply.
struct Driver<'a> {
    transport: MmioTransport<'static>,
    device: NetDevice,
    stack: Stack<'static>,
    net: &'a mut Net,
    irq: Handle<Interrupt>,
    /// A copy of the service's channel with NOTIFY: the service tells
    /// itself a step is due.
    notify: Handle<Channel>,
    timer: Handle<Timer>,
    _view: Handle<Channel>,
    ping: Option<Pending>,
    mac: [u8; 6],
    link: bool,
    /// The line is closed (the kernel masked it at delivery and the step
    /// has not opened it yet).
    line_closed: bool,
    /// The bits of the notifications to itself that are on their way.
    told: u64,
    /// A step of departure is due that no notification told.
    cleanup_due: bool,
    /// The deadline the timer is set for.
    armed: Option<u64>,
    /// The step that ran last among those asked for together.
    last_step: usize,
    /// When the neighbour entries of the own addresses are renewed.
    neighbours_at: u64,
    /// The probe holds the steps of the stack (HOLD), and an interrupt came
    /// meanwhile.
    #[cfg(feature = "probe")]
    hold: bool,
    #[cfg(feature = "probe")]
    held_irq: bool,
    /// A step of each kind was asked for while the steps were held.
    #[cfg(feature = "probe")]
    held_rx: bool,
    #[cfg(feature = "probe")]
    held_tx: bool,
    _maps: (Handle<Memory>, Handle<Memory>, Handle<Memory>),
}

impl Driver<'_> {
    /// Tells the loop `bit` unless it is told already; false when the
    /// notification was refused and nothing is on its way.
    fn tell(&mut self, bit: u64) -> bool {
        if self.told & bit != 0 {
            return true;
        }
        if sys::notify(&self.notify, bit).is_ok() {
            self.told |= bit;
            return true;
        }
        false
    }

    /// Asks the loop for a step of the stack.
    fn want_step(&mut self) -> bool {
        self.tell(TX)
    }

    /// The requests made while a step or a departure was wanted: the loop
    /// is told, once.
    fn after_request(&mut self) {
        if core::mem::take(&mut self.net.step_due) {
            self.want_step();
        }
        if core::mem::take(&mut self.net.cleanup_wanted) {
            self.cleanup();
        }
        if core::mem::take(&mut self.net.wake_wanted) {
            self.tell(WAKE);
        }
        if self.cleanup_due && self.tell(CLEANUP) {
            self.cleanup_due = false;
        }
    }

    /// A departure is due.
    fn cleanup(&mut self) {
        if !self.tell(CLEANUP) {
            self.cleanup_due = true;
        }
    }

    /// The step of receiving: from the interrupt (`interrupt`: read the
    /// status first) or the service's own notification. It takes up to
    /// STEP_RX frames, with the stack's answers to them, and asks for the
    /// steps that follow.
    fn rx_step(&mut self, interrupt: bool) {
        rt::service::step_own();
        #[cfg(feature = "probe")]
        if self.hold {
            self.held_irq |= interrupt;
            self.held_rx = true;
            return;
        }
        let began = split::now();
        split::begin_step();
        if interrupt {
            self.line_closed = true;
            let isr = Isr::read(&mut self.transport);
            if isr.config() {
                self.link_changed();
            }
        }
        let now = now_ns();
        self.device.rx.begin_step(Budget::receiving());
        self.device.tx.begin_step(Budget::receiving());
        stack::ingress(&mut self.stack, &mut self.device, self.net, now);
        self.events(now);
        self.finish_step(now);
        rt::service::step_detail(self.device.step_frames() as u64);
        // Frames the share of the step left in the queue or in the loop:
        // another step of receiving, with the line closed. A refused
        // notification opens the line instead: the level brings the
        // interrupt back for the frames still in the queue.
        let kernel = split::now();
        let more = self.device.rx.queue.can_pop() || self.device.looped.waiting() > 0;
        let continued = more && self.tell(RX);
        if !continued && core::mem::take(&mut self.line_closed) {
            virtio_mmio::reopen(&self.irq);
        }
        self.next_steps(now, continued);
        let end = split::now();
        split::record(split::KERNEL, end - kernel);
        let counted = split::get(&split::RX_TURNS) + split::get(&split::PASSES);
        split::record(split::FIXED_RX, (end - began).saturating_sub(counted));
    }

    /// The step of sending: the service's set when it has work and up to
    /// EGRESS_GROUPS groups of those that have, at most STEP_TX frames. From
    /// the timer (`deadline`) or the service's own notification.
    fn tx_step(&mut self, deadline: bool) {
        rt::service::step_own();
        #[cfg(feature = "probe")]
        if self.hold {
            self.held_tx = true;
            return;
        }
        let began = split::now();
        split::begin_step();
        let now = now_ns();
        self.device.rx.begin_step(Budget::sending());
        self.device.tx.begin_step(Budget::sending());
        self.stack.egress(
            now,
            &mut self.device,
            &mut self.net.due,
            &mut self.net.touched,
            &mut self.net.passed,
        );
        self.events(now);
        if now >= self.neighbours_at {
            self.addresses();
        }
        if deadline && self.net.orphans_wait() {
            self.tell(SWEEP);
        }
        self.finish_step(now);
        rt::service::step_detail(self.device.step_frames() as u64);
        let kernel = split::now();
        let continued = self.device.looped.waiting() > 0 && self.tell(RX);
        self.next_steps(now, continued);
        let end = split::now();
        split::record(split::KERNEL, end - kernel);
        let counted = split::get(&split::RX_TURNS) + split::get(&split::PASSES);
        split::record(split::FIXED_TX, (end - began).saturating_sub(counted));
    }

    /// What every step ends with: the operations that wait are looked at by a
    /// step of their own, and the doorbells ring.
    fn finish_step(&mut self, _now: u64) {
        self.net.schedule_wake(&mut self.stack);
        if self.net.wake_pending() {
            self.tell(WAKE);
        }
        self.doorbells();
    }

    /// Groups with work left want a step of sending; when no step follows,
    /// the timer is set for the next deadline.
    fn next_steps(&mut self, now: u64, receiving: bool) {
        let sending = self.net.due != 0 && self.tell(TX);
        if !receiving && !sending {
            self.arm(now);
        }
    }

    /// The change of the link (the interrupt's configuration bit).
    fn link_changed(&mut self) {
        let Ok((_, up)) = read_config(&self.transport) else {
            return;
        };
        if up != self.link {
            self.link = up;
            rt::println!("virtio-net: link {}", if up { "up" } else { "down" });
        }
    }

    /// What the DHCP client and the PING made of the step.
    fn events(&mut self, now: u64) {
        let dhcp = if self.stack.take_service_ran() {
            self.stack.dhcp_event()
        } else {
            None
        };
        match dhcp {
            Some(Event::Leased(lease)) => {
                self.net.external = Some(lease.address);
                self.addresses();
                self.net.touch_all();
                rt::println!("net: lease {}", lease.summary())
            }
            Some(Event::Lost) => {
                self.net.external = None;
                self.addresses();
                self.net.touch_all();
                rt::println!("net: lease lost")
            }
            None => {}
        }
        if self.ping.is_some()
            && let Some(end) = self.stack.ping_end(now)
        {
            self.finish_ping(end);
        }
    }

    /// The frames to the addresses of the interface stay in the loop.
    fn addresses(&mut self) {
        let (own, count) = self.stack.addresses();
        self.device.set_addresses(&own[..count]);
        self.device.seed_neighbours();
        self.neighbours_at = now_ns() + NEIGHBOURS_NS;
        self.net.step_due = true;
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

    /// Sets the timer for the stack's next work (`next`), the PING's
    /// deadline or the sweep of the streams that close, never in the past.
    fn arm(&mut self, now: u64) {
        let sweep = self.net.orphans_wait().then(|| now + SWEEP_NS);
        let at = [
            self.stack.next_deadline(),
            self.stack.ping.as_ref().map(|p| p.deadline_ns),
            sweep,
            Some(self.neighbours_at),
        ]
        .into_iter()
        .flatten()
        .min();
        if let Some(at) = at {
            let at = at.max(now + 1_000_000);
            // The timer is set when there is none or the new deadline is
            // earlier: a later one finds the timer firing early and a step
            // that sets it again.
            if self.armed.is_none_or(|armed| at < armed || armed <= now) {
                let _ = sys::timer_set(&self.timer, at);
                self.armed = Some(at);
            }
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
        let (rx, rx_dropped, rx_martian) = self.device.rx.counters();
        let tx = self.device.tx.counters();
        rt::println!(
            "net: frames rx {} tx {} dhcp {} dropped {} martian {} listen_short {} bad_sum {} demux_probe {}",
            rx,
            tx.tx,
            tx.dhcp,
            rx_dropped + tx.dropped + self.device.looped.dropped(),
            rx_martian + tx.martian,
            self.net.counters.listen_short,
            self.device.bad_sum,
            self.net.demux.probe_max
        );
        split::report();
    }

    /// HOLD: the steps of the stack wait (1), go on (0), or every group of
    /// sockets is marked as having work (2).
    #[cfg(feature = "probe")]
    fn hold(&mut self, r: &mut Request<'_>) -> Answer {
        let value = match proto_net::read_hold(r.body()) {
            Ok(value) => value,
            Err(status) => return Answer::Status(status),
        };
        match value {
            proto_net::HOLD_ON => self.hold = true,
            proto_net::HOLD_OFF => {
                self.hold = false;
                self.held_rx = false;
                self.held_tx = false;
                self.net.step_due = true;
                self.tell(RX);
            }
            proto_net::HOLD_DROP => self.device.tx.drop_loop = 1,
            _ => {
                self.net.touch_all();
                self.net.step_due = true;
            }
        }
        Answer::Status(Status::Ok)
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

/// How often the stack is told again that its own addresses are at its own
/// MAC: half the life of an entry of the neighbour cache (60 s).
const NEIGHBOURS_NS: u64 = 30_000_000_000;

/// How long after a step the streams that close are looked at again.
const SWEEP_NS: u64 = 1_000_000_000;

/// The methods of the service: PING and CRASH only with the feature
/// `probe`. CLONE_MORE (20) and the methods of later stages (22 to 26) are
/// UNKNOWN_METHOD.
#[cfg(feature = "probe")]
const METHODS: &[u16] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 27, 28, 29, 30, 62, 63,
];
#[cfg(not(feature = "probe"))]
const METHODS: &[u16] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 27, 28, 29,
];

impl Service<0> for Driver<'_> {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = Client;

    fn request(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        self.net.claim(s, r.label());
        let answer = match Method::from_number(r.method()) {
            Some(Method::Config) => self.config(r),
            #[cfg(feature = "probe")]
            Some(Method::Ping) => self.ping(r),
            #[cfg(feature = "probe")]
            Some(Method::Crash) => crash(r),
            #[cfg(feature = "probe")]
            Some(Method::Hold) => self.hold(r),
            Some(method) => match sockets::Request::parse(method, r.body()) {
                Some(Ok(call)) => self.net.call(&mut self.stack, s, r, call),
                Some(Err(status)) => Answer::Status(status),
                None => Answer::Status(Status::UnknownMethod),
            },
            None => Answer::Status(Status::UnknownMethod),
        };
        self.after_request();
        answer
    }

    /// The client of `s` went: its operations go, and its descriptions are
    /// let go of in steps.
    fn gone(&mut self, s: &mut Session<Client, 0>) {
        rt::service::step_own();
        self.net.abandon(s);
        let held = core::mem::take(&mut s.data.held);
        if self.net.depart(&mut self.stack, held) {
            self.cleanup();
        }
        self.net.step_due = true;
        self.after_request();
    }

    /// The last copy of a session Clone made went before it sent anything.
    fn closed(&mut self, label: u64) {
        rt::service::step_own();
        if let Some(held) = self.net.unborn(label)
            && self.net.depart(&mut self.stack, held)
        {
            self.cleanup();
        }
        self.after_request();
    }

    fn notification(&mut self, n: Notice) {
        match n.source {
            Source::Interrupt => self.rx_step(true),
            Source::Unlabeled if n.bits & STEP_BITS != 0 => {
                // One step at a time: the first bit in this order, and the
                // others are told again, so that a request waits for the
                // step that is on.
                let order = [RX, TX, WAKE, CLEANUP, SWEEP];
                let at =
                    netd::ring::next_bit(&order, n.bits & STEP_BITS, self.last_step).unwrap_or(0);
                self.last_step = at;
                let bit = order[at];
                let rest = n.bits & STEP_BITS & !bit;
                self.told &= !bit;
                if rest != 0 && sys::notify(&self.notify, rest).is_err() {
                    self.told &= !rest;
                    self.cleanup_due |= rest & CLEANUP != 0;
                }
                match bit {
                    RX => {
                        #[cfg(feature = "probe")]
                        let irq = core::mem::take(&mut self.held_irq);
                        #[cfg(not(feature = "probe"))]
                        let irq = false;
                        self.rx_step(irq)
                    }
                    TX => self.tx_step(false),
                    WAKE => {
                        rt::service::step_own();
                        if self.net.wake(&mut self.stack, now_ns()) {
                            self.tell(WAKE);
                        }
                    }
                    CLEANUP => {
                        rt::service::step_own();
                        if self.net.depart_step(&mut self.stack) {
                            self.cleanup();
                        }
                        self.net.step_due = true;
                    }
                    _ => {
                        rt::service::step_own();
                        if self.net.sweep(&mut self.stack, now_ns()) {
                            self.tell(SWEEP);
                        }
                    }
                }
                self.after_request();
            }
            Source::Timer if n.label == TIMER_LABEL => {
                self.armed = None;
                self.tx_step(true)
            }
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
