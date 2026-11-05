// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The second network device (spec 6, 3.9): an interface of its own that
//! runs DHCP (RFC 2131) or holds the static address of `netd.conf`
//! (`address1`), and nothing else. It sets no default route, takes no
//! name server, serves no socket of the descriptions and has no loopback;
//! the frames that reach its stack are ARP (the server asks who has the
//! leased address) and the server's DHCP messages (`NetDevice::stage`),
//! so it answers no echo and sends no reset or unreachable.
//!
//! A program with the superuser's rights may claim the device (CLAIM,
//! `owner.rs`): from then on the service touches neither the queues nor
//! the buffers (`Mode::Owned`). It keeps the line: an interrupt is a step
//! that reads the status, opens the line and tells the owner. The DHCP
//! client of the second address stays here and talks through the bypass
//! ring (`fast.rs`), and it asks for its lease again at once, so that the
//! ring is proven in every run. When the owner goes, the device comes back
//! in steps (`Mode::Back`): a reset, the features, the queues, the buffers
//! of receiving 64 at a time, then the line and DHCP from the start.
//!
//! The device's step is the first device's, smaller: its interrupt status,
//! up to `STEP_RX` frames into the stack, the stack's DHCP pass, the
//! doorbells. It lives in the service's `.bss` (`Tables`), built in place
//! (`Second::start_at`): its two queues are too big for a second copy on
//! the stack.

use crate::device::{NetDevice, RxRing, TxRing};
use crate::dma::Host;
use crate::fast::Fast;
use crate::stack::{Event, Lease, instant};
use crate::{RECEIVEQ, TRANSMITQ};
use core::ptr::addr_of_mut;
use netd::bypass::Own;
use netd::config::Cidr;
use netd::lines::{Ip, Mac};
use netd::ring::{Budget, QUEUE_SIZE};
use proto_net::fast::{FAST_ADDRESS, FAST_CONFIG, FAST_INTERRUPT, FAST_RING};
use rt::Handle;
use rt::handle::Interrupt;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::socket::dhcpv4;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address, Ipv4Cidr};
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::{DeviceStatus, SomeTransport, Transport};
use virtio_mmio::Isr;
use virtio_net::barrier::ring;

type Q = VirtQueue<Host<1>, QUEUE_SIZE>;

/// The storage of the one socket the device's set holds (the DHCP client).
pub type Storage = [SocketStorage<'static>; 1];

/// Why the device did not start: the code the service ends with.
pub const NOT_STARTED: u64 = 7;

/// What a step of the device found, for the service to say or to act on.
#[derive(Default)]
pub struct Outcome {
    /// The first interrupt of the device came in this step.
    pub first_interrupt: bool,
    /// The step read a status that was not empty.
    pub isr_seen: bool,
    /// The DHCP client leased an address or lost it.
    pub event: Option<Event>,
    /// Frames are left in the queue: another step of receiving.
    pub more: bool,
    /// The owner is to be told these bits (`proto_net::fast`).
    pub owner_bits: u64,
    /// The frames the step took from the bypass ring.
    pub taken: u32,
    /// The lease the client asked for again after a claim came: the lease
    /// and whether its address is another.
    pub renewed: Option<(Lease, bool)>,
}

/// Who drives the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The service: its queues, its buffers, its line.
    Own,
    /// A program (CLAIM): the service keeps the line and the DHCP client
    /// on the bypass ring.
    Owned,
    /// The owner went and the device comes back to the service.
    Back(Back),
}

/// The steps of the device's return (spec 6, 3.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Back {
    /// The status is written 0 and read back, `RESET_READS_STEP` times a
    /// step at most.
    Reset,
    /// The features and the configuration (`virtio_net::open`).
    Open,
    /// The queue of receiving on `dma1`, and then the queue of sending: one
    /// a step (each costs about two thirds of a step's bound).
    ReceiveQueue,
    SendQueue,
    /// The buffers of receiving from this one on, `FILL_STEP` a step.
    Fill(u16),
}

/// The reads of the status after the reset in one step: QEMU and VZ read 0
/// at once.
pub const RESET_READS_STEP: u32 = 64;
/// The buffers of receiving given to the queue in one step of the return.
pub const FILL_STEP: u16 = 64;

/// How a step of the return ended.
pub enum Returned {
    /// Another step follows.
    More,
    /// The device is the service's again.
    Done,
    /// The device refused; the service ends with this code.
    Failed(u64),
}

pub struct Second {
    transport: SomeTransport<'static>,
    pub device: NetDevice<1>,
    iface: Interface,
    sockets: SocketSet<'static>,
    dhcp: Option<SocketHandle>,
    pub irq: Handle<Interrupt>,
    /// The line is closed (the kernel masked it at delivery and the step
    /// has not opened it yet).
    pub line_closed: bool,
    interrupted: bool,
    /// The lease or the static address.
    pub lease: Option<Lease>,
    /// The deadline of the stack's next work, in nanoseconds of the counter.
    pub next_at: Option<u64>,
    /// Who drives the device.
    pub mode: Mode,
    /// The bypass ring while a program owns the device.
    pub fast: Option<Fast>,
    /// The DHCP client asks again after a claim, and the address it had.
    renewing: Option<Option<[u8; 4]>>,
    /// The physical addresses of the queues' object and of the buffers', for
    /// the queues of the return.
    objects: (u64, u64),
}

impl Second {
    /// Starts the device on `transport` (its status before the service's
    /// reset is `status`) and builds the interface in place at `at`; with
    /// `fixed` the interface takes that address and runs no DHCP. Says the
    /// device's line.
    ///
    /// # Safety
    ///
    /// `at` is valid for writes and exclusive, and `storage` is not used
    /// elsewhere.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn start_at(
        at: *mut Second,
        storage: &'static mut Storage,
        mut transport: SomeTransport<'static>,
        irq: Handle<Interrupt>,
        place: (bool, u64, u32),
        seed: u64,
        now_ns: u64,
        fixed: Option<Cidr>,
        objects: (u64, u64),
    ) -> Result<(), u64> {
        let (pci, function, status) = place;
        let opened = crate::start_device(&mut transport, "virtio-net1")?;
        let mac = opened.mac;
        if !crate::mtu_fits(&opened, "virtio-net1") {
            return Err(NOT_STARTED);
        }
        let Ok(rx_queue) = Q::new(&mut transport, RECEIVEQ, false, false) else {
            return Err(NOT_STARTED);
        };
        let Ok(tx_queue) = Q::new(&mut transport, TRANSMITQ, false, false) else {
            return Err(NOT_STARTED);
        };
        // SAFETY: `at` is valid and exclusive; each field is written once,
        // and the device before the interface that borrows it for its
        // creation only.
        unsafe {
            NetDevice::initialize_at(
                addr_of_mut!((*at).device),
                RxRing::new(rx_queue),
                TxRing::new(tx_queue),
                mac,
            );
            let device = &mut *addr_of_mut!((*at).device);
            device.takes_dhcp = fixed.is_none();
            device.rx.fill();
            transport.finish_init();
            ring(&mut transport, RECEIVEQ);
            device.rx.ring.dirty = false;
            let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
            config.random_seed = seed;
            let iface = Interface::new(config, device, instant(now_ns));
            let mut sockets = SocketSet::new(&mut storage[..]);
            let dhcp = fixed.is_none().then(|| sockets.add(dhcpv4::Socket::new()));
            addr_of_mut!((*at).iface).write(iface);
            addr_of_mut!((*at).sockets).write(sockets);
            addr_of_mut!((*at).dhcp).write(dhcp);
            addr_of_mut!((*at).irq).write(irq);
            addr_of_mut!((*at).line_closed).write(false);
            addr_of_mut!((*at).interrupted).write(false);
            addr_of_mut!((*at).lease).write(None);
            addr_of_mut!((*at).next_at).write(None);
            addr_of_mut!((*at).mode).write(Mode::Own);
            addr_of_mut!((*at).fast).write(None);
            addr_of_mut!((*at).renewing).write(None);
            addr_of_mut!((*at).objects).write(objects);
            addr_of_mut!((*at).transport).write(transport);
        }
        // SAFETY: every field is written; the line opens once the queues
        // are up.
        let this = unsafe { &mut *at };
        let line = rt::sys::irq_info(&this.irq).map_or(0, |info| info.line);
        if pci {
            rt::println!(
                "virtio-net1: 1af4:1041 at {function:#x}, line {line}, status {status:#x}, mac {}",
                Mac(mac)
            );
        } else {
            rt::println!(
                "virtio-net1: virtio-mmio at {function:#x}, line {line}, status {status:#x}, mac {}",
                Mac(mac)
            );
        }
        if let Some(cidr) = fixed {
            this.apply(&Lease {
                address: cidr.address,
                prefix: cidr.prefix,
                gateway: None,
                dns: None,
                servers: [None; netd::resolv::SERVERS],
            });
            rt::println!("net: static1 {}/{}", Ip(cidr.address), cidr.prefix);
        }
        virtio_mmio::reopen(&this.irq);
        Ok(())
    }

    /// The address on the interface: no route and no name server.
    fn apply(&mut self, lease: &Lease) {
        let cidr = Ipv4Cidr::new(Ipv4Address::from(lease.address), lease.prefix);
        self.iface.update_ip_addrs(|addrs| {
            addrs.clear();
            let _ = addrs.push(IpCidr::Ipv4(cidr));
        });
        self.lease = Some(*lease);
        let (own, _) = self.addresses();
        self.device.set_addresses(&[own]);
    }

    /// The interface's address, for the route of its frames.
    fn addresses(&self) -> ([u8; 4], bool) {
        match self.iface.ipv4_addr() {
            Some(a) => (a.octets(), true),
            None => ([0; 4], false),
        }
    }

    /// One step of the device: the interrupt status if `interrupt`, the
    /// frames the share allows into the stack, its pass of sending, the
    /// DHCP client's event, the doorbells.
    pub fn step(&mut self, now_ns: u64, interrupt: bool) -> Outcome {
        let mut outcome = Outcome::default();
        if interrupt {
            self.line_closed = true;
            let isr = Isr::read(&mut self.transport);
            outcome.isr_seen = !isr.is_empty();
            if outcome.isr_seen && !core::mem::replace(&mut self.interrupted, true) {
                outcome.first_interrupt = true;
            }
            match self.mode {
                Mode::Own => {}
                // The owner's queues: the step only tells it.
                Mode::Owned => {
                    if isr.queue() {
                        outcome.owner_bits |= FAST_INTERRUPT;
                    }
                    if isr.config() {
                        outcome.owner_bits |= FAST_CONFIG;
                    }
                    return outcome;
                }
                Mode::Back(_) => return outcome,
            }
        }
        match self.mode {
            Mode::Own => {}
            Mode::Owned => return self.ring_step(now_ns),
            Mode::Back(_) => return outcome,
        }
        let now = instant(now_ns);
        self.device.rx.begin_step(Budget::receiving());
        self.device.tx.begin_step(Budget::receiving());
        while self.device.stage().is_some() {
            let _ = self
                .iface
                .poll_ingress_single(now, &mut self.device, &mut self.sockets);
        }
        self.iface.poll_maintenance(now);
        let _ = self
            .iface
            .poll_egress(now, &mut self.device, &mut self.sockets);
        outcome.event = self.dhcp_event();
        // The deadline of the client's next work (a retransmission, a
        // renewal).
        self.next_at = self
            .iface
            .poll_at(now, &self.sockets)
            .map(|at| (at.total_micros().max(0) as u64).saturating_mul(1000));
        if core::mem::take(&mut self.device.rx.ring.dirty)
            && self.device.rx.ring.queue.should_notify()
        {
            ring(&mut self.transport, RECEIVEQ);
        }
        if core::mem::take(&mut self.device.tx.ring.dirty)
            && self.device.tx.ring.queue.should_notify()
        {
            ring(&mut self.transport, TRANSMITQ);
        }
        outcome.more = self.device.rx.ring.queue.can_pop();
        outcome
    }

    /// A step of the owned device: up to RING_RX frames of the bypass ring
    /// into the stack, its pass of sending into the ring to the owner, the
    /// DHCP client's event.
    fn ring_step(&mut self, now_ns: u64) -> Outcome {
        let mut outcome = Outcome::default();
        let own = Own {
            mac: self.device.mac,
            address: self.lease.map(|l| l.address),
        };
        let Some(fast) = self.fast.as_mut() else {
            return outcome;
        };
        let now = instant(now_ns);
        outcome.taken = fast.take(own);
        while fast.has_frame() {
            let _ = self.iface.poll_ingress_single(now, fast, &mut self.sockets);
        }
        self.iface.poll_maintenance(now);
        let _ = self.iface.poll_egress(now, fast, &mut self.sockets);
        if core::mem::take(&mut fast.pushed) > 0 {
            outcome.owner_bits |= FAST_RING;
        }
        outcome.more = fast.waiting();
        match self.dhcp_event() {
            Some(Event::Leased(lease)) => match self.renewing.take() {
                Some(before) => {
                    let changed = before != Some(lease.address);
                    if changed {
                        outcome.owner_bits |= FAST_ADDRESS;
                    }
                    outcome.renewed = Some((lease, changed));
                }
                None => outcome.event = Some(Event::Leased(lease)),
            },
            // The reset of a claim says "no configuration" first.
            Some(Event::Lost) if self.renewing.is_some() => {}
            other => outcome.event = other,
        }
        self.next_at = self
            .iface
            .poll_at(now, &self.sockets)
            .map(|at| (at.total_micros().max(0) as u64).saturating_mul(1000));
        outcome
    }

    /// The device goes to its owner, whose bypass ring the service mapped at
    /// `ring`: the service stops touching its queues, and the DHCP client
    /// asks for the lease again through the ring. With a static address
    /// there is no client, and the frames of the ring are dropped.
    ///
    /// # Safety
    ///
    /// As `Ring::at` for `ring`.
    pub unsafe fn hand_over(&mut self, ring: usize) {
        self.mode = Mode::Owned;
        // SAFETY: the caller's promise.
        self.fast = Some(unsafe { Fast::new(ring) });
        if let Some(handle) = self.dhcp {
            self.renewing = Some(self.lease.map(|l| l.address));
            self.sockets.get_mut::<dhcpv4::Socket>(handle).reset();
        }
        self.next_at = Some(0);
    }

    /// The owner went: the ring is no more, and the return starts.
    pub fn take_back(&mut self) {
        self.fast = None;
        self.renewing = None;
        self.next_at = None;
        self.mode = Mode::Back(Back::Reset);
    }

    /// The counters of the bypass ring: refused, lost, broken.
    #[cfg_attr(not(feature = "probe"), allow(dead_code))]
    pub fn ring_counters(&self) -> Option<(u64, u64, bool)> {
        self.fast.as_ref().map(|f| (f.refused, f.lost, f.broken))
    }

    /// Which step of the return is next, for the line of the longest
    /// step: 1 the reset, 2 the features, 3 and 4 the queues, 5 and on the
    /// fill.
    pub fn back_detail(&self) -> u64 {
        match self.mode {
            Mode::Back(Back::Reset) => 1,
            Mode::Back(Back::Open) => 2,
            Mode::Back(Back::ReceiveQueue) => 3,
            Mode::Back(Back::SendQueue) => 4,
            Mode::Back(Back::Fill(first)) => 5 + u64::from(first / FILL_STEP),
            _ => 0,
        }
    }

    /// One step of the return (`Back`).
    pub fn back_step(&mut self) -> Returned {
        let Mode::Back(back) = self.mode else {
            return Returned::Done;
        };
        match back {
            Back::Reset => {
                self.transport.set_status(DeviceStatus::empty());
                if !(0..RESET_READS_STEP).any(|_| self.transport.get_status().is_empty()) {
                    return Returned::More;
                }
                self.mode = Mode::Back(Back::Open);
            }
            Back::Open => {
                let opened = match crate::start_device(&mut self.transport, "virtio-net1") {
                    Ok(opened) => opened,
                    Err(code) => return Returned::Failed(code),
                };
                if opened.mac != self.device.mac {
                    rt::println!("virtio-net1: the MAC changed under its owner");
                    return Returned::Failed(NOT_STARTED);
                }
                let (dma_pa, net_pa) = self.objects;
                if !crate::dma::attach(1, dma_pa, net_pa) {
                    return Returned::Failed(NOT_STARTED);
                }
                self.mode = Mode::Back(Back::ReceiveQueue);
            }
            Back::ReceiveQueue => {
                let Ok(rx_queue) = Q::new(&mut self.transport, RECEIVEQ, false, false) else {
                    return Returned::Failed(NOT_STARTED);
                };
                self.device.rx = RxRing::new(rx_queue);
                self.mode = Mode::Back(Back::SendQueue);
            }
            Back::SendQueue => {
                let Ok(tx_queue) = Q::new(&mut self.transport, TRANSMITQ, false, false) else {
                    return Returned::Failed(NOT_STARTED);
                };
                self.device.tx = TxRing::new(tx_queue);
                self.device.forget_frames();
                self.mode = Mode::Back(Back::Fill(0));
            }
            Back::Fill(first) => {
                let end = (first + FILL_STEP).min(QUEUE_SIZE as u16);
                for n in first..end {
                    self.device.rx.give(n);
                }
                if end < QUEUE_SIZE as u16 {
                    self.mode = Mode::Back(Back::Fill(end));
                    return Returned::More;
                }
                self.transport.finish_init();
                ring(&mut self.transport, RECEIVEQ);
                self.device.rx.ring.dirty = false;
                self.mode = Mode::Own;
                // A static address stays; the DHCP client starts again.
                if let Some(handle) = self.dhcp {
                    self.lease = None;
                    self.iface.update_ip_addrs(|addrs| addrs.clear());
                    self.device.set_addresses(&[]);
                    self.sockets.get_mut::<dhcpv4::Socket>(handle).reset();
                    // The reset of a bound client says "no configuration"
                    // once: that is no loss to report.
                    let _ = self.sockets.get_mut::<dhcpv4::Socket>(handle).poll();
                }
                self.next_at = Some(0);
                if core::mem::take(&mut self.line_closed) {
                    virtio_mmio::reopen(&self.irq);
                }
                return Returned::Done;
            }
        }
        Returned::More
    }

    /// The DHCP client's change since the last call, applied: the address
    /// and nothing else.
    fn dhcp_event(&mut self) -> Option<Event> {
        let handle = self.dhcp?;
        let socket = self.sockets.get_mut::<dhcpv4::Socket>(handle);
        match socket.poll()? {
            dhcpv4::Event::Configured(config) => {
                let lease = Lease {
                    address: config.address.address().octets(),
                    prefix: config.address.prefix_len(),
                    gateway: config.router.map(|r| r.octets()),
                    dns: config.dns_servers.first().map(|d| d.octets()),
                    // The second device writes no resolv.conf.
                    servers: [None; netd::resolv::SERVERS],
                };
                self.apply(&lease);
                // The summary keeps what the server offered; only the
                // address is taken.
                self.lease = Some(lease);
                Some(Event::Leased(lease))
            }
            dhcpv4::Event::Deconfigured => {
                // The client reports "no configuration" once at its start,
                // before there was any to lose.
                let had = self.lease.take().is_some();
                self.iface.update_ip_addrs(|addrs| addrs.clear());
                self.device.set_addresses(&[]);
                had.then_some(Event::Lost)
            }
        }
    }
}
