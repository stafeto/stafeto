// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The second network device (spec 6, 3.9): an interface of its own that
//! runs DHCP (RFC 2131) or holds the static address of `netd.conf`
//! (`address1`), and nothing else. It sets no default route, takes no
//! name server, serves no socket of the descriptions and has no loopback;
//! the frames that reach its stack are ARP (the server asks who has the
//! leased address) and the server's DHCP messages (`NetDevice::stage`),
//! so it answers no echo and sends no reset or unreachable. The claim of
//! the device by a client of the sockets is a later stage (CLAIM).
//!
//! The device's step is the first device's, smaller: its interrupt status,
//! up to `STEP_RX` frames into the stack, the stack's DHCP pass, the
//! doorbells. It lives in the service's `.bss` (`Tables`), built in place
//! (`Second::start_at`): its two queues are too big for a second copy on
//! the stack.

use crate::device::{NetDevice, RxRing, TxRing};
use crate::dma::Host;
use crate::stack::{Event, Lease, instant};
use crate::{MAC, MTU, RECEIVEQ, STATUS, TRANSMITQ};
use core::ptr::addr_of_mut;
use netd::config::Cidr;
use netd::lines::{Ip, Mac};
use netd::ring::{Budget, QUEUE_SIZE};
use rt::Handle;
use rt::handle::Interrupt;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::socket::dhcpv4;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address, Ipv4Cidr};
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::{SomeTransport, Transport};
use virtio_mmio::{Isr, StartError};

type Q = VirtQueue<Host<1>, QUEUE_SIZE>;

/// The storage of the one socket the device's set holds (the DHCP client).
pub type Storage = [SocketStorage<'static>; 1];

/// Why the device did not start: the code the service ends with.
pub const NOT_STARTED: u64 = 7;
pub const NO_DEVICE: u64 = 6;

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
    ) -> Result<(), u64> {
        let (pci, function, status) = place;
        let features = match virtio_mmio::start_with(&mut transport, MTU | MAC | STATUS) {
            Ok(bits) => bits,
            Err(StartError::Reset) => return Err(NOT_STARTED),
            Err(StartError::Features) => {
                rt::println!(
                    "virtio-net1: features refused, offered {:#x}",
                    transport.read_device_features()
                );
                return Err(NOT_STARTED);
            }
        };
        if features & MAC == 0 {
            rt::println!("virtio-net1: the device offers no MAC address");
            return Err(NO_DEVICE);
        }
        let Ok((mac, _)) = crate::read_config(&transport) else {
            return Err(NOT_STARTED);
        };
        if !crate::mtu_fits(&transport, features, "virtio-net1") {
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
            virtio_mmio::ring(&mut transport, RECEIVEQ);
            device.rx.dirty = false;
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
        if core::mem::take(&mut self.device.rx.dirty) && self.device.rx.queue.should_notify() {
            virtio_mmio::ring(&mut self.transport, RECEIVEQ);
        }
        if core::mem::take(&mut self.device.tx.dirty) && self.device.tx.queue.should_notify() {
            virtio_mmio::ring(&mut self.transport, TRANSMITQ);
        }
        outcome.more = self.device.rx.queue.can_pop();
        outcome
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
