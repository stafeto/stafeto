// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The stack of the service: the smoltcp interface over the device, the
//! DHCP client (RFC 2131) or a static address, and the ICMP socket that
//! PING of the probe uses. The interface is polled one frame at a time and
//! never by the stack's own loop, which has no bound (smoltcp's `poll`
//! says so itself): `ingress` takes frames until the device has none or
//! the step's share is spent, `egress` sends until the stack has nothing or
//! the share is spent.
//!
//! smoltcp walks every socket of the set it is given in each pass, so the
//! cost of a step would grow with the number of sockets. The sockets of the
//! descriptions are therefore in sets of GROUP places, the place `i` of the
//! table in the set `i / GROUP`, and the sockets of the service itself (DHCP
//! and ICMP) in a set of their own. A received frame goes to the set of the
//! socket it is for (the table of destinations, demux.rs), and the pass of
//! sending visits a few sets of those that have work (EGRESS_GROUPS at most).

use crate::device::NetDevice;
use crate::net::Net;
use crate::split;
use netd::config::Cidr;
use netd::frames::Dest;
use netd::lines::Summary;
use netd::ring::EGRESS_GROUPS;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::socket::{dhcpv4, icmp, tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address,
    Ipv4Cidr,
};

/// The places of one set of sockets.
pub const GROUP: usize = 4;
/// The sets of the descriptions' sockets, and the room for their storage.
pub const GROUPS: usize = netd::places::SOCKETS_LIMIT / GROUP;
const _: () = assert!(netd::places::SOCKETS_LIMIT.is_multiple_of(GROUP));
// A set of groups is a bit each in a word.
const _: () = assert!(GROUPS <= 64);
const _: () = assert!(netd::places::SOCKETS_LIMIT <= netd::places::SOCKETS_MAX);
/// The sockets of the service itself: the DHCP client and the ICMP socket.
const SERVICE_SLOTS: usize = 2;

/// A socket of a description: the set it is in and its handle there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sh {
    pub group: u8,
    pub handle: SocketHandle,
}

/// The bytes of each ICMP buffer: the echo requests that fill a frame are a
/// method of the probe.
const ICMP_BYTES: usize = if cfg!(feature = "probe") { 2048 } else { 1024 };

/// The storage of the sockets and the ICMP socket's buffers, which the
/// stack borrows; it lives in the service's `.bss`.
pub struct Storage<'a> {
    sockets: [SocketStorage<'a>; netd::places::SOCKETS_LIMIT],
    service: [SocketStorage<'a>; SERVICE_SLOTS],
    rx_meta: [icmp::PacketMetadata; 4],
    rx_data: [u8; ICMP_BYTES],
    tx_meta: [icmp::PacketMetadata; 4],
    tx_data: [u8; ICMP_BYTES],
}

impl Storage<'_> {
    /// The storage as it starts, in place in zeroed memory (the empty
    /// socket is not all zeros, and a static of it would go to `.data`).
    ///
    /// # Safety
    /// `at` is valid for writes, exclusive and zeroed.
    pub unsafe fn initialize_at(at: *mut Self) {
        use core::ptr::addr_of_mut;
        // SAFETY: each field is in bounds and written once.
        unsafe {
            let sockets = addr_of_mut!((*at).sockets).cast::<SocketStorage<'_>>();
            for i in 0..netd::places::SOCKETS_LIMIT {
                sockets.add(i).write(SocketStorage::EMPTY);
            }
            let service = addr_of_mut!((*at).service).cast::<SocketStorage<'_>>();
            for i in 0..SERVICE_SLOTS {
                service.add(i).write(SocketStorage::EMPTY);
            }
            rt::bss::fill(addr_of_mut!((*at).rx_meta), icmp::PacketMetadata::EMPTY);
            rt::bss::fill(addr_of_mut!((*at).tx_meta), icmp::PacketMetadata::EMPTY);
        }
    }
}

/// The identifier of the echo requests of PING.
const IDENT: u16 = 0x5354;
/// The bytes of data in an echo request of PING.
#[cfg_attr(not(feature = "probe"), allow(dead_code))]
pub const ECHO_DATA: usize = 32;
/// How long a PING waits for its reply, in the guest's time.
#[cfg_attr(not(feature = "probe"), allow(dead_code))]
pub const PING_TIMEOUT_NS: u64 = 1_000_000_000;

/// What the interface has as its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub address: [u8; 4],
    pub prefix: u8,
    pub gateway: Option<[u8; 4]>,
    pub dns: Option<[u8; 4]>,
}

impl Lease {
    pub fn summary(&self) -> Summary {
        Summary {
            address: self.address,
            prefix: self.prefix,
            gateway: self.gateway,
            dns: self.dns,
        }
    }
}

/// What came of the DHCP client in a step.
pub enum Event {
    Leased(Lease),
    Lost,
}

/// The PING in flight.
pub struct Ping {
    seq: u16,
    started_ns: u64,
    pub deadline_ns: u64,
}

/// How a PING ended.
pub enum PingEnd {
    /// The round-trip time in nanoseconds.
    Reply(u64),
    TimedOut,
}

pub struct Stack<'a> {
    pub iface: Interface,
    groups: [SocketSet<'a>; GROUPS],
    service: SocketSet<'a>,
    dhcp: Option<SocketHandle>,
    icmp: SocketHandle,
    /// The next deadline of each set (`poll_at`), in nanoseconds of the
    /// counter: the groups, then the service's. None while it waits for a
    /// frame or a request.
    group_at: [Option<u64>; GROUPS + 1],
    /// Where the pass of sending goes on.
    cursor: usize,
    /// The least of the deadlines of the groups (u64::MAX for none): the walk
    /// over them is made only once it has come.
    earliest: u64,
    /// The service's set has work: a frame for it, a PING, a new address.
    pub service_due: bool,
    /// The service's set was passed or took a frame since `take_service_ran`.
    service_ran: bool,
    pub lease: Option<Lease>,
    pub ping: Option<Ping>,
    #[cfg_attr(not(feature = "probe"), allow(dead_code))]
    seq: u16,
}

/// The stack's clock: microseconds of the guest's counter.
pub fn instant(now_ns: u64) -> Instant {
    Instant::from_micros((now_ns / 1000) as i64)
}

/// 127.0.0.1/8, the interface's second address (RFC 1122, 3.2.1.3): the
/// first is the external one, which the stack takes as the source of the
/// frames it sends to a gateway.
const LOOPBACK: Ipv4Cidr = Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 8);

/// The endpoint a socket listens or binds on: the wildcard address is none.
pub fn listen_endpoint(address: [u8; 4], port: u16) -> smoltcp::wire::IpListenEndpoint {
    smoltcp::wire::IpListenEndpoint {
        addr: (address != [0; 4]).then(|| IpAddress::Ipv4(ipv4(address))),
        port,
    }
}

fn ipv4(octets: [u8; 4]) -> Ipv4Address {
    Ipv4Address::from(octets)
}

impl<'a> Stack<'a> {
    pub fn new(
        storage: &'a mut Storage<'a>,
        device: &mut NetDevice,
        mac: [u8; 6],
        seed: u64,
        now_ns: u64,
        dhcp: bool,
    ) -> Stack<'a> {
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        config.random_seed = seed;
        let mut iface = Interface::new(config, device, instant(now_ns));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::Ipv4(LOOPBACK));
        });
        let Storage {
            sockets,
            service,
            rx_meta,
            rx_data,
            tx_meta,
            tx_data,
        } = storage;
        let mut chunks = sockets.chunks_mut(GROUP);
        let groups: [SocketSet<'a>; GROUPS] = core::array::from_fn(|_| {
            SocketSet::new(chunks.next().expect("the storage of a group"))
        });
        let mut set = SocketSet::new(&mut service[..]);
        let mut icmp_socket = icmp::Socket::new(
            icmp::PacketBuffer::new(&mut rx_meta[..], &mut rx_data[..]),
            icmp::PacketBuffer::new(&mut tx_meta[..], &mut tx_data[..]),
        );
        // A bind that fails would leave PING with no reply to see; the
        // identifier is the only one on a fresh socket.
        let _ = icmp_socket.bind(icmp::Endpoint::Ident(IDENT));
        let icmp = set.add(icmp_socket);
        let dhcp = dhcp.then(|| set.add(dhcpv4::Socket::new()));
        Stack {
            iface,
            groups,
            service: set,
            dhcp,
            icmp,
            group_at: [None; GROUPS + 1],
            cursor: 0,
            earliest: u64::MAX,
            service_due: true,
            service_ran: false,
            lease: None,
            ping: None,
            seq: 0,
        }
    }

    /// Gives the interface the address of the file `netd.conf`.
    pub fn set_static(&mut self, address: Cidr, gateway: Option<[u8; 4]>, dns: Option<[u8; 4]>) {
        let lease = Lease {
            address: address.address,
            prefix: address.prefix,
            gateway,
            dns,
        };
        self.apply(&lease);
    }

    fn apply(&mut self, lease: &Lease) {
        let cidr = Ipv4Cidr::new(ipv4(lease.address), lease.prefix);
        self.iface.update_ip_addrs(|addrs| {
            addrs.clear();
            let _ = addrs.push(IpCidr::Ipv4(cidr));
            let _ = addrs.push(IpCidr::Ipv4(LOOPBACK));
        });
        let routes = self.iface.routes_mut();
        routes.remove_default_ipv4_route();
        if let Some(gateway) = lease.gateway {
            let _ = routes.add_default_ipv4_route(ipv4(gateway));
        }
        self.lease = Some(*lease);
        self.service_due = true;
    }

    fn remove(&mut self) {
        self.iface.update_ip_addrs(|addrs| {
            addrs.clear();
            let _ = addrs.push(IpCidr::Ipv4(LOOPBACK));
        });
        self.iface.routes_mut().remove_default_ipv4_route();
        self.lease = None;
    }

    /// Sends what the sets have that is due, at most EGRESS_GROUPS groups
    /// of the groups in `due` (a bit each) and the service's set, each in one
    /// pass over its few sockets. A group whose pass reached its end leaves
    /// `due`; one that the share of sending cut short stays. The groups the
    /// pass visited are added to `touched` and `passed`. Each pass also reads the deadline
    /// of its set.
    pub fn egress(
        &mut self,
        now_ns: u64,
        device: &mut NetDevice,
        due: &mut u64,
        touched: &mut u64,
        passed: &mut u64,
    ) {
        let now = instant(now_ns);
        // The service's set only when it has work.
        if self.service_due || self.group_at[GROUPS].is_some_and(|at| at <= now_ns) {
            self.service_due = false;
            self.service_ran = true;
            self.iface.poll_maintenance(now);
            let _ = self.iface.poll_egress(now, device, &mut self.service);
            self.group_at[GROUPS] = Self::deadline(self.iface.poll_at(now, &self.service));
        }
        // The walk over the deadlines of the groups only when one has come.
        if now_ns >= self.earliest {
            let mut earliest = u64::MAX;
            for (g, at) in self.group_at[..GROUPS].iter_mut().enumerate() {
                match *at {
                    Some(t) if t <= now_ns => {
                        *due |= 1 << g;
                        *at = None;
                    }
                    Some(t) => earliest = earliest.min(t),
                    None => {}
                }
            }
            self.earliest = earliest;
        }
        let mut ran = 0;
        let mut seen = 0;
        while ran < EGRESS_GROUPS && seen < GROUPS && *due != 0 && device.tx.can_send() {
            let g = self.cursor % GROUPS;
            self.cursor = g + 1;
            seen += 1;
            if *due >> g & 1 == 0 {
                continue;
            }
            ran += 1;
            let began = split::now();
            let tx_before = split::get(&split::TX);
            let before = device.tx.sent();
            let _ = self.iface.poll_egress(now, device, &mut self.groups[g]);
            let sent = device.tx.sent() - before;
            let at = Self::deadline(self.iface.poll_at(now, &self.groups[g]));
            let spent = split::now() - began;
            split::record(
                split::GROUP,
                spent.saturating_sub(split::get(&split::TX) - tx_before),
            );
            split::add(&split::PASSES, spent);
            *touched |= 1 << g;
            *passed |= 1 << g;
            *due &= !(1 << g);
            self.group_at[g] = match at {
                // Work now: another pass when it sent something and the share
                // is not spent; a group with nothing to send waits a
                // millisecond, as the timer of the service would.
                Some(at) if at <= now_ns => {
                    if sent > 0 {
                        *due |= 1 << g;
                        Some(at)
                    } else {
                        Some(now_ns + 1_000_000)
                    }
                }
                other => other,
            };
            if let Some(t) = self.group_at[g] {
                self.earliest = self.earliest.min(t);
            }
        }
    }

    /// Whether the service's set was passed or took a frame since the last
    /// call: the DHCP client may have something to say.
    pub fn take_service_ran(&mut self) -> bool {
        core::mem::take(&mut self.service_ran)
    }

    /// A deadline of smoltcp, in nanoseconds of the counter.
    fn deadline(at: Option<smoltcp::time::Instant>) -> Option<u64> {
        let at = at?;
        Some((at.total_micros().max(0) as u64).saturating_mul(1000))
    }

    /// The addresses of the interface, for the route of its frames.
    pub fn addresses(&self) -> ([[u8; 4]; 2], usize) {
        let mut own = [[0; 4]; 2];
        let mut n = 0;
        for cidr in self.iface.ip_addrs() {
            if let IpCidr::Ipv4(c) = cidr
                && n < own.len()
            {
                own[n] = c.address().octets();
                n += 1;
            }
        }
        (own, n)
    }

    /// A TCP socket of the place `place` over the two buffers.
    pub fn tcp_add(&mut self, place: usize, rx: &'a mut [u8], tx: &'a mut [u8]) -> Sh {
        let group = place / GROUP;
        let handle = self.groups[group].add(tcp::Socket::new(
            tcp::SocketBuffer::new(rx),
            tcp::SocketBuffer::new(tx),
        ));
        Sh {
            group: group as u8,
            handle,
        }
    }

    /// A UDP socket of the place `place` over the buffers of the two
    /// directions.
    pub fn udp_add(
        &mut self,
        place: usize,
        rx: udp::PacketBuffer<'a>,
        tx: udp::PacketBuffer<'a>,
    ) -> Sh {
        let group = place / GROUP;
        let handle = self.groups[group].add(udp::Socket::new(rx, tx));
        Sh {
            group: group as u8,
            handle,
        }
    }

    pub fn drop_socket(&mut self, sh: Sh) {
        let _ = self.groups[usize::from(sh.group)].remove(sh.handle);
    }

    pub fn tcp(&mut self, sh: Sh) -> &mut tcp::Socket<'a> {
        self.groups[usize::from(sh.group)].get_mut::<tcp::Socket>(sh.handle)
    }

    pub fn udp(&mut self, sh: Sh) -> &mut udp::Socket<'a> {
        self.groups[usize::from(sh.group)].get_mut::<udp::Socket>(sh.handle)
    }

    /// `connect` of a TCP socket: the interface's context chooses the route.
    pub fn tcp_connect(
        &mut self,
        sh: Sh,
        remote: ([u8; 4], u16),
        local: ([u8; 4], u16),
    ) -> Result<(), tcp::ConnectError> {
        let remote = smoltcp::wire::IpEndpoint::new(IpAddress::Ipv4(ipv4(remote.0)), remote.1);
        let addr = (local.0 != [0; 4]).then(|| IpAddress::Ipv4(ipv4(local.0)));
        let local = smoltcp::wire::IpListenEndpoint {
            addr,
            port: local.1,
        };
        let socket = self.groups[usize::from(sh.group)].get_mut::<tcp::Socket>(sh.handle);
        socket.connect(self.iface.context(), remote, local)
    }

    /// The deadline of the stack's next work, in nanoseconds of the
    /// counter's scale, or None when it waits for a frame: the earliest of
    /// the sets'.
    pub fn next_deadline(&self) -> Option<u64> {
        let groups = (self.earliest != u64::MAX).then_some(self.earliest);
        [groups, self.group_at[GROUPS]].into_iter().flatten().min()
    }

    /// The change of the DHCP client since the last call, applied to the
    /// interface.
    pub fn dhcp_event(&mut self) -> Option<Event> {
        let handle = self.dhcp?;
        let socket = self.service.get_mut::<dhcpv4::Socket>(handle);
        match socket.poll()? {
            dhcpv4::Event::Configured(config) => {
                let lease = Lease {
                    address: config.address.address().octets(),
                    prefix: config.address.prefix_len(),
                    gateway: config.router.map(|r| r.octets()),
                    dns: config.dns_servers.first().map(|d| d.octets()),
                };
                self.apply(&lease);
                Some(Event::Leased(lease))
            }
            dhcpv4::Event::Deconfigured => {
                // The client reports "no configuration" once at its start,
                // before there was any to lose.
                let had = self.lease.is_some();
                self.remove();
                had.then_some(Event::Lost)
            }
        }
    }

    /// Queues an echo request to `target`; false when the socket has no
    /// room.
    #[cfg_attr(not(feature = "probe"), allow(dead_code))]
    pub fn ping_start(&mut self, target: [u8; 4], now_ns: u64, length: usize) -> bool {
        let socket = self.service.get_mut::<icmp::Socket>(self.icmp);
        self.seq = self.seq.wrapping_add(1);
        let data = [0x5A; proto_net::PING_WIRE_DATA];
        let data = &data[..length];
        let repr = Icmpv4Repr::EchoRequest {
            ident: IDENT,
            seq_no: self.seq,
            data,
        };
        let Ok(bytes) = socket.send(repr.buffer_len(), IpAddress::Ipv4(ipv4(target))) else {
            return false;
        };
        let mut packet = Icmpv4Packet::new_unchecked(bytes);
        repr.emit(&mut packet, &smoltcp::phy::ChecksumCapabilities::default());
        self.service_due = true;
        self.ping = Some(Ping {
            seq: self.seq,
            started_ns: now_ns,
            deadline_ns: now_ns.saturating_add(PING_TIMEOUT_NS),
        });
        true
    }

    /// How the PING in flight ended, if it did: the reply is in the socket
    /// or its time ran out.
    pub fn ping_end(&mut self, now_ns: u64) -> Option<PingEnd> {
        let socket = self.service.get_mut::<icmp::Socket>(self.icmp);
        let mut reply = None;
        while socket.can_recv() {
            let Ok((payload, _)) = socket.recv() else {
                break;
            };
            let Ok(packet) = Icmpv4Packet::new_checked(payload) else {
                continue;
            };
            let sums = smoltcp::phy::ChecksumCapabilities::default();
            if let Ok(Icmpv4Repr::EchoReply { ident, seq_no, .. }) =
                Icmpv4Repr::parse(&packet, &sums)
            {
                let wanted = self.ping.as_ref().map(|p| p.seq);
                if ident == IDENT && Some(seq_no) == wanted {
                    reply = Some(now_ns);
                }
            }
        }
        let ping = self.ping.as_ref()?;
        if let Some(at) = reply {
            let took = at.saturating_sub(ping.started_ns);
            self.ping = None;
            return Some(PingEnd::Reply(took));
        }
        if now_ns >= ping.deadline_ns {
            self.ping = None;
            return Some(PingEnd::TimedOut);
        }
        None
    }
}

/// Takes the frames of the step off the device, each to the set of sockets it
/// is for: the table of destinations names the place (`Net::route`), the
/// frame goes to the set of its group, and a frame nobody owns to the set of
/// the service. The group is marked for the pass of sending. An ARP frame
/// marks every group: a socket that waited for the neighbour tries again.
pub fn ingress(stack: &mut Stack<'static>, device: &mut NetDevice, net: &mut Net, now_ns: u64) {
    let now = instant(now_ns);
    loop {
        let began = split::now();
        let sent = split::get(&split::TX);
        let Some(dest) = device.stage() else { break };
        let place = net.route(stack, dest);
        let set = match place {
            Some(place) => {
                net.touch(place);
                &mut stack.groups[place / GROUP]
            }
            None => {
                if dest == Dest::Arp {
                    net.touch_all();
                }
                stack.service_ran = true;
                stack.service_due = true;
                &mut stack.service
            }
        };
        let _ = stack.iface.poll_ingress_single(now, device, set);
        if place.is_some() {
            net.adopt(stack);
        }
        let spent = split::now() - began;
        split::record(
            split::FRAME_RX,
            spent.saturating_sub(split::get(&split::TX) - sent),
        );
        split::add(&split::RX_TURNS, spent);
    }
}
