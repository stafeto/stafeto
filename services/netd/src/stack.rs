// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The stack of the service: the smoltcp interface over the device, the
//! DHCP client (RFC 2131) or a static address, and the ICMP socket that
//! PING of the probe uses. The interface is polled one frame at a time and
//! never by the stack's own loop, which has no bound (smoltcp's `poll`
//! says so itself): `ingress` takes frames until the device has none or
//! the step's share is spent, `egress` sends until the stack has nothing or
//! the share is spent.

use crate::device::NetDevice;
use netd::config::Cidr;
use netd::lines::Summary;
use smoltcp::iface::{
    Config, Interface, PollIngressSingleResult, SocketHandle, SocketSet, SocketStorage,
};
use smoltcp::socket::{dhcpv4, icmp, tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address,
    Ipv4Cidr,
};

/// The sockets of the set: the descriptions' (SOCKETS_MAX, members of a
/// queue of `listen` among them), the ICMP socket of PING and the DHCP
/// client.
pub const SOCKET_SLOTS: usize = netd::places::SOCKETS_MAX + 2;

/// The storage of the sockets and the ICMP socket's buffers, which the
/// stack borrows; it lives in the service's `.bss`.
pub struct Storage<'a> {
    sockets: [SocketStorage<'a>; SOCKET_SLOTS],
    rx_meta: [icmp::PacketMetadata; 4],
    rx_data: [u8; 1024],
    tx_meta: [icmp::PacketMetadata; 4],
    tx_data: [u8; 1024],
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
            for i in 0..SOCKET_SLOTS {
                sockets.add(i).write(SocketStorage::EMPTY);
            }
            rt::bss::fill(addr_of_mut!((*at).rx_meta), icmp::PacketMetadata::EMPTY);
            rt::bss::fill(addr_of_mut!((*at).tx_meta), icmp::PacketMetadata::EMPTY);
        }
    }
}

/// The identifier of the echo requests of PING.
const IDENT: u16 = 0x5354;
/// The bytes of data in an echo request.
#[cfg_attr(not(feature = "probe"), allow(dead_code))]
const ECHO_DATA: usize = 32;
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
    sockets: SocketSet<'a>,
    dhcp: Option<SocketHandle>,
    icmp: SocketHandle,
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
            rx_meta,
            rx_data,
            tx_meta,
            tx_data,
        } = storage;
        let mut set = SocketSet::new(&mut sockets[..]);
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
            sockets: set,
            dhcp,
            icmp,
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
    }

    fn remove(&mut self) {
        self.iface.update_ip_addrs(|addrs| {
            addrs.clear();
            let _ = addrs.push(IpCidr::Ipv4(LOOPBACK));
        });
        self.iface.routes_mut().remove_default_ipv4_route();
        self.lease = None;
    }

    /// Takes frames from the device until it has none or the step's share
    /// of receiving is spent.
    pub fn ingress(&mut self, now_ns: u64, device: &mut NetDevice) {
        let now = instant(now_ns);
        loop {
            match self
                .iface
                .poll_ingress_single(now, device, &mut self.sockets)
            {
                PollIngressSingleResult::None => break,
                PollIngressSingleResult::PacketProcessed
                | PollIngressSingleResult::SocketStateChanged => {}
            }
        }
    }

    /// Sends what the stack has, in one pass over the sockets: each gives
    /// at most one frame, and the device gives no token once the share of
    /// sending is spent. A pass visits every socket, so a loop of calls would
    /// cost as many passes as it has rounds.
    pub fn egress(&mut self, now_ns: u64, device: &mut NetDevice) {
        let now = instant(now_ns);
        self.iface.poll_maintenance(now);
        let _ = self.iface.poll_egress(now, device, &mut self.sockets);
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

    /// A TCP socket over the two buffers.
    pub fn tcp_add(&mut self, rx: &'a mut [u8], tx: &'a mut [u8]) -> SocketHandle {
        self.sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(rx),
            tcp::SocketBuffer::new(tx),
        ))
    }

    /// A UDP socket over the buffers of the two directions.
    pub fn udp_add(
        &mut self,
        rx: udp::PacketBuffer<'a>,
        tx: udp::PacketBuffer<'a>,
    ) -> SocketHandle {
        self.sockets.add(udp::Socket::new(rx, tx))
    }

    pub fn drop_socket(&mut self, handle: SocketHandle) {
        let _ = self.sockets.remove(handle);
    }

    pub fn tcp(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'a> {
        self.sockets.get_mut::<tcp::Socket>(handle)
    }

    pub fn udp(&mut self, handle: SocketHandle) -> &mut udp::Socket<'a> {
        self.sockets.get_mut::<udp::Socket>(handle)
    }

    /// `connect` of a TCP socket: the interface's context chooses the route.
    pub fn tcp_connect(
        &mut self,
        handle: SocketHandle,
        remote: ([u8; 4], u16),
        local: ([u8; 4], u16),
    ) -> Result<(), tcp::ConnectError> {
        let remote = smoltcp::wire::IpEndpoint::new(IpAddress::Ipv4(ipv4(remote.0)), remote.1);
        let addr = (local.0 != [0; 4]).then(|| IpAddress::Ipv4(ipv4(local.0)));
        let local = smoltcp::wire::IpListenEndpoint {
            addr,
            port: local.1,
        };
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket.connect(self.iface.context(), remote, local)
    }

    /// The deadline of the stack's next work, in nanoseconds of the
    /// counter's scale, or None when it waits for a frame.
    pub fn poll_at_ns(&mut self, now_ns: u64) -> Option<u64> {
        let at = self.iface.poll_at(instant(now_ns), &self.sockets)?;
        Some((at.total_micros().max(0) as u64).saturating_mul(1000))
    }

    /// The change of the DHCP client since the last call, applied to the
    /// interface.
    pub fn dhcp_event(&mut self) -> Option<Event> {
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
    pub fn ping_start(&mut self, target: [u8; 4], now_ns: u64) -> bool {
        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp);
        self.seq = self.seq.wrapping_add(1);
        let data = [0x5A; ECHO_DATA];
        let repr = Icmpv4Repr::EchoRequest {
            ident: IDENT,
            seq_no: self.seq,
            data: &data,
        };
        let Ok(bytes) = socket.send(repr.buffer_len(), IpAddress::Ipv4(ipv4(target))) else {
            return false;
        };
        let mut packet = Icmpv4Packet::new_unchecked(bytes);
        repr.emit(&mut packet, &smoltcp::phy::ChecksumCapabilities::default());
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
        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp);
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
