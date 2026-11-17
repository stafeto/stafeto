// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the stack does with the segments a SYN scan sends, on the host: the
//! rules `net.rs` builds on (`route`, `adopt`). A listening socket that got a
//! SYN and then an RST listens again; a SYN on the four of a connection that
//! stands changes nothing and gets no reply; an ACK no socket holds is
//! answered with an RST (what a peer sees when the key of its connection was
//! not registered); a SYN to a port nobody listens on is answered with an RST;
//! and a burst of UDP datagrams to closed ports does not keep a SYN from its
//! SYN-ACK.

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    ArpOperation, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr,
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr,
    TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
};
use std::collections::VecDeque;

const SERVER: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
const PEER: Ipv4Address = Ipv4Address::new(10, 0, 0, 2);
const SERVER_MAC: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 1]);
const PEER_MAC: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 2]);

#[derive(Default)]
struct Wire {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0; len];
        let r = f(&mut buffer);
        self.0.push(buffer);
        r
    }
}

impl Device for Wire {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        let frame = self.rx.pop_front()?;
        Some((Rx(frame), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps
    }
}

fn tcp_frame(sport: u16, dport: u16, control: TcpControl, seq: u32, ack: Option<u32>) -> Vec<u8> {
    let tcp = TcpRepr {
        src_port: sport,
        dst_port: dport,
        control,
        seq_number: TcpSeqNumber(seq as i32),
        ack_number: ack.map(|a| TcpSeqNumber(a as i32)),
        window_len: 4000,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    let ip = Ipv4Repr {
        src_addr: PEER,
        dst_addr: SERVER,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let eth = EthernetRepr {
        src_addr: PEER_MAC,
        dst_addr: SERVER_MAC,
        ethertype: EthernetProtocol::Ipv4,
    };
    let mut buffer = vec![0; eth.buffer_len() + ip.buffer_len() + tcp.buffer_len()];
    let caps = ChecksumCapabilities::default();
    eth.emit(&mut EthernetFrame::new_unchecked(&mut buffer[..]));
    ip.emit(
        &mut Ipv4Packet::new_unchecked(&mut buffer[eth.buffer_len()..]),
        &caps,
    );
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut buffer[eth.buffer_len() + ip.buffer_len()..]),
        &IpAddress::Ipv4(PEER),
        &IpAddress::Ipv4(SERVER),
        &caps,
    );
    buffer
}

fn udp_frame(sport: u16, dport: u16) -> Vec<u8> {
    let udp = UdpRepr {
        src_port: sport,
        dst_port: dport,
    };
    let payload = [0u8; 8];
    let ip = Ipv4Repr {
        src_addr: PEER,
        dst_addr: SERVER,
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + payload.len(),
        hop_limit: 64,
    };
    let eth = EthernetRepr {
        src_addr: PEER_MAC,
        dst_addr: SERVER_MAC,
        ethertype: EthernetProtocol::Ipv4,
    };
    let mut buffer = vec![0; eth.buffer_len() + ip.buffer_len() + udp.header_len() + payload.len()];
    let caps = ChecksumCapabilities::default();
    eth.emit(&mut EthernetFrame::new_unchecked(&mut buffer[..]));
    ip.emit(
        &mut Ipv4Packet::new_unchecked(&mut buffer[eth.buffer_len()..]),
        &caps,
    );
    udp.emit(
        &mut UdpPacket::new_unchecked(&mut buffer[eth.buffer_len() + ip.buffer_len()..]),
        &IpAddress::Ipv4(PEER),
        &IpAddress::Ipv4(SERVER),
        payload.len(),
        |p| p.copy_from_slice(&payload),
        &caps,
    );
    buffer
}

/// What a frame of the server was: a TCP segment (control, sequence, ack) or
/// something else (ICMP, ARP).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Sent {
    Tcp(TcpControl, u32, Option<u32>, u16),
    Other,
}

fn sent(frame: &[u8]) -> Sent {
    let eth = EthernetFrame::new_checked(frame).unwrap();
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return Sent::Other;
    }
    let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
    if ip.next_header() != IpProtocol::Tcp {
        return Sent::Other;
    }
    let packet = TcpPacket::new_checked(ip.payload()).unwrap();
    let repr = TcpRepr::parse(
        &packet,
        &IpAddress::Ipv4(SERVER),
        &IpAddress::Ipv4(PEER),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    Sent::Tcp(
        repr.control,
        repr.seq_number.0 as u32,
        repr.ack_number.map(|a| a.0 as u32),
        repr.dst_port,
    )
}

const LISTEN_PORT: u16 = 443;

struct Rig<'a> {
    wire: Wire,
    iface: Interface,
    sockets: SocketSet<'a>,
    queue: [SocketHandle; 2],
    now: i64,
}

fn rig() -> Rig<'static> {
    let storage = Box::leak(Box::new([SocketStorage::EMPTY; 4]));
    let mut wire = Wire::default();
    let mut config = Config::new(HardwareAddress::Ethernet(SERVER_MAC));
    config.random_seed = 7;
    let mut iface = Interface::new(config, &mut wire, Instant::from_millis(0));
    iface.update_ip_addrs(|a| {
        a.push(IpCidr::new(IpAddress::Ipv4(SERVER), 24)).unwrap();
    });
    let mut sockets = SocketSet::new(&mut storage[..]);
    let mut queue = [SocketHandle::default(); 2];
    for slot in &mut queue {
        let rx = tcp::SocketBuffer::new(Box::leak(vec![0u8; 2048].into_boxed_slice()));
        let tx = tcp::SocketBuffer::new(Box::leak(vec![0u8; 2048].into_boxed_slice()));
        let mut socket = tcp::Socket::new(rx, tx);
        socket
            .listen(IpEndpoint::new(IpAddress::Ipv4(SERVER), LISTEN_PORT))
            .unwrap();
        *slot = sockets.add(socket);
    }
    let mut rig = Rig {
        wire,
        iface,
        sockets,
        queue,
        now: 0,
    };
    // The peer asks for the address of the server, which teaches the server
    // the address of the peer.
    let arp = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: PEER_MAC,
        source_protocol_addr: PEER,
        target_hardware_addr: EthernetAddress([0; 6]),
        target_protocol_addr: SERVER,
    };
    let eth = EthernetRepr {
        src_addr: PEER_MAC,
        dst_addr: EthernetAddress::BROADCAST,
        ethertype: EthernetProtocol::Arp,
    };
    let mut frame = vec![0; eth.buffer_len() + arp.buffer_len()];
    eth.emit(&mut EthernetFrame::new_unchecked(&mut frame[..]));
    arp.emit(&mut smoltcp::wire::ArpPacket::new_unchecked(
        &mut frame[eth.buffer_len()..],
    ));
    rig.feed(frame);
    rig
}

impl Rig<'_> {
    /// One frame in, the stack run, what it sent out.
    fn feed(&mut self, frame: Vec<u8>) -> Vec<Sent> {
        self.wire.rx.push_back(frame);
        self.now += 1;
        self.iface.poll(
            Instant::from_millis(self.now),
            &mut self.wire,
            &mut self.sockets,
        );
        self.wire.tx.drain(..).map(|f| sent(&f)).collect()
    }

    fn state(&mut self, i: usize) -> tcp::State {
        self.sockets.get::<tcp::Socket>(self.queue[i]).state()
    }

    fn states(&mut self) -> [tcp::State; 2] {
        [self.state(0), self.state(1)]
    }
}

/// The peer's side of a handshake: its SYN and the ACK of the SYN-ACK. Gives
/// the reply to the SYN, and the peer's next sequence number.
fn handshake(rig: &mut Rig<'_>, sport: u16, complete: bool) -> (Sent, u32) {
    let isn = 1000;
    let out = rig.feed(tcp_frame(sport, LISTEN_PORT, TcpControl::Syn, isn, None));
    assert_eq!(out.len(), 1, "{out:?}");
    let Sent::Tcp(TcpControl::Syn, server_isn, Some(ack), _) = out[0] else {
        panic!("no SYN-ACK: {out:?}");
    };
    assert_eq!(ack, isn + 1);
    if complete {
        let out = rig.feed(tcp_frame(
            sport,
            LISTEN_PORT,
            TcpControl::None,
            isn + 1,
            Some(server_isn + 1),
        ));
        assert!(out.is_empty(), "{out:?}");
    }
    (out[0], isn + 1)
}

fn server_next(reply: Sent) -> u32 {
    let Sent::Tcp(_, seq, _, _) = reply else {
        panic!("{reply:?}")
    };
    seq + 1
}

/// The premise of the stale key: an RST in SYN-RECEIVED sends the socket back
/// to LISTEN, and the SYN that follows is given to that same socket (the
/// first that listens), which is no longer in LISTEN when `adopt` looks.
#[test]
fn a_socket_reset_in_syn_received_listens_and_takes_the_next_syn() {
    let mut rig = rig();
    let (reply, next) = handshake(&mut rig, 40000, false);
    assert_eq!(rig.states(), [tcp::State::SynReceived, tcp::State::Listen]);
    // What the kernel of the scanner sends for a SYN-ACK it has no socket for.
    let out = rig.feed(tcp_frame(
        40000,
        LISTEN_PORT,
        TcpControl::Rst,
        next,
        Some(server_next(reply)),
    ));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(rig.states(), [tcp::State::Listen, tcp::State::Listen]);
    handshake(&mut rig, 40001, false);
    assert_eq!(rig.states(), [tcp::State::SynReceived, tcp::State::Listen]);
}

/// A SYN on the four of a connection that stands changes nothing and gets no
/// reply: a scan cannot reset an accepted connection through the stack.
#[test]
fn a_syn_on_the_four_of_an_established_connection_is_ignored() {
    let mut rig = rig();
    handshake(&mut rig, 40000, true);
    assert_eq!(rig.states(), [tcp::State::Established, tcp::State::Listen]);
    for isn in [5000, 1000, 1001, 90000] {
        let out = rig.feed(tcp_frame(40000, LISTEN_PORT, TcpControl::Syn, isn, None));
        assert!(
            out.iter()
                .all(|s| !matches!(s, Sent::Tcp(TcpControl::Rst, ..))),
            "{out:?}"
        );
        assert_eq!(rig.states(), [tcp::State::Established, tcp::State::Listen]);
    }
}

/// The ACK that completes a handshake whose socket no frame reached (the set
/// of the service holds no socket for it) is answered with an RST: the peer's
/// next write fails with "Connection reset by peer". This is what a queue
/// socket without the key of its connection costs the peer.
#[test]
fn an_ack_no_socket_holds_is_answered_with_an_rst() {
    let mut rig = rig();
    // The set of the service: no socket at all.
    let mut none = SocketSet::new(Box::leak(Box::new([SocketStorage::EMPTY])) as &mut [_]);
    rig.wire.rx.push_back(tcp_frame(
        40002,
        LISTEN_PORT,
        TcpControl::None,
        1001,
        Some(777),
    ));
    rig.iface
        .poll(Instant::from_millis(5), &mut rig.wire, &mut none);
    let out: Vec<Sent> = rig.wire.tx.drain(..).map(|f| sent(&f)).collect();
    assert_eq!(
        out,
        vec![Sent::Tcp(TcpControl::Rst, 777, None, 40002)],
        "{out:?}"
    );
}

/// A SYN to a port nobody listens on (the set of the service has no socket
/// for it) is answered with an RST at once.
#[test]
fn a_syn_to_a_port_nobody_listens_on_is_answered_with_an_rst() {
    let mut rig = rig();
    let out = rig.feed(tcp_frame(40003, 8443, TcpControl::Syn, 1000, None));
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(matches!(out[0], Sent::Tcp(TcpControl::Rst, ..)), "{out:?}");
}

/// A burst of UDP datagrams to closed ports gets an ICMP reply each and does
/// not keep a SYN that follows from its SYN-ACK.
#[test]
fn a_udp_burst_does_not_keep_a_syn_from_its_syn_ack() {
    let mut rig = rig();
    let mut replies = 0;
    for port in 1..=300u16 {
        replies += rig.feed(udp_frame(50000, port)).len();
    }
    assert!(replies > 0);
    let (reply, _) = handshake(&mut rig, 40004, false);
    assert!(matches!(reply, Sent::Tcp(TcpControl::Syn, ..)));
}

// ----- the rules of `adopt` over the stack: SYN A, RST A, SYN B, ACK B -----

use crate::queue::{self, KeyRule};
use std::collections::HashMap;

/// The table of destinations of the service for the sockets of the queue,
/// driven by the rules of `queue.rs` after each SYN as `adopt` is: a key is a
/// remote port, `keys[m]` the key socket `m` holds.
struct Table {
    by_key: HashMap<u16, usize>,
    keys: [Option<u16>; 2],
    /// The rule: the one `net.rs` uses, or the one it used before.
    old_rule: bool,
}

/// The rule of `adopt` before the replacement of a stale key.
fn old_rule(listening: bool, has_key: bool) -> KeyRule {
    match (listening, has_key) {
        (true, _) => KeyRule::Release,
        (false, false) => KeyRule::Register,
        (false, true) => KeyRule::Keep,
    }
}

impl Table {
    fn new(old_rule: bool) -> Table {
        Table {
            by_key: HashMap::new(),
            keys: [None; 2],
            old_rule,
        }
    }

    fn adopt(&mut self, rig: &mut Rig<'_>) {
        for m in 0..2 {
            let listening = rig.state(m) == tcp::State::Listen;
            let remote = rig
                .sockets
                .get::<tcp::Socket>(rig.queue[m])
                .remote_endpoint()
                .map(|e| e.port);
            let rule = if self.old_rule {
                old_rule(listening, self.keys[m].is_some())
            } else {
                queue::adopt_rule(
                    listening,
                    self.keys[m].is_some(),
                    self.keys[m].is_some() && self.keys[m] == remote,
                )
            };
            if matches!(rule, KeyRule::Release | KeyRule::Replace) {
                if let Some(k) = self.keys[m].take() {
                    self.by_key.remove(&k);
                }
            }
            if matches!(rule, KeyRule::Register | KeyRule::Replace)
                && let Some(port) = remote
            {
                self.keys[m] = Some(port);
                self.by_key.insert(port, m);
            }
        }
    }
}

/// The replay: a SYN from A, A's RST, a SYN from B (taken by the socket that
/// went back to LISTEN, with no step of `sync` between), and B's ACK. With the
/// rule of `adopt` B's key is registered and the ACK reaches the queue; the
/// rule before it left the old key and the ACK found no place.
fn replay(old: bool) -> (Vec<Sent>, tcp::State) {
    let mut rig = rig();
    let mut table = Table::new(old);
    let (reply, next) = handshake(&mut rig, 40000, false);
    table.adopt(&mut rig);
    rig.feed(tcp_frame(
        40000,
        LISTEN_PORT,
        TcpControl::Rst,
        next,
        Some(server_next(reply)),
    ));
    let (reply_b, next_b) = handshake(&mut rig, 40001, false);
    table.adopt(&mut rig);
    let ack = tcp_frame(
        40001,
        LISTEN_PORT,
        TcpControl::None,
        next_b,
        Some(server_next(reply_b)),
    );
    if table.by_key.contains_key(&40001) {
        let out = rig.feed(ack);
        let m = table.by_key[&40001];
        (out, rig.state(m))
    } else {
        // No key: the frame goes to the set of the service, which holds no socket.
        let mut none = SocketSet::new(Box::leak(Box::new([SocketStorage::EMPTY])) as &mut [_]);
        rig.wire.rx.push_back(ack);
        rig.iface
            .poll(Instant::from_millis(99), &mut rig.wire, &mut none);
        let out = rig.wire.tx.drain(..).map(|f| sent(&f)).collect();
        (out, rig.state(0))
    }
}

#[test]
fn the_ack_of_the_second_peer_finds_its_key_with_the_rule_of_adopt() {
    let (out, state) = replay(false);
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(state, tcp::State::Established);
}

#[test]
fn the_rule_before_the_replacement_loses_the_key_and_the_peer_is_reset() {
    let (out, _) = replay(true);
    assert!(
        matches!(out.as_slice(), [Sent::Tcp(TcpControl::Rst, ..)]),
        "{out:?}"
    );
}
