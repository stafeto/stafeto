//! The race of stafeto-design#730: a SYN of the host for a port with no listener arrives
//! before the guest knows the host's hardware address (its own ARP request is still
//! unanswered, or the stack's one request a second went to another neighbour). smoltcp sends
//! the reset once; with no neighbour entry the reset was dropped and the host's SYN came
//! again only a second later. The patched stack learns the sender of a unicast IPv4 packet
//! on the link before it answers.

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, IpAddress, IpCidr,
    IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};
use std::collections::VecDeque;

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
        let mut frame = vec![0u8; len];
        let r = f(&mut frame);
        self.0.push(frame);
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

const GUEST_MAC: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 15]);
const HOST_MAC: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 2]);
const GUEST: Ipv4Address = Ipv4Address::new(10, 0, 2, 15);
const HOST: Ipv4Address = Ipv4Address::new(10, 0, 2, 2);

fn syn(src: Ipv4Address, mac: EthernetAddress, port: u16) -> Vec<u8> {
    let tcp = TcpRepr {
        src_port: 40000,
        dst_port: port,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(1000),
        ack_number: None,
        window_len: 1000,
        window_scale: None,
        max_seg_size: Some(1460),
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    let ip = Ipv4Repr {
        src_addr: src,
        dst_addr: GUEST,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let mut frame = vec![0u8; 14 + ip.buffer_len() + tcp.buffer_len()];
    let mut eth = EthernetFrame::new_unchecked(&mut frame);
    eth.set_src_addr(mac);
    eth.set_dst_addr(GUEST_MAC);
    eth.set_ethertype(EthernetProtocol::Ipv4);
    let caps = DeviceCapabilities::default().checksum;
    let mut packet = Ipv4Packet::new_unchecked(eth.payload_mut());
    ip.emit(&mut packet, &caps);
    let mut segment = TcpPacket::new_unchecked(packet.payload_mut());
    tcp.emit(
        &mut segment,
        &IpAddress::Ipv4(src),
        &IpAddress::Ipv4(GUEST),
        &caps,
    );
    frame
}

fn stack() -> (Interface, Wire) {
    let mut wire = Wire::default();
    let mut config = Config::new(HardwareAddress::Ethernet(GUEST_MAC));
    config.random_seed = 1;
    let mut iface = Interface::new(config, &mut wire, Instant::from_millis(0));
    iface.update_ip_addrs(|a| a.push(IpCidr::new(GUEST.into(), 24)).unwrap());
    (iface, wire)
}

/// The frames sent to `mac` that carry a TCP reset.
fn resets_to(wire: &Wire, mac: EthernetAddress) -> usize {
    wire.tx
        .iter()
        .filter(|f| {
            let eth = EthernetFrame::new_unchecked(&f[..]);
            if eth.ethertype() != EthernetProtocol::Ipv4 || eth.dst_addr() != mac {
                return false;
            }
            let ip = Ipv4Packet::new_unchecked(eth.payload());
            ip.next_header() == IpProtocol::Tcp && TcpPacket::new_unchecked(ip.payload()).rst()
        })
        .count()
}

#[test]
fn the_reset_leaves_in_the_poll_that_took_the_syn_with_no_neighbour_entry() {
    let (mut iface, mut wire) = stack();
    let mut sockets = SocketSet::new(vec![]);
    // The cache is empty: the SYN is the first frame from the host.
    wire.rx.push_back(syn(HOST, HOST_MAC, 81));
    iface.poll(Instant::from_millis(5), &mut wire, &mut sockets);
    assert_eq!(resets_to(&wire, HOST_MAC), 1, "frames: {}", wire.tx.len());
}

#[test]
fn a_busy_arp_slot_does_not_hold_the_reset() {
    let (mut iface, mut wire) = stack();
    let mut sockets = SocketSet::new(vec![]);
    // A connection to the name server takes the interface's slot of ARP requests.
    let handle = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    ));
    let cx = iface.context();
    sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(cx, (Ipv4Address::new(10, 0, 2, 3), 53), 50000)
        .unwrap();
    iface.poll(Instant::from_millis(1), &mut wire, &mut sockets);
    let arp = wire
        .tx
        .iter()
        .filter(|f| EthernetFrame::new_unchecked(&f[..]).ethertype() == EthernetProtocol::Arp)
        .count();
    assert_eq!(
        arp, 1,
        "the slot is taken by the request for the name server"
    );
    wire.tx.clear();
    wire.rx.push_back(syn(HOST, HOST_MAC, 81));
    iface.poll(Instant::from_millis(10), &mut wire, &mut sockets);
    assert_eq!(resets_to(&wire, HOST_MAC), 1);
}

#[test]
fn a_source_outside_the_link_teaches_nothing() {
    let (mut iface, mut wire) = stack();
    let mut sockets = SocketSet::new(vec![]);
    wire.rx
        .push_back(syn(Ipv4Address::new(192, 168, 9, 9), HOST_MAC, 81));
    iface.poll(Instant::from_millis(5), &mut wire, &mut sockets);
    assert_eq!(resets_to(&wire, HOST_MAC), 0);
}
