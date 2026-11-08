// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The frame in a buffer of the device (Virtio 1.2, 5.1.6): the header
//! of 12 bytes that a device with `VIRTIO_F_VERSION_1` puts before every
//! frame it receives and wants before every frame it sends, then the
//! Ethernet frame itself.
//!
//! The header and the checksums are the library's (`virtio_net::frames`);
//! this module holds what the service decides from a frame: whom it is
//! for, where a frame of the stack goes, and what never reaches the wire.

pub use virtio_net::frames::{
    BUFFER_LEN, Csum, HDR_LEN, Header, MAX_FRAME, NUM_BUFFERS_AT, checksum, complete,
    complete_received, fill_partial, fill_sums, ipv4_ends, is_tcp, parse_header, partial_place,
    rx_frame, sum_checked, tx_prepare, verify_header, verify_sums,
};
use virtio_net::frames::{
    ETHERNET_HEADER, ETHERTYPE_ARP, IPV4_PROTO_ICMP, IPV4_PROTO_TCP, IPV4_PROTO_UDP, packet,
};

/// Where an ARP request's target protocol address is in the frame (RFC 826:
/// the Ethernet header, 8 bytes of fixed fields, two addresses of hardware
/// and one of protocol).
const ARP_TARGET: usize = ETHERNET_HEADER + 24;
/// Where the sender protocol address of an ARP frame is.
const ARP_SENDER: usize = ETHERNET_HEADER + 14;
const ARP_REQUEST: u16 = 1;

/// Whether an IPv4 address is of the loopback network, 127.0.0.0/8 (RFC
/// 1122, 3.2.1.3).
pub const fn is_loopback(ip: [u8; 4]) -> bool {
    ip[0] == 127
}

/// A frame of IPv4 whose source or destination is in 127.0.0.0/8: such a
/// frame never belongs on the wire (RFC 1122, 3.2.1.3). Dropped when it
/// comes from the device, so that a node of the network cannot reach the
/// services bound to 127.0.0.1 with a frame to the service's MAC, and when
/// the stack would send it to the device.
pub fn martian(frame: &[u8]) -> bool {
    if frame.len() >= ARP_TARGET + 4 && frame[12..14] == ETHERTYPE_ARP {
        // ARP names its ends too: a sender or a target in 127.0.0.0/8 would
        // teach the neighbour cache a false MAC for the loopback.
        return frame[ARP_SENDER] == 127 || frame[ARP_TARGET] == 127;
    }
    ipv4_ends(frame).is_some_and(|(src, dst)| is_loopback(src) || is_loopback(dst))
}

/// What a buffer the device filled holds, for the receiving ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxFrame {
    /// A frame of this length after the header.
    Frame(usize),
    /// A frame that must not reach the stack from the wire (127.0.0.0/8).
    Martian,
    /// No frame: too short, too long, or merged buffers.
    Invalid,
}

/// What the buffer of `used` bytes holds. Every kind costs the step one unit of
/// its share of receiving, so that a flood of frames that are dropped cannot
/// hold a step.
pub fn classify(buffer: &[u8], used: usize) -> RxFrame {
    match rx_frame(buffer, used) {
        None => RxFrame::Invalid,
        Some(frame) if martian(frame) => RxFrame::Martian,
        Some(frame) => RxFrame::Frame(frame.len()),
    }
}

/// Whether an ARP frame names one of `own` as its sender: from the wire it is
/// a forgery, which would send the stack's frames to itself out on the wire.
pub fn arp_claims(frame: &[u8], own: &[[u8; 4]]) -> bool {
    frame.len() >= ARP_TARGET + 4
        && frame[12..14] == ETHERTYPE_ARP
        && own
            .iter()
            .any(|a| a[..] == frame[ARP_SENDER..ARP_SENDER + 4])
}

/// An ARP request (RFC 826) from `mac` at `sender` for the hardware address of
/// `target`, to the broadcast address: the 42 bytes of the frame. smoltcp
/// learns the sender of an ARP frame aimed at its own address, request or
/// reply, so the answer fills its neighbour cache.
pub fn arp_request(mac: [u8; 6], sender: [u8; 4], target: [u8; 4]) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[..6].copy_from_slice(&[0xFF; 6]);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&ETHERTYPE_ARP);
    f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&sender);
    f[38..42].copy_from_slice(&target);
    f
}

/// Where a frame the stack sends goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Wire,
    Loop,
}

/// A frame to the service's own MAC, or an ARP request for one of its own
/// addresses, stays in the loop; any other goes to the device.
pub fn route(frame: &[u8], mac: [u8; 6], own: &[[u8; 4]]) -> Route {
    if frame.len() < ETHERNET_HEADER {
        return Route::Wire;
    }
    if frame[..6] == mac {
        return Route::Loop;
    }
    if frame[12..14] == ETHERTYPE_ARP
        && let Some(target) = frame.get(ARP_TARGET..ARP_TARGET + 4)
        && u16::from_be_bytes([frame[20], frame[21]]) == ARP_REQUEST
        && own.iter().any(|a| a[..] == *target)
    {
        return Route::Loop;
    }
    Route::Wire
}

/// Whom a received frame is for, as far as the headers say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    /// The service's own sockets (DHCP, ICMP), or nobody: ICMP, DHCP, other
    /// protocols, fragments and frames that do not parse. The stack answers
    /// what needs an answer (RST, port unreachable) there.
    Service,
    /// ARP: the service's set answers, and every socket that waited for the
    /// neighbour tries again.
    Arp,
    /// A segment of TCP; `syn` when it opens a connection (SYN without ACK).
    Tcp {
        local: [u8; 4],
        local_port: u16,
        remote: [u8; 4],
        remote_port: u16,
        syn: bool,
    },
    /// A datagram of UDP to `local:local_port`.
    Udp {
        local: [u8; 4],
        local_port: u16,
        broadcast: bool,
    },
}

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

/// Whom the frame is for (see `Dest`).
pub fn target(frame: &[u8]) -> Dest {
    if frame.len() >= ETHERNET_HEADER && frame[12..14] == ETHERTYPE_ARP {
        return Dest::Arp;
    }
    let Some(p) = packet(frame) else {
        return Dest::Service;
    };
    if !p.first_fragment || frame[ETHERNET_HEADER + 6] & 0x20 != 0 {
        return Dest::Service;
    }
    let ip = &frame[ETHERNET_HEADER..];
    let part = &ip[p.header..p.end];
    let dst: [u8; 4] = ip[16..20].try_into().expect("4 bytes");
    let src: [u8; 4] = ip[12..16].try_into().expect("4 bytes");
    let port = |at: usize| u16::from_be_bytes([part[at], part[at + 1]]);
    match p.protocol {
        IPV4_PROTO_TCP if part.len() >= 20 => Dest::Tcp {
            local: dst,
            local_port: port(2),
            remote: src,
            remote_port: port(0),
            syn: part[13] & (TCP_SYN | TCP_ACK) == TCP_SYN,
        },
        IPV4_PROTO_UDP if part.len() >= 8 => {
            // The DHCP client of the service listens on port 68.
            if port(0) == 67 && port(2) == 68 {
                return Dest::Service;
            }
            Dest::Udp {
                local: dst,
                local_port: port(2),
                broadcast: dst == [255; 4] || frame[..6] == [0xff; 6],
            }
        }
        _ => Dest::Service,
    }
}

/// Whether the stack answers the frame in the step that takes it: a frame
/// no socket of the table owns (`routed` false) that the stack replies to
/// with an echo reply (ICMP echo request, RFC 792), a reset (TCP to a port
/// with no socket, RFC 9293, 3.5.1), a port unreachable (UDP, RFC 1122,
/// 4.1.3.1) or a protocol unreachable (RFC 792). The reply is a frame of the
/// wire made from the request (up to 590 bytes of it in an error, the
/// whole of an echo), summed and sent in the same step, so the step costs
/// that of two frames; such a frame takes the whole step of receiving (the
/// rule of `device::NetDevice`). ARP, DHCP and every other ICMP type get no
/// answer; a fragment or a frame that does not parse is dropped by the
/// stack with none.
pub fn answered(dest: Dest, routed: bool, frame: &[u8]) -> bool {
    if routed {
        return false;
    }
    match dest {
        Dest::Arp => false,
        Dest::Tcp { .. } | Dest::Udp { .. } => true,
        Dest::Service => service_answered(frame),
    }
}

/// `answered` for a frame the service's set takes.
fn service_answered(frame: &[u8]) -> bool {
    let Some(p) = packet(frame) else {
        return false;
    };
    if !p.first_fragment || frame[ETHERNET_HEADER + 6] & 0x20 != 0 {
        return false;
    }
    let part = &frame[ETHERNET_HEADER + p.header..ETHERNET_HEADER + p.end];
    match p.protocol {
        IPV4_PROTO_ICMP => part.first() == Some(&ICMP_ECHO_REQUEST),
        // The UDP of the service is the DHCP client's (port 67 to 68), or
        // too short to parse.
        IPV4_PROTO_UDP | IPV4_PROTO_TCP => false,
        _ => true,
    }
}

const ICMP_ECHO_REQUEST: u8 = 8;

#[cfg(test)]
mod tests {

    #[test]
    fn an_arp_request_is_a_broadcast_who_has() {
        let f = super::arp_request([2, 0, 0, 0, 0, 1], [10, 0, 2, 15], [10, 0, 2, 2]);
        let want: [u8; 42] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2, 0, 0, 0, 0, 1, 0x08, 0x06, 0, 1, 8, 0, 6, 4, 0,
            1, 2, 0, 0, 0, 0, 1, 10, 0, 2, 15, 0, 0, 0, 0, 0, 0, 10, 0, 2, 2,
        ];
        assert_eq!(f, want);
    }

    use super::*;

    fn ipv4_frame(src: [u8; 4], dst: [u8; 4], mac: [u8; 6]) -> Vec<u8> {
        let mut f = vec![0; 14 + 20 + 8];
        f[..6].copy_from_slice(&mac);
        f[12..14].copy_from_slice(&[8, 0]);
        f[14] = 0x45;
        f[26..30].copy_from_slice(&src);
        f[30..34].copy_from_slice(&dst);
        f
    }

    fn arp_request(target: [u8; 4]) -> Vec<u8> {
        let mut f = vec![0; 42];
        f[..6].fill(0xff);
        f[12..14].copy_from_slice(&[8, 6]);
        f[20..22].copy_from_slice(&1u16.to_be_bytes());
        f[38..42].copy_from_slice(&target);
        f
    }

    #[test]
    fn a_frame_with_the_loopback_network_is_a_martian() {
        let mac = [2, 0, 0, 0, 0, 1];
        assert!(martian(&ipv4_frame([10, 0, 2, 2], [127, 0, 0, 1], mac)));
        assert!(martian(&ipv4_frame([127, 5, 5, 5], [10, 0, 2, 15], mac)));
        assert!(!martian(&ipv4_frame([10, 0, 2, 2], [10, 0, 2, 15], mac)));
        assert!(
            martian(&arp_request([127, 0, 0, 1])),
            "ARP names its ends too"
        );
        assert!(!martian(&[0; 20]));
    }

    #[test]
    fn a_frame_to_the_own_mac_or_for_an_own_address_stays_in_the_loop() {
        let mac = [2, 0, 0, 0, 0, 1];
        let own = [[10, 0, 2, 15], [127, 0, 0, 1]];
        let to_self = ipv4_frame([10, 0, 2, 15], [10, 0, 2, 15], mac);
        assert_eq!(route(&to_self, mac, &own), Route::Loop);
        let out = ipv4_frame([10, 0, 2, 15], [10, 0, 2, 3], [0x52, 0x55, 0, 0, 0, 2]);
        assert_eq!(route(&out, mac, &own), Route::Wire);
        assert_eq!(route(&arp_request([127, 0, 0, 1]), mac, &own), Route::Loop);
        assert_eq!(route(&arp_request([10, 0, 2, 15]), mac, &own), Route::Loop);
        assert_eq!(route(&arp_request([10, 0, 2, 2]), mac, &own), Route::Wire);
        assert_eq!(route(&arp_request([10, 0, 2, 2]), mac, &[]), Route::Wire);
        assert_eq!(route(&[0; 5], mac, &own), Route::Wire);
    }

    fn udp_frame(payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut f = vec![0; 14 + 20 + udp_len];
        f[12..14].copy_from_slice(&[8, 0]);
        f[14] = 0x45;
        f[16..18].copy_from_slice(&((20 + udp_len) as u16).to_be_bytes());
        f[22] = 64;
        f[23] = IPV4_PROTO_UDP;
        f[26..30].copy_from_slice(&[10, 0, 2, 15]);
        f[30..34].copy_from_slice(&[10, 0, 2, 2]);
        f[34..36].copy_from_slice(&68u16.to_be_bytes());
        f[36..38].copy_from_slice(&67u16.to_be_bytes());
        f[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());
        f[42..].copy_from_slice(payload);
        f
    }

    fn tcp_frame(payload: &[u8]) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let mut f = vec![0; 14 + 20 + tcp_len];
        f[12..14].copy_from_slice(&[8, 0]);
        f[14] = 0x45;
        f[16..18].copy_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
        f[22] = 64;
        f[23] = IPV4_PROTO_TCP;
        f[26..30].copy_from_slice(&[127, 0, 0, 1]);
        f[30..34].copy_from_slice(&[127, 0, 0, 1]);
        f[34..36].copy_from_slice(&5000u16.to_be_bytes());
        f[36..38].copy_from_slice(&80u16.to_be_bytes());
        f[46] = 0x50;
        f[47] = 0x18;
        f[54..].copy_from_slice(payload);
        f
    }

    fn icmp_frame(kind: u8) -> Vec<u8> {
        let mut f = vec![0; 14 + 20 + 8];
        f[12..14].copy_from_slice(&[8, 0]);
        f[14] = 0x45;
        f[16..18].copy_from_slice(&28u16.to_be_bytes());
        f[22] = 64;
        f[23] = IPV4_PROTO_ICMP;
        f[26..30].copy_from_slice(&[10, 0, 2, 2]);
        f[30..34].copy_from_slice(&[10, 0, 2, 15]);
        f[34] = kind;
        f
    }

    /// The classes of frames that take the whole step: those the stack
    /// answers with a frame of its own (ECHO, RST, port and protocol
    /// unreachable), and none of the others.
    #[test]
    fn the_stack_answers_an_echo_request_a_reset_and_an_unreachable() {
        let echo = icmp_frame(8);
        assert_eq!(target(&echo), Dest::Service);
        assert!(answered(Dest::Service, false, &echo));
        // An echo reply, and an error addressed to us (port unreachable,
        // type 3), get no answer.
        assert!(!answered(Dest::Service, false, &icmp_frame(0)));
        assert!(!answered(Dest::Service, false, &icmp_frame(3)));
        // UDP and TCP with no socket (place None): port unreachable, RST.
        let udp = udp_frame(&[0; 1472]);
        let tcp = tcp_frame(&[]);
        let (udp_dest, tcp_dest) = (target(&udp), target(&tcp));
        assert!(matches!(udp_dest, Dest::Udp { .. }));
        assert!(matches!(tcp_dest, Dest::Tcp { .. }));
        assert!(answered(udp_dest, false, &udp));
        assert!(answered(tcp_dest, false, &tcp));
        // With a socket the group of the socket answers in its own set.
        assert!(!answered(udp_dest, true, &udp));
        assert!(!answered(tcp_dest, true, &tcp));
        // ARP; DHCP (UDP 67 to 68 goes to the service's set).
        let arp = arp_request([10, 0, 2, 15]);
        assert!(!answered(target(&arp), false, &arp));
        let dhcp = udp_frame(b"offer");
        let mut dhcp = dhcp;
        dhcp[34..36].copy_from_slice(&67u16.to_be_bytes());
        dhcp[36..38].copy_from_slice(&68u16.to_be_bytes());
        assert_eq!(target(&dhcp), Dest::Service);
        assert!(!answered(Dest::Service, false, &dhcp));
    }

    #[test]
    fn an_unknown_protocol_is_answered_and_a_fragment_or_a_runt_is_not() {
        let mut other = icmp_frame(8);
        other[23] = 89;
        assert_eq!(target(&other), Dest::Service);
        assert!(answered(Dest::Service, false, &other));
        // A fragment after the first and a first fragment with more behind
        // it: the stack builds no answer.
        let mut later = icmp_frame(8);
        later[20..22].copy_from_slice(&0x0008u16.to_be_bytes());
        assert!(!answered(Dest::Service, false, &later));
        let mut more = icmp_frame(8);
        more[20] = 0x20;
        assert!(!answered(Dest::Service, false, &more));
        assert!(!answered(Dest::Service, false, &[0; 10]));
        assert!(!answered(Dest::Service, false, &[]));
    }

    #[test]
    fn a_frame_finds_its_destination() {
        let mut t = tcp_frame(b"x");
        assert_eq!(
            target(&t),
            Dest::Tcp {
                local: [127, 0, 0, 1],
                local_port: 80,
                remote: [127, 0, 0, 1],
                remote_port: 5000,
                syn: false
            }
        );
        t[14 + 20 + 13] = TCP_SYN;
        assert!(matches!(target(&t), Dest::Tcp { syn: true, .. }));
        t[14 + 20 + 13] = TCP_SYN | TCP_ACK;
        assert!(
            matches!(target(&t), Dest::Tcp { syn: false, .. }),
            "a SYN-ACK"
        );
        let mut u = udp_frame(b"abc");
        u[34..36].copy_from_slice(&67u16.to_be_bytes());
        u[36..38].copy_from_slice(&68u16.to_be_bytes());
        assert_eq!(target(&u), Dest::Service, "DHCP server to client");
        let mut v = udp_frame(b"abc");
        v[14 + 20 + 2..14 + 20 + 4].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(
            target(&v),
            Dest::Udp {
                local: [10, 0, 2, 2],
                local_port: 7,
                broadcast: false
            }
        );
        assert_eq!(target(&arp_request([10, 0, 2, 2])), Dest::Arp);
        assert_eq!(target(&[0; 10]), Dest::Service);
        // An ICMP packet and a fragment go to the service.
        let mut icmp = udp_frame(b"abcdefgh");
        icmp[14 + 9] = IPV4_PROTO_ICMP;
        assert_eq!(target(&icmp), Dest::Service);
        let mut frag = tcp_frame(b"x");
        frag[14 + 6] = 0x20;
        assert_eq!(target(&frag), Dest::Service);
    }

    #[test]
    fn arp_with_a_loopback_end_or_a_forged_sender_does_not_come_from_the_wire() {
        let mut ask = arp_request([127, 0, 0, 1]);
        assert!(martian(&ask), "a target in 127.0.0.0/8");
        let mut reply = arp_request([10, 0, 2, 15]);
        assert!(!martian(&reply));
        reply[28..32].copy_from_slice(&[127, 0, 0, 1]);
        assert!(martian(&reply), "a sender in 127.0.0.0/8");
        ask[28..32].copy_from_slice(&[10, 0, 2, 2]);
        ask[38..42].copy_from_slice(&[10, 0, 2, 15]);
        assert!(!martian(&ask));
        // A sender that is our own address.
        ask[28..32].copy_from_slice(&[10, 0, 2, 15]);
        assert!(arp_claims(&ask, &[[10, 0, 2, 15], [127, 0, 0, 1]]));
        assert!(!arp_claims(&ask, &[[10, 0, 2, 16]]));
        assert!(!arp_claims(&[0; 5], &[[10, 0, 2, 15]]));
        assert!(!arp_claims(
            &ipv4_frame([10, 0, 2, 15], [10, 0, 2, 2], [0; 6]),
            &[[10, 0, 2, 15]]
        ));
    }

    #[test]
    fn a_buffer_is_a_frame_a_martian_or_nothing() {
        let mut buffer = vec![0; HDR_LEN];
        buffer[NUM_BUFFERS_AT] = 1;
        let good = ipv4_frame([10, 0, 2, 2], [10, 0, 2, 15], [2; 6]);
        let bad = ipv4_frame([10, 0, 2, 2], [127, 0, 0, 1], [2; 6]);
        let with = |frame: &[u8]| {
            let mut b = buffer.clone();
            b.extend_from_slice(frame);
            b
        };
        let b = with(&good);
        assert_eq!(classify(&b, b.len()), RxFrame::Frame(good.len()));
        let b = with(&bad);
        assert_eq!(classify(&b, b.len()), RxFrame::Martian);
        assert_eq!(classify(&buffer, HDR_LEN), RxFrame::Invalid);
        assert_eq!(classify(&buffer, 3), RxFrame::Invalid);
    }
}
