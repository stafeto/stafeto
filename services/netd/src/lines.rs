// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The text the service prints and the one fact it reads from a frame it
//! sends: whether it is a DHCP client message (the counter of the probe).

use core::fmt;

pub use proto_net::text::{Ip, Mac};

/// What a lease or a static address says, as one line follows its word:
/// `10.0.2.15/24 gw 10.0.2.2 dns 10.0.2.3`; an absent field is `none`.
pub struct Summary {
    pub address: [u8; 4],
    pub prefix: u8,
    pub gateway: Option<[u8; 4]>,
    pub dns: Option<[u8; 4]>,
}

struct Field(Option<[u8; 4]>);

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(ip) => Ip(ip).fmt(f),
            None => f.write_str("none"),
        }
    }
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{} gw {} dns {}",
            Ip(self.address),
            self.prefix,
            Field(self.gateway),
            Field(self.dns)
        )
    }
}

const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ETHERNET_HEADER: usize = 14;
const UDP: u8 = 17;
const DHCP_SERVER_PORT: u16 = 67;

/// Whether `frame` is an Ethernet frame that carries an IPv4 datagram of
/// UDP to port 67, the DHCP server's (RFC 2131, 4.1): a client message.
/// The header length and the fragment offset of IPv4 are honoured.
pub fn is_dhcp_client_frame(frame: &[u8]) -> bool {
    if frame.len() < ETHERNET_HEADER + 20 || frame[12..14] != ETHERTYPE_IPV4 {
        return false;
    }
    let ip = &frame[ETHERNET_HEADER..];
    let header = usize::from(ip[0] & 0x0f) * 4;
    let fragment = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff;
    if ip[0] >> 4 != 4 || header < 20 || ip[9] != UDP || fragment != 0 {
        return false;
    }
    match ip.get(header + 2..header + 4) {
        Some(port) => u16::from_be_bytes([port[0], port[1]]) == DHCP_SERVER_PORT,
        None => false,
    }
}

const DHCP_CLIENT_PORT: u16 = 68;

/// Whether `frame` is an Ethernet frame that carries an IPv4 datagram of
/// UDP from port 67 to port 68 (RFC 2131, 4.1): a server's message to a
/// client. The header length and the fragment offset of IPv4 are honoured.
pub fn is_dhcp_server_frame(frame: &[u8]) -> bool {
    if frame.len() < ETHERNET_HEADER + 20 || frame[12..14] != ETHERTYPE_IPV4 {
        return false;
    }
    let ip = &frame[ETHERNET_HEADER..];
    let header = usize::from(ip[0] & 0x0f) * 4;
    let fragment = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff;
    if ip[0] >> 4 != 4 || header < 20 || ip[9] != UDP || fragment != 0 {
        return false;
    }
    match ip.get(header..header + 4) {
        Some(ports) => {
            u16::from_be_bytes([ports[0], ports[1]]) == DHCP_SERVER_PORT
                && u16::from_be_bytes([ports[2], ports[3]]) == DHCP_CLIENT_PORT
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_frame(ihl_words: u8, proto: u8, fragment: u16, dst_port: u16) -> Vec<u8> {
        let header = usize::from(ihl_words) * 4;
        let mut f = vec![0; ETHERNET_HEADER + header + 8];
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4);
        f[14] = 0x40 | ihl_words;
        f[14 + 6..14 + 8].copy_from_slice(&fragment.to_be_bytes());
        f[14 + 9] = proto;
        f[14 + header + 2..14 + header + 4].copy_from_slice(&dst_port.to_be_bytes());
        f
    }

    #[test]
    fn a_summary_prints_its_fields() {
        let s = Summary {
            address: [10, 0, 2, 15],
            prefix: 24,
            gateway: Some([10, 0, 2, 2]),
            dns: Some([10, 0, 2, 3]),
        };
        assert_eq!(s.to_string(), "10.0.2.15/24 gw 10.0.2.2 dns 10.0.2.3");
        let bare = Summary {
            gateway: None,
            dns: None,
            ..s
        };
        assert_eq!(bare.to_string(), "10.0.2.15/24 gw none dns none");
    }

    #[test]
    fn a_mac_prints_in_hex_pairs() {
        assert_eq!(
            Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]).to_string(),
            "52:54:00:12:34:56"
        );
    }

    #[test]
    fn a_dhcp_client_frame_is_found() {
        assert!(is_dhcp_client_frame(&udp_frame(5, UDP, 0, 67)));
        // IPv4 options move the UDP header.
        assert!(is_dhcp_client_frame(&udp_frame(7, UDP, 0, 67)));
    }

    #[test]
    fn a_dhcp_server_frame_is_from_67_to_68() {
        let mut offer = udp_frame(5, UDP, 0, 68);
        offer[14 + 20..14 + 22].copy_from_slice(&67u16.to_be_bytes());
        assert!(is_dhcp_server_frame(&offer));
        // Options move the UDP header.
        let mut long = udp_frame(7, UDP, 0, 68);
        long[14 + 28..14 + 30].copy_from_slice(&67u16.to_be_bytes());
        assert!(is_dhcp_server_frame(&long));
        // A client message, a datagram from another port, TCP, a later
        // fragment, ARP, and a cut frame are not.
        assert!(!is_dhcp_server_frame(&udp_frame(5, UDP, 0, 67)));
        assert!(!is_dhcp_server_frame(&udp_frame(5, UDP, 0, 68)));
        let mut tcp = offer.clone();
        tcp[14 + 9] = 6;
        assert!(!is_dhcp_server_frame(&tcp));
        let mut later = offer.clone();
        later[14 + 6..14 + 8].copy_from_slice(&8u16.to_be_bytes());
        assert!(!is_dhcp_server_frame(&later));
        let mut arp = offer.clone();
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert!(!is_dhcp_server_frame(&arp));
        assert!(!is_dhcp_server_frame(&offer[..14 + 20 + 3]));
        assert!(!is_dhcp_server_frame(&[]));
    }

    #[test]
    fn other_frames_are_not() {
        assert!(
            !is_dhcp_client_frame(&udp_frame(5, UDP, 0, 68)),
            "a server reply"
        );
        assert!(!is_dhcp_client_frame(&udp_frame(5, 6, 0, 67)), "TCP");
        assert!(
            !is_dhcp_client_frame(&udp_frame(5, UDP, 8, 67)),
            "a later fragment"
        );
        assert!(
            !is_dhcp_client_frame(&udp_frame(4, UDP, 0, 67)),
            "a header too short"
        );
        let mut arp = udp_frame(5, UDP, 0, 67);
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert!(!is_dhcp_client_frame(&arp));
        assert!(!is_dhcp_client_frame(&[]));
        let cut = udp_frame(5, UDP, 0, 67);
        assert!(!is_dhcp_client_frame(&cut[..14 + 20 + 3]));
    }
}
