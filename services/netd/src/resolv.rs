// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the service writes to `/etc/resolv.conf` and whom it asks for a
//! hardware address ahead of the first datagram: the text of the file from
//! the name servers of a lease, and the neighbours that carry a client's
//! first exchange (the gateway and the name servers on the link).

/// The name servers a lease can name (smoltcp's `MAX_DNS_SERVER_COUNT`) and
/// the resolver reads (`MAXNS`).
pub const SERVERS: usize = 3;

/// The longest text: three lines `nameserver 255.255.255.255\n`.
pub const TEXT_MAX: usize = 96;

/// The text of `resolv.conf`: a line `nameserver A.B.C.D` for each server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Text {
    bytes: [u8; TEXT_MAX],
    len: usize,
}

impl Text {
    /// The file for `servers`, in their order; empty when there are none.
    pub fn new(servers: &[Option<[u8; 4]>; SERVERS]) -> Text {
        let mut text = Text {
            bytes: [0; TEXT_MAX],
            len: 0,
        };
        for server in servers.iter().flatten() {
            text.push(b"nameserver ");
            for (k, octet) in server.iter().enumerate() {
                if k > 0 {
                    text.push(b".");
                }
                let digits = [octet / 100, octet / 10 % 10, octet % 10].map(|d| b'0' + d);
                let skip = match octet {
                    0..=9 => 2,
                    10..=99 => 1,
                    _ => 0,
                };
                text.push(&digits[skip..]);
            }
            text.push(b"\n");
        }
        text
    }

    fn push(&mut self, part: &[u8]) {
        self.bytes[self.len..self.len + part.len()].copy_from_slice(part);
        self.len += part.len();
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

fn on_link(address: [u8; 4], prefix: u8, other: [u8; 4]) -> bool {
    let mask = u32::MAX
        .checked_shl(32 - u32::from(prefix.min(32)))
        .unwrap_or(0);
    (u32::from_be_bytes(address) ^ u32::from_be_bytes(other)) & mask == 0
}

/// Whom to ask for a hardware address after a lease: the gateway, then each
/// name server on the link of `address`/`prefix` (a server beyond it is
/// reached through the gateway), each once.
pub fn neighbours(
    address: [u8; 4],
    prefix: u8,
    gateway: Option<[u8; 4]>,
    servers: &[Option<[u8; 4]>; SERVERS],
) -> ([[u8; 4]; SERVERS + 1], usize) {
    let mut out = [[0; 4]; SERVERS + 1];
    let mut n = 0;
    let candidates = gateway.into_iter().chain(
        servers
            .iter()
            .flatten()
            .copied()
            .filter(|&s| on_link(address, prefix, s)),
    );
    for ip in candidates {
        if ip != address && !out[..n].contains(&ip) {
            out[n] = ip;
            n += 1;
        }
    }
    (out, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_text_has_a_line_for_each_server() {
        assert!(Text::new(&[None; SERVERS]).is_empty());
        let one = Text::new(&[Some([10, 0, 2, 3]), None, None]);
        assert_eq!(one.as_bytes(), b"nameserver 10.0.2.3\n");
        let three = Text::new(&[
            Some([192, 168, 64, 1]),
            Some([8, 8, 4, 4]),
            Some([0, 100, 255, 7]),
        ]);
        assert_eq!(
            three.as_bytes(),
            b"nameserver 192.168.64.1\nnameserver 8.8.4.4\nnameserver 0.100.255.7\n"
        );
        assert!(three.as_bytes().len() <= TEXT_MAX);
    }

    #[test]
    fn the_same_servers_give_the_same_text() {
        let a = Text::new(&[Some([10, 0, 2, 3]), None, None]);
        let b = Text::new(&[Some([10, 0, 2, 3]), None, None]);
        let c = Text::new(&[Some([10, 0, 2, 4]), None, None]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn the_gateway_and_the_servers_on_the_link_are_asked_once() {
        let (out, n) = neighbours(
            [10, 0, 2, 15],
            24,
            Some([10, 0, 2, 2]),
            &[Some([10, 0, 2, 3]), Some([10, 0, 2, 2]), Some([8, 8, 8, 8])],
        );
        assert_eq!(&out[..n], &[[10, 0, 2, 2], [10, 0, 2, 3]]);
    }

    #[test]
    fn nobody_is_asked_without_a_gateway_or_a_server_on_the_link() {
        let (_, n) = neighbours([10, 0, 2, 15], 24, None, &[Some([8, 8, 8, 8]), None, None]);
        assert_eq!(n, 0);
        let (out, n) = neighbours([10, 0, 2, 15], 24, None, &[Some([10, 0, 2, 3]), None, None]);
        assert_eq!(&out[..n], &[[10, 0, 2, 3]]);
    }
}
