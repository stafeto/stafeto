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

/// The most bytes a write of `resolv.conf` has: the text and the empty lines
/// that cover what is left of an older, longer file.
pub const PAD_MAX: usize = 512;

/// `text` followed by empty lines to `size`, the length of the file now,
/// in `out`: the file service has no truncate here, and a text that is
/// shorter than the file must not leave the tail of the old one (a server
/// line among it). Gives the bytes to write and whether `size` was past
/// `PAD_MAX`, so that a tail remains.
pub fn pad(text: &[u8], size: usize, out: &mut [u8; PAD_MAX]) -> (usize, bool) {
    let total = text.len().max(size).min(PAD_MAX);
    out[..text.len()].copy_from_slice(text);
    out[text.len()..total].fill(b'\n');
    (total, size > PAD_MAX)
}

/// What follows a round of ARP requests of which `sent` went out: the
/// requests for the targets from `asked` on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Round {
    /// Every target was asked.
    Done,
    /// Some are left and the queue took one: the next step goes on at once.
    Continue,
    /// Some are left and the queue took none: a step after a short delay.
    Wait,
}

pub fn round(asked: usize, sent: usize, count: usize) -> (usize, Round) {
    let asked = asked + sent;
    if asked >= count {
        (0, Round::Done)
    } else if sent > 0 {
        (asked, Round::Continue)
    } else {
        (asked, Round::Wait)
    }
}

/// The text of `resolv.conf` as the service wrote it last. A renewal of the
/// lease with the same servers writes nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Written(Option<Text>);

impl Written {
    /// Whether `text` differs from what was written (nothing written yet
    /// counts as different).
    pub fn needs(&self, text: &Text) -> bool {
        self.0.as_ref() != Some(text)
    }

    /// `text` is in the file now.
    pub fn record(&mut self, text: Text) {
        self.0 = Some(text);
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
    fn a_shorter_text_is_padded_to_the_size_of_the_file() {
        let mut out = [0u8; PAD_MAX];
        let text = b"nameserver 10.0.2.3\n";
        // A file of another hand, longer than the text: no tail may stay.
        let (n, capped) = pad(text, 42, &mut out);
        assert_eq!((n, capped), (42, false));
        assert_eq!(&out[..20], text);
        assert!(out[20..42].iter().all(|&b| b == b'\n'));
        // A file as long or shorter: the text alone.
        assert_eq!(pad(text, 20, &mut out), (20, false));
        assert_eq!(pad(text, 0, &mut out), (20, false));
        // A file past the buffer: padded to it, and said so.
        assert_eq!(pad(text, 600, &mut out), (PAD_MAX, true));
    }

    #[test]
    fn the_requests_left_get_a_step_or_a_delay() {
        assert_eq!(round(0, 2, 2), (0, Round::Done));
        assert_eq!(round(0, 1, 2), (1, Round::Continue));
        assert_eq!(round(1, 0, 2), (1, Round::Wait));
        assert_eq!(round(1, 1, 2), (0, Round::Done));
    }

    #[test]
    fn a_renewal_with_the_same_servers_writes_nothing() {
        let a = Text::new(&[Some([10, 0, 2, 3]), None, None]);
        let b = Text::new(&[Some([10, 0, 2, 3]), None, None]);
        let c = Text::new(&[Some([10, 0, 2, 4]), None, None]);
        let mut written = Written::default();
        assert!(written.needs(&a));
        written.record(a);
        assert!(!written.needs(&b));
        assert!(written.needs(&c));
        written.record(c);
        assert!(written.needs(&a));
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
