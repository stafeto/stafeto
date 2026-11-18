// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Ethernet frames of ARP and TCP, built and read on the host, and the stream
//! format of the chardev backends of QEMU's network filters (a 4-byte big
//! endian length, then the frame). The user-mode forwarding of the emulator
//! finishes every TCP handshake, so a probe that needs a bare SYN, an RST in
//! SYN-RECEIVED or a SYN on a stale four-tuple builds the frames itself and
//! injects them below the forwarding (`filter-redirector`), and reads what
//! the guest sent (`filter-mirror`).

pub type Mac = [u8; 6];
pub type Ip = [u8; 4];

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const ACK: u8 = 0x10;

const ETH_ARP: u16 = 0x0806;
const ETH_IPV4: u16 = 0x0800;

/// The Internet checksum (RFC 1071) of `data`, with `seed` (a sum already
/// taken, for the pseudo header) added in.
pub fn checksum(data: &[u8], seed: u32) -> u16 {
    let mut sum = seed;
    let (pairs, rest) = data.as_chunks::<2>();
    for p in pairs {
        sum += u32::from(u16::from_be_bytes(*p));
    }
    if let [last] = rest {
        sum += u32::from(*last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One TCP segment without payload, with its Ethernet and IPv4 headers. A SYN
/// carries the option MSS 1460.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub src_mac: Mac,
    pub dst_mac: Mac,
    pub src_ip: Ip,
    pub dst_ip: Ip,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
}

impl Segment {
    /// The frame, the checksums of IPv4 and TCP filled in.
    pub fn frame(&self) -> Vec<u8> {
        let options: &[u8] = if self.flags & SYN != 0 {
            &[2, 4, 0x05, 0xb4]
        } else {
            &[]
        };
        let tcp_len = 20 + options.len();
        let mut f = Vec::with_capacity(14 + 20 + tcp_len);
        f.extend_from_slice(&self.dst_mac);
        f.extend_from_slice(&self.src_mac);
        f.extend_from_slice(&ETH_IPV4.to_be_bytes());
        // IPv4: version 4, header 5 words, no DSCP, length, id 0, DF, TTL 64.
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
        f.extend_from_slice(&self.src_ip);
        f.extend_from_slice(&self.dst_ip);
        let ip_sum = checksum(&f[14..34], 0);
        f[24..26].copy_from_slice(&ip_sum.to_be_bytes());
        let tcp = f.len();
        f.extend_from_slice(&self.src_port.to_be_bytes());
        f.extend_from_slice(&self.dst_port.to_be_bytes());
        f.extend_from_slice(&self.seq.to_be_bytes());
        f.extend_from_slice(&self.ack.to_be_bytes());
        f.push(((tcp_len / 4) as u8) << 4);
        f.push(self.flags);
        f.extend_from_slice(&64240u16.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0]);
        f.extend_from_slice(options);
        let mut seed = 6 + tcp_len as u32;
        for pair in self.src_ip.chunks(2).chain(self.dst_ip.chunks(2)) {
            seed += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        let sum = checksum(&f[tcp..], seed);
        f[tcp + 16..tcp + 18].copy_from_slice(&sum.to_be_bytes());
        f
    }
}

fn arp(op: u16, eth_dst: Mac, sha: Mac, spa: Ip, tha: Mac, tpa: Ip) -> Vec<u8> {
    let mut f = Vec::with_capacity(42);
    f.extend_from_slice(&eth_dst);
    f.extend_from_slice(&sha);
    f.extend_from_slice(&ETH_ARP.to_be_bytes());
    f.extend_from_slice(&[0, 1, 8, 0, 6, 4]);
    f.extend_from_slice(&op.to_be_bytes());
    f.extend_from_slice(&sha);
    f.extend_from_slice(&spa);
    f.extend_from_slice(&tha);
    f.extend_from_slice(&tpa);
    f
}

/// Who has `target_ip`? Broadcast, from `mac` and `ip`.
pub fn arp_request(mac: Mac, ip: Ip, target_ip: Ip) -> Vec<u8> {
    arp(1, [0xff; 6], mac, ip, [0; 6], target_ip)
}

/// `ip` is at `mac`, said to `to_mac` and `to_ip`.
pub fn arp_reply(mac: Mac, ip: Ip, to_mac: Mac, to_ip: Ip) -> Vec<u8> {
    arp(2, to_mac, mac, ip, to_mac, to_ip)
}

/// What a frame is, as far as a probe cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    ArpRequest {
        sender_mac: Mac,
        sender_ip: Ip,
        target_ip: Ip,
    },
    ArpReply {
        sender_mac: Mac,
        sender_ip: Ip,
    },
    Tcp {
        src_ip: Ip,
        dst_ip: Ip,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
    },
    Other,
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Reads `frame`; anything short or of another kind is `Other`.
pub fn parse(frame: &[u8]) -> Frame {
    if frame.len() < 14 {
        return Frame::Other;
    }
    let body = &frame[14..];
    match be16(&frame[12..14]) {
        ETH_ARP if body.len() >= 28 && be16(&body[6..8]) <= 2 => {
            let sender_mac = body[8..14].try_into().unwrap();
            let sender_ip = body[14..18].try_into().unwrap();
            if be16(&body[6..8]) == 1 {
                Frame::ArpRequest {
                    sender_mac,
                    sender_ip,
                    target_ip: body[24..28].try_into().unwrap(),
                }
            } else {
                Frame::ArpReply {
                    sender_mac,
                    sender_ip,
                }
            }
        }
        ETH_IPV4 if body.len() >= 20 && body[0] >> 4 == 4 && body[9] == 6 => {
            let ihl = usize::from(body[0] & 15) * 4;
            let tcp = body.get(ihl..).filter(|t| t.len() >= 20);
            let Some(tcp) = tcp else {
                return Frame::Other;
            };
            Frame::Tcp {
                src_ip: body[12..16].try_into().unwrap(),
                dst_ip: body[16..20].try_into().unwrap(),
                src_port: be16(&tcp[0..2]),
                dst_port: be16(&tcp[2..4]),
                seq: be32(&tcp[4..8]),
                ack: be32(&tcp[8..12]),
                flags: tcp[13],
            }
        }
        _ => Frame::Other,
    }
}

/// `frame` as the chardev of a QEMU network filter carries it: its length in
/// four bytes, big endian, then the frame.
pub fn framed(frame: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + frame.len());
    v.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    v.extend_from_slice(frame);
    v
}

/// The reading side of that stream: bytes in as they come, whole frames out.
#[derive(Default)]
pub struct Unframer {
    held: Vec<u8>,
}

impl Unframer {
    pub fn push(&mut self, bytes: &[u8]) {
        self.held.extend_from_slice(bytes);
    }

    /// The next whole frame, if the bytes so far hold one. A length past
    /// 64 KiB cannot be a frame: the stream is cut there, and the bytes held
    /// are dropped.
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        if self.held.len() < 4 {
            return None;
        }
        let len = be32(&self.held) as usize;
        if len > 65536 {
            self.held.clear();
            return None;
        }
        if self.held.len() < 4 + len {
            return None;
        }
        let rest = self.held.split_off(4 + len);
        let mut frame = std::mem::replace(&mut self.held, rest);
        frame.drain(..4);
        Some(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Mac = [2, 0, 0, 0, 0, 1];
    const B: Mac = [2, 0, 0, 0, 0, 2];

    fn seg(flags: u8) -> Segment {
        Segment {
            src_mac: A,
            dst_mac: B,
            src_ip: [10, 0, 2, 77],
            dst_ip: [10, 0, 2, 15],
            src_port: 40000,
            dst_port: 443,
            seq: 0xfffffff0,
            ack: 7,
            flags,
        }
    }

    #[test]
    fn the_checksum_is_the_one_of_rfc_1071() {
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data, 0), !0xddf2);
        // An odd length pads with a zero byte.
        assert_eq!(checksum(&[0x12, 0x34, 0x56], 0), !(0x1234 + 0x5600));
    }

    #[test]
    fn a_built_frame_checks_out_and_reads_back() {
        for flags in [SYN, RST, ACK, RST | ACK] {
            let f = seg(flags).frame();
            // The sum over the IPv4 header, checksum included, is all ones.
            assert_eq!(checksum(&f[14..34], 0), 0);
            // So is the sum over the pseudo header and the segment.
            let tcp = &f[34..];
            let mut seed = 6 + tcp.len() as u32;
            for pair in f[26..34].chunks(2) {
                seed += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
            }
            assert_eq!(checksum(tcp, seed), 0);
            assert_eq!(f.len(), 14 + 20 + if flags == SYN { 24 } else { 20 });
            assert_eq!(
                parse(&f),
                Frame::Tcp {
                    src_ip: [10, 0, 2, 77],
                    dst_ip: [10, 0, 2, 15],
                    src_port: 40000,
                    dst_port: 443,
                    seq: 0xfffffff0,
                    ack: 7,
                    flags,
                }
            );
        }
    }

    #[test]
    fn arp_frames_read_back() {
        let r = arp_request(A, [10, 0, 2, 77], [10, 0, 2, 15]);
        assert_eq!(r.len(), 42);
        assert_eq!(
            parse(&r),
            Frame::ArpRequest {
                sender_mac: A,
                sender_ip: [10, 0, 2, 77],
                target_ip: [10, 0, 2, 15]
            }
        );
        let a = arp_reply(A, [10, 0, 2, 77], B, [10, 0, 2, 15]);
        assert_eq!(
            parse(&a),
            Frame::ArpReply {
                sender_mac: A,
                sender_ip: [10, 0, 2, 77]
            }
        );
        assert_eq!(parse(&a[..10]), Frame::Other);
    }

    #[test]
    fn the_stream_gives_whole_frames_however_the_bytes_come() {
        let one = seg(SYN).frame();
        let two = seg(RST).frame();
        let mut stream = framed(&one);
        stream.extend(framed(&two));
        for cut in [1, 3, 4, 5, 60, stream.len() - 1] {
            let mut u = Unframer::default();
            u.push(&stream[..cut]);
            let mut got = Vec::new();
            while let Some(f) = u.pop() {
                got.push(f);
            }
            u.push(&stream[cut..]);
            while let Some(f) = u.pop() {
                got.push(f);
            }
            assert_eq!(got, vec![one.clone(), two.clone()], "cut at {cut}");
        }
        let mut u = Unframer::default();
        u.push(&[0xff, 0xff, 0xff, 0xff, 1]);
        assert_eq!(u.pop(), None);
        assert_eq!(u.pop(), None);
    }
}
