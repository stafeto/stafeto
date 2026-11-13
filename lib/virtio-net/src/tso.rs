// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The segmentation offload on sending (`VIRTIO_NET_F_HOST_TSO4`, Virtio 1.2, 5.1.6.2): a frame
//! of TCP in IPv4 longer than a segment goes to the device whole, in a chain of descriptors, behind
//! a header of virtio that says `GSO_TCPV4`, the length of the headers and the size of a segment,
//! and the device cuts it into segments of that size. Every cut segment gets the headers of the
//! frame with its own length, `ip_id`, `seq` and sums; FIN and PSH stay on the last segment only.
//!
//! This file reads the headers of a frame of a consumer (the copy the switch took of the first
//! bytes, `parse`), puts in it the sum of the pseudo-header (`put_pseudo`) and builds the header
//! of virtio (`header`). The device is the one that completes the sums: the field of the TCP sum
//! holds the pseudo-header's, as for `NEEDS_CSUM` on a single frame (N5).

use crate::frames::{
    ETHERNET_HEADER, ETHERTYPE_IPV4, HDR_LEN, IPV4_PROTO_TCP, NEEDS_CSUM, TCP_SUM_AT, add, fold,
};

/// `gso_type` of a frame of TCP in IPv4 (Virtio 1.2, 5.1.6.2).
pub const GSO_TCPV4: u8 = 1;

/// The pseudo-header sum of a frame of the segmentation offload (N5, `offload-pr0.md` 3): without
/// the length of the segment, the way FreeBSD and the drivers of DPDK write it for a frame of
/// TSO, so the device adds the length of each segment it cuts. `true` puts the length of the whole
/// frame's TCP part in it, as a single frame has it.
pub const PSEUDO_WITH_LENGTH: bool = true;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_CWR: u8 = 0x80;

/// The headers of a frame of the segmentation offload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// The length of the IPv4 header, of the TCP header, and of both with Ethernet's.
    pub ip: usize,
    pub tcp: usize,
    pub headers: usize,
    /// The bytes of TCP data in the frame.
    pub data: usize,
}

/// Why a frame is no frame of the segmentation offload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The copy of the headers is shorter than the headers say, or the headers are longer than
    /// the copy the switch keeps.
    Headers,
    /// No IPv4 header, a fragment, or a total length that is not the frame's.
    Ipv4,
    /// No TCP.
    Protocol,
    /// The data is no more than one segment (nothing to cut), or more than the offload takes.
    Data,
    /// The size of a segment is outside 216 (`TSO_MSS_MIN`) to what the MTU of 1 500 leaves after the headers.
    Mss,
    /// SYN, RST or CWR: a device without `HOST_ECN` does not cut a frame with CWR, and a SYN or
    /// an RST has no data to cut.
    Flags,
}

/// The headers of the frame of `len` bytes whose first bytes are `head` (at most `TSO_HEAD_MAX`
/// of them, or all of a shorter frame), for segments of `mss`.
pub fn parse(head: &[u8], len: usize, mss: u16) -> Result<Head, Refusal> {
    if head.len() < ETHERNET_HEADER + 20 + 20 || len < head.len() {
        return Err(Refusal::Headers);
    }
    let ip = &head[ETHERNET_HEADER..];
    if head[12..14] != ETHERTYPE_IPV4 || ip[0] >> 4 != 4 {
        return Err(Refusal::Ipv4);
    }
    let ip_len = usize::from(ip[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let fragment = u16::from_be_bytes([ip[6], ip[7]]);
    if ip_len < 20 || fragment & 0x3fff != 0 || total != len - ETHERNET_HEADER {
        return Err(Refusal::Ipv4);
    }
    if ip[9] != IPV4_PROTO_TCP {
        return Err(Refusal::Protocol);
    }
    let tcp_at = ETHERNET_HEADER + ip_len;
    if tcp_at + 20 > head.len() {
        return Err(Refusal::Headers);
    }
    let tcp_len = usize::from(head[tcp_at + 12] >> 4) * 4;
    let headers = tcp_at + tcp_len;
    if tcp_len < 20 || headers > head.len() || total < ip_len + tcp_len {
        return Err(Refusal::Headers);
    }
    let data = len - headers;
    if data <= usize::from(mss) || data > proto_net::switch::TSO_BODY_MAX {
        return Err(Refusal::Data);
    }
    if mss < proto_net::switch::TSO_MSS_MIN || usize::from(mss) + ip_len + tcp_len > 1500 {
        return Err(Refusal::Mss);
    }
    if head[tcp_at + 13] & (TCP_SYN | TCP_RST | TCP_CWR) != 0 {
        return Err(Refusal::Flags);
    }
    Ok(Head {
        ip: ip_len,
        tcp: tcp_len,
        headers,
        data,
    })
}

/// The flags FIN and PSH of the frame: the device keeps them on the last segment only.
pub fn last_only(head: &[u8], h: &Head) -> u8 {
    head[ETHERNET_HEADER + h.ip + 13] & (TCP_FIN | 0x08)
}

/// Writes the sum of the pseudo-header, folded and not complemented, in the field of the TCP sum
/// of `head` (see `PSEUDO_WITH_LENGTH` for the length in it).
pub fn put_pseudo(head: &mut [u8], h: &Head) {
    let ip = ETHERNET_HEADER;
    let mut pseudo = [0u8; 12];
    pseudo[..4].copy_from_slice(&head[ip + 12..ip + 16]);
    pseudo[4..8].copy_from_slice(&head[ip + 16..ip + 20]);
    pseudo[9] = IPV4_PROTO_TCP;
    if PSEUDO_WITH_LENGTH {
        pseudo[10..12].copy_from_slice(&((h.tcp + h.data) as u16).to_be_bytes());
    }
    let at = ip + h.ip + TCP_SUM_AT;
    head[at..at + 2].copy_from_slice(&fold(add(0, &pseudo)).to_be_bytes());
}

/// The header of virtio of the frame: the device completes the sum of each segment from
/// `csum_start` (the TCP header) and cuts the frame behind `hdr_len` bytes of headers into data of
/// `mss` (Virtio 1.2, 5.1.6.2.1: `num_buffers` 0, `hdr_len` not less than the headers).
pub fn header(h: &Head, mss: u16) -> [u8; HDR_LEN] {
    let mut out = [0u8; HDR_LEN];
    out[0] = NEEDS_CSUM;
    out[1] = GSO_TCPV4;
    out[2..4].copy_from_slice(&(h.headers as u16).to_le_bytes());
    out[4..6].copy_from_slice(&mss.to_le_bytes());
    out[6..8].copy_from_slice(&((ETHERNET_HEADER + h.ip) as u16).to_le_bytes());
    out[8..10].copy_from_slice(&(TCP_SUM_AT as u16).to_le_bytes());
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cut::Plan;
    use crate::frames::{checksum, fill_sums, verify_sums};

    /// A frame of the segmentation offload as a stack builds it: Ethernet, IPv4 (`ip_options`
    /// bytes of options), TCP (`tcp_options`), `data` bytes, the IPv4 header's sum whole and the
    /// TCP sum field junk (the switch overwrites it).
    pub fn frame(ip_options: usize, tcp_options: usize, data: usize, flags: u8) -> Vec<u8> {
        let ip = 20 + ip_options;
        let tcp = 20 + tcp_options;
        let mut f = vec![0u8; ETHERNET_HEADER + ip + tcp + data];
        f[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        f[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4);
        let i = ETHERNET_HEADER;
        f[i] = 0x40 | (ip / 4) as u8;
        let total = (f.len() - i) as u16;
        f[i + 2..i + 4].copy_from_slice(&total.to_be_bytes());
        f[i + 4..i + 6].copy_from_slice(&0x1000u16.to_be_bytes());
        f[i + 6] = 0x40;
        f[i + 8] = 64;
        f[i + 9] = IPV4_PROTO_TCP;
        f[i + 12..i + 16].copy_from_slice(&[10, 0, 0, 1]);
        f[i + 16..i + 20].copy_from_slice(&[10, 0, 0, 2]);
        let t = i + ip;
        f[t..t + 2].copy_from_slice(&80u16.to_be_bytes());
        f[t + 2..t + 4].copy_from_slice(&5000u16.to_be_bytes());
        f[t + 4..t + 8].copy_from_slice(&0xffff_fff0u32.to_be_bytes());
        f[t + 12] = ((tcp / 4) as u8) << 4;
        f[t + 13] = flags;
        f[t + 14..t + 16].copy_from_slice(&4096u16.to_be_bytes());
        for (k, b) in f[t + tcp..].iter_mut().enumerate() {
            *b = (k * 7 + k / 251) as u8;
        }
        let sum = checksum(&f[i..i + ip]);
        f[i + 10..i + 12].copy_from_slice(&sum.to_be_bytes());
        f[t + 16..t + 18].copy_from_slice(&[0x12, 0x34]);
        f
    }

    /// What a device does with a frame of the offload: cuts it into segments of `mss` and
    /// completes the TCP sum of each from the field's seed (the model of `Plan::build` plus the
    /// sum the header of virtio asks for).
    pub fn device(frame: &[u8], virtio: &[u8; HDR_LEN]) -> Vec<Vec<u8>> {
        let hdr_len = usize::from(u16::from_le_bytes([virtio[2], virtio[3]]));
        let mss = usize::from(u16::from_le_bytes([virtio[4], virtio[5]]));
        let start = usize::from(u16::from_le_bytes([virtio[6], virtio[7]]));
        assert_eq!((virtio[0], virtio[1]), (NEEDS_CSUM, GSO_TCPV4));
        let plan = Plan {
            headers: hdr_len,
            data: frame.len() - hdr_len,
            mss,
        };
        let two = crate::cut::Frame2 {
            head: frame,
            tail: &[],
        };
        let seed = u64::from(u16::from_be_bytes([
            frame[start + TCP_SUM_AT],
            frame[start + TCP_SUM_AT + 1],
        ]));
        (0..plan.segments())
            .map(|k| {
                let mut out = vec![0u8; hdr_len + mss];
                let n = plan.build(&two, k, &mut out).expect("a segment");
                out.truncate(n);
                // The pseudo-header of this segment, if the field has none of its length.
                let part = (n - start) as u16;
                let extra = if PSEUDO_WITH_LENGTH {
                    // The field holds the whole frame's length: take it out, put this one in.
                    let whole = (frame.len() - start) as u16;
                    add(0, &(!whole).to_be_bytes()) + add(0, &part.to_be_bytes())
                } else {
                    add(0, &part.to_be_bytes())
                };
                out[start + TCP_SUM_AT] = 0;
                out[start + TCP_SUM_AT + 1] = 0;
                let sum = !fold(add(seed + extra, &out[start..]));
                out[start + TCP_SUM_AT..start + TCP_SUM_AT + 2].copy_from_slice(&sum.to_be_bytes());
                out
            })
            .collect()
    }

    #[test]
    fn a_frame_of_two_hundred_bytes_over_the_mss_parses() {
        let f = frame(0, 12, 10_240, 0x10);
        let head = &f[..128];
        let h = parse(head, f.len(), 1448).expect("a frame of the offload");
        assert_eq!((h.ip, h.tcp, h.headers, h.data), (20, 32, 66, 10_240));
        // A shorter frame comes whole.
        let small = frame(0, 0, 2000, 0x10);
        assert_eq!(parse(&small, small.len(), 1448).map(|h| h.data), Ok(2000));
    }

    #[test]
    fn each_rule_of_the_headers_refuses_the_frame() {
        let good = frame(0, 0, 4000, 0x10);
        let n = good.len();
        let ok = |f: &[u8], len: usize, mss: u16| parse(&f[..f.len().min(128)], len, mss);
        assert!(ok(&good, n, 1448).is_ok());
        // The copy is shorter than the headers, or no frame is as long as the copy.
        assert_eq!(parse(&good[..50], n, 1448), Err(Refusal::Headers));
        assert_eq!(parse(&good[..100], 90, 1448), Err(Refusal::Headers));
        // Not IPv4.
        let mut f = good.clone();
        f[12..14].copy_from_slice(&[0x08, 0x06]);
        assert_eq!(ok(&f, n, 1448), Err(Refusal::Ipv4));
        let mut f = good.clone();
        f[14] = 0x65;
        assert_eq!(ok(&f, n, 1448), Err(Refusal::Ipv4));
        // A fragment, and a total length that is not the frame's.
        for (at, value) in [(20, 0x20u8), (21, 1)] {
            let mut f = good.clone();
            f[at] = value;
            assert_eq!(ok(&f, n, 1448), Err(Refusal::Ipv4), "{at}");
        }
        assert_eq!(ok(&good, n + 1, 1448), Err(Refusal::Ipv4));
        assert_eq!(ok(&good, n - 1, 1448), Err(Refusal::Ipv4));
        // UDP.
        let mut f = good.clone();
        f[23] = 17;
        assert_eq!(ok(&f, n, 1448), Err(Refusal::Protocol));
        // Headers that run past the copy the switch keeps (128 bytes), or a TCP header of fewer
        // than 20 bytes.
        let long = frame(40, 40, 4000, 0x10);
        assert_eq!(ok(&long, long.len(), 1448), Err(Refusal::Headers));
        let big = frame(0, 40, 4000, 0x10);
        assert!(ok(&big, big.len(), 1420).is_ok());
        let tiny = {
            let mut t = frame(0, 0, 0, 0x10);
            t[46] = 0x30;
            t
        };
        assert_eq!(parse(&tiny, tiny.len(), 536), Err(Refusal::Headers));
        // Data of one segment or less, or more than the offload takes.
        assert_eq!(ok(&good, n, 4000), Err(Refusal::Data));
        let few = frame(0, 0, 1448, 0x10);
        assert_eq!(ok(&few, few.len(), 1448), Err(Refusal::Data));
        let many = frame(0, 0, 16_385, 0x10);
        assert_eq!(ok(&many, many.len(), 1448), Err(Refusal::Data));
        let most = frame(0, 0, 16_384, 0x10);
        assert!(ok(&most, most.len(), 1448).is_ok());
        // The size of a segment: below 216, above what 1 500 leaves.
        assert_eq!(ok(&good, n, 215), Err(Refusal::Mss));
        assert!(ok(&good, n, 216).is_ok());
        // A peer with an MSS of 536 and timestamps: FreeBSD cuts at 524 (the old floor refused it).
        assert!(ok(&good, n, 524).is_ok());
        assert!(ok(&good, n, 1460).is_ok());
        assert_eq!(ok(&good, n, 1461), Err(Refusal::Mss));
        assert_eq!(ok(&big, big.len(), 1421), Err(Refusal::Mss));
        // SYN, RST, CWR.
        for flags in [0x02, 0x04, 0x80, 0x12] {
            let f = frame(0, 0, 4000, flags);
            assert_eq!(ok(&f, f.len(), 1448), Err(Refusal::Flags), "{flags:#x}");
        }
        for flags in [0x01, 0x08, 0x18, 0x19, 0x40] {
            let f = frame(0, 0, 4000, flags);
            assert!(ok(&f, f.len(), 1448).is_ok(), "{flags:#x}");
        }
    }

    #[test]
    fn the_header_of_virtio_names_the_headers_and_the_place_of_the_sum() {
        let f = frame(0, 12, 8000, 0x10);
        let h = parse(&f[..128], f.len(), 1448).unwrap();
        let v = header(&h, 1448);
        assert_eq!(v[0], NEEDS_CSUM);
        assert_eq!(v[1], GSO_TCPV4);
        assert_eq!(u16::from_le_bytes([v[2], v[3]]), 66);
        assert_eq!(u16::from_le_bytes([v[4], v[5]]), 1448);
        assert_eq!(u16::from_le_bytes([v[6], v[7]]), 34);
        assert_eq!(u16::from_le_bytes([v[8], v[9]]), 16);
        assert_eq!(&v[10..], &[0, 0], "num_buffers is 0 on sending");
    }

    #[test]
    fn the_pseudo_header_makes_every_segment_of_the_device_sum_whole() {
        for (tcp_options, data, mss, flags) in [
            (0usize, 4000usize, 1448u16, 0x10u8),
            (12, 10_240, 1448, 0x18),
            (12, 16_384, 1448, 0x19),
            (0, 1449, 536, 0x10),
            (12, 1449, 524, 0x10),
            (40, 9_999, 1460 - 40, 0x10),
        ] {
            let mut f = frame(0, tcp_options, data, flags);
            let len = f.len();
            let h = parse(&f[..128], len, mss).expect("parse");
            let mut head = f[..h.headers].to_vec();
            put_pseudo(&mut head, &h);
            f[..h.headers].copy_from_slice(&head);
            let segments = device(&f, &header(&h, mss));
            assert_eq!(segments.len(), data.div_ceil(usize::from(mss)));
            let mut joined = Vec::new();
            for (k, s) in segments.iter().enumerate() {
                assert!(verify_sums(s), "segment {k} of {data}/{mss}");
                joined.extend_from_slice(&s[h.headers..]);
                let last = k + 1 == segments.len();
                let flag = s[ETHERNET_HEADER + h.ip + 13];
                assert!(flag & 0x09 == 0 || last, "FIN and PSH on the last only");
            }
            assert_eq!(
                joined,
                f[h.headers..],
                "the data of the segments is the frame's"
            );
            // The same frame with its sums whole gives the same segments' sums.
            let mut whole = f.clone();
            fill_sums(&mut whole);
            assert!(verify_sums(&whole));
        }
    }

    #[test]
    fn a_sum_field_the_consumer_left_does_not_reach_the_wire() {
        let mut a = frame(0, 0, 4000, 0x10);
        let mut b = a.clone();
        b[ETHERNET_HEADER + 20 + 16..ETHERNET_HEADER + 20 + 18].copy_from_slice(&[0xff, 0xff]);
        for f in [&mut a, &mut b] {
            let h = parse(&f[..128], f.len(), 1448).unwrap();
            let mut head = f[..h.headers].to_vec();
            put_pseudo(&mut head, &h);
            f[..h.headers].copy_from_slice(&head);
        }
        assert_eq!(a, b);
    }
}
