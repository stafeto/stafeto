// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The frames the device merges (`VIRTIO_NET_F_GUEST_TSO4`): a device with
//! the feature hands over runs of in-order TCP segments of one flow as one
//! frame of up to 64 KiB (Virtio 1.2, 5.1.6.3), with `gso_type` NONE and, on
//! Apple's device, `DATA_VALID` and `RSC_INFO` in `flags`. The stacks and the
//! rings of the consumers take frames of an MTU, so the driver cuts a merged
//! frame into segments of the MTU again (`Plan`), each with its own headers
//! and the sum of the IPv4 header (the segments go on with the sum of the TCP segment good, the
//! device having checked the data), the way a device cuts a frame to send.
//!
//! A merged frame lies in two pieces: the first descriptor of its chain holds
//! the header of virtio and the start of the frame, the second the rest
//! (`Frame2`).

use crate::frames::{ETHERNET_HEADER, ETHERTYPE_IPV4, IPV4_PROTO_TCP, MAX_FRAME, checksum};

/// The most the headers of one segment hold: Ethernet, IPv4 with 40 bytes of
/// options, TCP with 40.
pub const MAX_HEADERS: usize = ETHERNET_HEADER + 60 + 60;

/// The bytes of a frame that lie in two pieces: `head`, then `tail`.
#[derive(Clone, Copy)]
pub struct Frame2<'a> {
    pub head: &'a [u8],
    pub tail: &'a [u8],
}

impl Frame2<'_> {
    pub fn len(&self) -> usize {
        self.head.len() + self.tail.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies the bytes from `at` on into `out`; false when the frame ends
    /// before `out` is full.
    pub fn copy(&self, at: usize, out: &mut [u8]) -> bool {
        let Some(end) = at.checked_add(out.len()).filter(|&end| end <= self.len()) else {
            return false;
        };
        let split = self.head.len();
        if at < split {
            let first = (split - at).min(out.len());
            out[..first].copy_from_slice(&self.head[at..at + first]);
            out[first..].copy_from_slice(&self.tail[..end.saturating_sub(split)]);
        } else {
            out.copy_from_slice(&self.tail[at - split..end - split]);
        }
        true
    }
}

/// How a merged frame is cut: the lengths of its headers and of its data, and
/// the data each segment carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Ethernet, IPv4 and TCP headers.
    pub headers: usize,
    /// The bytes of TCP data in the frame.
    pub data: usize,
    /// The bytes of data in each segment but the last.
    pub mss: usize,
}

/// TCP flags (RFC 9293, 3.1) and the offset of the flag byte in the header.
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_CWR: u8 = 0x80;

impl Plan {
    /// The plan for `frame`, a frame of TCP in IPv4 with data, no fragment, no
    /// SYN or RST (a merged frame holds segments of an open flow); None for
    /// any other. A segment is as long as `MAX_FRAME` allows.
    pub fn new(frame: &Frame2<'_>) -> Option<Plan> {
        let mut h = [0u8; MAX_HEADERS];
        let n = MAX_HEADERS.min(frame.len());
        if n < ETHERNET_HEADER + 40 || !frame.copy(0, &mut h[..n]) {
            return None;
        }
        if h[12..14] != ETHERTYPE_IPV4 || h[ETHERNET_HEADER] >> 4 != 4 {
            return None;
        }
        let ip = usize::from(h[ETHERNET_HEADER] & 0x0f) * 4;
        let ip_at = ETHERNET_HEADER;
        let total = usize::from(u16::from_be_bytes([h[ip_at + 2], h[ip_at + 3]]));
        let fragment = u16::from_be_bytes([h[ip_at + 6], h[ip_at + 7]]);
        if ip < 20
            || h[ip_at + 9] != IPV4_PROTO_TCP
            || fragment & 0x3fff != 0
            || total != frame.len() - ETHERNET_HEADER
            || ETHERNET_HEADER + ip + 20 > n
        {
            return None;
        }
        let tcp_at = ETHERNET_HEADER + ip;
        let tcp = usize::from(h[tcp_at + 12] >> 4) * 4;
        let headers = tcp_at + tcp;
        if tcp < 20 || headers > n || total < ip + tcp {
            return None;
        }
        if h[tcp_at + 13] & (TCP_SYN | TCP_RST) != 0 {
            return None;
        }
        let data = total - ip - tcp;
        let mss = MAX_FRAME.checked_sub(headers).filter(|&m| m > 0)?;
        (data > 0).then_some(Plan { headers, data, mss })
    }

    /// The segments the frame is cut into.
    pub fn segments(&self) -> usize {
        self.data.div_ceil(self.mss)
    }

    /// Writes segment `k` into `out`: the headers of the frame, the length,
    /// the identification and the sequence number of the segment, FIN and PSH
    /// on the last one only and CWR on the first only, then its data and
    /// the sum of the IPv4 header. The bytes of the frame `out` holds; None for a `k` past the last
    /// or an `out` too short.
    pub fn build(&self, frame: &Frame2<'_>, k: usize, out: &mut [u8]) -> Option<usize> {
        if k >= self.segments() {
            return None;
        }
        let at = k * self.mss;
        let part = self.mss.min(self.data - at);
        let len = self.headers + part;
        let out = out.get_mut(..len)?;
        if !frame.copy(0, &mut out[..self.headers])
            || !frame.copy(self.headers + at, &mut out[self.headers..])
        {
            return None;
        }
        let ip_at = ETHERNET_HEADER;
        let tcp_at = ip_at + usize::from(out[ip_at] & 0x0f) * 4;
        out[ip_at + 2..ip_at + 4].copy_from_slice(&((len - ip_at) as u16).to_be_bytes());
        let id = u16::from_be_bytes([out[ip_at + 4], out[ip_at + 5]]).wrapping_add(k as u16);
        out[ip_at + 4..ip_at + 6].copy_from_slice(&id.to_be_bytes());
        let seq = u32::from_be_bytes([
            out[tcp_at + 4],
            out[tcp_at + 5],
            out[tcp_at + 6],
            out[tcp_at + 7],
        ])
        .wrapping_add(at as u32);
        out[tcp_at + 4..tcp_at + 8].copy_from_slice(&seq.to_be_bytes());
        let last = k + 1 == self.segments();
        if !last {
            out[tcp_at + 13] &= !(TCP_FIN | TCP_PSH);
        }
        if k > 0 {
            out[tcp_at + 13] &= !TCP_CWR;
        }
        // The segment goes on with the sum good (the device checked the data): only the IPv4
        // header gets its sum; the field of the TCP sum stays the merged frame's.
        let ip_end = tcp_at;
        out[ip_at + 10] = 0;
        out[ip_at + 11] = 0;
        let header = checksum(&out[ip_at..ip_end]);
        out[ip_at + 10..ip_at + 12].copy_from_slice(&header.to_be_bytes());
        Some(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::{MAX_FRAME, fill_sums, verify_header};

    /// A merged frame: Ethernet, IPv4 with `ip_options` bytes of options, TCP
    /// with `tcp_options` and `data` bytes, sums whole.
    fn merged(ip_options: usize, tcp_options: usize, data: &[u8], flags: u8, seq: u32) -> Vec<u8> {
        let ip = 20 + ip_options;
        let tcp = 20 + tcp_options;
        let mut f = vec![0u8; ETHERNET_HEADER + ip + tcp];
        f[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        f[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4);
        let i = ETHERNET_HEADER;
        f[i] = 0x40 | (ip / 4) as u8;
        f[i + 4..i + 6].copy_from_slice(&0x1000u16.to_be_bytes());
        f[i + 6] = 0x40;
        f[i + 8] = 64;
        f[i + 9] = IPV4_PROTO_TCP;
        f[i + 12..i + 16].copy_from_slice(&[10, 0, 0, 1]);
        f[i + 16..i + 20].copy_from_slice(&[10, 0, 0, 2]);
        let t = i + ip;
        f[t..t + 2].copy_from_slice(&5000u16.to_be_bytes());
        f[t + 2..t + 4].copy_from_slice(&80u16.to_be_bytes());
        f[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
        f[t + 12] = ((tcp / 4) as u8) << 4;
        f[t + 13] = flags;
        f[t + 14..t + 16].copy_from_slice(&4096u16.to_be_bytes());
        f.extend_from_slice(data);
        let total = (f.len() - i) as u16;
        f[i + 2..i + 4].copy_from_slice(&total.to_be_bytes());
        fill_sums(&mut f);
        f
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    /// Cuts `frame` (split in two at `at`) and gathers the segments.
    fn cut(frame: &[u8], at: usize) -> (Plan, Vec<Vec<u8>>) {
        let two = Frame2 {
            head: &frame[..at],
            tail: &frame[at..],
        };
        let plan = Plan::new(&two).expect("a plan");
        let mut out = Vec::new();
        for k in 0..plan.segments() {
            let mut buf = [0u8; MAX_FRAME];
            let n = plan.build(&two, k, &mut buf).expect("a segment");
            out.push(buf[..n].to_vec());
        }
        (plan, out)
    }

    #[test]
    fn the_segments_hold_the_data_in_order_with_the_header_sums() {
        for (ip_options, tcp_options, size, at) in [
            (0, 12, 64_000, 2036),
            (0, 0, 64_240, 1500),
            (4, 12, 3_000, 2036),
            (0, 12, 1_449, 2036),
            (0, 12, 1_448, 2036),
            (0, 12, 10_000, 70),
        ] {
            let d = data(size);
            let f = merged(ip_options, tcp_options, &d, 0x18, 1_000);
            let (plan, segments) = cut(&f, at.min(f.len()));
            assert_eq!(plan.segments(), size.div_ceil(plan.mss));
            let mut gathered = Vec::new();
            for (k, s) in segments.iter().enumerate() {
                assert!(s.len() <= MAX_FRAME);
                assert!(
                    verify_header(s),
                    "segment {k} has the sum of its IPv4 header"
                );
                let t = ETHERNET_HEADER + 20 + ip_options;
                let seq = u32::from_be_bytes(s[t + 4..t + 8].try_into().unwrap());
                assert_eq!(seq, 1_000 + (k * plan.mss) as u32);
                let flags = s[t + 13];
                let last = k + 1 == segments.len();
                assert_eq!(
                    flags & (TCP_FIN | TCP_PSH) != 0,
                    last,
                    "PSH only on the last"
                );
                let id = u16::from_be_bytes([s[ETHERNET_HEADER + 4], s[ETHERNET_HEADER + 5]]);
                assert_eq!(id, 0x1000 + k as u16);
                gathered.extend_from_slice(&s[plan.headers..]);
            }
            assert_eq!(gathered, d);
        }
    }

    #[test]
    fn fin_goes_on_the_last_segment_and_cwr_on_the_first() {
        let d = data(5_000);
        let f = merged(0, 12, &d, 0x01 | 0x08 | 0x80 | 0x10, 7);
        let (plan, segments) = cut(&f, 2036);
        let t = ETHERNET_HEADER + 20;
        let flags: Vec<u8> = segments.iter().map(|s| s[t + 13]).collect();
        assert_eq!(flags.len(), plan.segments());
        assert_eq!(flags[0] & 0x80, 0x80);
        assert!(flags[1..].iter().all(|f| f & 0x80 == 0));
        assert!(flags[..flags.len() - 1].iter().all(|f| f & 0x09 == 0));
        assert_eq!(flags[flags.len() - 1] & 0x09, 0x09);
        assert!(flags.iter().all(|f| f & 0x10 != 0), "ACK stays everywhere");
    }

    #[test]
    fn the_sequence_number_wraps() {
        let d = data(4_000);
        let f = merged(0, 0, &d, 0x10, u32::MAX - 100);
        let (plan, segments) = cut(&f, 2036);
        let t = ETHERNET_HEADER + 20;
        let seq = u32::from_be_bytes(segments[1][t + 4..t + 8].try_into().unwrap());
        assert_eq!(seq, (u32::MAX - 100).wrapping_add(plan.mss as u32));
    }

    #[test]
    fn a_frame_that_is_no_open_flow_of_data_has_no_plan() {
        let two = |f: &[u8]| Plan::new(&Frame2 { head: f, tail: &[] });
        let good = merged(0, 12, &data(4_000), 0x10, 1);
        assert!(two(&good).is_some());
        // SYN, RST, no data.
        assert!(two(&merged(0, 12, &data(4_000), 0x12, 1)).is_none());
        assert!(two(&merged(0, 12, &data(4_000), 0x14, 1)).is_none());
        assert!(two(&merged(0, 12, &[], 0x10, 1)).is_none());
        // Not TCP, a fragment, a length that is not the frame's, a runt.
        let mut f = good.clone();
        f[ETHERNET_HEADER + 9] = 17;
        assert!(two(&f).is_none());
        let mut f = good.clone();
        f[ETHERNET_HEADER + 6] = 0x20;
        assert!(two(&f).is_none());
        let mut f = good.clone();
        f.push(0);
        assert!(two(&f).is_none());
        let mut f = good.clone();
        f[12] = 0x86;
        assert!(two(&f).is_none());
        assert!(two(&good[..30]).is_none());
    }

    #[test]
    fn a_frame_in_two_pieces_copies_across_the_seam() {
        let all: Vec<u8> = (0..200u8).collect();
        let two = Frame2 {
            head: &all[..60],
            tail: &all[60..],
        };
        for (at, n) in [(0, 200), (50, 20), (60, 10), (59, 2), (100, 100), (199, 1)] {
            let mut out = vec![0; n];
            assert!(two.copy(at, &mut out));
            assert_eq!(out, &all[at..at + n]);
        }
        assert!(!two.copy(199, &mut [0; 2]));
    }
}
