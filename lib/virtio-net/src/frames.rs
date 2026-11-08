// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The frame in a buffer of the device (Virtio 1.2, 5.1.6): the header
//! of 12 bytes that a device with `VIRTIO_F_VERSION_1` puts before every
//! frame it receives and wants before every frame it sends, then the
//! Ethernet frame itself; and the checksums of the frames of the wire
//! (RFC 1071), which a driver fills and checks (`fill_sums`, `verify_sums`),
//! or, with the checksum offload (`CSUM` and `GUEST_CSUM`), leaves in part to
//! the device (`fill_partial`, `tx_prepare_with`, `sum_checked`).

/// The bytes of `struct virtio_net_hdr` under `VIRTIO_F_VERSION_1`: flags,
/// gso_type, hdr_len, gso_size, csum_start, csum_offset and num_buffers
/// (Virtio 1.2, 5.1.6). The field num_buffers is there without
/// `VIRTIO_NET_F_MRG_RXBUF` too (the device sets it to 1). A header taken
/// for 10 bytes, the legacy layout, shifts every frame by two bytes.
pub const HDR_LEN: usize = 12;
/// The offset of num_buffers in the header.
pub const NUM_BUFFERS_AT: usize = 10;
/// The most an Ethernet frame holds without a VLAN tag: 14 bytes of header
/// and 1500 of payload.
pub const MAX_FRAME: usize = 1514;
/// The bytes of one buffer of a ring: the header and a frame, up to the
/// next power of two (Virtio 1.2, 5.1.6.3 asks for at least 1526).
pub const BUFFER_LEN: usize = 2048;

const _: () = assert!(HDR_LEN + MAX_FRAME <= BUFFER_LEN);
const _: () = assert!(NUM_BUFFERS_AT + 2 == HDR_LEN);

/// `flags` of the header: on a frame to send, the sum in the frame is partial
/// and the device completes it (`NEEDS_CSUM`); on a received frame, the device
/// has checked the sum of the data (`DATA_VALID`), or the sum is partial and
/// the data is good (`NEEDS_CSUM`) (Virtio 1.2, 5.1.6.2 and 5.1.6.4).
pub const NEEDS_CSUM: u8 = 1;
pub const DATA_VALID: u8 = 2;

/// The fields of the header of a received frame that a driver looks at, and
/// those of a frame to send that the checksum offload fills.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

/// The header at the start of `buffer`; None when fewer than HDR_LEN bytes.
pub fn parse_header(buffer: &[u8]) -> Option<Header> {
    let head = buffer.get(..HDR_LEN)?;
    let word = |at: usize| u16::from_le_bytes([head[at], head[at + 1]]);
    Some(Header {
        flags: head[0],
        gso_type: head[1],
        hdr_len: word(2),
        gso_size: word(4),
        csum_start: word(6),
        csum_offset: word(8),
        num_buffers: word(NUM_BUFFERS_AT),
    })
}

/// Whether the device checked the sum of the transport part of the frame in
/// `buffer` (a received one) or sent it with a partial sum and good data.
pub fn sum_checked(buffer: &[u8]) -> bool {
    buffer
        .first()
        .is_some_and(|flags| flags & (DATA_VALID | NEEDS_CSUM) != 0)
}

/// The Ethernet frame in a buffer the device filled with `used` bytes (the
/// length the used ring reports): None for a buffer that holds no frame,
/// is shorter than a header, or longer than the buffer or than a frame
/// may be. The device sets num_buffers to 1 without MRG_RXBUF, and a frame
/// with a header that says otherwise is dropped.
pub fn rx_frame(buffer: &[u8], used: usize) -> Option<&[u8]> {
    let whole = buffer.get(..used)?;
    let header = parse_header(whole)?;
    let frame = whole.get(HDR_LEN..)?;
    if header.num_buffers > 1 || frame.is_empty() || frame.len() > MAX_FRAME {
        return None;
    }
    Some(frame)
}

/// Writes the header of a frame to send into `buffer` (all of it zero: no
/// checksum offload, no segmentation) and returns the bytes to give the
/// device, header and frame. None for a frame past MAX_FRAME, an empty one,
/// or a buffer too short.
pub fn tx_prepare(buffer: &mut [u8], frame_len: usize) -> Option<usize> {
    if frame_len == 0 || frame_len > MAX_FRAME || buffer.len() < HDR_LEN + frame_len {
        return None;
    }
    buffer[..HDR_LEN].fill(0);
    Some(HDR_LEN + frame_len)
}

/// Where the device completes the sum of a frame to send: the offset of the
/// transport part in the frame and of the sum in that part
/// (`csum_start` and `csum_offset`, Virtio 1.2, 5.1.6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Csum {
    pub start: u16,
    pub offset: u16,
}

/// `tx_prepare` for a frame whose sum the device completes: the header says
/// `NEEDS_CSUM` with the place of the sum. With None it is `tx_prepare`.
pub fn tx_prepare_with(buffer: &mut [u8], frame_len: usize, csum: Option<Csum>) -> Option<usize> {
    let total = tx_prepare(buffer, frame_len)?;
    if let Some(c) = csum {
        buffer[0] = NEEDS_CSUM;
        buffer[6..8].copy_from_slice(&c.start.to_le_bytes());
        buffer[8..10].copy_from_slice(&c.offset.to_le_bytes());
    }
    Some(total)
}

/// The EtherTypes of IPv4 and ARP, and the bytes of an Ethernet header.
pub const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
pub const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
pub const ETHERNET_HEADER: usize = 14;

/// The source and destination of an Ethernet frame that carries IPv4.
pub fn ipv4_ends(frame: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    if frame.len() < ETHERNET_HEADER + 20 || frame[12..14] != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = &frame[ETHERNET_HEADER..];
    Some((ip[12..16].try_into().ok()?, ip[16..20].try_into().ok()?))
}

// ----- the checksums (RFC 1071) -----
//
// A driver that asks the device for no checksum offload gives the frames of
// the wire their sums here: `fill_sums` on the way out, `verify_sums` on the
// way in.

/// Adds `data` to the ones' complement sum `acc`, eight bytes at a time. The
/// words are read big-endian, so the sum of 64-bit words is the sum of the
/// 16-bit words of RFC 1071 (2^16 is 1 modulo 0xFFFF). A tail shorter than
/// eight bytes is padded with zeros, which only the last piece may have.
fn add(mut acc: u64, data: &[u8]) -> u64 {
    let (words, tail) = data.as_chunks::<8>();
    for chunk in words {
        let (sum, carry) = acc.overflowing_add(u64::from_be_bytes(*chunk));
        acc = sum + u64::from(carry);
    }
    if !tail.is_empty() {
        let mut last = [0u8; 8];
        last[..tail.len()].copy_from_slice(tail);
        let (sum, carry) = acc.overflowing_add(u64::from_be_bytes(last));
        acc = sum + u64::from(carry);
    }
    acc
}

/// The sum folded to 16 bits.
fn fold(acc: u64) -> u16 {
    let mut sum = (acc & 0xFFFF_FFFF) + (acc >> 32);
    sum = (sum & 0xFFFF_FFFF) + (sum >> 32);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum as u16
}

/// The Internet checksum of `data`: the complement of the folded sum.
pub fn checksum(data: &[u8]) -> u16 {
    !fold(add(0, data))
}

/// The offset of the sum in a TCP header.
const TCP_SUM_AT: usize = 16;

pub const IPV4_PROTO_ICMP: u8 = 1;
pub const IPV4_PROTO_TCP: u8 = 6;
pub const IPV4_PROTO_UDP: u8 = 17;

/// Where the parts of the IPv4 packet in an Ethernet frame are: the header
/// length, the protocol and the length of the transport part. None for a frame
/// that is no IPv4, or whose lengths do not fit it, or a fragment after the
/// first (it has no transport header).
pub struct Packet {
    pub header: usize,
    pub protocol: u8,
    pub end: usize,
    pub first_fragment: bool,
}

pub fn packet(frame: &[u8]) -> Option<Packet> {
    if frame.len() < ETHERNET_HEADER + 20 || frame[12..14] != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = &frame[ETHERNET_HEADER..];
    let header = usize::from(ip[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if ip[0] >> 4 != 4 || header < 20 || total < header || total > ip.len() {
        return None;
    }
    let fragment = u16::from_be_bytes([ip[6], ip[7]]);
    Some(Packet {
        header,
        protocol: ip[9],
        end: total,
        first_fragment: fragment & 0x1fff == 0 && fragment & 0x2000 == 0,
    })
}

/// The offset in the transport part of the checksum field, and whether the
/// checksum covers the pseudo-header (RFC 793, 3.1; RFC 768; RFC 792).
fn transport_sum(protocol: u8) -> Option<(usize, bool)> {
    match protocol {
        IPV4_PROTO_TCP => Some((TCP_SUM_AT, true)),
        IPV4_PROTO_UDP => Some((6, true)),
        IPV4_PROTO_ICMP => Some((2, false)),
        _ => None,
    }
}

/// The sum of the transport part of the packet, with the pseudo-header when
/// the protocol has one.
fn transport_total(ip: &[u8], p: &Packet, pseudo: bool) -> u64 {
    let part = &ip[p.header..p.end];
    let mut acc = 0;
    if pseudo {
        let mut head = [0u8; 12];
        head[..4].copy_from_slice(&ip[12..16]);
        head[4..8].copy_from_slice(&ip[16..20]);
        head[9] = p.protocol;
        head[10..12].copy_from_slice(&(part.len() as u16).to_be_bytes());
        acc = add(acc, &head);
    }
    add(acc, part)
}

/// Writes the checksums of the frame in place: the IPv4 header's and the
/// transport's (TCP, UDP, ICMP). A UDP sum that comes out 0 goes as 0xFFFF
/// (RFC 768). A frame that is no IPv4 stays as it is.
pub fn fill_sums(frame: &mut [u8]) {
    let Some(p) = packet(frame) else { return };
    let ip = &mut frame[ETHERNET_HEADER..];
    ip[10] = 0;
    ip[11] = 0;
    let header = checksum(&ip[..p.header]);
    ip[10..12].copy_from_slice(&header.to_be_bytes());
    let Some((at, pseudo)) = transport_sum(p.protocol) else {
        return;
    };
    if !p.first_fragment || p.end < p.header + at + 2 {
        return;
    }
    let field = p.header + at;
    ip[field] = 0;
    ip[field + 1] = 0;
    let mut sum = !fold(transport_total(ip, &p, pseudo));
    if sum == 0 && p.protocol == IPV4_PROTO_UDP {
        sum = 0xFFFF;
    }
    ip[field..field + 2].copy_from_slice(&sum.to_be_bytes());
}

/// Prepares a frame of TCP over IPv4 for a device that completes the sum of
/// the segment (Virtio 1.2, 5.1.6.2): the IPv4 header gets its whole sum and
/// the field of the segment's sum the sum of the pseudo-header, folded and not
/// complemented, which the device continues over the segment and complements.
/// Gives the place of the sum for the header; None (and the frame untouched)
/// for a frame that is no first fragment of TCP in IPv4 whole in the buffer.
pub fn fill_partial(frame: &mut [u8]) -> Option<Csum> {
    let (p, csum) = partial_parts(frame)?;
    let ip = &mut frame[ETHERNET_HEADER..];
    ip[10] = 0;
    ip[11] = 0;
    let header = checksum(&ip[..p.header]);
    ip[10..12].copy_from_slice(&header.to_be_bytes());
    put_pseudo(ip, &p);
    Some(csum)
}

/// `fill_partial` without the IPv4 header's sum, for a frame whose header has
/// its sum already (the frame of a stack that makes it, as FreeBSD does).
pub fn fill_pseudo(frame: &mut [u8]) -> Option<Csum> {
    let (p, csum) = partial_parts(frame)?;
    put_pseudo(&mut frame[ETHERNET_HEADER..], &p);
    Some(csum)
}

/// Writes the sum of the pseudo-header, folded, in the field of the segment's
/// sum, over the IPv4 packet `ip`.
fn put_pseudo(ip: &mut [u8], p: &Packet) {
    let mut head = [0u8; 12];
    head[..4].copy_from_slice(&ip[12..16]);
    head[4..8].copy_from_slice(&ip[16..20]);
    head[9] = p.protocol;
    head[10..12].copy_from_slice(&((p.end - p.header) as u16).to_be_bytes());
    let field = p.header + TCP_SUM_AT;
    ip[field..field + 2].copy_from_slice(&fold(add(0, &head)).to_be_bytes());
}

/// The place of the segment's sum in a first fragment of TCP in IPv4 that
/// lies whole in the frame (what `fill_partial` accepts), for the header of
/// a frame that has a partial sum already.
pub fn partial_place(frame: &[u8]) -> Option<Csum> {
    partial_parts(frame).map(|(_, csum)| csum)
}

fn partial_parts(frame: &[u8]) -> Option<(Packet, Csum)> {
    let p = packet(frame)?;
    if p.protocol != IPV4_PROTO_TCP || !p.first_fragment || p.end < p.header + TCP_SUM_AT + 2 {
        return None;
    }
    let csum = Csum {
        start: (ETHERNET_HEADER + p.header) as u16,
        offset: TCP_SUM_AT as u16,
    };
    Some((p, csum))
}

/// What the device does with a frame whose header says `NEEDS_CSUM`: the sum
/// of everything from `start` to the end of the frame, the field's own value
/// as the start of the sum, complemented into the field (a model of the
/// device, for tests and for a driver that has none).
pub fn complete(frame: &mut [u8], csum: Csum) {
    let (start, at) = (
        usize::from(csum.start),
        usize::from(csum.start + csum.offset),
    );
    let seed = u64::from(u16::from_be_bytes([frame[at], frame[at + 1]]));
    frame[at] = 0;
    frame[at + 1] = 0;
    let sum = !fold(add(seed, &frame[start..]));
    frame[at..at + 2].copy_from_slice(&sum.to_be_bytes());
}

/// Whether the frame is TCP in IPv4 (a first fragment or not is `packet`'s).
pub fn is_tcp(frame: &[u8]) -> bool {
    frame.len() >= ETHERNET_HEADER + 20
        && frame[12..14] == ETHERTYPE_IPV4
        && frame[ETHERNET_HEADER + 9] == IPV4_PROTO_TCP
}

/// Whether the sum of the IPv4 header of the frame holds; a frame that is no
/// IPv4 passes, one whose lengths do not fit it does not.
pub fn verify_header(frame: &[u8]) -> bool {
    if frame.len() < ETHERNET_HEADER + 20 || frame[12..14] != ETHERTYPE_IPV4 {
        return true;
    }
    let Some(p) = packet(frame) else { return false };
    fold(add(0, &frame[ETHERNET_HEADER..ETHERNET_HEADER + p.header])) == 0xFFFF
}

/// Whether the checksums of the frame hold: the IPv4 header's and the
/// transport's. A UDP datagram with the sum 0 has none (RFC 768). A frame that
/// is no IPv4, or whose lengths do not fit it, is not checked here (a stack
/// refuses the second kind itself); an IPv4 frame with a wrong total length
/// does not hold.
pub fn verify_sums(frame: &[u8]) -> bool {
    if frame.len() < ETHERNET_HEADER + 20 || frame[12..14] != ETHERTYPE_IPV4 {
        return true;
    }
    let Some(p) = packet(frame) else { return false };
    let ip = &frame[ETHERNET_HEADER..];
    if fold(add(0, &ip[..p.header])) != 0xFFFF {
        return false;
    }
    let Some((at, pseudo)) = transport_sum(p.protocol) else {
        return true;
    };
    if !p.first_fragment || p.end < p.header + at + 2 {
        return true;
    }
    if p.protocol == IPV4_PROTO_UDP && ip[p.header + at..p.header + at + 2] == [0, 0] {
        return true;
    }
    fold(transport_total(ip, &p, pseudo)) == 0xFFFF
}

#[cfg(test)]
mod tests {

    use super::*;

    fn frame_buffer(num_buffers: u16, frame: &[u8]) -> Vec<u8> {
        let mut b = vec![0; HDR_LEN];
        b[NUM_BUFFERS_AT..].copy_from_slice(&num_buffers.to_le_bytes());
        b.extend_from_slice(frame);
        b
    }

    #[test]
    fn the_header_is_twelve_bytes_with_num_buffers_at_ten() {
        assert_eq!(HDR_LEN, 12);
        let b = frame_buffer(1, &[0xAA; 60]);
        assert_eq!(parse_header(&b).map(|h| h.num_buffers), Some(1));
        // The legacy 10-byte layout would put the frame's first bytes
        // where num_buffers is.
        assert_eq!(parse_header(&b[..HDR_LEN - 1]), None);
    }

    #[test]
    fn a_frame_starts_after_the_header() {
        let frame: Vec<u8> = (0..60).collect();
        let b = frame_buffer(1, &frame);
        assert_eq!(rx_frame(&b, b.len()), Some(&frame[..]));
        // The buffer is bigger than the used length.
        let mut big = b.clone();
        big.resize(BUFFER_LEN, 0xEE);
        assert_eq!(rx_frame(&big, b.len()), Some(&frame[..]));
    }

    #[test]
    fn a_buffer_without_a_frame_is_dropped() {
        let b = frame_buffer(1, &[1; 60]);
        assert_eq!(rx_frame(&b, 0), None);
        assert_eq!(rx_frame(&b, HDR_LEN), None, "a header and no frame");
        assert_eq!(rx_frame(&b, HDR_LEN - 1), None);
        assert_eq!(rx_frame(&b, b.len() + 1), None, "longer than the buffer");
        let long = frame_buffer(1, &vec![1; MAX_FRAME + 1]);
        assert_eq!(rx_frame(&long, long.len()), None);
        let exact = frame_buffer(1, &vec![1; MAX_FRAME]);
        assert!(rx_frame(&exact, exact.len()).is_some());
        let merged = frame_buffer(2, &[1; 60]);
        assert_eq!(rx_frame(&merged, merged.len()), None);
    }

    #[test]
    fn a_frame_to_send_gets_a_zero_header() {
        let mut b = vec![0xFF; BUFFER_LEN];
        assert_eq!(tx_prepare(&mut b, 42), Some(HDR_LEN + 42));
        assert!(b[..HDR_LEN].iter().all(|&x| x == 0));
        assert_eq!(b[HDR_LEN], 0xFF, "the frame is the caller's");
        assert_eq!(tx_prepare(&mut b, 0), None);
        assert_eq!(tx_prepare(&mut b, MAX_FRAME + 1), None);
        assert_eq!(tx_prepare(&mut b[..HDR_LEN + 41], 42), None);
        assert_eq!(tx_prepare(&mut b, MAX_FRAME), Some(HDR_LEN + MAX_FRAME));
    }

    fn arp_request(target: [u8; 4]) -> Vec<u8> {
        let mut f = vec![0; 42];
        f[..6].fill(0xff);
        f[12..14].copy_from_slice(&[8, 6]);
        f[20..22].copy_from_slice(&1u16.to_be_bytes());
        f[38..42].copy_from_slice(&target);
        f
    }

    /// The sum by the plain rule of RFC 1071: 16-bit words, one at a time.
    fn plain(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for pair in data.chunks(2) {
            let word = if pair.len() == 2 {
                u16::from_be_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], 0])
            };
            sum += u32::from(word);
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn the_sum_agrees_with_the_plain_rule_on_every_length() {
        // A small generator of bytes, fixed so that the test repeats.
        let mut x: u32 = 0x1234_5678;
        let mut data = Vec::new();
        for _ in 0..1514 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((x >> 24) as u8);
        }
        for len in 0..=1514 {
            assert_eq!(checksum(&data[..len]), plain(&data[..len]), "length {len}");
        }
        // All ones and all zeros.
        assert_eq!(checksum(&[0xFF; 1500]), plain(&[0xFF; 1500]));
        assert_eq!(checksum(&[0; 64]), 0xFFFF);
        // The example of RFC 1071, section 3.
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            !0xddf2u16
        );
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

    #[test]
    fn a_frame_with_filled_sums_verifies() {
        for len in [0usize, 1, 7, 8, 9, 300, 1460] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            for mut frame in [udp_frame(&payload), tcp_frame(&payload)] {
                fill_sums(&mut frame);
                assert!(verify_sums(&frame), "length {len}");
            }
        }
        // The header's sum of a known packet (RFC 1071 style check: the sum
        // of the filled header is 0xFFFF).
        let mut f = udp_frame(b"hello");
        fill_sums(&mut f);
        assert_eq!(fold(add(0, &f[14..34])), 0xFFFF);
    }

    #[test]
    fn a_frame_with_a_bad_tcp_sum_is_dropped() {
        let mut frame = tcp_frame(b"some bytes of data");
        fill_sums(&mut frame);
        assert!(verify_sums(&frame));
        let last = frame.len() - 1;
        frame[last] ^= 1;
        assert!(!verify_sums(&frame), "a flipped bit in the data");
        fill_sums(&mut frame);
        frame[14 + 12] ^= 0x10;
        assert!(
            !verify_sums(&frame),
            "a changed address breaks the header's sum"
        );
    }

    #[test]
    fn a_udp_datagram_without_a_sum_passes_and_a_zero_sum_goes_as_ones() {
        let mut frame = udp_frame(b"abc");
        fill_sums(&mut frame);
        // The sum of the datagram is cleared by the sender: no sum.
        frame[40] = 0;
        frame[41] = 0;
        assert!(verify_sums(&frame));
        // A payload that makes the sum 0 is written as 0xFFFF.
        let mut x = udp_frame(&[0, 0]);
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                x[42] = a;
                x[43] = b;
                fill_sums(&mut x);
                assert_ne!(x[40..42], [0, 0], "{a} {b}");
                assert!(verify_sums(&x));
            }
        }
    }

    #[test]
    fn frames_that_are_no_ipv4_are_not_checked_and_a_wrong_length_does_not_hold() {
        assert!(verify_sums(&arp_request([10, 0, 2, 2])));
        let mut f = udp_frame(b"abc");
        fill_sums(&mut f);
        f[16] = 0xFF;
        assert!(!verify_sums(&f));
    }

    /// A generator of bytes, fixed so that the tests repeat.
    struct Lcg(u32);
    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            self.0 >> 8
        }
    }

    /// A TCP frame with random addresses, ports, header length (options
    /// make `doff` 5 to 15), IPv4 options and payload.
    fn random_tcp(g: &mut Lcg) -> Vec<u8> {
        let ihl = 5 + (g.next() % 3) as usize;
        let doff = 5 + (g.next() % 4) as usize;
        let payload = (g.next() % 1400) as usize;
        let tcp_len = doff * 4 + payload;
        let mut f = vec![0u8; 14 + ihl * 4 + tcp_len];
        for b in f.iter_mut() {
            *b = g.next() as u8;
        }
        f[12..14].copy_from_slice(&[8, 0]);
        f[14] = 0x40 | ihl as u8;
        let total = (ihl * 4 + tcp_len) as u16;
        f[16..18].copy_from_slice(&total.to_be_bytes());
        f[20..22].copy_from_slice(&[0, 0]);
        f[23] = IPV4_PROTO_TCP;
        let tcp = 14 + ihl * 4;
        f[tcp + 12] = (doff as u8) << 4;
        f
    }

    #[test]
    fn a_partial_sum_completed_by_the_device_equals_the_whole_sum() {
        let mut g = Lcg(7);
        for round in 0..10_000 {
            let mut whole = random_tcp(&mut g);
            let mut partial = whole.clone();
            fill_sums(&mut whole);
            let csum = fill_partial(&mut partial).expect("TCP in IPv4");
            let tcp = 14 + usize::from(whole[14] & 15) * 4;
            assert_eq!(
                csum,
                Csum {
                    start: tcp as u16,
                    offset: 16
                }
            );
            // The IPv4 header is whole already, the segment's sum is not.
            assert_eq!(partial[14..tcp], whole[14..tcp], "round {round}");
            assert_ne!(partial[tcp + 16..tcp + 18], whole[tcp + 16..tcp + 18]);
            complete(&mut partial, csum);
            assert_eq!(partial, whole, "round {round}");
            assert!(verify_sums(&partial));
        }
    }

    #[test]
    fn the_field_of_a_partial_sum_is_the_pseudo_header_without_the_complement() {
        let mut f = tcp_frame(&[1, 2, 3, 4]);
        f[26..30].copy_from_slice(&[10, 0, 0, 1]);
        f[30..34].copy_from_slice(&[10, 0, 0, 2]);
        f[50..52].copy_from_slice(&[0xAB, 0xCD]);
        fill_partial(&mut f).unwrap();
        // 0x0A00 + 0x0001 + 0x0A00 + 0x0002 + 6 + 24 (the segment's length).
        assert_eq!(
            f[50..52],
            (0x0A00u16 + 1 + 0x0A00 + 2 + 6 + 24).to_be_bytes()
        );
    }

    #[test]
    fn only_a_whole_first_segment_of_tcp_gets_a_partial_sum() {
        let mut udp = udp_frame(b"abc");
        let before = udp.clone();
        assert_eq!(fill_partial(&mut udp), None);
        assert_eq!(udp, before, "a frame refused stays as it was");
        let mut arp = arp_request([10, 0, 2, 2]);
        assert_eq!(fill_partial(&mut arp), None);
        let mut cut = tcp_frame(b"data");
        cut.truncate(cut.len() - 1);
        assert_eq!(fill_partial(&mut cut), None, "shorter than its IP length");
        let mut later = tcp_frame(b"data");
        later[20..22].copy_from_slice(&[0, 5]);
        assert_eq!(fill_partial(&mut later), None, "no transport header");
        let mut short = tcp_frame(b"");
        short[16..18].copy_from_slice(&(20u16 + 10).to_be_bytes());
        assert_eq!(fill_partial(&mut short), None, "no room for the sum");
    }

    #[test]
    fn a_frame_padded_to_the_minimum_completes_to_the_whole_sum() {
        // The sum of zeros past the end of the IP packet changes nothing.
        let mut whole = tcp_frame(b"");
        fill_sums(&mut whole);
        let mut partial = tcp_frame(b"");
        let csum = fill_partial(&mut partial).unwrap();
        partial.resize(60, 0);
        complete(&mut partial, csum);
        partial.truncate(whole.len());
        assert_eq!(partial, whole);
    }

    #[test]
    fn the_header_of_a_frame_to_send_names_the_sum() {
        let mut b = vec![0xFF; BUFFER_LEN];
        let c = Csum {
            start: 34,
            offset: 16,
        };
        assert_eq!(tx_prepare_with(&mut b, 60, Some(c)), Some(HDR_LEN + 60));
        let h = parse_header(&b).unwrap();
        assert_eq!(
            h,
            Header {
                flags: NEEDS_CSUM,
                gso_type: 0,
                hdr_len: 0,
                gso_size: 0,
                csum_start: 34,
                csum_offset: 16,
                num_buffers: 0
            }
        );
        // The offsets sit where the standard puts them: little-endian, after
        // flags, gso_type, hdr_len and gso_size.
        assert_eq!(b[6..10], [34, 0, 16, 0]);
        assert_eq!(tx_prepare_with(&mut b, 60, None), Some(HDR_LEN + 60));
        assert!(b[..HDR_LEN].iter().all(|&x| x == 0));
        assert_eq!(tx_prepare_with(&mut b, 0, Some(c)), None);
    }

    #[test]
    fn a_received_frame_is_checked_by_the_device_when_the_header_says_so() {
        let mut b = frame_buffer(1, &[0; 60]);
        assert!(!sum_checked(&b));
        b[0] = DATA_VALID;
        assert!(sum_checked(&b));
        b[0] = NEEDS_CSUM;
        assert!(sum_checked(&b));
        b[0] = 0x4;
        assert!(!sum_checked(&b), "RSC_INFO alone says nothing of sums");
        assert!(!sum_checked(&[]));
    }

    #[test]
    fn the_header_sum_is_checked_alone() {
        let mut f = tcp_frame(b"data");
        // Nothing filled: the header's sum is 0 and does not hold.
        assert!(!verify_header(&f));
        fill_partial(&mut f).unwrap();
        assert!(verify_header(&f), "the segment's sum is not looked at");
        f[14 + 12] ^= 1;
        assert!(!verify_header(&f));
        assert!(verify_header(&arp_request([10, 0, 2, 2])));
        assert!(is_tcp(&f) && !is_tcp(&udp_frame(b"x")));
    }
}
