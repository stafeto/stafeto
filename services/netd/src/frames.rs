// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The frame in a buffer of the device (Virtio 1.2, 5.1.6): the header
//! of 12 bytes that a device with `VIRTIO_F_VERSION_1` puts before every
//! frame it receives and wants before every frame it sends, then the
//! Ethernet frame itself.

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

/// The fields of the header of a received frame that the service looks at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub flags: u8,
    pub gso_type: u8,
    pub num_buffers: u16,
}

/// The header at the start of `buffer`; None when fewer than HDR_LEN bytes.
pub fn parse_header(buffer: &[u8]) -> Option<Header> {
    let head = buffer.get(..HDR_LEN)?;
    Some(Header {
        flags: head[0],
        gso_type: head[1],
        num_buffers: u16::from_le_bytes([head[NUM_BUFFERS_AT], head[NUM_BUFFERS_AT + 1]]),
    })
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

const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
const ETHERNET_HEADER: usize = 14;
/// Where an ARP request's target protocol address is in the frame (RFC 826:
/// the Ethernet header, 8 bytes of fixed fields, two addresses of hardware
/// and one of protocol).
const ARP_TARGET: usize = ETHERNET_HEADER + 24;
const ARP_REQUEST: u16 = 1;

/// The source and destination of an Ethernet frame that carries IPv4.
pub fn ipv4_ends(frame: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    if frame.len() < ETHERNET_HEADER + 20 || frame[12..14] != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = &frame[ETHERNET_HEADER..];
    Some((ip[12..16].try_into().ok()?, ip[16..20].try_into().ok()?))
}

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
    ipv4_ends(frame).is_some_and(|(src, dst)| is_loopback(src) || is_loopback(dst))
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
        assert!(!martian(&arp_request([127, 0, 0, 1])), "ARP is no IPv4");
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
}
