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
}
