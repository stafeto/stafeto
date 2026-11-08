// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the switch decides about checksums (the offload of the sums of TCP):
//! which received frames carry a sum a stack need not check, which flags go
//! with a frame into a consumer's ring, and what a frame of a consumer with
//! `TX_SUM` becomes before it goes out. UDP, ICMP and the IPv4 header keep
//! their software sums (the header's is checked here on every frame the device
//! vouches for).

use super::route::Decision;
use proto_net::switch::DONE_SUM_OK;
use virtio_net::frames::{Csum, ETHERNET_HEADER, fill_pseudo, is_tcp, packet, verify_header};

/// Whether a frame from the wire has a good sum of its segment without a
/// check by the stack that gets it: the device checked it or sent it partial
/// (`checked`, from the header of the buffer), it is TCP (the offload is that
/// of TCP alone), and the IPv4 header's own sum holds (the device checks the
/// segment's).
pub fn wire_sum_ok(checked: bool, frame: &[u8]) -> bool {
    checked && is_tcp(frame) && verify_header(frame)
}

/// The decision with the flag `DONE_SUM_OK` when `ok`: the consumer's stack
/// takes the segment's sum for good.
pub fn mark(decision: Decision, ok: bool) -> Decision {
    match decision {
        Decision::Consumer { consumer, flags } if ok => Decision::Consumer {
            consumer,
            flags: flags | DONE_SUM_OK,
        },
        other => other,
    }
}

/// The frame of a consumer with `TX_SUM`, already checked, in the switch's own
/// copy: the segment gets the sum of the pseudo-header made from the checked
/// addresses and length, whatever the consumer put in the field (the IPv4
/// header's sum is the consumer's own: a wrong one costs its flow alone).
/// Where the device completes the rest; None for a frame that is no whole
/// first segment of TCP (the entry is refused).
pub fn prepare_tx(frame: &mut [u8]) -> Option<Csum> {
    fill_pseudo(frame)
}

/// The length a frame with `TX_SUM` goes out with: the Ethernet header and the IP packet, without
/// the bytes the consumer left after it (the device sums to the end of the frame, and the
/// padding of F-Stack is zeros, but a trailer would change the sum).
pub fn wire_len(frame: &[u8]) -> usize {
    packet(frame).map_or(frame.len(), |p| frame.len().min(ETHERNET_HEADER + p.end))
}

/// How the sum of a frame with a partial sum goes out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finish {
    /// The frame has its sums whole.
    Whole,
    /// The header says `NEEDS_CSUM` with this place and the device completes the sum.
    Device(Csum),
    /// The device has no offload: the switch completes the sum (`complete`) before the frame goes.
    Software(Csum),
}

/// What becomes of a frame whose segment sum is partial at `csum` (None: whole) on a device
/// with the offload (`offload`) or without it.
pub fn finish(offload: bool, csum: Option<Csum>) -> Finish {
    match csum {
        None => Finish::Whole,
        Some(c) if offload => Finish::Device(c),
        Some(c) => Finish::Software(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use virtio_net::frames::{complete, fill_sums};

    fn tcp(payload: usize) -> Vec<u8> {
        let tcp_len = 20 + payload;
        let mut f = vec![0u8; ETHERNET_HEADER + 20 + tcp_len];
        f[12..14].copy_from_slice(&[8, 0]);
        f[14] = 0x45;
        f[16..18].copy_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
        f[22] = 64;
        f[23] = 6;
        f[26..30].copy_from_slice(&[192, 168, 64, 7]);
        f[30..34].copy_from_slice(&[192, 168, 64, 1]);
        f[34..36].copy_from_slice(&80u16.to_be_bytes());
        f[36..38].copy_from_slice(&4000u16.to_be_bytes());
        f[46] = 0x50;
        f[47] = 0x10;
        for (i, b) in f[54..].iter_mut().enumerate() {
            *b = (i * 13) as u8;
        }
        f
    }

    #[test]
    fn a_frame_the_device_vouches_for_has_a_good_sum_only_when_it_is_tcp_with_a_good_header() {
        let mut f = tcp(100);
        fill_sums(&mut f);
        assert!(wire_sum_ok(true, &f));
        assert!(!wire_sum_ok(false, &f), "the device said nothing");
        let mut bad = f.clone();
        bad[14 + 12] ^= 1;
        assert!(!wire_sum_ok(true, &bad), "the header's sum is looked at");
        let mut udp = f.clone();
        udp[23] = 17;
        assert!(!wire_sum_ok(true, &udp), "the offload is that of TCP");
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&[8, 6]);
        assert!(!wire_sum_ok(true, &arp));
    }

    #[test]
    fn the_flag_goes_into_the_flags_of_a_consumer_only() {
        let d = Decision::Consumer {
            consumer: 3,
            flags: proto_net::switch::DONE_LOOP,
        };
        assert_eq!(
            mark(d, true),
            Decision::Consumer {
                consumer: 3,
                flags: proto_net::switch::DONE_LOOP | DONE_SUM_OK
            }
        );
        assert_eq!(mark(d, false), d);
        assert_eq!(mark(Decision::Stack, true), Decision::Stack);
        assert_eq!(mark(Decision::ArpAll, true), Decision::ArpAll);
    }

    #[test]
    fn the_consumers_field_is_overwritten_and_completes_to_the_whole_sum() {
        let mut whole = tcp(1000);
        fill_sums(&mut whole);
        // The consumer left any bytes in the field of the segment's sum, and its
        // header has its sum.
        for junk in [[0u8, 0], [0xFF, 0xFF], [0x12, 0x34]] {
            let mut f = whole.clone();
            f[50..52].copy_from_slice(&junk);
            let csum = prepare_tx(&mut f).expect("TCP");
            assert_eq!(f[14..34], whole[14..34], "the header is left as it is");
            complete(&mut f, csum);
            assert_eq!(f, whole);
        }
    }

    #[test]
    fn a_frame_with_a_trailer_goes_out_without_it() {
        let mut f = tcp(100);
        let whole = f.len();
        assert_eq!(wire_len(&f), whole);
        f.extend_from_slice(&[0xAA; 6]);
        assert_eq!(wire_len(&f), whole, "the padding is cut");
        f.truncate(whole - 1);
        assert_eq!(wire_len(&f), whole - 1, "a short frame stays as it is");
        assert_eq!(wire_len(&[1, 2, 3]), 3);
    }

    #[test]
    fn a_partial_sum_goes_to_the_device_when_it_offloads_and_is_completed_here_when_not() {
        let c = Csum {
            start: 34,
            offset: 16,
        };
        assert_eq!(finish(true, Some(c)), Finish::Device(c));
        assert_eq!(finish(false, Some(c)), Finish::Software(c));
        assert_eq!(finish(true, None), Finish::Whole);
        assert_eq!(finish(false, None), Finish::Whole);
    }

    #[test]
    fn a_frame_that_is_no_whole_tcp_segment_is_refused_and_left_alone() {
        let mut udp = tcp(10);
        udp[23] = 17;
        let before = udp.clone();
        assert_eq!(prepare_tx(&mut udp), None);
        assert_eq!(udp, before);
        let mut cut = tcp(10);
        cut.truncate(cut.len() - 4);
        assert_eq!(prepare_tx(&mut cut), None);
    }
}
