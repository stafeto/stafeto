// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A frame of a consumer for the device to cut into segments (the segmentation offload, TX
//! entries `TX_SUM | TX_TSO`). The switch holds the frame across steps: a step copies at most
//! `CHUNK` bytes, because the whole frame (up to 16 KiB, about 9 900 ticks under -icount) would
//! not fit the bound of a step. The frame goes out as one chain of the device's buffers, its
//! first bytes behind the header of virtio, and is queued after the last chunk.
//!
//! The headers are read once into the switch's memory (`Send::new`, the double-read rule N31):
//! the checks, the sum of the pseudo-header and the copy that goes out are all of that one read,
//! and only the data is read from the consumer's cells chunk by chunk. A consumer that changes
//! its data meanwhile damages its own stream: the device sums what it was given.

use super::ring::ConsumerRing;
use proto_net::switch::TSO_HEAD_MAX;
use virtio_net::books::CHAIN_MAX;
use virtio_net::frames::{BUFFER_LEN, HDR_LEN};
use virtio_net::tso::{self, Head};

/// The data the switch copies in one step.
pub const CHUNK: usize = 4096;

/// A frame of the offload on its way to the device.
pub struct Send {
    pub mss: u16,
    /// The frame's length and the length of its headers.
    pub len: usize,
    pub head: Head,
    /// The headers, checked, with the sum of the pseudo-header in the field of the TCP sum.
    bytes: [u8; TSO_HEAD_MAX],
    /// The frame bytes copied so far (the headers count from the start).
    pub copied: usize,
    /// The device buffers of the chain, taken; `nbuf` of them.
    pub bufs: [u16; CHAIN_MAX],
    pub nbuf: usize,
    /// The frame waited for its buffers (said once, so the counter counts frames).
    pub waited: bool,
}

impl Send {
    /// The frame of `len` bytes whose headers are the first of `head` (a copy of its first
    /// `TSO_HEAD_MAX` bytes or all of a shorter frame), already refused or passed by
    /// `tso::parse` as `h`.
    pub fn new(head: &[u8], len: usize, mss: u16, h: Head) -> Send {
        let mut bytes = [0u8; TSO_HEAD_MAX];
        bytes[..h.headers].copy_from_slice(&head[..h.headers]);
        tso::put_pseudo(&mut bytes[..h.headers], &h);
        Send {
            mss,
            len,
            head: h,
            bytes,
            copied: h.headers,
            bufs: [0; CHAIN_MAX],
            nbuf: 0,
            waited: false,
        }
    }

    /// The buffers the chain takes: the header of virtio and the frame, `BUFFER_LEN` to a buffer.
    pub fn buffers(&self) -> usize {
        (HDR_LEN + self.len).div_ceil(BUFFER_LEN)
    }

    /// The bytes the device is given in all.
    pub fn total(&self) -> usize {
        HDR_LEN + self.len
    }

    /// The chain's buffers are taken (`bufs[..nbuf]`): the header of virtio and the headers of
    /// the frame go into the first.
    pub fn begin(&mut self, first: &mut [u8]) {
        first[..HDR_LEN].copy_from_slice(&tso::header(&self.head, self.mss));
        first[HDR_LEN..HDR_LEN + self.head.headers]
            .copy_from_slice(&self.bytes[..self.head.headers]);
    }

    /// Whether the chain can be taken now: `free` buffers are in the pool and the consumer has
    /// `held` of its share of `cap` in the queue. A consumer with nothing in the queue may always
    /// send one frame; the rest keeps to its share.
    pub fn may_take(&self, free: usize, held: usize, cap: usize) -> bool {
        let k = self.buffers();
        free >= k && (held == 0 || held + k <= cap)
    }

    /// Whether every byte is copied.
    pub fn done(&self) -> bool {
        self.copied >= self.len
    }

    /// Copies the next `CHUNK` bytes of the frame (or what is left) from the cells of `ring`
    /// into the buffers of the chain, `buf(n)` the memory of buffer `n`. True when the frame is
    /// whole in the chain.
    pub fn chunk<'a>(
        &mut self,
        ring: &ConsumerRing,
        buf: &mut dyn FnMut(u16) -> &'a mut [u8],
    ) -> bool {
        let end = self.len.min(self.copied + CHUNK);
        while self.copied < end {
            // Frame byte `at` lies after the header of virtio in the chain.
            let at = HDR_LEN + self.copied;
            let (n, off) = (at / BUFFER_LEN, at % BUFFER_LEN);
            let part = (end - self.copied).min(BUFFER_LEN - off);
            ring.tso_read(self.copied, &mut buf(self.bufs[n])[off..off + part]);
            self.copied += part;
        }
        self.done()
    }
}

#[cfg(test)]
mod tests {
    use super::super::ring::tests::Rig;
    use super::super::ring::{Poll, Tx};
    use super::*;
    use proto_net::switch::{self as sw, CELL, Layout, TxEntry};
    use virtio_net::frames::{ETHERNET_HEADER, ETHERTYPE_IPV4, checksum};

    /// A frame as the stack of a consumer builds it: IPv4 without options, TCP with
    /// timestamps, the IPv4 sum whole and the TCP sum field as the stack left it.
    fn frame(data: usize) -> Vec<u8> {
        let mut f = vec![0u8; ETHERNET_HEADER + 20 + 32 + data];
        f[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        f[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4);
        f[14] = 0x45;
        let total = (f.len() - 14) as u16;
        f[16..18].copy_from_slice(&total.to_be_bytes());
        f[20] = 0x40;
        f[22] = 64;
        f[23] = 6;
        f[26..30].copy_from_slice(&[10, 0, 0, 1]);
        f[30..34].copy_from_slice(&[10, 0, 0, 2]);
        f[34..36].copy_from_slice(&80u16.to_be_bytes());
        f[36..38].copy_from_slice(&5000u16.to_be_bytes());
        f[46] = 0x80;
        f[47] = 0x18;
        f[50..52].copy_from_slice(&[0xab, 0xcd]);
        for (k, b) in f[86..].iter_mut().enumerate() {
            *b = (k * 31 + k / 97) as u8;
        }
        let sum = checksum(&f[14..34]);
        f[24..26].copy_from_slice(&sum.to_be_bytes());
        f
    }

    /// The consumer writes `f` in `cells(len)` entries at its next index, as `vnet_port_tx_*`.
    fn send_tso(rig: &Rig, f: &[u8], mss: u32) {
        let m = rig.mem();
        let head = m.load(sw::TX_HEAD);
        let k = sw::cells(f.len());
        m.write(rig.layout.tx_cell(head), f);
        let first = TxEntry {
            len: f.len() as u16,
            flags: sw::TX_SUM | sw::TX_TSO,
            spare: mss,
        };
        m.write(rig.layout.tx_entry(head), &first.to_bytes());
        for i in 1..k {
            m.write(rig.layout.tx_entry(head + i), &[0; 8]);
        }
        m.store(sw::TX_HEAD, head + k);
    }

    /// Takes the frame as the switch does and builds the chain of buffers in host memory.
    fn through(f: &[u8], mss: u16) -> (Vec<Vec<u8>>, Shape) {
        let rig = Rig::new(Layout::new(256, 64).unwrap());
        let mut ring = rig.ring();
        send_tso(&rig, f, u32::from(mss));
        assert_eq!(ring.poll(), Poll::Live);
        let mut head = [0u8; CELL];
        let Tx::Tso { len, mss } = ring.take_tx(&mut head) else {
            panic!("a frame of the offload");
        };
        let h = tso::parse(&head[..len.min(TSO_HEAD_MAX)], len, mss).expect("the headers");
        let mut s = Send::new(&head, len, mss, h);
        let mut bufs: Vec<Vec<u8>> = vec![vec![0xEE; BUFFER_LEN]; CHAIN_MAX];
        s.nbuf = s.buffers();
        for (i, b) in s.bufs[..s.nbuf].iter_mut().enumerate() {
            *b = i as u16;
        }
        s.begin(&mut bufs[0]);
        let mut chunks = 0;
        let base = bufs.as_mut_ptr();
        let mut at = |n: u16| -> &mut [u8] {
            // SAFETY: `n` is below CHAIN_MAX, the vectors live until the end of the function.
            unsafe { &mut *base.add(usize::from(n)) }
        };
        while !s.chunk(&ring, &mut at) {
            chunks += 1;
            assert!(s.copied <= s.len);
        }
        chunks += 1;
        ring.tso_done();
        let shape = Shape {
            chunks,
            total: s.total(),
            nbuf: s.nbuf,
        };
        (bufs, shape)
    }

    struct Shape {
        chunks: usize,
        total: usize,
        nbuf: usize,
    }

    /// The bytes the device gets: the chain's buffers one after the other, `total` of them.
    fn gathered(bufs: &[Vec<u8>], total: usize) -> Vec<u8> {
        bufs.concat()[..total].to_vec()
    }

    #[test]
    fn the_chain_holds_the_virtio_header_then_the_frame_with_the_pseudo_sum_in_chunks() {
        for data in [1500usize, 3_000, 4_096, 10_240, 16_384] {
            let f = frame(data);
            let (bufs, shape) = through(&f, 1448);
            assert_eq!(shape.total, HDR_LEN + f.len());
            assert_eq!(shape.nbuf, (HDR_LEN + f.len()).div_ceil(BUFFER_LEN));
            let got = gathered(&bufs, shape.total);
            let h = tso::parse(&f[..f.len().min(128)], f.len(), 1448).unwrap();
            assert_eq!(&got[..HDR_LEN], &tso::header(&h, 1448));
            // The frame is the stack's, but for the pseudo sum in the field.
            let mut want = f.clone();
            let mut heads = want[..h.headers].to_vec();
            tso::put_pseudo(&mut heads, &h);
            want[..h.headers].copy_from_slice(&heads);
            assert_eq!(&got[HDR_LEN..], &want[..], "data {data}");
            // The pseudo-header's sum replaced the stack's field.
            assert_ne!(&got[HDR_LEN + 50..HDR_LEN + 52], &[0xab, 0xcd]);
            // Four KiB of data at a time (the step's bound, `CHUNK`).
            assert_eq!(shape.chunks, (f.len() - h.headers).div_ceil(4096), "{data}");
        }
    }

    #[test]
    fn the_chain_of_the_biggest_frame_is_nine_buffers_and_the_last_is_short() {
        let f = frame(sw::TSO_BODY_MAX);
        let (bufs, shape) = through(&f, 1460 - 12);
        assert_eq!(shape.nbuf, CHAIN_MAX);
        assert_eq!(shape.total, HDR_LEN + f.len());
        let last = shape.total - (CHAIN_MAX - 1) * BUFFER_LEN;
        assert!(last > 0 && last < BUFFER_LEN);
        // Bytes past the frame in the last buffer are untouched.
        assert!(bufs[CHAIN_MAX - 1][last..].iter().all(|&b| b == 0xEE));
    }

    #[test]
    fn a_change_of_the_data_in_the_cells_after_the_headers_were_read_does_not_change_the_headers() {
        let rig = Rig::new(Layout::new(256, 64).unwrap());
        let mut ring = rig.ring();
        let f = frame(6000);
        send_tso(&rig, &f, 1448);
        ring.poll();
        let mut head = [0u8; CELL];
        let Tx::Tso { len, mss } = ring.take_tx(&mut head) else {
            panic!("tso");
        };
        let h = tso::parse(&head[..TSO_HEAD_MAX], len, mss).unwrap();
        let s = Send::new(&head, len, mss, h);
        // The consumer rewrites the first cell, headers included.
        let mut evil = f.clone();
        evil[26..30].copy_from_slice(&[10, 9, 9, 9]);
        rig.mem().write(rig.layout.tx_cell(0), &evil[..CELL]);
        assert_eq!(
            &s.bytes[26..30],
            &[10, 0, 0, 1],
            "the checked copy is what goes out"
        );
    }

    #[test]
    fn the_entries_are_free_only_after_the_last_chunk() {
        let rig = Rig::new(Layout::new(256, 64).unwrap());
        let mut ring = rig.ring();
        send_tso(&rig, &frame(10_240), 1448);
        ring.poll();
        let mut head = [0u8; CELL];
        assert!(matches!(ring.take_tx(&mut head), Tx::Tso { .. }));
        ring.publish();
        assert_eq!(
            rig.mem().load(sw::TX_TAIL),
            0,
            "held: the consumer sees no room"
        );
        assert_eq!(
            ring.take_tx(&mut head),
            Tx::Empty,
            "nothing else is taken meanwhile"
        );
        assert!(!ring.tx_waiting());
        ring.tso_done();
        ring.publish();
        assert_eq!(
            rig.mem().load(sw::TX_TAIL),
            6,
            "six cells for a frame of 10 294 bytes"
        );
    }

    #[test]
    fn a_frame_waits_for_all_its_buffers_and_a_consumer_with_none_in_the_queue_may_always_send() {
        let f = frame(16_384);
        let (_bufs, shape) = through(&f, 1448);
        assert_eq!(shape.nbuf, 9);
        let h = tso::parse(&f[..128], f.len(), 1448).unwrap();
        let s = Send::new(&f[..128], f.len(), 1448, h);
        assert_eq!(s.buffers(), 9);
        // Free buffers: eight are not enough (the switch would spin on a frame it cannot take).
        for free in 0..9 {
            assert!(!s.may_take(free, 0, 64), "{free} free");
        }
        assert!(s.may_take(9, 0, 64));
        // A share of 21 (three workers) holds one frame of nine and not a second.
        assert!(s.may_take(200, 12, 21));
        assert!(!s.may_take(200, 13, 21));
        // A consumer with nothing in the queue takes a frame even when its share is smaller.
        assert!(s.may_take(200, 0, 8));
        assert!(!s.may_take(200, 1, 8));
    }
}
