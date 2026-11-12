// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The books of the two rings of a network device (Virtio 1.2, 5.1.2):
//! which buffer of the buffers' object each token of a queue stands for,
//! and the pool of the buffers for sending.
//!
//! The buffers are numbered 0 to 511 in the object, BUFFER_LEN bytes
//! each: 0 to 255 for receiving, 256 to 511 for sending. The queue of the
//! device's crate hands out a token (the number of the first descriptor of
//! the chain) that has nothing to do with the buffer's number, so each ring
//! keeps the map from token to buffer.

use crate::frames::BUFFER_LEN;

/// The entries of each queue.
pub const QUEUE_SIZE: usize = 256;
/// The buffers for receiving and for sending, and all of them.
pub const RX_BUFFERS: usize = QUEUE_SIZE;
pub const TX_BUFFERS: usize = QUEUE_SIZE;
pub const BUFFERS: usize = RX_BUFFERS + TX_BUFFERS;
/// The pages of the network object: 512 buffers of BUFFER_LEN bytes.
pub const NET_PAGES: usize = BUFFERS * BUFFER_LEN / 4096;
const _: () = assert!(NET_PAGES == 256);

/// The chains of the ring of receiving once the device merges segments
/// (`VIRTIO_NET_F_GUEST_TSO4`, Virtio 1.2, 5.1.6.3.1: buffers of at least 65 562
/// bytes): the buffer `n` of 0 to `TAILS` - 1 is the head of a chain and
/// its tail of `TAIL_LEN` bytes follows it in the object of tails. A chain holds
/// the 12-byte header and a frame of up to 67 572 bytes.
pub const TAILS: usize = 64;
pub const TAIL_LEN: usize = 65536;
/// The pages of the object of tails: the most a contiguous object may be.
pub const TAIL_PAGES: usize = TAILS * TAIL_LEN / 4096;
const _: () = assert!(TAIL_PAGES == 1024 && TAILS <= RX_BUFFERS);
const _: () = assert!(BUFFER_LEN + TAIL_LEN >= 65562);

/// The offset in the network object of buffer `n`.
pub const fn offset(n: u16) -> usize {
    n as usize * BUFFER_LEN
}

/// The ring of receiving: every buffer of 0 to 255 is in the device's
/// queue from the start, and goes back as soon as the stack is done with
/// the frame it held.
pub struct RxBook {
    buffer_of: [u16; QUEUE_SIZE],
    /// Whether the token is out with the device.
    out: [bool; QUEUE_SIZE],
}

impl RxBook {
    pub const fn new() -> RxBook {
        RxBook {
            buffer_of: [0; QUEUE_SIZE],
            out: [false; QUEUE_SIZE],
        }
    }

    /// Buffer `buffer` is in the queue under `token`. False for a token
    /// out of range, one already out, or a buffer that is no receive
    /// buffer: nothing is recorded.
    pub fn put(&mut self, token: u16, buffer: u16) -> bool {
        let t = usize::from(token);
        if t >= QUEUE_SIZE || self.out[t] || usize::from(buffer) >= RX_BUFFERS {
            return false;
        }
        self.buffer_of[t] = buffer;
        self.out[t] = true;
        true
    }

    /// The device returned `token`: its buffer, None for a token the
    /// device does not hold (a fault of the device).
    pub fn take(&mut self, token: u16) -> Option<u16> {
        let t = usize::from(token);
        if t >= QUEUE_SIZE || !self.out[t] {
            return None;
        }
        self.out[t] = false;
        Some(self.buffer_of[t])
    }

    /// How many buffers the device holds.
    pub fn outstanding(&self) -> usize {
        self.out.iter().filter(|&&o| o).count()
    }
}

impl Default for RxBook {
    fn default() -> RxBook {
        RxBook::new()
    }
}

/// The ring of sending: a pool of the buffers 256 to 511, the ones in the
/// queue under their tokens.
pub struct TxBook {
    /// The free buffers (their numbers, as a stack) and how many.
    free: [u16; TX_BUFFERS],
    free_len: usize,
    buffer_of: [u16; QUEUE_SIZE],
    out: [bool; QUEUE_SIZE],
    /// The buffers of the chain a token stands for (1 for a frame in one buffer), and the buffer
    /// that follows each buffer of a chain (a frame of the segmentation offload, `tso`).
    chain: [u8; QUEUE_SIZE],
    next: [u16; TX_BUFFERS],
}

/// The most buffers a frame of the segmentation offload takes: its header and
/// `TSO_FRAME_MAX` bytes in buffers of `BUFFER_LEN`.
pub const CHAIN_MAX: usize =
    (crate::frames::HDR_LEN + proto_net::switch::TSO_FRAME_MAX).div_ceil(BUFFER_LEN);
const _: () = assert!(CHAIN_MAX == 9);

impl TxBook {
    pub const fn new() -> TxBook {
        let mut free = [0; TX_BUFFERS];
        let mut i = 0;
        while i < TX_BUFFERS {
            // The first to leave is the lowest.
            free[i] = (BUFFERS - 1 - i) as u16;
            i += 1;
        }
        TxBook {
            free,
            free_len: TX_BUFFERS,
            buffer_of: [0; QUEUE_SIZE],
            out: [false; QUEUE_SIZE],
            chain: [1; QUEUE_SIZE],
            next: [0; TX_BUFFERS],
        }
    }

    /// How many buffers are free.
    pub fn free(&self) -> usize {
        self.free_len
    }

    /// Takes a free buffer.
    pub fn alloc(&mut self) -> Option<u16> {
        self.free_len = self.free_len.checked_sub(1)?;
        Some(self.free[self.free_len])
    }

    /// Gives back a buffer that was never sent.
    pub fn release(&mut self, buffer: u16) -> bool {
        let b = usize::from(buffer);
        if !(RX_BUFFERS..BUFFERS).contains(&b) || self.free_len == TX_BUFFERS {
            return false;
        }
        self.free[self.free_len] = buffer;
        self.free_len += 1;
        true
    }

    /// The buffer `buffer` is in the queue under `token`.
    pub fn sent(&mut self, token: u16, buffer: u16) -> bool {
        let t = usize::from(token);
        if t >= QUEUE_SIZE || self.out[t] || !(RX_BUFFERS..BUFFERS).contains(&usize::from(buffer)) {
            return false;
        }
        self.buffer_of[t] = buffer;
        self.out[t] = true;
        true
    }

    /// The chain of `buffers` (2 to `CHAIN_MAX`, all of the pool's, none twice) is in the queue
    /// under `token`: one frame of the segmentation offload. False, and nothing recorded, for a
    /// token that is out, a chain of another length or a buffer that is no send buffer.
    pub fn sent_chain(&mut self, token: u16, buffers: &[u16]) -> bool {
        let t = usize::from(token);
        let ok = (1..=CHAIN_MAX).contains(&buffers.len())
            && buffers
                .iter()
                .all(|&b| (RX_BUFFERS..BUFFERS).contains(&usize::from(b)));
        if !ok || t >= QUEUE_SIZE || self.out[t] {
            return false;
        }
        self.buffer_of[t] = buffers[0];
        self.chain[t] = buffers.len() as u8;
        for pair in buffers.windows(2) {
            self.next[usize::from(pair[0]) - RX_BUFFERS] = pair[1];
        }
        self.out[t] = true;
        true
    }

    /// The buffers of the chain under `token` (1 for a frame in one buffer; 0 for a token the
    /// device does not hold).
    pub fn chain_len(&self, token: u16) -> usize {
        let t = usize::from(token);
        if t < QUEUE_SIZE && self.out[t] {
            usize::from(self.chain[t])
        } else {
            0
        }
    }

    /// The device returned `token`: its buffer, or every buffer of its chain, goes back to the
    /// pool. The first buffer, None for a token the device does not hold.
    pub fn reclaim(&mut self, token: u16) -> Option<u16> {
        let t = usize::from(token);
        if t >= QUEUE_SIZE || !self.out[t] {
            return None;
        }
        let first = self.buffer_of[t];
        let mut buffer = first;
        for k in 0..self.chain[t] {
            // Read the link before the buffer is free to be sent again.
            let after = self.next[usize::from(buffer).wrapping_sub(RX_BUFFERS) % TX_BUFFERS];
            if !self.release(buffer) {
                return None;
            }
            if k + 1 < self.chain[t] {
                buffer = after;
            }
        }
        self.chain[t] = 1;
        self.out[t] = false;
        Some(first)
    }

    /// How many buffers the device holds.
    pub fn outstanding(&self) -> usize {
        (0..QUEUE_SIZE)
            .filter(|&t| self.out[t])
            .map(|t| usize::from(self.chain[t]))
            .sum()
    }
}

impl Default for TxBook {
    fn default() -> TxBook {
        TxBook::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_object_holds_the_buffers() {
        assert_eq!(NET_PAGES * 4096, BUFFERS * BUFFER_LEN);
        assert_eq!(offset(0), 0);
        assert_eq!(offset(256), 256 * 2048);
        assert_eq!(offset(511) + BUFFER_LEN, NET_PAGES * 4096);
    }

    #[test]
    fn a_receive_token_leads_to_its_buffer_once() {
        let mut book = RxBook::new();
        // The queue hands out numbers of its own.
        assert!(book.put(7, 0));
        assert!(book.put(0, 255));
        assert_eq!(book.outstanding(), 2);
        assert!(!book.put(7, 1), "a token already out");
        assert!(!book.put(256, 1), "a token past the queue");
        assert!(!book.put(8, 256), "a send buffer");
        assert_eq!(book.take(7), Some(0));
        assert_eq!(book.take(7), None, "the device returned it twice");
        assert_eq!(book.take(0), Some(255));
        assert_eq!(book.take(300), None);
        assert_eq!(book.outstanding(), 0);
    }

    #[test]
    fn a_buffer_that_is_not_returned_stays_out() {
        // The fault the probe's 300 pings catch: 256 buffers are all.
        let mut book = RxBook::new();
        for n in 0..RX_BUFFERS as u16 {
            assert!(book.put(n, n));
        }
        assert_eq!(book.outstanding(), RX_BUFFERS);
        assert_eq!(book.take(5), Some(5));
        assert!(book.put(5, 5), "back in the queue");
    }

    #[test]
    fn the_send_pool_hands_out_buffers_above_the_receive_ones() {
        let mut pool = TxBook::new();
        assert_eq!(pool.free(), TX_BUFFERS);
        let first = pool.alloc().expect("a buffer");
        assert_eq!(first, 256);
        let mut seen = vec![first];
        while let Some(b) = pool.alloc() {
            assert!((256..512).contains(&b));
            assert!(!seen.contains(&b), "{b} twice");
            seen.push(b);
        }
        assert_eq!(seen.len(), TX_BUFFERS);
        assert_eq!(pool.free(), 0);
        assert_eq!(pool.alloc(), None);
    }

    #[test]
    fn a_sent_buffer_returns_to_the_pool_by_its_token() {
        let mut pool = TxBook::new();
        let a = pool.alloc().unwrap();
        let b = pool.alloc().unwrap();
        assert!(pool.sent(40, a));
        assert!(pool.sent(3, b));
        assert!(!pool.sent(3, b), "a token already out");
        assert_eq!(pool.outstanding(), 2);
        assert_eq!(pool.free(), TX_BUFFERS - 2);
        assert_eq!(pool.reclaim(3), Some(b));
        assert_eq!(pool.reclaim(3), None);
        assert_eq!(pool.reclaim(999), None);
        assert_eq!(pool.reclaim(40), Some(a));
        assert_eq!(pool.free(), TX_BUFFERS);
        // A buffer given back that is not the pool's.
        assert!(!pool.release(5));
        assert!(!pool.release(300), "the pool is full");
    }

    #[test]
    fn a_chain_returns_every_buffer_by_its_token_and_only_once() {
        let mut pool = TxBook::new();
        let chain: Vec<u16> = (0..6).map(|_| pool.alloc().unwrap()).collect();
        let single = pool.alloc().unwrap();
        assert!(pool.sent_chain(9, &chain));
        assert!(pool.sent(10, single));
        assert_eq!(pool.chain_len(9), 6);
        assert_eq!(pool.chain_len(10), 1);
        assert_eq!(pool.chain_len(11), 0);
        assert_eq!(pool.outstanding(), 7);
        assert_eq!(pool.free(), TX_BUFFERS - 7);
        assert!(!pool.sent_chain(9, &chain), "a token already out");
        assert!(!pool.sent_chain(12, &[]), "no chain of no buffers");
        assert!(
            !pool.sent_chain(12, &[1, 2]),
            "receive buffers are no chain"
        );
        assert!(
            !pool.sent_chain(12, &[300; CHAIN_MAX + 1]),
            "a chain too long"
        );
        assert_eq!(pool.reclaim(9), Some(chain[0]));
        assert_eq!(pool.reclaim(9), None, "the device returned it twice");
        assert_eq!(pool.free(), TX_BUFFERS - 1);
        assert_eq!(pool.reclaim(10), Some(single));
        assert_eq!(pool.free(), TX_BUFFERS);
        // Every buffer of the chain can be allocated again, once.
        let mut again = vec![];
        while let Some(b) = pool.alloc() {
            again.push(b);
        }
        again.sort_unstable();
        again.dedup();
        assert_eq!(again.len(), TX_BUFFERS);
    }
}
