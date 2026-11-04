// SPDX-License-Identifier: MIT
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
}

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

    /// The device returned `token`: its buffer goes back to the pool. The
    /// buffer, None for a token the device does not hold.
    pub fn reclaim(&mut self, token: u16) -> Option<u16> {
        let t = usize::from(token);
        if t >= QUEUE_SIZE || !self.out[t] {
            return None;
        }
        let buffer = self.buffer_of[t];
        if !self.release(buffer) {
            return None;
        }
        self.out[t] = false;
        Some(buffer)
    }

    /// How many buffers the device holds.
    pub fn outstanding(&self) -> usize {
        self.out.iter().filter(|&&o| o).count()
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
}
