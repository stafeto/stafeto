// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The books of the two rings of the device (Virtio 1.2, 5.1.2): which
//! buffer of the network object each token of a queue stands for, the pool
//! of the buffers for sending, and the bounds of one step of the service.
//!
//! The buffers are numbered 0 to 511 in the network object, BUFFER_LEN
//! bytes each: 0 to 255 for receiving, 256 to 511 for sending. The queue
//! of the device's crate hands out a token (the number of the first
//! descriptor of the chain) that has nothing to do with the buffer's
//! number, so each ring keeps the map from token to buffer.

use crate::frames::BUFFER_LEN;

/// The entries of each queue.
pub const QUEUE_SIZE: usize = 256;
/// The buffers for receiving and for sending, and all of them.
pub const RX_BUFFERS: usize = QUEUE_SIZE;
pub const TX_BUFFERS: usize = QUEUE_SIZE;
pub const BUFFERS: usize = RX_BUFFERS + TX_BUFFERS;
/// The pages of the network object: 512 buffers of BUFFER_LEN bytes.
pub const NET_PAGES: usize = BUFFERS * BUFFER_LEN / 4096;
/// The frames one step receives and the frames it sends at most (the
/// bound of a step, so that a flood leaves the loop its other work). The
/// features `batch-8`, `batch-4` and `batch-2` are for the measurement that
/// chose them (reports/2026-11-04-net-p1a): the build of the service has
/// one value.
#[cfg(not(any(feature = "batch-8", feature = "batch-4", feature = "batch-2")))]
pub const BATCH: usize = 16;
#[cfg(feature = "batch-8")]
pub const BATCH: usize = 8;
#[cfg(feature = "batch-4")]
pub const BATCH: usize = 4;
#[cfg(feature = "batch-2")]
pub const BATCH: usize = 2;
pub const STEP_RX: usize = BATCH;
pub const STEP_TX: usize = BATCH;
/// The groups of sockets the pass of sending visits in one step. The
/// features `egress-1` and `egress-4` are for the measurement that chose it.
#[cfg(not(any(feature = "egress-1", feature = "egress-4")))]
pub const EGRESS_GROUPS: usize = 2;
#[cfg(feature = "egress-1")]
pub const EGRESS_GROUPS: usize = 1;
#[cfg(all(feature = "egress-4", not(feature = "egress-1")))]
pub const EGRESS_GROUPS: usize = 4;
/// The notifications to clients and the checks of readiness the step of
/// waking does at most (the pipe service wakes eight at most).
pub const WAKE_TELLS: usize = 8;
pub const WAKE_CHECKS: usize = 32;
/// The frames the loopback keeps for the next step: two steps of sending.
pub const LOOP_FRAMES: usize = 2 * STEP_TX;

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

/// The frames the loopback keeps (spec 6, 3.3): the stack's frames to its
/// own address wait here for the next reception. The frames themselves lie in
/// a table of the service; this is the book of its places. A frame is
/// pushed at `head`, read at `read`, and its place is the reader's until
/// `done`: the stack builds replies to a frame while it holds it.
pub struct LoopBook {
    head: usize,
    read: usize,
    done: usize,
}

impl LoopBook {
    pub const fn new() -> LoopBook {
        LoopBook {
            head: 0,
            read: 0,
            done: 0,
        }
    }

    /// The place for a new frame, None when all LOOP_FRAMES are taken.
    pub fn push(&mut self) -> Option<usize> {
        if self.head - self.done >= LOOP_FRAMES {
            return None;
        }
        let place = self.head % LOOP_FRAMES;
        self.head += 1;
        Some(place)
    }

    /// The place of the oldest frame not read.
    pub fn pop(&mut self) -> Option<usize> {
        if self.read == self.head {
            return None;
        }
        let place = self.read % LOOP_FRAMES;
        self.read += 1;
        Some(place)
    }

    /// The oldest frame read is done with, its place is free.
    pub fn done(&mut self) {
        if self.done < self.read {
            self.done += 1;
        }
    }

    /// The frames waiting to be read.
    pub fn waiting(&self) -> usize {
        self.head - self.read
    }
}

impl Default for LoopBook {
    fn default() -> LoopBook {
        LoopBook::new()
    }
}

/// What the step of waking may still do: WAKE_TELLS notifications and
/// WAKE_CHECKS checks of readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WakeBudget {
    tells: usize,
    checks: usize,
}

impl WakeBudget {
    pub const fn new() -> WakeBudget {
        WakeBudget {
            tells: WAKE_TELLS,
            checks: WAKE_CHECKS,
        }
    }

    /// Spends a check; false when the step has had its share.
    pub fn take_check(&mut self) -> bool {
        self.checks = match self.checks.checked_sub(1) {
            Some(left) => left,
            None => return false,
        };
        true
    }

    /// Spends a notification; false when the step has had its share.
    pub fn take_tell(&mut self) -> bool {
        self.tells = match self.tells.checked_sub(1) {
            Some(left) => left,
            None => return false,
        };
        true
    }
}

impl Default for WakeBudget {
    fn default() -> WakeBudget {
        WakeBudget::new()
    }
}

/// What one step of the service may still do: receive STEP_RX frames and
/// send STEP_TX (spec 6: a step is bounded so that a burst of frames
/// cannot hold the loop).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    rx: usize,
    tx: usize,
}

impl Budget {
    pub const fn new() -> Budget {
        Budget {
            rx: STEP_RX,
            tx: STEP_TX,
        }
    }

    /// Spends one reception; false when the step has had its share.
    pub fn take_rx(&mut self) -> bool {
        self.rx = match self.rx.checked_sub(1) {
            Some(left) => left,
            None => return false,
        };
        true
    }

    /// Spends one send; false when the step has had its share.
    pub fn take_tx(&mut self) -> bool {
        self.tx = match self.tx.checked_sub(1) {
            Some(left) => left,
            None => return false,
        };
        true
    }

    pub fn rx_left(&self) -> usize {
        self.rx
    }

    pub fn tx_left(&self) -> usize {
        self.tx
    }

    /// The frames received and sent so far in the step.
    pub fn spent(&self) -> (usize, usize) {
        (STEP_RX - self.rx, STEP_TX - self.tx)
    }
}

impl Default for Budget {
    fn default() -> Budget {
        Budget::new()
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
    fn the_loop_keeps_frames_in_order_and_holds_the_place_until_done() {
        let mut book = LoopBook::new();
        assert_eq!(book.pop(), None);
        let a = book.push().unwrap();
        let b = book.push().unwrap();
        assert_ne!(a, b);
        assert_eq!(book.waiting(), 2);
        assert_eq!(book.pop(), Some(a));
        // The frame read is still held: its reply goes to the next place.
        let c = book.push().unwrap();
        assert!(c != a && c != b);
        book.done();
        assert_eq!(book.pop(), Some(b));
        assert_eq!(book.pop(), Some(c));
        assert_eq!(book.pop(), None);
    }

    #[test]
    fn the_loop_refuses_a_frame_when_it_is_full() {
        let mut book = LoopBook::new();
        for _ in 0..LOOP_FRAMES {
            assert!(book.push().is_some());
        }
        assert_eq!(book.push(), None);
        assert!(book.pop().is_some());
        assert_eq!(book.push(), None, "a place is free after done alone");
        book.done();
        assert!(book.push().is_some());
        assert_eq!(book.waiting(), LOOP_FRAMES);
    }

    #[test]
    fn the_step_of_waking_tells_eight_and_checks_thirty_two() {
        let mut budget = WakeBudget::new();
        for _ in 0..WAKE_TELLS {
            assert!(budget.take_tell());
        }
        assert!(!budget.take_tell());
        for _ in 0..WAKE_CHECKS {
            assert!(budget.take_check());
        }
        assert!(!budget.take_check());
    }

    #[test]
    fn a_step_receives_and_sends_a_batch_of_frames() {
        let mut budget = Budget::new();
        for _ in 0..STEP_RX {
            assert!(budget.take_rx());
        }
        assert!(!budget.take_rx());
        assert_eq!(budget.tx_left(), STEP_TX);
        for _ in 0..STEP_TX {
            assert!(budget.take_tx());
        }
        assert!(!budget.take_tx());
        assert_eq!(budget.spent(), (STEP_RX, STEP_TX));
        assert_eq!(budget.rx_left(), 0);
    }
}
