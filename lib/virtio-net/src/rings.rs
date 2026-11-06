// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The two rings of a network device over the queues of the device's
//! crate (Virtio 1.2, 5.1.6.2 and 5.1.6.3): the ring of receiving, whose
//! buffers go back as soon as the driver is done with a frame, and the ring
//! of sending, whose used buffers are taken back by `reclaim` (no
//! interrupt for them, Virtio 1.2, 5.1.6.2.3). Buffer `n` of a ring lies at
//! `base + books::offset(n)`, where the driver maps its object of buffers;
//! the books (`books`) say which buffer each token of a queue stands for.
//!
//! A buffer is the device's from `add` to `pop_used`, and the driver
//! touches it only outside that time. The barriers are `barrier::ring`
//! before the doorbell and `barrier::rmb` after the used index is seen
//! (`pop`, `reclaim`).

use crate::barrier;
use crate::books::{QUEUE_SIZE, RxBook, TxBook, offset};
use crate::frames::{BUFFER_LEN, HDR_LEN, tx_prepare};
use virtio_drivers::Hal;
use virtio_drivers::queue::VirtQueue;

pub type Queue<H> = VirtQueue<H, QUEUE_SIZE>;

/// How the books of a ring and the device disagree: the device broke the
/// protocol, or the driver its books, and the driver stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Broken {
    /// The ring of receiving refused a buffer.
    Refused,
    /// A used buffer the ring does not hold.
    Unknown,
    /// A used buffer could not be taken back.
    NotTaken,
    /// The ring of sending gave a token twice.
    Twice,
}

impl Broken {
    /// The words a driver says it with.
    pub const fn text(self, sending: bool) -> &'static str {
        match (self, sending) {
            (Broken::Refused, _) => "the ring of receiving refused a buffer",
            (Broken::Unknown, false) => "a used buffer the ring of receiving does not hold",
            (Broken::Unknown, true) => "a used buffer the ring of sending does not hold",
            (Broken::NotTaken, false) => "a used buffer could not be taken back",
            (Broken::NotTaken, true) => "a sent buffer could not be taken back",
            (Broken::Twice, _) => "the ring of sending gave a token twice",
        }
    }
}

/// Buffer `n` of the object mapped at `base`.
///
/// # Safety
///
/// The object is mapped read and write at `base` and holds buffer `n`; the
/// device does not hold the buffer, and the caller holds no other reference
/// to it.
#[inline]
pub unsafe fn buffer_at<'a>(base: usize, n: u16) -> &'a mut [u8] {
    // SAFETY: the caller's promise.
    unsafe { core::slice::from_raw_parts_mut((base + offset(n)) as *mut u8, BUFFER_LEN) }
}

/// The buffers of the ring of receiving as far as its doorbell goes. A device
/// reads the ring of available buffers when a frame comes, so the driver may
/// leave the doorbell until the device has few of the buffers its last
/// doorbell showed it (`RX_LOW`): a doorbell is an exit from the guest, far
/// dearer than a frame. A device that looks at the ring only after a doorbell
/// finds buffers as long as `left` is above 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stock {
    /// In the queue: given, and neither used by the device nor taken back.
    queued: u32,
    /// Added since the last doorbell.
    pending: u32,
}

/// The least buffers the device is left with when the doorbell rings.
pub const RX_LOW: u32 = 64;

impl Stock {
    pub const fn new() -> Stock {
        Stock {
            queued: 0,
            pending: 0,
        }
    }

    /// A buffer went into the queue.
    pub fn added(&mut self) {
        self.queued += 1;
        self.pending += 1;
    }

    /// The driver took a used buffer back.
    pub fn used(&mut self) {
        self.queued = self.queued.saturating_sub(1);
    }

    /// The doorbell rang, or the device asked for none.
    pub fn rung(&mut self) {
        self.pending = 0;
    }

    /// The buffers the last doorbell showed the device and it has left.
    pub const fn left(&self) -> u32 {
        self.queued.saturating_sub(self.pending)
    }

    /// Whether the doorbell is due: buffers went in and the device runs low.
    pub const fn due(&self) -> bool {
        self.pending > 0 && self.left() <= RX_LOW
    }
}

/// The ring of receiving.
pub struct RxRing<H: Hal> {
    pub queue: Queue<H>,
    book: RxBook,
    base: usize,
    /// Buffers went back in since the last doorbell.
    pub dirty: bool,
    /// What the device was shown of the buffers (`Stock`).
    pub stock: Stock,
}

impl<H: Hal> RxRing<H> {
    /// The ring over `queue`, its buffers in the object mapped at `base`.
    pub fn new(queue: Queue<H>, base: usize) -> RxRing<H> {
        RxRing {
            queue,
            book: RxBook::new(),
            base,
            dirty: false,
            stock: Stock::new(),
        }
    }

    /// Where its buffers lie in the driver.
    pub fn base(&self) -> usize {
        self.base
    }

    /// The doorbell rang (or the device asked for none): nothing is pending.
    pub fn rung(&mut self) {
        self.dirty = false;
        self.stock.rung();
    }

    /// Puts buffer `n` in the queue.
    pub fn give(&mut self, n: u16) -> Result<(), Broken> {
        // SAFETY: the device does not hold the buffer (the books say so: it
        // is new or was popped), and nothing else refers to it until
        // `pop_used` returns it.
        let slice = unsafe { buffer_at(self.base, n) };
        // SAFETY: the buffer stays untouched until `pop` takes it.
        let token = unsafe { self.queue.add(&[], &mut [slice]) };
        match token {
            Ok(token) if self.book.put(token, n) => {
                self.dirty = true;
                self.stock.added();
                Ok(())
            }
            _ => Err(Broken::Refused),
        }
    }

    /// Fills the queue with the buffers 0 to `limit` - 1, at the start.
    pub fn fill(&mut self, limit: usize) -> Result<(), Broken> {
        for n in 0..limit.min(QUEUE_SIZE) as u16 {
            self.give(n)?;
        }
        Ok(())
    }

    /// Takes the next used buffer: its number and the bytes the device
    /// wrote into it (header and frame). None when the queue has none.
    #[inline]
    pub fn pop(&mut self) -> Result<Option<(u16, usize)>, Broken> {
        if !self.queue.can_pop() {
            return Ok(None);
        }
        // The device wrote the used index after the buffer.
        barrier::rmb();
        let Some(token) = self.queue.peek_used() else {
            return Ok(None);
        };
        let n = self.book.take(token).ok_or(Broken::Unknown)?;
        // SAFETY: the device returned the buffer (it is used).
        let slice = unsafe { buffer_at(self.base, n) };
        // SAFETY: the same buffer `give` added with this token.
        let popped = unsafe { self.queue.pop_used(token, &[], &mut [&mut *slice]) };
        let used = popped.map_err(|_| Broken::NotTaken)?;
        self.stock.used();
        Ok(Some((n, used as usize)))
    }
}

/// The ring of sending: its pool of buffers is `book`.
pub struct TxRing<H: Hal> {
    pub queue: Queue<H>,
    pub book: TxBook,
    base: usize,
    /// Buffers went in since the last doorbell.
    pub dirty: bool,
    /// How many.
    pub pending: u32,
}

/// What became of a frame given to the ring of sending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// In the queue.
    Queued,
    /// Not sent: the frame was no frame or the queue was full; the buffer is
    /// back in the pool.
    Dropped,
}

impl<H: Hal> TxRing<H> {
    /// The ring over `queue`, its buffers in the object mapped at `base`.
    pub fn new(mut queue: Queue<H>, base: usize) -> TxRing<H> {
        // No interrupt for sent buffers: `reclaim` takes them back
        // (Virtio 1.2, 5.1.6.2.3).
        queue.set_dev_notify(false);
        TxRing {
            queue,
            book: TxBook::new(),
            base,
            dirty: false,
            pending: 0,
        }
    }

    /// Where its buffers lie in the driver.
    pub fn base(&self) -> usize {
        self.base
    }

    /// The doorbell rang (or the device asked for none): nothing is pending.
    pub fn rung(&mut self) {
        self.dirty = false;
        self.pending = 0;
    }

    /// Puts the frame of `len` bytes in buffer `n` (the pool's, after its
    /// header) in the queue, with a header of zeroes: no checksum offload,
    /// no segmentation. The frame has its sums already.
    #[inline]
    pub fn submit(&mut self, n: u16, len: usize) -> Result<Sent, Broken> {
        // SAFETY: the buffer is the pool's and the device does not hold it.
        let slice = unsafe { buffer_at(self.base, n) };
        let Some(total) = tx_prepare(slice, len) else {
            self.book.release(n);
            return Ok(Sent::Dropped);
        };
        let shared: &[u8] = &slice[..total];
        // SAFETY: the buffer is untouched until `reclaim` pops it.
        let sent = unsafe { self.queue.add(&[shared], &mut []) };
        match sent {
            Ok(token) if self.book.sent(token, n) => {
                self.dirty = true;
                self.pending += 1;
                Ok(Sent::Queued)
            }
            Ok(_) => Err(Broken::Twice),
            Err(_) => {
                self.book.release(n);
                Ok(Sent::Dropped)
            }
        }
    }

    /// Takes back the buffers the device sent.
    #[inline]
    pub fn reclaim(&mut self) -> Result<(), Broken> {
        while self.queue.can_pop() {
            barrier::rmb();
            let Some(token) = self.queue.peek_used() else {
                break;
            };
            let n = self.book.reclaim(token).ok_or(Broken::Unknown)?;
            // SAFETY: the device returned the buffer; the book gave it back
            // to the pool just now and nothing uses it before this ends.
            let slice = unsafe { buffer_at(self.base, n) };
            // SAFETY: the buffer `submit` added with this token; only the
            // number of descriptors of the chain matters to the crate.
            let popped = unsafe { self.queue.pop_used(token, &[&slice[..HDR_LEN]], &mut []) };
            if popped.is_err() {
                return Err(Broken::NotTaken);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_doorbell_of_receiving_waits_until_the_device_runs_low() {
        let mut stock = Stock::new();
        assert!(!stock.due(), "nothing went in");
        for _ in 0..QUEUE_SIZE {
            stock.added();
        }
        assert!(stock.due(), "the device was shown nothing: the first ring");
        stock.rung();
        assert_eq!(stock.left(), QUEUE_SIZE as u32);
        assert!(!stock.due());
        // The device uses a buffer, the driver takes it back and gives it
        // again: the device is left with one buffer less of those it saw.
        for _ in 0..(QUEUE_SIZE as u32 - RX_LOW - 1) {
            stock.used();
            stock.added();
        }
        assert_eq!(stock.left(), RX_LOW + 1);
        assert!(!stock.due());
        stock.used();
        stock.added();
        assert!(stock.due());
        stock.rung();
        assert_eq!(stock.left(), QUEUE_SIZE as u32);
    }
}
