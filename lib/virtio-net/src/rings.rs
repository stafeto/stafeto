// SPDX-License-Identifier: MIT
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

/// The ring of receiving.
pub struct RxRing<H: Hal> {
    pub queue: Queue<H>,
    book: RxBook,
    base: usize,
    /// Buffers went back in since the last doorbell.
    pub dirty: bool,
}

impl<H: Hal> RxRing<H> {
    /// The ring over `queue`, its buffers in the object mapped at `base`.
    pub fn new(queue: Queue<H>, base: usize) -> RxRing<H> {
        RxRing {
            queue,
            book: RxBook::new(),
            base,
            dirty: false,
        }
    }

    /// Where its buffers lie in the driver.
    pub fn base(&self) -> usize {
        self.base
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
        }
    }

    /// Where its buffers lie in the driver.
    pub fn base(&self) -> usize {
        self.base
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
