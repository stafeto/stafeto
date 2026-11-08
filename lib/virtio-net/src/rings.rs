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
use crate::frames::{BUFFER_LEN, Csum, HDR_LEN, tx_prepare_with};
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
/// reads the ring of available buffers when a frame comes (VZ), so the
/// driver may leave the doorbell until the device has few of the buffers its
/// last doorbell showed it (`RX_LOW`): a doorbell is an exit from the guest,
/// far dearer than a frame.
///
/// `left` counts the buffers the last doorbell showed and the driver has not
/// taken back. That is more than the device holds: it also counts the buffers
/// the device filled and the driver has yet to take (the crate gives no
/// access to the used index). A device that looks at the ring only after a
/// doorbell (QEMU, once it found the ring empty) says so with the flag of
/// Virtio 1.2, 2.7.10.1 (`flags` 0 means the driver MUST notify). Two rules
/// bound the time such a device waits: the doorbell rings when the device
/// has used the flag once (`wanted` false was seen) and now asks for a
/// notification, and in any case after `RX_LOW` buffers went back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stock {
    /// In the queue: given, and neither used by the device nor taken back.
    queued: u32,
    /// Added since the last doorbell.
    pending: u32,
    /// The device has asked for no notification at least once: it uses the
    /// flag, and the flag 0 is its call for a doorbell.
    flagged: bool,
}

/// The least buffers the device is left with when the doorbell rings.
pub const RX_LOW: u32 = 64;

impl Stock {
    pub const fn new() -> Stock {
        Stock {
            queued: 0,
            pending: 0,
            flagged: false,
        }
    }

    /// A buffer went into the queue.
    pub fn added(&mut self) {
        self.queued += 1;
        self.pending += 1;
    }

    /// The driver took a used buffer back.
    pub fn used(&mut self) {
        debug_assert!(self.queued > 0, "a buffer taken back that was never given");
        self.queued = self.queued.saturating_sub(1);
    }

    /// The doorbell rang, or the device asked for none.
    pub fn rung(&mut self) {
        self.pending = 0;
    }

    /// Buffers added since the last doorbell.
    pub const fn pending(&self) -> u32 {
        self.pending
    }

    /// The buffers the last doorbell showed the device and the driver has
    /// not taken back. Below 0 when the device used buffers added after the
    /// doorbell: 0 then.
    pub const fn left(&self) -> u32 {
        self.queued.saturating_sub(self.pending)
    }

    /// Whether the doorbell is due: buffers went in, and the device runs
    /// low, or `RX_LOW` of them went in since the last doorbell, or the
    /// device that uses the flag asks for it. `wanted` is the flag as the
    /// queue reads it (`should_notify`).
    pub fn due(&mut self, wanted: bool) -> bool {
        if !wanted {
            self.flagged = true;
        }
        self.pending > 0
            && (self.left() <= RX_LOW || self.pending >= RX_LOW || (self.flagged && wanted))
    }
}

/// Whether the device wants a doorbell for the buffers added to `queue`:
/// reads its flag after a full barrier (Virtio 1.2, 2.7.13.4.1: a driver
/// MUST do a barrier before reading the flag or `avail_event`; the crate's
/// store of the index is a release and its read of the flag an acquire,
/// which AArch64 with `rcpc` may reorder).
pub fn wants_ring<H: Hal>(queue: &Queue<H>) -> bool {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    queue.should_notify()
}

/// Interrupts of `queue` on or off. Switching them on is followed by a full
/// barrier, so that the next look at the used index is not served before the
/// flag reaches the device (Virtio 1.2, 2.7.14).
pub fn notify_on<H: Hal>(queue: &mut Queue<H>, on: bool) {
    queue.set_dev_notify(on);
    if on {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
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
    /// Steps that ended since the first of them went in (`Pace`).
    pub waited: u32,
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
            waited: 0,
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
        self.waited = 0;
    }

    /// Puts the frame of `len` bytes in buffer `n` (the pool's, after its
    /// header) in the queue, with a header of zeroes: no checksum offload,
    /// no segmentation. The frame has its sums already.
    #[inline]
    pub fn submit(&mut self, n: u16, len: usize) -> Result<Sent, Broken> {
        self.submit_with(n, len, None)
    }

    /// `submit` for a frame whose sum the device completes: the header says
    /// where (`frames::tx_prepare_with`). The device must have accepted
    /// `VIRTIO_NET_F_CSUM` (Virtio 1.2, 5.1.6.2.1).
    #[inline]
    pub fn submit_with(&mut self, n: u16, len: usize, csum: Option<Csum>) -> Result<Sent, Broken> {
        // SAFETY: the buffer is the pool's and the device does not hold it.
        let slice = unsafe { buffer_at(self.base, n) };
        let Some(total) = tx_prepare_with(slice, len, csum) else {
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

    /// Takes back up to `limit` of the buffers the device sent; how many.
    /// The rest stay in the ring of used buffers for the next call: a device
    /// that sends a whole queue at once (QEMU's bottom half run late, VZ)
    /// returns up to QUEUE_SIZE buffers, and taking all of them in one step
    /// of the service would make that step as long as the queue.
    #[inline]
    pub fn reclaim(&mut self, limit: usize) -> Result<usize, Broken> {
        take_back(limit, || {
            if !self.queue.can_pop() {
                return Ok(false);
            }
            barrier::rmb();
            let Some(token) = self.queue.peek_used() else {
                return Ok(false);
            };
            let n = self.book.reclaim(token).ok_or(Broken::Unknown)?;
            // SAFETY: the device returned the buffer; the book gave it back
            // to the pool just now and nothing uses it before this ends.
            let slice = unsafe { buffer_at(self.base, n) };
            // SAFETY: the buffer `submit` added with this token; only the
            // number of descriptors of the chain matters to the crate.
            let popped = unsafe { self.queue.pop_used(token, &[&slice[..HDR_LEN]], &mut []) };
            popped.map(|_| true).map_err(|_| Broken::NotTaken)
        })
    }
}

/// Calls `one` until it says there was nothing to take back, fails, or has
/// taken back `limit` buffers; how many it took.
fn take_back(limit: usize, mut one: impl FnMut() -> Result<bool, Broken>) -> Result<usize, Broken> {
    let mut taken = 0;
    while taken < limit && one()? {
        taken += 1;
    }
    Ok(taken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_that_starved_and_waits_for_the_doorbell_gets_it() {
        let mut stock = Stock::new();
        for _ in 0..QUEUE_SIZE {
            stock.added();
        }
        assert!(stock.due(true));
        stock.rung();
        // The device used 250 buffers and the driver took back 2: `left`
        // shows 254 of 256, the device holds 6 (QEMU asked for the doorbell:
        // the flag is 0).
        for _ in 0..2 {
            stock.used();
            stock.added();
        }
        assert_eq!(stock.left(), QUEUE_SIZE as u32 - 2);
        // A device that never used the flag is not rung for it.
        assert!(
            !stock.due(true),
            "VZ never sets the flag: the old threshold"
        );
        // The device that sets the flag once (it has buffers) and clears it
        // (it ran dry) gets its doorbell with 2 buffers pending.
        assert!(!stock.due(false), "has buffers: no doorbell");
        assert!(stock.due(true), "the flag is 0 after it was 1: ring");
    }

    #[test]
    fn the_doorbell_is_due_after_rx_low_buffers_went_back() {
        let mut stock = Stock::new();
        for _ in 0..QUEUE_SIZE {
            stock.added();
        }
        stock.rung();
        for _ in 0..RX_LOW - 1 {
            stock.used();
            stock.added();
        }
        assert!(!stock.due(true));
        stock.used();
        stock.added();
        assert!(stock.due(true));
    }

    #[test]
    fn taking_back_stops_at_the_limit_and_leaves_the_rest() {
        let mut used = QUEUE_SIZE;
        let mut one = || {
            if used == 0 {
                return Ok(false);
            }
            used -= 1;
            Ok(true)
        };
        assert_eq!(take_back(16, &mut one), Ok(16));
        assert_eq!(used, QUEUE_SIZE - 16);
        let mut few = 3;
        let one = || {
            if few == 0 {
                return Ok(false);
            }
            few -= 1;
            Ok(true)
        };
        assert_eq!(take_back(16, one), Ok(3));
        assert_eq!(
            take_back(16, || Err(Broken::NotTaken)),
            Err(Broken::NotTaken)
        );
    }

    #[test]
    #[should_panic(expected = "never given")]
    fn a_buffer_taken_back_that_was_never_given_is_a_count_error() {
        Stock::new().used();
    }
}
