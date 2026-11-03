// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The two rings of the device as the stack's `Device` (smoltcp::phy): the
//! ring of receiving, always full, and the ring of sending, whose used
//! buffers are taken back at the start of every step (Virtio 1.2, 5.1.6.2.3
//! and 5.1.6.3). The halves are two structures so that a receive token and
//! a send token hold different borrows, and a reply made from a received
//! frame can go out on the other half.
//!
//! A buffer is the device's from `add` to `pop_used`, and the service
//! touches it only outside that time. The memory is cached and the device
//! coherent (dma.rs); the barriers are `virtio_mmio::ring` before the
//! doorbell and `rt::dma::rmb` after the used index is seen.

use crate::dma::{Host, net_at};
use netd::frames::{self, BUFFER_LEN, HDR_LEN, MAX_FRAME};
use netd::lines::is_dhcp_client_frame;
use netd::ring::{Budget, QUEUE_SIZE, RX_BUFFERS, RxBook, TxBook, offset};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use virtio_drivers::queue::VirtQueue;

/// The device the first stage serves.
pub const DEVICE: usize = 0;
pub type Queue = VirtQueue<Host<DEVICE>, QUEUE_SIZE>;

/// The frames counted since the start (the probe's line).
#[derive(Clone, Copy, Default)]
pub struct Counters {
    pub tx: u64,
    pub dhcp: u64,
    pub dropped: u64,
}

/// The device broke the protocol or a ring broke its books: the service
/// ends with this code, and init stops the device and starts it again.
pub const FAILED: u64 = 8;

fn fail(what: &str) -> ! {
    rt::println!("virtio-net: {what}");
    rt::sys::process_exit(FAILED)
}

/// Buffer `n` of the object `net`.
///
/// # Safety
///
/// The device does not hold buffer `n` (it is not between `add` and
/// `pop_used`), and the caller holds no other reference to it.
unsafe fn buffer<'a>(n: u16) -> &'a mut [u8] {
    // SAFETY: the object `net` is mapped read and write at net_at(DEVICE)
    // for the service's life; the offset is within it (ring::offset).
    unsafe { core::slice::from_raw_parts_mut((net_at(DEVICE) + offset(n)) as *mut u8, BUFFER_LEN) }
}

/// The ring of receiving.
pub struct RxRing {
    pub queue: Queue,
    book: RxBook,
    budget: Budget,
    /// Buffers went back in since the last doorbell.
    pub dirty: bool,
    dropped: u64,
    frames: u64,
}

impl RxRing {
    pub fn new(queue: Queue) -> RxRing {
        RxRing {
            queue,
            book: RxBook::new(),
            budget: Budget::new(),
            dirty: false,
            dropped: 0,
            frames: 0,
        }
    }

    /// Puts buffer `n` in the queue.
    fn give(&mut self, n: u16) {
        // SAFETY: the device does not hold the buffer (the books say so:
        // it is new or was popped), and nothing else refers to it until
        // `pop_used` returns it.
        let slice = unsafe { buffer(n) };
        // SAFETY: the buffer stays untouched until `take` pops it.
        let token = unsafe { self.queue.add(&[], &mut [slice]) };
        match token {
            Ok(token) if self.book.put(token, n) => self.dirty = true,
            _ => fail("the ring of receiving refused a buffer"),
        }
    }

    /// Fills the queue with every receive buffer, at the start.
    pub fn fill(&mut self) {
        for n in 0..RX_BUFFERS as u16 {
            self.give(n);
        }
    }

    pub fn begin_step(&mut self) {
        self.budget = Budget::new();
    }

    /// The frames the step received and dropped.
    pub fn received(&self) -> usize {
        self.budget.spent().0
    }

    #[cfg_attr(not(feature = "probe"), allow(dead_code))]
    pub fn counters(&self) -> (u64, u64) {
        (self.frames, self.dropped)
    }

    /// Takes the next used buffer: its number and the length of its frame,
    /// dropping (and returning to the queue) the buffers that hold none.
    fn pop(&mut self) -> Option<(u16, usize)> {
        loop {
            if !self.queue.can_pop() {
                return None;
            }
            // The device wrote the used index after the buffer.
            rt::dma::rmb();
            let token = self.queue.peek_used()?;
            let Some(n) = self.book.take(token) else {
                fail("a used buffer the ring of receiving does not hold");
            };
            // SAFETY: the device returned the buffer (it is used).
            let slice = unsafe { buffer(n) };
            // SAFETY: the same buffer `give` added with this token.
            let popped = unsafe { self.queue.pop_used(token, &[], &mut [&mut *slice]) };
            let Ok(used) = popped else {
                fail("a used buffer could not be taken back");
            };
            let length = frames::rx_frame(slice, used as usize).map(<[u8]>::len);
            match length {
                Some(len) => {
                    self.frames += 1;
                    return Some((n, len));
                }
                None => {
                    self.dropped += 1;
                    self.give(n);
                }
            }
        }
    }
}

/// The ring of sending.
pub struct TxRing {
    pub queue: Queue,
    book: TxBook,
    budget: Budget,
    pub dirty: bool,
    counters: Counters,
    /// Where a frame goes that no buffer is free for.
    scratch: [u8; MAX_FRAME],
}

impl TxRing {
    pub fn new(mut queue: Queue) -> TxRing {
        // No interrupt for sent buffers: the step takes them back
        // (Virtio 1.2, 5.1.6.2.3).
        queue.set_dev_notify(false);
        TxRing {
            queue,
            book: TxBook::new(),
            budget: Budget::new(),
            dirty: false,
            counters: Counters::default(),
            scratch: [0; MAX_FRAME],
        }
    }

    pub fn begin_step(&mut self) {
        self.budget = Budget::new();
        self.reclaim();
    }

    /// The frames the step sent.
    pub fn sent(&self) -> usize {
        self.budget.spent().1
    }

    #[cfg_attr(not(feature = "probe"), allow(dead_code))]
    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// Takes back the buffers the device sent.
    pub fn reclaim(&mut self) {
        while self.queue.can_pop() {
            rt::dma::rmb();
            let Some(token) = self.queue.peek_used() else {
                break;
            };
            let Some(n) = self.book.reclaim(token) else {
                fail("a used buffer the ring of sending does not hold");
            };
            // SAFETY: the device returned the buffer; the book gave it back
            // to the pool just now and nothing uses it before this ends.
            let slice = unsafe { buffer(n) };
            // SAFETY: the buffer `consume` added with this token; only the
            // number of descriptors of the chain matters to the crate.
            let popped = unsafe { self.queue.pop_used(token, &[&slice[..HDR_LEN]], &mut []) };
            if popped.is_err() {
                fail("a sent buffer could not be taken back");
            }
        }
    }
}

/// The two rings as the stack's device.
pub struct NetDevice {
    pub rx: RxRing,
    pub tx: TxRing,
}

impl NetDevice {
    /// The frames the step received and sent, for the line of steps.
    pub fn step_frames(&self) -> usize {
        self.rx.received() + self.tx.sent()
    }
}

pub struct RxToken<'a> {
    ring: &'a mut RxRing,
    buffer: u16,
    length: usize,
}

impl phy::RxToken for RxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        // SAFETY: the buffer was popped by `pop` and goes back only when
        // the token drops, after this borrow ends.
        let slice = unsafe { buffer(self.buffer) };
        f(&slice[HDR_LEN..HDR_LEN + self.length])
    }
}

impl Drop for RxToken<'_> {
    /// The buffer goes back to the queue as soon as the stack is done with
    /// the frame, whether or not it read it.
    fn drop(&mut self) {
        self.ring.give(self.buffer);
    }
}

pub struct TxToken<'a> {
    ring: &'a mut TxRing,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let ring = self.ring;
        let spare = len <= MAX_FRAME && ring.budget.take_tx();
        let n = if spare { ring.book.alloc() } else { None };
        let Some(n) = n else {
            // No buffer or no share of the step left: the stack builds the
            // frame where it harms nothing, and the protocol repeats it
            // (ARP and the echo reply are retried by their peers).
            ring.counters.dropped += 1;
            let len = len.min(MAX_FRAME);
            return f(&mut ring.scratch[..len]);
        };
        // SAFETY: the buffer is the pool's and the device does not hold it.
        let slice = unsafe { buffer(n) };
        let result = f(&mut slice[HDR_LEN..HDR_LEN + len]);
        let Some(total) = frames::tx_prepare(slice, len) else {
            ring.book.release(n);
            ring.counters.dropped += 1;
            return result;
        };
        let dhcp = is_dhcp_client_frame(&slice[HDR_LEN..total]);
        let shared: &[u8] = &slice[..total];
        // SAFETY: the buffer is untouched until `reclaim` pops it.
        let sent = unsafe { ring.queue.add(&[shared], &mut []) };
        match sent {
            Ok(token) if ring.book.sent(token, n) => {
                ring.counters.tx += 1;
                ring.counters.dhcp += u64::from(dhcp);
                ring.dirty = true;
            }
            Ok(_) => fail("the ring of sending gave a token twice"),
            Err(_) => {
                ring.book.release(n);
                ring.counters.dropped += 1;
            }
        }
        result
    }
}

impl phy::Device for NetDevice {
    type RxToken<'a>
        = RxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(RxToken<'_>, TxToken<'_>)> {
        if self.rx.budget.rx_left() == 0 {
            return None;
        }
        let (buffer, length) = self.rx.pop()?;
        self.rx.budget.take_rx();
        Some((
            RxToken {
                ring: &mut self.rx,
                buffer,
                length,
            },
            TxToken { ring: &mut self.tx },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<TxToken<'_>> {
        if self.tx.budget.tx_left() == 0 || self.tx.book.free() == 0 {
            return None;
        }
        Some(TxToken { ring: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        // The default checksum capabilities compute and check every sum in
        // the stack: the service negotiates no offload.
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = MAX_FRAME;
        caps
    }
}
