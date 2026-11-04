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
use netd::frames::{self, BUFFER_LEN, Dest, HDR_LEN, MAX_FRAME, Route};
use netd::lines::is_dhcp_client_frame;
use netd::ring::{Budget, LoopRing, QUEUE_SIZE, RX_BUFFERS, RxBook, TxBook, offset};
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
    /// Frames of 127.0.0.0/8 the stack would have sent to the device.
    pub martian: u64,
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
unsafe fn buffer_at<'a>(n: u16) -> &'a mut [u8] {
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
    /// Frames of 127.0.0.0/8 that came from the device.
    martian: u64,
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
            martian: 0,
        }
    }

    /// Puts buffer `n` in the queue.
    pub(crate) fn give(&mut self, n: u16) {
        // SAFETY: the device does not hold the buffer (the books say so:
        // it is new or was popped), and nothing else refers to it until
        // `pop_used` returns it.
        let slice = unsafe { buffer_at(n) };
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

    pub fn begin_step(&mut self, budget: Budget) {
        self.budget = budget;
    }

    /// The frames the step received and dropped.
    pub fn received(&self) -> usize {
        self.budget.spent().0
    }

    #[cfg_attr(not(feature = "probe"), allow(dead_code))]
    pub fn counters(&self) -> (u64, u64, u64) {
        (self.frames, self.dropped, self.martian)
    }

    /// Takes the next used buffer: its number and the length of its frame,
    /// dropping (and returning to the queue) the buffers that hold none or a
    /// frame that must not reach the stack. Every buffer taken, good or not,
    /// costs one unit of the step's share of receiving: a flood of frames
    /// that are dropped cannot hold a step.
    pub(crate) fn pop(&mut self) -> Option<(u16, usize)> {
        loop {
            if self.budget.rx_left() == 0 || !self.queue.can_pop() {
                return None;
            }
            // The device wrote the used index after the buffer.
            rt::dma::rmb();
            let token = self.queue.peek_used()?;
            let Some(n) = self.book.take(token) else {
                fail("a used buffer the ring of receiving does not hold");
            };
            // SAFETY: the device returned the buffer (it is used).
            let slice = unsafe { buffer_at(n) };
            // SAFETY: the same buffer `give` added with this token.
            let popped = unsafe { self.queue.pop_used(token, &[], &mut [&mut *slice]) };
            let Ok(used) = popped else {
                fail("a used buffer could not be taken back");
            };
            self.budget.take_rx();
            match frames::classify(slice, used as usize) {
                // A frame of the loopback network on the wire never reaches
                // the stack (RFC 1122, 3.2.1.3).
                frames::RxFrame::Martian => {
                    self.martian += 1;
                    self.give(n);
                }
                frames::RxFrame::Frame(len) => {
                    self.frames += 1;
                    return Some((n, len));
                }
                frames::RxFrame::Invalid => {
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
    /// The probe's test of the timers: the next frames of the loopback that
    /// go nowhere (the build with the feature `probe` only sets it).
    pub drop_loop: u32,
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
            drop_loop: 0,
            scratch: [0; MAX_FRAME],
        }
    }

    pub fn begin_step(&mut self, budget: Budget) {
        self.budget = budget;
        self.reclaim();
    }

    /// Whether the step may still send a frame: its share is not spent and a
    /// buffer is free.
    pub fn can_send(&self) -> bool {
        self.budget.tx_left() > 0 && self.book.free() > 0
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
            let slice = unsafe { buffer_at(n) };
            // SAFETY: the buffer `consume` added with this token; only the
            // number of descriptors of the chain matters to the crate.
            let popped = unsafe { self.queue.pop_used(token, &[&slice[..HDR_LEN]], &mut []) };
            if popped.is_err() {
                fail("a sent buffer could not be taken back");
            }
        }
    }
}

/// The two rings as the stack's device, and the loopback beside them.
pub struct NetDevice {
    pub rx: RxRing,
    pub tx: TxRing,
    pub looped: LoopRing,
    pub mac: [u8; 6],
    /// The addresses of the interface: the frames to them stay in the loop.
    own: [[u8; 4]; 2],
    own_len: usize,
    /// The frame `stage` took and `receive` gives to the stack.
    held: Option<Held>,
    /// Frames of the wire whose checksums did not hold.
    pub bad_sum: u64,
}

/// A frame taken from a ring, on its way to the stack.
#[derive(Clone, Copy)]
enum Held {
    Wire { buffer: u16, length: usize },
    Loop { buffer: u16, length: usize },
}

impl NetDevice {
    pub fn new(rx: RxRing, tx: TxRing, mac: [u8; 6]) -> NetDevice {
        NetDevice {
            rx,
            tx,
            looped: LoopRing::new(),
            mac,
            own: [[0; 4]; 2],
            own_len: 0,
            held: None,
            bad_sum: 0,
        }
    }

    /// Takes the next frame (the loopback's first, then the wire's) out of
    /// the rings and tells whom it is for, so that the stack is handed to
    /// the set of sockets it belongs to. The frame waits for `receive`.
    /// A frame of the wire whose checksums do not hold is dropped here and
    /// counted. None when the share of the step for receiving is spent or
    /// there is no frame.
    pub fn stage(&mut self) -> Option<Dest> {
        if self.held.is_some() {
            return None;
        }
        self.reclaim_loop();
        loop {
            if self.rx.budget.rx_left() == 0 {
                return None;
            }
            if let Some((_, buffer, length)) = self.looped.pop() {
                self.rx.budget.take_rx();
                // SAFETY: the ring holds the buffer until the token drops.
                let slice = unsafe { buffer_at(buffer) };
                let dest = frames::target(&slice[HDR_LEN..HDR_LEN + length]);
                self.held = Some(Held::Loop { buffer, length });
                return Some(dest);
            }
            let (buffer, length) = self.rx.pop()?;
            // SAFETY: the buffer was popped and goes back below or when the
            // token drops.
            let slice = unsafe { buffer_at(buffer) };
            let frame = &slice[HDR_LEN..HDR_LEN + length];
            // An ARP frame of the wire that names an address of the interface
            // as its sender is a forgery (it would send the stack's frames to
            // itself out on the wire).
            if frames::arp_claims(frame, &self.own[..self.own_len]) {
                self.rx.martian += 1;
                self.rx.give(buffer);
                continue;
            }
            if !frames::verify_sums(frame) {
                self.bad_sum += 1;
                self.rx.give(buffer);
                continue;
            }
            let dest = frames::target(frame);
            self.held = Some(Held::Wire { buffer, length });
            return Some(dest);
        }
    }

    /// Puts into the loop an ARP reply for each address of the interface, so
    /// that the stack learns they are at its own MAC without asking: an ARP
    /// request is rate limited for a second after any other (smoltcp's
    /// neighbour cache), and the first connection on the loopback would wait
    /// for that second.
    pub fn seed_neighbours(&mut self) {
        self.reclaim_loop();
        for k in 0..self.own_len {
            if !self.looped.room_to_send() {
                break;
            }
            let (mac, ip) = (self.mac, self.own[k]);
            let mut f = [0u8; 42];
            f[..6].copy_from_slice(&mac);
            f[6..12].copy_from_slice(&mac);
            f[12..14].copy_from_slice(&[0x08, 0x06]);
            f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
            f[22..28].copy_from_slice(&mac);
            f[28..32].copy_from_slice(&ip);
            f[32..38].copy_from_slice(&mac);
            f[38..42].copy_from_slice(&ip);
            let Some(n) = self.tx.book.alloc() else {
                continue;
            };
            // SAFETY: the buffer is the pool's and the device does not hold it.
            let slice = unsafe { buffer_at(n) };
            slice[HDR_LEN..HDR_LEN + f.len()].copy_from_slice(&f);
            if !self.looped.push(n, f.len()) {
                self.tx.book.release(n);
            }
        }
    }

    /// The buffers of the loopback the stack is done with go back to the pool
    /// of sending.
    fn reclaim_loop(&mut self) {
        if self.looped.overflowed() {
            fail("the list of returned buffers of the loop overflowed");
        }
        while let Some(n) = self.looped.take_returned() {
            self.tx.book.release(n);
        }
    }

    /// The addresses of the interface, for the route of the frames.
    pub fn set_addresses(&mut self, own: &[[u8; 4]]) {
        self.own_len = own.len().min(self.own.len());
        self.own[..self.own_len].copy_from_slice(&own[..self.own_len]);
    }

    /// The frames the step received and sent, for the line of steps.
    pub fn step_frames(&self) -> usize {
        self.rx.received() + self.tx.sent()
    }
}

pub enum RxToken<'a> {
    Wire {
        ring: &'a mut RxRing,
        buffer: u16,
        length: usize,
    },
    Loop {
        ring: &'a LoopRing,
        buffer: u16,
        length: usize,
    },
}

impl phy::RxToken for RxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        match &self {
            RxToken::Wire {
                buffer: n, length, ..
            } => {
                // SAFETY: the buffer was popped by `pop` and goes back only
                // when the token drops, after this borrow ends.
                let slice = unsafe { buffer_at(*n) };
                f(&slice[HDR_LEN..HDR_LEN + length])
            }
            RxToken::Loop {
                buffer: n, length, ..
            } => {
                // SAFETY: the ring holds the buffer until the token drops.
                let slice = unsafe { buffer_at(*n) };
                f(&slice[HDR_LEN..HDR_LEN + length])
            }
        }
    }
}

impl Drop for RxToken<'_> {
    /// The buffer goes back to the queue (the place back to the loop) as
    /// soon as the stack is done with the frame, whether or not it read it.
    fn drop(&mut self) {
        match self {
            RxToken::Wire { ring, buffer, .. } => ring.give(*buffer),
            RxToken::Loop { ring, .. } => ring.done(),
        }
    }
}

pub struct TxToken<'a> {
    ring: &'a mut TxRing,
    looped: &'a LoopRing,
    mac: [u8; 6],
    own: [[u8; 4]; 2],
    own_len: usize,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let began = crate::split::now();
        let result = self.consume_frame(len, f);
        let spent = crate::split::now() - began;
        crate::split::record(crate::split::FRAME_TX, spent);
        crate::split::add(&crate::split::TX, spent);
        result
    }
}

impl TxToken<'_> {
    fn consume_frame<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let ring = self.ring;
        while let Some(n) = self.looped.take_returned() {
            ring.book.release(n);
        }
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
        let slice = unsafe { buffer_at(n) };
        let result = f(&mut slice[HDR_LEN..HDR_LEN + len]);
        let frame = &slice[HDR_LEN..HDR_LEN + len];
        if frames::route(frame, self.mac, &self.own[..self.own_len]) == Route::Loop {
            // The frame stays inside, in its buffer, for the next reception.
            if ring.drop_loop > 0 {
                ring.drop_loop -= 1;
                ring.book.release(n);
                return result;
            }
            if !self.looped.push(n, len) {
                ring.counters.dropped += 1;
                ring.book.release(n);
            }
            return result;
        }
        if frames::martian(frame) {
            ring.book.release(n);
            ring.counters.martian += 1;
            return result;
        }
        frames::fill_sums(&mut slice[HDR_LEN..HDR_LEN + len]);
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
        let held = self.held.take()?;
        let tx = TxToken {
            ring: &mut self.tx,
            looped: &self.looped,
            mac: self.mac,
            own: self.own,
            own_len: self.own_len,
        };
        let rx = match held {
            Held::Loop { buffer, length } => RxToken::Loop {
                ring: &self.looped,
                buffer,
                length,
            },
            Held::Wire { buffer, length } => RxToken::Wire {
                ring: &mut self.rx,
                buffer,
                length,
            },
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<TxToken<'_>> {
        self.reclaim_loop();
        // A frame of the loop that finds no place is lost, and a lost segment
        // of TCP costs a second of the retransmission timer: the frame of
        // sending waits for the step in which the loop has room.
        if self.tx.budget.tx_left() == 0 || self.tx.book.free() == 0 || !self.looped.room_to_send()
        {
            return None;
        }
        Some(TxToken {
            ring: &mut self.tx,
            looped: &self.looped,
            mac: self.mac,
            own: self.own,
            own_len: self.own_len,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        // The frames of the loopback never leave the service, so smoltcp
        // computes and checks no sum; the frames of the wire get theirs in
        // `fill_sums` and lose them in `verify_sums`.
        caps.checksum = smoltcp::phy::ChecksumCapabilities::ignored();
        caps.max_transmission_unit = MAX_FRAME;
        caps
    }
}
