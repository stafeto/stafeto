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
//! coherent (virtio_net::host); the books and the barriers are the
//! library's rings (`virtio_net::rings`), and this module adds the share of
//! a step, the counters and the loopback.

use crate::dma::{Host, net_at};
use netd::frames::{self, BUFFER_LEN, Dest, HDR_LEN, MAX_FRAME, Route};
use netd::lines::{is_dhcp_client_frame, second_device_takes};
use netd::ring::{Budget, LoopRing, QUEUE_SIZE, RX_BUFFERS, offset};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use virtio_drivers::queue::VirtQueue;
use virtio_net::rings::Sent;

/// The device that serves the sockets and the loopback; the second device
/// (`D` = 1) only runs DHCP.
pub const DEVICE: usize = 0;
pub type Queue<const D: usize> = VirtQueue<Host<D>, QUEUE_SIZE>;

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

/// Buffer `n` of the object `net`, in the half of device `D`.
///
/// # Safety
///
/// The device does not hold buffer `n` (it is not between `add` and
/// `pop_used`), and the caller holds no other reference to it.
unsafe fn buffer_at<'a, const D: usize>(n: u16) -> &'a mut [u8] {
    // SAFETY: the object `net` (its half of device `D`) is mapped read and
    // write at net_at(D) for the service's life; the offset is within it
    // (ring::offset).
    unsafe { core::slice::from_raw_parts_mut((net_at(D) + offset(n)) as *mut u8, BUFFER_LEN) }
}

/// The ring of receiving (`virtio_net::RxRing`) with the share of the step
/// and the counters of the service.
pub struct RxRing<const D: usize = 0> {
    pub ring: virtio_net::RxRing<Host<D>>,
    budget: Budget,
    dropped: u64,
    frames: u64,
    /// Frames of 127.0.0.0/8 that came from the device.
    martian: u64,
}

impl<const D: usize> RxRing<D> {
    pub fn new(queue: Queue<D>) -> RxRing<D> {
        RxRing {
            ring: virtio_net::RxRing::new(queue, net_at(D)),
            budget: Budget::new(),
            dropped: 0,
            frames: 0,
            martian: 0,
        }
    }

    /// Puts buffer `n` in the queue.
    pub(crate) fn give(&mut self, n: u16) {
        if let Err(broken) = self.ring.give(n) {
            fail(broken.text(false));
        }
    }

    /// Fills the queue with every receive buffer, at the start.
    pub fn fill(&mut self) {
        if let Err(broken) = self.ring.fill(RX_BUFFERS) {
            fail(broken.text(false));
        }
    }

    pub fn begin_step(&mut self, budget: Budget) {
        self.budget = budget;
    }

    /// Ends the step's receiving after the frame it just took.
    pub fn end_rx(&mut self) {
        self.budget.end_rx();
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
            if self.budget.rx_left() == 0 {
                return None;
            }
            let (n, used) = match self.ring.pop() {
                Ok(Some(popped)) => popped,
                Ok(None) => return None,
                Err(broken) => fail(broken.text(false)),
            };
            self.budget.take_rx();
            // SAFETY: the device returned the buffer (it is used).
            let slice = unsafe { buffer_at::<D>(n) };
            match frames::classify(slice, used) {
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

/// The ring of sending (`virtio_net::TxRing`, with its pool of buffers) with
/// the share of the step and the counters of the service.
pub struct TxRing<const D: usize = 0> {
    pub ring: virtio_net::TxRing<Host<D>>,
    budget: Budget,
    counters: Counters,
    /// The probe's test of the timers: the next frames of the loopback that
    /// go nowhere (the build with the feature `probe` only sets it).
    pub drop_loop: u32,
    /// Where a frame goes that no buffer is free for.
    scratch: [u8; MAX_FRAME],
}

impl<const D: usize> TxRing<D> {
    pub fn new(queue: Queue<D>) -> TxRing<D> {
        TxRing {
            ring: virtio_net::TxRing::new(queue, net_at(D)),
            budget: Budget::new(),
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
        self.budget.tx_left() > 0 && self.ring.book.free() > 0
    }

    /// The frames the step sent.
    pub fn sent(&self) -> usize {
        self.budget.spent().1
    }

    #[cfg_attr(not(feature = "probe"), allow(dead_code))]
    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// Puts the frame of `len` bytes in buffer `n` (the pool's, after its
    /// header) on the wire: its sums, its header, the queue.
    fn submit(&mut self, n: u16, len: usize) {
        // SAFETY: the buffer is the pool's and the device does not hold it.
        let slice = unsafe { buffer_at::<D>(n) };
        let frame = &mut slice[HDR_LEN..HDR_LEN + len];
        frames::fill_sums(frame);
        let dhcp = is_dhcp_client_frame(frame);
        match self.ring.submit(n, len) {
            Ok(Sent::Queued) => {
                self.counters.tx += 1;
                self.counters.dhcp += u64::from(dhcp);
            }
            Ok(Sent::Dropped) => self.counters.dropped += 1,
            Err(broken) => fail(broken.text(true)),
        }
    }

    /// Takes back the buffers the device sent.
    pub fn reclaim(&mut self) {
        if let Err(broken) = self.ring.reclaim() {
            fail(broken.text(true));
        }
    }
}

/// The two rings as the stack's device, and the loopback beside them.
pub struct NetDevice<const D: usize = 0> {
    pub rx: RxRing<D>,
    pub tx: TxRing<D>,
    pub looped: LoopRing,
    pub mac: [u8; 6],
    /// The addresses of the interface: the frames to them stay in the loop.
    own: [[u8; 4]; 2],
    own_len: usize,
    /// The frame `stage` took and `receive` gives to the stack.
    held: Option<Held>,
    /// A frame of the wire the stack answers with a frame of its own that
    /// did not come first in its step: it waits for the next step of
    /// receiving, whose first frame it is (`defer`).
    deferred: Option<(u16, usize)>,
    /// Frames of the wire whose checksums did not hold.
    pub bad_sum: u64,
    /// The second device's stack has a DHCP client (its server's messages
    /// reach it); false with a static address.
    pub takes_dhcp: bool,
}

/// A frame taken from a ring, on its way to the stack.
#[derive(Clone, Copy)]
enum Held {
    Wire { buffer: u16, length: usize },
    Loop { buffer: u16, length: usize },
}

impl<const D: usize> NetDevice<D> {
    pub fn new(rx: RxRing<D>, tx: TxRing<D>, mac: [u8; 6]) -> NetDevice<D> {
        NetDevice {
            rx,
            tx,
            looped: LoopRing::new(),
            mac,
            own: [[0; 4]; 2],
            own_len: 0,
            held: None,
            deferred: None,
            bad_sum: 0,
            takes_dhcp: true,
        }
    }

    /// The device as `new` makes it, built in place: the two rings hold the
    /// queues, which are big, and a value of the whole device would be
    /// another copy of them on the stack.
    ///
    /// # Safety
    ///
    /// `at` is valid for writes and exclusive.
    pub unsafe fn initialize_at(at: *mut Self, rx: RxRing<D>, tx: TxRing<D>, mac: [u8; 6]) {
        use core::ptr::addr_of_mut;
        // SAFETY: each field is in bounds and written once.
        unsafe {
            addr_of_mut!((*at).rx).write(rx);
            addr_of_mut!((*at).tx).write(tx);
            addr_of_mut!((*at).looped).write(LoopRing::new());
            addr_of_mut!((*at).mac).write(mac);
            addr_of_mut!((*at).own).write([[0; 4]; 2]);
            addr_of_mut!((*at).own_len).write(0);
            addr_of_mut!((*at).held).write(None);
            addr_of_mut!((*at).deferred).write(None);
            addr_of_mut!((*at).bad_sum).write(0);
            addr_of_mut!((*at).takes_dhcp).write(true);
        }
    }

    /// Whether a frame waits for the next step of receiving.
    pub fn has_deferred(&self) -> bool {
        self.deferred.is_some()
    }

    /// Whether the frame `stage` took, a frame of the wire for `dest`, is one
    /// the stack answers with a frame of its own (`frames::answered`;
    /// `routed`: a socket owns it). The loop's frames are not: their answers
    /// carry no sums and cost less.
    pub fn held_is_answered(&self, dest: Dest, routed: bool) -> bool {
        let Some(Held::Wire { buffer, length }) = self.held else {
            return false;
        };
        // SAFETY: the frame was popped by `stage` and waits for `receive`.
        let slice = unsafe { buffer_at::<D>(buffer) };
        frames::answered(dest, routed, &slice[HDR_LEN..HDR_LEN + length])
    }

    /// Whether the frame `stage` took came from the wire (the breakdown of the
    /// steps tells the frames of the wire from those of the loopback).
    #[allow(dead_code)] // read by the feature `split` only.
    pub fn held_is_wire(&self) -> bool {
        matches!(self.held, Some(Held::Wire { .. }))
    }

    /// Drops the frame `stage` took without showing it to the stack: its
    /// buffer goes back where it came from.
    pub fn discard_held(&mut self) {
        match self.held.take() {
            Some(Held::Wire { buffer, .. }) => self.rx.give(buffer),
            Some(Held::Loop { .. }) => self.looped.done(),
            None => {}
        }
    }

    /// Puts the frame `stage` took aside for the next step of receiving.
    pub fn defer_held(&mut self) {
        if let Some(Held::Wire { buffer, length }) = self.held.take() {
            self.deferred = Some((buffer, length));
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
        if self.rx.budget.rx_left() == 0 {
            return None;
        }
        // The frame put aside by the step before comes first, before the
        // loop's: it passed the checks below when it was taken.
        if let Some((buffer, length)) = self.deferred.take() {
            self.rx.budget.take_rx();
            // SAFETY: the buffer was popped and has been held since.
            let slice = unsafe { buffer_at::<D>(buffer) };
            let dest = frames::target(&slice[HDR_LEN..HDR_LEN + length]);
            self.held = Some(Held::Wire { buffer, length });
            return Some(dest);
        }
        loop {
            if self.rx.budget.rx_left() == 0 {
                return None;
            }
            if let Some((_, buffer, length)) = self.looped.pop() {
                self.rx.budget.take_rx();
                // SAFETY: the ring holds the buffer until the token drops.
                let slice = unsafe { buffer_at::<D>(buffer) };
                let dest = frames::target(&slice[HDR_LEN..HDR_LEN + length]);
                self.held = Some(Held::Loop { buffer, length });
                return Some(dest);
            }
            let (buffer, length) = self.rx.pop()?;
            // SAFETY: the buffer was popped and goes back below or when the
            // token drops.
            let slice = unsafe { buffer_at::<D>(buffer) };
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
            // The second device only runs DHCP (lines::second_device_takes).
            if D != DEVICE && !second_device_takes(frame, self.takes_dhcp) {
                self.rx.dropped += 1;
                self.rx.give(buffer);
                continue;
            }
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
            let Some(n) = self.tx.ring.book.alloc() else {
                continue;
            };
            // SAFETY: the buffer is the pool's and the device does not hold it.
            let slice = unsafe { buffer_at::<D>(n) };
            slice[HDR_LEN..HDR_LEN + f.len()].copy_from_slice(&f);
            if !self.looped.push(n, f.len()) {
                self.tx.ring.book.release(n);
            }
        }
    }

    /// Queues an ARP request on the wire for the first of `targets` that the
    /// share of the step and the pool of buffers allow, from the first address
    /// of the interface (`sender`): the answers fill the stack's neighbour
    /// cache, so that the first datagram or SYN to the gateway or a name
    /// server does not wait for smoltcp's one request a second. Gives the
    /// number of requests queued; a step of sending has a share of
    /// `STEP_TX` frames, so the caller goes on with the rest in the next step.
    pub fn ask_neighbours(&mut self, sender: [u8; 4], targets: &[[u8; 4]]) -> usize {
        let mut queued = 0;
        for &target in targets {
            if !self.tx.can_send() || !self.tx.budget.take_tx() {
                break;
            }
            let Some(n) = self.tx.ring.book.alloc() else {
                break;
            };
            let request = frames::arp_request(self.mac, sender, target);
            // SAFETY: the buffer is the pool's and the device does not hold it.
            let slice = unsafe { buffer_at::<D>(n) };
            slice[HDR_LEN..HDR_LEN + request.len()].copy_from_slice(&request);
            self.tx.submit(n, request.len());
            queued += 1;
        }
        queued
    }

    /// The buffers of the loopback the stack is done with go back to the pool
    /// of sending.
    fn reclaim_loop(&mut self) {
        if self.looped.overflowed() {
            fail("the list of returned buffers of the loop overflowed");
        }
        while let Some(n) = self.looped.take_returned() {
            self.tx.ring.book.release(n);
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

pub enum RxToken<'a, const D: usize = 0> {
    Wire {
        ring: &'a mut RxRing<D>,
        buffer: u16,
        length: usize,
    },
    Loop {
        ring: &'a LoopRing,
        buffer: u16,
        length: usize,
    },
}

impl<const D: usize> phy::RxToken for RxToken<'_, D> {
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
                let slice = unsafe { buffer_at::<D>(*n) };
                f(&slice[HDR_LEN..HDR_LEN + length])
            }
            RxToken::Loop {
                buffer: n, length, ..
            } => {
                // SAFETY: the ring holds the buffer until the token drops.
                let slice = unsafe { buffer_at::<D>(*n) };
                f(&slice[HDR_LEN..HDR_LEN + length])
            }
        }
    }
}

impl<const D: usize> Drop for RxToken<'_, D> {
    /// The buffer goes back to the queue (the place back to the loop) as
    /// soon as the stack is done with the frame, whether or not it read it.
    fn drop(&mut self) {
        match self {
            RxToken::Wire { ring, buffer, .. } => ring.give(*buffer),
            RxToken::Loop { ring, .. } => ring.done(),
        }
    }
}

pub struct TxToken<'a, const D: usize = 0> {
    ring: &'a mut TxRing<D>,
    looped: &'a LoopRing,
    mac: [u8; 6],
    own: [[u8; 4]; 2],
    own_len: usize,
}

impl<const D: usize> phy::TxToken for TxToken<'_, D> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let began = crate::split::now();
        let (result, wire) = self.consume_frame(len, f);
        let spent = crate::split::now() - began;
        let part = if wire {
            crate::split::FRAME_TX_WIRE
        } else {
            crate::split::FRAME_TX
        };
        crate::split::record(part, spent);
        crate::split::add(&crate::split::TX, spent);
        result
    }
}

impl<const D: usize> TxToken<'_, D> {
    /// The frame built and where it went: true for the wire.
    fn consume_frame<R, F>(self, len: usize, f: F) -> (R, bool)
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let ring = self.ring;
        while let Some(n) = self.looped.take_returned() {
            ring.ring.book.release(n);
        }
        let spare = len <= MAX_FRAME && ring.budget.take_tx();
        let n = if spare { ring.ring.book.alloc() } else { None };
        let Some(n) = n else {
            // No buffer or no share of the step left: the stack builds the
            // frame where it harms nothing, and the protocol repeats it
            // (ARP and the echo reply are retried by their peers).
            ring.counters.dropped += 1;
            let len = len.min(MAX_FRAME);
            return (f(&mut ring.scratch[..len]), false);
        };
        // SAFETY: the buffer is the pool's and the device does not hold it.
        let slice = unsafe { buffer_at::<D>(n) };
        let result = f(&mut slice[HDR_LEN..HDR_LEN + len]);
        let frame = &slice[HDR_LEN..HDR_LEN + len];
        if frames::route(frame, self.mac, &self.own[..self.own_len]) == Route::Loop {
            // The frame stays inside, in its buffer, for the next reception.
            if ring.drop_loop > 0 {
                ring.drop_loop -= 1;
                ring.ring.book.release(n);
                return (result, false);
            }
            if !self.looped.push(n, len) {
                ring.counters.dropped += 1;
                ring.ring.book.release(n);
            }
            return (result, false);
        }
        if frames::martian(frame) {
            ring.ring.book.release(n);
            ring.counters.martian += 1;
            return (result, false);
        }
        ring.submit(n, len);
        (result, true)
    }
}

impl<const D: usize> phy::Device for NetDevice<D> {
    type RxToken<'a>
        = RxToken<'a, D>
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a, D>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(RxToken<'_, D>, TxToken<'_, D>)> {
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

    fn transmit(&mut self, _timestamp: Instant) -> Option<TxToken<'_, D>> {
        self.reclaim_loop();
        // A frame of the loop that finds no place is lost, and a lost segment
        // of TCP costs a second of the retransmission timer: the frame of
        // sending waits for the step in which the loop has room.
        if self.tx.budget.tx_left() == 0
            || self.tx.ring.book.free() == 0
            || !self.looped.room_to_send()
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
