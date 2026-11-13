// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The wire of the switch when the device is an ENA: one queue pair
//! (`ena::Io`) between the device and the rings of the stack's lane, with
//! the books of the buffers. The switch thread of `ena_switch.rs` calls
//! `step` once a step; everything here is a decision on buffers and rings
//! and runs on the host against the model of the device.
//!
//! The buffers are the object `net` as for Virtio: 512 of `BUFFER_LEN`
//! bytes, 0 to 255 for receiving and 256 to 511 for sending, a frame lying
//! `HDR_LEN` bytes into its buffer (the header stays zero: the stack checks
//! the sums itself). A buffer of receiving is the device's from the moment
//! it is in the queue until its completion, then the stack's until it comes
//! back through `rx_back`; a buffer of sending is the pool's, lent to the
//! stack, the device's from its submission to its completion. The admin
//! side tells the pair is up or down by an epoch (`sync`): an odd epoch is
//! down (a reset is in progress) and the queues are not touched; the next
//! even one is a fresh pair, over which every buffer the device held is
//! given again (receiving) or taken back to the pool (sending, as sent
//! without a confirmation).
//!
//! One step makes at most `SWITCH_BACK` buffers of each kind given back,
//! `SWITCH_TX` frames submitted, `RECLAIM_STEP` completions taken, `SWITCH_RX`
//! frames received and two doorbells; each call of the library makes at most
//! one register access (a head write after half a queue, a doorbell).
//! `Step::bound_accesses` is that sum on constants.

use crate::frames::{self, HDR_LEN, RxFrame};
use crate::ring::{
    RECLAIM_STEP, RX_AHEAD, RX_BUFFERS, SWITCH_BACK, SWITCH_RX, SWITCH_TX, TX_SHARE,
};
use crate::spsc::{Spsc, pack_frame, unpack_frame};
use core::sync::atomic::{AtomicBool, Ordering};
use ena::io::{Buffers, Info, Io};
use ena::{Platform, Region};
use virtio_net::books::{BUFFERS, TxBook};

/// The rings of the lane the wire serves.
pub struct Rings<'a> {
    pub rx_ready: &'a Spsc<256>,
    pub rx_back: &'a Spsc<256>,
    pub tx_sub: &'a Spsc<256>,
    pub tx_supply: &'a Spsc<256>,
    pub tx_back: &'a Spsc<256>,
    /// The stack found no buffer of sending free (the switch wakes it when it
    /// lends some).
    pub starved: &'a AtomicBool,
}

/// What a step did, for the switch thread's decisions after it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Step {
    /// Frames were put in the ring of the stack: wake it.
    pub passed: bool,
    /// Buffers of sending were lent to a stack that was out of them: wake it.
    pub lent: bool,
    /// Another step follows at once.
    pub more: bool,
    /// A completion the pair does not know: the queue is out of step, the
    /// admin side must reset the device.
    pub broken: bool,
}

/// The counters of the wire since the start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub rx: u64,
    pub tx: u64,
    /// Frames dropped on the way in (no room in the lane, not a frame, in pieces).
    pub rx_dropped: u64,
    /// Frames of the stack that went nowhere (the pair was down, or the queue full).
    pub tx_dropped: u64,
    /// Buffers given back twice, the stack's mistake.
    pub doubles: u64,
    /// The pairs that were made (the first and each after a reset).
    pub builds: u32,
}

/// The accesses to the registers of the device the longest step makes: two
/// doorbells, a head write for receiving, and one for sending.
pub const ACCESSES_PER_STEP: usize = 4;

pub struct Wire<P: Platform + Clone> {
    p: P,
    mem: Region,
    bufs: Buffers,
    io: Option<Io<P>>,
    epoch: u32,
    /// The buffers of receiving the device holds or is to hold: every one the
    /// stack does not.
    rx_out: [u64; RX_BUFFERS / 64],
    /// The buffers of sending in the device's queue (`n - RX_BUFFERS`).
    tx_out: [u64; RX_BUFFERS / 64],
    book: TxBook,
    counts: Counts,
}

fn bit(map: &[u64], n: usize) -> bool {
    map[n / 64] >> (n % 64) & 1 != 0
}

fn set(map: &mut [u64], n: usize, on: bool) {
    if on {
        map[n / 64] |= 1 << (n % 64);
    } else {
        map[n / 64] &= !(1 << (n % 64));
    }
}

impl<P: Platform + Clone> Wire<P> {
    /// The wire over the queues in `mem` (from `ena::io::IO_AT`) and the buffers
    /// `bufs`, which the device addresses as `bufs.pa`. Down until `sync` gets an even epoch (the first is 1, down).
    pub fn new(p: P, mem: Region, bufs: Buffers) -> Wire<P> {
        Wire {
            p,
            mem,
            bufs,
            io: None,
            epoch: 1,
            rx_out: [u64::MAX; RX_BUFFERS / 64],
            tx_out: [0; RX_BUFFERS / 64],
            book: TxBook::new(),
            counts: Counts::default(),
        }
    }

    pub fn counts(&self) -> Counts {
        self.counts
    }

    pub fn is_up(&self) -> bool {
        self.io.is_some()
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The admin side's word: `epoch` and, when it is even, what the device
    /// told of the pair. A new epoch makes a fresh pair; the same one does nothing.
    pub fn sync(&mut self, epoch: u32, info: Info) {
        if epoch == self.epoch {
            return;
        }
        let had = self.io.take().is_some();
        self.epoch = epoch;
        // The buffers of sending the old pair held went without a confirmation.
        if had {
            for i in 0..RX_BUFFERS {
                if bit(&self.tx_out, i) {
                    set(&mut self.tx_out, i, false);
                    self.book.release((RX_BUFFERS + i) as u16);
                }
            }
        }
        if epoch % 2 == 1 {
            return;
        }
        // SAFETY: the owner of the wire promised the memory of `mem` and `bufs`
        // for as long as it lives (the caller of the first `new` of this pair), and
        // the previous pair of the same queues was dropped above.
        let mut io = unsafe { Io::new(self.p.clone(), self.mem, self.bufs, info) };
        for n in 0..RX_BUFFERS {
            if bit(&self.rx_out, n) && !io.rx_give(n as u16) {
                set(&mut self.rx_out, n, false);
            }
        }
        io.rx_bell();
        self.io = Some(io);
        self.counts.builds += 1;
    }

    /// A buffer of receiving back from the stack: it goes into the queue when the
    /// pair is up, and at the next pair otherwise.
    fn rx_free(&mut self, n: u16) {
        let i = usize::from(n);
        if bit(&self.rx_out, i) {
            self.counts.doubles += 1;
            return;
        }
        set(&mut self.rx_out, i, true);
        if let Some(io) = self.io.as_mut()
            && !io.rx_give(n)
        {
            set(&mut self.rx_out, i, false);
        }
    }

    fn buffer(&self, n: u16) -> &'static mut [u8] {
        // SAFETY: the device returned the buffer (its completion came) or never
        // held it, and the caller of `step` is the only thread that touches the
        // buffers of receiving before they reach the lane.
        unsafe { virtio_net::rings::buffer_at(self.bufs.va, n) }
    }

    /// One step over `lane`: what the stack gave goes to the queues, the
    /// completions of sending free their buffers, buffers are lent, the frames
    /// of the wire go to the stack, and the doorbells ring.
    pub fn step(&mut self, lane: &Rings<'_>) -> Step {
        let mut out = Step::default();
        // What the stack gave back.
        for _ in 0..SWITCH_BACK {
            let Some(word) = lane.rx_back.pop() else {
                break;
            };
            let n = word as u16;
            if usize::from(n) >= RX_BUFFERS {
                // A buffer of sending that came back through the other ring.
                self.book.release(n);
            } else {
                self.rx_free(n);
            }
        }
        for _ in 0..SWITCH_BACK {
            let Some(word) = lane.tx_back.pop() else {
                break;
            };
            self.book.release(word as u16);
        }
        for _ in 0..SWITCH_TX {
            let Some(word) = lane.tx_sub.pop() else {
                break;
            };
            let (n, len, _) = unpack_frame(word);
            let taken = usize::from(n) >= RX_BUFFERS
                && usize::from(n) < BUFFERS
                && self.io.as_mut().is_some_and(|io| io.tx_submit(n, len));
            if taken {
                set(&mut self.tx_out, usize::from(n) - RX_BUFFERS, true);
                self.counts.tx += 1;
            } else {
                self.book.release(n);
                self.counts.tx_dropped += 1;
            }
        }
        // What the device completed.
        let mut done = [0u16; RECLAIM_STEP];
        let mut taken = 0;
        if let Some(io) = self.io.as_mut() {
            match io.tx_reclaim(RECLAIM_STEP, |n| {
                done[taken] = n;
                taken += 1;
            }) {
                Ok(_) => {}
                Err(_) => out.broken = true,
            }
        }
        for &n in &done[..taken] {
            let i = usize::from(n).wrapping_sub(RX_BUFFERS);
            if i < RX_BUFFERS && bit(&self.tx_out, i) {
                set(&mut self.tx_out, i, false);
                self.book.release(n);
            } else {
                out.broken = true;
            }
        }
        // Buffers of sending for the stack.
        let mut lent = false;
        while lane.tx_supply.len() < TX_SHARE {
            let Some(n) = self.book.alloc() else {
                break;
            };
            if !lane.tx_supply.push(u32::from(n)) {
                self.book.release(n);
                break;
            }
            lent = true;
        }
        out.lent = lent && !lane.tx_supply.is_empty() && lane.starved.swap(false, Ordering::AcqRel);
        // The frames of the wire.
        let room = RX_AHEAD.saturating_sub(lane.rx_ready.len());
        let mut budget = SWITCH_RX.min(room);
        while budget > 0 {
            let popped = match self.io.as_mut() {
                Some(io) => io.rx_pop(),
                None => Ok(None),
            };
            let rx = match popped {
                Ok(Some(rx)) => rx,
                Ok(None) => break,
                Err(_) => {
                    out.broken = true;
                    break;
                }
            };
            budget -= 1;
            let i = usize::from(rx.n);
            if !bit(&self.rx_out, i) {
                // A completion of a buffer the device does not hold.
                out.broken = true;
                continue;
            }
            set(&mut self.rx_out, i, false);
            let slice = self.buffer(rx.n);
            slice[..HDR_LEN].fill(0);
            let used = HDR_LEN + usize::from(rx.len);
            let frame = rx.whole && rx.len > 0 && used <= slice.len();
            match frames::classify(slice, used) {
                RxFrame::Frame(len)
                    if frame && lane.rx_ready.push(pack_frame(rx.n, len as u16, false)) =>
                {
                    self.counts.rx += 1;
                    out.passed = true;
                }
                _ => {
                    self.counts.rx_dropped += 1;
                    self.rx_free(rx.n);
                }
            }
        }
        if let Some(io) = self.io.as_mut() {
            io.rx_bell();
            io.tx_bell();
            out.more = RX_AHEAD > lane.rx_ready.len() && io.rx_ready()
                || !lane.tx_sub.is_empty()
                || !lane.rx_back.is_empty()
                || !lane.tx_back.is_empty();
        }
        out
    }

    /// The end of a run: lets the device interrupt for the next completion of
    /// receiving (the vector is masked after each one), then looks at the queue
    /// once more. True when a frame came in between and a step must follow.
    pub fn settle(&mut self) -> bool {
        match self.io.as_mut() {
            Some(io) => {
                io.unmask_rx();
                io.rx_ready()
            }
            None => false,
        }
    }

    /// Whether a completion of receiving waits (a poll on a timer looks).
    pub fn rx_ready(&self) -> bool {
        self.io.as_ref().is_some_and(|io| io.rx_ready())
    }
}

/// Whether the MSI-X table of the function is where the driver writes it: in BAR 0 at
/// `offset` (the t4g's ENA has it at 0x2000, which the capability says), with `vectors`
/// entries at least. The reason when not.
pub fn msix_table(m: &pci::Msix, offset: u32, vectors: u16) -> Result<(), &'static str> {
    if m.bar != 0 {
        Err("the table is not in BAR 0")
    } else if m.offset != offset && !cfg!(feature = "break-msix-offset") {
        Err("the table is not at the offset the driver writes")
    } else if m.vectors < vectors {
        Err("the table has too few vectors")
    } else {
        Ok(())
    }
}

/// The kernel's answer to the acknowledgement of a vector's interrupt
/// (`irq_ack` of an event of the MSI device): the ITS commands of the event
/// may not have run yet, and the acknowledgement says `WOULD_BLOCK` until they
/// have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ack {
    Done,
    NotYet,
    /// The binding is gone: nothing to wait for.
    Gone,
}

/// A vector of the pair as the switch thread keeps it: an interrupt came and
/// is not acknowledged yet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Vector {
    pending: bool,
    /// Interrupts counted, and acknowledgements that said not yet.
    pub fired: u64,
    pub not_yet: u64,
}

impl Vector {
    pub const fn new() -> Vector {
        Vector {
            pending: false,
            fired: 0,
            not_yet: 0,
        }
    }

    /// An interrupt of the vector came.
    pub fn interrupted(&mut self) {
        self.pending = true;
        self.fired += 1;
    }

    /// Whether an acknowledgement is owed (a retry on the next step, never a spin).
    pub fn owed(&self) -> bool {
        self.pending
    }

    /// The answer of an acknowledgement. True when the device's vector may be
    /// unmasked now: only after `Done`. After `NotYet` the acknowledgement stays
    /// owed for the next step.
    pub fn answered(&mut self, answer: Ack) -> bool {
        match answer {
            Ack::Done => {
                self.pending = false;
                true
            }
            Ack::NotYet if cfg!(feature = "break-would-block") => {
                self.pending = false;
                true
            }
            Ack::NotYet => {
                self.not_yet += 1;
                false
            }
            Ack::Gone => {
                self.pending = false;
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ena::device::Event;
    use ena::io::{BUFFER_LEN, IO_END};
    use ena::model::{Model, Scenario, region};

    const MS: u64 = 1_000_000;
    const MSI: [Option<(u64, u32)>; 2] = [Some((0x0801_0040, 5)), Some((0x0801_0040, 6))];

    struct Lane {
        rx_ready: Spsc<256>,
        rx_back: Spsc<256>,
        tx_sub: Spsc<256>,
        tx_supply: Spsc<256>,
        tx_back: Spsc<256>,
        starved: AtomicBool,
    }

    impl Lane {
        fn new() -> Lane {
            Lane {
                rx_ready: Spsc::new(),
                rx_back: Spsc::new(),
                tx_sub: Spsc::new(),
                tx_supply: Spsc::new(),
                tx_back: Spsc::new(),
                starved: AtomicBool::new(false),
            }
        }

        fn rings(&self) -> Rings<'_> {
            Rings {
                rx_ready: &self.rx_ready,
                rx_back: &self.rx_back,
                tx_sub: &self.tx_sub,
                tx_supply: &self.tx_supply,
                tx_back: &self.tx_back,
                starved: &self.starved,
            }
        }
    }

    struct Rig {
        model: Model,
        ena: ena::Ena<Model>,
        wire: Wire<Model>,
        lane: &'static Lane,
        bufs: Buffers,
    }

    fn arp(seed: u8) -> Vec<u8> {
        let mut f = vec![0u8; 60];
        f[..6].fill(0xFF);
        f[6..12].copy_from_slice(&[2, 0, 0, 0, 0, seed]);
        f[12..14].copy_from_slice(&[0x08, 0x06]);
        f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        f
    }

    fn rig() -> Rig {
        let mem = region(IO_END, 0x4_3000_0000);
        let model = Model::new(mem, 0, Scenario::default());
        let buffers = region(512 * BUFFER_LEN, 0x4_3200_0000);
        model.add_region(buffers);
        model.set_vectors(MSI);
        let bufs = Buffers {
            va: buffers.va,
            pa: buffers.pa,
            count: 512,
        };
        // SAFETY: the region is the model's heap block, which lives on.
        let mut ena = unsafe { ena::Ena::open(model.platform(), mem, 0) }.unwrap();
        ena.set_data_path(bufs, Some(ena::model::MSIX_TABLE))
            .unwrap();
        let wire = Wire::new(model.platform(), mem, bufs);
        let mut r = Rig {
            model,
            ena,
            wire,
            lane: Box::leak(Box::new(Lane::new())),
            bufs,
        };
        r.run(2_000);
        let info = r.ena.io_info().expect("up");
        r.wire.sync(2, info);
        assert!(r.wire.is_up());
        // The first step lends the buffers of sending.
        r.step();
        r
    }

    impl Rig {
        fn run(&mut self, ms: u64) {
            for _ in 0..ms {
                for _ in 0..200 {
                    if matches!(self.ena.poll(), Event::Idle) {
                        break;
                    }
                }
                self.model.advance(MS);
            }
        }

        fn step(&mut self) -> Step {
            self.wire.step(&self.lane.rings())
        }

        fn buffer(&self, n: u16) -> &'static mut [u8] {
            // SAFETY: inside the buffers' block, nobody else touches it in the test.
            unsafe { virtio_net::rings::buffer_at(self.bufs.va, n) }
        }
    }

    #[test]
    fn a_frame_from_the_wire_reaches_the_lane_with_its_bytes_and_the_buffer_comes_back() {
        let mut r = rig();
        let f = arp(7);
        assert!(r.model.inject(&f));
        let s = r.step();
        assert!(s.passed && !s.broken);
        let (n, len, sum) = unpack_frame(r.lane.rx_ready.pop().unwrap());
        assert_eq!((usize::from(len), sum), (60, false));
        assert_eq!(&r.buffer(n)[HDR_LEN..HDR_LEN + 60], &f[..]);
        // The stack gives the buffer back, and it is in the queue again.
        r.lane.rx_back.push(u32::from(n));
        r.step();
        assert!(r.model.inject(&f), "the buffer is the device's again");
        assert_eq!(r.wire.counts().doubles, 0);
    }

    #[test]
    fn six_hundred_frames_both_ways_go_through_two_wraps_of_each_queue() {
        let mut r = rig();
        for i in 0..600u32 {
            let f = arp(i as u8);
            assert!(r.model.inject(&f), "frame {i}");
            r.step();
            let word = r.lane.rx_ready.pop().expect("a frame");
            let (n, len, _) = unpack_frame(word);
            assert_eq!(&r.buffer(n)[HDR_LEN..HDR_LEN + usize::from(len)], &f[..]);
            r.lane.rx_back.push(u32::from(n));
            // A frame to send: a buffer the switch lent.
            let b = r.lane.tx_supply.pop().expect("a buffer of sending");
            assert!(b as usize >= 256);
            r.buffer(b as u16)[HDR_LEN..HDR_LEN + 60].copy_from_slice(&f);
            r.lane.tx_sub.push(pack_frame(b as u16, 60, false));
            r.step();
            r.step();
            assert_eq!(r.model.sent_frames().last().unwrap(), &f, "frame {i}");
        }
        assert_eq!(r.model.violations(), Vec::<String>::new());
        let c = r.wire.counts();
        assert_eq!((c.rx, c.tx, c.tx_dropped, c.rx_dropped), (600, 600, 0, 0));
        // The pool is whole again: all 256 buffers of sending are lent or free.
        assert_eq!(r.lane.tx_supply.len(), 256);
    }

    #[test]
    fn the_stack_that_ran_out_of_buffers_is_told_when_some_are_lent() {
        let mut r = rig();
        r.step();
        while r.lane.tx_supply.pop().is_some() {}
        r.lane.starved.store(true, Ordering::SeqCst);
        let b = 300;
        r.lane.tx_back.push(b);
        let s = r.step();
        assert!(s.lent);
    }

    #[test]
    fn one_step_makes_at_most_four_register_writes() {
        let mut r = rig();
        for i in 0..8 {
            r.model.inject(&arp(i));
        }
        for _ in 0..16 {
            let b = r.lane.tx_supply.pop().unwrap();
            r.buffer(b as u16)[HDR_LEN..HDR_LEN + 60].copy_from_slice(&arp(1));
            r.lane.tx_sub.push(pack_frame(b as u16, 60, false));
        }
        let before = r.model.0.borrow().reg_writes;
        let s = r.step();
        let after = r.model.0.borrow().reg_writes;
        assert!(s.passed);
        assert!(
            after - before <= ACCESSES_PER_STEP as u32,
            "{} writes",
            after - before
        );
        assert_eq!(r.model.0.borrow().reg_reads, r.model.0.borrow().reg_reads);
    }

    #[test]
    fn a_frame_the_lane_has_no_room_for_is_dropped_and_its_buffer_goes_back() {
        let mut r = rig();
        for i in 0..40u8 {
            r.model.inject(&arp(i));
        }
        for _ in 0..8 {
            r.step();
        }
        // The lane holds RX_AHEAD and no more.
        assert_eq!(r.lane.rx_ready.len(), RX_AHEAD);
        // Taking them all out lets the rest in.
        while let Some(w) = r.lane.rx_ready.pop() {
            r.lane.rx_back.push(w & 0xFFFF);
        }
        for _ in 0..8 {
            r.step();
        }
        assert_eq!(r.lane.rx_ready.len(), 40 - RX_AHEAD);
    }

    #[test]
    fn a_reset_takes_the_buffers_of_sending_back_and_regives_the_ones_of_receiving() {
        let mut r = rig();
        // Two frames of the stack are in the device's queue, one buffer of
        // receiving is with the stack.
        for _ in 0..2 {
            let b = r.lane.tx_supply.pop().unwrap();
            r.buffer(b as u16)[HDR_LEN..HDR_LEN + 60].copy_from_slice(&arp(1));
            r.lane.tx_sub.push(pack_frame(b as u16, 60, false));
        }
        r.model.inject(&arp(3));
        // The frame of the wire is taken (the stack holds its buffer); the two of
        // sending are submitted, and the model does not complete them in time.
        r.step();
        let held = unpack_frame(r.lane.rx_ready.pop().unwrap()).0;
        let in_flight = r.wire.counts().tx;
        assert_eq!(in_flight, 2);
        // The admin side starts a reset.
        r.wire.sync(3, ena::io::Info::default());
        assert!(!r.wire.is_up());
        let s = r.step();
        assert!(!s.passed);
        let free_before = r.lane.tx_supply.len();
        // A frame of the stack while the pair is down goes nowhere, and its
        // buffer is the pool's again.
        let b = r.lane.tx_supply.pop().unwrap();
        r.lane.tx_sub.push(pack_frame(b as u16, 60, false));
        r.step();
        assert_eq!(r.wire.counts().tx_dropped, 1);
        assert_eq!(
            r.lane.tx_supply.len(),
            free_before,
            "the pool lends it again"
        );
        // The reset ends: a fresh pair, over the same buffers.
        r.run(3_000);
        r.ena.request_reset(ena::regs::RESET_NORMAL);
        r.run(5_000);
        let info = r.ena.io_info().expect("up again");
        r.wire.sync(4, info);
        assert!(r.wire.is_up());
        assert_eq!(r.wire.counts().builds, 2);
        // 255 buffers of receiving are in the queue (the stack holds one).
        let mut taken = 0;
        while r.model.inject(&arp(taken as u8)) {
            taken += 1;
            if taken > 300 {
                break;
            }
        }
        assert_eq!(taken, 255);
        // The buffers the first pair held in flight went back to the pool.
        r.step();
        assert_eq!(r.lane.tx_supply.len(), 256);
        r.lane.rx_back.push(u32::from(held));
        r.step();
        assert!(
            r.model.inject(&arp(9)),
            "the stack's buffer joined the queue"
        );
        assert_eq!(r.model.violations(), Vec::<String>::new());
    }

    #[test]
    fn a_buffer_given_back_twice_is_counted_and_not_queued_twice() {
        let mut r = rig();
        r.model.inject(&arp(1));
        r.step();
        let n = unpack_frame(r.lane.rx_ready.pop().unwrap()).0;
        r.lane.rx_back.push(u32::from(n));
        r.lane.rx_back.push(u32::from(n));
        r.step();
        assert_eq!(r.wire.counts().doubles, 1);
    }

    #[test]
    fn a_frame_that_took_two_descriptors_is_dropped_and_its_buffer_regiven() {
        let mut r = rig();
        r.model.inject(&arp(1));
        // The completion says the frame is not the last of its descriptors.
        let at = r.model_cq_status_at(0);
        // SAFETY: the first entry of the completion queue in the model's block.
        unsafe {
            let w = core::ptr::read(at as *const u32);
            core::ptr::write(at as *mut u32, w & !ena::io::RX_STATUS_LAST);
        }
        let s = r.step();
        assert!(!s.passed);
        assert_eq!(r.wire.counts().rx_dropped, 1);
    }

    impl Rig {
        fn model_cq_status_at(&self, slot: usize) -> usize {
            self.ena_mem_va() + ena::io::RX_CQ_AT + slot * ena::io::RX_CDESC
        }

        fn ena_mem_va(&self) -> usize {
            self.wire.mem.va
        }
    }

    #[test]
    fn the_acknowledgement_that_would_block_is_retried_and_the_vector_not_unmasked() {
        let mut v = Vector::new();
        v.interrupted();
        assert!(v.owed());
        assert!(
            !v.answered(Ack::NotYet),
            "no unmask before the mapping is done"
        );
        assert!(v.owed(), "the acknowledgement stays owed");
        assert!(!v.answered(Ack::NotYet));
        assert_eq!(v.not_yet, 2);
        assert!(v.answered(Ack::Done));
        assert!(!v.owed());
        v.interrupted();
        assert!(!v.answered(Ack::Gone));
        assert!(!v.owed());
        assert_eq!((v.fired, v.not_yet), (2, 2));
    }

    fn msix(bar: u8, offset: u32, vectors: u16) -> pci::Msix {
        pci::Msix {
            at: 0x70,
            vectors,
            bar,
            offset,
            pba_bar: bar,
            pba_offset: 0x3000,
        }
    }

    #[test]
    fn the_table_must_be_in_bar_0_at_0x2000_with_two_vectors() {
        assert_eq!(msix_table(&msix(0, 0x2000, 9), 0x2000, 2), Ok(()));
        assert!(msix_table(&msix(4, 0x2000, 9), 0x2000, 2).is_err());
        assert!(msix_table(&msix(0, 0x0, 9), 0x2000, 2).is_err());
        assert!(msix_table(&msix(0, 0x2000, 1), 0x2000, 2).is_err());
    }

    #[test]
    fn settle_unmasks_the_vector_and_finds_a_frame_that_came_in_between() {
        let mut r = rig();
        r.model.inject(&arp(1));
        assert!(r.wire.settle(), "a frame waits: another step");
        r.step();
        r.lane.rx_ready.pop();
        assert!(!r.wire.settle());
        assert!(r.model.fired().iter().filter(|f| f.1 == 6).count() <= 1);
        r.model.inject(&arp(2));
        assert_eq!(
            r.model.fired().iter().filter(|f| f.1 == 6).count(),
            1,
            "unmasked, the next frame raises the vector"
        );
    }
}
