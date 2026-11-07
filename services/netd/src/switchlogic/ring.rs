// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The switch's side of a consumer's ring object. The switch keeps its own
//! `fill_tail`, `done_head` and `tx_tail`; the three indices the consumer
//! writes are read once per step into locals (`poll`), and every rule of
//! the layout is checked on those copies. A violation breaks the ring: it
//! is told once and the ring takes and gives nothing after it.

use core::sync::atomic::{AtomicU32, Ordering, fence};
use proto_net::switch::{self as sw, CELL, Layout};

/// Memory the switch reads and writes: the mapped ring object.
#[derive(Clone, Copy)]
pub struct Mem {
    base: *mut u8,
    len: usize,
}

// SAFETY: the memory is shared on purpose; every access below is a copy or an atomic word.
unsafe impl Send for Mem {}

impl Mem {
    /// # Safety
    /// `base` is valid for reads and writes of `len` bytes and 4-aligned for as long as
    /// the `Mem` or a copy is used.
    pub const unsafe fn new(base: *mut u8, len: usize) -> Mem {
        Mem { base, len }
    }

    fn word(&self, at: usize) -> &AtomicU32 {
        assert!(at.is_multiple_of(4) && at + 4 <= self.len);
        // SAFETY: in bounds and aligned (checked); the word is atomic.
        unsafe { &*(self.base.add(at) as *const AtomicU32) }
    }

    pub fn load(&self, at: usize) -> u32 {
        self.word(at).load(Ordering::Acquire)
    }

    pub fn store(&self, at: usize, v: u32) {
        self.word(at).store(v, Ordering::Release)
    }

    pub fn read(&self, at: usize, out: &mut [u8]) {
        assert!(at + out.len() <= self.len);
        // SAFETY: in bounds; the buffers do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(self.base.add(at), out.as_mut_ptr(), out.len()) }
    }

    pub fn write(&self, at: usize, data: &[u8]) {
        assert!(at + data.len() <= self.len);
        // SAFETY: in bounds; the buffers do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), self.base.add(at), data.len()) }
    }
}

/// The rule a consumer broke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    Fill,
    Done,
    Tx,
    Cell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll {
    Live,
    /// The ring broke now; told once.
    Broke(Violation),
    Broken,
}

/// What one take from TX gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx {
    Empty,
    /// A frame of this length is in the buffer.
    Frame(usize),
    /// An entry with flags or a spare or a length the cell cannot hold: dropped.
    Refused,
}

pub struct ConsumerRing {
    mem: Mem,
    pub layout: Layout,
    fill_tail: u32,
    done_head: u32,
    tx_tail: u32,
    fill_head: u32,
    tx_head: u32,
    done_tail: u32,
    broken: Option<Violation>,
    told: bool,
    pub rx_full: u32,
    pub refused: u32,
}

impl ConsumerRing {
    /// The ring over `mem`; the sizes go to line 0 for whoever debugs.
    pub fn new(mem: Mem, layout: Layout) -> Option<ConsumerRing> {
        if mem.len < layout.total() {
            return None;
        }
        for (i, v) in [sw::VERSION, layout.rx_slots, layout.tx_slots, CELL as u32]
            .into_iter()
            .enumerate()
        {
            mem.store(sw::SIZES + 4 * i, v);
        }
        Some(ConsumerRing {
            mem,
            layout,
            fill_tail: 0,
            done_head: 0,
            tx_tail: 0,
            fill_head: 0,
            tx_head: 0,
            done_tail: 0,
            broken: None,
            told: false,
            rx_full: 0,
            refused: 0,
        })
    }

    /// The switch's own DONE index: frames delivered so far.
    pub fn done_head(&self) -> u32 {
        self.done_head
    }

    pub fn is_broken(&self) -> bool {
        self.broken.is_some()
    }

    fn break_with(&mut self, v: Violation) {
        self.broken.get_or_insert(v);
    }

    /// The one read of the consumer's indices for this step, and the check.
    pub fn poll(&mut self) -> Poll {
        if self.broken.is_none() {
            self.fill_head = self.mem.load(sw::FILL_HEAD);
            self.tx_head = self.mem.load(sw::TX_HEAD);
            self.done_tail = self.mem.load(sw::DONE_TAIL);
            let (rx, tx) = (self.layout.rx_slots, self.layout.tx_slots);
            if self.fill_head.wrapping_sub(self.fill_tail) > rx {
                self.break_with(Violation::Fill);
            } else if self.tx_head.wrapping_sub(self.tx_tail) > tx {
                self.break_with(Violation::Tx);
            } else if self.done_head.wrapping_sub(self.done_tail) > rx {
                self.break_with(Violation::Done);
            }
        }
        match self.broken {
            None => Poll::Live,
            Some(v) if !self.told => {
                self.told = true;
                Poll::Broke(v)
            }
            Some(_) => Poll::Broken,
        }
    }

    /// Free cells of receiving the consumer has put in FILL.
    pub fn fill_avail(&self) -> u32 {
        if self.is_broken() {
            0
        } else {
            self.fill_head.wrapping_sub(self.fill_tail)
        }
    }

    fn take_fill(&mut self) -> Option<u16> {
        if self.fill_avail() == 0 {
            return None;
        }
        let cell = self.mem.load(self.layout.fill_entry(self.fill_tail));
        if cell >= self.layout.rx_slots {
            self.break_with(Violation::Cell);
            return None;
        }
        self.fill_tail = self.fill_tail.wrapping_add(1);
        Some(cell as u16)
    }

    /// Copies `frame` into a free cell and tells DONE; false (and `rx_full`
    /// grows) when FILL has no cell or DONE no room.
    pub fn deliver(&mut self, frame: &[u8], flags: u16) -> bool {
        let room = self.done_head.wrapping_sub(self.done_tail) < self.layout.rx_slots;
        let cell = if room && !self.is_broken() {
            self.take_fill()
        } else {
            None
        };
        debug_assert!(frame.len() <= CELL);
        let Some(cell) = cell else {
            self.rx_full = self.rx_full.wrapping_add(1);
            return false;
        };
        self.mem.write(self.layout.rx_cell(u32::from(cell)), frame);
        let entry = sw::Done {
            cell,
            len: frame.len() as u16,
            flags,
        };
        self.mem
            .write(self.layout.done_entry(self.done_head), &entry.to_bytes());
        self.done_head = self.done_head.wrapping_add(1);
        self.mem.store(sw::DONE_HEAD, self.done_head);
        true
    }

    /// Takes the next frame of TX into `out`.
    pub fn take_tx(&mut self, out: &mut [u8; CELL]) -> Tx {
        if self.is_broken() || self.tx_head == self.tx_tail {
            return Tx::Empty;
        }
        // Two atomic reads, so that the length checked is the length used.
        let at = self.layout.tx_entry(self.tx_tail);
        let (word0, word1) = (self.mem.load(at), self.mem.load(at + 4));
        let e = sw::TxEntry {
            len: word0 as u16,
            flags: (word0 >> 16) as u16,
            spare: word1,
        };
        let cell = self.layout.tx_cell(self.tx_tail);
        self.tx_tail = self.tx_tail.wrapping_add(1);
        if e.flags != sw::TX_FLAGS || e.spare != 0 || usize::from(e.len) > CELL {
            return Tx::Refused;
        }
        self.mem.read(cell, &mut out[..usize::from(e.len)]);
        Tx::Frame(usize::from(e.len))
    }

    /// The switch's indices and counters, for the consumer's eyes.
    pub fn publish(&self) {
        self.mem.store(sw::FILL_TAIL, self.fill_tail);
        self.mem.store(sw::TX_TAIL, self.tx_tail);
        self.mem.store(sw::COUNTERS, self.rx_full);
        self.mem.store(sw::COUNTERS + 4, self.refused);
    }

    /// Whether the TX index of this step's poll is ahead of the switch's.
    pub fn tx_waiting(&self) -> bool {
        !self.is_broken() && self.tx_head != self.tx_tail
    }

    /// Whether the consumer has put a frame in TX that the switch has not taken: a fresh read
    /// of `tx_head`, for the last look before the switch sleeps.
    pub fn tx_pending(&self) -> bool {
        !self.is_broken() && self.mem.load(sw::TX_HEAD) != self.tx_tail
    }

    /// Whether the consumer sleeps. The sleep flags are a store-buffering pair: the switch
    /// writes DONE_HEAD and reads `consumer_idle`, the consumer writes `consumer_idle` and
    /// reads DONE_HEAD, and each needs a full barrier between its write and its read or both
    /// may read the old value and the wake is lost. The consumer side (`vnet_port_*`) does
    /// the same: `consumer_idle = 1`, full barrier, look at DONE again, then wait.
    pub fn consumer_idle(&self) -> bool {
        fence(Ordering::SeqCst);
        self.mem.load(sw::CONSUMER_IDLE) != 0
    }

    /// The switch's own flag; the full barrier follows the write, and the caller looks at
    /// its inputs again after it.
    pub fn set_switch_idle(&self, idle: bool) {
        self.mem.store(sw::SWITCH_IDLE, u32::from(idle));
        fence(Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use proto_net::switch::TxEntry;

    /// A ring object in host memory, with the consumer's moves.
    pub struct Rig {
        pub buf: Vec<u64>,
        pub layout: Layout,
    }

    impl Rig {
        pub fn new(layout: Layout) -> Rig {
            Rig {
                buf: vec![0; layout.total() / 8],
                layout,
            }
        }
        pub fn mem(&self) -> Mem {
            // SAFETY: the vector outlives the tests that use the Mem.
            unsafe { Mem::new(self.buf.as_ptr() as *mut u8, self.layout.total()) }
        }
        pub fn ring(&self) -> ConsumerRing {
            ConsumerRing::new(self.mem(), self.layout).expect("the rig is whole")
        }
        /// The consumer puts `cells` in FILL.
        pub fn fill(&self, cells: &[u32]) {
            let m = self.mem();
            let mut head = m.load(sw::FILL_HEAD);
            for &c in cells {
                m.store(self.layout.fill_entry(head), c);
                head = head.wrapping_add(1);
            }
            m.store(sw::FILL_HEAD, head);
        }
        pub fn send(&self, frame: &[u8], flags: u16) {
            let m = self.mem();
            let head = m.load(sw::TX_HEAD);
            m.write(self.layout.tx_cell(head), frame);
            let e = TxEntry {
                len: frame.len() as u16,
                flags,
                spare: 0,
            };
            m.write(self.layout.tx_entry(head), &e.to_bytes());
            m.store(sw::TX_HEAD, head.wrapping_add(1));
        }
        pub fn done(&self, i: u32) -> (sw::Done, Vec<u8>) {
            let mut raw = [0; 8];
            self.mem().read(self.layout.done_entry(i), &mut raw);
            let d = sw::Done::from_bytes(raw);
            let mut f = vec![0; usize::from(d.len)];
            self.mem()
                .read(self.layout.rx_cell(u32::from(d.cell)), &mut f);
            (d, f)
        }
    }

    #[test]
    fn a_frame_goes_into_a_filled_cell_and_is_told_in_done() {
        let rig = Rig::new(Layout::DEFAULT);
        let mut ring = rig.ring();
        assert!(!ring.deliver(b"x", 0), "no cell yet");
        assert_eq!(ring.rx_full, 1);
        rig.fill(&[7, 9]);
        assert_eq!(ring.poll(), Poll::Live);
        assert_eq!(ring.fill_avail(), 2);
        assert!(ring.deliver(b"hello", sw::DONE_ARP_COPY));
        let (d, f) = rig.done(0);
        assert_eq!((d.cell, d.len, d.flags), (7, 5, 1));
        assert_eq!(f, b"hello");
        assert_eq!(rig.mem().load(sw::DONE_HEAD), 1);
        ring.publish();
        assert_eq!(rig.mem().load(sw::FILL_TAIL), 1);
        assert_eq!(rig.mem().load(sw::COUNTERS), 1);
    }

    #[test]
    fn a_full_done_drops_the_frame_and_keeps_the_cell() {
        let rig = Rig::new(Layout::new(256, 64).unwrap());
        let mut ring = rig.ring();
        rig.fill(&(0..256).collect::<Vec<_>>());
        ring.poll();
        for _ in 0..256 {
            assert!(ring.deliver(b"a", 0));
        }
        rig.fill(&[200]);
        ring.poll();
        assert!(!ring.deliver(b"a", 0));
        assert_eq!(ring.fill_avail(), 1, "the cell stays in FILL");
        rig.mem().store(sw::DONE_TAIL, 1);
        ring.poll();
        assert!(ring.deliver(b"a", 0));
    }

    #[test]
    fn a_rewound_index_takes_nothing_twice_and_the_break_is_told_once() {
        let rig = Rig::new(Layout::DEFAULT);
        let mut ring = rig.ring();
        rig.fill(&[1, 2, 3]);
        ring.poll();
        assert!(ring.deliver(b"a", 0) && ring.deliver(b"b", 0));
        rig.mem().store(sw::FILL_HEAD, 0);
        assert_eq!(ring.poll(), Poll::Broke(Violation::Fill));
        assert_eq!(ring.poll(), Poll::Broken);
        assert!(!ring.deliver(b"c", 0));
        assert_eq!(ring.fill_avail(), 0);
        assert_eq!(
            rig.mem().load(sw::DONE_HEAD),
            2,
            "nothing taken after the break"
        );
    }

    #[test]
    fn each_rule_of_the_indices_breaks_the_ring() {
        let l = Layout::new(256, 64).unwrap();
        for (line, value, v) in [
            (sw::FILL_HEAD, 257, Violation::Fill),
            (sw::TX_HEAD, 65, Violation::Tx),
            (sw::DONE_TAIL, 1, Violation::Done),
        ] {
            let rig = Rig::new(l);
            let mut ring = rig.ring();
            rig.mem().store(line, value);
            assert_eq!(ring.poll(), Poll::Broke(v));
        }
        let rig = Rig::new(l);
        let mut ring = rig.ring();
        rig.fill(&[l.rx_slots]);
        ring.poll();
        assert!(!ring.deliver(b"a", 0));
        assert_eq!(ring.poll(), Poll::Broke(Violation::Cell));
        let edge = Rig::new(l);
        let mut ring = edge.ring();
        edge.mem().store(sw::FILL_HEAD, 256);
        assert_eq!(ring.poll(), Poll::Live, "exactly rx_slots is allowed");
    }

    #[test]
    fn indices_wrap_past_u32() {
        let rig = Rig::new(Layout::DEFAULT);
        let mut ring = rig.ring();
        ring.fill_tail = u32::MAX - 1;
        rig.mem().store(sw::FILL_HEAD, u32::MAX - 1);
        rig.fill(&[4, 5, 6]);
        assert_eq!(ring.poll(), Poll::Live);
        assert_eq!(ring.fill_avail(), 3);
        for _ in 0..3 {
            assert!(ring.take_fill().is_some());
        }
        assert_eq!(ring.fill_tail, 1);
    }

    #[test]
    fn tx_frames_come_out_in_order_and_odd_entries_are_refused() {
        let rig = Rig::new(Layout::DEFAULT);
        let mut ring = rig.ring();
        let mut out = [0; CELL];
        assert_eq!(ring.take_tx(&mut out), Tx::Empty);
        rig.send(b"one", 0);
        rig.send(b"two", 1);
        rig.send(b"three", 0);
        ring.poll();
        assert_eq!(ring.take_tx(&mut out), Tx::Frame(3));
        assert_eq!(&out[..3], b"one");
        assert_eq!(ring.take_tx(&mut out), Tx::Refused);
        assert_eq!(ring.take_tx(&mut out), Tx::Frame(5));
        assert_eq!(ring.take_tx(&mut out), Tx::Empty);
    }

    /// An entry of TX as a hostile consumer writes it: any length, flags and spare.
    fn raw_tx(rig: &Rig, len: u16, flags: u16, spare: u32) {
        let m = rig.mem();
        let head = m.load(sw::TX_HEAD);
        let e = TxEntry { len, flags, spare };
        m.write(rig.layout.tx_entry(head), &e.to_bytes());
        m.store(sw::TX_HEAD, head.wrapping_add(1));
    }

    #[test]
    fn tx_entries_with_odd_lengths_spares_and_flags_are_taken_or_refused_by_the_rules() {
        let rig = Rig::new(Layout::new(256, 64).unwrap());
        let mut ring = rig.ring();
        let mut out = [0; CELL];
        for (len, flags, spare, taken) in [
            (1514, 0, 0, true),
            (1515, 0, 0, true),
            (2047, 0, 0, true),
            (2048, 0, 0, true),
            (2049, 0, 0, false),
            (u16::MAX, 0, 0, false),
            (100, 0, 1, false),
            (100, 0, u32::MAX, false),
            (100, 1, 0, false),
            (0, 0, 0, true),
        ] {
            raw_tx(&rig, len, flags, spare);
            ring.poll();
            let want = if taken {
                Tx::Frame(usize::from(len))
            } else {
                Tx::Refused
            };
            assert_eq!(ring.take_tx(&mut out), want, "{len} {flags} {spare}");
        }
        assert_eq!(ring.poll(), Poll::Live);
        assert_eq!(ring.take_tx(&mut out), Tx::Empty);
    }

    #[test]
    fn a_tx_head_behind_the_tail_and_a_done_tail_ahead_of_the_head_break_the_ring() {
        let l = Layout::new(256, 64).unwrap();
        let rig = Rig::new(l);
        let mut ring = rig.ring();
        let mut out = [0; CELL];
        for _ in 0..5 {
            rig.send(b"x", 0);
        }
        ring.poll();
        while ring.take_tx(&mut out) != Tx::Empty {}
        rig.mem().store(sw::TX_HEAD, 2);
        assert_eq!(ring.poll(), Poll::Broke(Violation::Tx));
        assert_eq!(ring.take_tx(&mut out), Tx::Empty, "nothing after the break");
        for (done_tail, live) in [(0, true), (1, true), (2, false), (3, false), (1000, false)] {
            let rig = Rig::new(l);
            let mut ring = rig.ring();
            rig.fill(&[1, 2]);
            ring.poll();
            ring.deliver(b"a", 0);
            rig.mem().store(sw::DONE_TAIL, done_tail);
            let want = if live {
                Poll::Live
            } else {
                Poll::Broke(Violation::Done)
            };
            assert_eq!(ring.poll(), want, "{done_tail}");
        }
    }

    #[test]
    fn a_sleeping_consumer_is_never_missed_with_the_barriers_of_both_sides() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering as O};
        use std::time::{Duration, Instant};
        const N: u32 = 1_000_000;
        let rig = Rig::new(Layout::DEFAULT);
        let (mem, ring) = (rig.mem(), rig.ring());
        let wake = Arc::new(AtomicBool::new(false));
        let acked = Arc::new(AtomicU32::new(0));
        let (w2, a2) = (wake.clone(), acked.clone());
        let consumer = std::thread::spawn(move || {
            for i in 1..=N {
                loop {
                    if mem.load(sw::DONE_HEAD) >= i {
                        break;
                    }
                    mem.store(sw::CONSUMER_IDLE, 1);
                    fence(Ordering::SeqCst);
                    if mem.load(sw::DONE_HEAD) >= i {
                        mem.store(sw::CONSUMER_IDLE, 0);
                        break;
                    }
                    let began = Instant::now();
                    while !w2.swap(false, O::AcqRel) {
                        if began.elapsed() > Duration::from_secs(5) {
                            return false;
                        }
                        std::hint::spin_loop();
                    }
                    mem.store(sw::CONSUMER_IDLE, 0);
                }
                a2.store(i, O::Release);
            }
            true
        });
        for i in 1..=N {
            while acked.load(O::Acquire) < i - 1 {
                std::hint::spin_loop();
                if consumer.is_finished() {
                    assert!(consumer.join().unwrap(), "a wake was lost");
                    return;
                }
            }
            mem.store(sw::DONE_HEAD, i);
            if ring.consumer_idle() {
                wake.store(true, O::Release);
            }
        }
        assert!(consumer.join().unwrap(), "a wake was lost");
    }
}
