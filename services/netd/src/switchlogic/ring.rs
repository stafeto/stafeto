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
    /// A packet of the loopback network with an address outside 127.0.0.0/8.
    Loop,
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
    /// A frame of this length whose TCP sum is not computed (`TX_SUM`).
    Sum(usize),
    /// A packet of the loopback network of this length (`TX_LOOP`).
    Loop(usize),
    /// A frame of the segmentation offload (`TX_SUM | TX_TSO`): its first `TSO_HEAD_MAX` bytes
    /// (or all of a shorter frame) are in the buffer, the rest stays in the cells (`tso_read`)
    /// until `tso_done`. The entries stay in TX meanwhile.
    Tso {
        len: usize,
        mss: u16,
    },
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
    /// The entries of the frame of the segmentation offload the switch holds (0: none).
    held: u32,
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
            held: 0,
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

    /// The consumer broke a rule of the layout the entry's content shows (the checks of the
    /// indices break the ring in `poll`): the ring is disabled, as for a bad index.
    pub fn break_with(&mut self, v: Violation) {
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

    /// Takes the next frame of TX into `out`. A frame of the segmentation offload comes as
    /// `Tso` with its headers in `out` and holds its entries until `tso_done`; nothing else is
    /// taken meanwhile.
    pub fn take_tx(&mut self, out: &mut [u8; CELL]) -> Tx {
        while !self.is_broken() && self.held == 0 && self.tx_head != self.tx_tail {
            // Two atomic reads, so that the length checked is the length used.
            let at = self.layout.tx_entry(self.tx_tail);
            let (word0, word1) = (self.mem.load(at), self.mem.load(at + 4));
            let e = sw::TxEntry {
                len: word0 as u16,
                flags: (word0 >> 16) as u16,
                spare: word1,
            };
            let queued = self.tx_head.wrapping_sub(self.tx_tail);
            if e.flags == sw::TX_PAD {
                // The cells to the end of the array, so that the next frame of the offload lies
                // in a row. Anything else about it breaks the ring.
                let rest = self.layout.tx_to_end(self.tx_tail);
                if e.len != 0 || e.spare != rest || rest >= sw::TSO_CELLS_MAX || queued < rest {
                    self.break_with(Violation::Tx);
                    return Tx::Empty;
                }
                self.tx_tail = self.tx_tail.wrapping_add(rest);
                continue;
            }
            if e.flags == sw::TX_SUM | sw::TX_TSO {
                return self.take_tso(e, queued, out);
            }
            let cell = self.layout.tx_cell(self.tx_tail);
            self.tx_tail = self.tx_tail.wrapping_add(1);
            if !matches!(e.flags, sw::TX_FLAGS | sw::TX_SUM | sw::TX_LOOP)
                || e.spare != 0
                || usize::from(e.len) > CELL
            {
                return Tx::Refused;
            }
            self.mem.read(cell, &mut out[..usize::from(e.len)]);
            return match e.flags {
                sw::TX_LOOP => Tx::Loop(usize::from(e.len)),
                sw::TX_SUM => Tx::Sum(usize::from(e.len)),
                _ => Tx::Frame(usize::from(e.len)),
            };
        }
        Tx::Empty
    }

    /// The entry of a frame of the segmentation offload at `tx_tail`, `queued` entries
    /// published. The shape of the run breaks the ring (a length past `TSO_FRAME_MAX`, fewer
    /// entries than the length needs, a run over the end of the array, a continuation that is
    /// not zero); the MSS and the length of the headers refuse the frame, and its entries are
    /// freed.
    fn take_tso(&mut self, e: sw::TxEntry, queued: u32, out: &mut [u8; CELL]) -> Tx {
        let len = usize::from(e.len);
        let k = sw::cells(len);
        let fits =
            len <= sw::TSO_FRAME_MAX && queued >= k && self.layout.tx_run_fits(self.tx_tail, k);
        let zero = fits
            && (1..k).all(|i| {
                let at = self.layout.tx_entry(self.tx_tail.wrapping_add(i));
                self.mem.load(at) == 0 && self.mem.load(at + 4) == 0
            });
        if !zero {
            self.break_with(Violation::Tx);
            return Tx::Empty;
        }
        let mss = e.spare;
        if !(u32::from(sw::TSO_MSS_MIN)..=sw::TSO_MSS_MAX).contains(&mss) || len < sw::TSO_HEAD_MIN
        {
            self.tx_tail = self.tx_tail.wrapping_add(k);
            return Tx::Refused;
        }
        let head = len.min(sw::TSO_HEAD_MAX);
        self.mem
            .read(self.layout.tx_cell(self.tx_tail), &mut out[..head]);
        self.held = k;
        Tx::Tso {
            len,
            mss: mss as u16,
        }
    }

    /// Frame bytes `from..from + out.len()` of the frame of the segmentation offload held now
    /// (`Tx::Tso`), read from the consumer's cells. The consumer may change them meanwhile:
    /// what is read is what goes out, and a change only damages its own stream.
    pub fn tso_read(&self, from: usize, out: &mut [u8]) {
        debug_assert!(self.held > 0 && from + out.len() <= self.held as usize * CELL);
        self.mem.read(self.layout.tx_cell(self.tx_tail) + from, out);
    }

    /// The frame held is gone (sent, or refused after its headers): its entries are free.
    pub fn tso_done(&mut self) {
        self.tx_tail = self.tx_tail.wrapping_add(self.held);
        self.held = 0;
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
        !self.is_broken() && self.held == 0 && self.tx_head != self.tx_tail
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
        rig.send(b"two", 2);
        rig.send(b"three", 0);
        rig.send(b"four", sw::TX_SUM);
        ring.poll();
        assert_eq!(ring.take_tx(&mut out), Tx::Frame(3));
        assert_eq!(&out[..3], b"one");
        assert_eq!(ring.take_tx(&mut out), Tx::Refused);
        assert_eq!(ring.take_tx(&mut out), Tx::Frame(5));
        assert_eq!(ring.take_tx(&mut out), Tx::Sum(4));
        assert_eq!(&out[..4], b"four");
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
            (100, 1, 0, true),
            (2048, 1, 0, true),
            (2049, 1, 0, false),
            (100, 1, 7, false),
            (100, 2, 0, false),
            (100, 5, 0, false),
            (100, 3, 0, false),
            (100, 0x100, 0, false),
            (100, 0x101, 0, false),
            (100, 0x104, 0, false),
            (0, 0, 0, true),
            (100, 4, 0, true),
            (2048, 4, 0, true),
            (2049, 4, 0, false),
            (100, 4, 7, false),
        ] {
            raw_tx(&rig, len, flags, spare);
            ring.poll();
            let want = if !taken {
                Tx::Refused
            } else if flags == sw::TX_LOOP {
                Tx::Loop(usize::from(len))
            } else if flags == sw::TX_SUM {
                Tx::Sum(usize::from(len))
            } else {
                Tx::Frame(usize::from(len))
            };
            assert_eq!(ring.take_tx(&mut out), want, "{len} {flags} {spare}");
        }
        assert_eq!(ring.poll(), Poll::Live);
        assert_eq!(ring.take_tx(&mut out), Tx::Empty);
    }

    /// A frame of the segmentation offload as the consumer writes it: the first entry with the
    /// length and the MSS, then `cells(len) - 1` entries of zeros, one `tx_head` store.
    fn tso_entries(rig: &Rig, len: u16, mss: u32) {
        let m = rig.mem();
        let head = m.load(sw::TX_HEAD);
        let k = sw::cells(usize::from(len));
        let first = TxEntry {
            len,
            flags: sw::TX_SUM | sw::TX_TSO,
            spare: mss,
        };
        m.write(rig.layout.tx_entry(head), &first.to_bytes());
        for i in 1..k {
            m.write(rig.layout.tx_entry(head.wrapping_add(i)), &[0; 8]);
        }
        m.store(sw::TX_HEAD, head.wrapping_add(k));
        // The cells hold a pattern the reads can be told by.
        let room = rig.layout.total() - rig.layout.tx_cell(head);
        for j in 0..usize::from(len).min(room) {
            m.write(rig.layout.tx_cell(head) + j, &[(j % 251) as u8]);
        }
    }

    #[test]
    fn a_frame_of_the_offload_comes_with_its_headers_and_holds_its_entries_until_done() {
        let l = Layout::new(256, 64).unwrap();
        let rig = Rig::new(l);
        let mut ring = rig.ring();
        let mut out = [0; CELL];
        tso_entries(&rig, 10_300, 1448);
        rig.send(b"after", 0);
        assert_eq!(ring.poll(), Poll::Live);
        assert_eq!(
            ring.take_tx(&mut out),
            Tx::Tso {
                len: 10_300,
                mss: 1448
            }
        );
        let want: Vec<u8> = (0..sw::TSO_HEAD_MAX).map(|j| (j % 251) as u8).collect();
        assert_eq!(
            &out[..sw::TSO_HEAD_MAX],
            &want[..],
            "the headers are copied"
        );
        // Nothing else is taken while it is held, and the room is not given back.
        assert_eq!(ring.take_tx(&mut out), Tx::Empty);
        assert!(!ring.tx_waiting());
        ring.publish();
        assert_eq!(rig.mem().load(sw::TX_TAIL), 0);
        // The data is read from the cells, past the headers, at any offset.
        let mut part = [0u8; 300];
        ring.tso_read(4_000, &mut part);
        let want: Vec<u8> = (4_000..4_300).map(|j| (j % 251) as u8).collect();
        assert_eq!(&part[..], &want[..]);
        ring.tso_done();
        ring.publish();
        assert_eq!(rig.mem().load(sw::TX_TAIL), 6);
        assert_eq!(
            ring.take_tx(&mut out),
            Tx::Frame(5),
            "the next entry follows the run"
        );
        assert_eq!(&out[..5], b"after");
    }

    #[test]
    fn a_frame_of_the_offload_shorter_than_a_cell_takes_one_entry_and_a_short_one_is_whole() {
        let rig = Rig::new(Layout::new(256, 64).unwrap());
        let mut ring = rig.ring();
        let mut out = [0; CELL];
        tso_entries(&rig, 2_000, 1448);
        tso_entries(&rig, 60, 1448);
        ring.poll();
        assert_eq!(
            ring.take_tx(&mut out),
            Tx::Tso {
                len: 2_000,
                mss: 1448
            }
        );
        ring.tso_done();
        // A frame under the headers' minimum is refused: its entry is free.
        assert_eq!(ring.take_tx(&mut out), Tx::Tso { len: 60, mss: 1448 });
        ring.tso_done();
        let rig = Rig::new(Layout::new(256, 64).unwrap());
        let mut ring = rig.ring();
        tso_entries(&rig, 53, 1448);
        ring.poll();
        assert_eq!(ring.take_tx(&mut out), Tx::Refused);
        assert_eq!(ring.poll(), Poll::Live, "a short frame breaks nothing");
    }

    #[test]
    fn an_mss_out_of_range_refuses_the_frame_and_frees_its_entries() {
        for mss in [0, 1, 215, 1461, 9_000, u32::MAX] {
            let rig = Rig::new(Layout::new(256, 64).unwrap());
            let mut ring = rig.ring();
            let mut out = [0; CELL];
            tso_entries(&rig, 5_000, mss);
            rig.send(b"next", 0);
            ring.poll();
            assert_eq!(ring.take_tx(&mut out), Tx::Refused, "{mss}");
            assert_eq!(
                ring.take_tx(&mut out),
                Tx::Frame(4),
                "three entries freed: {mss}"
            );
        }
        for mss in [216, 524, 1460] {
            let rig = Rig::new(Layout::new(256, 64).unwrap());
            let mut ring = rig.ring();
            let mut out = [0; CELL];
            tso_entries(&rig, 5_000, mss);
            ring.poll();
            assert!(matches!(ring.take_tx(&mut out), Tx::Tso { .. }), "{mss}");
        }
    }

    #[test]
    fn the_shape_of_a_run_of_the_offload_breaks_the_ring() {
        let l = Layout::new(256, 64).unwrap();
        let mut out = [0; CELL];
        // A length past the offload's bound.
        for len in [sw::TSO_FRAME_MAX as u16 + 1, 20_000, u16::MAX] {
            let rig = Rig::new(l);
            let mut ring = rig.ring();
            raw_tx(&rig, len, sw::TX_SUM | sw::TX_TSO, 1448);
            ring.poll();
            assert_eq!(ring.take_tx(&mut out), Tx::Empty);
            assert_eq!(ring.poll(), Poll::Broke(Violation::Tx), "{len}");
        }
        // Fewer entries published than the length takes (the rest of the run is not there).
        let rig = Rig::new(l);
        let mut ring = rig.ring();
        raw_tx(&rig, 10_000, sw::TX_SUM | sw::TX_TSO, 1448);
        ring.poll();
        assert_eq!(ring.take_tx(&mut out), Tx::Empty);
        assert_eq!(ring.poll(), Poll::Broke(Violation::Tx));
        // A continuation that is not zero: any of its three fields.
        for (len, flags, spare) in [(1u16, 0u16, 0u32), (0, 1, 0), (0, 0, 1), (0, sw::TX_PAD, 0)] {
            let rig = Rig::new(l);
            let mut ring = rig.ring();
            tso_entries(&rig, 5_000, 1448);
            let at = l.tx_entry(2);
            rig.mem()
                .write(at, &TxEntry { len, flags, spare }.to_bytes());
            ring.poll();
            assert_eq!(ring.take_tx(&mut out), Tx::Empty);
            assert_eq!(
                ring.poll(),
                Poll::Broke(Violation::Tx),
                "{len} {flags} {spare}"
            );
        }
        // A run over the end of the array without a pad in front.
        let rig = Rig::new(l);
        let mut ring = rig.ring();
        for _ in 0..62 {
            rig.send(b"x", 0);
        }
        ring.poll();
        for _ in 0..62 {
            assert_eq!(ring.take_tx(&mut out), Tx::Frame(1));
        }
        tso_entries(&rig, 5_000, 1448);
        ring.poll();
        assert_eq!(ring.take_tx(&mut out), Tx::Empty);
        assert_eq!(ring.poll(), Poll::Broke(Violation::Tx));
    }

    #[test]
    fn a_pad_skips_the_rest_of_the_array_and_the_frame_starts_at_its_first_cell() {
        let l = Layout::new(256, 64).unwrap();
        let rig = Rig::new(l);
        let mut ring = rig.ring();
        let mut out = [0; CELL];
        for _ in 0..61 {
            rig.send(b"x", 0);
        }
        ring.poll();
        for _ in 0..61 {
            assert_eq!(ring.take_tx(&mut out), Tx::Frame(1));
        }
        // Entries 61 to 63 are skipped by a pad at 61; the frame of three cells is at 64 (cell 0).
        raw_tx(&rig, 0, sw::TX_PAD, 3);
        let m = rig.mem();
        m.store(sw::TX_HEAD, 64);
        tso_entries(&rig, 5_000, 1448);
        ring.poll();
        assert_eq!(
            ring.take_tx(&mut out),
            Tx::Tso {
                len: 5_000,
                mss: 1448
            }
        );
        assert_eq!(out[0], 0);
        assert_eq!(ring.poll(), Poll::Live);
        let mut part = [0u8; 4];
        ring.tso_read(2_048, &mut part);
        assert_eq!(
            part,
            [
                (2048 % 251) as u8,
                (2049 % 251) as u8,
                (2050 % 251) as u8,
                (2051 % 251) as u8
            ]
        );
        ring.tso_done();
        ring.publish();
        assert_eq!(
            rig.mem().load(sw::TX_TAIL),
            67,
            "the pad's 3 and the frame's 3 are free"
        );
    }

    #[test]
    fn a_pad_that_is_not_the_rest_of_the_array_breaks_the_ring() {
        let l = Layout::new(256, 64).unwrap();
        let mut out = [0; CELL];
        // At index 56: the rest of the array is 8 entries.
        for (len, spare, queued, broke) in [
            (0u16, 8u32, 8u32, false),
            (0, 7, 8, true),
            (0, 9, 9, true),
            (1, 8, 8, true),
            (0, 8, 7, true),
        ] {
            let rig = Rig::new(l);
            let mut ring = rig.ring();
            for _ in 0..56 {
                rig.send(b"x", 0);
            }
            ring.poll();
            for _ in 0..56 {
                ring.take_tx(&mut out);
            }
            let m = rig.mem();
            m.write(
                l.tx_entry(56),
                &TxEntry {
                    len,
                    flags: sw::TX_PAD,
                    spare,
                }
                .to_bytes(),
            );
            m.store(sw::TX_HEAD, 56 + queued);
            ring.poll();
            let first = ring.take_tx(&mut out);
            if broke {
                assert_eq!(first, Tx::Empty, "{len} {spare} {queued}");
                assert_eq!(ring.poll(), Poll::Broke(Violation::Tx));
            } else {
                assert_eq!(first, Tx::Empty);
                assert_eq!(
                    ring.poll(),
                    Poll::Live,
                    "a pad of the rest, and no entry after it"
                );
            }
        }
        // A pad of nine or more cannot be: no frame is longer than nine cells.
        let big = Layout::new(256, 64).unwrap();
        let rig = Rig::new(big);
        let mut ring = rig.ring();
        for _ in 0..50 {
            rig.send(b"x", 0);
        }
        ring.poll();
        for _ in 0..50 {
            ring.take_tx(&mut out);
        }
        rig.mem().write(
            big.tx_entry(50),
            &TxEntry {
                len: 0,
                flags: sw::TX_PAD,
                spare: 14,
            }
            .to_bytes(),
        );
        rig.mem().store(sw::TX_HEAD, 64);
        ring.poll();
        assert_eq!(ring.take_tx(&mut out), Tx::Empty);
        assert_eq!(ring.poll(), Poll::Broke(Violation::Tx));
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
