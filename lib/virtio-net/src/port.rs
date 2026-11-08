// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The consumer side of the switch's ring (spec Sh4, 3.2 and 3.6): the
//! program that attached (ATTACH of `proto_net::switch`) owns the ring
//! object, fills FILL with the cells it receives into, reads the frames the
//! switch put in DONE, and writes the frames it sends into the cells of TX.
//! The switch is the other writer and reader; each index has one writer.
//!
//! Notifications. The consumer is told only while it sleeps and tells the
//! switch only while the switch sleeps, with the scheme SB of two stores
//! and two loads: each side stores its index, runs a full barrier, and
//! reads the other side's idle flag. The sleeper stores its flag, runs a
//! full barrier, looks at the index once more and only then waits
//! (`sleep_begin`); the writer of `tx_head` runs the barrier between the
//! store and the read of `switch_idle` (`tx_flush`). Without both barriers
//! a wake can be lost between two CPUs (stafeto-design#638, C3).
//!
//! The functions of `Port` are for one thread. With the feature `ffi` the
//! `vnet_port_*` functions of `include/vnet.h` hold one `Port` in a static;
//! they make no call of the kernel, `vnet_port_tx_flush` says whether the
//! caller pokes the switch (`stafeto_fast_poke`).

use core::sync::atomic::{AtomicU32, Ordering, fence};
use proto_net::switch::{
    self as sw, CELL, CONSUMER_IDLE, COUNTERS, DONE_HEAD, DONE_TAIL, Done, FILL_HEAD, FILL_TAIL,
    Layout, SWITCH_IDLE, TX_HEAD, TX_TAIL, TxEntry,
};

/// Cells of FILL below which the layer copies a frame and returns its
/// cell at once (`FF_STAFETO_RX_LOW`).
pub const RX_LOW: u32 = 512;

/// A frame the switch delivered: its cell, length and the DONE flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rx {
    pub cell: u32,
    pub len: u32,
    pub flags: u32,
    pub frame: *mut u8,
}

/// The ring broke a rule the consumer can see: DONE ahead of its size, or
/// a cell or length out of bounds. The consumer stops using it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Broken;

pub struct Port {
    base: *mut u8,
    layout: Layout,
    /// FILL: the next entry the consumer writes.
    fill_head: u32,
    /// DONE: the next entry the consumer reads.
    done_tail: u32,
    /// TX: entries written (`tx_next`) and published (`tx_head`), and the
    /// switch's `tx_tail` as last read.
    tx_next: u32,
    tx_head: u32,
    tx_tail: u32,
}

impl Port {
    /// The consumer over `base`, the ring object of `layout`, whose indices
    /// are all 0. FILL gets every cell of receiving the entries hold.
    ///
    /// # Safety
    /// `base` is valid for reads and writes of `layout.total()` bytes,
    /// 4-aligned, for as long as the `Port` lives.
    pub unsafe fn new(base: *mut u8, layout: Layout) -> Port {
        let mut port = Port {
            base,
            layout,
            fill_head: 0,
            done_tail: 0,
            tx_next: 0,
            tx_head: 0,
            tx_tail: 0,
        };
        for cell in 0..layout.rx_slots {
            port.give(cell);
        }
        port.publish_fill();
        port
    }

    fn word(&self, at: usize) -> &AtomicU32 {
        debug_assert!(at.is_multiple_of(4) && at + 4 <= self.layout.total());
        // SAFETY: in bounds and aligned by the layout; the word is atomic.
        unsafe { &*(self.base.add(at) as *const AtomicU32) }
    }

    fn give(&mut self, cell: u32) {
        self.word(self.layout.fill_entry(self.fill_head))
            .store(cell, Ordering::Relaxed);
        self.fill_head = self.fill_head.wrapping_add(1);
    }

    fn publish_fill(&self) {
        self.word(FILL_HEAD)
            .store(self.fill_head, Ordering::Release);
    }

    /// The cell of a frame the consumer is done with goes back to FILL.
    pub fn rx_return(&mut self, cell: u32) {
        if cell < self.layout.rx_slots {
            self.give(cell);
            self.publish_fill();
        }
    }

    /// Cells the switch may still take: FILL entries it has not used.
    pub fn fill_free(&self) -> u32 {
        self.fill_head
            .wrapping_sub(self.word(FILL_TAIL).load(Ordering::Acquire))
    }

    /// Whether DONE holds an entry.
    pub fn work(&self) -> bool {
        self.word(DONE_HEAD).load(Ordering::Acquire) != self.done_tail
    }

    /// Up to `out.len()` frames from DONE; their cells are the caller's
    /// until `rx_return`. `Err` when the indices or an entry break the
    /// rules: the caller stops.
    pub fn rx_burst(&mut self, out: &mut [Rx]) -> Result<usize, Broken> {
        let head = self.word(DONE_HEAD).load(Ordering::Acquire);
        let queued = head.wrapping_sub(self.done_tail);
        if queued > self.layout.rx_slots {
            return Err(Broken);
        }
        let n = (queued as usize).min(out.len());
        for slot in out.iter_mut().take(n) {
            let at = self.layout.done_entry(self.done_tail);
            let mut raw = [0u8; 8];
            for (i, chunk) in raw.chunks_mut(4).enumerate() {
                let w = self.word(at + 4 * i).load(Ordering::Relaxed);
                chunk.copy_from_slice(&w.to_le_bytes());
            }
            let d = Done::from_bytes(raw);
            if u32::from(d.cell) >= self.layout.rx_slots || usize::from(d.len) > CELL {
                return Err(Broken);
            }
            // SAFETY: the cell is inside the object (checked above).
            let frame = unsafe { self.base.add(self.layout.rx_cell(u32::from(d.cell))) };
            *slot = Rx {
                cell: u32::from(d.cell),
                len: u32::from(d.len),
                flags: u32::from(d.flags),
                frame,
            };
            self.done_tail = self.done_tail.wrapping_add(1);
        }
        if n > 0 {
            self.word(DONE_TAIL)
                .store(self.done_tail, Ordering::Release);
        }
        Ok(n)
    }

    /// The entries of TX the consumer may write: reads `tx_tail`.
    pub fn tx_room(&mut self) -> u32 {
        self.tx_tail = self.word(TX_TAIL).load(Ordering::Acquire);
        let cap = self.layout.tx_slots;
        cap.saturating_sub(self.tx_next.wrapping_sub(self.tx_tail))
    }

    /// The cell the next frame is built in, or None when TX is full (after
    /// one look at `tx_tail`).
    pub fn tx_cell(&mut self) -> Option<*mut u8> {
        let cap = self.layout.tx_slots;
        if self.tx_next.wrapping_sub(self.tx_tail) >= cap && self.tx_room() == 0 {
            return None;
        }
        // SAFETY: the cell lies inside the object (`tx_cell` folds the index).
        Some(unsafe { self.base.add(self.layout.tx_cell(self.tx_next)) })
    }

    /// The frame of `len` bytes in the cell `tx_cell` gave becomes an entry
    /// (flags and spare 0). It is published by `tx_flush`.
    pub fn tx_submit(&mut self, len: u32) {
        self.tx_submit_flags(len, sw::TX_FLAGS);
    }

    /// `tx_submit` for a frame of TCP whose sum is not computed (`TX_SUM`): the switch writes
    /// the sum of the pseudo-header and has the device complete the rest.
    pub fn tx_submit_sum(&mut self, len: u32) {
        self.tx_submit_flags(len, sw::TX_SUM);
    }

    /// `tx_submit` for a packet of the loopback network (`TX_LOOP`).
    pub fn tx_submit_loop(&mut self, len: u32) {
        self.tx_submit_flags(len, sw::TX_LOOP);
    }

    fn tx_submit_flags(&mut self, len: u32, flags: u16) {
        let raw = TxEntry {
            len: len as u16,
            flags,
            spare: 0,
        }
        .to_bytes();
        let at = self.layout.tx_entry(self.tx_next);
        for (i, chunk) in raw.chunks(4).enumerate() {
            let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            self.word(at + 4 * i).store(w, Ordering::Relaxed);
        }
        self.tx_next = self.tx_next.wrapping_add(1);
    }

    /// Entries written and not published.
    pub fn tx_pending(&self) -> u32 {
        self.tx_next.wrapping_sub(self.tx_head)
    }

    /// Publishes the entries (release store of `tx_head`), runs the full
    /// barrier and reads `switch_idle`. True when the switch sleeps and the
    /// caller must poke it. False when nothing was pending.
    pub fn tx_flush(&mut self) -> bool {
        if self.tx_head == self.tx_next {
            return false;
        }
        self.tx_head = self.tx_next;
        self.word(TX_HEAD).store(self.tx_head, Ordering::Release);
        fence(Ordering::SeqCst);
        self.word(SWITCH_IDLE).load(Ordering::Relaxed) != 0
    }

    /// The consumer is about to wait: flag, full barrier, one more look at
    /// DONE. True when an entry is there (the flag is cleared and the
    /// caller does not wait).
    pub fn sleep_begin(&mut self) -> bool {
        self.word(CONSUMER_IDLE).store(1, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        if self.work() {
            self.word(CONSUMER_IDLE).store(0, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// The wait is over.
    pub fn sleep_end(&mut self) {
        self.word(CONSUMER_IDLE).store(0, Ordering::Relaxed);
    }

    /// The switch's counters of line 9: frames dropped for a full FILL or
    /// DONE, and frames of TX refused.
    pub fn counters(&self) -> (u32, u32) {
        (
            self.word(COUNTERS).load(Ordering::Relaxed),
            self.word(COUNTERS + 4).load(Ordering::Relaxed),
        )
    }
}

#[cfg(feature = "ffi")]
mod c {
    use super::*;
    use core::cell::UnsafeCell;
    use core::ffi::{c_int, c_void};
    use core::mem::MaybeUninit;

    /// `struct vnet_port_rx`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct CRx {
        pub cell: u32,
        pub len: u32,
        pub flags: u32,
        pub pad: u32,
        pub frame: *mut c_void,
    }

    struct Slot(UnsafeCell<MaybeUninit<Port>>);
    // SAFETY: the functions are for one thread (module comment).
    unsafe impl Sync for Slot {}
    static PORT: Slot = Slot(UnsafeCell::new(MaybeUninit::uninit()));
    static OPEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    fn port() -> Option<&'static mut Port> {
        if !OPEN.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: written by `vnet_port_open` before OPEN; one thread.
        Some(unsafe { (*PORT.0.get()).assume_init_mut() })
    }

    /// Opens the consumer over the mapped ring object: 0, or -1 for sizes
    /// the layout does not allow or a second call.
    ///
    /// # Safety
    /// `ring` is the object's mapping, `Layout::new(rx, tx).total()` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn vnet_port_open(ring: *mut u8, rx_slots: u32, tx_slots: u32) -> c_int {
        let Some(layout) = Layout::new(rx_slots, tx_slots) else {
            return -1;
        };
        if ring.is_null() || !(ring as usize).is_multiple_of(4) || OPEN.load(Ordering::Acquire) {
            return -1;
        }
        // SAFETY: the caller's promise.
        let p = unsafe { Port::new(ring, layout) };
        // SAFETY: nothing reads the slot before OPEN.
        unsafe { (*PORT.0.get()).write(p) };
        OPEN.store(true, Ordering::Release);
        0
    }

    /// Up to `n` frames: the count, or -1 when the ring broke a rule.
    ///
    /// # Safety
    /// `out` holds `n` entries.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn vnet_port_rx_burst(out: *mut CRx, n: c_int) -> c_int {
        let (Some(p), true) = (port(), n > 0 && !out.is_null()) else {
            return -1;
        };
        let mut got = [Rx {
            cell: 0,
            len: 0,
            flags: 0,
            frame: core::ptr::null_mut(),
        }; 32];
        let want = (n as usize).min(got.len());
        match p.rx_burst(&mut got[..want]) {
            Ok(k) => {
                for (i, r) in got.iter().take(k).enumerate() {
                    // SAFETY: `i < n`, the caller's array.
                    unsafe {
                        out.add(i).write(CRx {
                            cell: r.cell,
                            len: r.len,
                            flags: r.flags,
                            pad: 0,
                            frame: r.frame.cast(),
                        })
                    };
                }
                k as c_int
            }
            Err(Broken) => -1,
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn vnet_port_rx_return(cell: u32) {
        if let Some(p) = port() {
            p.rx_return(cell);
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn vnet_port_fill_free() -> u32 {
        port().map_or(0, |p| p.fill_free())
    }

    /// The cell the next frame is built in, NULL when TX is full.
    #[unsafe(no_mangle)]
    pub extern "C" fn vnet_port_tx_cell() -> *mut u8 {
        port()
            .and_then(|p| p.tx_cell())
            .unwrap_or(core::ptr::null_mut())
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn vnet_port_tx_submit(len: u32) {
        if let Some(p) = port() {
            p.tx_submit(len);
        }
    }

    /// The entry for the frame in the cell is a segment of TCP without its sum (`TX_SUM`).
    #[unsafe(no_mangle)]
    pub extern "C" fn vnet_port_tx_submit_sum(len: u32) {
        if let Some(p) = port() {
            p.tx_submit_sum(len);
        }
    }

    /// The entry for the packet in the cell is one of the loopback network.
    #[unsafe(no_mangle)]
    pub extern "C" fn vnet_port_tx_submit_loop(len: u32) {
        if let Some(p) = port() {
            p.tx_submit_loop(len);
        }
    }

    /// Publishes the entries written; 1 when the switch sleeps and the
    /// caller pokes it (`stafeto_fast_poke`).
    #[unsafe(no_mangle)]
    pub extern "C" fn vnet_port_tx_flush() -> c_int {
        port().map_or(0, |p| c_int::from(p.tx_flush()))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn vnet_port_work() -> c_int {
        port().map_or(0, |p| c_int::from(p.work()))
    }

    /// Flag, full barrier, one more look: 1 when a frame is there.
    #[unsafe(no_mangle)]
    pub extern "C" fn vnet_port_sleep_begin() -> c_int {
        port().map_or(1, |p| c_int::from(p.sleep_begin()))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn vnet_port_sleep_end() {
        if let Some(p) = port() {
            p.sleep_end();
        }
    }

    /// The switch's counters (line 9) into `out[0]` (rx_full) and `out[1]`
    /// (tx_refused).
    ///
    /// # Safety
    /// `out` holds two `u32`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn vnet_port_counters(out: *mut u32) {
        if let Some(p) = port() {
            let (a, b) = p.counters();
            // SAFETY: the caller's two words.
            unsafe {
                out.write(a);
                out.add(1).write(b);
            }
        }
    }
}

#[cfg(feature = "ffi")]
pub use c::CRx;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    struct Mem {
        words: Vec<u32>,
    }

    impl Mem {
        fn new(layout: Layout) -> Mem {
            Mem {
                words: vec![0; layout.total() / 4],
            }
        }
        fn base(&mut self) -> *mut u8 {
            self.words.as_mut_ptr().cast()
        }
        fn word(&mut self, at: usize) -> &AtomicU32 {
            // SAFETY: in bounds, aligned, atomic.
            unsafe { &*(self.base().add(at) as *const AtomicU32) }
        }
        /// The switch writes a frame of `len` bytes into `cell` and DONE.
        fn deliver(&mut self, l: Layout, head: u32, cell: u16, len: u16, flags: u16) {
            let at = l.done_entry(head);
            let b = Done { cell, len, flags }.to_bytes();
            for (i, c) in b.chunks(4).enumerate() {
                let w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
                self.word(at + 4 * i).store(w, Ordering::Relaxed);
            }
            self.word(DONE_HEAD)
                .store(head.wrapping_add(1), Ordering::Release);
        }
    }

    fn rig() -> (Mem, Layout, Port) {
        let l = Layout::DEFAULT;
        let mut m = Mem::new(l);
        // SAFETY: the buffer is the layout's size.
        let p = unsafe { Port::new(m.base(), l) };
        (m, l, p)
    }

    fn empty() -> [Rx; 4] {
        [Rx {
            cell: 0,
            len: 0,
            flags: 0,
            frame: core::ptr::null_mut(),
        }; 4]
    }

    #[test]
    fn open_fills_fill_with_every_cell() {
        let (mut m, l, p) = rig();
        assert_eq!(m.word(FILL_HEAD).load(Ordering::Relaxed), 1024);
        assert_eq!(m.word(l.fill_entry(0)).load(Ordering::Relaxed), 0);
        assert_eq!(m.word(l.fill_entry(1023)).load(Ordering::Relaxed), 1023);
        assert_eq!(p.fill_free(), 1024);
    }

    #[test]
    fn a_burst_reads_done_and_a_return_refills() {
        let (mut m, l, mut p) = rig();
        m.deliver(l, 0, 7, 100, 1);
        m.deliver(l, 1, 9, 60, 0);
        assert!(p.work());
        let mut out = empty();
        assert_eq!(p.rx_burst(&mut out), Ok(2));
        assert_eq!((out[0].cell, out[0].len, out[0].flags), (7, 100, 1));
        assert_eq!(out[1].cell, 9);
        assert_eq!(m.word(DONE_TAIL).load(Ordering::Relaxed), 2);
        assert!(!p.work());
        p.rx_return(7);
        assert_eq!(m.word(FILL_HEAD).load(Ordering::Relaxed), 1025);
        assert_eq!(
            m.word(l.fill_entry(1024)).load(Ordering::Relaxed),
            7,
            "the entry wraps"
        );
    }

    #[test]
    fn indices_wrap_past_u32() {
        let (mut m, l, mut p) = rig();
        p.done_tail = u32::MAX;
        m.word(DONE_HEAD).store(u32::MAX, Ordering::Relaxed);
        m.deliver(l, u32::MAX, 3, 10, 0);
        let mut out = empty();
        assert_eq!(p.rx_burst(&mut out), Ok(1));
        assert_eq!(p.done_tail, 0);
        assert_eq!(p.rx_burst(&mut out), Ok(0));
    }

    #[test]
    fn a_done_ahead_of_its_size_or_a_bad_cell_breaks() {
        let (mut m, l, mut p) = rig();
        m.word(DONE_HEAD).store(3000, Ordering::Relaxed);
        assert_eq!(p.rx_burst(&mut empty()), Err(Broken));
        let (mut m, l2, mut p) = rig();
        m.deliver(l2, 0, 2048, 10, 0);
        assert_eq!(p.rx_burst(&mut empty()), Err(Broken));
        let (mut m, l3, mut p) = rig();
        m.deliver(l3, 0, 1, 2049, 0);
        assert_eq!(p.rx_burst(&mut empty()), Err(Broken));
        let _ = l;
    }

    #[test]
    fn tx_entries_are_written_then_published_and_the_room_follows_tx_tail() {
        let (mut m, l, mut p) = rig();
        let first = p.tx_cell().unwrap();
        assert_eq!(first as usize - m.base() as usize, l.tx_cell(0));
        p.tx_submit(60);
        assert_eq!(p.tx_pending(), 1);
        assert_eq!(m.word(TX_HEAD).load(Ordering::Relaxed), 0);
        assert!(!p.tx_flush(), "the switch is awake: no poke");
        assert_eq!(m.word(TX_HEAD).load(Ordering::Relaxed), 1);
        let e = l.tx_entry(0);
        let len = m.word(e).load(Ordering::Relaxed);
        assert_eq!(len, 60, "length 60, flags 0");
        assert_eq!(m.word(e + 4).load(Ordering::Relaxed), 0);
        m.word(SWITCH_IDLE).store(1, Ordering::Relaxed);
        p.tx_submit(61);
        assert!(p.tx_flush(), "a sleeping switch is poked");
        assert!(!p.tx_flush(), "nothing pending");
    }

    #[test]
    fn tx_is_full_after_256_entries_until_tx_tail_moves() {
        let (mut m, _l, mut p) = rig();
        for _ in 0..256 {
            assert!(p.tx_cell().is_some());
            p.tx_submit(60);
        }
        assert!(p.tx_cell().is_none());
        m.word(TX_TAIL).store(10, Ordering::Release);
        assert!(p.tx_cell().is_some());
        assert_eq!(p.tx_room(), 10);
    }

    #[test]
    fn a_loop_entry_carries_its_flag_and_an_ordinary_one_has_none() {
        let (mut m, l, mut p) = rig();
        assert!(p.tx_cell().is_some());
        p.tx_submit(60);
        assert!(p.tx_cell().is_some());
        p.tx_submit_loop(70);
        let word0 = |m: &mut Mem, i: u32| m.word(l.tx_entry(i)).load(Ordering::Relaxed);
        assert_eq!(word0(&mut m, 0), 60);
        assert_eq!(word0(&mut m, 1), 70 | u32::from(sw::TX_LOOP) << 16);
    }

    #[test]
    fn a_sum_entry_carries_tx_sum_and_a_delivered_frame_its_done_flag() {
        let (mut m, l, mut p) = rig();
        assert!(p.tx_cell().is_some());
        p.tx_submit_sum(60);
        let word0 = m.word(l.tx_entry(0)).load(Ordering::Relaxed);
        assert_eq!(word0, 60 | u32::from(sw::TX_SUM) << 16);
        assert_eq!(m.word(l.tx_entry(0) + 4).load(Ordering::Relaxed), 0);
        m.deliver(l, 0, 3, 60, sw::DONE_SUM_OK | sw::DONE_LOOP);
        let mut out = empty();
        assert_eq!(p.rx_burst(&mut out), Ok(1));
        assert_eq!(out[0].flags, u32::from(sw::DONE_SUM_OK | sw::DONE_LOOP));
    }

    #[test]
    fn sleeping_clears_the_flag_when_a_frame_is_there() {
        let (mut m, l, mut p) = rig();
        assert!(!p.sleep_begin());
        assert_eq!(m.word(CONSUMER_IDLE).load(Ordering::Relaxed), 1);
        p.sleep_end();
        assert_eq!(m.word(CONSUMER_IDLE).load(Ordering::Relaxed), 0);
        m.deliver(l, 0, 1, 60, 0);
        assert!(p.sleep_begin());
        assert_eq!(m.word(CONSUMER_IDLE).load(Ordering::Relaxed), 0);
    }

    /// The writer stores DONE_HEAD, runs the barrier and reads the flag; the
    /// sleeper stores the flag, runs the barrier and looks at DONE_HEAD: one
    /// of them sees the other, so a wake is never lost.
    #[test]
    fn no_wake_is_lost_between_two_threads() {
        struct Shared(*mut u8);
        // SAFETY: the memory outlives both threads and is used atomically.
        unsafe impl Send for Shared {}
        unsafe impl Sync for Shared {}
        let l = Layout::DEFAULT;
        let mut m = Mem::new(l);
        let shared = Arc::new(Shared(m.base()));
        let woke = Arc::new(AtomicBool::new(false));
        const ROUNDS: u32 = 200_000;
        // SAFETY: as above.
        let mut p = unsafe { Port::new(shared.0, l) };
        let (s2, w2) = (shared.clone(), woke.clone());
        let writer = std::thread::spawn(move || {
            let word = |at: usize| -> &AtomicU32 {
                // SAFETY: in bounds, atomic.
                unsafe { &*(s2.0.add(at) as *const AtomicU32) }
            };
            for i in 0..ROUNDS {
                while word(DONE_TAIL).load(Ordering::Acquire) != i {
                    std::hint::spin_loop();
                }
                // The wake of the round before is stale by now.
                w2.store(false, Ordering::Relaxed);
                word(DONE_HEAD).store(i + 1, Ordering::Release);
                fence(Ordering::SeqCst);
                if word(CONSUMER_IDLE).load(Ordering::Relaxed) != 0 {
                    w2.store(true, Ordering::Release);
                }
            }
        });
        let mut out = empty();
        for _ in 0..ROUNDS {
            loop {
                if p.sleep_begin() {
                    break;
                }
                let mut spins = 0u64;
                while !woke.swap(false, Ordering::Acquire) {
                    spins += 1;
                    assert!(spins < 2_000_000_000, "a wake was lost");
                    std::hint::spin_loop();
                }
                p.sleep_end();
                if p.work() {
                    break;
                }
            }
            p.sleep_end();
            // The entry is not written (the test has no cells): consume the index.
            let head = p.word(DONE_HEAD).load(Ordering::Acquire);
            p.done_tail = head;
            p.word(DONE_TAIL).store(head, Ordering::Release);
            let _ = &mut out;
        }
        writer.join().unwrap();
    }
}
