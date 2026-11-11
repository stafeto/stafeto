// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The ring of time stamps of one CPU (the kernel feature `stamps`, a
//! debug build). A record is two words: the counter ticks, then the key,
//! the point and the CPU (abi::INFO_STAMPS). Only the owner writes, with
//! interrupts masked, with plain stores and no lock: the words and the
//! count are atomics that the owner loads and stores relaxed (one
//! instruction each), and the count goes last with release, so that a
//! reader on another CPU that sees it sees the records below it. A full
//! ring writes over its oldest record. The memory comes from frames at
//! boot (`install`); a ring without memory takes no record.

use abi::STAMPS_BATCH;
use core::sync::atomic::{
    AtomicPtr, AtomicU64,
    Ordering::{Acquire, Relaxed, Release},
};

/// What a read of the ring gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Batch {
    /// The records given, at most abi::STAMPS_BATCH.
    pub count: u64,
    /// The number of the record after the last one given.
    pub next: u64,
    /// The records the ring has made in all.
    pub head: u64,
    /// The leading records among `count` that the owner wrote over while
    /// they were read: the reader drops them.
    pub torn: u64,
}

/// The words of a record: the ticks, and the key, point and CPU.
pub fn pack(time: u64, point: u8, cpu: u8, key: u32) -> [u64; 2] {
    [
        time,
        u64::from(key) | u64::from(point) << 32 | u64::from(cpu) << 40,
    ]
}

/// The ring: a power of two of records in memory the owner got.
pub struct Ring {
    words: AtomicPtr<AtomicU64>,
    /// The records in the ring minus one (a power of two minus one), 0 while
    /// there is no memory: what a read uses.
    mask: AtomicU64,
    /// What the owner's `push` uses: `mask`, or 0 once the ring is frozen.
    write_mask: AtomicU64,
    /// The number of the next record.
    head: AtomicU64,
}

impl Ring {
    /// A ring without memory.
    pub const fn new() -> Ring {
        Ring {
            words: AtomicPtr::new(core::ptr::null_mut()),
            mask: AtomicU64::new(0),
            write_mask: AtomicU64::new(0),
            head: AtomicU64::new(0),
        }
    }

    /// Gives the ring `records` records at `words`, which must hold zero
    /// or more records already written by nobody.
    ///
    /// # Safety
    /// `words` points at `2 * records` words that live for good and that
    /// nothing else uses, and `records` is a power of two above 1.
    pub unsafe fn install(&self, words: *mut u64, records: usize) {
        assert!(records.is_power_of_two() && records > 1, "a ring of stamps");
        self.head.store(0, Relaxed);
        self.mask.store(records as u64 - 1, Relaxed);
        self.write_mask.store(records as u64 - 1, Relaxed);
        self.words.store(words.cast(), Release);
    }

    /// Stops the ring taking records, for good: the records it holds stay,
    /// so that a dump that takes long reads what the load made, not what
    /// the idle CPU wrote meanwhile. Any CPU; the owner may finish the
    /// record it is writing.
    pub fn freeze(&self) {
        self.write_mask.store(0, Relaxed);
    }

    /// Whether the ring has memory.
    pub fn is_installed(&self) -> bool {
        self.mask.load(Relaxed) != 0
    }

    /// Writes a record, over the oldest when the ring is full. The owner
    /// only, with interrupts masked. O(1): about a dozen instructions.
    #[inline(always)]
    pub fn push(&self, time: u64, point: u8, cpu: u8, key: u32) {
        let mask = self.write_mask.load(Relaxed);
        if mask == 0 {
            return;
        }
        let n = self.head.load(Relaxed);
        let [w0, w1] = pack(time, point, cpu, key);
        // SAFETY: `install` gave `mask + 1` records of two words, and the
        // place is below that.
        unsafe {
            let at = self.words.load(Relaxed).add(((n & mask) * 2) as usize);
            (*at).store(w0, Relaxed);
            (*at.add(1)).store(w1, Relaxed);
        }
        self.head.store(n + 1, Release);
    }

    /// Up to abi::STAMPS_BATCH records from number `first` on, in order, to
    /// `put(i, words)`; a `first` past the head gives none, one older than
    /// the ring holds starts at the oldest record. Reads from any CPU and
    /// changes nothing: the owner may write meanwhile, and the records it
    /// wrote over during the read are counted in `torn`.
    pub fn read(&self, first: u64, mut put: impl FnMut(usize, [u64; 2])) -> Batch {
        let mask = self.mask.load(Relaxed);
        if mask == 0 {
            return Batch::default();
        }
        let len = mask + 1;
        let head = self.head.load(Acquire);
        let start = if cfg!(feature = "break-stamps-wrap") {
            first.min(head)
        } else {
            first.max(head.saturating_sub(len)).min(head)
        };
        let count = (head - start).min(STAMPS_BATCH as u64);
        let words = self.words.load(Acquire);
        for i in 0..count {
            // SAFETY: as in `push`.
            let (w0, w1) = unsafe {
                let at = words.add((((start + i) & mask) * 2) as usize);
                ((*at).load(Relaxed), (*at.add(1)).load(Relaxed))
            };
            put(i as usize, [w0, w1]);
        }
        // The owner wrote over the records from `start` up to this number
        // while they were read.
        let now = self.head.load(Acquire);
        let torn = now.saturating_sub(len).saturating_sub(start).min(count);
        let next = if cfg!(feature = "break-stamps-portion") {
            start + count + u64::from(count == STAMPS_BATCH as u64)
        } else {
            start + count
        };
        Batch {
            count,
            next,
            head,
            torn,
        }
    }
}

impl Default for Ring {
    fn default() -> Ring {
        Ring::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn ring(records: usize) -> (Ring, &'static mut [u64]) {
        let words: &'static mut [u64] = vec![0u64; records * 2].leak();
        let ring = Ring::new();
        // SAFETY: the memory is leaked, so it lives for good, and only this
        // ring uses it.
        unsafe { ring.install(words.as_mut_ptr(), records) };
        (ring, words)
    }

    /// Every record from number `first` on, portion after portion, with
    /// the numbers of the portions' first records.
    fn dump(ring: &Ring, mut first: u64) -> (Vec<[u64; 2]>, Vec<Batch>) {
        let (mut all, mut batches) = (Vec::new(), Vec::new());
        loop {
            let mut got = Vec::new();
            let b = ring.read(first, |_, w| got.push(w));
            batches.push(b);
            if b.count == 0 {
                return (all, batches);
            }
            all.extend(got.into_iter().skip(b.torn as usize));
            first = b.next;
        }
    }

    fn rec(n: u64) -> [u64; 2] {
        pack(1000 + n, (n % 6 + 1) as u8, (n % 4) as u8, n as u32)
    }

    fn fill(ring: &Ring, from: u64, to: u64) {
        for n in from..to {
            let [t, _] = rec(n);
            ring.push(t, (n % 6 + 1) as u8, (n % 4) as u8, n as u32);
        }
    }

    #[test]
    fn a_ring_without_memory_takes_and_gives_nothing() {
        let ring = Ring::new();
        ring.push(1, 2, 3, 4);
        assert!(!ring.is_installed());
        assert_eq!(ring.read(0, |_, _| panic!("a record")), Batch::default());
    }

    #[test]
    fn a_frozen_ring_takes_no_more_records_and_keeps_what_it_holds() {
        let (ring, _) = ring(16);
        fill(&ring, 0, 20);
        ring.freeze();
        fill(&ring, 20, 40);
        let (all, batches) = dump(&ring, 0);
        assert_eq!(all, (4..20).map(rec).collect::<Vec<_>>());
        assert_eq!(batches[0].head, 20);
    }

    #[test]
    fn a_record_has_the_ticks_then_key_point_and_cpu() {
        assert_eq!(pack(7, 2, 3, 0x1234), [7, 0x1234 | 2 << 32 | 3 << 40]);
    }

    #[test]
    fn records_come_back_in_order_before_the_ring_wraps() {
        let (ring, _) = ring(16);
        fill(&ring, 0, 10);
        let (all, _) = dump(&ring, 0);
        assert_eq!(all, (0..10).map(rec).collect::<Vec<_>>());
    }

    #[test]
    fn a_wrapped_ring_gives_the_newest_records_and_none_that_were_written_over() {
        let (ring, _) = ring(16);
        fill(&ring, 0, 40);
        let (all, batches) = dump(&ring, 0);
        assert_eq!(all, (24..40).map(rec).collect::<Vec<_>>());
        assert_eq!(batches[0].head, 40);
        // The next record after the last is the head.
        assert_eq!(batches.iter().map(|b| b.count).sum::<u64>(), 16);
        // A cursor inside the ring goes on from there.
        let (tail, _) = dump(&ring, 30);
        assert_eq!(tail, (30..40).map(rec).collect::<Vec<_>>());
    }

    #[test]
    fn a_dump_in_portions_loses_no_record_at_a_portion_edge() {
        let records = 4 * STAMPS_BATCH.next_power_of_two();
        let (ring, _) = ring(records);
        let made = 3 * STAMPS_BATCH as u64 + 7;
        fill(&ring, 0, made);
        let (all, batches) = dump(&ring, 0);
        assert_eq!(all, (0..made).map(rec).collect::<Vec<_>>());
        assert_eq!(
            batches.iter().map(|b| b.count).collect::<Vec<_>>(),
            [60, 60, 60, 7, 0]
        );
        assert_eq!(batches[0].next, 60);
        assert_eq!(batches[3].next, made);
    }

    #[test]
    fn a_cursor_past_the_head_gives_nothing() {
        let (ring, _) = ring(16);
        fill(&ring, 0, 5);
        let b = ring.read(99, |_, _| panic!("a record"));
        assert_eq!((b.count, b.next, b.head), (0, 5, 5));
    }

    #[test]
    fn records_the_owner_wrote_over_during_a_read_are_counted_torn() {
        let (ring, _) = ring(128);
        fill(&ring, 0, 128);
        // The owner writes 10 records while the reader takes the first.
        let mut got = Vec::new();
        let b = ring.read(0, |i, w| {
            got.push(w);
            if i == 0 {
                fill(&ring, 128, 138);
            }
        });
        assert_eq!((b.count, b.torn, b.next), (60, 10, 60));
        // The records after the torn ones are the true ones.
        assert_eq!(&got[10..], &(10..60).map(rec).collect::<Vec<_>>()[..]);
    }

    #[test]
    fn the_record_is_whole_before_the_count_shows_it() {
        let (ring, words) = ring(16);
        ring.push(11, 5, 1, 99);
        assert_eq!(ring.head.load(Relaxed), 1);
        assert_eq!(words[0], 11);
        assert_eq!(words[1], pack(11, 5, 1, 99)[1]);
    }
}
