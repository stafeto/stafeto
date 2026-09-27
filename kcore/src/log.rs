// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The ring of the kernel log (spec 3.2, 16.3): records of LOG_RECORD
//! bytes, each the time it was written, its kind and up to LOG_TEXT bytes
//! of text; a longer text takes several records in a row (`Chunks`). A
//! record the kernel showed on its console at once is marked shown; the
//! others wait for a reader, which takes them in batches of up to
//! LOG_BATCH (`take`): the cursor of what was taken is the ring's, so a
//! new reader goes on where the last one stopped. A full ring writes over
//! its oldest record, and counts it lost when nobody showed or took it.

use abi::{LOG_BATCH, LOG_KIND_AT, LOG_LEN_AT, LOG_RECORD, LOG_TEXT, LOG_TEXT_AT, LogBatch};
use core::fmt;

/// A record of the ring: LOG_RECORD bytes, as abi::LOG_RECORD lays them
/// out but for byte 10, which holds `shown` here (spec 16.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Record {
    /// The counter ticks when it was written.
    pub time: u64,
    /// abi::LOG_TEXT_KIND or LOG_KERNEL_KIND; 0 in a place never written.
    pub kind: u8,
    /// The bytes of `text` that count, 1 to LOG_TEXT.
    len: u8,
    /// The kernel showed it on its console when it was written.
    pub shown: bool,
    /// Zeros, bytes 11 to 15.
    zero: [u8; LOG_TEXT_AT - 11],
    text: [u8; LOG_TEXT],
}

const _: () = assert!(core::mem::size_of::<Record>() == LOG_RECORD);
const _: () = assert!(core::mem::offset_of!(Record, kind) == LOG_KIND_AT);
const _: () = assert!(core::mem::offset_of!(Record, len) == LOG_LEN_AT);
const _: () = assert!(core::mem::offset_of!(Record, text) == LOG_TEXT_AT);

impl Record {
    /// A place never written: all zeros, so a ring lies in .bss.
    const EMPTY: Record = Record {
        time: 0,
        kind: 0,
        len: 0,
        shown: false,
        zero: [0; LOG_TEXT_AT - 11],
        text: [0; LOG_TEXT],
    };

    /// Its text, at most LOG_TEXT bytes whatever its length says: the
    /// panic reads the ring without the lock, and a record it finds half
    /// written gives no more than that.
    pub fn text(&self) -> &[u8] {
        &self.text[..usize::from(self.len).min(LOG_TEXT)]
    }

    /// The record as the message buffer takes it (abi::LOG_RECORD), in
    /// words, least significant byte first: the time, the kind and the
    /// length with zeros after them, then the text with zeros past its
    /// length.
    pub fn words(&self) -> [u64; LOG_RECORD / 8] {
        const TEXT_WORD: usize = LOG_TEXT_AT / 8;
        let mut words = [0; LOG_RECORD / 8];
        words[0] = self.time;
        words[LOG_KIND_AT / 8] = u64::from(self.kind) << (8 * (LOG_KIND_AT % 8))
            | u64::from(self.len) << (8 * (LOG_LEN_AT % 8));
        for (i, w) in words[TEXT_WORD..].iter_mut().enumerate() {
            *w = u64::from_le_bytes(self.text[8 * i..8 * i + 8].try_into().expect("a word"));
        }
        words
    }
}

/// The ring of `N` records (spec 16.3). Records have numbers from 0 in
/// the order they were written; record `n` lies in place `n % N` until
/// record `n + N` writes over it.
pub struct Ring<const N: usize> {
    records: [Record; N],
    /// The number of the next record.
    head: u64,
    /// The number of the first record no read passed yet.
    taken: u64,
    /// Records nobody showed or took that were written over since the
    /// last read.
    lost: u64,
}

impl<const N: usize> Ring<N> {
    /// An empty ring: all zeros.
    pub const fn new() -> Ring<N> {
        Ring {
            records: [Record::EMPTY; N],
            head: 0,
            taken: 0,
            lost: 0,
        }
    }

    fn at(&self, n: u64) -> &Record {
        &self.records[(n % N as u64) as usize]
    }

    /// The number of the first record a read or the panic looks at: the
    /// first no read passed, or the oldest left.
    fn first(&self) -> u64 {
        self.taken.max(self.head.saturating_sub(N as u64))
    }

    /// Writes a record of `kind` with `text`, its first LOG_TEXT bytes, at
    /// counter ticks `time`, marked shown when the kernel showed it (spec
    /// 3.2). The oldest record goes when the ring is full, and counts as
    /// lost when nobody showed or took it. O(1).
    pub fn push(&mut self, time: u64, kind: u8, text: &[u8], shown: bool) {
        let len = text.len().min(LOG_TEXT);
        let place = (self.head % N as u64) as usize;
        let record = &mut self.records[place];
        if self.head >= N as u64 && self.head - N as u64 >= self.taken && !record.shown {
            self.lost += 1;
        }
        record.time = time;
        record.kind = kind;
        record.len = len as u8;
        record.shown = shown;
        record.text[..len].copy_from_slice(&text[..len]);
        record.text[len..].fill(0);
        self.head += 1;
    }

    /// A read (object_info LOG, spec 11): from the first record no read
    /// passed, or the oldest left, towards the newest, gives each record
    /// nobody showed to `put` with its place in the batch, up to
    /// LOG_BATCH, and moves the cursor past the last one it gave, or to
    /// the newest when it passed them all. Returns what it gave, the
    /// records lost since the last read, whose count starts over, and the
    /// records nobody showed or took that are left. O(N).
    pub fn take(&mut self, mut put: impl FnMut(usize, &Record)) -> LogBatch {
        let mut count = 0;
        let mut n = self.first();
        while n < self.head && count < LOG_BATCH {
            let record = self.at(n);
            if !record.shown {
                put(count, record);
                count += 1;
            }
            n += 1;
        }
        self.taken = n;
        let left = (n..self.head).filter(|&m| !self.at(m).shown).count();
        LogBatch {
            count: count as u64,
            lost: core::mem::take(&mut self.lost),
            left: left as u64,
        }
    }

    /// The records nobody showed or took, oldest first: what the panic
    /// prints before its report (spec 16.1). O(N).
    pub fn unshown(&self) -> impl Iterator<Item = &Record> {
        (self.first()..self.head)
            .map(|n| self.at(n))
            .filter(|r| !r.shown)
    }
}

impl<const N: usize> Default for Ring<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Text on its way into records (spec 16.3): the bytes written to it go
/// to `sink` in pieces of LOG_TEXT bytes, as each fills, and the rest at
/// `finish`; nothing goes for no bytes.
pub struct Chunks<F: FnMut(&[u8])> {
    buf: [u8; LOG_TEXT],
    len: usize,
    sink: F,
}

impl<F: FnMut(&[u8])> Chunks<F> {
    pub fn new(sink: F) -> Chunks<F> {
        Chunks {
            buf: [0; LOG_TEXT],
            len: 0,
            sink,
        }
    }

    /// Adds `bytes`; each full piece goes to the sink.
    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.buf[self.len] = b;
            self.len += 1;
            if self.len == LOG_TEXT {
                (self.sink)(&self.buf);
                self.len = 0;
            }
        }
    }

    /// The last piece, if any bytes are left, goes to the sink.
    pub fn finish(mut self) {
        if self.len > 0 {
            (self.sink)(&self.buf[..self.len]);
        }
    }
}

impl<F: FnMut(&[u8])> fmt::Write for Chunks<F> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::{LOG_KERNEL_KIND, LOG_TEXT_KIND};
    use std::vec::Vec;

    /// Everything `take` gives, batch after batch, until a batch is
    /// empty: the records and the batches.
    fn take_all<const N: usize>(ring: &mut Ring<N>) -> (Vec<Record>, Vec<LogBatch>) {
        let (mut records, mut batches) = (Vec::new(), Vec::new());
        loop {
            let batch = ring.take(|i, r| {
                assert_eq!(i, records.len() % LOG_BATCH);
                records.push(*r)
            });
            batches.push(batch);
            if batch.count == 0 {
                return (records, batches);
            }
        }
    }

    /// A text with the number `n`, as the tests write them.
    fn numbered(n: u64) -> Vec<u8> {
        format!("record {n}\n").into_bytes()
    }

    fn number_of(r: &Record) -> u64 {
        let text = core::str::from_utf8(r.text()).unwrap();
        text.trim_start_matches("record ")
            .trim_end()
            .parse()
            .unwrap()
    }

    #[test]
    fn a_record_keeps_its_time_kind_and_text() {
        let mut ring = Ring::<64>::new();
        ring.push(0x1234_5678_9ABC, LOG_TEXT_KIND, b"hello stafeto\n", false);
        let mut got = Vec::new();
        let batch = ring.take(|_, r| got.push(*r));
        assert_eq!(
            batch,
            LogBatch {
                count: 1,
                lost: 0,
                left: 0
            }
        );
        let r = got[0];
        assert_eq!(
            (r.time, r.kind, r.text()),
            (0x1234_5678_9ABC, 1, &b"hello stafeto\n"[..])
        );
        let words = r.words();
        assert_eq!(words[0], 0x1234_5678_9ABC);
        assert_eq!(words[1], 1 | 14 << 8);
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(&bytes[LOG_TEXT_AT..LOG_TEXT_AT + 14], b"hello stafeto\n");
        assert!(bytes[LOG_TEXT_AT + 14..].iter().all(|&b| b == 0));
    }

    #[test]
    fn a_line_longer_than_64_bytes_takes_several_records() {
        let mut ring = Ring::<64>::new();
        let line: Vec<u8> = (0..150)
            .map(|i| b'a' + (i % 26) as u8)
            .chain(*b"\n")
            .collect();
        let mut chunks = Chunks::new(|piece: &[u8]| ring.push(7, LOG_KERNEL_KIND, piece, false));
        chunks.write(&line[..100]);
        fmt::Write::write_str(&mut chunks, core::str::from_utf8(&line[100..]).unwrap()).unwrap();
        chunks.finish();
        let (records, _) = take_all(&mut ring);
        let lens: Vec<usize> = records.iter().map(|r| r.text().len()).collect();
        assert_eq!(lens, [64, 64, 23]);
        assert!(records.iter().all(|r| r.kind == LOG_KERNEL_KIND));
        let joined: Vec<u8> = records.iter().flat_map(|r| r.text().to_vec()).collect();
        assert_eq!(joined, line);
        let mut none = 0;
        Chunks::new(|_: &[u8]| none += 1).finish();
        assert_eq!(none, 0);
    }

    #[test]
    fn a_full_ring_drops_the_oldest_and_counts_it_lost() {
        let mut ring = Ring::<64>::new();
        for n in 1..=70 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        let (records, batches) = take_all(&mut ring);
        let numbers: Vec<u64> = records.iter().map(number_of).collect();
        assert_eq!(numbers, (7..=70).collect::<Vec<_>>());
        assert_eq!(batches[0].lost, 6);
        assert!(batches[1..].iter().all(|b| b.lost == 0));
        ring.push(71, LOG_TEXT_KIND, &numbered(71), false);
        assert_eq!(ring.take(|_, _| {}).lost, 0);
    }

    #[test]
    fn a_printed_record_is_neither_taken_nor_lost() {
        let mut ring = Ring::<64>::new();
        for n in 1..=70 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), n % 2 == 0);
        }
        let (records, batches) = take_all(&mut ring);
        let numbers: Vec<u64> = records.iter().map(number_of).collect();
        assert_eq!(numbers, (7..=70).step_by(2).collect::<Vec<_>>());
        assert_eq!(batches[0].lost, 3);
        for n in 71..=200 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), true);
        }
        assert_eq!(
            ring.take(|_, _| panic!("a shown record was taken")),
            LogBatch {
                count: 0,
                lost: 0,
                left: 0
            }
        );
    }

    #[test]
    fn a_batch_takes_at_most_12_records_in_order() {
        let mut ring = Ring::<64>::new();
        for n in 1..=20 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        let mut got = Vec::new();
        let batch = ring.take(|_, r| got.push(number_of(r)));
        assert_eq!(
            batch,
            LogBatch {
                count: 12,
                lost: 0,
                left: 8
            }
        );
        assert_eq!(got, (1..=12).collect::<Vec<_>>());
    }

    #[test]
    fn a_batch_moves_the_cursor_past_what_it_took() {
        let mut ring = Ring::<64>::new();
        for n in 1..=12 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        ring.push(13, LOG_TEXT_KIND, &numbered(13), true);
        ring.push(14, LOG_TEXT_KIND, &numbered(14), false);
        ring.take(|_, _| {});
        let mut got = Vec::new();
        let batch = ring.take(|_, r| got.push(number_of(r)));
        assert_eq!((got, batch.left), (vec![14], 0));
        assert_eq!(
            ring.take(|_, _| panic!("a record was taken twice")).count,
            0
        );
        ring.push(15, LOG_TEXT_KIND, &numbered(15), false);
        let mut got = Vec::new();
        ring.take(|_, r| got.push(number_of(r)));
        assert_eq!(got, [15]);
    }

    #[test]
    fn the_unshown_are_what_nobody_printed_or_took() {
        let mut ring = Ring::<8>::new();
        for n in 1..=4 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        let mut first = Vec::new();
        let taken = ring.take(|_, r| first.push(number_of(r)));
        assert_eq!(taken.count, 4);
        for n in 5..=12 {
            ring.push(n, LOG_KERNEL_KIND, &numbered(n), n == 6);
        }
        ring.push(13, LOG_TEXT_KIND, &numbered(13), true);
        let unshown: Vec<u64> = ring.unshown().map(number_of).collect();
        assert_eq!(unshown, [7, 8, 9, 10, 11, 12]);
        assert_eq!(ring.take(|_, _| {}).lost, 1);
    }
}
