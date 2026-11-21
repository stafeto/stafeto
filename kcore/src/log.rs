// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The ring of the kernel log (spec 3.2, 16.3): records of LOG_RECORD
//! bytes, each the time it was written, its kind and up to LOG_TEXT bytes
//! of text; a longer text takes several records in a row (`Chunks`). A
//! record the kernel showed on its console at once is marked shown; the
//! others wait for a reader, which takes them in batches of up to
//! LOG_BATCH (`take`): the cursor of what was taken is the ring's, so a
//! new reader goes on where the last one stopped. A reader on another CPU
//! reads the ring without moving that cursor (`peek_shared`) and moves the
//! `seen` cursor: what it was given counts as taken for the panic
//! (`unshown`, `merge_unseen`) and for the count of lost records. A full ring
//! writes over its oldest record, and counts it lost when nobody showed,
//! took or was given it.

use abi::{LOG_BATCH, LOG_KIND_AT, LOG_LEN_AT, LOG_RECORD, LOG_TEXT, LOG_TEXT_AT, LogBatch};
use core::cell::UnsafeCell;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering, fence};

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

const _: () = ::core::assert!(core::mem::size_of::<Record>() == LOG_RECORD);
const _: () = ::core::assert!(core::mem::offset_of!(Record, kind) == LOG_KIND_AT);
const _: () = ::core::assert!(core::mem::offset_of!(Record, len) == LOG_LEN_AT);
const _: () = ::core::assert!(core::mem::offset_of!(Record, text) == LOG_TEXT_AT);

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
///
/// The methods take `&self`: the owner CPU writes through a cell, one
/// caller at a time (the kernel's per-CPU lock), and another CPU reads the
/// ring and moves `seen` through shared references, so the atomics are never
/// behind a `&mut` of the owner.
#[repr(C)]
pub struct Ring<const N: usize> {
    /// The number of the first record the reader on another CPU was not
    /// given yet (`peek_shared`): it moves forward only. First in the
    /// structure, 5 000 bytes and more from `head` and the seqlock, so that
    /// the driver's store does not share a cache line with the words the
    /// owner writes at each record.
    seen: AtomicU64,
    inner: UnsafeCell<Inner<N>>,
    /// Odd while the owner writes a record, and one more for each record
    /// written (a seqlock): another CPU's read of the ring
    /// (`peek_shared`) takes a record only when the number is even and the
    /// same before and after its copy.
    seq: AtomicU64,
    /// The number of the first record no read of the owner passed yet. An
    /// atomic since the panic of another CPU reads it.
    taken: AtomicU64,
}

/// What only the owner writes.
struct Inner<const N: usize> {
    records: [Record; N],
    /// The number of the next record.
    head: u64,
    /// Records nobody showed or took that were written over since the
    /// last read.
    lost: u64,
}

impl<const N: usize> Ring<N> {
    /// An empty ring: all zeros.
    pub const fn new() -> Ring<N> {
        Ring {
            seen: AtomicU64::new(0),
            inner: UnsafeCell::new(Inner {
                records: [Record::EMPTY; N],
                head: 0,
                lost: 0,
            }),
            seq: AtomicU64::new(0),
            taken: AtomicU64::new(0),
        }
    }

    /// What the owner reads. Only the owner calls the methods that use it,
    /// one at a time, and a reader of another CPU touches the cells through
    /// volatile loads only (`peek_shared`, `Source`).
    fn own(&self) -> &Inner<N> {
        // SAFETY: as above; no `&mut Inner` lives while a method of the owner
        // reads.
        unsafe { &*self.inner.get() }
    }

    fn at(&self, n: u64) -> &Record {
        &self.own().records[(n % N as u64) as usize]
    }

    fn head(&self) -> u64 {
        self.own().head
    }

    /// The number of the first record a read or the panic looks at: the
    /// first no read passed and no reader of another CPU was given, or the
    /// oldest left.
    fn first(&self) -> u64 {
        Self::first_of(
            self.taken.load(Ordering::Relaxed),
            self.seen.load(Ordering::Relaxed),
            self.head(),
        )
    }

    fn first_of(taken: u64, seen: u64, head: u64) -> u64 {
        taken.max(seen).max(head.saturating_sub(N as u64))
    }

    /// Writes a record of `kind` with `text`, its first LOG_TEXT bytes, at
    /// counter ticks `time`, marked shown when the kernel showed it (spec
    /// 3.2). The oldest record goes when the ring is full, and counts as
    /// lost when nobody showed, took or was given it. O(1). Only the owner
    /// calls it, one call at a time.
    pub fn push(&self, time: u64, kind: u8, text: &[u8], shown: bool) {
        let len = text.len().min(LOG_TEXT);
        let seq = self.seq.load(Ordering::Relaxed);
        self.seq.store(seq.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        // SAFETY: the owner, one call at a time; a reader of another CPU
        // reads the cells with volatile loads between two looks at `seq`.
        let inner = unsafe { &mut *self.inner.get() };
        let place = (inner.head % N as u64) as usize;
        let record = &mut inner.records[place];
        if inner.head >= N as u64
            && !record.shown
            && matches!(record.kind, abi::LOG_TEXT_KIND | abi::LOG_KERNEL_KIND)
            && inner.head - N as u64 >= self.taken.load(Ordering::Relaxed)
            && inner.head - N as u64 >= self.seen.load(Ordering::Relaxed)
        {
            inner.lost += 1;
        }
        record.time = time;
        record.kind = kind;
        record.len = len as u8;
        record.shown = shown;
        record.text[..len].copy_from_slice(&text[..len]);
        record.text[len..].fill(0);
        inner.head += 1;
        // The number of the record goes last, with release: a reader on
        // another CPU that sees it even sees the record whole.
        self.seq.store(seq.wrapping_add(2), Ordering::Release);
    }

    /// `peek` for the ring of another CPU, which its owner writes while this
    /// reads: the records and the owner's cursor stay, and with `advance`
    /// the `seen` cursor moves to the record after the last one this gave
    /// (or lost), never back. A reader that only looks (a test of the
    /// kernel's) passes false: what it saw is still the owner's to show.
    /// Each record is copied between two looks at the seqlock and kept when
    /// the owner did not write meanwhile; one the owner wrote over is counted
    /// lost. The reader waits for the owner's push, a few instructions,
    /// which no interrupt cuts.
    ///
    /// # Safety
    /// `this` points at a ring that lives for good, written by its owner
    /// only.
    pub unsafe fn peek_shared(
        this: *const Self,
        first: u64,
        advance: bool,
        mut put: impl FnMut(usize, &Record),
    ) -> (LogBatch, u64) {
        // SAFETY: the caller's promise; every read of the cells is volatile,
        // since the owner may write the place meanwhile.
        let head = unsafe { Self::stable(this, None, Self::head_of) }
            .expect("no limit on the looks")
            .1;
        let oldest = head.saturating_sub(N as u64);
        let mut next = first.max(oldest).min(head);
        let mut lost = oldest.saturating_sub(first);
        let mut count = 0;
        while next < head && count < LOG_BATCH {
            // SAFETY: as above.
            let (_, (copy, now)) = unsafe {
                Self::stable(this, None, |r| (Self::record_of(r, next), Self::head_of(r)))
            }
            .expect("no limit on the looks");
            if now.saturating_sub(N as u64) > next {
                // Written over meanwhile.
                lost += 1;
            } else {
                put(count, &copy);
                count += 1;
            }
            next += 1;
        }
        // The feature `break-log-seen` leaves the cursor, for the probe that
        // must catch the repeat of the shown lines at the end of the system.
        if advance && !cfg!(feature = "break-log-seen") {
            // SAFETY: as above; `seen` is an atomic and no `&mut` of the
            // ring exists.
            unsafe { (*this).seen.fetch_max(next, Ordering::Relaxed) };
        }
        (
            LogBatch {
                count: count as u64,
                lost,
                left: head.saturating_sub(next),
            },
            next,
        )
    }

    /// Whether the ring of another CPU holds a record no read has passed: its
    /// `head` is past `max(taken, seen)` (the console's driver takes the
    /// records of the ring of its own CPU and reads the others with
    /// `peek_shared`). One look at the seqlock, no retry: a writer in the
    /// middle of a record (an odd number) or one that wrote meanwhile (the
    /// number changed) counts as "yes", so that a doubtful answer wakes the
    /// reader once too often and never once too rarely. O(1).
    ///
    /// # Safety
    /// As for `peek_shared`.
    pub unsafe fn has_unseen_shared(this: *const Self) -> bool {
        let mut looks = 1;
        // SAFETY: the caller's promise; the reads of the cells are volatile.
        let read = unsafe {
            Self::stable(this, Some(&mut looks), |r| {
                (
                    Self::head_of(r),
                    r.taken.load(Ordering::Relaxed),
                    r.seen.load(Ordering::Relaxed),
                )
            })
        };
        match read {
            Some((_, (head, taken, seen))) => head > taken.max(seen),
            None => true,
        }
    }

    /// The owner's `head`, by a volatile load.
    fn head_of(r: &Self) -> u64 {
        // SAFETY: a field of the cell, read by address.
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*r.inner.get()).head)) }
    }

    /// Record `n`, by a volatile load.
    fn record_of(r: &Self, n: u64) -> Record {
        let place = (n % N as u64) as usize;
        // SAFETY: a place of the array, read by address.
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*r.inner.get()).records[place])) }
    }

    /// `read` between two looks at the seqlock, again until the owner was
    /// not writing: with a `budget` of looks, shared by the calls that pass
    /// it, None once it ran out (the owner wrote all the time, or stopped
    /// inside a write); without one, as long as it takes.
    ///
    /// # Safety
    /// As for `peek_shared`.
    unsafe fn stable<T>(
        this: *const Self,
        mut budget: Option<&mut u32>,
        read: impl Fn(&Self) -> T,
    ) -> Option<(u64, T)> {
        loop {
            if let Some(left) = budget.as_deref_mut() {
                if *left == 0 {
                    return None;
                }
                *left -= 1;
            }
            // SAFETY: the caller's promise.
            let before = unsafe { (*this).seq.load(Ordering::Acquire) };
            if before & 1 == 0 {
                // SAFETY: as above; `read` copies with volatile reads.
                let value = read(unsafe { &*this });
                fence(Ordering::Acquire);
                // SAFETY: as above.
                if unsafe { (*this).seq.load(Ordering::Relaxed) } == before {
                    return Some((before, value));
                }
            }
            core::hint::spin_loop();
        }
    }

    /// A read (object_info LOG, spec 11): from the first record no read
    /// passed, or the oldest left, towards the newest, gives each record
    /// nobody showed to `put` with its place in the batch, up to
    /// LOG_BATCH, and moves the cursor past the last one it gave, or to
    /// the newest when it passed them all. Returns what it gave, the
    /// records lost since the last read, whose count starts over, and the
    /// records nobody showed or took that are left. O(N).
    ///
    /// When a reader on another CPU serves this ring (`seen` is past
    /// `taken`), that reader reports what it lost, and the count here is
    /// dropped: the same gap would come out twice.
    pub fn take(&self, mut put: impl FnMut(usize, &Record)) -> LogBatch {
        let mut count = 0;
        let mut n = self.first();
        let head = self.head();
        while n < head && count < LOG_BATCH {
            let record = self.at(n);
            if !record.shown {
                put(count, record);
                count += 1;
            }
            n += 1;
        }
        let served = self.seen.load(Ordering::Relaxed) > self.taken.load(Ordering::Relaxed);
        self.taken.store(n, Ordering::Relaxed);
        let left = (n..head).filter(|&m| !self.at(m).shown).count();
        // SAFETY: the owner, one call at a time.
        let lost = core::mem::take(&mut unsafe { &mut *self.inner.get() }.lost);
        LogBatch {
            count: count as u64,
            lost: if served { 0 } else { lost },
            left: left as u64,
        }
    }

    /// Reads from sequence `first` without moving the console reader's
    /// cursor. Includes shown text and event records. Returns the next
    /// sequence number and the count already overwritten before `first`.
    pub fn peek(&self, first: u64, mut put: impl FnMut(usize, &Record)) -> (LogBatch, u64) {
        let head = self.head();
        let oldest = head.saturating_sub(N as u64);
        let mut next = first.max(oldest).min(head);
        let lost = oldest.saturating_sub(first);
        let mut count = 0;
        while next < head && count < LOG_BATCH {
            put(count, self.at(next));
            count += 1;
            next += 1;
        }
        (
            LogBatch {
                count: count as u64,
                lost,
                left: head - next,
            },
            next,
        )
    }

    /// Gives the text records nobody showed or took to `put`, oldest
    /// first, and marks them shown: what the kernel said before it had a
    /// port, which goes out once the port is known (spec 3.2). O(N).
    pub fn show(&self, mut put: impl FnMut(&Record)) {
        // SAFETY: the owner, one call at a time.
        let inner = unsafe { &mut *self.inner.get() };
        for n in self.first()..inner.head {
            let record = &mut inner.records[(n % N as u64) as usize];
            let text = matches!(record.kind, abi::LOG_TEXT_KIND | abi::LOG_KERNEL_KIND);
            if text && !record.shown {
                put(record);
                record.shown = true;
            }
        }
    }

    /// The records nobody showed, took or was given through `peek_shared`,
    /// oldest first: what the panic prints before its report (spec 16.1).
    /// O(N).
    pub fn unshown(&self) -> impl Iterator<Item = &Record> {
        (self.first()..self.head())
            .map(|n| self.at(n))
            .filter(|r| !r.shown)
    }
}

/// A ring the panic reads (`merge_unseen`): its own CPU's, which it reads
/// as it lies, or another CPU's, which its owner may write meanwhile.
pub struct Source<'a, const N: usize>(Kind<'a, N>);

enum Kind<'a, const N: usize> {
    None,
    Own(&'a Ring<N>),
    Shared(*const Ring<N>),
}

/// What a read of a record of a source gives.
enum Read {
    Record(Record),
    /// The owner wrote over it.
    Gone,
    /// The budget of looks ran out: the owner is stuck inside a write.
    Stuck,
}

/// The looks at the seqlocks of all the rings of one `merge_unseen` may
/// make together, so that a CPU stopped inside a write costs a bounded
/// time at the end of the system.
const SPINS: u32 = 1 << 20;

impl<'a, const N: usize> Source<'a, N> {
    /// No ring: gives nothing.
    pub const fn none() -> Self {
        Source(Kind::None)
    }

    /// The ring of the CPU that reads, which nobody writes: the panic runs
    /// on that CPU, and a writer it interrupted never runs again.
    pub fn own(ring: &'a Ring<N>) -> Self {
        Source(Kind::Own(ring))
    }

    /// The ring of another CPU, read the way `peek_shared` reads it, within
    /// the budget of looks of the merge, since its owner may stop in the
    /// middle of a write.
    ///
    /// # Safety
    /// As for `Ring::peek_shared`.
    pub unsafe fn shared(ring: *const Ring<N>) -> Self {
        Source(Kind::Shared(ring))
    }

    /// The number of the first record the panic prints and the number of
    /// the next one to be written. An empty span for a ring whose owner
    /// is stuck.
    fn span(&self, budget: &mut u32) -> (u64, u64) {
        match self.0 {
            Kind::None => (0, 0),
            Kind::Own(r) => (r.first(), r.head()),
            Kind::Shared(r) => {
                // SAFETY: the caller's promise at `shared`.
                let read = unsafe {
                    Ring::stable(r, Some(budget), |r| {
                        (
                            Ring::head_of(r),
                            r.taken.load(Ordering::Relaxed),
                            r.seen.load(Ordering::Relaxed),
                        )
                    })
                };
                match read {
                    Some((_, (head, taken, seen))) => {
                        (Ring::<N>::first_of(taken, seen, head), head)
                    }
                    None => (0, 0),
                }
            }
        }
    }

    /// Record `n`.
    fn read(&self, n: u64, budget: &mut u32) -> Read {
        match self.0 {
            Kind::None => Read::Gone,
            Kind::Own(r) => {
                if n >= r.head().saturating_sub(N as u64) && n < r.head() {
                    Read::Record(*r.at(n))
                } else {
                    Read::Gone
                }
            }
            Kind::Shared(r) => {
                // SAFETY: the caller's promise at `shared`.
                let read = unsafe {
                    Ring::stable(r, Some(budget), |r| {
                        (Ring::record_of(r, n), Ring::head_of(r))
                    })
                };
                match read {
                    None => Read::Stuck,
                    Some((_, (copy, head))) if head.saturating_sub(N as u64) <= n => {
                        Read::Record(copy)
                    }
                    Some(_) => Read::Gone,
                }
            }
        }
    }
}

/// What the panic prints of several rings (spec 16.1): the records of each
/// that nobody showed, took or was given, from all of them in the order of
/// their times, ties to the first ring. `spans` has a place for each
/// source. The records each ring has when the call starts are the ones it
/// gives; what its owner writes later stays. A source whose owner is stuck
/// inside a write is given up at the first failed look, and all the looks of
/// the call share one budget (SPINS). O(rings x N) looks at records.
pub fn merge_unseen<const N: usize>(
    sources: &[Source<'_, N>],
    spans: &mut [(u64, u64)],
    mut put: impl FnMut(&Record),
) {
    let mut budget = SPINS;
    for (source, span) in sources.iter().zip(spans.iter_mut()) {
        *span = source.span(&mut budget);
    }
    loop {
        let mut best: Option<(usize, Record)> = None;
        for (i, (source, span)) in sources.iter().zip(spans.iter_mut()).enumerate() {
            while span.0 < span.1 {
                match source.read(span.0, &mut budget) {
                    Read::Record(r) if !r.shown => {
                        if best.is_none_or(|(_, b)| r.time < b.time) {
                            best = Some((i, r));
                        }
                        break;
                    }
                    Read::Stuck => *span = (0, 0),
                    _ => span.0 += 1,
                }
            }
        }
        let Some((i, r)) = best else { return };
        put(&r);
        spans[i].0 += 1;
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
    fn take_all<const N: usize>(ring: &Ring<N>) -> (Vec<Record>, Vec<LogBatch>) {
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

    /// What the kernel said before it had a port goes out once, in its
    /// order, and no reader takes it afterwards; a record shown when it
    /// was written and an event record stay as they were.
    #[test]
    fn show_gives_the_early_records_once_in_order() {
        let ring = Ring::<8>::new();
        ring.push(1, LOG_KERNEL_KIND, &numbered(0), false);
        ring.push(2, LOG_TEXT_KIND, &numbered(1), true);
        ring.push(3, 3, b"event", false);
        ring.push(4, LOG_KERNEL_KIND, &numbered(2), false);
        let mut shown = Vec::new();
        ring.show(|r| shown.push(number_of(r)));
        assert_eq!(shown, [0, 2]);
        ring.show(|_| panic!("a record went out twice"));
        let kinds: Vec<u8> = ring.unshown().map(|r| r.kind).collect();
        assert_eq!(kinds, [3]);
    }

    #[test]
    fn a_record_keeps_its_time_kind_and_text() {
        let ring = Ring::<64>::new();
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
        let ring = Ring::<64>::new();
        let line: Vec<u8> = (0..150)
            .map(|i| b'a' + (i % 26) as u8)
            .chain(*b"\n")
            .collect();
        let mut chunks = Chunks::new(|piece: &[u8]| ring.push(7, LOG_KERNEL_KIND, piece, false));
        chunks.write(&line[..100]);
        fmt::Write::write_str(&mut chunks, core::str::from_utf8(&line[100..]).unwrap()).unwrap();
        chunks.finish();
        let (records, _) = take_all(&ring);
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
        let ring = Ring::<64>::new();
        for n in 1..=70 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        let (records, batches) = take_all(&ring);
        let numbers: Vec<u64> = records.iter().map(number_of).collect();
        assert_eq!(numbers, (7..=70).collect::<Vec<_>>());
        assert_eq!(batches[0].lost, 6);
        assert!(batches[1..].iter().all(|b| b.lost == 0));
        ring.push(71, LOG_TEXT_KIND, &numbered(71), false);
        assert_eq!(ring.take(|_, _| {}).lost, 0);
    }

    #[test]
    fn a_printed_record_is_neither_taken_nor_lost() {
        let ring = Ring::<64>::new();
        for n in 1..=70 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), n % 2 == 0);
        }
        let (records, batches) = take_all(&ring);
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
        let ring = Ring::<64>::new();
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
        let ring = Ring::<64>::new();
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
    fn peek_reports_overflow_and_keeps_the_text_cursor() {
        let ring = Ring::<8>::new();
        for n in 1..=12 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        let mut got = Vec::new();
        let (batch, next) = ring.peek(0, |_, r| got.push(number_of(r)));
        assert_eq!((batch.count, batch.lost, next), (8, 4, 12));
        assert_eq!(got, (5..=12).collect::<Vec<_>>());
        let (again, _) = ring.peek(0, |_, _| {});
        assert_eq!(again.lost, 4);
        assert_eq!(ring.take(|_, _| {}).count, 8);
    }

    #[test]
    fn a_shared_peek_reads_what_peek_reads_and_changes_nothing() {
        let ring = Ring::<8>::new();
        for n in 1..=12 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        let (mut own, mut shared) = (Vec::new(), Vec::new());
        let (batch, next) = ring.peek(0, |_, r| own.push(number_of(r)));
        // SAFETY: the ring lives here and nothing writes it meanwhile.
        let (other, after) = unsafe {
            Ring::peek_shared(&ring as *const Ring<8>, 0, false, |_, r| {
                shared.push(number_of(r))
            })
        };
        assert_eq!((own, batch, next), (shared, other, after));
        assert_eq!(
            ring.taken.load(Ordering::Relaxed),
            0,
            "the owner's cursor stayed"
        );
        assert_eq!(
            ring.seen.load(Ordering::Relaxed),
            0,
            "a peek that does not advance leaves seen"
        );
        assert_eq!(
            ring.take(|_, _| {}).count,
            8,
            "and the records to the owner"
        );
        // A cursor past the newest gives nothing and the newest back.
        // SAFETY: as above.
        let (none, end) =
            unsafe { Ring::peek_shared(&ring as *const Ring<8>, u64::MAX, false, |_, _| {}) };
        assert_eq!((none.count, none.lost, end), (0, 0, 12));
    }

    #[test]
    fn each_record_is_pushed_between_an_odd_and_an_even_number() {
        let ring = Ring::<8>::new();
        assert_eq!(ring.seq.load(Ordering::Relaxed), 0);
        ring.push(1, LOG_TEXT_KIND, b"x", false);
        assert_eq!(ring.seq.load(Ordering::Relaxed), 2);
        ring.push(2, LOG_TEXT_KIND, b"y", false);
        assert_eq!(ring.seq.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn overwritten_events_do_not_report_lost_console_text() {
        let ring = Ring::<8>::new();
        for n in 1..=12 {
            ring.push(n, abi::LOG_SWITCH_KIND, b"thread=1", false);
        }
        assert_eq!(ring.peek(0, |_, _| {}).0.lost, 4);
        assert_eq!(ring.take(|_, _| {}).lost, 0);
    }

    #[test]
    fn the_unshown_are_what_nobody_printed_or_took() {
        let ring = Ring::<8>::new();
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

    /// A peek of the whole ring as the driver on another CPU makes it,
    /// batch after batch: the numbers of the records it was given.
    fn peek_all<const N: usize>(ring: &Ring<N>, from: &mut u64) -> Vec<u64> {
        let mut got = Vec::new();
        loop {
            // SAFETY: the ring lives here and nothing writes it meanwhile.
            let (batch, next) = unsafe {
                Ring::peek_shared(ring as *const Ring<N>, *from, true, |_, r| {
                    got.push(number_of(r))
                })
            };
            *from = next;
            if batch.count == 0 && batch.left == 0 {
                return got;
            }
        }
    }

    fn merged<const N: usize>(sources: &[Source<'_, N>]) -> Vec<u64> {
        let mut spans = vec![(0, 0); sources.len()];
        let mut got = Vec::new();
        merge_unseen(sources, &mut spans, |r| got.push(number_of(r)));
        got
    }

    #[test]
    fn a_shared_peek_moves_the_seen_cursor_and_never_back() {
        let ring = Ring::<8>::new();
        for n in 1..=6 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        assert_eq!(ring.seen.load(Ordering::Relaxed), 0);
        let mut from = 0;
        assert_eq!(peek_all(&ring, &mut from), [1, 2, 3, 4, 5, 6]);
        assert_eq!(ring.seen.load(Ordering::Relaxed), 6);
        // A reader that starts again from 0 does not move it back.
        let mut again = 0;
        peek_all(&ring, &mut again);
        assert_eq!(ring.seen.load(Ordering::Relaxed), 6);
        // The owner's cursor stayed.
        assert_eq!(ring.taken.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_ring_has_unseen_records_after_a_push_and_none_after_a_take_or_a_peek() {
        let ring = Ring::<8>::new();
        let has = |r: &Ring<8>| {
            // SAFETY: the ring lives here and nothing writes it meanwhile.
            unsafe { Ring::has_unseen_shared(r as *const Ring<8>) }
        };
        assert!(!has(&ring), "an empty ring has none");
        for n in 1..=3 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        assert!(has(&ring), "a pushed record is unseen");
        ring.take(|_, _| {});
        assert!(!has(&ring), "a take passes them all");
        ring.push(4, LOG_TEXT_KIND, &numbered(4), false);
        assert!(has(&ring));
        let mut from = 0;
        peek_all(&ring, &mut from);
        assert!(!has(&ring), "a peek that advances `seen` passes them");
        ring.push(5, LOG_TEXT_KIND, &numbered(5), false);
        // A peek that does not advance leaves the record unseen.
        // SAFETY: as above.
        unsafe { Ring::peek_shared(&ring as *const Ring<8>, 0, false, |_, _| {}) };
        assert!(has(&ring));
    }

    #[test]
    fn a_writer_in_the_middle_of_a_record_counts_as_unseen() {
        let ring = Ring::<8>::new();
        ring.push(1, LOG_TEXT_KIND, &numbered(1), false);
        ring.take(|_, _| {});
        // The owner stopped inside a push: the number is odd.
        ring.seq
            .store(ring.seq.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        // SAFETY: the ring lives here and nothing writes it meanwhile.
        assert!(unsafe { Ring::has_unseen_shared(&ring as *const Ring<8>) });
    }

    #[test]
    fn the_unseen_after_a_peek_leave_out_the_peeked() {
        let ring = Ring::<8>::new();
        for n in 1..=5 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        let mut from = 0;
        peek_all(&ring, &mut from);
        assert_eq!(ring.unshown().count(), 0);
        for n in 6..=7 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        let unshown: Vec<u64> = ring.unshown().map(number_of).collect();
        assert_eq!(unshown, [6, 7]);
        assert_eq!(merged(&[Source::own(&ring)]), [6, 7]);
        // SAFETY: the ring lives here and nothing writes it meanwhile.
        let shared = unsafe { Source::shared(&ring as *const Ring<8>) };
        assert_eq!(merged(&[shared]), [6, 7]);
    }

    #[test]
    fn the_lost_count_leaves_out_what_a_peek_gave() {
        let ring = Ring::<8>::new();
        for n in 1..=8 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        let mut from = 0;
        assert_eq!(peek_all(&ring, &mut from).len(), 8);
        // Four seen records go: none counts as lost.
        for n in 9..=12 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        let batch = ring.take(|_, _| {});
        assert_eq!((batch.count, batch.lost), (4, 0));
        // Without a peek the same overwrites count.
        let plain = Ring::<8>::new();
        for n in 1..=12 {
            plain.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        assert_eq!(plain.take(|_, _| {}).lost, 4);
        // A reader that passed the first three only: the rest counts.
        let quarter = Ring::<8>::new();
        for n in 1..=8 {
            quarter.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        quarter.seen.store(3, Ordering::Relaxed);
        for n in 9..=12 {
            quarter.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        // The reader of the other CPU reports record 4 itself: the owner's
        // count of it is dropped, so the gap comes out once.
        // SAFETY: the ring lives here and nothing writes it meanwhile.
        let (batch, _) =
            unsafe { Ring::peek_shared(&quarter as *const Ring<8>, 3, true, |_, _| {}) };
        assert_eq!(batch.lost, 1, "record 4 went before the peek");
        assert_eq!(quarter.take(|_, _| {}).lost, 0, "not a second time");
    }

    #[test]
    fn the_owner_counts_the_lost_when_no_other_reader_serves_the_ring() {
        let ring = Ring::<8>::new();
        for n in 1..=12 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        assert_eq!(ring.take(|_, _| {}).lost, 4);
        // A reader that looks without advancing does not serve the ring.
        let looked = Ring::<8>::new();
        for n in 1..=12 {
            looked.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        // SAFETY: the ring lives here and nothing writes it meanwhile.
        unsafe { Ring::peek_shared(&looked as *const Ring<8>, 0, false, |_, _| {}) };
        assert_eq!(looked.take(|_, _| {}).lost, 4);
    }

    #[test]
    fn the_merge_gives_up_a_stuck_ring_at_once_and_shares_one_budget() {
        let rings: Vec<Ring<8>> = (0..7).map(|_| Ring::<8>::new()).collect();
        for r in &rings {
            r.push(1, LOG_TEXT_KIND, b"x", false);
            r.seq
                .store(r.seq.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        }
        let sources: Vec<Source<'_, 8>> = rings
            .iter()
            // SAFETY: the rings live here and nothing writes them.
            .map(|r| unsafe { Source::shared(r as *const Ring<8>) })
            .collect();
        let mut spans = vec![(0, 0); 7];
        let mut gave = 0;
        // Each source fails at its span: the whole call looks SPINS times
        // at most, which a loop per ring would have exceeded seven times.
        merge_unseen(&sources, &mut spans, |_| gave += 1);
        assert_eq!(gave, 0);
    }

    #[test]
    fn the_seen_cursor_survives_a_wrap_around() {
        let ring = Ring::<8>::new();
        let mut from = 0;
        let mut seen = Vec::new();
        for n in 1..=100u64 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
            if n % 5 == 0 {
                seen.extend(peek_all(&ring, &mut from));
            }
        }
        assert_eq!(seen, (1..=100).collect::<Vec<_>>());
        assert_eq!(ring.seen.load(Ordering::Relaxed), 100);
        assert_eq!(ring.unshown().count(), 0);
        for n in 101..=103 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        assert_eq!(
            ring.unshown().map(number_of).collect::<Vec<_>>(),
            [101, 102, 103]
        );
        // A reader far behind loses the overwritten and moves seen to the end.
        let ring = Ring::<8>::new();
        for n in 1..=30 {
            ring.push(n, LOG_TEXT_KIND, &numbered(n), false);
        }
        let mut late = 0;
        assert_eq!(peek_all(&ring, &mut late), (23..=30).collect::<Vec<_>>());
        assert_eq!(ring.seen.load(Ordering::Relaxed), 30);
    }

    /// Two writers on one ring and one on another, a peeker that takes
    /// the first ring now and then, in a fixed order of steps that a
    /// generator picks: what the peeker was given and what the end path
    /// prints are disjoint, and together they are what the rings still
    /// hold and the peeker did not pass.
    #[test]
    fn two_writers_and_a_peeker_in_a_deterministic_model() {
        let (a, b) = (Ring::<8>::new(), Ring::<8>::new());
        let (mut from_a, mut from_b) = (0, 0);
        let (mut seen_a, mut seen_b) = (Vec::new(), Vec::new());
        let (mut count_a, mut count_b) = (0u64, 0u64);
        let mut x = 12345u64;
        for step in 0..600u64 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            match (x >> 33) % 6 {
                // Two writers on the ring of the CPU of A: numbers from 1000 up.
                0 | 1 => {
                    count_a += 1;
                    a.push(step, LOG_TEXT_KIND, &numbered(count_a), false);
                }
                2 => {
                    count_a += 1;
                    a.push(step, LOG_TEXT_KIND, &numbered(count_a), (x >> 40) & 1 == 1);
                }
                3 | 4 => {
                    count_b += 1;
                    b.push(step, LOG_TEXT_KIND, &numbered(count_b), false);
                }
                _ => {
                    seen_a.extend(peek_all(&a, &mut from_a));
                    if (x >> 45) & 1 == 1 {
                        seen_b.extend(peek_all(&b, &mut from_b));
                    }
                }
            }
        }
        // SAFETY: the rings live here and nothing writes them meanwhile.
        let sources = unsafe {
            [
                Source::shared(&a as *const Ring<8>),
                Source::shared(&b as *const Ring<8>),
            ]
        };
        let mut spans = [(0, 0); 2];
        let mut printed = [Vec::new(), Vec::new()];
        let mut last = 0;
        merge_unseen(&sources, &mut spans, |r| {
            assert!(r.time >= last, "the times come in order");
            last = r.time;
            printed[0].push(r.time);
            printed[1].push(number_of(r));
        });
        // Each ring alone: the unshown are the unseen that are not overwritten.
        for (ring, seen, count) in [(&a, &seen_a, count_a), (&b, &seen_b, count_b)] {
            let kept: Vec<u64> = ring.unshown().map(number_of).collect();
            assert!(kept.iter().all(|n| !seen.contains(n)), "no record twice");
            let head = count;
            for n in kept {
                assert!(
                    n > head.saturating_sub(8),
                    "only records the ring still holds"
                );
            }
        }
        // The merge gives the same records as the two rings' own lists.
        let mut all: Vec<(u64, u64)> = Vec::new();
        for ring in [&a, &b] {
            all.extend(ring.unshown().map(|r| (r.time, number_of(r))));
        }
        all.sort();
        let mut got: Vec<(u64, u64)> = printed[0]
            .iter()
            .copied()
            .zip(printed[1].iter().copied())
            .collect();
        got.sort();
        assert_eq!(got, all);
    }

    #[test]
    fn the_merge_goes_by_time_over_rings_and_skips_the_shown() {
        let (a, b) = (Ring::<8>::new(), Ring::<8>::new());
        a.push(1, LOG_TEXT_KIND, &numbered(10), false);
        b.push(2, LOG_TEXT_KIND, &numbered(20), false);
        a.push(3, LOG_TEXT_KIND, &numbered(11), true);
        a.push(4, LOG_TEXT_KIND, &numbered(12), false);
        b.push(4, LOG_TEXT_KIND, &numbered(21), false);
        b.push(9, LOG_TEXT_KIND, &numbered(22), false);
        // SAFETY: the ring b lives here and nothing writes it meanwhile.
        let sources = [
            Source::own(&a),
            unsafe { Source::shared(&b as *const Ring<8>) },
            Source::none(),
        ];
        assert_eq!(merged(&sources), [10, 20, 12, 21, 22]);
    }

    #[test]
    fn a_ring_the_owner_never_leaves_gives_nothing_and_does_not_hang() {
        let ring = Ring::<8>::new();
        ring.seq.store(1, Ordering::Relaxed);
        // SAFETY: the ring lives here and nothing writes it.
        let source = unsafe { Source::shared(&ring as *const Ring<8>) };
        assert_eq!(merged(&[source]), Vec::<u64>::new());
    }
}
