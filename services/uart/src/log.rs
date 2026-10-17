// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel log as the driver shows it (spec 13.5, 16.3): a batch of
//! object_info LOG (rt::sys::log_take) becomes the text of the output's
//! stream of the log. The records lost before the batch come out first as
//! one line, then the texts of the records of debug_write and of the
//! kernel in their order, joined as they come: a text longer than a
//! record took several in a row. Records of other kinds, which later
//! milestones add, are skipped, and so is a record that does not read.

use abi::{
    LOG_BATCH, LOG_KERNEL_KIND, LOG_KIND_AT, LOG_LEN_AT, LOG_RECORD, LOG_TEXT, LOG_TEXT_AT,
    LOG_TEXT_KIND, LogBatch,
};
use core::fmt::{self, Write};

/// The records of one batch, as rt::sys::log_take fills them.
pub type Records = [[u8; LOG_RECORD]; LOG_BATCH];

/// A record of the kernel log: its time in counter ticks, its kind and
/// its text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub time: u64,
    pub kind: u8,
    pub text: &'a [u8],
}

/// The length of a record's text is 0 or past abi::LOG_TEXT: the record
/// does not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadLength(pub u8);

/// The record in `bytes`, in the layout of abi::LOG_RECORD.
pub fn record(bytes: &[u8; LOG_RECORD]) -> Result<Record<'_>, BadLength> {
    let len = bytes[LOG_LEN_AT];
    if len == 0 || usize::from(len) > LOG_TEXT {
        return Err(BadLength(len));
    }
    Ok(Record {
        time: u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
        kind: bytes[LOG_KIND_AT],
        text: &bytes[LOG_TEXT_AT..LOG_TEXT_AT + usize::from(len)],
    })
}

/// The longest line of records lost.
pub const LOST_LINE: usize = 48;

/// Bytes formatted into a line of LOST_LINE bytes at most.
struct Line {
    bytes: [u8; LOST_LINE],
    len: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        let room = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        room.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// The text of the batch `batch` that object_info LOG put in `records`,
/// a piece at a time to `put`: `[kernel log: N records lost]` on a line
/// of its own when records were lost, then the texts of the records of
/// abi::LOG_TEXT_KIND and abi::LOG_KERNEL_KIND among the first
/// `batch.count`, in their order.
pub fn text(records: &Records, batch: LogBatch, mut put: impl FnMut(&[u8])) {
    if batch.lost > 0 {
        let mut line = Line {
            bytes: [0; LOST_LINE],
            len: 0,
        };
        let noun = if batch.lost == 1 { "record" } else { "records" };
        if writeln!(line, "[kernel log: {} {noun} lost]", batch.lost).is_ok() {
            put(&line.bytes[..line.len]);
        }
    }
    let count = (batch.count as usize).min(LOG_BATCH);
    for bytes in &records[..count] {
        match record(bytes) {
            Ok(r) if r.kind == LOG_TEXT_KIND || r.kind == LOG_KERNEL_KIND => put(r.text),
            _ => {}
        }
    }
}

/// The rings of the CPUs the driver shows: its own CPU's, taken, and those
/// of up to SOURCES - 1 other CPUs, peeked at (SMP stage 4, review 3 of
/// stage 3: `take` is of the CPU's own ring, and the driver merges what the
/// others wrote by the counter at which each record was written).
pub const SOURCES: usize = 4;

/// What the driver holds of one ring: up to LOG_BATCH records it fetched and
/// has not put out, and, for a ring it peeks at, where it goes on.
pub struct Source {
    records: Records,
    /// Records in `records`, and the next one to put out.
    count: usize,
    next: usize,
    /// The cursor of a peek (sequence plus one): 0 before the first, then
    /// where the next one starts.
    pub cursor: u64,
    /// The ring does not exist: no such CPU.
    absent: bool,
    /// Records the fetch said were left in the ring.
    left: u64,
    /// Records lost that no batch told of yet.
    lost: u64,
}

impl Source {
    pub const fn new() -> Source {
        Source {
            records: [[0; LOG_RECORD]; LOG_BATCH],
            count: 0,
            next: 0,
            cursor: 0,
            absent: false,
            left: 0,
            lost: 0,
        }
    }

    /// The time of the record this source puts out next, if it holds one.
    fn time(&self) -> Option<u64> {
        let bytes = self
            .records
            .get(self.next)
            .filter(|_| self.next < self.count)?;
        Some(u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")))
    }
}

impl Default for Source {
    fn default() -> Self {
        Self::new()
    }
}

/// The sources of the driver, merged.
pub struct Sources {
    pub sources: [Source; SOURCES],
}

impl Sources {
    pub const fn new() -> Sources {
        Sources {
            sources: [const { Source::new() }; SOURCES],
        }
    }

    /// Whether the driver has records to put out or knows of some left in a
    /// ring.
    pub fn more(&self) -> bool {
        self.sources.iter().any(|s| s.next < s.count || s.left > 0)
    }

    /// The next batch, up to LOG_BATCH records in the order of the times
    /// they were written, from the sources' records and from `fetch` where a
    /// source ran dry: `fetch(k, cursor, records)` fills `records` from
    /// source `k` (0 takes the own ring, k > 0 peeks at the kth other CPU's
    /// from `cursor`) and says what came, or None for a ring that does not
    /// exist. A source is asked again only when its records are all put out.
    /// The batch goes into `out`; `left` of it counts what the driver
    /// still holds and what the rings said they have.
    pub fn batch(
        &mut self,
        fetch: &mut impl FnMut(usize, &mut u64, &mut Records) -> Option<LogBatch>,
        out: &mut Records,
    ) -> LogBatch {
        let mut count = 0;
        let mut lost = 0;
        while count < LOG_BATCH {
            let mut best: Option<(u64, usize)> = None;
            for k in 0..SOURCES {
                let s = &mut self.sources[k];
                if s.absent {
                    continue;
                }
                if s.next >= s.count {
                    match fetch(k, &mut s.cursor, &mut s.records) {
                        None => {
                            s.absent = true;
                            continue;
                        }
                        Some(b) => {
                            s.count = (b.count as usize).min(LOG_BATCH);
                            s.next = 0;
                            s.left = b.left;
                            s.lost += b.lost;
                        }
                    }
                }
                if let Some(t) = s.time()
                    && best.is_none_or(|(bt, _)| t < bt)
                {
                    best = Some((t, k));
                }
            }
            let Some((_, k)) = best else { break };
            let s = &mut self.sources[k];
            out[count] = s.records[s.next];
            s.next += 1;
            count += 1;
        }
        for s in &mut self.sources {
            lost += core::mem::take(&mut s.lost);
        }
        let left: u64 = self
            .sources
            .iter()
            .map(|s| (s.count - s.next) as u64 + if s.next >= s.count { s.left } else { 0 })
            .sum();
        LogBatch {
            count: count as u64,
            lost,
            left,
        }
    }
}

impl Default for Sources {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// A record of `kind` with `text` at time `time`, in the layout of
    /// abi::LOG_RECORD.
    fn raw(time: u64, kind: u8, text: &[u8]) -> [u8; LOG_RECORD] {
        let mut r = [0; LOG_RECORD];
        r[..8].copy_from_slice(&time.to_le_bytes());
        r[LOG_KIND_AT] = kind;
        r[LOG_LEN_AT] = text.len() as u8;
        r[LOG_TEXT_AT..LOG_TEXT_AT + text.len()].copy_from_slice(text);
        r
    }

    /// The text of a batch of `records`, with `lost` records lost.
    fn joined(records: &[[u8; LOG_RECORD]], lost: u64) -> Vec<u8> {
        let mut batch: Records = [[0; LOG_RECORD]; LOG_BATCH];
        batch[..records.len()].copy_from_slice(records);
        let info = LogBatch {
            count: records.len() as u64,
            lost,
            left: 0,
        };
        let mut out = Vec::new();
        text(&batch, info, |piece| out.extend_from_slice(piece));
        out
    }

    #[test]
    fn log_records_refuse_a_length_past_64() {
        let full = raw(7, LOG_TEXT_KIND, &[b'x'; LOG_TEXT]);
        assert_eq!(
            record(&full),
            Ok(Record {
                time: 7,
                kind: LOG_TEXT_KIND,
                text: &[b'x'; LOG_TEXT],
            })
        );
        let mut long = full;
        long[LOG_LEN_AT] = 65;
        assert_eq!(record(&long), Err(BadLength(65)));
        let mut empty = full;
        empty[LOG_LEN_AT] = 0;
        assert_eq!(record(&empty), Err(BadLength(0)));
        assert_eq!(joined(&[long, full, empty], 0), [b'x'; LOG_TEXT]);
    }

    #[test]
    fn lost_records_come_out_as_a_line() {
        let r = raw(1, LOG_TEXT_KIND, b"init: services started\n");
        assert_eq!(
            joined(&[r], 6),
            b"[kernel log: 6 records lost]\ninit: services started\n"
        );
        assert_eq!(joined(&[], 1), b"[kernel log: 1 record lost]\n");
        assert_eq!(joined(&[r], 0), b"init: services started\n");
        let most = joined(&[], u64::MAX);
        assert!(most.starts_with(b"[kernel log: 18446744073709551615 records lost]"));
    }

    #[test]
    fn records_of_other_kinds_are_skipped() {
        let records = [
            raw(1, LOG_KERNEL_KIND, &[b'k'; LOG_TEXT]),
            raw(2, 3, b"an event of a later milestone"),
            raw(3, LOG_KERNEL_KIND, b" ELR=0x1000\n"),
            raw(4, 0, b"a place never written"),
            raw(5, LOG_TEXT_KIND, b"shell: crashing uart\n"),
        ];
        let mut want = [b'k'; LOG_TEXT].to_vec();
        want.extend_from_slice(b" ELR=0x1000\nshell: crashing uart\n");
        assert_eq!(joined(&records, 0), want);
    }

    /// A source for `batch`: the records of ring `k`, `LOG_BATCH` at a time.
    fn ring(
        rings: &[Vec<[u8; LOG_RECORD]>],
    ) -> impl FnMut(usize, &mut u64, &mut Records) -> Option<LogBatch> + '_ {
        move |k, cursor, into| {
            let all = rings.get(k)?;
            let from = *cursor as usize;
            let part: Vec<_> = all.iter().skip(from).take(LOG_BATCH).collect();
            for (i, r) in part.iter().enumerate() {
                into[i] = **r;
            }
            *cursor += part.len() as u64;
            Some(LogBatch {
                count: part.len() as u64,
                lost: 0,
                left: (all.len() - (from + part.len())) as u64,
            })
        }
    }

    #[test]
    fn records_of_every_cpu_come_out_in_the_order_of_their_times() {
        let rings = [
            vec![raw(10, LOG_TEXT_KIND, b"a0"), raw(40, LOG_TEXT_KIND, b"a1")],
            vec![raw(20, LOG_TEXT_KIND, b"b0"), raw(30, LOG_TEXT_KIND, b"b1")],
            vec![raw(5, LOG_TEXT_KIND, b"c0"), raw(50, LOG_TEXT_KIND, b"c1")],
        ];
        let mut sources = Sources::new();
        let mut out: Records = [[0; LOG_RECORD]; LOG_BATCH];
        let batch = sources.batch(&mut ring(&rings), &mut out);
        let mut texts = Vec::new();
        text(&out, batch, |p| texts.extend_from_slice(p));
        assert_eq!(texts, b"c0a0b0b1a1c1");
        assert_eq!((batch.count, batch.left), (6, 0));
        assert!(!sources.more());
    }

    #[test]
    fn a_ring_with_more_than_a_batch_goes_on_in_the_next() {
        let many: Vec<_> = (0..20).map(|n| raw(100 + n, LOG_TEXT_KIND, b"x")).collect();
        let rings = [many, vec![raw(1, LOG_TEXT_KIND, b"y")]];
        let mut sources = Sources::new();
        let mut out: Records = [[0; LOG_RECORD]; LOG_BATCH];
        let mut fetch = ring(&rings);
        let first = sources.batch(&mut fetch, &mut out);
        assert_eq!(first.count, LOG_BATCH as u64);
        assert_eq!(out[0][LOG_TEXT_AT], b'y');
        assert!(sources.more());
        let second = sources.batch(&mut fetch, &mut out);
        assert_eq!(first.count + second.count, 21);
        assert!(!sources.more());
    }
}
