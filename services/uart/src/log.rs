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
/// `batch.count`, in their order. The pieces of a line longer than a record
/// (console_line) wait in `lines` until the line is whole, so a text of
/// the batch can be up to console_line::RECORD_OUT bytes; an empty batch
/// lets `lines` put out the lines whose writers stopped.
pub fn text(
    records: &Records,
    batch: LogBatch,
    lines: &mut console_line::Lines,
    mut put: impl FnMut(&[u8]),
) {
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
            Ok(r) if r.kind == LOG_TEXT_KIND => lines.record(r.text, &mut put),
            Ok(r) if r.kind == LOG_KERNEL_KIND => put(r.text),
            _ => {}
        }
    }
    if count == 0 && batch.lost == 0 {
        lines.quiet(&mut put);
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
    /// The last fetch of this batch found the ring empty: it is not asked
    /// again until the next batch.
    dry: bool,
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
            dry: false,
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

    /// `batch` with the two reads of a driver: `take` of the ring of its own
    /// CPU, and `peek(k, cursor, records)` of the ring of the `k`th other
    /// CPU (object_info LOG), which gives None for a CPU that does not
    /// exist. The first look at another ring starts at its oldest record,
    /// for what that CPU said before the driver started and the kernel did
    /// not show goes out too; the records the kernel showed
    /// (abi::LOG_SHOWN_AT) are left out.
    pub fn next(
        &mut self,
        take: &mut impl FnMut(&mut Records) -> LogBatch,
        peek: &mut impl FnMut(u64, u64, &mut Records) -> Option<(LogBatch, u64)>,
        out: &mut Records,
    ) -> LogBatch {
        let mut fetch = |k: usize, cursor: &mut u64, into: &mut Records| {
            if k == 0 {
                return Some(take(into));
            }
            let first = if *cursor == 0 { 1 } else { *cursor };
            let (mut batch, next) = peek(k as u64, first, into)?;
            *cursor = next;
            let count = (batch.count as usize).min(LOG_BATCH);
            let mut kept = 0;
            for i in 0..count {
                if into[i][abi::LOG_SHOWN_AT] == 0 {
                    into[kept] = into[i];
                    kept += 1;
                }
            }
            batch.count = kept as u64;
            Some(batch)
        };
        self.batch(&mut fetch, out)
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
        for s in &mut self.sources {
            s.dry = false;
        }
        while count < LOG_BATCH {
            let mut best: Option<(u64, usize)> = None;
            for k in 0..SOURCES {
                let s = &mut self.sources[k];
                if s.absent {
                    continue;
                }
                if s.next >= s.count && !s.dry {
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
                            s.dry = s.count == 0 && b.left == 0;
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

/// The drain of the kernel's rings into the output's ring of the log
/// (spec 13.5, 16.3), as a decision apart from the calls: the driver takes
/// what the rings hold, a bounded part of it in each period, so a burst
/// that fills a ring of the kernel in a few milliseconds is in the driver's
/// buffer before the ring overwrites it.
///
/// The batches the driver takes in one period at most, all entry points
/// together: only the timer's tick takes (and the driver's start, once
/// before its first tick). A batch counts whatever text it adds, so the
/// bound holds with the records of the trace build, which add none. A
/// period then costs at most STEP_BATCHES times the calls of one batch
/// (`Sources::batch`: one object_info LOG of each source that has
/// records), and the driver takes at most 12 records in 2.5 ms, 4.8 a millisecond. A tick that
/// takes nothing costs about 3,200 ticks under -icount and a record about 800 (xtask
/// posix-tty-steps, the table of tag 18: a tick of 24 records took 22,600 to 23,100 ticks, past
/// the 18,369 a service step may take, and the cost of a record is what dominates, so the fixed
/// part of a batch is no reason to take two); one batch is about 12,900 ticks, 71 % of that
/// bound, and xtask posix-tty-steps checks the longest tick. The driver also has a budget of
/// 150 us of each 10 ms (9,375 ticks): the idle tick (about 110 us with the kernel's entries) fits
/// one piece of it, a tick of 12 records (206 us) does not, so while a backlog lasts the first of
/// the four ticks of a period (one each 2.5 ms) is cut at 150 us (0.73 of a tick) and the rest
/// of it and of the other three run at level 32, which the CPU gives the driver only when no level
/// from 33 to 59 runs. With those levels saturated the driver moves about 8.7 records in 10 ms,
/// 0.87 a millisecond, and a burst of 2.5 records a millisecond loses the records the ring of 64
/// cannot hold, the number the model of `run_saturated` gives (the lost count of the next batch
/// tells it). With one batch a tick the driver can also lose a few records of the kernel's own
/// trace burst in the trace dialog (three in the measured run), counted, within the rule that a
/// log line never waits.
pub const STEP_BATCHES: usize = 1;

/// The period of the reads while the driver holds log text it has not put
/// out, or the rings hold records it has not taken, in nanoseconds: a
/// period takes up to STEP_BATCHES of 12 records. The period was 10 ms with three batches
/// (3.6 records a millisecond); 2.5 ms with one gives 4.8, above the 2.5 lines a millisecond of
/// the console probes' burst.
pub const DRAIN_NS: u64 = 2_500_000;

/// The period of the reads while it holds none, in nanoseconds. The ring of
/// a CPU holds 64 records, so a writer that comes while the driver is idle
/// loses none while it writes less than 64 records in one period: 3 records
/// a millisecond, twice the rate of the boot burst of 150 records in 100 ms.
/// An idle system wakes the driver 50 times a second.
pub const IDLE_NS: u64 = 20_000_000;

/// The period of the safety tick of the mode with the log's binding, in
/// nanoseconds: the kernel's notification wakes the driver when a record lands
/// (spec 9, kernel/src/log.rs), and the tick only checks that none was
/// missed. An idle system wakes the driver once a second.
pub const SAFETY_NS: u64 = 1_000_000_000;

/// The period of the reads of the log with the binding of the log's line:
/// DRAIN_NS while the driver is not `drained`, since it holds text, the
/// rings hold records, a line waits for its empty batches (console_line::QUIET)
/// or the driver stops, and the kernel will not say that nothing more comes;
/// SAFETY_NS once it is, and the kernel's notification is what wakes it.
pub fn period_bound_ns(drained: bool) -> u64 {
    if drained { SAFETY_NS } else { DRAIN_NS }
}

/// Whether the driver may acknowledge the binding of the log's line, which
/// arms the kernel's notification of the next record: the rings hold no
/// record the driver has not taken (`more`), the text it took went out
/// (`log_done`), no line of the log is open (`lines_open`) and the driver is
/// not stopping (`stopping`: its exit waits for the ticks of the drain). The
/// kernel looks at the rings once more when it takes the acknowledgement, so
/// a record that came meanwhile posts at once.
pub fn drained(more: bool, log_done: bool, lines_open: bool, stopping: bool) -> bool {
    !more && log_done && !lines_open && !stopping
}

/// When the driver takes the log after the kernel's notification: at most
/// once in DRAIN_NS, whatever the rate of the notifications, so that the
/// work of a period (STEP_BATCHES) stays what it is with the timer alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pace {
    last: Option<u64>,
}

/// What `Pace::notified` says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Due {
    /// Take now.
    Now,
    /// Set the timer to this time, in nanoseconds, and take then.
    At(u64),
}

impl Pace {
    pub const fn new() -> Pace {
        Pace { last: None }
    }

    /// The log was taken at `now` (nanoseconds): by the timer, by a
    /// notification or at the start.
    pub fn took(&mut self, now: u64) {
        self.last = Some(now);
    }

    /// The kernel's notification came at `now`: now when the last take is
    /// DRAIN_NS or more behind, otherwise the time that makes it so.
    pub fn notified(&self, now: u64) -> Due {
        match self.last {
            Some(last) if now < last.saturating_add(DRAIN_NS) => Due::At(last + DRAIN_NS),
            _ => Due::Now,
        }
    }
}

/// A tick of the safety timer that found records: the kernel's notification
/// was missed unless the binding is masked (the kernel posted it, and it is
/// on its way). The driver says it once and counts the cases.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Missed {
    cases: u64,
}

impl Missed {
    pub const fn new() -> Missed {
        Missed { cases: 0 }
    }

    /// A safety tick took `records` records while the binding was `masked`
    /// (or not: `masked` is None when it could not be read). Gives the
    /// number to say at the first miss.
    pub fn tick(&mut self, records: usize, masked: Option<bool>) -> Option<usize> {
        if records == 0 || masked == Some(true) {
            return None;
        }
        self.cases += 1;
        (self.cases == 1).then_some(records)
    }

    /// The cases so far.
    pub fn cases(&self) -> u64 {
        self.cases
    }
}

/// Whether the driver takes one more batch in this period: `taken` batches
/// went in, `room` bytes of the output's ring of the log are free. A batch
/// is taken only when its worst text fits, so nothing the driver took is
/// dropped; with the buffer full the driver stops taking and the kernel
/// counts what its ring overwrites in `lost` of its next batch.
pub fn take_more(taken: usize, room: usize) -> bool {
    taken < STEP_BATCHES && room >= crate::output::LOG_BYTES
}

/// The period until the next tick, after a step that ended with `left`
/// records in the rings and `room` bytes free in the output's ring of the
/// log: DRAIN_NS while text is held or records wait, IDLE_NS otherwise.
/// Never "at once": a step that finds the log not accepted (a client's
/// DRAIN is pending) or the buffer full takes nothing, and asking again
/// immediately would spin at the driver's level.
pub fn period_ns(left: u64, room: usize) -> u64 {
    if room < crate::output::LOG_RING || left > 0 {
        DRAIN_NS
    } else {
        IDLE_NS
    }
}

/// The largest backlog of the kernel's rings the driver saw in a run, in
/// records (what a batch took and what the rings still held), and the
/// largest it said. The driver says it once the backlog is out, when it
/// is above one batch and above what it said before.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Peak {
    seen: u64,
    said: u64,
}

impl Peak {
    pub const fn new() -> Peak {
        Peak { seen: 0, said: 0 }
    }

    /// A batch of `batch.count` records was taken with `batch.left` left.
    pub fn batch(&mut self, batch: LogBatch) {
        self.seen = self.seen.max(batch.count + batch.left);
    }

    /// The backlog to say now, if any: `idle` says the driver holds no
    /// text and the rings no records, or the driver ends.
    pub fn say(&mut self, idle: bool) -> Option<u64> {
        if idle && self.seen > LOG_BATCH as u64 && self.seen > self.said {
            self.said = self.seen;
            return Some(self.seen);
        }
        None
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
        text(&batch, info, &mut console_line::Lines::new(), |piece| {
            out.extend_from_slice(piece)
        });
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
        text(&out, batch, &mut console_line::Lines::new(), |p| {
            texts.extend_from_slice(p)
        });
        assert_eq!(texts, b"c0a0b0b1a1c1");
        assert_eq!((batch.count, batch.left), (6, 0));
        assert!(!sources.more());
    }

    #[test]
    fn the_first_look_at_another_ring_shows_what_the_kernel_did_not() {
        let mut shown = raw(5, LOG_TEXT_KIND, b"shown");
        shown[abi::LOG_SHOWN_AT] = 1;
        let ring1 = [
            shown,
            raw(6, LOG_TEXT_KIND, b"early"),
            raw(9, LOG_TEXT_KIND, b"late"),
        ];
        let mut sources = Sources::new();
        let mut out: Records = [[0; LOG_RECORD]; LOG_BATCH];
        let mut take = |_: &mut Records| LogBatch {
            count: 0,
            lost: 0,
            left: 0,
        };
        let mut peek = |k: u64, cursor: u64, into: &mut Records| {
            if k != 1 {
                return None;
            }
            let from = (cursor - 1) as usize;
            for (i, r) in ring1[from..].iter().enumerate() {
                into[i] = *r;
            }
            Some((
                LogBatch {
                    count: (ring1.len() - from) as u64,
                    lost: 0,
                    left: 0,
                },
                ring1.len() as u64 + 1,
            ))
        };
        let batch = sources.next(&mut take, &mut peek, &mut out);
        let mut texts = Vec::new();
        text(&out, batch, &mut console_line::Lines::new(), |p| {
            texts.extend_from_slice(p)
        });
        assert_eq!(texts, b"earlylate");
        // The next look goes on where the last stopped: nothing new.
        let again = sources.next(&mut take, &mut peek, &mut out);
        assert_eq!(again.count, 0);
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

    #[test]
    fn the_pieces_of_two_writers_come_out_as_whole_lines() {
        let a: &[u8] = b"service step: 12 kind 64 3480 ticks of 23806, the longest of its loop\n";
        let b: &[u8] = b"store-probe: refused TOO_LONG, the receipt is gone, nothing changed\n";
        let pieces = |id: u32, line: &[u8]| -> Vec<Vec<u8>> {
            let n = line.chunks(console_line::PAYLOAD).count();
            line.chunks(console_line::PAYLOAD)
                .enumerate()
                .map(|(k, c)| {
                    let mut out = [0; 64];
                    let len = if k == 0 {
                        console_line::first_piece(id, c, &mut out)
                    } else {
                        console_line::piece(id, k + 1 == n, c, &mut out)
                    };
                    out[..len].to_vec()
                })
                .collect()
        };
        let records = [pieces(7, a), pieces(11, b)];
        // B's first piece, A's first piece, a whole line, then the rest.
        let order = [
            records[1][0].clone(),
            records[0][0].clone(),
            b"entropy: seeded from the boot page (32 bytes)\n".to_vec(),
            records[0][1].clone(),
            records[1][1].clone(),
        ];
        let raws: Vec<_> = order.iter().map(|t| raw(1, LOG_TEXT_KIND, t)).collect();
        let mut batch: Records = [[0; LOG_RECORD]; LOG_BATCH];
        batch[..raws.len()].copy_from_slice(&raws);
        let info = LogBatch {
            count: raws.len() as u64,
            lost: 0,
            left: 0,
        };
        let mut lines = console_line::Lines::new();
        let mut out: Vec<Vec<u8>> = Vec::new();
        text(&batch, info, &mut lines, |p| out.push(p.to_vec()));
        assert!(out.contains(&a.to_vec()), "{out:?}");
        assert!(out.contains(&b.to_vec()), "{out:?}");
        assert!(out.contains(&b"entropy: seeded from the boot page (32 bytes)\n".to_vec()));
    }

    /// A model of the kernel's ring of one CPU (kcore::log): CAP records,
    /// the oldest overwritten and counted when it is full, taken in batches.
    struct Kernel {
        ring: std::collections::VecDeque<u32>,
        lost: u64,
    }

    const CAP: usize = 64;
    /// The bytes of the text of one record in the model, and what the port
    /// puts out in a millisecond (uart::irq TX_PASS and TX_GAP_NS).
    const LINE: usize = 60;
    const PORT_PER_MS: usize = 32;
    /// The model steps in units of half a millisecond (the period of the drain is 2.5 ms).
    const UNIT_NS: u64 = 500_000;

    impl Kernel {
        fn push(&mut self, id: u32) {
            if self.ring.len() == CAP {
                self.ring.pop_front();
                self.lost += 1;
            }
            self.ring.push_back(id);
        }

        fn take(&mut self) -> (Vec<u32>, u64, u64) {
            let n = self.ring.len().min(LOG_BATCH);
            let got: Vec<u32> = self.ring.drain(..n).collect();
            (got, core::mem::take(&mut self.lost), self.ring.len() as u64)
        }
    }

    /// What the driver delivers to the port in a run of the model.
    #[derive(Default)]
    struct Run {
        delivered: Vec<u32>,
        lost: u64,
        peak_held: usize,
        longest_step: usize,
        /// The units of the model the steps ran at.
        steps_at: Vec<u32>,
    }

    /// `pushes` records arrive in the first `span_ms` milliseconds, evenly;
    /// the driver, idle, has its first step `phase` milliseconds into the
    /// run, and steps by the rule of `new` (take_more, next_step) or by the
    /// old one (one batch each 50 ms); the port puts out PORT_PER_MS bytes
    /// a millisecond, whole lines. Runs for `total_ms`.
    fn run(pushes: u32, span_ms: u32, total_ms: u32, new: bool, phase: u32) -> Run {
        let mut kernel = Kernel {
            ring: Default::default(),
            lost: 0,
        };
        let mut held: std::collections::VecDeque<u32> = Default::default();
        let mut run = Run::default();
        let mut owed = 0usize;
        let mut next_at = phase * 2;
        let mut sent = 0;
        for ms in 0..total_ms * 2 {
            while sent < pushes
                && u64::from(sent) * u64::from(span_ms) * 2 <= u64::from(ms) * u64::from(pushes)
            {
                kernel.push(sent);
                sent += 1;
            }
            // The port: PORT_PER_MS bytes of the lines in `held`.
            owed += PORT_PER_MS / 2;
            while owed >= LINE && !held.is_empty() {
                run.delivered.push(held.pop_front().unwrap());
                owed -= LINE;
            }
            if held.is_empty() {
                owed = owed.min(LINE);
            }
            // The driver: one step when its tick comes.
            if ms >= next_at {
                let mut taken = 0;
                let mut left = kernel.ring.len() as u64;
                loop {
                    let room = crate::output::LOG_RING - held.len() * LINE;
                    let more = if new {
                        take_more(taken, room)
                    } else {
                        taken < 1 && held.is_empty()
                    };
                    if !more {
                        break;
                    }
                    let (got, lost, rest) = kernel.take();
                    run.lost += lost;
                    held.extend(got);
                    taken += 1;
                    left = rest;
                    if left == 0 {
                        break;
                    }
                }
                run.steps_at.push(ms);
                run.longest_step = run.longest_step.max(taken);
                run.peak_held = run.peak_held.max(held.len() * LINE);
                let room = crate::output::LOG_RING - held.len() * LINE;
                next_at = ms
                    + if new {
                        (period_ns(left, room) / UNIT_NS) as u32
                    } else {
                        100
                    };
            }
        }
        run.lost += kernel.lost;
        run
    }

    /// As `run` for the driver that has the kernel's notification (`Pace`,
    /// `drained`, `period_bound_ns`): it has just taken the log and
    /// acknowledged the binding, so it sleeps until the first record, which
    /// the kernel posts `start_ms` milliseconds into the run; the safety tick is
    /// SAFETY_NS away. The records come as in `run`; the notification takes
    /// the log at once when the last take is DRAIN_NS behind, and at the time
    /// that makes it so otherwise. After a step the driver acknowledges when
    /// the ring is empty and the buffer is out, and ticks at DRAIN_NS until then.
    fn run_bound(pushes: u32, span_ms: u32, total_ms: u32, start_ms: u32) -> Run {
        let mut kernel = Kernel {
            ring: Default::default(),
            lost: 0,
        };
        let mut held: std::collections::VecDeque<u32> = Default::default();
        let mut run = Run::default();
        let mut owed = 0usize;
        let mut pace = Pace::new();
        pace.took(0);
        let mut armed = true;
        let mut next_at = (SAFETY_NS / UNIT_NS) as u32;
        let mut sent = 0;
        let start = start_ms * 2;
        for ms in 0..(total_ms + start_ms) * 2 {
            let before = sent;
            while ms >= start
                && sent < pushes
                && u64::from(sent) * u64::from(span_ms) * 2
                    <= u64::from(ms - start) * u64::from(pushes)
            {
                kernel.push(sent);
                sent += 1;
            }
            // The kernel posts the first record that lands while the binding
            // is armed, and the driver sees the notification at once.
            if armed && sent > before {
                armed = false;
                next_at = match pace.notified(u64::from(ms) * UNIT_NS) {
                    Due::Now => ms,
                    Due::At(at) => (at / UNIT_NS) as u32,
                };
            }
            owed += PORT_PER_MS / 2;
            while owed >= LINE && !held.is_empty() {
                run.delivered.push(held.pop_front().unwrap());
                owed -= LINE;
            }
            if held.is_empty() {
                owed = owed.min(LINE);
            }
            if ms >= next_at {
                let mut taken = 0;
                let mut left = kernel.ring.len() as u64;
                loop {
                    let room = crate::output::LOG_RING - held.len() * LINE;
                    if !take_more(taken, room) {
                        break;
                    }
                    let (got, lost, rest) = kernel.take();
                    run.lost += lost;
                    held.extend(got);
                    taken += 1;
                    left = rest;
                    if left == 0 {
                        break;
                    }
                }
                run.steps_at.push(ms);
                pace.took(u64::from(ms) * UNIT_NS);
                run.longest_step = run.longest_step.max(taken);
                run.peak_held = run.peak_held.max(held.len() * LINE);
                let done = drained(left > 0, held.is_empty(), false, false);
                armed = done;
                next_at = ms + (period_bound_ns(done) / UNIT_NS) as u32;
            }
        }
        run.lost += kernel.lost;
        run
    }

    #[test]
    fn a_boot_burst_comes_out_whole_with_the_notification_at_any_start() {
        // The first record lands at any time after the last take, the
        // distance of which decides whether the notification takes at once or
        // waits for DRAIN_NS; the idle period (SAFETY_NS) plays no part.
        for start in 0..40 {
            for (pushes, span) in [(150, 100), (150, 60), (64, 1)] {
                let r = run_bound(pushes, span, 1000, start);
                assert_eq!(r.lost, 0, "start {start}, {pushes} in {span} ms");
                assert_eq!(
                    r.delivered,
                    (0..pushes).collect::<Vec<u32>>(),
                    "start {start}, {pushes} in {span} ms"
                );
                assert!(r.longest_step <= STEP_BATCHES);
                assert!(r.peak_held <= crate::output::LOG_RING);
            }
        }
    }

    #[test]
    fn the_notification_takes_the_log_at_most_once_in_the_drain_period() {
        for start in 0..40 {
            let r = run_bound(150, 60, 1000, start);
            let gap = (DRAIN_NS / UNIT_NS) as u32;
            assert!(
                r.steps_at.windows(2).all(|w| w[1] - w[0] >= gap),
                "start {start}: {:?}",
                &r.steps_at[..r.steps_at.len().min(12)]
            );
        }
    }

    #[test]
    fn a_single_record_in_an_idle_system_comes_out_within_a_step() {
        // The driver slept since the last take: the record is taken at the
        // unit it lands, and a lone record is out in one step.
        let r = run_bound(1, 1, 1000, 100);
        assert_eq!(r.delivered, [0]);
        assert_eq!(r.steps_at[0], 200);
        // And the driver went back to sleep: no tick in the next 900 ms
        // but for the lines it still held and the end of its drain.
        assert!(r.steps_at.len() <= 3, "{:?}", r.steps_at);
    }

    #[test]
    fn an_idle_driver_with_the_notification_ticks_once_a_second() {
        let r = run_bound(0, 1, 10_500, 0);
        assert_eq!(r.steps_at.len(), 10);
    }

    #[test]
    fn the_notification_comes_at_most_once_in_a_period_and_waits_for_the_pace() {
        let mut pace = Pace::new();
        assert_eq!(pace.notified(5), Due::Now, "nothing taken yet");
        pace.took(1_000);
        assert_eq!(pace.notified(1_000), Due::At(1_000 + DRAIN_NS));
        assert_eq!(
            pace.notified(1_000 + DRAIN_NS - 1),
            Due::At(1_000 + DRAIN_NS)
        );
        assert_eq!(pace.notified(1_000 + DRAIN_NS), Due::Now);
        assert_eq!(pace.notified(u64::MAX), Due::Now);
    }

    #[test]
    fn the_binding_is_acknowledged_only_when_everything_is_out() {
        assert!(drained(false, true, false, false));
        assert!(
            !drained(true, true, false, false),
            "records are in the rings"
        );
        assert!(
            !drained(false, false, false, false),
            "text waits for the port"
        );
        assert!(!drained(false, true, true, false), "a line is open");
        assert!(!drained(false, true, false, true), "the driver stops");
        assert_eq!(period_bound_ns(true), SAFETY_NS);
        assert_eq!(period_bound_ns(false), DRAIN_NS);
    }

    #[test]
    fn a_safety_tick_that_finds_records_is_said_once_and_counted() {
        let mut missed = Missed::new();
        assert_eq!(missed.tick(0, Some(false)), None);
        // The kernel posted: the notification is on its way.
        assert_eq!(missed.tick(3, Some(true)), None);
        assert_eq!(missed.cases(), 0);
        assert_eq!(missed.tick(3, Some(false)), Some(3));
        assert_eq!(missed.tick(5, None), None, "said once");
        assert_eq!(missed.cases(), 2);
    }

    #[test]
    fn a_boot_burst_of_150_records_comes_out_whole_with_the_drain() {
        // Whatever the phase of the driver's idle tick against the burst.
        for phase in 0..(IDLE_NS / 1_000_000) as u32 {
            let r = run(150, 100, 1000, true, phase);
            assert_eq!(r.lost, 0, "phase {phase}");
            assert_eq!(r.delivered, (0..150).collect::<Vec<u32>>(), "phase {phase}");
            assert!(r.longest_step <= STEP_BATCHES);
            assert!(r.peak_held <= crate::output::LOG_RING);
        }
    }

    #[test]
    fn the_burst_of_the_console_probes_at_2_5_lines_a_millisecond_comes_out_whole() {
        // apps/shell logburst: 150 lines, 5 at a time every 2 ms, so 60 ms; the driver idle, its
        // first tick at any phase of its idle period.
        for phase in 0..(IDLE_NS / 1_000_000) as u32 {
            let r = run(150, 60, 1000, true, phase);
            assert_eq!(r.lost, 0, "phase {phase}");
            assert_eq!(r.delivered, (0..150).collect::<Vec<u32>>(), "phase {phase}");
        }
    }

    /// What the log tick costs under -icount, in ticks of the counter (xtask posix-tty-steps, the
    /// table of tag 18): the tick that finds nothing about 3,200 and a record about 800 (a tick
    /// of 24 records took 22,600 to 23,100), and the budget of the driver, 150 us of each 10 ms,
    /// 9,375 ticks.
    const TICK_FIXED: u64 = 3_200;
    const PER_RECORD: u64 = 808;
    const BUDGET_TICKS: u64 = 9_375;
    /// What the model gives for the burst of 150 records over the phases of the first tick: the
    /// ring of 64 and the records taken while the burst lasts leave this many overwritten.
    const SATURATED_LOST_MIN: u64 = 26;
    const SATURATED_LOST_MAX: u64 = 49;

    /// The driver when levels 33 to 59 never leave the CPU: it works at its own level only for its
    /// budget (refilled to 9,375 ticks every 10 ms), and a tick the budget cuts goes on in the next
    /// period. A tick takes its records when it starts, at the first moment the tick of the last
    /// one is done and the period (DRAIN_NS while records are left, IDLE_NS otherwise) has passed.
    /// `pushes` records arrive evenly in `span_ms`. Gives the records lost and delivered.
    fn run_saturated(pushes: u32, span_ms: u32, total_ms: u32, phase: u32) -> (u64, usize) {
        let mut kernel = Kernel {
            ring: Default::default(),
            lost: 0,
        };
        let mut delivered = 0usize;
        let mut lost = 0u64;
        let mut sent = 0;
        let mut credit = 0u64;
        let mut left = 0u64;
        let mut busy = false;
        let mut next_at = phase * 2;
        for t in 0..total_ms * 2 {
            while sent < pushes
                && u64::from(sent) * u64::from(span_ms) * 2 <= u64::from(t) * u64::from(pushes)
            {
                kernel.push(sent);
                sent += 1;
            }
            if t % 20 == 0 {
                credit = BUDGET_TICKS;
            }
            if !busy && t >= next_at {
                let take = kernel.ring.len().min(STEP_BATCHES * LOG_BATCH);
                kernel.ring.drain(..take);
                lost += core::mem::take(&mut kernel.lost);
                delivered += take;
                left = TICK_FIXED + take as u64 * PER_RECORD;
                busy = true;
            }
            if busy {
                let spent = credit.min(left);
                credit -= spent;
                left -= spent;
                if left == 0 {
                    busy = false;
                    next_at = t + if kernel.ring.is_empty() {
                        (IDLE_NS / UNIT_NS) as u32
                    } else {
                        (DRAIN_NS / UNIT_NS) as u32
                    };
                }
            }
        }
        (lost + kernel.lost, delivered)
    }

    #[test]
    fn the_burst_with_levels_33_to_59_saturated_loses_records_and_counts_them() {
        // The records a period takes under the budget: 9,375 ticks of a tick that costs 3,200 and
        // 808 a record, 8.7 records in 10 ms, 0.87 a millisecond, against the 2.5 of the burst.
        // Whatever the phase of the first tick, the ring (64) overflows and the kernel counts what
        // it overwrote; every record is delivered or counted.
        let mut worst = (u64::MAX, 0);
        for phase in 0..(IDLE_NS / 1_000_000) as u32 {
            let (lost, delivered) = run_saturated(150, 60, 4000, phase);
            assert_eq!(delivered as u64 + lost, 150, "phase {phase}");
            worst = (worst.0.min(lost), worst.1.max(lost));
        }
        assert_eq!(worst, (SATURATED_LOST_MIN, SATURATED_LOST_MAX));
    }

    #[test]
    fn the_burst_with_idle_middle_levels_loses_none_under_the_budget() {
        // The driver at 32 runs whenever nothing at 33 to 59 does: the budget does not cut its
        // rate, and the model of the drain (no loss at any phase) stands.
        for phase in 0..(IDLE_NS / 1_000_000) as u32 {
            let r = run(150, 60, 1000, true, phase);
            assert_eq!(r.lost, 0, "phase {phase}");
        }
    }

    #[test]
    fn the_same_burst_loses_records_with_one_batch_each_50_ms() {
        for phase in 0..50 {
            let r = run(150, 100, 1000, false, phase);
            assert!(r.lost > 0, "phase {phase}: {}", r.lost);
            assert!(r.delivered.len() < 150);
            assert_eq!(r.delivered.len() as u64 + r.lost, 150);
        }
    }

    #[test]
    fn with_the_buffer_full_the_driver_stops_and_the_kernel_counts() {
        // 1500 records at once: more than the buffer (16 KiB, 273 lines of
        // the model) and the ring together.
        let r = run(1500, 1, 20_000, true, 0);
        assert!(r.peak_held <= crate::output::LOG_RING);
        assert!(r.lost > 0);
        assert_eq!(r.delivered.len() as u64 + r.lost, 1500);
        // What came out is in order.
        assert!(r.delivered.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn the_decision_is_bounded_and_falls_back_to_idle() {
        assert!(take_more(0, crate::output::LOG_BYTES));
        assert!(!take_more(0, crate::output::LOG_BYTES - 1));
        assert!(!take_more(STEP_BATCHES, crate::output::LOG_RING));
        // The period is never zero, whatever is left: a step that takes
        // nothing (log not accepted, buffer full) does not ask again at once.
        assert_eq!(period_ns(5, crate::output::LOG_RING), DRAIN_NS);
        assert_eq!(period_ns(5, 10), DRAIN_NS);
        assert_eq!(period_ns(0, 10), DRAIN_NS);
        assert_eq!(period_ns(0, crate::output::LOG_RING), IDLE_NS);
        // The records a period takes at most, even when no batch adds text
        // (the trace build): STEP_BATCHES batches of LOG_BATCH.
        let mut taken = 0;
        while take_more(taken, crate::output::LOG_RING) {
            taken += 1;
        }
        assert_eq!(taken * LOG_BATCH, 12);
    }

    #[test]
    fn the_peak_is_said_once_the_backlog_is_out_and_only_when_it_grew() {
        let mut p = Peak::new();
        let batch = |count, left| LogBatch {
            count,
            lost: 0,
            left,
        };
        p.batch(batch(12, 0));
        assert_eq!(p.say(true), None);
        p.batch(batch(12, 40));
        assert_eq!(p.say(false), None);
        assert_eq!(p.say(true), Some(52));
        assert_eq!(p.say(true), None);
        p.batch(batch(12, 20));
        assert_eq!(p.say(true), None);
        p.batch(batch(12, 60));
        assert_eq!(p.say(true), Some(72));
    }

    #[test]
    fn a_source_found_empty_is_asked_once_in_a_batch() {
        let rings = [vec![], vec![], vec![raw(1, LOG_TEXT_KIND, b"x")]];
        let mut sources = Sources::new();
        let mut out: Records = [[0; LOG_RECORD]; LOG_BATCH];
        let mut asked = [0; SOURCES];
        let mut inner = ring(&rings);
        let mut fetch = |k: usize, c: &mut u64, into: &mut Records| {
            asked[k] += 1;
            inner(k, c, into)
        };
        let batch = sources.batch(&mut fetch, &mut out);
        assert_eq!(batch.count, 1);
        assert!(asked.iter().all(|&n| n <= 2), "{asked:?}");
    }
}
