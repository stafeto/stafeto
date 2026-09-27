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
}
