// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The line discipline under arbitrary input: a run of bytes is a
//! program of operations (`run`), and every program, the committed corpus
//! (corpus/) and 10^5 random bytes from a fixed seed, ends with no
//! panic and keeps the invariants after each operation: the queue and the
//! line within their bounds, ERASE never past the start of a line, the
//! echo of one byte within ECHO_MAX, a read within its count and its
//! deadline after its time. The same programs run on the discipline and
//! on a reference written apart from it (`reference`): the bytes for the
//! device, each read's result and its bytes are the same.

use crate::discipline::{ECHO_MAX, OUTPUT, Read, Terminal};
use crate::reference::{self, Reference};
use proto_tty::{
    ECHO, ECHOCTL, ECHOE, ECHOK, ECHOKE, ECHONL, ICANON, ICRNL, IEXTEN, IGNCR, INLCR, ISIG, ISTRIP,
    MAX_CANON, MAX_INPUT, NOFLSH, OCRNL, ONLCR, OPOST, Termios, VEOL, VMIN, VTIME,
};
use std::vec::Vec;

/// The bytes of a program at 0xF8 and above are operations; the rest are
/// input.
const READ: u8 = 0xF8;
const SET: u8 = 0xF9;
const WRITE: u8 = 0xFA;
const DRAIN: u8 = 0xFB;
const TIME: u8 = 0xFC;
const LITERAL: u8 = 0xFD;
const FLUSH: u8 = 0xFE;
const SIGNALS: u8 = 0xFF;

/// What a program did, for the corpus to show it reaches the cases.
#[derive(Default, Debug)]
struct Seen {
    lines: usize,
    eofs: usize,
    signals: usize,
    timeouts: usize,
    raw_reads: usize,
}

/// Settings from four bytes: the local, input and output modes from
/// tables of their flags, VMIN and VTIME small.
fn settings(b: [u8; 4]) -> Termios {
    let mut t = Termios::default();
    let local = [
        ISIG, ICANON, ECHO, ECHOE, ECHOK, ECHONL, NOFLSH, ECHOCTL, ECHOKE,
    ];
    t.lflag = IEXTEN;
    let bits = u16::from(b[0]) | (u16::from(b[1]) & 1) << 8;
    for (i, flag) in local.iter().enumerate() {
        if bits >> i & 1 != 0 {
            t.lflag |= flag;
        }
    }
    let input = [ICRNL, IGNCR, INLCR, ISTRIP];
    t.iflag = 0;
    for (i, flag) in input.iter().enumerate() {
        if (b[1] >> (i + 1)) & 1 != 0 {
            t.iflag |= flag;
        }
    }
    let output = [OPOST, ONLCR, OCRNL];
    t.oflag = 0;
    for (i, flag) in output.iter().enumerate() {
        if (b[1] >> (i + 5)) & 1 != 0 {
            t.oflag |= flag;
        }
    }
    t.cc[VMIN] = b[2] % 5;
    t.cc[VTIME] = b[3] % 4;
    if b[3] & 0x80 != 0 {
        t.cc[VEOL] = b'.';
    }
    t
}

/// Runs the program `data` on a terminal, checking the invariants after
/// each operation.
fn run(data: &[u8]) -> Seen {
    let mut t = Terminal::new();
    let mut seen = Seen::default();
    let mut now = 0u64;
    let mut i = 0;
    let next = |i: &mut usize| {
        let b = data.get(*i).copied().unwrap_or(0);
        *i += 1;
        b
    };
    while i < data.len() {
        let op = next(&mut i);
        let input = match op {
            READ => {
                // The low six bits less one, the count; the top two, how
                // long ago the read started, in tenths of a second.
                let arg = next(&mut i);
                let count = usize::from(arg % 64) + 1;
                let started = now.saturating_sub(u64::from(arg >> 6) * 100_000_000);
                let canonical = t.termios().lflag & ICANON != 0;
                let (_, cooked) = t.queued();
                let mut out = [0u8; 64];
                match t.read(&mut out[..count], started, now) {
                    Read::Ready(n) => {
                        assert!(n <= count);
                        if canonical {
                            assert!(cooked > 0, "a canonical read with no whole line");
                            if n == 0 {
                                seen.eofs += 1;
                            } else {
                                seen.lines += 1;
                            }
                        } else if n == 0 {
                            seen.timeouts += 1;
                        } else {
                            seen.raw_reads += 1;
                        }
                    }
                    Read::Wait(deadline) => {
                        assert!(deadline.is_none_or(|d| d > now));
                    }
                }
                None
            }
            SET => {
                let b = [next(&mut i), next(&mut i), next(&mut i), next(&mut i)];
                t.set_termios(settings(b), b[2] & 0x80 != 0);
                None
            }
            WRITE => {
                let len = usize::from(next(&mut i));
                let end = (i + len).min(data.len());
                let taken = t.write(&data[i.min(end)..end]);
                assert!(taken <= end - i.min(end));
                i = end;
                None
            }
            DRAIN => {
                let n = usize::from(next(&mut i)) * 8;
                let piece = t.output().len().min(n);
                t.sent(piece);
                None
            }
            TIME => {
                now += u64::from(next(&mut i)) * 10_000_000;
                None
            }
            LITERAL => Some(next(&mut i)),
            FLUSH => {
                t.flush_input();
                None
            }
            SIGNALS => {
                seen.signals += t.take_signals().count();
                None
            }
            b => Some(b),
        };
        if let Some(b) = input {
            let (_, cooked) = t.queued();
            let before = t.output_len();
            t.input(&[b], now);
            let (len, cooked_after) = t.queued();
            if cooked_after < cooked {
                assert_eq!(len, 0, "only a flush takes whole lines back");
            }
            let grew = t.output_len().saturating_sub(before);
            assert!(grew <= ECHO_MAX, "{grew} bytes of echo for {b:#x}");
        }
        let (len, cooked) = t.queued();
        assert!(cooked <= len && len <= MAX_INPUT);
        if t.termios().lflag & ICANON != 0 {
            assert!(t.line_len() < MAX_CANON, "the line keeps room for its end");
        }
        assert!(t.output_len() <= OUTPUT);
    }
    seen
}

/// A generator of fixed seed (xorshift64*).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// 10^5 random bytes of a fixed seed, most of them the bytes the
/// discipline cares for.
fn random_program() -> Vec<u8> {
    let mut rng = Rng(0x5f_7474_7931);
    let special = [
        b'\r', b'\n', 0x7f, 0x15, 0x17, 0x04, 0x03, 0x1c, 0x1a, b' ', b'.', 0x01, b'\t',
    ];
    let mut data = Vec::with_capacity(100_000);
    while data.len() < 100_000 {
        let r = rng.next();
        let b = match r % 16 {
            0..=5 => b'a' + (r >> 8) as u8 % 26,
            6..=10 => special[(r >> 8) as usize % special.len()],
            11 => READ,
            12 => [SET, WRITE, DRAIN, TIME][(r >> 8) as usize % 4],
            13 => DRAIN,
            14 => [LITERAL, FLUSH, SIGNALS, READ][(r >> 8) as usize % 4],
            _ => (r >> 16) as u8,
        };
        data.push(b);
    }
    data
}

#[test]
fn random_programs_keep_the_invariants() {
    let seen = run(&random_program());
    assert!(seen.lines > 0 && seen.raw_reads > 0, "{seen:?}");
}

/// Runs the program `data` on the discipline and on the reference, the
/// output taken whole after each operation: the same bytes for the device
/// and the same reads.
fn differ(data: &[u8]) -> usize {
    let mut t = Terminal::new();
    let mut r = Reference::new();
    let mut now = 0u64;
    let mut i = 0;
    let mut reads = 0;
    let next = |i: &mut usize| {
        let b = data.get(*i).copied().unwrap_or(0);
        *i += 1;
        b
    };
    while i < data.len() {
        let at = i;
        let op = next(&mut i);
        match op {
            READ => {
                let arg = next(&mut i);
                let count = usize::from(arg % 64) + 1;
                let started = now.saturating_sub(u64::from(arg >> 6) * 100_000_000);
                let mut out = [0u8; 64];
                let mut want = Vec::new();
                let got = t.read(&mut out[..count], started, now);
                let expected = r.read(count, started, now, &mut want);
                assert_eq!(got, expected, "read at {at}");
                if let Read::Ready(n) = got {
                    assert_eq!(out[..n], want[..], "the bytes of the read at {at}");
                    reads += 1;
                }
            }
            SET => {
                let b = [next(&mut i), next(&mut i), next(&mut i), next(&mut i)];
                t.set_termios(settings(b), b[2] & 0x80 != 0);
                r.set(settings(b), b[2] & 0x80 != 0);
            }
            WRITE => {
                let len = usize::from(next(&mut i));
                let end = (i + len).min(data.len());
                let bytes = &data[i.min(end)..end];
                assert_eq!(t.write(bytes), bytes.len());
                r.write(bytes);
                i = end;
            }
            TIME => now += u64::from(next(&mut i)) * 10_000_000,
            LITERAL => {
                let b = next(&mut i);
                t.input(&[b], now);
                r.input(&[b], now);
            }
            FLUSH => {
                t.flush_input();
                r.flush();
            }
            SIGNALS => {
                t.take_signals().count();
            }
            DRAIN => {}
            b => {
                t.input(&[b], now);
                r.input(&[b], now);
            }
        }
        assert_eq!(
            reference::drain(&mut t),
            core::mem::take(&mut r.out),
            "the bytes for the device after the operation at {at}"
        );
    }
    reads
}

/// The random program and the corpus give what the reference gives.
#[test]
fn programs_match_the_reference() {
    assert!(differ(&random_program()) > 1000);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    for file in std::fs::read_dir(&dir).expect("the corpus") {
        let data = std::fs::read(file.expect("an entry").path()).expect("a file");
        differ(&data);
    }
}

/// The committed corpus: each file runs whole, and together they reach
/// lines, end-of-file, signals, raw reads and VTIME's timeouts.
#[test]
fn the_corpus_keeps_the_invariants() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("the corpus")
        .map(|e| e.expect("an entry").path())
        .collect();
    files.sort();
    assert!(files.len() >= 4, "{files:?}");
    let mut total = Seen::default();
    for file in files {
        let data = std::fs::read(&file).expect("a file of the corpus");
        let seen = run(&data);
        total.lines += seen.lines;
        total.eofs += seen.eofs;
        total.signals += seen.signals;
        total.timeouts += seen.timeouts;
        total.raw_reads += seen.raw_reads;
    }
    assert!(
        total.lines > 0
            && total.eofs > 0
            && total.signals > 0
            && total.timeouts > 0
            && total.raw_reads > 0,
        "{total:?}"
    );
}
