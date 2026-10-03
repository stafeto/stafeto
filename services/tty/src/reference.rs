// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A reference of the line discipline for the fuzzing test, written apart
//! from `discipline` and straight from XBD 11.1.6 to 11.2: the input as
//! whole lines and the current line in vectors, the echo of each byte
//! spelled out. The programs of `fuzz` run on both; after each operation
//! the bytes for the device, the read's result and the bytes it gave must
//! be the same. The output is taken whole after each operation, so the
//! ring never fills: the reference keeps no ring.

use crate::discipline::{Read, Terminal};
use proto_tty::{
    DISABLED, ECHO, ECHOCTL, ECHOE, ECHOK, ECHOKE, ECHONL, ICANON, ICRNL, IEXTEN, IGNCR, INLCR,
    ISIG, ISTRIP, MAX_CANON, MAX_INPUT, NOFLSH, OCRNL, ONLCR, OPOST, Termios, VEOF, VEOL, VERASE,
    VINTR, VKILL, VMIN, VQUIT, VSUSP, VTIME, VWERASE,
};
use std::collections::VecDeque;
use std::vec::Vec;

/// A whole line: its bytes, its delimiter among them, and whether an EOF
/// ended it.
struct Line {
    bytes: VecDeque<u8>,
    eof: bool,
}

pub struct Reference {
    t: Termios,
    /// Canonical mode: the whole lines and the current line; otherwise
    /// the bytes in `raw`.
    lines: VecDeque<Line>,
    current: Vec<u8>,
    raw: VecDeque<u8>,
    last_input: u64,
    pub out: Vec<u8>,
}

impl Reference {
    pub fn new() -> Reference {
        Reference {
            t: Termios::default(),
            lines: VecDeque::new(),
            current: Vec::new(),
            raw: VecDeque::new(),
            last_input: 0,
            out: Vec::new(),
        }
    }

    fn l(&self, f: u32) -> bool {
        self.t.lflag & f != 0
    }

    fn cc(&self, b: u8, i: usize) -> bool {
        self.t.cc[i] != DISABLED && self.t.cc[i] == b
    }

    /// The entries of the queue: each byte, and each EOF of a line.
    fn entries(&self) -> usize {
        let lines: usize = self
            .lines
            .iter()
            .map(|l| l.bytes.len() + usize::from(l.eof))
            .sum();
        lines + self.current.len() + self.raw.len()
    }

    pub fn set(&mut self, t: Termios, flush: bool) {
        if flush {
            self.flush();
        }
        let was = self.l(ICANON);
        self.t = t;
        let now = self.l(ICANON);
        if was && !now {
            for line in self.lines.drain(..) {
                self.raw.extend(line.bytes);
            }
            self.raw.extend(self.current.drain(..));
        } else if !was && now && !self.raw.is_empty() {
            self.lines.push_back(Line {
                bytes: core::mem::take(&mut self.raw),
                eof: false,
            });
        }
    }

    pub fn flush(&mut self) {
        self.lines.clear();
        self.current.clear();
        self.raw.clear();
    }

    /// The output processing of one byte.
    fn opost(&self, b: u8) -> Vec<u8> {
        let o = self.t.oflag;
        if o & OPOST != 0 && b == b'\n' && o & ONLCR != 0 {
            vec![b'\r', b'\n']
        } else if o & OPOST != 0 && b == b'\r' && o & OCRNL != 0 {
            vec![b'\n']
        } else {
            vec![b]
        }
    }

    fn ctl(&self, b: u8) -> bool {
        self.l(ECHOCTL) && ((b < 0x20 && b != b'\t' && b != b'\n') || b == 0x7f)
    }

    /// How byte `b` shows when echoed.
    fn shown(&self, b: u8) -> Vec<u8> {
        if self.ctl(b) {
            vec![b'^', b ^ 0x40]
        } else {
            self.opost(b)
        }
    }

    fn echo(&mut self, b: u8) {
        if self.l(ECHO) {
            let shown = self.shown(b);
            self.out.extend(shown);
        }
    }

    /// The echo of erasing the bytes `erased`, one unit.
    fn erased(&mut self, erased: &[u8]) {
        if !self.l(ECHO) || erased.is_empty() {
            return;
        }
        if self.l(ECHOE) {
            for &b in erased {
                let columns = if self.ctl(b) { 2 } else { 1 };
                for _ in 0..columns {
                    self.out.extend_from_slice(b"\x08 \x08");
                }
            }
        } else {
            let erase = self.t.cc[VERASE];
            self.echo(erase);
        }
    }

    pub fn input(&mut self, bytes: &[u8], now: u64) {
        for &b in bytes {
            self.byte(b);
        }
        if !bytes.is_empty() {
            self.last_input = now;
        }
    }

    fn byte(&mut self, mut b: u8) {
        let i = self.t.iflag;
        if i & ISTRIP != 0 {
            b &= 0x7f;
        }
        if b == b'\r' && i & IGNCR != 0 {
            return;
        }
        if b == b'\r' && i & ICRNL != 0 {
            b = b'\n';
        } else if b == b'\n' && i & INLCR != 0 {
            b = b'\r';
        }
        if self.l(ISIG) && (self.cc(b, VINTR) || self.cc(b, VQUIT) || self.cc(b, VSUSP)) {
            if !self.l(NOFLSH) {
                self.flush();
                self.out.clear();
            }
            self.echo(b);
            return;
        }
        if !self.l(ICANON) {
            if self.entries() < MAX_INPUT {
                self.raw.push_back(b);
                self.echo(b);
            }
            return;
        }
        if self.cc(b, VERASE) {
            if let Some(gone) = self.current.pop() {
                self.erased(&[gone]);
            }
        } else if self.cc(b, VKILL) {
            if self.current.is_empty() {
                return;
            }
            let line = core::mem::take(&mut self.current);
            if self.l(ECHO) && self.l(ECHOKE) && self.l(ECHOE) && self.l(ECHOK) {
                self.erased(&line);
            } else if self.l(ECHO) {
                let kill = self.t.cc[VKILL];
                self.echo(kill);
                if self.l(ECHOK) {
                    let nl = self.opost(b'\n');
                    self.out.extend(nl);
                }
            }
        } else if self.cc(b, VWERASE) && self.l(IEXTEN) {
            let blank = |b: u8| b == b' ' || b == b'\t';
            let mut gone = Vec::new();
            while self.current.last().is_some_and(|&c| blank(c)) {
                gone.push(self.current.pop().unwrap());
            }
            while self.current.last().is_some_and(|&c| !blank(c)) {
                gone.push(self.current.pop().unwrap());
            }
            // Each byte is erased by itself, as ERASE would.
            for g in gone {
                self.erased(&[g]);
            }
        } else if self.cc(b, VEOF) {
            self.end(None);
        } else if b == b'\n' || self.cc(b, VEOL) {
            self.end(Some(b));
            if self.l(ECHO) || (b == b'\n' && self.l(ECHONL)) {
                let shown = self.shown(b);
                self.out.extend(shown);
            }
        } else if self.current.len() + 1 < MAX_CANON && self.entries() + 1 < MAX_INPUT {
            self.current.push(b);
            self.echo(b);
        }
    }

    /// The current line ends with `delimiter`, or with an EOF.
    fn end(&mut self, delimiter: Option<u8>) {
        if self.entries() >= MAX_INPUT {
            return;
        }
        let mut bytes: VecDeque<u8> = self.current.drain(..).collect();
        if let Some(d) = delimiter {
            bytes.push_back(d);
        }
        self.lines.push_back(Line {
            bytes,
            eof: delimiter.is_none(),
        });
    }

    /// A read of `count` bytes, its bytes into `got`.
    pub fn read(&mut self, count: usize, started: u64, now: u64, got: &mut Vec<u8>) -> Read {
        got.clear();
        if self.l(ICANON) {
            let Some(line) = self.lines.front_mut() else {
                return Read::Wait(None);
            };
            while got.len() < count {
                let Some(b) = line.bytes.pop_front() else {
                    break;
                };
                got.push(b);
            }
            if line.bytes.is_empty() {
                self.lines.pop_front();
            }
            return Read::Ready(got.len());
        }
        let have = self.raw.len();
        let min = usize::from(self.t.cc[VMIN]);
        let time = u64::from(self.t.cc[VTIME]) * 100_000_000;
        let ready = if min == 0 && time == 0 {
            true
        } else if min == 0 {
            if have == 0 && now < started + time {
                return Read::Wait(Some(started + time));
            }
            true
        } else if time == 0 {
            have >= min.min(count)
        } else if have >= min.min(count) {
            true
        } else if have == 0 {
            false
        } else {
            let deadline = self.last_input.max(started) + time;
            if now < deadline {
                return Read::Wait(Some(deadline));
            }
            true
        };
        if !ready {
            return Read::Wait(None);
        }
        for _ in 0..have.min(count) {
            got.push(self.raw.pop_front().unwrap());
        }
        Read::Ready(got.len())
    }

    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            let out = self.opost(b);
            self.out.extend(out);
        }
    }
}

/// Everything `t` has for the device.
pub fn drain(t: &mut Terminal) -> Vec<u8> {
    let mut out = Vec::new();
    while t.output_len() > 0 {
        let piece = t.output().to_vec();
        t.sent(piece.len());
        out.extend(piece);
    }
    out
}
