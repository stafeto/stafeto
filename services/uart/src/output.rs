// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The output of the driver (spec 13.5): two streams of bytes, the
//! clients' in a ring of TX_RING bytes and the kernel log's in the text of
//! one batch, go out to the port as one, a line at a time. A stream whose
//! line has begun goes on with it while it has bytes; at the start of a
//! line the log goes first. When the line of one stream stops for want of
//! bytes and the other has some, a CR LF ends it and the other goes on;
//! the part of a line of the clients cut short this way, up to REPEAT_MAX
//! bytes, goes out again once the log has ended its line and has no more.
//! A CR goes before each LF of a client's WRITE. The bytes of WRITE_SOME,
//! those of the terminal service, go out as they are: the terminal's
//! output processing (OPOST, ONLCR; XBD 11.2.3) made them; an LF among them
//! still ends the line for the turns with the log.

/// The bytes of the ring of the clients.
pub const TX_RING: usize = 4096;
/// The bytes of the text of one batch of the log at most: twelve records
/// of 64 bytes and the line of the records lost.
pub const LOG_BYTES: usize = 1024;
/// The longest part of a line of the clients that goes out again.
pub const REPEAT_MAX: usize = 128;

/// Where the output stands in its line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum At {
    /// At the start of a line.
    Start,
    /// Inside a line of the clients.
    Client,
    /// Inside a line of the log.
    Log,
}

/// The output: the ring of the clients, the text of the log, and where
/// the line stands.
pub struct Output {
    ring: [u8; TX_RING],
    ring_start: usize,
    ring_len: usize,
    log: [u8; LOG_BYTES],
    log_at: usize,
    log_len: usize,
    at: At,
    /// Bytes that go before all others: the CR LF that ends a line cut
    /// short, the LF after the CR of a newline.
    pending: &'static [u8],
    /// The part of the line of the clients that went out since its start,
    /// up to REPEAT_MAX bytes; `long` once more went.
    line: [u8; REPEAT_MAX],
    line_len: usize,
    long: bool,
    /// The log cut a line of the clients short: it goes out again once the
    /// log has no more bytes.
    cut: bool,
    /// The bytes of `line` that went out again so far, while they go.
    repeat: Option<usize>,
    /// One bit for each byte of the ring: it came with WRITE_SOME and goes
    /// out as it is.
    raw: [u8; TX_RING / 8],
}

impl Output {
    /// An empty output at the start of a line.
    pub const fn new() -> Output {
        Output {
            ring: [0; TX_RING],
            ring_start: 0,
            ring_len: 0,
            log: [0; LOG_BYTES],
            log_at: 0,
            log_len: 0,
            at: At::Start,
            pending: &[],
            line: [0; REPEAT_MAX],
            line_len: 0,
            long: false,
            cut: false,
            repeat: None,
            raw: [0; TX_RING / 8],
        }
    }

    /// The bytes of the clients the ring has room for.
    pub fn room(&self) -> usize {
        TX_RING - self.ring_len
    }

    /// Puts `bytes` of a client into the ring, all or none: false, with
    /// nothing taken, when they do not fit.
    pub fn put(&mut self, bytes: &[u8]) -> bool {
        self.put_as(bytes, false)
    }

    /// `put` of the bytes of WRITE_SOME, which go out as they are.
    pub fn put_raw(&mut self, bytes: &[u8]) -> bool {
        self.put_as(bytes, true)
    }

    fn put_as(&mut self, bytes: &[u8], raw: bool) -> bool {
        if bytes.len() > self.room() {
            return false;
        }
        // In one or two runs of the ring, a copy and the bits of each.
        let mut done = 0;
        while done < bytes.len() {
            let at = (self.ring_start + self.ring_len) % TX_RING;
            let n = (bytes.len() - done).min(TX_RING - at);
            self.ring[at..at + n].copy_from_slice(&bytes[done..done + n]);
            self.mark(at, n, raw);
            self.ring_len += n;
            done += n;
        }
        true
    }

    /// The bits of the `n` bytes of the ring from `at`, which does not
    /// wrap: set for `raw`, clear otherwise; whole bytes of bits at once.
    fn mark(&mut self, at: usize, n: usize, raw: bool) {
        let (mut i, end) = (at, at + n);
        while i < end {
            if i % 8 == 0 && end - i >= 8 {
                self.raw[i / 8] = if raw { 0xff } else { 0 };
                i += 8;
                continue;
            }
            let bit = 1 << (i % 8);
            if raw {
                self.raw[i / 8] |= bit;
            } else {
                self.raw[i / 8] &= !bit;
            }
            i += 1;
        }
    }

    /// The bytes of the clients in the ring go unsent, as if the port took
    /// them: for a stand-in of the driver whose port sends at once (the
    /// measure of the terminal service's steps, tests/tty).
    pub fn discard_clients(&mut self) {
        self.ring_start = (self.ring_start + self.ring_len) % TX_RING;
        self.ring_len = 0;
    }

    /// Whether the text of the last batch of the log went out whole: the
    /// driver takes the next batch only then (spec 13.5).
    pub fn log_done(&self) -> bool {
        self.log_at == self.log_len
    }

    /// Adds `bytes` to the text of the batch of the log, which starts
    /// over once the last went out whole: false, with nothing taken, when
    /// they do not fit.
    pub fn put_log(&mut self, bytes: &[u8]) -> bool {
        if self.log_done() {
            self.log_at = 0;
            self.log_len = 0;
        }
        let Some(room) = self.log.get_mut(self.log_len..self.log_len + bytes.len()) else {
            return false;
        };
        room.copy_from_slice(bytes);
        self.log_len += bytes.len();
        true
    }

    fn log_has(&self) -> bool {
        self.log_at < self.log_len
    }

    /// Whether `next_byte` has nothing to give now.
    pub fn is_idle(&self) -> bool {
        if !self.pending.is_empty() {
            return false;
        }
        let clients = self.ring_len > 0;
        match self.at {
            At::Start => {
                let repeats = self.cut && !self.long && self.line_len > 0;
                !(self.log_has() || clients || repeats)
            }
            At::Client => {
                let repeats = self.repeat.is_some_and(|i| i < self.line_len);
                !(repeats || clients || self.log_has())
            }
            At::Log => !(self.log_has() || clients),
        }
    }

    /// The next byte for the port, None while nothing waits (the rules
    /// above).
    pub fn next_byte(&mut self) -> Option<u8> {
        loop {
            if let Some((&b, rest)) = self.pending.split_first() {
                self.pending = rest;
                return Some(b);
            }
            match self.at {
                At::Start => {
                    if self.log_has() {
                        self.at = At::Log;
                    } else if self.cut {
                        self.cut = false;
                        self.at = At::Client;
                        if self.long {
                            self.line_len = 0;
                            self.long = false;
                        } else {
                            self.repeat = Some(0);
                        }
                    } else if self.ring_len > 0 {
                        self.at = At::Client;
                    } else {
                        return None;
                    }
                }
                At::Client => {
                    if let Some(i) = self.repeat {
                        if i < self.line_len {
                            self.repeat = Some(i + 1);
                            return Some(self.line[i]);
                        }
                        self.repeat = None;
                    }
                    if self.ring_len > 0 {
                        let at = self.ring_start;
                        let raw = self.raw[at / 8] & (1 << (at % 8)) != 0;
                        self.ring_start = (at + 1) % TX_RING;
                        self.ring_len -= 1;
                        return Some(self.client_byte(self.ring[at], raw));
                    }
                    if !self.log_has() {
                        return None;
                    }
                    self.cut = true;
                    self.end_line();
                }
                At::Log => {
                    if self.log_has() {
                        let b = self.log[self.log_at];
                        self.log_at += 1;
                        if b == b'\n' {
                            self.at = At::Start;
                            self.pending = b"\n";
                            return Some(b'\r');
                        }
                        return Some(b);
                    }
                    if self.ring_len == 0 {
                        return None;
                    }
                    self.end_line();
                }
            }
        }
    }

    /// Byte `b` of the clients as it goes out: an LF ends the line, with
    /// a CR before it unless the byte is `raw`; any other byte joins the
    /// line.
    fn client_byte(&mut self, b: u8, raw: bool) -> u8 {
        if b == b'\n' {
            self.at = At::Start;
            self.line_len = 0;
            self.long = false;
            if raw {
                return b'\n';
            }
            self.pending = b"\n";
            return b'\r';
        }
        if self.line_len < REPEAT_MAX {
            self.line[self.line_len] = b;
            self.line_len += 1;
        } else {
            self.long = true;
        }
        b
    }

    /// A line cut short ends with CR LF; the next starts after them.
    fn end_line(&mut self) {
        self.pending = b"\r\n";
        self.at = At::Start;
    }
}

impl Default for Output {
    fn default() -> Output {
        Output::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// What `next_byte` gives until it has nothing, 10 000 bytes at most;
    /// the output is idle then.
    fn drain(o: &mut Output) -> Vec<u8> {
        let out: Vec<u8> = core::iter::from_fn(|| o.next_byte()).take(10_000).collect();
        assert!(out.len() < 10_000, "the output does not run dry");
        assert!(o.is_idle());
        out
    }

    /// The first `n` bytes `next_byte` gives.
    fn take(o: &mut Output, n: usize) -> Vec<u8> {
        (0..n).map_while(|_| o.next_byte()).collect()
    }

    #[test]
    fn newlines_go_out_as_cr_lf() {
        let mut o = Output::new();
        assert!(o.put(b"one\ntwo\n\n"));
        assert_eq!(drain(&mut o), b"one\r\ntwo\r\n\r\n");
        assert!(o.put_log(b"k1\nk2\n"));
        assert_eq!(drain(&mut o), b"k1\r\nk2\r\n");
        assert!(o.log_done());
    }

    /// WRITE_SOME's bytes go out as the terminal made them: an LF alone
    /// stays alone; WRITE's LF gets its CR.
    #[test]
    fn the_bytes_of_write_some_go_out_as_they_are() {
        let mut o = Output::new();
        assert!(o.put_raw(b"one\r\ntwo\nx\ry"));
        assert!(o.put(b"\nz\n"));
        assert_eq!(drain(&mut o), b"one\r\ntwo\nx\ry\r\nz\r\n");
        // An LF of WRITE_SOME ends the line: the log goes after it.
        assert!(o.put_raw(b"raw\nmore\n"));
        assert_eq!(take(&mut o, 2), b"ra");
        assert!(o.put_log(b"log\n"));
        assert_eq!(drain(&mut o), b"w\nlog\r\nmore\n");
    }

    /// The marks of WRITE_SOME's bytes hold across the wrap of the ring
    /// and are cleared by WRITE's bytes in the same places.
    #[test]
    fn marks_hold_across_the_wrap() {
        let mut o = Output::new();
        assert!(o.put(&[b'.'; TX_RING - 5]));
        drain(&mut o);
        let raw = b"ab\ncdefghij\nkl\n";
        assert!(o.put_raw(raw));
        assert_eq!(drain(&mut o), raw);
        assert!(o.put(&[b'x'; TX_RING - 8]));
        drain(&mut o);
        assert!(o.put(b"ab\ncdefghij\nkl\n"));
        assert_eq!(drain(&mut o), b"ab\r\ncdefghij\r\nkl\r\n");
    }

    #[test]
    fn log_lines_wait_for_the_end_of_a_client_line() {
        let mut o = Output::new();
        assert!(o.put(b"hello world\n"));
        assert_eq!(take(&mut o, 3), b"hel");
        assert!(o.put_log(b"kernel\n"));
        assert_eq!(drain(&mut o), b"lo world\r\nkernel\r\n");
    }

    #[test]
    fn client_bytes_wait_for_the_end_of_a_log_line() {
        let mut o = Output::new();
        assert!(o.put_log(b"kernel line\n"));
        assert_eq!(take(&mut o, 3), b"ker");
        assert!(o.put(b"abc\n"));
        assert!(!o.log_done());
        assert_eq!(drain(&mut o), b"nel line\r\nabc\r\n");
        // At the start of a line the log goes first.
        assert!(o.put(b"client\n"));
        assert!(o.put_log(b"log\n"));
        assert_eq!(drain(&mut o), b"log\r\nclient\r\n");
    }

    #[test]
    fn an_idle_partial_line_lets_the_log_in_after_a_newline() {
        let mut o = Output::new();
        assert!(o.put(b"stafeto> "));
        assert_eq!(drain(&mut o), b"stafeto> ");
        assert!(o.put_log(b"init: uart ended\n"));
        assert!(!o.is_idle());
        assert!(drain(&mut o).starts_with(b"\r\ninit: uart ended\r\n"));
        // A line of the log that stops lets the clients in the same way.
        let mut o = Output::new();
        assert!(o.put_log(b"half a line"));
        assert_eq!(drain(&mut o), b"half a line");
        assert!(o.log_done());
        assert!(o.put(b"x\n"));
        assert_eq!(drain(&mut o), b"\r\nx\r\n");
    }

    #[test]
    fn an_interrupted_client_line_is_repeated_after_the_log() {
        let mut o = Output::new();
        assert!(o.put(b"stafeto> "));
        assert_eq!(drain(&mut o), b"stafeto> ");
        assert!(o.put_log(b"a\nb\n"));
        assert_eq!(drain(&mut o), b"\r\na\r\nb\r\nstafeto> ");
        assert!(o.put(b"x"));
        assert_eq!(drain(&mut o), b"x");
        // Cut again, the whole line so far comes back.
        assert!(o.put_log(b"c\n"));
        assert_eq!(drain(&mut o), b"\r\nc\r\nstafeto> x");
        // A line longer than REPEAT_MAX does not.
        let mut o = Output::new();
        assert!(o.put(&[b'y'; REPEAT_MAX + 1]));
        assert_eq!(drain(&mut o).len(), REPEAT_MAX + 1);
        assert!(o.put_log(b"k\n"));
        assert_eq!(drain(&mut o), b"\r\nk\r\n");
        assert!(o.put(b"z\n"));
        assert_eq!(drain(&mut o), b"z\r\n");
    }

    #[test]
    fn a_log_line_across_two_batches_stays_whole() {
        let mut o = Output::new();
        assert!(o.put(b"stafeto> "));
        assert_eq!(drain(&mut o), b"stafeto> ");
        assert!(o.put_log(b"process fault: data abort ESR="));
        assert_eq!(drain(&mut o), b"\r\nprocess fault: data abort ESR=");
        assert!(o.log_done());
        assert!(o.put_log(b"0x92000006\n"));
        assert_eq!(drain(&mut o), b"0x92000006\r\nstafeto> ");
    }
}
