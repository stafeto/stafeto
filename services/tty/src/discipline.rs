// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The line discipline of a terminal (XBD 11.1.6 to 11.2): a machine of
//! states from bytes of input to the input queue, the echo, the lines that
//! are ready and the signals the terminal asks for, and from the bytes of
//! a write to the bytes for the device. It keeps no time of its own: the
//! caller gives the time of each byte and of each read, for VMIN and
//! VTIME.
//!
//! The input queue holds MAX_INPUT entries. An entry is a byte, with
//! DELIM when it ends a line (NL, EOL) and EOF for the end-of-file of a
//! line, which carries no byte. In canonical mode the entries before
//! `cooked` are whole lines, a read takes from one of them at most, and
//! the entries after it are the current line, which ERASE, WERASE and
//! KILL edit; it holds MAX_CANON - 1 bytes at most, so that its delimiter
//! always fits. In non-canonical mode every entry is ready.
//!
//! The output ring holds OUTPUT bytes for the device: the echo and the
//! clients' writes after the output processing. A write leaves
//! ECHO_RESERVE bytes of it to the echo, so that typing shows while the
//! clients' output waits for the device; echo past a full ring is lost.

use proto_tty::{
    DISABLED, ECHO, ECHOCTL, ECHOE, ECHOK, ECHOKE, ECHONL, ICANON, ICRNL, IEXTEN, IGNCR, INLCR,
    ISIG, ISTRIP, MAX_CANON, MAX_INPUT, NOFLSH, OCRNL, ONLCR, OPOST, Termios, VEOF, VEOL, VERASE,
    VINTR, VKILL, VMIN, VQUIT, VSUSP, VTIME, VWERASE,
};

/// The bytes of the output ring.
pub const OUTPUT: usize = 4096;
/// The bytes of the output ring a write of a client leaves to the echo.
pub const ECHO_RESERVE: usize = 1024;
/// The most bytes of echo one byte of input makes: KILL erases a line of
/// MAX_CANON - 1 control characters, "\b\b  \b\b" each.
pub const ECHO_MAX: usize = 6 * (MAX_CANON - 1);

/// An entry of the input queue that ends a line.
const DELIM: u16 = 0x100;
/// An entry for the end-of-file of a line: no byte.
const EOF: u16 = 0x200;

/// VTIME's unit: a tenth of a second, in nanoseconds.
const DECISECOND_NS: u64 = 100_000_000;

/// A signal a byte of input asks the terminal's foreground process group
/// for (XBD 11.1.9): INTR, QUIT and SUSP with ISIG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Interrupt,
    Quit,
    Suspend,
}

impl Signal {
    const ALL: [Signal; 3] = [Signal::Interrupt, Signal::Quit, Signal::Suspend];

    fn bit(self) -> u8 {
        match self {
            Signal::Interrupt => 1,
            Signal::Quit => 2,
            Signal::Suspend => 4,
        }
    }
}

/// What a read finds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// This many bytes went into the caller's buffer, 0 for an end-of-file
    /// or a timer of VTIME that ran out: the read is over.
    Ready(usize),
    /// Nothing for it yet: it waits for input, and until this time too
    /// when VTIME runs for it.
    Wait(Option<u64>),
}

/// A ring of `N` items.
struct Ring<T: Copy, const N: usize> {
    items: [T; N],
    head: usize,
    len: usize,
}

impl<T: Copy, const N: usize> Ring<T, N> {
    const fn new(zero: T) -> Self {
        Ring {
            items: [zero; N],
            head: 0,
            len: 0,
        }
    }

    fn at(&self, i: usize) -> T {
        self.items[(self.head + i) % N]
    }

    fn set(&mut self, i: usize, item: T) {
        self.items[(self.head + i) % N] = item;
    }

    fn push(&mut self, item: T) -> bool {
        if self.len == N {
            return false;
        }
        self.items[(self.head + self.len) % N] = item;
        self.len += 1;
        true
    }

    fn pop_front(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let item = self.items[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(item)
    }

    fn pop_back(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        Some(self.at(self.len))
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    /// The first `n` items go, at most all of them. O(1).
    fn drop_front(&mut self, n: usize) {
        let n = n.min(self.len);
        self.head = (self.head + n) % N;
        self.len -= n;
    }

    /// As many of `items` as there is room for, in one or two copies;
    /// their count.
    fn push_slice(&mut self, items: &[T]) -> usize {
        let n = items.len().min(N - self.len);
        let tail = (self.head + self.len) % N;
        let first = n.min(N - tail);
        self.items[tail..tail + first].copy_from_slice(&items[..first]);
        self.items[..n - first].copy_from_slice(&items[first..n]);
        self.len += n;
        n
    }
}

/// The echo of erasing a column, again and again: "\b \b" for each of
/// up to 2 * (MAX_CANON - 1) columns.
const ERASE: [u8; 6 * MAX_CANON] = {
    let mut bytes = [b' '; 6 * MAX_CANON];
    let mut i = 0;
    while i < bytes.len() {
        bytes[i] = 0x08;
        bytes[i + 2] = 0x08;
        i += 3;
    }
    bytes
};

/// A terminal's line discipline: its settings, input queue and output
/// ring, and the signals its input asked for that the service did not
/// take yet.
pub struct Terminal {
    termios: Termios,
    queue: Ring<u16, MAX_INPUT>,
    /// The entries at the head of the queue that are whole lines
    /// (canonical mode); all of them otherwise.
    cooked: usize,
    output: Ring<u8, OUTPUT>,
    /// When the last byte of input came: VTIME between bytes runs from it.
    last_input: u64,
    /// The signals asked for, one bit each (Signal::bit).
    signals: u8,
    /// The bytes of input dropped for a full queue or line.
    dropped: u64,
}

impl Default for Terminal {
    fn default() -> Self {
        Self::new()
    }
}

impl Terminal {
    pub const fn new_with(termios: Termios) -> Terminal {
        Terminal {
            termios,
            queue: Ring::new(0),
            cooked: 0,
            output: Ring::new(0),
            last_input: 0,
            signals: 0,
            dropped: 0,
        }
    }

    pub const fn new() -> Terminal {
        Terminal::new_with(Termios::opened())
    }

    pub fn termios(&self) -> &Termios {
        &self.termios
    }

    fn local(&self, flag: u32) -> bool {
        self.termios.lflag & flag != 0
    }

    fn canonical(&self) -> bool {
        self.local(ICANON)
    }

    /// Whether `b` is the control character `index`, which is not off.
    fn is(&self, b: u8, index: usize) -> bool {
        let c = self.termios.cc[index];
        c != DISABLED && b == c
    }

    /// New settings (tcsetattr). Canonical input that turns off makes the
    /// current line ready, with no end-of-file entry left in the queue;
    /// canonical input that turns on makes the bytes there one line. With
    /// `flush` the input not read goes first.
    pub fn set_termios(&mut self, termios: Termios, flush: bool) {
        if flush {
            self.flush_input();
        }
        let was = self.canonical();
        self.termios = termios;
        match (was, self.canonical()) {
            (true, false) => {
                let mut kept = 0;
                for i in 0..self.queue.len {
                    let e = self.queue.at(i);
                    if e & EOF == 0 {
                        self.queue.set(kept, e & 0xff);
                        kept += 1;
                    }
                }
                self.queue.len = kept;
                self.cooked = kept;
            }
            (false, true) => {
                if let Some(last) = self.queue.len.checked_sub(1) {
                    let e = self.queue.at(last);
                    self.queue.set(last, e | DELIM);
                }
                self.cooked = self.queue.len;
            }
            _ => {}
        }
    }

    /// The input not read goes (TCSAFLUSH, tcflush).
    pub fn flush_input(&mut self) {
        self.queue.clear();
        self.cooked = 0;
    }

    /// The signals the input asked for since the last call, one bit each,
    /// and none left.
    pub fn take_signals(&mut self) -> impl Iterator<Item = Signal> {
        let bits = core::mem::take(&mut self.signals);
        Signal::ALL.into_iter().filter(move |s| bits & s.bit() != 0)
    }

    /// The bytes of input dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The entries of the input queue, and those of whole lines.
    pub fn queued(&self) -> (usize, usize) {
        (self.queue.len, self.cooked)
    }

    /// The bytes of the current line.
    pub fn line_len(&self) -> usize {
        self.queue.len - self.cooked
    }

    /// Bytes of input that came at `now` (nanoseconds).
    pub fn input(&mut self, bytes: &[u8], now: u64) {
        for &b in bytes {
            self.byte(b);
        }
        if !bytes.is_empty() {
            self.last_input = now;
        }
    }

    /// One byte of input (XBD 11.2.2, 11.1.9, 11.1.6).
    fn byte(&mut self, mut b: u8) {
        let iflag = self.termios.iflag;
        if iflag & ISTRIP != 0 {
            b &= 0x7f;
        }
        if b == b'\r' {
            if iflag & IGNCR != 0 {
                return;
            }
            if iflag & ICRNL != 0 {
                b = b'\n';
            }
        } else if b == b'\n' && iflag & INLCR != 0 {
            b = b'\r';
        }
        if self.local(ISIG) {
            let signal = if self.is(b, VINTR) {
                Some(Signal::Interrupt)
            } else if self.is(b, VQUIT) {
                Some(Signal::Quit)
            } else if self.is(b, VSUSP) {
                Some(Signal::Suspend)
            } else {
                None
            };
            if let Some(signal) = signal {
                self.signal(signal, b);
                return;
            }
        }
        if !self.canonical() {
            if self.queue.push(u16::from(b)) {
                self.cooked = self.queue.len;
                self.echo(b);
            } else {
                self.dropped += 1;
            }
            return;
        }
        if self.is(b, VERASE) {
            self.erase();
        } else if self.is(b, VKILL) {
            self.kill();
        } else if self.is(b, VWERASE) && self.local(IEXTEN) {
            self.word_erase();
        } else if self.is(b, VEOF) {
            self.end_line(EOF);
        } else if b == b'\n' || self.is(b, VEOL) {
            self.end_line(u16::from(b) | DELIM);
            if self.local(ECHO) || (b == b'\n' && self.local(ECHONL)) {
                self.echo_char(b);
            }
        } else if self.line_len() + 1 >= MAX_CANON || self.queue.len + 1 >= MAX_INPUT {
            // The line, or the queue, keeps room for its delimiter alone.
            self.dropped += 1;
        } else {
            self.queue.push(u16::from(b));
            self.echo(b);
        }
    }

    /// The current line ends with the entry `e`: it is ready. The queue
    /// always has room for it (`byte` keeps it).
    fn end_line(&mut self, e: u16) {
        let e = e | DELIM;
        if self.queue.push(e) {
            self.cooked = self.queue.len;
        } else {
            self.dropped += 1;
        }
    }

    /// INTR, QUIT or SUSP (byte `b`): the input and output go unless
    /// NOFLSH, the echo shows it, and the signal is asked for.
    fn signal(&mut self, signal: Signal, b: u8) {
        if !self.local(NOFLSH) {
            self.flush_input();
            self.output.clear();
        }
        self.echo(b);
        self.signals |= signal.bit();
    }

    /// Echo of byte `b` of input, with ECHO.
    fn echo(&mut self, b: u8) {
        if self.local(ECHO) {
            self.echo_char(b);
        }
    }

    /// Whether `b` echoes as ^X: a control character other than TAB and
    /// NL, or DEL, with ECHOCTL.
    fn caret(&self, b: u8) -> bool {
        self.local(ECHOCTL) && ((b < 0x20 && b != b'\t' && b != b'\n') || b == 0x7f)
    }

    /// The columns the echo of `b` took.
    fn width(&self, b: u8) -> usize {
        if self.caret(b) { 2 } else { 1 }
    }

    fn echo_char(&mut self, b: u8) {
        if self.caret(b) {
            self.put_echo(b'^');
            self.put_echo(b ^ 0x40);
        } else {
            self.post(b, true);
        }
    }

    /// The echo of erasing bytes `columns` columns wide: back over them
    /// with ECHOE, the ERASE character itself otherwise.
    fn echo_erase(&mut self, columns: usize) {
        if !self.local(ECHO) {
            return;
        }
        if self.local(ECHOE) {
            self.output
                .push_slice(&ERASE[..3 * columns.min(2 * MAX_CANON)]);
        } else {
            let erase = self.termios.cc[VERASE];
            self.echo_char(erase);
        }
    }

    /// ERASE: the last byte of the current line goes; none past its start
    /// (XBD 11.1.9).
    fn erase(&mut self) {
        if self.line_len() == 0 {
            return;
        }
        if let Some(e) = self.queue.pop_back() {
            let columns = self.width(e as u8);
            self.echo_erase(columns);
        }
    }

    /// WERASE: the blanks at the end of the current line, then the word
    /// before them.
    fn word_erase(&mut self) {
        let blank = |e: u16| matches!(e as u8, b' ' | b'\t');
        while self.line_len() > 0 && blank(self.queue.at(self.queue.len - 1)) {
            self.erase();
        }
        while self.line_len() > 0 && !blank(self.queue.at(self.queue.len - 1)) {
            self.erase();
        }
    }

    /// KILL: the current line goes; its echo erases it byte by byte with
    /// ECHOKE and ECHOE, or shows KILL and, with ECHOK, a newline.
    fn kill(&mut self) {
        if self.line_len() == 0 {
            return;
        }
        if self.local(ECHO) && self.local(ECHOKE) && self.local(ECHOE) {
            let mut columns = 0;
            while self.line_len() > 0 {
                let e = self.queue.pop_back().unwrap_or(0);
                columns += self.width(e as u8);
            }
            self.echo_erase(columns);
            return;
        }
        self.queue.len = self.cooked;
        if self.local(ECHO) {
            let kill = self.termios.cc[VKILL];
            self.echo_char(kill);
            if self.local(ECHOK) {
                self.post(b'\n', true);
            }
        }
    }

    /// A read of at most `out.len()` bytes, at least one, that started at
    /// `started`, at `now` (XBD 11.1.6, 11.1.7).
    pub fn read(&mut self, out: &mut [u8], started: u64, now: u64) -> Read {
        if out.is_empty() {
            return Read::Ready(0);
        }
        if self.canonical() {
            if self.cooked == 0 {
                return Read::Wait(None);
            }
            return Read::Ready(self.take_line(out));
        }
        let count = out.len();
        let have = self.queue.len;
        let min = usize::from(self.termios.cc[VMIN]);
        let time = u64::from(self.termios.cc[VTIME]) * DECISECOND_NS;
        let ready = match (min, time) {
            // Case D: what there is.
            (0, 0) => true,
            // Case C: a byte, or the timer of the read.
            (0, _) => {
                if have == 0 && now < started.saturating_add(time) {
                    return Read::Wait(Some(started.saturating_add(time)));
                }
                true
            }
            // Case B: MIN bytes, or as many as asked.
            (_, 0) => have >= min.min(count),
            // Case A: MIN bytes, or the timer between bytes once one came;
            // bytes there at the start count as come at once after it.
            _ => {
                if have >= min.min(count) {
                    true
                } else if have == 0 {
                    false
                } else {
                    let deadline = self.last_input.max(started).saturating_add(time);
                    if now < deadline {
                        return Read::Wait(Some(deadline));
                    }
                    true
                }
            }
        };
        if !ready {
            return Read::Wait(None);
        }
        let n = have.min(count);
        for b in &mut out[..n] {
            *b = self.queue.pop_front().unwrap_or(0) as u8;
        }
        self.cooked = self.queue.len;
        Read::Ready(n)
    }

    /// Bytes of the first whole line into `out`: up to and with its NL or
    /// EOL, none for its end-of-file, which goes with the line's last
    /// byte. The line stays for the next read when `out` is shorter.
    fn take_line(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        while self.cooked > 0 {
            let e = self.queue.at(0);
            if e & EOF != 0 {
                self.queue.pop_front();
                self.cooked -= 1;
                break;
            }
            if n == out.len() {
                break;
            }
            self.queue.pop_front();
            self.cooked -= 1;
            out[n] = e as u8;
            n += 1;
            if e & DELIM != 0 {
                break;
            }
        }
        n
    }

    /// A byte of output for the device, through the output processing
    /// (XBD 11.2.3): echo when `echo`, the client's write otherwise.
    fn post(&mut self, b: u8, echo: bool) {
        let oflag = self.termios.oflag;
        let put = |t: &mut Terminal, c: u8| {
            if echo {
                t.put_echo(c)
            } else {
                t.output.push(c);
            }
        };
        if oflag & OPOST == 0 {
            put(self, b);
        } else if b == b'\n' && oflag & ONLCR != 0 {
            put(self, b'\r');
            put(self, b'\n');
        } else if b == b'\r' && oflag & OCRNL != 0 {
            put(self, b'\n');
        } else {
            put(self, b);
        }
    }

    /// A byte of echo: lost when the ring is full.
    fn put_echo(&mut self, b: u8) {
        self.output.push(b);
    }

    /// A client's write: the bytes of `bytes` that fit, through the output
    /// processing, leaving ECHO_RESERVE of the ring; their count. They are
    /// processed into a buffer on the stack, which goes into the ring in
    /// one copy.
    pub fn write(&mut self, bytes: &[u8]) -> usize {
        let oflag = self.termios.oflag;
        let post = oflag & OPOST != 0;
        let (onlcr, ocrnl) = (post && oflag & ONLCR != 0, post && oflag & OCRNL != 0);
        let mut buffer = [0u8; 512];
        let mut n = 0;
        while n < bytes.len() {
            let room = (OUTPUT - self.output.len).saturating_sub(ECHO_RESERVE + 1);
            let cap = room.min(buffer.len());
            if cap < 2 {
                break;
            }
            let mut k = 0;
            while n < bytes.len() && k + 2 <= cap {
                let b = bytes[n];
                if b == b'\n' && onlcr {
                    buffer[k] = b'\r';
                    buffer[k + 1] = b'\n';
                    k += 2;
                } else {
                    buffer[k] = if b == b'\r' && ocrnl { b'\n' } else { b };
                    k += 1;
                }
                n += 1;
            }
            self.output.push_slice(&buffer[..k]);
        }
        n
    }

    /// The bytes for the device at the head of the output ring, in one
    /// piece: those before its wrap.
    pub fn output(&self) -> &[u8] {
        let end = (self.output.head + self.output.len).min(OUTPUT);
        &self.output.items[self.output.head..end]
    }

    /// The device took `n` bytes of `output`.
    pub fn sent(&mut self, n: usize) {
        self.output.drop_front(n);
    }

    /// The bytes for the device.
    pub fn output_len(&self) -> usize {
        self.output.len
    }

    /// Whether a client's write finds room for any byte, a newline that
    /// goes out as two among them.
    pub fn writable(&self) -> bool {
        OUTPUT - self.output.len >= ECHO_RESERVE + 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_tty::VMIN;
    use std::vec::Vec;

    /// Everything for the device, as it went out.
    fn drain(t: &mut Terminal) -> Vec<u8> {
        let mut out = Vec::new();
        while t.output_len() > 0 {
            let piece = t.output().to_vec();
            t.sent(piece.len());
            out.extend(piece);
        }
        out
    }

    fn read(t: &mut Terminal, count: usize) -> Read {
        let mut out = vec![0; count];
        t.read(&mut out, 0, 0)
    }

    fn read_bytes(t: &mut Terminal, count: usize) -> Option<Vec<u8>> {
        let mut out = vec![0; count];
        match t.read(&mut out, 0, 0) {
            Read::Ready(n) => Some(out[..n].to_vec()),
            Read::Wait(_) => None,
        }
    }

    fn raw(min: u8, time: u8) -> Termios {
        let mut t = Termios::default();
        t.lflag &= !ICANON;
        t.cc[VMIN] = min;
        t.cc[VTIME] = time;
        t
    }

    /// The design's first case: "abx", DEL, "c", CR gives the line "abc\n"
    /// and the echo "abx\b \bc\r\n" (ECHOE erases visually, ONLCR).
    #[test]
    fn erase_edits_the_line_and_its_echo() {
        let mut t = Terminal::new();
        t.input(b"abx\x7fc", 0);
        assert_eq!(read(&mut t, 64), Read::Wait(None), "no line before Enter");
        t.input(b"\r", 0);
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"abc\n");
        assert_eq!(drain(&mut t), b"abx\x08 \x08c\r\n");
        // The probe's own case.
        t.input(b"ab\x7fc\r", 0);
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"ac\n");
    }

    /// ERASE stops at the start of the line: the line before it is whole
    /// and stays (XBD 11.1.9), and the echo erases nothing more.
    #[test]
    fn erase_never_crosses_the_start_of_a_line() {
        let mut t = Terminal::new();
        t.input(b"ab\r\x7f\x7f\x7fc\r", 0);
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"ab\n");
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"c\n");
        assert_eq!(drain(&mut t), b"ab\r\nc\r\n");
    }

    /// Without ECHOE the echo of ERASE is the character itself, ^? with
    /// ECHOCTL; a control character echoes as ^X and erases two columns.
    #[test]
    fn echo_of_control_characters() {
        let mut t = Terminal::new();
        t.input(b"\x01\x7f", 0);
        assert_eq!(drain(&mut t), b"^A\x08 \x08\x08 \x08");
        let mut s = Termios::default();
        s.lflag &= !ECHOE;
        t.set_termios(s, false);
        t.input(b"a\x7f", 0);
        assert_eq!(drain(&mut t), b"a^?");
    }

    /// ^U erases the line: byte by byte with ECHOKE; with ECHOK alone the
    /// echo is ^U and a newline.
    #[test]
    fn kill_erases_the_line() {
        let mut t = Terminal::new();
        t.input(b"done\rabc\x15xy\r", 0);
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"done\n");
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"xy\n");
        assert_eq!(
            drain(&mut t),
            b"done\r\nabc\x08 \x08\x08 \x08\x08 \x08xy\r\n"
        );
        let mut s = Termios::default();
        s.lflag &= !ECHOKE;
        t.set_termios(s, false);
        t.input(b"abc\x15d\r", 0);
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"d\n");
        assert_eq!(drain(&mut t), b"abc^U\r\nd\r\n");
        // KILL on an empty line does nothing.
        t.input(b"\x15", 0);
        assert_eq!(drain(&mut t), b"");
    }

    #[test]
    fn word_erase_takes_the_last_word() {
        let mut t = Terminal::new();
        t.input(b"one two  \x17three\r", 0);
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"one three\n");
    }

    /// ^D on an empty line gives a read of 0; after bytes it gives them
    /// without a newline and goes with them.
    #[test]
    fn eof_ends_a_line_or_the_input() {
        let mut t = Terminal::new();
        t.input(b"\x04", 0);
        assert_eq!(read(&mut t, 64), Read::Ready(0));
        t.input(b"ab\x04", 0);
        assert_eq!(read_bytes(&mut t, 2).unwrap(), b"ab");
        assert_eq!(read(&mut t, 64), Read::Wait(None), "the EOF went with ab");
        assert_eq!(drain(&mut t), b"ab", "EOF has no echo");
    }

    /// A read takes one line at most, and any part of it.
    #[test]
    fn a_read_takes_one_line_at_most() {
        let mut t = Terminal::new();
        t.input(b"abc\rde\r", 0);
        assert_eq!(read_bytes(&mut t, 2).unwrap(), b"ab");
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"c\n");
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"de\n");
        assert_eq!(read(&mut t, 64), Read::Wait(None));
    }

    /// ^C drops what was typed and asks for SIGINT; the line after it
    /// reads whole.
    #[test]
    fn interrupt_flushes_and_asks_for_a_signal() {
        let mut t = Terminal::new();
        t.input(b"lost\rhalf", 0);
        t.input(b"\x03", 0);
        assert_eq!(t.take_signals().collect::<Vec<_>>(), [Signal::Interrupt]);
        assert_eq!(t.take_signals().count(), 0);
        assert_eq!(read(&mut t, 64), Read::Wait(None));
        assert_eq!(drain(&mut t), b"^C");
        t.input(b"next\r", 0);
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"next\n");
        t.input(b"\x1c\x1a", 0);
        assert_eq!(
            t.take_signals().collect::<Vec<_>>(),
            [Signal::Quit, Signal::Suspend]
        );
        // NOFLSH keeps the input; without ISIG ^C is a byte.
        let mut s = Termios::default();
        s.lflag |= NOFLSH;
        t.set_termios(s, false);
        t.input(b"kept\r\x03", 0);
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"kept\n");
        s.lflag &= !ISIG;
        t.set_termios(s, false);
        t.input(b"\x03\r", 0);
        assert_eq!(read_bytes(&mut t, 64).unwrap(), b"\x03\n");
        assert_eq!(t.take_signals().collect::<Vec<_>>(), [Signal::Interrupt]);
    }

    /// The case of the probe: ICANON off, VMIN 1, VTIME 0 gives each byte
    /// as it comes, with no newline.
    #[test]
    fn vmin_1_gives_each_byte() {
        let mut t = Terminal::new();
        t.set_termios(raw(1, 0), false);
        assert_eq!(read(&mut t, 16), Read::Wait(None));
        t.input(b"x", 0);
        assert_eq!(read_bytes(&mut t, 16).unwrap(), b"x");
        t.input(b"\x7f", 0);
        assert_eq!(read_bytes(&mut t, 16).unwrap(), b"\x7f", "no erase");
        t.input(b"\r", 0);
        assert_eq!(read_bytes(&mut t, 16).unwrap(), b"\n", "ICRNL still maps");
    }

    /// VMIN 0, VTIME 5: a read with nothing gives 0 at half a second from
    /// its start (case C), a byte at once.
    #[test]
    fn vtime_alone_times_a_read() {
        let mut t = Terminal::new();
        t.set_termios(raw(0, 5), false);
        let half = 500_000_000;
        let mut out = [0; 8];
        assert_eq!(t.read(&mut out, 1000, 1000), Read::Wait(Some(1000 + half)));
        assert_eq!(t.read(&mut out, 1000, 1000 + half), Read::Ready(0));
        t.input(b"q", 2000);
        assert_eq!(t.read(&mut out, 3000, 3000), Read::Ready(1));
        t.set_termios(raw(0, 0), false);
        assert_eq!(t.read(&mut out, 0, 0), Read::Ready(0), "case D");
    }

    /// VMIN 3, VTIME 1 (case A): no timer before a byte; after one, the
    /// timer between bytes; three bytes at once.
    #[test]
    fn vmin_and_vtime_time_the_bytes() {
        let mut t = Terminal::new();
        t.set_termios(raw(3, 1), false);
        let tenth = 100_000_000;
        let mut out = [0; 8];
        assert_eq!(t.read(&mut out, 0, 0), Read::Wait(None));
        t.input(b"a", 50);
        assert_eq!(t.read(&mut out, 0, 60), Read::Wait(Some(50 + tenth)));
        t.input(b"b", 70);
        assert_eq!(t.read(&mut out, 0, 80), Read::Wait(Some(70 + tenth)));
        assert_eq!(t.read(&mut out, 0, 70 + tenth), Read::Ready(2));
        t.input(b"cde", 1000);
        assert_eq!(t.read(&mut out, 0, 1000), Read::Ready(3));
        // A read that asks for fewer than VMIN is satisfied by its count.
        t.input(b"f", 2000);
        assert_eq!(t.read(&mut out[..1], 0, 2000), Read::Ready(1));
    }

    #[test]
    fn switching_modes_keeps_the_bytes() {
        let mut t = Terminal::new();
        t.input(b"ab\x04cd", 0);
        t.set_termios(raw(1, 0), false);
        assert_eq!(read_bytes(&mut t, 16).unwrap(), b"abcd");
        t.input(b"xy", 0);
        t.set_termios(Termios::default(), false);
        assert_eq!(read_bytes(&mut t, 16).unwrap(), b"xy");
        t.input(b"zz", 0);
        t.set_termios(Termios::default(), true);
        assert_eq!(t.queued(), (0, 0), "TCSAFLUSH drops the input");
    }

    #[test]
    fn input_maps_cr_and_nl() {
        let mut t = Terminal::new();
        let mut s = Termios {
            iflag: IGNCR,
            ..Termios::default()
        };
        t.set_termios(s, false);
        t.input(b"a\rb\n", 0);
        assert_eq!(read_bytes(&mut t, 16).unwrap(), b"ab\n");
        s.iflag = INLCR;
        s.cc[VEOL] = b'\r';
        t.set_termios(s, false);
        t.input(b"c\n", 0);
        assert_eq!(read_bytes(&mut t, 16).unwrap(), b"c\r", "NL as CR, the EOL");
        s.iflag = ISTRIP | ICRNL;
        t.set_termios(s, false);
        t.input(b"\xe1\x8d", 0);
        assert_eq!(read_bytes(&mut t, 16).unwrap(), b"a\n");
    }

    /// ECHONL echoes the newline alone when ECHO is off.
    #[test]
    fn echonl_without_echo() {
        let mut t = Terminal::new();
        let mut s = Termios::default();
        s.lflag = (s.lflag & !ECHO) | ECHONL;
        t.set_termios(s, false);
        t.input(b"secret\r", 0);
        assert_eq!(drain(&mut t), b"\r\n");
    }

    /// A line holds MAX_CANON - 1 bytes and its delimiter; the bytes past
    /// it are dropped, the delimiter still ends it.
    #[test]
    fn a_line_holds_max_canon_bytes() {
        let mut t = Terminal::new();
        let long = [b'x'; 300];
        t.input(&long, 0);
        assert_eq!(t.line_len(), MAX_CANON - 1);
        assert_eq!(t.dropped(), (300 - (MAX_CANON - 1)) as u64);
        t.input(b"\r", 0);
        let line = read_bytes(&mut t, 1016).unwrap();
        assert_eq!(line.len(), MAX_CANON);
        assert_eq!(line.last(), Some(&b'\n'));
    }

    /// The output processing: NL as CR NL with ONLCR, CR as NL with OCRNL,
    /// nothing without OPOST; a write stops where its echo room starts.
    #[test]
    fn writes_go_through_the_output_processing() {
        let mut t = Terminal::new();
        assert_eq!(t.write(b"a\nb"), 3);
        assert_eq!(drain(&mut t), b"a\r\nb");
        let mut s = Termios {
            oflag: OPOST | OCRNL,
            ..Termios::default()
        };
        t.set_termios(s, false);
        t.write(b"\r\n");
        assert_eq!(drain(&mut t), b"\n\n");
        s.oflag = 0;
        t.set_termios(s, false);
        t.write(b"\r\n");
        assert_eq!(drain(&mut t), b"\r\n");
        let big = [b'y'; 8192];
        let taken = t.write(&big);
        assert_eq!(taken, OUTPUT - ECHO_RESERVE - 2);
        assert!(!t.writable());
        assert_eq!(t.write(b"z"), 0);
        // The echo still finds room.
        t.input(b"k", 0);
        assert_eq!(t.output_len(), taken + 1);
        t.sent(100);
        assert!(t.writable());
    }
}
