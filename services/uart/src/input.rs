// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The input of the driver (spec 13.5, proto_uart READ): a ring of
//! RX_RING bytes that the interrupt fills from the receive FIFO, the
//! owner of the console and its read that waits. The first client that
//! reads while the console has no owner becomes its owner; a read of
//! another client is refused (BAD_STATE for the program to send), and so
//! is a second read of the owner while one waits. A read takes what the
//! ring holds, up to its most, at once; with nothing there it waits for
//! input. The owner that goes frees the console. `T` is what answers a
//! read later: the program's deferred reply.
//!
//! A read in two steps (proto_uart READ_START, READ_TAKE, READ_CANCEL;
//! proto_wire::long) holds no reply: the driver keeps the reader (its key
//! and, once it armed, `H`, its handle to tell it that input came) and
//! the bytes stay in the ring until READ_TAKE or READ_CANCEL takes them.
//! The console has one reader, so one read in two steps waits at most.

use crate::regs::DR_ERRORS;

/// The bytes of the ring of input.
pub const RX_RING: usize = 256;

/// What became of a read.
#[derive(Debug, PartialEq, Eq)]
pub enum Taken<T> {
    /// This many bytes came at once: answer with them through the token.
    Now(usize, T),
    /// It waits for input; `answer` answers it.
    Waits,
    /// The console is another's, or a read of the owner waits already:
    /// answer with BAD_STATE.
    Refused(T),
}

/// How READ_START went.
#[derive(Debug, PartialEq, Eq)]
pub enum Start {
    /// This many bytes came at once.
    Now(usize),
    /// None came: the read waits under this key.
    Wait(u64),
    /// The console is another's, or a read of the owner waits already.
    Refused,
}

/// How READ_TAKE or READ_CANCEL went.
#[derive(Debug, PartialEq, Eq)]
pub enum Taken2 {
    /// This many bytes came: the read is over.
    Ready(usize),
    /// Nothing came yet: the read waits (READ_TAKE).
    Armed,
    /// Nothing came: the read is over without an effect (READ_CANCEL).
    Cancelled,
    /// No read of the client waits under the key.
    Unknown,
}

/// The read in two steps that waits.
struct Reader<H> {
    label: u64,
    key: u64,
    max: usize,
    notify: Option<H>,
    told: bool,
}

/// The input: the ring, the owner and the read that waits.
pub struct Input<T, H = ()> {
    ring: [u8; RX_RING],
    start: usize,
    len: usize,
    owner: Option<u64>,
    /// The most bytes of the plain read that waits, and its answer.
    waiting: Option<(usize, T)>,
    /// The read in two steps that waits.
    reader: Option<Reader<H>>,
    /// The key of the next read in two steps.
    next_key: u64,
    /// Bytes that came with an error: framing, parity, break or overrun.
    errors: u64,
    /// The last successfully acknowledged input-flush nonce of the owner.
    last_flush: u64,
}

impl<T, H> Input<T, H> {
    pub const fn new() -> Input<T, H> {
        Input {
            ring: [0; RX_RING],
            start: 0,
            len: 0,
            owner: None,
            waiting: None,
            reader: None,
            next_key: 1,
            errors: 0,
            last_flush: 0,
        }
    }

    /// Flush only the owning console. The backend discards its received prefix
    /// before the software ring is cleared. An exact retry never calls it twice.
    /// A waiting reader retains its key and notification, which fresh input rearms.
    pub fn flush(&mut self, label: u64, nonce: u64, discard: impl FnOnce() -> bool) -> bool {
        if nonce == 0 || self.owner.is_some_and(|owner| owner != label) {
            return false;
        }
        if self.last_flush == nonce {
            return true;
        }
        if !discard() {
            return false;
        }
        self.owner = Some(label);
        self.start = 0;
        self.len = 0;
        if let Some(reader) = &mut self.reader {
            reader.told = false;
        }
        self.last_flush = nonce;
        true
    }

    /// The bytes the ring has room for.
    pub fn room(&self) -> usize {
        RX_RING - self.len
    }

    pub fn is_full(&self) -> bool {
        self.len == RX_RING
    }

    /// The label of the client that owns the console, if one does.
    pub fn owner(&self) -> Option<u64> {
        self.owner
    }

    /// The bytes that came with an error so far.
    pub fn errors(&self) -> u64 {
        self.errors
    }

    /// A byte that came, as DR gives it: the byte goes into the ring and
    /// an error in bits 11:8 is counted; false, with nothing kept, when the
    /// ring is full.
    pub fn push(&mut self, dr: u32) -> bool {
        if self.is_full() {
            return false;
        }
        if dr & DR_ERRORS != 0 {
            self.errors += 1;
        }
        self.ring[(self.start + self.len) % RX_RING] = dr as u8;
        self.len += 1;
        true
    }

    /// Moves up to `max` bytes of the ring, and no more than `out` holds,
    /// into `out`; gives their count.
    fn copy_out(&mut self, max: usize, out: &mut [u8]) -> usize {
        let n = self.len.min(max).min(out.len());
        for b in &mut out[..n] {
            *b = self.ring[self.start];
            self.start = (self.start + 1) % RX_RING;
        }
        self.len -= n;
        n
    }

    /// Whether the client of `label` may read now: the console becomes its
    /// own when it has no owner; a client that waits already may not.
    fn claim(&mut self, label: u64) -> bool {
        match self.owner {
            Some(owner) if owner != label => false,
            Some(_) if self.waiting.is_some() || self.reader.is_some() => false,
            _ => {
                self.owner = Some(label);
                true
            }
        }
    }

    /// A read of at most `max` bytes, 1 or more, from the client of label
    /// `label`, answered through `token`; the bytes that come at once go
    /// into `out`.
    pub fn read(&mut self, label: u64, max: usize, token: T, out: &mut [u8]) -> Taken<T> {
        if !self.claim(label) {
            return Taken::Refused(token);
        }
        if self.len > 0 {
            return Taken::Now(self.copy_out(max, out), token);
        }
        self.waiting = Some((max, token));
        Taken::Waits
    }

    /// The plain read that waits takes what came: its token and the count
    /// of bytes it moved into `out`; None while no read waits or nothing
    /// came.
    pub fn answer(&mut self, out: &mut [u8]) -> Option<(T, usize)> {
        if self.len == 0 {
            return None;
        }
        let (max, token) = self.waiting.take()?;
        Some((token, self.copy_out(max, out)))
    }

    /// READ_START of at most `max` bytes from the client of `label`.
    pub fn start(&mut self, label: u64, max: usize, out: &mut [u8]) -> Start {
        if !self.claim(label) {
            return Start::Refused;
        }
        if self.len > 0 {
            return Start::Now(self.copy_out(max, out));
        }
        let key = self.next_key;
        self.next_key = key.wrapping_add(1).max(1);
        self.reader = Some(Reader {
            label,
            key,
            max,
            notify: None,
            told: false,
        });
        Start::Wait(key)
    }

    /// Takes the bytes of the waiting read of `label` under `key`, when
    /// some came; the read is over then.
    fn finish(&mut self, label: u64, key: u64, out: &mut [u8]) -> Option<Option<usize>> {
        let reader = self.reader.as_ref()?;
        if reader.label != label || reader.key != key {
            return None;
        }
        if self.len == 0 {
            return Some(None);
        }
        let max = reader.max;
        self.reader = None;
        Some(Some(self.copy_out(max, out)))
    }

    /// READ_TAKE: the bytes that came, or ARMED, keeping `notify` when it
    /// came with the request.
    pub fn take(&mut self, label: u64, key: u64, notify: Option<H>, out: &mut [u8]) -> Taken2 {
        match self.finish(label, key, out) {
            None => Taken2::Unknown,
            Some(Some(n)) => Taken2::Ready(n),
            Some(None) => {
                let reader = self.reader.as_mut().expect("the waiting read");
                if notify.is_some() {
                    reader.notify = notify;
                    reader.told = false;
                }
                Taken2::Armed
            }
        }
    }

    /// READ_CANCEL: the bytes that came, or CANCELLED with nothing taken.
    pub fn cancel(&mut self, label: u64, key: u64, out: &mut [u8]) -> Taken2 {
        match self.finish(label, key, out) {
            None => Taken2::Unknown,
            Some(Some(n)) => Taken2::Ready(n),
            Some(None) => {
                self.reader = None;
                Taken2::Cancelled
            }
        }
    }

    /// The handle to tell the waiting read that input came, once: Some
    /// when bytes are there and the read armed and was not told yet.
    pub fn to_tell(&mut self) -> Option<&H> {
        if self.len == 0 {
            return None;
        }
        let reader = self.reader.as_mut()?;
        if reader.told || reader.notify.is_none() {
            return None;
        }
        reader.told = true;
        reader.notify.as_ref()
    }

    /// Whether a read in two steps waits, for the probes.
    pub fn reading(&self) -> bool {
        self.reader.is_some()
    }

    /// Restore bytes when reply delivery failed. The single driver thread
    /// has not handled another read or IRQ since taking them from this ring.
    pub fn restore(&mut self, bytes: &[u8]) {
        assert!(
            self.len + bytes.len() <= RX_RING,
            "input rollback exceeds ring"
        );
        self.start = (self.start + RX_RING - bytes.len()) % RX_RING;
        for (index, byte) in bytes.iter().enumerate() {
            self.ring[(self.start + index) % RX_RING] = *byte;
        }
        self.len += bytes.len();
    }

    /// The client of label `label` went: when it owned the console, the
    /// console is free, and the token of its read that waits comes back.
    pub fn gone(&mut self, label: u64) -> Option<T> {
        if self.owner != Some(label) {
            return None;
        }
        self.owner = None;
        self.last_flush = 0;
        self.reader = None;
        self.waiting.take().map(|(_, token)| token)
    }
}

impl<T, H> Default for Input<T, H> {
    fn default() -> Input<T, H> {
        Input::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_flush_keeps_waiter_rearms_and_replays_without_discarding_fresh_bytes() {
        let mut input: Input<char, &str> = Input::new();
        let mut out = [0; RX_RING];
        assert_eq!(input.start(7, 2, &mut out), Start::Wait(1));
        assert_eq!(input.take(7, 1, Some("reader"), &mut out), Taken2::Armed);
        assert!(input.push(u32::from(b'o')));
        assert_eq!(input.to_tell(), Some(&"reader"));
        let nonce = (1_u64 << 32) | 5;
        assert!(input.flush(7, nonce, || true));
        // A stale notification cannot deliver input predating the flush.
        assert_eq!(input.take(7, 1, None, &mut out), Taken2::Armed);
        assert!(input.push(u32::from(b'n')));
        assert_eq!(input.to_tell(), Some(&"reader"));
        // Model loss of the first acknowledgment and identical request replay.
        assert!(input.flush(7, nonce, || panic!("replayed hardware discard")));
        assert_eq!(input.take(7, 1, None, &mut out), Taken2::Ready(1));
        assert_eq!(out[0], b'n');
        assert!(input.push(u32::from(b'q')));
        // The high half belongs to the identity, even with the same low half.
        assert!(input.flush(7, (2_u64 << 32) | 5, || true));
        assert_eq!(input.start(7, 2, &mut out), Start::Wait(2));
    }

    #[test]
    fn input_flush_discards_a_full_wrapped_ring() {
        let mut input: Input<()> = Input::new();
        let mut out = [0; RX_RING];
        for _ in 0..RX_RING {
            assert!(input.push(u32::from(b'o')));
        }
        assert_eq!(input.start(7, 17, &mut out), Start::Now(17));
        for _ in 0..17 {
            assert!(input.push(u32::from(b'o')));
        }
        assert!(input.is_full());
        assert!(input.flush(7, 1, || true));
        assert!(input.push(u32::from(b'n')));
        assert_eq!(input.start(7, RX_RING, &mut out), Start::Now(1));
        assert_eq!(out[0], b'n');
    }

    #[test]
    fn input_flush_validates_owner_and_zero_and_commits_only_backend_success() {
        let mut input: Input<char> = Input::new();
        let mut out = [0; RX_RING];
        assert!(!input.flush(7, 0, || panic!("zero reached backend")));
        assert_eq!(input.read(7, 2, 'r', &mut out), Taken::Waits);
        assert!(input.push(u32::from(b'o')));
        assert!(!input.flush(8, 1, || panic!("foreign owner reached backend")));
        let hardware_discarded = core::cell::Cell::new(false);
        assert!(!input.flush(7, 1, || {
            // A failed repost may have already discarded a hardware prefix.
            hardware_discarded.set(true);
            false
        }));
        assert!(hardware_discarded.get());
        assert_eq!(input.room(), RX_RING - 1);
        assert!(input.flush(7, 1, || true));
        assert!(input.push(u32::from(b'n')));
        assert_eq!(input.answer(&mut out), Some(('r', 1)));
        assert_eq!(out[0], b'n');
        input.gone(7);
        assert!(input.push(u32::from(b'q')));
        // An actual new owner may reuse a nonce from the old session.
        assert!(input.flush(8, 1, || true));
        assert_eq!(input.owner(), Some(8));
        assert_eq!(input.room(), RX_RING);
    }

    #[test]
    fn a_read_in_two_steps_keeps_its_bytes_until_take_or_cancel() {
        let mut input: Input<char, &str> = Input::new();
        let mut out = [0; RX_RING];
        assert_eq!(input.start(7, 2, &mut out), Start::Wait(1));
        assert_eq!(input.start(8, 2, &mut out), Start::Refused);
        assert_eq!(input.start(7, 2, &mut out), Start::Refused);
        assert_eq!(input.take(8, 1, None, &mut out), Taken2::Unknown);
        assert_eq!(input.take(7, 2, None, &mut out), Taken2::Unknown);
        assert_eq!(input.take(7, 1, Some("h"), &mut out), Taken2::Armed);
        assert_eq!(input.to_tell(), None);
        assert!(input.push(u32::from(b'q')));
        assert_eq!(input.to_tell(), Some(&"h"));
        assert_eq!(input.to_tell(), None);
        // Cancel after the bytes came gives them: nothing is lost.
        assert_eq!(input.cancel(7, 1, &mut out), Taken2::Ready(1));
        assert_eq!(out[0], b'q');
        assert!(!input.reading());
        // Cancel before they came takes nothing.
        assert_eq!(input.start(7, 2, &mut out), Start::Wait(2));
        assert_eq!(input.cancel(7, 2, &mut out), Taken2::Cancelled);
        assert_eq!(input.cancel(7, 2, &mut out), Taken2::Unknown);
        assert!(input.push(u32::from(b'r')));
        assert_eq!(input.start(7, 4, &mut out), Start::Now(1));
        assert_eq!(out[0], b'r');
        assert_eq!(input.start(7, 4, &mut out), Start::Wait(3));
        assert_eq!(input.read(7, 1, 'a', &mut out), Taken::Refused('a'));
        assert_eq!(input.gone(7), None);
        assert!(!input.reading());
    }

    #[test]
    fn failed_delivery_restores_wrapped_bytes_in_order() {
        let mut input: Input<char> = Input::new();
        let mut out = [0; RX_RING];
        for value in 0..RX_RING {
            assert!(input.push(value as u32));
        }
        assert_eq!(
            input.read(7, RX_RING - 2, 'a', &mut out),
            Taken::Now(RX_RING - 2, 'a')
        );
        for value in *b"abc" {
            assert!(input.push(u32::from(value)));
        }
        assert_eq!(input.read(7, 3, 'b', &mut out), Taken::Now(3, 'b'));
        assert_eq!(&out[..3], &[254, 255, b'a']);
        input.restore(&out[..3]);
        assert_eq!(input.read(7, 5, 'c', &mut out), Taken::Now(5, 'c'));
        assert_eq!(&out[..5], &[254, 255, b'a', b'b', b'c']);
        assert_eq!(input.room(), RX_RING);
        assert_eq!(input.read(7, 2, 'd', &mut out), Taken::Waits);
        for value in *b"xyz" {
            assert!(input.push(u32::from(value)));
        }
        assert_eq!(input.answer(&mut out), Some(('d', 2)));
        input.restore(&out[..2]);
        assert_eq!(input.read(7, 3, 'e', &mut out), Taken::Now(3, 'e'));
        assert_eq!(&out[..3], b"xyz");
    }

    #[test]
    fn the_first_reader_owns_the_console() {
        let mut i: Input<char> = Input::new();
        assert_eq!(i.owner(), None);
        assert_eq!(i.read(7, 64, 'a', &mut [0; 64]), Taken::Waits);
        assert_eq!(i.owner(), Some(7));
    }

    #[test]
    fn another_reader_gets_bad_state() {
        let mut i: Input<char> = Input::new();
        let mut out = [0; 64];
        assert!(i.push(u32::from(b'q')));
        assert_eq!(i.read(7, 64, 'a', &mut out), Taken::Now(1, 'a'));
        assert_eq!(i.read(8, 64, 'b', &mut out), Taken::Refused('b'));
        assert_eq!(i.owner(), Some(7));
        // A second read of the owner while one waits.
        assert_eq!(i.read(7, 64, 'c', &mut out), Taken::Waits);
        assert_eq!(i.read(7, 64, 'd', &mut out), Taken::Refused('d'));
    }

    #[test]
    fn the_owner_that_goes_frees_the_console() {
        let mut i: Input<char> = Input::new();
        let mut out = [0; 64];
        assert_eq!(i.read(7, 64, 'a', &mut out), Taken::Waits);
        assert_eq!(i.gone(8), None);
        assert_eq!(i.owner(), Some(7));
        assert_eq!(i.gone(7), Some('a'));
        assert_eq!(i.owner(), None);
        assert_eq!(i.read(8, 64, 'b', &mut out), Taken::Waits);
        assert_eq!(i.owner(), Some(8));
    }

    #[test]
    fn a_waiting_read_takes_what_comes() {
        let mut i: Input<char> = Input::new();
        let mut out = [0; 64];
        assert_eq!(i.answer(&mut out), None);
        assert_eq!(i.read(7, 2, 'a', &mut out), Taken::Waits);
        assert_eq!(i.answer(&mut out), None);
        for b in *b"abc" {
            assert!(i.push(u32::from(b)));
        }
        // An overrun and a framing error on the byte, which still counts.
        assert!(i.push(0x800 | 0x100 | u32::from(b'd')));
        assert_eq!(i.errors(), 1);
        assert_eq!(i.answer(&mut out), Some(('a', 2)));
        assert_eq!(&out[..2], b"ab");
        assert_eq!(i.answer(&mut out), None);
        assert_eq!(i.read(7, 64, 'b', &mut out), Taken::Now(2, 'b'));
        assert_eq!(&out[..2], b"cd");
        // A full ring takes nothing more.
        for _ in 0..RX_RING {
            assert!(i.push(u32::from(b'x')));
        }
        assert!(i.is_full() && !i.push(u32::from(b'y')));
        assert_eq!(i.room(), 0);
    }
}
