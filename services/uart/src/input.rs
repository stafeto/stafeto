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

/// The input: the ring, the owner and the read that waits.
pub struct Input<T> {
    ring: [u8; RX_RING],
    start: usize,
    len: usize,
    owner: Option<u64>,
    /// The most bytes of the read that waits, and its answer.
    waiting: Option<(usize, T)>,
    /// Bytes that came with an error: framing, parity, break or overrun.
    errors: u64,
}

impl<T> Input<T> {
    pub const fn new() -> Input<T> {
        Input {
            ring: [0; RX_RING],
            start: 0,
            len: 0,
            owner: None,
            waiting: None,
            errors: 0,
        }
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

    /// A read of at most `max` bytes, 1 or more, from the client of label
    /// `label`, answered through `token`; the bytes that come at once go
    /// into `out`.
    pub fn read(&mut self, label: u64, max: usize, token: T, out: &mut [u8]) -> Taken<T> {
        match self.owner {
            Some(owner) if owner != label => return Taken::Refused(token),
            Some(_) if self.waiting.is_some() => return Taken::Refused(token),
            _ => self.owner = Some(label),
        }
        if self.len > 0 {
            return Taken::Now(self.copy_out(max, out), token);
        }
        self.waiting = Some((max, token));
        Taken::Waits
    }

    /// The read that waits takes what came: its token and the count of
    /// bytes it moved into `out`; None while no read waits or nothing came.
    pub fn answer(&mut self, out: &mut [u8]) -> Option<(T, usize)> {
        if self.len == 0 {
            return None;
        }
        let (max, token) = self.waiting.take()?;
        Some((token, self.copy_out(max, out)))
    }

    /// The client of label `label` went: when it owned the console, the
    /// console is free, and the token of its read that waits comes back.
    pub fn gone(&mut self, label: u64) -> Option<T> {
        if self.owner != Some(label) {
            return None;
        }
        self.owner = None;
        self.waiting.take().map(|(_, token)| token)
    }
}

impl<T> Default for Input<T> {
    fn default() -> Input<T> {
        Input::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_reader_owns_the_console() {
        let mut i = Input::new();
        assert_eq!(i.owner(), None);
        assert_eq!(i.read(7, 64, 'a', &mut [0; 64]), Taken::Waits);
        assert_eq!(i.owner(), Some(7));
    }

    #[test]
    fn another_reader_gets_bad_state() {
        let mut i = Input::new();
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
        let mut i = Input::new();
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
        let mut i = Input::new();
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
