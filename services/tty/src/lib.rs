// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the terminal service decides (5f), apart from the loop and the
//! calls: the line discipline (`discipline`), the output's way to the
//! console's driver in parts (`Pump`), and the reads and writes that wait
//! on a terminal (`Waiters`). Everything here builds for the host too,
//! where `cargo test -p tty` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod discipline;
pub mod endpoints;
#[cfg(test)]
mod fuzz;
pub mod jobs;
#[cfg(test)]
mod reference;

use discipline::Terminal;
use proto_uart::WRITE_MAX;

/// The most bytes one WRITE_SOME of the pump carries: half a message, so
/// that the driver's copy of them fits a step of the service.
pub const PIECE: usize = WRITE_MAX / 2;

/// The driver's side of the output (proto_uart WRITE_SOME and ROOM).
pub trait Driver {
    type Error;
    /// WRITE_SOME: the driver takes as many of `bytes` as its ring has room
    /// for, and gives their count.
    fn write_some(&mut self, bytes: &[u8]) -> Result<usize, Self::Error>;
    /// ROOM: true when the driver has room now; false once it armed its
    /// notification, which comes when room does.
    fn room(&mut self) -> Result<bool, Self::Error>;
}

/// How a run of the pump ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pumped {
    /// The terminal has no output to give now: none left, or it is
    /// stopped (`Terminal::stopped`).
    Idle,
    /// The driver's notification of room is armed: no write until it
    /// comes (`Pump::room_came`).
    WaitsRoom,
    /// Output is left after the writes of one run: the next step goes on.
    More,
}

/// The output of a terminal on its way to the driver, which never waits
/// for the port: the pump writes what the driver takes and arms its
/// notification of room for the rest (5f design, decision 2).
#[derive(Default)]
pub struct Pump {
    waits_room: bool,
}

impl Pump {
    pub const fn new() -> Pump {
        Pump { waits_room: false }
    }

    /// The driver's notification of room came.
    pub fn room_came(&mut self) {
        self.waits_room = false;
    }

    pub fn waits_room(&self) -> bool {
        self.waits_room
    }

    /// Up to `writes` WRITE_SOME of the terminal's output, each of PIECE
    /// bytes at most; ROOM after one the driver took in part. The
    /// bytes the driver took leave the terminal, and only they.
    pub fn run<D: Driver>(
        &mut self,
        terminal: &mut Terminal,
        driver: &mut D,
        writes: usize,
    ) -> Result<Pumped, D::Error> {
        for _ in 0..writes {
            if terminal.stopped() {
                return Ok(Pumped::Idle);
            }
            if self.waits_room {
                return Ok(Pumped::WaitsRoom);
            }
            let piece = terminal.output();
            let piece = &piece[..piece.len().min(PIECE)];
            if piece.is_empty() {
                return Ok(Pumped::Idle);
            }
            let len = piece.len();
            let taken = driver.write_some(piece)?.min(len);
            terminal.sent(taken);
            if taken < len && !driver.room()? {
                self.waits_room = true;
                return Ok(Pumped::WaitsRoom);
            }
        }
        Ok(if terminal.output_len() == 0 {
            Pumped::Idle
        } else {
            Pumped::More
        })
    }
}

/// A read or a write that waits on a terminal: its client, its key, and
/// for a read when it started and the deadline of its VTIME.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Waiter {
    pub label: u64,
    pub key: u64,
    pub started: u64,
    pub deadline: Option<u64>,
}

/// The reads, or the writes, that wait on one terminal, `N` at most.
pub struct Waiters<const N: usize> {
    list: [Option<Waiter>; N],
}

impl<const N: usize> Default for Waiters<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Waiters<N> {
    pub const fn new() -> Self {
        Waiters { list: [None; N] }
    }

    /// One more; false with N there.
    pub fn add(&mut self, waiter: Waiter) -> bool {
        match self.list.iter_mut().find(|w| w.is_none()) {
            Some(place) => {
                *place = Some(waiter);
                true
            }
            None => false,
        }
    }

    pub fn find(&mut self, label: u64, key: u64) -> Option<&mut Waiter> {
        self.list
            .iter_mut()
            .flatten()
            .find(|w| w.label == label && w.key == key)
    }

    /// The waiter `key` of `label` goes, if it waits.
    pub fn remove(&mut self, label: u64, key: u64) {
        for place in &mut self.list {
            if place.is_some_and(|w| w.label == label && w.key == key) {
                *place = None;
            }
        }
    }

    /// Stale generation keys are discarded before a new subscription.
    pub fn retain(&mut self, mut alive: impl FnMut(u64, u64) -> bool) {
        for place in &mut self.list {
            if place.is_some_and(|w| !alive(w.label, w.key)) {
                *place = None;
            }
        }
    }

    /// Every waiter of `label` goes.
    pub fn remove_all(&mut self, label: u64) {
        for place in &mut self.list {
            if place.is_some_and(|w| w.label == label) {
                *place = None;
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Waiter> {
        self.list.iter().flatten()
    }

    /// Each waiter whose deadline is past at `at` goes to `f`, and its
    /// deadline with it: the timer that ran out tells it once.
    pub fn expire(&mut self, at: u64, mut f: impl FnMut(&Waiter)) {
        for w in self.list.iter_mut().flatten() {
            if w.deadline.is_some_and(|d| d <= at) {
                f(w);
                w.deadline = None;
            }
        }
    }

    /// The earliest deadline of a waiter.
    pub fn deadline(&self) -> Option<u64> {
        self.iter().filter_map(|w| w.deadline).min()
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// A driver whose ring holds `room` bytes until the port drains it.
    struct Fake {
        room: usize,
        port: Vec<u8>,
        ring: Vec<u8>,
        armed: bool,
        writes: usize,
    }

    impl Fake {
        fn new(room: usize) -> Fake {
            Fake {
                room,
                port: Vec::new(),
                ring: Vec::new(),
                armed: false,
                writes: 0,
            }
        }

        /// The port sends `n` bytes of the ring: true when the armed
        /// notification fires.
        fn drain(&mut self, n: usize) -> bool {
            let n = n.min(self.ring.len());
            self.port.extend(self.ring.drain(..n));
            core::mem::take(&mut self.armed)
        }
    }

    impl Driver for Fake {
        type Error = ();
        fn write_some(&mut self, bytes: &[u8]) -> Result<usize, ()> {
            self.writes += 1;
            let n = bytes.len().min(self.room - self.ring.len());
            self.ring.extend_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn room(&mut self) -> Result<bool, ()> {
            if self.ring.len() < self.room {
                return Ok(true);
            }
            self.armed = true;
            Ok(false)
        }
    }

    /// A write to a terminal whose driver's ring is full waits for room
    /// and loses no byte: the port shows every byte in its order, and the
    /// pump never spins on a full driver.
    #[test]
    fn output_waits_for_the_driver_and_loses_nothing() {
        let mut t = Terminal::new();
        let mut sent = Vec::new();
        for i in 0..2500u32 {
            sent.push(b'a' + (i % 26) as u8);
        }
        assert_eq!(t.write(&sent), sent.len());
        let mut d = Fake::new(100);
        let mut pump = Pump::new();
        assert_eq!(pump.run(&mut t, &mut d, 2), Ok(Pumped::WaitsRoom));
        assert_eq!(d.writes, 1, "a full driver takes one WRITE_SOME");
        assert_eq!(pump.run(&mut t, &mut d, 2), Ok(Pumped::WaitsRoom));
        assert_eq!(d.writes, 1, "no write while room is armed");
        let mut rounds = 0;
        while t.output_len() > 0 || !d.ring.is_empty() {
            if d.drain(37) {
                pump.room_came();
            }
            let _ = pump.run(&mut t, &mut d, 2);
            rounds += 1;
            assert!(rounds < 1000);
        }
        d.drain(usize::MAX);
        assert_eq!(d.port, sent);
        assert_eq!(pump.run(&mut t, &mut d, 2), Ok(Pumped::Idle));
    }

    /// A run of the pump writes `writes` messages at most and says More
    /// for the rest.
    #[test]
    fn a_run_is_bounded() {
        let mut t = Terminal::new();
        t.write(&[b'x'; 2500]);
        let mut d = Fake::new(10_000);
        let mut pump = Pump::new();
        assert_eq!(pump.run(&mut t, &mut d, 1), Ok(Pumped::More));
        assert_eq!(d.ring.len(), PIECE);
        assert_eq!(pump.run(&mut t, &mut d, 8), Ok(Pumped::Idle));
        assert_eq!(d.ring.len(), 2500);
    }

    /// Stopped output stays in the terminal: the pump gives the driver
    /// nothing, and every byte goes once the output starts again (tcflow
    /// with TCOOFF and TCOON).
    #[test]
    fn stopped_output_waits_in_the_terminal() {
        let mut t = Terminal::new();
        t.write(b"abc");
        t.set_stopped(true);
        let mut d = Fake::new(100);
        let mut pump = Pump::new();
        assert_eq!(pump.run(&mut t, &mut d, 2), Ok(Pumped::Idle));
        assert_eq!((d.writes, t.output_len()), (0, 3));
        t.set_stopped(false);
        assert_eq!(pump.run(&mut t, &mut d, 2), Ok(Pumped::Idle));
        assert_eq!((d.writes, t.output_len()), (1, 0));
        d.drain(usize::MAX);
        assert_eq!(d.port, b"abc");
    }

    /// The output the driver did not take goes at a flush (tcflush with
    /// TCOFLUSH), and the bytes the driver took stay its own.
    #[test]
    fn a_flush_drops_the_output_the_driver_did_not_take() {
        let mut t = Terminal::new();
        t.write(&[b'x'; 300]);
        let mut d = Fake::new(100);
        let mut pump = Pump::new();
        assert_eq!(pump.run(&mut t, &mut d, 1), Ok(Pumped::WaitsRoom));
        assert_eq!((d.ring.len(), t.output_len()), (100, 200));
        t.flush_output();
        assert_eq!(t.output_len(), 0);
        assert_eq!(d.ring.len(), 100);
        assert_eq!(t.write(b"after"), 5);
        assert_eq!(t.output(), b"after");
    }

    #[test]
    fn waiters_are_bounded_and_found() {
        let mut w = Waiters::<2>::new();
        let one = Waiter {
            label: 1,
            key: 5,
            started: 0,
            deadline: Some(9),
        };
        assert!(w.add(one));
        assert!(w.add(Waiter {
            key: 6,
            deadline: Some(4),
            ..one
        }));
        assert!(!w.add(one));
        assert_eq!(w.deadline(), Some(4));
        let mut expired = Vec::new();
        w.expire(5, |w| expired.push(w.key));
        assert_eq!(expired, [6]);
        assert_eq!(w.deadline(), Some(9), "an expired deadline goes");
        assert!(w.find(1, 6).is_some());
        w.remove(1, 6);
        assert_eq!(w.len(), 1);
        w.remove_all(1);
        assert!(w.is_empty());
    }
}
