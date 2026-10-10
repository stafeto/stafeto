// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The writes of the clients (spec 13.5, proto_uart WRITE): a write goes
//! into the ring of output whole, and is answered at once, when it fits
//! and no write waits before it; otherwise its bytes wait whole in one of
//! WAITING places, in the order they came, and it is answered once they
//! went into the ring. A write past the places is refused (LIMIT_REACHED
//! for the program to send). `T` is what answers a write later: the
//! program's deferred reply.
//!
//! WRITE_SOME takes the part that fits at once and never waits; ROOM keeps
//! a client's handle (`Rooms`, `H`) to tell it of room once ROOM_MARK bytes
//! are free and no write waits (proto_uart, 5f).

use crate::output::Output;
use proto_uart::{ROOM_MARK, ROOMS, WRITE_MAX};

/// The places of writes that wait.
pub const WAITING: usize = 4;

/// What became of a write.
#[derive(Debug, PartialEq, Eq)]
pub enum Taken<T> {
    /// All its bytes went into the ring: answer at once, through the
    /// token, with the count.
    Now(u32, T),
    /// It waits for room, whole; `flush` answers it.
    Waits,
    /// No place is left: answer with LIMIT_REACHED.
    Full(T),
}

/// A write that waits: its client, its bytes in the place of the same
/// number, their count, its answer and its turn.
struct Waiting<T> {
    label: u64,
    len: usize,
    token: T,
    turn: u64,
}

/// The writes that wait.
pub struct Writes<T> {
    places: [Option<Waiting<T>>; WAITING],
    bytes: [[u8; WRITE_MAX]; WAITING],
    /// The turn of the next write that waits.
    turn: u64,
}

impl<T> Writes<T> {
    pub const fn new() -> Writes<T> {
        Writes {
            places: [const { None }; WAITING],
            bytes: [[0; WRITE_MAX]; WAITING],
            turn: 0,
        }
    }

    /// Whether no write waits.
    pub fn is_empty(&self) -> bool {
        self.places.iter().all(Option::is_none)
    }

    /// The accepted bytes that have not entered the client ring yet.
    pub fn queued_bytes(&self) -> usize {
        self.places.iter().flatten().map(|w| w.len).sum()
    }

    /// A write of `bytes`, at most WRITE_MAX of them, from the client of
    /// label `label`, answered through `token`: into `output` at once when
    /// it fits and no write waits, into a place otherwise, refused with
    /// its token when no place is left.
    pub fn write(&mut self, output: &mut Output, label: u64, bytes: &[u8], token: T) -> Taken<T> {
        let len = bytes.len().min(WRITE_MAX);
        if self.is_empty() && output.put(&bytes[..len]) {
            return Taken::Now(len as u32, token);
        }
        let Some(i) = self.places.iter().position(Option::is_none) else {
            return Taken::Full(token);
        };
        self.bytes[i][..len].copy_from_slice(&bytes[..len]);
        self.places[i] = Some(Waiting {
            label,
            len,
            token,
            turn: self.turn,
        });
        self.turn += 1;
        Taken::Waits
    }

    /// WRITE_SOME of `bytes`: as many as `output` has room for go into it,
    /// none while a write waits, which goes first; their count.
    pub fn write_some(&self, output: &mut Output, bytes: &[u8]) -> usize {
        if !self.is_empty() {
            return 0;
        }
        let n = bytes.len().min(WRITE_MAX).min(output.room());
        // `n` fits the room.
        let _ = output.put_raw(&bytes[..n]);
        n
    }

    /// Whether a client of ROOM may write now: ROOM_MARK bytes are free
    /// and no write waits.
    pub fn roomy(&self, output: &Output) -> bool {
        self.is_empty() && output.room() >= ROOM_MARK
    }

    /// The writes that wait go into `output` in their order while they
    /// fit, each whole; each one that went is answered through `answer`
    /// with its token and count.
    pub fn flush(&mut self, output: &mut Output, mut answer: impl FnMut(T, u32)) {
        while let Some(i) = self.first() {
            let len = self.places[i].as_ref().map_or(0, |w| w.len);
            if !output.put(&self.bytes[i][..len]) {
                return;
            }
            if let Some(w) = self.places[i].take() {
                answer(w.token, len as u32);
            }
        }
    }

    /// The place of the write that waits longest.
    fn first(&self) -> Option<usize> {
        (0..WAITING)
            .filter_map(|i| self.places[i].as_ref().map(|w| (w.turn, i)))
            .min()
            .map(|(_, i)| i)
    }

    /// Remove a departing client's pending writes, preserving their positions
    /// for captured drains. At most WAITING records are inspected.
    pub fn gone_before(
        &mut self,
        label: u64,
        mut start: u64,
        mut drop: impl FnMut(T),
        mut removed: impl FnMut(u64, usize),
    ) {
        let mut visited = [false; WAITING];
        for _ in 0..WAITING {
            let Some(i) = (0..WAITING)
                .filter(|&i| !visited[i])
                .filter_map(|i| self.places[i].as_ref().map(|w| (w.turn, i)))
                .min()
                .map(|(_, i)| i)
            else {
                break;
            };
            visited[i] = true;
            let waiting = self.places[i].as_ref().expect("a pending write");
            if waiting.label == label {
                let waiting = self.places[i].take().expect("a pending write");
                removed(start, waiting.len);
                drop(waiting.token);
            } else {
                start = start.wrapping_add(waiting.len as u64);
            }
        }
    }

    /// The client went; callers without observers need only its reply tokens.
    pub fn gone(&mut self, label: u64, drop: impl FnMut(T)) {
        self.gone_before(label, 0, drop, |_, _| {});
    }
}

impl<T> Default for Writes<T> {
    fn default() -> Writes<T> {
        Writes::new()
    }
}

/// A client of ROOM: its label, its handle, and whether it waits for room.
struct Room<H> {
    label: u64,
    notify: H,
    armed: bool,
    drain: Option<Drain>,
    last_released: u64,
}

#[derive(Clone, Copy)]
struct Drain {
    key: u64,
    target: u64,
    ready: bool,
    armed: bool,
}

/// The clients of ROOM that keep a handle, ROOMS at most.
pub struct Rooms<H> {
    places: [Option<Room<H>>; ROOMS],
}

/// How ROOM went.
#[derive(Debug, PartialEq, Eq)]
pub enum Armed {
    /// The client may write now: nothing armed.
    Now,
    /// The notification is armed.
    Armed,
    /// The client brought no handle and keeps none, or no place is left:
    /// LIMIT_REACHED.
    Refused,
}

impl<H> Rooms<H> {
    pub const fn new() -> Rooms<H> {
        Rooms {
            places: [const { None }; ROOMS],
        }
    }

    /// ROOM of the client `label`, with the handle it brought, if any:
    /// `roomy` says whether it may write now (Writes::roomy). The first
    /// handle a client brings stays its own until it goes.
    pub fn room(&mut self, label: u64, notify: Option<H>, roomy: bool) -> Armed {
        let known = self
            .places
            .iter()
            .position(|p| p.as_ref().is_some_and(|r| r.label == label));
        let i = match (known, notify) {
            (Some(i), _) => i,
            (None, Some(notify)) => {
                let Some(i) = self.places.iter().position(Option::is_none) else {
                    return Armed::Refused;
                };
                self.places[i] = Some(Room {
                    label,
                    notify,
                    armed: false,
                    drain: None,
                    last_released: 0,
                });
                i
            }
            (None, None) if roomy => return Armed::Now,
            (None, None) => return Armed::Refused,
        };
        let room = self.places[i].as_mut().expect("a place of ROOM");
        room.armed = !roomy;
        if roomy { Armed::Now } else { Armed::Armed }
    }

    /// The handles of the clients that wait for room, once each, when
    /// `roomy`: they wait no more.
    pub fn to_tell(&mut self, roomy: bool, mut tell: impl FnMut(&H)) {
        if !roomy {
            return;
        }
        for room in self.places.iter_mut().flatten() {
            if room.armed {
                room.armed = false;
                tell(&room.notify);
            }
        }
    }

    /// Capture a prefix with the existing terminal operation's full key.
    /// A replay of that key observes the same prefix, even after completion.
    pub fn drain_begin(&mut self, label: u64, key: u64, capture: u64) -> Option<bool> {
        let room = self
            .places
            .iter_mut()
            .flatten()
            .find(|r| r.label == label)?;
        if key == 0 || room.last_released == key {
            return None;
        }
        if let Some(drain) = room.drain.as_mut() {
            if drain.key == key {
                drain.armed = !drain.ready;
                return Some(drain.ready);
            }
            if !drain.ready {
                return None;
            }
        }
        room.drain = Some(Drain {
            key,
            target: capture,
            ready: false,
            armed: true,
        });
        Some(false)
    }

    /// Poll only this exact operation; notification bits carry no authority.
    pub fn drain(&mut self, label: u64, key: u64) -> Option<bool> {
        let room = self
            .places
            .iter_mut()
            .flatten()
            .find(|r| r.label == label)?;
        let drain = room.drain.as_mut().filter(|d| d.key == key)?;
        drain.armed = !drain.ready;
        Some(drain.ready)
    }

    /// A removed queued write belongs to each captured prefix containing it.
    /// Both distances are bounded by the ring plus the four pending records.
    pub fn drain_discard(&mut self, submitted: u64, start: u64, len: usize) {
        let start = start.wrapping_sub(submitted);
        for room in self.places.iter_mut().flatten() {
            if let Some(drain) = room.drain.as_mut()
                && !drain.ready
                && start < drain.target.wrapping_sub(submitted)
            {
                drain.target = drain.target.wrapping_sub(len as u64);
            }
        }
    }

    /// The nearest unfinished target. Every live distance fits the fixed queues.
    pub fn drain_target(&self, submitted: u64) -> Option<u64> {
        self.places
            .iter()
            .flatten()
            .filter_map(|r| r.drain)
            .filter(|d| !d.ready)
            .map(|d| d.target)
            .min_by_key(|target| target.wrapping_sub(submitted))
    }

    /// Latch physical completion before any newer hardware loads are allowed.
    pub fn drain_complete(&mut self, submitted: u64, mut tell: impl FnMut(&H)) {
        for room in self.places.iter_mut().flatten() {
            if let Some(drain) = room.drain.as_mut()
                && drain.target == submitted
                && !drain.ready
            {
                drain.ready = true;
                if drain.armed {
                    drain.armed = false;
                    tell(&room.notify);
                }
            }
        }
    }

    /// Remove this exact observation while retaining the paid ROOM handle.
    /// Retain one full key so a lost short reply can be retried without
    /// removing a newer observation or reopening the released operation.
    pub fn drain_release(&mut self, label: u64, key: u64) -> bool {
        let Some(room) = self.places.iter_mut().flatten().find(|r| r.label == label) else {
            return false;
        };
        if room.drain.is_some_and(|d| d.key == key) {
            room.drain = None;
            room.last_released = key;
            true
        } else {
            key != 0 && room.last_released == key
        }
    }

    /// The client of `label` went: its place goes with its handle.
    pub fn gone(&mut self, label: u64) {
        for place in &mut self.places {
            if place.as_ref().is_some_and(|r| r.label == label) {
                *place = None;
            }
        }
    }
}

impl<H> Default for Rooms<H> {
    fn default() -> Rooms<H> {
        Rooms::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::TX_RING;
    use std::vec::Vec;

    #[test]
    fn drain_uses_exact_operation_identity_and_sticky_completion() {
        let mut rooms = Rooms::new();
        rooms.room(0x100000001, Some(7), true);
        assert_eq!(rooms.drain_begin(1, 90, 0), None);
        assert_eq!(rooms.drain_begin(0x100000001, 90, 0), Some(false));
        assert_eq!(rooms.drain_begin(0x100000001, 91, 0), None);
        let mut told = Vec::new();
        rooms.drain_complete(0, |h| told.push(*h));
        rooms.drain_complete(0, |h| told.push(*h));
        assert_eq!(told, [7]);
        assert_eq!(rooms.drain(0x100000001, 90), Some(true));
        assert_eq!(rooms.drain_target(u64::MAX), None);
        // Another drain at the same byte position cannot be polled by old key.
        assert_eq!(rooms.drain_begin(0x100000001, 91, 0), Some(false));
        assert_eq!(rooms.drain(0x100000001, 90), None);
        assert!(!rooms.drain_release(0x100000001, 90));
        assert!(rooms.drain_release(0x100000001, 91));
        assert_eq!(rooms.room(0x100000001, None, false), Armed::Armed);
    }

    #[test]
    fn released_drain_replays_a_lost_reply_without_touching_new_observers() {
        let mut rooms = Rooms::new();
        let old = 0x100000007;
        let new = 0x200000007;
        let other = 0x300000007;
        rooms.room(1, Some(11), true);
        rooms.room(2, Some(22), true);
        assert_eq!(rooms.drain_begin(1, old, 3), Some(false));
        assert_eq!(rooms.drain_begin(2, other, 10), Some(false));
        rooms.drain_complete(3, |_| {});
        // The backend accepted RELEASE, but its first short reply was lost.
        assert!(rooms.drain_release(1, old));
        assert!(rooms.drain_release(1, old));
        assert_eq!(rooms.drain_begin(1, old, 100), None);
        assert_eq!(rooms.drain_begin(1, new, 7), Some(false));
        // A delayed replay cannot release a different full-generation key.
        assert!(rooms.drain_release(1, old));
        assert_eq!(rooms.drain(1, new), Some(false));
        assert_eq!(rooms.drain_target(3), Some(7));
        assert_eq!(rooms.drain(2, other), Some(false));
        assert!(!rooms.drain_release(2, old));
        assert!(!rooms.drain_release(1, other));
        assert!(!rooms.drain_release(1, 0));
        assert_eq!(rooms.drain_begin(1, old, 100), None);
        assert!(rooms.drain_release(1, new));
        assert!(rooms.drain_release(1, new));
        assert!(!rooms.drain_release(1, old));
        rooms.gone(1);
        rooms.room(1, Some(33), true);
        assert!(!rooms.drain_release(1, new));
        assert_eq!(rooms.drain_begin(1, new, 11), Some(false));
    }

    #[test]
    fn drain_frontiers_cross_wrap_and_discard_only_captured_queued_bytes() {
        let mut rooms = Rooms::new();
        rooms.room(1, Some(11), true);
        rooms.room(2, Some(12), true);
        let submitted = u64::MAX - 3;
        rooms.drain_begin(1, 101, submitted.wrapping_add(6));
        rooms.drain_begin(2, 102, submitted.wrapping_add(10));
        assert_eq!(rooms.drain_target(submitted), Some(2));
        // A later accepted write is outside the first prefix.
        rooms.drain_discard(submitted, submitted.wrapping_add(6), 4);
        assert_eq!(rooms.drain_target(submitted), Some(2));
        rooms.drain_discard(submitted, submitted.wrapping_add(4), 2);
        assert_eq!(rooms.drain_target(submitted), Some(0));
        let mut told = Vec::new();
        rooms.drain_complete(0, |h| told.push(*h));
        assert_eq!(told, [11, 12]);
        rooms.drain_discard(submitted, submitted, 1);
        assert_eq!(rooms.drain(1, 101), Some(true));
        assert_eq!(rooms.drain(2, 102), Some(true));
    }

    #[test]
    fn departing_pending_writes_adjust_positions_in_fifo_order() {
        let mut output = full_but(0);
        let mut writes = Writes::new();
        assert_eq!(writes.write(&mut output, 1, b"aa", 1), Taken::Waits);
        assert_eq!(writes.write(&mut output, 2, b"bbb", 2), Taken::Waits);
        assert_eq!(writes.write(&mut output, 1, b"cccc", 3), Taken::Waits);
        assert_eq!(writes.write(&mut output, 3, b"d", 4), Taken::Waits);
        let mut removed = Vec::new();
        let mut dropped = Vec::new();
        writes.gone_before(
            1,
            u64::MAX - 1,
            |t| dropped.push(t),
            |start, len| removed.push((start, len)),
        );
        assert_eq!(dropped, [1, 3]);
        assert_eq!(removed, [(u64::MAX - 1, 2), (1, 4)]);
        assert_eq!(writes.queued_bytes(), 4);
    }

    /// What `next_byte` gives until it has nothing, 10 000 bytes at most.
    fn drain(o: &mut Output) -> Vec<u8> {
        let out: Vec<u8> = core::iter::from_fn(|| o.next_byte()).take(10_000).collect();
        assert!(out.len() < 10_000, "the output does not run dry");
        out
    }

    /// An output whose ring has room for `room` bytes.
    fn full_but(room: usize) -> Output {
        let mut o = Output::new();
        assert!(o.put(&[b'.'; TX_RING][room..]));
        o
    }

    #[test]
    fn a_write_that_fits_is_answered_at_once() {
        let mut o = Output::new();
        let mut w = Writes::new();
        assert_eq!(w.write(&mut o, 1, b"hello", 'a'), Taken::Now(5, 'a'));
        assert!(w.is_empty());
        assert_eq!(drain(&mut o), b"hello");
    }

    #[test]
    fn a_write_that_does_not_fit_waits_whole() {
        let mut o = full_but(10);
        let mut w = Writes::new();
        assert_eq!(
            w.write(&mut o, 1, b"twenty bytes of text", 'a'),
            Taken::Waits
        );
        assert_eq!(o.room(), 10);
        let mut answered = Vec::new();
        w.flush(&mut o, |t, n| answered.push((t, n)));
        assert!(answered.is_empty());
        assert_eq!(drain(&mut o).len(), TX_RING - 10);
        w.flush(&mut o, |t, n| answered.push((t, n)));
        assert_eq!(answered, [('a', 20)]);
        assert_eq!(drain(&mut o), b"twenty bytes of text");
        assert!(w.is_empty());
    }

    #[test]
    fn waiting_writes_go_in_their_order() {
        let mut o = full_but(0);
        let mut w = Writes::new();
        assert_eq!(w.write(&mut o, 1, b"first ", 'a'), Taken::Waits);
        assert_eq!(w.write(&mut o, 2, b"second ", 'b'), Taken::Waits);
        drain(&mut o);
        // A write that fits waits behind those that wait.
        assert_eq!(w.write(&mut o, 3, b"third", 'c'), Taken::Waits);
        let mut answered = Vec::new();
        w.flush(&mut o, |t, _| answered.push(t));
        assert_eq!(answered, ['a', 'b', 'c']);
        assert_eq!(drain(&mut o), b"first second third");
    }

    /// WRITE_SOME takes what fits and never waits; it takes nothing while
    /// a write waits, which keeps the order of the bytes.
    #[test]
    fn write_some_takes_the_part_that_fits() {
        let mut o = full_but(10);
        let mut w: Writes<char> = Writes::new();
        assert_eq!(w.write_some(&mut o, b"twenty bytes of text"), 10);
        assert_eq!(o.room(), 0);
        assert_eq!(w.write_some(&mut o, b"more"), 0);
        assert_eq!(w.write(&mut o, 1, b"waits", 'b'), Taken::Waits);
        drain(&mut o);
        assert_eq!(
            w.write_some(&mut o, b"late"),
            0,
            "behind the write that waits"
        );
        assert!(!w.roomy(&o));
        w.flush(&mut o, |_, _| {});
        assert!(w.roomy(&o));
        assert_eq!(w.write_some(&mut o, b"late"), 4);
        assert_eq!(&drain(&mut o)[..], b"waitslate");
        // Its bytes go out as they are: the terminal made them.
        assert_eq!(w.write_some(&mut o, b"\nbare\n"), 6);
        assert_eq!(&drain(&mut o)[..], b"\nbare\n");
    }

    /// ROOM arms below the mark and tells once; a client keeps its first
    /// handle; ROOMS clients at most.
    #[test]
    fn room_arms_and_tells_once() {
        let mut r: Rooms<u32> = Rooms::new();
        assert_eq!(r.room(1, None, true), Armed::Now);
        assert_eq!(r.room(1, None, false), Armed::Refused, "no handle to tell");
        assert_eq!(r.room(1, Some(10), false), Armed::Armed);
        let mut told = Vec::new();
        r.to_tell(false, |h| told.push(*h));
        assert!(told.is_empty());
        r.to_tell(true, |h| told.push(*h));
        r.to_tell(true, |h| told.push(*h));
        assert_eq!(told, [10]);
        assert_eq!(r.room(1, None, false), Armed::Armed, "the handle stays");
        for label in 2..=ROOMS as u64 {
            assert_eq!(r.room(label, Some(label as u32), true), Armed::Now);
        }
        assert_eq!(r.room(99, Some(99), false), Armed::Refused);
        r.gone(2);
        assert_eq!(r.room(99, Some(99), false), Armed::Armed);
    }

    #[test]
    fn the_fifth_waiting_write_gets_limit_reached() {
        let mut o = full_but(0);
        let mut w = Writes::new();
        for (label, t) in [(1, 'a'), (2, 'b'), (2, 'c'), (3, 'd')] {
            assert_eq!(w.write(&mut o, label, b"x", t), Taken::Waits);
        }
        assert_eq!(w.write(&mut o, 4, b"y", 'e'), Taken::Full('e'));
        let mut dropped = Vec::new();
        w.gone(2, |t| dropped.push(t));
        assert_eq!(dropped, ['b', 'c']);
        assert_eq!(w.write(&mut o, 4, b"y", 'e'), Taken::Waits);
        drain(&mut o);
        let mut answered = Vec::new();
        w.flush(&mut o, |t, _| answered.push(t));
        assert_eq!(answered, ['a', 'd', 'e']);
    }
}
