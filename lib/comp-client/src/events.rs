// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The events of a window as `struct stafeto_window_event` has them: the 16
//! bytes of `proto_comp::Event`, kind and code (u16), value, x and y (i32),
//! low byte first, which is also the order of the C structure on AArch64.

use crate::layout::{EVENTS_LOST, EVENTS_MAX, WindowEvent};
use proto_comp::{EVENT_LEN, Event};

/// The events one EVENTS call brought that the caller had no room for. The
/// service gave them up with the call, so they wait here for the next call
/// of the program; the lost flag waits with them.
#[derive(Clone, Copy, Debug)]
pub struct Stash {
    events: [WindowEvent; EVENTS_MAX],
    head: usize,
    len: usize,
    lost: bool,
}

impl Stash {
    pub const fn new() -> Stash {
        Stash {
            events: [WindowEvent {
                kind: 0,
                code: 0,
                value: 0,
                x: 0,
                y: 0,
            }; EVENTS_MAX],
            head: 0,
            len: 0,
            lost: false,
        }
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The events of a reply (the stash is empty, and the service gives at
    /// most `EVENTS_MAX`; more are cut) and its LOST flag.
    pub fn fill(&mut self, events: &[WindowEvent], lost: bool) {
        let n = events.len().min(EVENTS_MAX);
        self.events[..n].copy_from_slice(&events[..n]);
        self.head = 0;
        self.len = n;
        self.lost = lost;
    }

    /// Up to `out.len()` events into `out`, the oldest first: how many, and
    /// the flags (`EVENTS_LOST` once, with the first events after the loss).
    pub fn take(&mut self, out: &mut [WindowEvent]) -> (usize, u32) {
        let n = out.len().min(self.len);
        out[..n].copy_from_slice(&self.events[self.head..self.head + n]);
        self.head += n;
        self.len -= n;
        let flags = if self.lost && (n > 0 || self.len == 0) {
            self.lost = false;
            EVENTS_LOST
        } else {
            0
        };
        (n, flags)
    }
}

impl Default for Stash {
    fn default() -> Stash {
        Stash::new()
    }
}

impl From<Event> for WindowEvent {
    fn from(e: Event) -> WindowEvent {
        WindowEvent {
            kind: e.kind,
            code: e.code,
            value: e.value,
            x: e.x,
            y: e.y,
        }
    }
}

impl From<WindowEvent> for Event {
    fn from(e: WindowEvent) -> Event {
        Event::at(e.kind, e.code, e.value, e.x, e.y)
    }
}

impl WindowEvent {
    /// The 16 bytes of the wire.
    pub const fn to_bytes(self) -> [u8; EVENT_LEN] {
        Event {
            kind: self.kind,
            code: self.code,
            value: self.value,
            x: self.x,
            y: self.y,
        }
        .to_bytes()
    }

    pub const fn from_bytes(b: [u8; EVENT_LEN]) -> WindowEvent {
        let e = Event::from_bytes(b);
        WindowEvent {
            kind: e.kind,
            code: e.code,
            value: e.value,
            x: e.x,
            y: e.y,
        }
    }
}

/// The events of a window as a program takes them. The service's ring holds
/// 64 events and one EVENTS call gives at most `EVENTS_MAX` of them, and it
/// sends its bit only for new events, so a program that stops at what one
/// call gave would strand the rest. `take` asks the service again while the
/// last reply was full and the caller has room, so a call returns fewer
/// than `out.len()` only when the ring is empty. What a reply held beyond
/// the caller's room waits in the stash.
#[derive(Clone, Copy, Debug)]
pub struct Taker {
    stash: Stash,
    /// The last reply of the service held `EVENTS_MAX` events: more may wait.
    last_full: bool,
}

impl Taker {
    pub const fn new() -> Taker {
        Taker {
            stash: Stash::new(),
            last_full: false,
        }
    }

    /// Up to `out.len()` events: how many and the flags. `ask` is one EVENTS
    /// call: it fills the array and gives the count and whether the ring
    /// lost events. An error of `ask` after some events were taken ends the
    /// call with what it has.
    pub fn take<E>(
        &mut self,
        out: &mut [WindowEvent],
        mut ask: impl FnMut(&mut [WindowEvent; EVENTS_MAX]) -> Result<(usize, bool), E>,
    ) -> Result<(usize, u32), E> {
        let mut done = 0;
        let mut flags = 0;
        loop {
            if self.stash.is_empty() {
                let mut list = [WindowEvent::default(); EVENTS_MAX];
                match ask(&mut list) {
                    Ok((n, lost)) => {
                        let n = n.min(EVENTS_MAX);
                        self.stash.fill(&list[..n], lost);
                        self.last_full = n == EVENTS_MAX;
                    }
                    Err(_) if done > 0 => break,
                    Err(e) => return Err(e),
                }
            }
            let (n, f) = self.stash.take(&mut out[done..]);
            done += n;
            flags |= f;
            if done == out.len() || !self.stash.is_empty() || !self.last_full {
                break;
            }
        }
        Ok((done, flags))
    }

    /// Forgets what was held (a new window).
    pub fn reset(&mut self) {
        *self = Taker::new();
    }
}

impl Default for Taker {
    fn default() -> Taker {
        Taker::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: WindowEvent = WindowEvent {
        kind: 3,
        code: 0x110,
        value: -2,
        x: 123,
        y: -456,
    };

    #[test]
    fn the_wire_bytes_round_trip() {
        assert_eq!(WindowEvent::from_bytes(SAMPLE.to_bytes()), SAMPLE);
        let wire = Event::at(1, 30, 1, 0, 0).to_bytes();
        assert_eq!(WindowEvent::from_bytes(wire).to_bytes(), wire);
    }

    #[test]
    fn the_c_structure_is_the_wire_event() {
        // On a little-endian machine (every target of the system) the memory
        // of the structure is the wire's 16 bytes.
        if cfg!(target_endian = "little") {
            let raw: [u8; 16] = unsafe { core::mem::transmute(SAMPLE) };
            assert_eq!(raw, SAMPLE.to_bytes());
            let back: WindowEvent = unsafe { core::mem::transmute(raw) };
            assert_eq!(back, SAMPLE);
        }
    }

    #[test]
    fn conversion_with_the_protocol_event_keeps_every_field() {
        let e: Event = SAMPLE.into();
        assert_eq!(WindowEvent::from(e), SAMPLE);
        assert_eq!(e.to_bytes(), SAMPLE.to_bytes());
    }

    fn key(code: u16) -> WindowEvent {
        WindowEvent {
            kind: 1,
            code,
            value: 1,
            x: 0,
            y: 0,
        }
    }

    #[test]
    fn the_stash_keeps_what_the_caller_had_no_room_for() {
        let mut stash = Stash::new();
        assert!(stash.is_empty());
        let events: Vec<WindowEvent> = (1..=5).map(key).collect();
        stash.fill(&events, true);
        let mut out = [WindowEvent::default(); 2];
        assert_eq!(stash.take(&mut out), (2, EVENTS_LOST));
        assert_eq!([out[0].code, out[1].code], [1, 2]);
        assert_eq!(stash.take(&mut out), (2, 0));
        assert_eq!([out[0].code, out[1].code], [3, 4]);
        assert!(!stash.is_empty());
        assert_eq!(stash.take(&mut out), (1, 0));
        assert_eq!(out[0].code, 5);
        assert!(stash.is_empty());
        assert_eq!(stash.take(&mut out), (0, 0));
    }

    #[test]
    fn lost_with_no_events_is_still_told_once() {
        let mut stash = Stash::new();
        stash.fill(&[], true);
        let mut out = [WindowEvent::default(); 4];
        assert_eq!(stash.take(&mut out), (0, EVENTS_LOST));
        assert_eq!(stash.take(&mut out), (0, 0));
    }

    #[test]
    fn a_full_reply_of_32_fits() {
        let mut stash = Stash::new();
        let events: Vec<WindowEvent> = (0..32).map(key).collect();
        stash.fill(&events, false);
        let mut out = [WindowEvent::default(); 32];
        assert_eq!(stash.take(&mut out), (32, 0));
        assert_eq!(out[31].code, 31);
    }

    /// A ring of `n` events the way the service serves it: 32 a call.
    struct Ring {
        left: Vec<u16>,
        calls: usize,
    }

    impl Ring {
        fn new(n: u16) -> Ring {
            Ring {
                left: (1..=n).collect(),
                calls: 0,
            }
        }

        fn ask(&mut self, list: &mut [WindowEvent; EVENTS_MAX]) -> Result<(usize, bool), ()> {
            self.calls += 1;
            let n = self.left.len().min(EVENTS_MAX);
            for (slot, code) in list.iter_mut().zip(self.left.drain(..n)) {
                *slot = key(code);
            }
            Ok((n, false))
        }
    }

    #[test]
    fn max_above_the_ring_reply_takes_every_event_waiting() {
        let mut ring = Ring::new(40);
        let mut taker = Taker::new();
        let mut out = [WindowEvent::default(); 64];
        let (n, _) = taker.take(&mut out, |l| ring.ask(l)).unwrap();
        assert_eq!(n, 40);
        assert_eq!(out[39].code, 40);
        assert_eq!(ring.calls, 2);
        // A full ring of 64 is two full replies and one empty one.
        let mut ring = Ring::new(64);
        let (n, _) = taker.take(&mut out, |l| ring.ask(l)).unwrap();
        assert_eq!(n, 64);
        // Exactly 32 asks again and finds none.
        let mut ring = Ring::new(32);
        let (n, _) = taker.take(&mut out, |l| ring.ask(l)).unwrap();
        assert_eq!((n, ring.calls), (32, 2));
    }

    #[test]
    fn a_small_max_never_returns_fewer_while_the_ring_holds_more() {
        let mut ring = Ring::new(64);
        let mut taker = Taker::new();
        let mut out = [WindowEvent::default(); 10];
        let mut sizes = Vec::new();
        let mut codes = Vec::new();
        loop {
            let (n, _) = taker.take(&mut out, |l| ring.ask(l)).unwrap();
            sizes.push(n);
            codes.extend(out[..n].iter().map(|e| e.code));
            if n < out.len() {
                break;
            }
        }
        assert_eq!(sizes, [10, 10, 10, 10, 10, 10, 4]);
        assert_eq!(codes, (1..=64).collect::<Vec<u16>>());
        assert!(ring.left.is_empty());
    }

    #[test]
    fn an_error_after_some_events_keeps_them() {
        let mut taker = Taker::new();
        let mut out = [WindowEvent::default(); 64];
        let mut ring = Ring::new(32);
        let mut first = true;
        let got = taker.take(&mut out, |l| {
            if first {
                first = false;
                ring.ask(l)
            } else {
                Err(())
            }
        });
        assert_eq!(got.map(|(n, _)| n), Ok(32));
        let got = taker.take(&mut out, |_| Err::<(usize, bool), ()>(()));
        assert_eq!(got, Err(()));
    }

    #[test]
    fn lost_is_told_once_across_calls() {
        let mut taker = Taker::new();
        let mut out = [WindowEvent::default(); 64];
        let got = taker
            .take(&mut out, |l| {
                l[0] = key(1);
                Ok::<_, ()>((1, true))
            })
            .unwrap();
        assert_eq!(got, (1, EVENTS_LOST));
        let got = taker.take(&mut out, |_| Ok::<_, ()>((0, false))).unwrap();
        assert_eq!(got, (0, 0));
    }
}
