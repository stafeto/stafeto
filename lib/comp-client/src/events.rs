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
}
