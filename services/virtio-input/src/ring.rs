// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The events of the focus (spec 3, 3.6): a ring of RING events. When it
//! is full the oldest goes and the ring remembers that something was lost,
//! which the next read reports once. Apart from the device and the calls,
//! tested on the host.

use proto_input::{Event, RING};

/// The ring: the events from `head`, `len` of them, and whether any went.
#[derive(Debug)]
pub struct Ring {
    events: [Event; RING],
    head: usize,
    len: usize,
    lost: bool,
}

impl Default for Ring {
    fn default() -> Ring {
        Ring::new()
    }
}

impl Ring {
    pub const fn new() -> Ring {
        Ring {
            events: [Event {
                kind: 0,
                code: 0,
                value: 0,
            }; RING],
            head: 0,
            len: 0,
            lost: false,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the next read carries LOST.
    pub const fn lost(&self) -> bool {
        self.lost
    }

    /// Appends `event`; a full ring drops its oldest first and sets LOST.
    pub fn push(&mut self, event: Event) {
        if self.len == RING {
            self.head = (self.head + 1) % RING;
            self.len -= 1;
            self.lost = true;
        }
        self.events[(self.head + self.len) % RING] = event;
        self.len += 1;
    }

    /// Takes up to `out.len()` of the oldest events into `out`; the count
    /// and whether LOST was set, which the call clears.
    pub fn take(&mut self, out: &mut [Event]) -> (usize, bool) {
        let n = out.len().min(self.len);
        for slot in out.iter_mut().take(n) {
            *slot = self.events[self.head];
            self.head = (self.head + 1) % RING;
        }
        self.len -= n;
        (n, core::mem::take(&mut self.lost))
    }

    /// Forgets everything: a new focus starts with no events and no LOST.
    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
        self.lost = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: u16) -> Event {
        Event::key(code, true)
    }

    #[test]
    fn events_come_out_in_order() {
        let mut ring = Ring::new();
        for c in 1..=5 {
            ring.push(press(c));
        }
        let mut out = [Event::default(); 3];
        assert_eq!(ring.take(&mut out), (3, false));
        assert_eq!(out.map(|e| e.code), [1, 2, 3]);
        assert_eq!(ring.len(), 2);
        let mut out = [Event::default(); 8];
        assert_eq!(ring.take(&mut out), (2, false));
        assert_eq!(out[..2].iter().map(|e| e.code).collect::<Vec<_>>(), [4, 5]);
        assert!(ring.is_empty());
        assert_eq!(ring.take(&mut out), (0, false));
    }

    #[test]
    fn a_full_ring_holds_64_and_loses_nothing_until_the_65th() {
        let mut ring = Ring::new();
        for c in 0..RING as u16 {
            ring.push(press(c));
        }
        assert_eq!(ring.len(), RING);
        assert!(!ring.lost());
        ring.push(press(1000));
        assert_eq!(ring.len(), RING);
        assert!(ring.lost());
    }

    #[test]
    fn the_oldest_goes_and_lost_comes_once() {
        let mut ring = Ring::new();
        for c in 0..80u16 {
            ring.push(press(c));
        }
        let mut out = [Event::default(); RING];
        assert_eq!(ring.take(&mut out), (RING, true));
        // 80 pressed, the first 16 dropped.
        assert_eq!(out[0].code, 16);
        assert_eq!(out[RING - 1].code, 79);
        ring.push(press(7));
        let mut out = [Event::default(); 1];
        assert_eq!(ring.take(&mut out), (1, false));
    }

    #[test]
    fn lost_waits_for_a_read_even_when_the_read_is_short() {
        let mut ring = Ring::new();
        for c in 0..70u16 {
            ring.push(press(c));
        }
        let mut one = [Event::default(); 1];
        assert_eq!(ring.take(&mut one), (1, true));
        assert_eq!(ring.take(&mut one), (1, false));
    }

    #[test]
    fn the_ring_wraps_around() {
        let mut ring = Ring::new();
        let mut out = [Event::default(); 1];
        // Three in flight, 200 rounds: the head passes the end of the
        // array more than once, in order and with nothing lost.
        for c in 0..3u16 {
            ring.push(press(c));
        }
        for round in 0..200u16 {
            ring.push(press(round + 3));
            assert_eq!(ring.take(&mut out), (1, false));
            assert_eq!(out[0].code, round);
        }
        assert_eq!(ring.len(), 3);
    }

    #[test]
    fn clear_forgets_the_events_and_the_loss() {
        let mut ring = Ring::new();
        for c in 0..100u16 {
            ring.push(press(c));
        }
        ring.clear();
        assert!(ring.is_empty() && !ring.lost());
        let mut out = [Event::default(); 4];
        assert_eq!(ring.take(&mut out), (0, false));
        ring.push(press(9));
        assert_eq!(ring.take(&mut out), (1, false));
        assert_eq!(out[0].code, 9);
    }

    #[test]
    fn a_take_of_no_room_still_reports_the_loss() {
        let mut ring = Ring::new();
        for c in 0..70u16 {
            ring.push(press(c));
        }
        assert_eq!(ring.take(&mut []), (0, true));
    }
}
