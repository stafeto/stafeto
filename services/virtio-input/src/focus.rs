// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Who holds the focus (spec 3, 3.6): at most one session, a label this
//! service gave, with the ring of the events it has not read. The device's
//! events go to it, and to no one when there is none. Apart from the
//! device and the calls, tested on the host.

use crate::ring::Ring;
use proto_input::{Event, Method};

/// The tag of the labels this service gives the focus: bit 62. The
/// labels init gives the sessions of `connects` are small.
pub const TAG: u64 = 1 << 62;

/// Whether `label` is a focus's (a label this service gave).
pub const fn is_focus_label(label: u64) -> bool {
    label & TAG != 0
}

/// Why a READ is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The session is not the focus: it never was, or it was revoked.
    Revoked,
}

/// Whether the session of `label` may call `method`: the sessions init
/// gave (the display service's) GRANT and REVOKE; the focus READs.
pub const fn allowed(label: u64, method: Method) -> bool {
    match method {
        Method::Grant | Method::Revoke => !is_focus_label(label),
        Method::Read => is_focus_label(label),
    }
}

/// The focus and its events.
#[derive(Debug)]
pub struct Focus {
    current: Option<u64>,
    /// The sessions given so far, for the next label.
    given: u64,
    ring: Ring,
    /// The events dropped for want of a focus, for the log.
    dropped: u32,
}

impl Default for Focus {
    fn default() -> Focus {
        Focus::new()
    }
}

impl Focus {
    pub const fn new() -> Focus {
        Focus {
            current: None,
            given: 0,
            ring: Ring::new(),
            dropped: 0,
        }
    }

    /// The label of the focus, when there is one.
    pub const fn holder(&self) -> Option<u64> {
        self.current
    }

    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// A new session of focus, which revokes the one before: its label,
    /// never given twice, and an empty ring.
    pub fn grant(&mut self) -> u64 {
        self.given = (self.given + 1) & (TAG - 1);
        let label = TAG | self.given;
        self.current = Some(label);
        self.ring.clear();
        label
    }

    /// Ends the focus.
    pub fn revoke(&mut self) {
        self.current = None;
        self.ring.clear();
    }

    /// The last copy of the session `label` went: it was the focus, or it
    /// was a revoked one that is none now, or it was the display service's
    /// (a label without the tag): the service ended, and the focus it
    /// granted ends with it, so that no process reads keys of a screen
    /// that has no service.
    pub fn closed(&mut self, label: u64) {
        if self.current == Some(label) || !is_focus_label(label) {
            self.revoke();
        }
    }

    /// An event of the device: into the ring when it passes and someone
    /// has the focus; counted as dropped when no one has.
    pub fn event(&mut self, event: Event) {
        if !event.passes() {
            return;
        }
        if self.current.is_some() {
            self.ring.push(event);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// READ by the session `label`: up to `out.len()` events and whether
    /// LOST is set; Revoked unless `label` is the focus.
    pub fn read(&mut self, label: u64, out: &mut [Event]) -> Result<(usize, bool), Refusal> {
        if self.current != Some(label) {
            return Err(Refusal::Revoked);
        }
        Ok(self.ring.take(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_input::RING;

    #[test]
    fn only_the_display_service_grants_and_only_the_focus_reads() {
        let init_given = 5;
        let focus = TAG | 1;
        for m in [Method::Grant, Method::Revoke] {
            assert!(allowed(init_given, m));
            assert!(!allowed(focus, m));
        }
        assert!(allowed(focus, Method::Read));
        assert!(!allowed(init_given, Method::Read));
        assert!(!allowed(0, Method::Read));
    }

    #[test]
    fn events_without_a_focus_are_dropped_and_counted() {
        let mut f = Focus::new();
        f.event(Event::key(48, true));
        f.event(Event::key(48, false));
        assert_eq!(f.dropped(), 2);
        let label = f.grant();
        let mut out = [Event::default(); 4];
        assert_eq!(f.read(label, &mut out), Ok((0, false)));
    }

    #[test]
    fn a_press_and_a_release_reach_the_focus() {
        let mut f = Focus::new();
        let label = f.grant();
        f.event(Event::key(30, true));
        f.event(Event::key(30, false));
        let mut out = [Event::default(); 4];
        assert_eq!(f.read(label, &mut out), Ok((2, false)));
        assert_eq!(out[0], Event::key(30, true));
        assert_eq!(out[1], Event::key(30, false));
    }

    #[test]
    fn repeats_and_other_types_never_reach_the_ring() {
        let mut f = Focus::new();
        let label = f.grant();
        f.event(Event {
            kind: 1,
            code: 30,
            value: 2,
        });
        f.event(Event {
            kind: 0,
            code: 0,
            value: 0,
        });
        f.event(Event::key(31, true));
        let mut out = [Event::default(); 4];
        assert_eq!(f.read(label, &mut out), Ok((1, false)));
        assert_eq!(out[0].code, 31);
        // Not counted as dropped for want of a focus: there was one.
        assert_eq!(f.dropped(), 0);
    }

    #[test]
    fn eighty_events_leave_64_and_lost() {
        let mut f = Focus::new();
        let label = f.grant();
        for i in 0..80u16 {
            f.event(Event::key(i, true));
        }
        let mut out = [Event::default(); 120];
        assert_eq!(f.read(label, &mut out), Ok((RING, true)));
        assert_eq!(out[0].code, 16);
    }

    #[test]
    fn a_new_grant_revokes_the_old_session_and_starts_empty() {
        let mut f = Focus::new();
        let old = f.grant();
        f.event(Event::key(1, true));
        let new = f.grant();
        assert_ne!(old, new);
        assert!(is_focus_label(new));
        let mut out = [Event::default(); 4];
        assert_eq!(f.read(old, &mut out), Err(Refusal::Revoked));
        assert_eq!(f.read(new, &mut out), Ok((0, false)));
        f.event(Event::key(2, true));
        assert_eq!(f.read(new, &mut out), Ok((1, false)));
        assert_eq!(f.read(old, &mut out), Err(Refusal::Revoked));
    }

    #[test]
    fn revoke_ends_the_focus_and_the_events_after_it_go_nowhere() {
        let mut f = Focus::new();
        let label = f.grant();
        f.event(Event::key(1, true));
        f.revoke();
        let mut out = [Event::default(); 4];
        assert_eq!(f.read(label, &mut out), Err(Refusal::Revoked));
        f.event(Event::key(2, true));
        assert_eq!(f.dropped(), 1);
        assert_eq!(f.holder(), None);
        // A revoke with no focus is harmless.
        f.revoke();
    }

    #[test]
    fn the_end_of_the_holder_ends_the_focus_and_another_s_does_not() {
        let mut f = Focus::new();
        let old = f.grant();
        let new = f.grant();
        f.closed(old);
        assert_eq!(f.holder(), Some(new));
        f.closed(new);
        assert_eq!(f.holder(), None);
    }

    #[test]
    fn the_end_of_the_display_service_ends_the_focus() {
        let mut f = Focus::new();
        let label = f.grant();
        f.event(Event::key(1, true));
        // A session init gave: the label has no tag.
        f.closed(5);
        assert_eq!(f.holder(), None);
        let mut out = [Event::default(); 4];
        assert_eq!(f.read(label, &mut out), Err(Refusal::Revoked));
    }

    #[test]
    fn a_label_is_never_given_twice() {
        let mut f = Focus::new();
        let mut seen = Vec::new();
        for _ in 0..1000 {
            let l = f.grant();
            assert!(!seen.contains(&l));
            seen.push(l);
        }
        assert!(seen.iter().all(|l| is_focus_label(*l) && *l != TAG));
    }
}
