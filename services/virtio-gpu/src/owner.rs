// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Who owns the screen (spec 3, 3.5): the machine of the owner, apart from
//! the device and the calls. The screen is free, owned by one session
//! (named by its label), or on its way back to free: the scanout goes off,
//! then the buffer is cleared in portions, so that the next owner does not
//! read the last one's points. The service moves it with its events (OPEN,
//! CLOSE, the end of the owner's session, the device's answer, a portion's
//! turn) and does what the machine says.

/// The tag of the labels this service gives owners: bit 62. The labels
/// init gives `Display` sessions are small, and those of CLONE carry bit 63.
pub const TAG: u64 = 1 << 62;

/// The bytes of the buffer's object, which a return to free clears.
pub const BUFFER_BYTES: u32 = proto_gpu::BUFFER_BYTES;
/// The bytes of one portion of clearing, one step of the service: 16 KiB,
/// 64 steps for the object. The step stays under 0.8 of term B (xtask).
pub const PORTION: u32 = 16 * 1024;

/// Whether `label` is an owner's (a label this service gave).
pub const fn is_owner_label(label: u64) -> bool {
    label & TAG != 0 && label & (1 << 63) == 0
}

/// Why OPEN is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Someone owns the screen.
    Busy,
    /// The screen is on its way back; ask again.
    Clearing,
}

/// The way back, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Way {
    /// The scanout is to go off: not asked of the device yet, or asked
    /// (`asked`) and waiting for its answer.
    Scanout { asked: bool },
    /// The buffer is cleared up to `done`.
    Clear { done: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Free,
    Owned(u64),
    Returning(Way),
}

/// One portion of clearing: where it starts, how long it is, and whether
/// it is the last, after which the screen is free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Portion {
    pub offset: u32,
    pub len: u32,
    pub last: bool,
}

/// The owner of the screen.
#[derive(Debug)]
pub struct Owner {
    state: State,
    /// The owners given so far, for the next label.
    given: u64,
}

impl Default for Owner {
    fn default() -> Owner {
        Owner::new()
    }
}

impl Owner {
    pub const fn new() -> Owner {
        Owner {
            state: State::Free,
            given: 0,
        }
    }

    /// OPEN: the screen goes to a new owner, whose label is returned; a
    /// label is never given twice. Busy while owned, Clearing while it
    /// returns.
    pub fn open(&mut self) -> Result<u64, Refusal> {
        match self.state {
            State::Free => {
                self.given += 1;
                let label = TAG | self.given;
                self.state = State::Owned(label);
                Ok(label)
            }
            State::Owned(_) => Err(Refusal::Busy),
            State::Returning(_) => Err(Refusal::Clearing),
        }
    }

    /// Whether `label` owns the screen now.
    pub fn owns(&self, label: u64) -> bool {
        self.state == State::Owned(label)
    }

    /// The owner's label, if there is one.
    pub fn owner(&self) -> Option<u64> {
        match self.state {
            State::Owned(label) => Some(label),
            _ => None,
        }
    }

    /// Whether the screen is free to give.
    pub fn is_free(&self) -> bool {
        self.state == State::Free
    }

    /// Whether the screen is on its way back.
    pub fn is_returning(&self) -> bool {
        matches!(self.state, State::Returning(_))
    }

    /// CLOSE, or the end of the owner's session (its last copy closed):
    /// the screen starts back. False when `label` does not own it, which
    /// changes nothing (a second close, a session of an earlier owner).
    pub fn release(&mut self, label: u64) -> bool {
        if !self.owns(label) {
            return false;
        }
        self.state = State::Returning(Way::Scanout { asked: false });
        true
    }

    /// Whether the service is to ask the device to take the scanout off now;
    /// true once for each way back, and the machine then waits for
    /// `scanout_off`.
    pub fn wants_scanout_off(&mut self) -> bool {
        match self.state {
            State::Returning(Way::Scanout { asked: false }) => {
                self.state = State::Returning(Way::Scanout { asked: true });
                true
            }
            _ => false,
        }
    }

    /// The device answered the command that took the scanout off, well or
    /// not: the buffer is cleared next. False when no such command was
    /// asked.
    pub fn scanout_off(&mut self) -> bool {
        match self.state {
            State::Returning(Way::Scanout { asked: true }) => {
                self.state = State::Returning(Way::Clear { done: 0 });
                true
            }
            _ => false,
        }
    }

    /// Whether a portion of clearing is due.
    pub fn clearing(&self) -> bool {
        matches!(self.state, State::Returning(Way::Clear { .. }))
    }

    /// The next portion to clear, and the machine takes it as done: the
    /// service clears it at once. The last one frees the screen. None when
    /// the machine is not at the clearing.
    pub fn portion(&mut self) -> Option<Portion> {
        let State::Returning(Way::Clear { done }) = self.state else {
            return None;
        };
        let len = PORTION.min(BUFFER_BYTES - done);
        let end = done + len;
        let last = end == BUFFER_BYTES;
        self.state = if last {
            State::Free
        } else {
            State::Returning(Way::Clear { done: end })
        };
        Some(Portion {
            offset: done,
            len,
            last,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Takes the machine from the start of a way back to free, counting
    /// the portions.
    fn finish(o: &mut Owner) -> u32 {
        assert!(o.wants_scanout_off());
        assert!(o.scanout_off());
        let mut portions = 0;
        let mut at = 0;
        while let Some(p) = o.portion() {
            assert_eq!(p.offset, at);
            assert!(p.len <= PORTION);
            at += p.len;
            portions += 1;
            assert_eq!(p.last, at == BUFFER_BYTES);
        }
        assert_eq!(at, BUFFER_BYTES);
        portions
    }

    #[test]
    fn a_free_screen_opens_to_one_owner() {
        let mut o = Owner::new();
        assert!(o.is_free());
        let label = o.open().expect("a free screen");
        assert!(is_owner_label(label));
        assert!(o.owns(label));
        assert_eq!(o.owner(), Some(label));
        assert!(!o.is_free());
        assert_eq!(o.open(), Err(Refusal::Busy));
    }

    #[test]
    fn labels_are_never_given_twice_and_carry_the_tag() {
        let mut o = Owner::new();
        let mut seen = Vec::new();
        for _ in 0..5 {
            let label = o.open().expect("open");
            assert!(!seen.contains(&label));
            assert!(is_owner_label(label));
            seen.push(label);
            assert!(o.release(label));
            finish(&mut o);
        }
        // Not a label of init or of a clone.
        assert!(!is_owner_label(1));
        assert!(!is_owner_label((1 << 63) | 5));
        assert!(!is_owner_label((1 << 63) | TAG | 5));
    }

    #[test]
    fn only_the_owner_releases() {
        let mut o = Owner::new();
        let label = o.open().expect("open");
        assert!(!o.release(label + 1));
        assert!(o.owns(label));
        assert!(!o.release(0));
        assert!(o.release(label));
        // A second close of the same session changes nothing.
        assert!(!o.release(label));
        assert!(o.is_returning());
    }

    #[test]
    fn a_screen_on_its_way_back_says_clearing() {
        let mut o = Owner::new();
        let label = o.open().expect("open");
        o.release(label);
        assert_eq!(o.open(), Err(Refusal::Clearing));
        assert!(o.wants_scanout_off());
        assert_eq!(o.open(), Err(Refusal::Clearing));
        assert!(o.scanout_off());
        assert_eq!(o.open(), Err(Refusal::Clearing));
        assert!(o.portion().is_some());
        assert_eq!(o.open(), Err(Refusal::Clearing));
    }

    #[test]
    fn the_way_back_has_its_steps_in_order() {
        let mut o = Owner::new();
        let label = o.open().expect("open");
        // Nothing to do while owned.
        assert!(!o.wants_scanout_off() && !o.scanout_off() && o.portion().is_none());
        o.release(label);
        // Clearing waits for the scanout, which is asked once.
        assert!(o.portion().is_none());
        assert!(!o.scanout_off());
        assert!(o.wants_scanout_off());
        assert!(!o.wants_scanout_off());
        assert!(o.portion().is_none());
        assert!(o.scanout_off());
        assert!(!o.scanout_off());
        assert!(o.clearing());
    }

    #[test]
    fn the_object_is_cleared_in_sixty_four_portions() {
        let mut o = Owner::new();
        let label = o.open().expect("open");
        o.release(label);
        assert_eq!(finish(&mut o), 64);
        assert!(o.is_free());
        assert!(o.portion().is_none());
    }

    #[test]
    fn a_free_screen_opens_again_with_a_new_label() {
        let mut o = Owner::new();
        let first = o.open().expect("open");
        o.release(first);
        finish(&mut o);
        let second = o.open().expect("open again");
        assert_ne!(first, second);
        assert!(!o.owns(first));
        // The first owner's session ending late changes nothing.
        assert!(!o.release(first));
        assert!(o.owns(second));
    }

    #[test]
    fn a_portion_never_passes_the_object() {
        // A portion that does not divide the object ends at its end.
        assert_eq!(BUFFER_BYTES % PORTION, 0);
        let mut o = Owner::new();
        let label = o.open().expect("open");
        o.release(label);
        o.wants_scanout_off();
        o.scanout_off();
        let mut last = None;
        while let Some(p) = o.portion() {
            assert!(p.offset + p.len <= BUFFER_BYTES);
            last = Some(p);
        }
        let last = last.expect("portions");
        assert!(last.last);
        assert_eq!(last.offset + last.len, BUFFER_BYTES);
    }
}
