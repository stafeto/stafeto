// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The passes of EXPORT: a description handed to another process as a copy
//! of the service's channel with a label of its own (`proto_net::sockets::PASS`
//! tag, the generation of the pass and its index). The pass holds a
//! reference of the place until a session adopts it (ADOPT) or the last copy
//! of the handle goes (CLIENT_GONE of the label). The table is short: the
//! kernel charges each label to the service's quota, so the service gives no
//! more than `PASSES_MAX` at once and `SESSION_PASSES` for one session.

use proto_net::sockets::{PASS, PASSES_MAX, SESSION_PASSES};

/// The bits of a label that must be zero between the tag and the index and
/// generation: bit 63 is the tag of the clones of the service itself.
const FIXED: u64 = 0xFFFF_0000_0000_0000;
/// The bits 16 to 47 of a label are the generation, the low 16 the index.
const GENERATION_SHIFT: u32 = 16;

/// Why no pass was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The table holds `PASSES_MAX`.
    Full,
    /// The session holds `SESSION_PASSES`.
    Session,
}

#[derive(Clone, Copy)]
struct Entry {
    used: bool,
    place: u16,
    generation: u32,
    /// The label of the session that made the pass.
    owner: u64,
}

const EMPTY: Entry = Entry {
    used: false,
    place: 0,
    generation: 0,
    owner: 0,
};

/// The table of passes.
pub struct Passes {
    entries: [Entry; PASSES_MAX],
    generation: u32,
}

impl Default for Passes {
    fn default() -> Self {
        Self::new()
    }
}

impl Passes {
    pub const fn new() -> Self {
        Passes {
            entries: [EMPTY; PASSES_MAX],
            generation: 0,
        }
    }

    /// The passes in use.
    pub fn count(&self) -> usize {
        self.entries.iter().filter(|e| e.used).count()
    }

    /// A pass of `place` for the session `owner`: its label.
    pub fn make(&mut self, place: usize, owner: u64) -> Result<u64, Refused> {
        let mut free = None;
        let mut mine = 0;
        for (i, e) in self.entries.iter().enumerate() {
            if !e.used {
                free.get_or_insert(i);
            } else if e.owner == owner {
                mine += 1;
            }
        }
        if mine >= SESSION_PASSES {
            return Err(Refused::Session);
        }
        let i = free.ok_or(Refused::Full)?;
        self.generation = match self.generation.wrapping_add(1) {
            0 => 1,
            g => g,
        };
        self.entries[i] = Entry {
            used: true,
            place: place as u16,
            generation: self.generation,
            owner,
        };
        Ok(PASS | u64::from(self.generation) << GENERATION_SHIFT | i as u64)
    }

    /// Whether `label` has the shape of a pass.
    pub fn is_pass(label: u64) -> bool {
        label & FIXED == PASS
    }

    /// The pass `label` names, when it is in use with that generation:
    /// its place. The pass is not changed.
    pub fn place_of(&self, label: u64) -> Option<usize> {
        if !Self::is_pass(label) {
            return None;
        }
        let e = self.entries.get((label & 0xFFFF) as usize)?;
        let generation = (label >> GENERATION_SHIFT) as u32;
        (e.used && e.generation == generation).then_some(usize::from(e.place))
    }

    /// Ends the pass `label` names: its place, which the caller lets go of
    /// or gives to a session. None for a label that names no pass in use.
    pub fn end(&mut self, label: u64) -> Option<usize> {
        let place = self.place_of(label)?;
        self.entries[(label & 0xFFFF) as usize] = EMPTY;
        Some(place)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tag of the labels of the service's own clones.
    const OWN_TAG: u64 = 1 << 63;

    #[test]
    fn a_pass_names_its_place_until_it_ends() {
        let mut p = Passes::new();
        let label = p.make(7, 100).unwrap();
        assert!(Passes::is_pass(label));
        assert_eq!(p.place_of(label), Some(7));
        assert_eq!(p.end(label), Some(7));
        assert_eq!(p.end(label), None);
        assert_eq!(p.place_of(label), None);
    }

    #[test]
    fn a_label_of_an_ended_pass_names_nothing_when_its_index_is_used_again() {
        let mut p = Passes::new();
        let old = p.make(1, 100).unwrap();
        p.end(old).unwrap();
        let new = p.make(2, 100).unwrap();
        assert_eq!(old & 0xFFFF, new & 0xFFFF);
        assert_ne!(old, new);
        assert_eq!(p.place_of(old), None);
        assert_eq!(p.end(old), None);
        assert_eq!(p.place_of(new), Some(2));
    }

    #[test]
    fn the_labels_of_sessions_and_clones_are_no_passes() {
        let p = Passes::new();
        assert!(!Passes::is_pass(5));
        assert!(!Passes::is_pass(OWN_TAG | 3));
        assert!(!Passes::is_pass(PASS | OWN_TAG));
        assert_eq!(p.place_of(PASS), None);
        assert_eq!(p.place_of(PASS | 70_000), None);
    }

    #[test]
    fn a_session_holds_sixteen_passes_and_the_table_sixty_four() {
        let mut p = Passes::new();
        for k in 0..SESSION_PASSES {
            p.make(k, 1).unwrap();
        }
        assert_eq!(p.make(0, 1), Err(Refused::Session));
        for owner in 2..5 {
            for k in 0..SESSION_PASSES {
                if p.count() == PASSES_MAX {
                    assert_eq!(p.make(k, owner), Err(Refused::Full));
                } else {
                    p.make(k, owner).unwrap();
                }
            }
        }
        assert_eq!(p.count(), PASSES_MAX);
        assert_eq!(p.make(0, 9), Err(Refused::Full));
    }

    #[test]
    fn a_session_that_ended_its_pass_may_make_another() {
        let mut p = Passes::new();
        let first = p.make(0, 1).unwrap();
        for k in 1..SESSION_PASSES {
            p.make(k, 1).unwrap();
        }
        assert!(p.make(0, 1).is_err());
        p.end(first).unwrap();
        assert!(p.make(0, 1).is_ok());
    }
}
