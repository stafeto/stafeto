// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The clones that sent nothing yet (the births of CLONE) and the rules of
//! CLONE_MORE, which adds descriptions to one: only the session that made
//! the birth may add to it, by the word CLONE answered with; a description
//! the birth holds is passed over; no birth holds more than a session may.

use crate::places::Held;
use proto_net::sockets::birth_word;

/// A clone that sent nothing yet: its label, its descriptions, its root and
/// the label of the session that made it.
pub type Birth = (u64, Held, u64, u64);

/// Why CLONE_MORE is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No such birth, one that is claimed already, one of another
    /// generation, or one that another session made.
    NoBirth,
    /// The birth would hold more descriptions than a session may.
    Full,
}

/// The birth `word` names in `births` (the place is the low 16 bits), when
/// it is live, is the same generation, and was made by `caller`.
pub fn permitted(
    births: &[Option<Birth>],
    word: u32,
    caller: u64,
) -> Result<(usize, Birth), Refusal> {
    let place = (word & 0xFFFF) as usize;
    match births.get(place) {
        Some(Some(birth)) if birth_word(place, birth.0 >> 16) == word && birth.3 == caller => {
            Ok((place, *birth))
        }
        _ => Err(Refusal::NoBirth),
    }
}

/// Whether `held` plus the places of `added` that it does not hold stays
/// within `limit` descriptions.
pub fn fits(held: &Held, added: &Held, limit: usize) -> Result<(), Refusal> {
    let mut count = held.count();
    let mut at = 0;
    while let Some(p) = added.next(at) {
        at = p + 1;
        if !held.has(p) {
            count += 1;
        }
    }
    if count > limit {
        Err(Refusal::Full)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CALLER: u64 = (1 << 63) | 0x40;

    fn birth(place: usize, generation: u64, parent: u64) -> Birth {
        let label = (1 << 63) | generation << 16 | place as u64;
        (label, Held::EMPTY, 0x40, parent)
    }

    #[test]
    fn a_birth_of_another_session_is_refused() {
        let mut births = [None; 4];
        births[2] = Some(birth(2, 5, CALLER));
        let word = birth_word(2, 5);
        assert!(permitted(&births, word, CALLER).is_ok());
        assert_eq!(permitted(&births, word, CALLER + 1), Err(Refusal::NoBirth));
    }

    #[test]
    fn a_birth_that_is_gone_or_of_another_generation_is_refused() {
        let mut births = [None; 4];
        births[1] = Some(birth(1, 9, CALLER));
        assert_eq!(
            permitted(&births, birth_word(1, 8), CALLER),
            Err(Refusal::NoBirth)
        );
        assert_eq!(
            permitted(&births, birth_word(3, 9), CALLER),
            Err(Refusal::NoBirth)
        );
        assert_eq!(
            permitted(&births, birth_word(200, 9), CALLER),
            Err(Refusal::NoBirth)
        );
        births[1] = None;
        assert_eq!(
            permitted(&births, birth_word(1, 9), CALLER),
            Err(Refusal::NoBirth)
        );
    }

    #[test]
    fn the_descriptions_a_birth_holds_are_passed_over_and_the_limit_counts_the_rest() {
        let mut held = Held::EMPTY;
        let mut added = Held::EMPTY;
        for p in 0..10 {
            held.add(p);
        }
        for p in 5..15 {
            added.add(p);
        }
        // Ten held, five new: fifteen.
        assert_eq!(fits(&held, &added, 15), Ok(()));
        assert_eq!(fits(&held, &added, 14), Err(Refusal::Full));
    }
}
