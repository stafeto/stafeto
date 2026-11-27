// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The descriptions the service keeps: one for each merged directory a program opened (files are
//! the data file service's, after a pass, or the RAM file service's, after a redirect). A handle
//! is the place of the description, its generation and the epoch of the instance
//! (`proto_fs::names::handle`): a handle of an earlier instance answers STALE, a handle of
//! another session or one that closed answers BAD_FD. A session holds `PER_SESSION` descriptions
//! at most and the service `PLACES`; a session that goes frees what it held.

use proto_fs::names::{handle, split_handle};

pub const PLACES: usize = 128;
pub const PER_SESSION: usize = 16;
const _: () = assert!(PLACES <= proto_fs::names::PLACES_MAX);

/// Where a listing stands: the stage and the position in it (`proto_fs::names::cursor`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Position {
    pub stage: u32,
    pub at: u32,
}

pub struct Description<D> {
    /// The label of the session that holds it.
    pub owner: u64,
    /// The id of the directory in the index (0 is the root of the layer).
    pub dir: u32,
    pub position: Position,
    /// The directory of the lower set, open from the first request of the second stage.
    pub lower: Option<D>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The session holds `PER_SESSION` descriptions.
    PerSession,
    /// The service holds `PLACES`.
    Full,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lost {
    /// BAD_FD: no such description, or the session does not hold it.
    Bad,
    /// STALE: the handle is of an earlier instance.
    Stale,
}

pub struct Table<D> {
    slots: [Option<Description<D>>; PLACES],
    generations: [u8; PLACES],
    epoch: u16,
}

impl<D> Table<D> {
    /// A table for the instance `epoch` (never 0, so that a handle of 0 is none).
    pub fn new(epoch: u16) -> Table<D> {
        Table {
            slots: [const { None }; PLACES],
            generations: [0; PLACES],
            epoch: epoch.max(1),
        }
    }

    pub fn epoch(&self) -> u16 {
        self.epoch
    }

    pub fn held_by(&self, owner: u64) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|d| d.owner == owner)
            .count()
    }

    pub fn count(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// A new description of the directory `dir` for `owner`; its handle.
    pub fn make(&mut self, owner: u64, dir: u32) -> Result<u32, Refused> {
        if self.held_by(owner) >= PER_SESSION {
            return Err(Refused::PerSession);
        }
        let place = self.slots.iter().position(Option::is_none).ok_or(Refused::Full)?;
        // Generation 0 is skipped, so a handle with generation 0 and place 0 is never given.
        self.generations[place] = self.generations[place].wrapping_add(1).max(1);
        self.slots[place] = Some(Description {
            owner,
            dir,
            position: Position::default(),
            lower: None,
        });
        Ok(handle(place as u8, self.generations[place], self.epoch))
    }

    pub fn get(&mut self, owner: u64, h: u32) -> Result<&mut Description<D>, Lost> {
        let (place, generation, epoch) = split_handle(h);
        if epoch != self.epoch {
            return Err(Lost::Stale);
        }
        let place = usize::from(place);
        match self.slots.get_mut(place) {
            Some(Some(d)) if d.owner == owner && self.generations[place] == generation => Ok(d),
            _ => Err(Lost::Bad),
        }
    }

    /// Frees a description; what it held (the lower directory) comes back to be closed.
    pub fn close(&mut self, owner: u64, h: u32) -> Result<Description<D>, Lost> {
        self.get(owner, h)?;
        let (place, _, _) = split_handle(h);
        self.slots[usize::from(place)].take().ok_or(Lost::Bad)
    }

    /// The session `owner` went: its descriptions, one by one.
    pub fn take_owned(&mut self, owner: u64) -> Option<Description<D>> {
        let place = self
            .slots
            .iter()
            .position(|d| d.as_ref().is_some_and(|d| d.owner == owner))?;
        self.slots[place].take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_names_its_place_its_generation_and_its_epoch() {
        let mut t = Table::<()>::new(7);
        let a = t.make(1, 5).unwrap();
        assert_eq!(t.get(1, a).unwrap().dir, 5);
        // Another session, a closed description and a forged generation are BAD_FD.
        assert_eq!(t.get(2, a).err(), Some(Lost::Bad));
        assert!(t.close(1, a).is_ok());
        assert_eq!(t.get(1, a).err(), Some(Lost::Bad));
        assert_eq!(t.close(1, a).err(), Some(Lost::Bad));
        // The place is taken again with the next generation: the old handle stays dead.
        let b = t.make(1, 6).unwrap();
        assert_ne!(a, b);
        assert_eq!(t.get(1, a).err(), Some(Lost::Bad));
        assert_eq!(t.get(1, b).unwrap().dir, 6);
        // A handle of another epoch is STALE, whatever else it says.
        let other = Table::<()>::new(8);
        let mut other = other;
        let c = other.make(1, 1).unwrap();
        assert_eq!(t.get(1, c).err(), Some(Lost::Stale));
        assert_eq!(t.get(1, 0).err(), Some(Lost::Stale));
    }

    #[test]
    fn a_session_holds_sixteen_and_the_table_a_hundred_and_twenty_eight() {
        let mut t = Table::<()>::new(1);
        for _ in 0..PER_SESSION {
            t.make(1, 0).unwrap();
        }
        assert_eq!(t.make(1, 0).err(), Some(Refused::PerSession));
        let mut owner = 2;
        let mut made = PER_SESSION;
        while made < PLACES {
            for _ in 0..PER_SESSION.min(PLACES - made) {
                t.make(owner, 0).unwrap();
                made += 1;
            }
            owner += 1;
        }
        assert_eq!(t.count(), PLACES);
        assert_eq!(t.make(99, 0).err(), Some(Refused::Full));
        let mut freed = 0;
        while t.take_owned(1).is_some() {
            freed += 1;
        }
        assert_eq!(freed, PER_SESSION);
        assert_eq!(t.held_by(1), 0);
        assert!(t.make(99, 0).is_ok());
    }
}
