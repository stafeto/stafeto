// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The descriptions the service keeps: one for each merged directory a program opened (files are
//! the data file service's, after a pass, or the RAM file service's, after a redirect). A handle
//! is the place of the description, its generation and the epoch of the instance
//! (`proto_fs::names::handle`): a handle of an earlier instance answers STALE, a handle of
//! another session or one that closed answers BAD_FD. A session holds `PER_SESSION` descriptions
//! at most and the service `PLACES`; a session that goes frees what it held.
//!
//! A description is shared across a fork or a spawn, as POSIX shares an open file description: a
//! session made by CLONE holds the descriptions of its parent that it names, and a description is
//! one place with one position, so what one holder reads the others do not read again. The
//! description goes when its last holder lets go of it (CLOSE or the end of its session); a
//! description has `HOLDERS` holders at most.

use proto_fs::names::{handle, split_handle};

pub const PLACES: usize = 128;
pub const PER_SESSION: usize = 16;
/// The descriptions the sessions of one process hold together (the pid Vouch named), so that one
/// process fills neither the table of the service nor the places of the others.
pub const PER_PROCESS: usize = 32;
/// The sessions that hold one description at once: the creator and the clones of its forks.
pub const HOLDERS: usize = 8;
const _: () = assert!(PLACES <= proto_fs::names::PLACES_MAX);

/// The directory of a description whose directory was removed: it lists nothing and has no
/// attributes.
pub const GONE: u32 = u32::MAX;

/// Where a listing stands: the stage and the position in it (`proto_fs::names::cursor`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    pub stage: u32,
    pub at: u32,
}

pub struct Description<D> {
    /// The labels of the sessions that hold it (0 for an empty place).
    holders: [u64; HOLDERS],
    /// The process the session was bound to when the description was made.
    pub pid: u32,
    /// The id of the directory in the index (0 is the root of the layer).
    pub dir: u32,
    /// The lower set was hidden from the directory when the description was made (it or a
    /// directory above it is opaque): the listing has no second stage.
    pub hidden: bool,
    pub position: Position,
    /// The furthest position the replies gave out: SEEK_DIR goes back to one, never past it.
    pub given: Position,
    /// The directory of the lower set, open from the first request of the second stage.
    pub lower: Option<D>,
    /// The entries of the open lower directory read so far (a request after a seek replays them
    /// up to the position, a few at a time).
    pub replayed: u32,
}

impl<D> Description<D> {
    fn holds(&self, owner: u64) -> bool {
        self.holders.contains(&owner)
    }

    fn add_holder(&mut self, owner: u64) -> bool {
        match self.holders.iter_mut().find(|h| **h == 0) {
            Some(free) => {
                *free = owner;
                true
            }
            None => false,
        }
    }

    /// `owner` lets go; whether nobody holds the description now.
    fn drop_holder(&mut self, owner: u64) -> bool {
        for h in self.holders.iter_mut().filter(|h| **h == owner) {
            *h = 0;
        }
        self.holders.iter().all(|h| *h == 0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The session holds `PER_SESSION` descriptions.
    PerSession,
    /// The sessions of the process hold `PER_PROCESS`.
    PerProcess,
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
            .filter(|d| d.holds(owner))
            .count()
    }

    pub fn count(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// A new description of the directory `dir` for `owner`; its handle.
    pub fn make(&mut self, owner: u64, pid: u32, dir: u32, hidden: bool) -> Result<u32, Refused> {
        if self.held_by(owner) >= PER_SESSION {
            return Err(Refused::PerSession);
        }
        if self.slots.iter().flatten().filter(|d| d.pid == pid).count() >= PER_PROCESS {
            return Err(Refused::PerProcess);
        }
        let place = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Refused::Full)?;
        // Generation 0 is skipped, so a handle with generation 0 and place 0 is never given.
        self.generations[place] = self.generations[place].wrapping_add(1).max(1);
        let mut holders = [0; HOLDERS];
        holders[0] = owner;
        self.slots[place] = Some(Description {
            holders,
            pid,
            dir,
            hidden,
            position: Position::default(),
            given: Position::default(),
            lower: None,
            replayed: 0,
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
            Some(Some(d)) if d.holds(owner) && self.generations[place] == generation => Ok(d),
            _ => Err(Lost::Bad),
        }
    }

    /// `owner` lets go of a description; the description itself comes back, to be closed, when
    /// `owner` was its last holder.
    pub fn close(&mut self, owner: u64, h: u32) -> Result<Option<Description<D>>, Lost> {
        self.get(owner, h)?;
        let (place, _, _) = split_handle(h);
        let place = usize::from(place);
        let last = self.slots[place]
            .as_mut()
            .is_some_and(|d| d.drop_holder(owner));
        Ok(if last { self.slots[place].take() } else { None })
    }

    /// The session `to` takes a share of each description of `handles` that `from` holds, all or
    /// none: a handle `from` does not hold is `Lost`, a session that would hold more than
    /// `PER_SESSION` or a description that would have more than `HOLDERS` holders is `Full`.
    pub fn share(&mut self, from: u64, handles: &[u32], to: u64) -> Result<(), ShareError> {
        let mut fresh = 0;
        for (i, &h) in handles.iter().enumerate() {
            if handles[..i].contains(&h) {
                continue;
            }
            let d = self.get(from, h).map_err(ShareError::Lost)?;
            if !d.holds(to) {
                if d.holders.iter().all(|x| *x != 0) {
                    return Err(ShareError::Full);
                }
                fresh += 1;
            }
        }
        if self.held_by(to) + fresh > PER_SESSION {
            return Err(ShareError::Full);
        }
        for &h in handles {
            let d = self.get(from, h).map_err(ShareError::Lost)?;
            if !d.holds(to) {
                d.add_holder(to);
            }
        }
        Ok(())
    }

    /// The directory `old` of the index is now `new` (a rename moved it to a slot of its own):
    /// the descriptions of it follow.
    pub fn retarget(&mut self, old: u32, new: u32) {
        for d in self.slots.iter_mut().flatten().filter(|d| d.dir == old) {
            d.dir = new;
        }
    }

    /// The directory `dir` of the index is gone (removed): its descriptions list nothing.
    pub fn forget(&mut self, dir: u32) {
        self.retarget(dir, GONE);
    }

    /// The session `owner` went: the descriptions it was the last holder of, one by one (the
    /// others lose one holder and live on).
    pub fn take_owned(&mut self, owner: u64) -> Option<Description<D>> {
        for place in 0..PLACES {
            let Some(d) = self.slots[place].as_mut() else {
                continue;
            };
            if d.holds(owner) && d.drop_holder(owner) {
                return self.slots[place].take();
            }
        }
        None
    }
}

/// Why a share of descriptions was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareError {
    Lost(Lost),
    Full,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_names_its_place_its_generation_and_its_epoch() {
        let mut t = Table::<()>::new(7);
        let a = t.make(1, 100, 5, false).unwrap();
        assert_eq!(t.get(1, a).unwrap().dir, 5);
        // Another session, a closed description and a forged generation are BAD_FD.
        assert_eq!(t.get(2, a).err(), Some(Lost::Bad));
        assert!(t.close(1, a).is_ok());
        assert_eq!(t.get(1, a).err(), Some(Lost::Bad));
        assert_eq!(t.close(1, a).err(), Some(Lost::Bad));
        // The place is taken again with the next generation: the old handle stays dead.
        let b = t.make(1, 100, 6, false).unwrap();
        assert_ne!(a, b);
        assert_eq!(t.get(1, a).err(), Some(Lost::Bad));
        assert_eq!(t.get(1, b).unwrap().dir, 6);
        // A handle of another epoch is STALE, whatever else it says.
        let other = Table::<()>::new(8);
        let mut other = other;
        let c = other.make(1, 100, 1, false).unwrap();
        assert_eq!(t.get(1, c).err(), Some(Lost::Stale));
        assert_eq!(t.get(1, 0).err(), Some(Lost::Stale));
    }

    #[test]
    fn a_session_holds_sixteen_and_the_table_a_hundred_and_twenty_eight() {
        let mut t = Table::<()>::new(1);
        for _ in 0..PER_SESSION {
            t.make(1, 100, 0, false).unwrap();
        }
        assert_eq!(t.make(1, 100, 0, false).err(), Some(Refused::PerSession));
        let mut owner = 2;
        let mut made = PER_SESSION;
        while made < PLACES {
            for _ in 0..PER_SESSION.min(PLACES - made) {
                t.make(owner, 1000 + owner as u32, 0, false).unwrap();
                made += 1;
            }
            owner += 1;
        }
        assert_eq!(t.count(), PLACES);
        assert_eq!(t.make(99, 5000, 0, false).err(), Some(Refused::Full));
        let mut freed = 0;
        while t.take_owned(1).is_some() {
            freed += 1;
        }
        assert_eq!(freed, PER_SESSION);
        assert_eq!(t.held_by(1), 0);
        assert!(t.make(99, 5000, 0, false).is_ok());
    }

    #[test]
    fn a_clone_shares_a_description_and_it_goes_with_its_last_holder() {
        let mut t = Table::<u8>::new(3);
        let a = t.make(1, 100, 5, false).unwrap();
        let b = t.make(1, 100, 6, false).unwrap();
        // The session 2 takes a share of both: one description each, held by two.
        assert_eq!(t.share(1, &[a, b], 2), Ok(()));
        assert_eq!(t.count(), 2);
        assert_eq!(t.get(2, a).unwrap().dir, 5);
        // The position is one: what a holder reads, the other has read.
        t.get(1, a).unwrap().position.at = 7;
        assert_eq!(t.get(2, a).unwrap().position.at, 7);
        // A holder lets go: the description lives on for the other, and is BAD_FD for the one gone.
        assert!(t.close(1, a).unwrap().is_none());
        assert_eq!(t.get(1, a).err(), Some(Lost::Bad));
        assert_eq!(t.get(2, a).unwrap().dir, 5);
        // The last holder frees it, and the place is free for the next description.
        assert!(t.close(2, a).unwrap().is_some());
        assert_eq!(t.count(), 1);
        // A session that goes frees what it alone held and only lets go of the rest.
        assert!(t.take_owned(1).is_none());
        assert_eq!(t.count(), 1);
        assert!(t.take_owned(2).is_some());
        assert_eq!(t.count(), 0);
        assert!(t.take_owned(2).is_none());
    }

    #[test]
    fn a_share_is_all_or_none_and_has_its_limits() {
        let mut t = Table::<u8>::new(3);
        let a = t.make(1, 100, 5, false).unwrap();
        let b = t.make(1, 100, 6, false).unwrap();
        // A handle the session does not hold, and a handle of another epoch.
        assert_eq!(t.share(2, &[a], 3), Err(ShareError::Lost(Lost::Bad)));
        assert_eq!(
            t.share(1, &[a, 0x0001_0000], 2),
            Err(ShareError::Lost(Lost::Stale))
        );
        // Nothing was given by the refused call.
        assert_eq!(t.held_by(2), 0);
        // A handle twice, and a share the target holds already, count once.
        assert_eq!(t.share(1, &[a, a], 2), Ok(()));
        assert_eq!(t.share(1, &[a, b], 2), Ok(()));
        assert_eq!(t.held_by(2), 2);
        // A description has HOLDERS holders at most.
        for to in 3..=HOLDERS as u64 {
            assert_eq!(t.share(1, &[a], to), Ok(()));
        }
        assert_eq!(t.share(1, &[a], 99), Err(ShareError::Full));
        assert_eq!(t.held_by(99), 0);
        // A session holds PER_SESSION descriptions at most, the shared ones included.
        let mut t = Table::<u8>::new(3);
        let mut handles = [0u32; PER_SESSION];
        for h in handles.iter_mut() {
            *h = t.make(1, 100, 1, false).unwrap();
        }
        let extra = t.make(5, 200, 1, false).unwrap();
        assert_eq!(t.share(1, &handles, 2), Ok(()));
        assert_eq!(t.share(5, &[extra], 2), Err(ShareError::Full));
    }
}
