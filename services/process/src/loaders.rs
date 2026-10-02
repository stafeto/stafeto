// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The places of the loaders (spec 2, 3.2; 5c): LOADERS of them, one for
//! each child whose loader runs, from SpawnStart until the loader takes
//! its program's sessions (Take), its process ends, or the parent aborts.
//! A place keeps what the service holds for the loader (`T`), the stage
//! of the load and the IDs a file service said the file sets (SetId).
//! Each place has a generation, which moves whenever the place is taken,
//! so its ticket (Vouch gives it, SetId names it) names one attempt and
//! never a later one. The service answers Vouch of a loader's identity
//! with the ticket only while the place loads (condition O5), takes SetId only then
//! and only once (condition O4), and applies it only to the record whose place it
//! is, at SpawnCommit; Abort, the end of the process and Take wipe it with
//! the place.

use proto_process::{Credentials, NO_ID, RECORDS, SPAWN_RESETIDS};

/// The service's own pages it keeps out of the pool of the children's
/// quotas (5c): the objects of the pages of its records (8 of 32 pages),
/// the data and stacks of its loaders (16 of 5 pages) and room for the
/// tables of its mappings.
pub const RESERVE: u64 = 384 * 4096;

/// Whether a child of `quota` bytes fits the pool: the service's quota
/// left (`free`) keeps RESERVE after it.
pub const fn pool_allows(free: u64, quota: u64) -> bool {
    match free.checked_sub(RESERVE) {
        Some(pool) => quota <= pool,
        None => false,
    }
}

/// The credentials a child of `parent` starts with: those of an exec, the
/// saved IDs taken from the effective ones, and the effective ones reset
/// to the real ones for POSIX_SPAWN_RESETIDS ([P24-SPAWN], [P24-EXEC]).
pub fn child_credentials(parent: Credentials, flags: u32) -> Credentials {
    let (euid, egid) = if flags & SPAWN_RESETIDS != 0 {
        (parent.uid, parent.gid)
    } else {
        (parent.euid, parent.egid)
    };
    Credentials {
        euid,
        suid: euid,
        egid,
        sgid: egid,
        ..parent
    }
}

/// `c` with the IDs of a set-ID file (SetId, NO_ID for one the file does
/// not set): the effective and the saved ID take it, the real one stays.
pub fn set_ids(c: Credentials, (uid, gid): (u32, u32)) -> Credentials {
    let (euid, egid) = (
        if uid == NO_ID { c.euid } else { uid },
        if gid == NO_ID { c.egid } else { gid },
    );
    Credentials {
        euid,
        suid: euid,
        egid,
        sgid: egid,
        ..c
    }
}

/// The loaders that run at most: the service pays for their data and
/// stack (five pages each) and holds a place of its channel for each.
pub const LOADERS: usize = 16;
/// The loaders of one parent at once (5c, decision 7): a process that
/// starts spawns and never finishes them holds no more places than these.
pub const LOADERS_OF_PARENT: usize = 2;

/// Where a load is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The process was made and the loader runs; it has not said Boot.
    Booting,
    /// Boot came: the parent has the loader's start channel, and the
    /// loader opens and reads the program.
    Loading,
    /// SpawnCommit came: the record lives, and the loader takes its
    /// program's sessions next.
    Ready,
}

/// A place of a loader.
pub struct Place<T> {
    /// The record of the child it loads, and that of the parent.
    pub record: usize,
    pub parent: usize,
    /// The image of the record it loads.
    pub image: u32,
    pub stage: Stage,
    /// The user and group IDs the file sets (NO_ID for none), once a file
    /// service said so for this place.
    pub set_id: Option<(u32, u32)>,
    /// What the service holds for the loader.
    pub held: T,
}

/// Why SetId is refused: no place of the ticket, a place of another
/// record or image, one that does not load now, or one that has a SetId.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused;

pub struct Loaders<T> {
    places: [Option<Place<T>>; LOADERS],
    generations: [u32; LOADERS],
    /// The place of each record whose loader runs.
    of_record: [Option<u8>; RECORDS],
}

impl<T> Default for Loaders<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Loaders<T> {
    pub const fn new() -> Self {
        Self {
            places: [const { None }; LOADERS],
            generations: [0; LOADERS],
            of_record: [None; RECORDS],
        }
    }

    /// Whether a place is free.
    pub fn room(&self) -> bool {
        self.places.iter().any(Option::is_none)
    }

    /// Whether the record in `parent` may start another load: a place is
    /// free and it has fewer than LOADERS_OF_PARENT.
    pub fn room_for(&self, parent: usize) -> bool {
        let own = self
            .places
            .iter()
            .flatten()
            .filter(|p| p.parent == parent)
            .count();
        self.room() && own < LOADERS_OF_PARENT
    }

    /// A place for the loader of the record in `record`, a child of the
    /// record in `parent`, image `image`: Booting, one generation on. None
    /// with every place taken, when the parent has LOADERS_OF_PARENT, or
    /// when the record has one.
    pub fn take(&mut self, record: usize, parent: usize, image: u32, held: T) -> Option<usize> {
        if self.of_record[record].is_some() || !self.room_for(parent) {
            return None;
        }
        let index = self.places.iter().position(Option::is_none)?;
        self.generations[index] = self.generations[index].wrapping_add(1);
        self.places[index] = Some(Place {
            record,
            parent,
            image,
            stage: Stage::Booting,
            set_id: None,
            held,
        });
        self.of_record[record] = Some(index as u8);
        Some(index)
    }

    /// The place of the loader of the record in `record`.
    pub fn of(&self, record: usize) -> Option<usize> {
        self.of_record
            .get(record)
            .copied()
            .flatten()
            .map(usize::from)
    }

    pub fn get(&self, index: usize) -> Option<&Place<T>> {
        self.places.get(index)?.as_ref()
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Place<T>> {
        self.places.get_mut(index)?.as_mut()
    }

    /// The ticket of the place in `index`: its generation and its index.
    pub fn ticket(&self, index: usize) -> u64 {
        u64::from(self.generations[index]) << 8 | index as u64
    }

    /// The ticket of the loader of the record in `record`, while it loads:
    /// what Vouch says of its identity. None before Boot and from
    /// SpawnCommit on, so a copy of the identity proves nothing then.
    pub fn vouches(&self, record: usize) -> Option<u64> {
        let index = self.of(record)?;
        let place = self.get(index)?;
        (place.stage == Stage::Loading).then(|| self.ticket(index))
    }

    /// SetId of a file service for the place of `ticket`: kept when the
    /// place loads the record in `record`, image `image`, and has none.
    pub fn set_id(
        &mut self,
        ticket: u64,
        record: usize,
        image: u32,
        ids: (u32, u32),
    ) -> Result<(), Refused> {
        let index = (ticket & 0xFF) as usize;
        if index >= LOADERS || self.ticket(index) != ticket {
            return Err(Refused);
        }
        let place = self.places[index].as_mut().ok_or(Refused)?;
        if place.record != record
            || place.image != image
            || place.stage != Stage::Loading
            || place.set_id.is_some()
        {
            return Err(Refused);
        }
        place.set_id = Some(ids);
        Ok(())
    }

    /// SpawnCommit of the record in `record`, whose loader loads: the place
    /// is Ready, and what SetId kept comes back to be applied.
    pub fn commit(&mut self, record: usize) -> Result<Option<(u32, u32)>, Refused> {
        let index = self.of(record).ok_or(Refused)?;
        let place = self.places[index].as_mut().ok_or(Refused)?;
        if place.stage != Stage::Loading {
            return Err(Refused);
        }
        place.stage = Stage::Ready;
        Ok(place.set_id.take())
    }

    /// The place of the record in `record` goes, with its SetId; the next
    /// attempt in it has another ticket.
    pub fn free(&mut self, record: usize) -> Option<Place<T>> {
        let index = self.of(record)?;
        self.of_record[record] = None;
        self.generations[index] = self.generations[index].wrapping_add(1);
        self.places[index].take()
    }

    /// The places taken.
    pub fn count(&self) -> usize {
        self.places.iter().flatten().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RESETIDS takes the real IDs for the effective ones; the saved ones
    /// follow the effective ones, as at an exec; a set-ID file's IDs win
    /// over both, and the real ones stay.
    #[test]
    fn credentials_of_a_child() {
        let parent = Credentials {
            uid: 1,
            euid: 2,
            suid: 3,
            gid: 4,
            egid: 5,
            sgid: 6,
        };
        let plain = child_credentials(parent, 0);
        assert_eq!(plain.words(), [1, 2, 2, 4, 5, 5]);
        let reset = child_credentials(parent, SPAWN_RESETIDS);
        assert_eq!(reset.words(), [1, 1, 1, 4, 4, 4]);
        assert_eq!(set_ids(reset, (0, NO_ID)).words(), [1, 0, 0, 4, 4, 4]);
        assert_eq!(set_ids(reset, (NO_ID, 7)).words(), [1, 1, 1, 4, 7, 7]);
    }

    /// A child's quota comes from the pool only while the service keeps
    /// its reserve after it.
    #[test]
    fn the_pool_keeps_the_reserve() {
        let child = 512 * 4096;
        assert!(pool_allows(RESERVE + child, child));
        assert!(!pool_allows(RESERVE + child - 1, child));
        assert!(!pool_allows(RESERVE - 1, 0));
    }

    /// A loader that booted: the place loads.
    fn loading(t: &mut Loaders<()>, record: usize) -> u64 {
        let index = t.take(record, 0, 1, ()).unwrap();
        assert_eq!(t.vouches(record), None, "no identity before Boot");
        t.get_mut(index).unwrap().stage = Stage::Loading;
        t.vouches(record).unwrap()
    }

    #[test]
    fn sixteen_places_one_per_record() {
        let mut t = Loaders::<()>::new();
        for record in 1..=LOADERS {
            assert!(t.take(record, 200 + record, 1, ()).is_some());
        }
        assert!(!t.room());
        assert_eq!(t.take(100, 0, 1, ()), None, "the seventeenth waits");
        t.free(3);
        assert_eq!(t.take(4, 0, 1, ()), None, "one place a record");
        assert!(t.take(100, 0, 1, ()).is_some());
        assert_eq!(t.count(), LOADERS);
    }

    /// One parent holds LOADERS_OF_PARENT places at most: the others stay
    /// for the other parents, and a place it frees is its own again.
    #[test]
    fn a_parent_holds_two_places_at_most() {
        let mut t = Loaders::<()>::new();
        for record in 1..=LOADERS_OF_PARENT {
            assert!(t.room_for(7));
            assert!(t.take(record, 7, 1, ()).is_some());
        }
        assert!(!t.room_for(7));
        assert_eq!(t.take(50, 7, 1, ()), None, "a third load of one parent");
        assert!(t.take(50, 8, 1, ()).is_some(), "another parent's");
        t.free(1);
        assert!(t.take(51, 7, 1, ()).is_some());
    }

    /// SetId is kept once, for the record and image of its place, while it
    /// loads; a foreign ticket, a second SetId, another record or image
    /// and a place that committed are refused.
    #[test]
    fn set_id_is_kept_once_for_its_own_attempt() {
        let mut t = Loaders::<()>::new();
        let a = loading(&mut t, 5);
        let b = loading(&mut t, 6);
        assert_eq!(t.set_id(b, 5, 1, (0, 0)), Err(Refused), "another's ticket");
        assert_eq!(t.set_id(a, 5, 2, (0, 0)), Err(Refused), "another image");
        assert_eq!(t.set_id(a ^ 1 << 8, 5, 1, (0, 0)), Err(Refused), "stale");
        assert_eq!(t.set_id(a, 5, 1, (0, 7)), Ok(()));
        assert_eq!(t.set_id(a, 5, 1, (0, 0)), Err(Refused), "a second SetId");
        assert_eq!(t.commit(5), Ok(Some((0, 7))));
        assert_eq!(t.vouches(5), None, "no loader after SpawnCommit");
        assert_eq!(t.set_id(b, 6, 1, (0, 0)), Ok(()));
        assert_eq!(t.commit(5), Err(Refused), "one commit");
        assert_eq!(t.set_id(a, 5, 1, (0, 0)), Err(Refused), "after commit");
    }

    /// Condition O4: a set-ID load that failed leaves nothing for the next one, in
    /// the same place, whatever its record: the place's SetId goes with
    /// it and the next attempt has another ticket.
    #[test]
    fn a_failed_set_id_load_leaves_nothing_behind() {
        let mut t = Loaders::<()>::new();
        let first = loading(&mut t, 5);
        assert_eq!(t.set_id(first, 5, 1, (0, 0)), Ok(()));
        assert!(t.free(5).is_some());
        let next = loading(&mut t, 5);
        assert_ne!(next, first);
        assert_eq!(t.commit(5), Ok(None), "no IDs from the attempt before");
        assert_eq!(t.set_id(first, 5, 1, (0, 0)), Err(Refused));
    }
}
