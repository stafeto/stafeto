// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The index of the names of the live layer (the layered file system, section 5.1): a table of
//! `BUCKETS` buckets of `WAYS` places, keyed by the pair (the key of the directory above, the
//! name). A name has two buckets, one in each half of the table, chosen by two parts of its
//! 64-bit hash; an insertion takes the less loaded of the two (a tie goes to the left one) and no
//! entry ever moves, so the id of an entry is its slot plus one (the slot is bucket times `WAYS`
//! plus the way) and the root of the layer is id 0. A lookup reads the 16 tags of the two buckets
//! and compares the entry and the name for each tag that matches. The service is the only writer
//! of the names of `/.layers`, so the index is exact without a journal.
//!
//! Two choices make the table fail only at the edge of its capacity: with random hashes 10,240
//! entries in the 16,384 places never overflowed a bucket in 2,000,000 builds. The table holds at
//! most `ENTRIES_MAX` entries (the names and the marks) at run time: a new name over that is
//! NO_SPACE (ENOSPC for the program that created it), which keeps the next build of the same
//! names, under the seed of the next start, inside what the buckets take. A build that does
//! overflow a bucket (`Error::Buckets`) starts again under another seed.
//!
//! The names live in an arena (`ARENA` bytes, each name once); an insertion that finds no room
//! in the arena is NO_SPACE too.
//!
//! An entry has the layer it lies in, its kind (a file, a directory, a symbolic link, or the mark of
//! a deletion: the file `.wh.<name>` of the layer says "the name of the lower set is gone"; a link
//! is the file `.wh..wh.lnk.<name>` and its text), the number the
//! data file service gave it and, for a directory, its owner, group and mode (the walk of a path
//! checks the right to search a directory of the layer of the user from these, with no call), and
//! the flags OPAQUE (the directory holds the file `.wh..wh..opq`: the lower set shows through it
//! no more) and HAS_CHILDREN (a name of the layer lies in it).

/// The places of the table: `BUCKETS` buckets of `WAYS`.
pub const BUCKETS: usize = 2048;
pub const WAYS: usize = 8;
pub const SLOTS: usize = BUCKETS * WAYS;
/// The most entries (names and marks) the table takes at run time. A build takes every name the
/// volume holds (it does not look at the limit), so the names of a layer that was filled to the
/// limit still build.
pub const ENTRIES_MAX: usize = 10_240;
pub const ARENA: usize = 256 * 1024;
pub const NAME_MAX: usize = 255;
/// The bytes a link's file name (`.wh..wh.lnk.`) and a mark (`.wh.`) add to a name, and the marker of
/// an opaque directory (`/.wh..wh..opq`) to a directory.
const LINK_EXTRA: usize = 12;
const MARK_EXTRA: usize = 4;
pub const OPAQUE_EXTRA: usize = 13;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Empty = 0,
    /// A name that was removed: the slot keeps its name for a probe that passes it. It follows
    /// `Empty` so that "no entry" is one comparison (`kind < 2`) in the loops that look at slots.
    Gone = 1,
    Whiteout = 2,
    File = 3,
    Dir = 4,
    /// A symbolic link: littlefs has none, so the layer keeps it as the file `.wh..wh.lnk.<name>`
    /// whose bytes are the target.
    Link = 5,
}

/// The directory is opaque: the lower set does not show through it.
pub const OPAQUE: u8 = 1;
/// The directory holds a name of the layer.
pub const HAS_CHILDREN: u8 = 2;
/// The directory has not been listed yet by the build of the index (`scan`).
pub const UNSCANNED: u8 = 4;
/// An entry. The key of its place is (the key of its directory, its name). A directory has a key
/// of its own that never changes (`dkey`, 1 to `SLOTS`), so a directory that moves to another place
/// of the table (a rename) keeps its children, which name it by that key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The key of the directory the entry lies in (0 for the root of the layer).
    pkey: u32,
    /// The key of this entry when it is a directory, else 0.
    dkey: u32,
    /// For a directory: the most bytes any name below it adds to its path (a slash and the name at
    /// each level, a link's file name and a mark with their prefixes). It only grows, so a rename
    /// that would take a subtree past the volume's limit on paths is refused with no scan.
    reach: u16,
    name_at: u32,
    name_len: u8,
    pub kind: Kind,
    pub flags: u8,
    pub layer: u8,
    pub number: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    /// For a directory: how many of its children are names (not marks).
    pub live_children: u16,
}

const EMPTY: Entry = Entry {
    pkey: 0,
    dkey: 0,
    reach: 0,
    name_at: 0,
    name_len: 0,
    kind: Kind::Empty,
    flags: 0,
    layer: 0,
    number: 0,
    uid: 0,
    gid: 0,
    mode: 0,
    live_children: 0,
};

/// What `next_child` found: an entry (the position after it and its id), the end of the slots
/// looked at with more to come (the position to go on from), or the end of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextChild {
    Found(usize, u32),
    Continue(usize),
    End,
}

/// What an insertion carries besides its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fields {
    pub kind: Kind,
    pub layer: u8,
    pub number: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No room for the name in the arena, or the table holds `ENTRIES_MAX` entries.
    NoSpace,
    /// Both buckets of the name are full (the build starts again under another seed; at run time
    /// the table is at its limit long before, so a program sees NO_SPACE).
    Buckets,
    /// An empty name, one over `NAME_MAX`, or a parent that is no directory.
    Invalid,
}

/// The attributes of the root of the layer and its flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Root {
    pub number: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub flags: u8,
}

pub struct Index {
    slots: [Entry; SLOTS],
    /// The tag of each place (the top 16 bits of the hash of its name, 0 mapped to 1): 0 is a free
    /// place, and a gone entry keeps its tag.
    tags: [u16; SLOTS],
    /// The live entries of each bucket.
    loads: [u8; BUCKETS],
    arena: [u8; ARENA],
    arena_len: usize,
    live: u32,
    marks: u32,
    /// The slot plus one of the directory with the key `k`, at `dslot[k]` (0 for a key in no use).
    dslot: [u32; SLOTS],
    /// The keys issued so far, and the keys given back, which are used again first.
    keys_issued: u32,
    free_keys: [u32; SLOTS],
    free_len: usize,
    /// The seed of the hash, chosen at each start of the service (`reseed`): the names of a layer
    /// cannot be made to collide offline.
    seed: u64,
    /// A test hook: this many of the next insertions fail with `Error::Buckets`.
    #[cfg(test)]
    pub fail_inserts: u32,
    pub root: Root,
}

const EMPTY_ROOT: Root = Root {
    number: 0,
    uid: 0,
    gid: 0,
    mode: 0,
    flags: 0,
};

/// The 64-bit hash of a key: FNV-1a over the key and the name, then the final mix of murmur3, so
/// that names that differ in one byte spread over the table.
fn hash(seed: u64, parent: u32, name: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ seed;
    for b in parent.to_le_bytes().iter().chain(name) {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    h
}

/// The two buckets of a hash (one in each half) and its tag.
fn places(h: u64) -> (usize, usize, u16) {
    let tag = (h >> 48) as u16;
    (
        (h & 1023) as usize,
        BUCKETS / 2 + ((h >> 10) & 1023) as usize,
        if tag == 0 { 1 } else { tag },
    )
}

/// The places one step of `clear_step` empties.
pub const CLEAR_SLOTS: usize = 256;

/// What a look at the two buckets of a key found.
struct Probe {
    /// The slot of the live entry of the key.
    live: Option<usize>,
    /// The slot of a gone entry of the same key (its name is in the arena still).
    gone: Option<usize>,
    /// The place a new entry would take: in the less loaded bucket, a free way, else a gone one.
    place: Option<usize>,
}

impl Index {
    pub const fn new() -> Index {
        Index {
            slots: [EMPTY; SLOTS],
            tags: [0; SLOTS],
            loads: [0; BUCKETS],
            arena: [0; ARENA],
            arena_len: 0,
            live: 0,
            marks: 0,
            dslot: [0; SLOTS],
            keys_issued: 0,
            free_keys: [0; SLOTS],
            free_len: 0,
            seed: 0,
            #[cfg(test)]
            fail_inserts: 0,
            // All zeros, so that the static of the program is `.bss`: the build of the index
            // sets the attributes of the root from the volume.
            root: Root {
                number: 0,
                uid: 0,
                gid: 0,
                mode: 0,
                flags: 0,
            },
        }
    }

    /// Chooses the seed of the hash; the index is empty (the start of the service, before the
    /// build).
    pub fn reseed(&mut self, seed: u64) {
        self.clear();
        self.seed = seed;
    }

    /// The seed of the hash.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Takes the seed of the next build; the index is emptied by `clear_step` first.
    pub fn set_seed(&mut self, seed: u64) {
        self.seed = seed;
    }

    /// Empties the index (the build starts again).
    pub fn clear(&mut self) {
        let mut from = 0;
        while let Some(next) = self.clear_step(from) {
            from = next;
        }
    }

    /// One step of emptying the index: `CLEAR_SLOTS` places from `from` (and, at the end, the keys
    /// and the counters). The place to go on from, or None when the index is empty.
    pub fn clear_step(&mut self, from: usize) -> Option<usize> {
        if from < SLOTS {
            let to = (from + CLEAR_SLOTS).min(SLOTS);
            // SAFETY: the bytes of `EMPTY` are all zero (the kind `Empty` is 0), and a fill of
            // zero bytes is a memset, which the loop over the places is not (it stores the fields
            // one by one, 100 ticks a place under -icount).
            unsafe {
                core::ptr::write_bytes(self.slots.as_mut_ptr().add(from), 0, to - from);
            }
            self.tags[from..to].fill(0);
            self.dslot[from..to].fill(0);
            return Some(to);
        }
        self.loads.fill(0);
        self.arena_len = 0;
        self.live = 0;
        self.marks = 0;
        self.keys_issued = 0;
        self.free_len = 0;
        self.root = EMPTY_ROOT;
        None
    }

    /// The names of a layer (files and directories) and the marks of deletion.
    pub fn counts(&self) -> (u32, u32) {
        (self.live, self.marks)
    }

    /// The entries in all, for STATUS.
    pub fn names(&self) -> u32 {
        self.live + self.marks
    }

    fn name_of(&self, e: &Entry) -> &[u8] {
        &self.arena[e.name_at as usize..e.name_at as usize + usize::from(e.name_len)]
    }

    /// The key of the directory `id` (0 for the root); None for an entry that is no directory.
    fn dkey_of(&self, id: u32) -> Option<u32> {
        if id == 0 {
            return Some(0);
        }
        self.entry(id)
            .filter(|e| e.kind == Kind::Dir)
            .map(|e| e.dkey)
    }

    /// The id of the directory `id` lies in (0 for the root, and for an id that is none).
    pub fn parent_of(&self, id: u32) -> u32 {
        match self.entry(id) {
            Some(e) => self.dslot[e.pkey as usize & (SLOTS - 1)],
            _ => 0,
        }
    }

    /// What the two buckets of (`pkey`, `name`) hold: the entry (live or gone) of the key, and the
    /// place a new one takes. Every one of the 16 tags is looked at.
    fn probe(&self, pkey: u32, name: &[u8]) -> Probe {
        let (b1, b2, tag) = places(hash(self.seed, pkey, name));
        let mut found = Probe {
            live: None,
            gone: None,
            place: None,
        };
        for b in [b1, b2] {
            for slot in b * WAYS..(b + 1) * WAYS {
                if self.tags[slot] == tag {
                    let e = &self.slots[slot];
                    if e.pkey == pkey && self.name_of(e) == name {
                        if e.kind == Kind::Gone {
                            found.gone = Some(slot);
                        } else {
                            found.live = Some(slot);
                        }
                    }
                }
            }
        }
        let b = if self.loads[b2] < self.loads[b1] {
            b2
        } else {
            b1
        };
        if usize::from(self.loads[b]) < WAYS {
            let ways = b * WAYS..(b + 1) * WAYS;
            found.place = ways
                .clone()
                .find(|&slot| self.slots[slot].kind == Kind::Empty)
                .or_else(|| {
                    ways.into_iter()
                        .find(|&slot| self.slots[slot].kind == Kind::Gone)
                });
        }
        found
    }

    /// The slot of the live entry of (`pkey`, `name`).
    fn find(&self, pkey: u32, name: &[u8]) -> Option<usize> {
        let (b1, b2, tag) = places(hash(self.seed, pkey, name));
        for b in [b1, b2] {
            for slot in b * WAYS..(b + 1) * WAYS {
                if self.tags[slot] == tag {
                    let e = &self.slots[slot];
                    if e.kind != Kind::Gone && e.pkey == pkey && self.name_of(e) == name {
                        return Some(slot);
                    }
                }
            }
        }
        None
    }

    /// The entry of `name` in the directory `parent`, with its id; a gone entry is none.
    pub fn lookup(&self, parent: u32, name: &[u8]) -> Option<(u32, &Entry)> {
        self.lookup_in(self.dkey_of(parent)?, name)
    }

    /// `lookup` in the directory with the key `pkey`.
    pub fn lookup_in(&self, pkey: u32, name: &[u8]) -> Option<(u32, &Entry)> {
        let slot = self.find(pkey, name)?;
        Some((slot as u32 + 1, &self.slots[slot]))
    }

    /// The entry with id `id` (not the root).
    #[inline]
    pub fn entry(&self, id: u32) -> Option<&Entry> {
        let slot = (id as usize).checked_sub(1)?;
        let e = self.slots.get(slot)?;
        (!matches!(e.kind, Kind::Empty | Kind::Gone)).then_some(e)
    }

    pub fn name(&self, id: u32) -> Option<&[u8]> {
        self.entry(id).map(|e| self.name_of(e))
    }

    /// The next entry of the directory `parent` at a slot from `from` on (a position of a listing,
    /// 0 for the start), looking at `budget` slots at most: each slot looked at is taken off the
    /// budget, so the cost of a request does not depend on the size of the table.
    pub fn next_child(&self, parent: u32, from: usize, budget: &mut usize) -> NextChild {
        let Some(pkey) = self.dkey_of(parent) else {
            return NextChild::End;
        };
        self.next_child_of(pkey, from, budget)
    }

    /// The key of the directory `id` (0 for the root): a listing asks for it once.
    pub fn dir_key(&self, id: u32) -> Option<u32> {
        self.dkey_of(id)
    }

    /// `next_child` for the directory with the key `pkey`.
    pub fn next_child_of(&self, pkey: u32, from: usize, budget: &mut usize) -> NextChild {
        let mut slot = from;
        while slot < SLOTS {
            if *budget == 0 {
                return NextChild::Continue(slot);
            }
            *budget -= 1;
            let e = &self.slots[slot];
            if !matches!(e.kind, Kind::Empty | Kind::Gone) && e.pkey == pkey {
                return NextChild::Found(slot + 1, slot as u32 + 1);
            }
            slot += 1;
        }
        NextChild::End
    }

    /// A key for a new directory.
    fn issue_key(&mut self) -> Result<u32, Error> {
        if self.free_len > 0 {
            self.free_len -= 1;
            return Ok(self.free_keys[self.free_len]);
        }
        // The keys are 1 to `SLOTS - 1`: 0 is the root, and `dslot` is indexed by a masked key.
        if self.keys_issued as usize >= SLOTS - 1 {
            return Err(Error::NoSpace);
        }
        self.keys_issued += 1;
        Ok(self.keys_issued)
    }

    fn give_back(&mut self, key: u32) {
        if key != 0 {
            self.dslot[key as usize & (SLOTS - 1)] = 0;
            self.free_keys[self.free_len] = key;
            self.free_len += 1;
        }
    }

    /// Inserts a name. A mark of deletion over a name of the layer changes nothing, and a name over
    /// a mark replaces it (the layer says the name is there). Returns the id.
    pub fn insert(&mut self, parent: u32, name: &[u8], f: Fields) -> Result<u32, Error> {
        self.insert_with(parent, name, f, None, false, true)
    }

    /// `insert` for the build of the index: only the directory the name lies in learns how far it
    /// reaches (a walk up the index costs a level at a time, and a deep chain would take its depth in
    /// one step); the directories above learn it from `lift`, which the build runs when it has
    /// listed them all.
    pub fn insert_shallow(&mut self, parent: u32, name: &[u8], f: Fields) -> Result<u32, Error> {
        self.insert_with(parent, name, f, None, true, false)
    }

    /// The directory above `id` reaches as far as `id` does and its name: the build calls it for the
    /// directories children first.
    pub fn lift(&mut self, id: u32) {
        let Some(e) = self.entry(id).copied() else {
            return;
        };
        let parent = self.parent_of(id);
        self.grow(
            parent,
            1 + usize::from(e.name_len) + usize::from(e.reach),
            true,
        );
    }

    /// `insert`, giving a directory the key `keep` (a directory that moved) when there is one.
    fn insert_with(
        &mut self,
        parent: u32,
        name: &[u8],
        f: Fields,
        keep: Option<u32>,
        shallow: bool,
        capped: bool,
    ) -> Result<u32, Error> {
        let id = self.insert_raw(parent, name, f, keep, capped)?;
        let extra = match f.kind {
            Kind::Link => LINK_EXTRA,
            Kind::Whiteout => MARK_EXTRA,
            _ => 0,
        };
        self.grow(parent, 1 + name.len() + extra, shallow);
        Ok(id)
    }

    /// The directory `at` and each one above it reach `add` bytes below themselves at least.
    fn grow(&mut self, mut at: u32, mut add: usize, shallow: bool) {
        if shallow {
            // The build: the one directory the name lies in.
            if let Some(e) = (at as usize)
                .checked_sub(1)
                .and_then(|slot| self.slots.get_mut(slot))
            {
                e.reach = e.reach.max(add.min(usize::from(u16::MAX)) as u16);
            }
            return;
        }
        while at != 0 {
            let Some(slot) = (at as usize).checked_sub(1) else {
                return;
            };
            let Some(e) = self.slots.get_mut(slot) else {
                return;
            };
            let known = usize::from(e.reach) >= add;
            e.reach = e.reach.max(add.min(usize::from(u16::MAX)) as u16);
            // The directories above reach further than this one already (an earlier name did it).
            if shallow || known {
                return;
            }
            add += 1 + usize::from(e.name_len);
            at = self.parent_of(at);
        }
    }

    /// Whether `insert` of `name` in `parent` would find a place: the name's own place (a live
    /// entry of it, which an insertion replaces), or a free one with the table under `ENTRIES_MAX`
    /// and room in the arena. The service asks before it touches the volume.
    pub fn has_room(&self, parent: u32, name: &[u8]) -> bool {
        let Some(pkey) = self.dkey_of(parent) else {
            return false;
        };
        let p = self.probe(pkey, name);
        if p.live.is_some() {
            return true;
        }
        if self.names() as usize >= ENTRIES_MAX {
            return false;
        }
        p.gone.is_some() || (p.place.is_some() && self.arena_len + name.len() <= ARENA)
    }

    /// The most bytes a name below the directory `id` adds to its path.
    pub fn reach(&self, id: u32) -> usize {
        self.entry(id).map_or(0, |e| usize::from(e.reach))
    }

    /// `capped` is false for the build and for a move: an entry that is net zero (the name over
    /// its mark, a moved name) does not count against `ENTRIES_MAX` either way.
    fn insert_raw(
        &mut self,
        parent: u32,
        name: &[u8],
        f: Fields,
        keep: Option<u32>,
        capped: bool,
    ) -> Result<u32, Error> {
        if name.is_empty() || name.len() > NAME_MAX || f.kind == Kind::Empty {
            return Err(Error::Invalid);
        }
        let pkey = self.dkey_of(parent).ok_or(Error::Invalid)?;
        let p = self.probe(pkey, name);
        if let Some(slot) = p.live {
            return self.replace(slot, f, keep);
        }
        #[cfg(test)]
        if self.fail_inserts > 0 {
            if self.fail_inserts != u32::MAX {
                self.fail_inserts -= 1;
            }
            return Err(Error::Buckets);
        }
        if capped && self.names() as usize >= ENTRIES_MAX {
            return Err(Error::NoSpace);
        }
        if let Some(slot) = p.gone {
            // The same name again: the slot and the name in the arena are taken up.
            let dkey = self.key_for(f.kind, keep)?;
            let e = self.slots[slot];
            self.slots[slot] = Entry {
                dkey,
                reach: 0,
                live_children: 0,
                kind: f.kind,
                flags: if f.kind == Kind::Dir { UNSCANNED } else { 0 },
                layer: f.layer,
                number: f.number,
                uid: f.uid,
                gid: f.gid,
                mode: f.mode,
                ..e
            };
            self.loads[slot / WAYS] += 1;
            self.place_key(dkey, slot);
            self.count_in(f.kind);
            self.mark_parent(parent, f.kind);
            return Ok(slot as u32 + 1);
        }
        let slot = p.place.ok_or(Error::Buckets)?;
        if self.arena_len + name.len() > ARENA {
            return Err(Error::NoSpace);
        }
        let dkey = self.key_for(f.kind, keep)?;
        let at = self.arena_len;
        self.arena[at..at + name.len()].copy_from_slice(name);
        self.arena_len += name.len();
        self.slots[slot] = Entry {
            pkey,
            dkey,
            reach: 0,
            live_children: 0,
            name_at: at as u32,
            name_len: name.len() as u8,
            kind: f.kind,
            flags: if f.kind == Kind::Dir { UNSCANNED } else { 0 },
            layer: f.layer,
            number: f.number,
            uid: f.uid,
            gid: f.gid,
            mode: f.mode,
        };
        self.tags[slot] = places(hash(self.seed, pkey, name)).2;
        self.loads[slot / WAYS] += 1;
        self.place_key(dkey, slot);
        self.count_in(f.kind);
        self.mark_parent(parent, f.kind);
        Ok(slot as u32 + 1)
    }

    fn key_for(&mut self, kind: Kind, keep: Option<u32>) -> Result<u32, Error> {
        if kind != Kind::Dir {
            return Ok(0);
        }
        match keep {
            Some(key) => Ok(key),
            None => self.issue_key(),
        }
    }

    fn place_key(&mut self, dkey: u32, slot: usize) {
        if dkey != 0 {
            self.dslot[dkey as usize & (SLOTS - 1)] = slot as u32 + 1;
        }
    }

    fn count_in(&mut self, kind: Kind) {
        if kind == Kind::Whiteout {
            self.marks += 1;
        } else {
            self.live += 1;
        }
    }

    fn count_out(&mut self, kind: Kind) {
        if kind == Kind::Whiteout {
            self.marks -= 1;
        } else {
            self.live -= 1;
        }
    }

    /// Removes the entry `id`: its slot keeps the name as a gone entry. The children of a
    /// directory stay (`remove_children` takes them).
    pub fn remove(&mut self, id: u32) {
        self.take_out(id, true);
    }

    fn take_out(&mut self, id: u32, give_key_back: bool) {
        let Some(slot) = (id as usize).checked_sub(1) else {
            return;
        };
        let Some(e) = self.slots.get(slot).copied() else {
            return;
        };
        if matches!(e.kind, Kind::Empty | Kind::Gone) {
            return;
        }
        self.count_out(e.kind);
        self.slots[slot].kind = Kind::Gone;
        self.slots[slot].flags = 0;
        self.slots[slot].dkey = 0;
        self.loads[slot / WAYS] -= 1;
        if give_key_back {
            self.give_back(e.dkey);
        }
    }

    /// Removes every entry that lies in the directory `id` (a scan of the table). Returns how
    /// many it removed. The root is not a directory a removal reaches.
    pub fn remove_children(&mut self, id: u32) -> usize {
        let Some(pkey) = self.dkey_of(id).filter(|&k| k != 0) else {
            return 0;
        };
        let mut removed = 0;
        for slot in 0..SLOTS {
            let e = self.slots[slot];
            if !matches!(e.kind, Kind::Empty | Kind::Gone) && e.pkey == pkey {
                self.take_out(slot as u32 + 1, true);
                removed += 1;
            }
        }
        removed
    }

    /// Moves the entry `id` to (`parent`, `name`), which must not be held by another entry: the
    /// entry keeps its fields and flags, a directory keeps its key (so its children stay in it).
    /// Returns the new id.
    pub fn move_to(&mut self, id: u32, parent: u32, name: &[u8]) -> Result<u32, Error> {
        let e = *self.entry(id).ok_or(Error::Invalid)?;
        let fields = Fields {
            kind: e.kind,
            layer: e.layer,
            number: e.number,
            uid: e.uid,
            gid: e.gid,
            mode: e.mode,
        };
        if self.lookup(parent, name).is_some() {
            return Err(Error::Invalid);
        }
        // The new place first, so a refusal leaves the entry where it was.
        let keep = (e.kind == Kind::Dir).then_some(e.dkey);
        let new = self.insert_with(parent, name, fields, keep, false, false)?;
        self.take_out(id, false);
        if let Some(slot) = (new as usize).checked_sub(1) {
            self.slots[slot].flags = e.flags & !UNSCANNED;
            self.slots[slot].reach = e.reach;
            self.grow(parent, 1 + name.len() + usize::from(e.reach), false);
        }
        Ok(new)
    }

    fn replace(&mut self, slot: usize, f: Fields, keep: Option<u32>) -> Result<u32, Error> {
        let old = self.slots[slot];
        match (old.kind, f.kind) {
            // A name of the layer wins over its own mark of deletion, and a mark never over a name.
            (Kind::Whiteout, Kind::File | Kind::Dir | Kind::Link) => {
                let dkey = self.key_for(f.kind, keep)?;
                self.marks -= 1;
                self.live += 1;
                let e = &mut self.slots[slot];
                e.kind = f.kind;
                e.dkey = dkey;
                e.flags = if f.kind == Kind::Dir { UNSCANNED } else { 0 };
                (e.layer, e.number, e.uid, e.gid, e.mode) =
                    (f.layer, f.number, f.uid, f.gid, f.mode);
                self.place_key(dkey, slot);
            }
            (Kind::File | Kind::Dir | Kind::Link, Kind::Whiteout)
            | (Kind::Whiteout, Kind::Whiteout) => {}
            // Both a file `x` and the file of a link `x` on the volume (a cut in a rename): the file
            // wins, whichever the listing gave first.
            (Kind::File | Kind::Dir, Kind::Link) => {}
            _ => {
                let dkey = if old.kind == f.kind {
                    old.dkey
                } else {
                    let new = self.key_for(f.kind, keep)?;
                    self.give_back(old.dkey);
                    new
                };
                let e = &mut self.slots[slot];
                e.kind = f.kind;
                e.dkey = dkey;
                (e.layer, e.number, e.uid, e.gid, e.mode) =
                    (f.layer, f.number, f.uid, f.gid, f.mode);
                self.place_key(dkey, slot);
            }
        }
        Ok(slot as u32 + 1)
    }

    fn mark_parent(&mut self, parent: u32, _kind: Kind) {
        if parent == 0 {
            self.root.flags |= HAS_CHILDREN;
        } else if let Some(p) = (parent as usize)
            .checked_sub(1)
            .and_then(|s| self.slots.get_mut(s))
        {
            p.flags |= HAS_CHILDREN;
        }
    }

    /// Sets and clears flags of a directory (id 0 is the root).
    pub fn set_flags(&mut self, id: u32, set: u8, clear: u8) {
        if id == 0 {
            self.root.flags = (self.root.flags | set) & !clear;
        } else if let Some(e) = (id as usize)
            .checked_sub(1)
            .and_then(|s| self.slots.get_mut(s))
        {
            e.flags = (e.flags | set) & !clear;
        }
    }

    /// The flags of a directory.
    pub fn flags(&self, id: u32) -> u8 {
        if id == 0 {
            self.root.flags
        } else {
            self.entry(id).map_or(0, |e| e.flags)
        }
    }

    /// The owner, group and mode of a directory of the layer, the root included.
    pub fn attr(&self, id: u32) -> Option<posix_perm::Attr> {
        let (uid, gid, mode) = if id == 0 {
            (self.root.uid, self.root.gid, self.root.mode)
        } else {
            let e = self.entry(id)?;
            if e.kind != Kind::Dir {
                return None;
            }
            (e.uid, e.gid, e.mode)
        };
        Some(posix_perm::Attr {
            kind: posix_perm::Kind::Directory,
            mode: u32::from(mode),
            uid,
            gid,
        })
    }

    /// Sets the owner, group, mode and number of a directory (id 0 is the root), from what the
    /// volume says of it.
    pub fn set_attr(&mut self, id: u32, number: u64, uid: u32, gid: u32, mode: u16) {
        if id == 0 {
            self.root.number = number;
            (self.root.uid, self.root.gid, self.root.mode) = (uid, gid, mode);
        } else if let Some(e) = (id as usize)
            .checked_sub(1)
            .and_then(|s| self.slots.get_mut(s))
        {
            (e.number, e.uid, e.gid, e.mode) = (number, uid, gid, mode);
        }
    }

    /// The path of the directory or file `id` inside the layer, with a slash first (`/` for the
    /// root): the bytes at the start of `out` and their count; None when `out` is short.
    pub fn path_of(&self, id: u32, out: &mut [u8]) -> Option<usize> {
        if id == 0 {
            *out.first_mut()? = b'/';
            return Some(1);
        }
        // Walk up, writing the names from the end of `out`.
        let mut end = out.len();
        let mut at = id;
        let mut depth = 0;
        while at != 0 {
            let e = self.entry(at)?;
            let name = self.name_of(e);
            let start = end.checked_sub(name.len() + 1)?;
            let dest = out.get_mut(start..end)?;
            dest[0] = b'/';
            if name.len() <= 8 {
                for (to, from) in dest[1..].iter_mut().zip(name) {
                    *to = *from;
                }
            } else {
                dest[1..].copy_from_slice(name);
            }
            end = start;
            // The key 0 is the root, and `dslot[0]` is 0.
            at = self.dslot[e.pkey as usize & (SLOTS - 1)];
            depth += 1;
            if depth > 4096 {
                return None;
            }
        }
        let len = out.len() - end;
        out.copy_within(end.., 0);
        Some(len)
    }
}

/// An index on the heap, made without a copy on the stack (the table is over 700 KiB, more than the
/// stack of a test thread holds): every field of an empty index is zero.
#[cfg(test)]
pub fn boxed() -> std::boxed::Box<Index> {
    // SAFETY: all-zero bytes are an empty index: `EMPTY` has kind 0 (`Kind::Empty`) and zeros, the
    // counters, the seed, the keys and the root are zeros.
    unsafe { std::boxed::Box::<Index>::new_zeroed().assume_init() }
}

impl Default for Index {
    fn default() -> Self {
        Index::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> std::boxed::Box<Index> {
        super::boxed()
    }

    fn file(n: u64) -> Fields {
        Fields {
            kind: Kind::File,
            layer: 0,
            number: n,
            uid: 1000,
            gid: 1000,
            mode: 0o640,
        }
    }

    fn dir(n: u64) -> Fields {
        Fields {
            kind: Kind::Dir,
            mode: 0o755,
            ..file(n)
        }
    }

    #[test]
    fn a_name_is_found_by_its_parent_and_its_name() {
        let mut ix = index();
        let a = ix.insert(0, b"etc", dir(10)).unwrap();
        let b = ix.insert(a, b"passwd", file(11)).unwrap();
        let c = ix.insert(0, b"passwd", file(12)).unwrap();
        assert_ne!(b, c);
        assert_eq!(
            ix.lookup(a, b"passwd").map(|(id, e)| (id, e.number)),
            Some((b, 11))
        );
        assert_eq!(
            ix.lookup(0, b"passwd").map(|(id, e)| (id, e.number)),
            Some((c, 12))
        );
        assert!(ix.lookup(0, b"etc").is_some());
        assert!(ix.lookup(a, b"etc").is_none());
        assert!(ix.lookup(0, b"pass").is_none());
        assert_eq!(ix.name(b), Some(&b"passwd"[..]));
        assert_eq!(ix.counts(), (3, 0));
        assert_ne!(ix.root.flags & HAS_CHILDREN, 0);
        assert_ne!(ix.flags(a) & HAS_CHILDREN, 0);
        assert_eq!(ix.flags(b) & HAS_CHILDREN, 0);
    }

    #[test]
    fn a_name_of_the_layer_replaces_its_mark_and_a_mark_never_replaces_a_name() {
        let mut ix = index();
        let w = Fields {
            kind: Kind::Whiteout,
            ..file(0)
        };
        let id = ix.insert(0, b"x", w).unwrap();
        assert_eq!(ix.counts(), (0, 1));
        assert_eq!(ix.insert(0, b"x", file(5)).unwrap(), id);
        assert_eq!(ix.counts(), (1, 0));
        assert_eq!(ix.entry(id).unwrap().kind, Kind::File);
        assert_eq!(ix.insert(0, b"x", w).unwrap(), id);
        assert_eq!(ix.entry(id).unwrap().kind, Kind::File);
        assert_eq!(ix.counts(), (1, 0));
    }

    #[test]
    fn the_table_holds_entries_max_and_the_next_new_name_is_no_space() {
        let mut ix = index();
        let mut inserted = 0u32;
        let mut refused = None;
        for n in 0..SLOTS as u32 * 2 {
            let name = std::format!("n{n}");
            match ix.insert(0, name.as_bytes(), file(u64::from(n))) {
                Ok(_) => inserted += 1,
                Err(e) => {
                    refused = Some((n, e));
                    break;
                }
            }
        }
        // The cap or a bucket that overflowed first (at run time the cap is far from it).
        let (_, e) = refused.expect("the table fills up");
        assert!(matches!(e, Error::NoSpace | Error::Buckets));
        assert!(inserted as usize >= ENTRIES_MAX, "{inserted}");
        for n in 0..inserted {
            let name = std::format!("n{n}");
            assert!(ix.lookup(0, name.as_bytes()).is_some(), "{name}");
        }
        assert_eq!(ix.counts().0, inserted);
    }

    /// An index with `ENTRIES_MAX` entries: the names `n0` and on, the last of them a mark.
    fn full() -> std::boxed::Box<Index> {
        let mut ix = index();
        ix.reseed(0x1234_5678_9abc_def0);
        let w = Fields {
            kind: Kind::Whiteout,
            ..file(0)
        };
        for n in 0..ENTRIES_MAX - 1 {
            let name = std::format!("n{n}");
            ix.insert_shallow(0, name.as_bytes(), file(n as u64))
                .unwrap();
        }
        ix.insert_shallow(0, b"mark", w).unwrap();
        assert_eq!(ix.names() as usize, ENTRIES_MAX);
        ix
    }

    #[test]
    fn at_entries_max_a_new_name_is_no_space_and_a_net_zero_change_is_not() {
        let mut ix = full();
        let w = Fields {
            kind: Kind::Whiteout,
            ..file(0)
        };
        assert_eq!(ix.insert(0, b"fresh", file(1)), Err(Error::NoSpace));
        assert!(!ix.has_room(0, b"fresh"));
        // A name over its own mark: net zero.
        assert!(ix.has_room(0, b"mark"));
        let id = ix.insert(0, b"mark", file(2)).unwrap();
        assert_eq!(ix.entry(id).unwrap().kind, Kind::File);
        assert_eq!(ix.names() as usize, ENTRIES_MAX);
        // A mark over a name changes nothing, and a name over a name replaces it.
        assert!(ix.insert(0, b"n5", w).is_ok());
        assert!(ix.insert(0, b"n5", file(9)).is_ok());
        assert_eq!(ix.names() as usize, ENTRIES_MAX);
        // A move: net zero, so it needs only a free way.
        let before = ix.lookup(0, b"n7").unwrap().0;
        let dir = ix.entry(before).map(|e| e.kind);
        assert_eq!(dir, Some(Kind::File));
        let to = ix.move_to(before, 0, b"moved");
        assert!(to.is_ok() || to == Err(Error::Buckets), "{to:?}");
        assert!(ix.names() as usize <= ENTRIES_MAX);
        // A removal makes room for a new name again.
        let gone = ix.lookup(0, b"n8").unwrap().0;
        ix.remove(gone);
        assert!(ix.insert(0, b"fresh", file(1)).is_ok());
    }

    #[test]
    fn the_entry_is_forty_bytes() {
        assert_eq!(core::mem::size_of::<Entry>(), 40);
    }

    #[test]
    fn a_name_created_and_removed_over_and_over_never_runs_out_of_space() {
        let mut ix = index();
        ix.reseed(77);
        let mut arena = None;
        for n in 0..100_000u32 {
            let id = ix.insert(0, b"churn", file(u64::from(n))).unwrap();
            if arena.is_none() {
                arena = Some(ix.arena_len);
            }
            ix.remove(id);
            assert_eq!(ix.arena_len, arena.unwrap(), "{n}");
        }
        assert_eq!(ix.counts(), (0, 0));
    }

    /// The most live entries any bucket holds.
    fn max_load(ix: &Index) -> usize {
        ix.loads.iter().map(|&l| usize::from(l)).max().unwrap()
    }

    fn build_the_probe_set(seed: u64, marks: usize, ix: &mut Index) -> usize {
        ix.reseed(seed);
        let placed = crate::testkit::scale_set(ix, marks)
            .unwrap_or_else(|e| panic!("seed {seed:#x}: {e:?}"));
        let mut ids = std::collections::HashSet::new();
        for (parent, name, id) in &placed {
            assert_eq!(ix.lookup(*parent, name).map(|(i, _)| i), Some(*id));
            assert!(ids.insert(*id));
        }
        let (live, marked) = ix.counts();
        assert_eq!((live + marked) as usize, placed.len());
        assert_eq!(marked as usize, marks);
        max_load(ix)
    }

    #[test]
    fn the_probe_set_and_2048_marks_build_for_every_seed() {
        let mut ix = index();
        for k in 0..SEEDS as u64 {
            let load =
                build_the_probe_set(k.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x55, 2048, &mut ix);
            assert!(load <= WAYS);
        }
    }

    /// The seeds the ordinary test runs (the sweep that follows runs 100,000).
    const SEEDS: usize = 2000;

    #[test]
    #[ignore = "a sweep of 100,000 seeds"]
    fn seed_sweep() {
        let mut ix = index();
        let mut histogram = [0u32; WAYS + 1];
        for k in 0..100_000u64 {
            let load =
                build_the_probe_set(k.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xa5, 2048, &mut ix);
            histogram[load] += 1;
        }
        std::println!("max load of a bucket over 100,000 builds: {histogram:?}");
    }

    #[test]
    fn the_arena_runs_out_and_a_bad_name_or_parent_is_invalid() {
        let mut ix = index();
        let long = [b'a'; NAME_MAX];
        let mut n = 0u32;
        let err = loop {
            let mut name = long;
            name[..4].copy_from_slice(&n.to_le_bytes());
            match ix.insert(0, &name, file(1)) {
                Ok(_) => n += 1,
                Err(e) => break e,
            }
            assert!(n < 100_000);
        };
        assert_eq!(err, Error::NoSpace);
        assert!(
            n as usize >= ARENA / NAME_MAX - 8 && n as usize <= ARENA / NAME_MAX,
            "{n}"
        );
        let mut ix = index();
        assert_eq!(ix.insert(0, b"", file(1)), Err(Error::Invalid));
        assert_eq!(
            ix.insert(0, &[b'x'; NAME_MAX + 1], file(1)),
            Err(Error::Invalid)
        );
        assert_eq!(ix.insert(77, b"x", file(1)), Err(Error::Invalid));
        let f = ix.insert(0, b"f", file(1)).unwrap();
        assert_eq!(ix.insert(f, b"x", file(1)), Err(Error::Invalid));
    }

    #[test]
    fn paths_and_children_come_back_in_order() {
        let mut ix = index();
        let a = ix.insert(0, b"usr", dir(1)).unwrap();
        let b = ix.insert(a, b"lib", dir(2)).unwrap();
        let c = ix.insert(b, b"libc.so", file(3)).unwrap();
        let mut out = [0u8; 64];
        assert_eq!(ix.path_of(0, &mut out), Some(1));
        assert_eq!(&out[..1], b"/");
        let n = ix.path_of(c, &mut out).unwrap();
        assert_eq!(&out[..n], b"/usr/lib/libc.so");
        assert_eq!(ix.path_of(c, &mut [0u8; 8]), None);
        let mut pos = 0;
        let mut seen = std::vec::Vec::new();
        let mut budget = SLOTS;
        loop {
            match ix.next_child(a, pos, &mut budget) {
                NextChild::Found(next, id) => {
                    seen.push(id);
                    pos = next;
                }
                NextChild::Continue(_) => panic!("the budget covers the table"),
                NextChild::End => break,
            }
        }
        assert_eq!(seen, std::vec![b]);
        // A small budget stops where it runs out, and the next call goes on from there.
        let mut budget = 3;
        let mut pos = 0;
        let mut windows = 0;
        loop {
            match ix.next_child(a, pos, &mut budget) {
                NextChild::Found(next, _) => pos = next,
                NextChild::Continue(next) => {
                    windows += 1;
                    pos = next;
                    budget = 3;
                }
                NextChild::End => break,
            }
        }
        assert!(windows >= SLOTS / 3 - 1, "{windows}");
        assert_eq!(ix.attr(a).unwrap().mode, 0o755);
        assert!(ix.attr(c).is_none());
        assert_eq!(ix.attr(0).unwrap().mode, 0);
        ix.set_attr(0, 1, 0, 0, 0o755);
        assert_eq!(ix.attr(0).unwrap().mode, 0o755);
    }
}
