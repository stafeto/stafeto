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
//! The names live in an arena (`ARENA` bytes, each name once) as blocks: a 4-byte header (the slot
//! of the entry, the length of the name, a flag that says the block is dead) and the name. A name
//! that leaves the index leaves a dead block, and the arena is compacted in place, 1 KiB and 48
//! blocks at most in each step (`maintain_step`): a read pointer and a write pointer go up the arena, a live
//! block moves down and its entry learns the new place in the same step. An insertion that finds no
//! room in the arena is NO_SPACE too, unless compaction would make room (`Room::Later`: the change
//! answers STARTING and the client asks again).
//!
//! The entries of a directory are a doubly linked list (`head`, `prev`, `next`, all by slot), so a
//! merged listing costs the number of the children. A listing that is in the middle of the
//! list holds the directory open (`walk_enter`): an entry that leaves such a directory stays in
//! the list as a `Gone` entry (its place is taken by no other name) until the last listing lets
//! go, and `maintain_step` takes those out a few at a time.
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
/// The bytes in front of a name in the arena.
pub(crate) const HEADER: usize = 4;
/// The dead flag of a block header; the slot is in the low 16 bits and the length of the name in
/// the next 8.
const DEAD: u32 = 1 << 31;
/// What one step of compaction does at most: it reads `COMPACT_BYTES` of the arena (a block that
/// starts below this is read whole, so a step moves up to `COMPACT_BYTES + NAME_MAX + HEADER`),
/// and looks at `COMPACT_BLOCKS` blocks. The measurement under `-icount` (`cargo xtask
/// layer-steps`) shows the cost is by the block, about 200 ticks for one that moves (the blocks of
/// the scale volume are 9 bytes): 1 KiB of them took 17,300 ticks, over the margin of the gate
/// (0.9 B is 18,369); 48 blocks take about 10,000.
pub const COMPACT_BYTES: usize = if cfg!(feature = "break-layerd-compact-one-step") {
    ARENA
} else {
    1024
};
pub const COMPACT_BLOCKS: usize = if cfg!(feature = "break-layerd-compact-one-step") {
    usize::MAX
} else {
    48
};
/// The `Gone` entries one step of the sweep takes out, and the places it looks at.
pub const SWEEP_FREES: usize = 32;
pub const SWEEP_SLOTS: usize = 384;
/// The entries one step of `remove_children_step` takes out.
pub const ORPHANS_PER_STEP: usize = 32;
/// The `Gone` entries the table holds at most (the directories held open by a listing); a new name
/// over that is NO_SPACE.
pub const PENDING_MAX: usize = 2048;
/// The bytes a link's file name (`.wh..wh.lnk.`) and a mark (`.wh.`) add to a name, and the marker of
/// an opaque directory (`/.wh..wh..opq`) to a directory.
const LINK_EXTRA: usize = 12;
const MARK_EXTRA: usize = 4;
pub const OPAQUE_EXTRA: usize = 13;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Empty = 0,
    /// A name that was removed from a directory a listing holds open: the slot stays in the list
    /// of the directory (so the listing can go on from it) and keeps its name, until the last
    /// listing lets go. It follows `Empty` so that "no entry" is one comparison (`kind < 2`) in
    /// the loops that look at slots.
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

/// What `Index::room` says of a new name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Room {
    Yes,
    /// The arena is full of dead blocks: compaction makes room, ask again.
    Later,
    No,
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
    /// The bytes of the live blocks of the arena (headers included).
    live_bytes: usize,
    /// Compaction: it runs (the read and write pointers) or is wanted for an insertion that found
    /// no room.
    compacting: bool,
    starved: bool,
    c_read: usize,
    c_write: usize,
    /// The dead bytes the running compaction took on at its start and the steps it has made, and
    /// the report of the last one that ended (`take_compaction`).
    c_dead: usize,
    c_steps: u32,
    c_report: Option<(usize, u32)>,
    /// What the last step of the index did, for the report of the steps: 1 the orphans of a
    /// retired directory, 2 the sweep, 3 the compaction.
    pub last_work: u8,
    live: u32,
    marks: u32,
    /// The first entry of each directory, by key (the root is key 0), as a slot plus one; and the
    /// entry before and after each entry in its directory's list, also slot plus one.
    head: [u16; SLOTS],
    prev: [u16; SLOTS],
    next: [u16; SLOTS],
    /// The listings that hold the directory with the key open.
    walkers: [u8; SLOTS],
    /// The `Gone` entries, and the sweep that takes them out: where it stands, and whether a
    /// listing let go since it started.
    pending: u32,
    sweep_at: Option<usize>,
    sweep_dirty: bool,
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
    /// The slot of a gone entry of the same key (it is in the list of its directory still).
    gone: Option<usize>,
    /// The place a new entry would take: a free way of the less loaded bucket.
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
            live_bytes: 0,
            compacting: false,
            starved: false,
            c_read: 0,
            c_write: 0,
            c_dead: 0,
            c_steps: 0,
            c_report: None,
            last_work: 0,
            live: 0,
            marks: 0,
            head: [0; SLOTS],
            prev: [0; SLOTS],
            next: [0; SLOTS],
            walkers: [0; SLOTS],
            pending: 0,
            sweep_at: None,
            sweep_dirty: false,
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
            self.prev[from..to].fill(0);
            self.next[from..to].fill(0);
            return Some(to);
        }
        self.loads.fill(0);
        self.head.fill(0);
        self.walkers.fill(0);
        self.pending = 0;
        self.sweep_at = None;
        self.sweep_dirty = false;
        self.compacting = false;
        self.starved = false;
        self.live_bytes = 0;
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
            found.place =
                (b * WAYS..(b + 1) * WAYS).find(|&slot| self.slots[slot].kind == Kind::Empty);
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

    /// The next entry of the directory `parent` after the entry `after` (a position of a listing: 0
    /// for the start, else the id of the entry the listing stood at), looking at `budget` entries
    /// at most: each entry looked at is taken off the budget, so the cost of a request does not
    /// depend on the size of the table.
    pub fn next_child(&self, parent: u32, after: usize, budget: &mut usize) -> NextChild {
        let Some(pkey) = self.dkey_of(parent) else {
            return NextChild::End;
        };
        self.next_child_of(pkey, after, budget)
    }

    /// The key of the directory `id` (0 for the root): a listing asks for it once.
    pub fn dir_key(&self, id: u32) -> Option<u32> {
        self.dkey_of(id)
    }

    /// `next_child` for the directory with the key `pkey`; it gives names (files, directories,
    /// links), and passes marks and gone entries. A position whose entry is no longer in
    /// the directory (it was taken out after the listing let go of the directory) ends the list.
    pub fn next_child_of(&self, pkey: u32, after: usize, budget: &mut usize) -> NextChild {
        let mut at = if after == 0 {
            self.head[pkey as usize & (SLOTS - 1)]
        } else {
            match self.slots.get(after - 1) {
                Some(e) if e.kind != Kind::Empty && e.pkey == pkey => self.next[after - 1],
                _ => return NextChild::End,
            }
        };
        let mut last = after;
        while at != 0 {
            if *budget == 0 {
                return NextChild::Continue(last);
            }
            *budget -= 1;
            let slot = usize::from(at) - 1;
            last = usize::from(at);
            // A mark of deletion and a gone entry are no name: they are passed here, at the cost
            // of a look (a listing has no use for them, and a trip out to its loop for each costs
            // more than the walk).
            if !matches!(self.slots[slot].kind, Kind::Gone | Kind::Whiteout) {
                return NextChild::Found(last, u32::from(at));
            }
            at = self.next[slot];
        }
        NextChild::End
    }

    /// A listing of the directory with the key `key` stands in the middle of its list: entries
    /// that leave the directory stay as `Gone` entries until `walk_leave`. False when 255
    /// listings hold it already (the service has far fewer descriptions).
    pub fn walk_enter(&mut self, key: u32) -> bool {
        let w = &mut self.walkers[key as usize & (SLOTS - 1)];
        if *w == u8::MAX {
            return false;
        }
        *w += 1;
        true
    }

    /// A listing let go of the directory with the key `key`.
    pub fn walk_leave(&mut self, key: u32) {
        let w = &mut self.walkers[key as usize & (SLOTS - 1)];
        if *w > 0 {
            *w -= 1;
            if *w == 0 && self.pending > 0 {
                self.sweep_dirty = true;
            }
        }
    }

    /// The listings that hold the directory with the key `key`.
    pub fn walkers(&self, key: u32) -> u8 {
        self.walkers[key as usize & (SLOTS - 1)]
    }

    /// The `Gone` entries.
    pub fn pending(&self) -> u32 {
        self.pending
    }

    /// The bytes of the arena that dead blocks hold (a compaction gives them back).
    pub fn garbage(&self) -> usize {
        self.arena_len - self.live_bytes
    }

    fn link(&mut self, slot: usize, pkey: u32) {
        let k = pkey as usize & (SLOTS - 1);
        let h = self.head[k];
        self.prev[slot] = 0;
        self.next[slot] = h;
        if h != 0 {
            self.prev[usize::from(h) - 1] = slot as u16 + 1;
        }
        self.head[k] = slot as u16 + 1;
    }

    fn unlink(&mut self, slot: usize, pkey: u32) {
        let (p, n) = (self.prev[slot], self.next[slot]);
        if p != 0 {
            self.next[usize::from(p) - 1] = n;
        } else {
            self.head[pkey as usize & (SLOTS - 1)] = n;
        }
        if n != 0 {
            self.prev[usize::from(n) - 1] = p;
        }
        self.prev[slot] = 0;
        self.next[slot] = 0;
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
    /// and room in the arena. The service asks before it touches the volume. `Later` says the
    /// arena has room once the compaction ran (it is wanted from now on): the change answers
    /// STARTING.
    pub fn room(&mut self, parent: u32, name: &[u8]) -> Room {
        let Some(pkey) = self.dkey_of(parent) else {
            return Room::No;
        };
        let p = self.probe(pkey, name);
        if p.live.is_some() {
            return Room::Yes;
        }
        if self.names() as usize >= ENTRIES_MAX || self.pending as usize >= PENDING_MAX {
            return Room::No;
        }
        if p.gone.is_some() {
            return Room::Yes;
        }
        if p.place.is_none() {
            return Room::No;
        }
        self.room_bytes(HEADER + name.len())
    }

    /// `room` for new names that take `need` bytes of the arena in all (their headers included): a
    /// copy up asks for the names of its path before it copies, so a finished copy is not thrown
    /// away at the commit. While a compaction that an insertion waits for runs (`starved`), every
    /// such request waits for its end (`Later`): nothing is appended behind the pointers, and the
    /// compaction takes one step ahead of the reaper's items in each turn, so it ends within
    /// `ARENA / COMPACT_BYTES` steps at best and `ARENA / (HEADER + 1) / COMPACT_BLOCKS` at worst
    /// (the client's window of STARTING covers the time, see `posix_abi::layer`).
    pub fn room_bytes(&mut self, need: usize) -> Room {
        if self.names() as usize >= ENTRIES_MAX || self.pending as usize >= PENDING_MAX {
            return Room::No;
        }
        if self.starved {
            Room::Later
        } else if self.arena_len + need <= ARENA {
            Room::Yes
        } else if self.live_bytes + need <= ARENA {
            self.starved = true;
            Room::Later
        } else {
            Room::No
        }
    }

    /// A test hook: an insertion waits for a compaction.
    #[cfg(test)]
    pub fn starve(&mut self) {
        self.starved = true;
    }

    /// An insertion waits for the compaction of the arena.
    pub fn starved(&self) -> bool {
        self.starved
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
            self.pending -= 1;
            self.place_key(dkey, slot);
            self.count_in(f.kind);
            self.mark_parent(parent, f.kind);
            return Ok(slot as u32 + 1);
        }
        let slot = p.place.ok_or(Error::Buckets)?;
        let block = HEADER + name.len();
        if self.arena_len + block > ARENA {
            return Err(Error::NoSpace);
        }
        let dkey = self.key_for(f.kind, keep)?;
        let at = self.arena_len + HEADER;
        let header = slot as u32 | ((name.len() as u32) << 16);
        self.arena[at - HEADER..at].copy_from_slice(&header.to_le_bytes());
        self.arena[at..at + name.len()].copy_from_slice(name);
        self.arena_len += block;
        self.live_bytes += block;
        self.link(slot, pkey);
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
        if e.kind != Kind::Whiteout {
            self.lose_child(slot);
        }
        if self.walkers[e.pkey as usize & (SLOTS - 1)] > 0
            && cfg!(not(feature = "break-layerd-chain-unlink"))
        {
            // A listing stands in the directory: the entry stays in its list, gone.
            let s = &mut self.slots[slot];
            s.kind = Kind::Gone;
            s.flags = 0;
            s.dkey = 0;
            self.pending += 1;
        } else {
            self.free_slot(slot);
        }
        if give_key_back {
            self.give_back(e.dkey);
        }
    }

    /// Empties the slot: it leaves the list of its directory and its block in the arena is dead.
    fn free_slot(&mut self, slot: usize) {
        let e = self.slots[slot];
        self.unlink(slot, e.pkey);
        let at = e.name_at as usize - HEADER;
        let mut header = [0u8; HEADER];
        header.copy_from_slice(&self.arena[at..at + HEADER]);
        let header = u32::from_le_bytes(header) | DEAD;
        self.arena[at..at + HEADER].copy_from_slice(&header.to_le_bytes());
        self.live_bytes -= HEADER + usize::from(e.name_len);
        if e.kind == Kind::Gone {
            self.pending -= 1;
        }
        self.slots[slot] = EMPTY;
        self.tags[slot] = 0;
        self.loads[slot / WAYS] -= 1;
    }

    /// The directory `id` leaves the layer with what is in it: its entry is taken out and its key
    /// stays unused (no name is reachable through it from then on), so the entries that lie in it
    /// are orphans that `remove_children_step` takes out a few at a time. The key to hand to it.
    pub fn retire(&mut self, id: u32) -> Option<u32> {
        let key = self.entry(id).filter(|e| e.kind == Kind::Dir)?.dkey;
        let children = self.entry(id).is_some_and(|e| e.flags & HAS_CHILDREN != 0);
        self.take_out(id, false);
        self.dslot[key as usize & (SLOTS - 1)] = 0;
        if !children {
            // Nothing lay in it: the key is free at once, and the reaper has no orphans to take.
            self.give_back(key);
            return Some(0);
        }
        Some(key)
    }

    /// Takes out the entries that lie in the retired directory with the key `key`, `ORPHANS_PER_STEP`
    /// at most, from the head of its list. True while some are left; after the last one the key
    /// is free to be used again.
    pub fn remove_children_step(&mut self, key: u32) -> bool {
        self.last_work = 1;
        for _ in 0..ORPHANS_PER_STEP {
            let h = self.head[key as usize & (SLOTS - 1)];
            if h == 0 {
                self.give_back(key);
                return false;
            }
            let slot = usize::from(h) - 1;
            if self.slots[slot].kind == Kind::Gone {
                self.free_slot(slot);
            } else {
                self.take_out(h.into(), true);
            }
        }
        true
    }

    /// Whether `maintain_step` has work: a sweep of the `Gone` entries, or a compaction of the
    /// arena (a quarter of it is dead blocks, or an insertion found no room).
    pub fn maintenance_due(&self) -> bool {
        self.sweep_at.is_some()
            || self.sweep_dirty
            || self.compacting
            || self.starved
            || self.garbage() * 4 > ARENA
    }

    /// One step of the work in the background: the sweep first, then the compaction. True while
    /// more is due.
    pub fn maintain_step(&mut self) -> bool {
        if !self.starved && (self.sweep_at.is_some() || self.sweep_dirty) {
            self.last_work = 2;
            self.sweep_step();
        } else if self.compacting || self.starved || self.garbage() * 4 > ARENA {
            self.last_work = 3;
            self.compact_step();
        }
        self.maintenance_due()
    }

    fn sweep_step(&mut self) {
        let from = match self.sweep_at {
            Some(from) => from,
            None => {
                self.sweep_dirty = false;
                0
            }
        };
        let to = (from + SWEEP_SLOTS).min(SLOTS);
        let mut freed = 0;
        let mut slot = from;
        while slot < to && freed < SWEEP_FREES {
            let e = &self.slots[slot];
            if e.kind == Kind::Gone && self.walkers[e.pkey as usize & (SLOTS - 1)] == 0 {
                self.free_slot(slot);
                freed += 1;
            }
            slot += 1;
        }
        self.sweep_at = (slot < SLOTS).then_some(slot);
    }

    fn compact_step(&mut self) {
        if !self.compacting {
            self.compacting = true;
            self.c_read = 0;
            self.c_write = 0;
            self.c_dead = self.garbage();
            self.c_steps = 0;
        }
        self.c_steps += 1;
        let (mut read, mut blocks) = (0, 0);
        while read < COMPACT_BYTES && blocks < COMPACT_BLOCKS && self.c_read < self.arena_len {
            let at = self.c_read;
            let mut header = [0u8; HEADER];
            header.copy_from_slice(&self.arena[at..at + HEADER]);
            let header = u32::from_le_bytes(header);
            let block = HEADER + ((header >> 16) & 0xff) as usize;
            if header & DEAD == 0 {
                if at != self.c_write {
                    self.arena.copy_within(at..at + block, self.c_write);
                    self.slots[(header & 0xffff) as usize].name_at = (self.c_write + HEADER) as u32;
                }
                self.c_write += block;
            }
            self.c_read += block;
            read += block;
            blocks += 1;
        }
        if self.c_read >= self.arena_len {
            self.arena_len = self.c_write;
            self.compacting = false;
            self.starved = false;
            self.c_report = Some((self.c_dead, self.c_steps));
        }
    }

    /// The dead bytes and the steps of the compaction that ended since the last call.
    pub fn take_compaction(&mut self) -> Option<(usize, u32)> {
        self.c_report.take()
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
            self.slots[slot].live_children = e.live_children;
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
                if let Some(p) = self.parent_slot(slot) {
                    self.slots[p].live_children += 1;
                }
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

    /// The directory `parent` has a child (and a child that is no mark counts as live).
    fn mark_parent(&mut self, parent: u32, kind: Kind) {
        if parent == 0 {
            self.root.flags |= HAS_CHILDREN;
        } else if let Some(p) = (parent as usize)
            .checked_sub(1)
            .and_then(|s| self.slots.get_mut(s))
        {
            p.flags |= HAS_CHILDREN;
            if kind != Kind::Whiteout {
                p.live_children += 1;
            }
        }
    }

    /// The entry in the slot lost a child that is no mark: its directory counts one less (the
    /// directory is none when it was retired, and the root has no entry).
    fn lose_child(&mut self, slot: usize) {
        if let Some(p) = self.parent_slot(slot) {
            self.slots[p].live_children = self.slots[p].live_children.saturating_sub(1);
        }
    }

    /// The slot of the directory the entry in `slot` lies in (None for the root, and for a directory
    /// that was retired).
    fn parent_slot(&self, slot: usize) -> Option<usize> {
        let pkey = self.slots[slot].pkey;
        if pkey == 0 {
            return None;
        }
        (self.dslot[pkey as usize & (SLOTS - 1)] as usize).checked_sub(1)
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
        assert_eq!(ix.room(0, b"fresh"), Room::No);
        // A name over its own mark: net zero.
        assert_eq!(ix.room(0, b"mark"), Room::Yes);
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

    /// The entries that lie in each directory (by key), and the ones of them that are no mark.
    fn children_by_key(ix: &Index) -> (std::vec::Vec<usize>, std::vec::Vec<usize>) {
        let (mut all, mut live) = (std::vec![0; SLOTS], std::vec![0; SLOTS]);
        for e in ix.slots.iter() {
            if !matches!(e.kind, Kind::Empty | Kind::Gone) {
                all[e.pkey as usize] += 1;
                if e.kind != Kind::Whiteout {
                    live[e.pkey as usize] += 1;
                }
            }
        }
        (all, live)
    }

    #[test]
    fn the_counter_of_live_children_follows_every_insert_remove_move_mark_and_replace() {
        let mut ix = index();
        ix.reseed(5);
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n as u64) as usize
        };
        let mark = Fields {
            kind: Kind::Whiteout,
            ..file(0)
        };
        let mut dirs = std::vec![0u32];
        for round in 0..100_000 {
            let parent = dirs[next(dirs.len())];
            let name = std::format!("n{}", next(12));
            // A directory is never replaced by a file or a link (the service removes it first).
            let kind_of_name = ix.lookup(parent, name.as_bytes()).map(|(_, e)| e.kind);
            let op = next(7);
            if kind_of_name == Some(Kind::Dir) && matches!(op, 1 | 2 | 6) {
                continue;
            }
            match op {
                0 => {
                    if let Ok(id) = ix.insert(parent, name.as_bytes(), dir(1))
                        && !dirs.contains(&id)
                    {
                        dirs.push(id);
                    }
                }
                1 | 2 => {
                    let _ = ix.insert(parent, name.as_bytes(), file(1));
                }
                3 => {
                    let _ = ix.insert(parent, name.as_bytes(), mark);
                }
                4 => {
                    // Remove a name that holds nothing.
                    if let Some((id, e)) = ix.lookup(parent, name.as_bytes()) {
                        let (kind, key) = (e.kind, e.dkey);
                        let empty = kind != Kind::Dir || children_by_key(&ix).0[key as usize] == 0;
                        if empty {
                            ix.remove(id);
                            dirs.retain(|&d| d != id);
                        }
                    }
                }
                5 => {
                    // Move a name; a directory not into itself or below itself.
                    let to = dirs[next(dirs.len())];
                    let new = std::format!("m{}", next(12));
                    if let Some((id, kind)) =
                        ix.lookup(parent, name.as_bytes()).map(|(i, e)| (i, e.kind))
                    {
                        let mut below = to == id;
                        let mut up = to;
                        while up != 0 && !below {
                            up = ix.parent_of(up);
                            below = up == id;
                        }
                        if !(kind == Kind::Dir && below)
                            && let Ok(moved) = ix.move_to(id, to, new.as_bytes())
                            && kind == Kind::Dir
                        {
                            dirs.retain(|&d| d != id);
                            dirs.push(moved);
                        }
                    }
                }
                _ => {
                    // A name of another kind over the same name.
                    let _ = ix.insert(parent, name.as_bytes(), file(2));
                }
            }
            dirs.retain(|&d| d == 0 || ix.entry(d).is_some());
            if round % 997 == 0 {
                check(&ix);
                let (_, live) = children_by_key(&ix);
                for &d in dirs.iter().filter(|&&d| d != 0) {
                    let e = *ix.entry(d).unwrap();
                    assert_eq!(
                        usize::from(e.live_children),
                        live[e.dkey as usize],
                        "round {round}"
                    );
                }
            }
        }
        let (_, live) = children_by_key(&ix);
        for &d in dirs.iter().filter(|&&d| d != 0) {
            let e = *ix.entry(d).unwrap();
            assert_eq!(usize::from(e.live_children), live[e.dkey as usize]);
        }
    }

    /// Every invariant of the lists, the counters and the arena, against a scan of the table.
    fn check(ix: &Index) {
        // The list of each directory holds exactly the entries the table scan finds for its key,
        // and the links are two-way.
        let mut per_key = std::collections::HashMap::<u32, std::vec::Vec<usize>>::new();
        let (mut pending, mut live, mut marks, mut bytes) = (0u32, 0u32, 0u32, 0usize);
        let mut loads = std::vec![0usize; BUCKETS];
        for (slot, e) in ix.slots.iter().enumerate() {
            if e.kind == Kind::Empty {
                assert_eq!(ix.tags[slot], 0, "slot {slot}");
                assert_eq!((ix.prev[slot], ix.next[slot]), (0, 0), "slot {slot}");
                continue;
            }
            per_key.entry(e.pkey).or_default().push(slot);
            loads[slot / WAYS] += 1;
            bytes += HEADER + usize::from(e.name_len);
            match e.kind {
                Kind::Gone => pending += 1,
                Kind::Whiteout => marks += 1,
                _ => live += 1,
            }
            // The block of the name: its header names the slot and the length, and is not dead.
            let at = e.name_at as usize - HEADER;
            let h = u32::from_le_bytes(ix.arena[at..at + HEADER].try_into().unwrap());
            assert_eq!(h & DEAD, 0, "slot {slot}");
            assert_eq!(h & 0xffff, slot as u32);
            assert_eq!((h >> 16) & 0xff, u32::from(e.name_len));
        }
        assert_eq!((pending, live, marks), (ix.pending, ix.live, ix.marks));
        assert_eq!(bytes, ix.live_bytes);
        for (b, &l) in loads.iter().enumerate() {
            assert_eq!(l, usize::from(ix.loads[b]), "bucket {b}");
        }
        for key in 0..SLOTS as u32 {
            let want = per_key.remove(&key).unwrap_or_default();
            let mut got = std::vec::Vec::new();
            let mut at = ix.head[key as usize];
            let mut before = 0u16;
            while at != 0 {
                let slot = usize::from(at) - 1;
                assert_eq!(ix.prev[slot], before, "key {key}");
                assert_eq!(ix.slots[slot].pkey, key);
                got.push(slot);
                assert!(got.len() <= SLOTS);
                before = at;
                at = ix.next[slot];
            }
            let mut sorted = got.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, want, "key {key}");
            // A `Gone` entry waits for a listing or for the sweep.
            for &slot in &got {
                if ix.slots[slot].kind == Kind::Gone && ix.walkers[key as usize] == 0 {
                    assert!(ix.sweep_dirty || ix.sweep_at.is_some(), "key {key}");
                }
            }
        }
        // With no compaction running, the blocks of the arena tile it, and the live ones are the
        // entries' names.
        if !ix.compacting {
            let (mut at, mut live_bytes) = (0, 0);
            while at < ix.arena_len {
                let h = u32::from_le_bytes(ix.arena[at..at + HEADER].try_into().unwrap());
                let block = HEADER + ((h >> 16) & 0xff) as usize;
                if h & DEAD == 0 {
                    let e = &ix.slots[(h & 0xffff) as usize];
                    assert_ne!(e.kind, Kind::Empty);
                    assert_eq!(e.name_at as usize, at + HEADER);
                    live_bytes += block;
                }
                at += block;
            }
            assert_eq!(at, ix.arena_len);
            assert_eq!(live_bytes, ix.live_bytes);
        }
    }

    /// A listing of a directory the way the service keeps one: the position, the entries given.
    struct Listing {
        key: u32,
        after: usize,
        seen: std::vec::Vec<u32>,
        /// The ids of the entries the directory held at the start.
        must: std::vec::Vec<u32>,
        removed: std::vec::Vec<u32>,
        done: bool,
    }

    #[test]
    fn the_child_lists_and_the_arena_follow_100000_random_operations() {
        let mut ix = index();
        ix.reseed(11);
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n as u64) as usize
        };
        let mark = Fields {
            kind: Kind::Whiteout,
            ..file(0)
        };
        // Eight directories, made first; they stay.
        let mut dirs = std::vec![0u32];
        for k in 0..7 {
            dirs.push(
                ix.insert(0, std::format!("d{k}").as_bytes(), dir(1))
                    .unwrap(),
            );
        }
        let mut listings: std::vec::Vec<Listing> = std::vec::Vec::new();
        let mut max_read = 0;
        let mut compactions = 0;
        let mut finished = 0;
        for round in 0..100_000 {
            let parent = dirs[next(dirs.len())];
            let pkey = ix.dir_key(parent).unwrap();
            // Short names (so that names collide and are replaced and removed) and long ones (so
            // that the arena fills and dead blocks pile up).
            let name = if next(4) == 0 {
                let mut n = std::format!("long{}-", next(60)).into_bytes();
                n.resize(8 + next(240), b'x');
                n
            } else {
                std::format!("n{}", next(40)).into_bytes()
            };
            match next(12) {
                0..=3 => {
                    let f = if next(5) == 0 {
                        mark
                    } else {
                        file(round as u64)
                    };
                    match ix.room(parent, &name) {
                        Room::Yes => {
                            // (A name removed during a listing may or may not show if it comes
                            // back: the listing may be past its place.)
                            ix.insert(parent, &name, f).unwrap();
                        }
                        Room::Later => {
                            compactions += 1;
                            let mut guard = 0;
                            while ix.room(parent, &name) == Room::Later {
                                ix.maintain_step();
                                guard += 1;
                                assert!(guard < 100_000);
                            }
                        }
                        Room::No => {}
                    }
                }
                4..=6 => {
                    if let Some((id, e)) = ix.lookup(parent, &name).map(|(i, e)| (i, *e))
                        && e.kind != Kind::Dir
                    {
                        for l in listings.iter_mut().filter(|l| l.key == pkey) {
                            l.removed.push(id);
                        }
                        ix.remove(id);
                    }
                }
                7 => {
                    // A listing starts: every entry of the directory now is due.
                    if listings.len() < 12 && ix.walk_enter(pkey) {
                        let mut must = std::vec::Vec::new();
                        let mut at = ix.head[pkey as usize];
                        while at != 0 {
                            if !matches!(
                                ix.slots[usize::from(at) - 1].kind,
                                Kind::Gone | Kind::Whiteout
                            ) {
                                must.push(u32::from(at));
                            }
                            at = ix.next[usize::from(at) - 1];
                        }
                        listings.push(Listing {
                            key: pkey,
                            after: 0,
                            seen: std::vec::Vec::new(),
                            must,
                            removed: std::vec::Vec::new(),
                            done: false,
                        });
                    }
                }
                8 | 9 => {
                    // A listing goes on by a few entries.
                    if !listings.is_empty() {
                        let pick = next(listings.len());
                        let l = &mut listings[pick];
                        let mut budget = 1 + next(12);
                        while !l.done {
                            match ix.next_child_of(l.key, l.after, &mut budget) {
                                NextChild::Found(pos, id) => {
                                    l.seen.push(id);
                                    l.after = pos;
                                }
                                NextChild::Continue(pos) => {
                                    l.after = pos;
                                    break;
                                }
                                NextChild::End => l.done = true,
                            }
                        }
                    }
                }
                10 => {
                    // A listing ends (or is dropped half way): the ones that read the whole list
                    // saw every entry that stayed, and none twice.
                    if !listings.is_empty() {
                        let l = listings.swap_remove(next(listings.len()));
                        ix.walk_leave(l.key);
                        if l.done {
                            finished += 1;
                            let mut sorted = l.seen.clone();
                            sorted.sort_unstable();
                            sorted.dedup();
                            assert_eq!(sorted.len(), l.seen.len(), "an entry twice");
                            for id in &l.must {
                                assert!(
                                    l.seen.contains(id) || l.removed.contains(id),
                                    "round {round}: the entry {id} was lost"
                                );
                            }
                        }
                    }
                }
                _ => {
                    let read = ix.c_read;
                    let was = ix.compacting;
                    ix.maintain_step();
                    if was && ix.compacting {
                        max_read = max_read.max(ix.c_read - read);
                    }
                }
            }
            if round % 499 == 0 {
                check(&ix);
            }
        }
        for l in listings.drain(..) {
            ix.walk_leave(l.key);
        }
        while ix.maintain_step() {}
        check(&ix);
        assert_eq!(ix.pending, 0);
        assert!(max_read <= COMPACT_BYTES + NAME_MAX + HEADER, "{max_read}");
        assert!(compactions > 0 && finished > 20, "{compactions} {finished}");
    }

    #[test]
    fn an_entry_that_leaves_a_directory_a_listing_holds_stays_until_the_listing_lets_go() {
        let mut ix = index();
        let d = ix.insert(0, b"d", dir(1)).unwrap();
        let key = ix.dir_key(d).unwrap();
        for k in 0..6 {
            ix.insert(d, std::format!("e{k}").as_bytes(), file(k))
                .unwrap();
        }
        let list = |ix: &Index, from: usize| {
            let (mut out, mut p, mut b) = (std::vec::Vec::new(), from, 100);
            while let NextChild::Found(next, id) = ix.next_child_of(key, p, &mut b) {
                out.push(id);
                p = next;
            }
            out
        };
        let order = list(&ix, 0);
        assert_eq!(order.len(), 6);
        // A listing stood at the second entry; that entry and the one after it are removed.
        assert!(ix.walk_enter(key));
        let (stands, after_it) = (order[1], order[2]);
        ix.remove(stands);
        ix.remove(after_it);
        assert_eq!(ix.pending(), 2);
        assert!(ix.lookup(d, b"e0").is_some() || ix.lookup(d, b"e1").is_some());
        // The listing goes on from the entry it stood at, over the gone ones, to the rest.
        assert_eq!(list(&ix, stands as usize), order[3..].to_vec());
        // The place of a gone entry is taken by no other name.
        for k in 0..200 {
            let id = ix
                .insert(0, std::format!("other{k}").as_bytes(), file(9))
                .unwrap();
            assert!(id != stands && id != after_it);
        }
        // Nothing is taken out while the listing holds the directory.
        while ix.maintain_step() {}
        assert_eq!(ix.pending(), 2);
        ix.walk_leave(key);
        assert!(ix.maintenance_due());
        while ix.maintain_step() {}
        assert_eq!(ix.pending(), 0);
        check(&ix);
        // The same name again, with the entry still gone, comes back to its place.
        let mut ix = index();
        let d = ix.insert(0, b"d", dir(1)).unwrap();
        let key = ix.dir_key(d).unwrap();
        let a = ix.insert(d, b"a", file(1)).unwrap();
        assert!(ix.walk_enter(key));
        ix.remove(a);
        assert!(ix.lookup(d, b"a").is_none());
        assert_eq!(ix.insert(d, b"a", file(2)).unwrap(), a);
        assert_eq!(ix.pending(), 0);
        check(&ix);
    }

    #[test]
    fn a_compaction_moves_the_names_down_a_few_hundred_bytes_in_a_step() {
        let mut ix = index();
        ix.reseed(3);
        let mut ids = std::vec::Vec::new();
        for k in 0..800u32 {
            let mut name = std::format!("name{k:04}-").into_bytes();
            name.resize(100, b'y');
            ids.push((k, ix.insert(0, &name, file(u64::from(k))).unwrap(), name));
        }
        // Every other name leaves: half of the arena is dead blocks.
        for (k, id, _) in &ids {
            if k % 2 == 0 {
                ix.remove(*id);
            }
        }
        let before = ix.arena_len;
        assert_eq!(ix.garbage() * 2, before);
        // A quarter of the arena is not yet dead: no compaction is due until it is.
        assert_eq!(ix.maintenance_due(), ix.garbage() * 4 > ARENA);
        ix.starved = true;
        let mut steps = 0;
        while ix.maintain_step() {
            steps += 1;
            // The names are found by the entries at every moment of the compaction.
            for (k, _, name) in &ids {
                assert_eq!(ix.lookup(0, name).is_some(), k % 2 == 1);
            }
            check(&ix);
        }
        // A step reads `COMPACT_BYTES` and the block that crosses it.
        assert!(
            steps + 1 >= before / (COMPACT_BYTES + NAME_MAX + HEADER),
            "{steps}"
        );
        assert_eq!(ix.garbage(), 0);
        assert_eq!(ix.arena_len, 400 * 104);
        for (k, id, name) in &ids {
            if k % 2 == 1 {
                assert_eq!(ix.name(*id), Some(&name[..]));
            }
        }
        check(&ix);
    }

    #[test]
    fn while_a_compaction_waited_for_runs_every_new_name_waits_and_the_reaper_takes_its_step_first()
    {
        let mut ix = index();
        ix.reseed(9);
        let mut ids = std::vec::Vec::new();
        let mut k = 0u32;
        // Fill the arena with names of 200 bytes, then remove every other one.
        loop {
            let mut name = std::format!("n{k:05}-").into_bytes();
            name.resize(200, b'q');
            match ix.room(0, &name) {
                Room::Yes => ids.push(ix.insert(0, &name, file(1)).unwrap()),
                _ => break,
            }
            k += 1;
        }
        for (i, id) in ids.iter().enumerate() {
            if i % 2 == 0 {
                ix.remove(*id);
            }
        }
        let name = [b'z'; 150];
        // No room at the end of the arena, room after the compaction: wait.
        assert_eq!(ix.room(0, &name), Room::Later);
        assert!(ix.starved());
        // Even a short name (that would fit behind the pointers) waits until the end.
        for _ in 0..3 {
            assert_eq!(ix.room(0, b"short"), Room::Later);
            assert_eq!(ix.room_bytes(10), Room::Later);
            if !ix.maintain_step() {
                break;
            }
        }
        while ix.maintain_step() {}
        assert!(!ix.starved());
        assert_eq!(ix.room(0, &name), Room::Yes);
        assert_eq!(ix.room_bytes(1000), Room::Yes);
        check(&ix);
    }

    #[test]
    fn the_entry_is_forty_bytes() {
        assert_eq!(core::mem::size_of::<Entry>(), 40);
    }

    #[test]
    fn a_name_created_and_removed_over_and_over_never_runs_out_of_space() {
        let mut ix = index();
        ix.reseed(77);
        let mut compactions = 0;
        for n in 0..100_000u32 {
            // The service asks for room first, and a change that is told to wait is asked again
            // after the steps of the loop made the compaction.
            while ix.room(0, b"churn") == Room::Later {
                compactions += 1;
                while ix.maintain_step() {}
            }
            let id = ix.insert(0, b"churn", file(u64::from(n))).unwrap();
            ix.remove(id);
            assert!(ix.arena_len <= ARENA, "{n}");
        }
        assert!(compactions > 0);
        assert_eq!(ix.counts(), (0, 0));
        assert_eq!(ix.live_bytes, 0);
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
            n as usize >= ARENA / (NAME_MAX + HEADER) - 8
                && n as usize <= ARENA / (NAME_MAX + HEADER),
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
        // A small budget stops where it runs out, and the next call goes on from there: the cost
        // of a listing is the number of the children.
        let kids: std::vec::Vec<u32> = (0..10)
            .map(|k| {
                ix.insert(a, std::format!("k{k}").as_bytes(), file(k))
                    .unwrap()
            })
            .collect();
        let mut budget = 3;
        let mut pos = 0;
        let mut windows = 0;
        let mut seen = std::vec::Vec::new();
        loop {
            match ix.next_child(a, pos, &mut budget) {
                NextChild::Found(next, id) => {
                    pos = next;
                    seen.push(id);
                }
                NextChild::Continue(next) => {
                    windows += 1;
                    pos = next;
                    budget = 3;
                }
                NextChild::End => break,
            }
        }
        assert_eq!(seen.len(), 11);
        assert!(kids.iter().all(|k| seen.contains(k)));
        assert!(windows <= 5, "{windows}");
        assert_eq!(ix.attr(a).unwrap().mode, 0o755);
        assert!(ix.attr(c).is_none());
        assert_eq!(ix.attr(0).unwrap().mode, 0);
        ix.set_attr(0, 1, 0, 0, 0o755);
        assert_eq!(ix.attr(0).unwrap().mode, 0o755);
    }
}
