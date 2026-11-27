// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The index of the names of the live layer (the layered file system, section 5.1): an open
//! table of `SLOTS` entries with at most `PROBES` probes for a name, keyed by the pair (the id of
//! the directory above, the name). The id of an entry is its slot plus one, and the root of the
//! layer is id 0. The service is the only writer of the names of `/.layers`, so the index is exact
//! without a journal; nothing is ever removed in this part, which keeps a probe sequence unbroken.
//! The names live in an arena (`ARENA` bytes, each name once); an insertion that finds no free slot
//! within the probes, or no room in the arena, is NO_SPACE (ENOSPC for the program that created
//! the name).
//!
//! An entry has the layer it lies in, its kind (a file, a directory, a symbolic link, or the mark of
//! a deletion: the file `.wh.<name>` of the layer says "the name of the lower set is gone"; a link
//! is the file `.wh..wh.lnk.<name>` and its text), the number the
//! data file service gave it and, for a directory, its owner, group and mode (the walk of a path
//! checks the right to search a directory of the layer of the user from these, with no call), and
//! the flags OPAQUE (the directory holds the file `.wh..wh..opq`: the lower set shows through it
//! no more) and HAS_CHILDREN (a name of the layer lies in it).

pub const SLOTS: usize = 8192;
pub const PROBES: usize = 8;
pub const ARENA: usize = 256 * 1024;
pub const NAME_MAX: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Empty = 0,
    Whiteout = 1,
    File = 2,
    Dir = 3,
    /// A symbolic link: littlefs has none, so the layer keeps it as the file `.wh..wh.lnk.<name>`
    /// whose bytes are the target.
    Link = 4,
    /// A name that was removed: the slot keeps its name for a probe that passes it.
    Gone = 5,
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
    name_at: u32,
    name_len: u8,
    pub kind: Kind,
    pub flags: u8,
    pub layer: u8,
    pub number: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
}

const EMPTY: Entry = Entry {
    pkey: 0,
    dkey: 0,
    name_at: 0,
    name_len: 0,
    kind: Kind::Empty,
    flags: 0,
    layer: 0,
    number: 0,
    uid: 0,
    gid: 0,
    mode: 0,
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
    /// No free slot within `PROBES` probes, or no room for the name in the arena.
    NoSpace,
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
    arena: [u8; ARENA],
    arena_len: usize,
    live: u32,
    marks: u32,
    /// The slot plus one of the directory with the key `k`, at `dslot[k]` (0 for a key in no use).
    dslot: [u32; SLOTS + 1],
    /// The keys issued so far, and the keys given back, which are used again first.
    keys_issued: u32,
    free_keys: [u32; SLOTS],
    free_len: usize,
    pub root: Root,
}

fn hash(parent: u32, name: &[u8]) -> usize {
    // FNV-1a over the key and the name, folded into the table.
    let mut h: u32 = 0x811c_9dc5;
    for b in parent.to_le_bytes().iter().chain(name) {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    // The final mix of murmur3, so that names that differ in one byte spread over the table.
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h as usize
}

impl Index {
    pub const fn new() -> Index {
        Index {
            slots: [EMPTY; SLOTS],
            arena: [0; ARENA],
            arena_len: 0,
            live: 0,
            marks: 0,
            dslot: [0; SLOTS + 1],
            keys_issued: 0,
            free_keys: [0; SLOTS],
            free_len: 0,
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

    /// Empties the index (the build starts again).
    pub fn clear(&mut self) {
        self.slots.fill(EMPTY);
        self.dslot.fill(0);
        self.arena_len = 0;
        self.live = 0;
        self.marks = 0;
        self.keys_issued = 0;
        self.free_len = 0;
        self.root = Index::new().root;
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
            Some(e) if e.pkey != 0 => self.dslot[e.pkey as usize],
            _ => 0,
        }
    }

    /// The slot of (`pkey`, `name`) within the probes.
    fn find(&self, pkey: u32, name: &[u8]) -> Option<usize> {
        let start = hash(pkey, name);
        for i in 0..PROBES {
            let slot = (start + i) & (SLOTS - 1);
            let e = &self.slots[slot];
            match e.kind {
                Kind::Empty => return None,
                Kind::Gone => {}
                _ if e.pkey == pkey && self.name_of(e) == name => return Some(slot),
                _ => {}
            }
        }
        None
    }

    /// The entry of `name` in the directory `parent`, with its id; a gone entry is none.
    pub fn lookup(&self, parent: u32, name: &[u8]) -> Option<(u32, &Entry)> {
        let slot = self.find(self.dkey_of(parent)?, name)?;
        Some((slot as u32 + 1, &self.slots[slot]))
    }

    /// The entry with id `id` (not the root).
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
        if self.keys_issued as usize >= SLOTS {
            return Err(Error::NoSpace);
        }
        self.keys_issued += 1;
        Ok(self.keys_issued)
    }

    fn give_back(&mut self, key: u32) {
        if key != 0 {
            self.dslot[key as usize] = 0;
            self.free_keys[self.free_len] = key;
            self.free_len += 1;
        }
    }

    /// Inserts a name. A mark of deletion over a name of the layer changes nothing, and a name over
    /// a mark replaces it (the layer says the name is there). Returns the id.
    pub fn insert(&mut self, parent: u32, name: &[u8], f: Fields) -> Result<u32, Error> {
        self.insert_with(parent, name, f, None)
    }

    /// `insert`, giving a directory the key `keep` (a directory that moved) when there is one.
    fn insert_with(
        &mut self,
        parent: u32,
        name: &[u8],
        f: Fields,
        keep: Option<u32>,
    ) -> Result<u32, Error> {
        if name.is_empty() || name.len() > NAME_MAX || f.kind == Kind::Empty {
            return Err(Error::Invalid);
        }
        let pkey = self.dkey_of(parent).ok_or(Error::Invalid)?;
        let start = hash(pkey, name);
        let mut free = None;
        for i in 0..PROBES {
            let slot = (start + i) & (SLOTS - 1);
            let e = self.slots[slot];
            match e.kind {
                Kind::Empty => {
                    free.get_or_insert(slot);
                    break;
                }
                Kind::Gone => {
                    if e.pkey == pkey && self.name_of(&e) == name {
                        // The same name again: the slot and the name in the arena are taken up.
                        let dkey = self.key_for(f.kind, keep)?;
                        self.slots[slot] = Entry {
                            dkey,
                            kind: f.kind,
                            flags: if f.kind == Kind::Dir { UNSCANNED } else { 0 },
                            layer: f.layer,
                            number: f.number,
                            uid: f.uid,
                            gid: f.gid,
                            mode: f.mode,
                            ..e
                        };
                        self.place_key(dkey, slot);
                        self.count_in(f.kind);
                        self.mark_parent(parent);
                        return Ok(slot as u32 + 1);
                    }
                    free.get_or_insert(slot);
                }
                _ if e.pkey == pkey && self.name_of(&e) == name => {
                    return self.replace(slot, f, keep);
                }
                _ => {}
            }
        }
        let slot = free.ok_or(Error::NoSpace)?;
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
        self.place_key(dkey, slot);
        self.count_in(f.kind);
        self.mark_parent(parent);
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
            self.dslot[dkey as usize] = slot as u32 + 1;
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
        let new = self.insert_with(parent, name, fields, keep)?;
        self.take_out(id, false);
        if let Some(slot) = (new as usize).checked_sub(1) {
            self.slots[slot].flags = e.flags & !UNSCANNED;
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

    fn mark_parent(&mut self, parent: u32) {
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
            out[start] = b'/';
            out[start + 1..end].copy_from_slice(name);
            end = start;
            at = self.parent_of(at);
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

impl Default for Index {
    fn default() -> Self {
        Index::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> std::boxed::Box<Index> {
        std::boxed::Box::new(Index::new())
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
    fn a_name_that_finds_no_free_slot_in_eight_probes_is_no_space() {
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
        let (_, e) = refused.expect("the table fills up");
        assert_eq!(e, Error::NoSpace);
        // Open addressing with eight probes fills a good part of the table before the first miss,
        // and every name inserted is found again.
        assert!(inserted > SLOTS as u32 / 8, "{inserted}");
        for n in 0..inserted {
            let name = std::format!("n{n}");
            assert!(ix.lookup(0, name.as_bytes()).is_some(), "{name}");
        }
        assert_eq!(ix.counts().0, inserted);
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
