// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The names of the volume as the server sees them: the attribute of an entry, the search of a path
//! with the rights of the caller, the memory of directories and of their counts, the creation, removal
//! and renaming of names, the changes of attributes, and the listing of a directory. Part of
//! `server`, split out of it; the tables it works on are the server's.

use super::*;

impl Server {
    // ---- The attribute of an entry, the search of a path, and what a directory holds ----

    /// The kind and size of the entry at `path`, and its record, in one lookup (no right is checked:
    /// the callers that name a description, which has its path from the server, use this).
    pub(super) fn load<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        path: &[u8],
    ) -> Res<(crate::fs::Info, Record)> {
        let mut buf = [0u8; WALK_EACH];
        let (info, size) = volume(fs.stat_attr(path, ATTR_TYPE, &mut buf))?;
        Ok((info, record_of(info.kind, path, size, &buf)))
    }

    /// The kind and record of the entry a change of attributes names: by path, with search on every
    /// directory of it; by description (the path is the server's own), with no walk of rights.
    fn load_for_change<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        by_path: bool,
        path: &[u8],
    ) -> Res<(crate::fs::Info, Record)> {
        if by_path {
            let found = self.lookup(fs, caller, false, path)?;
            found.last.ok_or_else(|| p::code(p::NO_ENTRY))
        } else {
            self.load(fs, path)
        }
    }

    /// Walks `path` once, from the root, and checks search permission (rule 3) with the real or the
    /// effective identifiers on every directory the path passes, before any answer about a name:
    /// a directory that is refused answers ACCESS whatever is below it, so a denied ancestor reveals
    /// nothing about the names under it. The walk gives the kind and record of the root and of every
    /// entry (`Fs::path_attrs`, about 3 reads a component, no lookup repeated).
    ///
    /// The path is canonical: the service takes no `.` or `..` component (`canonical` drops `.` and
    /// answers INVALID for `..`; the POSIX layer normalises a path before it sends it, and littlefs
    /// would resolve `/a/ghost/..` lexically without looking `ghost` up), so the entries of the
    /// walk are the root and one for each component.
    ///
    /// The name at the end may be missing: `last` is then None and `parent` is the directory it
    /// would be in (a create checks write and search on it). A missing directory above it is
    /// NO_ENTRY, a file in the middle of the path NOT_DIRECTORY.
    pub(super) fn lookup<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        real: bool,
        path: &[u8],
    ) -> Res<Found> {
        let comps = if path == b"/" {
            0
        } else {
            path.iter().filter(|&&b| b == b'/').count()
        };
        let (count, status) = fs.path_attrs(
            path,
            ATTR_TYPE,
            &mut self.walk.entries,
            &mut self.walk.bytes,
            WALK_EACH,
        );
        let id = caller.identity(real);
        // Search on every ancestor the walk reached, before anything is said of what follows.
        for i in 0..count.min(comps) {
            let kind = volume(self.walk.entries[i].kind())?;
            if kind != Kind::Directory {
                return Err(p::code(p::NOT_DIRECTORY));
            }
            let entry = self.walk_record(path, i, kind, comps);
            if !perm::permits(id, &entry.attr.perm(Kind::Directory), perm::EXEC) {
                return Err(p::code(p::ACCESS));
            }
        }
        let parent = |this: &Self| {
            (comps > 0 && count >= comps)
                .then(|| this.walk_record(path, comps - 1, Kind::Directory, comps))
        };
        match status {
            Ok(info) => {
                let entry = self.walk_record(path, comps, info.kind, comps);
                Ok(Found {
                    last: Some((info, entry)),
                    parent: parent(self),
                })
            }
            // Only the last name is missing: every ancestor was reached.
            Err(Error::NoEntry) if count == comps && comps > 0 => Ok(Found {
                last: None,
                parent: parent(self),
            }),
            Err(Error::NoEntry) => Err(p::code(p::NO_ENTRY)),
            Err(e) => Err(status_of(e)),
        }
    }

    /// The record of entry `i` of the last walk of `path` (`comps` components). An attribute of
    /// exactly `ATTR_LEN` bytes is trusted; any other length is a record this service does not know
    /// (it comes back zero-padded and would read as user 0), and no attribute is the default.
    fn walk_record(&self, path: &[u8], i: usize, kind: Kind, comps: usize) -> Record {
        let prefix = walk_prefix(path, i, comps);
        let size = self.walk.entries[i].attr_size().unwrap_or(Some(usize::MAX));
        let at = i * WALK_EACH;
        record_of(kind, prefix, size, &self.walk.bytes[at..at + WALK_EACH])
    }

    /// What the server remembers of the counts of the directories at `path` or under it is dropped:
    /// the names under them moved.
    pub(super) fn forget(&mut self, path: &[u8]) {
        for c in &mut self.counts {
            if c.used && within(c.path.get(), path) {
                c.used = false;
            }
        }
    }

    /// The entries of the directory at `dir`, from the memory of the server or by one scan of the
    /// directory. TABLE_FULL when every directory place of the volume is held and the scan cannot be
    /// made.
    pub(super) fn dir_entries<D: Device>(&mut self, fs: &mut Fs<'_, D>, dir: &[u8]) -> Res<usize> {
        if let Some(c) = self.counts.iter().find(|c| c.used && c.path.get() == dir) {
            return Ok(c.entries);
        }
        let slot = match fs.opendir(dir) {
            Ok(slot) => slot,
            // Every directory place of the volume is held by a description: the count cannot be
            // made, and a create is not let through unchecked.
            Err(Error::NoMemory) => return Err(p::code(p::TABLE_FULL)),
            Err(e) => return Err(status_of(e)),
        };
        let mut n = 0;
        loop {
            match fs.readdir(slot) {
                Ok(Some(e)) => {
                    let name = e.name();
                    if name != b"." && name != b".." && !(dir == b"/" && name == &ORPHANS[1..]) {
                        n += 1;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = fs.closedir(slot);
                    return Err(status_of(e));
                }
            }
        }
        volume(fs.closedir(slot))?;
        let hand = self.counts_hand;
        self.counts_hand = (hand + 1) % COUNT_CACHE;
        self.counts[hand].used = true;
        self.counts[hand].path.set(dir);
        self.counts[hand].entries = n;
        Ok(n)
    }

    /// A name is about to be added to `dir`: NO_SPACE when it holds `DIR_ENTRIES_MAX` entries.
    pub(super) fn room_in_dir<D: Device>(&mut self, fs: &mut Fs<'_, D>, dir: &[u8]) -> Res<()> {
        if self.dir_entries(fs, dir)? >= DIR_ENTRIES_MAX {
            Err(p::code(p::NO_SPACE))
        } else {
            Ok(())
        }
    }

    /// The remembered count of `dir` follows a name added (`+1`) or removed (`-1`).
    pub(super) fn count_add(&mut self, dir: &[u8], delta: isize) {
        if let Some(c) = self
            .counts
            .iter_mut()
            .find(|c| c.used && c.path.get() == dir)
        {
            c.entries = (c.entries as isize + delta).max(0) as usize;
        }
    }

    /// The pairs and the directories of the volume are counted (one fetch of each pair, about two
    /// reads for each): the exact count replaces the estimate and the count of directories, a
    /// refusal that was waiting for a removal is forgotten, and the line of the count is left for
    /// the worker to tell (`take_pairs_report`). At the mount, at each refresh walk and before the
    /// first refusal.
    pub fn recount<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> Res<(u64, u64)> {
        let (pairs, dirs) = volume(fs.metadata_pairs())?;
        // A count that disagrees with the directories the service followed catches a change it did
        // not see (a rollback that failed, an orphan of a cut commit): the worker says so in a line.
        let mismatch = self
            .pairs
            .dirs
            .filter(|tracked| *tracked != dirs)
            .map(|tracked| (tracked, dirs));
        self.pairs = Pairs {
            known: Some(pairs),
            since: 0,
            dirs: Some(dirs),
            refused: false,
            dirs_refused: false,
            report: Some((pairs, dirs)),
            mismatch,
        };
        Ok((pairs, dirs))
    }

    /// The tracked and the counted directories when the last recount found them different, once.
    pub fn take_dirs_mismatch(&mut self) -> Option<(u64, u64)> {
        self.pairs.mismatch.take()
    }

    /// The count the last `recount` made, once: the worker tells it in a line.
    pub fn take_pairs_report(&mut self) -> Option<(u64, u64)> {
        self.pairs.report.take()
    }

    /// MKDIR is about to make a directory: NO_SPACE when the volume has `DIRS_MAX` directories or
    /// more. The count is exact (followed by every MKDIR and RMDIR since the last count), so the
    /// refusal needs no recount.
    pub(super) fn room_for_dir<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> Res<()> {
        let dirs = match self.pairs.dirs {
            Some(dirs) => dirs,
            None => self.recount(fs)?.1,
        };
        if dirs < self.dirs_max {
            return Ok(());
        }
        // The tracked count can be over the volume's (a rollback that could not remove the name, an
        // orphan the next write repairs): a refusal is made on an exact count, as the pairs' is, and
        // after a confirmed refusal the service does not count again until a removal.
        if self.pairs.dirs_refused {
            return Err(p::code(p::NO_SPACE));
        }
        let (_, dirs) = self.recount(fs)?;
        if dirs >= self.dirs_max {
            self.pairs.dirs_refused = true;
            Err(p::code(p::NO_SPACE))
        } else {
            Ok(())
        }
    }

    /// A commit that may make a pair is about to be done (MKDIR, the creation of a file, a RENAME
    /// into another directory, at the cap a RENAME to a longer name): NO_SPACE when the volume has
    /// `PAIRS_MAX` pairs or more. The estimate (the last count plus what the commits since may have
    /// added) is kept below the cap with no read. When it reaches the cap, or there is no count yet,
    /// the pairs are counted and the exact count decides: a refusal is never made on the estimate.
    /// After a refusal on an exact count the service does not count again until a removal, so a
    /// refused loop costs one count. A removal, which is never refused, is what makes room.
    pub(super) fn room_for_pair<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> Res<()> {
        if let Some(known) = self.pairs.known
            && known + self.pairs.since < self.pairs_max
        {
            return Ok(());
        }
        if self.pairs.refused {
            return Err(p::code(p::NO_SPACE));
        }
        let (pairs, _) = self.recount(fs)?;
        if pairs >= self.pairs_max {
            self.pairs.refused = true;
            Err(p::code(p::NO_SPACE))
        } else {
            Ok(())
        }
    }

    /// Commits that may add pairs: `n` more to the estimate.
    pub(super) fn pairs_added(&mut self, n: u64) {
        self.pairs.since += n;
    }

    /// A directory was made (+1) or removed (-1); a removal also lets the service count again.
    pub(super) fn dirs_changed(&mut self, delta: i64) {
        if let Some(d) = self.pairs.dirs.as_mut() {
            *d = d.saturating_add_signed(delta);
        }
        if delta < 0 {
            self.pairs.refused = false;
            self.pairs.dirs_refused = false;
        }
    }

    /// A name was removed: a refusal that waited for a removal may be tried again.
    pub(super) fn removed(&mut self) {
        self.pairs.refused = false;
        self.pairs.dirs_refused = false;
    }

    /// The reserve (rule 14): a caller other than user 0 gets NO_SPACE with fewer than
    /// `RESERVE_BLOCKS` free blocks, for a create, a rename and a change of attributes: each may
    /// split or compact a pair of metadata blocks, which takes blocks the superuser needs to remove
    /// what fills the volume.
    pub(super) fn reserve_allows<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
    ) -> Res<()> {
        if caller.is_superuser() || volume(fs.free_blocks())? >= RESERVE_BLOCKS {
            Ok(())
        } else {
            Err(p::code(p::NO_SPACE))
        }
    }

    /// The directory at `path` has its `mtime` and `ctime` set to now (rule 10): a name was added,
    /// removed or renamed in it. A record this service cannot rewrite is left as it is.
    /// `entry` is the record of the directory as the walk of the call read it: the call changed no
    /// attribute of it since, so it is not read again.
    pub(super) fn touch<D: Device>(&mut self, fs: &mut Fs<'_, D>, path: &[u8], entry: Record) {
        if entry.standing != Standing::Foreign {
            let mut attr = entry.attr;
            attr.mtime = self.now;
            attr.ctime = self.now;
            let _ = fs.setattr(path, ATTR_TYPE, &attr.to_bytes());
        }
    }

    /// The next file number: from the block of numbers reserved in the counter at the root, which is
    /// raised by one block with one commit when it is used up.
    pub(super) fn next_ino<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> Res<u64> {
        if self.ino_next >= self.ino_end {
            let mut old = [0u8; 8];
            let last = match fs.getattr(b"/", ATTR_COUNTER_TYPE, &mut old) {
                Ok(8) => u64::from_le_bytes(old),
                Ok(_) | Err(Error::NoAttr) => 2,
                Err(e) => return Err(status_of(e)),
            }
            .max(2);
            let end = last + INO_BLOCK;
            volume(fs.setattr(b"/", ATTR_COUNTER_TYPE, &end.to_le_bytes()))?;
            self.ino_next = last;
            self.ino_end = end;
        }
        let ino = self.ino_next;
        self.ino_next += 1;
        Ok(ino)
    }

    /// The record of a new entry made by `caller` in `parent` (rule 5): the owner and the group by
    /// the rules of `posix-perm`, the mode as it came (the layer applied the umask), a new number,
    /// every time now.
    pub(super) fn new_record<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        parent: &perm::Attr,
        kind: Kind,
        mode: u32,
    ) -> Res<Attr> {
        let pkind = match kind {
            Kind::File => perm::Kind::File,
            Kind::Directory => perm::Kind::Directory,
        };
        let made = perm::creation(caller.identity(false), parent, pkind, mode, 0);
        let ino = self.next_ino(fs)?;
        Ok(Attr {
            uid: made.uid,
            gid: made.gid,
            mode: made.mode,
            ino,
            atime: self.now,
            mtime: self.now,
            ctime: self.now,
        })
    }

    pub(super) fn do_mkdir<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        mode: u32,
        path: &[u8],
    ) -> Res<()> {
        if path == b"/" {
            return Err(p::code(p::EXISTS));
        }
        let found = self.lookup(fs, caller, false, path)?;
        let (parent, _) = split(path);
        let parent_record = found.parent.ok_or_else(|| p::code(p::NO_ENTRY))?;
        let parent_attr = parent_record.attr.perm(Kind::Directory);
        perm::place_allowed(caller.identity(false), &parent_attr, None).map_err(denied)?;
        if found.last.is_some() {
            return Err(p::code(p::EXISTS));
        }
        self.room_in_dir(fs, parent)?;
        self.room_for_dir(fs)?;
        self.room_for_pair(fs)?;
        self.reserve_allows(fs, caller)?;
        let record = self.new_record(fs, caller, &parent_attr, Kind::Directory, mode)?;
        volume(fs.mkdir(path))?;
        self.pairs_added(2);
        self.dirs_changed(1);
        // The record is written in the same job as the name; a cut between the two commits leaves
        // an entry with no record, which reads as the closed default. When the record cannot be
        // written the name goes again, and so does the directory from the count (a removal that
        // failed leaves it in the count until the next recount, which tells the difference).
        #[cfg(test)]
        let written = if self.fail_record {
            Err(Error::Io)
        } else {
            fs.setattr(path, ATTR_TYPE, &record.to_bytes())
        };
        #[cfg(not(test))]
        let written = fs.setattr(path, ATTR_TYPE, &record.to_bytes());
        if let Err(e) = written {
            if fs.remove(path).is_ok() {
                self.dirs_changed(-1);
            }
            return Err(status_of(e));
        }
        self.count_add(parent, 1);
        self.touch(fs, parent, parent_record);
        Ok(())
    }

    pub(super) fn do_remove<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        rmdir: bool,
        path: &[u8],
    ) -> Res<()> {
        if path == b"/" {
            return Err(p::code(p::BUSY));
        }
        let found = self.lookup(fs, caller, false, path)?;
        let (parent, _) = split(path);
        let parent_record = found.parent.ok_or_else(|| p::code(p::NO_ENTRY))?;
        let parent_attr = parent_record.attr.perm(Kind::Directory);
        let (info, entry) = found.last.ok_or_else(|| p::code(p::NO_ENTRY))?;
        perm::remove_allowed(
            caller.identity(false),
            &parent_attr,
            &entry.attr.perm(info.kind),
        )
        .map_err(denied)?;
        match (rmdir, info.kind) {
            (false, Kind::Directory) => return Err(p::code(p::IS_DIRECTORY)),
            (true, Kind::File) => return Err(p::code(p::NOT_DIRECTORY)),
            _ => {}
        }
        if info.kind == Kind::Directory {
            if self.dir_in_use(path) {
                return Err(p::code(p::BUSY));
            }
            volume(fs.remove(path))?;
            // The two blocks of its pair come back at the next walk.
            fs.note_freed_blocks(2);
            self.forget(path);
        } else {
            match self.node_at(path) {
                // Open: the descriptions keep the file, which leaves the tree; its blocks are
                // counted when the last description closes (`node_unref`).
                Some(ni) => self.orphan(fs, ni, None)?,
                None => {
                    volume(fs.remove(path))?;
                    fs.note_freed_file(u64::from(info.size));
                }
            }
        }
        self.count_add(parent, -1);
        if info.kind == Kind::Directory {
            self.dirs_changed(-1);
        }
        self.removed();
        self.touch(fs, parent, parent_record);
        Ok(())
    }

    pub(super) fn do_rename<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        from: &[u8],
        to: &[u8],
    ) -> Res<()> {
        if from == b"/" || to == b"/" {
            return Err(p::code(p::INVALID));
        }
        visible(from)?;
        visible(to)?;
        let from_found = self.lookup(fs, caller, false, from)?;
        let to_found = self.lookup(fs, caller, false, to)?;
        let (from_parent, _) = split(from);
        let (to_parent, _) = split(to);
        let from_record = from_found.parent.ok_or_else(|| p::code(p::NO_ENTRY))?;
        let to_record = to_found.parent.ok_or_else(|| p::code(p::NO_ENTRY))?;
        let from_attr = from_record.attr.perm(Kind::Directory);
        let to_attr = to_record.attr.perm(Kind::Directory);
        let (source, source_entry) = from_found.last.ok_or_else(|| p::code(p::NO_ENTRY))?;
        // A directory into its own subtree is INVALID; a file has no subtree (a path through it
        // already failed the search with NOT_DIRECTORY).
        if source.kind == Kind::Directory && within(to, from) && to != from {
            return Err(p::code(p::INVALID));
        }
        let replaced = to_found.last.map(|(info, _)| info);
        let target_entry = match to_found.last {
            Some((target, _)) if target.kind != source.kind => {
                return Err(p::code(match target.kind {
                    Kind::Directory => p::IS_DIRECTORY,
                    Kind::File => p::NOT_DIRECTORY,
                }));
            }
            Some((_, entry)) => Some(entry),
            None => None,
        };
        perm::rename_allowed(
            caller.identity(false),
            &from_attr,
            &source_entry.attr.perm(source.kind),
            &to_attr,
            target_entry
                .as_ref()
                .map(|e| e.attr.perm(source.kind))
                .as_ref(),
            from_parent == to_parent,
        )
        .map_err(denied)?;
        // A rename to itself succeeds and does nothing (XSH `rename()`): no count moves, no time.
        if from == to {
            return Ok(());
        }
        // A rename may split a directory's pair of blocks: below the reserve it is the superuser's.
        self.reserve_allows(fs, caller)?;
        // A name added to another directory counts toward its cap.
        if from_parent != to_parent && target_entry.is_none() {
            self.room_in_dir(fs, to_parent)?;
        }
        // A name in another directory, or a longer name in the same one, may split a pair: refused
        // at the cap of pairs, on an exact count. A name that does not grow in its own directory
        // makes no pair and is never refused.
        let adds_pair = target_entry.is_none()
            && (from_parent != to_parent || split(to).1.len() > split(from).1.len());
        if adds_pair {
            self.room_for_pair(fs)?;
        }
        if source.kind == Kind::Directory {
            if self.dir_in_use(from) || self.dir_in_use(to) {
                return Err(p::code(p::BUSY));
            }
            volume(fs.rename(from, to))?;
            self.forget(from);
            self.forget(to);
        } else {
            if from == to {
                return Ok(());
            }
            // A file that the rename replaces and that is open goes under the orphans first,
            // marked with its home name; if the second commit fails it goes back.
            let target = self.node_at(to);
            if let Some(t) = target {
                self.orphan(fs, t, Some(to))?;
            }
            #[cfg(test)]
            let refused = self.fail_second;
            #[cfg(not(test))]
            let refused = false;
            let moved = match self.node_at(from) {
                _ if refused => Err(p::code(p::NO_SPACE)),
                Some(ni) => self.move_node(fs, ni, to, None),
                None => volume(fs.rename(from, to)),
            };
            // A file the rename replaced and that nobody had open gave its blocks back.
            if let (Ok(()), None, Some(old)) = (&moved, target, replaced) {
                fs.note_freed_file(u64::from(old.size));
            }
            if let Some(t) = target {
                let at = self.nodes[t].path;
                match &moved {
                    Ok(()) => {
                        let _ = fs.removeattr(at.get(), ATTR_HOME);
                    }
                    Err(_) => {
                        let _ = self.move_node(fs, t, to, None);
                        let _ = fs.removeattr(to, ATTR_HOME);
                    }
                }
            }
            moved?;
        }
        if adds_pair {
            self.pairs_added(1);
        }
        // A directory the rename replaced is gone, and the removal of a name lets the count run again.
        if target_entry.is_some() {
            if replaced.is_some_and(|r| r.kind == Kind::Directory) {
                self.dirs_changed(-1);
            }
            self.removed();
        }
        if from_parent != to_parent {
            self.count_add(from_parent, -1);
            if target_entry.is_none() {
                self.count_add(to_parent, 1);
            }
        } else if target_entry.is_some() {
            self.count_add(to_parent, -1);
        }
        if target_entry.is_some() && from_parent != to_parent {
            // The replaced name is gone from the destination and the source's name came: no change.
        }
        self.touch(fs, from_parent, from_record);
        if to_parent != from_parent {
            self.touch(fs, to_parent, to_record);
        }
        Ok(())
    }

    /// CHMOD and FCHMOD (rule 7).
    pub(super) fn change_mode<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        by_path: bool,
        path: &[u8],
        mode: u32,
    ) -> Res<()> {
        let (info, mut entry) = self.load_for_change(fs, caller, by_path, path)?;
        let node = self.fold_into(path, &mut entry);
        let new = perm::chmod_result(caller.identity(false), &entry.attr.perm(info.kind), mode)
            .map_err(denied)?;
        self.reserve_allows(fs, caller)?;
        self.write_changed(fs, path, info.kind, (entry, node), |a, now| {
            a.mode = new;
            a.ctime = now;
        })
    }

    /// CHOWN and FCHOWN (rule 7): `UID_KEEP` leaves a number as it is.
    pub(super) fn change_owner<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        by_path: bool,
        path: &[u8],
        uid: u32,
        gid: u32,
    ) -> Res<()> {
        let (info, mut entry) = self.load_for_change(fs, caller, by_path, path)?;
        let node = self.fold_into(path, &mut entry);
        let keep = |v: u32| (v != p::UID_KEEP).then_some(v);
        let owned = perm::chown_result(
            caller.identity(false),
            &entry.attr.perm(info.kind),
            keep(uid),
            keep(gid),
        )
        .map_err(denied)?;
        self.reserve_allows(fs, caller)?;
        self.write_changed(fs, path, info.kind, (entry, node), |a, now| {
            a.mode = owned.mode;
            a.uid = owned.uid;
            a.gid = owned.gid;
            a.ctime = now;
        })
    }

    /// UTIMENS and FUTIMENS (rule 8).
    pub(super) fn change_times<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        by_path: bool,
        path: &[u8],
        atime: p::TimeSpec,
        mtime: p::TimeSpec,
    ) -> Res<()> {
        let (info, mut entry) = self.load_for_change(fs, caller, by_path, path)?;
        let node = self.fold_into(path, &mut entry);
        let request = match (atime, mtime) {
            (p::TimeSpec::Omit, p::TimeSpec::Omit) => TimesRequest::Omit,
            (p::TimeSpec::Now, p::TimeSpec::Now) => TimesRequest::Now,
            _ => TimesRequest::Explicit,
        };
        perm::utimens_allowed(caller.identity(false), &entry.attr.perm(info.kind), request)
            .map_err(denied)?;
        if request == TimesRequest::Omit {
            return Ok(());
        }
        self.reserve_allows(fs, caller)?;
        let pick = |t: p::TimeSpec, old: i64, now: i64| match t {
            p::TimeSpec::Now => now,
            p::TimeSpec::Omit => old,
            p::TimeSpec::At(t) => t,
        };
        self.write_changed(fs, path, info.kind, (entry, node), |a, now| {
            a.atime = pick(atime, a.atime, now);
            a.mtime = pick(mtime, a.mtime, now);
            a.ctime = now;
        })
    }

    /// Writes the record of the entry at `path` after `change` (one commit). A record of a format
    /// this service does not know is never rewritten: CORRUPT. The memory of the directories is
    /// dropped for a directory, whose permissions may have changed.
    pub(super) fn write_changed<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        path: &[u8],
        kind: Kind,
        (entry, node): (Record, Option<usize>),
        change: impl FnOnce(&mut Attr, i64),
    ) -> Res<()> {
        if entry.standing == Standing::Foreign {
            return Err(p::code(p::CORRUPT));
        }
        let mut attr = entry.attr;
        change(&mut attr, self.now);
        volume(fs.setattr(path, ATTR_TYPE, &attr.to_bytes()))?;
        // The writes pending on the open node went into this commit (`fold_into`).
        if let Some(ni) = node {
            self.nodes[ni].wrote = false;
        }
        if kind == Kind::Directory {
            self.forget(path);
        }
        Ok(())
    }

    /// READDIR: the entries of the next batch (rule of the listing): `ino`, `kind` and the name of
    /// as many as the reply holds, `.` and `..` first. An entry that did not fit waits in the
    /// description's slot for the next call.
    pub(super) fn do_readdir<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        di: usize,
        w: &mut Writer,
    ) -> Res<()> {
        let d = self.descriptions[di];
        if d.kind != Kind::Directory || !d.read {
            return Err(bad_handle());
        }
        let slot = usize::from(d.object);
        let dir = self.dirs[slot];
        let root = dir.get() == b"/";
        let mut batch = p::DirBatch::new();
        let mut more = false;
        loop {
            let next = match self.pending[slot].take() {
                Some(pending) => pending,
                None => match listed(fs, Dir(d.object)) {
                    // Entries already gathered are sent; the failed one was put back, so the next
                    // READDIR meets the error again and reports it.
                    Err(_) if !batch.is_empty() => {
                        more = true;
                        break;
                    }
                    Err(e) => return Err(e),
                    Ok(found) => match found {
                        None => break,
                        Some((entry, _, _)) if root && entry.name() == &ORPHANS[1..] => continue,
                        Some((entry, record, at)) => {
                            // The number of `.` and `..` is looked up: a failure there moves the
                            // iterator back too.
                            let ino =
                                match entry_ino(fs, dir.get(), entry.name(), entry.kind, &record) {
                                    Ok(ino) => ino,
                                    Err(e) => {
                                        let _ = fs.seek_dir(Dir(d.object), at);
                                        if batch.is_empty() {
                                            return Err(e);
                                        }
                                        more = true;
                                        break;
                                    }
                                };
                            let mut pending = Pending {
                                ino,
                                kind: entry.kind,
                                name: [0; crate::NAME_MAX],
                                len: entry.name().len(),
                            };
                            pending.name[..pending.len].copy_from_slice(entry.name());
                            pending
                        }
                    },
                },
            };
            if !batch.push(next.ino, kind_word(next.kind), &next.name[..next.len]) {
                self.pending[slot] = Some(next);
                more = true;
                break;
            }
        }
        batch.write(more, w)
    }
}

/// The path split into its directory and its last name; the root splits into itself and nothing.
pub(super) fn split(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) | None => (&path[..1.min(path.len())], &path[path.len().min(1)..]),
        Some(i) => (&path[..i], &path[i + 1..]),
    }
}

/// The status of a refusal of `posix-perm`.
pub(super) fn denied(denial: Denial) -> Status {
    p::code(match denial {
        Denial::Access => p::ACCESS,
        Denial::Permission => p::PERMISSION,
    })
}

/// The record of the entry at `path` of `kind` as it stands on the volume (none: the closed default).
pub(super) fn entry_of<D: Device>(fs: &mut Fs<'_, D>, path: &[u8], kind: Kind) -> Res<Record> {
    let mut buf = [0u8; 64];
    match fs.getattr(path, ATTR_TYPE, &mut buf) {
        Ok(n) => Ok(read_entry(kind, path, Some(&buf[..n.min(64)]))),
        Err(Error::NoAttr) => Ok(read_entry(kind, path, None)),
        Err(e) => Err(status_of(e)),
    }
}

/// The next entry of an open directory, the size and bytes of its record and the position of the
/// iterator before it, from the attribute of the entry the iterator stands at (`Fs::readdir_attr`: no
/// lookup of the entry by its path, which costs more the further the entry is in a large directory).
/// The iterator keeps its place from one READDIR to the next. When the read fails (the attribute could
/// not be read after the iterator moved) it goes back to the position taken before, so that a retry
/// does not lose the entry; the caller does the same when it fails after this.
#[allow(clippy::type_complexity)]
fn listed<D: Device>(
    fs: &mut Fs<'_, D>,
    dir: Dir,
) -> Res<Option<(crate::fs::Entry, ([u8; WALK_EACH], Option<usize>), u32)>> {
    let at = volume(fs.tell_dir(dir))?;
    let mut buf = [0u8; WALK_EACH];
    match fs.readdir_attr(dir, ATTR_TYPE, &mut buf) {
        Ok(Some((entry, size))) => Ok(Some((entry, (buf, size), at))),
        Ok(None) => Ok(None),
        Err(e) => {
            let _ = fs.seek_dir(dir, at);
            Err(status_of(e))
        }
    }
}

/// The number of the entry `name` of the directory `dir`, as STAT gives it: from the record the
/// listing read with the entry. `.` and `..` carry no attribute on the volume: they take the number
/// of the directory itself and of its parent (looked up once for each listing).
fn entry_ino<D: Device>(
    fs: &mut Fs<'_, D>,
    dir: &[u8],
    name: &[u8],
    kind: Kind,
    record: &([u8; WALK_EACH], Option<usize>),
) -> Res<u64> {
    if name == b"." {
        return Ok(entry_of(fs, dir, Kind::Directory)?.attr.ino);
    }
    if name == b".." {
        let (parent, _) = split(dir);
        return Ok(entry_of(fs, parent, Kind::Directory)?.attr.ino);
    }
    // The path is wanted only for the default of an entry with no record (a number from the path).
    let mut path = [0u8; MAX_PATH + 1 + crate::NAME_MAX];
    let mut n = dir.len();
    path[..n].copy_from_slice(dir);
    if dir != b"/" {
        path[n] = b'/';
        n += 1;
    }
    path[n..n + name.len()].copy_from_slice(name);
    let (bytes, size) = record;
    Ok(record_of(kind, &path[..n + name.len()], *size, bytes)
        .attr
        .ino)
}

/// The stat record of an entry.
pub(super) fn stat_record(kind: Kind, size: u32, attr: &Attr, nlink: u32) -> p::Stat {
    p::Stat {
        kind: kind_word(kind),
        mode: attr.mode,
        uid: attr.uid,
        gid: attr.gid,
        size: u64::from(size),
        ino: attr.ino,
        atime: attr.atime,
        mtime: attr.mtime,
        ctime: attr.ctime,
        nlink,
    }
}

/// What a walk of a path found: the last name's kind and record when it is there, and the record of
/// the directory it is in (None for the root).
#[derive(Clone, Copy)]
pub(super) struct Found {
    pub last: Option<(crate::fs::Info, Record)>,
    pub parent: Option<Record>,
}

/// The path of entry `i` of a walk: the root for 0, the path up to the end of component `i`.
fn walk_prefix(path: &[u8], i: usize, comps: usize) -> &[u8] {
    if i == 0 {
        return &path[..1];
    }
    if i >= comps {
        return path;
    }
    let end = path
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'/')
        .nth(i)
        .map_or(path.len(), |(at, _)| at);
    &path[..end]
}

/// The record of an entry from the size of its attribute on the volume and the bytes read. A record
/// of exactly `ATTR_LEN` bytes is read as one; no attribute is the default; any other size is a
/// record of another format (`usize::MAX` stands for one the walk could not size).
fn record_of(kind: Kind, path: &[u8], size: Option<usize>, bytes: &[u8]) -> Record {
    match size {
        None => read_entry(kind, path, None),
        Some(n) if n == crate::attr::ATTR_LEN => {
            read_entry(kind, path, Some(&bytes[..crate::attr::ATTR_LEN]))
        }
        // A length that is not 48: a wrong-length slice, which reads as foreign.
        Some(_) => read_entry(kind, path, Some(&bytes[..1])),
    }
}
