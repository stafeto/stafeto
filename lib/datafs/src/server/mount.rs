// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The work after the mount: the directory of the orphans and what a stop or a cut left in it, the
//! epoch of the instance, and the attributes of the volume (the conversion of a volume of version 2,
//! the format mark). Part of `server`, split out of it.

use super::*;
use crate::attr::RECORDS_FORMAT;

/// What `recover_orphans` did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Recovered {
    /// Orphans removed: files that were unlinked while open, and replaced files whose home name
    /// is taken.
    pub removed: usize,
    /// Orphans put back under their home name: the old target of a rename that a cut stopped
    /// between its two commits.
    pub restored: usize,
    /// Entries that could not be removed or restored (the volume failed); they stay.
    pub failed: usize,
}

/// Makes the hidden directory of the orphans, so that the first unlink of an open file does not
/// have to make it on a volume that may be full. Run after the mount.
pub fn ensure_orphans<D: Device>(fs: &mut Fs<'_, D>) -> Result<(), Error> {
    match fs.mkdir(ORPHANS) {
        Ok(()) | Err(Error::Exists) => Ok(()),
        Err(e) => Err(e),
    }
}

/// The count of the mounts of the volume, the epoch of this instance: read from the root's
/// attribute, one more, written back. It differs from the epoch of every earlier instance of the
/// volume (until the count wraps past the bits a handle carries).
pub fn bump_epoch<D: Device>(fs: &mut Fs<'_, D>) -> Result<u32, Error> {
    let mut old = [0u8; 4];
    let last = match fs.getattr(b"/", ATTR_EPOCH, &mut old) {
        Ok(4) => u32::from_le_bytes(old),
        Ok(_) | Err(Error::NoAttr) => 0,
        Err(e) => return Err(e),
    };
    let mut next = last.wrapping_add(1);
    if next & EPOCH_MASK == 0 {
        next = next.wrapping_add(1);
    }
    fs.setattr(b"/", ATTR_EPOCH, &next.to_le_bytes())?;
    Ok(next)
}

/// What the mount work did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Mounted {
    /// The volume's format mark is above this service's: the service refuses it (every request
    /// answers NOT_READY) and wrote nothing.
    pub refused: bool,
    /// Entries that got a record (a volume of version 2 has none).
    pub converted: usize,
    /// Inline files moved out to blocks of their own (a volume made with inline data on).
    pub moved: usize,
    /// The walk of the tree ended: the format mark was written. False when it was cut short by its
    /// bound (`CONVERT_MAX` records written); the next mount goes on. Entries deeper than
    /// `CONVERT_DEPTH` directories are left with no record (they read as the closed default, which is
    /// safe) and do not hold the mark back.
    pub complete: bool,
}

/// The entries one run of the conversion writes at most (a record or a move-out each), and the depth
/// it goes to.
pub const CONVERT_MAX: usize = 8192;
const CONVERT_DEPTH: usize = 32;

impl Server {
    /// The work after the mount that gives the volume the records of version 3 (rule 12) and moves
    /// the inline files out, after `ensure_orphans` and `recover_orphans` and before the first
    /// request. A volume whose format mark is above `VOLUME_FORMAT` is refused and left as it is. A
    /// volume with no mark or an older one gets the record of every entry that has none (the closed
    /// default, a number from the counter at the root) and every inline file moved out; a volume with
    /// the mark of the records (`RECORDS_FORMAT`) only the move-out; one with `VOLUME_FORMAT` nothing.
    /// Then the mark: a cut in between starts the walk again at the next mount, and the entries done
    /// are skipped at no write. The move-out is for the writes at the start or in the middle of an
    /// old inline file, which are lost with CORRUPT in littlefs 2.11.3 once inline data is off.
    pub fn mount_work<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> Result<Mounted, Error> {
        let mut mark = [0u8; 4];
        let format = match fs.getattr(b"/", ATTR_FORMAT_TYPE, &mut mark) {
            Ok(4) => Some(u32::from_le_bytes(mark)),
            Ok(_) => Some(u32::MAX),
            Err(Error::NoAttr) => None,
            Err(e) => return Err(e),
        };
        self.ino_next = 0;
        self.ino_end = 0;
        // What the server remembers of directories and of the pairs starts empty at every mount.
        self.pairs = super::Pairs::NONE;
        for c in &mut self.counts {
            c.used = false;
        }
        if format.is_some_and(|f| f > VOLUME_FORMAT) {
            self.refused = true;
            return Ok(Mounted {
                refused: true,
                ..Mounted::default()
            });
        }
        let records = !format.is_some_and(|f| f >= RECORDS_FORMAT);
        let inline = !format.is_some_and(|f| f >= VOLUME_FORMAT);
        if !records && !inline {
            self.count_at_mount(fs)?;
            return Ok(Mounted {
                complete: true,
                ..Mounted::default()
            });
        }
        let (converted, moved, complete) = self.convert(fs, records)?;
        if complete {
            fs.setattr(b"/", ATTR_FORMAT_TYPE, &VOLUME_FORMAT.to_le_bytes())?;
        }
        self.count_at_mount(fs)?;
        Ok(Mounted {
            refused: false,
            converted,
            moved,
            complete,
        })
    }

    /// The pairs and the directories are counted once the volume is in its final shape: the exact
    /// count the service starts from (about two reads for each pair), told in the line `datafs:
    /// pairs N of 2048, directories M of 1024`.
    fn count_at_mount<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> Result<(), Error> {
        let (pairs, dirs) = fs.metadata_pairs()?;
        self.pairs = super::Pairs {
            known: Some(pairs),
            since: 0,
            dirs: Some(dirs),
            refused: false,
            dirs_refused: false,
            report: Some((pairs, dirs)),
            mismatch: None,
        };
        Ok(())
    }

    /// Walks the tree, writes the record of every entry that has none (`records`) and moves out every
    /// inline file. The root first. The records written and the files moved, and whether the walk
    /// ended.
    fn convert<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        records: bool,
    ) -> Result<(usize, usize, bool), Error> {
        let mut converted = 0;
        let mut moved = 0;
        // The root has number 1 and the default `0755`.
        if let Ok(root) = entry_of(fs, b"/", Kind::Directory)
            && records
            && root.standing == Standing::Missing
        {
            let mut a = default_attr(Kind::Directory, b"/");
            a.ino = 1;
            fs.setattr(b"/", ATTR_TYPE, &a.to_bytes())?;
            converted += 1;
        }
        let mut path = [0u8; MAX_PATH + 1];
        path[0] = b'/';
        let mut len = 1;
        // The entry each level has gone past, so that a level that was closed for a write
        // is opened again and skips what it did.
        let mut done = [0usize; CONVERT_DEPTH];
        let mut depth = 0;
        'levels: loop {
            let dir = fs.opendir(&path[..len])?;
            let mut skip = done[depth];
            loop {
                let entry = match fs.readdir(dir) {
                    Ok(Some(e)) => e,
                    Ok(None) => {
                        fs.closedir(dir)?;
                        if depth == 0 {
                            return Ok((converted, moved, true));
                        }
                        // Up: drop the last name of the path.
                        depth -= 1;
                        len = path[..len]
                            .iter()
                            .rposition(|&b| b == b'/')
                            .map_or(1, |i| i.max(1));
                        continue 'levels;
                    }
                    Err(e) => {
                        let _ = fs.closedir(dir);
                        return Err(e);
                    }
                };
                let name = entry.name();
                if name == b"." || name == b".." {
                    continue;
                }
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                done[depth] += 1;
                let mut child = [0u8; MAX_PATH + 1 + crate::NAME_MAX];
                child[..len].copy_from_slice(&path[..len]);
                let mut n = len;
                if len > 1 {
                    child[n] = b'/';
                    n += 1;
                }
                if n + name.len() > MAX_PATH {
                    continue;
                }
                child[n..n + name.len()].copy_from_slice(name);
                n += name.len();
                let child_path = &child[..n];
                let rec = match entry_of(fs, child_path, entry.kind) {
                    Ok(r) => r,
                    Err(_) => {
                        fs.closedir(dir)?;
                        return Err(Error::Io);
                    }
                };
                let mut wrote = false;
                if records && rec.standing == Standing::Missing {
                    // The bound counts the records written and the files moved, so that a volume of
                    // more entries than the bound still ends: each mount writes some, and the
                    // entries done are skipped at no write.
                    if converted + moved >= CONVERT_MAX {
                        fs.closedir(dir)?;
                        return Ok((converted, moved, false));
                    }
                    let mut a = default_attr(entry.kind, child_path);
                    // A number from the counter; a failed reserve leaves the entry for the next mount.
                    match self.next_ino(fs) {
                        Ok(ino) => a.ino = ino,
                        Err(_) => {
                            fs.closedir(dir)?;
                            return Err(Error::Io);
                        }
                    }
                    fs.closedir(dir)?;
                    fs.setattr(child_path, ATTR_TYPE, &a.to_bytes())?;
                    converted += 1;
                    wrote = true;
                }
                // An inline file (found with a read, the directory still open) is moved out with the
                // directory closed, as a record is written.
                if entry.kind == Kind::File && fs.outline(child_path, true).unwrap_or(false) {
                    if converted + moved >= CONVERT_MAX {
                        if !wrote {
                            fs.closedir(dir)?;
                        }
                        return Ok((converted, moved, false));
                    }
                    if !wrote {
                        fs.closedir(dir)?;
                        wrote = true;
                    }
                    fs.outline(child_path, false)?;
                    moved += 1;
                }
                if entry.kind == Kind::Directory && depth + 1 < CONVERT_DEPTH {
                    if !wrote {
                        fs.closedir(dir)?;
                    }
                    path[..n].copy_from_slice(&child[..n]);
                    len = n;
                    depth += 1;
                    done[depth] = 0;
                    continue 'levels;
                }
                if wrote {
                    // Closed for the write: open again past what was done.
                    continue 'levels;
                }
            }
        }
    }
}

/// Deals with what a stop or a cut of the power left under `ORPHANS`, once after the mount and
/// before the first request. A file that a rename over an open file moved there carries a mark
/// (its token, which its name spells, and its home name): when the home name is missing, the rename
/// never reached its second commit, and the file goes back. Every other entry is removed. An entry
/// that cannot be dealt with stays and is counted; the others go on.
pub fn recover_orphans<D: Device>(fs: &mut Fs<'_, D>) -> Result<Recovered, Error> {
    let mut done = Recovered::default();
    let mut skip = 0;
    loop {
        let dir = match fs.opendir(ORPHANS) {
            Ok(dir) => dir,
            Err(Error::NoEntry) => return Ok(done),
            Err(e) => return Err(e),
        };
        let mut path = [0u8; MAX_PATH];
        let mut found = None;
        let mut result = Ok(());
        let mut passed = 0;
        loop {
            match fs.readdir(dir) {
                Ok(Some(e)) if e.name() == b"." || e.name() == b".." => {}
                Ok(Some(_)) if passed < skip => passed += 1,
                Ok(Some(e)) => {
                    let n = ORPHANS.len();
                    path[..n].copy_from_slice(ORPHANS);
                    path[n] = b'/';
                    let len = e.name().len();
                    path[n + 1..n + 1 + len].copy_from_slice(e.name());
                    found = Some((n + 1, n + 1 + len));
                    break;
                }
                Ok(None) => break,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        let closed = fs.closedir(dir);
        result?;
        closed?;
        let Some((name_at, len)) = found else {
            return Ok(done);
        };
        let entry = &path[..len];
        let token = token_of(&path[name_at..len]);
        let mut mark = [0u8; 8 + MAX_PATH];
        let home = match fs.getattr(entry, ATTR_HOME, &mut mark) {
            Ok(n) if n > 8 && token == Some(u64::from_le_bytes(mark[..8].try_into().unwrap())) => {
                Some(&mark[8..n])
            }
            _ => None,
        };
        // A marked file whose home name is free goes back; if that fails it stays.
        let back = home.filter(|h| !hidden(h) && matches!(fs.stat(h), Err(Error::NoEntry)));
        match back {
            Some(home) => {
                if fs.rename(entry, home).is_ok() {
                    let _ = fs.removeattr(home, ATTR_HOME);
                    done.restored += 1;
                } else {
                    done.failed += 1;
                    skip += 1;
                }
            }
            None => {
                if fs.remove(entry).is_ok() {
                    done.removed += 1;
                } else {
                    done.failed += 1;
                    skip += 1;
                }
            }
        }
    }
}
