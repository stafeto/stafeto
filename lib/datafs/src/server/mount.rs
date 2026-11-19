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
    /// The records and the move-out of the inline files are still to do: the conversion job runs
    /// after READY, one entry a step (`Server::convert_step`).
    pub pending: bool,
    /// Nothing is left to do: the volume had the mark 4.
    pub complete: bool,
}

/// What the work before READY did, each part with its own result (a failure of one leaves the others).
pub struct StartWork {
    pub recovered: Result<Recovered, Error>,
    pub mounted: Result<Mounted, Error>,
    pub epoch: Result<u32, Error>,
}

/// The depth of directories the conversion goes to.
const CONVERT_DEPTH: usize = 32;

/// The conversion job, one entry a step: the records of every entry that has none and the move-out
/// of every inline file, in a walk of the tree that keeps the iterator of the directory it is in open
/// between steps (a directory is read once; the walk goes back into a parent after a child directory
/// with a skip of the entries done, which costs the entries and not a lookup of each).
pub(super) struct Conversion {
    /// Whether records are to be written (a volume with no mark or an older one) besides the move-out.
    records: bool,
    path: [u8; MAX_PATH + 1],
    len: usize,
    depth: usize,
    /// The entries each level has gone past.
    done: [usize; CONVERT_DEPTH],
    dir: Option<Dir>,
    root_done: bool,
    pub(super) converted: usize,
    pub(super) moved: usize,
}

impl Conversion {
    fn new(records: bool) -> Conversion {
        let mut path = [0u8; MAX_PATH + 1];
        path[0] = b'/';
        Conversion {
            records,
            path,
            len: 1,
            depth: 0,
            done: [0; CONVERT_DEPTH],
            dir: None,
            root_done: false,
            converted: 0,
            moved: 0,
        }
    }
}

/// What a step of the conversion did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// An entry was looked at (and written if it needed it): more to do.
    More,
    /// The walk ended and the mark 4 is written: the records given and the files moved out.
    Done { converted: usize, moved: usize },
}

impl Server {
    /// Everything the service does between the mount and READY: what a stop or a cut left under the
    /// orphans, the mount work (the format mark and the count of pairs) and the count of the epoch. It
    /// makes no commit that needs a block: the first allocation of a volume scans the allocator's
    /// window, which traverses every file's blocks (about 100,000 reads for 760 MiB of files, 34 s
    /// before READY in the first fill run), so the hidden directory of the orphans is made afterwards
    /// (`ensure_orphans`, a job of the worker after READY) and `orphan` makes it when it is missing.
    /// The reads of this are bounded by the pairs of the volume (two for each, for the count), and a
    /// test holds it to a number on a volume full of files.
    pub fn start_work<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> StartWork {
        let recovered = recover_orphans(fs);
        let mounted = self.mount_work(fs);
        let epoch = bump_epoch(fs);
        StartWork {
            recovered,
            mounted,
            epoch,
        }
    }

    /// The work after the mount before READY, bounded and cheap: the orphans are dealt with by the
    /// caller, and this reads the format mark and counts the pairs and the directories. A volume whose
    /// format mark is above `VOLUME_FORMAT` is refused and left as it is. A volume with the mark 4
    /// (every entry has its record and no file is inline) needs nothing. Any other (no mark, an older
    /// one, or the mark of the records, which the part A build wrote while it kept small files inside
    /// the pairs of their directories) gets the conversion job: the record of every entry that has
    /// none and every inline file moved out, one entry a step after READY (`convert_step`), then the
    /// mark. Until the job reaches an entry it reads as before (the closed default with the number
    /// its path gives, which the record then keeps, so a program sees the same owner, mode and
    /// `st_ino` before and after), and an inline file is moved out when it is first opened for writing
    /// or for truncation, so that no write meets the loss of littlefs 2.11.3 (see the notes of the
    /// vendored copy). A cut in the middle leaves the mark as it was and the job starts again at the
    /// next mount, skipping what it did at no write.
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
        self.conversion = None;
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
        self.count_at_mount(fs)?;
        if !records && !inline {
            return Ok(Mounted {
                complete: true,
                ..Mounted::default()
            });
        }
        self.conversion = Some(Conversion::new(records));
        Ok(Mounted {
            pending: true,
            ..Mounted::default()
        })
    }

    /// The conversion job has steps to do.
    pub fn conversion_pending(&self) -> bool {
        self.conversion.is_some()
    }

    /// Gives up the job (the volume failed under it): the mark stays as it was and the next mount
    /// starts again.
    pub fn abandon_conversion<D: Device>(&mut self, fs: &mut Fs<'_, D>) {
        if let Some(c) = self.conversion.take()
            && let Some(dir) = c.dir
        {
            let _ = fs.closedir(dir);
        }
    }

    /// One step of the conversion: the next entry of the directory the walk is in (opened at the
    /// first step of a directory, kept open after it), its record written when it has none, an inline
    /// file moved out, a directory gone into. The last step writes the mark 4.
    pub fn convert_step<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> Result<Step, Error> {
        let Some(mut c) = self.conversion.take() else {
            return Ok(Step::Done {
                converted: 0,
                moved: 0,
            });
        };
        match self.convert_one(fs, &mut c) {
            Ok(Some(done)) => {
                // The job is over: the mark says every entry has its record and no file is inline.
                match fs.setattr(b"/", ATTR_FORMAT_TYPE, &VOLUME_FORMAT.to_le_bytes()) {
                    Ok(()) => Ok(done),
                    Err(e) => {
                        self.conversion = Some(c);
                        Err(e)
                    }
                }
            }
            Ok(None) => {
                self.conversion = Some(c);
                Ok(Step::More)
            }
            Err(e) => {
                if let Some(dir) = c.dir.take() {
                    let _ = fs.closedir(dir);
                }
                self.conversion = Some(c);
                Err(e)
            }
        }
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

    /// The work of one step: Some when the walk has ended.
    fn convert_one<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        c: &mut Conversion,
    ) -> Result<Option<Step>, Error> {
        // The root's record first.
        if !c.root_done {
            c.root_done = true;
            if c.records
                && let Ok(root) = entry_of(fs, b"/", Kind::Directory)
                && root.standing == Standing::Missing
            {
                let a = default_attr(Kind::Directory, b"/");
                fs.setattr(b"/", ATTR_TYPE, &a.to_bytes())?;
                c.converted += 1;
            }
            return Ok(None);
        }
        let dir = match c.dir {
            Some(dir) => dir,
            None => {
                // The directory is opened again past the entries the walk did in it.
                let dir = fs.opendir(&c.path[..c.len])?;
                let mut skip = c.done[c.depth];
                while skip > 0 {
                    match fs.readdir(dir) {
                        Ok(Some(e)) => {
                            if e.name() != b"." && e.name() != b".." {
                                skip -= 1;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            let _ = fs.closedir(dir);
                            return Err(e);
                        }
                    }
                }
                c.dir = Some(dir);
                return Ok(None);
            }
        };
        let entry = match fs.readdir(dir) {
            Ok(Some(e)) => e,
            Ok(None) => {
                fs.closedir(dir)?;
                c.dir = None;
                if c.depth == 0 {
                    return Ok(Some(Step::Done {
                        converted: c.converted,
                        moved: c.moved,
                    }));
                }
                // Up: drop the last name of the path.
                c.depth -= 1;
                c.len = c.path[..c.len]
                    .iter()
                    .rposition(|&b| b == b'/')
                    .map_or(1, |i| i.max(1));
                return Ok(None);
            }
            Err(e) => {
                let _ = fs.closedir(dir);
                c.dir = None;
                return Err(e);
            }
        };
        let name = entry.name();
        if name == b"." || name == b".." {
            return Ok(None);
        }
        c.done[c.depth] += 1;
        let mut child = [0u8; MAX_PATH + 1 + crate::NAME_MAX];
        child[..c.len].copy_from_slice(&c.path[..c.len]);
        let mut n = c.len;
        if c.len > 1 {
            child[n] = b'/';
            n += 1;
        }
        if n + name.len() > MAX_PATH {
            return Ok(None);
        }
        child[n..n + name.len()].copy_from_slice(name);
        n += name.len();
        let child_path = &child[..n];
        // An entry a client removed or renamed since the walk read its name is passed over.
        let Ok(rec) = entry_of(fs, child_path, entry.kind) else {
            return Ok(None);
        };
        if c.records && rec.standing == Standing::Missing {
            // The record is what the entry already shows (the closed default and the number its path
            // gives), written down.
            let a = default_attr(entry.kind, child_path);
            if fs.setattr(child_path, ATTR_TYPE, &a.to_bytes()).is_ok() {
                c.converted += 1;
            }
        }
        if entry.kind == Kind::File && fs.outline(child_path, true).unwrap_or(false) {
            fs.outline(child_path, false)?;
            c.moved += 1;
        }
        if entry.kind == Kind::Directory && c.depth + 1 < CONVERT_DEPTH {
            fs.closedir(dir)?;
            c.dir = None;
            c.path[..n].copy_from_slice(&child[..n]);
            c.len = n;
            c.depth += 1;
            c.done[c.depth] = 0;
        }
        Ok(None)
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
