// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The build of the index from the live layer, in steps (section 5.1: "a job by steps up to
//! READY"). A step is one of: open the next directory of the queue (the root of the layer is
//! statted first), or read one batch of entries of the directory that is open (a READDIR_ATTR of
//! the data file service, at most one message of entries with the mode, owner and group of each). A directory is listed once; its subdirectories join the queue, whose size the
//! table bounds (a directory is an entry). The root of the layer is `/.layers/NN`.
//!
//! In a listing the name `.wh..wh..opq` makes its directory opaque, `.wh.<name>` is the mark of
//! deletion of `<name>`, `.wh..wh.lnk.<name>` is the symbolic link `<name>` (a file whose bytes are
//! its target), and any other name that begins `.wh..wh.` is reserved and ignored. The attributes of a
//! directory come from the listing of its parent (the root's from its stat); those of the files the listing does not
//! need.

use crate::index::{Error, Fields, Index, Kind, OPAQUE, SLOTS, UNSCANNED};
use crate::volume::{BATCH_BYTES, Volume};
use proto_data::{DIRECTORY, KIND_DIRECTORY, READ, dir_attr_entry};
use proto_wire::Status;

/// The directories one step of the pass of `index.lift` takes.
const LIFTS_PER_STEP: usize = 64;

pub const OPAQUE_NAME: &[u8] = b".wh..wh..opq";
pub const WHITEOUT_PREFIX: &[u8] = b".wh.";
const RESERVED: &[u8] = b".wh..wh.";
/// The prefix of the file that holds a symbolic link of the layer (littlefs has none).
pub const LINK_PREFIX: &[u8] = b".wh..wh.lnk.";

/// What a name of a layer means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Special<'a> {
    /// An ordinary name.
    None,
    /// `.wh..wh..opq`: the directory is opaque.
    Opaque,
    /// `.wh.<name>`: the name is deleted.
    Whiteout(&'a [u8]),
    /// `.wh..wh.lnk.<name>`: the name is a symbolic link.
    Link(&'a [u8]),
    /// `.wh..wh.*` other than the opaque marker.
    Reserved,
}

pub fn special(name: &[u8]) -> Special<'_> {
    if name == OPAQUE_NAME {
        Special::Opaque
    } else if let Some(rest) = name.strip_prefix(LINK_PREFIX) {
        if rest.is_empty() {
            Special::Reserved
        } else {
            Special::Link(rest)
        }
    } else if name.starts_with(RESERVED) {
        Special::Reserved
    } else if let Some(rest) = name.strip_prefix(WHITEOUT_PREFIX) {
        if rest.is_empty() {
            Special::Reserved
        } else {
            Special::Whiteout(rest)
        }
    } else {
        Special::None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The index is full: the arena has no room for the names of the layer.
    NoSpace,
    /// Both buckets of a name are full: the build starts again under another seed.
    Reseed,
    /// The volume answered with this status.
    Volume(Status),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    More,
    Done,
}

/// The entries of a batch one step takes into the index.
pub const ENTRIES_PER_STEP: usize = 12;

pub struct Scan {
    queue: [u32; SLOTS],
    /// Where the pass that lets each directory reach as far as its children stands (`index.lift`),
    /// counting down the queue; 0 before the pass starts.
    lifted: usize,
    /// The batch of the open directory (`Volume::read_dir_raw`) and how far it is taken; whether
    /// no more batches follow it.
    batch: [u8; BATCH_BYTES],
    batch_len: usize,
    batch_pos: usize,
    batch_last: bool,
    /// The directory whose start is in progress: its id and the length of its path in `dir_path`,
    /// and whether its attributes are known (a directory below the root has them from the listing
    /// of its parent; the root's come from a STAT).
    dir: Option<(u32, usize)>,
    dir_path: [u8; 512],
    statted: bool,
    head: usize,
    tail: usize,
    /// The directory that is open: its id and the handle.
    open: Option<(u32, u32)>,
    /// The root has been taken from the queue.
    started: bool,
    /// The steps taken (for the probe's report).
    pub steps: u32,
    /// The directories left unlisted because their path passes the volume's limit.
    pub skipped: u32,
    /// Whether a name that finds both buckets full ends the build (it starts again under another
    /// seed); once the seeds are used up the name is left out and the build goes on.
    pub patient: bool,
    /// The names (and the directories among them, whose subtrees go with them) and the marks the
    /// build left out for the buckets.
    pub skipped_names: u32,
    pub skipped_marks: u32,
}

impl Scan {
    pub const fn new() -> Scan {
        Scan {
            queue: [0; SLOTS],
            lifted: 0,
            batch: [0; BATCH_BYTES],
            batch_len: 0,
            batch_pos: 0,
            batch_last: false,
            dir: None,
            dir_path: [0; 512],
            statted: false,
            head: 0,
            tail: 0,
            open: None,
            started: false,
            steps: 0,
            skipped: 0,
            patient: true,
            skipped_names: 0,
            skipped_marks: 0,
        }
    }

    pub fn reset(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.batch_len = 0;
        self.batch_pos = 0;
        self.batch_last = false;
        self.dir = None;
        self.statted = false;
        self.open = None;
        self.started = false;
        self.steps = 0;
        self.skipped = 0;
        self.skipped_names = 0;
        self.skipped_marks = 0;
        self.lifted = 0;
    }

    fn push(&mut self, id: u32) {
        // At most one id for each entry, and the root: the ring cannot be over `SLOTS + 1`, and
        // the root leaves it first.
        self.queue[self.tail % SLOTS] = id;
        self.tail += 1;
    }

    /// The path of a directory of the layer on the volume, `root` (`/.layers/NN`) and the path
    /// inside the layer in 512 bytes, the volume's own limit with room to spare (`proto_data::MAX_PATH`
    /// is 506). A directory whose path does not fit is NAME_TOO_LONG, which fails the
    /// build (`Failure::Volume`), and so does a name the volume would refuse; the names the layer
    /// holds were made through the volume, so they fit it.
    pub fn volume_path(index: &Index, root: &[u8], id: u32, out: &mut [u8; 512]) -> Option<usize> {
        let n = root.len();
        out.get_mut(..n)?.copy_from_slice(root);
        if id == 0 {
            return Some(n);
        }
        let inside = index.path_of(id, &mut out[n..])?;
        Some(n + inside)
    }

    /// The start of a directory, a step for each part: its path (a deep path takes the longest
    /// walk up the index), the attributes of the root (STAT), its description (OPEN).
    fn start_directory<V: Volume>(
        &mut self,
        index: &mut Index,
        volume: &mut V,
        root: &[u8],
    ) -> Result<Progress, Failure> {
        let Some((id, n)) = self.dir else {
            if self.head == self.tail {
                // Every directory is listed: the directories reach as far as their children, the
                // last first, a few in each step.
                if self.lifted == 0 {
                    self.lifted = self.tail;
                }
                let mut taken = 0;
                while self.lifted > 1 && taken < LIFTS_PER_STEP {
                    self.lifted -= 1;
                    index.lift(self.queue[self.lifted % SLOTS]);
                    taken += 1;
                }
                return Ok(if self.lifted > 1 {
                    Progress::More
                } else {
                    Progress::Done
                });
            }
            let id = self.queue[self.head % SLOTS];
            self.head += 1;
            // A directory whose path the volume would refuse is left out of the index and told
            // of (`skipped`), so that one over-long name does not stop the build.
            let n = match Self::volume_path(index, root, id, &mut self.dir_path) {
                Some(n) if n <= proto_data::MAX_PATH => n,
                _ => {
                    self.skipped += 1;
                    return Ok(Progress::More);
                }
            };
            self.dir = Some((id, n));
            self.statted = id != 0;
            return Ok(Progress::More);
        };
        let path = &self.dir_path[..n];
        if !self.statted {
            let stat = volume.stat(path).map_err(Failure::Volume)?;
            if stat.kind != proto_data::KIND_DIRECTORY {
                return Err(Failure::Volume(proto_data::code(proto_data::NOT_DIRECTORY)));
            }
            index.set_attr(
                id,
                stat.ino,
                stat.uid,
                stat.gid,
                (stat.mode & 0o7777) as u16,
            );
            self.statted = true;
            return Ok(Progress::More);
        }
        let handle = volume
            .open(path, READ | DIRECTORY, 0)
            .map_err(Failure::Volume)?;
        index.set_flags(id, 0, UNSCANNED);
        self.open = Some((id, handle));
        self.dir = None;
        self.statted = false;
        Ok(Progress::More)
    }

    /// One step. `root` is the path of the layer on the volume, `/.layers/NN`.
    pub fn step<V: Volume>(
        &mut self,
        index: &mut Index,
        volume: &mut V,
        root: &[u8],
        layer: u8,
    ) -> Result<Progress, Failure> {
        self.steps += 1;
        if !self.started {
            self.started = true;
            self.push(0);
        }
        let Some((id, handle)) = self.open else {
            return self.start_directory(index, volume, root);
        };
        // A batch of the directory in the stash: read in one step, taken in steps of
        // `ENTRIES_PER_STEP` entries (an insertion is about 450 ticks under -icount, a batch of a
        // directory of short names holds 48 entries).
        if self.batch_pos == self.batch_len && !self.batch_last {
            self.batch_pos = 0;
            self.batch_len = 0;
            match volume.read_dir_attr_raw(handle, &mut self.batch) {
                Ok((len, more)) => {
                    self.batch_len = len;
                    self.batch_last = !more;
                }
                Err(e) => {
                    let _ = volume.close(handle);
                    self.open = None;
                    return Err(Failure::Volume(e));
                }
            }
            if self.batch_len > 0 {
                return Ok(Progress::More);
            }
        }
        let mut found_queue = [0u32; ENTRIES_PER_STEP];
        let mut found = 0;
        let mut taken = 0;
        let mut failure = None;
        while taken < ENTRIES_PER_STEP {
            let Some((entry, next)) = dir_attr_entry(&self.batch[..self.batch_len], self.batch_pos)
            else {
                break;
            };
            self.batch_pos = next;
            taken += 1;
            let (ino, kind, name) = (entry.ino, entry.kind, entry.name);
            let (name, kind) = match special(name) {
                Special::Opaque => {
                    index.set_flags(id, OPAQUE, 0);
                    continue;
                }
                Special::Reserved => continue,
                Special::Whiteout(target) => (target, Kind::Whiteout),
                Special::Link(target) => (target, Kind::Link),
                Special::None if kind == KIND_DIRECTORY => (name, Kind::Dir),
                Special::None => (name, Kind::File),
            };
            let fields = Fields {
                kind,
                layer,
                number: ino,
                uid: 0,
                gid: 0,
                mode: 0,
            };
            match index.insert_shallow(id, name, fields) {
                Ok(child) => {
                    if kind == Kind::Dir {
                        index.set_attr(
                            child,
                            ino,
                            entry.uid,
                            entry.gid,
                            (entry.mode & 0o7777) as u16,
                        );
                        found_queue[found] = child;
                        found += 1;
                    }
                }
                Err(Error::Buckets) if self.patient => {
                    failure = Some(Failure::Reseed);
                    break;
                }
                Err(Error::Buckets) => {
                    if kind == Kind::Whiteout {
                        self.skipped_marks += 1;
                    } else {
                        self.skipped_names += 1;
                    }
                }
                Err(_) => {
                    failure = Some(Failure::NoSpace);
                    break;
                }
            }
        }
        if let Some(f) = failure {
            let _ = volume.close(handle);
            self.open = None;
            return Err(f);
        }
        for &child in &found_queue[..found] {
            self.push(child);
        }
        // The batch is taken and no more follow: the directory is done.
        if self.batch_pos >= self.batch_len && self.batch_last {
            let _ = volume.close(handle);
            self.open = None;
            self.batch_len = 0;
            self.batch_pos = 0;
            self.batch_last = false;
        }
        Ok(Progress::More)
    }
}

impl Default for Scan {
    fn default() -> Self {
        Scan::new()
    }
}
