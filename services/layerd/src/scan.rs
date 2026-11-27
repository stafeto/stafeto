// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The build of the index from the live layer, in steps (section 5.1: "a job by steps up to
//! READY"). A step is one of: stat and open the next directory of the queue, or read one batch of
//! entries of the directory that is open (a READDIR of the data file service, at most one message
//! of entries). A directory is listed once; its subdirectories join the queue, whose size the
//! table bounds (a directory is an entry). The root of the layer is `/.layers/NN`.
//!
//! In a listing the name `.wh..wh..opq` makes its directory opaque, `.wh.<name>` is the mark of
//! deletion of `<name>`, and any other name that begins `.wh..wh.` is reserved and ignored (a
//! later part keeps the links of the live layer under `.wh..wh.lnk.`). The attributes of a
//! directory come from its stat; those of the files the listing does not need.

use crate::index::{Fields, Index, Kind, OPAQUE, SLOTS, UNSCANNED};
use crate::volume::{BATCH_BYTES, Volume, raw_entry};
use proto_data::{DIRECTORY, KIND_DIRECTORY, READ};
use proto_wire::Status;

pub const OPAQUE_NAME: &[u8] = b".wh..wh..opq";
pub const WHITEOUT_PREFIX: &[u8] = b".wh.";
const RESERVED: &[u8] = b".wh..wh.";

/// What a name of a layer means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Special<'a> {
    /// An ordinary name.
    None,
    /// `.wh..wh..opq`: the directory is opaque.
    Opaque,
    /// `.wh.<name>`: the name is deleted.
    Whiteout(&'a [u8]),
    /// `.wh..wh.*` other than the opaque marker.
    Reserved,
}

pub fn special(name: &[u8]) -> Special<'_> {
    if name == OPAQUE_NAME {
        Special::Opaque
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
    /// The index is full: the layer holds more names than the table.
    NoSpace,
    /// The volume answered with this status.
    Volume(Status),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    More,
    Done,
}

/// The entries of a batch one step takes into the index.
pub const ENTRIES_PER_STEP: usize = 24;

pub struct Scan {
    queue: [u32; SLOTS],
    /// The batch of the open directory (`Volume::read_dir_raw`) and how far it is taken; whether
    /// no more batches follow it.
    batch: [u8; BATCH_BYTES],
    batch_len: usize,
    batch_pos: usize,
    batch_last: bool,
    /// The directory whose start is in progress: its id and the length of its path in `dir_path`,
    /// and whether its attributes have been read.
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
}

impl Scan {
    pub const fn new() -> Scan {
        Scan {
            queue: [0; SLOTS],
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
    /// walk up the index), its attributes (STAT), its description (OPEN).
    fn start_directory<V: Volume>(
        &mut self,
        index: &mut Index,
        volume: &mut V,
        root: &[u8],
    ) -> Result<Progress, Failure> {
        let Some((id, n)) = self.dir else {
            if self.head == self.tail {
                return Ok(Progress::Done);
            }
            let id = self.queue[self.head % SLOTS];
            self.head += 1;
            let n = Self::volume_path(index, root, id, &mut self.dir_path)
                .ok_or(Failure::Volume(proto_data::code(proto_data::NAME_TOO_LONG)))?;
            self.dir = Some((id, n));
            self.statted = false;
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
            match volume.read_dir_raw(handle, &mut self.batch) {
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
            let Some((ino, kind, name, next)) =
                raw_entry(&self.batch[..self.batch_len], self.batch_pos)
            else {
                break;
            };
            self.batch_pos = next;
            taken += 1;
            if name == b"." || name == b".." {
                continue;
            }
            let (name, kind) = match special(name) {
                Special::Opaque => {
                    index.set_flags(id, OPAQUE, 0);
                    continue;
                }
                Special::Reserved => continue,
                Special::Whiteout(target) => (target, Kind::Whiteout),
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
            match index.insert(id, name, fields) {
                Ok(child) => {
                    if kind == Kind::Dir {
                        found_queue[found] = child;
                        found += 1;
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
