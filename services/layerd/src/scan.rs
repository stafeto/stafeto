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
use crate::volume::Volume;
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

pub struct Scan {
    queue: [u32; SLOTS],
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

    /// The path of a directory of the layer on the volume: `root` and the path inside the layer.
    pub fn volume_path(index: &Index, root: &[u8], id: u32, out: &mut [u8; 512]) -> Option<usize> {
        let n = root.len();
        out.get_mut(..n)?.copy_from_slice(root);
        if id == 0 {
            return Some(n);
        }
        let inside = index.path_of(id, &mut out[n..])?;
        Some(n + inside)
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
            if self.head == self.tail {
                return Ok(Progress::Done);
            }
            let id = self.queue[self.head % SLOTS];
            self.head += 1;
            let mut path = [0u8; 512];
            let n = Self::volume_path(index, root, id, &mut path)
                .ok_or(Failure::Volume(proto_data::code(proto_data::NAME_TOO_LONG)))?;
            let stat = volume.stat(&path[..n]).map_err(Failure::Volume)?;
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
            let handle = volume
                .open(&path[..n], READ | DIRECTORY, 0)
                .map_err(Failure::Volume)?;
            index.set_flags(id, 0, UNSCANNED);
            self.open = Some((id, handle));
            return Ok(Progress::More);
        };
        let mut failure = None;
        let mut found_queue = [0u32; 64];
        let mut found = 0;
        let mut opaque = false;
        let more = {
            let index_ref = &mut *index;
            let mut visit = |ino: u64, kind: u32, name: &[u8]| {
                if failure.is_some() || name == b"." || name == b".." {
                    return;
                }
                let (name, kind) = match special(name) {
                    Special::Opaque => {
                        opaque = true;
                        return;
                    }
                    Special::Reserved => return,
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
                match index_ref.insert(id, name, fields) {
                    Ok(child) => {
                        if kind == Kind::Dir && found < found_queue.len() {
                            found_queue[found] = child;
                            found += 1;
                        }
                    }
                    Err(_) => failure = Some(Failure::NoSpace),
                }
            };
            volume.read_dir(handle, &mut visit)
        };
        if opaque {
            index.set_flags(id, OPAQUE, 0);
        }
        if let Some(f) = failure {
            let _ = volume.close(handle);
            self.open = None;
            return Err(f);
        }
        for &child in &found_queue[..found] {
            self.push(child);
        }
        match more {
            Ok(true) => {}
            Ok(false) => {
                let _ = volume.close(handle);
                self.open = None;
            }
            Err(e) => {
                let _ = volume.close(handle);
                self.open = None;
                return Err(Failure::Volume(e));
            }
        }
        Ok(Progress::More)
    }
}

impl Default for Scan {
    fn default() -> Self {
        Scan::new()
    }
}
