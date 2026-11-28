// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The answers to the requests of the layered root (`proto_fs::names`) and of `proto_layer` that
//! this part serves, over the traits of the calls (`Volume`, `Lower`): the program wraps the
//! requests of the wire around `Core`, the host tests drive it with a tree in memory.
//!
//! The rules (sections 4 and 5 and the decisions 1, 5, 6 and 7 of the split):
//!
//! - OPEN walks the path (`lookup`). A name the index does not hold is REDIRECT to the RAM file
//!   service with the whole path. A file of the layer of the user is opened by the service at the
//!   data file service (its own session, user 0) after the service has checked the right to read
//!   by `posix_perm` on the attributes the volume keeps, and the reply is a pass of that
//!   description. A directory with a name in the layer becomes a description of the service (its
//!   listing is merged); a directory of the lower set alone is REDIRECT. A write flag or a create
//!   flag is READ_ONLY_FILESYSTEM.
//! - STAT is answered by the service for both sets: a name of the layer from the data file
//!   service's attributes, a lower name from the RAM file service's information, with `device` 0
//!   (the POSIX layer puts one number in every stat of the layered root).
//! - CHANGE and the creating or writing OPEN are in `change`.

use crate::composition::{Composition, MAX_TEXT, State as LayerState};
use crate::descriptions::{Lost, Refused, ShareError, Table};
use crate::identity::Vouched;
use crate::index::{Index, Kind};
use crate::listing;
use crate::lookup::{Hidden, Outcome, Walk, normalize_dots};
use crate::scan::{Failure, Progress, Scan};
use crate::volume::{Lower, R, Volume};
use posix_perm::{EXEC, READ, WRITE, permits};
use proto_data as d;
use proto_fs::names::{self as n, DirReply, OpenAnswer};
use proto_fs::{NodeInfo, Redirect, Timestamp};
use proto_layer as l;
use proto_wire::{Status, Writer};

pub(crate) fn st(code: u32) -> Status {
    Status::Unknown(code)
}

/// The directory of the layers on the volume, the file of the composition, the name it is written
/// under, and the work directory.
pub const LAYERS_DIR: &[u8] = b"/.layers";
pub const COMPOSITION: &[u8] = b"/.layers/COMPOSITION";
pub const COMPOSITION_TMP: &[u8] = b"/.layers/COMPOSITION.tmp";
pub const WORK_DIR: &[u8] = b"/.layers/work";
/// The longest path and name the volume holds, and the names the emptying of a directory takes
/// in a batch.
const PATH_MAX: usize = d::MAX_PATH;
const NAME_MAX: usize = d::NAME_MAX;
const BATCH: usize = 8;

/// Where the service stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// The volume is read and the index is being built.
    Starting,
    Ready,
    /// There is no data volume: nothing is served.
    NoStore,
    /// COMPOSITION holds what this part does not serve (a frozen layer) or does not parse, or the
    /// live layer is not there.
    Damaged,
    /// The start failed with this code of `proto_layer` (the index is full, the volume failed).
    Failed(u32),
}

/// Who asks: the session's label and the identity it is bound to.
#[derive(Clone, Copy)]
pub struct Client<'a> {
    pub owner: u64,
    pub who: &'a Vouched,
}

/// What a handler has done with the reply: written it, or written it and has a pass to send. The
/// step that goes on (`Continue`) is the rare one and the one a job keeps, so its size is no cost.
#[allow(clippy::large_enum_variant)]
pub enum Done<P> {
    Written,
    Pass(P),
    /// The OPEN of a file of the layer goes on with its next call to the data file service
    /// (`Core::open_continue`); `Core::open` never returns it.
    Continue(OpenCont),
}

/// The times a build starts again under another seed before it leaves names out.
pub const RESEEDS: u8 = 3;

/// A listing holds the directory open in the index from the first name it gives (the first
/// stage, past `.` and `..`) until it closes, the directory goes, or it is put back to the start:
/// a seek may return to any cursor the replies gave, so the entry at one must stay in the list of
/// the directory (as a gone entry when it is removed) for as long as the cursor may be used.
fn settle<D>(index: &mut Index, desc: &mut crate::descriptions::Description<D>) {
    let inside = desc.position.stage == 0 && desc.position.at > 2;
    if inside
        && desc.walk.is_none()
        && let Some(key) = index.dir_key(desc.dir)
        && index.walk_enter(key)
    {
        desc.walk = Some(key);
    }
}

/// The seed of the next build: a mix of the last one and the number of the attempt.
fn next_seed(seed: u64, attempt: u64) -> u64 {
    let mut h = seed ^ attempt.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    h ^= h >> 30;
    h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 31)
}

pub struct Core<'a, V: Volume, L: Lower> {
    pub volume: V,
    pub lower: L,
    pub index: &'a mut Index,
    scan: &'a mut Scan,
    /// The reaper and the lock of the changes.
    pub(crate) work: &'a mut crate::reaper::Workers,
    pub composition: Composition,
    pub state: State,
    /// The builds that started again under another seed, and the place of the clearing between
    /// two of them (`Index::clear_step`).
    reseeds: u8,
    clearing: Option<usize>,
    /// The build left names out for the buckets: the root is served read-only.
    pub partial: bool,
    /// `/.layers/NN`, the live layer's directory.
    live: [u8; 16],
    live_len: usize,
    pub(crate) table: Table<L::Dir>,
    /// The descriptions whose lower directory is being opened (`listing::LISTINGS_RESOLVING`).
    pub(crate) resolving: u32,
    /// What the changes keep between requests (`change`).
    pub(crate) writes: crate::change::Writes,
    /// The copies up (`copy`).
    pub copies: crate::copy::Table,
    /// The names `work/` held when the service started: what an earlier instance left.
    pub cleared: u32,
}

/// The result of a walk and the plain path it walked, which a redirect carries.
pub struct Walked {
    pub(crate) outcome: Outcome,
    pub(crate) trailing: bool,
    path: [u8; 512],
    len: usize,
    /// The plain path holds a `..`.
    dotted: bool,
    /// The lower set is hidden from the directory the outcome names (`Walk::hidden`).
    pub(crate) hidden: bool,
}

/// The paths of more components than this are walked in steps of their own (`Prewalk`): a step
/// that walks a path and then asks the data file service (the pass of a file, 16,500 ticks under
/// -icount) has room for about four more components of the 0.9 B of a step, 420 ticks each.
pub const SYNC_COMPONENTS: usize = 3;
/// The paths of more bytes than this are walked in steps too: a few long names cost as much to
/// make plain and to compare as many short ones.
pub const SYNC_BYTES: usize = 96;

/// A walk of a long path in progress: the path as it came, then the plain path (`normalize`, which
/// takes a step of its own) and where the walk stands. A request whose path has more than
/// `SYNC_COMPONENTS` components is made plain and walked `lookup::STEP` components a step, and the
/// step that finishes the request starts from the walk's result (`Core::open_walked` and its like),
/// so that no step holds the walk of a long path and the calls to the volume together.
pub struct Prewalk {
    raw: [u8; 512],
    raw_len: usize,
    planned: bool,
    path: [u8; 512],
    len: usize,
    pos: usize,
    cur: u32,
    hidden: Hidden,
    real: bool,
    /// A link at the end of the path is followed.
    follow: bool,
    dotted: bool,
}

impl Prewalk {
    /// Whether `path` is long enough to be walked in steps: more slashes than a short path holds
    /// (a count of bytes, a step of the request that costs a fraction of making the path plain).
    pub fn long(path: &[u8]) -> bool {
        path.len() > SYNC_BYTES || path.iter().filter(|&&b| b == b'/').count() > SYNC_COMPONENTS
    }

    /// The walk of `path` with the real identifiers when `real`.
    pub fn new(path: &[u8], real: bool, follow: bool) -> Prewalk {
        let mut raw = [0u8; 512];
        let raw_len = path.len().min(raw.len());
        raw[..raw_len].copy_from_slice(&path[..raw_len]);
        Prewalk {
            raw,
            raw_len,
            planned: false,
            path: [0; 512],
            len: 0,
            pos: 0,
            cur: 0,
            hidden: Hidden::default(),
            real,
            follow,
            dotted: false,
        }
    }
}

/// What is left of an OPEN of a file of the layer once its name is walked: the three calls to the
/// data file service (the rights of the file, its description, the pass and the close), one in each
/// request of a job. A request that is not deferred runs them one after the other in its own step.
pub struct OpenCont {
    vp: [u8; 512],
    len: usize,
    phase: OpenPhase,
    handle: u32,
    /// The flags of the OPEN: the rights asked and the flags of the description.
    flags: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenPhase {
    Stat,
    Open,
    Export,
}

impl Walked {
    pub fn path(&self) -> &[u8] {
        &self.path[..self.len]
    }

    /// The walk ended at a name the layer does not hold (the lower set's or none): an OPEN that
    /// creates makes it.
    pub fn is_missing(&self) -> bool {
        matches!(self.outcome, Outcome::Lower | Outcome::Absent)
    }

    /// The walk ended at a name of the lower set: an OPEN for writing copies it up.
    pub fn is_lower(&self) -> bool {
        self.outcome == Outcome::Lower
    }

    /// The path ended with a slash.
    pub fn trailing(&self) -> bool {
        self.trailing
    }
}

/// The mapping of a status of the volume to the status of the names.
pub(crate) fn from_volume(status: Status) -> Status {
    match status {
        Status::Unknown(code) => st(match code {
            d::NO_ENTRY => proto_fs::NO_ENTRY,
            d::NOT_DIRECTORY => proto_fs::NOT_DIRECTORY,
            d::IS_DIRECTORY => proto_fs::IS_DIRECTORY,
            d::ACCESS => proto_fs::ACCESS_DENIED,
            d::PERMISSION => proto_fs::PERMISSION,
            d::NAME_TOO_LONG => proto_fs::NAME_TOO_LONG,
            d::NO_SPACE => proto_fs::NO_SPACE,
            d::TABLE_FULL => proto_fs::TOO_MANY_FILES_IN_SYSTEM,
            d::TOO_MANY_OPEN => proto_fs::TOO_MANY_OPEN_FILES,
            d::READ_ONLY => proto_fs::READ_ONLY_FILESYSTEM,
            d::NOT_READY => l::NO_STORE,
            _ => l::IO,
        }),
        other => other,
    }
}

pub(crate) fn node_from(s: &d::Stat) -> R<NodeInfo> {
    let time = |ns: i64| Timestamp::from_ns(i128::from(ns));
    Ok(NodeInfo {
        kind: if s.kind == d::KIND_DIRECTORY { 1 } else { 2 },
        permissions: s.mode & 0o7777,
        device: 0,
        special_device: 0,
        inode: s.ino,
        links: u64::from(s.nlink.max(1)),
        uid: s.uid,
        gid: s.gid,
        size: s.size,
        block_size: 4096,
        blocks: s.size.div_ceil(512),
        access_time: time(s.atime)?,
        modify_time: time(s.mtime)?,
        change_time: time(s.ctime)?,
    })
}

pub(crate) fn attr_of(s: &d::Stat) -> posix_perm::Attr {
    posix_perm::Attr {
        kind: if s.kind == d::KIND_DIRECTORY {
            posix_perm::Kind::Directory
        } else {
            posix_perm::Kind::File
        },
        mode: s.mode & 0o7777,
        uid: s.uid,
        gid: s.gid,
    }
}

impl<'a, V: Volume, L: Lower> Core<'a, V, L> {
    pub fn new(
        index: &'a mut Index,
        scan: &'a mut Scan,
        work: &'a mut crate::reaper::Workers,
        volume: V,
        lower: L,
        epoch: u16,
    ) -> Core<'a, V, L> {
        Core {
            volume,
            lower,
            index,
            scan,
            work,
            composition: Composition::first(),
            state: State::Starting,
            reseeds: 0,
            clearing: None,
            partial: false,
            live: *b"/.layers/00\0\0\0\0\0",
            live_len: 11,
            table: Table::new(epoch),
            resolving: 0,
            writes: crate::change::Writes::default(),
            copies: crate::copy::Table::new(),
            cleared: 0,
        }
    }

    pub fn epoch(&self) -> u16 {
        self.table.epoch()
    }

    pub fn descriptions(&self) -> usize {
        self.table.count()
    }

    pub(crate) fn live_path(&self) -> &[u8] {
        &self.live[..self.live_len]
    }

    // ------------------------------------------------------------------ the start

    /// The start before the loop: reads COMPOSITION (or makes the first one), empties `work/`.
    /// The state after it is Starting (the index is to be built), NoStore, Damaged or Failed.
    pub fn prepare(&mut self) {
        self.state = match self.read_volume() {
            Ok(()) => State::Starting,
            Err(state) => state,
        };
    }

    fn read_volume(&mut self) -> Result<(), State> {
        let failed = |s: Status| match s {
            Status::Unknown(d::NOT_READY) => State::NoStore,
            other => State::Failed(match other {
                Status::Unknown(d::NO_SPACE) => l::NO_SPACE,
                _ => l::IO,
            }),
        };
        let mut text = [0u8; MAX_TEXT];
        let got = match self.read_file(COMPOSITION, &mut text) {
            Ok(len) => Some(len),
            Err(Status::Unknown(d::NO_ENTRY)) => None,
            Err(other) => return Err(failed(other)),
        };
        match got {
            None => {
                self.first_start().map_err(failed)?;
                self.composition = Composition::first();
            }
            Some(len) => match Composition::parse(&text[..len]) {
                Ok(c) if !c.has_stack() => self.composition = c,
                // A frozen or deferred layer needs the checks and the seal of later parts, and a
                // file that does not parse is no composition.
                Ok(_) | Err(_) => return Err(State::Damaged),
            },
        }
        let number = self.composition.live().number;
        self.live[..9].copy_from_slice(b"/.layers/");
        self.live[9] = b'0' + number / 10;
        self.live[10] = b'0' + number % 10;
        self.live_len = 11;
        let live = self.live;
        match self.volume.stat(&live[..self.live_len]) {
            Ok(s) if s.kind == d::KIND_DIRECTORY => {}
            Ok(_) | Err(Status::Unknown(d::NO_ENTRY)) => return Err(State::Damaged),
            Err(e) => return Err(failed(e)),
        }
        self.clear_work().map_err(failed)
    }

    pub(crate) fn read_file(&mut self, path: &[u8], out: &mut [u8]) -> R<usize> {
        let h = self.volume.open(path, d::READ, 0)?;
        let mut len = 0;
        let result = loop {
            if len == out.len() {
                break Err(st(d::TOO_BIG));
            }
            match self.volume.read(h, &mut out[len..]) {
                Ok(0) => break Ok(len),
                Ok(k) => len += k,
                Err(e) => break Err(e),
            }
        };
        let closed = self.volume.close(h);
        result.and_then(|len| closed.map(|()| len))
    }

    /// The first start on a volume: `/.layers` (0700, user 0), `00` (0755), `work` (0700) and the
    /// COMPOSITION file made under a temporary name, synced and renamed.
    fn first_start(&mut self) -> R<()> {
        for (path, mode) in [
            (LAYERS_DIR, 0o700),
            (&b"/.layers/00"[..], 0o755),
            (WORK_DIR, 0o700),
        ] {
            match self.volume.mkdir(path, mode) {
                Ok(()) | Err(Status::Unknown(d::EXISTS)) => {}
                Err(e) => return Err(e),
            }
        }
        let mut text = [0u8; MAX_TEXT];
        let len = Composition::first().render(&mut text);
        let h = self
            .volume
            .open(COMPOSITION_TMP, d::WRITE | d::CREATE | d::TRUNCATE, 0o600)?;
        let written = (|| {
            let mut at = 0;
            while at < len {
                let k = self.volume.write(h, &text[at..len])?;
                if k == 0 {
                    return Err(st(d::NO_SPACE));
                }
                at += k;
            }
            self.volume.fsync(h)
        })();
        let closed = self.volume.close(h);
        written.and(closed)?;
        self.volume.rename(COMPOSITION_TMP, COMPOSITION)
    }

    /// Empties `work/`: it holds what an interrupted change left, which no name refers to.
    fn clear_work(&mut self) -> R<()> {
        match self.volume.stat(WORK_DIR) {
            Ok(_) => {}
            Err(Status::Unknown(d::NO_ENTRY)) => {
                return self.volume.mkdir(WORK_DIR, 0o700);
            }
            Err(e) => return Err(e),
        }
        self.remove_inside(WORK_DIR)
    }

    /// Removes everything below `root`, depth first with no recursion: the path of the directory
    /// being emptied is one buffer, a directory that is found is entered, and an empty one is
    /// removed and left. The depth is the longest path the volume holds (`PATH_MAX`), and a name is
    /// as long as the volume allows.
    pub(crate) fn remove_inside(&mut self, root: &[u8]) -> R<()> {
        let mut path = [0u8; PATH_MAX];
        let mut len = root.len();
        path[..len].copy_from_slice(root);
        loop {
            // The names of one batch of the directory, then their removal; a listing that finds
            // the directory empty ends it.
            let mut names = [[0u8; NAME_MAX]; BATCH];
            let mut lens = [0usize; BATCH];
            let mut kinds = [0u32; BATCH];
            let mut count = 0;
            let h = self.volume.open(&path[..len], d::READ | d::DIRECTORY, 0)?;
            let more = self.volume.read_dir(h, &mut |_, kind, name| {
                if name == b"." || name == b".." || count == BATCH || name.len() > NAME_MAX {
                    return;
                }
                names[count][..name.len()].copy_from_slice(name);
                lens[count] = name.len();
                kinds[count] = kind;
                count += 1;
            });
            let _ = self.volume.close(h);
            more?;
            if count == 0 {
                if len == root.len() {
                    return Ok(());
                }
                self.volume.rmdir(&path[..len])?;
                if root == WORK_DIR {
                    self.cleared += 1;
                }
                while path[len - 1] != b'/' {
                    len -= 1;
                }
                len -= 1;
                continue;
            }
            for i in 0..count {
                let at = len + 1 + lens[i];
                if at > PATH_MAX {
                    return Err(st(d::NAME_TOO_LONG));
                }
                path[len] = b'/';
                path[len + 1..at].copy_from_slice(&names[i][..lens[i]]);
                if kinds[i] == d::KIND_DIRECTORY {
                    len = at;
                    break;
                }
                self.volume.unlink(&path[..at])?;
                if root == WORK_DIR {
                    self.cleared += 1;
                }
            }
        }
    }

    /// One step of the build of the index; true when it is done. A failure ends the build and
    /// leaves the state `Failed`.
    pub fn build_step(&mut self) -> bool {
        if self.state != State::Starting {
            return true;
        }
        if let Some(from) = self.clearing {
            self.clearing = self.index.clear_step(from);
            if self.clearing.is_none() {
                self.scan.reset();
            }
            return false;
        }
        let mut root = [0u8; 16];
        let len = self.live_len;
        root[..len].copy_from_slice(self.live_path());
        let layer = self.composition.live().number;
        let mut stepped = self
            .scan
            .step(self.index, &mut self.volume, &root[..len], layer);
        // The deliberate break: the whole layer in one step.
        while cfg!(feature = "break-layerd-one-step") && stepped == Ok(Progress::More) {
            stepped = self
                .scan
                .step(self.index, &mut self.volume, &root[..len], layer);
        }
        match stepped {
            Ok(Progress::More) => false,
            Ok(Progress::Done) => {
                self.partial = self.scan.skipped_names + self.scan.skipped_marks != 0;
                self.state = State::Ready;
                true
            }
            Err(Failure::Reseed) => {
                // Both buckets of a name are full: the build starts again under another seed, a
                // few times at most.
                self.reseeds += 1;
                self.scan.patient = self.reseeds < RESEEDS;
                self.index
                    .set_seed(next_seed(self.index.seed(), u64::from(self.reseeds)));
                self.clearing = Some(0);
                false
            }
            Err(Failure::NoSpace) => {
                self.state = State::Failed(l::NO_SPACE);
                true
            }
            Err(Failure::Volume(s)) => {
                self.state = match s {
                    Status::Unknown(d::NOT_READY) => State::NoStore,
                    _ => State::Failed(l::IO),
                };
                true
            }
        }
    }

    /// The names and the marks the build left out for the buckets.
    pub fn left_out(&self) -> (u32, u32) {
        (self.scan.skipped_names, self.scan.skipped_marks)
    }

    /// The directories the build left out for a path past the volume's limit.
    pub fn skipped(&self) -> u32 {
        self.scan.skipped
    }

    pub fn build_steps(&self) -> u32 {
        self.scan.steps
    }

    // ------------------------------------------------------------------ proto_layer

    /// The code a request of the names answers while the service cannot serve.
    pub(crate) fn gate(&self) -> Result<(), Status> {
        match self.state {
            State::Ready => Ok(()),
            State::Starting => Err(st(crate::starting::code(crate::starting::Cause::Build))),
            State::NoStore => Err(st(l::NO_STORE)),
            State::Damaged => Err(st(l::DAMAGED)),
            State::Failed(code) => Err(st(code)),
        }
    }

    /// The reply of STATUS after its status.
    pub fn status(&self, w: &mut Writer) -> R<()> {
        let flags = match self.state {
            State::Starting => l::STATUS_STARTING,
            State::NoStore => l::STATUS_NO_STORE,
            State::Ready if self.partial => l::STATUS_PARTIAL,
            State::Ready => 0,
            State::Damaged => return Err(st(l::DAMAGED)),
            State::Failed(code) => return Err(st(code)),
        };
        let (added, deleted) = self.index.counts();
        let stat = l::Stat {
            live: u32::from(self.composition.live().number),
            frozen: 0,
            deferred: 0,
            flags,
            generation: 1,
            added,
            changed: 0,
            deleted,
            names: self.index.names(),
            bytes: 0,
            job: l::JOB_NONE,
            queued: 0,
            done: 0,
            total: 0,
        };
        w.u32(0)?;
        stat.write(w)
    }

    /// The reply of LIST: the lower set and the live layer, one page.
    pub fn list(&self, first: u32, w: &mut Writer) -> R<()> {
        self.gate()?;
        let live = self.composition.live();
        let zero = [0u8; l::DIGEST_LEN];
        let entries = [
            l::Entry {
                number: l::NO_NUMBER,
                kind: l::KIND_PACKAGES,
                flags: l::ENTRY_SEALED,
                parent: l::NO_NUMBER,
                composition: 0,
                root: self.composition.lower.unwrap_or(zero),
                chain: zero,
                lower: zero,
                bytes: 0,
                time: 0,
                note: b"",
            },
            l::Entry {
                number: u32::from(live.number),
                kind: l::KIND_LIVE,
                flags: 0,
                parent: l::NO_NUMBER,
                composition: 0,
                root: zero,
                chain: zero,
                lower: zero,
                bytes: 0,
                time: 0,
                note: b"",
            },
        ];
        let page = entries.get(first as usize..).unwrap_or(&[]);
        w.u32(0)?;
        l::write_list_head(page.len() as u32, 0, w)?;
        for e in page {
            e.write(w)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------ the names

    /// The path of the entry `id` on the volume. A symbolic link is the file
    /// `.wh..wh.lnk.<name>` in the directory of the name.
    pub(crate) fn vpath(&self, id: u32, out: &mut [u8; 512]) -> R<usize> {
        let n = Scan::volume_path(self.index, self.live_path(), id, out)
            .ok_or_else(|| st(proto_fs::NAME_TOO_LONG))?;
        if self.index.entry(id).is_none_or(|e| e.kind != Kind::Link) {
            return Ok(n);
        }
        let at = out[..n].iter().rposition(|&b| b == b'/').unwrap_or(0) + 1;
        let prefix = crate::scan::LINK_PREFIX;
        if n + prefix.len() > out.len() {
            return Err(st(proto_fs::NAME_TOO_LONG));
        }
        out.copy_within(at..n, at + prefix.len());
        out[at..at + prefix.len()].copy_from_slice(prefix);
        Ok(n + prefix.len())
    }

    /// The volume path of the entry `id` a walk reached: the live layer's path and the plain path
    /// of the walk, which names the chain of the entry exactly (each component was matched by its
    /// name), where the way up the index costs 70 ticks for each level, 17,000 for the deepest
    /// path.
    fn vpath_of(&self, walked: &Walked, id: u32, out: &mut [u8; 512]) -> R<usize> {
        let live = self.live_path();
        let plain = walked.path();
        let plain = match plain.strip_suffix(b"/") {
            Some(rest) if !rest.is_empty() => rest,
            _ => plain,
        };
        let end = live.len() + plain.len();
        // A link's file has another name, and a path with a `..` does not name the chain.
        let dotted = walked.dotted;
        let link = self.index.entry(id).is_some_and(|e| e.kind == Kind::Link);
        if id == 0 || dotted || link || plain.first() != Some(&b'/') || end > out.len() {
            return self.vpath(id, out);
        }
        out[..live.len()].copy_from_slice(live);
        out[live.len()..end].copy_from_slice(plain);
        Ok(end)
    }

    /// Whether a request can be walked in steps: the service answers (not STARTING or damaged).
    pub fn walkable(&self) -> bool {
        self.state == State::Ready
    }

    /// One step of a long walk: `lookup::STEP` components of `pw`; the result when the walk is done.
    pub fn prewalk_step(&self, who: &Vouched, pw: &mut Prewalk) -> Option<Walked> {
        // The first step makes the path plain (about 13,000 ticks for a path of 253 components).
        if !pw.planned {
            (pw.len, pw.dotted) = normalize_dots(&pw.raw[..pw.raw_len], &mut pw.path);
            pw.planned = true;
            return None;
        }
        let mut walk = Walk::resume(&pw.path[..pw.len], pw.pos, pw.cur, pw.hidden);
        if !pw.follow {
            walk = walk.no_follow();
        }
        let step = walk.advance(self.index, who.identity(pw.real), crate::lookup::STEP);
        (pw.pos, pw.cur, pw.hidden) = walk.state();
        let trailing = walk.trailing_slash();
        match step {
            crate::lookup::Step::More => None,
            crate::lookup::Step::Done(outcome) => Some(Walked {
                outcome,
                trailing,
                path: pw.path,
                len: pw.len,
                dotted: pw.dotted,
                hidden: walk.hidden(),
            }),
        }
    }

    /// The walk of `path` after it is made plain (`lookup::normalize`), with the real identifiers
    /// when `real` (ACCESS with `ACCESS_REAL`) and the effective ones otherwise.
    pub(crate) fn walk(&self, c: &Client<'_>, path: &[u8], real: bool, follow: bool) -> Walked {
        let mut plain = [0u8; 512];
        let (len, dotted) = normalize_dots(path, &mut plain);
        let walk = if follow {
            Walk::new(&plain[..len])
        } else {
            Walk::new(&plain[..len]).no_follow()
        };
        let trailing = walk.trailing_slash();
        let mut walk = walk;
        let outcome = loop {
            if let crate::lookup::Step::Done(o) =
                walk.advance(self.index, c.who.identity(real), crate::lookup::STEP)
            {
                break o;
            }
        };
        Walked {
            outcome,
            trailing,
            path: plain,
            len,
            dotted,
            hidden: walk.hidden(),
        }
    }

    /// A failure of a walk, as a status.
    pub(crate) fn refusal(outcome: Outcome) -> Status {
        st(match outcome {
            Outcome::Absent => proto_fs::NO_ENTRY,
            Outcome::NotDir => proto_fs::NOT_DIRECTORY,
            Outcome::Denied => proto_fs::ACCESS_DENIED,
            Outcome::NameTooLong => proto_fs::NAME_TOO_LONG,
            _ => proto_fs::INVALID_ARGUMENT,
        })
    }

    pub(crate) fn redirect(path: &[u8], target: u32, w: &mut Writer) -> R<()> {
        Redirect {
            target,
            index: 0,
            links: 0,
            path,
        }
        .write(w)
    }

    fn redirect_for(outcome: Outcome, path: &[u8], w: &mut Writer) -> Option<R<()>> {
        match outcome {
            Outcome::Lower | Outcome::PassThrough { data: false } => {
                Some(Self::redirect(path, proto_fs::REDIRECT_RAM, w))
            }
            Outcome::PassThrough { data: true } => {
                Some(Self::redirect(path, proto_fs::REDIRECT_DATA, w))
            }
            _ => None,
        }
    }

    /// OPEN (`names::read_open` has checked the request).
    pub fn open(
        &mut self,
        c: &Client<'_>,
        flags: u32,
        path: &[u8],
        w: &mut Writer,
    ) -> R<Done<V::Pass>> {
        self.open_walked(c, flags, None, false, path, w)
    }

    /// OPEN of a path the walk of which was made in steps (`prewalk_step`), or of `path` when None.
    /// With `stepwise` the open of a file of the layer ends in `Done::Continue`: its calls to the
    /// data file service go on with `open_continue`, one in each step (a copy of the state is a
    /// copy of 530 bytes, 1,600 ticks under -icount, so the request that does all the calls in
    /// its own step does not make it).
    pub fn open_walked(
        &mut self,
        c: &Client<'_>,
        flags: u32,
        walked: Option<Walked>,
        stepwise: bool,
        path: &[u8],
        w: &mut Writer,
    ) -> R<Done<V::Pass>> {
        self.gate()?;
        let creates = flags & proto_fs::CREATE != 0;
        let excl = flags & proto_fs::EXCLUSIVE != 0;
        // A name that is made (CREATE and EXCLUSIVE) is not followed at its end.
        let follow = flags & proto_fs::NO_FOLLOW == 0 && !(creates && excl);
        let walked = walked.unwrap_or_else(|| self.walk(c, path, false, follow));
        let (outcome, trailing) = (walked.outcome, walked.trailing);
        if let Outcome::Link { id, start, end } = outcome {
            return self
                .link_redirect(&walked, id, start, end, w)
                .map(|()| Done::Written);
        }
        // The names the root passes through are the services' own, writes included. A name that
        // the layer of the user does not hold is made in the layer when it is not there (in the
        // lower set too), and a name of the lower set that is opened for writing is copied up
        // first (the answer is COPYING, `copy`).
        let writes = n::open_writes(flags);
        let makes = creates && matches!(outcome, Outcome::Lower | Outcome::Absent);
        if (makes || writes && outcome == Outcome::Lower)
            && let Some(done) = self.create_and_open(c, flags, &walked, w)?
        {
            return Ok(done);
        }
        if let Some(done) = Self::redirect_for(outcome, walked.path(), w) {
            return done.map(|()| Done::Written);
        }
        let Outcome::Upper(id) = outcome else {
            return Err(Self::refusal(outcome));
        };
        // A create of a name of the layer opens it, and with EXCLUSIVE it is there.
        if creates && excl {
            return Err(st(proto_fs::ALREADY_EXISTS));
        }
        let entry_kind = self.index.entry(id).map(|e| e.kind);
        if entry_kind == Some(Kind::Link) {
            return Err(st(proto_fs::LOOP));
        }
        let is_dir = id == 0 || entry_kind == Some(Kind::Dir);
        if is_dir {
            if writes {
                return Err(st(proto_fs::IS_DIRECTORY));
            }
            let attr = self
                .index
                .attr(id)
                .ok_or_else(|| st(proto_fs::NOT_DIRECTORY))?;
            if !permits(c.who.identity(false), &attr, READ) {
                return Err(st(proto_fs::ACCESS_DENIED));
            }
            // Every limit of the descriptions, of the session, of the process and of the service,
            // is the service's own table: ENFILE.
            let handle = self
                .table
                .make(c.owner, c.who.pid, id, walked.hidden)
                .map_err(|_: Refused| st(proto_fs::TOO_MANY_FILES_IN_SYSTEM))?;
            OpenAnswer::Directory { handle }.write(w)?;
            return Ok(Done::Written);
        }
        if flags & proto_fs::DIRECTORY_ONLY != 0 || trailing {
            return Err(st(proto_fs::NOT_DIRECTORY));
        }
        let mut vp = [0u8; 512];
        let len = self.vpath_of(&walked, id, &mut vp)?;
        if stepwise {
            return Ok(Done::Continue(OpenCont {
                vp,
                len,
                phase: OpenPhase::Stat,
                handle: 0,
                flags,
            }));
        }
        let path = &vp[..len];
        self.open_rights(c, path, flags)?;
        let handle = self
            .volume
            .open(path, Self::wire_flags(flags), 0)
            .map_err(from_volume)?;
        self.open_pass(handle, w)
    }

    /// The flags of the data file service for the flags of an OPEN of a file of the layer: the
    /// access asked, and for a write the cut and the append.
    pub(crate) fn wire_flags(flags: u32) -> u32 {
        let writes = n::open_writes(flags);
        let mut wire = 0;
        if flags & 3 != proto_fs::WRITE_ONLY {
            wire |= d::READ;
        }
        if writes {
            wire |= d::WRITE;
            if flags & proto_fs::TRUNCATE != 0 {
                wire |= d::TRUNCATE;
            }
            if flags & proto_fs::APPEND != 0 {
                wire |= d::APPEND;
            }
        }
        wire
    }

    /// The right to read and to write (as `flags` ask) the file at `path` on the volume.
    pub(crate) fn open_rights(&mut self, c: &Client<'_>, path: &[u8], flags: u32) -> R<()> {
        let stat = self.volume.stat(path).map_err(from_volume)?;
        let mut bits = 0;
        if flags & 3 != proto_fs::WRITE_ONLY {
            bits |= READ;
        }
        if n::open_writes(flags) {
            bits |= WRITE;
        }
        if permits(c.who.identity(false), &attr_of(&stat), bits) {
            Ok(())
        } else {
            Err(st(proto_fs::ACCESS_DENIED))
        }
    }

    /// The pass of the description `handle`, which closes whatever the pass came to.
    pub(crate) fn open_pass(&mut self, handle: u32, w: &mut Writer) -> R<Done<V::Pass>> {
        let pass = self.volume.export(handle);
        let _ = self.volume.close(handle);
        let pass = pass.map_err(from_volume)?;
        OpenAnswer::Pass.write(w)?;
        Ok(Done::Pass(pass))
    }

    /// The next call of the OPEN of a file of the layer: the rights, then the description, then
    /// the pass (and the close of the description, whatever the pass came to).
    pub fn open_continue(
        &mut self,
        c: &Client<'_>,
        mut cont: OpenCont,
        w: &mut Writer,
    ) -> R<Done<V::Pass>> {
        let path = &cont.vp[..cont.len];
        match cont.phase {
            OpenPhase::Stat => {
                self.open_rights(c, path, cont.flags)?;
                cont.phase = OpenPhase::Open;
                Ok(Done::Continue(cont))
            }
            OpenPhase::Open => {
                cont.handle = self
                    .volume
                    .open(path, Self::wire_flags(cont.flags), 0)
                    .map_err(from_volume)?;
                cont.phase = OpenPhase::Export;
                Ok(Done::Continue(cont))
            }
            OpenPhase::Export => self.open_pass(cont.handle, w),
        }
    }

    /// An OPEN given up between its calls (its client went): the description it holds closes.
    pub fn open_abandon(&mut self, cont: OpenCont) {
        if cont.phase == OpenPhase::Export {
            let _ = self.volume.close(cont.handle);
        }
    }

    /// STAT: the node information of a name of the layer. A name of the lower set, and the names
    /// the root passes through, are a redirect: the RAM file service answers with the rights of the
    /// caller's own session and follows the links as the flags say.
    pub fn stat(&mut self, c: &Client<'_>, flags: u32, path: &[u8], w: &mut Writer) -> R<()> {
        self.stat_walked(c, flags, None, path, w)
    }

    /// STAT of a path the walk of which was made in steps, or of `path` when None.
    pub fn stat_walked(
        &mut self,
        c: &Client<'_>,
        flags: u32,
        walked: Option<Walked>,
        path: &[u8],
        w: &mut Writer,
    ) -> R<()> {
        self.gate()?;
        let walked =
            walked.unwrap_or_else(|| self.walk(c, path, false, flags & n::STAT_NO_FOLLOW == 0));
        if let Outcome::Link { id, start, end } = walked.outcome {
            return self.link_redirect(&walked, id, start, end, w);
        }
        if let Some(done) = Self::redirect_for(walked.outcome, walked.path(), w) {
            return done;
        }
        let Outcome::Upper(id) = walked.outcome else {
            return Err(Self::refusal(walked.outcome));
        };
        let mut vp = [0u8; 512];
        let len = self.vpath_of(&walked, id, &mut vp)?;
        let stat = self.volume.stat(&vp[..len]).map_err(from_volume)?;
        let is_link = self.index.entry(id).is_some_and(|e| e.kind == Kind::Link);
        if walked.trailing && (stat.kind != d::KIND_DIRECTORY || is_link) {
            return Err(st(proto_fs::NOT_DIRECTORY));
        }
        let mut info = node_from(&stat)?;
        if is_link {
            info.kind = 5;
            info.permissions = 0o777;
        }
        n::write_info(&info, w)
    }

    /// ACCESS: whether the bits are allowed; a name of the lower set is the RAM file service's.
    pub fn access(
        &mut self,
        c: &Client<'_>,
        bits: u32,
        flags: u32,
        path: &[u8],
        w: &mut Writer,
    ) -> R<()> {
        self.access_walked(c, (bits, flags), None, path, w)
    }

    /// ACCESS of a path the walk of which was made in steps (with the identifiers the bits are
    /// checked with), or of `path` when None.
    pub fn access_walked(
        &mut self,
        c: &Client<'_>,
        (bits, flags): (u32, u32),
        walked: Option<Walked>,
        path: &[u8],
        w: &mut Writer,
    ) -> R<()> {
        self.gate()?;
        // The path is walked with the identifiers the bits are checked with.
        let walked =
            walked.unwrap_or_else(|| self.walk(c, path, flags & d::ACCESS_REAL != 0, true));
        if let Outcome::Link { id, start, end } = walked.outcome {
            return self.link_redirect(&walked, id, start, end, w);
        }
        if let Some(done) = Self::redirect_for(walked.outcome, walked.path(), w) {
            return done;
        }
        let Outcome::Upper(id) = walked.outcome else {
            return Err(Self::refusal(walked.outcome));
        };
        let mut vp = [0u8; 512];
        let len = self.vpath_of(&walked, id, &mut vp)?;
        let stat = self.volume.stat(&vp[..len]).map_err(from_volume)?;
        posix_perm::access(
            c.who.ids,
            c.who.groups(),
            &attr_of(&stat),
            bits & (READ | WRITE | EXEC),
            flags & d::ACCESS_REAL != 0,
        )
        .map_err(|_| st(proto_fs::ACCESS_DENIED))?;
        w.u32(0)
    }

    /// READLINK: the text of a link of the layer of the user; a name of the layer that is no link
    /// is INVALID_ARGUMENT, and a lower name is the RAM file service's.
    pub fn readlink(&mut self, c: &Client<'_>, path: &[u8], w: &mut Writer) -> R<()> {
        self.readlink_walked(c, None, path, w)
    }

    /// READLINK of a path the walk of which was made in steps, or of `path` when None.
    pub fn readlink_walked(
        &mut self,
        c: &Client<'_>,
        walked: Option<Walked>,
        path: &[u8],
        w: &mut Writer,
    ) -> R<()> {
        self.gate()?;
        let walked = walked.unwrap_or_else(|| self.walk(c, path, false, false));
        if let Outcome::Link { id, start, end } = walked.outcome {
            return self.link_redirect(&walked, id, start, end, w);
        }
        if let Some(done) = Self::redirect_for(walked.outcome, walked.path(), w) {
            return done;
        }
        match walked.outcome {
            Outcome::Upper(id) if self.index.entry(id).is_some_and(|e| e.kind == Kind::Link) => {
                let mut text = [0u8; 512];
                let len = self.link_text(id, &mut text)?;
                w.u32(0)?;
                w.bytes(&text[..len])
            }
            Outcome::Upper(_) => Err(st(proto_fs::INVALID_ARGUMENT)),
            other => Err(Self::refusal(other)),
        }
    }

    fn lost(l: Lost) -> Status {
        st(match l {
            Lost::Bad => proto_fs::BAD_FD,
            Lost::Stale => proto_fs::STALE,
        })
    }

    pub fn fstat(&mut self, owner: u64, handle: u32, w: &mut Writer) -> R<()> {
        self.gate()?;
        let dir = self.table.get(owner, handle).map_err(Self::lost)?.dir;
        if dir == crate::descriptions::GONE {
            return Err(st(proto_fs::NO_ENTRY));
        }
        let mut vp = [0u8; 512];
        let len = self.vpath(dir, &mut vp)?;
        let stat = self.volume.stat(&vp[..len]).map_err(from_volume)?;
        n::write_info(&node_from(&stat)?, w)
    }

    /// READ_DIR: the reply is returned whole, with its length.
    /// READ_DIR: the reply is written to the end of `out`, and its length is the answer.
    pub fn read_dir_into(&mut self, owner: u64, handle: u32, out: &mut Writer) -> R<usize> {
        self.gate()?;
        let Core {
            table,
            index,
            lower,
            resolving,
            ..
        } = self;
        let mine = table.opening_held(owner);
        let desc = table.get(owner, handle).map_err(Self::lost)?;
        let mut reply = DirReply::new()?;
        if desc.dir == crate::descriptions::GONE {
            let len = reply.len();
            reply.finish_into(false, 0, out)?;
            return Ok(len);
        }
        let listed = listing::read_dir(
            index,
            lower,
            desc.dir,
            desc.hidden,
            &mut desc.position,
            &mut desc.lower,
            &mut desc.opening,
            resolving,
            mine,
            &mut desc.replayed,
            &mut reply,
        )?;
        // What the replies have given out, which SEEK_DIR may go back to and not past.
        desc.given = desc.given.max(desc.position);
        settle(index, desc);
        let len = reply.len();
        reply.finish_into(listed.more, listed.cursor, out)?;
        Ok(len)
    }

    /// `read_dir_into` with the reply as an array (for the tests).
    #[cfg(test)]
    pub fn read_dir(&mut self, owner: u64, handle: u32) -> R<([u8; abi::MESSAGE_MAX], usize)> {
        let mut w = Writer::new();
        let len = self.read_dir_into(owner, handle, &mut w)?;
        let mut bytes = [0u8; abi::MESSAGE_MAX];
        bytes[..len].copy_from_slice(w.as_bytes());
        Ok((bytes, len))
    }

    pub fn rewind(&mut self, owner: u64, handle: u32) -> R<()> {
        self.gate()?;
        let Core {
            table,
            index,
            lower,
            resolving,
            ..
        } = self;
        let desc = table.get(owner, handle).map_err(Self::lost)?;
        listing::rewind(
            lower,
            &mut desc.position,
            &mut desc.lower,
            &mut desc.opening,
            resolving,
            &mut desc.replayed,
        )?;
        // Back at the start: the cursors given so far are no more, so the hold goes with them.
        desc.given = crate::descriptions::Position::default();
        if let Some(key) = desc.walk.take() {
            index.walk_leave(key);
        }
        Ok(())
    }

    pub fn seek_dir(&mut self, owner: u64, handle: u32, cursor: u64) -> R<()> {
        self.gate()?;
        let Core {
            table,
            index,
            lower,
            resolving,
            ..
        } = self;
        let desc = table.get(owner, handle).map_err(Self::lost)?;
        listing::seek(
            lower,
            &mut desc.position,
            desc.given,
            &mut desc.lower,
            &mut desc.opening,
            resolving,
            &mut desc.replayed,
            cursor,
        )?;
        settle(index, desc);
        Ok(())
    }

    /// `owner` lets go of a description; the lower directory it kept closes with the last holder.
    pub fn close(&mut self, owner: u64, handle: u32) -> R<()> {
        let freed = self.table.close(owner, handle).map_err(Self::lost)?;
        if let Some(d) = freed {
            if let Some(key) = d.walk {
                self.index.walk_leave(key);
            }
            self.give_back(d.lower, d.opening);
        }
        Ok(())
    }

    /// CLONE and CLONE_MORE: the session `to` holds a share of each description of `handles` that
    /// the session `from` holds. A description is one for the holders, its position shared, as
    /// POSIX shares an open file description across a fork. All or none.
    pub fn share(&mut self, from: u64, handles: &[u32], to: u64) -> R<()> {
        self.table.share(from, handles, to).map_err(|e| match e {
            ShareError::Lost(lost) => Self::lost(lost),
            ShareError::Full => st(proto_fs::TOO_MANY_FILES_IN_SYSTEM),
        })
    }

    /// The session `owner` went: what it held closes.
    pub fn gone(&mut self, owner: u64) {
        while let Some(d) = self.table.take_owned(owner) {
            if let Some(key) = d.walk {
                self.index.walk_leave(key);
            }
            self.give_back(d.lower, d.opening);
        }
    }

    /// The lower directory of a description that went closes; one that was being opened frees its
    /// place among the listings that resolve.
    fn give_back(&mut self, dir: Option<L::Dir>, opening: bool) {
        if let Some(dir) = dir {
            self.lower.close_dir(dir);
            if opening {
                self.resolving -= 1;
            }
        }
    }

    /// The number of the live layer, for the lines of the program.
    pub fn live_number(&self) -> u8 {
        self.composition.live().number
    }

    pub fn has_live(&self) -> bool {
        self.composition
            .layers()
            .iter()
            .any(|x| x.state == LayerState::Live)
    }
}
