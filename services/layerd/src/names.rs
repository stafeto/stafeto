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
//! - CHANGE is READ_ONLY_FILESYSTEM, and the other methods the part does not serve are not in the
//!   list of the program.

use crate::composition::{Composition, MAX_TEXT, State as LayerState};
use crate::descriptions::{Lost, Refused, Table};
use crate::identity::Vouched;
use crate::index::{Index, Kind};
use crate::listing;
use crate::lookup::{Outcome, Walk, normalize};
use crate::scan::{Failure, Progress, Scan};
use crate::volume::{Lower, R, Volume};
use posix_perm::{EXEC, READ, WRITE, permits};
use proto_data as d;
use proto_fs::names::{self as n, DirReply, OpenAnswer};
use proto_fs::{NodeInfo, Redirect, Timestamp};
use proto_layer as l;
use proto_wire::{Status, Writer};

fn st(code: u32) -> Status {
    Status::Unknown(code)
}

/// The directory of the layers on the volume, the file of the composition, the name it is written
/// under, and the work directory.
pub const LAYERS_DIR: &[u8] = b"/.layers";
pub const COMPOSITION: &[u8] = b"/.layers/COMPOSITION";
pub const COMPOSITION_TMP: &[u8] = b"/.layers/COMPOSITION.tmp";
pub const WORK_DIR: &[u8] = b"/.layers/work";

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

/// What a handler has done with the reply: written it, or written it and has a pass to send.
pub enum Done<P> {
    Written,
    Pass(P),
}

pub struct Core<'a, V: Volume, L: Lower> {
    pub volume: V,
    pub lower: L,
    pub index: &'a mut Index,
    scan: &'a mut Scan,
    pub composition: Composition,
    pub state: State,
    /// `/.layers/NN`, the live layer's directory.
    live: [u8; 16],
    live_len: usize,
    table: Table<L::Dir>,
}

/// The result of a walk and the plain path it walked, which a redirect carries.
struct Walked {
    outcome: Outcome,
    trailing: bool,
    path: [u8; 512],
    len: usize,
}

impl Walked {
    fn path(&self) -> &[u8] {
        &self.path[..self.len]
    }
}

/// The mapping of a status of the volume to the status of the names.
fn from_volume(status: Status) -> Status {
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

fn node_from(s: &d::Stat) -> R<NodeInfo> {
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

fn attr_of(s: &d::Stat) -> posix_perm::Attr {
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
        volume: V,
        lower: L,
        epoch: u16,
    ) -> Core<'a, V, L> {
        Core {
            volume,
            lower,
            index,
            scan,
            composition: Composition::first(),
            state: State::Starting,
            live: *b"/.layers/00\0\0\0\0\0",
            live_len: 11,
            table: Table::new(epoch),
        }
    }

    pub fn epoch(&self) -> u16 {
        self.table.epoch()
    }

    pub fn descriptions(&self) -> usize {
        self.table.count()
    }

    fn live_path(&self) -> &[u8] {
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

    fn read_file(&mut self, path: &[u8], out: &mut [u8]) -> R<usize> {
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
        self.remove_inside(WORK_DIR, 0)
    }

    fn remove_inside(&mut self, dir: &[u8], depth: usize) -> R<()> {
        // The names of one batch, then their removal; the listing starts again until it is empty.
        loop {
            let mut names = [[0u8; 64]; 8];
            let mut lens = [0usize; 8];
            let mut kinds = [0u32; 8];
            let mut count = 0;
            let h = self.volume.open(dir, d::READ | d::DIRECTORY, 0)?;
            let more = self.volume.read_dir(h, &mut |_, kind, name| {
                if name == b"." || name == b".." || count == 8 || name.len() > 64 {
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
                return Ok(());
            }
            for i in 0..count {
                let mut path = [0u8; 160];
                let dl = dir.len();
                if dl + 1 + lens[i] > path.len() {
                    return Err(st(d::NAME_TOO_LONG));
                }
                path[..dl].copy_from_slice(dir);
                path[dl] = b'/';
                path[dl + 1..dl + 1 + lens[i]].copy_from_slice(&names[i][..lens[i]]);
                let path = &path[..dl + 1 + lens[i]];
                if kinds[i] == d::KIND_DIRECTORY {
                    if depth >= 4 {
                        return Err(st(d::NOT_EMPTY));
                    }
                    self.remove_inside(path, depth + 1)?;
                    self.volume.rmdir(path)?;
                } else {
                    self.volume.unlink(path)?;
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
        let mut root = [0u8; 16];
        let len = self.live_len;
        root[..len].copy_from_slice(self.live_path());
        let layer = self.composition.live().number;
        match self
            .scan
            .step(self.index, &mut self.volume, &root[..len], layer)
        {
            Ok(Progress::More) => false,
            Ok(Progress::Done) => {
                self.state = State::Ready;
                true
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

    pub fn build_steps(&self) -> u32 {
        self.scan.steps
    }

    // ------------------------------------------------------------------ proto_layer

    /// The code a request of the names answers while the service cannot serve.
    fn gate(&self) -> Result<(), Status> {
        match self.state {
            State::Ready => Ok(()),
            State::Starting => Err(st(l::STARTING)),
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

    fn vpath(&self, id: u32, out: &mut [u8; 512]) -> R<usize> {
        Scan::volume_path(self.index, self.live_path(), id, out)
            .ok_or_else(|| st(proto_fs::NAME_TOO_LONG))
    }

    /// The walk of `path` after it is made plain (`lookup::normalize`), with the real identifiers
    /// when `real` (ACCESS with `ACCESS_REAL`) and the effective ones otherwise.
    fn walk(&self, c: &Client<'_>, path: &[u8], real: bool) -> Walked {
        let mut plain = [0u8; 512];
        let len = normalize(path, &mut plain);
        let walk = Walk::new(&plain[..len]);
        let trailing = walk.trailing_slash();
        let outcome = walk.run(self.index, c.who.identity(real)).0;
        Walked {
            outcome,
            trailing,
            path: plain,
            len,
        }
    }

    /// A failure of a walk, as a status.
    fn refusal(outcome: Outcome) -> Status {
        st(match outcome {
            Outcome::Absent => proto_fs::NO_ENTRY,
            Outcome::NotDir => proto_fs::NOT_DIRECTORY,
            Outcome::Denied => proto_fs::ACCESS_DENIED,
            Outcome::NameTooLong => proto_fs::NAME_TOO_LONG,
            _ => proto_fs::INVALID_ARGUMENT,
        })
    }

    fn redirect(path: &[u8], target: u32, w: &mut Writer) -> R<()> {
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
        self.gate()?;
        let walked = self.walk(c, path, false);
        let (outcome, trailing) = (walked.outcome, walked.trailing);
        // The names the root passes through are the services' own, writes included. A name of
        // the lower set is read only in this part: the RAM file service would write it below the
        // layers, so a write or a create is refused here (whether the name exists is the RAM
        // file service's to say, and a create of a name that may be there is as much a write).
        let writes = n::open_writes(flags);
        let creates = flags & proto_fs::CREATE != 0;
        if (writes || creates) && matches!(outcome, Outcome::Lower | Outcome::Absent) {
            return Err(st(proto_fs::READ_ONLY_FILESYSTEM));
        }
        if let Some(done) = Self::redirect_for(outcome, walked.path(), w) {
            return done.map(|()| Done::Written);
        }
        let Outcome::Upper(id) = outcome else {
            return Err(Self::refusal(outcome));
        };
        if writes {
            return Err(st(proto_fs::READ_ONLY_FILESYSTEM));
        }
        // A create of a name of the layer opens it for reading, and with EXCLUSIVE it is there.
        if creates && flags & proto_fs::EXCLUSIVE != 0 {
            return Err(st(proto_fs::ALREADY_EXISTS));
        }
        let is_dir = id == 0 || self.index.entry(id).is_some_and(|e| e.kind == Kind::Dir);
        if is_dir {
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
                .make(c.owner, c.who.pid, id)
                .map_err(|_: Refused| st(proto_fs::TOO_MANY_FILES_IN_SYSTEM))?;
            OpenAnswer::Directory { handle }.write(w)?;
            return Ok(Done::Written);
        }
        if flags & proto_fs::DIRECTORY_ONLY != 0 || trailing {
            return Err(st(proto_fs::NOT_DIRECTORY));
        }
        let mut vp = [0u8; 512];
        let len = self.vpath(id, &mut vp)?;
        let stat = self.volume.stat(&vp[..len]).map_err(from_volume)?;
        if !permits(c.who.identity(false), &attr_of(&stat), READ) {
            return Err(st(proto_fs::ACCESS_DENIED));
        }
        let handle = self
            .volume
            .open(&vp[..len], d::READ, 0)
            .map_err(from_volume)?;
        let pass = self.volume.export(handle);
        let _ = self.volume.close(handle);
        let pass = pass.map_err(from_volume)?;
        OpenAnswer::Pass.write(w)?;
        Ok(Done::Pass(pass))
    }

    /// STAT: the node information of a name of the layer. A name of the lower set, and the names
    /// the root passes through, are a redirect: the RAM file service answers with the rights of the
    /// caller's own session and follows the links as the flags say.
    pub fn stat(&mut self, c: &Client<'_>, _flags: u32, path: &[u8], w: &mut Writer) -> R<()> {
        self.gate()?;
        let walked = self.walk(c, path, false);
        if let Some(done) = Self::redirect_for(walked.outcome, walked.path(), w) {
            return done;
        }
        let Outcome::Upper(id) = walked.outcome else {
            return Err(Self::refusal(walked.outcome));
        };
        let mut vp = [0u8; 512];
        let len = self.vpath(id, &mut vp)?;
        let stat = self.volume.stat(&vp[..len]).map_err(from_volume)?;
        if walked.trailing && stat.kind != d::KIND_DIRECTORY {
            return Err(st(proto_fs::NOT_DIRECTORY));
        }
        n::write_info(&node_from(&stat)?, w)
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
        self.gate()?;
        // The path is walked with the identifiers the bits are checked with.
        let walked = self.walk(c, path, flags & d::ACCESS_REAL != 0);
        if let Some(done) = Self::redirect_for(walked.outcome, walked.path(), w) {
            return done;
        }
        let Outcome::Upper(id) = walked.outcome else {
            return Err(Self::refusal(walked.outcome));
        };
        if bits & WRITE != 0 {
            return Err(st(proto_fs::READ_ONLY_FILESYSTEM));
        }
        let mut vp = [0u8; 512];
        let len = self.vpath(id, &mut vp)?;
        let stat = self.volume.stat(&vp[..len]).map_err(from_volume)?;
        posix_perm::access(
            c.who.ids,
            c.who.groups(),
            &attr_of(&stat),
            bits & (READ | EXEC),
            flags & d::ACCESS_REAL != 0,
        )
        .map_err(|_| st(proto_fs::ACCESS_DENIED))?;
        w.u32(0)
    }

    /// READLINK: the layer of the user holds no link in this part, so a name of it is no link.
    pub fn readlink(&mut self, c: &Client<'_>, path: &[u8], w: &mut Writer) -> R<()> {
        self.gate()?;
        let walked = self.walk(c, path, false);
        if let Some(done) = Self::redirect_for(walked.outcome, walked.path(), w) {
            return done;
        }
        match walked.outcome {
            Outcome::Upper(_) => Err(st(proto_fs::INVALID_ARGUMENT)),
            other => Err(Self::refusal(other)),
        }
    }

    /// CHANGE: the service writes no names in this part.
    pub fn change(&self) -> Status {
        match self.gate() {
            Err(s) => s,
            Ok(()) => st(proto_fs::READ_ONLY_FILESYSTEM),
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
        let mut vp = [0u8; 512];
        let len = self.vpath(dir, &mut vp)?;
        let stat = self.volume.stat(&vp[..len]).map_err(from_volume)?;
        n::write_info(&node_from(&stat)?, w)
    }

    /// READ_DIR: the reply is returned whole, with its length.
    pub fn read_dir(&mut self, owner: u64, handle: u32) -> R<([u8; abi::MESSAGE_MAX], usize)> {
        self.gate()?;
        let Core {
            table,
            index,
            lower,
            ..
        } = self;
        let desc = table.get(owner, handle).map_err(Self::lost)?;
        let mut reply = DirReply::new()?;
        let listed = listing::read_dir(
            index,
            lower,
            desc.dir,
            &mut desc.position,
            &mut desc.lower,
            &mut reply,
        )?;
        // What the replies have given out, which SEEK_DIR may go back to and not past.
        desc.given = desc.given.max(desc.position);
        let len = reply.len();
        Ok((reply.finish(listed.more, listed.cursor)?, len))
    }

    pub fn rewind(&mut self, owner: u64, handle: u32) -> R<()> {
        self.gate()?;
        let Core { table, lower, .. } = self;
        let desc = table.get(owner, handle).map_err(Self::lost)?;
        listing::rewind(lower, &mut desc.position, &mut desc.lower)
    }

    pub fn seek_dir(&mut self, owner: u64, handle: u32, cursor: u64) -> R<()> {
        self.gate()?;
        let Core { table, lower, .. } = self;
        let desc = table.get(owner, handle).map_err(Self::lost)?;
        listing::seek(
            lower,
            &mut desc.position,
            desc.given,
            &mut desc.lower,
            cursor,
        )
    }

    pub fn close(&mut self, owner: u64, handle: u32) -> R<()> {
        let d = self.table.close(owner, handle).map_err(Self::lost)?;
        if let Some(dir) = d.lower {
            self.lower.close_dir(dir);
        }
        Ok(())
    }

    /// The session `owner` went: what it held closes.
    pub fn gone(&mut self, owner: u64) {
        while let Some(d) = self.table.take_owned(owner) {
            if let Some(dir) = d.lower {
                self.lower.close_dir(dir);
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
