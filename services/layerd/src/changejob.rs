// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The changes of names as jobs of the loop (`change` has the rules and the helpers). A change is
//! a `ChangeJob`: the request, the plain paths of its legs (the first path, and for a rename the
//! second), and where it stands. `Core::change_step` takes one step of it, and a step does at most
//!
//! - `lookup::STEP` lookups of the index (a walk of the directory part), or
//! - `SLOTS_PER_READDIR` slots of a scan of the table (the reaper's, `reaper`), or
//! - one call to the data file service or to the lower set (a batch of `LOWER_PER_STEP` calls
//!   for the listing of the emptiness check), with the changes to the index that call makes
//!   visible, the one exception being the step of a rename over a directory, which makes two
//!   renames (the target into `work/`, the source over its name).
//!
//! The phases: `PlainA` and `PlainB` make the paths plain; `WalkA` and `WalkB` walk the directory
//! part; `LowerA` and `LowerB` stat the lower directories below the deepest one of the layer;
//! `LeafA` and `LeafB` look at the name; `StatA` and `StatB` stat the file a rule reads;
//! `Empty` lists the lower directory a removal must find empty; then the checks make a plan of
//! stages and `Commit` runs it, a stage a step at most (`Stage`): the copy up of the directories,
//! the name made in `work/` and renamed in, the marks, the removal, the rename. A change that
//! walks a path is never done inline in one step.
//!
//! One change job at a time holds the lock (`Workers::lock`) from its first step to its last call;
//! the others wait in the table without taking steps. A job whose session went before its first
//! call of `Commit` is dropped (`Core::change_abandon`); after it the job runs to its end, answers
//! nobody and lets the lock go.
//!
//! The visible steps are the ones that make a change visible with the call and the change of the
//! index together: the rename from `work/` into the layer with the insertion, the unlink with the
//! removal, the rename of a name with `move_to` and the retargeting of the descriptions. A reader
//! of the index sees the state before or after each of them, never a name that is missing from
//! both.

use crate::change::{
    F, INO_BLOCK, LINK_MODE, Leaf, Parent, Parts, Stop, denial, fail, removal_allowed, reserved,
    split,
};
use crate::composition::{Composition, MAX_TEXT};
use crate::index::{Fields, Kind, NAME_MAX, OPAQUE, UNSCANNED};
use crate::listing::LOWER_PER_STEP;
use crate::lookup::{Hidden, Outcome, STEP, Step, Walk, normalize_dots};
use crate::names::{COMPOSITION, COMPOSITION_TMP, Client, Core, Done, attr_of, from_volume, st};
use crate::scan::{LINK_PREFIX, OPAQUE_NAME, WHITEOUT_PREFIX};
use crate::volume::{Lower, LowerStat, R, Volume};
use posix_perm::{Created, EXEC, TimesRequest, WRITE, permits};
use proto_data as d;
use proto_fs::names::{self as n, Change, ChangeOp, OpenAnswer, UPPER_INO_TAG};
use proto_fs::{MAX_PATH, Redirect};
use proto_wire::{Reader, Status, Writer};

/// What a step of a change job came to.
#[allow(clippy::large_enum_variant)]
pub enum ChangeStep<P> {
    /// Another job holds the lock: the job takes no step.
    Wait,
    /// The job goes on.
    More,
    /// The job is done: the answer.
    Done(R<Done<P>>),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    PlainA,
    PlainB,
    WalkA,
    LowerA,
    LeafA,
    StatA,
    WalkB,
    LowerB,
    LeafB,
    StatB,
    /// The attribute operations walk the whole path.
    WalkFull,
    LowerTarget,
    Empty,
    Commit,
    LinkOpen,
    LinkRead,
    LinkClose,
}

/// A directory the stages of a plan name.
#[derive(Clone, Copy)]
enum DirRef {
    /// The directory of the first path, and of the second (after the copy up).
    A,
    B,
    /// An entry of the index.
    Id(u32),
}

#[derive(Clone, Copy)]
enum Stage {
    /// The directories of the lower components of a leg are made in the layer.
    Ensure { b: bool },
    /// A directory at the leaf of a leg.
    Dir {
        b: bool,
        opaque: bool,
        created: Created,
    },
    /// A file or a link at the leaf of the first leg.
    File { kind: Kind, created: Created },
    /// The mark of the leaf of a leg in `dir`: the volume.
    Mark { dir: DirRef, b: bool },
    /// The mark of the leaf of a leg in `dir`: the index.
    IndexMark { dir: DirRef, b: bool },
    /// The mark of the leaf of a leg in `dir` goes (the name is there again).
    DropMark { dir: DirRef, b: bool },
    /// The directory at the leaf of the first path becomes opaque.
    Opaque,
    /// The file or link at the leaf of the first path is removed.
    UnlinkVictim { link: bool },
    /// The file at the leaf of the second path is removed (a link goes over a file).
    UnlinkDst,
    /// The directory at the leaf of the first path leaves the layer.
    Retire,
    /// The rename.
    RenameMain,
    /// The file of the link a file went over is removed.
    UnlinkOldLink,
    /// The file made by an OPEN that creates is opened and its pass taken.
    OpenFile,
    /// An attribute operation.
    Attr,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Mkdir,
    Symlink,
    Create,
    Unlink,
    Rmdir,
    Rename,
    Attr,
    Link,
}

/// One of the two paths of a change.
struct Leg {
    plain: [u8; 512],
    len: usize,
    parts: Parts,
    dotted: bool,
    pos: usize,
    cur: u32,
    hid: Hidden,
    /// Where the walk left the layer, the deepest directory it found, the place of the next lower
    /// component and the attributes of the last one.
    miss: usize,
    deepest: u32,
    lpos: usize,
    last: Option<posix_perm::Attr>,
    parent: Option<Parent>,
    leaf: Option<Leaf>,
    stat: Option<d::Stat>,
}

impl Leg {
    const fn new() -> Leg {
        Leg {
            plain: [0; 512],
            len: 0,
            parts: Parts {
                parent_len: 0,
                leaf_at: 0,
                len: 0,
                trailing: false,
            },
            dotted: false,
            pos: 0,
            cur: 0,
            hid: Hidden::new(),
            miss: 0,
            deepest: 0,
            lpos: 0,
            last: None,
            parent: None,
            leaf: None,
            stat: None,
        }
    }

    fn restart(&mut self) {
        self.pos = 0;
        self.cur = 0;
        self.hid = Hidden::new();
        self.parent = None;
        self.leaf = None;
        self.stat = None;
    }

    fn leaf_name(&self) -> &[u8] {
        &self.plain[self.parts.leaf_at..self.parts.len]
    }

    fn full(&self) -> &[u8] {
        &self.plain[..self.parts.len]
    }
}

/// What the plan of a rename or a removal remembers.
#[derive(Clone, Copy)]
struct Victim {
    id: u32,
    kind: Kind,
    lower: Option<LowerStat>,
    /// The attributes the rules read (the source of a rename, the victim of a removal).
    attr: Option<posix_perm::Attr>,
}

/// The emptiness check of a directory: the lower listing in batches.
struct Empty<D> {
    /// The index directory the marks are looked up in.
    up: Option<u32>,
    /// The path is the second leg's.
    b: bool,
    dir: Option<D>,
    sub: u8,
    empty: bool,
    err: Option<Status>,
}

#[derive(Clone, Copy)]
struct LinkRead {
    which: u32,
    start: usize,
    end: usize,
    handle: u32,
    len: usize,
    text: [u8; 512],
    err: Option<Status>,
}

/// What an attribute operation does, once its checks are made.
#[derive(Clone, Copy)]
struct AttrPlan {
    id: u32,
    dir: bool,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    keep_uid: u32,
    keep_gid: u32,
    atime: i64,
    mtime: i64,
    size: u64,
}

const NO_ATTR: AttrPlan = AttrPlan {
    id: 0,
    dir: false,
    ino: 0,
    uid: 0,
    gid: 0,
    mode: 0,
    keep_uid: 0,
    keep_gid: 0,
    atime: 0,
    mtime: 0,
    size: 0,
};

/// What the rename remembers between its phases.
#[derive(Clone, Copy)]
struct Rn {
    src_id: u32,
    src_kind: Kind,
    src_lower: Option<LowerStat>,
    src_parent: u32,
    src_attr: Option<posix_perm::Attr>,
    dst: Option<Leaf>,
    dst_attr: Option<posix_perm::Attr>,
}

const NO_STAGE: Stage = Stage::Attr;
const STAGES: usize = 12;

/// A change of names in progress.
pub struct ChangeJob<V: Volume, L: Lower> {
    req: [u8; abi::MESSAGE_MAX],
    first: (usize, usize),
    second: (usize, usize),
    op: ChangeOp,
    a_val: u64,
    b_val: u64,
    /// The OPEN that creates: its flags.
    flags: u32,
    creating: bool,
    /// The place of the job in the table (the lock's key), whether it holds the lock, and whether
    /// its first call of `Commit` has been made.
    id: u8,
    locked: bool,
    committed: bool,
    phase: Phase,
    sub: u8,
    a: Leg,
    b: Leg,
    /// The directories of the layer the leaves of the two legs lie in, and the last one made.
    dir_a: u32,
    dir_b: u32,
    made: u32,
    victim: Victim,
    rn: Rn,
    empty: Empty<L::Dir>,
    stages: [Stage; STAGES],
    nstages: usize,
    pc: usize,
    // The state of the stage being run.
    dsub: u8,
    handle: u32,
    work: u32,
    ino: u64,
    written: usize,
    err: Option<Status>,
    ens_pos: usize,
    ens_cur: u32,
    ens_created: Created,
    ctext: [u8; MAX_TEXT],
    clen: usize,
    cnext: Option<Composition>,
    link: LinkRead,
    attr: AttrPlan,
    pass: Option<V::Pass>,
}

impl<V: Volume, L: Lower> ChangeJob<V, L> {
    pub const fn new() -> ChangeJob<V, L> {
        ChangeJob {
            req: [0; abi::MESSAGE_MAX],
            first: (0, 0),
            second: (0, 0),
            op: ChangeOp::Mkdir,
            a_val: 0,
            b_val: 0,
            flags: 0,
            creating: false,
            id: 0,
            locked: false,
            committed: false,
            phase: Phase::PlainA,
            sub: 0,
            a: Leg::new(),
            b: Leg::new(),
            dir_a: 0,
            dir_b: 0,
            made: 0,
            victim: Victim {
                id: 0,
                kind: Kind::Empty,
                lower: None,
                attr: None,
            },
            rn: Rn {
                src_id: 0,
                src_kind: Kind::Empty,
                src_lower: None,
                src_parent: 0,
                src_attr: None,
                dst: None,
                dst_attr: None,
            },
            empty: Empty {
                up: None,
                b: false,
                dir: None,
                sub: 0,
                empty: true,
                err: None,
            },
            stages: [NO_STAGE; STAGES],
            nstages: 0,
            pc: 0,
            dsub: 0,
            handle: 0,
            work: 0,
            ino: 0,
            written: 0,
            err: None,
            ens_pos: 0,
            ens_cur: 0,
            ens_created: Created {
                mode: 0,
                uid: 0,
                gid: 0,
            },
            ctext: [0; MAX_TEXT],
            clen: 0,
            cnext: None,
            link: LinkRead {
                which: 0,
                start: 0,
                end: 0,
                handle: 0,
                len: 0,
                text: [0; 512],
                err: None,
            },
            attr: NO_ATTR,
            pass: None,
        }
    }

    fn reset(&mut self, id: u8) {
        self.creating = false;
        self.flags = 0;
        self.id = id;
        self.locked = false;
        self.committed = false;
        self.phase = Phase::PlainA;
        self.sub = 0;
        self.a.restart();
        self.b.restart();
        self.dir_a = 0;
        self.dir_b = 0;
        self.made = 0;
        self.nstages = 0;
        self.pc = 0;
        self.dsub = 0;
        self.empty.dir = None;
        self.empty.sub = 0;
        self.err = None;
        self.pass = None;
        self.attr = NO_ATTR;
    }

    /// A CHANGE: the operation and its two paths (copied; the body of the request is gone when
    /// the job runs). BAD_SIZE for a body that does not fit.
    pub fn start(
        &mut self,
        id: u8,
        op: ChangeOp,
        a: u64,
        b: u64,
        first: &[u8],
        second: &[u8],
    ) -> R<()> {
        if first.len() + second.len() > self.req.len() {
            return Err(Status::BadSize);
        }
        self.reset(id);
        self.op = op;
        self.a_val = a;
        self.b_val = b;
        self.req[..first.len()].copy_from_slice(first);
        self.req[first.len()..first.len() + second.len()].copy_from_slice(second);
        self.first = (0, first.len());
        self.second = (first.len(), first.len() + second.len());
        Ok(())
    }

    /// A CHANGE from the bytes of a request.
    pub fn start_request(&mut self, id: u8, bytes: &[u8]) -> R<()> {
        let req = Change::read(Reader::new(bytes))?;
        self.start(id, req.op, req.a, req.b, req.first, req.second)
    }

    /// An OPEN that creates, at a name the walk of `plain` did not find in the layer.
    pub fn start_create(&mut self, id: u8, flags: u32, plain: &[u8], trailing: bool) -> R<()> {
        if plain.len() > self.a.plain.len() {
            return Err(Status::BadSize);
        }
        self.reset(id);
        self.creating = true;
        self.flags = flags;
        self.op = ChangeOp::Mkdir;
        self.a.plain[..plain.len()].copy_from_slice(plain);
        self.a.len = plain.len();
        if trailing && plain.len() > 1 && !plain.ends_with(b"/") {
            // The walk's path kept its trailing slash (`Walked::path`), so this does not occur;
            // the length keeps the flag in the path.
            self.a.plain[plain.len()] = b'/';
            self.a.len += 1;
        }
        Ok(())
    }

    /// Whether the job holds the lock of the changes.
    pub fn holds_lock(&self) -> bool {
        self.locked
    }

    /// The code the loop prints for the next step of the job (the line of the steps): 1000 for the
    /// paths and the walk, 1200 for a step with a call, 1400 for the lower listing of the
    /// emptiness check.
    pub fn detail(&self) -> u64 {
        match self.phase {
            Phase::PlainA | Phase::PlainB | Phase::WalkA | Phase::WalkB | Phase::WalkFull => 1000,
            Phase::Empty => 1400,
            _ => 1200,
        }
    }

    /// Whether the job has made its first call of `Commit`: it runs to its end whatever happens
    /// to its session.
    pub fn committed(&self) -> bool {
        self.committed
    }

    fn class(&self) -> Class {
        if self.creating {
            return Class::Create;
        }
        match self.op {
            ChangeOp::Mkdir => Class::Mkdir,
            ChangeOp::Symlink => Class::Symlink,
            ChangeOp::Unlink => Class::Unlink,
            ChangeOp::Rmdir => Class::Rmdir,
            ChangeOp::Rename => Class::Rename,
            ChangeOp::Link => Class::Link,
            ChangeOp::Chmod | ChangeOp::Chown | ChangeOp::Utimens | ChangeOp::Truncate => {
                Class::Attr
            }
        }
    }

    fn leg(&self, b: bool) -> &Leg {
        if b { &self.b } else { &self.a }
    }

    fn push(&mut self, stage: Stage) {
        self.stages[self.nstages] = stage;
        self.nstages += 1;
    }

    fn dir_of(&self, r: DirRef) -> u32 {
        match r {
            DirRef::A => self.dir_a,
            DirRef::B => self.dir_b,
            DirRef::Id(id) => id,
        }
    }
}

impl<V: Volume, L: Lower> Default for ChangeJob<V, L> {
    fn default() -> Self {
        ChangeJob::new()
    }
}

/// What a stage's step did: no call (the next stage goes on in the same step), a call and more
/// to come, or a call and the stage is done.
enum Flow {
    Pure,
    Call,
    CallDone,
}

impl<V: Volume, L: Lower> Core<'_, V, L> {
    // ------------------------------------------------------------------ the entries

    /// CHANGE, to its end in one go: for the tests, and for a caller that does not run it in steps.
    /// The job of a request is `ChangeJob` and `change_step`.
    pub fn change(&mut self, c: &Client<'_>, req: &Change<'_>, w: &mut Writer) -> R<()> {
        let mut job = ChangeJob::<V, L>::new();
        job.start(0, req.op, req.a, req.b, req.first, req.second)?;
        match self.run_job(c, &mut job, w)? {
            Done::Written => Ok(()),
            _ => Err(Status::BadSize),
        }
    }

    /// An OPEN that creates, to its end in one go (see `change`).
    pub(crate) fn create_and_open(
        &mut self,
        c: &Client<'_>,
        flags: u32,
        walked: &crate::names::Walked,
        w: &mut Writer,
    ) -> R<Option<Done<V::Pass>>> {
        let mut job = ChangeJob::<V, L>::new();
        job.start_create(0, flags, walked.path(), walked.trailing)?;
        self.run_job(c, &mut job, w).map(Some)
    }

    fn run_job(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        w: &mut Writer,
    ) -> R<Done<V::Pass>> {
        for _ in 0..1_000_000 {
            match self.change_step(c, job, w) {
                ChangeStep::More => {}
                ChangeStep::Wait => return Err(st(proto_layer::STARTING)),
                ChangeStep::Done(r) => return r,
            }
        }
        Err(st(proto_fs::INVALID_ARGUMENT))
    }

    /// Whether a change job holds the lock.
    pub fn change_locked(&self) -> bool {
        self.work.locked()
    }

    /// One step of a change job.
    pub fn change_step(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        w: &mut Writer,
    ) -> ChangeStep<V::Pass> {
        if !job.locked {
            if !self.work.lock(job.id) {
                return ChangeStep::Wait;
            }
            job.locked = true;
        }
        let step = match self.gate() {
            Err(s) => Err(Stop::Status(s)),
            Ok(()) => self.drive(c, job, w),
        };
        let result = match step {
            Ok(None) => return ChangeStep::More,
            Ok(Some(done)) => Ok(done),
            Err(stop) => match self.on_stop(job, stop, w) {
                Ok(None) => return ChangeStep::More,
                Ok(Some(done)) => Ok(done),
                Err(status) => Err(status),
            },
        };
        self.release(job);
        ChangeStep::Done(result)
    }

    /// The job's session went before its first call: it is dropped, with what it holds.
    pub fn change_abandon(&mut self, job: &mut ChangeJob<V, L>) {
        self.release(job);
    }

    fn release(&mut self, job: &mut ChangeJob<V, L>) {
        if let Some(dir) = job.empty.dir.take() {
            self.lower.close_dir(dir);
        }
        if job.locked {
            self.work.unlock(job.id);
            job.locked = false;
        }
    }

    /// A stop of a step that is no status: a link in the path is read (steps of its own) and the
    /// redirect that routes by the path is the answer; a link of the lower set is the redirect to
    /// the RAM file service.
    fn on_stop(
        &mut self,
        job: &mut ChangeJob<V, L>,
        stop: Stop,
        w: &mut Writer,
    ) -> R<Option<Done<V::Pass>>> {
        match stop {
            Stop::Status(s) => Err(s),
            Stop::Link { which, start, end } => {
                job.link.which = which;
                job.link.start = start;
                job.link.end = end;
                job.link.len = 0;
                job.link.err = None;
                job.phase = Phase::LinkOpen;
                Ok(None)
            }
            Stop::LowerLink { which } => {
                let leg = job.leg(which != 0);
                Redirect {
                    target: proto_fs::REDIRECT_RAM,
                    index: which,
                    links: 0,
                    path: &leg.plain[..leg.len],
                }
                .write(w)?;
                Ok(Some(Done::Written))
            }
        }
    }

    fn drive(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        w: &mut Writer,
    ) -> F<Option<Done<V::Pass>>> {
        match job.phase {
            Phase::PlainA => {
                if job.class() == Class::Link {
                    return fail(proto_fs::TOO_MANY_LINKS);
                }
                if job.creating {
                    // The walk of the request made the path plain.
                } else {
                    let (from, to) = job.first;
                    let (len, dotted) = normalize_dots(&job.req[from..to], &mut job.a.plain);
                    job.a.len = len;
                    job.a.dotted = dotted;
                }
                self.decide(c, job, Phase::PlainA)
            }
            Phase::PlainB => {
                let (from, to) = job.second;
                let (len, dotted) = normalize_dots(&job.req[from..to], &mut job.b.plain);
                job.b.len = len;
                job.b.dotted = dotted;
                self.decide(c, job, Phase::PlainB)
            }
            Phase::WalkA => self.step_walk(c, job, false),
            Phase::WalkB => self.step_walk(c, job, true),
            Phase::LowerA => self.step_lower(c, job, false),
            Phase::LowerB => self.step_lower(c, job, true),
            Phase::LeafA => {
                self.step_leaf(job, false)?;
                self.decide(c, job, Phase::LeafA)
            }
            Phase::LeafB => {
                self.step_leaf(job, true)?;
                self.decide(c, job, Phase::LeafB)
            }
            Phase::StatA => {
                self.step_stat(job, false)?;
                self.decide(c, job, Phase::StatA)
            }
            Phase::StatB => {
                self.step_stat(job, true)?;
                self.decide(c, job, Phase::StatB)
            }
            Phase::WalkFull => self.step_walk_full(c, job),
            Phase::LowerTarget => match self.lower_stat(&job.a.plain[..job.a.len])? {
                Some(_) => fail(proto_fs::READ_ONLY_FILESYSTEM),
                None => fail(proto_fs::NO_ENTRY),
            },
            Phase::Empty => {
                if self.step_empty(job)? {
                    self.decide(c, job, Phase::Empty)
                } else {
                    Ok(None)
                }
            }
            Phase::Commit => self.commit_step(c, job, w),
            Phase::LinkOpen => {
                let mut vp = [0u8; 512];
                let n = self.link_file_path(job, &mut vp)?;
                job.link.handle = self
                    .volume
                    .open(&vp[..n], d::READ, 0)
                    .map_err(from_volume)?;
                job.phase = Phase::LinkRead;
                Ok(None)
            }
            Phase::LinkRead => {
                let link = &mut job.link;
                if link.len == link.text.len() {
                    link.err = Some(st(d::TOO_BIG));
                    job.phase = Phase::LinkClose;
                    return Ok(None);
                }
                match self.volume.read(link.handle, &mut link.text[link.len..]) {
                    Ok(0) => job.phase = Phase::LinkClose,
                    Ok(k) => link.len += k,
                    Err(e) => {
                        link.err = Some(e);
                        job.phase = Phase::LinkClose;
                    }
                }
                Ok(None)
            }
            Phase::LinkClose => {
                let closed = self.volume.close(job.link.handle);
                if let Some(e) = job.link.err {
                    return Err(Stop::Status(from_volume(e)));
                }
                closed.map_err(from_volume)?;
                let leg = job.leg(job.link.which != 0);
                Self::link_redirect_text(
                    job.link.which,
                    &leg.plain[..leg.len],
                    &job.link.text[..job.link.len],
                    job.link.start,
                    job.link.end,
                    w,
                )?;
                Ok(Some(Done::Written))
            }
        }
    }

    /// The volume path of the file of the link of a stop: the live layer, the path up to the
    /// component, the prefix of the link's file, and the component.
    fn link_file_path(&self, job: &ChangeJob<V, L>, out: &mut [u8; 512]) -> R<usize> {
        let leg = job.leg(job.link.which != 0);
        let live = self.live_path();
        let (head, comp) = (
            &leg.plain[..job.link.start],
            &leg.plain[job.link.start..job.link.end],
        );
        let total = live.len() + head.len() + LINK_PREFIX.len() + comp.len();
        if total > d::MAX_PATH {
            return Err(st(proto_fs::NAME_TOO_LONG));
        }
        let mut at = 0;
        for piece in [live, head, LINK_PREFIX, comp] {
            out[at..at + piece.len()].copy_from_slice(piece);
            at += piece.len();
        }
        Ok(at)
    }

    // ------------------------------------------------------------------ paths on the volume

    /// The path on the volume of `leg.plain[..upto]`; the file of a link when `link_last`.
    fn leg_vpath(&self, leg: &Leg, upto: usize, link_last: bool, out: &mut [u8; 512]) -> R<usize> {
        let live = self.live_path();
        let plain = &leg.plain[..upto];
        let base = if plain == b"/" { 0 } else { plain.len() };
        let prefix: &[u8] = if link_last && base > 0 {
            LINK_PREFIX
        } else {
            b""
        };
        let total = live.len() + base + prefix.len();
        if total > d::MAX_PATH {
            return Err(st(proto_fs::NAME_TOO_LONG));
        }
        out[..live.len()].copy_from_slice(live);
        let at = live.len();
        if prefix.is_empty() {
            out[at..at + base].copy_from_slice(&plain[..base]);
        } else {
            let slash = plain.iter().rposition(|&b| b == b'/').unwrap_or(0);
            let head = &plain[..=slash];
            let tail = &plain[slash + 1..];
            out[at..at + head.len()].copy_from_slice(head);
            let at = at + head.len();
            out[at..at + prefix.len()].copy_from_slice(prefix);
            let at = at + prefix.len();
            out[at..at + tail.len()].copy_from_slice(tail);
        }
        Ok(total)
    }

    /// The path on the volume of the file `prefix` + the leaf of `leg` in the directory of the leaf.
    fn leg_leaf_path(&self, leg: &Leg, prefix: &[u8], out: &mut [u8; 512]) -> R<usize> {
        let live = self.live_path();
        let parent_len = leg.parts.parent_len;
        let base = if parent_len == 1 { 0 } else { parent_len };
        let leaf = leg.leaf_name();
        let total = live.len() + base + 1 + prefix.len() + leaf.len();
        if total > d::MAX_PATH {
            return Err(st(proto_fs::NAME_TOO_LONG));
        }
        let mut at = 0;
        out[..live.len()].copy_from_slice(live);
        at += live.len();
        out[at..at + base].copy_from_slice(&leg.plain[..base]);
        at += base;
        out[at] = b'/';
        at += 1;
        out[at..at + prefix.len()].copy_from_slice(prefix);
        at += prefix.len();
        out[at..at + leaf.len()].copy_from_slice(leaf);
        Ok(total)
    }

    // ------------------------------------------------------------------ the generic phases

    fn step_walk(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        b: bool,
    ) -> F<Option<Done<V::Pass>>> {
        let which = u32::from(b);
        let who = c.who.identity(false);
        let leg = if b { &mut job.b } else { &mut job.a };
        let (step, state, hidden, missed) = {
            let mut walk = Walk::resume(
                &leg.plain[..leg.parts.parent_len],
                leg.pos,
                leg.cur,
                leg.hid,
            );
            let step = walk.advance(self.index, who, STEP);
            (step, walk.state(), walk.hidden(), walk.missed())
        };
        (leg.pos, leg.cur, leg.hid) = state;
        let Step::Done(outcome) = step else {
            return Ok(None);
        };
        let next_leaf = if b { Phase::LeafB } else { Phase::LeafA };
        let next_lower = if b { Phase::LowerB } else { Phase::LowerA };
        match outcome {
            Outcome::Upper(id) => {
                let attr = self
                    .index
                    .attr(id)
                    .ok_or_else(|| Stop::Status(st(proto_fs::NOT_DIRECTORY)))?;
                leg.parent = Some(Parent {
                    up: Some(id),
                    attr,
                    visible: !hidden,
                });
                job.phase = next_leaf;
                Ok(None)
            }
            Outcome::Lower => {
                let (cur, start) = missed;
                if hidden {
                    return fail(proto_fs::NO_ENTRY);
                }
                leg.deepest = cur;
                leg.miss = start;
                leg.lpos = start;
                leg.last = None;
                job.phase = next_lower;
                Ok(None)
            }
            Outcome::Link { start, end, .. } => Err(Stop::Link { which, start, end }),
            Outcome::PassThrough { .. } => fail(proto_fs::CROSS_DEVICE),
            other => Err(Stop::Status(Self::refusal(other))),
        }
    }

    /// One lower component of the directory part: its stat.
    fn step_lower(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        b: bool,
    ) -> F<Option<Done<V::Pass>>> {
        let which = u32::from(b);
        let who = c.who.identity(false);
        let leg = if b { &mut job.b } else { &mut job.a };
        let parent_len = leg.parts.parent_len;
        let pos = leg.lpos;
        let end = leg.plain[pos..parent_len]
            .iter()
            .position(|&x| x == b'/')
            .map_or(parent_len, |i| pos + i);
        let Some(ls) = self.lower_stat(&leg.plain[..end])? else {
            return fail(proto_fs::NO_ENTRY);
        };
        match ls.kind {
            1 => {}
            5 => return Err(Stop::LowerLink { which }),
            _ => return fail(proto_fs::NOT_DIRECTORY),
        }
        let attr = posix_perm::Attr {
            kind: posix_perm::Kind::Directory,
            mode: ls.mode & 0o7777,
            uid: ls.uid,
            gid: ls.gid,
        };
        if !permits(who, &attr, EXEC) {
            return fail(proto_fs::ACCESS_DENIED);
        }
        leg.last = Some(attr);
        leg.lpos = end + 1;
        if leg.lpos >= parent_len {
            leg.parent = Some(Parent {
                up: None,
                attr,
                visible: true,
            });
            job.phase = if b { Phase::LeafB } else { Phase::LeafA };
        }
        Ok(None)
    }

    /// What the merged view has at the leaf of a leg: a lookup in the index and at most one stat
    /// of the lower set.
    fn step_leaf(&mut self, job: &mut ChangeJob<V, L>, b: bool) -> F<()> {
        let leg = if b { &mut job.b } else { &mut job.a };
        let Some(p) = leg.parent.as_ref() else {
            return fail(proto_fs::NO_ENTRY);
        };
        let full = &leg.plain[..leg.parts.len];
        let leaf = &leg.plain[leg.parts.leaf_at..leg.parts.len];
        let mut hidden = false;
        let mut found = None;
        if let Some(pid) = p.up
            && let Some((id, e)) = self.index.lookup(pid, leaf)
        {
            match e.kind {
                Kind::Whiteout => hidden = true,
                Kind::File | Kind::Dir | Kind::Link => found = Some((id, e.kind)),
                _ => {}
            }
        }
        let seen = if p.visible {
            self.lower_stat(full)?
        } else {
            None
        };
        leg.leaf = Some(match (found, hidden, seen) {
            (Some((id, kind)), _, lower) => Leaf::Upper { id, kind, lower },
            (None, true, s) => Leaf::Missing {
                hidden: true,
                lower_dir: s.is_some_and(|s| s.kind == 1 || s.kind == 5),
            },
            (None, false, Some(s)) => Leaf::Lower(s),
            (None, false, None) => Leaf::Missing {
                hidden: false,
                lower_dir: false,
            },
        });
        Ok(())
    }

    /// The stat of the file at the leaf of a leg (a file a rule reads the attributes of).
    fn step_stat(&mut self, job: &mut ChangeJob<V, L>, b: bool) -> F<()> {
        let link = {
            let leg = job.leg(b);
            matches!(
                leg.leaf,
                Some(Leaf::Upper {
                    kind: Kind::Link,
                    ..
                })
            )
        };
        let stat = if job.class() == Class::Attr {
            // The path on the volume of the name the walk found is in the second leg's buffer.
            self.volume
                .stat(&job.b.plain[..job.b.len])
                .map_err(from_volume)?
        } else {
            let mut vp = [0u8; 512];
            let leg = if b { &job.b } else { &job.a };
            let n = self.leg_vpath(leg, leg.parts.len, link, &mut vp)?;
            self.volume.stat(&vp[..n]).map_err(from_volume)?
        };
        if b {
            job.b.stat = Some(stat);
        } else {
            job.a.stat = Some(stat);
        }
        Ok(())
    }

    /// One batch of the lower listing of the emptiness check; true when the check is done.
    fn step_empty(&mut self, job: &mut ChangeJob<V, L>) -> F<bool> {
        let path_leg = job.leg(job.empty.b);
        match job.empty.sub {
            0 => {
                let path = &path_leg.plain[..path_leg.parts.len];
                match self.lower.open_dir(path) {
                    Ok(dir) => {
                        job.empty.dir = Some(dir);
                        job.empty.sub = 1;
                        Ok(false)
                    }
                    Err(Status::Unknown(proto_fs::NO_ENTRY | proto_fs::NOT_DIRECTORY)) => {
                        job.empty.empty = true;
                        Ok(true)
                    }
                    Err(e) => Err(Stop::Status(e)),
                }
            }
            1 => {
                let mut name = [0u8; 256];
                let up = job.empty.up;
                let Some(dir) = job.empty.dir.as_mut() else {
                    return Ok(true);
                };
                for _ in 0..LOWER_PER_STEP {
                    match self.lower.next(dir, &mut name) {
                        Ok(Some((_, _, len))) => {
                            let found = &name[..len];
                            if found == b"." || found == b".." {
                                continue;
                            }
                            let hidden = up.is_some_and(|id| {
                                self.index
                                    .lookup(id, found)
                                    .is_some_and(|(_, e)| e.kind == Kind::Whiteout)
                            });
                            if !hidden {
                                job.empty.empty = false;
                                job.empty.sub = 2;
                                break;
                            }
                        }
                        Ok(None) => {
                            job.empty.sub = 2;
                            break;
                        }
                        Err(e) => {
                            job.empty.err = Some(e);
                            job.empty.sub = 2;
                            break;
                        }
                    }
                }
                Ok(false)
            }
            _ => {
                if let Some(dir) = job.empty.dir.take() {
                    self.lower.close_dir(dir);
                }
                match job.empty.err.take() {
                    Some(e) => Err(Stop::Status(e)),
                    None => Ok(true),
                }
            }
        }
    }

    /// The emptiness check of the directory at the leaf of a leg starts (the lower listing).
    fn start_empty(&mut self, job: &mut ChangeJob<V, L>, up: Option<u32>, b: bool) {
        job.empty.up = up;
        job.empty.b = b;
        job.empty.sub = 0;
        job.empty.empty = true;
        job.empty.err = None;
        job.phase = Phase::Empty;
    }

    // ------------------------------------------------------------------ what each change decides

    /// A phase is done: the next one, or the plan. Each change has its own order, which the
    /// checks of its rules keep.
    fn decide(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        done: Phase,
    ) -> F<Option<Done<V::Pass>>> {
        match job.class() {
            Class::Mkdir | Class::Symlink | Class::Create => self.decide_make(c, job, done),
            Class::Unlink | Class::Rmdir => self.decide_remove(c, job, done),
            Class::Rename => self.decide_rename(c, job, done),
            Class::Attr => self.decide_attr(c, job, done),
            Class::Link => fail(proto_fs::TOO_MANY_LINKS),
        }
    }

    fn begin_walk(job: &mut ChangeJob<V, L>, b: bool) {
        let leg = if b { &mut job.b } else { &mut job.a };
        leg.restart();
        job.phase = if b { Phase::WalkB } else { Phase::WalkA };
    }

    /// `mkdir`, `symlink` and the OPEN that creates.
    fn decide_make(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        done: Phase,
    ) -> F<Option<Done<V::Pass>>> {
        let class = job.class();
        let who = c.who.identity(false);
        match done {
            Phase::PlainA => {
                let path = &job.a.plain[..job.a.len];
                if class == Class::Mkdir && path == b"/" {
                    return fail(proto_fs::ALREADY_EXISTS);
                }
                let parts = split(path)?;
                if class == Class::Create && parts.trailing {
                    return fail(proto_fs::IS_DIRECTORY);
                }
                let leaf = &path[parts.leaf_at..parts.len];
                if reserved(leaf) {
                    return fail(proto_fs::INVALID_ARGUMENT);
                }
                if class == Class::Symlink {
                    let second = job.second.1 - job.second.0;
                    if leaf.len() + LINK_PREFIX.len() > NAME_MAX || second > MAX_PATH {
                        return fail(proto_fs::NAME_TOO_LONG);
                    }
                    if parts.trailing || second == 0 {
                        return fail(proto_fs::NO_ENTRY);
                    }
                }
                job.a.parts = parts;
                Self::begin_walk(job, false);
                Ok(None)
            }
            Phase::LeafA => {
                let (Some(p), Some(leaf)) = (job.a.parent.as_ref(), job.a.leaf) else {
                    return fail(proto_fs::NO_ENTRY);
                };
                let attr = p.attr;
                let (hidden, lower_dir) = match leaf {
                    Leaf::Missing { hidden, lower_dir } => (hidden, lower_dir),
                    Leaf::Upper { .. } => return fail(proto_fs::ALREADY_EXISTS),
                    Leaf::Lower(ls) => {
                        if class != Class::Create {
                            return fail(proto_fs::ALREADY_EXISTS);
                        }
                        if job.flags & proto_fs::EXCLUSIVE != 0 {
                            return fail(proto_fs::ALREADY_EXISTS);
                        }
                        if ls.kind == 5 && job.flags & proto_fs::NO_FOLLOW == 0 {
                            return Err(Stop::LowerLink { which: 0 });
                        }
                        if n::open_writes(job.flags) {
                            return fail(proto_fs::READ_ONLY_FILESYSTEM);
                        }
                        // The name is the lower set's to open for reading: the redirect to the
                        // RAM file service, which is the one of a link of the lower set.
                        return Err(Stop::LowerLink { which: 0 });
                    }
                };
                if !permits(who, &attr, WRITE | EXEC) {
                    return fail(proto_fs::ACCESS_DENIED);
                }
                // The path must fit the volume before anything is made for it.
                let mut vp = [0u8; 512];
                self.leg_vpath(&job.a, job.a.parts.len, class == Class::Symlink, &mut vp)?;
                job.committed = true;
                match class {
                    Class::Mkdir => {
                        let created = posix_perm::creation(
                            who,
                            &attr,
                            posix_perm::Kind::Directory,
                            (job.a_val & 0o7777) as u32,
                            0,
                        );
                        job.push(Stage::Ensure { b: false });
                        job.push(Stage::Dir {
                            b: false,
                            opaque: lower_dir,
                            created,
                        });
                    }
                    Class::Symlink => {
                        let created =
                            posix_perm::creation(who, &attr, posix_perm::Kind::File, LINK_MODE, 0);
                        // The file of a link is 0644 on the volume; `stat` reports 0777.
                        let created = Created {
                            mode: 0o644,
                            ..created
                        };
                        job.push(Stage::Ensure { b: false });
                        job.push(Stage::File {
                            kind: Kind::Link,
                            created,
                        });
                    }
                    _ => {
                        let created = posix_perm::creation(
                            who,
                            &attr,
                            posix_perm::Kind::File,
                            n::permissions_of(job.flags),
                            0,
                        );
                        job.push(Stage::Ensure { b: false });
                        job.push(Stage::File {
                            kind: Kind::File,
                            created,
                        });
                    }
                }
                if hidden {
                    job.push(Stage::DropMark {
                        dir: DirRef::A,
                        b: false,
                    });
                }
                if class == Class::Create {
                    job.push(Stage::OpenFile);
                }
                job.pc = 0;
                job.dsub = 0;
                job.phase = Phase::Commit;
                Ok(None)
            }
            _ => Err(Stop::Status(st(proto_fs::INVALID_ARGUMENT))),
        }
    }
}

fn lower_attr(ls: &LowerStat) -> posix_perm::Attr {
    posix_perm::Attr {
        kind: if ls.kind == 1 {
            posix_perm::Kind::Directory
        } else {
            posix_perm::Kind::File
        },
        mode: ls.mode & 0o7777,
        uid: ls.uid,
        gid: ls.gid,
    }
}

/// What the name a rename lands on is: a directory, the entry of the layer, whether the lower set
/// has a directory there.
fn dst_facts(dst: Leaf) -> (bool, Option<(u32, Kind)>, bool) {
    match dst {
        Leaf::Missing { lower_dir, .. } => (false, None, lower_dir),
        Leaf::Lower(ls) => (ls.kind == 1, None, ls.kind == 1),
        Leaf::Upper { id, kind, lower } => (
            kind == Kind::Dir,
            Some((id, kind)),
            lower.is_some_and(|s| s.kind == 1),
        ),
    }
}

impl<V: Volume, L: Lower> Core<'_, V, L> {
    fn begin_commit(job: &mut ChangeJob<V, L>) {
        job.committed = true;
        job.pc = 0;
        job.dsub = 0;
        job.phase = Phase::Commit;
    }

    /// A place of the reaper for the directory a change is about to retire, before the volume is
    /// touched: STARTING (the client asks again) when the queue is full.
    fn reaper_room(&self) -> F<()> {
        if self.work.room() {
            Ok(())
        } else {
            fail(proto_layer::STARTING)
        }
    }

    // ------------------------------------------------------------------ unlink and rmdir

    fn decide_remove(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        done: Phase,
    ) -> F<Option<Done<V::Pass>>> {
        let dir = job.class() == Class::Rmdir;
        let who = c.who.identity(false);
        match done {
            Phase::PlainA => {
                let path = &job.a.plain[..job.a.len];
                let parts = split(path)?;
                if reserved(&path[parts.leaf_at..parts.len]) {
                    return fail(proto_fs::INVALID_ARGUMENT);
                }
                job.a.parts = parts;
                Self::begin_walk(job, false);
                Ok(None)
            }
            Phase::LeafA => {
                let (Some(p), Some(leaf)) = (job.a.parent.as_ref(), job.a.leaf) else {
                    return fail(proto_fs::NO_ENTRY);
                };
                let (parent_attr, trailing) = (p.attr, job.a.parts.trailing);
                match leaf {
                    Leaf::Missing { .. } => fail(proto_fs::NO_ENTRY),
                    Leaf::Lower(ls) => {
                        let is_dir = ls.kind == 1;
                        if is_dir && !dir {
                            return fail(proto_fs::IS_DIRECTORY);
                        }
                        if !is_dir && (dir || trailing) {
                            return fail(proto_fs::NOT_DIRECTORY);
                        }
                        let victim = lower_attr(&ls);
                        removal_allowed(who, &parent_attr, &victim)?;
                        job.victim = Victim {
                            id: 0,
                            kind: Kind::Empty,
                            lower: Some(ls),
                            attr: Some(victim),
                        };
                        if is_dir {
                            self.start_empty(job, None, false);
                            Ok(None)
                        } else {
                            self.plan_remove_lower(job)
                        }
                    }
                    Leaf::Upper { id, kind, lower } => {
                        let is_dir = kind == Kind::Dir;
                        if is_dir && !dir {
                            return fail(proto_fs::IS_DIRECTORY);
                        }
                        if !is_dir && (dir || trailing) {
                            return fail(proto_fs::NOT_DIRECTORY);
                        }
                        job.victim = Victim {
                            id,
                            kind,
                            lower,
                            attr: None,
                        };
                        if is_dir {
                            let attr = self
                                .index
                                .attr(id)
                                .ok_or_else(|| Stop::Status(st(proto_fs::NOT_DIRECTORY)))?;
                            job.victim.attr = Some(attr);
                            self.remove_upper_checks(c, job)
                        } else {
                            job.phase = Phase::StatA;
                            Ok(None)
                        }
                    }
                }
            }
            Phase::StatA => {
                let Some(stat) = job.a.stat else {
                    return fail(proto_fs::NO_ENTRY);
                };
                job.victim.attr = Some(attr_of(&stat));
                self.remove_upper_checks(c, job)
            }
            Phase::Empty => {
                if !job.empty.empty {
                    return fail(proto_fs::NOT_EMPTY);
                }
                if job.victim.kind == Kind::Empty {
                    self.plan_remove_lower(job)
                } else {
                    self.plan_remove_upper(job)
                }
            }
            _ => fail(proto_fs::INVALID_ARGUMENT),
        }
    }

    fn remove_upper_checks(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
    ) -> F<Option<Done<V::Pass>>> {
        let who = c.who.identity(false);
        let (Some(p), Some(victim)) = (job.a.parent.as_ref(), job.victim.attr) else {
            return fail(proto_fs::NO_ENTRY);
        };
        removal_allowed(who, &p.attr, &victim)?;
        if p.up.is_none() {
            return fail(proto_fs::NO_ENTRY);
        }
        let (id, kind, lower) = (job.victim.id, job.victim.kind, job.victim.lower);
        if kind == Kind::Dir {
            if self.index.entry(id).is_some_and(|e| e.live_children != 0) {
                return fail(proto_fs::NOT_EMPTY);
            }
            if lower.is_some_and(|s| s.kind == 1) && self.index.flags(id) & OPAQUE == 0 {
                self.start_empty(job, Some(id), false);
                return Ok(None);
            }
        }
        self.plan_remove_upper(job)
    }

    fn plan_remove_lower(&mut self, job: &mut ChangeJob<V, L>) -> F<Option<Done<V::Pass>>> {
        job.push(Stage::Ensure { b: false });
        job.push(Stage::Mark {
            dir: DirRef::A,
            b: false,
        });
        job.push(Stage::IndexMark {
            dir: DirRef::A,
            b: false,
        });
        Self::begin_commit(job);
        Ok(None)
    }

    fn plan_remove_upper(&mut self, job: &mut ChangeJob<V, L>) -> F<Option<Done<V::Pass>>> {
        let Some(up) = job.a.parent.as_ref().and_then(|p| p.up) else {
            return fail(proto_fs::NO_ENTRY);
        };
        let (kind, lower) = (job.victim.kind, job.victim.lower);
        let is_dir = kind == Kind::Dir;
        if is_dir {
            self.reaper_room()?;
        }
        let marked = lower.is_some();
        if marked {
            job.push(Stage::Mark {
                dir: DirRef::Id(up),
                b: false,
            });
        }
        if is_dir {
            job.push(Stage::Retire);
        } else {
            job.push(Stage::UnlinkVictim {
                link: kind == Kind::Link,
            });
        }
        if marked {
            job.push(Stage::IndexMark {
                dir: DirRef::Id(up),
                b: false,
            });
        }
        Self::begin_commit(job);
        Ok(None)
    }

    // ------------------------------------------------------------------ rename

    fn decide_rename(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        done: Phase,
    ) -> F<Option<Done<V::Pass>>> {
        match done {
            Phase::PlainA => {
                job.a.parts = split(&job.a.plain[..job.a.len])?;
                job.phase = Phase::PlainB;
                Ok(None)
            }
            Phase::PlainB => {
                job.b.parts = split(&job.b.plain[..job.b.len])?;
                if reserved(job.a.leaf_name()) || reserved(job.b.leaf_name()) {
                    return fail(proto_fs::INVALID_ARGUMENT);
                }
                Self::begin_walk(job, false);
                Ok(None)
            }
            Phase::LeafA => {
                let Some(leaf) = job.a.leaf else {
                    return fail(proto_fs::NO_ENTRY);
                };
                let (src_id, src_kind, src_lower) = match leaf {
                    Leaf::Missing { .. } => return fail(proto_fs::NO_ENTRY),
                    Leaf::Lower(_) => return fail(proto_fs::CROSS_DEVICE),
                    Leaf::Upper { id, kind, lower } => (id, kind, lower),
                };
                let src_is_dir = src_kind == Kind::Dir;
                // A directory with a lower one showing through it moves with it, which waits for
                // the copy up. An opaque directory has no lower content: it moves, with a mark at
                // the old name.
                if src_is_dir
                    && src_lower.is_some_and(|s| s.kind == 1)
                    && self.index.flags(src_id) & OPAQUE == 0
                {
                    return fail(proto_fs::CROSS_DEVICE);
                }
                if (job.a.parts.trailing || job.b.parts.trailing) && !src_is_dir {
                    return fail(proto_fs::NOT_DIRECTORY);
                }
                let a_full = job.a.full();
                let b_full = job.b.full();
                if a_full == b_full {
                    // The same name: nothing to do.
                    job.nstages = 0;
                    job.pc = 0;
                    job.phase = Phase::Commit;
                    return Ok(None);
                }
                if src_is_dir
                    && b_full.starts_with(a_full)
                    && b_full.get(a_full.len()) == Some(&b'/')
                {
                    return fail(proto_fs::INVALID_ARGUMENT);
                }
                // What lies below the directory must still fit the volume's limit on paths at its
                // new place.
                if src_is_dir
                    && self.live_path().len()
                        + b_full.len()
                        + self.index.reach(src_id)
                        + crate::index::OPAQUE_EXTRA
                        > d::MAX_PATH
                {
                    return fail(proto_fs::NAME_TOO_LONG);
                }
                job.rn = Rn {
                    src_id,
                    src_kind,
                    src_lower,
                    src_parent: 0,
                    src_attr: None,
                    dst: None,
                    dst_attr: None,
                };
                Self::begin_walk(job, true);
                Ok(None)
            }
            Phase::LeafB => {
                let Some(dst) = job.b.leaf else {
                    return fail(proto_fs::NO_ENTRY);
                };
                let src_parent = job
                    .a
                    .parent
                    .as_ref()
                    .and_then(|p| p.up)
                    .ok_or_else(|| Stop::Status(st(proto_fs::NO_ENTRY)))?;
                let mut vp = [0u8; 512];
                self.leg_vpath(
                    &job.b,
                    job.b.parts.len,
                    job.rn.src_kind == Kind::Link,
                    &mut vp,
                )?;
                job.rn.src_parent = src_parent;
                job.rn.dst = Some(dst);
                if job.rn.src_kind == Kind::Dir {
                    job.rn.src_attr = Some(
                        self.index
                            .attr(job.rn.src_id)
                            .ok_or_else(|| Stop::Status(st(proto_fs::NOT_DIRECTORY)))?,
                    );
                    return self.rename_after_src(c, job);
                }
                job.phase = Phase::StatA;
                Ok(None)
            }
            Phase::StatA => {
                let Some(stat) = job.a.stat else {
                    return fail(proto_fs::NO_ENTRY);
                };
                job.rn.src_attr = Some(attr_of(&stat));
                self.rename_after_src(c, job)
            }
            Phase::StatB => {
                let Some(stat) = job.b.stat else {
                    return fail(proto_fs::NO_ENTRY);
                };
                job.rn.dst_attr = Some(attr_of(&stat));
                self.rename_checks(c, job)
            }
            Phase::Empty => {
                if !job.empty.empty {
                    return fail(proto_fs::NOT_EMPTY);
                }
                self.rename_perms_and_plan(c, job)
            }
            _ => fail(proto_fs::INVALID_ARGUMENT),
        }
    }

    /// The source's attributes are known: the name it lands on.
    fn rename_after_src(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
    ) -> F<Option<Done<V::Pass>>> {
        match job.rn.dst {
            Some(Leaf::Upper { kind, id, .. }) => {
                if kind == Kind::Dir {
                    job.rn.dst_attr = Some(
                        self.index
                            .attr(id)
                            .ok_or_else(|| Stop::Status(st(proto_fs::NOT_DIRECTORY)))?,
                    );
                    self.rename_checks(c, job)
                } else {
                    job.phase = Phase::StatB;
                    Ok(None)
                }
            }
            Some(Leaf::Lower(ls)) => {
                job.rn.dst_attr = Some(lower_attr(&ls));
                self.rename_checks(c, job)
            }
            _ => self.rename_checks(c, job),
        }
    }

    fn rename_checks(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
    ) -> F<Option<Done<V::Pass>>> {
        let Some(dst) = job.rn.dst else {
            return fail(proto_fs::NO_ENTRY);
        };
        let src_is_dir = job.rn.src_kind == Kind::Dir;
        let (dst_is_dir, dst_up, dst_lower_dir) = dst_facts(dst);
        if job.rn.dst_attr.is_some() {
            if src_is_dir && !dst_is_dir {
                return fail(proto_fs::NOT_DIRECTORY);
            }
            if !src_is_dir && dst_is_dir {
                return fail(proto_fs::IS_DIRECTORY);
            }
        }
        if dst_is_dir {
            let up = dst_up.map(|(id, _)| id);
            if let Some(id) = up
                && self.index.entry(id).is_some_and(|e| e.live_children != 0)
            {
                return fail(proto_fs::NOT_EMPTY);
            }
            if dst_lower_dir && !up.is_some_and(|id| self.index.flags(id) & OPAQUE != 0) {
                self.start_empty(job, up, true);
                return Ok(None);
            }
        }
        self.rename_perms_and_plan(c, job)
    }

    fn rename_perms_and_plan(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
    ) -> F<Option<Done<V::Pass>>> {
        let who = c.who.identity(false);
        let (Some(pa), Some(pb), Some(dst), Some(src_attr)) = (
            job.a.parent.as_ref(),
            job.b.parent.as_ref(),
            job.rn.dst,
            job.rn.src_attr,
        ) else {
            return fail(proto_fs::NO_ENTRY);
        };
        let same_parent = pb.up.is_some() && pb.up == pa.up;
        if cfg!(feature = "break-layerd-sticky") {
            removal_allowed(who, &pa.attr, &src_attr)?;
            posix_perm::place_allowed(who, &pb.attr, None).map_err(denial)?;
        } else {
            posix_perm::rename_allowed(
                who,
                &pa.attr,
                &src_attr,
                &pb.attr,
                job.rn.dst_attr.as_ref(),
                same_parent,
            )
            .map_err(denial)?;
        }
        // The index must have room for the new name, and for the mark of the old one, before the
        // volume is touched.
        if let Some(up) = pb.up
            && !self.index.has_room(up, job.b.leaf_name())
        {
            return fail(proto_fs::NO_SPACE);
        }
        if job.rn.src_lower.is_some() && !self.index.has_room(job.rn.src_parent, job.a.leaf_name())
        {
            return fail(proto_fs::NO_SPACE);
        }
        let (src_id, src_kind, src_lower, src_parent) = (
            job.rn.src_id,
            job.rn.src_kind,
            job.rn.src_lower,
            job.rn.src_parent,
        );
        let src_is_dir = src_kind == Kind::Dir;
        let (_, dst_up, dst_lower_dir) = dst_facts(dst);
        if dst_up.is_some_and(|(_, kind)| kind == Kind::Dir) {
            self.reaper_room()?;
        }
        // The checks are done: make what the new name needs. The order keeps every cut safe: the
        // opaque marker on the source, the mark of the target name (the lower directory stays
        // hidden when the target directory goes), the removal of a file the link goes over, the
        // mark of the old name, the rename (which takes a target directory into `work/` first),
        // and the mark of the target name goes after it.
        job.push(Stage::Ensure { b: true });
        if src_is_dir && dst_lower_dir && self.index.flags(src_id) & OPAQUE == 0 {
            job.push(Stage::Opaque);
        }
        let mut dst_marked = false;
        let mut old_link = false;
        if let Some((_, kind)) = dst_up {
            if kind == Kind::Dir {
                if dst_lower_dir {
                    job.push(Stage::Mark {
                        dir: DirRef::B,
                        b: true,
                    });
                    dst_marked = true;
                }
            } else if src_kind == Kind::Link && kind != Kind::Link {
                // A link over a file: the file goes first, so a cut never leaves both (a file
                // over a link leaves both, and the scan lets the file win).
                job.push(Stage::UnlinkDst);
            } else if src_kind != Kind::Link && kind == Kind::Link {
                old_link = true;
            }
        }
        if src_lower.is_some() {
            job.push(Stage::Mark {
                dir: DirRef::Id(src_parent),
                b: false,
            });
        }
        job.push(Stage::RenameMain);
        if old_link {
            job.push(Stage::UnlinkOldLink);
        }
        if dst_marked || matches!(dst, Leaf::Missing { hidden: true, .. }) {
            job.push(Stage::DropMark {
                dir: DirRef::B,
                b: true,
            });
        }
        Self::begin_commit(job);
        Ok(None)
    }

    // ------------------------------------------------------------------ chmod, chown, utimensat, truncate

    /// The walk of the whole path of an attribute operation.
    fn step_walk_full(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
    ) -> F<Option<Done<V::Pass>>> {
        let who = c.who.identity(false);
        let leg = &mut job.a;
        let (step, state) = {
            let mut walk = Walk::resume(&leg.plain[..leg.len], leg.pos, leg.cur, leg.hid);
            let step = walk.advance(self.index, who, STEP);
            (step, walk.state())
        };
        (leg.pos, leg.cur, leg.hid) = state;
        let Step::Done(outcome) = step else {
            return Ok(None);
        };
        match outcome {
            Outcome::Upper(id) => {
                job.attr.id = id;
                // The path of the name on the volume goes to the second leg's buffer.
                let live = self.live_path();
                let mut plain = &job.a.plain[..job.a.len];
                if plain.len() > 1 && plain.ends_with(b"/") {
                    plain = &plain[..plain.len() - 1];
                }
                let n = if id == 0 {
                    job.b.plain[..live.len()].copy_from_slice(live);
                    live.len()
                } else if job.a.dotted {
                    let mut vp = [0u8; 512];
                    let n = self.vpath(id, &mut vp)?;
                    job.b.plain[..n].copy_from_slice(&vp[..n]);
                    n
                } else {
                    let total = live.len() + plain.len();
                    if total > d::MAX_PATH {
                        return fail(proto_fs::NAME_TOO_LONG);
                    }
                    job.b.plain[..live.len()].copy_from_slice(live);
                    job.b.plain[live.len()..total].copy_from_slice(plain);
                    total
                };
                job.b.len = n;
                job.phase = Phase::StatA;
                Ok(None)
            }
            Outcome::Link { start, end, .. } => Err(Stop::Link {
                which: 0,
                start,
                end,
            }),
            Outcome::Lower => {
                job.phase = Phase::LowerTarget;
                Ok(None)
            }
            Outcome::PassThrough { .. } => fail(proto_fs::CROSS_DEVICE),
            other => Err(Stop::Status(Self::refusal(other))),
        }
    }

    fn decide_attr(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        done: Phase,
    ) -> F<Option<Done<V::Pass>>> {
        match done {
            Phase::PlainA => {
                job.a.restart();
                job.phase = Phase::WalkFull;
                Ok(None)
            }
            Phase::StatA => {
                let who = c.who.identity(false);
                let id = job.attr.id;
                let Some(stat) = job.a.stat else {
                    return fail(proto_fs::NO_ENTRY);
                };
                let kind = if id == 0 {
                    Kind::Dir
                } else {
                    self.index.entry(id).map_or(Kind::File, |e| e.kind)
                };
                let attr = if kind == Kind::Dir {
                    self.index
                        .attr(id)
                        .ok_or_else(|| Stop::Status(st(proto_fs::NOT_DIRECTORY)))?
                } else {
                    attr_of(&stat)
                };
                let mut plan = AttrPlan {
                    id,
                    dir: kind == Kind::Dir,
                    ino: stat.ino,
                    uid: attr.uid,
                    gid: attr.gid,
                    mode: attr.mode,
                    ..NO_ATTR
                };
                match job.op {
                    ChangeOp::Chmod => {
                        if kind == Kind::Link {
                            return fail(proto_fs::NOT_SUPPORTED);
                        }
                        plan.mode =
                            posix_perm::chmod_result(who, &attr, (job.a_val & 0o7777) as u32)
                                .map_err(denial)?;
                    }
                    ChangeOp::Chown => {
                        let keep = |v: u64| (v as u32 != u32::MAX).then_some(v as u32);
                        let (uid, gid) = (keep(job.a_val), keep(job.b_val));
                        let owned =
                            posix_perm::chown_result(who, &attr, uid, gid).map_err(denial)?;
                        plan.keep_uid = uid.unwrap_or(d::UID_KEEP);
                        plan.keep_gid = gid.unwrap_or(d::UID_KEEP);
                        plan.uid = owned.uid;
                        plan.gid = owned.gid;
                        plan.mode = owned.mode;
                    }
                    ChangeOp::Utimens => {
                        if kind == Kind::Link {
                            return fail(proto_fs::NOT_SUPPORTED);
                        }
                        let (atime, mtime) = (job.a_val as i64, job.b_val as i64);
                        let request = match (atime, mtime) {
                            (d::UTIME_OMIT, d::UTIME_OMIT) => TimesRequest::Omit,
                            (d::UTIME_NOW, d::UTIME_NOW) => TimesRequest::Now,
                            _ => TimesRequest::Explicit,
                        };
                        posix_perm::utimens_allowed(who, &attr, request).map_err(denial)?;
                        plan.atime = atime;
                        plan.mtime = mtime;
                    }
                    ChangeOp::Truncate => {
                        if kind == Kind::Dir {
                            return fail(proto_fs::IS_DIRECTORY);
                        }
                        if !permits(who, &attr, WRITE) {
                            return fail(proto_fs::ACCESS_DENIED);
                        }
                        plan.size = job.a_val;
                    }
                    _ => return fail(proto_fs::INVALID_ARGUMENT),
                }
                job.attr = plan;
                job.push(Stage::Attr);
                Self::begin_commit(job);
                Ok(None)
            }
            _ => fail(proto_fs::INVALID_ARGUMENT),
        }
    }
}

impl<V: Volume, L: Lower> Core<'_, V, L> {
    // ------------------------------------------------------------------ the commit

    fn finish_ok(&mut self, job: &mut ChangeJob<V, L>, w: &mut Writer) -> F<Option<Done<V::Pass>>> {
        if job.creating {
            OpenAnswer::Pass.write(w)?;
            let pass = job
                .pass
                .take()
                .ok_or_else(|| Stop::Status(st(proto_fs::INVALID_ARGUMENT)))?;
            Ok(Some(Done::Pass(pass)))
        } else {
            w.u32(0)?;
            Ok(Some(Done::Written))
        }
    }

    /// Runs the plan: the stages in order, a stage that makes no call going on in the same step,
    /// and the step that makes a call ends there.
    fn commit_step(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        w: &mut Writer,
    ) -> F<Option<Done<V::Pass>>> {
        let _ = c;
        loop {
            if job.pc >= job.nstages {
                return self.finish_ok(job, w);
            }
            let stage = job.stages[job.pc];
            match self.stage(job, stage)? {
                Flow::Pure => {
                    job.pc += 1;
                    job.sub = 0;
                    job.dsub = 0;
                }
                Flow::Call => return Ok(None),
                Flow::CallDone => {
                    job.pc += 1;
                    job.sub = 0;
                    job.dsub = 0;
                    if job.pc >= job.nstages {
                        return self.finish_ok(job, w);
                    }
                    return Ok(None);
                }
            }
        }
    }

    /// What a failure after the name was made in `work/` leaves: the item is queued for the
    /// reaper, and the failure is the answer.
    fn scrub_fail(&mut self, job: &ChangeJob<V, L>, dir: bool, e: Status) -> Stop {
        let (work, len) = Self::work_path_of(job.work);
        let _ = self.work.push(&work[..len], dir, 0);
        Stop::Status(from_volume(e))
    }

    fn stage(&mut self, job: &mut ChangeJob<V, L>, stage: Stage) -> F<Flow> {
        match stage {
            Stage::Ensure { b } => self.stage_ensure(job, b),
            Stage::Dir { b, opaque, created } => {
                let parent = if b { job.dir_b } else { job.dir_a };
                let (at, len) = {
                    let leg = job.leg(b);
                    (leg.parts.leaf_at, leg.parts.len)
                };
                match self.dir_step(job, b, parent, (at, len), len, created, opaque)? {
                    Some(_) => Ok(Flow::CallDone),
                    None => Ok(Flow::Call),
                }
            }
            Stage::File { kind, created } => self.stage_file(job, kind, created),
            Stage::Mark { dir, b } => self.stage_mark(job, dir, b),
            Stage::IndexMark { dir, b } => {
                let fields = Fields {
                    kind: Kind::Whiteout,
                    layer: self.composition.live().number,
                    number: 0,
                    uid: 0,
                    gid: 0,
                    mode: 0,
                };
                let parent = job.dir_of(dir);
                match self.index.insert(parent, job.leg(b).leaf_name(), fields) {
                    Ok(_) => Ok(Flow::Pure),
                    Err(_) => fail(proto_fs::NO_SPACE),
                }
            }
            Stage::DropMark { dir, b } => {
                let _ = dir;
                let leaf_len = job.leg(b).leaf_name().len();
                if WHITEOUT_PREFIX.len() + leaf_len > NAME_MAX {
                    return Ok(Flow::Pure);
                }
                let mut path = [0u8; 512];
                let Ok(n) = self.leg_leaf_path(job.leg(b), WHITEOUT_PREFIX, &mut path) else {
                    return Ok(Flow::Pure);
                };
                let _ = self.volume.unlink(&path[..n]);
                Ok(Flow::CallDone)
            }
            Stage::Opaque => self.stage_opaque(job),
            Stage::UnlinkVictim { link } => {
                let mut path = [0u8; 512];
                let n = self.leg_vpath(&job.a, job.a.parts.len, link, &mut path)?;
                self.volume.unlink(&path[..n]).map_err(from_volume)?;
                self.index.remove(job.victim.id);
                Ok(Flow::CallDone)
            }
            Stage::UnlinkDst => {
                let mut path = [0u8; 512];
                let n = self.leg_vpath(&job.b, job.b.parts.len, false, &mut path)?;
                self.volume.unlink(&path[..n]).map_err(from_volume)?;
                Ok(Flow::CallDone)
            }
            Stage::Retire => {
                let mut path = [0u8; 512];
                let n = self.leg_vpath(&job.a, job.a.parts.len, false, &mut path)?;
                let (num, work, wl) = self.work_path();
                job.work = num;
                self.volume
                    .rename(&path[..n], &work[..wl])
                    .map_err(from_volume)?;
                let id = job.victim.id;
                let key = self.index.retire(id).unwrap_or(0);
                self.table.forget(id);
                let _ = self.work.push(&work[..wl], true, key);
                Ok(Flow::CallDone)
            }
            Stage::RenameMain => self.stage_rename(job),
            Stage::UnlinkOldLink => {
                let mut path = [0u8; 512];
                let n = self.leg_vpath(&job.b, job.b.parts.len, true, &mut path)?;
                // A file over a link: the file of the link is not replaced by the rename.
                let _ = self.volume.unlink(&path[..n]);
                Ok(Flow::CallDone)
            }
            Stage::OpenFile => self.stage_open_file(job),
            Stage::Attr => self.stage_attr(job),
        }
    }

    /// The directories of the lower components of a leg are made in the layer, one call in each
    /// step: the stat of the lower directory, then the calls of `dir_step`.
    fn stage_ensure(&mut self, job: &mut ChangeJob<V, L>, b: bool) -> F<Flow> {
        let (parent_len, up, miss, deepest) = {
            let leg = job.leg(b);
            let Some(p) = leg.parent.as_ref() else {
                return fail(proto_fs::NO_ENTRY);
            };
            (leg.parts.parent_len, p.up, leg.miss, leg.deepest)
        };
        let set_dir = |job: &mut ChangeJob<V, L>, id: u32| {
            if b {
                job.dir_b = id;
            } else {
                job.dir_a = id;
            }
        };
        if let Some(id) = up {
            set_dir(job, id);
            return Ok(Flow::Pure);
        }
        if job.sub == 0 {
            job.ens_pos = miss;
            job.ens_cur = deepest;
            job.sub = 1;
        }
        let pos = job.ens_pos;
        if pos >= parent_len {
            let cur = job.ens_cur;
            set_dir(job, cur);
            return Ok(Flow::Pure);
        }
        let end = job.leg(b).plain[pos..parent_len]
            .iter()
            .position(|&x| x == b'/')
            .map_or(parent_len, |i| pos + i);
        if job.sub == 1 {
            let ls = match self.lower.stat(&job.leg(b).plain[..end], false) {
                Ok(s) if s.kind == 1 => s,
                Ok(_) => return fail(proto_fs::NOT_DIRECTORY),
                Err(e) => return Err(Stop::Status(e)),
            };
            job.ens_created = Created {
                uid: ls.uid,
                gid: ls.gid,
                mode: ls.mode & 0o7777,
            };
            job.sub = 2;
            return Ok(Flow::Call);
        }
        let (cur, created) = (job.ens_cur, job.ens_created);
        match self.dir_step(job, b, cur, (pos, end), end, created, false)? {
            Some(id) => {
                job.ens_cur = id;
                job.ens_pos = end + 1;
                job.sub = 1;
                if job.ens_pos >= parent_len {
                    set_dir(job, id);
                    Ok(Flow::CallDone)
                } else {
                    Ok(Flow::Call)
                }
            }
            None => Ok(Flow::Call),
        }
    }

    /// A directory `name` (the bytes `name.0..name.1` of the plain path of the leg) in `parent`,
    /// prepared in `work/` and renamed in; opaque when `opaque`. The path of the directory is
    /// `leg.plain[..end]`. One call in each step; the id when the last one is made.
    #[allow(clippy::too_many_arguments)]
    fn dir_step(
        &mut self,
        job: &mut ChangeJob<V, L>,
        b: bool,
        parent: u32,
        name: (usize, usize),
        end: usize,
        created: Created,
        opaque: bool,
    ) -> F<Option<u32>> {
        let Created { uid, gid, mode } = created;
        match job.dsub {
            0 => {
                let mut live = [0u8; 512];
                self.leg_vpath(job.leg(b), end, false, &mut live)?;
                if !self
                    .index
                    .has_room(parent, &job.leg(b).plain[name.0..name.1])
                {
                    return fail(proto_fs::NO_SPACE);
                }
                let (num, work, wl) = self.work_path();
                job.work = num;
                self.volume.mkdir(&work[..wl], 0o700).map_err(from_volume)?;
                job.dsub = 1;
                Ok(None)
            }
            1 => {
                let (work, wl) = Self::work_path_of(job.work);
                match self.volume.stat(&work[..wl]) {
                    Ok(stat) => job.ino = stat.ino,
                    Err(e) => return Err(self.scrub_fail(job, true, e)),
                }
                job.dsub = if opaque { 2 } else { 4 };
                Ok(None)
            }
            2 => {
                let (work, wl) = Self::work_path_of(job.work);
                let mut marker = [0u8; 80];
                marker[..wl].copy_from_slice(&work[..wl]);
                marker[wl] = b'/';
                let at = wl + 1 + OPAQUE_NAME.len();
                marker[wl + 1..at].copy_from_slice(OPAQUE_NAME);
                match self
                    .volume
                    .open(&marker[..at], d::WRITE | d::CREATE | d::EXCLUSIVE, 0o600)
                {
                    Ok(h) => job.handle = h,
                    Err(e) => return Err(self.scrub_fail(job, true, e)),
                }
                job.dsub = 3;
                Ok(None)
            }
            3 => {
                if let Err(e) = self.volume.close(job.handle) {
                    return Err(self.scrub_fail(job, true, e));
                }
                job.dsub = 4;
                Ok(None)
            }
            4 => {
                let (work, wl) = Self::work_path_of(job.work);
                if let Err(e) = self.volume.chown(&work[..wl], uid, gid) {
                    return Err(self.scrub_fail(job, true, e));
                }
                job.dsub = 5;
                Ok(None)
            }
            5 => {
                let (work, wl) = Self::work_path_of(job.work);
                if let Err(e) = self.volume.chmod(&work[..wl], mode) {
                    return Err(self.scrub_fail(job, true, e));
                }
                job.dsub = 6;
                Ok(None)
            }
            _ => {
                let (work, wl) = Self::work_path_of(job.work);
                let mut live = [0u8; 512];
                let n = self.leg_vpath(job.leg(b), end, false, &mut live)?;
                if let Err(e) = self.volume.rename(&work[..wl], &live[..n]) {
                    return Err(self.scrub_fail(job, true, e));
                }
                let fields = Fields {
                    kind: Kind::Dir,
                    layer: self.composition.live().number,
                    number: job.ino,
                    uid,
                    gid,
                    mode: mode as u16,
                };
                let inserted = self
                    .index
                    .insert(parent, &job.leg(b).plain[name.0..name.1], fields);
                match inserted {
                    Ok(id) => {
                        self.index.set_flags(id, 0, UNSCANNED);
                        if opaque {
                            self.index.set_flags(id, OPAQUE, 0);
                        }
                        job.made = id;
                        job.dsub = 0;
                        Ok(Some(id))
                    }
                    Err(_) => {
                        let _ = self.work.push(&live[..n], true, 0);
                        fail(proto_fs::NO_SPACE)
                    }
                }
            }
        }
    }

    /// A file or a link at the leaf of the first leg, with the text of a link for its bytes,
    /// prepared in `work/`: the number from the counter of COMPOSITION (written back, in steps, when
    /// its block is used up), the file, its bytes, its owner and mode, the rename.
    fn stage_file(&mut self, job: &mut ChangeJob<V, L>, kind: Kind, created: Created) -> F<Flow> {
        let link = kind == Kind::Link;
        let parent = job.dir_a;
        let Created { uid, gid, mode } = created;
        let (text_from, text_to) = if link { job.second } else { (0, 0) };
        loop {
            match job.dsub {
                0 => {
                    let mut live = [0u8; 512];
                    self.leg_vpath(&job.a, job.a.parts.len, link, &mut live)?;
                    if !self.index.has_room(parent, job.a.leaf_name()) {
                        return fail(proto_fs::NO_SPACE);
                    }
                    if !self.writes.started {
                        self.writes.ino_next = self.composition.ino;
                        self.writes.ino_limit = self.composition.ino;
                        self.writes.started = true;
                    }
                    if self.writes.ino_next >= self.writes.ino_limit {
                        let limit = self.writes.ino_next + INO_BLOCK;
                        if limit >= UPPER_INO_TAG {
                            return fail(proto_fs::NO_SPACE);
                        }
                        let mut next = self.composition;
                        next.ino = limit;
                        job.clen = next.render(&mut job.ctext);
                        job.cnext = Some(next);
                        job.dsub = 20;
                    } else {
                        job.dsub = 1;
                    }
                }
                20 => {
                    job.handle = self
                        .volume
                        .open(COMPOSITION_TMP, d::WRITE | d::CREATE | d::TRUNCATE, 0o600)
                        .map_err(from_volume)?;
                    job.written = 0;
                    job.err = None;
                    job.dsub = 21;
                    return Ok(Flow::Call);
                }
                21 => {
                    match self
                        .volume
                        .write(job.handle, &job.ctext[job.written..job.clen])
                    {
                        Ok(0) => {
                            job.err = Some(st(d::NO_SPACE));
                            job.dsub = 23;
                        }
                        Ok(k) => {
                            job.written += k;
                            if job.written >= job.clen {
                                job.dsub = 22;
                            }
                        }
                        Err(e) => {
                            job.err = Some(e);
                            job.dsub = 23;
                        }
                    }
                    return Ok(Flow::Call);
                }
                22 => {
                    if let Err(e) = self.volume.fsync(job.handle) {
                        job.err = Some(e);
                    }
                    job.dsub = 23;
                    return Ok(Flow::Call);
                }
                23 => {
                    let closed = self.volume.close(job.handle);
                    if let Some(e) = job.err.take() {
                        return Err(Stop::Status(from_volume(e)));
                    }
                    closed.map_err(from_volume)?;
                    job.dsub = 24;
                    return Ok(Flow::Call);
                }
                24 => {
                    self.volume
                        .rename(COMPOSITION_TMP, COMPOSITION)
                        .map_err(from_volume)?;
                    if let Some(next) = job.cnext.take() {
                        self.writes.ino_limit = next.ino;
                        self.composition = next;
                    }
                    job.dsub = 1;
                    return Ok(Flow::Call);
                }
                1 => {
                    let ino = UPPER_INO_TAG | self.writes.ino_next;
                    self.writes.ino_next += 1;
                    job.ino = ino;
                    let (num, work, wl) = self.work_path();
                    job.work = num;
                    job.handle = self
                        .volume
                        .open_numbered(&work[..wl], d::WRITE | d::CREATE | d::EXCLUSIVE, 0o600, ino)
                        .map_err(from_volume)?;
                    job.written = 0;
                    job.err = None;
                    job.dsub = 2;
                    return Ok(Flow::Call);
                }
                2 => {
                    let left = text_to - text_from - job.written;
                    if left == 0 {
                        job.dsub = 3;
                        continue;
                    }
                    let at = text_from + job.written;
                    match self.volume.write(job.handle, &job.req[at..text_to]) {
                        Ok(0) => {
                            job.err = Some(st(d::NO_SPACE));
                            job.dsub = 4;
                        }
                        Ok(k) => job.written += k,
                        Err(e) => {
                            job.err = Some(e);
                            job.dsub = 4;
                        }
                    }
                    return Ok(Flow::Call);
                }
                3 => {
                    job.dsub = 4;
                    if link {
                        if let Err(e) = self.volume.fsync(job.handle) {
                            job.err = Some(e);
                        }
                        return Ok(Flow::Call);
                    }
                }
                4 => {
                    let closed = self.volume.close(job.handle);
                    if let Some(e) = job.err.take() {
                        return Err(self.scrub_fail(job, false, e));
                    }
                    if let Err(e) = closed {
                        return Err(self.scrub_fail(job, false, e));
                    }
                    job.dsub = 5;
                    return Ok(Flow::Call);
                }
                5 => {
                    let (work, wl) = Self::work_path_of(job.work);
                    if let Err(e) = self.volume.chown(&work[..wl], uid, gid) {
                        return Err(self.scrub_fail(job, false, e));
                    }
                    job.dsub = 6;
                    return Ok(Flow::Call);
                }
                6 => {
                    let (work, wl) = Self::work_path_of(job.work);
                    if let Err(e) = self.volume.chmod(&work[..wl], mode) {
                        return Err(self.scrub_fail(job, false, e));
                    }
                    job.dsub = 7;
                    return Ok(Flow::Call);
                }
                _ => {
                    let (work, wl) = Self::work_path_of(job.work);
                    let mut live = [0u8; 512];
                    let n = self.leg_vpath(&job.a, job.a.parts.len, link, &mut live)?;
                    if let Err(e) = self.volume.rename(&work[..wl], &live[..n]) {
                        return Err(self.scrub_fail(job, false, e));
                    }
                    let fields = Fields {
                        kind,
                        layer: self.composition.live().number,
                        number: job.ino,
                        uid,
                        gid,
                        mode: mode as u16,
                    };
                    return match self.index.insert(parent, job.a.leaf_name(), fields) {
                        Ok(id) => {
                            job.made = id;
                            Ok(Flow::CallDone)
                        }
                        Err(_) => {
                            let _ = self.work.push(&live[..n], false, 0);
                            fail(proto_fs::NO_SPACE)
                        }
                    };
                }
            }
        }
    }

    /// The mark `.wh.<leaf>` of a leg in a directory: made in `work/` and renamed in (the volume
    /// only: the index has its own stage).
    fn stage_mark(&mut self, job: &mut ChangeJob<V, L>, dir: DirRef, b: bool) -> F<Flow> {
        if cfg!(feature = "break-layerd-no-mark") {
            return Ok(Flow::Pure);
        }
        match job.dsub {
            0 => {
                let leaf_len = job.leg(b).leaf_name().len();
                if leaf_len + WHITEOUT_PREFIX.len() > NAME_MAX {
                    return fail(proto_fs::NAME_TOO_LONG);
                }
                let mut path = [0u8; 512];
                self.leg_leaf_path(job.leg(b), WHITEOUT_PREFIX, &mut path)?;
                if !self.index.has_room(job.dir_of(dir), job.leg(b).leaf_name()) {
                    return fail(proto_fs::NO_SPACE);
                }
                let (num, work, wl) = self.work_path();
                job.work = num;
                job.handle = self
                    .volume
                    .open(&work[..wl], d::WRITE | d::CREATE | d::EXCLUSIVE, 0o600)
                    .map_err(from_volume)?;
                job.dsub = 1;
                Ok(Flow::Call)
            }
            1 => {
                if let Err(e) = self.volume.close(job.handle) {
                    return Err(self.scrub_fail(job, false, e));
                }
                job.dsub = 2;
                Ok(Flow::Call)
            }
            _ => {
                let (work, wl) = Self::work_path_of(job.work);
                let mut path = [0u8; 512];
                let n = self.leg_leaf_path(job.leg(b), WHITEOUT_PREFIX, &mut path)?;
                if let Err(e) = self.volume.rename(&work[..wl], &path[..n]) {
                    return Err(self.scrub_fail(job, false, e));
                }
                Ok(Flow::CallDone)
            }
        }
    }

    /// The directory at the leaf of the first path becomes opaque: the file `.wh..wh..opq` in it.
    fn stage_opaque(&mut self, job: &mut ChangeJob<V, L>) -> F<Flow> {
        if job.dsub == 0 {
            let mut path = [0u8; 512];
            let n = self.leg_vpath(&job.a, job.a.parts.len, false, &mut path)?;
            let total = n + 1 + OPAQUE_NAME.len();
            if total > d::MAX_PATH {
                return fail(proto_fs::NAME_TOO_LONG);
            }
            path[n] = b'/';
            path[n + 1..total].copy_from_slice(OPAQUE_NAME);
            job.handle = self
                .volume
                .open(&path[..total], d::WRITE | d::CREATE, 0o600)
                .map_err(from_volume)?;
            job.dsub = 1;
            return Ok(Flow::Call);
        }
        let _ = self.volume.close(job.handle);
        self.index.set_flags(job.rn.src_id, OPAQUE, 0);
        Ok(Flow::CallDone)
    }

    /// The rename: the visible step. A directory the name goes over is taken into `work/` first (the
    /// second call of this step), and the index follows both calls.
    fn stage_rename(&mut self, job: &mut ChangeJob<V, L>) -> F<Flow> {
        let Some(dst) = job.rn.dst else {
            return fail(proto_fs::NO_ENTRY);
        };
        let (_, dst_up, _) = dst_facts(dst);
        let src_link = job.rn.src_kind == Kind::Link;
        let mut old = [0u8; 512];
        let on = self.leg_vpath(&job.a, job.a.parts.len, src_link, &mut old)?;
        let mut new = [0u8; 512];
        let nn = self.leg_vpath(&job.b, job.b.parts.len, src_link, &mut new)?;
        if let Some((id, Kind::Dir)) = dst_up {
            let (num, work, wl) = self.work_path();
            job.work = num;
            self.volume
                .rename(&new[..nn], &work[..wl])
                .map_err(from_volume)?;
            if let Err(e) = self.volume.rename(&old[..on], &new[..nn]) {
                // The target directory goes back.
                let _ = self.volume.rename(&work[..wl], &new[..nn]);
                return Err(Stop::Status(from_volume(e)));
            }
            let key = self.index.retire(id).unwrap_or(0);
            self.table.forget(id);
            let _ = self.work.push(&work[..wl], true, key);
        } else {
            self.volume
                .rename(&old[..on], &new[..nn])
                .map_err(from_volume)?;
            if let Some((id, _)) = dst_up {
                self.index.remove(id);
            }
        }
        let (to, src_id) = (job.dir_b, job.rn.src_id);
        let b_leaf = job.b.leaf_name();
        if let Leaf::Missing { hidden: true, .. } = dst
            && let Some((mark, _)) = self.index.lookup(to, b_leaf)
        {
            self.index.remove(mark);
        }
        let new_id = self
            .index
            .move_to(src_id, to, b_leaf)
            .map_err(|_| Stop::Status(st(proto_fs::NO_SPACE)))?;
        if job.rn.src_kind == Kind::Dir {
            self.table.retarget(src_id, new_id);
        }
        if job.rn.src_lower.is_some() {
            let fields = Fields {
                kind: Kind::Whiteout,
                layer: self.composition.live().number,
                number: 0,
                uid: 0,
                gid: 0,
                mode: 0,
            };
            if self
                .index
                .insert(job.rn.src_parent, job.a.leaf_name(), fields)
                .is_err()
            {
                return fail(proto_fs::NO_SPACE);
            }
        }
        Ok(Flow::CallDone)
    }

    /// The file an OPEN that creates made: opened, its pass taken and the description closed.
    fn stage_open_file(&mut self, job: &mut ChangeJob<V, L>) -> F<Flow> {
        match job.dsub {
            0 => {
                let mut path = [0u8; 512];
                let n = self.leg_vpath(&job.a, job.a.parts.len, false, &mut path)?;
                job.handle = self
                    .volume
                    .open(&path[..n], Self::wire_flags(job.flags), 0)
                    .map_err(from_volume)?;
                job.err = None;
                job.dsub = 1;
                Ok(Flow::Call)
            }
            1 => {
                match self.volume.export(job.handle) {
                    Ok(pass) => job.pass = Some(pass),
                    Err(e) => job.err = Some(e),
                }
                job.dsub = 2;
                Ok(Flow::Call)
            }
            _ => {
                let _ = self.volume.close(job.handle);
                match job.err.take() {
                    Some(e) => Err(Stop::Status(from_volume(e))),
                    None => Ok(Flow::CallDone),
                }
            }
        }
    }

    /// `chmod`, `chown`, `utimensat` and `truncate` of the name the walk found.
    fn stage_attr(&mut self, job: &mut ChangeJob<V, L>) -> F<Flow> {
        let plan = job.attr;
        let n = job.b.len;
        match job.op {
            ChangeOp::Chmod => {
                self.volume
                    .chmod(&job.b.plain[..n], plan.mode)
                    .map_err(from_volume)?;
                if plan.dir {
                    self.index
                        .set_attr(plan.id, plan.ino, plan.uid, plan.gid, plan.mode as u16);
                }
                Ok(Flow::CallDone)
            }
            ChangeOp::Chown => {
                self.volume
                    .chown(&job.b.plain[..n], plan.keep_uid, plan.keep_gid)
                    .map_err(from_volume)?;
                if plan.dir {
                    self.index
                        .set_attr(plan.id, plan.ino, plan.uid, plan.gid, plan.mode as u16);
                }
                Ok(Flow::CallDone)
            }
            ChangeOp::Utimens => {
                self.volume
                    .utimens(&job.b.plain[..n], plan.atime, plan.mtime)
                    .map_err(from_volume)?;
                Ok(Flow::CallDone)
            }
            _ => match job.dsub {
                0 => {
                    job.handle = self
                        .volume
                        .open(&job.b.plain[..n], d::WRITE, 0)
                        .map_err(from_volume)?;
                    job.err = None;
                    job.dsub = 1;
                    Ok(Flow::Call)
                }
                1 => {
                    if let Err(e) = self.volume.truncate(job.handle, plan.size) {
                        job.err = Some(e);
                    }
                    job.dsub = 2;
                    Ok(Flow::Call)
                }
                _ => {
                    let _ = self.volume.close(job.handle);
                    match job.err.take() {
                        Some(e) => Err(Stop::Status(from_volume(e))),
                        None => Ok(Flow::CallDone),
                    }
                }
            },
        }
    }
}
