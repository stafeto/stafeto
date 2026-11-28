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
//!   visible, the exceptions being the step of a rename over a directory, which makes two
//!   renames (the target into `work/`, the source over its name) and a third when the second
//!   fails (the target goes back), and the step of a link over a file (the rename and the
//!   removal of the file).
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
use crate::index::{Fields, Kind, NAME_MAX, OPAQUE, Room, UNSCANNED};
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

/// What `Core::commit_start` did.
pub enum CommitStart {
    /// No copy waits for a commit.
    None,
    /// The commit job has a copy.
    Job,
    /// The copy of this ticket is over at once, failed.
    Failed(u64),
}

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
    /// The read of the text of a link of the lower set (a copy of the link).
    LowerLink,
    Empty,
    Commit,
    LinkOpen,
    LinkRead,
    LinkClose,
}

impl Stage {
    fn code(&self) -> u64 {
        match self {
            Stage::Ensure { .. } => 0,
            Stage::Dir { .. } => 1,
            Stage::File { .. } => 2,
            Stage::Mark { .. } => 3,
            Stage::IndexMark { .. } => 4,
            Stage::DropMark { .. } => 5,
            Stage::Opaque => 6,
            Stage::UnlinkVictim { .. } => 7,
            Stage::Retire => 9,
            Stage::RenameMain => 10,
            Stage::UnlinkOldLink => 11,
            Stage::OpenFile { .. } => 12,
            Stage::Attr => 13,
            Stage::CopyReserve => 14,
            Stage::CopyIn => 15,
            Stage::CopyDrop => 16,
        }
    }
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
    /// A directory at the leaf of a leg; the number of the directory of the lower set when it is
    /// the copy of one (a new directory takes the next number of the counter).
    Dir {
        b: bool,
        opaque: bool,
        created: Created,
        lower: Option<u64>,
    },
    /// A file or a link at the leaf of the first leg; the number of the link of the lower set when
    /// it is the copy of one.
    File {
        kind: Kind,
        created: Created,
        lower: Option<u64>,
    },
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
    /// The directory at the leaf of the first path leaves the layer.
    Retire,
    /// The rename.
    RenameMain,
    /// The file of the link a file went over is removed.
    UnlinkOldLink,
    /// The file made by an OPEN that creates is opened and its pass taken.
    OpenFile { check: bool },
    /// An attribute operation.
    Attr,
    /// The copy of a file of the lower set is queued: its ticket is the answer (COPYING).
    CopyReserve,
    /// The copy the worker made is renamed into the layer and entered in the index, in one
    /// visible step.
    CopyIn,
    /// The copy the worker made is of no use (the name changed meanwhile, or the copy failed):
    /// the file in `work/` goes to the reaper.
    CopyDrop,
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
    /// The step that makes a finished copy visible (no request: the loop starts it).
    Commit,
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
    /// The entry the operation acts on was made by this job (the copy of a lower directory or
    /// link): `Stage::Attr` takes its id from `made` and its path from the first leg.
    fresh: bool,
    link: bool,
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
    fresh: false,
    link: false,
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
    /// The job needs no lock (it changes nothing).
    lockless: bool,
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
    /// The stat of the lower set in flight (`Core::lower_stat`): one at a time.
    probe: Option<L::Probe>,
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
    /// The copy up the job plans: what it copies and the stat of the lower file; the ticket the
    /// answer COPYING carries (0 for none).
    copy_kind: crate::copy::Kind,
    copy_stat: LowerStat,
    ticket: u64,
    /// The copy a commit job makes visible: its place and generation.
    commit_of: Option<(u8, u32)>,
    /// The state of the counter of numbers (`next_number`), the number of the directory of the lower
    /// set a copy of one keeps, and the read of the text of a link of the lower set.
    csub: u8,
    ens_ino: u64,
    /// The times (access, modification) of the lower directory a copy of one keeps: of the
    /// directory `stage_ensure` is making, of the leaf of an attribute operation, and the ones
    /// `dir_step` gives the directory it makes (None for a new directory).
    ens_times: (i64, i64),
    leaf_times: (i64, i64),
    dir_times: Option<(i64, i64)>,
    lprobe: Option<L::Link>,
    /// What a commit job did with its copy: made it visible, or dropped it (the file in `work/`
    /// is the reaper's); and the code the waiters get when the copy could not be made visible.
    copy_visible: bool,
    dropped: bool,
    copy_code: u32,
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
            lockless: false,
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
            probe: None,
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
            copy_kind: crate::copy::Kind::Whole,
            copy_stat: LowerStat {
                kind: 2,
                mode: 0,
                uid: 0,
                gid: 0,
                ino: 0,
                atime: 0,
                mtime: 0,
            },
            ticket: 0,
            commit_of: None,
            csub: 0,
            ens_ino: 0,
            ens_times: (0, 0),
            leaf_times: (0, 0),
            dir_times: None,
            lprobe: None,
            copy_visible: false,
            dropped: false,
            copy_code: 0,
        }
    }

    fn reset(&mut self, id: u8) {
        self.creating = false;
        self.flags = 0;
        self.id = id;
        self.locked = false;
        self.lockless = false;
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
        self.ticket = 0;
        self.commit_of = None;
        self.csub = 0;
        self.ens_ino = 0;
        self.lprobe = None;
        self.copy_visible = false;
        self.dropped = false;
        self.copy_code = 0;
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

    /// The step that makes the finished copy of `place` and `generation` visible: its path is the
    /// one of the lower file the copy was made for.
    pub fn start_commit(&mut self, id: u8, place: u8, generation: u32, path: &[u8]) -> R<()> {
        if path.len() > self.a.plain.len() {
            return Err(Status::BadSize);
        }
        self.reset(id);
        self.commit_of = Some((place, generation));
        self.a.plain[..path.len()].copy_from_slice(path);
        self.a.len = path.len();
        Ok(())
    }

    /// The copy a commit job works for.
    pub fn commit_of(&self) -> Option<(u8, u32)> {
        self.commit_of
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
            Phase::LowerA | Phase::LowerB => {
                let leg = self.leg(self.phase == Phase::LowerB);
                3000 + leg.plain[..leg.lpos].iter().filter(|&&c| c == b'/').count() as u64
            }
            Phase::Commit
                if matches!(self.stages.get(self.pc), Some(Stage::Ensure { .. }))
                    && self.sub == 1 =>
            {
                let leg = self.leg(matches!(
                    self.stages.get(self.pc),
                    Some(Stage::Ensure { b: true })
                ));
                3100 + leg.plain[..self.ens_pos]
                    .iter()
                    .filter(|&&c| c == b'/')
                    .count() as u64
            }
            Phase::Commit => {
                2000 + self.stages.get(self.pc).map_or(99, |s| s.code()) * 100
                    + u64::from(self.dsub)
            }
            other => 1200 + other as u64,
        }
    }

    /// Whether the job has made its first call of `Commit`: it runs to its end whatever happens
    /// to its session.
    pub fn committed(&self) -> bool {
        self.committed
    }

    fn class(&self) -> Class {
        if self.commit_of.is_some() {
            return Class::Commit;
        }
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
        let mut step = self.change_step_once(c, job, w);
        // The deliberate break: the whole change in one step.
        while cfg!(feature = "break-layerd-change-one-step") && matches!(step, ChangeStep::More) {
            step = self.change_step_once(c, job, w);
        }
        step
    }

    fn change_step_once(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        w: &mut Writer,
    ) -> ChangeStep<V::Pass> {
        if !job.locked && !job.lockless {
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
        if let Some(probe) = job.probe.take() {
            self.lower.stat_cancel(probe);
        }
        if let Some(link) = job.lprobe.take() {
            self.lower.readlink_cancel(link);
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
                if job.creating || job.commit_of.is_some() {
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
                if !self.step_leaf(job, false)? {
                    return Ok(None);
                }
                self.decide(c, job, Phase::LeafA)
            }
            Phase::LeafB => {
                if !self.step_leaf(job, true)? {
                    return Ok(None);
                }
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
            Phase::LowerLink => self.step_lower_link(c, job),
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
    ///
    /// The bound of the lock. Each component is a stat of its whole path from the root, so a lower
    /// chain of k components costs the RAM file service about k*(k+1)/2 resolve steps (about
    /// 1,400 ticks each) for the walk, and as many again for the directories a copy up makes
    /// (`stage_ensure`), all of them with the job holding the lock of the changes. Each is a step
    /// of the loop of its own, so no step is longer, but a change below a deep chain holds the
    /// lock for many of them, and the other changes wait their turns (round robin over the
    /// places, about `JOBS - 1` times the longest change). A resolve of each prefix against the
    /// descriptor of its parent (`Files::path_start` takes a base) would make the cost linear; it
    /// needs a descriptor of the RAM file service for each level, and is left for a later change.
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
        let ls = match self.lower_stat(&mut job.probe, &leg.plain[..end])? {
            None => return Ok(None),
            Some(None) => return fail(proto_fs::NO_ENTRY),
            Some(Some(ls)) => ls,
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
    /// of the lower set, which goes on over steps; false while it does.
    fn step_leaf(&mut self, job: &mut ChangeJob<V, L>, b: bool) -> F<bool> {
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
            match self.lower_stat(&mut job.probe, full)? {
                None => return Ok(false),
                Some(seen) => seen,
            }
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
        Ok(true)
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
                match self.lower.open_dir_start(path) {
                    Ok(dir) => {
                        job.empty.dir = Some(dir);
                        job.empty.sub = 1;
                        Ok(false)
                    }
                    Err(Status::Unknown(proto_fs::NO_ENTRY | proto_fs::NOT_DIRECTORY)) => {
                        job.empty.empty = true;
                        Ok(true)
                    }
                    // The session has no path job free: the start is made again in the next step.
                    Err(Status::Unknown(proto_fs::TOO_MANY_OPEN_FILES)) => Ok(false),
                    Err(e) => Err(Stop::Status(e)),
                }
            }
            // The open goes on over steps, one round trip each.
            1 => {
                let Some(dir) = job.empty.dir.as_mut() else {
                    return Ok(true);
                };
                match self.lower.open_dir_poll(dir) {
                    Ok(true) => job.empty.sub = 2,
                    Ok(false) => {}
                    Err(e) => {
                        if let Some(dir) = job.empty.dir.take() {
                            self.lower.close_dir(dir);
                        }
                        return match e {
                            Status::Unknown(proto_fs::NO_ENTRY | proto_fs::NOT_DIRECTORY) => {
                                job.empty.empty = true;
                                Ok(true)
                            }
                            e => Err(Stop::Status(e)),
                        };
                    }
                }
                Ok(false)
            }
            2 => {
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
                                job.empty.sub = 3;
                                break;
                            }
                        }
                        Ok(None) => {
                            job.empty.sub = 3;
                            break;
                        }
                        Err(e) => {
                            job.empty.err = Some(e);
                            job.empty.sub = 3;
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
            Class::Commit => self.decide_commit(job, done),
        }
    }

    fn begin_walk(job: &mut ChangeJob<V, L>, b: bool) {
        let leg = if b { &mut job.b } else { &mut job.a };
        leg.restart();
        job.phase = if b { Phase::WalkB } else { Phase::WalkA };
    }

    /// A finished copy: its name is walked again, and the copy is made visible when the name is
    /// still the lower set's and visible and the layer has the directory of the path; otherwise,
    /// and when the worker failed, the copy goes to the reaper.
    fn decide_commit(
        &mut self,
        job: &mut ChangeJob<V, L>,
        done: Phase,
    ) -> F<Option<Done<V::Pass>>> {
        let Some((place, generation)) = job.commit_of else {
            return fail(proto_fs::INVALID_ARGUMENT);
        };
        match done {
            Phase::PlainA => {
                let Some((_, _, code, _)) = self.copies.facts(place, generation) else {
                    return fail(proto_fs::INVALID_ARGUMENT);
                };
                if code != 0 {
                    // The worker failed: nothing to walk.
                    job.committed = true;
                    job.push(Stage::CopyDrop);
                    job.pc = 0;
                    job.dsub = 0;
                    job.phase = Phase::Commit;
                    return Ok(None);
                }
                job.a.parts = split(&job.a.plain[..job.a.len])?;
                job.committed = true;
                Self::begin_walk(job, false);
                Ok(None)
            }
            Phase::LeafA => {
                let leaf = job.a.leaf;
                let ino = self
                    .copies
                    .facts(place, generation)
                    .map_or(0, |(_, stat, _, _)| stat.ino);
                let same = matches!(leaf, Some(Leaf::Lower(ls)) if ls.ino == ino && ls.kind == 2);
                // The deliberate break `break-layerd-copy-recheck`: the copy is made visible whatever
                // the walk found at the name.
                let same = same || cfg!(feature = "break-layerd-copy-recheck");
                // The directories of the path the layer does not hold are made with the copy.
                if same {
                    job.push(Stage::Ensure { b: false });
                    job.push(Stage::CopyIn);
                } else {
                    job.push(Stage::CopyDrop);
                }
                job.pc = 0;
                job.dsub = 0;
                job.phase = Phase::Commit;
                Ok(None)
            }
            _ => fail(proto_fs::INVALID_ARGUMENT),
        }
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
                    Leaf::Upper { kind, .. } => {
                        if class != Class::Create || job.flags & proto_fs::EXCLUSIVE != 0 {
                            return fail(proto_fs::ALREADY_EXISTS);
                        }
                        // Another job made the name in the meantime: only EXCLUSIVE minds. The
                        // file is opened, and the lock goes at once (nothing is changed).
                        match kind {
                            Kind::Dir => return fail(proto_fs::IS_DIRECTORY),
                            Kind::Link => return fail(proto_fs::LOOP),
                            _ => {}
                        }
                        self.work.unlock(job.id);
                        job.locked = false;
                        job.lockless = true;
                        job.push(Stage::OpenFile { check: true });
                        Self::begin_commit(job);
                        return Ok(None);
                    }
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
                        if !n::open_writes(job.flags) {
                            // The name is the lower set's to open for reading: the redirect to the
                            // RAM file service, which is the one of a link of the lower set.
                            return Err(Stop::LowerLink { which: 0 });
                        }
                        // An open for writing of a name of the lower set: the file is copied up
                        // (the cut of `O_TRUNC` makes the copy empty), and the open is made again
                        // when the copy is there.
                        match ls.kind {
                            1 => return fail(proto_fs::IS_DIRECTORY),
                            2 => {}
                            5 => return fail(proto_fs::LOOP),
                            _ => return fail(proto_fs::NOT_SUPPORTED),
                        }
                        let mut bits = WRITE;
                        if job.flags & 3 != proto_fs::WRITE_ONLY {
                            bits |= posix_perm::READ;
                        }
                        if !permits(who, &lower_attr(&ls), bits) {
                            return fail(proto_fs::ACCESS_DENIED);
                        }
                        let kind = if job.flags & proto_fs::TRUNCATE != 0 {
                            crate::copy::Kind::Empty
                        } else {
                            crate::copy::Kind::Whole
                        };
                        return self.plan_copy(job, ls, kind);
                    }
                };
                // Without CREATE a name that is not there is NO_ENTRY.
                if class == Class::Create && job.flags & proto_fs::CREATE == 0 {
                    return fail(proto_fs::NO_ENTRY);
                }
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
                            lower: None,
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
                            lower: None,
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
                            lower: None,
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
                    job.push(Stage::OpenFile { check: false });
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

/// The code of the answer for a failure of the volume.
fn from_volume_code(status: Status) -> u32 {
    match from_volume(status) {
        Status::Unknown(code) => code,
        _ => proto_layer::IO,
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
            && let Some(code) = self.no_room(up, job.b.leaf_name())
        {
            return fail(code);
        }
        if job.rn.src_lower.is_some()
            && let Some(code) = self.no_room(job.rn.src_parent, job.a.leaf_name())
        {
            return fail(code);
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
                // The name is the lower set's: the walk goes again by the directory part and the
                // leaf, as a change that makes a name does (`decide_attr` at `LeafA`).
                job.a.parts = split(&job.a.plain[..job.a.len])?;
                Self::begin_walk(job, false);
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
                let plan = Self::attr_plan(c, job, id, kind, &attr, stat.ino)?;
                job.attr = plan;
                job.push(Stage::Attr);
                Self::begin_commit(job);
                Ok(None)
            }
            // A name the layer does not hold: the lower set's, which is copied up first.
            Phase::LeafA => {
                let Some(leaf) = job.a.leaf else {
                    return fail(proto_fs::NO_ENTRY);
                };
                match leaf {
                    Leaf::Missing { .. } => fail(proto_fs::NO_ENTRY),
                    // The layer made the name since the walk of the whole path: it is walked again.
                    Leaf::Upper { .. } => {
                        job.a.restart();
                        job.phase = Phase::WalkFull;
                        Ok(None)
                    }
                    Leaf::Lower(ls) => self.plan_lower_attr(c, job, ls),
                }
            }
            _ => fail(proto_fs::INVALID_ARGUMENT),
        }
    }

    /// What an attribute operation does to a name with `attr`, its rights checked: the plan of
    /// the stage `Attr`.
    fn attr_plan(
        c: &Client<'_>,
        job: &ChangeJob<V, L>,
        id: u32,
        kind: Kind,
        attr: &posix_perm::Attr,
        ino: u64,
    ) -> F<AttrPlan> {
        let who = c.who.identity(false);
        let mut plan = AttrPlan {
            id,
            dir: kind == Kind::Dir,
            ino,
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
                plan.mode = posix_perm::chmod_result(who, attr, (job.a_val & 0o7777) as u32)
                    .map_err(denial)?;
            }
            ChangeOp::Chown => {
                let keep = |v: u64| (v as u32 != u32::MAX).then_some(v as u32);
                let (uid, gid) = (keep(job.a_val), keep(job.b_val));
                let owned = posix_perm::chown_result(who, attr, uid, gid).map_err(denial)?;
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
                posix_perm::utimens_allowed(who, attr, request).map_err(denial)?;
                plan.atime = atime;
                plan.mtime = mtime;
            }
            ChangeOp::Truncate => {
                if kind == Kind::Dir {
                    return fail(proto_fs::IS_DIRECTORY);
                }
                if !permits(who, attr, WRITE) {
                    return fail(proto_fs::ACCESS_DENIED);
                }
                plan.size = job.a_val;
            }
            _ => return fail(proto_fs::INVALID_ARGUMENT),
        }
        Ok(plan)
    }

    /// An attribute operation on a name of the lower set: a file is copied up whole (and the
    /// request sent again finds the copy), a directory is made in the layer with the attributes and
    /// the number of the lower one and then changed, a link (`lchown`) is made the same way once its
    /// text is read.
    fn plan_lower_attr(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        ls: LowerStat,
    ) -> F<Option<Done<V::Pass>>> {
        let attr = lower_attr(&ls);
        let trailing = job.a.parts.trailing;
        self.number_kept(&ls)?;
        match ls.kind {
            1 => {
                let mut plan = Self::attr_plan(c, job, 0, Kind::Dir, &attr, ls.ino)?;
                plan.fresh = true;
                job.attr = plan;
                job.leaf_times = (ls.atime, ls.mtime);
                job.committed = true;
                job.push(Stage::Ensure { b: false });
                job.push(Stage::Dir {
                    b: false,
                    opaque: false,
                    created: Created {
                        uid: ls.uid,
                        gid: ls.gid,
                        mode: ls.mode & 0o7777,
                    },
                    lower: Some(ls.ino),
                });
                job.push(Stage::Attr);
                job.pc = 0;
                job.dsub = 0;
                job.phase = Phase::Commit;
                Ok(None)
            }
            2 => {
                if trailing {
                    return fail(proto_fs::NOT_DIRECTORY);
                }
                // The rights are those of the lower attributes: the request that fails fails now,
                // before a byte is copied.
                Self::attr_plan(c, job, 0, Kind::File, &attr, ls.ino)?;
                self.plan_copy(job, ls, crate::copy::Kind::Whole)
            }
            5 => {
                // A link takes `lchown` only (its mode and times are not the volume's to keep).
                if job.op != ChangeOp::Chown || trailing {
                    return fail(proto_fs::NOT_SUPPORTED);
                }
                let mut plan = Self::attr_plan(c, job, 0, Kind::Link, &attr, ls.ino)?;
                plan.fresh = true;
                plan.link = true;
                job.attr = plan;
                job.copy_stat = ls;
                job.committed = true;
                job.phase = Phase::LowerLink;
                Ok(None)
            }
            _ => fail(proto_fs::NOT_SUPPORTED),
        }
    }

    /// The text of the lower link is in the second path: the link is made in the layer.
    fn step_lower_link(
        &mut self,
        _c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
    ) -> F<Option<Done<V::Pass>>> {
        let Some(probe) = job.lprobe.as_mut() else {
            let path = &job.a.plain[..job.a.parts.len];
            match self.lower.readlink_start(path) {
                Ok(link) => job.lprobe = Some(link),
                // No place for a job of the RAM file service: asked again in the next step.
                Err(Status::Unknown(proto_fs::TOO_MANY_OPEN_FILES)) => {}
                Err(e) => return Err(e.into()),
            }
            return Ok(None);
        };
        let mut text = [0u8; 512];
        match self.lower.readlink_poll(probe, &mut text) {
            Ok(None) => Ok(None),
            Ok(Some(len)) => {
                job.lprobe = None;
                let at = job.first.1;
                if len == 0 || at + len > job.req.len() {
                    return fail(proto_fs::NAME_TOO_LONG);
                }
                job.req[at..at + len].copy_from_slice(&text[..len]);
                job.second = (at, at + len);
                let ls = job.copy_stat;
                job.push(Stage::Ensure { b: false });
                job.push(Stage::File {
                    kind: Kind::Link,
                    // The file of a link is 0644 on the volume; `stat` reports 0777.
                    created: Created {
                        uid: ls.uid,
                        gid: ls.gid,
                        mode: 0o644,
                    },
                    lower: Some(ls.ino),
                });
                job.push(Stage::Attr);
                job.pc = 0;
                job.dsub = 0;
                job.phase = Phase::Commit;
                Ok(None)
            }
            Err(e) => {
                job.lprobe = None;
                Err(Stop::Status(e))
            }
        }
    }

    /// The copy up of the lower file at the leaf of the first leg: the ticket of the copy that is
    /// in work, or the directories of the path made in the layer and a place in the table. The
    /// answer is COPYING (`finish_ok`), and the lock goes with it: the bytes move outside the
    /// loop.
    fn plan_copy(
        &mut self,
        job: &mut ChangeJob<V, L>,
        ls: LowerStat,
        kind: crate::copy::Kind,
    ) -> F<Option<Done<V::Pass>>> {
        // The names the layer would make must fit the volume.
        let mut vp = [0u8; 512];
        self.leg_vpath(&job.a, job.a.parts.len, false, &mut vp)?;
        self.number_kept(&ls)?;
        let found = self.copies.find(&job.a.plain[..job.a.parts.len]);
        if let Some(ticket) = found {
            job.ticket = ticket;
            job.nstages = 0;
        } else {
            if !self.copies.room() {
                return fail(proto_layer::STARTING);
            }
            job.copy_kind = kind;
            job.copy_stat = ls;
            // The directories of the path are not made here: the commit makes them with the copy,
            // so a copy that is refused (a program) leaves no directory in the layer.
            job.push(Stage::CopyReserve);
        }
        Self::begin_commit(job);
        Ok(None)
    }

    /// The number of a lower name is kept by its copy, so it must be one the layer's own numbers
    /// (bit 62) and the numbers of the volume's paths (bit 63) cannot be: a lower number with either
    /// bit set is INVALID_ARGUMENT, before anything is made. (A number kept can still equal that of
    /// another lower file after an image or package change: a matter for a later part.)
    fn number_kept(&self, ls: &LowerStat) -> F<()> {
        if ls.ino & (proto_data::INO_NUMBERED | proto_data::INO_PATH) != 0 {
            return fail(proto_fs::INVALID_ARGUMENT);
        }
        Ok(())
    }
}

impl<V: Volume, L: Lower> Core<'_, V, L> {
    // ------------------------------------------------------------------ the copies the worker ended

    /// The next copy the worker ended becomes the work of the commit job `job` (with the place
    /// `id` of the lock). A copy whose job cannot start is over at once with an I/O error and its
    /// file goes to the reaper: its ticket is given back, for the waiters to be told.
    pub fn commit_start(&mut self, job: &mut ChangeJob<V, L>, id: u8) -> CommitStart {
        let Some((place, generation)) = self.copies.finished() else {
            return CommitStart::None;
        };
        let mut path = [0u8; crate::copy::PATH];
        let (len, made) = match self.copies.facts(place, generation) {
            Some((p, _, _, made)) => {
                path[..p.len()].copy_from_slice(p);
                (p.len(), made)
            }
            None => return CommitStart::None,
        };
        if job
            .start_commit(id, place, generation, &path[..len])
            .is_err()
        {
            if made {
                let (work, wl) = crate::copy::work_path(place, generation);
                let _ = self.work.push(&work[..wl], false, 0);
            }
            self.copies.over(place, generation, proto_layer::IO, true);
            return CommitStart::Failed(crate::copy::ticket_of(place, generation));
        }
        CommitStart::Job
    }

    /// The commit job is over, whatever it came to: the copy is made visible or it is not, and a
    /// file in `work/` that nobody took is the reaper's. `failed` is the code of the job's own
    /// failure, which the waiters get when the worker had none. The waiters are answered from the
    /// table.
    pub fn commit_done(&mut self, job: &mut ChangeJob<V, L>, failed: Option<u32>) {
        let Some((place, generation)) = job.commit_of.take() else {
            return;
        };
        let Some((_, _, worker, made)) = self.copies.facts(place, generation) else {
            return;
        };
        if !job.copy_visible && !job.dropped && made {
            let (work, wl) = crate::copy::work_path(place, generation);
            let _ = self.work.push(&work[..wl], false, 0);
        }
        let code = [worker, job.copy_code, failed.unwrap_or(0)]
            .into_iter()
            .find(|&c| c != 0)
            .unwrap_or(0);
        self.copies.over(place, generation, code, !job.copy_visible);
    }

    /// The code the waiters of the commit job's copy get: the outcome the table keeps.
    pub fn copy_wait(&self, ticket: u64) -> crate::copy::Wait {
        self.copies.wait(ticket)
    }
}

impl<V: Volume, L: Lower> Core<'_, V, L> {
    // ------------------------------------------------------------------ the commit

    fn finish_ok(&mut self, job: &mut ChangeJob<V, L>, w: &mut Writer) -> F<Option<Done<V::Pass>>> {
        if job.ticket != 0 {
            // The file is copied up outside the loop: the program waits for the ticket and asks
            // again.
            n::write_copying(job.ticket, w)?;
            return Ok(Some(Done::Written));
        }
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
            match self.stage(c, job, stage)? {
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
                    // The mark of the index goes in with the call that made the removal visible, so
                    // a reader never sees the lower name in between.
                    while let Some(stage @ Stage::IndexMark { .. }) =
                        job.stages.get(job.pc).copied()
                        && job.pc < job.nstages
                    {
                        self.stage(c, job, stage)?;
                        job.pc += 1;
                    }
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

    fn stage(&mut self, c: &Client<'_>, job: &mut ChangeJob<V, L>, stage: Stage) -> F<Flow> {
        match stage {
            Stage::Ensure { b } => self.stage_ensure(job, b),
            Stage::Dir {
                b,
                opaque,
                created,
                lower,
            } => {
                let parent = if b { job.dir_b } else { job.dir_a };
                let (at, len) = {
                    let leg = job.leg(b);
                    (leg.parts.leaf_at, leg.parts.len)
                };
                job.dir_times = lower.map(|_| job.leaf_times);
                match self.dir_step(job, b, parent, (at, len), len, (created, lower), opaque)? {
                    Some(_) => Ok(Flow::CallDone),
                    None => Ok(Flow::Call),
                }
            }
            Stage::File {
                kind,
                created,
                lower,
            } => self.stage_file(job, kind, created, lower),
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
                self.table.forget(id, |key| self.index.walk_leave(key));
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
            Stage::OpenFile { check } => self.stage_open_file(c, job, check),
            Stage::Attr => self.stage_attr(job),
            Stage::CopyReserve => self.stage_copy_reserve(job),
            Stage::CopyIn => self.stage_copy_in(job),
            Stage::CopyDrop => self.stage_copy_drop(job),
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
            // The stat goes on over steps: the stage stays at this sub until it is answered.
            let ls = {
                let plain = &(if b { &job.b } else { &job.a }).plain[..end];
                match self.lower_stat(&mut job.probe, plain)? {
                    None => return Ok(Flow::Call),
                    Some(Some(s)) if s.kind == 1 => s,
                    Some(Some(_)) => return fail(proto_fs::NOT_DIRECTORY),
                    // The directory of the walk is gone from the lower set.
                    Some(None) => return fail(proto_fs::NO_ENTRY),
                }
            };
            job.ens_created = Created {
                uid: ls.uid,
                gid: ls.gid,
                mode: ls.mode & 0o7777,
            };
            // The directory of the layer keeps the number of the lower one.
            self.number_kept(&ls)?;
            job.ens_ino = ls.ino;
            job.ens_times = (ls.atime, ls.mtime);
            job.sub = 2;
            return Ok(Flow::Call);
        }
        let (cur, created, lower) = (job.ens_cur, job.ens_created, job.ens_ino);
        job.dir_times = Some(job.ens_times);
        match self.dir_step(job, b, cur, (pos, end), end, (created, Some(lower)), false)? {
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
        made: (Created, Option<u64>),
        opaque: bool,
    ) -> F<Option<u32>> {
        let (Created { uid, gid, mode }, lower) = made;
        // The deliberate break `break-layerd-copy-counter-ino`: a directory of a copy takes a
        // number of the counter and loses the lower one.
        let lower = lower.filter(|_| !cfg!(feature = "break-layerd-copy-counter-ino"));
        match job.dsub {
            0 => {
                let mut live = [0u8; 512];
                self.leg_vpath(job.leg(b), end, false, &mut live)?;
                if let Some(code) = self.no_room(parent, &job.leg(b).plain[name.0..name.1]) {
                    return fail(code);
                }
                job.dsub = 8;
                Ok(None)
            }
            // The number: the lower directory's when this is the copy of one, else the next of the
            // counter (so no two names of the root share a number: the numbers of the data file
            // service's counter and those of the RAM file service meet).
            8 => {
                let ino = match lower {
                    Some(ino) => ino,
                    None => match self.next_number(job)? {
                        Some(ino) => ino,
                        None => return Ok(None),
                    },
                };
                job.ino = ino;
                let (num, work, wl) = self.work_path();
                job.work = num;
                self.volume
                    .mkdir_numbered(&work[..wl], 0o700, ino)
                    .map_err(from_volume)?;
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
                job.dsub = if job.dir_times.is_some() { 9 } else { 6 };
                Ok(None)
            }
            // The times of the lower directory a copy of one keeps.
            9 => {
                let (work, wl) = Self::work_path_of(job.work);
                let (atime, mtime) = job.dir_times.unwrap_or((d::UTIME_OMIT, d::UTIME_OMIT));
                if let Err(e) = self.volume.utimens(&work[..wl], atime, mtime) {
                    return Err(self.scrub_fail(job, true, e));
                }
                job.dsub = 6;
                Ok(None)
            }
            7 => {
                let (work, wl) = Self::work_path_of(job.work);
                let mut live = [0u8; 512];
                let n = self.leg_vpath(job.leg(b), end, false, &mut live)?;
                let item = if self.volume.rename(&live[..n], &work[..wl]).is_ok() {
                    &work[..wl]
                } else {
                    &live[..n]
                };
                let _ = self.work.push(item, true, 0);
                fail(proto_fs::NO_SPACE)
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
                        // The directory goes back into `work/` in the next step, then the
                        // reaper has it.
                        job.dsub = 7;
                        Ok(None)
                    }
                }
            }
        }
    }

    /// The next number of a name the service makes, `UPPER_INO_TAG | n` of the counter of
    /// COMPOSITION, which is written back, in steps, when its block is used up. None while the
    /// write goes on (a call was made; the stage asks again in its next step).
    fn next_number(&mut self, job: &mut ChangeJob<V, L>) -> F<Option<u64>> {
        loop {
            match job.csub {
                0 => {
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
                        job.csub = 20;
                    } else {
                        let ino = UPPER_INO_TAG | self.writes.ino_next;
                        self.writes.ino_next += 1;
                        return Ok(Some(ino));
                    }
                }
                20 => {
                    job.handle = self
                        .volume
                        .open(COMPOSITION_TMP, d::WRITE | d::CREATE | d::TRUNCATE, 0o600)
                        .map_err(from_volume)?;
                    job.written = 0;
                    job.err = None;
                    job.csub = 21;
                    return Ok(None);
                }
                21 => {
                    match self
                        .volume
                        .write(job.handle, &job.ctext[job.written..job.clen])
                    {
                        Ok(0) => {
                            job.err = Some(st(d::NO_SPACE));
                            job.csub = 23;
                        }
                        Ok(k) => {
                            job.written += k;
                            if job.written >= job.clen {
                                job.csub = 22;
                            }
                        }
                        Err(e) => {
                            job.err = Some(e);
                            job.csub = 23;
                        }
                    }
                    return Ok(None);
                }
                22 => {
                    if let Err(e) = self.volume.fsync(job.handle) {
                        job.err = Some(e);
                    }
                    job.csub = 23;
                    return Ok(None);
                }
                23 => {
                    let closed = self.volume.close(job.handle);
                    if let Some(e) = job.err.take() {
                        job.csub = 0;
                        return Err(Stop::Status(from_volume(e)));
                    }
                    closed.map_err(from_volume)?;
                    job.csub = 24;
                    return Ok(None);
                }
                _ => {
                    self.volume
                        .rename(COMPOSITION_TMP, COMPOSITION)
                        .map_err(from_volume)?;
                    if let Some(next) = job.cnext.take() {
                        self.writes.ino_limit = next.ino;
                        self.composition = next;
                    }
                    job.csub = 0;
                    return Ok(None);
                }
            }
        }
    }

    /// A file or a link at the leaf of the first leg, with the text of a link for its bytes,
    /// prepared in `work/`: the number from the counter of COMPOSITION (written back, in steps, when
    /// its block is used up), the file, its bytes, its owner and mode, the rename.
    fn stage_file(
        &mut self,
        job: &mut ChangeJob<V, L>,
        kind: Kind,
        created: Created,
        lower: Option<u64>,
    ) -> F<Flow> {
        let link = kind == Kind::Link;
        let parent = job.dir_a;
        let Created { uid, gid, mode } = created;
        let (text_from, text_to) = if link { job.second } else { (0, 0) };
        loop {
            match job.dsub {
                0 => {
                    let mut live = [0u8; 512];
                    self.leg_vpath(&job.a, job.a.parts.len, link, &mut live)?;
                    if let Some(code) = self.no_room(parent, job.a.leaf_name()) {
                        return fail(code);
                    }
                    job.dsub = 25;
                }
                // The number: the lower link's when this is the copy of one, else the next of the
                // counter.
                25 => {
                    job.ino = match lower {
                        Some(ino) => ino,
                        None => match self.next_number(job)? {
                            Some(ino) => ino,
                            None => return Ok(Flow::Call),
                        },
                    };
                    job.dsub = 1;
                }
                1 => {
                    let ino = job.ino;
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
                30 => {
                    let (work, wl) = Self::work_path_of(job.work);
                    let mut live = [0u8; 512];
                    let n = self.leg_vpath(&job.a, job.a.parts.len, link, &mut live)?;
                    let item = if self.volume.rename(&live[..n], &work[..wl]).is_ok() {
                        &work[..wl]
                    } else {
                        &live[..n]
                    };
                    let _ = self.work.push(item, false, 0);
                    return fail(proto_fs::NO_SPACE);
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
                            job.dsub = 30;
                            Ok(Flow::Call)
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
                if let Some(code) = self.no_room(job.dir_of(dir), job.leg(b).leaf_name()) {
                    return fail(code);
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
            self.table.forget(id, |key| self.index.walk_leave(key));
            let _ = self.work.push(&work[..wl], true, key);
        } else {
            self.volume
                .rename(&old[..on], &new[..nn])
                .map_err(from_volume)?;
            if let Some((id, kind)) = dst_up {
                if src_link && kind != Kind::Link {
                    // A link over a file: the file goes in the same step (the second call), so
                    // the target is never missing; a cut between the calls leaves both, and the
                    // scan lets the file win, which is the target before the rename.
                    let mut file = [0u8; 512];
                    let fnn = self.leg_vpath(&job.b, job.b.parts.len, false, &mut file)?;
                    self.volume.unlink(&file[..fnn]).map_err(from_volume)?;
                }
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
    fn stage_open_file(
        &mut self,
        c: &Client<'_>,
        job: &mut ChangeJob<V, L>,
        check: bool,
    ) -> F<Flow> {
        match job.dsub {
            0 if check => {
                // A file that was there: the rights of the open are read from the volume.
                let mut path = [0u8; 512];
                let n = self.leg_vpath(&job.a, job.a.parts.len, false, &mut path)?;
                self.open_rights(c, &path[..n], job.flags)?;
                job.dsub = 10;
                Ok(Flow::Call)
            }
            0 | 10 => {
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

    /// The code a change fails with when the index has no room for `name` in `parent`: NO_SPACE,
    /// or STARTING when the arena has room once its compaction ran (the client asks again).
    fn no_room(&mut self, parent: u32, name: &[u8]) -> Option<u32> {
        match self.index.room(parent, name) {
            Room::Yes => None,
            Room::Later => Some(proto_layer::STARTING),
            Room::No => Some(proto_fs::NO_SPACE),
        }
    }

    /// The copy of the lower file at the leaf of the first leg is queued; its ticket is the answer.
    fn stage_copy_reserve(&mut self, job: &mut ChangeJob<V, L>) -> F<Flow> {
        let path = &job.a.plain[..job.a.parts.len];
        let Some(ticket) = self.copies.reserve(path, job.copy_kind, job.copy_stat) else {
            return fail(proto_layer::STARTING);
        };
        job.ticket = ticket;
        Ok(Flow::Pure)
    }

    /// The copy of `commit_of` is renamed from `work/` into the layer and entered in the index in
    /// one step (the visible one): the directory of the layer is the one the walk found.
    fn stage_copy_in(&mut self, job: &mut ChangeJob<V, L>) -> F<Flow> {
        let Some((place, generation)) = job.commit_of else {
            return fail(proto_fs::INVALID_ARGUMENT);
        };
        let Some((_, stat, _, _)) = self.copies.facts(place, generation) else {
            return fail(proto_fs::INVALID_ARGUMENT);
        };
        let (work, wl) = crate::copy::work_path(place, generation);
        let mut live = [0u8; 512];
        let n = self.leg_vpath(&job.a, job.a.parts.len, false, &mut live)?;
        let parent = job.dir_a;
        if let Some(code) = self.no_room(parent, job.a.leaf_name()) {
            // The arena is waiting for its compaction: the copy is dropped quietly, the waiters
            // ask again and find the name as it is then.
            let code = if code == proto_layer::STARTING {
                0
            } else {
                code
            };
            return self.copy_gone(job, code);
        }
        if let Err(e) = self.volume.rename(&work[..wl], &live[..n]) {
            return self.copy_gone(job, from_volume_code(e));
        }
        let fields = Fields {
            kind: Kind::File,
            layer: self.composition.live().number,
            number: stat.ino,
            uid: stat.uid,
            gid: stat.gid,
            mode: (stat.mode & 0o7777) as u16,
        };
        if self
            .index
            .insert(parent, job.a.leaf_name(), fields)
            .is_err()
        {
            // Out of room in the index after all: the file goes back into `work/` and the reaper has it.
            let item = if self.volume.rename(&live[..n], &work[..wl]).is_ok() {
                &work[..wl]
            } else {
                &live[..n]
            };
            let _ = self.work.push(item, false, 0);
            return self.copy_gone(job, proto_fs::NO_SPACE);
        }
        job.copy_visible = true;
        Ok(Flow::CallDone)
    }

    /// A copy that cannot be made visible: the file in `work/` is the reaper's, and the waiters
    /// are answered with `code` (0 when the name changed under the copy: they ask again and see
    /// the present state).
    fn copy_gone(&mut self, job: &mut ChangeJob<V, L>, code: u32) -> F<Flow> {
        job.copy_code = code;
        self.stage_copy_drop(job)
    }

    fn stage_copy_drop(&mut self, job: &mut ChangeJob<V, L>) -> F<Flow> {
        let Some((place, generation)) = job.commit_of else {
            return fail(proto_fs::INVALID_ARGUMENT);
        };
        let made = self
            .copies
            .facts(place, generation)
            .is_some_and(|(_, _, _, made)| made);
        if made {
            let (work, wl) = crate::copy::work_path(place, generation);
            let _ = self.work.push(&work[..wl], false, 0);
        }
        job.dropped = true;
        // The stages that follow are of no use.
        job.nstages = job.pc + 1;
        Ok(Flow::Pure)
    }

    /// `chmod`, `chown`, `utimensat` and `truncate` of the name the walk found.
    fn stage_attr(&mut self, job: &mut ChangeJob<V, L>) -> F<Flow> {
        if job.attr.fresh {
            // The entry was made by this job (the copy of a lower directory or link): its id is
            // the last one made, and its path on the volume is the first leg's.
            job.attr.fresh = false;
            job.attr.id = job.made;
            let mut vp = [0u8; 512];
            let len = self.leg_vpath(&job.a, job.a.parts.len, job.attr.link, &mut vp)?;
            job.b.plain[..len].copy_from_slice(&vp[..len]);
            job.b.len = len;
        }
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
