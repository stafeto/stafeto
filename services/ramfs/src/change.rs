// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The change jobs: one keyed, paid job for each operation on names and
//! metadata. The journals of the model (`namespace`, `create`, `metadata`,
//! `getcwd`) do the work; this module captures a request, walks its paths a
//! portion at a time, drives the journal through its phases, keeps the one
//! outcome until the client releases the key, and answers the five methods.
//!
//! A step is one portion: a component of a path, a link, eight names of a
//! directory, one reservation, or the publication of the effect. Every
//! refusal is found and paid before the publication, so an error leaves no
//! effect. A change of the tree between two steps (STALE_PROOF) never
//! reaches the client: the job starts its paths again and counts a restart.

use crate::authority::{Identity, Stamp};
use crate::cwd::{GetcwdJournal, GetcwdOutcome};
use crate::job::{JobGenerations, JobOperation, JobTable, ResolveJob, Seconds};
use crate::metadata::{MetadataIntent, MetadataJournal, MetadataOutcome, TimeSetting};
use crate::namespace::{
    CreateJournal, NamespaceIntent, NamespaceOutcome, NamespacePath, Preparation, ReadLinkJournal,
};
use crate::resolve::{Intent, Progress, Resolve};
use crate::storage::{NONE, ROOT, Token};
use crate::{DIR, Fds, Ram};
use proto_fs::{
    ACCESS_EFFECTIVE, BAD_FD, Base, ChangeOp, ChangePhase, ChangeReply, ChangeSecond, ChangeStart,
    ID_UNCHANGED, INVALID_ARGUMENT, JOBS_FULL, LINK_FOLLOW, NO_ENTRY, NOFOLLOW, NOT_DIRECTORY,
    OPEN_RETIRED, OpenKey, PATH_FOLLOW_LAST, PATH_REQUIRE_DIR, PERMISSION, STALE_PROOF, TIME_NOW,
    TIME_OMIT, TOO_MANY_OPEN_FILES, Timestamp, UNLINK_REMOVEDIR,
};
use proto_wire::{Status, Writer};

/// The places for second paths and link contents.
pub const SECONDS: usize = 32;

/// The source of calendar time. `None` is an unstable snapshot: the step
/// makes no effect and the client asks again.
pub trait Clock {
    fn read_once(&self) -> Result<Option<Timestamp>, Status>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Resolve,
    Build,
    Prepare,
    Ready,
    Done,
}

#[allow(clippy::large_enum_variant)]
enum Work {
    None,
    Namespace(Preparation),
    Create(CreateJournal),
    ReadLink(ReadLinkJournal),
    Metadata(MetadataJournal),
    Path(GetcwdJournal),
}

enum Stop {
    /// The operation fails; nothing has happened.
    Fail(u32),
    /// The tree changed under the job: start the paths again.
    Stale,
    /// The request itself is wrong.
    Protocol(u32),
}
impl From<u32> for Stop {
    fn from(code: u32) -> Self {
        if code == STALE_PROOF {
            Stop::Stale
        } else {
            Stop::Fail(code)
        }
    }
}

pub struct ChangeJob {
    op: ChangeOp,
    flags: u32,
    base: Base,
    args: [u64; 4],
    second_base: Option<Base>,
    /// The first path, or the empty path of an operation on a descriptor.
    /// Its working buffer carries the bytes of a result once the job is done.
    first: Resolve,
    /// The place in `Seconds` of a two-path operation.
    second_place: Option<u8>,
    stage: Stage,
    work: Work,
    result: u32,
    /// The bytes of a result in the buffer of `first`.
    length: u16,
    restarts: u32,
    /// The restarts the resolvers have made, as far as they are counted.
    seen: u32,
}

fn first_intent(op: ChangeOp, flags: u32) -> Intent {
    match op {
        ChangeOp::Unlink | ChangeOp::Rename => Intent::Namespace {
            path: NamespacePath::Victim,
        },
        ChangeOp::Mkdir => Intent::DirectoryCreate,
        ChangeOp::Symlink => Intent::SymbolicLinkCreate,
        ChangeOp::Link => Intent::Namespace {
            path: NamespacePath::LinkSource {
                follow: flags & LINK_FOLLOW != 0,
            },
        },
        ChangeOp::ReadLink => Intent::Lookup { follow: false },
        ChangeOp::Chmod | ChangeOp::Chown | ChangeOp::Times => Intent::Metadata {
            path: crate::metadata::MetadataPath {
                follow: flags & NOFOLLOW == 0,
                real: false,
            },
        },
        ChangeOp::Access => Intent::Metadata {
            path: crate::metadata::MetadataPath {
                follow: true,
                real: flags & ACCESS_EFFECTIVE == 0,
            },
        },
        ChangeOp::StatVfs => Intent::Lookup { follow: true },
        ChangeOp::Path => Intent::Lookup {
            follow: flags & (PATH_REQUIRE_DIR | PATH_FOLLOW_LAST) != 0,
        },
    }
}

/// Whether the operation reads the real identity of the caller.
pub fn uses_real_identity(op: ChangeOp, flags: u32) -> bool {
    op == ChangeOp::Access && flags & ACCESS_EFFECTIVE == 0
}

/// The node a base stands for when the path is relative (or empty).
fn anchor(ram: &Ram<'_>, fds: &Fds, base: Base, relative: bool) -> Result<Token, u32> {
    if !relative {
        return Ok(ROOT);
    }
    match base {
        // The current directory is not held by the service yet.
        Base::Absolute | Base::Cwd => Err(BAD_FD),
        Base::Fd { fd, generation } => ram.description_node(fds, fd, generation),
    }
}

fn timestamp(seconds: u64, nanos: u64) -> TimeSetting {
    match nanos {
        TIME_NOW => TimeSetting::Now,
        TIME_OMIT => TimeSetting::Omit,
        _ => TimeSetting::Exact(
            Timestamp::new(seconds as i64, nanos as u32).expect("validated nanoseconds"),
        ),
    }
}

impl ChangeJob {
    /// Captures the request. A wrong base (BAD_FD) is not an error of the
    /// request: the job is born done with that result and no effect.
    pub fn capture(
        ram: &mut Ram<'_>,
        fds: &Fds,
        identity: Identity,
        req: &ChangeStart<'_>,
        second_place: Option<u8>,
    ) -> Result<Self, u32> {
        let relative = req.path.first() != Some(&b'/');
        let (first, stage, result) = match anchor(ram, fds, req.base, relative) {
            Ok(token) if !req.path.is_empty() => (
                Resolve::with_intent(
                    &mut ram.storage,
                    req.path,
                    token,
                    identity,
                    first_intent(req.op, req.flags),
                )?,
                Stage::Resolve,
                0,
            ),
            Ok(_) => (Resolve::scratch(&mut ram.storage, b"")?, Stage::Resolve, 0),
            Err(code) => {
                // The bytes stay so that a repeated Start compares equal.
                let mut kept = Resolve::scratch(&mut ram.storage, req.path)?;
                kept.retire(&mut ram.storage);
                (kept, Stage::Done, code)
            }
        };
        Ok(Self {
            op: req.op,
            flags: req.flags,
            base: req.base,
            args: req.args,
            second_base: None,
            first,
            second_place,
            stage,
            work: Work::None,
            result,
            length: 0,
            restarts: 0,
            seen: 0,
        })
    }

    pub fn phase(&self) -> ChangePhase {
        if self.stage == Stage::Done {
            return ChangePhase::Done;
        }
        if self.op.needs_second() && self.second_base.is_none() {
            return ChangePhase::AwaitingSecond;
        }
        match self.stage {
            Stage::Resolve => ChangePhase::Resolving,
            Stage::Build | Stage::Prepare => ChangePhase::Preparing,
            _ => ChangePhase::Ready,
        }
    }

    pub fn is_done(&self) -> bool {
        self.stage == Stage::Done
    }

    /// The same arguments as a request that came before.
    fn same_start(&self, req: &ChangeStart<'_>) -> bool {
        self.op == req.op
            && self.flags == req.flags
            && self.base == req.base
            && self.args == req.args
            && self.first.original_path() == req.path
    }

    pub fn second_place(&self) -> Option<usize> {
        self.second_place.map(usize::from)
    }

    /// A new authority generation or a changed identity: the paths are walked again.
    pub fn invalidate(&mut self, second: Option<&mut Resolve>) {
        self.first.invalidate();
        if let Some(second) = second {
            second.invalidate();
        }
    }

    /// The second path, or the contents of the link. The first call stores
    /// it; a repeat with the same bytes is answered 0 in every phase.
    pub fn second(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &Fds,
        identity: Identity,
        slot: Option<&mut Option<Resolve>>,
        req: &ChangeSecond<'_>,
    ) -> Result<(), u32> {
        req.validate_for(self.op).map_err(|e| e.code())?;
        let slot = slot.ok_or(INVALID_ARGUMENT)?;
        if let Some(base) = self.second_base {
            let same = slot
                .as_ref()
                .is_some_and(|second| second.original_path() == req.bytes)
                && base == req.base;
            return if same { Ok(()) } else { Err(PERMISSION) };
        }
        if req.bytes.contains(&0) {
            return Err(INVALID_ARGUMENT);
        }
        if self.op == ChangeOp::Symlink {
            *slot = Some(Resolve::scratch(&mut ram.storage, req.bytes)?);
        } else {
            let relative = req.bytes.first() != Some(&b'/');
            let made = anchor(ram, fds, req.base, relative).and_then(|token| {
                Resolve::with_intent(
                    &mut ram.storage,
                    req.bytes,
                    token,
                    identity,
                    Intent::Namespace {
                        path: NamespacePath::Destination,
                    },
                )
            });
            match made {
                Ok(second) => *slot = Some(second),
                Err(code) if code == BAD_FD => {
                    // The job ends with that result; the bytes stay for a repeat.
                    *slot = Some(Resolve::scratch(&mut ram.storage, req.bytes)?);
                    self.second_base = Some(req.base);
                    let mut none = 0;
                    self.fail(ram, &mut none, slot.as_mut(), code);
                    return Ok(());
                }
                Err(code) => return Err(code),
            }
        }
        self.second_base = Some(req.base);
        Ok(())
    }

    fn resolver_restarts(&self, second: Option<&Resolve>) -> u32 {
        self.first
            .restarts
            .saturating_add(second.map_or(0, |second| second.restarts))
    }

    /// One portion of work. `Err` is a protocol error: the step did not run.
    #[allow(clippy::too_many_arguments)]
    pub fn step(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &Fds,
        identity: Identity,
        charge: &mut u16,
        mut second: Option<&mut Resolve>,
        clock: &dyn Clock,
    ) -> Result<(), u32> {
        if self.op.needs_second() && self.second_base.is_none() {
            return Err(INVALID_ARGUMENT);
        }
        if self.stage == Stage::Done {
            return Ok(());
        }
        let outcome = self.advance(ram, fds, identity, charge, second.as_deref_mut(), clock);
        let now = self.resolver_restarts(second.as_deref());
        if now > self.seen {
            self.seen = now;
            self.restarts = self.restarts.saturating_add(1);
        }
        match outcome {
            Ok(()) => Ok(()),
            Err(Stop::Fail(code)) => {
                self.fail(ram, charge, second, code);
                Ok(())
            }
            Err(Stop::Stale) => {
                self.restart(ram, charge, identity, second);
                Ok(())
            }
            Err(Stop::Protocol(code)) => Err(code),
        }
    }

    /// The job starts its paths again; the resources of the journal go back.
    fn restart(
        &mut self,
        ram: &mut Ram<'_>,
        charge: &mut u16,
        identity: Identity,
        second: Option<&mut Resolve>,
    ) {
        self.cancel_work(ram, charge);
        let _ = self.first.rewind(&mut ram.storage, identity);
        if let Some(second) = second {
            let _ = second.rewind(&mut ram.storage, identity);
            self.seen = self.resolver_restarts(Some(second));
        } else {
            self.seen = self.resolver_restarts(None);
        }
        self.stage = Stage::Resolve;
        self.restarts = self.restarts.saturating_add(1);
    }

    fn advance(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &Fds,
        identity: Identity,
        charge: &mut u16,
        mut second: Option<&mut Resolve>,
        clock: &dyn Clock,
    ) -> Result<(), Stop> {
        match self.stage {
            Stage::Resolve => {
                if !self.first.is_inert() {
                    match self.first.step(&mut ram.storage, identity)? {
                        Progress::More => return Ok(()),
                        Progress::Found(_) | Progress::Missing(_) => {}
                    }
                }
                if let Some(second) = second.as_deref_mut()
                    && !second.is_inert()
                {
                    match second.step(&mut ram.storage, identity)? {
                        Progress::More => return Ok(()),
                        Progress::Found(_) | Progress::Missing(_) => {}
                    }
                }
                self.stage = Stage::Build;
                Ok(())
            }
            Stage::Build => self.build(ram, fds, identity, charge, second),
            Stage::Prepare => self.prepare(ram, fds, identity, charge, second),
            Stage::Ready => self.commit(ram, fds, identity, charge, second, clock),
            Stage::Done => Ok(()),
        }
    }

    fn fd_base(&self) -> Option<(u32, u64)> {
        match self.base {
            Base::Fd { fd, generation } => Some((fd, generation)),
            _ => None,
        }
    }

    fn metadata_intent(&self) -> MetadataIntent {
        let a = self.args;
        match self.op {
            ChangeOp::Chmod => MetadataIntent::Chmod(a[0] as u32),
            ChangeOp::Chown => MetadataIntent::Chown {
                uid: (a[0] != ID_UNCHANGED).then_some(a[0] as u32),
                gid: (a[1] != ID_UNCHANGED).then_some(a[1] as u32),
            },
            ChangeOp::Times => {
                MetadataIntent::Times([timestamp(a[0], a[1]), timestamp(a[2], a[3])])
            }
            _ => MetadataIntent::Access {
                bits: a[0] as u32,
                real: self.flags & ACCESS_EFFECTIVE == 0,
            },
        }
    }

    fn build(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &Fds,
        identity: Identity,
        charge: &mut u16,
        second: Option<&mut Resolve>,
    ) -> Result<(), Stop> {
        let root = fds.root;
        match self.op {
            ChangeOp::Unlink | ChangeOp::Rename | ChangeOp::Link => {
                let (intent, role) = match self.op {
                    ChangeOp::Unlink if self.flags & UNLINK_REMOVEDIR != 0 => {
                        (NamespaceIntent::Rmdir, NamespacePath::Victim)
                    }
                    ChangeOp::Unlink => (NamespaceIntent::Unlink, NamespacePath::Victim),
                    ChangeOp::Rename => (NamespaceIntent::Rename, NamespacePath::Victim),
                    _ => {
                        let follow = self.flags & LINK_FOLLOW != 0;
                        (
                            NamespaceIntent::Link {
                                follow_source: follow,
                            },
                            NamespacePath::LinkSource { follow },
                        )
                    }
                };
                let source = self.first.namespace_proof(&ram.storage, identity, role)?;
                let destination = match second.as_deref() {
                    Some(second) => Some(second.namespace_proof(
                        &ram.storage,
                        identity,
                        NamespacePath::Destination,
                    )?),
                    None => None,
                };
                let prep = ram.storage.prepare_namespace_paid(
                    root,
                    *charge,
                    intent,
                    source,
                    destination,
                    identity,
                )?;
                self.work = Work::Namespace(prep);
                self.stage = Stage::Prepare;
            }
            ChangeOp::Mkdir => {
                self.work = Work::Create(CreateJournal::directory(
                    self.args[0] as u32,
                    self.args[1] as u32,
                ));
                self.stage = Stage::Prepare;
            }
            ChangeOp::Symlink => {
                let content = second.as_deref().ok_or(INVALID_ARGUMENT)?.original_path();
                self.work = Work::Create(CreateJournal::symlink(content)?);
                self.stage = Stage::Prepare;
            }
            ChangeOp::ReadLink => {
                self.work = Work::ReadLink(ReadLinkJournal::new(self.args[0] as usize));
                self.stage = Stage::Ready;
            }
            ChangeOp::Chmod | ChangeOp::Chown | ChangeOp::Times | ChangeOp::Access => {
                let intent = self.metadata_intent();
                let journal = if let Some((fd, generation)) = self.fd_base()
                    && self.first.original_path().is_empty()
                {
                    ram.description_node(fds, fd, generation)?;
                    ram.prepare_metadata(fds, fd, *charge, identity, intent)?
                } else {
                    let path = match first_intent(self.op, self.flags) {
                        Intent::Metadata { path } => path,
                        _ => unreachable!("metadata intent"),
                    };
                    let proof = self.first.metadata_proof(&ram.storage, identity, path)?;
                    MetadataJournal::path(&mut ram.storage, root, *charge, proof, identity, intent)?
                };
                self.work = Work::Metadata(journal);
                self.stage = Stage::Ready;
            }
            ChangeOp::StatVfs => {
                if let Some((fd, generation)) = self.fd_base()
                    && self.first.original_path().is_empty()
                {
                    let token = ram.description_node(fds, fd, generation)?;
                    ram.storage.node(token)?;
                }
                self.stage = Stage::Ready;
            }
            ChangeOp::Path => {
                let require = self.flags & PATH_REQUIRE_DIR != 0;
                let follow = require || self.flags & PATH_FOLLOW_LAST != 0;
                let journal = if let Some((fd, generation)) = self.fd_base()
                    && self.first.original_path().is_empty()
                {
                    let token = ram.description_node(fds, fd, generation)?;
                    ram.prepare_path(root, *charge, identity, token, None, require)?
                } else {
                    let proof = self.first.result_proof(
                        &ram.storage,
                        identity,
                        Intent::Lookup { follow },
                    )?;
                    let target = proof.target.ok_or(NO_ENTRY)?;
                    if ram.storage.node(target)?.kind == DIR {
                        ram.prepare_path(root, *charge, identity, target, None, require)?
                    } else if require {
                        return Err(Stop::Fail(NOT_DIRECTORY));
                    } else {
                        ram.prepare_path(
                            root,
                            *charge,
                            identity,
                            proof.parent,
                            Some(proof.leaf),
                            false,
                        )?
                    }
                };
                self.work = Work::Path(journal);
                self.stage = Stage::Prepare;
            }
        }
        Ok(())
    }

    fn prepare(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &Fds,
        identity: Identity,
        charge: &mut u16,
        _second: Option<&mut Resolve>,
    ) -> Result<(), Stop> {
        let ready = match &mut self.work {
            Work::Namespace(prep) => prep.step(&mut ram.storage, identity)?,
            Work::Create(journal) => {
                let proof = self
                    .first
                    .namespace_proof(&ram.storage, identity, journal.role())?;
                journal.step_paid(&mut ram.storage, fds.root, charge, proof, identity)?
            }
            Work::Path(journal) => journal.step(&mut ram.storage, identity)?,
            _ => true,
        };
        if ready {
            self.stage = Stage::Ready;
        }
        Ok(())
    }

    fn needs_time(&self) -> bool {
        match &self.work {
            Work::Namespace(_) | Work::Create(_) | Work::ReadLink(_) => true,
            Work::Metadata(journal) => journal.needs_time(),
            _ => false,
        }
    }

    fn commit(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &Fds,
        identity: Identity,
        charge: &mut u16,
        second: Option<&mut Resolve>,
        clock: &dyn Clock,
    ) -> Result<(), Stop> {
        let now = if self.needs_time() {
            match clock.read_once() {
                Ok(Some(now)) => Some(now),
                // The snapshot is unstable: no effect, the client steps again.
                Ok(None) => return Ok(()),
                Err(status) => return Err(Stop::Protocol(status.code())),
            }
        } else {
            None
        };
        let root = fds.root;
        let result = match &mut self.work {
            Work::Namespace(prep) => {
                match prep.commit(&mut ram.storage, identity, now.expect("time was read"))? {
                    NamespaceOutcome::Applied | NamespaceOutcome::Unchanged => 0,
                    NamespaceOutcome::Failed(code) => code,
                }
            }
            Work::Create(journal) => {
                let proof = self
                    .first
                    .namespace_proof(&ram.storage, identity, journal.role())?;
                match journal.commit(
                    &mut ram.storage,
                    root,
                    charge,
                    Some(proof),
                    identity,
                    now.expect("time was read"),
                )? {
                    NamespaceOutcome::Applied | NamespaceOutcome::Unchanged => 0,
                    NamespaceOutcome::Failed(code) => code,
                }
            }
            Work::Metadata(journal) => {
                let proof = if self.first.original_path().is_empty() {
                    None
                } else {
                    let path = match first_intent(self.op, self.flags) {
                        Intent::Metadata { path } => path,
                        _ => unreachable!("metadata intent"),
                    };
                    Some(self.first.metadata_proof(&ram.storage, identity, path)?)
                };
                match journal.commit(ram, root, identity, proof, now)? {
                    MetadataOutcome::Applied | MetadataOutcome::Unchanged => 0,
                    MetadataOutcome::Failed(code) => code,
                }
            }
            Work::ReadLink(journal) => {
                let proof =
                    self.first
                        .namespace_proof(&ram.storage, identity, NamespacePath::ReadLink)?;
                let count = journal.capture(
                    &mut ram.storage,
                    Some(proof),
                    identity,
                    now.expect("time was read"),
                )?;
                let bytes = journal.result().expect("captured link");
                self.first.buffer()[..count].copy_from_slice(bytes);
                self.length = count as u16;
                0
            }
            Work::Path(journal) => match journal.outcome() {
                Some(GetcwdOutcome::Ready { .. }) => {
                    let bytes = journal.inline_bytes().ok_or(Stop::Fail(PERMISSION))?;
                    let count = bytes.len();
                    self.first.buffer()[..count].copy_from_slice(bytes);
                    self.length = count as u16;
                    0
                }
                Some(GetcwdOutcome::Failed(code)) => code,
                _ => return Err(Stop::Fail(PERMISSION)),
            },
            Work::None => {
                debug_assert_eq!(self.op, ChangeOp::StatVfs);
                let info = ram.storage.filesystem_information(root);
                let words = [
                    info.block_size,
                    info.fragment_size,
                    info.blocks,
                    info.free_blocks,
                    info.available_blocks,
                    info.files,
                    info.free_files,
                    info.available_files,
                    info.filesystem_id,
                    info.flags,
                    info.name_max,
                ];
                let buffer = self.first.buffer();
                for (i, word) in words.iter().enumerate() {
                    buffer[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
                }
                self.length = proto_fs::STATVFS_BYTES as u16;
                0
            }
        };
        self.finish(ram, charge, second, result);
        Ok(())
    }

    /// The journal goes back, the pins of the paths are released, and the
    /// outcome is all the job keeps.
    fn finish(
        &mut self,
        ram: &mut Ram<'_>,
        charge: &mut u16,
        second: Option<&mut Resolve>,
        result: u32,
    ) {
        if self.stage == Stage::Done {
            return;
        }
        self.cancel_work(ram, charge);
        self.first.retire(&mut ram.storage);
        if let Some(second) = second {
            second.retire(&mut ram.storage);
        }
        self.result = result;
        if result != 0 {
            self.length = 0;
        }
        self.stage = Stage::Done;
    }

    fn fail(
        &mut self,
        ram: &mut Ram<'_>,
        charge: &mut u16,
        second: Option<&mut Resolve>,
        code: u32,
    ) {
        self.finish(ram, charge, second, code);
        self.length = 0;
    }

    fn cancel_work(&mut self, ram: &mut Ram<'_>, charge: &mut u16) {
        match core::mem::replace(&mut self.work, Work::None) {
            Work::None => {}
            Work::Namespace(mut prep) => {
                for _ in 0..64 {
                    if prep.cancel_step(&mut ram.storage).unwrap_or(true) {
                        break;
                    }
                }
            }
            Work::Create(mut journal) => {
                let _ = journal.cancel_step(&mut ram.storage, charge);
            }
            Work::ReadLink(mut journal) => {
                let _ = journal.cancel_step(&mut ram.storage);
            }
            Work::Metadata(mut journal) => {
                let _ = journal.cancel_step(ram);
            }
            Work::Path(mut journal) => {
                for _ in 0..64 {
                    if journal.cancel_step(&mut ram.storage).unwrap_or(true) {
                        break;
                    }
                }
            }
        }
    }

    /// Everything the job holds goes back at once, whatever its phase.
    pub fn cancel(&mut self, ram: &mut Ram<'_>, charge: &mut u16, second: Option<Resolve>) {
        self.cancel_work(ram, charge);
        self.first.retire(&mut ram.storage);
        if let Some(second) = second {
            second.release(&mut ram.storage);
        }
    }

    fn reply(&self) -> ChangeReply<'_> {
        let done = self.stage == Stage::Done;
        let bytes = if done && self.result == 0 {
            &self.first.buffer_ref()[..self.length as usize]
        } else {
            &[]
        };
        ChangeReply {
            done,
            result: if done { self.result } else { 0 },
            restarts: self.restarts,
            value: if done && self.result == 0 {
                u64::from(self.length)
            } else {
                0
            },
            bytes,
        }
    }
}

/// The tables the five methods work on.
pub struct Ctx<'a, 'r> {
    pub ram: &'a mut Ram<'r>,
    pub jobs: &'a mut JobTable,
    pub generations: &'a mut JobGenerations,
    pub seconds: &'a mut Seconds,
}

fn find(jobs: &JobTable, owner: u64, key: OpenKey) -> Option<usize> {
    jobs.iter().position(|job| {
        job.as_ref()
            .is_some_and(|job| job.owner == owner && job.open_key == Some(key))
    })
}

fn same_image(job: &ResolveJob, fds: &Fds) -> bool {
    job.authority.map(|stamp: Stamp| stamp.image) == fds.binding.stamp().map(|stamp| stamp.image)
}

/// Method 44. The job is paid and keyed before it has any effect; the same
/// key with the same arguments returns the same job.
pub fn start(
    ctx: &mut Ctx<'_, '_>,
    fds: &mut Fds,
    owner: u64,
    req: &ChangeStart<'_>,
    out: &mut Writer,
) -> Result<(), u32> {
    let key = req.key;
    if let Some(i) = find(ctx.jobs, owner, key) {
        let job = ctx.jobs[i].as_ref().expect("found");
        let JobOperation::Change(change) = &job.operation else {
            return Err(PERMISSION);
        };
        if job.abandoned {
            return Err(OPEN_RETIRED);
        }
        if !change.same_start(req) {
            return Err(PERMISSION);
        }
        if !fds.resolvers.contains(&job.id) || !same_image(job, fds) {
            return Err(OPEN_RETIRED);
        }
        return proto_fs::write_start_reply(out, change.phase()).map_err(|e| e.code());
    }
    if ctx
        .jobs
        .iter()
        .flatten()
        .any(|job| job.owner == owner && job.open_key.is_some_and(|other| other.slot == key.slot))
    {
        return Err(TOO_MANY_OPEN_FILES);
    }
    if key.generation <= fds.open_watermarks[key.slot as usize] {
        return Err(OPEN_RETIRED);
    }
    for id in &mut fds.resolvers {
        if *id != 0
            && !ctx.jobs[(*id & 255) as usize]
                .as_ref()
                .is_some_and(|job| job.id == *id && job.owner == owner)
        {
            *id = 0;
        }
    }
    // The session keeps its own count; the client counts too, so this is
    // the error of a client that does not.
    if !fds.preparation_available() {
        return Err(TOO_MANY_OPEN_FILES);
    }
    let Some(place) = fds.resolvers.iter().position(|&id| id == 0) else {
        return Err(TOO_MANY_OPEN_FILES);
    };
    // A full table, a full share of the root or a full place for a second
    // path make no effect and keep the key free: the client sleeps and tries again.
    let Some(slot) = ctx.jobs.iter().position(Option::is_none) else {
        return Err(JOBS_FULL);
    };
    let generation = ctx.generations[slot]
        .checked_add(1)
        .filter(|&generation| generation < 1 << 56)
        .ok_or(TOO_MANY_OPEN_FILES)?;
    // The identity comes before the place of the side table, so that no
    // early exit leaves the place reserved.
    let real = uses_real_identity(req.op, req.flags);
    let identity = fds.binding.identity(real)?;
    let second_place = if req.op.needs_second() {
        Some(ctx.seconds.reserve().ok_or(JOBS_FULL)? as u8)
    } else {
        None
    };
    let charge = match ctx.ram.storage.charge_preparation(fds.root) {
        Ok(charge) => charge,
        Err(code) => {
            if let Some(place) = second_place {
                ctx.seconds.free(place as usize);
            }
            return Err(if code == TOO_MANY_OPEN_FILES {
                JOBS_FULL
            } else {
                code
            });
        }
    };
    let change = match ChangeJob::capture(ctx.ram, fds, identity, req, second_place) {
        Ok(change) => change,
        Err(code) => {
            ctx.ram.storage.release_preparation(charge);
            if let Some(place) = second_place {
                ctx.seconds.free(place as usize);
            }
            return Err(code);
        }
    };
    let phase = change.phase();
    let id = generation << 8 | slot as u64;
    ctx.jobs[slot] = Some(ResolveJob {
        id,
        owner,
        root: charge,
        real,
        authority: fds.binding.stamp(),
        operation: JobOperation::Change(change),
        open_key: Some(key),
        raw_base: (0, 0),
        abandoned: false,
    });
    ctx.generations[slot] = generation;
    fds.resolvers[place] = id;
    fds.open_watermarks[key.slot as usize] = key.generation;
    if proto_fs::write_start_reply(out, phase).is_err() {
        cancel_slot(ctx, Some(fds), slot);
        return Err(proto_wire::BAD_SIZE);
    }
    Ok(())
}

/// Method 45.
pub fn second(
    ctx: &mut Ctx<'_, '_>,
    fds: &Fds,
    owner: u64,
    req: &ChangeSecond<'_>,
) -> Result<(), u32> {
    let Some(i) = find(ctx.jobs, owner, req.key) else {
        return Err(
            if req.key.generation <= fds.open_watermarks[req.key.slot as usize] {
                OPEN_RETIRED
            } else {
                proto_fs::NO_ENTRY
            },
        );
    };
    let job = ctx.jobs[i].as_mut().expect("found");
    if job.abandoned || !fds.resolvers.contains(&job.id) || !same_image(job, fds) {
        return Err(OPEN_RETIRED);
    }
    let real = job.real;
    let JobOperation::Change(change) = &mut job.operation else {
        return Err(PERMISSION);
    };
    let identity = fds.binding.identity(real)?;
    let place = change.second_place();
    change.second(
        ctx.ram,
        fds,
        identity,
        place.map(|place| &mut ctx.seconds.slots[place]),
        req,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Advance {
    Step,
    Query,
}

/// Methods 46 and 47. The reply carries the outcome of a done job and the
/// restarts of every job.
pub fn step(
    ctx: &mut Ctx<'_, '_>,
    fds: &Fds,
    owner: u64,
    key: OpenKey,
    advance: Advance,
    clock: &dyn Clock,
    out: &mut Writer,
) -> Result<(), u32> {
    let Some(i) = find(ctx.jobs, owner, key) else {
        return Err(
            if key.generation <= fds.open_watermarks[key.slot as usize] {
                OPEN_RETIRED
            } else {
                proto_fs::NO_ENTRY
            },
        );
    };
    let job = ctx.jobs[i].as_mut().expect("found");
    if job.abandoned || !fds.resolvers.contains(&job.id) || !same_image(job, fds) {
        return Err(OPEN_RETIRED);
    }
    let stamp = fds.binding.stamp();
    let new_authority = job.authority != stamp;
    let real = job.real;
    let identity = fds.binding.identity(real)?;
    let JobOperation::Change(change) = &mut job.operation else {
        return Err(PERMISSION);
    };
    if advance == Advance::Step {
        let place = change.second_place();
        let mut none: Option<Resolve> = None;
        let second = match place {
            Some(place) => &mut ctx.seconds.slots[place],
            None => &mut none,
        };
        if new_authority {
            change.invalidate(second.as_mut());
            job.authority = stamp;
        }
        change.step(
            ctx.ram,
            fds,
            identity,
            &mut job.root,
            second.as_mut(),
            clock,
        )?;
    }
    let JobOperation::Change(change) = &job.operation else {
        unreachable!()
    };
    change.reply().write(out).map_err(|e| e.code())
}

/// Method 48: whatever the job holds goes back in this one call, the job
/// is forgotten, and the mark of the key rises.
pub fn release(ctx: &mut Ctx<'_, '_>, fds: &mut Fds, owner: u64, key: OpenKey) -> Result<(), u32> {
    if let Some(i) = find(ctx.jobs, owner, key) {
        if !matches!(
            ctx.jobs[i].as_ref().expect("found").operation,
            JobOperation::Change(_)
        ) {
            return Err(PERMISSION);
        }
        cancel_slot(ctx, Some(fds), i);
    }
    let mark = &mut fds.open_watermarks[key.slot as usize];
    *mark = (*mark).max(key.generation);
    Ok(())
}

/// Frees the job at `slot`: the journal, the pins, the second path, the
/// charge and the place of the session. Returns whether the job had been
/// abandoned by a session that went.
pub fn cancel_slot(ctx: &mut Ctx<'_, '_>, fds: Option<&mut Fds>, slot: usize) -> bool {
    let Some(job) = ctx.jobs[slot].as_mut() else {
        return false;
    };
    let (id, abandoned) = (job.id, job.abandoned);
    if let JobOperation::Change(change) = &mut job.operation {
        let place = change.second_place();
        let second = place.and_then(|place| ctx.seconds.slots[place].take());
        change.cancel(ctx.ram, &mut job.root, second);
        if let Some(place) = place {
            ctx.seconds.free(place);
        }
    }
    if job.root != NONE {
        ctx.ram.storage.release_preparation(job.root);
    }
    ctx.jobs[slot] = None;
    if let Some(fds) = fds
        && let Some(place) = fds.resolvers.iter_mut().find(|place| **place == id)
    {
        *place = 0;
    }
    abandoned
}
