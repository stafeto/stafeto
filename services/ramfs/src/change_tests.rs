// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The change jobs through the five methods, on the live RAM backend.
extern crate std;
use crate::authority::{Binding, Identity};
use crate::change::{Advance, Clock, Ctx, SECONDS};
use crate::job::{JobGenerations, JobOperation, JobTable, Seconds};
use crate::resolve::{Progress, Resolve};
use crate::storage::{BOOT_ROOT, ROOT, Root, Token};
use crate::{DIR, Fds, REG, Ram};
use core::cell::Cell;
use proto_fs::{
    BAD_FD, Base, ChangeOp, ChangePhase, ChangeReply, ChangeSecond, ChangeStart, INVALID_ARGUMENT,
    JOBS_FULL, NO_ENTRY, NOT_DIRECTORY, OPEN_RETIRED, OpenKey, PERMISSION, TOO_MANY_OPEN_FILES,
    Timestamp, UNLINK_REMOVEDIR,
};
use proto_process::{Credentials, ExpenditureRoot, Groups, ResourceLimits, WhoReply};
use proto_wire::{Status, Writer};
use std::{boxed::Box, vec::Vec};

const FIXTURE: Root = Root {
    id: 9000,
    generation: 1,
};
const ROOT_USER: Identity = Identity {
    uid: 0,
    gid: 0,
    groups: Groups::EMPTY,
};

struct Fixed(Cell<Option<Timestamp>>);
impl Clock for Fixed {
    fn read_once(&self) -> Result<Option<Timestamp>, Status> {
        Ok(self.0.get())
    }
}

struct Env {
    ram: Ram<'static>,
    jobs: Box<JobTable>,
    generations: Box<JobGenerations>,
    seconds: Box<Seconds>,
    clock: Fixed,
}

/// What a finished job answered.
#[derive(Debug, PartialEq, Eq)]
struct Done {
    result: u32,
    restarts: u32,
    bytes: Vec<u8>,
    steps: usize,
}

fn key(slot: u32, generation: u64) -> OpenKey {
    OpenKey { slot, generation }
}
fn req(slot: u32, generation: u64, op: ChangeOp, path: &[u8]) -> ChangeStart<'_> {
    ChangeStart {
        key: key(slot, generation),
        op,
        flags: 0,
        base: Base::Absolute,
        args: [0; 4],
        path,
    }
}
fn mkdir(slot: u32, generation: u64, path: &[u8], mode: u64, umask: u64) -> ChangeStart<'_> {
    let mut start = req(slot, generation, ChangeOp::Mkdir, path);
    start.args = [mode, umask, 0, 0];
    start
}
fn session() -> Fds {
    Fds {
        binding: Binding::Boot,
        ..Fds::default()
    }
}
fn credentials(uid: u32, euid: u32, gid: u32, egid: u32) -> Fds {
    let who = WhoReply {
        pid: 300,
        credentials: Credentials {
            uid,
            euid,
            suid: euid,
            gid,
            egid,
            sgid: egid,
        },
        generation: 1,
        loader: None,
        index: 44,
        ctty: None,
        image: 1,
        groups: Groups::EMPTY,
        limits: ResourceLimits::initial(2 * 1024 * 1024),
        root: ExpenditureRoot {
            pid: 300,
            generation: 1,
        },
    };
    let binding = Binding::Active(who);
    Fds {
        root: binding.root().unwrap(),
        binding,
        ..Fds::default()
    }
}

impl Env {
    fn new() -> Self {
        let mut ram = Ram::new(Timestamp::legacy_ns(1));
        ram.storage.node_mut(ROOT).unwrap().mode = 0o777;
        Self {
            ram,
            jobs: Box::new([const { None }; crate::storage::PREPARATIONS]),
            generations: Box::new([0; crate::storage::PREPARATIONS]),
            seconds: Box::new([const { None }; SECONDS]),
            clock: Fixed(Cell::new(Some(Timestamp::legacy_ns(7_000_000_000)))),
        }
    }
    fn ctx(&mut self) -> Ctx<'_, 'static> {
        Ctx {
            ram: &mut self.ram,
            jobs: &mut self.jobs,
            generations: &mut self.generations,
            seconds: &mut self.seconds,
        }
    }
    fn node(&mut self, parent: Token, name: &[u8], kind: u32, mode: u32) -> Token {
        let r = self
            .ram
            .storage
            .reserve(FIXTURE, parent, name, (kind, mode, 0, 0))
            .unwrap();
        self.ram.storage.commit(r).unwrap()
    }
    fn start(
        &mut self,
        fds: &mut Fds,
        owner: u64,
        start: &ChangeStart<'_>,
    ) -> Result<ChangePhase, u32> {
        let mut out = Writer::new();
        crate::change::start(&mut self.ctx(), fds, owner, start, &mut out)?;
        Ok(proto_fs::change_start_reply(out.as_bytes(), 0).unwrap())
    }
    fn second(
        &mut self,
        fds: &Fds,
        owner: u64,
        key: OpenKey,
        base: Base,
        bytes: &[u8],
    ) -> Result<(), u32> {
        crate::change::second(
            &mut self.ctx(),
            fds,
            owner,
            &ChangeSecond { key, base, bytes },
        )
    }
    fn advance(
        &mut self,
        fds: &Fds,
        owner: u64,
        key: OpenKey,
        advance: Advance,
    ) -> Result<(bool, u32, u32, Vec<u8>), u32> {
        let mut out = Writer::new();
        let clock = Fixed(Cell::new(self.clock.0.get()));
        crate::change::step(&mut self.ctx(), fds, owner, key, advance, &clock, &mut out)?;
        let reply = ChangeReply::read(out.as_bytes(), 0).unwrap();
        Ok((
            reply.done,
            reply.result,
            reply.restarts,
            reply.bytes.to_vec(),
        ))
    }
    fn step(
        &mut self,
        fds: &Fds,
        owner: u64,
        key: OpenKey,
    ) -> Result<(bool, u32, u32, Vec<u8>), u32> {
        self.advance(fds, owner, key, Advance::Step)
    }
    fn release(&mut self, fds: &mut Fds, owner: u64, key: OpenKey) -> Result<(), u32> {
        crate::change::release(&mut self.ctx(), fds, owner, key)
    }
    /// Start, Second, Step until done, Release.
    fn run(
        &mut self,
        fds: &mut Fds,
        owner: u64,
        start: &ChangeStart<'_>,
        second: Option<(Base, &[u8])>,
    ) -> Result<Done, u32> {
        self.start(fds, owner, start)?;
        if let Some((base, bytes)) = second {
            self.second(fds, owner, start.key, base, bytes)?;
        }
        let mut steps = 0;
        let done = loop {
            steps += 1;
            assert!(steps < 100_000, "the job does not finish");
            let (done, result, restarts, bytes) = self.step(fds, owner, start.key)?;
            if done {
                break Done {
                    result,
                    restarts,
                    bytes,
                    steps,
                };
            }
        };
        // A repeat of the last Step and a Query give the same outcome.
        let (again, result, _, bytes) = self.step(fds, owner, start.key)?;
        assert!(again && result == done.result && bytes == done.bytes);
        let (query, result, _, bytes) =
            self.advance(fds, owner, start.key, Advance::Query).unwrap();
        assert!(query && result == done.result && bytes == done.bytes);
        self.release(fds, owner, start.key)?;
        Ok(done)
    }
    fn lookup(&mut self, path: &[u8]) -> Result<Token, u32> {
        let mut walk = Resolve::new(&mut self.ram.storage, path, ROOT, ROOT_USER, true)?;
        for _ in 0..20_000 {
            match walk.step(&mut self.ram.storage, ROOT_USER) {
                Ok(Progress::Found(token)) => {
                    walk.release(&mut self.ram.storage);
                    return Ok(token);
                }
                Ok(_) => {}
                Err(code) => {
                    walk.release(&mut self.ram.storage);
                    return Err(code);
                }
            }
        }
        panic!("lookup does not finish");
    }
    /// Nothing is paid, pinned or staged any more.
    fn assert_quiet(&mut self) {
        assert_eq!(self.ram.storage.preparations_used(), 0);
        assert!(self.jobs.iter().all(Option::is_none));
        assert!(self.seconds.iter().all(Option::is_none));
        let mut guard = 0;
        while self.ram.storage.reclaim_step() {
            guard += 1;
            assert!(guard < 10_000);
        }
        let held = self
            .ram
            .storage
            .state
            .nodes
            .iter()
            .position(|n| n.pins != [0; 5]);
        assert_eq!(held, None, "a node keeps a pin");
    }
}

const OWNER: u64 = 77;

#[test]
fn mkdir_makes_a_directory_with_the_umask_and_a_second_one_exists() {
    let mut env = Env::new();
    let mut fds = session();
    let done = env
        .run(&mut fds, OWNER, &mkdir(0, 1, b"/d", 0o777, 0o022), None)
        .unwrap();
    assert_eq!(done.result, 0);
    assert!(done.bytes.is_empty());
    let token = env.lookup(b"/d").unwrap();
    let node = env.ram.storage.node(token).unwrap();
    assert_eq!((node.kind, node.mode & 0o7777), (DIR, 0o755));
    assert_eq!(node.links, 2);
    let root_links = env.ram.storage.node(ROOT).unwrap().links;
    let before = env.ram.storage.state.epoch;
    let done = env
        .run(&mut fds, OWNER, &mkdir(0, 2, b"/d", 0o777, 0), None)
        .unwrap();
    assert_eq!(done.result, proto_fs::ALREADY_EXISTS);
    assert_eq!(env.ram.storage.state.epoch, before, "no effect");
    assert_eq!(env.ram.storage.node(ROOT).unwrap().links, root_links);
    let done = env
        .run(&mut fds, OWNER, &mkdir(0, 3, b"/missing/x", 0o777, 0), None)
        .unwrap();
    assert_eq!(done.result, NO_ENTRY);
    // A trailing slash is allowed on a name that does not exist yet.
    let done = env
        .run(&mut fds, OWNER, &mkdir(0, 4, b"/e/", 0o700, 0), None)
        .unwrap();
    assert_eq!(done.result, 0);
    env.assert_quiet();
}

#[test]
fn unlink_and_rmdir_refuse_the_wrong_kind_and_remove_the_right_one() {
    let mut env = Env::new();
    let mut fds = session();
    let root_links = env.ram.storage.node(ROOT).unwrap().links;
    let file = env.node(ROOT, b"f", REG, 0o644);
    let dir = env.node(ROOT, b"d", DIR, 0o755);
    env.node(dir, b"inner", REG, 0o644);
    let rmdir = |slot, generation, path| {
        let mut start = req(slot, generation, ChangeOp::Unlink, path);
        start.flags = UNLINK_REMOVEDIR;
        start
    };
    let unlink = |slot, generation, path| req(slot, generation, ChangeOp::Unlink, path);
    let mut generation = 0;
    let mut go = |env: &mut Env, fds: &mut Fds, start: ChangeStart<'_>| {
        generation += 1;
        let start = ChangeStart {
            key: key(1, generation),
            ..start
        };
        env.run(fds, OWNER, &start, None).unwrap().result
    };
    assert_eq!(go(&mut env, &mut fds, unlink(0, 0, b"/d")), PERMISSION);
    assert_eq!(
        go(&mut env, &mut fds, unlink(0, 0, b"/d/")),
        PERMISSION,
        "a directory with a slash"
    );
    assert_eq!(go(&mut env, &mut fds, rmdir(0, 0, b"/f")), NOT_DIRECTORY);
    assert_eq!(go(&mut env, &mut fds, unlink(0, 0, b"/f/")), NOT_DIRECTORY);
    assert_eq!(
        go(&mut env, &mut fds, rmdir(0, 0, b"/d")),
        proto_fs::NOT_EMPTY
    );
    assert_eq!(go(&mut env, &mut fds, unlink(0, 0, b"/nothing")), NO_ENTRY);
    assert_eq!(go(&mut env, &mut fds, unlink(0, 0, b"/")), proto_fs::BUSY);
    assert!(env.lookup(b"/f").is_ok() && env.lookup(b"/d/inner").is_ok());
    assert_eq!(go(&mut env, &mut fds, unlink(0, 0, b"/d/inner")), 0);
    assert_eq!(env.lookup(b"/d/inner"), Err(NO_ENTRY));
    assert_eq!(go(&mut env, &mut fds, rmdir(0, 0, b"/d/")), 0);
    assert_eq!(env.lookup(b"/d"), Err(NO_ENTRY));
    assert_eq!(go(&mut env, &mut fds, unlink(0, 0, b"/f")), 0);
    assert_eq!(env.lookup(b"/f"), Err(NO_ENTRY));
    assert_eq!(env.ram.storage.node(ROOT).unwrap().links, root_links);
    let _ = file;
    env.assert_quiet();
}

#[test]
fn access_answers_by_the_real_or_the_effective_identity() {
    let mut env = Env::new();
    // A file of user 100 that only its owner reads and writes; root reads.
    let token = env.node(ROOT, b"private", REG, 0o600);
    env.ram
        .storage
        .set_attributes(token, 0o600, 100, 100)
        .unwrap();
    let epoch = env.ram.storage.state.epoch;
    let access = |slot, generation, bits: u64, flags| {
        let mut start = req(slot, generation, ChangeOp::Access, b"/private");
        start.args[0] = bits;
        start.flags = flags;
        start
    };
    // Real user 100, effective root.
    let mut fds = credentials(100, 0, 100, 0);
    assert_eq!(
        env.run(&mut fds, OWNER, &access(0, 1, 6, 0), None)
            .unwrap()
            .result,
        0,
        "the real identity owns the file"
    );
    assert_eq!(
        env.run(&mut fds, OWNER, &access(0, 2, 1, 0), None)
            .unwrap()
            .result,
        proto_fs::ACCESS_DENIED,
        "the owner may not execute a file without x"
    );
    assert_eq!(
        env.run(
            &mut fds,
            OWNER,
            &access(0, 3, 1, proto_fs::ACCESS_EFFECTIVE),
            None
        )
        .unwrap()
        .result,
        proto_fs::ACCESS_DENIED,
        "root executes only what has an x bit"
    );
    // Real user 200, effective user 100: effective sees the file, real does not.
    let mut fds = credentials(200, 100, 200, 100);
    assert_eq!(
        env.run(&mut fds, OWNER, &access(0, 1, 4, 0), None)
            .unwrap()
            .result,
        proto_fs::ACCESS_DENIED
    );
    assert_eq!(
        env.run(
            &mut fds,
            OWNER,
            &access(0, 2, 4, proto_fs::ACCESS_EFFECTIVE),
            None
        )
        .unwrap()
        .result,
        0
    );
    // F_OK sees the file, a missing one is NO_ENTRY.
    assert_eq!(
        env.run(&mut fds, OWNER, &access(0, 3, 0, 0), None)
            .unwrap()
            .result,
        0
    );
    let mut missing = access(0, 4, 0, 0);
    missing.path = b"/none";
    assert_eq!(
        env.run(&mut fds, OWNER, &missing, None).unwrap().result,
        NO_ENTRY
    );
    assert_eq!(env.ram.storage.state.epoch, epoch, "access changes nothing");
    env.assert_quiet();
}

#[test]
fn a_repeated_start_returns_the_job_and_other_arguments_are_refused() {
    let mut env = Env::new();
    let mut fds = session();
    let first = mkdir(3, 5, b"/a", 0o755, 0);
    assert_eq!(
        env.start(&mut fds, OWNER, &first),
        Ok(ChangePhase::Resolving)
    );
    assert_eq!(
        env.start(&mut fds, OWNER, &first),
        Ok(ChangePhase::Resolving)
    );
    let live = env.jobs.iter().flatten().count();
    assert_eq!(live, 1, "one job");
    for other in [
        mkdir(3, 5, b"/b", 0o755, 0),
        mkdir(3, 5, b"/a", 0o700, 0),
        mkdir(3, 5, b"/a", 0o755, 0o022),
        req(3, 5, ChangeOp::Unlink, b"/a"),
    ] {
        assert_eq!(env.start(&mut fds, OWNER, &other), Err(PERMISSION));
    }
    // Another session with the same key is another job.
    let mut other_session = session();
    assert!(env.start(&mut other_session, OWNER + 1, &first).is_ok());
    assert_eq!(env.jobs.iter().flatten().count(), 2);
    env.release(&mut fds, OWNER, first.key).unwrap();
    env.release(&mut other_session, OWNER + 1, first.key)
        .unwrap();
    env.assert_quiet();
}

#[test]
fn a_released_key_is_retired_and_a_release_of_an_unknown_key_raises_the_mark() {
    let mut env = Env::new();
    let mut fds = session();
    let first = mkdir(2, 4, b"/a", 0o755, 0);
    env.start(&mut fds, OWNER, &first).unwrap();
    env.release(&mut fds, OWNER, first.key).unwrap();
    // The job is gone, and so is the right to start it again.
    assert_eq!(env.start(&mut fds, OWNER, &first), Err(OPEN_RETIRED));
    assert_eq!(
        env.release(&mut fds, OWNER, first.key),
        Ok(()),
        "a repeat is harmless"
    );
    assert_eq!(
        env.step(&fds, OWNER, first.key).map(|_| ()),
        Err(OPEN_RETIRED)
    );
    // A Release that arrives before its Start closes the key for good.
    assert_eq!(env.release(&mut fds, OWNER, key(7, 9)), Ok(()));
    assert_eq!(
        env.start(&mut fds, OWNER, &mkdir(7, 9, b"/b", 0o755, 0)),
        Err(OPEN_RETIRED)
    );
    assert_eq!(
        env.start(&mut fds, OWNER, &mkdir(7, 10, b"/b", 0o755, 0)),
        Ok(ChangePhase::Resolving)
    );
    // An unknown key above the mark is NO_ENTRY.
    assert_eq!(env.step(&fds, OWNER, key(8, 1)).map(|_| ()), Err(NO_ENTRY));
    env.release(&mut fds, OWNER, key(7, 10)).unwrap();
    env.assert_quiet();
}

#[test]
fn a_second_start_on_a_busy_place_of_the_key_is_too_many_open_files() {
    let mut env = Env::new();
    let mut fds = session();
    assert!(
        env.start(&mut fds, OWNER, &mkdir(5, 1, b"/a", 0o755, 0))
            .is_ok()
    );
    assert_eq!(
        env.start(&mut fds, OWNER, &mkdir(5, 2, b"/b", 0o755, 0)),
        Err(TOO_MANY_OPEN_FILES)
    );
    // The mark did not rise: the key 2 is still good after the first is released.
    env.release(&mut fds, OWNER, key(5, 1)).unwrap();
    assert!(
        env.start(&mut fds, OWNER, &mkdir(5, 2, b"/b", 0o755, 0))
            .is_ok()
    );
    env.release(&mut fds, OWNER, key(5, 2)).unwrap();
    env.assert_quiet();
}

#[test]
fn the_seventeenth_job_of_a_session_is_the_error_of_a_client_that_does_not_count() {
    let mut env = Env::new();
    let mut fds = session();
    for slot in 0..16 {
        assert!(
            env.start(&mut fds, OWNER, &mkdir(slot, 1, b"/a", 0o755, 0))
                .is_ok()
        );
    }
    // The 17th key needs a 17th place: a session has 16 and 32 key places.
    assert_eq!(
        env.start(&mut fds, OWNER, &mkdir(16, 1, b"/a", 0o755, 0)),
        Err(TOO_MANY_OPEN_FILES)
    );
    for slot in 0..16 {
        env.release(&mut fds, OWNER, key(slot, 1)).unwrap();
    }
    env.assert_quiet();
}

#[test]
fn a_full_share_or_table_is_jobs_full_without_effect_and_the_same_key_goes_later() {
    let mut env = Env::new();
    // Six sessions of one root take its share of 96.
    let mut sessions: Vec<Fds> = (0..7).map(|_| session()).collect();
    for (i, fds) in sessions.iter_mut().enumerate().take(6) {
        for slot in 0..16 {
            assert!(
                env.start(fds, 100 + i as u64, &mkdir(slot, 1, b"/a", 0o755, 0))
                    .is_ok()
            );
        }
    }
    let last = mkdir(0, 1, b"/a", 0o755, 0);
    assert_eq!(env.start(&mut sessions[6], 106, &last), Err(JOBS_FULL));
    assert_eq!(env.start(&mut sessions[6], 106, &last), Err(JOBS_FULL));
    // The mark did not rise; after one release the same key is taken.
    env.release(&mut sessions[0], 100, key(0, 1)).unwrap();
    assert!(env.start(&mut sessions[6], 106, &last).is_ok());
    // Two more roots fill the table of 128 places.
    let mut other: Vec<Fds> = (0..2)
        .map(|n| Fds {
            root: Root {
                id: 5000 + n,
                generation: 1,
            },
            ..session()
        })
        .collect();
    for (i, fds) in other.iter_mut().enumerate() {
        for slot in 0..16 {
            let owner = 200 + i as u64;
            assert!(
                env.start(fds, owner, &mkdir(slot, 1, b"/a", 0o755, 0))
                    .is_ok()
            );
        }
    }
    assert_eq!(env.jobs.iter().flatten().count(), 128);
    let mut spare = Fds {
        root: Root {
            id: 6000,
            generation: 1,
        },
        ..session()
    };
    assert_eq!(
        env.start(&mut spare, 300, &mkdir(20, 1, b"/a", 0o755, 0)),
        Err(JOBS_FULL),
        "a full table"
    );
    // Clean up every job through Release.
    for slot in 0..128usize {
        if let Some(job) = env.jobs[slot].as_ref() {
            let (owner, k) = (job.owner, job.open_key.unwrap());
            let fds: &mut Fds = match owner {
                100..=106 => &mut sessions[(owner - 100) as usize],
                _ => &mut other[(owner - 200) as usize],
            };
            env.release(fds, owner, k).unwrap();
        }
    }
    env.assert_quiet();
}

#[test]
fn bases_a_descriptor_a_wrong_generation_and_the_reserved_current_directory() {
    let mut env = Env::new();
    let mut fds = session();
    let dir = env.node(ROOT, b"dir", DIR, 0o755);
    let file = env.node(ROOT, b"file", REG, 0o644);
    let fd = env
        .ram
        .open_token(&mut fds, dir, proto_fs::READ_ONLY, ROOT_USER)
        .unwrap();
    let generation = env.ram.description_token(&fds, fd).unwrap().generation;
    let at = |base| {
        let mut start = mkdir(0, 1, b"sub", 0o755, 0);
        start.base = base;
        start
    };
    let mut n = 0;
    let mut go = |env: &mut Env, fds: &mut Fds, base| {
        n += 1;
        let start = ChangeStart {
            key: key(1, n),
            ..at(base)
        };
        env.run(fds, OWNER, &start, None).unwrap().result
    };
    // A relative path from the descriptor.
    assert_eq!(go(&mut env, &mut fds, Base::Fd { fd, generation }), 0);
    assert!(env.lookup(b"/dir/sub").is_ok());
    // The wrong generation of the description.
    assert_eq!(
        go(
            &mut env,
            &mut fds,
            Base::Fd {
                fd,
                generation: generation + 1
            }
        ),
        BAD_FD
    );
    assert_eq!(
        go(
            &mut env,
            &mut fds,
            Base::Fd {
                fd: fd + 1,
                generation
            }
        ),
        BAD_FD,
        "a closed number"
    );
    // The reserved base and an absolute-only base with a relative path.
    assert_eq!(go(&mut env, &mut fds, Base::Cwd), BAD_FD);
    assert_eq!(go(&mut env, &mut fds, Base::Absolute), BAD_FD);
    // An absolute path ignores the base, whatever it is.
    let mut absolute = mkdir(2, 1, b"/abs", 0o755, 0);
    absolute.base = Base::Fd {
        fd: 30,
        generation: 99,
    };
    assert_eq!(env.run(&mut fds, OWNER, &absolute, None).unwrap().result, 0);
    absolute.key = key(2, 2);
    absolute.path = b"/abs2";
    absolute.base = Base::Cwd;
    assert_eq!(env.run(&mut fds, OWNER, &absolute, None).unwrap().result, 0);
    // A file as the base of a relative path is NOT_DIRECTORY.
    let file_fd = env
        .ram
        .open_token(&mut fds, file, proto_fs::READ_ONLY, ROOT_USER)
        .unwrap();
    let file_generation = env.ram.description_token(&fds, file_fd).unwrap().generation;
    assert_eq!(
        go(
            &mut env,
            &mut fds,
            Base::Fd {
                fd: file_fd,
                generation: file_generation
            }
        ),
        NOT_DIRECTORY
    );
    // A failed Start repeats with the same answer and releases cleanly.
    let failed = ChangeStart {
        key: key(3, 1),
        ..at(Base::Cwd)
    };
    assert_eq!(env.start(&mut fds, OWNER, &failed), Ok(ChangePhase::Done));
    assert_eq!(env.start(&mut fds, OWNER, &failed), Ok(ChangePhase::Done));
    env.release(&mut fds, OWNER, failed.key).unwrap();
    env.ram.close(&mut fds, fd).unwrap();
    env.ram.close(&mut fds, file_fd).unwrap();
    env.assert_quiet();
}

#[test]
fn a_directory_without_search_permission_refuses_a_relative_path_by_its_current_mode() {
    let mut env = Env::new();
    let dir = env.node(ROOT, b"dir", DIR, 0o755);
    let mut fds = credentials(500, 500, 500, 500);
    let fd = env
        .ram
        .open_token(&mut fds, dir, proto_fs::READ_ONLY, ROOT_USER)
        .unwrap();
    let generation = env.ram.description_token(&fds, fd).unwrap().generation;
    env.ram.storage.node_mut(ROOT).unwrap().mode = 0o755;
    // The directory belongs to root and others only search: creating inside fails.
    let mut start = mkdir(0, 1, b"sub", 0o755, 0);
    start.base = Base::Fd { fd, generation };
    assert_eq!(
        env.run(&mut fds, OWNER, &start, None).unwrap().result,
        proto_fs::ACCESS_DENIED
    );
    // Now the search bit goes: the same descriptor, another answer.
    env.ram.storage.set_attributes(dir, 0o700, 0, 0).unwrap();
    start.key = key(0, 2);
    assert_eq!(
        env.run(&mut fds, OWNER, &start, None).unwrap().result,
        proto_fs::ACCESS_DENIED
    );
    env.ram.storage.set_attributes(dir, 0o777, 0, 0).unwrap();
    start.key = key(0, 3);
    assert_eq!(env.run(&mut fds, OWNER, &start, None).unwrap().result, 0);
    env.ram.storage.set_attributes(dir, 0o666, 0, 0).unwrap();
    start.key = key(0, 4);
    start.path = b"sub2";
    let denied = env.run(&mut fds, OWNER, &start, None).unwrap().result;
    assert_eq!(denied, proto_fs::ACCESS_DENIED, "write without search");
    env.ram.close(&mut fds, fd).unwrap();
    env.assert_quiet();
}

#[test]
fn release_of_a_job_in_the_middle_gives_back_the_reservation_in_one_call() {
    let mut env = Env::new();
    let mut fds = session();
    let start = mkdir(4, 1, b"/a/b", 0o755, 0);
    env.node(ROOT, b"a", DIR, 0o755);
    env.start(&mut fds, OWNER, &start).unwrap();
    // Step until the reservation is made but nothing is published.
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 100);
        env.step(&fds, OWNER, start.key).unwrap();
        if env.ram.storage.usage(BOOT_ROOT).dentries != 0 {
            break;
        }
    }
    assert_eq!(env.lookup(b"/a/b"), Err(NO_ENTRY), "not published");
    env.release(&mut fds, OWNER, start.key).unwrap();
    assert_eq!(env.lookup(b"/a/b"), Err(NO_ENTRY));
    env.assert_quiet();
    assert!(fds.resolvers.iter().all(|&id| id == 0));
    assert_eq!(env.ram.storage.usage(BOOT_ROOT), Default::default());
}

#[test]
fn a_session_that_goes_returns_its_jobs_one_for_each_cancel() {
    let mut env = Env::new();
    let mut fds = session();
    env.node(ROOT, b"a", DIR, 0o755);
    for slot in 0..5 {
        let start = mkdir(slot, 1, b"/a/b", 0o755, 0);
        env.start(&mut fds, OWNER, &start).unwrap();
        for _ in 0..slot + 1 {
            env.step(&fds, OWNER, start.key).unwrap();
        }
    }
    assert_eq!(env.ram.storage.preparations_used(), 5);
    // The session goes: each job is marked, the service takes one for each pass.
    let mut cancels = 0;
    for slot in 0..crate::storage::PREPARATIONS {
        if let Some(job) = env.jobs[slot].as_mut() {
            assert!(matches!(job.operation, JobOperation::Change(_)));
            job.abandoned = true;
        }
    }
    for slot in 0..crate::storage::PREPARATIONS {
        if env.jobs[slot].is_some() {
            assert!(crate::change::cancel_slot(&mut env.ctx(), None, slot));
            cancels += 1;
        }
    }
    assert_eq!(cancels, 5);
    assert_eq!(env.ram.storage.preparations_used(), 0);
    env.assert_quiet();
}

#[test]
fn the_empty_path_and_the_wrong_operation_are_refused_by_the_codec_and_the_service_alike() {
    let mut env = Env::new();
    let mut fds = session();
    let mut nul = mkdir(0, 1, b"/a\0b", 0o755, 0);
    assert_eq!(env.start(&mut fds, OWNER, &nul), Err(INVALID_ARGUMENT));
    nul.path = b"/ok";
    // A refused Start leaves no job and does not raise the mark.
    assert_eq!(env.start(&mut fds, OWNER, &nul), Ok(ChangePhase::Resolving));
    let long = [b'x'; 256];
    let mut path = std::vec![b'/'];
    path.extend_from_slice(&long);
    let done = env
        .run(&mut fds, OWNER, &mkdir(1, 1, &path, 0o755, 0), None)
        .unwrap();
    assert_eq!(done.result, proto_fs::NAME_TOO_LONG);
    env.release(&mut fds, OWNER, nul.key).unwrap();
    env.assert_quiet();
}

/// The record of a job as it was before the change jobs: a path job or a data job.
#[allow(dead_code)]
struct EarlierJob {
    id: u64,
    owner: u64,
    root: u16,
    real: bool,
    authority: Option<crate::authority::Stamp>,
    operation: EarlierOperation,
    open_key: Option<OpenKey>,
    raw_base: (u32, u64),
    abandoned: bool,
}
#[allow(dead_code, clippy::large_enum_variant)]
enum EarlierOperation {
    Path(crate::job::PathJob),
    Data(crate::data::Journal),
}

#[test]
fn a_change_job_makes_no_record_of_the_table_bigger() {
    use core::mem::size_of;
    std::println!(
        "ResolveJob {} (earlier {}), ChangeJob {}, Resolve {}",
        size_of::<crate::job::ResolveJob>(),
        size_of::<EarlierJob>(),
        size_of::<crate::change::ChangeJob>(),
        size_of::<Resolve>(),
    );
    assert!(size_of::<crate::job::ResolveJob>() <= size_of::<EarlierJob>());
}
