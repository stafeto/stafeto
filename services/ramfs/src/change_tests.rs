// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The change jobs through the five methods, on the live RAM backend.
extern crate std;
use crate::authority::{Binding, Identity};
use crate::change::{Advance, Clock, Ctx};
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
    counter: u64,
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
            seconds: Box::new(Seconds::new()),
            clock: Fixed(Cell::new(Some(Timestamp::legacy_ns(7_000_000_000)))),
            counter: 0,
        }
    }
    /// A fresh key for each call, so that no test has to count.
    fn go(&mut self, fds: &mut Fds, mut start: ChangeStart<'_>, second: Option<&[u8]>) -> Done {
        self.counter += 1;
        start.key = key((self.counter % 32) as u32, self.counter);
        self.run(
            fds,
            OWNER,
            &start,
            second.map(|bytes| (Base::Absolute, bytes)),
        )
        .expect("the protocol accepts the request")
    }
    fn go_result(&mut self, fds: &mut Fds, start: ChangeStart<'_>, second: Option<&[u8]>) -> u32 {
        self.go(fds, start, second).result
    }
    fn now() -> Timestamp {
        Timestamp::legacy_ns(7_000_000_000)
    }
    fn times(&mut self, token: Token) -> [Timestamp; 3] {
        self.ram.storage.node(token).unwrap().times
    }
    fn lookup_link(&mut self, path: &[u8]) -> Result<Token, u32> {
        let mut walk = Resolve::new(&mut self.ram.storage, path, ROOT, ROOT_USER, false)?;
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
    /// The change jobs that hold a place of the side table.
    fn seconds_held(&self) -> usize {
        self.jobs
            .iter()
            .flatten()
            .filter(
                |job| matches!(&job.operation, JobOperation::Change(c) if c.second_place().is_some()),
            )
            .count()
    }
    /// Nothing is paid, pinned or staged any more.
    fn assert_quiet(&mut self) {
        self.ram.storage.check_name_index();
        assert_eq!(self.ram.cancel_refusals, 0, "a cancel step was refused");
        assert_eq!(self.ram.storage.preparations_used(), 0);
        assert!(self.jobs.iter().all(Option::is_none));
        assert!(self.seconds.is_clear());
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
        assert!(self.ram.storage.free_overlays_are_empty());
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
fn a_start_refused_for_its_identity_leaves_no_place_of_the_side_table() {
    let mut env = Env::new();
    // An unbound session has no identity: each Start of a rename fails
    // before it reserves anything, however many are made.
    let mut unbound = Fds::default();
    for n in 0..40 {
        let mut start = req(0, 1 + n, ChangeOp::Rename, b"/a");
        start.args = [0; 4];
        assert_eq!(env.start(&mut unbound, OWNER, &start), Err(PERMISSION));
    }
    assert!(env.seconds.is_clear());
    // The 33rd place is free for a session that has an identity.
    let mut fds = session();
    assert!(
        env.start(&mut fds, OWNER, &req(0, 1, ChangeOp::Rename, b"/a"))
            .is_ok()
    );
    env.release(&mut fds, OWNER, key(0, 1)).unwrap();
    env.assert_quiet();
}

/// Sessions of the root `id`, each with the 16 places a session has.
fn sessions_of(id: u64, count: usize) -> Vec<Fds> {
    (0..count)
        .map(|_| Fds {
            root: Root { id, generation: 1 },
            ..session()
        })
        .collect()
}

#[test]
fn the_side_table_gives_a_root_24_of_32_places_and_the_rest_to_the_others() {
    let mut env = Env::new();
    let rename = |slot, generation| req(slot, generation, ChangeOp::Rename, b"/a");
    // One root takes its share of 24 places in two sessions.
    let mut first = sessions_of(1000, 2);
    for n in 0..24usize {
        let (session, slot) = (n / 16, (n % 16) as u32);
        assert!(
            env.start(&mut first[session], 10 + session as u64, &rename(slot, 1))
                .is_ok(),
            "the {}th place",
            n + 1
        );
    }
    // The 25th Start is JOBS_FULL, however often it is repeated, and the
    // mark of its key does not rise: after one Release the key is taken.
    let late = rename(8, 1);
    assert_eq!(env.start(&mut first[1], 11, &late), Err(JOBS_FULL));
    assert_eq!(env.start(&mut first[1], 11, &late), Err(JOBS_FULL));
    // Nothing else is held for the refusal: 24 jobs, 24 charges.
    assert_eq!(env.ram.storage.preparations_used(), 24);
    // A job of the same root that needs no second path goes on.
    assert!(
        env.start(&mut first[1], 11, &mkdir(9, 1, b"/m", 0o755, 0))
            .is_ok()
    );
    env.release(&mut first[0], 10, key(0, 1)).unwrap();
    assert!(env.start(&mut first[1], 11, &late).is_ok());
    // Another root finds the 8 places the first root leaves.
    let mut other = sessions_of(2000, 1);
    for slot in 0..8u32 {
        assert!(
            env.start(&mut other[0], 20, &rename(slot, 1)).is_ok(),
            "the other root, place {}",
            slot + 1
        );
    }
    assert_eq!(env.seconds_held(), 32);
    // The 33rd place is nobody's: JOBS_FULL for either root.
    assert_eq!(env.start(&mut other[0], 20, &rename(8, 1)), Err(JOBS_FULL));
    env.release(&mut first[1], 11, key(8, 1)).unwrap();
    assert!(env.start(&mut other[0], 20, &rename(8, 1)).is_ok());
    // Everything goes back through Release.
    let held: Vec<(u64, OpenKey)> = env
        .jobs
        .iter()
        .flatten()
        .map(|job| (job.owner, job.open_key.unwrap()))
        .collect();
    for (owner, k) in held {
        let fds = match owner {
            10 => &mut first[0],
            11 => &mut first[1],
            _ => &mut other[0],
        };
        env.release(fds, owner, k).unwrap();
    }
    env.assert_quiet();
}

#[test]
fn a_refused_start_gives_back_its_charge_and_its_place_of_the_side_table() {
    let mut env = Env::new();
    let rename = |slot, generation| req(slot, generation, ChangeOp::Rename, b"/a");
    // A root at its share of 24 places: the refusal gives the charge back.
    let mut fds = sessions_of(1000, 2);
    for n in 0..24usize {
        let (session, slot) = (n / 16, (n % 16) as u32);
        env.start(&mut fds[session], 10 + session as u64, &rename(slot, 1))
            .unwrap();
    }
    let charges = env.ram.storage.preparations_used();
    assert_eq!(env.start(&mut fds[1], 11, &rename(8, 1)), Err(JOBS_FULL));
    assert_eq!(env.ram.storage.preparations_used(), charges);
    assert_eq!(env.seconds_held(), 24);
    // A path the capture refuses gives back both.
    let long = [b'a'; 5000];
    let before = env.ram.storage.preparations_used();
    let mut spare = sessions_of(3000, 1);
    let refused = env.start(&mut spare[0], 30, &req(0, 1, ChangeOp::Rename, &long));
    assert!(refused.is_err(), "a path of 5000 bytes is refused");
    assert_eq!(env.ram.storage.preparations_used(), before);
    assert_eq!(env.seconds_held(), 24);
    for n in 0..24usize {
        let (session, slot) = (n / 16, (n % 16) as u32);
        env.release(&mut fds[session], 10 + session as u64, key(slot, 1))
            .unwrap();
    }
    env.assert_quiet();
    // A root at its share of 96 charges takes no place of the side table
    // for the Start it refuses.
    let mut crowd = sessions_of(4000, 7);
    for (i, fds) in crowd.iter_mut().enumerate().take(6) {
        for slot in 0..16 {
            env.start(fds, 100 + i as u64, &mkdir(slot, 1, b"/a", 0o755, 0))
                .unwrap();
        }
    }
    assert_eq!(env.start(&mut crowd[6], 106, &rename(0, 1)), Err(JOBS_FULL));
    assert_eq!(env.seconds_held(), 0);
    for (i, fds) in crowd.iter_mut().enumerate().take(6) {
        for slot in 0..16 {
            env.release(fds, 100 + i as u64, key(slot, 1)).unwrap();
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
fn search_permission_of_the_base_is_checked_by_the_mode_it_has_when_the_path_is_walked() {
    let mut env = Env::new();
    let dir = env.node(ROOT, b"dir", DIR, 0o755);
    env.node(dir, b"f", REG, 0o644);
    let mut fds = credentials(500, 500, 500, 500);
    let fd = env
        .ram
        .open_token(&mut fds, dir, proto_fs::READ_ONLY, ROOT_USER)
        .unwrap();
    let generation = env.ram.description_token(&fds, fd).unwrap().generation;
    let access = |base| ChangeStart {
        base,
        ..with_args(ChangeOp::Access, b"f", 0, [0, 0, 0, 0])
    };
    let from = Base::Fd { fd, generation };
    assert_eq!(env.go_result(&mut fds, access(from), None), 0);
    // The mode changes after the descriptor was opened: the next walk sees it.
    env.ram.storage.set_attributes(dir, 0o644, 0, 0).unwrap();
    assert_eq!(
        env.go_result(&mut fds, access(from), None),
        proto_fs::ACCESS_DENIED
    );
    env.ram.storage.set_attributes(dir, 0o711, 0, 0).unwrap();
    assert_eq!(env.go_result(&mut fds, access(from), None), 0);
    // An empty path names the descriptor's own object and asks no search.
    env.ram.storage.set_attributes(dir, 0o644, 0, 0).unwrap();
    let own = ChangeStart {
        base: from,
        ..with_args(ChangeOp::StatVfs, b"", 0, [0; 4])
    };
    assert_eq!(env.go_result(&mut fds, own, None), 0);
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

fn op<'a>(op: ChangeOp, path: &'a [u8]) -> ChangeStart<'a> {
    req(0, 1, op, path)
}
fn with_args<'a>(op_: ChangeOp, path: &'a [u8], flags: u32, args: [u64; 4]) -> ChangeStart<'a> {
    ChangeStart {
        flags,
        args,
        ..req(0, 1, op_, path)
    }
}
const STAMP: Timestamp = Timestamp::legacy_ns(7_000_000_000);

#[test]
fn rename_moves_a_file_keeps_its_inode_and_stamps_what_the_standard_names() {
    let mut env = Env::new();
    let mut fds = session();
    let dir_a = env.node(ROOT, b"a", DIR, 0o755);
    let dir_b = env.node(ROOT, b"b", DIR, 0o755);
    let file = env.node(dir_a, b"f", REG, 0o644);
    let epoch = env.ram.storage.state.epoch;
    let done = env.go(&mut fds, op(ChangeOp::Rename, b"/a/f"), Some(b"/b/g"));
    assert_eq!(done.result, 0);
    assert_eq!(env.lookup(b"/b/g"), Ok(file));
    assert_eq!(env.lookup(b"/a/f"), Err(NO_ENTRY));
    assert_eq!(env.ram.storage.state.epoch, epoch + 1);
    // st_ctime of the node, st_mtime and st_ctime of both parents.
    assert_eq!(env.times(file)[2], STAMP);
    for parent in [dir_a, dir_b] {
        assert_eq!(env.times(parent)[1..], [STAMP; 2]);
    }
    // A name over an existing file replaces it.
    let old = env.node(dir_b, b"h", REG, 0o644);
    let second = env.node(dir_a, b"i", REG, 0o600);
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/a/i"), Some(b"/b/h")),
        0
    );
    assert_eq!(env.lookup(b"/b/h"), Ok(second));
    assert!(env.ram.storage.node(old).map_or(true, |n| n.links == 0));
    // Two names of one inode: nothing happens.
    env.go_result(&mut fds, op(ChangeOp::Link, b"/b/g"), Some(b"/b/g2"));
    let epoch = env.ram.storage.state.epoch;
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/b/g"), Some(b"/b/g2")),
        0
    );
    assert_eq!(env.ram.storage.state.epoch, epoch);
    assert!(env.lookup(b"/b/g").is_ok() && env.lookup(b"/b/g2").is_ok());
    env.assert_quiet();
}

#[test]
fn rename_of_a_directory_follows_the_standard_for_kinds_slashes_and_descendants() {
    let mut env = Env::new();
    let mut fds = session();
    let top = env.node(ROOT, b"top", DIR, 0o755);
    let sub = env.node(top, b"sub", DIR, 0o755);
    let deep = env.node(sub, b"deep", DIR, 0o755);
    env.node(ROOT, b"file", REG, 0o644);
    let empty = env.node(ROOT, b"empty", DIR, 0o755);
    let full = env.node(ROOT, b"full", DIR, 0o755);
    env.node(full, b"x", REG, 0o644);
    let epoch = env.ram.storage.state.epoch;
    let rename = |env: &mut Env, fds: &mut Fds, from: &[u8], to: &[u8]| {
        env.go_result(fds, op(ChangeOp::Rename, from), Some(to))
    };
    use proto_fs::{BUSY, IS_DIRECTORY, NOT_EMPTY};
    assert_eq!(
        rename(&mut env, &mut fds, b"/top", b"/top/sub/deep/x"),
        proto_fs::INVALID_ARGUMENT
    );
    assert_eq!(
        rename(&mut env, &mut fds, b"/top", b"/top/sub"),
        proto_fs::INVALID_ARGUMENT
    );
    assert_eq!(
        rename(&mut env, &mut fds, b"/top/sub", b"/empty/.."),
        proto_fs::INVALID_ARGUMENT
    );
    assert_eq!(
        rename(&mut env, &mut fds, b"/top/.", b"/z"),
        proto_fs::INVALID_ARGUMENT
    );
    assert_eq!(rename(&mut env, &mut fds, b"/", b"/z"), BUSY);
    assert_eq!(rename(&mut env, &mut fds, b"/top", b"/full"), NOT_EMPTY);
    assert_eq!(rename(&mut env, &mut fds, b"/top", b"/file"), NOT_DIRECTORY);
    assert_eq!(rename(&mut env, &mut fds, b"/file", b"/top"), IS_DIRECTORY);
    assert_eq!(rename(&mut env, &mut fds, b"/file/", b"/f2"), NOT_DIRECTORY);
    assert_eq!(rename(&mut env, &mut fds, b"/file", b"/f2/"), NOT_DIRECTORY);
    assert_eq!(rename(&mut env, &mut fds, b"/missing", b"/f2"), NO_ENTRY);
    assert_eq!(
        env.ram.storage.state.epoch, epoch,
        "every refusal left no effect"
    );
    // A directory takes a new name with a slash, and replaces an empty one.
    assert_eq!(rename(&mut env, &mut fds, b"/top/sub", b"/moved/"), 0);
    assert_eq!(env.lookup(b"/moved/deep"), Ok(deep));
    assert_eq!(env.ram.storage.node(sub).unwrap().parent, ROOT);
    assert_eq!(rename(&mut env, &mut fds, b"/moved", b"/empty"), 0);
    assert_eq!(env.lookup(b"/empty/deep"), Ok(deep));
    assert!(env.ram.storage.node(empty).map_or(true, |n| n.links == 0));
    // The link counts follow: top lost a child directory, root gained none overall.
    assert_eq!(env.ram.storage.node(top).unwrap().links, 2);
    env.assert_quiet();
}

#[test]
fn rename_into_a_full_parent_is_emlink_and_a_directory_that_cannot_be_written_stays() {
    let mut env = Env::new();
    let mut root_session = session();
    let target = env.node(ROOT, b"target", DIR, 0o777);
    let src = env.node(ROOT, b"src", DIR, 0o755);
    env.node(src, b"d", DIR, 0o755);
    env.ram.storage.node_mut(target).unwrap().links = u32::MAX;
    assert_eq!(
        env.go_result(
            &mut root_session,
            op(ChangeOp::Rename, b"/src/d"),
            Some(b"/target/d")
        ),
        proto_fs::TOO_MANY_LINKS
    );
    assert!(env.lookup(b"/src/d").is_ok());
    env.ram.storage.node_mut(target).unwrap().links = 2;
    // User 500 may write both parents; the directory it moves refuses writes.
    env.ram.storage.set_attributes(src, 0o777, 0, 0).unwrap();
    let mut user = credentials(500, 500, 500, 500);
    assert_eq!(
        env.go_result(
            &mut user,
            op(ChangeOp::Rename, b"/src/d"),
            Some(b"/target/d")
        ),
        proto_fs::ACCESS_DENIED
    );
    assert!(env.lookup(b"/src/d").is_ok());
    // In one parent the directory keeps its ".." and needs no write.
    assert_eq!(
        env.go_result(&mut user, op(ChangeOp::Rename, b"/src/d"), Some(b"/src/e")),
        0
    );
    let moved = env.lookup(b"/src/e").unwrap();
    env.ram.storage.set_attributes(moved, 0o777, 0, 0).unwrap();
    assert_eq!(
        env.go_result(
            &mut user,
            op(ChangeOp::Rename, b"/src/e"),
            Some(b"/target/e")
        ),
        0
    );
    env.assert_quiet();
}

#[test]
fn sticky_directories_keep_a_file_from_a_user_who_owns_neither() {
    let mut env = Env::new();
    let tmp = env.node(ROOT, b"sticky", DIR, 0o1777);
    let theirs = env.node(tmp, b"theirs", REG, 0o666);
    env.ram
        .storage
        .set_attributes(theirs, 0o666, 100, 100)
        .unwrap();
    let mut other = credentials(200, 200, 200, 200);
    for start in [
        op(ChangeOp::Unlink, b"/sticky/theirs"),
        with_args(
            ChangeOp::Unlink,
            b"/sticky/theirs",
            UNLINK_REMOVEDIR,
            [0; 4],
        ),
    ] {
        let result = env.go_result(&mut other, start, None);
        assert!(result == PERMISSION || result == NOT_DIRECTORY, "{result}");
    }
    assert_eq!(
        env.go_result(
            &mut other,
            op(ChangeOp::Rename, b"/sticky/theirs"),
            Some(b"/sticky/mine")
        ),
        PERMISSION
    );
    assert!(env.lookup(b"/sticky/theirs").is_ok());
    let mut owner = credentials(100, 100, 100, 100);
    assert_eq!(
        env.go_result(&mut owner, op(ChangeOp::Unlink, b"/sticky/theirs"), None),
        0
    );
    env.assert_quiet();
}

#[test]
fn rename_never_follows_its_last_component() {
    let mut env = Env::new();
    let mut fds = session();
    let target = env.node(ROOT, b"target", REG, 0o644);
    let link = env.node(ROOT, b"link", crate::storage::SYMLINK, 0o777);
    env.ram.storage.write(link, FIXTURE, 0, b"target").unwrap();
    let other = env.node(ROOT, b"other", REG, 0o644);
    // The link itself moves.
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/link"), Some(b"/moved")),
        0
    );
    assert_eq!(env.lookup_link(b"/moved"), Ok(link));
    assert_eq!(env.lookup(b"/target"), Ok(target));
    // A file replaces the link at the new name and leaves what it pointed to.
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/other"), Some(b"/moved")),
        0
    );
    assert_eq!(env.lookup_link(b"/moved"), Ok(other));
    assert_eq!(env.ram.storage.node(target).unwrap().links, 1);
    env.assert_quiet();
}

#[test]
fn link_makes_a_second_name_of_the_inode_or_of_the_link_itself() {
    let mut env = Env::new();
    let mut fds = session();
    let dir = env.node(ROOT, b"d", DIR, 0o755);
    let file = env.node(ROOT, b"file", REG, 0o644);
    let link = env.node(ROOT, b"link", crate::storage::SYMLINK, 0o777);
    env.ram.storage.write(link, FIXTURE, 0, b"file").unwrap();
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Link, b"/file"), Some(b"/d/second")),
        0
    );
    assert_eq!(env.lookup(b"/d/second"), Ok(file));
    assert_eq!(env.ram.storage.node(file).unwrap().links, 2);
    // st_ctime of the file, st_mtime and st_ctime of the new parent.
    assert_eq!(env.times(file)[2], STAMP);
    assert_eq!(env.times(dir)[1..], [STAMP; 2]);
    // Without FOLLOW the new name is the link; with it, the file.
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Link, b"/link"), Some(b"/d/of-link")),
        0
    );
    assert_eq!(env.lookup_link(b"/d/of-link"), Ok(link));
    assert_eq!(env.ram.storage.node(link).unwrap().links, 2);
    assert_eq!(
        env.go_result(
            &mut fds,
            with_args(ChangeOp::Link, b"/link", proto_fs::LINK_FOLLOW, [0; 4]),
            Some(b"/d/of-file")
        ),
        0
    );
    assert_eq!(env.lookup_link(b"/d/of-file"), Ok(file));
    // Refusals.
    use proto_fs::ALREADY_EXISTS;
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Link, b"/file"), Some(b"/link")),
        ALREADY_EXISTS
    );
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Link, b"/d"), Some(b"/d2")),
        PERMISSION
    );
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Link, b"/none"), Some(b"/n")),
        NO_ENTRY
    );
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Link, b"/file"), Some(b"/new/")),
        NO_ENTRY
    );
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Link, b"/file/"), Some(b"/new")),
        NOT_DIRECTORY
    );
    env.ram.storage.node_mut(file).unwrap().links = u32::MAX;
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Link, b"/file"), Some(b"/d/third")),
        proto_fs::TOO_MANY_LINKS
    );
    env.ram.storage.node_mut(file).unwrap().links = 2;
    env.assert_quiet();
}

#[test]
fn symlink_keeps_its_contents_raw_and_readlink_returns_them_cut_to_the_buffer() {
    let mut env = Env::new();
    let mut fds = session();
    let dir = env.node(ROOT, b"d", DIR, 0o755);
    let symlink = |path| op(ChangeOp::Symlink, path);
    let readlink = |path, size| with_args(ChangeOp::ReadLink, path, 0, [size, 0, 0, 0]);
    assert_eq!(
        env.go_result(&mut fds, symlink(b"/d/l"), Some(b"../where/to")),
        0
    );
    let token = env.lookup_link(b"/d/l").unwrap();
    assert_eq!(env.times(token), [STAMP; 3]);
    assert_eq!(env.times(dir)[1..], [STAMP; 2]);
    let done = env.go(&mut fds, readlink(b"/d/l", 511), None);
    assert_eq!(
        (done.result, done.bytes.as_slice()),
        (0, b"../where/to".as_slice())
    );
    let done = env.go(&mut fds, readlink(b"/d/l", 5), None);
    assert_eq!(done.bytes.as_slice(), b"../wh");
    // An empty target is kept, and reads back as nothing.
    assert_eq!(env.go_result(&mut fds, symlink(b"/d/empty"), Some(b"")), 0);
    let done = env.go(&mut fds, readlink(b"/d/empty", 10), None);
    assert_eq!((done.result, done.bytes.len()), (0, 0));
    // The longest target.
    let long = [b'x'; 511];
    assert_eq!(env.go_result(&mut fds, symlink(b"/d/long"), Some(&long)), 0);
    let done = env.go(&mut fds, readlink(b"/d/long", 511), None);
    assert_eq!(done.bytes.as_slice(), &long[..]);
    // Refusals: a file is no link, a name exists, a target holds no NUL.
    assert_eq!(
        env.go_result(&mut fds, readlink(b"/d", 10), None),
        proto_fs::INVALID_ARGUMENT
    );
    assert_eq!(
        env.go_result(&mut fds, symlink(b"/d/l"), Some(b"x")),
        proto_fs::ALREADY_EXISTS
    );
    assert_eq!(
        env.go_result(&mut fds, readlink(b"/d/none", 10), None),
        NO_ENTRY
    );
    assert_eq!(
        env.start(
            &mut fds,
            OWNER,
            &ChangeStart {
                key: key(1, 900),
                ..symlink(b"/d/nul")
            }
        ),
        Ok(ChangePhase::AwaitingSecond)
    );
    assert_eq!(
        env.second(&fds, OWNER, key(1, 900), Base::Absolute, b"a\0b"),
        Err(INVALID_ARGUMENT)
    );
    env.release(&mut fds, OWNER, key(1, 900)).unwrap();
    env.assert_quiet();
}

#[test]
fn chmod_chown_and_times_follow_the_ownership_rules() {
    let mut env = Env::new();
    let file = env.node(ROOT, b"f", REG, 0o644);
    env.ram
        .storage
        .set_attributes(file, 0o644, 100, 50)
        .unwrap();
    let chmod = |mode: u64, flags| with_args(ChangeOp::Chmod, b"/f", flags, [mode, 0, 0, 0]);
    let chown = |uid: u64, gid: u64| with_args(ChangeOp::Chown, b"/f", 0, [uid, gid, 0, 0]);
    let times = |a: [u64; 4]| with_args(ChangeOp::Times, b"/f", 0, a);
    let mut owner = credentials(100, 100, 100, 100);
    let mut other = credentials(200, 200, 200, 200);
    // chmod: the owner may, another may not; a group that is not the owner's drops S_ISGID.
    assert_eq!(env.go_result(&mut other, chmod(0o600, 0), None), PERMISSION);
    assert_eq!(env.ram.storage.node(file).unwrap().mode & 0o7777, 0o644);
    assert_eq!(env.go_result(&mut owner, chmod(0o2755, 0), None), 0);
    assert_eq!(
        env.ram.storage.node(file).unwrap().mode & 0o7777,
        0o755,
        "S_ISGID of a foreign group goes"
    );
    assert_eq!(env.times(file)[2], STAMP);
    assert_eq!(env.go_result(&mut owner, chmod(0o4755, 0), None), 0);
    assert_eq!(env.ram.storage.node(file).unwrap().mode & 0o7777, 0o4755);
    // chown: an owner may only pick its own group, and set-id goes with a change.
    assert_eq!(
        env.go_result(&mut owner, chown(200, proto_fs::ID_UNCHANGED), None),
        PERMISSION
    );
    assert_eq!(
        env.go_result(&mut owner, chown(proto_fs::ID_UNCHANGED, 77), None),
        PERMISSION
    );
    assert_eq!(
        env.go_result(&mut owner, chown(proto_fs::ID_UNCHANGED, 100), None),
        0
    );
    let node = *env.ram.storage.node(file).unwrap();
    assert_eq!((node.uid, node.gid, node.mode & 0o7777), (100, 100, 0o755));
    let mut root = session();
    assert_eq!(env.go_result(&mut root, chown(300, 400), None), 0);
    let node = *env.ram.storage.node(file).unwrap();
    assert_eq!((node.uid, node.gid), (300, 400));
    // times: explicit by the owner alone, "now" by write permission, two omissions by anyone.
    let mut owner = credentials(300, 300, 400, 400);
    let explicit = times([5, 6, 7, 8]);
    assert_eq!(env.go_result(&mut other, explicit, None), PERMISSION);
    assert_eq!(env.go_result(&mut owner, explicit, None), 0);
    let t = env.times(file);
    assert_eq!(
        (t[0], t[1]),
        (Timestamp::new(5, 6).unwrap(), Timestamp::new(7, 8).unwrap())
    );
    assert_eq!(t[2], STAMP);
    let now = times([0, proto_fs::TIME_NOW, 0, proto_fs::TIME_NOW]);
    env.ram
        .storage
        .set_attributes(file, 0o644, 300, 400)
        .unwrap();
    assert_eq!(
        env.go_result(&mut other, now, None),
        proto_fs::ACCESS_DENIED
    );
    env.ram
        .storage
        .set_attributes(file, 0o666, 300, 400)
        .unwrap();
    assert_eq!(env.go_result(&mut other, now, None), 0);
    assert_eq!(env.times(file)[..2], [STAMP; 2]);
    // Two omissions need no right and leave st_ctime alone.
    env.ram
        .storage
        .set_attributes(file, 0o600, 300, 400)
        .unwrap();
    let before = env.times(file);
    let epoch = env.ram.storage.state.epoch;
    let omit = times([0, proto_fs::TIME_OMIT, 0, proto_fs::TIME_OMIT]);
    assert_eq!(env.go_result(&mut other, omit, None), 0);
    assert_eq!(env.times(file), before);
    assert_eq!(env.ram.storage.state.epoch, epoch);
    env.assert_quiet();
}

#[test]
fn a_link_has_no_mode_and_utimensat_with_nofollow_stamps_the_link() {
    let mut env = Env::new();
    let mut fds = session();
    let file = env.node(ROOT, b"f", REG, 0o644);
    let link = env.node(ROOT, b"l", crate::storage::SYMLINK, 0o777);
    env.ram.storage.write(link, FIXTURE, 0, b"f").unwrap();
    let chmod = |flags| with_args(ChangeOp::Chmod, b"/l", flags, [0o600, 0, 0, 0]);
    assert_eq!(
        env.go_result(&mut fds, chmod(proto_fs::NOFOLLOW), None),
        proto_fs::NOT_SUPPORTED
    );
    assert_eq!(env.ram.storage.node(link).unwrap().mode & 0o7777, 0o777);
    assert_eq!(
        env.go_result(&mut fds, chmod(0), None),
        0,
        "followed, the file changes"
    );
    assert_eq!(env.ram.storage.node(file).unwrap().mode & 0o7777, 0o600);
    let stamp = with_args(ChangeOp::Times, b"/l", proto_fs::NOFOLLOW, [1, 2, 3, 4]);
    assert_eq!(env.go_result(&mut fds, stamp, None), 0);
    assert_eq!(env.times(link)[0], Timestamp::new(1, 2).unwrap());
    assert_ne!(env.times(file)[0], Timestamp::new(1, 2).unwrap());
    env.assert_quiet();
}

#[test]
fn metadata_by_descriptor_uses_an_empty_path_and_the_description_generation() {
    let mut env = Env::new();
    let mut fds = session();
    let file = env.node(ROOT, b"f", REG, 0o644);
    let fd = env
        .ram
        .open_token(&mut fds, file, proto_fs::READ_ONLY, ROOT_USER)
        .unwrap();
    let generation = env.ram.description_token(&fds, fd).unwrap().generation;
    let fchmod = |generation| ChangeStart {
        base: Base::Fd { fd, generation },
        ..with_args(ChangeOp::Chmod, b"", 0, [0o640, 0, 0, 0])
    };
    assert_eq!(env.go_result(&mut fds, fchmod(generation), None), 0);
    assert_eq!(env.ram.storage.node(file).unwrap().mode & 0o7777, 0o640);
    assert_eq!(
        env.go_result(&mut fds, fchmod(generation + 1), None),
        BAD_FD
    );
    assert_eq!(env.ram.storage.node(file).unwrap().mode & 0o7777, 0o640);
    env.ram.close(&mut fds, fd).unwrap();
    env.assert_quiet();
}

#[test]
fn second_is_repeated_safely_in_every_phase_and_refused_where_it_does_not_belong() {
    let mut env = Env::new();
    let mut fds = session();
    env.node(ROOT, b"f", REG, 0o644);
    let start = ChangeStart {
        key: key(2, 5),
        ..op(ChangeOp::Rename, b"/f")
    };
    assert_eq!(
        env.start(&mut fds, OWNER, &start),
        Ok(ChangePhase::AwaitingSecond)
    );
    // Step before Second advances nothing.
    assert_eq!(
        env.step(&fds, OWNER, start.key).map(|_| ()),
        Err(INVALID_ARGUMENT)
    );
    assert_eq!(
        env.second(&fds, OWNER, start.key, Base::Absolute, b""),
        Err(INVALID_ARGUMENT),
        "an empty second path"
    );
    assert_eq!(
        env.second(&fds, OWNER, start.key, Base::Absolute, b"/g"),
        Ok(())
    );
    assert_eq!(
        env.second(&fds, OWNER, start.key, Base::Absolute, b"/g"),
        Ok(())
    );
    assert_eq!(
        env.second(&fds, OWNER, start.key, Base::Absolute, b"/h"),
        Err(PERMISSION)
    );
    assert_eq!(
        env.second(&fds, OWNER, start.key, Base::Cwd, b"/g"),
        Err(PERMISSION)
    );
    // After the first Step the resolution has begun; a repeat is still 0.
    env.step(&fds, OWNER, start.key).unwrap();
    assert_eq!(
        env.second(&fds, OWNER, start.key, Base::Absolute, b"/g"),
        Ok(())
    );
    let mut done = false;
    for _ in 0..1000 {
        if env.step(&fds, OWNER, start.key).unwrap().0 {
            done = true;
            break;
        }
    }
    assert!(done);
    // After Done as well, and a different one is refused without a change.
    assert_eq!(
        env.second(&fds, OWNER, start.key, Base::Absolute, b"/g"),
        Ok(())
    );
    assert_eq!(
        env.second(&fds, OWNER, start.key, Base::Absolute, b"/x"),
        Err(PERMISSION)
    );
    assert!(env.lookup(b"/g").is_ok() && env.lookup(b"/f").is_err());
    env.release(&mut fds, OWNER, start.key).unwrap();
    // Second for a one-path operation, and for an unknown key.
    let single = ChangeStart {
        key: key(2, 6),
        ..op(ChangeOp::Unlink, b"/g")
    };
    env.start(&mut fds, OWNER, &single).unwrap();
    assert_eq!(
        env.second(&fds, OWNER, single.key, Base::Absolute, b"/y"),
        Err(INVALID_ARGUMENT)
    );
    assert_eq!(
        env.second(&fds, OWNER, key(3, 1), Base::Absolute, b"/y"),
        Err(NO_ENTRY)
    );
    env.release(&mut fds, OWNER, single.key).unwrap();
    // A second path from a bad base ends the job with that result.
    let both = ChangeStart {
        key: key(2, 7),
        ..op(ChangeOp::Link, b"/g")
    };
    env.start(&mut fds, OWNER, &both).unwrap();
    assert_eq!(env.second(&fds, OWNER, both.key, Base::Cwd, b"rel"), Ok(()));
    assert_eq!(env.second(&fds, OWNER, both.key, Base::Cwd, b"rel"), Ok(()));
    let (finished, result, _, _) = env.step(&fds, OWNER, both.key).unwrap();
    assert!(finished && result == BAD_FD);
    env.release(&mut fds, OWNER, both.key).unwrap();
    env.assert_quiet();
}

#[test]
fn a_change_of_the_tree_between_steps_restarts_the_job_and_the_client_sees_only_the_count() {
    let mut env = Env::new();
    let mut fds = session();
    let dir = env.node(ROOT, b"d", DIR, 0o755);
    let file = env.node(dir, b"f", REG, 0o644);
    let start = ChangeStart {
        key: key(4, 1),
        ..op(ChangeOp::Rename, b"/d/f")
    };
    env.start(&mut fds, OWNER, &start).unwrap();
    env.second(&fds, OWNER, start.key, Base::Absolute, b"/d/g")
        .unwrap();
    // Step until the journal is ready to publish.
    let phase = |env: &Env| match &env.jobs.iter().flatten().next().unwrap().operation {
        JobOperation::Change(change) => change.phase(),
        _ => unreachable!(),
    };
    let mut steps = 0;
    while phase(&env) != ChangePhase::Ready {
        steps += 1;
        assert!(steps < 200);
        let (done, ..) = env.step(&fds, OWNER, start.key).unwrap();
        assert!(!done);
    }
    // Another client changes the tree: a new name in the root.
    env.node(ROOT, b"unrelated", REG, 0o644);
    let mut restarts = 0;
    for _ in 0..1000 {
        match env.step(&fds, OWNER, start.key) {
            Ok((true, result, count, _)) => {
                assert_eq!(result, 0);
                restarts = count;
                break;
            }
            Ok((false, result, count, bytes)) => {
                assert_eq!((result, bytes.len()), (0, 0));
                restarts = count;
            }
            Err(code) => panic!("status {code}: the client must never see STALE_PROOF"),
        }
    }
    assert_eq!(restarts, 1);
    assert_eq!(env.lookup(b"/d/g"), Ok(file));
    env.release(&mut fds, OWNER, start.key).unwrap();
    env.assert_quiet();
}

#[test]
fn release_gives_back_a_prepared_rename_over_a_directory_in_one_call() {
    let mut env = Env::new();
    let mut fds = session();
    // Two directories of the boot tree: every name and inode of both is staged.
    let tmp = env.node(ROOT, b"dst", DIR, 0o755);
    let etc = env.lookup(b"/etc").unwrap();
    let start = ChangeStart {
        key: key(6, 1),
        ..op(ChangeOp::Rename, b"/etc")
    };
    env.start(&mut fds, OWNER, &start).unwrap();
    env.second(&fds, OWNER, start.key, Base::Absolute, b"/dst")
        .unwrap();
    let phase = |env: &Env| match &env.jobs.iter().flatten().next().unwrap().operation {
        JobOperation::Change(change) => change.phase(),
        _ => unreachable!(),
    };
    let mut steps = 0;
    while phase(&env) != ChangePhase::Ready {
        steps += 1;
        assert!(steps < 200);
        let (done, result, ..) = env.step(&fds, OWNER, start.key).unwrap();
        assert!(!done, "the rename ends with {result}");
    }
    let before = env.ram.storage.usage(BOOT_ROOT);
    assert!(before.dentries >= 2 && before.inodes >= 1, "{before:?}");
    let epoch = env.ram.storage.state.epoch;
    env.release(&mut fds, OWNER, start.key).unwrap();
    assert_eq!(env.ram.storage.usage(BOOT_ROOT), Default::default());
    assert_eq!(env.ram.storage.state.epoch, epoch);
    env.assert_quiet();
    assert_eq!(env.lookup(b"/etc"), Ok(etc));
    assert_eq!(env.lookup(b"/dst"), Ok(tmp));
}

#[test]
#[should_panic(expected = "a step of a cancel was refused")]
fn a_refused_step_of_a_cancel_stops_a_debug_build_and_is_counted() {
    let mut env = Env::new();
    let mut fds = session();
    env.node(ROOT, b"dst", DIR, 0o755);
    let start = ChangeStart {
        key: key(6, 1),
        ..op(ChangeOp::Rename, b"/etc")
    };
    env.start(&mut fds, OWNER, &start).unwrap();
    env.second(&fds, OWNER, start.key, Base::Absolute, b"/dst")
        .unwrap();
    let phase = |env: &Env| match &env.jobs.iter().flatten().next().unwrap().operation {
        JobOperation::Change(change) => change.phase(),
        _ => unreachable!(),
    };
    while phase(&env) != ChangePhase::Ready {
        env.step(&fds, OWNER, start.key).unwrap();
    }
    // Something else lets go of the pins held on /etc: the cancel of the
    // job finds them gone.
    let etc = env.lookup(b"/etc").unwrap();
    let pending = env.ram.storage.node(etc).unwrap().pins[crate::storage::Pin::Pending as usize];
    for _ in 0..pending {
        env.ram
            .storage
            .unpin(etc, crate::storage::Pin::Pending)
            .unwrap();
    }
    let _ = env.release(&mut fds, OWNER, start.key);
}

#[test]
#[should_panic(expected = "a step of a cancel was refused")]
fn a_refused_rewind_of_a_restart_stops_a_debug_build_and_is_counted() {
    let mut env = Env::new();
    let mut fds = session();
    env.node(ROOT, b"dst", DIR, 0o755);
    let start = ChangeStart {
        key: key(6, 1),
        ..op(ChangeOp::Rename, b"/etc")
    };
    env.start(&mut fds, OWNER, &start).unwrap();
    env.second(&fds, OWNER, start.key, Base::Absolute, b"/dst")
        .unwrap();
    while phase_of(&env) != ChangePhase::Ready {
        env.step(&fds, OWNER, start.key).unwrap();
    }
    // Something else lets go of the pin the walk holds on /etc, and the tree
    // changes: the step finds the proof stale, the cancel of the journal
    // goes well and the rewind of the walk finds its pin gone.
    let etc = env.lookup(b"/etc").unwrap();
    env.ram
        .storage
        .unpin(etc, crate::storage::Pin::Pending)
        .unwrap();
    env.node(ROOT, b"foreign", REG, 0o644);
    let _ = env.step(&fds, OWNER, start.key);
}

#[test]
fn an_unknown_second_path_component_ends_the_job_with_the_result_of_the_walk() {
    let mut env = Env::new();
    let mut fds = session();
    env.node(ROOT, b"f", REG, 0o644);
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/f"), Some(b"/nodir/g")),
        NO_ENTRY
    );
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/f"), Some(b"/f/g")),
        NOT_DIRECTORY
    );
    assert!(env.lookup(b"/f").is_ok());
    env.assert_quiet();
}

#[test]
fn unlink_rmdir_and_mkdir_stamp_the_nodes_the_standard_names_and_a_refusal_stamps_nothing() {
    let mut env = Env::new();
    let mut fds = session();
    let dir = env.node(ROOT, b"d", DIR, 0o755);
    let file = env.node(dir, b"f", REG, 0o644);
    env.go_result(&mut fds, op(ChangeOp::Link, b"/d/f"), Some(b"/d/g"));
    let before = [env.times(dir), env.times(file)];
    // A refusal changes no time.
    let refused = op(ChangeOp::Unlink, b"/d/none");
    assert_eq!(env.go_result(&mut fds, refused, None), NO_ENTRY);
    assert_eq!([env.times(dir), env.times(file)], before);
    // Unlink: st_mtime and st_ctime of the parent, st_ctime of a file that stays.
    env.ram.storage.node_mut(dir).unwrap().times = [Timestamp::ZERO; 3];
    env.ram.storage.node_mut(file).unwrap().times = [Timestamp::ZERO; 3];
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Unlink, b"/d/g"), None),
        0
    );
    assert_eq!(env.times(dir), [Timestamp::ZERO, STAMP, STAMP]);
    assert_eq!(env.times(file), [Timestamp::ZERO, Timestamp::ZERO, STAMP]);
    // mkdir: the three times of the new node, mtime and ctime of the parent.
    env.ram.storage.node_mut(dir).unwrap().times = [Timestamp::ZERO; 3];
    assert_eq!(
        env.go_result(&mut fds, mkdir(0, 1, b"/d/sub", 0o755, 0), None),
        0
    );
    let sub = env.lookup(b"/d/sub").unwrap();
    assert_eq!(env.times(sub), [STAMP; 3]);
    assert_eq!(env.times(dir), [Timestamp::ZERO, STAMP, STAMP]);
    // rmdir: the parent.
    env.ram.storage.node_mut(dir).unwrap().times = [Timestamp::ZERO; 3];
    let rmdir = with_args(ChangeOp::Unlink, b"/d/sub", UNLINK_REMOVEDIR, [0; 4]);
    assert_eq!(env.go_result(&mut fds, rmdir, None), 0);
    assert_eq!(env.times(dir), [Timestamp::ZERO, STAMP, STAMP]);
    env.assert_quiet();
}

#[test]
fn an_unstable_clock_defers_the_effect_and_the_step_goes_on_without_one() {
    let mut env = Env::new();
    let mut fds = session();
    let start = mkdir(0, 1, b"/late", 0o755, 0);
    env.start(&mut fds, OWNER, &start).unwrap();
    env.clock.0.set(None);
    let epoch = env.ram.storage.state.epoch;
    // The walk takes its steps (8 names each); then the job waits for a time.
    for _ in 0..300 {
        let (done, ..) = env.step(&fds, OWNER, start.key).unwrap();
        assert!(!done, "no effect without a time");
    }
    assert_eq!(env.ram.storage.state.epoch, epoch);
    let phase = match &env.jobs.iter().flatten().next().unwrap().operation {
        JobOperation::Change(change) => change.phase(),
        _ => unreachable!(),
    };
    assert_eq!(phase, ChangePhase::Ready);
    env.clock.0.set(Some(Env::now()));
    let (done, result, ..) = env.step(&fds, OWNER, start.key).unwrap();
    assert!(done && result == 0);
    assert!(env.lookup(b"/late").is_ok());
    env.release(&mut fds, OWNER, start.key).unwrap();
    env.assert_quiet();
}

fn words(bytes: &[u8]) -> Vec<u64> {
    assert_eq!(bytes.len(), proto_fs::STATVFS_BYTES);
    bytes
        .chunks(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

#[test]
fn statvfs_needs_only_search_in_the_ancestors_and_counts_the_free_inodes() {
    let mut env = Env::new();
    let dir = env.node(ROOT, b"d", DIR, 0o755);
    let sealed = env.node(dir, b"sealed", REG, 0o000);
    let hidden = env.node(ROOT, b"hidden", DIR, 0o700);
    env.node(hidden, b"inside", REG, 0o644);
    let mut user = credentials(500, 500, 500, 500);
    let stat = |path| op(ChangeOp::StatVfs, path);
    // A file nobody may open answers, because only the search in "/d" counts.
    let done = env.go(&mut user, stat(b"/d/sealed"), None);
    assert_eq!(done.result, 0);
    let before = words(&done.bytes);
    let info = env.ram.storage.filesystem_information(user.root);
    assert_eq!(
        before,
        [
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
            info.name_max
        ]
    );
    assert_eq!((before[0], before[10]), (4096, 255));
    let _ = sealed;
    // A directory the user cannot search refuses before the file is looked at.
    assert_eq!(
        env.go_result(&mut user, stat(b"/hidden/inside"), None),
        proto_fs::ACCESS_DENIED
    );
    // One more directory is one free inode less.
    assert_eq!(
        env.go_result(&mut user, mkdir(0, 1, b"/d/new", 0o777, 0), None),
        proto_fs::ACCESS_DENIED,
        "no write permission in /d"
    );
    env.ram.storage.set_attributes(dir, 0o777, 0, 0).unwrap();
    assert_eq!(
        env.go_result(&mut user, mkdir(0, 1, b"/d/new", 0o777, 0), None),
        0
    );
    let after = words(&env.go(&mut user, stat(b"/d/sealed"), None).bytes);
    assert_eq!(after[6], before[6] - 1, "f_ffree");
    assert_eq!(after[2], before[2], "f_blocks");
    // By descriptor, with the generation of the description.
    let fd = env
        .ram
        .open_token(&mut user, dir, proto_fs::READ_ONLY, ROOT_USER)
        .unwrap();
    let generation = env.ram.description_token(&user, fd).unwrap().generation;
    let by_fd = |generation| ChangeStart {
        base: Base::Fd { fd, generation },
        ..stat(b"")
    };
    assert_eq!(
        words(&env.go(&mut user, by_fd(generation), None).bytes),
        after
    );
    assert_eq!(
        env.go_result(&mut user, by_fd(generation + 1), None),
        BAD_FD
    );
    env.ram.close(&mut user, fd).unwrap();
    env.assert_quiet();
}

#[test]
fn path_answers_the_canonical_name_without_links_dots_or_dotdots() {
    use proto_fs::{PATH_FOLLOW_LAST, PATH_REQUIRE_DIR};
    let mut env = Env::new();
    let mut fds = session();
    let p = env.node(ROOT, b"p", DIR, 0o755);
    let q = env.node(p, b"q", DIR, 0o755);
    env.node(q, b"f", REG, 0o644);
    let l = env.node(p, b"l", crate::storage::SYMLINK, 0o777);
    env.ram.storage.write(l, FIXTURE, 0, b"q").unwrap();
    let up = env.node(q, b"up", crate::storage::SYMLINK, 0o777);
    env.ram.storage.write(up, FIXTURE, 0, b"../..").unwrap();
    env.node(ROOT, b"rootfile", REG, 0o644);
    let path = |path, flags| with_args(ChangeOp::Path, path, flags, [0; 4]);
    let real = |env: &mut Env, fds: &mut Fds, p, flags| {
        let done = env.go(fds, path(p, flags), None);
        (
            done.result,
            std::string::String::from_utf8(done.bytes).unwrap(),
        )
    };
    let follow = PATH_FOLLOW_LAST;
    assert_eq!(
        real(&mut env, &mut fds, b"/p/l/f", follow),
        (0, "/p/q/f".into())
    );
    assert_eq!(
        real(&mut env, &mut fds, b"/p/l", follow),
        (0, "/p/q".into())
    );
    assert_eq!(
        real(&mut env, &mut fds, b"/p/l", 0),
        (0, "/p/l".into()),
        "the link itself"
    );
    assert_eq!(
        real(&mut env, &mut fds, b"/p/q/.", follow),
        (0, "/p/q".into())
    );
    assert_eq!(
        real(&mut env, &mut fds, b"/p/q/../q/f", follow),
        (0, "/p/q/f".into())
    );
    assert_eq!(
        real(&mut env, &mut fds, b"/p/q/up", follow),
        (0, "/".into())
    );
    assert_eq!(real(&mut env, &mut fds, b"/", follow), (0, "/".into()));
    assert_eq!(
        real(&mut env, &mut fds, b"//rootfile", follow),
        (0, "/rootfile".into())
    );
    assert_eq!(
        real(&mut env, &mut fds, b"/p/none", follow),
        (NO_ENTRY, "".into())
    );
    assert_eq!(
        real(&mut env, &mut fds, b"/p/q/f/", follow),
        (NOT_DIRECTORY, "".into())
    );
    // The physical path follows a rename of an ancestor.
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/p"), Some(b"/moved")),
        0
    );
    assert_eq!(
        real(&mut env, &mut fds, b"/moved/l/f", follow),
        (0, "/moved/q/f".into())
    );
    // REQUIRE_DIR: a file is not a directory, a directory without search is refused.
    assert_eq!(
        real(&mut env, &mut fds, b"/moved/q/f", PATH_REQUIRE_DIR),
        (NOT_DIRECTORY, "".into())
    );
    assert_eq!(
        real(&mut env, &mut fds, b"/moved/q", PATH_REQUIRE_DIR),
        (0, "/moved/q".into())
    );
    env.ram.storage.set_attributes(q, 0o600, 0, 0).unwrap();
    let mut user = credentials(500, 500, 500, 500);
    let (result, _) = real(&mut env, &mut user, b"/moved/q", PATH_REQUIRE_DIR);
    assert_eq!(result, proto_fs::ACCESS_DENIED);
    // The final name needs no right of its own; the directories passed through do.
    assert_eq!(
        real(&mut env, &mut user, b"/moved/l", follow),
        (0, "/moved/q".into())
    );
    let (result, _) = real(&mut env, &mut user, b"/moved/l/f", follow);
    assert_eq!(result, proto_fs::ACCESS_DENIED, "q cannot be searched");
    env.assert_quiet();
}

#[test]
fn path_by_descriptor_and_a_name_past_the_limit() {
    use proto_fs::{PATH_FOLLOW_LAST, PATH_REQUIRE_DIR};
    let mut env = Env::new();
    let mut fds = session();
    let long = std::vec![b'a'; 255];
    let first = env.node(ROOT, &long, DIR, 0o755);
    let second_name = std::vec![b'b'; 255];
    env.node(first, &second_name, DIR, 0o755);
    let file = env.node(ROOT, b"file", REG, 0o644);
    let fd = env
        .ram
        .open_token(&mut fds, first, proto_fs::READ_ONLY, ROOT_USER)
        .unwrap();
    let generation = env.ram.description_token(&fds, fd).unwrap().generation;
    let at = |path, flags, generation| ChangeStart {
        base: Base::Fd { fd, generation },
        ..with_args(ChangeOp::Path, path, flags, [0; 4])
    };
    // fchdir: the canonical path of the directory the descriptor names.
    let done = env.go(&mut fds, at(b"", PATH_REQUIRE_DIR, generation), None);
    let mut expected = std::vec![b'/'];
    expected.extend_from_slice(&long);
    assert_eq!((done.result, done.bytes), (0, expected.clone()));
    assert_eq!(
        env.go_result(&mut fds, at(b"", PATH_REQUIRE_DIR, generation + 1), None),
        BAD_FD
    );
    // Relative to it, with the name past 511 bytes: 1 + 255 + 1 + 255 = 512.
    assert_eq!(
        env.go_result(
            &mut fds,
            at(&second_name, PATH_FOLLOW_LAST, generation),
            None
        ),
        proto_fs::NAME_TOO_LONG
    );
    // A short name past the same directory fits.
    assert_eq!(
        env.go(&mut fds, at(b".", PATH_FOLLOW_LAST, generation), None)
            .bytes,
        expected
    );
    // A file descriptor with REQUIRE_DIR is NOT_DIRECTORY.
    let file_fd = env
        .ram
        .open_token(&mut fds, file, proto_fs::READ_ONLY, ROOT_USER)
        .unwrap();
    let file_generation = env.ram.description_token(&fds, file_fd).unwrap().generation;
    let on_file = ChangeStart {
        base: Base::Fd {
            fd: file_fd,
            generation: file_generation,
        },
        ..with_args(ChangeOp::Path, b"", PATH_REQUIRE_DIR, [0; 4])
    };
    assert_eq!(env.go_result(&mut fds, on_file, None), NOT_DIRECTORY);
    env.ram.close(&mut fds, fd).unwrap();
    env.ram.close(&mut fds, file_fd).unwrap();
    env.assert_quiet();
}

#[test]
fn the_base_of_a_resolve_or_an_open_names_a_descriptor_a_node_or_the_reserved_directory() {
    let mut env = Env::new();
    let mut fds = session();
    let dir = env.node(ROOT, b"d", DIR, 0o755);
    let file = env.node(dir, b"f", REG, 0o644);
    let fd = env
        .ram
        .open_token(&mut fds, dir, proto_fs::READ_ONLY, ROOT_USER)
        .unwrap();
    let generation = env.ram.description_token(&fds, fd).unwrap().generation;
    let base = |env: &Env, slot, generation, relative| {
        env.ram.request_base(&fds, slot, generation, relative)
    };
    // The new form: bit 31, the descriptor, the generation of its description.
    assert_eq!(base(&env, fd | 1 << 31, generation, true), Ok(dir));
    assert_eq!(base(&env, fd | 1 << 31, generation + 1, true), Err(BAD_FD));
    assert_eq!(
        base(&env, (fd + 1) | 1 << 31, generation, true),
        Err(BAD_FD)
    );
    // The reserved value is the current directory of the session: BAD_FD.
    assert_eq!(base(&env, proto_fs::BASE_CWD, 0, true), Err(BAD_FD));
    assert_eq!(base(&env, proto_fs::BASE_ABSOLUTE, 0, true), Err(BAD_FD));
    // A reserved value with a generation is malformed, as in the Change codec.
    assert_eq!(
        base(&env, proto_fs::BASE_CWD, 1, true),
        Err(proto_wire::BAD_SIZE)
    );
    assert_eq!(
        base(&env, proto_fs::BASE_ABSOLUTE, 1, true),
        Err(proto_wire::BAD_SIZE)
    );
    // The earlier form: the root token, and a token of a directory the session holds.
    assert_eq!(base(&env, 0, 1, true), Ok(ROOT));
    assert_eq!(
        base(&env, u32::from(dir.slot), dir.generation, true),
        Ok(dir)
    );
    assert_eq!(
        base(&env, u32::from(file.slot), file.generation, true),
        Err(BAD_FD),
        "a file is no base in the earlier form"
    );
    // An absolute path asks nothing of the base.
    assert!(base(&env, proto_fs::BASE_CWD, 0, false).is_ok());
    env.ram.close(&mut fds, fd).unwrap();
}

fn phase_of(env: &Env) -> ChangePhase {
    match &env.jobs.iter().flatten().next().unwrap().operation {
        JobOperation::Change(change) => change.phase(),
        _ => unreachable!(),
    }
}

#[test]
fn a_change_during_the_walk_counts_one_restart_and_the_answer_is_the_same() {
    let mut env = Env::new();
    let mut fds = session();
    let one = env.node(ROOT, b"one", DIR, 0o755);
    let two = env.node(one, b"two", DIR, 0o755);
    env.node(two, b"three", DIR, 0o755);
    let start = mkdir(7, 1, b"/one/two/three/walked", 0o755, 0);
    env.start(&mut fds, OWNER, &start).unwrap();
    // The walk is under way: a component takes a step.
    for _ in 0..2 {
        let (done, _, restarts, _) = env.step(&fds, OWNER, start.key).unwrap();
        assert!(!done && restarts == 0);
    }
    assert_eq!(phase_of(&env), ChangePhase::Resolving);
    env.node(ROOT, b"foreign", REG, 0o644);
    let mut last = 0;
    for _ in 0..2000 {
        let (done, result, restarts, _) = env.step(&fds, OWNER, start.key).unwrap();
        last = restarts;
        if done {
            assert_eq!(result, 0);
            break;
        }
    }
    assert_eq!(last, 1);
    assert!(env.lookup(b"/one/two/three/walked").is_ok());
    env.release(&mut fds, OWNER, start.key).unwrap();
    env.assert_quiet();
}

#[test]
fn a_change_after_the_reservation_gives_the_reservation_back_and_the_job_goes_on() {
    let mut env = Env::new();
    let mut fds = session();
    let start = mkdir(7, 1, b"/reserved", 0o755, 0);
    env.start(&mut fds, OWNER, &start).unwrap();
    let mut steps = 0;
    while env.ram.storage.usage(BOOT_ROOT).dentries == 0 {
        steps += 1;
        assert!(steps < 500);
        env.step(&fds, OWNER, start.key).unwrap();
    }
    assert_eq!(env.lookup(b"/reserved"), Err(NO_ENTRY), "not published");
    env.node(ROOT, b"foreign", REG, 0o644);
    let mut restarts = 0;
    for _ in 0..3000 {
        let (done, result, count, _) = env.step(&fds, OWNER, start.key).unwrap();
        restarts = count;
        if done {
            assert_eq!(result, 0);
            break;
        }
    }
    assert_eq!(restarts, 1);
    let made = env.lookup(b"/reserved").unwrap();
    assert_eq!(env.ram.storage.node(made).unwrap().kind, DIR);
    // One directory is paid for, and only one: the first reservation went back
    // (its inode is reclaimed by the service's maintenance, a step at a time).
    while env.ram.storage.reclaim_step() {}
    let mut plain = Env::new();
    let mut other = session();
    plain.go(&mut other, mkdir(7, 1, b"/reserved", 0o755, 0), None);
    assert_eq!(
        env.ram.storage.usage(BOOT_ROOT),
        plain.ram.storage.usage(BOOT_ROOT)
    );
    env.release(&mut fds, OWNER, start.key).unwrap();
    env.assert_quiet();
}

/// `count` more names of one file in the root directory, over several roots
/// because a root may hold only part of the table.
fn fill_names(env: &mut Env, prefix: &str, count: usize) {
    let seed = env.node(ROOT, std::format!("{prefix}seed").as_bytes(), REG, 0o644);
    for i in 0..count {
        let root = Root {
            id: 100 + (i / 200) as u64,
            generation: 1,
        };
        let name = std::format!("{prefix}{i}");
        env.ram
            .storage
            .link(root, ROOT, name.as_bytes(), seed)
            .unwrap();
    }
}

/// Every name goes into one bucket while the guard lives.
struct OneBucket;
impl OneBucket {
    fn new() -> Self {
        crate::storage::tests_support::FORCED_BUCKET.with(|b| b.set(Some(5)));
        Self
    }
}
impl Drop for OneBucket {
    fn drop(&mut self) {
        crate::storage::tests_support::FORCED_BUCKET.with(|b| b.set(None));
    }
}

/// Steps of the walk of `path` to its end, found or missing.
fn walk_steps(env: &mut Env, path: &[u8]) -> (usize, Result<Progress, u32>) {
    let mut walk = Resolve::new(&mut env.ram.storage, path, ROOT, ROOT_USER, true).unwrap();
    let mut steps = 0;
    let end = loop {
        steps += 1;
        assert!(steps < 20_000);
        match walk.step(&mut env.ram.storage, ROOT_USER) {
            Ok(Progress::More) => {}
            other => break other,
        }
    };
    walk.release(&mut env.ram.storage);
    (steps, end)
}

#[test]
fn the_name_index_follows_create_unlink_link_and_every_kind_of_rename() {
    let mut env = Env::new();
    let mut fds = session();
    let a = env.node(ROOT, b"a", DIR, 0o755);
    let b = env.node(ROOT, b"b", DIR, 0o755);
    let f = env.node(a, b"f", REG, 0o644);
    env.ram.storage.check_name_index();
    assert_eq!(env.lookup(b"/a/f"), Ok(f));
    // A name moved to another directory is found there and not in the old one.
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/a/f"), Some(b"/b/g")),
        0
    );
    env.ram.storage.check_name_index();
    assert_eq!(env.lookup(b"/b/g"), Ok(f));
    assert_eq!(env.lookup(b"/a/f"), Err(NO_ENTRY));
    // A second name, then the first one goes.
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Link, b"/b/g"), Some(b"/a/h")),
        0
    );
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Unlink, b"/b/g"), None),
        0
    );
    env.ram.storage.check_name_index();
    assert_eq!(env.lookup(b"/b/g"), Err(NO_ENTRY));
    assert_eq!(env.lookup(b"/a/h"), Ok(f));
    // A name replaced by a rename: the victim leaves, the source arrives.
    let victim = env.node(b, b"v", REG, 0o644);
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/a/h"), Some(b"/b/v")),
        0
    );
    env.ram.storage.check_name_index();
    assert_eq!(env.lookup(b"/b/v"), Ok(f));
    assert_ne!(env.lookup(b"/b/v"), Ok(victim));
    assert_eq!(env.lookup(b"/a/h"), Err(NO_ENTRY));
    // A directory moves, and a name of the image does too.
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/a"), Some(b"/b/a2")),
        0
    );
    env.ram.storage.check_name_index();
    assert!(env.lookup(b"/b/a2").is_ok() && env.lookup(b"/a").is_err());
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/tmp/probe"), Some(b"/b/p")),
        0
    );
    env.ram.storage.check_name_index();
    assert!(env.lookup(b"/b/p").is_ok() && env.lookup(b"/tmp/probe").is_err());
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Unlink, b"/etc/motd"), None),
        0
    );
    env.ram.storage.check_name_index();
    assert_eq!(env.lookup(b"/etc/motd"), Err(NO_ENTRY));
    // A reserved name is no name for anyone else until it is published.
    let r = env
        .ram
        .storage
        .reserve(FIXTURE, ROOT, b"pending", (REG, 0o644, 0, 0))
        .unwrap();
    env.ram.storage.check_name_index();
    assert_eq!(env.lookup(b"/pending"), Err(NO_ENTRY));
    env.ram.storage.commit(r).unwrap();
    env.ram.storage.check_name_index();
    assert!(env.lookup(b"/pending").is_ok());
    let r = env
        .ram
        .storage
        .reserve(FIXTURE, ROOT, b"given-back", (REG, 0o644, 0, 0))
        .unwrap();
    env.ram.storage.cancel(r).unwrap();
    env.ram.storage.check_name_index();
    assert_eq!(env.lookup(b"/given-back"), Err(NO_ENTRY));
    env.assert_quiet();
}

#[test]
fn all_names_in_one_bucket_cost_no_more_steps_than_the_scan_of_the_table() {
    let _one = OneBucket::new();
    let mut env = Env::new();
    fill_names(&mut env, "n", crate::storage::DENTRIES - 2);
    env.ram.storage.check_name_index();
    let entries = env.ram.storage.entries();
    let (missing, end) = walk_steps(&mut env, b"/absent");
    assert!(matches!(end, Err(NO_ENTRY)));
    assert!(
        missing <= entries / 8 + 1,
        "{missing} steps, {entries} entries"
    );
    let (last, end) = walk_steps(&mut env, b"/n0");
    assert!(matches!(end, Ok(Progress::Found(_))));
    assert!(last <= entries / 8 + 2);
    // Names go from the middle and the ends of the chain.
    let mut fds = session();
    for name in [&b"/n0"[..], b"/n250", b"/n509"] {
        assert_eq!(env.go_result(&mut fds, op(ChangeOp::Unlink, name), None), 0);
        env.ram.storage.check_name_index();
        assert_eq!(env.lookup(name), Err(NO_ENTRY));
    }
}

#[test]
fn the_names_of_a_full_image_and_a_full_table_are_one_chain_in_the_worst_case() {
    use bootimg::rootfs::{Entry, REGULAR};
    let _one = OneBucket::new();
    let paths: Vec<std::string::String> = (0..bootimg::rootfs::ENTRIES_MAX)
        .map(|i| std::format!("/i{i}"))
        .collect();
    let entries: Vec<Entry<'_>> = paths
        .iter()
        .map(|path| Entry {
            path,
            mode: REGULAR | 0o644,
            uid: 0,
            gid: 0,
            file: 1,
        })
        .collect();
    let image: &'static [u8] = std::vec::Vec::leak(crate::tree::test_image(&entries));
    let index: &'static mut crate::tree::Index = Box::leak(Box::new(crate::tree::Index::new()));
    let tree = crate::tree::load(image, index).unwrap();
    let mut env = Env::new();
    env.ram = Ram::with_tree(Timestamp::legacy_ns(1), tree);
    env.ram.storage.node_mut(ROOT).unwrap().mode = 0o777;
    fill_names(&mut env, "d", crate::storage::DENTRIES - 2);
    env.ram.storage.check_name_index();
    let total = env.ram.storage.entries();
    let (missing, end) = walk_steps(&mut env, b"/absent");
    assert!(matches!(end, Err(NO_ENTRY)));
    // The scan of the table took entries / 8 steps for a miss.
    assert!(missing <= total / 8 + 1, "{missing} steps, {total} entries");
    std::println!("one bucket, {total} names: a miss takes {missing} steps");
}

#[test]
fn a_miss_and_a_hit_take_one_step_a_component_with_ordinary_chains() {
    let mut env = Env::new();
    fill_names(&mut env, "file-", crate::storage::DENTRIES - 2);
    env.ram.storage.check_name_index();
    let (missing, end) = walk_steps(&mut env, b"/absent");
    assert!(matches!(end, Err(NO_ENTRY)));
    assert!(missing <= 2, "{missing}");
    let (hit, end) = walk_steps(&mut env, b"/file-100");
    assert!(matches!(end, Ok(Progress::Found(_))));
    assert!(hit <= 3, "{hit}");
}

fn rmdir_op(path: &[u8]) -> ChangeStart<'_> {
    with_args(ChangeOp::Unlink, path, UNLINK_REMOVEDIR, [0; 4])
}

#[test]
fn the_count_of_names_decides_rmdir_and_follows_every_change() {
    let mut env = Env::new();
    let mut fds = session();
    let d = env.node(ROOT, b"d", DIR, 0o755);
    let e = env.node(ROOT, b"e", DIR, 0o755);
    let names = |env: &Env, t: Token| env.ram.storage.node(t).unwrap().names;
    assert_eq!((names(&env, d), names(&env, e)), (0, 0));
    env.node(d, b"x", REG, 0o644);
    env.node(d, b"y", REG, 0o644);
    env.node(d, b"sub", DIR, 0o755);
    assert_eq!(names(&env, d), 3);
    assert_eq!(
        env.go_result(&mut fds, rmdir_op(b"/d"), None),
        proto_fs::NOT_EMPTY
    );
    // A name between directories moves one count; a replaced name takes none.
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/d/x"), Some(b"/e/x")),
        0
    );
    assert_eq!((names(&env, d), names(&env, e)), (2, 1));
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Link, b"/e/x"), Some(b"/e/x2")),
        0
    );
    assert_eq!(names(&env, e), 2);
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/e/x2"), Some(b"/d/y")),
        0
    );
    assert_eq!((names(&env, d), names(&env, e)), (2, 1));
    // A directory moves with its own count.
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/d/sub"), Some(b"/e/sub")),
        0
    );
    assert_eq!((names(&env, d), names(&env, e)), (1, 2));
    // The last name goes, and the empty directory goes with rmdir.
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Unlink, b"/d/y"), None),
        0
    );
    assert_eq!(names(&env, d), 0);
    assert_eq!(env.go_result(&mut fds, rmdir_op(b"/d"), None), 0);
    assert_eq!(env.lookup(b"/d"), Err(NO_ENTRY));
    // A directory of the image: its names are counted at the start.
    let tmp = env.lookup(b"/tmp").unwrap();
    assert_eq!(names(&env, tmp), 1);
    assert_eq!(
        env.go_result(&mut fds, rmdir_op(b"/tmp"), None),
        proto_fs::NOT_EMPTY
    );
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Unlink, b"/tmp/probe"), None),
        0
    );
    assert_eq!(names(&env, tmp), 0);
    assert_eq!(env.go_result(&mut fds, rmdir_op(b"/tmp"), None), 0);
    env.assert_quiet();
}

#[test]
fn rmdir_and_unlink_take_a_few_steps_however_many_names_the_table_holds() {
    let mut env = Env::new();
    let mut fds = session();
    fill_names(&mut env, "pad", 400);
    let d = env.node(ROOT, b"d", DIR, 0o755);
    env.node(d, b"a", REG, 0o644);
    let unlink = env.go(&mut fds, op(ChangeOp::Unlink, b"/d/a"), None);
    assert_eq!(unlink.result, 0);
    let rmdir = env.go(&mut fds, rmdir_op(b"/d"), None);
    assert_eq!(rmdir.result, 0);
    std::println!("unlink {} steps, rmdir {} steps", unlink.steps, rmdir.steps);
    assert!(unlink.steps <= 10, "{}", unlink.steps);
    assert!(rmdir.steps <= unlink.steps + 1, "{}", rmdir.steps);
    env.assert_quiet();
}

#[test]
fn path_follows_the_back_reference_of_a_renamed_directory_in_one_step_a_level() {
    let mut env = Env::new();
    let mut fds = session();
    let mut parent = ROOT;
    let mut text = std::string::String::new();
    for level in 0..64 {
        let name = std::format!("l{level}");
        parent = env.node(parent, name.as_bytes(), DIR, 0o755);
        text.push('/');
        text.push_str(&name);
    }
    let path = with_args(
        ChangeOp::Path,
        text.as_bytes(),
        proto_fs::PATH_FOLLOW_LAST,
        [0; 4],
    );
    let done = env.go(&mut fds, path, None);
    assert_eq!(done.result, 0);
    assert_eq!(done.bytes, text.as_bytes());
    std::println!("path of depth 64: {} steps", done.steps);
    assert!(done.steps <= 200, "{}", done.steps);
    // A directory of the image renamed: the new entry names it.
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/etc"), Some(b"/cfg")),
        0
    );
    env.ram.storage.check_name_index();
    let path = with_args(
        ChangeOp::Path,
        b"/cfg/.",
        proto_fs::PATH_FOLLOW_LAST,
        [0; 4],
    );
    let done = env.go(&mut fds, path, None);
    assert_eq!((done.result, done.bytes.as_slice()), (0, &b"/cfg"[..]));
    // And a directory made at run time, moved below another.
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/l0"), Some(b"/cfg/moved")),
        0
    );
    let path = with_args(
        ChangeOp::Path,
        b"/cfg/moved/l1",
        proto_fs::PATH_FOLLOW_LAST,
        [0; 4],
    );
    let done = env.go(&mut fds, path, None);
    assert_eq!(
        (done.result, done.bytes.as_slice()),
        (0, &b"/cfg/moved/l1"[..])
    );
    env.assert_quiet();
}

fn read_name(env: &mut Env, fds: &mut Fds, fd: u32) -> Option<(std::string::String, u32)> {
    env.ram
        .directory_read(fds, fd, Timestamp::legacy_ns(5))
        .unwrap()
        .map(|record| {
            (
                std::string::String::from_utf8(record.name().to_vec()).unwrap(),
                record.kind,
            )
        })
}
fn open_directory(env: &mut Env, fds: &mut Fds, path: &str) -> u32 {
    env.ram
        .open(fds, path, proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY)
        .unwrap()
}
/// Every name from the start to the end, with `.` and `..` left out.
fn list(env: &mut Env, fds: &mut Fds, path: &str) -> Vec<std::string::String> {
    let fd = open_directory(env, fds, path);
    let mut names = Vec::new();
    while let Some((name, _)) = read_name(env, fds, fd) {
        if name != "." && name != ".." {
            names.push(name);
        }
    }
    env.ram.close(fds, fd).unwrap();
    names
}
/// `rm -r`: one name read, then removed, at every level.
fn remove_tree(env: &mut Env, fds: &mut Fds, path: &str) {
    let fd = open_directory(env, fds, path);
    while let Some((name, kind)) = read_name(env, fds, fd) {
        if name == "." || name == ".." {
            continue;
        }
        let child = std::format!("{path}/{name}");
        if kind == DIR {
            remove_tree(env, fds, &child);
            assert_eq!(env.go_result(fds, rmdir_op(child.as_bytes()), None), 0);
        } else {
            assert_eq!(
                env.go_result(fds, op(ChangeOp::Unlink, child.as_bytes()), None),
                0
            );
        }
    }
    env.ram.close(fds, fd).unwrap();
}

#[test]
fn a_directory_made_at_run_time_lists_its_names_with_their_kinds_and_inodes() {
    let mut env = Env::new();
    let mut fds = session();
    assert_eq!(
        env.go_result(&mut fds, mkdir(0, 1, b"/tmp/d", 0o755, 0), None),
        0
    );
    assert_eq!(
        env.go_result(&mut fds, mkdir(0, 1, b"/tmp/d/sub", 0o755, 0), None),
        0
    );
    let tmp_d = env.lookup(b"/tmp/d").unwrap();
    let file = env.node(tmp_d, b"f", REG, 0o644);
    assert_eq!(list(&mut env, &mut fds, "/tmp/d"), ["sub", "f"]);
    // The boot names stay, the new ones come after them.
    assert_eq!(list(&mut env, &mut fds, "/tmp"), ["probe", "d"]);
    assert_eq!(list(&mut env, &mut fds, "/"), ["etc", "tmp"]);
    let fd = open_directory(&mut env, &mut fds, "/tmp/d");
    let dot = env
        .ram
        .directory_read(&mut fds, fd, Timestamp::legacy_ns(5));
    let dir = env.lookup(b"/tmp/d").unwrap();
    assert_eq!(
        dot.unwrap().unwrap().inode,
        env.ram.inode(env.ram.file(dir))
    );
    let dotdot = env
        .ram
        .directory_read(&mut fds, fd, Timestamp::legacy_ns(5));
    assert_eq!(dotdot.unwrap().unwrap().inode, 3, "the inode of /tmp");
    let sub = env
        .ram
        .directory_read(&mut fds, fd, Timestamp::legacy_ns(5))
        .unwrap()
        .unwrap();
    assert_eq!((sub.name(), sub.kind), (&b"sub"[..], DIR));
    let f = env
        .ram
        .directory_read(&mut fds, fd, Timestamp::legacy_ns(5))
        .unwrap()
        .unwrap();
    assert_eq!((f.name(), f.kind), (&b"f"[..], REG));
    assert_eq!(f.inode, env.ram.inode(env.ram.file(file)));
    assert_eq!(
        env.ram
            .directory_read(&mut fds, fd, Timestamp::legacy_ns(5)),
        Ok(None)
    );
    env.ram.close(&mut fds, fd).unwrap();
    env.assert_quiet();
}

#[test]
fn a_name_that_exists_all_the_time_is_listed_once_whatever_else_changes() {
    let mut env = Env::new();
    let mut fds = session();
    let dir = env.node(ROOT, b"d", DIR, 0o755);
    let kept: Vec<std::string::String> = (0..24).map(|i| std::format!("keep{i:02}")).collect();
    let others: Vec<std::string::String> = (0..24).map(|i| std::format!("gone{i:02}")).collect();
    // Kept and doomed names alternate.
    for i in 0..24 {
        env.node(dir, kept[i].as_bytes(), REG, 0o644);
        env.node(dir, others[i].as_bytes(), REG, 0o644);
    }
    let fd = open_directory(&mut env, &mut fds, "/d");
    let mut seen = Vec::new();
    let mut round = 0;
    while let Some((name, _)) = read_name(&mut env, &mut fds, fd) {
        if name == "." || name == ".." {
            continue;
        }
        seen.push(name.clone());
        round += 1;
        // The name just given may go; names ahead go; new ones and a name that
        // moves in and out of the directory come.
        if round % 3 == 0 {
            let path = std::format!("/d/{name}");
            if name.starts_with("gone") {
                assert_eq!(
                    env.go_result(&mut fds, op(ChangeOp::Unlink, path.as_bytes()), None),
                    0
                );
            }
        }
        if round == 5 {
            for other in &others[10..] {
                let path = std::format!("/d/{other}");
                assert_eq!(
                    env.go_result(&mut fds, op(ChangeOp::Unlink, path.as_bytes()), None),
                    0
                );
            }
        }
        if round == 7 {
            for i in 0..6 {
                env.node(dir, std::format!("late{i}").as_bytes(), REG, 0o644);
            }
            let moved = env.lookup(b"/d/keep00").unwrap();
            let _ = moved;
        }
        env.ram.storage.check_name_index();
    }
    for name in &kept {
        assert_eq!(
            seen.iter().filter(|n| *n == name).count(),
            1,
            "{name} is listed once"
        );
    }
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), seen.len(), "no name twice");
    env.ram.close(&mut fds, fd).unwrap();
    env.assert_quiet();
}

#[test]
fn rm_r_of_a_tree_of_three_levels_reads_and_removes_name_by_name() {
    let mut env = Env::new();
    let mut fds = session();
    let top = env.node(ROOT, b"top", DIR, 0o755);
    for a in 0..3 {
        let one = env.node(top, std::format!("a{a}").as_bytes(), DIR, 0o755);
        env.node(top, std::format!("fa{a}").as_bytes(), REG, 0o644);
        for b in 0..3 {
            let two = env.node(one, std::format!("b{b}").as_bytes(), DIR, 0o755);
            env.node(one, std::format!("fb{b}").as_bytes(), REG, 0o644);
            for c in 0..3 {
                env.node(two, std::format!("c{c}").as_bytes(), REG, 0o644);
            }
        }
    }
    assert_eq!(list(&mut env, &mut fds, "/top").len(), 6);
    remove_tree(&mut env, &mut fds, "/top");
    assert_eq!(env.go_result(&mut fds, rmdir_op(b"/top"), None), 0);
    assert_eq!(list(&mut env, &mut fds, "/"), ["etc", "tmp"]);
    env.assert_quiet();
}

#[test]
fn boot_names_leave_and_arrive_in_the_listing_with_renames_and_unlinks() {
    let mut env = Env::new();
    let mut fds = session();
    assert_eq!(list(&mut env, &mut fds, "/etc"), ["motd"]);
    assert_eq!(
        env.go_result(
            &mut fds,
            op(ChangeOp::Rename, b"/etc/motd"),
            Some(b"/tmp/m")
        ),
        0
    );
    assert!(list(&mut env, &mut fds, "/etc").is_empty());
    assert_eq!(list(&mut env, &mut fds, "/tmp"), ["probe", "m"]);
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Unlink, b"/tmp/probe"), None),
        0
    );
    assert_eq!(list(&mut env, &mut fds, "/tmp"), ["m"]);
    // A name moved to another directory is listed there and no longer here;
    // a name renamed within its directory keeps its place.
    let dir = env.node(ROOT, b"d", DIR, 0o755);
    env.node(dir, b"one", REG, 0o644);
    env.node(dir, b"two", REG, 0o644);
    env.node(dir, b"three", REG, 0o644);
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/d/two"), Some(b"/d/zwei")),
        0
    );
    assert_eq!(list(&mut env, &mut fds, "/d"), ["one", "zwei", "three"]);
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Rename, b"/d/one"), Some(b"/tmp/one")),
        0
    );
    assert_eq!(list(&mut env, &mut fds, "/d"), ["zwei", "three"]);
    assert_eq!(list(&mut env, &mut fds, "/tmp"), ["m", "one"]);
    // A name from the middle of the past takes the end of the new directory,
    // after the names that are younger than it.
    let old = env.node(ROOT, b"old", DIR, 0o755);
    env.node(old, b"first", REG, 0o644);
    let young = env.node(ROOT, b"young", DIR, 0o755);
    for name in ["y1", "y2", "y3"] {
        env.node(young, name.as_bytes(), REG, 0o644);
    }
    assert_eq!(
        env.go_result(
            &mut fds,
            op(ChangeOp::Rename, b"/old/first"),
            Some(b"/young/first")
        ),
        0
    );
    assert_eq!(
        list(&mut env, &mut fds, "/young"),
        ["y1", "y2", "y3", "first"]
    );
    assert!(list(&mut env, &mut fds, "/old").is_empty());
    env.assert_quiet();
}

#[test]
fn a_position_is_a_cookie_that_can_be_taken_again_and_survives_the_removal_of_its_name() {
    let mut env = Env::new();
    let mut fds = session();
    let dir = env.node(ROOT, b"d", DIR, 0o755);
    for name in ["a", "b", "c", "d"] {
        env.node(dir, name.as_bytes(), REG, 0o644);
    }
    let fd = open_directory(&mut env, &mut fds, "/d");
    let position = |env: &mut Env, fds: &mut Fds| {
        env.ram
            .seek_from(fds, fd, 0, proto_fs::SeekFrom::Current)
            .unwrap()
    };
    let mut at = Vec::new();
    for _ in 0..4 {
        read_name(&mut env, &mut fds, fd);
        at.push(position(&mut env, &mut fds));
    }
    // After `a`: the position that precedes `b`.
    assert!(at.windows(2).all(|w| w[0] < w[1]));
    env.ram
        .seek_from(&mut fds, fd, at[2], proto_fs::SeekFrom::Start)
        .unwrap();
    assert_eq!(read_name(&mut env, &mut fds, fd).unwrap().0, "b");
    // The name before the position goes: the next one is still the next.
    env.ram
        .seek_from(&mut fds, fd, at[2], proto_fs::SeekFrom::Start)
        .unwrap();
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Unlink, b"/d/a"), None),
        0
    );
    assert_eq!(read_name(&mut env, &mut fds, fd).unwrap().0, "b");
    env.ram
        .seek_from(&mut fds, fd, at[3], proto_fs::SeekFrom::Start)
        .unwrap();
    assert_eq!(
        env.go_result(&mut fds, op(ChangeOp::Unlink, b"/d/b"), None),
        0
    );
    assert_eq!(read_name(&mut env, &mut fds, fd).unwrap().0, "c");
    assert_eq!(read_name(&mut env, &mut fds, fd).unwrap().0, "d");
    assert_eq!(read_name(&mut env, &mut fds, fd), None);
    // Rewound, the rest.
    env.ram
        .seek_from(&mut fds, fd, 0, proto_fs::SeekFrom::Start)
        .unwrap();
    assert_eq!(list(&mut env, &mut fds, "/d"), ["c", "d"]);
    env.ram.close(&mut fds, fd).unwrap();
    env.assert_quiet();
}

#[test]
fn the_listing_by_index_agrees_with_the_listing_by_position() {
    let mut env = Env::new();
    let dir = env.node(ROOT, b"d", DIR, 0o755);
    for name in ["x", "y", "z"] {
        env.node(dir, name.as_bytes(), REG, 0o644);
    }
    let mut by_index = Vec::new();
    while let Some(record) = env
        .ram
        .directory_read_path("/d", by_index.len() as u32, Timestamp::legacy_ns(6))
        .unwrap()
    {
        by_index.push(std::string::String::from_utf8(record.name().to_vec()).unwrap());
    }
    assert_eq!(by_index, [".", "..", "x", "y", "z"]);
    env.assert_quiet();
}

#[test]
fn a_loop_of_mkdir_and_rmdir_does_not_outrun_the_reclamation_of_the_nodes() {
    // The share of a root is 192 nodes and a removed directory is reclaimed
    // later. Without the maintenance of the service, which is absent here,
    // the steps of the operations reclaim as fast as the operations make.
    let mut env = Env::new();
    let mut fds = session();
    for round in 0..800 {
        let made = env.go_result(&mut fds, mkdir(0, 1, b"/tmp/r", 0o755, 0), None);
        assert_eq!(made, 0, "mkdir in round {round}");
        let removed = env.go_result(&mut fds, rmdir_op(b"/tmp/r"), None);
        assert_eq!(removed, 0, "rmdir in round {round}");
    }
    env.assert_quiet();
}
