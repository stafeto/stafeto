// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A paid caller-owned proof scratch; no Actor, RPC or notification custody.
use super::{
    Owner,
    actor::{ReadSnapshot, ReadState, Reader},
    deadlock::{Graph, PORTION, Scope, Verdict, Vertex, Watch, WatchPart, Work},
    request::Captured,
    service::LockService,
    wait_receipts::{Id, Phase as ReceiptPhase, Queue},
    waiters::{CAPACITY, Cursor, Input, Phase as PoolPhase, Pool, RegistrationToken},
};
use crate::storage::{Storage, Token};

#[derive(Clone, Copy)]
struct Seed {
    token: RegistrationToken,
    input: Input,
    captured: Captured,
    phase: PoolPhase,
    revision: u64,
}
#[derive(Clone, Copy)]
struct SavedWatch {
    watch: Watch,
    snapshot: ReadSnapshot,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub verdict: Verdict,
    pub candidate: Id,
    pub captured: Captured,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    pub visited: usize,
    pub outcome: Option<Outcome>,
}
enum Phase {
    Idle,
    ClearSeeds(usize),
    Starting,
    Seed(Cursor),
    Graph,
    Collect { vertex: Vertex, first: usize },
    Watch { vertex: Vertex, seed: usize },
    Read { vertex: Vertex, seed: usize },
    FinishVertex(Vertex),
    Verify(usize),
    Cleanup(Verdict),
    Finished(Outcome),
}
pub struct Proof {
    graph: Graph,
    #[cfg(feature = "lifetime-probe")]
    probe_snapshot: Option<[u32; 3]>,
    candidate: Option<Seed>,
    seeds: [Option<Seed>; CAPACITY],
    watches: [Option<SavedWatch>; CAPACITY],
    reader: Option<Reader>,
    reader_watch: Option<Watch>,
    used: u16,
    blocked: bool,
    phase: Phase,
}
fn seed(queue: &Queue, pool: &Pool, token: RegistrationToken) -> Option<Seed> {
    let (input, phase, revision) = pool.proof_snapshot(token)?;
    let (captured, receipt_phase, cancelling) = queue.snapshot(token.receipt()).ok()?;
    let super::actor::Command::Set(Some(kind)) = captured.request.command else {
        return None;
    };
    if cancelling
        || receipt_phase == ReceiptPhase::Complete
        || input.root != captured.root
        || input.inode != captured.request.inode
        || input.range != captured.request.range
        || input.kind != kind
    {
        return None;
    }
    Some(Seed {
        token,
        input,
        captured,
        phase,
        revision,
    })
}
fn current(queue: &Queue, pool: &Pool, saved: Seed) -> bool {
    seed(queue, pool, saved.token).is_some_and(|now| {
        now.input == saved.input
            && now.captured == saved.captured
            && now.phase == saved.phase
            && now.revision == saved.revision
    })
}
impl Proof {
    /// Cold initialization only; writes permanent fields without a full temporary.
    ///
    /// # Safety
    /// Exclusive aligned writable uninitialized allocation for Self.
    pub unsafe fn initialize_at(destination: *mut Self) {
        // SAFETY: each field is within the caller's complete exclusive allocation.
        unsafe {
            #[cfg(feature = "lifetime-probe")]
            core::ptr::addr_of_mut!((*destination).probe_snapshot).write(None);
            Graph::initialize_empty_at(core::ptr::addr_of_mut!((*destination).graph));
            let seeds = core::ptr::addr_of_mut!((*destination).seeds).cast::<Option<Seed>>();
            let watches =
                core::ptr::addr_of_mut!((*destination).watches).cast::<Option<SavedWatch>>();
            for index in 0..CAPACITY {
                seeds.add(index).write(None);
                watches.add(index).write(None);
            }
            core::ptr::addr_of_mut!((*destination).candidate).write(None);
            core::ptr::addr_of_mut!((*destination).reader).write(None);
            core::ptr::addr_of_mut!((*destination).reader_watch).write(None);
            core::ptr::addr_of_mut!((*destination).used).write(0);
            core::ptr::addr_of_mut!((*destination).blocked).write(false);
            core::ptr::addr_of_mut!((*destination).phase).write(Phase::Idle);
        }
    }
    /// Counts saved before cleanup of a genuinely verified candidate cycle.
    #[cfg(feature = "lifetime-probe")]
    pub fn probe_snapshot(&self) -> Option<[u32; 3]> {
        self.probe_snapshot
    }
    /// False means decline optional detection, never a new public errno.
    pub fn start(
        &mut self,
        queue: &Queue,
        pool: &Pool,
        token: RegistrationToken,
        captured: Captured,
        scope: Scope,
    ) -> bool {
        if !matches!(self.phase, Phase::Idle | Phase::Finished(_)) {
            return false;
        }
        let Some(candidate) = seed(queue, pool, token) else {
            return false;
        };
        let Owner::Process(pid) = candidate.captured.request.owner else {
            return false;
        };
        if candidate.captured != captured
            || candidate.phase != PoolPhase::Sleeping
            || queue
                .snapshot(token.receipt())
                .ok()
                .is_none_or(|(_, phase, _)| phase != ReceiptPhase::Sleeping)
            || scope.owner != token.receipt().owner()
            || scope.key != token.receipt().key()
            || self.graph.restart(pid, scope).is_err()
        {
            return false;
        }
        self.candidate = Some(candidate);
        self.reader = None;
        self.reader_watch = None;
        self.used = 0;
        self.blocked = false;
        #[cfg(feature = "lifetime-probe")]
        {
            self.probe_snapshot = None;
        }
        self.phase = Phase::ClearSeeds(0);
        true
    }
    fn candidate_current(&self, queue: &Queue, pool: &Pool) -> bool {
        self.candidate.is_some_and(|saved| {
            current(queue, pool, saved)
                && queue
                    .snapshot(saved.token.receipt())
                    .ok()
                    .is_some_and(|(_, phase, cancel)| phase == ReceiptPhase::Sleeping && !cancel)
        })
    }
    fn abort(&mut self) {
        self.reader = None;
        self.reader_watch = None;
        if self.graph.defer().is_err() {
            self.graph.cleanup().expect("terminal proof cleanup");
            self.phase = Phase::Cleanup(Verdict::Deferred);
        } else {
            self.phase = Phase::Graph;
        }
    }
    fn progress(visited: usize) -> Progress {
        Progress {
            visited,
            outcome: None,
        }
    }
    pub fn step(
        &mut self,
        queue: &Queue,
        pool: &Pool,
        locks: &LockService,
        storage: &Storage<'_>,
        mut pid_live: impl FnMut(u32) -> bool,
        mut ofd_live: impl FnMut(Token) -> bool,
    ) -> Progress {
        if !matches!(
            self.phase,
            Phase::Idle | Phase::Cleanup(_) | Phase::Finished(_)
        ) && !self.candidate_current(queue, pool)
        {
            self.abort();
        }
        match &mut self.phase {
            Phase::Idle => Self::progress(0),
            Phase::Finished(outcome) => {
                let mut outcome = *outcome;
                if outcome.verdict == Verdict::Deadlock && !self.candidate_current(queue, pool) {
                    outcome.verdict = Verdict::Deferred;
                }
                Progress {
                    visited: 1,
                    outcome: Some(outcome),
                }
            }
            Phase::ClearSeeds(first) => {
                let end = (*first + PORTION).min(CAPACITY);
                for index in *first..end {
                    self.seeds[index] = None;
                }
                let visited = end - *first;
                self.phase = if end == CAPACITY {
                    Phase::Starting
                } else {
                    Phase::ClearSeeds(end)
                };
                Self::progress(visited)
            }
            Phase::Starting => {
                let progress = self.graph.step_watches(|_| false, |_| false);
                if self.graph.seed_ready() {
                    let candidate = self.candidate.expect("started candidate");
                    self.seeds[candidate.token.slot()] = Some(candidate);
                    self.phase = Phase::Seed(pool.cursor());
                }
                Self::progress(progress.visited)
            }
            Phase::Seed(cursor) => {
                let graph = &mut self.graph;
                let seeds = &mut self.seeds;
                let mut invalid = false;
                let result = pool.scan(cursor, |token, _, _| {
                    let Some(item) = seed(queue, pool, token) else {
                        return;
                    };
                    if seeds[token.slot()].is_some_and(|old| old.token != token) {
                        invalid = true;
                        return;
                    }
                    if let Owner::Process(pid) = item.captured.request.owner
                        && graph.register(pid).is_err()
                    {
                        invalid = true;
                        return;
                    }
                    seeds[token.slot()] = Some(item);
                });
                let visited = result.unwrap_or(PORTION);
                if result.is_err() || invalid {
                    self.abort();
                } else if cursor.done() {
                    self.graph.begin().expect("frozen vertices");
                    self.phase = Phase::Graph;
                }
                Self::progress(visited)
            }
            Phase::Graph => {
                let watches = &self.watches;
                let progress = self.graph.step_watches(
                    |pid| pid_live(pid) && locks.pid_visible(pid),
                    |watch| {
                        watches[watch.slot()].is_some_and(|saved| {
                            saved.watch == watch
                                && locks.reader_snapshot_valid(storage, saved.snapshot)
                        })
                    },
                );
                match progress.work {
                    Work::NeedEdges(vertex) => {
                        self.blocked = false;
                        self.phase = Phase::Collect { vertex, first: 0 };
                    }
                    Work::ClearWatch(watch) => {
                        if self.watches[watch.slot()].is_some_and(|saved| saved.watch != watch) {
                            panic!("full watch mismatch");
                        }
                        self.watches[watch.slot()] = None;
                        self.graph
                            .unwatched(watch)
                            .expect("exact unwatch acknowledgement");
                    }
                    Work::Rebuild => {
                        self.reader = None;
                        self.reader_watch = None;
                        self.used = 0;
                    }
                    Work::Done(Verdict::Deadlock) => self.phase = Phase::Verify(0),
                    Work::Done(verdict) => {
                        self.graph.cleanup().expect("terminal cleanup");
                        self.phase = Phase::Cleanup(verdict);
                    }
                    Work::Progress => {}
                    Work::Cleaned => panic!("active graph unexpectedly cleaned"),
                }
                Self::progress(progress.visited)
            }
            Phase::Collect { vertex, first } => {
                let vertex = *vertex;
                let first = *first;
                let end = (first + PORTION).min(CAPACITY);
                for index in first..end {
                    if let Some(item) = self.seeds[index]
                        && item.captured.request.owner == Owner::Process(vertex.pid())
                    {
                        if !current(queue, pool, item) {
                            self.abort();
                        } else {
                            self.used |= 1 << index;
                            self.phase = Phase::Watch {
                                vertex,
                                seed: index,
                            };
                        }
                        return Self::progress(index - first + 1);
                    }
                }
                self.phase = if end == CAPACITY {
                    Phase::FinishVertex(vertex)
                } else {
                    Phase::Collect { vertex, first: end }
                };
                Self::progress(end - first)
            }
            Phase::Watch {
                vertex,
                seed: index,
            } => {
                let vertex = *vertex;
                let index = *index;
                let item = self.seeds[index].expect("selected registration");
                if !current(queue, pool, item) {
                    self.abort();
                    return Self::progress(1);
                }
                let Ok(progress) = self.graph.watch_part(vertex, item.input.inode) else {
                    self.abort();
                    return Self::progress(1);
                };
                if let WatchPart::Ready(watch) = progress.part {
                    let Some(snapshot) = locks.reader_snapshot(storage, item.input.inode) else {
                        self.abort();
                        return Self::progress(progress.visited);
                    };
                    if let Some(old) = self.watches[watch.slot()] {
                        if old.watch != watch || old.snapshot != snapshot {
                            self.graph.changed(watch);
                            self.phase = Phase::Graph;
                            return Self::progress(progress.visited);
                        }
                    } else {
                        self.watches[watch.slot()] = Some(SavedWatch { watch, snapshot });
                    }
                    match locks.reader(storage, item.captured.request) {
                        Ok(Some(reader)) if reader.snapshot() == snapshot => {
                            self.reader = Some(reader);
                            self.reader_watch = Some(watch);
                            self.phase = Phase::Read {
                                vertex,
                                seed: index,
                            };
                        }
                        _ => self.abort(),
                    }
                }
                Self::progress(progress.visited)
            }
            Phase::Read {
                vertex,
                seed: index,
            } => {
                let vertex = *vertex;
                let index = *index;
                if !current(queue, pool, self.seeds[index].expect("selected reader")) {
                    self.abort();
                    return Self::progress(1);
                }
                let reader = self.reader.as_mut().expect("active reader");
                let progress = locks.reader_part(storage, reader, &mut pid_live, &mut ofd_live);
                for blocker in progress.blockers.into_iter().flatten() {
                    self.blocked = true;
                    self.graph
                        .blocker(vertex, blocker.owner)
                        .expect("complete genuine blocker");
                }
                match progress.state {
                    ReadState::More => {}
                    ReadState::Done => {
                        self.reader = None;
                        self.reader_watch = None;
                        self.phase = Phase::Collect {
                            vertex,
                            first: index + 1,
                        };
                    }
                    ReadState::Invalidated => {
                        let watch = self.reader_watch.take().expect("active exact watch");
                        self.graph.changed(watch);
                        self.phase = Phase::Graph;
                        self.reader = None;
                    }
                }
                Self::progress(progress.visited)
            }
            Phase::FinishVertex(vertex) => {
                self.graph
                    .finish_edges(*vertex, self.blocked)
                    .expect("complete union");
                self.phase = Phase::Graph;
                Self::progress(1)
            }
            Phase::Verify(first) => {
                let end = (*first + PORTION).min(CAPACITY);
                for index in *first..end {
                    if self.used & (1 << index) != 0
                        && !current(queue, pool, self.seeds[index].expect("used registration"))
                    {
                        let visited = index - *first + 1;
                        self.abort();
                        return Self::progress(visited);
                    }
                }
                let visited = end - *first;
                if end == CAPACITY {
                    #[cfg(feature = "lifetime-probe")]
                    {
                        let (vertices, watches) = self.graph.probe_counts();
                        self.probe_snapshot =
                            Some([vertices as u32, self.used.count_ones(), watches as u32]);
                    }
                    self.graph.cleanup().expect("proven terminal cleanup");
                    self.phase = Phase::Cleanup(Verdict::Deadlock);
                } else {
                    self.phase = Phase::Verify(end);
                }
                Self::progress(visited)
            }
            Phase::Cleanup(verdict) => {
                let verdict = *verdict;
                let progress = self.graph.step_watches(|_| false, |_| false);
                match progress.work {
                    Work::ClearWatch(watch) => {
                        self.watches[watch.slot()] = None;
                        self.graph.unwatched(watch).expect("exact terminal unwatch");
                    }
                    Work::Cleaned => {
                        let candidate = self.candidate.expect("completed candidate");
                        let verdict = if verdict == Verdict::Deadlock
                            && !self.candidate_current(queue, pool)
                        {
                            Verdict::Deferred
                        } else {
                            verdict
                        };
                        let outcome = Outcome {
                            verdict,
                            candidate: candidate.token.receipt(),
                            captured: candidate.captured,
                        };
                        self.phase = Phase::Finished(outcome);
                        return Progress {
                            visited: progress.visited + 1,
                            outcome: Some(outcome),
                        };
                    }
                    Work::Progress => {}
                    _ => panic!("terminal cleanup work"),
                }
                Self::progress(progress.visited)
            }
        }
    }
}

#[cfg(test)]
#[path = "wait_proof_tests.rs"]
mod tests;
