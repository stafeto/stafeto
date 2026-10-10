// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Candidate-rooted PID deadlock proofs from complete, caller-validated blockers.
//! The caller installs exact inode watches before its bounded Reader and removes
//! them on ClearWatch before acknowledging. No actor or RPC is retained here.

use super::Owner;
use crate::storage::Token;
use proto_fs::WaitKey;

pub const CAPACITY: usize = 16;
pub const PORTION: usize = 8;
const NONE: u8 = u8::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Invalid,
    Full,
    PidCollision,
    StaleInode,
    Phase,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    pub owner: u64,
    pub key: WaitKey,
    pub scan: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vertex {
    scope: Scope,
    index: u8,
    pid: u32,
}
impl Vertex {
    pub const fn pid(self) -> u32 {
        self.pid
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Watch {
    scope: Scope,
    round: u8,
    index: u8,
    inode: Token,
}
impl Watch {
    pub const fn inode(self) -> Token {
        self.inode
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    NoCycle,
    Deadlock,
    Deferred,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Work {
    Progress,
    /// Collect the union of genuine blockers of every registered WAIT of PID.
    NeedEdges(Vertex),
    /// Remove the caller's direct inode watch before calling unwatched().
    ClearWatch(Watch),
    Rebuild,
    Done(Verdict),
    Cleaned,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    pub visited: usize,
    pub work: Work,
}
impl Progress {
    fn new(visited: usize, work: Work) -> Self {
        Self { visited, work }
    }
}
#[derive(Clone, Copy)]
enum Resume {
    Rebuild,
    Done(Verdict),
    Cleaned,
}
#[derive(Clone, Copy)]
enum Phase {
    Vertices,
    Traverse,
    Collect(u8),
    Expand { from: u8, fresh: u16 },
    Trace(u8),
    Inodes(usize),
    Life(u16),
    Clear { remaining: u16, resume: Resume },
    Reset(usize),
    Announce,
    Done(Verdict),
    Cleaned,
}

#[derive(Clone, Copy)]
struct WatchCursor {
    node: u8,
    inode: Token,
    first: usize,
}

pub struct Graph {
    scope: Scope,
    pids: [u32; CAPACITY],
    index: [u16; proto_process::RECORDS],
    count: usize,
    edges: [u16; CAPACITY],
    node_watches: [u16; CAPACITY],
    parents: [u8; CAPACITY],
    ready: u16,
    discovered: u16,
    frontier: u16,
    cycle: u16,
    watches: [Option<Watch>; CAPACITY],
    watch_count: usize,
    watch_cursor: Option<WatchCursor>,
    round: u8,
    dirty: bool,
    phase: Phase,
}

/// Use the actual Process Label parser to validate the PID decomposition. Page
/// and Label both define PID = index + RECORDS * generation, not UID generation.
fn pid_place(pid: u32) -> Option<usize> {
    let label = proto_process::Label {
        index: (pid % proto_process::RECORDS as u32) as u16,
        generation: pid / proto_process::RECORDS as u32,
    };
    let parsed = proto_process::Label::from_raw(label.raw())?;
    (parsed.pid() == pid).then_some(parsed.index as usize)
}
impl Graph {
    pub fn new(candidate: u32, scope: Scope) -> Result<Self, Error> {
        if scope.owner == 0 || scope.scan == 0 || scope.key.validate().is_err() {
            return Err(Error::Invalid);
        }
        let mut graph = Self {
            scope,
            pids: [0; CAPACITY],
            index: [0; proto_process::RECORDS],
            count: 0,
            edges: [0; CAPACITY],
            node_watches: [0; CAPACITY],
            parents: [NONE; CAPACITY],
            ready: 0,
            discovered: 1,
            frontier: 1,
            cycle: 0,
            watches: [None; CAPACITY],
            watch_count: 0,
            watch_cursor: None,
            round: 0,
            dirty: false,
            phase: Phase::Vertices,
        };
        graph.register(candidate)?;
        Ok(graph)
    }
    fn vertex(&self, index: usize) -> Vertex {
        Vertex {
            scope: self.scope,
            index: index as u8,
            pid: self.pids[index],
        }
    }
    fn check_vertex(&self, vertex: Vertex) -> Result<usize, Error> {
        let index = usize::from(vertex.index);
        if vertex.scope != self.scope || index >= self.count || self.pids[index] != vertex.pid {
            return Err(Error::Invalid);
        }
        Ok(index)
    }
    pub fn register(&mut self, pid: u32) -> Result<Vertex, Error> {
        if !matches!(self.phase, Phase::Vertices) {
            return Err(Error::Phase);
        }
        let place = pid_place(pid).ok_or(Error::Invalid)?;
        let old = self.index[place];
        if old != 0 {
            let index = old.trailing_zeros() as usize;
            return if self.pids[index] == pid {
                Ok(self.vertex(index))
            } else {
                Err(Error::PidCollision)
            };
        }
        if self.count == CAPACITY {
            return Err(Error::Full);
        }
        let index = self.count;
        self.count += 1;
        self.pids[index] = pid;
        self.index[place] = 1 << index;
        Ok(self.vertex(index))
    }
    pub fn begin(&mut self) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Vertices) {
            return Err(Error::Phase);
        }
        self.phase = Phase::Traverse;
        Ok(())
    }
    fn collecting(&self, vertex: Vertex) -> Result<usize, Error> {
        let index = self.check_vertex(vertex)?;
        if !matches!(self.phase, Phase::Collect(current) if usize::from(current) == index) {
            return Err(Error::Phase);
        }
        Ok(index)
    }
    /// At most eight watch objects are compared. Continue is not a reservation.
    pub fn watch_part(&mut self, vertex: Vertex, inode: Token) -> Result<WatchProgress, Error> {
        let node = self.collecting(vertex)?;
        let first = match self.watch_cursor {
            Some(cursor) if usize::from(cursor.node) == node && cursor.inode == inode => {
                cursor.first
            }
            Some(_) => return Err(Error::Phase),
            None => 0,
        };
        if inode.generation == 0 || usize::from(inode.slot) >= crate::storage::NODES {
            return Err(Error::Invalid);
        }
        let end = self.watch_count.min(first + PORTION);
        for index in first..end {
            let watch = self.watches[index].ok_or(Error::Phase)?;
            if watch.inode.slot == inode.slot {
                if watch.inode != inode {
                    return Err(Error::StaleInode);
                }
                self.node_watches[node] |= 1 << index;
                self.watch_cursor = None;
                return Ok(WatchProgress {
                    visited: index - first + 1,
                    part: WatchPart::Ready(watch),
                });
            }
        }
        if end != self.watch_count || end - first == PORTION {
            self.watch_cursor = Some(WatchCursor {
                node: node as u8,
                inode,
                first: end,
            });
            return Ok(WatchProgress {
                visited: end - first,
                part: WatchPart::Continue,
            });
        }
        if self.watch_count == CAPACITY {
            return Err(Error::Full);
        }
        let watch = Watch {
            scope: self.scope,
            round: self.round,
            index: self.watch_count as u8,
            inode,
        };
        self.watch_cursor = None;
        self.watches[self.watch_count] = Some(watch);
        self.node_watches[node] |= 1 << self.watch_count;
        self.watch_count += 1;
        Ok(WatchProgress {
            visited: end - first + 1,
            part: WatchPart::Ready(watch),
        })
    }
    pub fn blocker(&mut self, vertex: Vertex, owner: Owner) -> Result<(), Error> {
        let from = self.collecting(vertex)?;
        if self.node_watches[from] == 0 {
            return Err(Error::Phase);
        }
        let Owner::Process(pid) = owner else {
            return Ok(());
        };
        if pid == vertex.pid {
            return Ok(());
        }
        let Some(place) = pid_place(pid) else {
            return Err(Error::Invalid);
        };
        let bit = self.index[place];
        if bit != 0 && self.pids[bit.trailing_zeros() as usize] == pid {
            self.edges[from] |= bit;
        }
        Ok(())
    }
    /// All WAIT registrations of this PID must have been scanned, not only one.
    pub fn finish_edges(&mut self, vertex: Vertex, blocked: bool) -> Result<(), Error> {
        let index = self.collecting(vertex)?;
        if self.watch_cursor.is_some() {
            return Err(Error::Phase);
        }
        if self.node_watches[index] == 0 || !blocked && self.edges[index] != 0 {
            return Err(Error::Invalid);
        }
        self.ready |= 1 << index;
        self.phase = Phase::Traverse;
        Ok(())
    }
    pub fn changed(&mut self, watch: Watch) -> bool {
        let index = usize::from(watch.index);
        if matches!(self.phase, Phase::Done(_) | Phase::Cleaned)
            || index >= self.watch_count
            || self.watches[index] != Some(watch)
        {
            return false;
        }
        self.dirty = true;
        true
    }
    fn clear(&mut self, resume: Resume) {
        self.phase = Phase::Clear {
            remaining: ((1u32 << self.watch_count) - 1) as u16,
            resume,
        };
    }
    fn invalidate(&mut self) {
        let resume = if self.round < 2 {
            Resume::Rebuild
        } else {
            Resume::Done(Verdict::Deferred)
        };
        self.clear(resume);
    }
    /// Caller has removed this exact handle from its direct inode index.
    pub fn unwatched(&mut self, watch: Watch) -> Result<(), Error> {
        let Phase::Clear { remaining, .. } = &mut self.phase else {
            return Err(Error::Phase);
        };
        let index = usize::from(watch.index);
        if index >= self.watch_count
            || self.watches[index] != Some(watch)
            || *remaining & (1 << index) == 0
        {
            return Err(Error::Invalid);
        }
        self.watches[index] = None;
        *remaining &= !(1 << index);
        Ok(())
    }
    pub fn defer(&mut self) -> Result<(), Error> {
        match self.phase {
            Phase::Done(_) | Phase::Cleaned => return Err(Error::Phase),
            Phase::Clear { remaining, .. } => {
                self.phase = Phase::Clear {
                    remaining,
                    resume: Resume::Done(Verdict::Deferred),
                };
            }
            _ => self.clear(Resume::Done(Verdict::Deferred)),
        }
        Ok(())
    }
    pub fn cleanup(&mut self) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Done(_)) {
            return Err(Error::Phase);
        }
        self.clear(Resume::Cleaned);
        Ok(())
    }
    /// Life callbacks compare full PID; inode callbacks validate the caller's
    /// full snapshots. Watched changes must keep arriving through changed().
    pub fn step(
        &mut self,
        mut live: impl FnMut(u32) -> bool,
        mut inode_valid: impl FnMut(Token) -> bool,
    ) -> Progress {
        if self.dirty
            && !matches!(
                self.phase,
                Phase::Clear { .. }
                    | Phase::Reset(_)
                    | Phase::Announce
                    | Phase::Done(_)
                    | Phase::Cleaned
            )
        {
            self.invalidate();
        }
        match self.phase {
            Phase::Vertices => Progress::new(0, Work::Progress),
            Phase::Collect(index) => {
                Progress::new(0, Work::NeedEdges(self.vertex(usize::from(index))))
            }
            Phase::Traverse => {
                let mut visited = 0;
                while self.frontier != 0 && visited < PORTION {
                    let index = self.frontier.trailing_zeros() as usize;
                    let bit = 1 << index;
                    if self.ready & bit == 0 {
                        self.phase = Phase::Collect(index as u8);
                        return Progress::new(visited, Work::NeedEdges(self.vertex(index)));
                    }
                    self.frontier &= !bit;
                    visited += 1;
                    if index != 0 && self.edges[index] & 1 != 0 {
                        self.cycle = 1;
                        self.phase = Phase::Trace(index as u8);
                        return Progress::new(visited, Work::Progress);
                    }
                    let fresh = self.edges[index] & !self.discovered;
                    self.frontier |= fresh;
                    self.discovered |= fresh;
                    if fresh != 0 {
                        self.phase = Phase::Expand {
                            from: index as u8,
                            fresh,
                        };
                        return Progress::new(visited, Work::Progress);
                    }
                }
                if self.frontier == 0 {
                    self.phase = Phase::Done(Verdict::NoCycle);
                }
                Progress::new(visited, Work::Progress)
            }
            Phase::Expand { from, mut fresh } => {
                let mut visited = 0;
                while fresh != 0 && visited < PORTION {
                    let next = fresh.trailing_zeros() as usize;
                    self.parents[next] = from;
                    fresh &= !(1 << next);
                    visited += 1;
                }
                self.phase = if fresh == 0 {
                    Phase::Traverse
                } else {
                    Phase::Expand { from, fresh }
                };
                Progress::new(visited, Work::Progress)
            }
            Phase::Trace(mut next) => {
                let mut visited = 0;
                while next != 0 && visited < PORTION {
                    self.cycle |= 1 << next;
                    next = self.parents[usize::from(next)];
                    visited += 1;
                    if next == NONE {
                        self.clear(Resume::Done(Verdict::Deferred));
                        return Progress::new(visited, Work::Progress);
                    }
                }
                self.phase = if next == 0 {
                    Phase::Inodes(0)
                } else {
                    Phase::Trace(next)
                };
                Progress::new(visited, Work::Progress)
            }
            Phase::Inodes(first) => {
                let end = self.watch_count.min(first + PORTION);
                for index in first..end {
                    let watch = self.watches[index].expect("watched snapshot");
                    if !inode_valid(watch.inode) {
                        self.invalidate();
                        return Progress::new(index - first + 1, Work::Progress);
                    }
                }
                self.phase = if end == self.watch_count {
                    Phase::Life(self.cycle)
                } else {
                    Phase::Inodes(end)
                };
                Progress::new(end - first, Work::Progress)
            }
            Phase::Life(mut remaining) => {
                let mut visited = 0;
                while remaining != 0 && visited < PORTION {
                    let index = remaining.trailing_zeros() as usize;
                    visited += 1;
                    if !live(self.pids[index]) {
                        self.invalidate();
                        return Progress::new(visited, Work::Progress);
                    }
                    remaining &= !(1 << index);
                }
                self.phase = if remaining == 0 {
                    Phase::Done(Verdict::Deadlock)
                } else {
                    Phase::Life(remaining)
                };
                Progress::new(visited, Work::Progress)
            }
            Phase::Clear { remaining, resume } => {
                if remaining != 0 {
                    let index = remaining.trailing_zeros() as usize;
                    return Progress::new(
                        1,
                        Work::ClearWatch(self.watches[index].expect("unacknowledged watch")),
                    );
                }
                self.watch_count = 0;
                self.watch_cursor = None;
                self.dirty = false;
                match resume {
                    Resume::Rebuild => {
                        self.round += 1;
                        self.phase = Phase::Reset(0);
                    }
                    Resume::Done(verdict) => self.phase = Phase::Done(verdict),
                    Resume::Cleaned => self.phase = Phase::Cleaned,
                }
                Progress::new(0, Work::Progress)
            }
            Phase::Reset(first) => {
                let end = self.count.min(first + PORTION);
                for index in first..end {
                    self.edges[index] = 0;
                    self.node_watches[index] = 0;
                    self.parents[index] = NONE;
                }
                if end == self.count {
                    self.ready = 0;
                    self.discovered = 1;
                    self.frontier = 1;
                    self.cycle = 0;
                    self.phase = Phase::Announce;
                } else {
                    self.phase = Phase::Reset(end);
                }
                Progress::new(end - first, Work::Progress)
            }
            Phase::Announce => {
                self.phase = Phase::Traverse;
                Progress::new(0, Work::Rebuild)
            }
            Phase::Done(verdict) => Progress::new(0, Work::Done(verdict)),
            Phase::Cleaned => Progress::new(0, Work::Cleaned),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchPart {
    Ready(Watch),
    Continue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchProgress {
    pub visited: usize,
    pub part: WatchPart,
}

#[cfg(test)]
#[path = "deadlock_tests.rs"]
mod tests;
