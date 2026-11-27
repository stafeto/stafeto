// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tail of a rewrite, copied in steps (issue #626).
//!
//! A write in the middle of a file leaves the bytes past the last one written to the next seek,
//! read, sync or close of the file's shared handle: littlefs copies them from the old list to the
//! new one in one call (`lfs_file_flush`), about a second per MiB on QEMU and bounded only by
//! `FILE_MAX`. The service takes that copy out of the jobs of clients and runs it as its own work
//! in steps of `TAIL_SLICE_BLOCKS` blocks, one step after each job of the worker (and in the idle
//! time), so that a job of another file waits for at most one step.
//!
//! A node is in one of three states (`Tail`). `None`: nothing is known to be left. `Maybe`: a
//! write ran since the last check, so the handle may hold a tail. `Running`: the tail is being
//! copied; the jobs that would flush the node (`Wants::flushes`: a read, a truncation, a sync, the
//! close of the last description, an open with truncation, and a write that does not go on where
//! the last one stopped) wait for it as they wait for a lease, and jobs of other files run
//! between the steps. A write that goes on where the last one stopped needs no flush and runs at
//! once, so a file rewritten in many small calls is not copied after each (the copy begins when a
//! job that flushes arrives, or when the lease of a rewriting call lapses: nobody goes on after a
//! lapse). A job that is not known to flush (the unlink or rename of an open file) finds the rest
//! of the copy done in its own job, as before, and the files stay correct in every case: littlefs
//! finishes a half done flush in whatever call comes next (`lfs_file_flush_step`).
//!
//! The bound for `docs/data.md`: a job of another file waits for one step, `T_slice`, the copy of
//! `TAIL_SLICE_BLOCKS` blocks. The job that waits for the node itself waits for the whole tail,
//! as many steps as the tail has blocks divided by `TAIL_SLICE_BLOCKS`, with a job of another file
//! between two of them.

use super::*;

/// The blocks one step copies: the bytes of a part of a full cell (`proto_data::CELL_BYTES`), so
/// that a step costs about what a part costs.
pub const TAIL_SLICE_BLOCKS: u32 = (p::CELL_BYTES / BLOCK) as u32;

/// What the handle of a node is known to hold.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Tail {
    None,
    Maybe,
    Running,
}

impl Server {
    /// A write ran on node `ni`: its handle may hold a tail.
    pub(super) fn tail_maybe(&mut self, ni: usize) {
        if self.nodes[ni].tail == Tail::None {
            self.nodes[ni].tail = Tail::Maybe;
        }
    }

    /// The handle of node `ni` has been flushed whole (a sync, a truncation, a close).
    pub(super) fn tail_done(&mut self, ni: usize) {
        self.nodes[ni].tail = Tail::None;
    }

    /// Starts the copy for node `ni` when its handle holds a tail.
    fn tail_begin<D: Device>(&mut self, fs: &mut Fs<'_, D>, ni: usize) {
        let n = &mut self.nodes[ni];
        if !n.used || n.broken || n.tail != Tail::Maybe {
            return;
        }
        n.tail = match fs.tail(File(n.slot)) {
            Ok(left) if left > 0 => Tail::Running,
            _ => Tail::None,
        };
    }

    /// `tail_begin` for a node no lease is held on (the lease of a rewriting call has lapsed).
    pub(super) fn tail_begin_unleased<D: Device>(&mut self, fs: &mut Fs<'_, D>, ni: usize) {
        if !self
            .leases
            .iter()
            .any(|l| l.used && usize::from(l.node) == ni)
        {
            self.tail_begin(fs, ni);
        }
    }

    /// Before the worker chooses a job: the copy begins for the node of every queued job that
    /// would flush it, when no lease is held on the node.
    pub fn tails_start<D: Device>(&mut self, fs: &mut Fs<'_, D>, jobs: &[Candidate<'_>]) {
        if cfg!(feature = "break-datafs-tail-whole") {
            return;
        }
        for j in jobs.iter().take(CANDIDATES_MAX) {
            if let Some((ni, false)) = self.flush_of(j.owner, j.request) {
                self.tail_begin_unleased(fs, ni);
            }
        }
    }

    /// Whether a copy is running.
    pub fn tail_running(&self) -> bool {
        self.nodes.iter().any(|n| n.used && n.tail == Tail::Running)
    }

    /// One step of the copy of one node that has one, the one after the last that ran. Whether a
    /// step ran. A step that fails or ends the copy leaves the node in `None`; a failure shows
    /// again in the job that flushes the node.
    pub fn tail_step<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> bool {
        let count = self.nodes.len();
        for k in 1..=count {
            let ni = (self.tail_after + k) % count;
            if !self.nodes[ni].used || self.nodes[ni].tail != Tail::Running {
                continue;
            }
            self.tail_after = ni;
            if self.lapse.count != 0 && self.lapse.ran == 0 {
                self.lapse.steps += 1;
            }
            let file = File(self.nodes[ni].slot);
            #[cfg(test)]
            {
                self.tail_steps += 1;
            }
            if !matches!(fs.flush_step(file, TAIL_SLICE_BLOCKS), Ok(true)) {
                self.nodes[ni].tail = Tail::None;
            }
            return true;
        }
        false
    }

    /// Every copy that runs is done at once (the service stops, so that every job runs).
    pub fn tails_finish<D: Device>(&mut self, fs: &mut Fs<'_, D>) {
        while self.tail_step(fs) {}
    }
}
