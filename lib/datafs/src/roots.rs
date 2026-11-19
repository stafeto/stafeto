// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The root each session counts under, published by the worker for the request thread: the jobs in
//! flight are counted by root, so that one process tree, with its many sessions, never fills the
//! table of jobs for the others. The worker knows the roots (a session made by SESSION counts
//! under the root of the expenditure the vouching names, a clone under its parent's, a client of
//! init under its own label); the request thread only reads them, one session at a time, with no
//! call.
//!
//! An entry is written key first and label last (Release) and cleared by label first, and the
//! request thread reads the label first (Acquire). A label is never given twice and its session's
//! request is not in the table once the worker has forgotten it, so a reader that matched a label
//! reads that session's root. A label with no entry (a session the worker has not seen yet, or a
//! full table) counts under its own label, the same as a client of init.

use crate::binding::Root;
use crate::server::Server;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct Entry {
    label: AtomicU64,
    key: AtomicU64,
    expense: AtomicBool,
}

/// The table of `N` sessions.
pub struct Roots<const N: usize> {
    table: [Entry; N],
}

impl<const N: usize> Roots<N> {
    pub const fn new() -> Self {
        Self {
            table: [const {
                Entry {
                    label: AtomicU64::new(0),
                    key: AtomicU64::new(0),
                    expense: AtomicBool::new(false),
                }
            }; N],
        }
    }

    /// Makes `label` known with `root`, or forgets it for None. The worker's call.
    pub fn publish(&self, label: u64, root: Option<Root>) {
        if label == 0 {
            return;
        }
        let at = self
            .table
            .iter()
            .position(|e| e.label.load(Ordering::Relaxed) == label);
        match (root.map(Root::key), at) {
            (Some((key, expense)), Some(i)) => {
                // The label stays and its root changes in place (the two words are read as a pair
                // by a thread that tolerates the moment between them: a count off by a job).
                self.table[i].key.store(key, Ordering::Release);
                self.table[i].expense.store(expense, Ordering::Release);
            }
            (Some((key, expense)), None) => {
                if let Some(free) = self
                    .table
                    .iter()
                    .find(|e| e.label.load(Ordering::Relaxed) == 0)
                {
                    free.key.store(key, Ordering::Relaxed);
                    free.expense.store(expense, Ordering::Relaxed);
                    free.label.store(label, Ordering::Release);
                }
            }
            (None, Some(i)) => self.table[i].label.store(0, Ordering::Release),
            (None, None) => {}
        }
    }

    /// What the worker publishes after a job: the roots of the sessions the job touched (its
    /// owner, and the session a CLONE or SESSION made, whose label is `aux`), or the end of a
    /// session that went.
    pub fn after_job(&self, server: &Server, gone: bool, owner: u64, aux: u64) {
        if gone {
            self.publish(owner, None);
            return;
        }
        for label in [owner, aux] {
            self.publish(label, server.root_of(label));
        }
    }

    /// The root `owner` counts under, for the request thread, as the number and whether it is the
    /// root of an expenditure: its own label when none is published.
    pub fn root_of(&self, owner: u64) -> (u64, bool) {
        self.table
            .iter()
            .find(|e| e.label.load(Ordering::Acquire) == owner)
            .map_or((owner, false), |e| {
                (
                    e.key.load(Ordering::Acquire),
                    e.expense.load(Ordering::Acquire),
                )
            })
    }
}

impl<const N: usize> Default for Roots<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_counts_under_the_root_the_worker_published() {
        let roots = Roots::<4>::new();
        // Not published: its own label, as a client of init.
        assert_eq!(roots.root_of(7), (7, false));
        roots.publish(7, Some(Root::Expense(900)));
        roots.publish(8, Some(Root::Expense(900)));
        roots.publish(9, Some(Root::Label(9)));
        assert_eq!(roots.root_of(7), (900, true));
        assert_eq!(roots.root_of(8), (900, true));
        // Two sessions of one tree share a root, and a label and an expense with the same number
        // are two roots.
        assert_eq!(roots.root_of(7), roots.root_of(8));
        roots.publish(9, Some(Root::Label(900)));
        assert_ne!(roots.root_of(9), roots.root_of(7));
        // A change in place, and the end of a session frees its place.
        roots.publish(7, Some(Root::Expense(901)));
        assert_eq!(roots.root_of(7), (901, true));
        roots.publish(7, None);
        assert_eq!(roots.root_of(7), (7, false));
        roots.publish(10, Some(Root::Expense(5)));
        roots.publish(11, Some(Root::Expense(5)));
        assert_eq!(roots.root_of(11), (5, true));
    }

    #[test]
    fn a_full_table_leaves_a_session_under_its_own_label() {
        let roots = Roots::<2>::new();
        roots.publish(1, Some(Root::Expense(50)));
        roots.publish(2, Some(Root::Expense(50)));
        roots.publish(3, Some(Root::Expense(50)));
        assert_eq!(
            roots.root_of(3),
            (3, false),
            "alone, never in another's tree"
        );
        assert_eq!(roots.root_of(1), (50, true));
        roots.publish(0, Some(Root::Label(1)));
        assert_eq!(roots.root_of(0), (0, false));
    }
}
