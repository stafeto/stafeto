// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The decisions of the service's request thread that need no kernel: which jobs a session may
//! have, what becomes of the handle a reply carries, which labels wait for a free job. The thread
//! (`services/datafs/src/main.rs`) calls these; the tests run here on the host.

use proto_data as p;

/// A free job for a request of a session that has `mine` jobs in flight, when `limit` is the most it
/// may have: None when there is no free job or the session has its share.
pub fn job_for(free: Option<usize>, mine: usize, limit: usize) -> Option<usize> {
    free.filter(|_| mine < limit)
}

/// Whether a request of a session may take a job when `free` jobs are free: a session of a native
/// client may take any, every other session leaves the last `reserve` for the native clients. The
/// sessions of one process tree are many (up to 32 for a root, 4 jobs each, more than the table), and
/// the request thread does not know the trees, so the table keeps a share for `datakey` and the
/// other native clients that no tree can use up.
pub fn leaves_for_native(free: usize, native: bool, reserve: usize) -> bool {
    native || free > reserve
}

/// What a reply's status is: whether it is a success (the status word is zero).
pub fn said_yes(reply: &[u8]) -> bool {
    reply.get(..4) == Some(&[0; 4][..])
}

/// The status word of a reply, or None when it has none.
pub fn status_of(reply: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(reply.get(..4)?.try_into().ok()?))
}

/// What a request thread holds a handle for until its job is done.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Held {
    /// A new session (CLONE) or a pass (EXPORT) that goes to the client when the service says yes.
    Made,
    /// The pass a client spent in ADOPT: it goes back to the client when the service refused for a
    /// limit that the client can lift (the pass was not spent), and closes otherwise.
    Spent,
}

/// What becomes of a held handle once the worker has answered with `reply`: true when it goes to
/// the client in the reply, false when it closes.
pub fn carries(held: Held, reply: &[u8]) -> bool {
    matches!(
        (held, status_of(reply)),
        (Held::Made, Some(0)) | (Held::Spent, Some(p::TOO_MANY_OPEN | p::TABLE_FULL))
    )
}

/// What a request for ADOPT meets before it is queued: how many handles it brought and whether a
/// job is free for its session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Adopt {
    /// Not one handle: BAD_SIZE.
    BadSize,
    /// A job is free: queue it with the pass.
    Queue,
    /// No job: answer busy and give the pass back, so that the client may ask again.
    GiveBack,
}

pub fn adopt_plan(handles: usize, job_free: bool) -> Adopt {
    match (handles, job_free) {
        (1, true) => Adopt::Queue,
        (1, false) => Adopt::GiveBack,
        _ => Adopt::BadSize,
    }
}

/// The labels whose close found no free job: what they held is closed when jobs free up.
pub struct Forgotten<const N: usize> {
    labels: [u64; N],
    count: usize,
}

impl<const N: usize> Default for Forgotten<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Forgotten<N> {
    pub const fn new() -> Self {
        Self {
            labels: [0; N],
            count: 0,
        }
    }

    /// False when the list is full: the label is lost, so the size must cover everything that can
    /// close at once (`closers`).
    pub fn push(&mut self, label: u64) -> bool {
        if self.count == N {
            return false;
        }
        self.labels[self.count] = label;
        self.count += 1;
        true
    }

    pub fn pop(&mut self) -> Option<u64> {
        self.count = self.count.checked_sub(1)?;
        Some(self.labels[self.count])
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The labels that can have gone while no job was free: every session of the loop and every clone
/// the worker holds (`sessions`, as many as its table), every pass (`passes`), and for each job
/// in flight the handle its reply would have carried and the pass its ADOPT spent (`jobs` of each,
/// and one more for the label of the request itself).
pub const fn closers(sessions: usize, passes: usize, jobs: usize) -> usize {
    sessions + passes + 3 * jobs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u32) -> [u8; 8] {
        let mut r = [0; 8];
        r[..4].copy_from_slice(&status.to_le_bytes());
        r
    }

    #[test]
    fn a_session_gets_a_job_only_inside_its_share() {
        assert_eq!(job_for(Some(3), 0, 4), Some(3));
        assert_eq!(job_for(Some(3), 3, 4), Some(3));
        assert_eq!(job_for(Some(3), 4, 4), None);
        assert_eq!(job_for(None, 0, 4), None);
    }

    #[test]
    fn the_last_jobs_are_kept_for_the_native_clients() {
        assert!(leaves_for_native(5, false, 4));
        assert!(!leaves_for_native(4, false, 4));
        assert!(!leaves_for_native(1, false, 4));
        assert!(
            leaves_for_native(1, true, 4),
            "a native client takes the last one"
        );
    }

    #[test]
    fn a_made_handle_goes_with_a_yes_and_closes_with_anything_else() {
        assert!(carries(Held::Made, &reply(0)));
        assert!(!carries(Held::Made, &reply(p::BAD_HANDLE)));
        assert!(!carries(Held::Made, &reply(p::TOO_MANY_OPEN)));
        assert!(!carries(Held::Made, &[]));
        assert!(said_yes(&reply(0)) && !said_yes(&reply(1)) && !said_yes(&[0, 0]));
    }

    #[test]
    fn a_spent_pass_comes_back_only_when_the_limit_left_it_unspent() {
        assert!(carries(Held::Spent, &reply(p::TOO_MANY_OPEN)));
        assert!(carries(Held::Spent, &reply(p::TABLE_FULL)));
        assert!(
            !carries(Held::Spent, &reply(0)),
            "adopted: the pass is spent"
        );
        assert!(!carries(Held::Spent, &reply(p::BAD_HANDLE)));
        assert!(!carries(Held::Spent, &reply(p::IO)));
        assert!(!carries(Held::Spent, &[]));
    }

    #[test]
    fn adopt_needs_one_handle_and_gives_it_back_when_no_job_is_free() {
        assert_eq!(adopt_plan(1, true), Adopt::Queue);
        assert_eq!(adopt_plan(1, false), Adopt::GiveBack);
        assert_eq!(adopt_plan(0, true), Adopt::BadSize);
        assert_eq!(adopt_plan(2, false), Adopt::BadSize);
    }

    #[test]
    fn the_forgotten_hold_exactly_their_size_and_come_back_last_first() {
        let mut f = Forgotten::<3>::new();
        assert!(f.is_empty());
        assert!(f.push(1) && f.push(2) && f.push(3));
        assert!(!f.push(4), "full: the label would be lost");
        assert_eq!(f.len(), 3);
        assert_eq!(
            (f.pop(), f.pop(), f.pop(), f.pop()),
            (Some(3), Some(2), Some(1), None)
        );
    }

    #[test]
    fn the_list_of_the_forgotten_covers_everything_that_can_close_at_once() {
        assert_eq!(closers(32, 8, 12), 76);
        assert!(closers(1, 1, 1) > 3);
    }
}
