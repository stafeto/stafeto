// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The look of the request thread at the worker: whether the oldest job has waited too long.
//!
//! The heartbeat of the service comes from the request thread, which stays alive while the worker is
//! caught in a loop on a damaged volume. The request thread therefore asks, at each beat, how long
//! the oldest job in the table has been waiting, and ends the service when that is more than
//! `STUCK_NS`: init starts a new instance, which mounts the volume again.

/// The longest a job may wait (queued or being run) while the worker is up: 20 s. A request of the
/// service costs a few disk calls of milliseconds, so this is two orders of magnitude over a healthy
/// wait, and inside the 30 s the clients of the volume wait for.
pub const STUCK_NS: u64 = 20_000_000_000;

/// Whether a job that was queued at one of the `queued` instants has waited more than `limit` at
/// `now`. A wait counts from the later of the queueing and `since`, the instant the worker finished
/// its start (a job queued during the mount waits for it by design). Times are nanoseconds.
pub fn stuck(now: u64, since: u64, queued: impl IntoIterator<Item = u64>, limit: u64) -> bool {
    queued
        .into_iter()
        .any(|at| now.saturating_sub(at.max(since)) > limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_job_older_than_the_limit_is_stuck() {
        assert!(stuck(100, 0, [10], 50));
        assert!(!stuck(100, 0, [60], 50));
        assert!(!stuck(100, 0, [50], 50));
        assert!(stuck(100, 0, [90, 10], 50));
    }

    #[test]
    fn no_job_is_never_stuck() {
        assert!(!stuck(u64::MAX, 0, [], 50));
    }

    #[test]
    fn the_wait_counts_from_the_end_of_the_start() {
        // Queued at 10 during a mount that ended at 90: it has waited 10, not 90.
        assert!(!stuck(100, 90, [10], 50));
        assert!(stuck(200, 90, [10], 50));
    }

    #[test]
    fn a_clock_behind_the_stamp_is_no_wait() {
        assert!(!stuck(5, 0, [10], 1));
    }
}
