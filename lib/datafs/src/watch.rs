// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The look of the request thread at the worker: whether it has stopped making progress.
//!
//! The heartbeat of the service comes from the request thread, which stays alive while the worker is
//! caught in a loop on a damaged volume. A job can legitimately run for minutes (littlefs walks the
//! whole file system when its look-ahead window runs out, and `Statfs` does the same walk), so the age
//! of a job tells nothing. What a healthy worker does all the time is complete disk calls. The worker
//! stamps the instant of every completed disk call, and the request thread ends the service when a
//! job is in the table and no disk call has completed for `STUCK_NS`: init starts a new instance,
//! which mounts the volume again.

/// The longest the worker may go without completing a disk call while a job is in the table: 20 s.
/// One disk call (at most 16 KiB, or a flush) takes milliseconds on a healthy volume and a bounded
/// wait of the disk service on a failing one, so 20 s is far above the time of one call.
pub const STUCK_NS: u64 = 20_000_000_000;

/// Whether the worker is stuck at `now`: a job was queued at one of the `queued` instants and no disk
/// call has completed for more than `limit`. The silence counts from the latest of `progress` (the
/// last completed disk call), `since` (the instant the worker finished its start, which has its own
/// limits) and the queueing of the oldest job (an idle worker has no call to complete). With no job
/// in the table the worker is not stuck. Times are nanoseconds.
pub fn stuck(
    now: u64,
    since: u64,
    progress: u64,
    queued: impl IntoIterator<Item = u64>,
    limit: u64,
) -> bool {
    let Some(oldest) = queued.into_iter().min() else {
        return false;
    };
    let quiet_from = oldest.max(progress).max(since);
    now.saturating_sub(quiet_from) > limit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_job_with_steady_disk_calls_is_never_stuck() {
        // Queued at 0; a disk call completes every 10 for a long time.
        for now in (10..10_000).step_by(10) {
            assert!(!stuck(now, 0, now - 5, [0], 50), "at {now}");
        }
    }

    #[test]
    fn a_job_with_no_disk_call_for_over_the_limit_is_stuck() {
        assert!(stuck(200, 0, 100, [0], 50));
        assert!(!stuck(150, 0, 100, [0], 50));
        assert!(stuck(151, 0, 100, [0], 50));
    }

    #[test]
    fn an_empty_table_is_not_stuck() {
        assert!(!stuck(u64::MAX, 0, 0, [], 50));
    }

    #[test]
    fn the_start_is_excluded() {
        // Queued at 10 during a mount that ended at 90: the silence is 10 long at 100.
        assert!(!stuck(100, 90, 0, [10], 50));
        assert!(stuck(200, 90, 0, [10], 50));
    }

    #[test]
    fn an_idle_worker_that_gets_a_job_is_not_stuck_at_once() {
        // The last call was long ago, the job has just come.
        assert!(!stuck(1_000, 0, 5, [990], 50));
        assert!(stuck(1_100, 0, 5, [990], 50));
    }

    #[test]
    fn a_clock_behind_the_stamps_is_no_silence() {
        assert!(!stuck(5, 0, 10, [10], 1));
    }
}
