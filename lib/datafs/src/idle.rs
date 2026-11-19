// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The rules of the walks the worker makes while its queue is empty: the first one after the mount
//! and the refresh after many removals. A walk reads every block the tree refers to and can take
//! seconds on a large volume. A try starts only after the queue has been empty for `QUIET_NS`,
//! counted from the end of the last job, so the requests of a boot (which come in bursts with
//! gaps of milliseconds) are served with no walk beside them. A job that is queued during a try
//! stops it at its next read (the walk only reads, so nothing is lost), is served, and the next
//! try waits for a quiet time again. A steady trickle of jobs must not keep the window empty for
//! ever, so after `MAX_YIELDS` stopped tries the walk runs to its end.

/// How long the queue must have been empty before a try of a walk starts, from the end of the last
/// job. The refresh walk and the first walk after the mount use the same time.
pub const QUIET_NS: u64 = 2_000_000_000;

/// The nanoseconds still to wait before a try may start at `now`, with the last job ended at
/// `last_job_end` (both on the one scale of the system): 0 when the queue has been quiet for
/// `QUIET_NS`.
pub const fn quiet_wait(now: u64, last_job_end: u64) -> u64 {
    last_job_end.saturating_add(QUIET_NS).saturating_sub(now)
}

/// The tries of a walk that a queued job may stop. Each stop takes a job that arrives during a try,
/// and each try starts after a quiet time, so three stops need three bursts of requests, each
/// after 2 s of quiet. A request that arrives while the last try runs waits for the walk: at most
/// the time of a walk of the whole volume (14 to 50 s on a volume of 2 GiB at 10,000 reads a
/// second, by the files on it). A stopped try costs at most its own reads again, spent while the
/// job that stopped it waited a read.
pub const MAX_YIELDS: u32 = 3;

/// Whether the walk about to start may be stopped by a queued job, after `tries` stopped tries.
pub const fn may_yield(tries: u32) -> bool {
    tries < MAX_YIELDS
}

/// Whether the walk about to start may be stopped by a queued job: the first walk after the mount
/// after `tries` stopped tries as `may_yield` says, and a refresh walk always. A refresh that runs
/// to its end for a reader that comes late gives nothing: the free count of STATFS is low by what was
/// given back, and the allocator walks by itself inside a request that needs a block; the reader
/// would wait the 14 to 50 s of a walk for the exactness of `df`.
pub const fn walk_may_yield(first: bool, tries: u32) -> bool {
    !first || may_yield(tries)
}

/// Whether a walk in the idle would help (the refresh): the blocks that removals, truncations and
/// replacing renames gave back since the last walk (`freed`) are over a sixteenth of the volume
/// (`blocks`), or the window holds less than the volume (`window_short`: the allocator wrapped in the
/// middle of a request). The free count of STATFS comes from the bits of the window, which a removal
/// does not touch, so it is low by what was given back until a walk fills the window again; a sixteenth
/// is the most a reader is allowed to be told too little (a `df` after a large `rm` must not lie
/// for long, whatever the window holds). A volume with a sixteenth or less given back has no
/// refresh. A first version also asked the window to be nearly full; a probe that removed 384 MiB
/// from a volume with 23 percent free saw the count stay where it was.
pub const fn refresh_wanted(blocks: u64, freed: u64, window_short: bool) -> bool {
    window_short || freed > blocks / 16
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn a_job_a_moment_after_the_last_one_starts_no_try() {
        // The last job ended at 10 s; 100 ms later the queue has not been quiet for 2 s.
        assert_eq!(quiet_wait(10_000 * MS + 100 * MS, 10_000 * MS), 1_900 * MS);
        assert!(quiet_wait(10_000 * MS + 1_999 * MS, 10_000 * MS) > 0);
        // A try starts exactly when 2 s of quiet are over.
        assert_eq!(quiet_wait(12_000 * MS, 10_000 * MS), 0);
        assert_eq!(quiet_wait(60_000 * MS, 10_000 * MS), 0);
        // A clock behind the stamp is no quiet.
        assert_eq!(quiet_wait(0, 10_000 * MS), 12_000 * MS);
    }

    /// The worker's rule as a loop over time: jobs end at the given instants; a try starts when
    /// `quiet_wait` is 0 and the next job has not come; a try is stopped by a job that comes before
    /// it ends (`try_ns` long). Returns the instants the tries started and whether the last one ran
    /// to its end.
    fn run(jobs: &[u64], try_ns: u64) -> (Vec<u64>, bool) {
        let (mut last, mut tries, mut starts) = (0u64, 0u32, Vec::new());
        let mut next = 0;
        loop {
            let start = last + QUIET_NS;
            // A job that comes before the quiet time is over keeps the walk from starting.
            if next < jobs.len() && jobs[next] <= start {
                last = jobs[next];
                next += 1;
                continue;
            }
            starts.push(start);
            let ends = start + try_ns;
            if may_yield(tries) && next < jobs.len() && jobs[next] < ends {
                // Stopped: the job is served and ends at once.
                tries += 1;
                last = jobs[next];
                next += 1;
                continue;
            }
            return (starts, true);
        }
    }

    #[test]
    fn a_boot_of_requests_a_few_ms_apart_starts_no_try_until_two_seconds_after_the_last() {
        // Requests every 50 ms for a second: the first try starts 2 s after the last of them.
        let jobs: Vec<u64> = (1..=20).map(|i| i * 50 * MS).collect();
        let (starts, done) = run(&jobs, 30_000 * MS);
        assert!(done);
        assert_eq!(starts, [1_000 * MS + QUIET_NS]);
    }

    #[test]
    fn three_stops_then_a_full_walk_need_three_bursts_each_after_two_seconds_of_quiet() {
        // A walk of 30 s; a job arrives 1 s into each try, four times over: three stops, and the
        // fourth try runs to its end though the fourth job arrives during it.
        let jobs = [
            QUIET_NS + 1_000 * MS,
            2 * QUIET_NS + 2_000 * MS,
            3 * QUIET_NS + 3_000 * MS,
            4 * QUIET_NS + 4_000 * MS,
        ];
        let (starts, done) = run(&jobs, 30_000 * MS);
        assert!(done);
        assert_eq!(starts.len(), 4, "{starts:?}");
        assert_eq!(starts[0], QUIET_NS);
        for pair in starts.windows(2) {
            assert!(pair[1] - pair[0] >= QUIET_NS, "{starts:?}");
        }
    }

    #[test]
    fn a_refresh_walk_always_yields_and_the_first_walk_yields_three_times() {
        for tries in [0, 1, 2, 3, 4, 100, u32::MAX] {
            assert!(
                walk_may_yield(false, tries),
                "a refresh after {tries} stops"
            );
        }
        assert!([0, 1, 2].iter().all(|&t| walk_may_yield(true, t)));
        assert!(!walk_may_yield(true, 3));
    }

    #[test]
    fn the_fourth_try_runs_to_its_end() {
        assert!([0, 1, 2].iter().all(|&t| may_yield(t)));
        assert!(!may_yield(3) && !may_yield(u32::MAX));
    }

    const BLOCKS: u64 = 262_144;

    #[test]
    fn the_refresh_starts_above_a_sixteenth_given_back_and_not_at_a_thirty_second() {
        assert!(refresh_wanted(BLOCKS, BLOCKS / 16 + 1, false));
        assert!(
            !refresh_wanted(BLOCKS, BLOCKS / 16, false),
            "exactly a sixteenth"
        );
        assert!(!refresh_wanted(BLOCKS, BLOCKS / 32, false));
        // A lot given back refreshes the count whatever the window holds: a volume with most of its
        // blocks free still tells too little after a large removal.
        assert!(refresh_wanted(BLOCKS, BLOCKS / 4, false));
        // A window cut short is walked again whatever was given back.
        assert!(refresh_wanted(BLOCKS, 0, true));
    }

    /// Removals of `each` blocks one after another with a quiet time after each: the walks the rule
    /// asks for (a walk ends with the estimate at 0 and the window full of what was free).
    fn walks_for(removals: u64, each: u64) -> u64 {
        let (mut freed, mut walks) = (0, 0);
        for _ in 0..removals {
            freed += each;
            if refresh_wanted(BLOCKS, freed, false) {
                walks += 1;
                freed = 0;
            }
        }
        walks
    }

    #[test]
    fn many_small_removals_make_few_walks() {
        // Each removal gives back a sixty-fourth of the volume: a walk after the fifth (5/64 is over
        // 4/64), so twenty removals make four walks and never one for each removal.
        assert_eq!(walks_for(20, BLOCKS / 64), 4);
        // Removals of a thirty-second each stay under a sixteenth for two of every three.
        assert_eq!(walks_for(30, BLOCKS / 32), 10);
        // Tiny removals never reach the sixteenth in a hundred.
        assert_eq!(walks_for(100, 16), 0);
    }
}
