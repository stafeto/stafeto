// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The rules of the walks the worker makes while its queue is empty: the first one after the mount
//! and the refresh after many removals. A walk reads every block the tree refers to and can take
//! seconds on a large volume. A job that is queued stops it at its next read (the walk only reads,
//! so nothing is lost), is served, and the walk is tried again when the queue is empty. A steady
//! trickle of jobs must not keep the window empty for ever, so after `MAX_YIELDS` stopped tries the
//! walk runs to its end.

/// The tries of a walk that a queued job may stop. A request that arrives while the last try runs
/// waits for the walk: at most the time of a walk of the whole volume (14 to 50 s on a volume of
/// 2 GiB at 10,000 reads a second, by the files on it). The three stopped tries cost at most their
/// own reads again, spent while the jobs that stopped them waited a read each.
pub const MAX_YIELDS: u32 = 3;

/// Whether the walk about to start may be stopped by a queued job, after `tries` stopped tries.
pub const fn may_yield(tries: u32) -> bool {
    tries < MAX_YIELDS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fourth_try_runs_to_its_end() {
        assert!([0, 1, 2].iter().all(|&t| may_yield(t)));
        assert!(!may_yield(3) && !may_yield(u32::MAX));
    }
}
