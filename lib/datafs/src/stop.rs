// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The drain decision of the stop of the data file service. After the stop notice the service takes
//! no new request, and its worker runs the jobs already queued. The record of the service gives
//! init 3 s to end; the drain keeps well inside it so that the volume can still be unmounted.

/// How long the worker runs queued jobs after the stop notice.
pub const DRAIN_NS: u64 = 2_000_000_000;

/// What the worker does next while the service stops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Drain {
    /// Run the oldest queued job.
    Run,
    /// The queue is empty: put the volume away.
    Done,
    /// Jobs are left and the time is out: put the volume away and leave them.
    GiveUp,
}

/// The step after `elapsed_ns` since the stop notice with `queued` jobs waiting.
pub const fn drain(queued: usize, elapsed_ns: u64) -> Drain {
    if queued == 0 {
        Drain::Done
    } else if elapsed_ns >= DRAIN_NS {
        Drain::GiveUp
    } else {
        Drain::Run
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_queue_is_done_at_any_time() {
        assert_eq!(drain(0, 0), Drain::Done);
        assert_eq!(drain(0, DRAIN_NS * 10), Drain::Done);
    }

    #[test]
    fn queued_jobs_run_until_the_time_is_out() {
        assert_eq!(drain(3, 0), Drain::Run);
        assert_eq!(drain(1, DRAIN_NS - 1), Drain::Run);
        assert_eq!(drain(1, DRAIN_NS), Drain::GiveUp);
        assert_eq!(drain(12, DRAIN_NS + 1), Drain::GiveUp);
    }

    #[test]
    fn the_drain_ends_well_inside_the_record_deadline() {
        assert!(DRAIN_NS <= 2_000_000_000 && DRAIN_NS < 3_000_000_000);
    }
}
