// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The choice of the frames of one step and of the sockets' limit from the
//! steps the probe measured (spec 6, 6). A step of the service takes at
//! most 0.9 of term B (18 369 ticks under -icount, TERM_B * 9 / 10).
//!
//! The batch is the largest of 16, 8, 4 and 2 whose longest step with a
//! full batch at 8 sockets stays within the bound. The limit comes from the
//! straight line through the longest steps at three numbers of sockets with
//! that batch: the largest multiple of 8, 256 at most, where the line stays
//! within the bound less a margin of 5 percent.

/// The longest step the service may take, in ticks.
pub const BOUND: u64 = 18_369;
/// The margin below the bound the line must keep, in percent.
pub const MARGIN: u64 = 5;
/// The batches to try, the largest first.
pub const BATCHES: [usize; 4] = [16, 8, 4, 2];
/// The limit below which the service cannot serve the probes of the next
/// stage (28 sockets in TIME-WAIT, 9 in the queue of `httpd`, the others).
pub const LIMIT_LEAST: usize = 48;

/// A measured longest step: the sockets, and the ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub sockets: usize,
    pub ticks: u64,
}

/// Why the choice stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// Even a batch of 2 at 8 sockets is past the bound.
    NoBatch,
    /// The limit comes out below LIMIT_LEAST, or the line is past the bound at 8.
    LimitTooLow(usize),
}

/// The batch for the longest step at 8 sockets that `steps` gives for
/// each batch (None for a batch not measured).
pub fn batch(steps: impl Fn(usize) -> Option<u64>) -> Result<usize, Stop> {
    BATCHES
        .into_iter()
        .find(|&k| steps(k).is_some_and(|ticks| ticks <= BOUND))
        .ok_or(Stop::NoBatch)
}

/// The least-squares line through `points`, as (ticks at 0, ticks per
/// socket) in f64.
fn line(points: &[Point]) -> (f64, f64) {
    let n = points.len() as f64;
    let sx: f64 = points.iter().map(|p| p.sockets as f64).sum();
    let sy: f64 = points.iter().map(|p| p.ticks as f64).sum();
    let sxx: f64 = points.iter().map(|p| (p.sockets * p.sockets) as f64).sum();
    let sxy: f64 = points
        .iter()
        .map(|p| p.sockets as f64 * p.ticks as f64)
        .sum();
    let slope = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    ((sy - slope * sx) / n, slope)
}

/// The limit of the sockets from the longest steps at three numbers.
pub fn limit(points: &[Point; 3]) -> Result<usize, Stop> {
    let (base, slope) = line(points);
    let allowed = (BOUND * (100 - MARGIN) / 100) as f64;
    let mut best = 0;
    let mut n = 8;
    while n <= 256 {
        if base + slope * n as f64 <= allowed {
            best = n;
        }
        n += 8;
    }
    if best < LIMIT_LEAST {
        Err(Stop::LimitTooLow(best))
    } else {
        Ok(best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_largest_batch_within_the_bound_is_chosen() {
        let steps = |k: usize| Some(1_000 * k as u64);
        assert_eq!(batch(steps), Ok(16), "16 000 is within the bound");
        let steps = |k: usize| Some(1_500 * k as u64);
        assert_eq!(batch(steps), Ok(8), "24 000 is past, 12 000 is within");
        let steps = |k: usize| Some(8_000 * k as u64);
        assert_eq!(batch(steps), Ok(2), "32 000 is past, 16 000 is within");
        assert_eq!(batch(|k| Some(9_500 * k as u64)), Err(Stop::NoBatch));
        assert_eq!(batch(|_| None), Err(Stop::NoBatch));
    }

    #[test]
    fn the_limit_is_the_largest_multiple_of_eight_under_the_line() {
        // 5 000 + 20 per socket: 17 449 is the allowed, 622 sockets away.
        let flat = [8, 64, 256].map(|n| Point {
            sockets: n,
            ticks: 5_000 + 20 * n as u64,
        });
        assert_eq!(limit(&flat), Ok(256));
        // 5 000 + 100 per socket: (17 449 - 5 000) / 100 = 124.
        let steep = [8, 64, 256].map(|n| Point {
            sockets: n,
            ticks: 5_000 + 100 * n as u64,
        });
        assert_eq!(limit(&steep), Ok(120));
        // The line passes through the points: the margin is on the bound.
        let exact = [8, 64, 256].map(|n| Point {
            sockets: n,
            ticks: 4_000 + 50 * n as u64,
        });
        assert_eq!(limit(&exact), Ok(256));
    }

    #[test]
    fn a_limit_below_the_least_stops() {
        let steep = [8, 64, 256].map(|n| Point {
            sockets: n,
            ticks: 5_000 + 300 * n as u64,
        });
        assert_eq!(limit(&steep), Err(Stop::LimitTooLow(40)));
        let past = [8, 64, 256].map(|n| Point {
            sockets: n,
            ticks: 20_000 + n as u64,
        });
        assert_eq!(limit(&past), Err(Stop::LimitTooLow(0)));
    }
}
