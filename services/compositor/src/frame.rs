// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The clock of the frame, as logic with no call of the kernel in it, so that
//! the host tests it (stage G5). Times are nanoseconds on the scale of the
//! counter; the service reads the counter and converts. Nothing here arms a
//! timer: `Pacer` says when one is needed (`Wake`) and the program arms it.
//!
//! * `Clock`: the starts of the periods, t(k) = t0 + k T, each computed by
//!   a multiplication, so no start is off by what the ones before it were.
//! * `Pacer`: what happens at a start. A change that arrives in the middle
//!   of a period is taken at the nearest start after it; a frame is in work
//!   until the device shows it, and a start that finds one in work takes
//!   nothing, which the next taking counts as skipped periods; a frame is
//!   late when it is shown after the start of the period after the one it
//!   was taken in; the bands of a period are capped (`band_cap`), and what
//!   the cap puts off waits for the next start. The timer is needed only
//!   while a change waits with no frame in work, or while bands are put off:
//!   an idle screen never wakes the service.
//! * `Pace`: one window's promise. A window with interval N (1 to 4) is
//!   taken at most once in N periods and awaited at the start e = k + N after
//!   a taking at k: a buffer posted by then is on time, one posted after e
//!   and by the start e + 1 is late, and none by e + 1 is a miss. A window
//!   that went quiet is missed once for its pause. A window with interval 0
//!   is counted for nothing of that.
//! * `Counters`: the counters and the greatest values of the whole service,
//!   and the histogram of the time of a frame.
//!
//! The definitions are those of the design of the frame clock: the time of a
//! frame is t_shown - t(k), the time to compose t_commit - t(k), the delay of
//! a taking t_take - t(k), the time of the device t_shown - t_commit.

use proto_comp::{BUCKETS, INTERVAL_MAX, Stats, WindowStats};

/// The nanoseconds of one tick of the model that prices a band
/// (`BAND_TICKS`, `BAND_GATE`): the counter of a run under -icount, 62.5 MHz.
pub const TICK_NS: u64 = 16;

/// The default period, 60 Hz, and the default cap of the work of a period in
/// parts a million of it.
pub const DEFAULT_PERIOD_NS: u64 = 16_666_667;
pub const DEFAULT_CAP_PPM: u64 = 750_000;

/// The bands a period holds at most: the cap, as a part of the period, over
/// the gate of a band (`BAND_GATE`), at least one. The service and the probes
/// take the cap from this function alone.
pub const fn band_cap(period_ns: u64, cap_ppm: u64) -> u32 {
    let ticks = period_ns * cap_ppm / 1_000_000 / TICK_NS;
    let bands = ticks / crate::BAND_GATE as u64;
    if bands == 0 { 1 } else { bands as u32 }
}

/// The own arguments of the service's record: the period and the cap of the
/// work of a period in parts a million of it, two u64. No arguments are the
/// defaults (60 Hz, 750 000); a period of 0 is the free run (its cap is not
/// read); bytes past the sixteen are not read, and fewer than sixteen are the
/// defaults. A period outside 1 ms to 1 s, or a cap outside 1 to 1 000 000,
/// makes no sense (a period of a nanosecond would be a storm of skipped
/// periods, a very long one overflows `band_cap`): the defaults, and the third
/// word is true so that the caller says so on the console.
pub fn parse_args(own: &[u8]) -> (u64, u64, bool) {
    let word = |i: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&own[8 * i..8 * i + 8]);
        u64::from_le_bytes(b)
    };
    if own.len() < 16 {
        return (DEFAULT_PERIOD_NS, DEFAULT_CAP_PPM, !own.is_empty());
    }
    let (period, cap) = (word(0), word(1));
    if period == 0 {
        return (0, cap, false);
    }
    if !(1_000_000..=1_000_000_000).contains(&period) || !(1..=1_000_000).contains(&cap) {
        return (DEFAULT_PERIOD_NS, DEFAULT_CAP_PPM, true);
    }
    (period, cap, false)
}

/// The starts of the periods.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    pub t0: u64,
    pub period: u64,
}

impl Clock {
    pub const fn new(t0: u64, period: u64) -> Clock {
        assert!(period > 0);
        Clock { t0, period }
    }

    /// The start of period `k`.
    pub const fn start(&self, k: u64) -> u64 {
        self.t0 + k * self.period
    }

    /// The period `t` lies in: the last start at or before it (0 before the
    /// first).
    pub const fn index(&self, t: u64) -> u64 {
        if t < self.t0 {
            0
        } else {
            (t - self.t0) / self.period
        }
    }

    /// The first start at or after `t`: its number.
    pub const fn next(&self, t: u64) -> u64 {
        if t <= self.t0 {
            0
        } else {
            (t - self.t0).div_ceil(self.period)
        }
    }
}

/// What the caller does with its timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wake {
    /// Nothing: no timer is needed.
    None,
    /// Arm the timer for this time (a time already past fires at once).
    At(u64),
    /// Take now: the free run, which has no periods.
    Now,
}

/// What a firing of the timer asks of the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fire {
    /// Nothing is due: no frame was wanted, or one is in work.
    Idle,
    /// Take the posted buffers and begin the frame of period `k`.
    Take(u64),
    /// Go on with the bands a cap put off.
    Continue,
    /// The expiry came before the time the timer is armed for (the kernel
    /// delivers the expiry of an earlier deadline that `timer_set` has moved
    /// since): nothing is done, the timer stays armed, and no wakeup is counted.
    Early,
}

/// What the caller does after a band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    /// The next band may follow.
    Go,
    /// The cap of the period is reached: wait for the timer at this time.
    Defer(u64),
}

/// The frame in work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Work {
    k: u64,
    taken_at: u64,
    committed_at: Option<u64>,
}

/// The decisions at the starts of the periods.
#[derive(Clone, Debug)]
pub struct Pacer {
    clock: Clock,
    /// The bands a period holds at most.
    cap: u32,
    /// The first start after the change that waits for a frame.
    pending: Option<u64>,
    work: Option<Work>,
    /// The time the timer is armed for.
    armed: Option<u64>,
    /// Bands put off wait for the next start.
    deferred: bool,
    /// The period the bands are counted in, and how many.
    band_period: u64,
    bands: u32,
    /// The period `capped` was last counted for.
    capped_period: Option<u64>,
    pub counters: Counters,
}

impl Pacer {
    /// A pacer of period `period` (0 is the free run) from `t0`, with a cap of
    /// `cap` bands a period.
    pub fn new(t0: u64, period: u64, cap: u32) -> Pacer {
        Pacer {
            clock: Clock::new(t0, period.max(1)),
            cap,
            pending: None,
            work: None,
            armed: None,
            deferred: false,
            band_period: 0,
            bands: 0,
            capped_period: None,
            counters: Counters::new(t0, period),
        }
    }

    fn free(&self) -> bool {
        self.counters.period == 0
    }

    /// Whether this is the free run (no period).
    pub fn is_free(&self) -> bool {
        self.free()
    }

    /// A taking found nothing to take (only windows held by their intervals):
    /// the frame is not made, the taking is not counted, and the timer is
    /// wanted again for what is owed.
    pub fn nothing_taken(&mut self, now: u64) -> Wake {
        if self.work.take().is_some() {
            self.counters.releases = self.counters.releases.saturating_sub(1);
        }
        self.armed = None;
        self.arm(self.clock.next(now))
    }

    pub fn clock(&self) -> &Clock {
        &self.clock
    }

    /// Whether a frame is in work.
    pub fn busy(&self) -> bool {
        self.work.is_some()
    }

    /// Whether the timer is armed.
    pub fn armed(&self) -> bool {
        self.armed.is_some()
    }

    /// A change came at `now` (a post, a flush, a window that went, the
    /// manager), that a window may have it taken `not_before` a period only
    /// (its interval): it waits for the first start at or after both. The
    /// pacer keeps one `pending` for the whole service, the least of the starts
    /// its changes are owed, so `not_before` is the earliest start for the
    /// window that gave it and says nothing of the others: a taking that
    /// another window's change brings on can come before it, and the frame
    /// then leaves that window's buffer posted (`Scene::begin` takes only the
    /// windows `Pace::due`) and the caller says `hold` with the start it is due.
    /// The timer is armed for it when no frame is in work.
    pub fn change(&mut self, now: u64, not_before: Option<u64>) -> Wake {
        if self.free() {
            self.pending = Some(0);
            return if self.work.is_some() {
                Wake::None
            } else {
                Wake::Now
            };
        }
        let first = self.clock.next(now).max(not_before.unwrap_or(0));
        // The earliest start a waiting change is owed.
        self.pending = Some(self.pending.map_or(first, |p| p.min(first)));
        self.arm(self.clock.next(now))
    }

    /// The timer's time for the pending change, when one is needed: a
    /// change waits, no frame is in work, bands are not put off, and the
    /// timer is not armed for it already. The start is the pending one or,
    /// when the change has waited, the first at or after `from`.
    fn arm(&mut self, from: u64) -> Wake {
        let Some(p) = self.pending else {
            return Wake::None;
        };
        if self.work.is_some() || self.deferred {
            return Wake::None;
        }
        let at = self.clock.start(p.max(from));
        if self.armed == Some(at) {
            return Wake::None;
        }
        self.armed = Some(at);
        Wake::At(at)
    }

    /// The timer fired at `now`.
    pub fn fire(&mut self, now: u64) -> Fire {
        if let Some(at) = self.armed
            && now < at
        {
            return Fire::Early;
        }
        self.armed = None;
        self.counters.wakeups += 1;
        if self.deferred {
            self.deferred = false;
            return Fire::Continue;
        }
        let Some(p) = self.pending else {
            return Fire::Idle;
        };
        if self.work.is_some() {
            return Fire::Idle;
        }
        let k = self.clock.index(now).max(p);
        if k > p {
            self.counters.skipped += (k - p) as u32;
        }
        self.counters.releases += 1;
        self.counters.take_max_ns = self
            .counters
            .take_max_ns
            .max(now.saturating_sub(self.clock.start(k)));
        self.pending = None;
        self.work = Some(Work {
            k,
            taken_at: now,
            committed_at: None,
        });
        Fire::Take(k)
    }

    /// A window the frame did not take (its interval says its buffer is due at
    /// the start `due`, a later one) keeps its change: the next taking is owed
    /// no later than that start. The timer is armed when the frame is shown.
    pub fn hold(&mut self, due: u64) {
        self.pending = Some(self.pending.map_or(due, |p| p.min(due)));
    }

    /// In the free run a frame begins at `now` (nothing waited for a start).
    pub fn take_now(&mut self, now: u64) {
        self.pending = None;
        self.counters.releases += 1;
        self.work = Some(Work {
            k: 0,
            taken_at: now,
            committed_at: None,
        });
    }

    /// A band was made, by the wall in `ns`; `more` bands of the frame are
    /// left. At the cap of the period the next one waits for the next start.
    pub fn band_done(&mut self, now: u64, ns: u64, more: bool) -> Band {
        self.counters.band_max_ns = self.counters.band_max_ns.max(ns);
        if self.free() {
            return Band::Go;
        }
        let period = self.clock.index(now);
        if period != self.band_period {
            self.band_period = period;
            self.bands = 0;
        }
        self.bands += 1;
        if !more || self.bands < self.cap {
            return Band::Go;
        }
        if self.capped_period != Some(period) {
            self.capped_period = Some(period);
            self.counters.capped += 1;
        }
        self.deferred = true;
        let at = self.clock.start(period + 1);
        self.armed = Some(at);
        Band::Defer(at)
    }

    /// The frame's last step of work ended at `now`: its commit.
    pub fn committed(&mut self, now: u64) {
        if let Some(work) = &mut self.work {
            work.committed_at = Some(now);
            let spent = now.saturating_sub(self.clock.start(work.k));
            if !self.free() {
                self.counters.compose_max_ns = self.counters.compose_max_ns.max(spent);
            }
        }
    }

    /// The device answered at `now` (`ok` for FRAME_SHOWN): the frame is done.
    /// `direct` marks a frame shown straight from a buffer. When a change
    /// waits the timer is wanted for the next start.
    pub fn shown(&mut self, now: u64, ok: bool, direct: bool) -> Wake {
        let Some(work) = self.work.take() else {
            return Wake::None;
        };
        let c = &mut self.counters;
        if !ok {
            c.failed += 1;
        } else {
            c.frames += 1;
            if let Some(at) = work.committed_at {
                c.device_max_ns = c.device_max_ns.max(now.saturating_sub(at));
            }
            if c.period == 0 {
                c.frame_max_ns = c.frame_max_ns.max(now.saturating_sub(work.taken_at));
            } else {
                let start = self.clock.start(work.k);
                let time = now.saturating_sub(start);
                c.frame_max_ns = c.frame_max_ns.max(time);
                c.hist[bucket(time, c.period)] += 1;
                if direct {
                    c.direct_max_ns = c.direct_max_ns.max(time);
                }
                // Late: shown after the start of the next period; on it is
                // in time.
                if now > self.clock.start(work.k + 1) {
                    c.late += 1;
                }
            }
            if direct {
                c.direct += 1;
            }
        }
        if self.free() {
            return if self.pending.is_some() {
                Wake::Now
            } else {
                Wake::None
            };
        }
        // A change that waited is taken at the nearest start after the show.
        self.armed = None;
        self.arm(self.clock.next(now))
    }

    /// STATS' counters at `now`, in microseconds.
    pub fn stats(&self, now: u64) -> Stats {
        self.counters.snapshot(now, self.cap, self.clock.period)
    }
}

/// The bucket of a time of a frame: 32 of a sixteenth of the period up to
/// twice the period, and the last for twice the period and more.
pub fn bucket(time: u64, period: u64) -> usize {
    if period == 0 {
        return BUCKETS - 1;
    }
    let b = (time * 16 / period) as usize;
    b.min(BUCKETS - 1)
}

/// The counters of the service and the greatest values, in nanoseconds.
#[derive(Clone, Debug)]
pub struct Counters {
    pub period: u64,
    pub since: u64,
    pub releases: u32,
    pub frames: u32,
    pub direct: u32,
    pub late: u32,
    pub skipped: u32,
    pub failed: u32,
    pub capped: u32,
    pub wakeups: u32,
    pub take_max_ns: u64,
    pub compose_max_ns: u64,
    pub device_max_ns: u64,
    pub frame_max_ns: u64,
    pub direct_max_ns: u64,
    pub band_max_ns: u64,
    pub hist: [u32; BUCKETS],
}

impl Counters {
    pub const fn new(now: u64, period: u64) -> Counters {
        Counters {
            period,
            since: now,
            releases: 0,
            frames: 0,
            direct: 0,
            late: 0,
            skipped: 0,
            failed: 0,
            capped: 0,
            wakeups: 0,
            take_max_ns: 0,
            compose_max_ns: 0,
            device_max_ns: 0,
            frame_max_ns: 0,
            direct_max_ns: 0,
            band_max_ns: 0,
            hist: [0; BUCKETS],
        }
    }

    /// Everything counted starts again from `now`; the period stays.
    pub fn reset(&mut self, now: u64) {
        *self = Counters::new(now, self.period);
    }

    /// The reply's counters: times in microseconds (rounded down, at most
    /// u32::MAX), the time since the reset in milliseconds, the cap as the
    /// time `cap` bands take at the model's rate.
    pub fn snapshot(&self, now: u64, cap_bands: u32, period: u64) -> Stats {
        let us = |ns: u64| (ns / 1_000).min(u64::from(u32::MAX)) as u32;
        Stats {
            period_us: us(period),
            cap_us: us(u64::from(cap_bands) * u64::from(crate::BAND_GATE) * TICK_NS),
            since_ms: (now.saturating_sub(self.since) / 1_000_000).min(u64::from(u32::MAX)) as u32,
            releases: self.releases,
            frames: self.frames,
            direct: self.direct,
            late: self.late,
            skipped: self.skipped,
            failed: self.failed,
            capped: self.capped,
            wakeups: self.wakeups,
            take_max_us: us(self.take_max_ns),
            compose_max_us: us(self.compose_max_ns),
            device_max_us: us(self.device_max_ns),
            frame_max_us: us(self.frame_max_ns),
            direct_max_us: us(self.direct_max_ns),
            band_max_us: us(self.band_max_ns),
            hist: self.hist,
        }
    }
}

/// A window's promise and its counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pace {
    interval: u32,
    /// The period the window is awaited at, after a taking.
    expected: Option<u64>,
    pub posts: u32,
    pub taken: u32,
    pub replaced: u32,
    pub late: u32,
    pub missed: u32,
    pub late_max_ns: u64,
}

impl Pace {
    pub const fn new() -> Pace {
        Pace {
            interval: 0,
            expected: None,
            posts: 0,
            taken: 0,
            replaced: 0,
            late: 0,
            missed: 0,
            late_max_ns: 0,
        }
    }

    pub const fn interval(&self) -> u32 {
        self.interval
    }

    /// SET INTERVAL: 0 to INTERVAL_MAX (false for more). The window is
    /// awaited no more until it has been taken again.
    pub fn set_interval(&mut self, n: u32) -> bool {
        if n > INTERVAL_MAX {
            return false;
        }
        self.interval = n;
        self.expected = None;
        true
    }

    /// The first period the window's next buffer may be taken in: the start it
    /// is awaited at, for a window with an interval that was taken; None
    /// when it may be taken at any start.
    pub const fn earliest(&self) -> Option<u64> {
        if self.interval == 0 {
            None
        } else {
            self.expected
        }
    }

    /// Whether a buffer of the window may be taken at the start of period `k`.
    pub const fn due(&self, k: u64) -> bool {
        match self.earliest() {
            Some(e) => k >= e,
            None => true,
        }
    }

    /// RESET: the counts start again; the interval and the start the window is
    /// awaited at stay.
    pub fn reset_counts(&mut self) {
        *self = Pace {
            interval: self.interval,
            expected: self.expected,
            ..Pace::new()
        };
    }

    /// A buffer was taken with no clock to count periods by (the free run).
    pub fn count_taken(&mut self) {
        self.taken += 1;
    }

    /// A post with no interval to judge: counted.
    pub fn count_post(&mut self, replaced: bool) {
        self.posts += 1;
        if replaced {
            self.replaced += 1;
        }
    }

    /// The window's counters as STATS' record of window `id`.
    pub fn record(&self, id: u32) -> WindowStats {
        WindowStats {
            id,
            interval: self.interval,
            posts: self.posts,
            taken: self.taken,
            replaced: self.replaced,
            late: self.late,
            missed: self.missed,
            late_max_us: (self.late_max_ns / 1_000).min(u64::from(u32::MAX)) as u32,
        }
    }

    /// The window is a miss at `now` when it was awaited and the start after
    /// the awaited one has passed with nothing posted: counted once, and the
    /// window is awaited no more.
    pub fn settle(&mut self, clock: &Clock, now: u64) {
        if let Some(e) = self.expected
            && now > clock.start(e + 1)
        {
            self.missed += 1;
            self.expected = None;
        }
    }

    /// A buffer was posted at `now`, `replaced` when it displaced one not yet
    /// taken. With an interval the post is judged against the start it was
    /// awaited at: on time, late (counted, and the greatest lateness), or
    /// after a miss. The first period the buffer may be taken in is returned
    /// for `Pacer::change`.
    pub fn posted(&mut self, clock: &Clock, now: u64, replaced: bool) -> Option<u64> {
        self.posts += 1;
        if replaced {
            self.replaced += 1;
        }
        if self.interval == 0 {
            return None;
        }
        self.settle(clock, now);
        let e = self.expected?;
        let due = clock.start(e);
        if now > due {
            // Between the awaited start and the next: late, and taken at the
            // next start.
            self.late += 1;
            self.late_max_ns = self.late_max_ns.max(now - due);
            self.expected = None;
            None
        } else {
            // On time, or early: taken at the awaited start and not before.
            Some(e)
        }
    }

    /// The window's buffer was taken into the frame of period `k`.
    pub fn took(&mut self, k: u64) {
        self.taken += 1;
        if self.interval > 0 {
            self.expected = Some(k + u64::from(self.interval));
        }
    }
}

/// The response-time bound of the frame (the analysis of the design): the
/// least `w` with `w = own + sum I_j(w)`, in ticks, where a source above the
/// service with a budget `c` of every `t` ticks makes
/// `I(w) = floor(w/t) c + min(w mod t, c) + step + 2 e ceil(w/t)`: the whole
/// budgets of the periods that began, a part of the last, one step of the
/// service that has it (`step`, the longest of its steps) and the events of
/// the budget, `e` ticks each, two for each period. None when the iteration
/// does not settle within `limit` ticks, which is the case for shares that sum
/// to 1 or more.
///
/// The term `2 e ceil(w/t)` carries the cost of a preemption, which belongs to
/// the preempting source: two switches of 1 300 ticks each. The bound assumes at
/// most two preemptions from a source in its period; a source that wakes more
/// often (the network's under load) breaks the assumption, and the term of the
/// preemptions is separate from the events of the budget once the budgets have
/// their specification.
pub fn bound(own: u64, sources: &[Source], e: u64, limit: u64) -> Option<u64> {
    let mut w = own;
    // A sum of shares of 1 or more never settles: the value passes the limit
    // (or the rounds run out) and there is no bound. A sum a little under 1
    // settles slowly, which the rounds allow for.
    for _ in 0..1_000_000 {
        let mut next = own;
        for s in sources {
            let periods = w / s.period;
            let rest = w % s.period;
            next += periods * s.budget + rest.min(s.budget) + s.step + 2 * e * w.div_ceil(s.period);
        }
        if next == w {
            return Some(w);
        }
        if next > limit {
            return None;
        }
        w = next;
    }
    None
}

/// A source of interference above the service: a budget of `budget` ticks
/// every `period` ticks, and the longest step `step` of the service that has
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub budget: u64,
    pub period: u64,
    pub step: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = DEFAULT_PERIOD_NS;

    fn pacer() -> Pacer {
        Pacer::new(1_000, T, 52)
    }

    #[test]
    fn the_starts_do_not_drift_over_a_million_periods() {
        let c = Clock::new(123_456_789, T);
        for k in (0..1_000_000u64).step_by(7) {
            assert_eq!(c.start(k), 123_456_789 + k * 16_666_667);
            assert_eq!(c.index(c.start(k)), k);
            assert_eq!(c.next(c.start(k)), k);
            if k > 0 {
                assert_eq!(c.index(c.start(k) - 1), k - 1);
                assert_eq!(c.next(c.start(k) - 1), k);
            }
            assert_eq!(c.next(c.start(k) + 1), k + 1);
        }
        assert_eq!(c.start(1_000_000), 123_456_789 + 16_666_667_000_000);
        // Before the first start.
        assert_eq!(c.index(5), 0);
        assert_eq!(c.next(5), 0);
    }

    #[test]
    fn a_change_in_the_middle_of_a_period_is_taken_at_the_nearest_start() {
        let mut p = pacer();
        let c = *p.clock();
        let now = c.start(3) + T / 2;
        // The timer is armed for the start of period 4, which lies after now.
        assert_eq!(p.change(now, None), Wake::At(c.start(4)));
        assert_eq!(p.fire(c.start(4)), Fire::Take(4));
        assert_eq!(p.counters.skipped, 0);
        assert_eq!(p.counters.take_max_ns, 0);
        // A change exactly on a start is taken at that start.
        let mut p = pacer();
        assert_eq!(p.change(c.start(5), None), Wake::At(c.start(5)));
    }

    #[test]
    fn a_start_that_finds_a_frame_in_work_takes_nothing_and_counts_a_skip() {
        let mut p = pacer();
        let c = *p.clock();
        p.change(c.start(1) - 1, None);
        assert_eq!(p.fire(c.start(1)), Fire::Take(1));
        // A change while the frame is in work arms no timer.
        assert_eq!(p.change(c.start(1) + 10, None), Wake::None);
        // The frame is shown in period 3: the change, owed since period 2,
        // is taken at the next start, 4, and two starts passed (2 and 3).
        let wake = p.shown(c.start(3) + 5, true, false);
        assert_eq!(wake, Wake::At(c.start(4)));
        assert_eq!(p.fire(c.start(4)), Fire::Take(4));
        assert_eq!(p.counters.skipped, 2);
    }

    #[test]
    fn two_periods_without_the_cpu_are_two_skips() {
        let mut p = pacer();
        let c = *p.clock();
        p.change(c.start(1) - 1, None);
        // The timer fires in period 3: the service did not run at 1 and 2.
        assert_eq!(p.fire(c.start(3) + 40), Fire::Take(3));
        assert_eq!(p.counters.skipped, 2);
        assert_eq!(p.counters.take_max_ns, 40);
    }

    #[test]
    fn a_frame_is_late_when_shown_after_the_next_start_and_not_on_it() {
        let c = Clock::new(1_000, T);
        for (offset, late) in [(-1i64, 0), (0, 0), (1, 1)] {
            let mut p = Pacer::new(1_000, T, 52);
            p.change(c.start(2) - 1, None);
            assert_eq!(p.fire(c.start(2)), Fire::Take(2));
            p.committed(c.start(2) + 100);
            let at = (c.start(3) as i64 + offset) as u64;
            p.shown(at, true, false);
            assert_eq!(p.counters.late, late, "offset {offset}");
            assert_eq!(p.counters.frames, 1);
        }
    }

    #[test]
    fn the_times_of_a_frame_are_those_of_the_definitions() {
        let mut p = pacer();
        let c = *p.clock();
        p.change(c.start(1) - 1, None);
        p.fire(c.start(1) + 30);
        p.committed(c.start(1) + 500);
        p.shown(c.start(1) + 900, true, true);
        let s = p.counters.clone();
        assert_eq!(s.take_max_ns, 30);
        assert_eq!(s.compose_max_ns, 500);
        assert_eq!(s.device_max_ns, 400);
        assert_eq!(s.frame_max_ns, 900);
        assert_eq!((s.direct, s.direct_max_ns), (1, 900));
        let stats = p.stats(c.start(1) + 5_000_000);
        assert_eq!((stats.frames, stats.direct, stats.releases), (1, 1, 1));
        assert_eq!(stats.period_us, 16_666);
        assert_eq!(stats.since_ms, 21);
    }

    #[test]
    fn the_cap_puts_the_53rd_band_into_the_next_period() {
        let mut p = pacer();
        let c = *p.clock();
        p.change(c.start(1) - 1, None);
        assert_eq!(p.fire(c.start(1)), Fire::Take(1));
        let at = c.start(1) + 100;
        for n in 1..=51 {
            assert_eq!(p.band_done(at + n, 10, true), Band::Go, "band {n}");
        }
        // The 52nd is made, and the 53rd waits for the next start; `capped`
        // counts the period once however many bands ask.
        assert_eq!(p.band_done(at + 52, 10, true), Band::Defer(c.start(2)));
        assert_eq!(p.counters.capped, 1);
        assert!(p.armed());
        assert_eq!(p.fire(c.start(2)), Fire::Continue);
        assert_eq!(p.counters.capped, 1);
        // The next period has a cap of its own, and the last band of a frame
        // never waits.
        for n in 1..=51 {
            assert_eq!(p.band_done(c.start(2) + n, 10, true), Band::Go);
        }
        assert_eq!(p.band_done(c.start(2) + 60, 10, false), Band::Go);
        assert_eq!(p.counters.capped, 1);
        // A second capped period counts again.
        for n in 1..=51 {
            p.band_done(c.start(3) + n, 10, true);
        }
        assert_eq!(
            p.band_done(c.start(3) + 99, 10, true),
            Band::Defer(c.start(4))
        );
        assert_eq!(p.counters.capped, 2);
        assert_eq!(p.counters.band_max_ns, 10);
    }

    #[test]
    fn the_cap_in_bands_is_47_at_60_hz() {
        // Derived: 0.75 of the period in ticks over the gate of a band.
        let ticks = T * DEFAULT_CAP_PPM / 1_000_000 / TICK_NS;
        let derived = (ticks / u64::from(crate::BAND_GATE)) as u32;
        assert_eq!(band_cap(T, DEFAULT_CAP_PPM), derived);
        // Pinned on purpose: the gate 16 328 and the cap of 60 Hz give 47.
        assert_eq!(derived, 47);
        assert_eq!(band_cap(T, 0), 1);
        assert_eq!(band_cap(T, 1_000_000), 63);
        // The service takes the cap's bands at their gates and the three steps
        // of the frame around them: about 79 percent of a period.
        let service = u64::from(derived) * u64::from(crate::BAND_GATE) + 3 * (20_410 * 9 / 10);
        assert_eq!(service, 822_523);
        let period_ticks = T / TICK_NS;
        assert!((78..80).contains(&(service * 100 / period_ticks)));
    }

    #[test]
    fn without_a_change_no_step_needs_a_timer() {
        let mut p = pacer();
        let c = *p.clock();
        assert!(!p.armed());
        // A firing with nothing wanted is idle and arms nothing.
        assert_eq!(p.fire(c.start(1)), Fire::Idle);
        assert!(!p.armed());
        // A frame that ends with nothing waiting asks for no timer.
        p.change(c.start(1) - 1, None);
        assert_eq!(p.fire(c.start(1)), Fire::Take(1));
        assert_eq!(p.band_done(c.start(1) + 1, 5, false), Band::Go);
        p.committed(c.start(1) + 2);
        assert_eq!(p.shown(c.start(1) + 3, true, false), Wake::None);
        assert!(!p.armed() && !p.busy());
    }

    #[test]
    fn the_timer_is_armed_once_for_a_start() {
        let mut p = pacer();
        let c = *p.clock();
        assert_eq!(p.change(c.start(2) - 10, None), Wake::At(c.start(2)));
        assert_eq!(p.change(c.start(2) - 5, None), Wake::None);
    }

    #[test]
    fn the_free_run_takes_at_once_and_has_no_lateness() {
        let mut p = Pacer::new(0, 0, 52);
        assert_eq!(p.change(10, None), Wake::Now);
        p.take_now(10);
        assert_eq!(p.change(20, None), Wake::None);
        assert_eq!(p.shown(5_000_000_000, true, false), Wake::Now);
        assert_eq!(p.counters.late, 0);
        assert_eq!(p.counters.frame_max_ns, 4_999_999_990);
        assert_eq!(p.stats(0).period_us, 0);
    }

    #[test]
    fn the_time_of_a_frame_goes_into_its_bucket() {
        let t = 1_600;
        assert_eq!(bucket(0, t), 0);
        assert_eq!(bucket(t / 16 - 1, t), 0);
        assert_eq!(bucket(t / 16, t), 1);
        assert_eq!(bucket(2 * t - 1, t), 31);
        assert_eq!(bucket(2 * t, t), 32);
        assert_eq!(bucket(100 * t, t), 32);
        let mut p = Pacer::new(0, t, 52);
        p.change(0, None);
        p.fire(0);
        p.shown(2 * t, true, false);
        assert_eq!(p.counters.hist[32], 1);
        assert_eq!(p.counters.hist.iter().sum::<u32>(), 1);
    }

    #[test]
    fn a_reset_clears_the_counts_and_keeps_the_period() {
        let mut p = pacer();
        let c = *p.clock();
        p.change(c.start(1) - 1, None);
        p.fire(c.start(1));
        p.shown(c.start(1) + 10, true, false);
        p.counters.reset(c.start(9));
        let s = p.stats(c.start(9));
        assert_eq!((s.frames, s.releases, s.wakeups), (0, 0, 0));
        assert_eq!(s.period_us, 16_666);
        assert_eq!(s.hist, [0; BUCKETS]);
    }

    // ---- the window's promise

    fn clock() -> Clock {
        Clock::new(0, 1_000)
    }

    /// A window of interval `n` taken at period `k`.
    fn taken_at(n: u32, k: u64) -> Pace {
        let mut w = Pace::new();
        assert!(w.set_interval(n));
        w.took(k);
        w
    }

    #[test]
    fn interval_1_on_time_late_and_missed() {
        let c = clock();
        // Taken at 3, awaited at 4 (t = 4000).
        let mut w = taken_at(1, 3);
        // Early or exactly on the start: on time, taken at 4.
        assert_eq!(w.posted(&c, 3_500, false), Some(4));
        assert_eq!(w.posted(&c, 4_000, false), Some(4));
        assert_eq!((w.late, w.missed), (0, 0));
        // One tick after: late by a tick, taken at the next start.
        let mut w = taken_at(1, 3);
        assert_eq!(w.posted(&c, 4_001, false), None);
        assert_eq!((w.late, w.late_max_ns), (1, 1));
        let mut w = taken_at(1, 3);
        w.posted(&c, 4_999, false);
        assert_eq!((w.late, w.late_max_ns, w.missed), (1, 999, 0));
        // At the start after that nothing came: a miss, and the post that
        // follows is no one's lateness.
        let mut w = taken_at(1, 3);
        assert_eq!(w.posted(&c, 5_001, false), None);
        assert_eq!((w.late, w.missed), (0, 1));
        assert_eq!(w.record(7).late_max_us, 0);
    }

    #[test]
    fn a_quiet_window_is_missed_once_for_its_pause() {
        let c = clock();
        let mut w = taken_at(1, 3);
        w.settle(&c, 5_000);
        assert_eq!(w.missed, 0);
        w.settle(&c, 5_001);
        assert_eq!(w.missed, 1);
        // Asking again, or posting after the pause, adds nothing.
        w.settle(&c, 90_000);
        w.posted(&c, 91_000, false);
        w.settle(&c, 92_000);
        assert_eq!(w.missed, 1);
        // A window that is taken again is awaited again and can miss again.
        w.took(100);
        w.settle(&c, 102_000);
        assert_eq!(w.missed, 1);
        w.settle(&c, 102_001);
        assert_eq!(w.missed, 2);
    }

    #[test]
    fn interval_2_takes_a_buffer_at_most_every_two_periods() {
        let c = clock();
        let mut w = taken_at(2, 3);
        // Awaited at 5: a post in period 4 is held until 5.
        assert_eq!(w.posted(&c, 4_200, false), Some(5));
        // The pacer takes it no earlier than 5.
        let mut p = Pacer::new(0, 1_000, 52);
        assert_eq!(p.change(4_200, Some(5)), Wake::At(5_000));
        assert_eq!(p.fire(5_000), Fire::Take(5));
        w.took(5);
        assert_eq!(w.taken, 2);
        // And the next is awaited at 7.
        assert_eq!(w.posted(&c, 6_100, false), Some(7));
    }

    #[test]
    fn a_window_with_no_interval_counts_no_lateness() {
        let c = clock();
        let mut w = Pace::new();
        w.took(3);
        assert_eq!(w.posted(&c, 900_000, false), None);
        w.settle(&c, 99_000_000);
        assert_eq!((w.late, w.missed, w.posts), (0, 0, 1));
        // A replaced buffer is counted.
        w.posted(&c, 900_001, true);
        assert_eq!((w.replaced, w.posts), (1, 2));
    }

    #[test]
    fn the_interval_is_bounded_and_the_record_is_the_windows() {
        let mut w = Pace::new();
        assert!(w.set_interval(4));
        assert!(!w.set_interval(5));
        assert_eq!(w.interval(), 4);
        let c = clock();
        w.took(0);
        w.posted(&c, 4_000 + 3_000_000, false);
        let r = w.record(9);
        assert_eq!(
            (r.id, r.interval, r.posts, r.taken, r.missed),
            (9, 4, 1, 1, 1)
        );
    }

    #[test]
    fn the_arguments_are_the_period_and_the_cap_or_the_defaults() {
        let words = |a: u64, b: u64| {
            let mut v = Vec::new();
            v.extend_from_slice(&a.to_le_bytes());
            v.extend_from_slice(&b.to_le_bytes());
            v
        };
        assert_eq!(parse_args(&[]), (16_666_667, 750_000, false));
        // Fewer than sixteen bytes are a mistake the caller tells of.
        assert_eq!(parse_args(&[1; 15]), (16_666_667, 750_000, true));
        assert_eq!(
            parse_args(&words(8_333_333, 500_000)),
            (8_333_333, 500_000, false)
        );
        // The free run, with bytes past the sixteen.
        let mut free = words(0, 0);
        assert_eq!(parse_args(&free), (0, 0, false));
        free.extend_from_slice(&[9; 5]);
        assert_eq!(parse_args(&free), (0, 0, false));
        // The edges of the period and of the cap.
        assert!(!parse_args(&words(1_000_000, 1)).2);
        assert!(!parse_args(&words(1_000_000_000, 1_000_000)).2);
        for bad in [
            words(1, 750_000),
            words(999_999, 750_000),
            words(1_000_000_001, 750_000),
            words(u64::MAX, 750_000),
            words(16_666_667, 0),
            words(16_666_667, 1_000_001),
        ] {
            assert_eq!(parse_args(&bad), (16_666_667, 750_000, true));
        }
    }

    #[test]
    fn a_taking_that_found_nothing_is_not_counted_and_asks_for_the_owed_start() {
        let mut p = pacer();
        let c = *p.clock();
        p.change(c.start(4) - 1, None);
        assert_eq!(p.fire(c.start(4)), Fire::Take(4));
        // The frame took none of the windows: they are due at 6.
        p.hold(6);
        assert_eq!(p.nothing_taken(c.start(4) + 10), Wake::At(c.start(6)));
        assert_eq!(p.counters.releases, 0);
        assert!(!p.busy());
    }

    #[test]
    fn a_stale_expiry_before_the_armed_time_does_nothing() {
        let mut p = pacer();
        let c = *p.clock();
        assert_eq!(p.change(c.start(2) - 500, None), Wake::At(c.start(2)));
        // An expiry delivered for an earlier deadline: nothing is taken, the
        // timer stays armed, and no wakeup is counted.
        assert_eq!(p.fire(c.start(2) - 1), Fire::Early);
        assert!(p.armed() && !p.busy());
        assert_eq!(p.counters.wakeups, 0);
        assert_eq!(p.fire(c.start(2)), Fire::Take(2));
        assert_eq!(p.counters.wakeups, 1);
        // The same for bands put off by the cap.
        for n in 1..=51 {
            p.band_done(c.start(2) + n, 1, true);
        }
        assert_eq!(
            p.band_done(c.start(2) + 60, 1, true),
            Band::Defer(c.start(3))
        );
        assert_eq!(p.fire(c.start(3) - 1), Fire::Early);
        assert!(p.armed());
        assert_eq!(p.fire(c.start(3)), Fire::Continue);
        assert_eq!(p.counters.wakeups, 2);
    }

    /// A window of interval 2 waits for its start e while another window's
    /// change brings a taking at k < e: the frame leaves it, `hold` keeps the
    /// pacer owing it, and the next taking is at e with no new post.
    #[test]
    fn a_window_held_by_its_interval_is_taken_at_its_start_without_a_new_post() {
        let mut p = Pacer::new(0, 1_000, 52);
        let c = *p.clock();
        let mut a = Pace::new();
        let mut b = Pace::new();
        assert!(b.set_interval(2));
        b.took(3); // awaited at 5
        assert_eq!(b.earliest(), Some(5));
        // B posts in period 4: its buffer waits for 5.
        let not_before = b.posted(&c, 4_200, false);
        assert_eq!(not_before, Some(5));
        assert_eq!(p.change(4_200, not_before), Wake::At(5_000));
        // A posts in period 3: the nearest start is 4.
        a.posted(&c, 3_500, false);
        assert_eq!(p.change(3_500, None), Wake::At(4_000));
        assert_eq!(p.fire(4_000), Fire::Take(4));
        // The frame takes A and not B, which is not due; the pacer owes it 5.
        assert!(a.due(4) && !b.due(4));
        a.took(4);
        p.hold(b.earliest().unwrap());
        assert_eq!(p.shown(4_300, true, false), Wake::At(5_000));
        assert_eq!(p.fire(5_000), Fire::Take(5));
        assert!(b.due(5));
        b.took(5);
        assert_eq!(b.taken, 2);
        assert_eq!(p.counters.skipped, 0);
        assert_eq!(p.shown(5_200, true, false), Wake::None);
    }

    #[test]
    fn a_reset_clears_the_counts_of_a_window_and_keeps_its_interval_and_awaited_start() {
        let c = clock();
        let mut w = taken_at(2, 3);
        w.posted(&c, 4_500, true);
        w.posted(&c, 4_600, false);
        assert!(w.posts > 0 && w.taken > 0 && w.replaced > 0);
        w.settle(&c, 9_000);
        assert_eq!(w.missed, 1);
        let kept = w.earliest();
        w.reset_counts();
        assert_eq!(
            (
                w.posts,
                w.taken,
                w.replaced,
                w.late,
                w.missed,
                w.late_max_ns
            ),
            (0, 0, 0, 0, 0, 0)
        );
        assert_eq!(w.interval(), 2);
        assert_eq!(w.earliest(), kept);
        let mut v = taken_at(2, 3);
        v.reset_counts();
        assert_eq!((v.interval(), v.earliest()), (2, Some(5)));
    }

    // ---- the bound

    #[test]
    fn the_bound_is_the_response_time_of_the_design() {
        // No source: the work alone.
        assert_eq!(bound(100, &[], 10, 1_000_000), Some(100));
        // One source of 10 every 100 with a step of 5 and events of 1: a work
        // of 100 settles where w = 100 + 10 floor(w/100) + min(w mod 100, 10)
        // + 5 + 2 ceil(w/100).
        let s = Source {
            budget: 10,
            period: 100,
            step: 5,
        };
        let w = bound(100, &[s], 1, 1_000_000).unwrap();
        let i = |w: u64| 10 * (w / 100) + (w % 100).min(10) + 5 + 2 * w.div_ceil(100);
        assert_eq!(w, 100 + i(w));
        // The least such w: one less does not satisfy it.
        assert!(w - 1 < 100 + i(w - 1));
        // A source of the share 1 or more has no bound.
        let full = Source {
            budget: 100,
            period: 100,
            step: 0,
        };
        assert_eq!(bound(1, &[full], 0, 1_000_000), None);
        let two = [
            Source {
                budget: 60,
                period: 100,
                step: 0,
            },
            Source {
                budget: 40,
                period: 100,
                step: 0,
            },
        ];
        assert_eq!(bound(1, &two, 0, 1_000_000), None);
        // The floor of the first term: a ceiling there gives more.
        let more = |w: u64| 10 * w.div_ceil(100) + (w % 100).min(10) + 5 + 2 * w.div_ceil(100);
        assert!(100 + more(w) > w);
    }

    /// The rows of the design's table of bounds (section 9 of the plan): each
    /// source steps 18 369 ticks, the events are 1 875, the budgets are rounded
    /// up in ticks of 62.5 MHz.
    #[test]
    fn the_four_rows_of_the_table_of_bounds() {
        // The terms come from term B (20 410): a step of a source is 0.9 B, the
        // gate of a band 0.8 B, the longest kernel path and a step B + 0.9 B.
        let term_b: u64 = 20_410;
        let step = term_b * 9 / 10;
        let gate = term_b * 8 / 10;
        let kernel = term_b + step;
        assert_eq!((step, gate, kernel), (18_369, 16_328, 38_779));
        assert_eq!(gate, u64::from(crate::BAND_GATE));
        let src = |budget, period| Source {
            budget,
            period,
            step,
        };
        let all = [
            src(9_375, 62_500),   // switch
            src(4_688, 62_500),   // stack0
            src(15_625, 312_500), // ramfs
            src(4_688, 312_500),  // pipe
            src(4_688, 312_500),  // tty
            src(9_375, 625_000),  // console
            src(6_250, 625_000),  // datafs
        ];
        let console = [src(9_375, 625_000)];
        let (e, limit) = (1_875, 10_000_000);
        // The term of the events covers two preemptions of 1 300 ticks.
        assert!(2 * e >= 2 * 1_300);
        // The terms: a band is 16 328, the taking 3 000, the commit and the end
        // 2 x 18 369, the longest kernel path and a step 38 779, the display
        // driver 13 596, the disk 2 x 18 369, the signs of life 64 000, the
        // clients' requests 10 000.
        let own = |bands: u64, disk: bool, requests: bool| {
            let mut w = 3_000 + bands * gate + 2 * step + kernel + 13_596;
            if disk {
                w += 2 * step;
            }
            w += 64_000;
            if requests {
                w += 10_000;
            }
            w
        };
        // P: a window of 160 by 100, its bands from `tile` (7 at 16 lines,
        // pinned on purpose), all the loads.
        let p_bands = {
            let mut scene = crate::Scene::new();
            let r = crate::Rect {
                x: 0,
                y: 0,
                w: 160,
                h: 100,
            };
            let a = scene.create(1, 1, r, true, 0).unwrap();
            scene.flush(a, r).unwrap();
            let damage = scene.begin().unwrap();
            let rows = scene.tile(damage).1;
            scene.end(true);
            u64::from(100u32.div_ceil(rows))
        };
        assert_eq!(p_bands, 7);
        assert_eq!(own(p_bands, true, true), 317_147);
        assert_eq!(bound(317_147, &all, e, limit), Some(924_178));
        // D: a direct frame, no band, all the loads (no taking by bands).
        let d = 2 * step + kernel + 13_596 + 2 * step + 64_000 + 10_000;
        assert_eq!(d, 199_851);
        assert_eq!(bound(d, &all, e, limit), Some(742_193));
        // F: the whole screen, no load: the bands of a copy over the screen by
        // the prices (37 with the terms of a band and of a layer, pinned here on
        // purpose; the rest follows from the code), one band fewer, and the limit
        // of 45 that the probe holds.
        let full = u64::from(crate::full_screen_bands());
        assert_eq!(full, 37);
        assert_eq!(own(full, false, false), 760_249);
        assert_eq!(
            bound(own(full, false, false), &console, e, limit),
            Some(804_868)
        );
        assert_eq!(own(full - 1, false, false), 743_921);
        assert_eq!(
            bound(own(full - 1, false, false), &console, e, limit),
            Some(788_540)
        );
        assert_eq!(own(45, false, false), 890_873);
        assert_eq!(bound(890_873, &console, e, limit), Some(935_492));
        // The network's budgets of the tables (60 percent of the CPU) leave no
        // bound inside a period.
        let net = [src(25_000, 62_500), src(12_500, 62_500)];
        let mut sources = net.to_vec();
        sources.extend_from_slice(&all[2..]);
        assert!(bound(317_147, &sources, e, limit).is_none_or(|w| w > 1_041_667));
    }
}
