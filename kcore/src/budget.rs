// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The time budget of a thread (spec 8): a sporadic server with the budget
//! `c` for each period `t` that drops its thread to the level `low` when
//! the budget is gone and gives it back when a replenishment arrives. The
//! rules are those of the corrected sporadic server of Stanovich, Baker,
//! Wang and Gonzalez Harbour, "Defects of the POSIX Sporadic Server and How
//! to Correct Them" (RTAS 2010, section 6.5, figures 6.3 to 6.5 of the
//! thesis), with the replenishments kept in a queue of at most
//! `MAX_REPLENISHMENTS` entries:
//!
//! - The queue holds replenishments (time, amount) in the order of their
//!   times, and the amounts add up to `c`. The server has capacity while the
//!   head's time is not after `now`: the head's amount less the usage, the
//!   time its thread ran at its own level since the head's time.
//! - `unblock` (the thread became ready, the activation of the server): with
//!   capacity, the head's time moves to `now`, and the replenishments that
//!   are available meanwhile merge into it; without, the head's time is the
//!   time of the replenishment event.
//! - `stop` (the thread left the CPU): its stint counts as usage; with the
//!   capacity gone, the heads that the usage used up go `t` later, as new
//!   replenishments at the tail; what is left of the usage is an overrun,
//!   which is charged against the next head by moving its time later (the
//!   correction of the budget amplification); two heads whose chunks touch
//!   merge (the correction of the premature replenishment); with no
//!   capacity left the thread is in the background, and the replenishment
//!   event is the head's time. When the thread blocks, `split` makes what it
//!   used a replenishment of its own at its activation time plus `t`; with
//!   `MAX_REPLENISHMENTS` entries already, the remnant merges into the next
//!   entry, which postpones it and never advances it (the sliding window
//!   constraint holds).
//! - `replenish` (the event): the thread returns to its own level.
//!
//! The time the thread runs in the background is not charged: it costs the
//! levels at `low` and below, which the budget does not promise anything.
//! Every loop is bounded by `MAX_REPLENISHMENTS`. The scheduler
//! (kcore::sched) applies the levels; the kernel keeps the event in the
//! heaps of the timers.

/// The most pending replenishments: `_POSIX_SS_REPL_MAX`.
pub const MAX_REPLENISHMENTS: usize = 4;

/// A chunk of budget that comes back at `time` ticks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Replenishment {
    pub time: u64,
    pub amount: u64,
}

/// The least budget and period the kernel accepts, in nanoseconds:
/// budget_create checks them (spec 11).
pub use abi::{MIN_BUDGET_NS, MIN_PERIOD_NS};

/// The sporadic server of one thread, in counter ticks.
pub struct Server {
    c: u64,
    t: u64,
    q: [Replenishment; MAX_REPLENISHMENTS],
    /// Ticks the thread ran at its own level since the head's time.
    usage: u64,
    /// The counter at which the running thread's time began to count, and
    /// at which its budget ends if it keeps running (`run`).
    fg_since: u64,
    exhaust_at: u64,
    /// The time of the replenishment event the server wants, and the one the
    /// kernel holds (0 for none: a time that is a future never is 0).
    event: u64,
    armed: u64,
    /// The sum of the ticks that were charged, and the budgets that ran out.
    ran: u64,
    overruns: u32,
    low: u8,
    background: bool,
    len: u8,
}

/// The effect of an operation on the queue, for tests and the kernel's
/// report: the replenishment event the server wants now.
pub type Event = Option<u64>;

impl Server {
    /// A server with the budget `c` for each period `t` ticks, whose thread
    /// drops to `low` when the budget is gone; full at `now`. The caller
    /// checked 0 < c <= t (budget_create).
    pub const fn new(c: u64, t: u64, low: u8, now: u64) -> Server {
        let mut q = [Replenishment { time: 0, amount: 0 }; MAX_REPLENISHMENTS];
        q[0] = Replenishment {
            time: now,
            amount: c,
        };
        Server {
            c,
            t,
            q,
            usage: 0,
            fg_since: 0,
            exhaust_at: 0,
            event: 0,
            armed: 0,
            ran: 0,
            overruns: 0,
            low,
            background: false,
            len: 1,
        }
    }

    pub fn budget(&self) -> u64 {
        self.c
    }

    pub fn period(&self) -> u64 {
        self.t
    }

    /// The level the thread falls to when the budget is gone.
    pub fn low(&self) -> u8 {
        self.low
    }

    /// Whether the thread is in the background: its budget is gone, and it
    /// waits for a replenishment.
    pub fn background(&self) -> bool {
        self.background
    }

    /// The pending replenishments, the earliest first.
    pub fn queue(&self) -> &[Replenishment] {
        &self.q[..usize::from(self.len)]
    }

    /// The usage since the head's time.
    pub fn usage(&self) -> u64 {
        self.usage
    }

    /// The sum of the ticks charged so far.
    pub fn ran(&self) -> u64 {
        self.ran
    }

    /// The number of times the budget ran out.
    pub fn overruns(&self) -> u32 {
        self.overruns
    }

    /// The ticks the thread may still run at its own level at `now`.
    pub fn capacity(&self, now: u64) -> u64 {
        let head = self.q[0];
        if head.time > now {
            0
        } else {
            head.amount.saturating_sub(self.usage)
        }
    }

    /// The counter at which the running thread's budget ends. Meaningful
    /// while it runs at its own level.
    pub fn exhaust_at(&self) -> u64 {
        self.exhaust_at
    }

    /// The thread begins to run at `now` (a decision chose it, or its
    /// budget came back while it runs): its time counts from here, and the
    /// budget ends at `now` plus the capacity.
    pub fn run(&mut self, now: u64) {
        if !self.background {
            self.fg_since = now;
            self.exhaust_at = now.saturating_add(self.capacity(now));
        }
    }

    /// The change of the replenishment event the kernel has to make: Some
    /// with the new time (None for off) when it differs from the one it
    /// holds, which this call then counts as held.
    pub fn event_change(&mut self) -> Option<Event> {
        if self.event == self.armed {
            return None;
        }
        self.armed = self.event;
        Some((self.event != 0).then_some(self.event))
    }

    /// No event is wanted any more: the thread goes.
    pub fn event_off(&mut self) {
        self.event = 0;
    }

    fn pop(&mut self) -> Replenishment {
        let head = self.q[0];
        // The whole array moves up by one, whatever `len` is: three fixed
        // moves are less code than a call of memmove for a size that varies.
        self.q[0] = self.q[1];
        self.q[1] = self.q[2];
        self.q[2] = self.q[3];
        self.len -= 1;
        head
    }

    /// Adds `r` after the entries that are not after its time.
    fn add(&mut self, r: Replenishment) {
        let mut at = usize::from(self.len);
        while at > 0 && self.q[at - 1].time > r.time {
            self.q[at] = self.q[at - 1];
            at -= 1;
        }
        self.q[at] = r;
        self.len += 1;
        debug_assert!(usize::from(self.len) <= MAX_REPLENISHMENTS);
    }

    /// Budget_Check (figure 6.3): the usage is up to date at `now`.
    #[inline(never)]
    fn check(&mut self, now: u64, blocked: bool) {
        if self.capacity(now) > 0 {
            return;
        }
        // An overrun beyond a whole budget is charged as one budget.
        self.usage = self.usage.min(2 * self.c);
        for _ in 0..2 * MAX_REPLENISHMENTS {
            if self.q[0].amount > self.usage {
                break;
            }
            self.usage -= self.q[0].amount;
            let mut r = self.pop();
            #[cfg(feature = "break-budget-short-period")]
            {
                r.time += self.t / 2;
            }
            #[cfg(not(feature = "break-budget-short-period"))]
            {
                r.time += self.t;
            }
            self.add(r);
        }
        if self.usage > 0 {
            // The overrun is time received early: the next chunk comes
            // later by as much.
            #[cfg(not(feature = "break-budget-no-overrun"))]
            {
                self.q[0].time += self.usage;
            }
            #[cfg(feature = "break-budget-no-overrun")]
            {
                self.usage = 0;
            }
        }
        // Chunks that touch are one replenishment (figure 6.3, line 10).
        #[cfg(not(feature = "break-budget-merge-always"))]
        let touch = self.len > 1 && self.q[0].time + self.q[0].amount >= self.q[1].time;
        #[cfg(feature = "break-budget-merge-always")]
        let touch = self.len > 1;
        if touch {
            let (amount, time) = (self.q[0].amount, self.q[0].time);
            self.pop();
            self.q[0].amount += amount;
            self.q[0].time = time;
        }
        if self.capacity(now) == 0 {
            if !self.background {
                self.overruns = self.overruns.saturating_add(1);
            }
            self.background = true;
            if !blocked {
                self.event = self.q[0].time;
            }
        }
    }

    /// Split_Check (figure 6.4): the thread blocked at `now`.
    #[inline(never)]
    fn split(&mut self, now: u64) {
        if self.usage == 0 || self.q[0].time > now {
            return;
        }
        let remnant = self.q[0].amount - self.usage;
        let mut r = Replenishment {
            time: self.q[0].time,
            amount: self.usage,
        };
        if usize::from(self.len) == MAX_REPLENISHMENTS {
            // The remnant goes to the next entry: later, never earlier.
            self.pop();
            if self.len > 0 {
                self.q[0].amount += remnant;
            } else {
                r.amount += remnant;
            }
        } else {
            self.q[0].amount = remnant;
            self.q[0].time += self.usage;
            // The remnant starts later: it may stand behind entries that
            // came back meanwhile.
            let head = self.pop();
            self.add(head);
        }
        r.time += self.t;
        self.add(r);
        self.usage = 0;
    }

    /// The thread leaves the CPU at `now`, `blocked` when it waits (Budget_
    /// Check, and Split_Check for a block). Its stint counts when it ran at
    /// its own level; the time in the background counts nowhere.
    #[inline(never)]
    pub fn stop(&mut self, now: u64, blocked: bool) {
        if self.background {
            return;
        }
        let ran = now.saturating_sub(self.fg_since);
        self.ran = self.ran.saturating_add(ran);
        self.usage = self.usage.saturating_add(ran);
        self.fg_since = now;
        self.check(now, blocked);
        if blocked {
            self.split(now);
        }
    }

    /// The thread becomes ready at `now` (Unblock_Check, figure 6.5).
    #[inline(never)]
    pub fn unblock(&mut self, now: u64) {
        if self.capacity(now) > 0 {
            self.background = false;
            self.event = 0;
            self.q[0].time = now;
            // The replenishments that arrive while the chunk runs are part
            // of it.
            while self.len > 1 {
                let a = self.q[0].amount;
                if self.q[1].time > now + a - self.usage {
                    break;
                }
                self.pop();
                self.q[0].amount += a;
                self.q[0].time = now;
            }
        } else {
            self.background = true;
            self.event = self.q[0].time;
        }
    }

    /// The replenishment event at `now`: the thread returns to its own
    /// level when it has capacity.
    #[inline(never)]
    pub fn replenish(&mut self, now: u64) {
        self.armed = 0;
        self.event = 0;
        #[cfg(feature = "break-budget-refill")]
        {
            let _ = now;
        }
        #[cfg(not(feature = "break-budget-refill"))]
        {
            self.check(now, false);
            if self.capacity(now) > 0 {
                self.background = false;
            }
        }
    }

    /// The sum of the amounts, which is the budget whatever happens.
    #[cfg(test)]
    fn sum(&self) -> u64 {
        self.queue().iter().map(|r| r.amount).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Xorshift: the same numbers on every run.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n
        }
    }

    /// One thread of a fixed priority CPU, in steps of one tick: it wants
    /// the CPU in random bursts, a higher level takes the CPU from it at
    /// random, and the server charges what it ran at its own level.
    /// Returns the ticks it ran at its own level, a 1 for each.
    fn simulate(
        c: u64,
        t: u64,
        seed: u64,
        steps: u64,
        bursts: u64,
        interference: bool,
    ) -> (Vec<u8>, Server) {
        let mut rng = Rng(seed | 1);
        let mut s = Server::new(c, t, 1, 0);
        let mut fg = vec![0u8; steps as usize];
        // Waiting, or ready (maybe running).
        let mut ready = false;
        let mut running = false;
        let mut work = 0u64;
        let mut away = 0u64;
        let mut heap: Option<u64> = None;
        for now in 0..steps {
            // The event of the heap.
            if let Some(change) = s.event_change() {
                heap = change;
            }
            if heap.is_some_and(|at| at <= now) {
                heap = None;
                s.replenish(now);
                if let Some(change) = s.event_change() {
                    heap = change;
                }
                if running && !s.background() {
                    s.run(now);
                }
            }
            // The thread's own demand and the interference.
            if work == 0 && rng.below(bursts) == 0 {
                work = 1 + rng.below(c + 3);
            }
            if interference && away == 0 && rng.below(7 * bursts) == 0 {
                away = 1 + rng.below(c + 2);
            }
            if work > 0 && !ready {
                ready = true;
                s.unblock(now);
                if let Some(change) = s.event_change() {
                    heap = change;
                }
            }
            let gone = away > 0;
            if running && (gone || work == 0) {
                running = false;
                s.stop(now, work == 0);
                if let Some(change) = s.event_change() {
                    heap = change;
                }
                if work == 0 {
                    ready = false;
                }
            }
            if ready && !running && !gone && !s.background() {
                running = true;
                s.run(now);
            }
            if running {
                // The budget ends exactly: the timer of the kernel.
                if now >= s.exhaust_at() {
                    running = false;
                    s.stop(now, false);
                    if let Some(change) = s.event_change() {
                        heap = change;
                    }
                } else {
                    fg[now as usize] = 1;
                    work -= 1;
                }
            }
            away = away.saturating_sub(1);
            assert_eq!(s.sum(), c, "the amounts add up to the budget at {now}");
            assert!(s.queue().len() <= MAX_REPLENISHMENTS);
            assert!(
                s.queue().windows(2).all(|w| w[0].time <= w[1].time),
                "the queue is in order at {now}: {:?}",
                s.queue()
            );
            if work == 0 && running {
                // Ends its burst: blocks at the next step.
            }
        }
        (fg, s)
    }

    /// The most ticks run in any window of `t` ticks.
    fn busiest(fg: &[u8], t: u64) -> u64 {
        let t = t as usize;
        let mut sum: u64 = fg.iter().take(t).map(|&x| u64::from(x)).sum();
        let mut most = sum;
        for i in t..fg.len() {
            sum += u64::from(fg[i]);
            sum -= u64::from(fg[i - t]);
            most = most.max(sum);
        }
        most
    }

    #[test]
    fn a_thread_that_always_wants_the_cpu_never_gets_more_than_the_budget_in_a_period() {
        // Alone on its CPU, wanting it all the time: the server is a
        // periodic task of the budget and the period, and a window of `l`
        // ticks holds at most the budget for each period it touches.
        let mut ran = 0;
        for seed in 1..300u64 {
            let t = 20 + (seed * 7) % 180;
            let c = 1 + (seed * 13) % t;
            let (fg, s) = simulate(c, t, seed.wrapping_mul(0x9e37_79b9), 6_000, 1, false);
            for l in [t / 2, t, 2 * t, 5 * t] {
                let most = busiest(&fg, l);
                assert!(
                    most <= l.div_ceil(t) * c,
                    "C {c} T {t} seed {seed}: {most} ticks in {l}"
                );
            }
            ran += s.ran();
        }
        assert!(ran > 100_000, "the runs did something: {ran}");
    }

    #[test]
    fn a_thread_that_blocks_and_wakes_gets_one_budget_more_than_its_periods_at_most() {
        // A thread that sleeps between its bursts may run the chunks of
        // consecutive periods one after the other: a window of `m` periods
        // holds `m + 1` budgets at most.
        for seed in 1..400u64 {
            let t = 20 + (seed * 7) % 180;
            let c = 1 + (seed * 13) % t;
            for bursts in [2, 5, 20] {
                let (fg, _) = simulate(c, t, seed.wrapping_mul(0x9e37_79b9), 8_000, bursts, false);
                for m in [1, 2, 5, 10] {
                    let most = busiest(&fg, m * t);
                    assert!(
                        most <= (m + 1) * c,
                        "C {c} T {t} seed {seed} bursts {bursts}: {most} ticks in {m} periods"
                    );
                }
            }
        }
    }

    #[test]
    fn a_server_kept_off_the_cpu_by_a_higher_level_keeps_its_queue_in_order() {
        // The level above holds the thread ready and away for stretches: the
        // chunks come back late, and the queue stays what it must be (the
        // checks inside `simulate`) while the thread still runs.
        let mut ran = 0;
        for seed in 1..300u64 {
            let t = 20 + (seed * 7) % 180;
            let c = 1 + (seed * 13) % t;
            for bursts in [2, 5, 20] {
                let (_, s) = simulate(c, t, seed.wrapping_mul(0x9e37_79b9), 8_000, bursts, true);
                ran += s.ran();
            }
        }
        assert!(ran > 100_000, "the runs did something: {ran}");
    }

    #[test]
    fn a_budget_comes_back_after_its_period() {
        let mut s = Server::new(30, 100, 1, 0);
        s.unblock(0);
        s.run(0);
        assert_eq!(s.exhaust_at(), 30);
        s.stop(30, false);
        assert!(s.background());
        assert_eq!(
            s.queue(),
            &[Replenishment {
                time: 100,
                amount: 30
            }]
        );
        assert_eq!(s.event_change(), Some(Some(100)));
        assert_eq!(s.capacity(99), 0);
        s.replenish(100);
        assert!(!s.background());
        assert_eq!(s.capacity(100), 30);
    }

    #[test]
    fn what_a_thread_used_before_it_blocked_comes_back_at_its_activation_plus_the_period() {
        let mut s = Server::new(30, 100, 1, 0);
        s.unblock(10);
        s.run(10);
        s.stop(20, true);
        assert!(!s.background());
        // 10 ticks used from the activation at 10 return at 110; the rest
        // of the chunk, 20 ticks, is available from 20 on.
        assert_eq!(
            s.queue(),
            &[
                Replenishment {
                    time: 20,
                    amount: 20
                },
                Replenishment {
                    time: 110,
                    amount: 10
                },
            ]
        );
        assert_eq!(s.capacity(20), 20);
    }

    #[test]
    fn the_fifth_replenishment_merges_into_the_last_and_comes_later() {
        let (c, t) = (40, 1000);
        let mut s = Server::new(c, t, 1, 0);
        let mut now = 0;
        // Wake, run 5 ticks, block: a replenishment each time.
        for i in 0..6 {
            s.unblock(now);
            s.run(now);
            now += 5;
            s.stop(now, true);
            assert!(s.queue().len() <= MAX_REPLENISHMENTS, "round {i}");
            assert_eq!(s.sum(), c);
            now += 5;
        }
        assert_eq!(s.queue().len(), MAX_REPLENISHMENTS);
        // The time of no entry moved before the first replenishment's
        // activation plus the period.
        assert!(s.queue().iter().skip(1).all(|r| r.time >= t));
        assert!(s.queue().windows(2).all(|w| w[0].time <= w[1].time));
    }

    #[test]
    fn an_overrun_is_charged_against_the_next_replenishment() {
        let (c, t) = (30, 100);
        let mut s = Server::new(c, t, 1, 0);
        s.unblock(0);
        s.run(0);
        // The thread ran on for 7 ticks past its budget before the kernel
        // looked (a poll of the way out of the kernel).
        s.stop(37, false);
        assert!(s.background());
        // The chunk comes back at 100, and the overrun moves it by 7.
        assert_eq!(
            s.queue(),
            &[Replenishment {
                time: 107,
                amount: 30
            }]
        );
        assert_eq!(s.event_change(), Some(Some(107)));
        s.replenish(107);
        assert_eq!(s.capacity(107), 23, "the overrun stays in the usage");
    }

    #[test]
    fn overruns_do_not_amplify_the_budget() {
        // Every period the thread runs 3 ticks past each chunk: the work in
        // a long run stays at the budget per period plus one overrun.
        let (c, t) = (30, 100);
        let mut s = Server::new(c, t, 1, 0);
        let mut now = 0;
        let mut total = 0;
        let mut heap: Option<u64> = None;
        s.unblock(0);
        for _ in 0..200 {
            if let Some(change) = s.event_change() {
                heap = change;
            }
            if let Some(at) = heap.filter(|&at| at <= now) {
                let _ = at;
                heap = None;
                s.replenish(now);
            }
            if s.background() {
                now += 1;
                continue;
            }
            s.run(now);
            // Runs to the end of its budget and 3 ticks past it.
            let len = s.capacity(now) + 3;
            now += len;
            total += len;
            s.stop(now, false);
        }
        // Whole run: `now` ticks, in periods of 100; the work per period
        // averages the budget.
        assert!(
            total <= (now / t + 1) * c + 3 * (now / t + 1) / 10 + 3,
            "total {total} in {now} ticks"
        );
    }

    #[test]
    fn time_in_the_background_is_not_charged() {
        let mut s = Server::new(30, 100, 1, 0);
        s.unblock(0);
        s.run(0);
        s.stop(30, false);
        assert!(s.background());
        let before = (s.usage(), s.ran());
        s.stop(80, false);
        s.stop(90, true);
        assert_eq!((s.usage(), s.ran()), before);
    }

    #[test]
    fn a_thread_that_wakes_with_no_capacity_waits_for_the_event() {
        let mut s = Server::new(30, 100, 1, 0);
        s.unblock(0);
        s.run(0);
        s.stop(30, true);
        assert!(s.background());
        assert_eq!(s.event_change(), None, "a blocked thread has no event yet");
        s.unblock(50);
        assert!(s.background());
        assert_eq!(s.event_change(), Some(Some(100)));
        s.replenish(100);
        assert!(!s.background());
    }

    #[test]
    fn a_new_chunk_merges_with_those_that_arrive_while_it_runs() {
        let mut s = Server::new(40, 100, 1, 0);
        s.unblock(0);
        s.run(0);
        s.stop(10, true);
        // 10 used: (10, 30) and (100, 10); the thread wakes at 95 and the
        // second chunk arrives within the 30 it can run.
        s.unblock(95);
        assert_eq!(
            s.queue(),
            &[Replenishment {
                time: 95,
                amount: 40
            }]
        );
        assert_eq!(s.capacity(95), 40);
    }

    #[test]
    fn a_budget_that_never_comes_back_is_caught() {
        // The same run as the first one: a replenishment that is never
        // applied leaves the thread in the background for good.
        let (c, t) = (30, 100);
        let (fg, _) = simulate(c, t, 5, 5_000, 1, false);
        let total: u64 = fg.iter().map(|&x| u64::from(x)).sum();
        assert!(
            total > 2 * c,
            "the thread ran {total} ticks: its budget never came back"
        );
    }
}
