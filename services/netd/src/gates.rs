// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the switch thread and the stack thread tell each other besides the
//! words of their rings (`spsc`, `switch.rs`): who has to wake whom, and when
//! the switch may hold a doorbell. Both are the
//! scheme of two stores and two loads (sleep flag and index) that needs a
//! full barrier on both sides to lose no wake with two CPUs (spec 6, 3.6,
//! the note of the stage 4): the sleeper stores its flag, fences, and looks
//! at its inputs once more; the writer fences after its word and reads the
//! flag. Each flag here is an atomic read-modify-write, or is followed by
//! a `SeqCst` fence, and the decisions that depend on two flags at once
//! share one byte, so that the two threads see them in one order.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering, fence};

/// "Told and not seen": a notification to a thread that waits is sent once
/// until the thread looks at its inputs.
pub struct Told(AtomicBool);

impl Told {
    pub const fn new() -> Told {
        Told(AtomicBool::new(false))
    }

    /// The writer's side, after it put its word in the ring: whether the
    /// other thread is to be notified (nobody else has told it since it last
    /// looked).
    pub fn tell(&self) -> bool {
        fence(Ordering::SeqCst);
        !self.0.swap(true, Ordering::SeqCst)
    }

    /// The reader's side, before it looks at the ring: the next word put in
    /// tells again.
    pub fn seen(&self) {
        self.0.store(false, Ordering::SeqCst);
        fence(Ordering::SeqCst);
    }

    /// A notification that failed: the flag is down again, so that the next
    /// word tells.
    pub fn failed(&self) {
        self.0.store(false, Ordering::SeqCst);
    }

    /// Whether the reader was told and has not looked.
    pub fn is_told(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Default for Told {
    fn default() -> Told {
        Told::new()
    }
}

/// The stack is in a run of steps.
const BUSY: u8 = 1;
/// A doorbell of sending waits for the end of the run.
const HELD: u8 = 2;

/// The state of the stack's run, seen by the switch: one byte, so that "the
/// run ended" and "the switch holds a doorbell for the end of the run" cannot
/// miss each other. The switch sets BUSY when it wakes the stack, and the
/// stack clears it when its run ends; a doorbell the switch held
/// meanwhile is told to the stack by the clearing (`end`), whichever came
/// first.
pub struct Run(AtomicU8);

impl Run {
    pub const fn new() -> Run {
        Run(AtomicU8::new(0))
    }

    /// The switch woke the stack: a run is due, and ends with `end`.
    pub fn begin(&self) {
        self.0.fetch_or(BUSY, Ordering::SeqCst);
    }

    /// Whether a run is on.
    pub fn busy(&self) -> bool {
        self.0.load(Ordering::SeqCst) & BUSY != 0
    }

    /// The stack's run is over. True when the switch holds a doorbell and has to
    /// be woken; what it held is taken from it here (it holds
    /// again if it still needs to), so that one wake serves one hold.
    pub fn end(&self) -> bool {
        self.0.fetch_and(!(BUSY | HELD), Ordering::SeqCst) & HELD != 0
    }

    /// The switch holds its doorbell for the end of the run. False when the
    /// run is over already (the switch rings at once; nothing is held).
    pub fn hold(&self) -> bool {
        if self.0.fetch_or(HELD, Ordering::SeqCst) & BUSY != 0 {
            return true;
        }
        self.0.fetch_and(!HELD, Ordering::SeqCst);
        false
    }

    /// The doorbell rang: nothing is held.
    pub fn unhold(&self) {
        self.0.fetch_and(!HELD, Ordering::SeqCst);
    }
}

impl Default for Run {
    fn default() -> Run {
        Run::new()
    }
}

/// How long the loop may go without serving a request before it looks at its queue for one: a
/// period of the stack's budget.
pub const YIELD_NS: u64 = 1_000_000;

/// The loop of the stack takes the head of its queue, and the queue gives the head to the
/// notification with the higher level: a request of a client at a level below the stack's
/// waits for as long as the stack tells itself the next step and the switch the next frames,
/// which is as long as the wire has more (stafeto-design#713). So when no request has been
/// served for `YIELD_NS` the loop looks at the queue at the end of a notification (`after`, one
/// `object_info` a millisecond at most, none while requests are served, and outside the step):
/// with anything queued the next step that comes is put off (`arrive`: `owed`; the caller leaves
/// its bits in its own `told`, so that no one tells them again) and the loop takes what stands in
/// the queue. A notification that stands ahead of a request was told before the step was put off:
/// the stack's own and the switch's share one slot, and the timer's and each session's have one
/// each, so the request is taken after the receives of those and of the notifications the switch
/// tells meanwhile (it tells the step of sending for each lend of buffers, and each costs one
/// cheap receive). When the queue is empty, or a request is served, the steps owed are told and
/// the time starts again. Under a load of requests one is served in every millisecond, so no step
/// is ever put off.
pub struct Yielding {
    served_at: u64,
    owed: u64,
    defer: bool,
    /// The steps put off.
    pub deferred: u32,
    /// The times the steps owed were told with no request served (the queue held only
    /// notifications): the cost of such a deferral is two system calls and a receive.
    pub idle: u32,
    /// The times the steps owed were told after a request was served.
    pub served: u32,
}

impl Default for Yielding {
    fn default() -> Yielding {
        Yielding::new()
    }
}

impl Yielding {
    pub const fn new() -> Yielding {
        Yielding {
            served_at: 0,
            owed: 0,
            defer: false,
            deferred: 0,
            idle: 0,
            served: 0,
        }
    }

    /// A notification of steps `bits` came. The steps to run now: `bits` with those owed, or,
    /// when the next step is to be put off, the steps of `bits` outside `deferrable` (the others
    /// are put off).
    pub fn arrive(&mut self, bits: u64, deferrable: u64) -> u64 {
        if self.defer && bits & deferrable != 0 {
            self.owed |= bits & deferrable;
            self.deferred += 1;
            return bits & !deferrable;
        }
        bits | core::mem::take(&mut self.owed)
    }

    /// The end of a notification at `now` (ns). `queued` says whether anything stands in the
    /// queue; it is asked only when no request was served for `YIELD_NS`. With something
    /// queued the next step is put off; with the queue empty the steps owed are to be told, and
    /// the time starts again. Returns the steps to tell.
    pub fn after(&mut self, now: u64, queued: impl FnOnce() -> bool) -> u64 {
        if now.wrapping_sub(self.served_at) < YIELD_NS {
            return 0;
        }
        if queued() {
            self.defer = true;
            return 0;
        }
        self.defer = false;
        self.served_at = now;
        if self.owed != 0 {
            self.idle += 1;
        }
        core::mem::take(&mut self.owed)
    }

    /// A request was served at `now`: the steps owed are to be told now, and the time starts
    /// again. Returns the steps to tell.
    pub fn served(&mut self, now: u64) -> u64 {
        self.served_at = now;
        self.defer = false;
        if self.owed != 0 {
            self.served += 1;
        }
        core::mem::take(&mut self.owed)
    }

    /// The steps put off and not told yet.
    pub fn owed(&self) -> u64 {
        self.owed
    }

    /// The steps of `mask` that were put off are run by the caller at once: they are no longer
    /// owed.
    pub fn settle(&mut self, mask: u64) {
        self.owed &= !mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spsc::Spsc;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::time::{Duration, Instant};

    #[test]
    fn a_word_tells_once_until_the_reader_looks() {
        let told = Told::new();
        assert!(told.tell());
        assert!(!told.tell());
        told.seen();
        assert!(told.tell());
        told.failed();
        assert!(told.tell(), "a failed notification tells again");
    }

    #[test]
    fn the_end_of_a_run_tells_what_the_switch_holds() {
        let run = Run::new();
        run.begin();
        assert!(run.busy());
        assert!(run.hold());
        assert!(run.end(), "a held doorbell is told");
        assert!(!run.busy());
        run.begin();
        assert!(!run.end(), "told once: nothing is held now");
    }

    #[test]
    fn the_switch_rings_itself_when_the_run_is_over() {
        let run = Run::new();
        assert!(!run.hold(), "no run: nothing is held");
        assert!(!run.end());
        run.begin();
        assert!(!run.end(), "no flag was left behind");
    }

    /// A reader that sleeps when its ring is empty and a writer that wakes
    /// it only when `Told` says so: every word comes out, none waits for a
    /// wake that was not sent.
    #[test]
    fn no_wake_is_lost_between_a_sleeper_and_a_writer() {
        const WORDS: u32 = 200_000;
        let ring = Arc::new(Spsc::<64>::new());
        let told = Arc::new(Told::new());
        // The notifications sent and taken: a wake is a count the sleeper
        // waits to see grow.
        let sent = Arc::new(AtomicU64::new(0));
        let writer = {
            let (ring, told, sent) = (ring.clone(), told.clone(), sent.clone());
            std::thread::spawn(move || {
                for w in 0..WORDS {
                    while !ring.push(w) {
                        std::hint::spin_loop();
                    }
                    if told.tell() {
                        sent.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        };
        let mut next = 0;
        let mut taken = 0;
        let started = Instant::now();
        while next < WORDS {
            // Awake: the flag first, then the ring, as the stack does.
            told.seen();
            while let Some(w) = ring.pop() {
                assert_eq!(w, next);
                next += 1;
            }
            if next == WORDS {
                break;
            }
            // Asleep: until a notification came that it has not taken.
            while sent.load(Ordering::SeqCst) == taken {
                assert!(
                    started.elapsed() < Duration::from_secs(60),
                    "a wake was lost at word {next}"
                );
                std::hint::spin_loop();
            }
            taken = sent.load(Ordering::SeqCst);
        }
        writer.join().unwrap();
    }

    /// The doorbell the switch holds for the end of the run and the stack's
    /// end of the run, from two threads: a held doorbell is always told.
    #[test]
    fn a_held_doorbell_is_always_told_to_the_stack() {
        for _ in 0..20_000 {
            let run = Arc::new(Run::new());
            run.begin();
            let stack = {
                let run = run.clone();
                std::thread::spawn(move || run.end())
            };
            let held = run.hold();
            let told = stack.join().unwrap();
            // Held: the stack's end saw it. Not held: the switch rings
            // itself. Never both missed.
            assert!(!run.busy());
            if held {
                assert!(told, "a doorbell was held and nobody was told");
            }
        }
    }
    const MS: u64 = 1_000_000;
    const ALL: u64 = u64::MAX;

    #[test]
    fn nothing_is_asked_while_requests_are_served_within_a_period() {
        let mut y = Yielding::new();
        y.served(5 * MS);
        for k in 1..8 {
            let now = 5 * MS + k * 100_000;
            assert_eq!(y.after(now, || unreachable!("served lately")), 0);
            assert_eq!(y.arrive(0b1, ALL), 0b1);
        }
        assert_eq!(y.deferred, 0);
    }

    #[test]
    fn a_period_without_a_request_puts_the_next_step_off_while_a_request_waits() {
        let mut y = Yielding::new();
        y.served(5 * MS);
        assert_eq!(y.after(6 * MS + 1, || true), 0);
        assert_eq!(y.arrive(0b1, ALL), 0);
        // The notifications of other steps that stand ahead of the request are put off too.
        assert_eq!(y.after(6 * MS + 2, || true), 0);
        assert_eq!(y.arrive(0b10, ALL), 0);
        // The request is served: the steps owed come back together, and a period starts.
        assert_eq!(y.served(6 * MS + 3), 0b11);
        assert_eq!(y.after(6 * MS + 4, || unreachable!("a new period")), 0);
        assert_eq!(y.arrive(0b1, ALL), 0b1);
        assert_eq!((y.deferred, y.idle, y.served), (2, 0, 1));
    }

    #[test]
    fn an_empty_queue_tells_the_steps_owed() {
        let mut y = Yielding::new();
        assert_eq!(y.after(2 * MS, || true), 0);
        assert_eq!(y.arrive(0b1, ALL), 0);
        // What stood in the queue was no request; the end of the next notification finds it
        // empty.
        assert_eq!(y.after(2 * MS + 1, || false), 0b1);
        assert_eq!(y.arrive(0b100, ALL), 0b100);
        assert_eq!(y.after(2 * MS + 2, || unreachable!("a new period")), 0);
        assert_eq!((y.deferred, y.idle), (1, 1));
    }

    #[test]
    fn only_the_deferrable_steps_are_put_off() {
        let mut y = Yielding::new();
        assert_eq!(y.after(2 * MS, || true), 0);
        // The answers of the switch (0b1000) and the sweep (0b100) run; receiving (0b1) waits.
        assert_eq!(y.arrive(0b1101, 0b11), 0b1100);
        assert_eq!(y.owed(), 0b1);
        assert_eq!(y.arrive(0b1000, 0b11), 0b1000);
        assert_eq!(y.deferred, 1);
        assert_eq!(y.served(2 * MS + 1), 0b1);
    }

    /// The queue of the loop in a model: one slot of label 0 (the stack's own bits and the
    /// switch's, ORed, ahead of the request as a level above it) and the requests behind it.
    /// The switch tells the stack every time it can, as under a full wire (the step of receiving
    /// once until the stack looks, the step of sending at each turn); it can in three turns of
    /// four, the fourth being the one its budget is spent in (the stack's turn in the period).
    /// A receive takes 250 us. A request that comes in the middle is served within a period and
    /// a few receives, the steps put off come back after it, and when the wire stops no step is
    /// left owed.
    #[test]
    fn a_request_is_served_within_the_bound_under_a_full_wire_and_no_step_is_lost() {
        const RX: u64 = 1;
        const TX: u64 = 2;
        let (mut slot, mut told, mut requests) = (0u64, 0u64, 0u32);
        let (mut rx_left, mut tx_left) = (1_000_000u32, 1_000_000u32);
        let mut switch_told = false;
        let mut y = Yielding::new();
        let (mut asked_at, mut served_at, mut rx_at_served) = (None, None, 0);
        let mut progress_after = None;
        for receive in 0..4_000u32 {
            let now = 10 * MS + u64::from(receive) * 250_000;
            let flood = receive < 300;
            if flood && receive % 4 != 3 {
                // The switch, at a level above the stack, tells before each receive.
                if !switch_told {
                    switch_told = true;
                    slot |= RX;
                }
                slot |= TX;
            }
            if receive == 300 {
                (rx_left, tx_left) = (40, 40);
            }
            if receive == 50 {
                requests += 1;
                asked_at = Some(receive);
            }
            if slot != 0 {
                let bits = core::mem::take(&mut slot);
                let run = y.arrive(bits, ALL);
                if run != 0 {
                    let first = 1u64 << run.trailing_zeros();
                    told &= !first;
                    if run & !first != 0 {
                        slot |= run & !first;
                    }
                    let left = if first == RX {
                        // The stack looks at its ring: the switch may tell it again.
                        switch_told = false;
                        &mut rx_left
                    } else {
                        &mut tx_left
                    };
                    *left = left.saturating_sub(1);
                    if *left > 0 && told & first == 0 {
                        told |= first;
                        slot |= first;
                    }
                    if first == RX
                        && served_at.is_some()
                        && progress_after.is_none()
                        && rx_left < rx_at_served
                    {
                        progress_after = Some(receive);
                    }
                }
                let queued_end = slot != 0 || requests > 0;
                slot |= y.after(now, || queued_end);
            } else if requests > 0 {
                requests -= 1;
                served_at = Some(receive);
                rx_at_served = rx_left;
                slot |= y.served(now);
            } else if !flood {
                break;
            }
        }
        let (asked, served) = (asked_at.unwrap(), served_at.expect("the request is served"));
        // A period (4 receives) and a few receives of the notifications ahead of it.
        assert!(
            served - asked <= 12,
            "served after {} receives",
            served - asked
        );
        // The steps put off come back right after it, while the wire is still full.
        let progress = progress_after.expect("the steps run again after the request");
        assert!(
            progress - served <= 4,
            "steps came back after {} receives",
            progress - served
        );
        // Nothing is lost when the wire stops.
        assert_eq!((rx_left, tx_left, y.owed(), told), (0, 0, 0, 0));
        assert!(y.deferred > 0);
    }
}
