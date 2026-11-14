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

/// The steps in a row after which the loop looks at its queue for a request before the next
/// step runs (`Yielding`).
pub const RUN_STEPS: u32 = 2;

/// The loop of the stack takes the head of its queue, and the queue gives the head to the
/// notification with the higher level: a request of a client at a level below the stack's
/// waits for as long as the stack tells itself the next step and the switch the next frames,
/// which is as long as the wire has more (stafeto-design#713). So after `RUN_STEPS` steps in a
/// row the loop looks at the queue before the next one: with anything queued the step is put
/// off (`owed`; the caller leaves its bits in its own `told`, so that no one tells them again)
/// and the loop takes what stands in the queue. A notification that stands ahead of a request
/// was told before the step was put off: the stack's own and the switch's share one slot, and
/// the timer's and each session's have one each, so the request is taken after the receives of
/// those and of the notifications the switch tells meanwhile (it tells the step of sending for
/// each lend of buffers, and each costs one cheap receive). When the queue is empty, or a
/// request is served, the steps owed are told and the run starts again.
pub struct Yielding {
    run: u32,
    owed: u64,
}

impl Default for Yielding {
    fn default() -> Yielding {
        Yielding::new()
    }
}

impl Yielding {
    pub const fn new() -> Yielding {
        Yielding { run: 0, owed: 0 }
    }

    /// A notification of steps `bits` came. The steps to run now: `bits` (with those owed, when
    /// the queue is seen empty), or 0 when they are put off. `queued` says whether anything
    /// stands in the queue; it is asked only after `RUN_STEPS` steps in a row.
    pub fn arrive(&mut self, bits: u64, queued: impl FnOnce() -> bool) -> u64 {
        self.run = self.run.saturating_add(1);
        if self.run <= RUN_STEPS {
            return bits;
        }
        if queued() {
            self.owed |= bits;
            return 0;
        }
        self.run = 0;
        bits | core::mem::take(&mut self.owed)
    }

    /// A request was served: the steps owed are to be told now (`always`), and the run starts
    /// again. Without `always` (the end of a notification that no step took) the queue must be
    /// empty for it, the steps owed are told then, so that none waits for a step that does not
    /// follow.
    pub fn resume(&mut self, always: bool, queued: impl FnOnce() -> bool) -> u64 {
        if always {
            self.run = 0;
        }
        if self.owed == 0 || (!always && queued()) {
            return 0;
        }
        self.run = 0;
        core::mem::take(&mut self.owed)
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
    #[test]
    fn a_run_of_steps_puts_the_next_off_while_a_request_waits() {
        let mut y = Yielding::new();
        for _ in 0..RUN_STEPS {
            assert_eq!(
                y.arrive(0b1, || unreachable!("not asked in the first steps")),
                0b1
            );
        }
        // The next step, with a request queued, is put off and owed.
        assert_eq!(y.arrive(0b1, || true), 0);
        // The notifications of other steps that stand ahead of the request are put off too.
        assert_eq!(y.arrive(0b10, || true), 0);
        // The request is served: the steps owed come back together, and a run starts.
        assert_eq!(y.resume(true, || unreachable!("always")), 0b11);
        assert_eq!(y.arrive(0b1, || unreachable!("a new run")), 0b1);
        // Nothing owed, nothing told.
        assert_eq!(y.resume(true, || true), 0);
    }

    #[test]
    fn an_empty_queue_takes_the_steps_owed_with_the_next_step() {
        let mut y = Yielding::new();
        for _ in 0..RUN_STEPS {
            y.arrive(0b1, || false);
        }
        assert_eq!(y.arrive(0b1, || true), 0);
        // What stood in the queue was no request; the next notification finds it empty.
        assert_eq!(y.arrive(0b100, || false), 0b101);
        assert_eq!(y.arrive(0b1, || unreachable!("a new run")), 0b1);
    }

    #[test]
    fn steps_owed_are_told_when_no_step_follows_and_the_queue_is_empty() {
        let mut y = Yielding::new();
        for _ in 0..RUN_STEPS {
            y.arrive(0b1, || false);
        }
        assert_eq!(y.arrive(0b1, || true), 0);
        // The end of a notification that is no step: the queue still holds something.
        assert_eq!(y.resume(false, || true), 0);
        // It is empty now: the steps owed are told.
        assert_eq!(y.resume(false, || false), 0b1);
        assert_eq!(y.resume(false, || false), 0);
    }
}
