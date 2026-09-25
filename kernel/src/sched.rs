// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel's scheduler (spec 8, 8.1): the rules of kcore::sched over
//! the kernel's threads, the virtual timer and the cleanup queue. Every
//! entry into the kernel ends in `resume`, the one way out: a loop on the
//! empty kernel stack that handles a pending interrupt, decides, arms the
//! timer for the deadline that decision needs, writing the timer only when
//! the deadline changes, and then runs the chosen thread, does one portion
//! of cleanup (spec 7.7) or sleeps in `wfi` with interrupts masked. Idle is
//! that loop with nothing ready: no thread object, and cleanup of every
//! level runs there. Between two polls for interrupts the kernel does at
//! most one portion, and it begins one only with no interrupt pending.
//! The kernel holds a reference to every thread the
//! scheduler holds, from `start` until `exit`.

use crate::arch::{self, gic, timer};
use crate::cleanup;
use crate::thread::{self, Policy, Thread};
use abi::Error;
use core::ptr::NonNull;
use kcore::sched::{Armed, Decision, Scheduler, State, Timer};
use kcore::sync::Lock;
use kcore::time::Clock;

struct Sched {
    s: Scheduler<Thread>,
    /// The deadline the timer holds.
    armed: Armed,
    /// Counter ticks spent asleep in `wfi`, for KSTATS and `uptime`
    /// (milestone 1.4).
    idle: u64,
    /// The kernel handles the interrupt that woke it from `wfi`.
    waking: bool,
    /// The deadline of the timer interrupt that came last, and whether it
    /// woke the kernel from `wfi`, until a thread runs after it or the
    /// kernel sleeps again.
    fired: Option<(u64, bool)>,
    /// The longest time from a deadline to the thread run after its
    /// interrupt, in ticks: after `wfi`, and otherwise.
    idle_latency: u64,
    irq_latency: u64,
}

/// The quantum is 0 until `init` knows the counter's frequency.
static SCHED: Lock<Sched> = Lock::new(Sched {
    s: Scheduler::new(0),
    armed: Armed::new(),
    idle: 0,
    waking: false,
    fired: None,
    idle_latency: 0,
    irq_latency: 0,
});

/// What the scheduler counts for KSTATS (spec 16), in counter ticks.
#[derive(Debug, Clone, Copy)]
pub struct Stats {
    /// Asleep in `wfi`.
    pub idle: u64,
    /// The longest time from a timer's deadline to the thread run after
    /// its interrupt, when the interrupt woke the kernel from `wfi`.
    pub idle_latency: u64,
    /// The same for an interrupt that came while the kernel was awake: at
    /// EL0, or found by the poll on the way out.
    pub irq_latency: u64,
}

/// The scheduler's counters for KSTATS.
pub fn stats() -> Stats {
    let g = SCHED.lock();
    Stats {
        idle: g.idle,
        idle_latency: g.idle_latency,
        irq_latency: g.irq_latency,
    }
}

/// The EL1 virtual timer as the scheduler writes it.
struct VirtualTimer;

impl Timer for VirtualTimer {
    fn arm(&mut self, deadline: u64) {
        timer::arm(deadline);
    }

    fn disarm(&mut self) {
        timer::disarm();
    }
}

/// Sets the round-robin quantum, abi::RR_QUANTUM_NS, in ticks of `clock`:
/// 250 000 at QEMU's 62.5 MHz, 96 000 at the A64's 24 MHz. Runs at boot,
/// before any thread starts.
pub fn init(clock: Clock) {
    SCHED
        .lock()
        .s
        .set_quantum(clock.ns_to_ticks(abi::RR_QUANTUM_NS));
}

/// A stopped thread becomes ready: the tail of its level with a new
/// quantum. The kernel takes a reference to it, which `exit` drops.
/// BAD_STATE for a thread that started before. thread::start comes here,
/// once it knows the thread's process lives.
pub fn start(t: NonNull<Thread>) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to `t`; the one taken below keeps
    // it alive, and a pool object never moves, until `exit`.
    unsafe { SCHED.lock().s.start(t)? };
    thread::retain(t);
    Ok(())
}

/// Ends `t` for the scheduler, whatever its state: it never runs again,
/// and the reference the kernel took at `start` goes, with `cause` for the
/// cleanup its last reference starts. When `t` was the running thread,
/// `resume` decides who runs next. A thread that ended before stays as it
/// is.
///
/// # Safety
/// `t` is alive. When the kernel's reference is its last, `t` is queued
/// for cleanup here, and the caller does not use it afterwards.
pub unsafe fn exit(t: NonNull<Thread>, cause: u8) {
    let held = {
        let mut g = SCHED.lock();
        // SAFETY: `t` is alive; its node is read before the scheduler takes it.
        let state = unsafe { t.as_ref() }.sched.state();
        // SAFETY: `t` and the scheduler's threads are alive.
        unsafe { g.s.exit(t) };
        matches!(state, State::Ready | State::Running)
    };
    if held {
        // SAFETY: the reference `start` took ends with the thread.
        unsafe { thread::release(t, cause) };
    }
}

/// yield: the running thread goes to the tail of its level with a new
/// quantum; `resume` runs the next thread of that level, or the same one
/// when it is alone there. Lower levels never run through yield.
pub fn yield_running() {
    // SAFETY: the scheduler's threads are alive (`start`).
    unsafe { SCHED.lock().s.yield_running() };
}

/// thread_set_priority: `priority` (1-63) becomes the base priority of
/// `t`, and with it the effective one until milestone 1.3; the thread
/// moves by the rules of `pthread_setschedprio` (kcore::sched). The next
/// `resume` runs a thread raised above the running one, or another one
/// when the running thread lowered itself below it. BAD_STATE for a
/// thread that ended.
pub fn set_priority(mut t: NonNull<Thread>, priority: u8, policy: Policy) -> Result<(), Error> {
    let now = timer::now();
    // SAFETY: the caller holds a reference to `t`; the scheduler's threads
    // are alive.
    unsafe { SCHED.lock().s.set_priority(t, priority, policy, now)? };
    // SAFETY: as above; the scheduler is done with the thread.
    unsafe { t.as_mut() }.base_priority = priority;
    Ok(())
}

/// The timer's interrupt, before its EOI: the timer goes off, since its
/// line is level-triggered and must be quiet by the EOI, and a round-robin
/// thread whose quantum is over goes to the tail of its level. `resume`
/// arms the timer again. The deadline that fired, CNTV_CVAL_EL0, waits
/// for the next thread to run, which measures the latency for KSTATS.
pub fn timer_fired() {
    let now = timer::now();
    let mut g = SCHED.lock();
    let g = &mut *g;
    g.fired = Some((timer::cval(), g.waking));
    // The line must drop before the EOI whatever `armed` remembers: the
    // hardware said the timer is on.
    VirtualTimer.disarm();
    g.armed = Armed::new();
    // SAFETY: the scheduler's threads are alive.
    unsafe { g.s.tick(now) };
}

/// The way out of the kernel (spec 8.1, 7.7): `exit_loop` on the empty
/// kernel stack, so that neither a portion of cleanup nor the idle wait
/// depends on how deep the caller was. The caller's stack holds nothing
/// with a `Drop`: it is abandoned.
pub fn resume() -> ! {
    arch::on_empty_stack(exit_loop)
}

/// The loop every way out of the kernel takes: an interrupt that is
/// pending is acknowledged and handled first; then the decision, and the
/// chosen thread runs at EL0, one portion of cleanup runs, or the kernel
/// sleeps until an interrupt. A portion begins only with no interrupt
/// pending. TTBR0, TPIDR_EL1 and the FP registers keep
/// the last thread's meanwhile, so going back to that thread costs
/// nothing. Leaves only through thread::run.
extern "C" fn exit_loop() -> ! {
    loop {
        if arch::irq_pending()
            && let Some(ack) = gic::acknowledge()
        {
            crate::interrupt::handle(ack);
        }
        match decide() {
            Decision::Run(t) => thread::run(t),
            // Another line of the same priority shows only after the EOI
            // of the one just handled (GICv2 running priority): poll again
            // first. Deciding again costs nothing: the running thread went
            // to the head of its level already.
            Decision::Clean if arch::irq_pending() => {}
            Decision::Clean => cleanup::portion(),
            Decision::Idle => sleep(),
        }
    }
}

/// Decides what the kernel does from now on and arms the timer for the
/// deadline that needs: the end of a round-robin thread's quantum;
/// nothing for a FIFO thread, for cleanup or while idle. From milestone
/// 1.3 the nearest timer of a program joins it; test builds add the
/// running test's own deadline (ktest::el0::deadline). A thread chosen
/// after a timer's interrupt ends that interrupt's latency.
fn decide() -> Decision<Thread> {
    #[cfg(feature = "ktest")]
    let test = crate::ktest::el0::deadline();
    let cleanup = cleanup::top();
    let now = timer::now();
    let mut g = SCHED.lock();
    let g = &mut *g;
    // SAFETY: the scheduler's threads are alive.
    let decision = unsafe { g.s.pick(now, cleanup) };
    if let Decision::Run(_) = decision
        && let Some((deadline, woke)) = g.fired.take()
    {
        let latency = now.saturating_sub(deadline);
        let max = if woke {
            &mut g.idle_latency
        } else {
            &mut g.irq_latency
        };
        *max = (*max).max(latency);
    }
    if let Decision::Idle = decision {
        // Nothing runs after the interrupt: the sleep that follows is no
        // part of its latency.
        g.fired = None;
    }
    // Programs have no timers yet (spec 10): the heap's earliest deadline
    // (kcore::timer::Heap::first) comes here with them.
    let deadline = g.s.deadline(None);
    #[cfg(feature = "ktest")]
    let deadline = deadline.into_iter().chain(test).min();
    g.armed.set(&mut VirtualTimer, deadline);
    decision
}

/// Nothing to do: sleeps in `wfi` with interrupts masked until one is
/// pending, and handles it; the time asleep counts for KSTATS.
fn sleep() {
    #[cfg(feature = "ktest")]
    crate::ktest::el0::note_idle_stack();
    let slept = timer::now();
    let ack = gic::wait();
    let woke = timer::now();
    {
        let mut g = SCHED.lock();
        g.idle += woke.saturating_sub(slept);
        g.waking = true;
    }
    if let Some(ack) = ack {
        crate::interrupt::handle(ack);
    }
    SCHED.lock().waking = false;
}

/// The ready thread that runs next at `level`.
#[cfg(feature = "ktest")]
pub fn first(level: u8) -> Option<NonNull<Thread>> {
    SCHED.lock().s.ready().first(level)
}
