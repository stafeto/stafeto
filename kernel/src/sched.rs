// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel's scheduler (spec 8, 8.1): the rules of kcore::sched over
//! the kernel's threads, the virtual timer and the idle loop. Every entry
//! into the kernel ends in `resume`, the one way out: it decides who runs,
//! arms the timer for the deadline that decision needs, writing the timer
//! only when the deadline changes, and runs the chosen thread or idles. The
//! idle loop is kernel code with no thread object: it sleeps in `wfi` with
//! interrupts masked, handles what woke it and decides again. The kernel
//! holds a reference to every thread the scheduler holds, from `start`
//! until `exit`.

use crate::arch::{self, gic, timer};
use crate::thread::{self, Policy, Thread};
use abi::Error;
use core::ptr::NonNull;
use kcore::sched::{Armed, Scheduler, State, Timer};
use kcore::sync::Lock;
use kcore::time::Clock;

struct Sched {
    s: Scheduler<Thread>,
    /// The deadline the timer holds.
    armed: Armed,
    /// Counter ticks spent asleep in the idle loop, for KSTATS (milestone
    /// 1.3) and `uptime` (milestone 1.4).
    idle: u64,
}

/// The quantum is 0 until `init` knows the counter's frequency.
static SCHED: Lock<Sched> = Lock::new(Sched {
    s: Scheduler::new(0),
    armed: Armed::new(),
    idle: 0,
});

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
/// BAD_STATE for a thread that started before.
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "thread_start and init (milestone 1.2c) start threads; so far only the kernel tests do"
    )
)]
pub fn start(t: NonNull<Thread>) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to `t`; the one taken below keeps
    // it alive, and a pool object never moves, until `exit`.
    unsafe { SCHED.lock().s.start(t)? };
    thread::retain(t);
    Ok(())
}

/// Ends `t` for the scheduler, whatever its state: it never runs again,
/// and the reference the kernel took at `start` goes. When `t` was the
/// running thread, `resume` decides who runs next. A thread that ended
/// before stays as it is.
///
/// # Safety
/// `t` is alive. When the kernel's reference is its last, `t` goes here,
/// and the caller does not use it afterwards.
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "thread_exit and process_kill (milestone 1.2c) end threads; so far only the kernel tests do"
    )
)]
pub unsafe fn exit(t: NonNull<Thread>) {
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
        unsafe { thread::release(t) };
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
/// arms the timer again.
pub fn timer_fired() {
    let now = timer::now();
    let mut g = SCHED.lock();
    let g = &mut *g;
    // The line must drop before the EOI whatever `armed` remembers: the
    // hardware said the timer is on.
    VirtualTimer.disarm();
    g.armed = Armed::new();
    // SAFETY: the scheduler's threads are alive.
    unsafe { g.s.tick(now) };
}

/// The way out of the kernel: the decision, the timer for it, then the
/// chosen thread at EL0, or the idle loop when no thread is ready. The
/// caller's stack holds nothing with a `Drop` (thread::run).
pub fn resume() -> ! {
    match decide() {
        Some(t) => thread::run(t),
        None => arch::on_empty_stack(idle),
    }
}

/// Decides who runs from now on, None to idle, and arms the timer for
/// the deadline that needs: the end of a round-robin thread's quantum;
/// nothing for a FIFO thread or while idle. From milestone 1.3 the
/// nearest timer of a program joins it; test builds add the running
/// test's own deadline (ktest::el0::deadline).
fn decide() -> Option<NonNull<Thread>> {
    #[cfg(feature = "ktest")]
    let test = crate::ktest::el0::deadline();
    let mut g = SCHED.lock();
    let g = &mut *g;
    // SAFETY: the scheduler's threads are alive.
    let next = unsafe { g.s.pick(timer::now()) };
    let deadline = g.s.deadline();
    #[cfg(feature = "ktest")]
    let deadline = deadline.into_iter().chain(test).min();
    g.armed.set(&mut VirtualTimer, deadline);
    next
}

/// The idle loop, on an empty kernel stack: sleeps in `wfi` with
/// interrupts masked until one is pending, handles it, and decides again.
/// TTBR0, TPIDR_EL1 and the FP registers keep the last thread's, so going
/// back to that thread costs nothing. Leaves only through thread::run.
extern "C" fn idle() -> ! {
    #[cfg(feature = "ktest")]
    crate::ktest::el0::note_idle_stack();
    loop {
        let slept = timer::now();
        let ack = gic::wait();
        let woke = timer::now();
        SCHED.lock().idle += woke.saturating_sub(slept);
        if let Some(ack) = ack {
            crate::interrupt::handle(ack);
        }
        if let Some(t) = decide() {
            thread::run(t)
        }
    }
}

/// Counter ticks the kernel has slept in the idle loop.
#[cfg(feature = "ktest")]
pub fn idle_ticks() -> u64 {
    SCHED.lock().idle
}

/// The ready thread that runs next at `level`.
#[cfg(feature = "ktest")]
pub fn first(level: u8) -> Option<NonNull<Thread>> {
    SCHED.lock().s.ready().first(level)
}
