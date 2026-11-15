// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The role `burner` (the probe of init's journal of overruns, xtask
//! `budget-journal`, init's table `table-budget-journal`): a service with two
//! budgets from its start data and an idle loop that sends the heartbeats.
//! The thread under `hog` works without a pause, so its budget runs out in
//! every period until the ticker stops it at second 13; the thread under
//! `quiet` works 100 us of each 10 ms and its budget never runs out. The
//! ticker prints a line each second of the clock with what the kernel counts
//! for each budget (`object_info`), which the probe sets against init's lines.

use abi::Policy;
use core::hint::black_box;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use proto_wire::Status;
use rt::handle::{Budget, Channel, Process, Thread, Timer};
use rt::service::{Answer, Request, Service, Session};
use rt::startup::Startup;
use rt::{Handle, Stack, sys, time};

const MS: u64 = 1_000_000;
const SECOND: u64 = 1_000 * MS;
const STACK_BYTES: usize = 16 * 1024;
static HOG_STACK: Stack<STACK_BYTES> = Stack::new();
static QUIET_STACK: Stack<STACK_BYTES> = Stack::new();
static TICK_STACK: Stack<STACK_BYTES> = Stack::new();
/// The message buffers of the two threads: the pages after the first thread's.
const HOG_BUFFER: usize = abi::INIT_MSGBUF as usize + 4096;
const QUIET_BUFFER: usize = abi::INIT_MSGBUF as usize + 2 * 4096;
const TICK_BUFFER: usize = abi::INIT_MSGBUF as usize + 3 * 4096;
/// The seconds the first thread counts.
const SECONDS: u64 = 30;
/// The code of a role that could not do its part.
const FAILED: u64 = 1;

/// Set by the ticker once the hog is to stop: the budget stops overrunning.
static STOP: AtomicBool = AtomicBool::new(false);
/// The budgets' handles, for the ticker.
static HOG_BUDGET: AtomicU64 = AtomicU64::new(0);
static QUIET_BUDGET: AtomicU64 = AtomicU64::new(0);
/// The second at which the hog stops.
const STOP_AT: u64 = 13;

pub fn run(mut s: Startup) -> u64 {
    if let Ok(console) = s.take::<rt::handle::Resource>("console") {
        rt::console::set(console);
    }
    let (Ok(hog), Ok(quiet)) = (s.take::<Budget>("hog"), s.take::<Budget>("quiet")) else {
        rt::println!("burner: no budgets in the start data");
        return FAILED;
    };
    HOG_BUDGET.store(hog.raw().0, Ordering::Release);
    QUIET_BUDGET.store(quiet.raw().0, Ordering::Release);
    let Some(_hog_thread) = start(&s.process, hog_loop, &HOG_STACK, HOG_BUFFER, &hog) else {
        return FAILED;
    };
    let Some(_quiet_thread) = start(&s.process, quiet_loop, &QUIET_STACK, QUIET_BUFFER, &quiet)
    else {
        return FAILED;
    };
    let Some(_ticker) = start_free(&s.process, ticker, &TICK_STACK, TICK_BUFFER) else {
        return FAILED;
    };
    let Ok(channel) = sys::channel_create(crate::base(&s)) else {
        return FAILED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return FAILED;
    }
    // The service itself does nothing: the loop sends the heartbeats that
    // init writes the tail of the overruns at.
    crate::serve(&s, &channel, &mut Idle)
}

/// A service with no methods.
struct Idle;

impl Service<1> for Idle {
    const VERSION: u16 = crate::VERSION;
    const METHODS: &'static [u16] = &[];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, _: &mut Request<'_>) -> Answer {
        Answer::Status(Status::UnknownMethod)
    }
}

/// The thread that prints a line each second and stops the hog at STOP_AT.
extern "C" fn ticker(_: u64) -> ! {
    let hog = Handle::<Budget>::borrowed(abi::Handle(HOG_BUDGET.load(Ordering::Acquire)));
    let quiet = Handle::<Budget>::borrowed(abi::Handle(QUIET_BUDGET.load(Ordering::Acquire)));
    let Ok(wait) = sys::channel_create_wait(30) else {
        sys::thread_exit()
    };
    let Ok(timer) = sys::timer_create(&wait, 30) else {
        sys::thread_exit()
    };
    let began = time::ticks_to_ns(time::now());
    for second in 0..=SECONDS {
        let overruns = |b: &Handle<Budget>| sys::budget_info(b).map_or(u64::MAX, |i| i.overruns);
        rt::println!(
            "burner: t={second} hog={} quiet={}",
            overruns(&hog),
            overruns(&quiet)
        );
        if second == STOP_AT {
            STOP.store(true, Ordering::Release);
        }
        sleep_until(&wait, &timer, began + (second + 1) * SECOND);
    }
    rt::println!("burner: done");
    loop {
        sleep_until(&wait, &timer, began + 1000 * SECOND);
    }
}

/// A thread under `budget`, bound before it starts.
fn start<const N: usize>(
    process: &Handle<Process>,
    entry: extern "C" fn(u64) -> !,
    stack: &'static Stack<N>,
    buffer: usize,
    budget: &Handle<Budget>,
) -> Option<Handle<Thread>> {
    // SAFETY: each stack and message buffer page is one thread's alone.
    let thread =
        unsafe { sys::thread_create(process, entry, stack.top(), 0, 30, Policy::Fifo, buffer) }
            .ok()?;
    sys::thread_bind_budget(&thread, budget).ok()?;
    sys::thread_start(&thread).ok()?;
    Some(thread)
}

/// A thread with no budget.
fn start_free<const N: usize>(
    process: &Handle<Process>,
    entry: extern "C" fn(u64) -> !,
    stack: &'static Stack<N>,
    buffer: usize,
) -> Option<Handle<Thread>> {
    // SAFETY: each stack and message buffer page is one thread's alone.
    let thread =
        unsafe { sys::thread_create(process, entry, stack.top(), 0, 30, Policy::Fifo, buffer) }
            .ok()?;
    sys::thread_start(&thread).ok()?;
    Some(thread)
}

fn sleep_until(wait: &Handle<Channel>, timer: &Handle<Timer>, ns: u64) {
    if sys::timer_set(timer, ns).is_ok() {
        let _ = sys::receive(wait);
    }
}

extern "C" fn hog_loop(_: u64) -> ! {
    let mut i = 0u64;
    while !STOP.load(Ordering::Acquire) {
        i = black_box(i.wrapping_add(1));
    }
    // Stopped: the thread waits for ever, and its budget overruns no more.
    let Ok(wait) = sys::channel_create_wait(30) else {
        sys::thread_exit()
    };
    loop {
        let _ = sys::receive(&wait);
    }
}

extern "C" fn quiet_loop(_: u64) -> ! {
    let Ok(wait) = sys::channel_create_wait(30) else {
        sys::thread_exit()
    };
    let Ok(timer) = sys::timer_create(&wait, 30) else {
        sys::thread_exit()
    };
    let mut next = time::ticks_to_ns(time::now()) + 10 * MS;
    loop {
        let until = time::now() + time::ns_to_ticks(100_000);
        while time::now() < until {
            black_box(0);
        }
        sleep_until(&wait, &timer, next);
        next += 10 * MS;
    }
}
