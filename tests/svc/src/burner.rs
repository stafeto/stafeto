// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The role `burner` (the probe of init's journal of overruns, xtask
//! `budget-journal`, init's table `table-budget-journal`): a client with two
//! budgets from its start data. The thread under `hog` works without a pause,
//! so its budget runs out in every period; the thread under `quiet` works
//! 100 us of each 10 ms and its budget never runs out. The first thread
//! prints a line each second of the clock with what the kernel counts for
//! each budget (`object_info`), which the probe sets against init's lines.

use abi::Policy;
use core::hint::black_box;
use rt::handle::{Budget, Channel, Process, Thread, Timer};
use rt::startup::Startup;
use rt::{Handle, Stack, sys, time};

const MS: u64 = 1_000_000;
const SECOND: u64 = 1_000 * MS;
const STACK_BYTES: usize = 16 * 1024;
static HOG_STACK: Stack<STACK_BYTES> = Stack::new();
static QUIET_STACK: Stack<STACK_BYTES> = Stack::new();
/// The message buffers of the two threads: the pages after the first thread's.
const HOG_BUFFER: usize = abi::INIT_MSGBUF as usize + 4096;
const QUIET_BUFFER: usize = abi::INIT_MSGBUF as usize + 2 * 4096;
/// The seconds the first thread counts.
const SECONDS: u64 = 25;
/// The code of a role that could not do its part.
const FAILED: u64 = 1;

pub fn run(mut s: Startup) -> u64 {
    if let Ok(console) = s.take::<rt::handle::Resource>("console") {
        rt::console::set(console);
    }
    let (Ok(hog), Ok(quiet)) = (s.take::<Budget>("hog"), s.take::<Budget>("quiet")) else {
        rt::println!("burner: no budgets in the start data");
        return FAILED;
    };
    let Some(hog_thread) = start(&s.process, hog_loop, &HOG_STACK, HOG_BUFFER, &hog) else {
        return FAILED;
    };
    let Some(quiet_thread) = start(&s.process, quiet_loop, &QUIET_STACK, QUIET_BUFFER, &quiet)
    else {
        return FAILED;
    };
    let Ok(wait) = sys::channel_create_wait(30) else {
        return FAILED;
    };
    let Ok(timer) = sys::timer_create(&wait, 30) else {
        return FAILED;
    };
    let began = time::ticks_to_ns(time::now());
    for second in 0..=SECONDS {
        let overruns = |b: &Handle<Budget>| sys::budget_info(b).map_or(u64::MAX, |i| i.overruns);
        rt::println!(
            "burner: t={second} hog={} quiet={}",
            overruns(&hog),
            overruns(&quiet)
        );
        sleep_until(&wait, &timer, began + (second + 1) * SECOND);
    }
    rt::println!("burner: done");
    // The threads are not stopped: the probe ends the machine on this line.
    drop((hog_thread, quiet_thread));
    0
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

fn sleep_until(wait: &Handle<Channel>, timer: &Handle<Timer>, ns: u64) {
    if sys::timer_set(timer, ns).is_ok() {
        let _ = sys::receive(wait);
    }
}

extern "C" fn hog_loop(_: u64) -> ! {
    let mut i = 0u64;
    loop {
        i = black_box(i.wrapping_add(1));
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
