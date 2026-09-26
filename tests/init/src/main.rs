// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The test init (spec 15.2). It runs in place of init on the normal
//! build of the kernel, the one that ships, and tests the system calls
//! from EL0, in its own process, in children with no code and in children
//! it loads from the boot image, the child program (tests/child). The
//! contract of the calls is checked here and only here: the order of
//! their checks, their rights, and that on an error x0 alone changes
//! (spec 11), the caller's own ceiling among them, which a child under a
//! lower ceiling checks; the kernel tests keep what a program cannot see
//! or reach, such as a caller's full table or the kernel's own state after
//! a call. It prints `TEST <name> ok` or `TEST <name> FAIL <why>`
//! for each test, then `TESTS DONE total=<n> failed=<m>`, and exits with
//! the number of failures, which turns the machine off; xtask reads the
//! lines.
//!
//! Its first line gives the counter ticks of a counted loop, which xtask
//! checks in the runs under -icount. The first test runs with the
//! priority the kernel gave init; the others with init at TEST_PRIORITY.
//! A thread above it runs at once; threads below it run when init lowers
//! itself to 1 (`let_run`), and init runs again once they all have ended
//! or wait: the order of priorities joins threads. Init hears of the end
//! of a child through the child's exit channel (`wait_exit`, `Kid::end`,
//! spec 7.9).
//! Notifications that init takes in its own thread have priority 1
//! (QUIET), and init asks once more afterwards: their boost never lifts
//! init above its threads (spec 6.6).

#![no_std]
#![no_main]

mod calls;
mod channels;
mod devices;
mod harness;
mod memory;
mod messages;
mod processes;
mod runtime;
mod timers;
mod transfers;

use harness::{LOOP_TICKS, Policy, Relaxed, TEST_PRIORITY, Test, keep, me, println, sys};
use processes::prepare;

rt::entry!(main);

/// The tests of each module, in the order they run.
const MODULES: [&[Test]; 9] = [
    &calls::TESTS,
    &channels::TESTS,
    &timers::TESTS,
    &memory::TESTS,
    &processes::TESTS,
    &messages::TESTS,
    &transfers::TESTS,
    &devices::TESTS,
    &runtime::TESTS,
];

fn main(_: u64) -> u64 {
    keep(rt::init_handles().expect("init's first handles come once"));
    let ticks = loop_ticks();
    LOOP_TICKS.store(ticks, Relaxed);
    println!("counter ticks of 10000 turns: {ticks}");
    if let Err(why) = prepare() {
        println!("test init: no children with code: {why}");
    }
    let mut failed = 0;
    let tests = MODULES.into_iter().flatten();
    for (i, &(name, test)) in tests.enumerate() {
        if i == 1 {
            sys::thread_set_priority(&me(), TEST_PRIORITY, Policy::Fifo)
                .expect("init takes the priority of the tests");
        }
        match test() {
            Ok(()) => println!("TEST {name} ok"),
            Err(why) => {
                failed += 1;
                println!("TEST {name} FAIL {why}");
            }
        }
    }
    let total: usize = MODULES.iter().map(|m| m.len()).sum();
    println!("TESTS DONE total={total} failed={failed}");
    failed
}

/// Counter ticks of 10 000 turns of a two-instruction loop: 20 000 and a
/// few more under `-icount shift=4`, one instruction per tick of the
/// 62.5 MHz counter.
fn loop_ticks() -> u64 {
    let (start, end): (u64, u64);
    // SAFETY: a counted loop between two counter reads; no memory access.
    unsafe {
        core::arch::asm!(
            "isb",
            "mrs {start}, cntvct_el0",
            "mov {n}, #10000",
            "1: subs {n}, {n}, #1",
            "b.ne 1b",
            "isb",
            "mrs {end}, cntvct_el0",
            start = out(reg) start,
            end = out(reg) end,
            n = out(reg) _,
            options(nomem, nostack),
        )
    };
    end - start
}
