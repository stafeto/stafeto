// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! init, the first program (spec 13.4), as milestone 1.2c has it: it
//! prints from EL0, starts two round-robin threads at one level, which
//! take turns as their quanta end, waits for them and exits; its exit
//! turns the machine off. Nothing to wait on exists in 1.2c, so init waits
//! by priority: it lowers itself below the threads and runs again only
//! once both have ended.

#![no_std]
#![no_main]

use abi::{Error, Policy};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use rt::{Stack, init, println, sys};

rt::entry!(main);

/// The threads' level, below init's 63.
const LEVEL: u8 = 10;
/// Lines each thread prints.
const TURNS: u64 = 3;
const STACK_SIZE: usize = 16 * 1024;
const PAGE: usize = 4096;

/// What a thread shows its peer: how far it has counted, and whether it
/// is done.
struct Progress {
    count: AtomicU64,
    done: AtomicBool,
}

static PROGRESS: [Progress; 2] = [const {
    Progress {
        count: AtomicU64::new(0),
        done: AtomicBool::new(false),
    }
}; 2];
static STACKS: [Stack<STACK_SIZE>; 2] = [const { Stack::new() }; 2];

fn main(_: u64) -> u64 {
    rt::console::set(&init::RESOURCE);
    println!("init: hello from EL0");
    println!("init: threads 1 and 2 take turns at priority {LEVEL}, round robin");
    for i in 0..2 {
        start(i).expect("init starts its threads");
    }
    // Both threads are above init now; the call returns once both ended.
    sys::thread_set_priority(&init::THREAD, 1, Policy::Fifo).expect("init lowers itself");
    println!("init: both threads are done");
    0
}

/// Starts thread `i` of the two; its message buffer lies above init's own.
fn start(i: usize) -> Result<(), Error> {
    let buffer = abi::INIT_MSGBUF as usize + (i + 1) * PAGE;
    // SAFETY: the stack is the thread's alone.
    let t = unsafe {
        sys::thread_create(
            &init::PROCESS,
            turns,
            STACKS[i].top(),
            i as u64,
            LEVEL,
            Policy::RoundRobin,
            buffer,
        )
    }?;
    sys::thread_start(&t)?;
    // The thread goes on without the handle.
    t.close()
}

/// Thread `me` of the two (0 or 1) prints its turn, then counts, with no
/// call, until its peer has run: that is when the thread's quantum ended
/// and the peer's did too. A peer that is done lets the last turn go.
extern "C" fn turns(me: u64) -> ! {
    let me = me as usize;
    let (mine, peer) = (&PROGRESS[me], &PROGRESS[1 - me]);
    for turn in 1..=TURNS {
        println!("thread {}: turn {turn}", me + 1);
        if turn < TURNS {
            let seen = peer.count.load(Relaxed);
            while peer.count.load(Relaxed) == seen && !peer.done.load(Relaxed) {
                mine.count.fetch_add(1, Relaxed);
            }
        }
    }
    mine.done.store(true, Relaxed);
    sys::thread_exit()
}
