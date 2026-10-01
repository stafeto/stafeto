// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The hostile load of rtbench 2, which measures under the longest
//! operations of the kernel: a worker thread at the lowest level of the
//! image makes a process, gives it the most threads a process holds
//! (abi::MAX_THREADS, stopped: the child has no code), kills it, and
//! makes and drops a large memory object, over and over. The first thread
//! serves ROUNDS, which the benchmark asks at its end: the rounds the
//! worker made, or FAILED once a round failed (it stops then). The program
//! speaks once at its start and once on a failure: a line in the middle of
//! the benchmark's lines could cut one of them in the console.

#![no_std]
#![no_main]

use abi::{MAX_THREADS, Policy};
use core::sync::atomic::{AtomicU64, Ordering};
use proto_init::ServiceArgs;
use proto_wire::Status;
use rt::handle::{Outgoing, Resource};
use rt::service::{self, Answer, Config, Heartbeat, Request, Service, Session};
use rt::{Stack, println, sys};

rt::entry!(main);

const PAGE: u64 = 4096;
/// The quota of the child: its threads' kernel memory.
const CHILD_QUOTA: u64 = 512 * PAGE;
/// The large memory object of each round.
const LARGE: u64 = 1024 * PAGE;
/// Where the child's threads would have their stacks and message buffers:
/// nothing is mapped there, and they never start.
const STACK: usize = 0x1000_0000;
const BUFFERS: usize = 0x2000_0000;
/// The level of the worker, below every thread of the benchmark.
const LEVEL: u8 = 5;
/// The method of the service: the rounds so far, u64 after the status.
pub const ROUNDS: u16 = 1;
const VERSION: u16 = 1;
/// The rounds once a round failed.
const FAILED: u64 = u64::MAX;

static ROUND_COUNT: AtomicU64 = AtomicU64::new(0);
static WORKER: Stack<16384> = Stack::new();

/// The entry of the child's threads, which never run.
extern "C" fn idle(_: u64) -> ! {
    sys::thread_exit()
}

fn round(level: u8) -> Result<(), abi::Error> {
    let child = sys::process_create(CHILD_QUOTA, 8, level)?;
    for index in 0..MAX_THREADS as usize {
        // SAFETY: the threads stay stopped and the child dies before any
        // of them could run.
        let thread = unsafe {
            sys::thread_create(
                &child,
                idle,
                STACK,
                0,
                level,
                Policy::Fifo,
                BUFFERS + index * PAGE as usize,
            )
        }?;
        drop(thread);
    }
    sys::process_kill(&child)?;
    drop(child);
    drop(sys::mem_create(LARGE)?);
    Ok(())
}

extern "C" fn worker(_: u64) -> ! {
    loop {
        if let Err(error) = round(LEVEL) {
            println!(
                "rtbench-load: failed after {} rounds: {:?}",
                ROUND_COUNT.load(Ordering::Relaxed),
                error
            );
            ROUND_COUNT.store(FAILED, Ordering::Relaxed);
            sys::thread_exit()
        }
        ROUND_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

struct Load;

impl Service<1> for Load {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = &[ROUNDS];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, r: &mut Request<'_>) -> Answer {
        let rounds = ROUND_COUNT.load(Ordering::Relaxed);
        let w = r.reply();
        match w.u32(Status::Ok.code()).and_then(|()| w.u64(rounds)) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let base = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(base) else {
        return 1;
    };
    if service::register(&start.parent, &channel).is_err() {
        return 1;
    }
    // SAFETY: WORKER is the worker's alone; its message buffer is the page
    // after the first thread's.
    let thread = unsafe {
        sys::thread_create(
            &start.process,
            worker,
            WORKER.top(),
            0,
            LEVEL,
            Policy::Fifo,
            abi::INIT_MSGBUF as usize + PAGE as usize,
        )
    };
    match thread.map(|t| (sys::thread_start(&t), t)) {
        Ok((Ok(()), t)) => drop(t),
        _ => return 1,
    }
    println!("rtbench-load: running at {}", LEVEL);
    let period_ns = ServiceArgs::read(start.args()).map_or(0, |a| a.period_ns);
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &start.parent,
            period_ns,
            priority: base,
        }),
    };
    let _ = service::run::<Load, 4, 1>(&channel, &mut Load, config);
    1
}
