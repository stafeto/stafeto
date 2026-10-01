// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Fixed-duration RTOS primitive throughput and periodic wakeup latency.
//! The workloads follow Thread-Metric and Zyclictest's measurement patterns.
//! It runs as init (QEMU), or as a client of init beside the console's
//! driver, which shows its lines (Apple VZ, where the kernel has no port):
//! the same layout of stacks and message buffers either way
//! (rt::loader).

#![no_std]
#![no_main]

use abi::{Policy, Source};
use core::hint::black_box;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rt::handle::{Channel, Process, Resource, Thread};
use rt::{Handle, Stack, println, sys, time};

rt::entry!(main);

const SECOND: u64 = 1_000_000_000;
const PERIOD: u64 = 1_000_000;
const SAMPLES: usize = 1000;
const MAIN_PRIORITY: u8 = 20;
const HIGH_PRIORITY: u8 = 30;
const LOW_PRIORITY: u8 = 5;
const PAGE: usize = 4096;

static STACKS: [Stack<16384>; 4] = [const { Stack::new() }; 4];
static RUN: AtomicBool = AtomicBool::new(false);
static COUNT: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

fn now_ns() -> u64 {
    time::ticks_to_ns(time::now())
}

fn spawn(
    process: &Handle<Process>,
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    arg: u64,
    priority: u8,
) -> Handle<Thread> {
    // SAFETY: each worker gets its own stack and message-buffer page;
    // a phase waits for every worker to exit before reusing its stack.
    let thread = unsafe {
        sys::thread_create(
            process,
            entry,
            STACKS[slot].top(),
            arg,
            priority,
            Policy::Fifo,
            abi::INIT_MSGBUF as usize + (slot + 1) * PAGE,
        )
    }
    .expect("create benchmark thread");
    sys::thread_start(&thread).expect("start benchmark thread");
    thread
}

fn finish_workers(me: &Handle<Thread>) {
    RUN.store(false, Ordering::Release);
    sys::thread_set_priority(me, 1, Policy::Fifo).expect("let workers finish");
    sys::thread_set_priority(me, MAIN_PRIORITY, Policy::Fifo).expect("restore benchmark priority");
}

extern "C" fn cooperative_worker(slot: u64) -> ! {
    let counter = &COUNT[slot as usize];
    while RUN.load(Ordering::Acquire) {
        counter.fetch_add(1, Ordering::Relaxed);
        sys::yield_now().expect("cooperative yield");
    }
    sys::thread_exit()
}

extern "C" fn notification_worker(raw: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(raw));
    loop {
        match sys::receive(&channel).expect("notification receive") {
            sys::Received::Notification { .. } => {
                if !RUN.load(Ordering::Acquire) {
                    break;
                }
                COUNT[0].fetch_add(1, Ordering::Relaxed);
            }
            _ => panic!("unexpected notification workload message"),
        }
    }
    sys::thread_exit()
}

extern "C" fn message_worker(raw: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(raw));
    loop {
        match sys::receive(&channel).expect("message receive") {
            sys::Received::Message { token, .. } => {
                token.reply(b"ok").expect("message reply");
                if !RUN.load(Ordering::Acquire) {
                    break;
                }
            }
            _ => panic!("unexpected message workload notification"),
        }
    }
    sys::thread_exit()
}

extern "C" fn load_worker(_: u64) -> ! {
    let mut value = 1u64;
    while RUN.load(Ordering::Acquire) {
        for _ in 0..1024 {
            value = black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
        }
    }
    black_box(value);
    sys::thread_exit()
}

fn baseline() {
    let start = now_ns();
    let deadline = start + SECOND;
    let mut ops = 0u64;
    let mut value = 1u64;
    while now_ns() < deadline {
        for _ in 0..1024 {
            value = black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
        }
        ops += 1024;
    }
    black_box(value);
    println!("RTBENCH baseline ops={} ns={}", ops, now_ns() - start);
}

fn cooperative(process: &Handle<Process>, me: &Handle<Thread>) {
    for count in &COUNT {
        count.store(0, Ordering::Relaxed);
    }
    RUN.store(true, Ordering::Release);
    let workers = core::array::from_fn::<_, 4, _>(|slot| {
        spawn(
            process,
            slot,
            cooperative_worker,
            slot as u64,
            MAIN_PRIORITY,
        )
    });
    let start = now_ns();
    let deadline = start + SECOND;
    let mut own = 0u64;
    while now_ns() < deadline {
        own += 1;
        sys::yield_now().expect("main cooperative yield");
    }
    let elapsed = now_ns() - start;
    finish_workers(me);
    let total = own + COUNT.iter().map(|n| n.load(Ordering::Relaxed)).sum::<u64>();
    let smallest = COUNT
        .iter()
        .map(|n| n.load(Ordering::Relaxed))
        .min()
        .unwrap()
        .min(own);
    let largest = COUNT
        .iter()
        .map(|n| n.load(Ordering::Relaxed))
        .max()
        .unwrap()
        .max(own);
    drop(workers);
    println!(
        "RTBENCH cooperative ops={} ns={} min={} max={}",
        total, elapsed, smallest, largest
    );
}

fn preemptive(process: &Handle<Process>, me: &Handle<Thread>) {
    let channel = sys::channel_create(HIGH_PRIORITY).expect("preemption channel");
    COUNT[0].store(0, Ordering::Relaxed);
    RUN.store(true, Ordering::Release);
    let worker = spawn(
        process,
        0,
        notification_worker,
        channel.raw().0,
        HIGH_PRIORITY,
    );
    let start = now_ns();
    let deadline = start + SECOND;
    let mut ops = 0u64;
    while now_ns() < deadline {
        sys::notify(&channel, 1).expect("notify higher priority thread");
        ops += 1;
    }
    let elapsed = now_ns() - start;
    RUN.store(false, Ordering::Release);
    sys::notify(&channel, 1).expect("stop notification worker");
    finish_workers(me);
    let handled = COUNT[0].load(Ordering::Relaxed);
    drop(worker);
    println!(
        "RTBENCH preemptive ops={} ns={} handled={}",
        ops, elapsed, handled
    );
}

fn messages(process: &Handle<Process>, me: &Handle<Thread>) {
    let channel = sys::channel_create(HIGH_PRIORITY).expect("message channel");
    RUN.store(true, Ordering::Release);
    let worker = spawn(process, 0, message_worker, channel.raw().0, HIGH_PRIORITY);
    let start = now_ns();
    let deadline = start + SECOND;
    let mut ops = 0u64;
    while now_ns() < deadline {
        let reply = sys::send(&channel, b"ping").expect("message round trip");
        assert_eq!(reply.len, 2);
        ops += 1;
    }
    let elapsed = now_ns() - start;
    RUN.store(false, Ordering::Release);
    sys::send(&channel, b"stop").expect("stop message worker");
    finish_workers(me);
    drop(worker);
    println!("RTBENCH messages ops={} ns={}", ops, elapsed);
}

fn allocation() {
    let start = now_ns();
    let deadline = start + SECOND;
    let mut ops = 0u64;
    while now_ns() < deadline {
        let object = sys::mem_create(PAGE as u64).expect("allocate memory object");
        drop(object);
        ops += 1;
    }
    println!("RTBENCH allocation ops={} ns={}", ops, now_ns() - start);
}

fn synchronization() {
    let channel = sys::channel_create(MAIN_PRIORITY).expect("synchronization channel");
    let start = now_ns();
    let deadline = start + SECOND;
    let mut ops = 0u64;
    while now_ns() < deadline {
        sys::notify(&channel, 1).expect("signal self");
        assert!(matches!(
            sys::receive(&channel).expect("take self notification"),
            sys::Received::Notification {
                source: Source::Unlabeled,
                bits: 1,
                ..
            }
        ));
        ops += 1;
    }
    println!(
        "RTBENCH synchronization ops={} ns={}",
        ops,
        now_ns() - start
    );
}

fn percentile(histogram: &[u32; 4097], rank: usize) -> usize {
    let mut total = 0usize;
    for (bucket, count) in histogram.iter().enumerate() {
        total += *count as usize;
        if total >= rank {
            return bucket;
        }
    }
    histogram.len() - 1
}

fn timer_wakeup(process: &Handle<Process>, me: &Handle<Thread>, load: bool) {
    let channel = sys::channel_create(MAIN_PRIORITY).expect("timer channel");
    let timer = sys::timer_create(&channel, MAIN_PRIORITY).expect("periodic timer");
    let worker = if load {
        RUN.store(true, Ordering::Release);
        Some(spawn(process, 0, load_worker, 0, LOW_PRIORITY))
    } else {
        None
    };
    let mut histogram = [0u32; 4097];
    let mut maximum = 0u64;
    let mut missed = 0u64;
    let mut deadline = now_ns() + PERIOD;
    for _ in 0..SAMPLES {
        sys::timer_set(&timer, deadline).expect("arm periodic timer");
        let received = sys::receive(&channel).expect("wait for periodic timer");
        assert!(matches!(
            received,
            sys::Received::Notification {
                source: Source::Timer,
                ..
            }
        ));
        let late = now_ns().saturating_sub(deadline);
        maximum = maximum.max(late);
        histogram[(late / 1000).min(4096) as usize] += 1;
        missed += late / PERIOD;
        deadline += (late / PERIOD + 1) * PERIOD;
    }
    if load {
        finish_workers(me);
    }
    drop(worker);
    let name = if load { "timer_load" } else { "timer_idle" };
    println!(
        "RTBENCH {} n={} p50us={} p99us={} maxns={} missed={}",
        name,
        SAMPLES,
        percentile(&histogram, SAMPLES.div_ceil(2)),
        percentile(&histogram, SAMPLES * 99 / 100),
        maximum,
        missed
    );
}

fn main(_: u64) -> u64 {
    let (process, me, child) = match rt::init_handles() {
        Some(init) => {
            rt::console::set(init.resource);
            (init.process, init.thread, false)
        }
        None => {
            let mut start = rt::startup().expect("benchmark start data");
            if let Ok(console) = start.take::<Resource>("console") {
                rt::console::set(console);
            }
            (start.process, start.thread, true)
        }
    };
    sys::thread_set_priority(&me, MAIN_PRIORITY, Policy::Fifo).expect("set benchmark priority");
    println!("RTBENCH START hz={}", time::frequency());
    baseline();
    cooperative(&process, &me);
    preemptive(&process, &me);
    messages(&process, &me);
    synchronization();
    allocation();
    timer_wakeup(&process, &me, false);
    timer_wakeup(&process, &me, true);
    println!("RTBENCH DONE");
    if child {
        return 0;
    }
    loop {
        sys::yield_now().expect("wait for benchmark host");
    }
}
