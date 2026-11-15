// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the time budgets of threads (spec 8), for QEMU under
//! -icount, where the numbers of one build repeat to the tick. It runs as
//! init and prints lines that `cargo xtask budget-hog` checks against their
//! bounds. Five phases, on one CPU unless a phase says another:
//!
//! 1. A hog at 50 with the budget of 300 us for each 1 ms, low 1, spins
//!    against a victim at 10 with no budget. The victim notes the time it
//!    runs and the hog its own, a bucket of 1 ms each; the lines give for
//!    windows of 1, 5 and 10 ms the least share the victim got and the most
//!    time the hog took.
//! 2. A service at 20 with the budget of 200 us works 500 us for each
//!    request of a client at 40: the boost of the client's request stays
//!    when the budget is gone, so the request takes the work and no more.
//! 3. The loan: a client at 40 with a budget calls a service whose budget is
//!    gone, on its CPU and on another; the service's work is the client's
//!    time, so the requests the client makes stay within its budget.
//! 4. The queue: a client at 5 has a request in a service whose budget is
//!    gone, which a spinner at 10 on the service's CPU keeps from running;
//!    a client at 40 sends a request that queues behind it: the service is
//!    lifted to 40, ends the first request and takes the second, so the
//!    second client waits for one request at most, and the service never
//!    waits at its low level between a reply and its next receive.
//! 5. A worker at 5 with the budget of 200 us is notified through a channel
//!    of 55 and spins 800 us for each notification: the boost of the slot
//!    goes with the budget, and the victim at 10 keeps its share.

#![no_std]
#![no_main]

use abi::Policy;
use core::hint::black_box;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use rt::handle::{Channel, Process, Resource, Thread};
use rt::{Handle, Stack, println, sys, time};

rt::entry!(main);

const MS: u64 = 1_000_000;
const PAGE: usize = 4096;
/// The buckets of 1 ms the time of a thread is noted in.
const BUCKETS: usize = 256;
const PHASE_MS: u64 = 200;
/// A gap between two looks at the counter longer than this is time the
/// thread did not run.
const GAP_NS: u64 = 20_000;

static STACKS: [Stack<16384>; 4] = [const { Stack::new() }; 4];
static START: AtomicU64 = AtomicU64::new(0);
static BUCKET: AtomicU64 = AtomicU64::new(1);
static SPENT: [[AtomicU64; BUCKETS]; 2] = [const { [const { AtomicU64::new(0) }; BUCKETS] }; 2];
/// The longest gap each spinner saw, in ticks.
static GAP: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
/// What a phase's threads work on, ticks: the end of the phase, the work of
/// a request, the channel of a service.
static END: AtomicU64 = AtomicU64::new(0);
static WORK: AtomicU64 = AtomicU64::new(0);
static CHANNEL: AtomicU64 = AtomicU64::new(0);

const VICTIM: usize = 0;
const HOG: usize = 1;

fn spawn(
    process: &Handle<Process>,
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    priority: u8,
) -> Handle<Thread> {
    spawn_on(process, slot, entry, priority, 0)
}

fn spawn_on(
    process: &Handle<Process>,
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    priority: u8,
    cpu: u8,
) -> Handle<Thread> {
    // SAFETY: each thread gets its own stack and message buffer page; a
    // phase waits for its threads to end before the next reuses them.
    unsafe {
        sys::thread_create_on(
            process,
            entry,
            STACKS[slot].top(),
            0,
            priority,
            Policy::Fifo,
            abi::INIT_MSGBUF as usize + (slot + 1) * PAGE,
            None,
            // CPU number plus one: 0 is the CPU of the caller.
            cpu + 1,
        )
    }
    .expect("create a thread")
}

/// Spins until `END`, noting in the buckets of `who` the ticks it ran: the
/// gaps between two looks that are no longer than GAP_NS; a longer one goes
/// to the longest gap.
fn spin(who: usize) {
    let bucket = BUCKET.load(Relaxed);
    let start = START.load(Relaxed);
    let end = END.load(Relaxed);
    let gap_ticks = time::ns_to_ticks(GAP_NS);
    let mut last = time::now();
    let mut i = 0u64;
    loop {
        for _ in 0..16 {
            i = black_box(i.wrapping_add(1));
        }
        let now = time::now();
        let gap = now - last;
        last = now;
        if gap > gap_ticks {
            GAP[who].fetch_max(gap, Relaxed);
        } else {
            let b = (now.saturating_sub(start) / bucket) as usize;
            if b < BUCKETS {
                SPENT[who][b].fetch_add(gap, Relaxed);
            }
        }
        if now >= end {
            return;
        }
    }
}

extern "C" fn victim(_: u64) -> ! {
    spin(VICTIM);
    sys::thread_exit()
}

extern "C" fn hog(_: u64) -> ! {
    spin(HOG);
    sys::thread_exit()
}

/// A service: takes requests, works WORK ticks for each, answers; the
/// answer goes with the next receive (`Token::reply_receive`), as the loop of
/// `rt::service` does it.
extern "C" fn service(_: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    let mut next = sys::receive(&channel).expect("receive a request");
    while let sys::Received::Message { token, words, .. } = next {
        // "stop" ends the service; any other request is work.
        let stop = words[0].to_le_bytes()[0] == b's';
        if stop {
            token.reply(b"ok").expect("reply");
            break;
        }
        let until = time::now() + WORK.load(Relaxed);
        while time::now() < until {
            black_box(0);
        }
        next = token
            .reply_receive(&channel, b"ok")
            .expect("reply and receive");
    }
    sys::thread_exit()
}

/// A worker: spins WORK ticks for each notification of its channel.
extern "C" fn worker(_: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    while let sys::Received::Notification { .. } =
        sys::receive(&channel).expect("receive a notification")
    {
        let until = time::now() + WORK.load(Relaxed);
        while time::now() < until {
            black_box(0);
        }
        if time::now() >= END.load(Relaxed) {
            break;
        }
    }
    sys::thread_exit()
}

/// Sleeps until `ns` on the scale of the clock: a timer of the calling
/// thread's own channel.
fn sleep_until(channel: &Handle<Channel>, timer: &Handle<rt::handle::Timer>, ns: u64) {
    sys::timer_set(timer, ns).expect("arm a timer");
    match sys::receive(channel).expect("wait for a timer") {
        sys::Received::Notification { .. } => {}
        _ => panic!("a timer's wait ends in something else"),
    }
}

fn now_ns() -> u64 {
    time::ticks_to_ns(time::now())
}

fn begin(phase_ms: u64) {
    for who in &SPENT {
        for b in who {
            b.store(0, Relaxed);
        }
    }
    GAP[0].store(0, Relaxed);
    GAP[1].store(0, Relaxed);
    BUCKET.store(time::ns_to_ticks(MS), Relaxed);
    let now = time::now();
    START.store(now, Relaxed);
    END.store(now + time::ns_to_ticks(phase_ms * MS), Relaxed);
}

/// The most and the least of `who` over the windows of `l` buckets, in ns:
/// (least, most).
fn windows(who: usize, l: usize, buckets: usize) -> (u64, u64) {
    let (mut least, mut most) = (u64::MAX, 0);
    // The first 2 buckets are the start of the threads.
    for first in 2..buckets.saturating_sub(l + 1) {
        let sum: u64 = SPENT[who][first..first + l]
            .iter()
            .map(|b| b.load(Relaxed))
            .sum();
        let ns = time::ticks_to_ns(sum);
        least = least.min(ns);
        most = most.max(ns);
    }
    (least, most)
}

/// The hog and the victim on CPU `cpu`; `tag` names the lines. False when
/// there is no such CPU.
fn phase_hog(process: &Handle<Process>, resource: &Handle<Resource>, cpu: u8, tag: &str) -> bool {
    let Ok(budget) = sys::budget_create(resource, cpu.into(), 300_000, 1_000_000, 1) else {
        return false;
    };
    begin(PHASE_MS);
    let victim = spawn_on(process, 0, victim, 10, cpu);
    let hog = spawn_on(process, 1, hog, 50, cpu);
    sys::thread_bind_budget(&hog, &budget).expect("bind the hog's budget");
    sys::thread_start(&victim).expect("start the victim");
    sys::thread_start(&hog).expect("start the hog");
    let channel = sys::channel_create_wait(62).expect("channel");
    let timer = sys::timer_create(&channel, 62).expect("timer");
    sleep_until(&channel, &timer, now_ns() + (PHASE_MS + 5) * MS);
    let info = sys::budget_info(&budget).expect("budget info");
    let buckets = PHASE_MS as usize;
    for l in [1, 5, 10] {
        let (least, _) = windows(VICTIM, l, buckets);
        let (_, most) = windows(HOG, l, buckets);
        let (hog_least, _) = windows(HOG, l, buckets);
        println!(
            "budget{} window={} min_share={} max_hog={} hog_min={} overruns={}",
            tag,
            l,
            least * 1000 / (l as u64 * MS),
            most / 1000,
            hog_least / 1000,
            info.overruns
        );
    }
    println!(
        "budget{} gaps victim_us={} hog_us={}",
        tag,
        time::ticks_to_ns(GAP[VICTIM].load(Relaxed)) / 1000,
        time::ticks_to_ns(GAP[HOG].load(Relaxed)) / 1000
    );
    true
}

fn phase_boost(process: &Handle<Process>, resource: &Handle<Resource>) {
    begin(PHASE_MS / 2);
    let channel = sys::channel_create(20).expect("service channel");
    CHANNEL.store(channel.raw().0, Relaxed);
    WORK.store(time::ns_to_ticks(500_000), Relaxed);
    let budget = sys::budget_create(resource, 0, 200_000, 1_000_000, 1).expect("service budget");
    let spinner = spawn(process, 0, victim, 10);
    let server = spawn(process, 1, service, 20);
    sys::thread_bind_budget(&server, &budget).expect("bind the service's budget");
    sys::thread_start(&spinner).expect("start the victim");
    sys::thread_start(&server).expect("start the service");
    // The client at 40 asks every 2 ms; its own thread runs the requests.
    let client = spawn(process, 2, client_entry, 40);
    sys::thread_start(&client).expect("start the client");
    let wait = sys::channel_create_wait(62).expect("channel");
    let timer = sys::timer_create(&wait, 62).expect("timer");
    sleep_until(&wait, &timer, now_ns() + (PHASE_MS / 2 + 5) * MS);
    let n = ROUND_N.load(Relaxed);
    println!(
        "budget boost n={} max_round_trip_us={}",
        n,
        time::ticks_to_ns(ROUND_MAX.load(Relaxed)) / 1000
    );
    drop(channel);
}

static ROUND_MAX: AtomicU64 = AtomicU64::new(0);
static ROUND_N: AtomicU64 = AtomicU64::new(0);

extern "C" fn client_entry(_: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    let wait = sys::channel_create_wait(40).expect("client channel");
    let timer = sys::timer_create(&wait, 40).expect("client timer");
    ROUND_MAX.store(0, Relaxed);
    ROUND_N.store(0, Relaxed);
    let mut next = now_ns() + 2 * MS;
    while time::now() < END.load(Relaxed) {
        sleep_until(&wait, &timer, next);
        let began = time::now();
        sys::send(&channel, b"work").expect("request");
        let took = time::now() - began;
        ROUND_MAX.fetch_max(took, Relaxed);
        ROUND_N.fetch_add(1, Relaxed);
        next += 2 * MS;
    }
    sys::send(&channel, b"stop").expect("stop the service");
    sys::thread_exit()
}

/// The requests of the loan phase: a client at 40 with a budget calls a
/// service whose budget is gone as fast as it can until `END`; each request
/// is work of the service that the client pays for.
extern "C" fn loan_client(_: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    ROUND_N.store(0, Relaxed);
    while time::now() < END.load(Relaxed) {
        sys::send(&channel, b"work").expect("request");
        ROUND_N.fetch_add(1, Relaxed);
    }
    sys::send(&channel, b"stop").expect("stop the service");
    sys::thread_exit()
}

/// The loan: a client at 40 with the budget of 600 us for each 2 ms calls a
/// service at 20 on CPU `server_cpu` whose budget of 100 us for 1 s is gone
/// with its first request; every request is 500 us of the service's work, at
/// the client's level. The work is the client's time: its budget runs out
/// (`overruns`), and the client makes about 1.2 requests for each period at
/// most. A victim at 10 shares the client's CPU: on that CPU it also holds
/// the exhausted service, at level 1, away from its next `receive`, so the
/// client's third request waits for the end of the phase. False when there
/// is no such CPU.
fn phase_loan(
    process: &Handle<Process>,
    resource: &Handle<Resource>,
    server_cpu: u8,
    tag: &str,
) -> bool {
    let Ok(service_budget) =
        sys::budget_create(resource, server_cpu.into(), 100_000, 1_000_000_000, 1)
    else {
        return false;
    };
    let client_budget =
        sys::budget_create(resource, 0, 600_000, 2_000_000, 1).expect("client budget");
    begin(PHASE_MS / 2);
    let channel = sys::channel_create(20).expect("service channel");
    CHANNEL.store(channel.raw().0, Relaxed);
    WORK.store(time::ns_to_ticks(500_000), Relaxed);
    let spinner = spawn(process, 0, victim, 10);
    let server = spawn_on(process, 1, service, 20, server_cpu);
    sys::thread_bind_budget(&server, &service_budget).expect("bind the service's budget");
    sys::thread_start(&spinner).expect("start the victim");
    sys::thread_start(&server).expect("start the service");
    let client = spawn(process, 2, loan_client, 40);
    sys::thread_bind_budget(&client, &client_budget).expect("bind the client's budget");
    sys::thread_start(&client).expect("start the client");
    let wait = sys::channel_create_wait(62).expect("channel");
    let timer = sys::timer_create(&wait, 62).expect("timer");
    sleep_until(&wait, &timer, now_ns() + (PHASE_MS / 2 + 10) * MS);
    let info = sys::budget_info(&client_budget).expect("budget info");
    println!(
        "budget loan {} requests={} overruns={}",
        tag,
        ROUND_N.load(Relaxed),
        info.overruns
    );
    true
}

/// The longest wait of a request of the queue phase's client at 40 for the
/// service to take it, ticks.
static QUEUE_MAX: AtomicU64 = AtomicU64::new(0);

/// The service of the queue phase: as `service`, and a request of 8 bytes,
/// the counter at which the client at 40 sent it, gives the wait until this
/// receive (QUEUE_MAX). The time is the service's own, so the wake of a
/// client's CPU that sleeps (QEMU's turn under -icount) is not in it.
extern "C" fn queue_service(_: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    let mut next = sys::receive(&channel).expect("receive a request");
    while let sys::Received::Message {
        token, words, len, ..
    } = next
    {
        if len == 8 {
            QUEUE_MAX.fetch_max(time::now().saturating_sub(words[0]), Relaxed);
        } else if words[0].to_le_bytes()[0] == b's' {
            token.reply(b"ok").expect("reply");
            break;
        }
        let until = time::now() + WORK.load(Relaxed);
        while time::now() < until {
            black_box(0);
        }
        next = token
            .reply_receive(&channel, b"ok")
            .expect("reply and receive");
    }
    sys::thread_exit()
}

/// The client at 5 of the queue phase: requests until the end, each of the
/// service's 500 us; one of them is in hand when the other client's request
/// queues. The phase ends it by closing the channel.
extern "C" fn queue_low(_: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    while time::now() < END.load(Relaxed) {
        if sys::send(&channel, b"work").is_err() {
            break;
        }
    }
    sys::thread_exit()
}

/// The client at 40 of the queue phase: a request every 4 ms from 5 ms on,
/// which carries the counter of its send. It stops the service at the end.
extern "C" fn queue_high(_: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    let wait = sys::channel_create_wait(40).expect("client channel");
    let timer = sys::timer_create(&wait, 40).expect("client timer");
    QUEUE_MAX.store(0, Relaxed);
    ROUND_N.store(0, Relaxed);
    let mut next = now_ns() + 5 * MS;
    while time::now() < END.load(Relaxed) {
        sleep_until(&wait, &timer, next);
        sys::send(&channel, &time::now().to_le_bytes()).expect("request");
        ROUND_N.fetch_add(1, Relaxed);
        next += 4 * MS;
    }
    sys::send(&channel, b"stop").expect("stop the service");
    sys::thread_exit()
}

/// The queue: a service at 20 on CPU `server_cpu` whose budget of 100 us
/// for 1 s is gone with its first request works 500 us for each request.
/// The client at 5 has a request in it, which a spinner at 10 on the
/// service's CPU would keep from running; the client at 40, on CPU 0, sends
/// one every 4 ms. The first of these queues behind the request in hand,
/// which lifts the service to 40: it waits for the rest of that request,
/// 500 us at most, and the kernel's longest stretch. The line says the
/// longest wait of a request of the client at 40 for the service to take
/// it. False when there is no such CPU.
fn phase_queue(
    process: &Handle<Process>,
    resource: &Handle<Resource>,
    server_cpu: u8,
    tag: &str,
) -> bool {
    let Ok(service_budget) =
        sys::budget_create(resource, server_cpu.into(), 100_000, 1_000_000_000, 1)
    else {
        return false;
    };
    begin(PHASE_MS / 2);
    let channel = sys::channel_create(20).expect("service channel");
    CHANNEL.store(channel.raw().0, Relaxed);
    WORK.store(time::ns_to_ticks(500_000), Relaxed);
    let server = spawn_on(process, 1, queue_service, 20, server_cpu);
    sys::thread_bind_budget(&server, &service_budget).expect("bind the service's budget");
    sys::thread_start(&server).expect("start the service");
    let low = spawn(process, 2, queue_low, 5);
    sys::thread_start(&low).expect("start the client at 5");
    // The service takes the first request before the spinner starts.
    let wait = sys::channel_create_wait(62).expect("channel");
    let timer = sys::timer_create(&wait, 62).expect("timer");
    sleep_until(&wait, &timer, now_ns() + MS);
    let spinner = spawn_on(process, 0, victim, 10, server_cpu);
    sys::thread_start(&spinner).expect("start the spinner");
    let high = spawn(process, 3, queue_high, 40);
    sys::thread_start(&high).expect("start the client at 40");
    sleep_until(&wait, &timer, now_ns() + (PHASE_MS / 2 + 10) * MS);
    println!(
        "budget queue {} requests={} wait_us={}",
        tag,
        ROUND_N.load(Relaxed),
        time::ticks_to_ns(QUEUE_MAX.load(Relaxed)) / 1000
    );
    drop(channel);
    true
}

fn phase_slot(process: &Handle<Process>, resource: &Handle<Resource>) {
    begin(PHASE_MS);
    let channel = sys::channel_create(55).expect("worker channel");
    CHANNEL.store(channel.raw().0, Relaxed);
    WORK.store(time::ns_to_ticks(800_000), Relaxed);
    let budget = sys::budget_create(resource, 0, 200_000, 1_000_000, 1).expect("worker budget");
    let spinner = spawn(process, 0, victim, 10);
    let work = spawn(process, 1, worker, 5);
    sys::thread_bind_budget(&work, &budget).expect("bind the worker's budget");
    sys::thread_start(&work).expect("start the worker");
    let wait = sys::channel_create_wait(62).expect("channel");
    let timer = sys::timer_create(&wait, 62).expect("timer");
    // The worker, at 5, waits for its first notification before the victim,
    // at 10, takes the CPU.
    sleep_until(&wait, &timer, now_ns() + MS);
    sys::thread_start(&spinner).expect("start the victim");
    let mut next = now_ns() + 2 * MS;
    while time::now() < END.load(Relaxed) {
        sleep_until(&wait, &timer, next);
        sys::notify(&channel, 1).expect("notify the worker");
        next += 2 * MS;
    }
    sys::notify(&channel, 1).expect("last notification");
    sleep_until(&wait, &timer, now_ns() + 5 * MS);
    let (least, _) = windows(VICTIM, 10, PHASE_MS as usize);
    let info = sys::budget_info(&budget).expect("budget info");
    println!(
        "budget slot min_share={} max_gap_us={} worker_us={} overruns={}",
        least * 1000 / (10 * MS),
        time::ticks_to_ns(GAP[VICTIM].load(Relaxed)) / 1000,
        time::ticks_to_ns(info.ran) / 1000,
        info.overruns
    );
}

fn main(_: u64) -> u64 {
    let init = rt::init_handles().expect("init's handles");
    // The console takes the handle it prints through; the budgets need a
    // copy with the right to make them (BUDGET: init's handle alone has it).
    let resource = sys::handle_duplicate(&init.resource, abi::INIT_RESOURCE_RIGHTS)
        .expect("a copy of the resource");
    rt::console::set(init.resource);
    let (process, me) = (init.process, init.thread);
    sys::thread_set_priority(&me, 62, Policy::Fifo).expect("set the priority");
    println!("budget START hz={}", time::frequency());
    phase_hog(&process, &resource, 0, "");
    // On another CPU, when there is one: its own heap of timers and its own
    // scheduler hold the hog's budget.
    if phase_hog(&process, &resource, 1, " cpu1") {
        println!("budget cpu1 ran");
    }
    phase_boost(&process, &resource);
    phase_loan(&process, &resource, 0, "same");
    if phase_loan(&process, &resource, 1, "other") {
        println!("budget loan ran");
    }
    phase_queue(&process, &resource, 0, "same");
    if phase_queue(&process, &resource, 1, "other") {
        println!("budget queue ran");
    }
    phase_slot(&process, &resource);
    println!("budget DONE");
    loop {
        sys::yield_now().expect("wait for the host");
    }
}
