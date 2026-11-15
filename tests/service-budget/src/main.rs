// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the time budgets of the services (spec 8; `cargo xtask service-budget`), for
//! QEMU under -icount with two CPUs, where the numbers of one build repeat to the tick. The
//! RAM file, pipe and terminal services run as init starts them, with their budgets, on CPU 0.
//! Each service has two phases of 200 ms, with a greedy client at 20 on CPU 1 that asks it
//! without a pause (the RAM service a path of eight names, 488 bytes, to look up; the others a
//! request their loop refuses for its header). The client sits on another CPU, so the service
//! works for it at its own level on CPU 0, above whatever stands there:
//!
//! - `share`: a victim at 25 on CPU 0 spins and notes the time it runs in buckets of 1 ms. The
//!   service without its budget works at its `free` level 31, above the victim, and starves it;
//!   with its budget it works at its own level for C of each T and at the client's level, 20,
//!   below the victim, for the rest. The line gives, for windows of 1, 5 and 10 ms, the least
//!   share (per mille) the victim got;
//! - `ping`: a spinner at 10 on CPU 0 keeps an exhausted service from running below it, and
//!   the probe's own thread at 40 asks the service every 2 ms; the line gives the longest round
//!   trip of its request.
//!
//! An `idle` phase before them has the victim alone: the time it loses to the machine itself.

#![no_std]
#![no_main]

use abi::Policy;
use core::hint::black_box;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use proto_wire::{Header, Reader, Writer};
use rt::handle::{Channel, Process, Thread, Timer};
use rt::{Handle, Stack, println, sys, time};

rt::entry!(main);

const MS: u64 = 1_000_000;
const PAGE: usize = 4096;
/// The buckets of 1 ms the time of the victim is noted in.
const BUCKETS: usize = 256;
const PHASE_MS: u64 = 200;
/// A gap between two looks at the counter longer than this is time the thread did not run.
const GAP_NS: u64 = 20_000;

/// The names of the services, in the order of the phases.
const SERVICES: [&str; 3] = ["ramfs", "pipe", "tty"];

/// What a request to the service `name` is (`ask`): 0 a lookup of a path, 1 and 2 a header the
/// loop of the pipe service and the terminal service refuse.
fn kind_of(name: &str) -> u64 {
    match name {
        "ramfs" => 0,
        "pipe" => 1,
        _ => 2,
    }
}

/// The path the RAM service looks up for the greedy client: eight names of 60 bytes, 488
/// bytes in all, which the image carries (xtask rootfs `service_budget`).
const NAME: [u8; 60] = *b"nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";
const DEPTH: usize = 8;

/// The threads of a phase: the victim, the control server and the greedy clients, each on a
/// stack of its own.
static STACKS: [Stack<8192>; 2 + GREEDIES] = [const { Stack::new() }; 2 + GREEDIES];
/// The greedy clients of a phase, on CPU 1: more than one, so that the service has a request
/// waiting when it ends one, whatever the wake of a client on the other CPU takes.
const GREEDIES: usize = 24;
static START: AtomicU64 = AtomicU64::new(0);
static END: AtomicU64 = AtomicU64::new(0);
static SPENT: [AtomicU64; BUCKETS] = [const { AtomicU64::new(0) }; BUCKETS];
/// The longest gap the victim saw, in ticks.
static GAP: AtomicU64 = AtomicU64::new(0);
/// The phase's service (index in SERVICES) and the sessions the clients ask it through.
static WHICH: AtomicU64 = AtomicU64::new(0);
static GREEDY_SESSIONS: [AtomicU64; GREEDIES] = [const { AtomicU64::new(0) }; GREEDIES];
static STOP: AtomicBool = AtomicBool::new(false);
static GREEDY_N: AtomicU64 = AtomicU64::new(0);
static GREEDY_FAILED: AtomicU64 = AtomicU64::new(0);
/// The greedy clients that ended.
static ENDED: AtomicU64 = AtomicU64::new(0);
/// The status of the last RAM request that failed, for the line of the phase.
static LAST_STATUS: AtomicU64 = AtomicU64::new(0);

fn path(depth: usize, out: &mut [u8; 512]) -> usize {
    let mut len = 0;
    for _ in 0..depth {
        out[len] = b'/';
        out[len + 1..len + 1 + NAME.len()].copy_from_slice(&NAME);
        len += 1 + NAME.len();
    }
    len
}

fn spawn_on(
    process: &Handle<Process>,
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    arg: u64,
    priority: u8,
    cpu: u8,
) -> Handle<Thread> {
    // SAFETY: each thread gets its own stack and message buffer page; a phase waits for its
    // threads to end before the next reuses them.
    unsafe {
        sys::thread_create_on(
            process,
            entry,
            STACKS[slot].top(),
            arg,
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

/// One request of the greedy client or of the client at 40 to the phase's service through
/// `session`: for the RAM service a lookup of a path of `depth` names, for the others a
/// request their loop refuses for its header (UNKNOWN_METHOD, without a session).
fn ask(which: u64, session: &Handle<Channel>, depth: usize) -> bool {
    match which {
        0 => {
            let files = rt::fs::Files::from_sessions(Handle::from_raw(session.raw()), None);
            let mut bytes = [0; 512];
            let len = path(depth, &mut bytes);
            let result = files.lookup_bytes(&bytes[..len]);
            // The session is the probe's: the `Files` that borrowed it lets it be.
            core::mem::forget(files);
            if let Err(status) = &result {
                LAST_STATUS.store(u64::from(status.code()), Relaxed);
            }
            result.is_ok()
        }
        1 => sys::send(session, &Header::new(0x7ff0, proto_pipe::VERSION).bytes()).is_ok(),
        2 => sys::send(session, &Header::new(0x7ff0, proto_tty::VERSION).bytes()).is_ok(),
        _ => sys::send(session, b"ask").is_ok(),
    }
}

/// The ends of the pipe each greedy client of the pipe phase made: (read end << 32 | write end) + 1,
/// 0 before it made one.
static PIPE_ENDS: [AtomicU64; GREEDIES] = [const { AtomicU64::new(0) }; GREEDIES];

/// The dearest request of the pipe and terminal services, for the greedy client `index`: the pipe
/// service takes a write of 1000 bytes into the pipe of the client and gives them back in a read
/// of 1000 (two requests in turn, each moving 1000 bytes through the ring); the terminal service
/// takes a write of 1000 bytes (MAX_WRITE) of the console, which its driver takes in parts. The
/// RAM service's dearest is the lookup of the path of eight names.
fn heavy(which: u64, session: &Handle<Channel>, index: usize, odd: bool) -> bool {
    let bytes = [b'x'; 1000];
    let mut w = Writer::new();
    let mut buffer = [0; abi::MESSAGE_MAX];
    match which {
        1 => {
            let ends = PIPE_ENDS[index].load(Relaxed);
            if ends == 0 {
                let ok = Header::new(proto_pipe::Method::Create as u16, proto_pipe::VERSION)
                    .write(&mut w)
                    .and_then(|()| w.u32(0))
                    .is_ok();
                let Ok(reply) = sys::send(session, w.as_bytes()) else {
                    return false;
                };
                let mut r = Reader::new(reply.bytes(&mut buffer));
                let (Ok(0), Ok(read), Ok(write), true) = (r.u32(), r.u32(), r.u32(), ok) else {
                    LAST_STATUS.store(1, Relaxed);
                    return false;
                };
                PIPE_ENDS[index].store((u64::from(read) << 32 | u64::from(write)) + 1, Relaxed);
                return true;
            }
            let (read, write) = (((ends - 1) >> 32) as u32, (ends - 1) as u32);
            let made = if odd {
                proto_pipe::Read {
                    key: None,
                    end: read,
                    count: 1000,
                }
                .write(&mut w)
            } else {
                proto_pipe::Write {
                    key: None,
                    end: write,
                    bytes: &bytes,
                }
                .write(&mut w)
            };
            made.is_ok() && sys::send(session, w.as_bytes()).is_ok()
        }
        _ => {
            let made = proto_tty::Write {
                key: None,
                terminal: proto_tty::CONSOLE,
                blocked: 0,
                bytes: &bytes,
            }
            .write(&mut w);
            made.is_ok() && sys::send(session, w.as_bytes()).is_ok()
        }
    }
}

/// Spins until `END`, noting in the buckets the ticks it ran: the gaps between two looks that
/// are no longer than GAP_NS; a longer one goes to the longest gap.
extern "C" fn victim(_: u64) -> ! {
    let start = START.load(Relaxed);
    let end = END.load(Relaxed);
    let bucket = time::ns_to_ticks(MS);
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
            GAP.fetch_max(gap, Relaxed);
        } else {
            let b = (now.saturating_sub(start) / bucket) as usize;
            if b < BUCKETS {
                SPENT[b].fetch_add(gap, Relaxed);
            }
        }
        if now >= end {
            sys::thread_exit()
        }
    }
}

/// The greedy client number `index`: asks (the dearest request of the service, `heavy`) the phase's service through its session until STOP.
extern "C" fn greedy(index: u64) -> ! {
    let which = WHICH.load(Relaxed);
    let session =
        Handle::<Channel>::borrowed(abi::Handle(GREEDY_SESSIONS[index as usize].load(Relaxed)));
    let mut odd = true;
    while !STOP.load(Relaxed) {
        let done = if which == 0 || which > 2 {
            ask(which, &session, DEPTH)
        } else {
            heavy(which, &session, index as usize, odd)
        };
        odd = !odd;
        if done {
            GREEDY_N.fetch_add(1, Relaxed);
        } else {
            GREEDY_FAILED.fetch_add(1, Relaxed);
        }
    }
    ENDED.fetch_add(1, Relaxed);
    sys::thread_exit()
}

fn sleep_until(channel: &Handle<Channel>, timer: &Handle<Timer>, ns: u64) {
    sys::timer_set(timer, ns).expect("arm a timer");
    match sys::receive(channel).expect("wait for a timer") {
        sys::Received::Notification { .. } => {}
        _ => panic!("a timer's wait ends in something else"),
    }
}

fn now_ns() -> u64 {
    time::ticks_to_ns(time::now())
}

/// The least and the median of the time of the victim over the windows of `l` buckets, in ns.
/// The first two buckets are the start of the threads. The two CPUs of QEMU under -icount stall
/// now and then for some milliseconds a thread that runs on one of them while the other runs, which
/// shows as a window with no victim in it; the median is the share the victim keeps window after
/// window, which a budget that is not bound takes to nothing.
fn windows(l: usize) -> (u64, u64) {
    let mut sums = [0u64; BUCKETS];
    let mut count = 0;
    for first in 2..(PHASE_MS as usize).saturating_sub(l + 1) {
        let sum: u64 = SPENT[first..first + l]
            .iter()
            .map(|b| b.load(Relaxed))
            .sum();
        // Insertion into the sorted prefix.
        let mut at = count;
        while at > 0 && sums[at - 1] > sum {
            sums[at] = sums[at - 1];
            at -= 1;
        }
        sums[at] = sum;
        count += 1;
    }
    if count == 0 {
        return (0, 0);
    }
    (
        time::ticks_to_ns(sums[0]),
        time::ticks_to_ns(sums[count / 2]),
    )
}

/// The line of the shares of a phase: for each window the least and the median share, per mille.
fn print_windows(name: &str) {
    for l in [1u64, 5, 10] {
        let (least, median) = windows(l as usize);
        println!(
            "svcbudget {name} window={l} min_share={} median_share={}",
            least * 1000 / (l * MS),
            median * 1000 / (l * MS)
        );
    }
}

/// The phase with no client: the victim alone, so that the time it loses to what the machine
/// does besides (the interrupts of the timer, the heartbeats of the services, the entries of
/// the probe's own thread) is told apart.
fn idle(process: &Handle<Process>, wait: &Handle<Channel>, timer: &Handle<Timer>) {
    reset();
    let victim = spawn_on(process, 0, victim, 0, 25, 0);
    sys::thread_start(&victim).expect("start the victim");
    sleep_until(wait, timer, now_ns() + (PHASE_MS + 5) * MS);
    print_windows("idle");
}

/// What the server of the `replies` phase found: bit 0 the reply of MESSAGE_MAX bytes with a
/// handle went with the next receive, bit 1 a reply of MESSAGE_MAX + 1 bytes was refused with
/// INVALID_ARGS.
static REPLY_RESULT: AtomicU64 = AtomicU64::new(0);

/// The server of the `replies` phase: a reply of the most bytes a message holds, with a handle,
/// goes through `reply_receive_handles`; the next request is answered with one byte too many,
/// which the call refuses before it enters the kernel.
extern "C" fn reply_server(channel: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(channel));
    let Ok(sys::Received::Message { token, .. }) = sys::receive(&channel) else {
        sys::thread_exit()
    };
    let Ok(own) = sys::channel_create(5) else {
        sys::thread_exit()
    };
    let big = [7u8; abi::MESSAGE_MAX];
    let mut handles = rt::handle::Outgoing::new();
    let _ = handles.push(own.erase());
    let next = token.reply_receive_handles(&channel, &big, handles);
    if let Ok(sys::Received::Message { token, .. }) = next {
        REPLY_RESULT.fetch_or(1, Relaxed);
        let over = [7u8; abi::MESSAGE_MAX + 1];
        if token.reply_receive_handles(&channel, &over, rt::handle::Outgoing::new())
            == Err(abi::Error::InvalidArgs)
        {
            REPLY_RESULT.fetch_or(2, Relaxed);
        }
    }
    sys::thread_exit()
}

/// The second request of the `replies` phase, from a thread of its own: the server refuses its
/// reply, so the request waits until the probe closes the channel.
extern "C" fn second_client(channel: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(channel));
    let _ = sys::send(&channel, b"two");
    sys::thread_exit()
}

/// The `replies` phase: the reply of MESSAGE_MAX bytes with a handle reaches the client whole
/// (its second request is the one the server answers wrong), and the over-long reply is refused.
fn replies(process: &Handle<Process>, wait: &Handle<Channel>, timer: &Handle<Timer>) {
    let channel = sys::channel_create(5).expect("channel of the reply server");
    // SAFETY: the server gets its own stack and message buffer page (slot 1) and the channel,
    // which stays open until the phase ends.
    let server = unsafe {
        sys::thread_create_on(
            process,
            reply_server,
            STACKS[1].top(),
            channel.raw().0,
            35,
            Policy::Fifo,
            abi::INIT_MSGBUF as usize + 2 * PAGE,
            None,
            1,
        )
    }
    .expect("create the reply server");
    sys::thread_start(&server).expect("start the reply server");
    let first = sys::send(&channel, b"one");
    let whole = first.as_ref().is_ok_and(|r| {
        let mut buffer = [0; abi::MESSAGE_MAX];
        r.len == abi::MESSAGE_MAX
            && r.bytes(&mut buffer).iter().all(|b| *b == 7)
            && r.handles.len() == 1
    });
    let second = spawn_on(process, 0, second_client, channel.raw().0, 35, 0);
    sys::thread_start(&second).expect("start the second client");
    sleep_until(wait, timer, now_ns() + 5 * MS);
    // The request the server refused to answer ends with the channel.
    drop(channel);
    sleep_until(wait, timer, now_ns() + 5 * MS);
    println!(
        "svcbudget replies whole_with_handle={} server_saw={}",
        u8::from(whole),
        REPLY_RESULT.load(Relaxed)
    );
}

/// The local server of the control phase, at 5 on CPU 0: answers each request at once. It ends
/// when the probe closes the channel.
extern "C" fn local_server(channel: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(channel));
    let mut next = sys::receive(&channel);
    while let Ok(sys::Received::Message { token, .. }) = next {
        next = token.reply_receive(&channel, b"ok");
    }
    sys::thread_exit()
}

/// The queued greedy clients, stopped, on CPU 1 at 20. A spinner on CPU 1 that keeps it from
/// halting makes QEMU under -icount stall CPU 0 (the victim of the control phase then keeps
/// 649 per mille in 10 ms), so there is none; 24 clients keep a request queued instead.
fn spawn_greedies(process: &Handle<Process>) -> [Handle<Thread>; GREEDIES] {
    core::array::from_fn(|i| spawn_on(process, 2 + i, greedy, i as u64, 20, 1))
}

fn start_all(threads: &[Handle<Thread>]) {
    for t in threads {
        sys::thread_start(t).expect("start a greedy client");
    }
}

/// Waits for the greedy clients to end after STOP, 500 ms at most.
fn wait_ended(wait: &Handle<Channel>, timer: &Handle<Timer>) {
    for _ in 0..100 {
        sleep_until(wait, timer, now_ns() + 5 * MS);
        if ENDED.load(Relaxed) == GREEDIES as u64 {
            return;
        }
    }
    println!("svcbudget a greedy client did not end");
}

/// The control phase: the greedy client on CPU 1 asks a server of the probe at 5 on CPU 0, which
/// has no budget and answers at the client's level (20), below the victim. What the victim
/// loses here is what the greedy client costs it on its own (the interrupts, the rest of the
/// machine's work across the two CPUs, which the 2-CPU machine under -icount makes), and the
/// services' phases lose that and their budgets.
fn control(process: &Handle<Process>, wait: &Handle<Channel>, timer: &Handle<Timer>) {
    reset();
    let channel = sys::channel_create(5).expect("the control server's channel");
    WHICH.store(3, Relaxed);
    for session in &GREEDY_SESSIONS {
        session.store(channel.raw().0, Relaxed);
    }
    // SAFETY: the server gets its own stack and message buffer page (slot 1) and the channel,
    // which stays open until the phase ends.
    let server = unsafe {
        sys::thread_create_on(
            process,
            local_server,
            STACKS[1].top(),
            channel.raw().0,
            5,
            Policy::Fifo,
            abi::INIT_MSGBUF as usize + 2 * PAGE,
            None,
            1,
        )
    }
    .expect("create the control server");
    let victim = spawn_on(process, 0, victim, 0, 25, 0);
    let greedies = spawn_greedies(process);
    sys::thread_start(&server).expect("start the control server");
    sys::thread_start(&victim).expect("start the victim");
    start_all(&greedies);
    sleep_until(wait, timer, now_ns() + PHASE_MS * MS);
    STOP.store(true, Relaxed);
    wait_ended(wait, timer);
    print_windows("control");
    println!("svcbudget control share greedy={}", GREEDY_N.load(Relaxed));
    drop(channel);
}

/// The start of a phase: the buckets and the counters at zero, the time of its end.
fn reset() {
    for b in &SPENT {
        b.store(0, Relaxed);
    }
    GAP.store(0, Relaxed);
    GREEDY_N.store(0, Relaxed);
    GREEDY_FAILED.store(0, Relaxed);
    ENDED.store(0, Relaxed);
    STOP.store(false, Relaxed);
    let now = time::now();
    START.store(now, Relaxed);
    END.store(now + time::ns_to_ticks(PHASE_MS * MS), Relaxed);
}

/// A phase against `SERVICES[which]`: the greedy client asks it through a session of its own.
/// With `ping` false a victim at 25 spins and the lines give its shares; with `ping` true a
/// spinner at 10 does, and the probe's thread at 40 asks the service every 2 ms through its own
/// session and notes the longest round trip.
fn phase(
    process: &Handle<Process>,
    parent: &Handle<Channel>,
    which: usize,
    ping: bool,
    wait: &Handle<Channel>,
    timer: &Handle<Timer>,
) {
    let name = SERVICES[which];
    let sessions: [Option<Handle<Channel>>; GREEDIES + 1] =
        core::array::from_fn(|_| rt::service::connect(parent, name).ok());
    if sessions.iter().any(Option::is_none) {
        println!("svcbudget {name} FAILED no session");
        return;
    }
    reset();
    WHICH.store(kind_of(name), Relaxed);
    for (slot, session) in GREEDY_SESSIONS.iter().zip(&sessions) {
        slot.store(session.as_ref().map_or(0, |s| s.raw().0), Relaxed);
    }
    let ping_session = sessions[GREEDIES]
        .as_ref()
        .expect("the session of the client at 40");
    let spinner = spawn_on(process, 0, victim, 0, if ping { 10 } else { 25 }, 0);
    let greedies = spawn_greedies(process);
    sys::thread_start(&spinner).expect("start the victim");
    start_all(&greedies);
    let (mut n, mut max, mut failed) = (0u64, 0u64, 0u64);
    let (mut over, mut worst_at) = (0u64, 0u64);
    let mut sum = 0u64;
    if ping {
        // The client at 40 asks every 2 ms, from 20 ms on: the greedy client starts on CPU 1
        // meanwhile, and its start is not the service's.
        let mut next = now_ns() + 20 * MS;
        while time::now() < END.load(Relaxed) {
            sleep_until(wait, timer, next);
            let began = time::now();
            let ok = ask(kind_of(name), ping_session, 1);
            let took = time::now() - began;
            if ok {
                n += 1;
                sum += took;
                if took > time::ns_to_ticks(750_000) {
                    over += 1;
                }
                if took > max {
                    max = took;
                    worst_at = time::ticks_to_ns(began.saturating_sub(START.load(Relaxed))) / MS;
                }
            } else {
                failed += 1;
            }
            next += 2 * MS;
        }
    } else {
        sleep_until(wait, timer, now_ns() + PHASE_MS * MS);
    }
    STOP.store(true, Relaxed);
    // The greedy clients end after the request in hand; the victim ended at END.
    wait_ended(wait, timer);
    if ping {
        println!(
            "svcbudget {name} ping n={n} failed={failed} max_us={} over_750us={over} mean_us={} worst_at_ms={worst_at} greedy={} greedy_failed={} status={}",
            time::ticks_to_ns(max) / 1000,
            time::ticks_to_ns(sum) / 1000 / n.max(1),
            GREEDY_N.load(Relaxed),
            GREEDY_FAILED.load(Relaxed),
            LAST_STATUS.load(Relaxed)
        );
    } else {
        print_windows(name);
        println!(
            "svcbudget {name} share greedy={} greedy_failed={} gap_us={} status={}",
            GREEDY_N.load(Relaxed),
            GREEDY_FAILED.load(Relaxed),
            time::ticks_to_ns(GAP.load(Relaxed)) / 1000,
            LAST_STATUS.load(Relaxed)
        );
    }
}

fn main(_: u64) -> u64 {
    let Ok(start) = rt::startup() else {
        return 1;
    };
    let mut start = start;
    if let Ok(console) = start.take::<rt::handle::Resource>("console") {
        rt::console::set(console);
    }
    println!("svcbudget START hz={}", time::frequency());
    let ping_wait = sys::channel_create_wait(40).expect("channel");
    let ping_timer = sys::timer_create(&ping_wait, 40).expect("timer");
    // The services register before they finish their start (the tables of the RAM service, the
    // process service they wait for), and work unbudgeted until they bind the budget of their
    // loop: a request answered is a service in its loop, under its budget. The probe waits for
    // each, and 100 ms more for what the services do once they are ready.
    for name in SERVICES {
        let session = rt::service::connect(&start.parent, name).expect("a session");
        if !ask(kind_of(name), &session, 1) {
            println!("svcbudget {name} FAILED the first request");
            return 3;
        }
    }
    sleep_until(&ping_wait, &ping_timer, now_ns() + 100 * MS);
    replies(&start.process, &ping_wait, &ping_timer);
    idle(&start.process, &ping_wait, &ping_timer);
    control(&start.process, &ping_wait, &ping_timer);
    for which in 0..SERVICES.len() {
        for ping in [false, true] {
            phase(
                &start.process,
                &start.parent,
                which,
                ping,
                &ping_wait,
                &ping_timer,
            );
        }
    }
    println!("svcbudget DONE");
    0
}
