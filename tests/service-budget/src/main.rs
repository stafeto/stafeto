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
//! - `share`: a victim at 34 on CPU 0 spins and notes the time it runs in buckets of 1 ms. The
//!   service works at its own level for C of each T and, with its budget spent, at its demoted
//!   level 32, below the victim, for the rest: the guarantee of the budgets is that it takes at
//!   most C of each T from the levels 33 and above, and for the levels at or below 32 it is a
//!   service without a budget (a victim at 25 would be starved by the demoted service, which is
//!   no breach). The line gives, for windows of 1, 5 and 10 ms, the least share (per mille) the
//!   victim got;
//! - `ping`: a spinner at 10 on CPU 0 (below the demoted level 32, so it is only a load) and
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
/// The level of the victims. The three services take at most C of each T from the levels 33 and
/// above, and are services without a budget for the levels at or below 32 (the level they work
/// at when their budget is spent, `low` in init's table: above every POSIX process, below the
/// network service at 35), so the guarantee is judged for a victim above 32 and below 35.
const VICTIM_LEVEL: u8 = 34;
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
/// The clients a phase starts: 8, and 24 in the stress phase (`CLIENTS`).
const CLIENTS_DEFAULT: usize = 8;
static CLIENTS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(CLIENTS_DEFAULT);
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
/// Whether the victim of the phase ended: a starved victim (a service with no budget) ends late,
/// and its slot is not reused before.
static VICTIM_DONE: AtomicBool = AtomicBool::new(false);
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
    .unwrap_or_else(|e| panic!("create a thread in slot {slot}: {e:?}"))
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
            VICTIM_DONE.store(true, Relaxed);
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

/// The least and the median of the time of the victim over the windows of `l` buckets that lie
/// whole in the buckets `from` to `to`, in ns; None when none does.
fn windows_in(l: usize, from: usize, to: usize) -> Option<(u64, u64)> {
    let mut sums = [0u64; BUCKETS];
    let mut count = 0;
    let mut first = from;
    while first + l <= to.min(BUCKETS) {
        let sum: u64 = SPENT[first..first + l]
            .iter()
            .map(|b| b.load(Relaxed))
            .sum();
        let mut at = count;
        while at > 0 && sums[at - 1] > sum {
            sums[at] = sums[at - 1];
            at -= 1;
        }
        sums[at] = sum;
        count += 1;
        first += 1;
    }
    (count > 0).then(|| {
        (
            time::ticks_to_ns(sums[0]),
            time::ticks_to_ns(sums[count / 2]),
        )
    })
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
/// the probe's own thread) is set apart.
fn idle(process: &Handle<Process>, wait: &Handle<Channel>, timer: &Handle<Timer>) {
    reset();
    let victim = spawn_on(process, 0, victim, 0, VICTIM_LEVEL, 0);
    sys::thread_start(&victim).expect("start the victim");
    sleep_until(wait, timer, now_ns() + (PHASE_MS + 5) * MS);
    wait_ended(wait, timer, 0);
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
        let again = token.again();
        if token.reply_receive_handles(&channel, &over, rt::handle::Outgoing::new())
            == Err(abi::Error::InvalidArgs)
        {
            REPLY_RESULT.fetch_or(2, Relaxed);
        }
        // The refused call left the request waiting: the token answers it.
        let _ = again.reply(b"ok");
    }
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
    let _ = sys::send(&channel, b"two");
    let _ = (wait, timer);
    // The handles of a failed reply_receive: x1 = 1 says the reply went, whatever the error.
    use abi::Error::{BadHandle, InvalidArgs, LimitReached, PeerClosed};
    let took = sys::reply_receive_took_handles(1, BadHandle)
        && sys::reply_receive_took_handles(1, PeerClosed)
        && !sys::reply_receive_took_handles(0, InvalidArgs)
        && !sys::reply_receive_took_handles(0, BadHandle)
        && sys::reply_receive_took_handles(0, LimitReached);
    println!(
        "svcbudget replies whole_with_handle={} server_saw={} took_handles={}",
        u8::from(whole),
        REPLY_RESULT.load(Relaxed),
        u8::from(took)
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
fn spawn_greedies(process: &Handle<Process>, cpu: u8) -> [Option<Handle<Thread>>; GREEDIES] {
    let n = CLIENTS.load(Relaxed);
    core::array::from_fn(|i| (i < n).then(|| spawn_on(process, 2 + i, greedy, i as u64, 20, cpu)))
}

fn start_all(threads: &[Option<Handle<Thread>>]) {
    for t in threads.iter().flatten() {
        sys::thread_start(t).expect("start a greedy client");
    }
}

/// Waits for the greedy clients to end after STOP, 5 s at most.
fn wait_ended(wait: &Handle<Channel>, timer: &Handle<Timer>, greedies: u64) {
    for _ in 0..1000 {
        sleep_until(wait, timer, now_ns() + 5 * MS);
        if ENDED.load(Relaxed) == greedies && VICTIM_DONE.load(Relaxed) {
            return;
        }
    }
    println!("svcbudget a greedy client did not end");
}

/// The control phase: the greedy client on CPU 1 asks a server of the probe at 5 on CPU 0, which
/// has no budget and answers at the client's level (20), below the victim (34). What the victim
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
    let victim = spawn_on(process, 0, victim, 0, VICTIM_LEVEL, 0);
    let greedies = spawn_greedies(process, 1);
    sys::thread_start(&server).expect("start the control server");
    sys::thread_start(&victim).expect("start the victim");
    start_all(&greedies);
    sleep_until(wait, timer, now_ns() + PHASE_MS * MS);
    STOP.store(true, Relaxed);
    wait_ended(wait, timer, CLIENTS.load(Relaxed) as u64);
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
    VICTIM_DONE.store(false, Relaxed);
    STOP.store(false, Relaxed);
    let now = time::now();
    START.store(now, Relaxed);
    END.store(now + time::ns_to_ticks(PHASE_MS * MS), Relaxed);
}

/// A phase against `SERVICES[which]`: the greedy client asks it through a session of its own.
/// With `ping` false a victim at 34 spins and the lines give its shares; with `ping` true a
/// spinner at 10 does, and the probe's thread at 40 asks the service every 2 ms through its own
/// session and notes the longest round trip.
fn phase(
    process: &Handle<Process>,
    parent: &Handle<Channel>,
    which: usize,
    ping: bool,
    wait: &Handle<Channel>,
    timer: &Handle<Timer>,
    label: &str,
) {
    let name = SERVICES[which];
    let sessions: [Option<Handle<Channel>>; GREEDIES + 1] = core::array::from_fn(|i| {
        (i < CLIENTS.load(Relaxed) || i == GREEDIES)
            .then(|| rt::service::connect(parent, name).ok())
            .flatten()
    });
    let wanted = CLIENTS.load(Relaxed);
    if sessions
        .iter()
        .enumerate()
        .any(|(i, s)| (i < wanted || i == GREEDIES) && s.is_none())
    {
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
    let spinner = spawn_on(
        process,
        0,
        victim,
        0,
        if ping { 10 } else { VICTIM_LEVEL },
        0,
    );
    let greedies = spawn_greedies(process, 1);
    sys::thread_start(&spinner).expect("start the victim");
    start_all(&greedies);
    let (mut n, mut max, mut failed) = (0u64, 0u64, 0u64);
    let (mut over, mut worst_at) = (0u64, 0u64);
    let mut sum = 0u64;
    // The requests of the pings (a lookup of the RAM service is five) and the longest one.
    let (mut requests, mut worst_request) = (0u64, 0u64);
    sys::send_stats::watch(ping_session.raw().0);
    if ping {
        // The client at 40 asks every 2 ms, from 20 ms on: the greedy client starts on CPU 1
        // meanwhile, and its start is not the service's.
        let mut next = now_ns() + 20 * MS;
        while time::now() < END.load(Relaxed) {
            sleep_until(wait, timer, next);
            let (sends_before, _) = sys::send_stats::read();
            sys::send_stats::reset_longest();
            let began = time::now();
            let ok = ask(kind_of(name), ping_session, 1);
            let took = time::now() - began;
            let (sends_after, longest) = sys::send_stats::read();
            requests += sends_after - sends_before;
            worst_request = worst_request.max(longest);
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
    wait_ended(wait, timer, CLIENTS.load(Relaxed) as u64);
    if ping {
        println!(
            "svcbudget {label} ping n={n} failed={failed} max_us={} over_750us={over} requests={requests} worst_request_us={} mean_us={} worst_at_ms={worst_at} greedy={} greedy_failed={} status={}",
            time::ticks_to_ns(max) / 1000,
            time::ticks_to_ns(worst_request) / 1000,
            time::ticks_to_ns(sum) / 1000 / n.max(1),
            GREEDY_N.load(Relaxed),
            GREEDY_FAILED.load(Relaxed),
            LAST_STATUS.load(Relaxed)
        );
    } else {
        print_windows(label);
        println!(
            "svcbudget {label} share greedy={} greedy_failed={} gap_us={} status={}",
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
    if sys::cpu_info(0).map_or(1, |c| c.cpus) < 2 {
        one_cpu(&mut start, &ping_wait, &ping_timer);
        println!("svcbudget DONE");
        return 0;
    }
    replies(&start.process, &ping_wait, &ping_timer);
    idle(&start.process, &ping_wait, &ping_timer);
    control(&start.process, &ping_wait, &ping_timer);
    let name_of = |which: usize| SERVICES[which];
    for which in 0..SERVICES.len() {
        for ping in [false, true] {
            phase(
                &start.process,
                &start.parent,
                which,
                ping,
                &ping_wait,
                &ping_timer,
                name_of(which),
            );
        }
    }
    // The stress phase: 24 queued clients of the pipe service, the victim's share printed (no gate;
    // with the bound pipe on the kernel of #364 the victim kept 0 per mille: issue #750).
    CLIENTS.store(GREEDIES, Relaxed);
    phase(
        &start.process,
        &start.parent,
        1,
        false,
        &ping_wait,
        &ping_timer,
        "pipe24",
    );
    println!("svcbudget DONE");
    0
}

// ---- The one-CPU probe (QEMU under -icount with one CPU): the oracle the verdicts hold to.
//
// With two CPUs QEMU runs the vCPUs in turn in one thread with one instruction counter, so a busy
// CPU 1 advances the guest clock while CPU 0 executes nothing: the victim's share and a client's
// wait on a two-CPU machine are partly the emulator's, and the phases above are printed for
// information.
// On one CPU everything below runs on CPU 0 and the numbers are the kernel's.

/// C of each service's budget in microseconds and the longest stretch B of the kernel
/// (`budget-hog`); the cost of one timer event is measured (`control_budget`).
const C_US: [u64; 3] = [250, 75, 75];
const B_K_US: u64 = 150;
/// The period T of the three budgets, microseconds.
const T_US: u64 = 5_000;
/// One round trip of a call (C_ipc, about 2 000 ticks; the comment above `CALL_WAIT_MAX` in
/// `xtask/src/main.rs`).
const C_IPC_US: u64 = 32;
/// What init (level 63, no budget) takes from one window of the level-40 phase for one service:
/// the answer to its heartbeat (43 us: in the time stamps of the kernel, `STAMP_RUN` records of a
/// window with a heartbeat of the RAM service, init ran 2 688 ticks) and up to two notifications
/// of the overruns of its budget (13 us each: 824 and 766 ticks), 69 us in all.
const INIT_PER_SERVICE_US: u64 = 70;
/// What the starvation gate allows beyond the terms it explains, per service: the events of one
/// period of the budget (its exhaustion and its replenishment, 2 e, with e from the control phase
/// of the same run) and the work of init for it (`INIT_PER_SERVICE_US`). No term comes from the
/// measured run of the service itself.
fn allowance_us(e: u64) -> u64 {
    2 * e + INIT_PER_SERVICE_US
}

/// What one overrun of a budget is, microseconds: the kernel charges a loan at the end of the
/// request, so a budget runs over by at most one step of its service before the next
/// replenishment repays it (`B_K_US`, the kernel's longest stretch, and the longest step of a
/// service, `STEP_LIMIT_US`, 18 369 ticks).
const OVERRUN_US: u64 = B_K_US + STEP_LIMIT_US;
/// The longest step of a service, microseconds: the bound of a notice or a request of the
/// services (`xtask` holds each step under 18 369 ticks, 294 us at 62.5 MHz).
const STEP_LIMIT_US: u64 = 294;

/// The cost of one timer event of a budget in microseconds, by C: [250, 75] (`control`), measured.
static E_MEASURED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
/// The cycles of the duty-cycled victim: the time it ran and the time it was awake, in ticks.
static CYC_RUN: [AtomicU64; 512] = [const { AtomicU64::new(0) }; 512];
static CYC_WALL: [AtomicU64; 512] = [const { AtomicU64::new(0) }; 512];
static CYCLES: AtomicU64 = AtomicU64::new(0);

/// The ticks `serve` of the service has charged (`BudgetInfo::ran`), or None when init gave the
/// probe no copy of the budget (a probe that reads nothing fails the run).
fn ran_of(budget: &Option<Handle<rt::handle::Budget>>) -> Option<u64> {
    budget
        .as_ref()
        .and_then(|b| sys::budget_info(b).ok())
        .map(|i| i.ran)
}

/// The e of the service `which` (index of SERVICES): the control phase of its C.
fn e_of(which: usize) -> u64 {
    E_MEASURED[usize::from(which != 0)].load(Relaxed)
}

/// A spinner with no IPC, which the control phase puts under a budget: it exhausts the budget in
/// each period, so the victim's loss is C and the events of the budget alone.
extern "C" fn busy(_: u64) -> ! {
    let mut i = 0u64;
    while !STOP.load(Relaxed) {
        i = black_box(i.wrapping_add(1));
    }
    ENDED.fetch_add(1, Relaxed);
    sys::thread_exit()
}

/// The control phase for C = `c_us`: the victim at 34 against a spinner at 40 under `budget`
/// (that C for each 5 ms, `low` 1): the victim's worst window of 10 ms loses 2 C and four events
/// (the exhaustion and the replenishment of each of its two periods), so
/// e = (loss - 2 C) / 4. Told per C.
fn control_budget(
    process: &Handle<Process>,
    budget: Option<Handle<rt::handle::Budget>>,
    c_us: u64,
    slot: usize,
    wait: &Handle<Channel>,
    timer: &Handle<Timer>,
) {
    let Some(budget) = budget else {
        println!("svcbudget1 control c_us={c_us} FAILED no budget in the start data");
        return;
    };
    reset();
    let spinner = spawn_on(process, 2, busy, 0, 40, 0);
    if let Err(e) = sys::thread_bind_budget(&spinner, &budget) {
        println!("svcbudget1 control c_us={c_us} FAILED bind {e:?}");
        return;
    }
    let victim_thread = spawn_on(process, 0, victim, 0, VICTIM_LEVEL, 0);
    let now = time::now();
    START.store(now, Relaxed);
    END.store(now + time::ns_to_ticks(150 * MS), Relaxed);
    sys::thread_start(&spinner).expect("start the spinner");
    sys::thread_start(&victim_thread).expect("start the victim");
    sleep_until(wait, timer, now_ns() + 155 * MS);
    STOP.store(true, Relaxed);
    wait_ended(wait, timer, 1);
    let l = 10;
    let (worst, median) = windows_in(l, 0, 150).map_or((0, 0), |(least, med)| {
        (least * 1000 / (l as u64 * MS), med * 1000 / (l as u64 * MS))
    });
    // The loss of a typical window in microseconds: (1000 - median) per mille of 10 ms. (The worst
    // window can take the end of one period, a whole one and the start of the third, and tells
    // a larger e; that is printed too.)
    let loss_us = (1000 - median) * 10;
    let e = loss_us.saturating_sub(2 * c_us) / 4;
    let e_worst = ((1000 - worst) * 10).saturating_sub(2 * c_us) / 4;
    E_MEASURED[slot].store(e, Relaxed);
    println!(
        "svcbudget1 control c_us={c_us} worst10={worst} median10={median} loss_us={loss_us} e_us={e} e_worst_us={e_worst}"
    );
}

/// The victim of the starvation phase: it spins 0.8 ms of its own running time and sleeps 0.2 ms,
/// and notes for each cycle the time it ran and the time it was awake (the difference is what
/// others took above it).
extern "C" fn victim_duty(_: u64) -> ! {
    let end = END.load(Relaxed);
    let gap_ticks = time::ns_to_ticks(GAP_NS);
    let want = time::ns_to_ticks(800_000);
    let Ok(channel) = sys::channel_create_wait(VICTIM_LEVEL) else {
        sys::thread_exit()
    };
    let Ok(timer) = sys::timer_create(&channel, VICTIM_LEVEL) else {
        sys::thread_exit()
    };
    let mut i = 0u64;
    loop {
        let awake = time::now();
        let (mut run, mut last) = (0u64, awake);
        while run < want {
            for _ in 0..16 {
                i = black_box(i.wrapping_add(1));
            }
            let now = time::now();
            let gap = now - last;
            last = now;
            if gap <= gap_ticks {
                run += gap;
            }
        }
        let wall = time::now() - awake;
        let c = CYCLES.fetch_add(1, Relaxed) as usize;
        if c < CYC_RUN.len() {
            CYC_RUN[c].store(run, Relaxed);
            CYC_WALL[c].store(wall, Relaxed);
        }
        if time::now() >= end {
            VICTIM_DONE.store(true, Relaxed);
            sys::thread_exit()
        }
        let _ = sys::timer_set(&timer, time::ticks_to_ns(time::now()) + 200_000);
        let _ = sys::receive(&channel);
    }
}

/// The least and the median of the victim's share of its own active time (per mille) over the
/// windows of 10 consecutive cycles.
fn duty_windows() -> (u64, u64, u64) {
    let n = (CYCLES.load(Relaxed) as usize).min(CYC_RUN.len());
    let mut shares = [0u64; 512];
    let mut count = 0;
    let mut first = 2;
    while first + 10 <= n {
        let run: u64 = CYC_RUN[first..first + 10]
            .iter()
            .map(|b| b.load(Relaxed))
            .sum();
        let wall: u64 = CYC_WALL[first..first + 10]
            .iter()
            .map(|b| b.load(Relaxed))
            .sum();
        let share = run * 1000 / wall.max(1);
        let mut at = count;
        while at > 0 && shares[at - 1] > share {
            shares[at] = shares[at - 1];
            at -= 1;
        }
        shares[at] = share;
        count += 1;
        first += 1;
    }
    if count == 0 {
        return (0, 0, 0);
    }
    (shares[0], shares[count / 2], n as u64)
}

/// The starvation phase against `SERVICES[which]`: 24 clients at 20 on CPU 0 ask the service the
/// dear request without a pause, and the victim at 34 (`VICTIM_LEVEL`, above the demoted level
/// 32) spins 0.8 ms and sleeps 0.2 ms; the clients refill the queue in each sleep. The service
/// works above the victim for C of each T and at 32, below it, for the rest, so the victim loses
/// what the budget and its events explain and no more: in 10 ms, two periods, 2 C, the two
/// timer events of each period (4 e, e from the control phase) and the 2 x 10 us of the kernel's
/// entries, with the allowance `allowance_us`. A victim at or below 32 would lose all of its
/// time to the demoted service, which the guarantee does not cover. The line gives the worst and
/// the median share of the victim's own active time over 10 cycles, and the ticks the service's
/// `serve` budget charged over the phase against its bound, `ceil(P / T) * C` and one overrun,
/// with a floor of one C (a budget that charged less was not bound, or the clients did not
/// ask).
fn starve(
    process: &Handle<Process>,
    parent: &Handle<Channel>,
    which: usize,
    budget: &Option<Handle<rt::handle::Budget>>,
    wait: &Handle<Channel>,
    timer: &Handle<Timer>,
) {
    let name = SERVICES[which];
    let n = GREEDIES;
    let sessions: [Option<Handle<Channel>>; GREEDIES] = core::array::from_fn(|i| {
        (i < n)
            .then(|| rt::service::connect(parent, name).ok())
            .flatten()
    });
    if sessions[..n].iter().any(Option::is_none) {
        println!("svcbudget1 {name} FAILED no session");
        return;
    }
    WHICH.store(kind_of(name), Relaxed);
    for (slot, session) in GREEDY_SESSIONS.iter().zip(&sessions) {
        slot.store(session.as_ref().map_or(0, |s| s.raw().0), Relaxed);
    }
    for (i, s) in sessions.iter().flatten().enumerate() {
        PIPE_ENDS[i].store(0, Relaxed);
        if which == 1 {
            heavy(1, s, i, false);
        }
    }
    reset();
    CYCLES.store(0, Relaxed);
    CLIENTS.store(n, Relaxed);
    let clients = spawn_greedies(process, 0);
    let victim_thread = spawn_on(process, 0, victim_duty, 0, VICTIM_LEVEL, 0);
    let now = time::now();
    START.store(now, Relaxed);
    END.store(now + time::ns_to_ticks(150 * MS), Relaxed);
    let Some(ran_before) = ran_of(budget) else {
        println!("svcbudget1 {name} FAILED no ran-{name}");
        return;
    };
    let began = time::now();
    start_all(&clients);
    sys::thread_start(&victim_thread).expect("start the victim");
    sleep_until(wait, timer, now_ns() + 155 * MS);
    STOP.store(true, Relaxed);
    wait_ended(wait, timer, n as u64);
    let (ran_after, ended) = (ran_of(budget), time::now());
    let Some(ran_after) = ran_after else {
        println!("svcbudget1 {name} FAILED no ran-{name}");
        return;
    };
    let (worst, median, cycles) = duty_windows();
    let e = e_of(which);
    // The victim's loss in 10 ms of wall time (8 ms of them awake) against what the budget and
    // the events explain: the remainder.
    let loss_us = (1000 - worst) * 8;
    let explained = 2 * C_US[which] + 2 * 10 + 4 * e;
    let remainder = loss_us.saturating_sub(explained);
    let bound = 1000 - (explained + allowance_us(e)) / 8;
    // The budget's own account: the ticks charged in the phase against ceil(P / T) periods of C
    // and one overrun, and against the floor of one C.
    let phase_us = time::ticks_to_ns(ended - began) / 1000;
    let ran_us = time::ticks_to_ns(ran_after.saturating_sub(ran_before)) / 1000;
    let ran_bound = phase_us.div_ceil(T_US) * C_US[which] + OVERRUN_US;
    println!(
        "svcbudget1 {name} starve clients={n} cycles={cycles} worst10={worst} median10={median} bound10={bound} c_us={} e_us={e} remainder_us={remainder} allowance_us={} ran_us={ran_us} ran_bound_us={ran_bound} ran_floor_us={} phase_us={phase_us}",
        C_US[which],
        allowance_us(e),
        C_US[which]
    );
}

/// The level-40 phase against `SERVICES[which]`: 8 clients at 20 queue the dear request of the
/// service without a pause (nothing above them but the thread at 40, asleep), the thread at 40
/// asks every 1037 us from absolute times, so that its release sweeps the budget period of 5 ms
/// by 37 us a step, 200 times. `s_max` is the longest single request of the dear kind alone and
/// `s0` that of the thread's own, both of the same build; a request of the thread must wait
/// R at most, the fixed point of
///
///   R = 1.10 * s_max + s0 + B_k + C_ipc
///       + sum over the three services j of ceil(R / T) * C_j
///       + 2 * sum over the three budgets of e_j
///       + 3 * INIT
///
/// (the request in hand, the thread's own request, the kernel's longest stretch, one round trip;
/// the budgets of every service above 40 in that window, the target's included: after its reply
/// the target keeps its own level, with the client at 40 ready, until its budget is gone (81 us
/// of thread time in the stamps of a window against C = 75 us), and the RAM service, idle in this
/// phase, ran 235 us (C = 250 us) after a timer wake and a call to init in the worst window the
/// stamps showed; two timer events of each of the three budgets, e measured in the control
/// phase; init at 63 for each service). The worst request moves by 176 us with the image alone
/// (359 to 535 us of the pipe on the unbroken kernel), the timer wakes of the other services and
/// the notifications of init landing in other places of the window; the bound holds them all.
/// A ping of the
/// RAM service is `requests` requests, each held to that.
fn level40(
    process: &Handle<Process>,
    parent: &Handle<Channel>,
    which: usize,
    wait: &Handle<Channel>,
    timer: &Handle<Timer>,
) {
    let name = SERVICES[which];
    let kind = kind_of(name);
    let n = 8;
    let sessions: [Option<Handle<Channel>>; GREEDIES + 1] = core::array::from_fn(|i| {
        (i < n || i >= GREEDIES - 1)
            .then(|| rt::service::connect(parent, name).ok())
            .flatten()
    });
    // Slots 0 to 7 are the clients', 22 the calibration's, 23 the thread at 40's.
    let (Some(cal), Some(ping)) = (&sessions[GREEDIES - 1], &sessions[GREEDIES]) else {
        println!("svcbudget1 {name} FAILED no session");
        return;
    };
    WHICH.store(kind, Relaxed);
    for i in 0..n {
        GREEDY_SESSIONS[i].store(sessions[i].as_ref().map_or(0, |s| s.raw().0), Relaxed);
        PIPE_ENDS[i].store(0, Relaxed);
        if let (1, Some(s)) = (kind, &sessions[i]) {
            heavy(1, s, i, false);
        }
    }
    // Alone: the longest single request of the dear kind and of the thread's own.
    PIPE_ENDS[GREEDIES - 1].store(0, Relaxed);
    if kind == 1 {
        heavy(1, cal, GREEDIES - 1, false);
    }
    sys::send_stats::watch(cal.raw().0);
    // Each request goes with the budget fresh: a pause of more than one period T before it lets
    // the replenishment come, so no exhaustion (a wait of up to T - C for the next replenishment)
    // lies inside the measure. Asked one after the other, the requests drain C of the service and
    // the longest of them would be that wait (4.9 ms for the RAM and terminal services), which is
    // no request in hand.
    let mut s_max = 0;
    for i in 0..30 {
        sleep_until(wait, timer, now_ns() + (T_US + 500) * 1000);
        sys::send_stats::reset_longest();
        if kind == 0 {
            ask(0, cal, DEPTH);
        } else {
            heavy(kind, cal, GREEDIES - 1, i % 2 == 1);
        }
        s_max = s_max.max(sys::send_stats::read().1);
    }
    sys::send_stats::watch(ping.raw().0);
    let (mut s0, mut requests) = (0, 0);
    for _ in 0..50 {
        let before = sys::send_stats::read().0;
        sys::send_stats::reset_longest();
        ask(kind, ping, 1);
        let (after, longest) = sys::send_stats::read();
        s0 = s0.max(longest);
        requests = requests.max(after - before);
    }
    reset();
    CLIENTS.store(n, Relaxed);
    let clients = spawn_greedies(process, 0);
    start_all(&clients);
    sleep_until(wait, timer, now_ns() + MS);
    let t0 = now_ns() + 2 * MS;
    let (mut worst_request, mut worst_wait) = (0, 0);
    for k in 0..200u64 {
        let release = t0 + k * 1_037_000;
        sleep_until(wait, timer, release);
        sys::send_stats::reset_longest();
        ask(kind, ping, 1);
        let (_, longest) = sys::send_stats::read();
        worst_request = worst_request.max(longest);
        worst_wait = worst_wait.max(now_ns().saturating_sub(release));
    }
    STOP.store(true, Relaxed);
    wait_ended_clients(wait, timer, n as u64);
    let us = |t: u64| time::ticks_to_ns(t) / 1000;
    let e = e_of(which);
    let bound = level40_bound(us(s_max), us(s0), [e_of(0), e_of(1), e_of(2)]);
    println!(
        "svcbudget1 {name} level40 releases=200 requests_per_ping={requests} worst_request_us={} worst_wait_us={} s_max_us={} s0_us={} e_us={e} bound_us={bound}",
        us(worst_request),
        worst_wait / 1000,
        us(s_max),
        us(s0)
    );
}

/// The bound R of `level40` for the build's `s_max` and `s0` and the e of the three budgets
/// (microseconds): the fixed point of the formula above, reached from below.
fn level40_bound(s_max: u64, s0: u64, e: [u64; 3]) -> u64 {
    let fixed = s_max * 110 / 100
        + s0
        + B_K_US
        + C_IPC_US
        + 2 * e.iter().sum::<u64>()
        + 3 * INIT_PER_SERVICE_US;
    let c: u64 = C_US.iter().sum();
    let mut r = fixed;
    for _ in 0..8 {
        r = fixed + r.div_ceil(T_US) * c;
    }
    r
}

/// `wait_ended` without the victim (the level-40 phase has none).
fn wait_ended_clients(wait: &Handle<Channel>, timer: &Handle<Timer>, clients: u64) {
    for _ in 0..1000 {
        sleep_until(wait, timer, now_ns() + 5 * MS);
        if ENDED.load(Relaxed) == clients {
            return;
        }
    }
    println!("svcbudget1 a client did not end");
}

/// The service whose starvation phase alone the image runs (features `break-only-*`, for the
/// images of `cargo xtask budget-breaks` in which that service binds no budget): the account of
/// its budget is all they judge, so no control phase, no level-40 phase and no other service
/// runs.
fn only_service() -> Option<usize> {
    if cfg!(feature = "break-only-ramfs") {
        Some(0)
    } else if cfg!(feature = "break-only-pipe") {
        Some(1)
    } else if cfg!(feature = "break-only-tty") {
        Some(2)
    } else {
        None
    }
}

/// The one-CPU probe: the replies, then for each service the starvation and the level-40 phase.
fn one_cpu(start: &mut rt::startup::Startup, wait: &Handle<Channel>, timer: &Handle<Timer>) {
    replies(&start.process, wait, timer);
    if let Some(which) = only_service() {
        let observed = [
            rt::budget::take(start, "ran-ramfs"),
            rt::budget::take(start, "ran-pipe"),
            rt::budget::take(start, "ran-tty"),
        ];
        starve(
            &start.process,
            &start.parent,
            which,
            &observed[which],
            wait,
            timer,
        );
        return;
    }
    // The control phases first: they measure e for the two C of the services.
    let ramfs_budget = rt::budget::take(start, "ctl-ramfs");
    let pipe_budget = rt::budget::take(start, "ctl-pipe");
    control_budget(&start.process, ramfs_budget, 250, 0, wait, timer);
    control_budget(&start.process, pipe_budget, 75, 1, wait, timer);
    // The budgets of the services' request threads, read-only, from init (feature
    // `table-service-budget`): the account of what each charged.
    let observed = [
        rt::budget::take(start, "ran-ramfs"),
        rt::budget::take(start, "ran-pipe"),
        rt::budget::take(start, "ran-tty"),
    ];
    for (which, budget) in observed.iter().enumerate() {
        starve(&start.process, &start.parent, which, budget, wait, timer);
        level40(&start.process, &start.parent, which, wait, timer);
    }
}
