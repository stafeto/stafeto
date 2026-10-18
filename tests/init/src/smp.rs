// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of SMP stage 4 (decision 2): threads on every CPU, a service on
//! another CPU than its client, a gate that stops the threads of a process
//! on every CPU, the lock of objects under the calls of every CPU. On one
//! CPU each of them ends at once and passes; `cargo xtask smp-probe` runs
//! them on four, where each also prints the line xtask looks for.

use crate::harness::*;
use crate::processes::{Gift, Kid, LEAF_QUOTA, SPAWN_CPU, kid_mark, reset_kid_marks};
use crate::timers::timer_at;
use crate::transfers::copy_raw;
use abi::{Access, Call, Error, ProcessState, Rights};
use core::hint::spin_loop;
use core::sync::atomic::Ordering::SeqCst;
use rt::sys::Received;

pub(crate) const TESTS: [Test; 12] = [
    ("smp_threads_run_together_on_every_cpu", threads_together),
    (
        "smp_service_works_at_its_clients_level_across_cpus",
        service_across_cpus,
    ),
    (
        "smp_suspend_and_kill_stop_threads_on_every_cpu",
        suspend_and_kill,
    ),
    ("smp_lock_holds_under_calls_of_every_cpu", lock_under_load),
    (
        "smp_time_of_a_thread_at_el0_on_another_cpu",
        time_across_cpus,
    ),
    (
        "smp_signal_reaches_a_thread_at_el0_on_another_cpu",
        signal_across_cpus,
    ),
    (
        "smp_log_of_another_cpu_is_read_without_changing_it",
        log_across_cpus,
    ),
    (
        "smp_raise_of_a_client_reaches_its_service_on_another_cpu",
        raise_across_cpus,
    ),
    (
        "smp_timer_of_another_cpu_is_armed_there_and_let_go_there",
        timer_across_cpus,
    ),
    (
        "smp_client_ends_on_its_cpu_while_its_reply_is_on_its_way",
        client_ends_with_reply_on_its_way,
    ),
    (
        "smp_mapping_is_made_once_while_another_cpu_makes_threads",
        mapping_while_threads_join,
    ),
    (
        "smp_boost_leaves_a_service_that_ended_on_its_cpu_alone",
        boost_of_a_service_that_ended,
    ),
];

/// How long a wait for another CPU may last, in nanoseconds: far longer
/// than any of them takes.
const WAIT_NS: u64 = 3_000_000_000;

fn now() -> u64 {
    sys::clock_now().unwrap_or(0)
}

/// Spins until `done` or the time is up.
fn wait_for(done: impl Fn() -> bool) -> bool {
    let limit = now() + WAIT_NS;
    while !done() {
        if now() > limit {
            return false;
        }
        spin_loop();
    }
    true
}

/// Spins for `ns`.
fn pause(ns: u64) {
    let until = now() + ns;
    while now() < until {
        spin_loop();
    }
}

/// A stopped thread of init's process on CPU `cpu`, started.
fn spawn_on(
    slot: usize,
    cpu: usize,
    entry: extern "C" fn(u64) -> !,
    arg: u64,
    priority: u8,
) -> Result<Handle<Thread>, &'static str> {
    let mut x = [0; 10];
    x[0] = own().raw().0;
    x[1] = entry as *const () as u64;
    x[2] = STACKS[slot].top() as u64;
    x[3] = arg;
    x[4] = priority.into();
    x[5] = Policy::Fifo as u64 | ((cpu as u64 + 1) << abi::THREAD_CPU_SHIFT);
    x[6] = buffer(slot) as u64;
    // SAFETY: the stack of the slot is the thread's alone until it ends.
    let after = unsafe { sys::raw::<{ Call::ThreadCreate.number() }>(x) };
    if Error::from_code(after[0]).is_some() {
        return Err("thread_create on a CPU failed");
    }
    let t = Handle::<Thread>::from_raw(abi::Handle(after[1]));
    sys::thread_start(&t).map_err(|_| "thread_start failed")?;
    Ok(t)
}

/// The number of CPUs, found by the highest CPU thread_create takes.
fn cpus() -> Result<usize, &'static str> {
    let mut found = 1;
    for cpu in 1..8 {
        let mut x = [0; 10];
        x[0] = own().raw().0;
        x[1] = 0x1000;
        x[4] = LOW.into();
        x[5] = Policy::Fifo as u64 | ((cpu as u64 + 1) << abi::THREAD_CPU_SHIFT);
        x[6] = buffer(3) as u64;
        // SAFETY: the thread never starts, so it runs nothing.
        let after = unsafe { sys::raw::<{ Call::ThreadCreate.number() }>(x) };
        match Error::from_code(after[0]) {
            None => {
                close(Handle::<Thread>::from_raw(abi::Handle(after[1])))?;
                found = cpu + 1;
            }
            Some(Error::InvalidArgs) => break,
            Some(_) => return Err("thread_create failed while the CPUs were counted"),
        }
    }
    Ok(found)
}

static ARRIVED: AtomicU64 = AtomicU64::new(0);
static WANT: AtomicU64 = AtomicU64::new(0);
static CHANNEL: AtomicU64 = AtomicU64::new(0);

/// Takes part in a barrier: the thread comes, and waits for all. Threads of
/// one level that share a CPU would never meet: FIFO.
extern "C" fn barrier(slot: u64) -> ! {
    ARRIVED.fetch_add(1, SeqCst);
    while ARRIVED.load(SeqCst) < WANT.load(SeqCst) {
        spin_loop();
    }
    MARKS[slot as usize].store(1, Relaxed);
    sys::thread_exit()
}

/// A thread on each CPU but init's, and init, all at one level, wait for
/// each other: on one CPU, FIFO would never let them meet.
fn threads_together() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    ARRIVED.store(0, SeqCst);
    WANT.store(n as u64, SeqCst);
    let mut kept = [None, None, None];
    for cpu in 1..n.min(4) {
        kept[cpu - 1] = Some(spawn_on(
            cpu - 1,
            cpu,
            barrier,
            (cpu - 1) as u64,
            TEST_PRIORITY,
        )?);
    }
    ARRIVED.fetch_add(1, SeqCst);
    let met = wait_for(|| ARRIVED.load(SeqCst) >= n as u64);
    let all = wait_for(|| (0..n - 1).all(|i| mark(i) == 1));
    // Let whoever waits go, whatever came of it.
    WANT.store(0, SeqCst);
    let_run()?;
    for t in kept.into_iter().flatten() {
        close(t)?;
    }
    check(
        met && all,
        "the threads on the other CPUs did not run together",
    )?;
    println!("smp: {n} CPUs, threads ran together on every CPU");
    Ok(())
}

/// The service: takes one request, reads its own priority while it works on
/// it (mark 0), answers, and reads it again (mark 2).
extern "C" fn serve_once(_: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    if let Ok(Received::Message { token, .. }) = sys::receive(&c) {
        let level = |t: &Handle<Thread>| sys::thread_info(t).map_or(0, |i| u64::from(i.priority));
        if let Ok(own) = sys::self_thread() {
            MARKS[0].store(level(&own), Relaxed);
            let _ = token.reply(&[]);
            MARKS[2].store(level(&own), Relaxed);
            let _ = own.close();
        }
    }
    MARKS[3].store(1, Relaxed);
    sys::thread_exit()
}

extern "C" fn ask_once(_: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    MARKS[1].store(if sys::send(&c, &[1]).is_ok() { 1 } else { 2 }, Relaxed);
    sys::thread_exit()
}

/// A service at LEVEL on one CPU takes a request of a client at HIGH on
/// another: while it works on it, it is at HIGH (the boost, spec 6.6, through
/// a command to its CPU), and after the reply it is at LEVEL again.
fn service_across_cpus() -> Outcome {
    let n = cpus()?;
    if n < 3 {
        return Ok(());
    }
    reset_marks();
    let c = channel(QUIET)?;
    CHANNEL.store(c.raw().0, Relaxed);
    let server = spawn_on(0, 2, serve_once, 0, LEVEL)?;
    // The service reaches its receive on its CPU.
    pause(20_000_000);
    let client = spawn_on(1, 1, ask_once, 0, HIGH)?;
    let done = wait_for(|| mark(1) != 0 && mark(3) != 0);
    let (during, replied, after) = (mark(0), mark(1), mark(2));
    let_run()?;
    for t in [server, client] {
        close(t)?;
    }
    close(c)?;
    check(done && replied == 1, "the client did not get its reply")?;
    check(
        during == u64::from(HIGH),
        "the service on another CPU did not work at its client's priority",
    )?;
    check(
        after == u64::from(LEVEL),
        "the boost of the service on another CPU did not end with its reply",
    )?;
    println!("smp: service on CPU 2 worked at {during} for a client on CPU 1, then at {after}");
    Ok(())
}

/// A child with a spinning thread on every CPU is suspended: after the call
/// returns no counter moves; resumed, they all move; killed, they stop for
/// good, and the teardown ends.
fn suspend_and_kill() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    let kid = Kid::load(SPIN_QUOTA, 16, LEVEL)?;
    kid.start()?;
    kid.serve(Role::SmpSpin, &[n as u64, LEVEL.into()], &[Gift::Own])?;
    reset_kid_marks();
    reset_marks();
    // A thread of init's own, below the child's, on CPU 1: it runs once the
    // child's thread there is parked, and keeps that CPU at EL0 while the
    // wait for the quiescent points goes on: only a way to EL0 that is a
    // quiescent point lets that wait end.
    let low = spawn_on(1, 1, spin_marked, 1, LOW)?;
    let_run()?;
    // A thread of init's own on this CPU, above init, waits for a timer of
    // this CPU: the suspension waits for the other CPUs between looks, so
    // that this CPU takes the timer's interrupt and runs the thread meanwhile.
    let hear = if n >= 3 {
        let c = channel(QUIET)?;
        CHANNEL.store(c.raw().0, Relaxed);
        // Its notification is at NOTICE, above init: the portion that
        // posts it runs at once, where a notification at the lowest level
        // would wait for init to stop.
        let t = timer_at(&c, NOTICE)?;
        Some((c, t, spawn_on(2, 0, timer_listener, 0, HIGH)?))
    } else {
        None
    };
    let moving = |before: &[u64; 8]| (1..n).all(|i| kid_mark(i) > before[i]);
    let snapshot = || {
        let mut s = [0; 8];
        for (i, w) in s.iter_mut().enumerate().take(n) {
            *w = kid_mark(i);
        }
        s
    };
    let zero = [0; 8];
    check(
        wait_for(|| moving(&zero)),
        "the threads of the child did not run on every CPU",
    )?;
    // The level at which the kernel built with `window-probe` holds a CPU
    // back from its quiescent point once, 20 ms.
    sys::thread_set_priority(&me(), LAG_LEVEL, Policy::Fifo).map_err(|_| "init lowered itself")?;
    let deadline = now() + 2_000_000;
    if let Some((_, t, _)) = &hear {
        sys::timer_set(t, deadline).map_err(|_| "the timer was not armed")?;
    }
    let began = now();
    let suspended = sys::process_control(&kid.process, true, 0);
    let waited = now() - began;
    sys::thread_set_priority(&me(), TEST_PRIORITY, Policy::Fifo)
        .map_err(|_| "init could not take its priority back")?;
    suspended.map_err(|e| {
        println!("process_control: {e:?}");
        "process_control failed"
    })?;
    let held = snapshot();
    pause(30_000_000);
    let still = snapshot();
    sys::process_control(&kid.process, false, 0).map_err(|_| "process_control failed")?;
    check(
        held == still,
        "a thread of a suspended process ran on another CPU",
    )?;
    check(
        wait_for(|| moving(&held)),
        "the threads of the resumed process did not run again",
    )?;
    sys::process_kill(&kid.process).map_err(|_| "process_kill failed")?;
    let_run()?;
    MARKS[3].store(1, Relaxed);
    let ended =
        wait_for(|| sys::thread_info(&low).is_ok_and(|i| i.state == abi::ThreadState::Ended));
    close(low)?;
    check(ended, "the thread of init on CPU 1 did not stop")?;
    let gone = snapshot();
    pause(30_000_000);
    let after = snapshot();
    kid.close()?;
    let_run()?;
    check(
        gone == after,
        "a thread of a killed process ran on another CPU",
    )?;
    if let Some((c, t, l)) = hear {
        let heard = wait_for(|| mark(2) != 0);
        let late = mark(2).saturating_sub(deadline);
        close(l)?;
        close(t)?;
        close(c)?;
        check(heard, "the thread that waits for the timer did not run")?;
        println!(
            "smp: suspend waited {} us for the CPUs, a timer of this CPU woke its thread {} us after its deadline",
            waited / 1000,
            late / 1000
        );
    }
    println!("smp: suspend and kill stopped the threads of the child on {n} CPUs");
    Ok(())
}

/// The level init suspends at: the kernel built with `window-probe` holds
/// CPU 2 back from a quiescent point for 20 ms once for a suspension made
/// at it (kernel cmd::window).
const LAG_LEVEL: u8 = 19;

/// Waits for the timer's notification and marks when it came (mark 2).
extern "C" fn timer_listener(_: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    if sys::receive(&c).is_ok() {
        MARKS[2].store(now(), SeqCst);
    }
    sys::thread_exit()
}

/// Rounds of the lock test on each CPU.
const ROUNDS: u64 = 4000;
/// The quota of the child that spins on every CPU: its threads, buffers and
/// tables.
const SPIN_QUOTA: u64 = LEAF_QUOTA + 10 * PAGE as u64;

/// Duplicates and closes a handle of init's table `ROUNDS` times, as every
/// CPU does at once: each takes OBJ, and the table is one.
extern "C" fn churn_handles(slot: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    let mut ok = 0;
    for _ in 0..ROUNDS {
        if let Ok(d) = sys::handle_duplicate(&*c, Rights::NONE)
            && d.close().is_ok()
        {
            ok += 1;
        }
    }
    MARKS[slot as usize].store(ok, Relaxed);
    sys::thread_exit()
}

/// Every CPU takes OBJ in calls on one table: all the rounds of all of them
/// succeed, and the table holds what it did.
fn lock_under_load() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    let c = channel(QUIET)?;
    CHANNEL.store(c.raw().0, Relaxed);
    let before = sys::process_handles(&own()).map_err(|_| "PROCESS_HANDLES failed")?;
    let mut kept = [None, None, None];
    for cpu in 1..n.min(4) {
        kept[cpu - 1] = Some(spawn_on(
            cpu - 1,
            cpu,
            churn_handles,
            (cpu - 1) as u64,
            TEST_PRIORITY,
        )?);
    }
    let mut mine = 0;
    for _ in 0..ROUNDS {
        if let Ok(d) = sys::handle_duplicate(&c, Rights::NONE)
            && d.close().is_ok()
        {
            mine += 1;
        }
    }
    let done = wait_for(|| (0..n - 1).all(|i| mark(i) != 0));
    let rounds: u64 = (0..n - 1).map(mark).sum::<u64>() + mine;
    let_run()?;
    for t in kept.into_iter().flatten() {
        close(t)?;
    }
    let after = sys::process_handles(&own()).map_err(|_| "PROCESS_HANDLES failed")?;
    close(c)?;
    check(done, "a CPU did not finish its rounds")?;
    check(
        rounds == ROUNDS * n as u64,
        "a call on one CPU failed while the others held OBJ",
    )?;
    check(before.live == after.live, "the table lost or kept a handle")?;
    println!("smp: {} calls on {n} CPUs, each took OBJ", rounds);
    Ok(())
}

/// Runs at EL0 until mark 3 says to stop: mark `slot` moves.
extern "C" fn spin_marked(slot: u64) -> ! {
    while MARKS[3].load(Relaxed) == 0 {
        MARKS[slot as usize].fetch_add(1, Relaxed);
    }
    sys::thread_exit()
}

/// Calls the kernel until mark 3 says to stop, so that a good part of its
/// time is system time: mark `slot` moves.
extern "C" fn call_marked(slot: u64) -> ! {
    while MARKS[3].load(Relaxed) == 0 {
        let _ = sys::clock_now();
        MARKS[slot as usize].fetch_add(1, Relaxed);
    }
    sys::thread_exit()
}

/// The times of a thread that calls the kernel on another CPU: read from
/// CPU 0 while it runs, its time is what it ran (the stretch it is in
/// included), and both its system part and its user part are a share of it.
fn time_across_cpus() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    let t = spawn_on(0, 1, call_marked, 0, TEST_PRIORITY)?;
    pause(10_000_000);
    // Read again and again while it runs: it is at EL0 for two thirds of
    // them, where its stretch is open, and in the kernel for the rest.
    let (mut sane, mut last) = (true, (0, 0));
    for _ in 0..40 {
        pause(1_000_000);
        let (ran, system) = sys::thread_times(&t).map_err(|_| "thread_times failed")?;
        let (ran_ns, system_ns) = (time::ticks_to_ns(ran), time::ticks_to_ns(system));
        sane &= ran_ns >= last.0
            && system_ns >= ran_ns / 20
            && system_ns <= ran_ns / 20 * 19
            && ran_ns < 4_000_000_000;
        last = (ran_ns, system_ns);
    }
    let moved = mark(0) != 0;
    MARKS[3].store(1, Relaxed);
    let ended = wait_for(|| sys::thread_info(&t).is_ok_and(|i| i.state == abi::ThreadState::Ended));
    let_run()?;
    close(t)?;
    let (ran_ns, system_ns) = last;
    check(
        moved && ended,
        "the thread on the other CPU did not run and stop",
    )?;
    check(
        sane && ran_ns >= 40_000_000,
        "the time of a thread on another CPU is not what it ran, with a share in the kernel",
    )?;
    println!("smp: a thread at EL0 on CPU 1 ran {ran_ns} ns, {system_ns} ns of them in the kernel");
    Ok(())
}

/// The handler of the entry of the thread on another CPU: counts, and notes
/// the counter at which it began.
unsafe fn signalled() {
    MARKS[2].store(time::now(), Relaxed);
    MARKS[1].fetch_add(1, Relaxed);
}

rt::upcall_entry!(signalled_entry, signalled);

/// Binds the entry, then runs at EL0 with no call at all until mark 3 says
/// to stop: the request of another CPU has to bring it into the kernel.
extern "C" fn signalled_thread(_: u64) -> ! {
    // SAFETY: the handler touches the marks alone.
    unsafe {
        let _ = rt::upcall::bind(signalled_entry);
        let _ = rt::upcall::enable();
    }
    MARKS[0].store(1, Relaxed);
    while MARKS[3].load(Relaxed) == 0 {
        spin_loop();
    }
    sys::thread_exit()
}

/// Rounds of the signal test.
const SIGNALS: usize = 100;

/// A thread at EL0 on CPU 1 in a loop with no call gets thread_upcall_request
/// from CPU 0 (SMP stage 4, S5x): its CPU enters the kernel for it, and the
/// handler runs. The time from the request to the handler, in counter
/// ticks, is printed (rtbench-style row S5x).
fn signal_across_cpus() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    let t = spawn_on(0, 1, signalled_thread, 0, TEST_PRIORITY)?;
    let ready = wait_for(|| mark(0) == 1);
    let mut latency = [0u64; SIGNALS];
    let mut all = ready;
    for slot in latency.iter_mut() {
        if !all {
            break;
        }
        let seen = mark(1);
        let before = time::now();
        all = sys::thread_upcall_request(&t).is_ok() && wait_for(|| mark(1) > seen);
        *slot = mark(2).saturating_sub(before);
        pause(100_000);
    }
    MARKS[3].store(1, Relaxed);
    let ended = wait_for(|| sys::thread_info(&t).is_ok_and(|i| i.state == abi::ThreadState::Ended));
    let_run()?;
    close(t)?;
    check(
        ready && all && ended,
        "a request did not reach the thread at EL0 on the other CPU",
    )?;
    latency.sort_unstable();
    println!(
        "smp: signal to a thread at EL0 on CPU 1: median {} ticks, longest {} ticks of {SIGNALS} (counter {} Hz)",
        latency[SIGNALS / 2],
        latency[SIGNALS - 1],
        time::frequency()
    );
    Ok(())
}

/// The text a thread on CPU 2 writes to the log.
const MARKER: &[u8] = b"smp log marker of a thread on CPU 2\n";

extern "C" fn write_marker(_: u64) -> ! {
    let _ = sys::debug_write(&resource(), MARKER);
    MARKS[0].store(1, Relaxed);
    sys::thread_exit()
}

/// The ring of a CPU is its own (SMP stage 3, decision of review 3): a
/// thread on CPU 2 writes a line, which lands in the ring of CPU 2, and CPU 0
/// reads that ring with `log_peek_other`, as the driver of the UART does,
/// finds the line there and in no other ring, and finds it again at the same
/// cursor: the read changed nothing.
fn log_across_cpus() -> Outcome {
    let n = cpus()?;
    if n < 3 {
        return Ok(());
    }
    reset_marks();
    let t = spawn_on(0, 2, write_marker, 0, TEST_PRIORITY)?;
    let wrote = wait_for(|| mark(0) == 1);
    let_run()?;
    close(t)?;
    check(wrote, "the thread on CPU 2 did not write")?;
    let mut records: [[u8; abi::LOG_RECORD]; abi::LOG_BATCH] =
        [[0; abi::LOG_RECORD]; abi::LOG_BATCH];
    let mut found = [0u32; 8];
    for _pass in 0..2 {
        for (k, slot) in found.iter_mut().enumerate().take(n).skip(1) {
            let mut next = 1;
            loop {
                let Ok((batch, after)) =
                    sys::log_peek_other(&resource(), k as u64, next, &mut records)
                else {
                    return Err("log_peek_other failed for a CPU that is up");
                };
                for r in &records[..(batch.count as usize).min(abi::LOG_BATCH)] {
                    let len = usize::from(r[abi::LOG_LEN_AT]);
                    let text = &r[abi::LOG_TEXT_AT..abi::LOG_TEXT_AT + len.min(abi::LOG_TEXT)];
                    if text == MARKER {
                        *slot += 1;
                    }
                }
                if batch.left == 0 {
                    break;
                }
                next = after;
            }
        }
    }
    // The kth other CPU of CPU 0 is CPU k: the line is in ring 2, twice (two
    // passes), and in no other.
    check(
        found[2] == 2 && found[1] == 0 && found[3] == 0,
        "the line of CPU 2 was not in its ring alone, twice",
    )?;
    let past = sys::log_peek_other(&resource(), n as u64, 1, &mut records);
    check(
        past == Err(Error::InvalidArgs),
        "a peek at a CPU that does not exist was not refused",
    )?;
    println!("smp: the line of a thread on CPU 2 is in the ring of CPU 2, read from CPU 0 twice");
    Ok(())
}

/// The service of the raise test: takes a request, and, while it works on
/// it, watches its own priority until it is the one the client was raised
/// to, or two seconds pass; mark 0 is what it saw last. Then it answers.
extern "C" fn serve_until_raised(_: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    if let Ok(Received::Message { token, .. }) = sys::receive(&c)
        && let Ok(own) = sys::self_thread()
    {
        let level = |t: &Handle<Thread>| sys::thread_info(t).map_or(0, |i| u64::from(i.priority));
        let limit = now() + WAIT_NS;
        loop {
            let seen = level(&own);
            MARKS[0].store(seen, Relaxed);
            if seen >= u64::from(RAISED) || now() > limit {
                break;
            }
            spin_loop();
        }
        let _ = token.reply(&[]);
        let _ = own.close();
    }
    MARKS[3].store(1, Relaxed);
    sys::thread_exit()
}

/// The level the client of the raise test is raised to.
const RAISED: u8 = 40;

/// A client on CPU 1 waits for the reply of a service on CPU 2, which works
/// on its request at the client's level. Another thread raises the client
/// (thread_set_priority, a command to CPU 1, which moves the client and goes
/// on along the chain of requests, spec 6.6): the service, on CPU 2, is
/// raised by a second command, and sees its own priority change.
fn raise_across_cpus() -> Outcome {
    let n = cpus()?;
    if n < 3 {
        return Ok(());
    }
    reset_marks();
    let c = channel(QUIET)?;
    CHANNEL.store(c.raw().0, Relaxed);
    let server = spawn_on(0, 2, serve_until_raised, 0, LEVEL)?;
    pause(20_000_000);
    let client = spawn_on(1, 1, ask_once, 0, LEVEL)?;
    pause(30_000_000);
    let before = mark(0);
    sys::thread_set_priority(&client, RAISED, Policy::Fifo).map_err(|_| "the raise failed")?;
    let done = wait_for(|| mark(1) != 0 && mark(3) != 0);
    let (seen, replied) = (mark(0), mark(1));
    let_run()?;
    for t in [server, client] {
        close(t)?;
    }
    close(c)?;
    check(done && replied == 1, "the client did not get its reply")?;
    check(
        before == u64::from(LEVEL),
        "the service did not work at its client's level before the raise",
    )?;
    check(
        seen >= u64::from(RAISED),
        "a raise of the client did not reach its service on another CPU",
    )?;
    println!("smp: a client raised on CPU 1 raised its service on CPU 2 from {before} to {seen}");
    Ok(())
}

/// Makes a timer, arms it for 30 ms on this CPU, and says which (marks 1 and
/// 2: the handles of the channel and of the timer).
extern "C" fn arm_timer(_: u64) -> ! {
    let made = sys::channel_create(QUIET).and_then(|c| {
        let t = sys::timer_create(&c, QUIET)?;
        let deadline = time::ticks_to_ns(time::now()) + 30_000_000;
        sys::timer_set(&t, deadline)?;
        Ok((c, t))
    });
    if let Ok((c, t)) = made {
        MARKS[1].store(c.into_raw().0, Relaxed);
        MARKS[2].store(t.into_raw().0, Relaxed);
        MARKS[0].store(1, Relaxed);
    } else {
        MARKS[0].store(2, Relaxed);
    }
    while MARKS[3].load(Relaxed) == 0 {
        spin_loop();
    }
    sys::thread_exit()
}

/// A timer a thread on CPU 1 armed lives in the heap of CPU 1: CPU 0 may
/// neither cancel nor arm it (BAD_STATE), and when CPU 0 lets go its last
/// handle while it is armed, CPU 1 takes it off its heap and frees it, so
/// that its deadline, which passes meanwhile, finds nothing there.
fn timer_across_cpus() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    let thread = spawn_on(0, 1, arm_timer, 0, TEST_PRIORITY)?;
    let armed = wait_for(|| mark(0) != 0);
    check(
        armed && mark(0) == 1,
        "the thread on CPU 1 did not arm its timer",
    )?;
    let channel = Handle::<Channel>::from_raw(abi::Handle(mark(1)));
    let timer = Handle::<Timer>::from_raw(abi::Handle(mark(2)));
    let cancelled = sys::timer_cancel(&timer);
    let rearmed = sys::timer_set(&timer, time::ticks_to_ns(time::now()) + 1_000_000_000);
    // The last handle goes on this CPU, while the timer is armed on CPU 1.
    close(timer)?;
    pause(100_000_000);
    close(channel)?;
    MARKS[3].store(1, Relaxed);
    let ended =
        wait_for(|| sys::thread_info(&thread).is_ok_and(|i| i.state == abi::ThreadState::Ended));
    let_run()?;
    close(thread)?;
    check(
        cancelled == Err(Error::BadState) && rearmed == Err(Error::BadState),
        "a timer armed on another CPU was cancelled or armed again from this one",
    )?;
    check(ended, "the thread on CPU 1 did not stop")?;
    println!(
        "smp: a timer armed on CPU 1 was let go from CPU 0, its deadline passed, the kernel went on"
    );
    Ok(())
}

/// The process the killer of the reply test ends, by its handle.
static VICTIM: AtomicU64 = AtomicU64::new(0);

/// The priority of the client of the reply test: the kernel built with
/// `window-probe` holds the end of a thread at it until its reply was posted
/// and widens the window between the post and the flush (kernel cmd::window).
const WINDOW_LEVEL: u8 = 17;
/// The killer's, above the client's.
const KILLER: u8 = 18;

/// Says it is about to end the victim, and ends it.
extern "C" fn kill_victim(_: u64) -> ! {
    let p = Handle::<Process>::borrowed(abi::Handle(VICTIM.load(Relaxed)));
    MARKS[0].store(1, SeqCst);
    MARKS[1].store(if sys::process_kill(&p).is_ok() { 1 } else { 2 }, SeqCst);
    sys::thread_exit()
}

/// A client on CPU 1 waits for the reply of init on CPU 0; the process of
/// the client is killed, its end on CPU 1 begins, and the reply goes out:
/// the CPU of the client ends it while the wake that the reply posted for it
/// is on its way from CPU 0. The wake finds the thread ended and does
/// nothing; the kernel goes on (the kernel built with `window-probe` makes
/// the order sure and prints the line xtask looks for).
fn client_ends_with_reply_on_its_way() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    let c = channel(QUIET)?;
    let send = copy_raw(&c, Rights::SEND | Rights::TRANSFER)?;
    SPAWN_CPU.store(2, Relaxed);
    let kid = Kid::load(LEAF_QUOTA, 16, WINDOW_LEVEL);
    SPAWN_CPU.store(0, Relaxed);
    let kid = kid?;
    kid.start()?;
    kid.serve(Role::Send, &[1], &[Gift::Given(send)])?;
    VICTIM.store(kid.process.raw().0, Relaxed);
    let Ok(Received::Message { token, .. }) = sys::receive(&c) else {
        return Err("the client's request did not come");
    };
    let killer = spawn_on(0, 1, kill_victim, 0, KILLER)?;
    check(
        wait_for(|| mark(0) != 0),
        "the killer on CPU 1 did not start",
    )?;
    // The CPUs see the gate of the process meanwhile: its end waits for the
    // reply, which follows.
    pause(3_000_000);
    let _ = token.reply(&[]);
    let done = wait_for(|| mark(1) != 0);
    let state = kid.end();
    let_run()?;
    close(killer)?;
    kid.close()?;
    close(c)?;
    check(done && mark(1) == 1, "process_kill of the client failed")?;
    check(
        state == Ok(ProcessState::Killed),
        "the client's process did not end killed",
    )?;
    println!(
        "smp: a client on CPU 1 ended with the reply from CPU 0 on its way, the kernel went on"
    );
    Ok(())
}

/// Makes threads of init's own process that never start, and lets them go,
/// until mark 3 says to stop; mark 0 counts them. Each takes a message
/// buffer page into the process.
extern "C" fn make_threads(_: u64) -> ! {
    while MARKS[3].load(Relaxed) == 0 {
        let mut x = [0; 10];
        x[0] = own().raw().0;
        x[1] = 0x1000;
        x[4] = LOW.into();
        x[5] = Policy::Fifo as u64;
        x[6] = buffer(3) as u64;
        // SAFETY: the thread never starts, so it runs nothing.
        let after = unsafe { sys::raw::<{ Call::ThreadCreate.number() }>(x) };
        if Error::from_code(after[0]).is_none() {
            let _ = Handle::<Thread>::from_raw(abi::Handle(after[1])).close();
            MARKS[0].fetch_add(1, Relaxed);
        }
    }
    sys::thread_exit()
}

/// The priority at which the kernel built with `window-probe` takes 1 ms
/// between the two sections of mem_map and counts the passes of its checks
/// (kernel cmd::window).
const GAP_LEVEL: u8 = 16;
/// Calls of mem_map the kernel counts.
const GAP_CALLS: u64 = 20;

/// A thread on another CPU makes threads in init's process, each of which
/// puts a message buffer into it, while init maps pages into the same
/// process: each mem_map makes its checks once and goes on, whatever joins
/// the process between its sections (the kernel built with `window-probe`
/// leaves 1 ms between them and says how many passes the worst call took).
fn mapping_while_threads_join() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    let m = sys::mem_create(PAGE as u64).map_err(|_| "mem_create failed")?;
    let maker = spawn_on(0, 1, make_threads, 0, LOW)?;
    sys::thread_set_priority(&me(), GAP_LEVEL, Policy::Fifo).map_err(|_| "init lowered itself")?;
    let mut mapped = 0;
    for i in 0..GAP_CALLS as usize {
        let at = WINDOW + i * PAGE;
        if sys::mem_map(&own(), &m, 0, PAGE as u64, at, Access::ReadWrite).is_ok() {
            mapped += 1;
            // SAFETY: nothing of init uses the page.
            let _ = unsafe { sys::mem_unmap(&own(), at, PAGE as u64) };
        }
    }
    sys::thread_set_priority(&me(), TEST_PRIORITY, Policy::Fifo)
        .map_err(|_| "init could not take its priority back")?;
    MARKS[3].store(1, Relaxed);
    let ended =
        wait_for(|| sys::thread_info(&maker).is_ok_and(|i| i.state == abi::ThreadState::Ended));
    let made = mark(0);
    let_run()?;
    close(maker)?;
    close(m)?;
    check(ended, "the thread on CPU 1 did not stop")?;
    check(mapped == GAP_CALLS, "a mem_map failed while threads joined")?;
    check(made > 0, "no thread was made meanwhile")?;
    println!(
        "smp: {mapped} mem_map calls while another CPU made {made} threads in the same process"
    );
    Ok(())
}

/// The priority of the service of the boost test: the kernel built with
/// `window-probe` keeps the owner of a thread at it from serving the thread's
/// end for 150 ms (kernel cmd::window).
const SERVICE_LEVEL: u8 = 15;

/// The thread the raiser of the boost test raises.
static RAISED_CLIENT: AtomicU64 = AtomicU64::new(0);

/// Raises and lowers the client of the boost test by one level for 300 ms,
/// which ends before the clients of the killed process are released (400 ms
/// after its threads ended in the kernel built with `window-probe`); it
/// cannot be a thread of CPU 0, which is busy with the end of the process
/// meanwhile.
extern "C" fn raise_and_lower(_: u64) -> ! {
    let client = Handle::<Thread>::borrowed(abi::Handle(RAISED_CLIENT.load(Relaxed)));
    let mut level = RAISED;
    let until = now() + 300_000_000;
    while now() < until {
        level = if level == RAISED { RAISED + 1 } else { RAISED };
        // Fails once the client was released and ended.
        let _ = sys::thread_set_priority(&client, level, Policy::Fifo);
        pause(500_000);
    }
    MARKS[2].store(1, Relaxed);
    sys::thread_exit()
}

/// A client on CPU 1 waits for the reply of a service in a child on CPU 2.
/// The child is killed from CPU 0; the end of its thread is on its way to
/// CPU 2, which has taken it and not served it yet, while a thread on CPU 3
/// raises the client again and again (thread_set_priority, on CPU 1, whose
/// chain of requests still finds the service by its number). The boost of
/// the service is left alone: no command stands in the queue of CPU 2 past
/// the release of the thread (the kernel built with `window-probe` keeps the
/// clients of the killed process waiting for it, panics when the boost is
/// posted and prints the line xtask looks for).
fn boost_of_a_service_that_ended() -> Outcome {
    let n = cpus()?;
    if n < 4 {
        return Ok(());
    }
    reset_marks();
    reset_kid_marks();
    let c = channel(QUIET)?;
    CHANNEL.store(c.raw().0, Relaxed);
    let receive = copy_raw(&c, Rights::RECEIVE | Rights::TRANSFER)?;
    SPAWN_CPU.store(3, Relaxed);
    let kid = Kid::load_under(LEAF_QUOTA, 16, RAISED, SERVICE_LEVEL);
    SPAWN_CPU.store(0, Relaxed);
    let kid = kid?;
    kid.start()?;
    kid.serve(Role::TakeThenWait, &[], &[Gift::Given(receive)])?;
    let client = spawn_on(1, 1, ask_once, 0, LEVEL)?;
    check(
        wait_for(|| kid_mark(child::SEEN) == 1),
        "the service did not take the request",
    )?;
    RAISED_CLIENT.store(client.raw().0, Relaxed);
    let raiser = spawn_on(2, 3, raise_and_lower, 0, LEVEL)?;
    sys::process_kill(&kid.process).map_err(|_| "process_kill of the service failed")?;
    let done = wait_for(|| mark(1) != 0);
    let state = kid.end();
    let raised = wait_for(|| mark(2) != 0);
    let_run()?;
    close(raiser)?;
    close(client)?;
    kid.close()?;
    close(c)?;
    check(raised, "the raiser did not end")?;
    check(done, "the client was not released when the service ended")?;
    check(
        state == Ok(ProcessState::Killed),
        "the process of the service did not end killed",
    )?;
    println!(
        "smp: a client on CPU 1 was raised while its service on CPU 2 ended, the kernel went on"
    );
    Ok(())
}
