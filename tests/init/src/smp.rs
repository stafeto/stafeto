// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of SMP stage 4 (decision 2): threads on every CPU, a service on
//! another CPU than its client, a gate that stops the threads of a process
//! on every CPU, the lock of objects under the calls of every CPU. On one
//! CPU each of them ends at once and passes; `cargo xtask smp-probe` runs
//! them on four, where each also prints the line xtask looks for.

use crate::harness::*;
use crate::processes::{Gift, Kid, LEAF_QUOTA, kid_mark, reset_kid_marks};
use abi::{Call, Error, Rights};
use core::hint::spin_loop;
use core::sync::atomic::Ordering::SeqCst;
use rt::sys::Received;

pub(crate) const TESTS: [Test; 7] = [
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
    let_run()?;
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
    sys::process_control(&kid.process, true, 0).map_err(|e| {
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
    let gone = snapshot();
    pause(30_000_000);
    let after = snapshot();
    kid.close()?;
    let_run()?;
    check(
        gone == after,
        "a thread of a killed process ran on another CPU",
    )?;
    println!("smp: suspend and kill stopped the threads of the child on {n} CPUs");
    Ok(())
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

/// The times of a thread that runs at EL0 on another CPU: read from CPU 0
/// while it runs, its time is what it ran (the stretch it is in included),
/// and its system part is a small share of it.
fn time_across_cpus() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    let t = spawn_on(0, 1, spin_marked, 0, TEST_PRIORITY)?;
    pause(40_000_000);
    let (ran, system) = sys::thread_times(&t).map_err(|_| "thread_times failed")?;
    let moved = mark(0) != 0;
    MARKS[3].store(1, Relaxed);
    let ended = wait_for(|| sys::thread_info(&t).is_ok_and(|i| i.state == abi::ThreadState::Ended));
    let_run()?;
    close(t)?;
    let (ran_ns, system_ns) = (time::ticks_to_ns(ran), time::ticks_to_ns(system));
    check(
        moved && ended,
        "the thread on the other CPU did not run and stop",
    )?;
    check(
        (30_000_000..4_000_000_000).contains(&ran_ns),
        "the time of a thread at EL0 on another CPU is not what it ran",
    )?;
    check(
        system_ns < ran_ns / 2,
        "a thread at EL0 on another CPU has most of its time in the kernel",
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
    for pass in 0..2 {
        for k in 1..n {
            let (mut next, mut seen) = (1, 0);
            loop {
                let Ok((batch, after)) =
                    sys::log_peek_other(&resource(), k as u64, next, &mut records)
                else {
                    return Err("log_peek_other failed for a CPU that is up");
                };
                seen += batch.count;
                for r in &records[..(batch.count as usize).min(abi::LOG_BATCH)] {
                    let len = usize::from(r[abi::LOG_LEN_AT]);
                    let text = &r[abi::LOG_TEXT_AT..abi::LOG_TEXT_AT + len.min(abi::LOG_TEXT)];
                    if text == MARKER {
                        found[k] += 1;
                    }
                }
                if batch.left == 0 {
                    break;
                }
                next = after;
            }
            let _ = (pass, seen);
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
