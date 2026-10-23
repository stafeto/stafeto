// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of SMP stage 4 (decision 2): threads on every CPU, a service on
//! another CPU than its client, a gate that stops the threads of a process
//! on every CPU, the lock of objects under the calls of every CPU. On one
//! CPU each of them ends at once and passes; `cargo xtask smp-probe` runs
//! them on four, where each also prints the line xtask looks for.

use crate::harness::*;
use crate::processes::{
    Gift, KID_PATIENCE_NS, KID_WAIT_NS, Kid, LEAF_QUOTA, SPAWN_CPU, kid_mark, quota_of,
    reset_kid_marks, set_kid_mark,
};
use crate::timers::timer_at;
use crate::transfers::copy_raw;
use abi::{Access, Call, Error, ProcessState, Rights};
use core::hint::spin_loop;
use core::sync::atomic::Ordering::{Acquire, Release, SeqCst};
use rt::sys::Received;

pub(crate) const TESTS: [Test; 28] = [
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
    ("smp_lines_of_every_cpu_come_whole", whole_lines_across_cpus),
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
        "smp_exec_map_of_a_process_killed_meanwhile_fails",
        exec_map_of_a_killed_process,
    ),
    (
        "smp_spawn_with_its_start_channel_closed_meanwhile_fails",
        spawn_with_the_start_channel_closed,
    ),
    (
        "smp_spawn_with_its_exit_channel_closed_meanwhile_fails",
        spawn_with_the_exit_channel_closed,
    ),
    (
        "smp_spawn_by_a_process_that_ends_meanwhile_leaves_nothing",
        spawn_by_a_process_that_ends,
    ),
    (
        "smp_boost_leaves_a_service_that_ended_on_its_cpu_alone",
        boost_of_a_service_that_ended,
    ),
    (
        "smp_processes_keep_their_pages_across_asid_generations",
        asids_across_cpus,
    ),
    (
        "smp_unmap_reaches_a_thread_on_another_cpu",
        unmap_across_cpus,
    ),
    (
        "smp_asid_of_a_process_that_ended_is_clean_on_every_cpu",
        asid_after_end_across_cpus,
    ),
    (
        "smp_process_of_threads_being_woken_is_killed_from_another_cpu",
        kill_of_threads_being_woken,
    ),
    (
        "smp_calls_that_make_handles_meet_the_end_of_their_process",
        calls_that_meet_the_end_of_their_process,
    ),
    (
        "smp_thread_info_of_a_client_with_its_wake_on_the_way",
        info_of_a_client_being_woken,
    ),
    (
        "smp_request_before_a_receive_waits_ends_it",
        request_before_receive_waits,
    ),
    (
        "smp_request_before_a_send_waits_ends_it",
        request_before_send_waits,
    ),
    (
        "smp_request_with_a_handle_is_taken_in_one_section",
        request_with_a_handle_is_taken_in_one_section,
    ),
    ("smp_measures_of_stage_6", stage_6_measures),
    ("smp_litmus_tests_of_memory_order", litmus_tests),
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

/// The number of CPUs that are up, as object_info CPU gives it. A count by
/// the highest CPU thread_create takes would read a message buffer page
/// that a thread of the test before still holds, until its cleanup ran, as
/// a CPU that is not there (INVALID_ARGS for both), and the tests of more
/// than one CPU would pass without running (#436). thread_create still
/// refuses the CPU past the last: the kernel checks the CPU before the
/// buffer, so the answer does not depend on the page.
fn cpus() -> Result<usize, &'static str> {
    let n = sys::cpu_info(0).map_err(|_| "object_info CPU failed")?.cpus as usize;
    let mut x = [0; 10];
    x[0] = own().raw().0;
    x[1] = 0x1000;
    x[4] = LOW.into();
    x[5] = Policy::Fifo as u64 | ((n as u64 + 1) << abi::THREAD_CPU_SHIFT);
    x[6] = buffer(3) as u64;
    // SAFETY: the call fails before it makes a thread.
    let after = unsafe { sys::raw::<{ Call::ThreadCreate.number() }>(x) };
    if Error::from_code(after[0]) != Some(Error::InvalidArgs) {
        return Err("thread_create took a CPU past those that are up");
    }
    Ok(n)
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
/// at it (kernel window).
const LAG_LEVEL: u8 = 19;

/// Waits for the timer's notification and marks when it came (mark 2).
extern "C" fn timer_listener(_: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    if sys::receive(&c).is_ok() {
        MARKS[2].store(now(), SeqCst);
    }
    sys::thread_exit()
}

/// How long every CPU churns the table in the lock test: the rounds it
/// manages in that time are as many as its host lets it, a few thousand on
/// TCG and some hundred thousand on the real processor (HVF).
const TORTURE_NS: u64 = 250_000_000;
/// Rounds between two readings of the clock.
const TORTURE_BATCH: u64 = 64;
/// The quota of the child that spins on every CPU: its threads, buffers and
/// tables.
const SPIN_QUOTA: u64 = LEAF_QUOTA + 10 * PAGE as u64;

static TORTURE_UNTIL: AtomicU64 = AtomicU64::new(0);
/// Calls made and calls that succeeded, of each CPU's thread.
static TORTURE: [[AtomicU64; 2]; 4] = [const { [AtomicU64::new(0), AtomicU64::new(0)] }; 4];

/// Duplicates and closes a handle of init's table until the deadline, as
/// every CPU does at once: each takes OBJ, and the table is one. Gives the
/// rounds made and the rounds that went through.
fn churn(c: &Handle<Channel>) -> (u64, u64) {
    let (mut tried, mut ok) = (0, 0);
    let until = TORTURE_UNTIL.load(Relaxed);
    while now() < until {
        for _ in 0..TORTURE_BATCH {
            tried += 1;
            if let Ok(d) = sys::handle_duplicate(c, Rights::NONE)
                && d.close().is_ok()
            {
                ok += 1;
            }
        }
    }
    (tried, ok)
}

extern "C" fn churn_handles(slot: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    let (tried, ok) = churn(&c);
    TORTURE[slot as usize][0].store(tried, Relaxed);
    TORTURE[slot as usize][1].store(ok, Relaxed);
    MARKS[slot as usize].store(1, Relaxed);
    sys::thread_exit()
}

/// Every CPU takes OBJ in calls on one table for TORTURE_NS: all the rounds
/// of all of them succeed, and the table holds what it did.
fn lock_under_load() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    let c = channel(QUIET)?;
    CHANNEL.store(c.raw().0, Relaxed);
    let before = sys::process_handles(&own()).map_err(|_| "PROCESS_HANDLES failed")?;
    let began = now();
    TORTURE_UNTIL.store(began + TORTURE_NS, Relaxed);
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
    let (tried, ok) = churn(&c);
    let done = wait_for(|| (0..n.min(4) - 1).all(|i| mark(i) != 0));
    let (mut tried_all, mut ok_all) = (tried, ok);
    for row in &TORTURE[..n.min(4) - 1] {
        tried_all += row[0].load(Relaxed);
        ok_all += row[1].load(Relaxed);
    }
    let_run()?;
    for t in kept.into_iter().flatten() {
        close(t)?;
    }
    let after = sys::process_handles(&own()).map_err(|_| "PROCESS_HANDLES failed")?;
    close(c)?;
    check(done, "a CPU did not finish its rounds")?;
    check(
        ok_all == tried_all && tried_all > 0,
        "a call on one CPU failed while the others held OBJ",
    )?;
    check(before.live == after.live, "the table lost or kept a handle")?;
    println!(
        "smp: {ok_all} calls on {n} CPUs in {} ms, each took OBJ",
        (now() - began) / 1_000_000
    );
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
    // Its time only grows, in each reading. The share in the kernel is
    // read once, at the last: a reading that finds the CPU of the thread
    // stopped by the host inside the kernel shows a share above the bound.
    let (mut grows, mut last) = (true, (0, 0));
    for _ in 0..40 {
        pause(1_000_000);
        let (ran, system) = sys::thread_times(&t).map_err(|_| "thread_times failed")?;
        let (ran_ns, system_ns) = (time::ticks_to_ns(ran), time::ticks_to_ns(system));
        grows &= ran_ns >= last.0 && ran_ns < 4_000_000_000;
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
        grows && ran_ns >= 40_000_000,
        "the time of a thread on another CPU is not what it ran",
    )?;
    check(
        system_ns >= ran_ns / 20 && system_ns <= ran_ns / 20 * 19,
        "the share of a thread on another CPU in the kernel is out of its bounds",
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

/// Whether a line that begins with `prefix` is in the ring of any CPU
/// other than this one (`log_peek_other`, as the driver of the UART reads
/// them): the way to see a line of the kernel that its CPU prints through the
/// driver, which may come late or after the end of the run.
fn ring_has_line(prefix: &[u8], n: usize) -> Result<bool, &'static str> {
    let mut records: [[u8; abi::LOG_RECORD]; abi::LOG_BATCH] =
        [[0; abi::LOG_RECORD]; abi::LOG_BATCH];
    for cpu in 1..n {
        let mut next = 1;
        loop {
            let Ok((batch, after)) =
                sys::log_peek_other(&resource(), cpu as u64, next, &mut records)
            else {
                return Err("log_peek_other failed for a CPU that is up");
            };
            for r in &records[..(batch.count as usize).min(abi::LOG_BATCH)] {
                let len = usize::from(r[abi::LOG_LEN_AT]);
                let text = &r[abi::LOG_TEXT_AT..abi::LOG_TEXT_AT + len.min(abi::LOG_TEXT)];
                if text.starts_with(prefix) {
                    return Ok(true);
                }
            }
            if batch.left == 0 {
                break;
            }
            next = after;
        }
    }
    Ok(false)
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

/// Lines each CPU writes in `whole_lines_across_cpus`.
const WHOLE_LINES: u64 = 40;

/// Waits for mark 1, then writes WHOLE_LINES lines of 64 bytes, each with
/// one debug_write, as `whole_line` makes them for CPU `cpu`; mark 0 counts
/// the threads that wrote all.
extern "C" fn write_whole_lines(cpu: u64) -> ! {
    while mark(1) == 0 {
        spin_loop();
    }
    for i in 0..WHOLE_LINES {
        let _ = sys::debug_write(&resource(), &whole_line(cpu, i));
    }
    MARKS[0].fetch_add(1, Release);
    sys::thread_exit()
}

/// `smp whole line C NN ` and `x` up to 63 bytes, then a newline: the line
/// xtask counts (`init_tests_in`).
fn whole_line(cpu: u64, i: u64) -> [u8; 64] {
    let mut line = [b'x'; 64];
    line[..15].copy_from_slice(b"smp whole line ");
    line[15] = b'0' + cpu as u8;
    line[16] = b' ';
    line[17] = b'0' + (i / 10) as u8;
    line[18] = b'0' + (i % 10) as u8;
    line[19] = b' ';
    line[63] = b'\n';
    line
}

/// Lines of the CPUs do not mix (#432, #436): a thread on every other CPU
/// and init on CPU 0 write WHOLE_LINES lines of 64 bytes each at the same
/// time, one debug_write a line, while the kernel has the console's port and
/// shows each record from the CPU that wrote it. xtask finds every line
/// whole: debug_write writes its record under OBJ, one CPU at a time.
fn whole_lines_across_cpus() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    let mut threads = [const { None }; 3];
    for cpu in 1..n.min(4) {
        threads[cpu - 1] = Some(spawn_on(
            cpu - 1,
            cpu,
            write_whole_lines,
            cpu as u64,
            TEST_PRIORITY,
        )?);
    }
    let others = (n.min(4) - 1) as u64;
    MARKS[1].store(1, Release);
    for i in 0..WHOLE_LINES {
        let _ = sys::debug_write(&resource(), &whole_line(0, i));
    }
    let wrote = wait_for(|| MARKS[0].load(Acquire) == others);
    let_run()?;
    for t in threads.into_iter().flatten() {
        close(t)?;
    }
    check(wrote, "a thread on another CPU did not write its lines")?;
    println!(
        "smp: {} CPUs wrote {} lines of 64 bytes at the same time",
        others + 1,
        (others + 1) * WHOLE_LINES
    );
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
    let client = spawn_on(1, 1, ask_once, 0, LEVEL)?;
    // The service marks its level once it works on the request; the raise
    // comes after that, whenever the host lets it.
    let taken = wait_for(|| mark(0) != 0);
    let before = mark(0);
    if !taken {
        let_run()?;
        for t in [server, client] {
            close(t)?;
        }
        close(c)?;
        return Err("the service did not take the request of the client");
    }
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

/// Threads of the process the test kills, and how many times it does.
const KILL_THREADS: usize = 8;
const KILL_ROUNDS: usize = 50;
/// The level of those threads: the kernel built with `window-probe` waits
/// inside the removal from a ready queue for the items of this level
/// (kcore READY_GAP_LEVEL).
const KILL_LEVEL: u8 = 9;
/// The marks of Role::SmpTimed: the instant its timers fire, and the first
/// of the marks of its threads.
const TIMED_AT: usize = 20;
const TIMED_MARKS: usize = 21;

/// A process of eight threads on CPUs 1 to 3, all waiting for timers that
/// fire at one instant, is killed from CPU 0 shortly before that instant,
/// fifty times in a row. The timers wake the threads on
/// their CPUs, which take them off their ready queues one after the other
/// (and the kernel built with `window-probe` waits inside each removal),
/// while the end of the process, on CPU 0, takes the threads out of the
/// scheduler. A link read or written from the wrong CPU stops the kernel
/// (#438).
fn kill_of_threads_being_woken() -> Outcome {
    let n = cpus()?;
    if n < 4 {
        return Ok(());
    }
    let mut margin = 60_000_000;
    let mut round = 0;
    while round < KILL_ROUNDS {
        let kid = Kid::load(LEAF_QUOTA + 60 * PAGE as u64, 40, KILL_LEVEL)?;
        reset_kid_marks();
        // Far enough for the threads to be made and to wait.
        let at = now() + margin;
        set_kid_mark(TIMED_AT, at);
        kid.start()?;
        kid.serve(
            Role::SmpTimed,
            &[KILL_THREADS as u64, KILL_LEVEL.into(), n as u64],
            &[Gift::Own],
        )?;
        let_run()?;
        let waiting = || (0..KILL_THREADS).all(|i| kid_mark(TIMED_MARKS + i) != 0);
        if !(wait_for(waiting) && now() < at) {
            // The host held the run back past the instant: the premise of
            // the round, not its property. Again, with twice the margin.
            kid.close()?;
            let_run()?;
            margin *= 2;
            check(
                margin <= 2_000_000_000,
                "the threads of the child never waited for their timers in time",
            )?;
            continue;
        }
        // The kernel built with `window-probe` holds the end of the process
        // until the timers fire (kernel window::hold_until_woken).
        let kill_at = at - 20_000_000;
        while now() < kill_at {
            spin_loop();
        }
        sys::process_kill(&kid.process).map_err(|_| "process_kill failed")?;
        let state = kid.end();
        kid.close()?;
        let_run()?;
        check(
            state == Ok(ProcessState::Killed),
            "the process of the waking threads did not end killed",
        )?;
        round += 1;
    }
    println!(
        "smp: a process of {KILL_THREADS} threads on CPUs 1 to 3 was killed {KILL_ROUNDS} times shortly before their timers fired"
    );
    Ok(())
}

/// The level of the thread whose timer_create the kernel built with
/// `window-probe` holds between its entry and its section, until its
/// process ended (kernel window::entry_gap).
const ENTRY_LEVEL: u8 = 7;
/// Processes the test ends, and the mark that counts the timers one makes.
const ENTRY_ROUNDS: usize = 200;
const TIMERS_MARK: usize = 12;

/// A thread on CPU 1 makes timers and closes them; init on CPU 0 ends its
/// process, 200 times. A call that entered the kernel before the end takes
/// its section after it, and the handle it makes has no table to go to: the
/// call fails with BAD_STATE (#438: the kernel stopped on an assertion that
/// the process of the caller lives).
fn calls_that_meet_the_end_of_their_process() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    for _ in 0..ENTRY_ROUNDS {
        // SPAWN_CPU counts from 1.
        SPAWN_CPU.store(2, Relaxed);
        let kid = Kid::load(LEAF_QUOTA + 4 * PAGE as u64, 16, ENTRY_LEVEL);
        SPAWN_CPU.store(0, Relaxed);
        let kid = kid?;
        reset_kid_marks();
        kid.start()?;
        kid.serve(Role::SmpTimers, &[], &[])?;
        check(
            wait_for(|| kid_mark(TIMERS_MARK) > 2),
            "the thread on CPU 1 made no timers",
        )?;
        sys::process_kill(&kid.process).map_err(|_| "process_kill failed")?;
        let state = kid.end();
        kid.close()?;
        let_run()?;
        check(
            state == Ok(ProcessState::Killed),
            "the process that made timers did not end killed",
        )?;
    }
    println!("smp: {ENTRY_ROUNDS} processes that made timers on CPU 1 were killed from CPU 0");
    Ok(())
}

/// The level of the client of the test of thread_info: the kernel built
/// with `window-probe` asks for the state of a thread at it as the reply
/// posts its wake (kernel window).
const INFO_LEVEL: u8 = 6;

/// A client on CPU 2 waits for the reply of init on CPU 0. The section of
/// the reply takes it out of its wait and posts the wake for CPU 2; before
/// that CPU serves it the thread is Waiting with nothing to wait for, which
/// object_info reports as Ready (#438: it stopped the kernel). The kernel
/// built with `window-probe` asks in that interval and prints the line xtask
/// looks for; init also asks, from its own CPU, all the time.
fn info_of_a_client_being_woken() -> Outcome {
    let n = cpus()?;
    if n < 3 {
        return Ok(());
    }
    reset_marks();
    let c = channel(QUIET)?;
    CHANNEL.store(c.raw().0, Relaxed);
    let client = spawn_on(0, 2, ask_once, 0, INFO_LEVEL)?;
    let Ok(Received::Message { token, .. }) = sys::receive(&c) else {
        return Err("the client's request did not come");
    };
    // The client waits for its reply on its CPU.
    pause(20_000_000);
    let _ = token.reply(&[]);
    let done = wait_for(|| {
        let state = sys::thread_info(&client).map(|i| i.state);
        mark(1) != 0 && matches!(state, Ok(abi::ThreadState::Ended) | Err(_))
    });
    let_run()?;
    close(client)?;
    close(c)?;
    check(done && mark(1) == 1, "the client did not get its reply")?;
    println!(
        "smp: the state of a client woken from another CPU was asked for all the time, none failed"
    );
    Ok(())
}

/// The process the killer of the reply test ends, by its handle.
static VICTIM: AtomicU64 = AtomicU64::new(0);

/// The priority of the client of the reply test: the kernel built with
/// `window-probe` holds the end of a thread at it until its reply was posted
/// and widens the window between the post and the flush (kernel window).
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
/// (kernel window).
const GAP_LEVEL: u8 = 16;
/// Calls of mem_map the kernel counts.
const GAP_CALLS: u64 = 20;

/// The priority at which the kernel built with `window-probe` holds the
/// portion of a mem_map RX outside OBJ, after the instruction cache, until
/// another CPU killed the process it maps into (kernel window).
const EXEC_LEVEL: u8 = 12;
/// How long the killer of the exec test waits after init marked its call.
const EXEC_KILL_NS: u64 = 200_000_000;

/// Waits for mark 2, which init sets right before its mem_map, then for
/// EXEC_KILL_NS, and ends the victim; mark 1 says it did.
extern "C" fn kill_victim_later(_: u64) -> ! {
    let p = Handle::<Process>::borrowed(abi::Handle(VICTIM.load(Relaxed)));
    while MARKS[2].load(SeqCst) == 0 {
        spin_loop();
    }
    pause(EXEC_KILL_NS);
    MARKS[1].store(if sys::process_kill(&p).is_ok() { 1 } else { 2 }, SeqCst);
    sys::thread_exit()
}

/// Init maps a page RX into a child while a thread on CPU 1 kills the child
/// EXEC_KILL_NS after init's mark: a call that lasted that long saw the kill
/// and fails with BAD_STATE.
/// The kernel built with `window-probe` holds the portion outside OBJ until
/// the kill, so that the portion has to look at the life of the process
/// again before it maps; elsewhere the kill comes after the call.
fn exec_map_of_a_killed_process() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    let kid = Kid::load(LEAF_QUOTA, 16, LEVEL)?;
    kid.start()?;
    let m = sys::mem_create(PAGE as u64).map_err(|_| "mem_create failed")?;
    VICTIM.store(kid.process.raw().0, Relaxed);
    let killer = spawn_on(0, 1, kill_victim_later, 0, KILLER)?;
    sys::thread_set_priority(&me(), EXEC_LEVEL, Policy::Fifo).map_err(|_| "init lowered itself")?;
    MARKS[2].store(1, SeqCst);
    let began = now();
    let mapped = sys::mem_map(&kid.process, &m, 0, PAGE as u64, WINDOW, Access::ReadExec);
    // The kill began during the call when the call lasted past its time.
    let killed_first = now() - began >= EXEC_KILL_NS;
    sys::thread_set_priority(&me(), TEST_PRIORITY, Policy::Fifo)
        .map_err(|_| "init could not take its priority back")?;
    let done = wait_for(|| mark(1) != 0);
    let state = kid.end();
    let_run()?;
    close(killer)?;
    close(m)?;
    kid.close()?;
    check(done && mark(1) == 1, "process_kill of the child failed")?;
    check(
        state == Ok(ProcessState::Killed),
        "the child did not end killed",
    )?;
    check(
        !killed_first || mapped == Err(Error::BadState),
        "a mem_map RX into a process killed during the call mapped its page",
    )?;
    println!(
        "smp: a mem_map RX {} the kill of its process: {mapped:?}",
        if killed_first {
            "lasted into"
        } else {
            "came before"
        }
    );
    Ok(())
}

/// The priority at which the kernel built with `window-probe` holds a
/// process_create between its two sections, with no section held, until
/// another thread closed a handle or the caller's process ended (kernel
/// window).
const SPAWN_LEVEL: u8 = 11;
/// How long the closer of the spawn tests waits after init marked its call.
const SPAWN_CLOSE_NS: u64 = 200_000_000;
/// The handle the closer closes.
static SPAWN_HANDLE: AtomicU64 = AtomicU64::new(0);

/// Waits for mark 2, which init sets right before its process_create, then
/// for SPAWN_CLOSE_NS, and closes SPAWN_HANDLE; mark 1 says whether it did
/// (1) or the close failed (2).
extern "C" fn close_later(_: u64) -> ! {
    while MARKS[2].load(SeqCst) == 0 {
        spin_loop();
    }
    pause(SPAWN_CLOSE_NS);
    // The raw call: the typed one stops the program on BAD_HANDLE, which is
    // the answer when the process_create took the handle first.
    let mut x = marked();
    x[0] = SPAWN_HANDLE.load(Relaxed);
    // SAFETY: handle_close only reads its registers.
    let closed = unsafe { sys::raw::<{ Call::HandleClose.number() }>(x) };
    MARKS[1].store(if closed[0] == 0 { 1 } else { 2 }, SeqCst);
    sys::thread_exit()
}

/// process_create with raw registers, for a call that may fail with
/// BAD_HANDLE (the typed call stops the program on it): the child's handle,
/// or why not.
fn create_raw(x3: abi::Handle, x4: u64, x5: abi::Handle) -> Result<Handle<Process>, Error> {
    let x = crate::channels::raw_create(crate::channels::create_regs(x3, x4, x5));
    match Error::from_code(x[0]) {
        Some(e) => Err(e),
        None => Ok(Handle::from_raw(abi::Handle(x[1]))),
    }
}

/// Ends a child a spawn test got, if it got one.
fn end_child(made: Result<Handle<Process>, Error>) -> Outcome {
    if let Ok(child) = made {
        let killed = sys::process_kill(&child);
        close(child)?;
        check(killed.is_ok(), "the child of a spawn test did not end")?;
    }
    Ok(())
}

/// Init makes a process with a start channel (x5) while a thread on CPU 1
/// closes that handle SPAWN_CLOSE_NS after init's mark: a call that lasted
/// that long saw the close and fails with BAD_HANDLE, whether the child
/// took the channel or not; a kernel that looked at x5 only in its first
/// section would find its entry 0 without a handle to close behind it and
/// stop. The kernel built with `window-probe` holds the call between its
/// sections until the close; elsewhere the close comes after the call.
fn spawn_with_the_start_channel_closed() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    let start = channel(QUIET)?;
    SPAWN_HANDLE.store(start.raw().0, Relaxed);
    let closer = spawn_on(0, 1, close_later, 0, KILLER)?;
    sys::thread_set_priority(&me(), SPAWN_LEVEL, Policy::Fifo)
        .map_err(|_| "init lowered itself")?;
    MARKS[2].store(1, SeqCst);
    let began = now();
    let made = create_raw(abi::Handle(0), 0, start.raw());
    let closed_first = now() - began >= SPAWN_CLOSE_NS;
    sys::thread_set_priority(&me(), TEST_PRIORITY, Policy::Fifo)
        .map_err(|_| "init could not take its priority back")?;
    let done = wait_for(|| mark(1) != 0);
    let_run()?;
    close(closer)?;
    // The channel is the child's, or the closer closed it: init's handle
    // is not to be closed again.
    start.into_raw();
    check(done, "the closer of the start channel did not run")?;
    let error = made.as_ref().err().copied();
    check(
        !closed_first || error == Some(Error::BadHandle),
        "process_create with a start channel closed meanwhile failed otherwise",
    )?;
    end_child(made)?;
    println!("smp: process_create met the close of its start channel: {error:?}");
    Ok(())
}

/// The same with the exit channel (x3): the call fails with BAD_HANDLE when
/// the close came during it.
fn spawn_with_the_exit_channel_closed() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_marks();
    let base = channel(QUIET)?;
    let exit = session(&base, Rights::NOTIFY, CHILD, QUIET)?;
    SPAWN_HANDLE.store(exit.raw().0, Relaxed);
    let closer = spawn_on(0, 1, close_later, 0, KILLER)?;
    sys::thread_set_priority(&me(), SPAWN_LEVEL, Policy::Fifo)
        .map_err(|_| "init lowered itself")?;
    MARKS[2].store(1, SeqCst);
    let began = now();
    let made = create_raw(exit.raw(), QUIET.into(), abi::Handle(0));
    let closed_first = now() - began >= SPAWN_CLOSE_NS;
    sys::thread_set_priority(&me(), TEST_PRIORITY, Policy::Fifo)
        .map_err(|_| "init could not take its priority back")?;
    let done = wait_for(|| mark(1) != 0);
    let_run()?;
    close(closer)?;
    // The closer closed this handle, whatever the call did.
    exit.into_raw();
    close(base)?;
    let error = made.as_ref().err().copied();
    check(done, "the closer of the exit channel did not run")?;
    check(
        !closed_first || error == Some(Error::BadHandle),
        "process_create with an exit channel closed meanwhile failed otherwise",
    )?;
    end_child(made)?;
    println!("smp: process_create met the close of its exit channel: {error:?}");
    Ok(())
}

/// A child at SPAWN_LEVEL makes a child of its own (the loader's
/// process_create) while a thread on CPU 1 kills it SPAWN_CLOSE_NS after
/// init's mark: the kernel built with `window-probe` holds the call between
/// its sections until the kill, which then finds the caller ended and lets
/// its child go; the kernel stays up and the child ends killed.
fn spawn_by_a_process_that_ends() -> Outcome {
    let n = cpus()?;
    if n < 3 {
        return Ok(());
    }
    reset_marks();
    reset_kid_marks();
    // On CPU 2 (the value is the CPU plus one): init spins on CPU 0, and
    // the killer is on CPU 1.
    SPAWN_CPU.store(3, Relaxed);
    let kid = Kid::load(quota_of(Role::Grandparent), 16, SPAWN_LEVEL);
    SPAWN_CPU.store(0, Relaxed);
    let kid = kid?;
    kid.start()?;
    VICTIM.store(kid.process.raw().0, Relaxed);
    let killer = spawn_on(0, 1, kill_victim_later, 0, KILLER)?;
    let args = [LEAF_QUOTA, LOW.into(), 1];
    let gifts = [Gift::Own, Gift::Image, Gift::GrandchildExit, Gift::Marks];
    let served = kid.serve(Role::Grandparent, &args, &gifts);
    // The child is about to call process_create: the killer's clock starts.
    let about = wait_for(|| kid_mark(child::SEEN) != 0);
    MARKS[2].store(1, SeqCst);
    let done = wait_for(|| mark(1) != 0);
    // The kill returned after the teardown. A child that did not wait in the
    // kernel for it may have got as far as its request to init, which its
    // end cancels, so the state is read, and the ear is not waited on.
    let state = sys::process_state(&kid.process);
    let_run()?;
    close(killer)?;
    kid.close()?;
    served?;
    check(about, "the child did not come to its process_create")?;
    check(done && mark(1) == 1, "process_kill of the child failed")?;
    check(
        state == Ok(ProcessState::Killed),
        "the child that made a child did not end killed",
    )
}

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
    // A host that is busy starts CPU 1 late: the calls below begin when the
    // thread has made its first thread, so that they overlap its work.
    check(
        wait_for(|| mark(0) > 0),
        "the thread on CPU 1 made no thread",
    )?;
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
/// end for 150 ms (kernel window).
const SERVICE_LEVEL: u8 = 15;

/// The thread the raiser of the boost test raises.
static RAISED_CLIENT: AtomicU64 = AtomicU64::new(0);
static RAISES: AtomicU64 = AtomicU64::new(0);
static RAISES_FAILED: AtomicU64 = AtomicU64::new(0);

/// Raises and lowers the client of the boost test by one level until the
/// client is released (MARKS[1]), which the kernel built with `window-probe`
/// does 400 ms after the threads of the killed process ended: the raises
/// cover that window however late the process is killed on a loaded host. It
/// cannot be a thread of CPU 0, which is busy with the end of the process
/// meanwhile.
extern "C" fn raise_and_lower(_: u64) -> ! {
    let client = Handle::<Thread>::borrowed(abi::Handle(RAISED_CLIENT.load(Relaxed)));
    let mut level = RAISED;
    let limit = now() + 20_000_000_000;
    while MARKS[1].load(Relaxed) == 0 && now() < limit {
        level = if level == RAISED { RAISED + 1 } else { RAISED };
        // Fails once the client was released and ended.
        RAISES.fetch_add(1, Relaxed);
        if sys::thread_set_priority(&client, level, Policy::Fifo).is_err() {
            RAISES_FAILED.fetch_add(1, Relaxed);
        }
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
        "smp window  the raiser made {} requests, {} of them failed",
        RAISES.load(Relaxed),
        RAISES_FAILED.load(Relaxed)
    );
    // The kernel built with `window-probe` notes the boost it left alone in
    // the ring of the CPU that met it, and the driver of the UART shows that
    // ring when it can, which on a busy host is after the run ended: the
    // line xtask looks for is said from here, once the ring holds it.
    if ring_has_line(b"smp window  a boost of a thread that ended", n)? {
        println!("smp window  a boost of a thread that ended on its CPU was left alone");
    }
    println!(
        "smp: a client on CPU 1 was raised while its service on CPU 2 ended, the kernel went on"
    );
    Ok(())
}

/// The priority at which the kernel built with `window-probe` holds the
/// receive or the send of a thread, before its section, until a request for
/// its entry was made, so that the look under OBJ before it waits has to
/// find the request (kernel window).
const WAIT_LEVEL: u8 = 14;
/// The priority of the receiver whose section the kernel built with
/// `break-one-section` splits in two, after the room for the handles of the
/// request at the head.
const HEAD_LEVEL: u8 = 13;

/// What the threads of the probes of the window say: [0] the thread that
/// sends or waits is about to call, [1] its result, [2] the result of the
/// receiver, [5] the entries of its handler that ran. 1 is the outcome the
/// probe wants.
static STEPS: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
/// The raw value of the handle the sender of the probe carries.
static CARRIED: AtomicU64 = AtomicU64::new(0);

fn reset_steps() {
    for s in &STEPS {
        s.store(0, Relaxed);
    }
}

fn step(i: usize) -> u64 {
    STEPS[i].load(SeqCst)
}

/// The handler of the entry of the probes: counts.
unsafe fn counted() {
    STEPS[5].fetch_add(1, SeqCst);
}

rt::upcall_entry!(counted_entry, counted);

/// Binds and opens the entry of the calling thread.
fn open_entry() {
    // SAFETY: the handler touches the counter alone.
    unsafe {
        let _ = rt::upcall::bind(counted_entry);
        let _ = rt::upcall::enable();
    }
}

/// Waits in receive, with its entry open: step 1 is 1 when the call ended
/// Interrupted.
extern "C" fn waits_in_receive(_: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    open_entry();
    STEPS[0].store(1, SeqCst);
    let ended = matches!(sys::receive(&c), Err(Error::Interrupted));
    STEPS[1].store(if ended { 1 } else { 2 }, SeqCst);
    sys::thread_exit()
}

/// Waits in send to a channel nobody receives from, with its entry open.
extern "C" fn waits_in_send(_: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    open_entry();
    STEPS[0].store(1, SeqCst);
    let ended = matches!(sys::send(&c, &[1]), Err(Error::Interrupted));
    STEPS[1].store(if ended { 1 } else { 2 }, SeqCst);
    sys::thread_exit()
}

/// A thread at WAIT_LEVEL on CPU 1 is about to call `body`; once it is in
/// the kernel, a request for its entry from CPU 0 finds nothing to end (the
/// answer is Ok): the call has to end Interrupted, and the entry has to
/// come. The kernel built with `window-probe` holds the call out of OBJ
/// until the request was made, whenever it comes; the kernel without the
/// look under OBJ lets the call wait, and the test ends it by a second
/// request after the time is up.
fn request_ends_the_call(
    body: extern "C" fn(u64) -> !,
    what: &'static str,
    said: &'static str,
) -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    reset_steps();
    let c = channel(QUIET)?;
    CHANNEL.store(c.raw().0, Relaxed);
    let t = spawn_on(0, 1, body, 0, WAIT_LEVEL)?;
    let ready = wait_for(|| step(0) == 1);
    // The thread reaches the kernel, and the point of the probe.
    pause(20_000_000);
    let asked = sys::thread_upcall_request(&t);
    let ended = wait_for(|| step(1) != 0);
    if !ended {
        // It waits for ever: the request found no wait to end and the call
        // did not look. Another request ends it now.
        let _ = sys::thread_upcall_request(&t);
        wait_for(|| step(1) != 0);
    }
    let entered = wait_for(|| step(5) != 0);
    let_run()?;
    close(t)?;
    close(c)?;
    check(ready, "the thread did not reach its call")?;
    check(asked.is_ok(), "thread_upcall_request failed")?;
    check(ended, what)?;
    check(step(1) == 1, "the call did not end Interrupted")?;
    check(entered, "the entry of the thread did not come")?;
    println!("{said}");
    Ok(())
}

fn request_before_receive_waits() -> Outcome {
    request_ends_the_call(
        waits_in_receive,
        "a request made after the first look of receive was lost: the call waited",
        "smp: a request after the first look of receive ended the call Interrupted, the entry came",
    )
}

fn request_before_send_waits() -> Outcome {
    request_ends_the_call(
        waits_in_send,
        "a request made after the first look of send was lost: the call waited",
        "smp: a request after the first look of send ended the call Interrupted, the entry came",
    )
}

/// Sends a request with a handle (the one in CARRIED) and waits for its
/// reply, with its entry open: step 1 is 1 for the reply, 2 for Interrupted.
extern "C" fn sends_a_handle(_: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    let carried = Handle::<Channel>::from_raw(abi::Handle(CARRIED.load(Relaxed)));
    open_entry();
    STEPS[0].store(1, SeqCst);
    let result = sys::send_handles(&c, &[1], [carried.erase()]);
    STEPS[1].store(
        match result {
            Ok(_) => 1,
            Err(r) if r.error == Error::Interrupted => 2,
            Err(_) => 3,
        },
        SeqCst,
    );
    sys::thread_exit()
}

/// Takes one request, answers it, and says so in step `slot`.
extern "C" fn takes_one(slot: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    let result = match sys::receive(&c) {
        Ok(Received::Message { token, .. }) => {
            let _ = token.reply(&[]);
            1
        }
        Ok(_) => 2,
        Err(_) => 3,
    };
    STEPS[slot as usize].store(result, SeqCst);
    sys::thread_exit()
}

/// A request with a handle waits at the head of a channel's queue, from CPU
/// 3. A receiver at HEAD_LEVEL on CPU 1 finds it, makes room for the handle
/// and takes the request in the same section, and answers it: the sender
/// gets its reply. A kernel built with `break-one-section` gives `OBJ` back
/// between the look and the take, and stops at the number of the section
/// (xtask smp-window).
fn request_with_a_handle_is_taken_in_one_section() -> Outcome {
    let n = cpus()?;
    if n < 4 {
        return Ok(());
    }
    reset_steps();
    let c = channel(QUIET)?;
    let spare = channel(QUIET)?;
    CHANNEL.store(c.raw().0, Relaxed);
    CARRIED.store(copy_raw(&spare, Rights::TRANSFER)?.0, Relaxed);
    let sender = spawn_on(0, 3, sends_a_handle, 0, TEST_PRIORITY)?;
    check(wait_for(|| step(0) == 1), "the sender did not start")?;
    // Its request is in the queue.
    pause(20_000_000);
    let receiver = spawn_on(1, 1, takes_one, 2, HEAD_LEVEL)?;
    let done = wait_for(|| step(1) != 0 && step(2) != 0);
    let_run()?;
    for t in [sender, receiver] {
        close(t)?;
    }
    close(spare)?;
    close(c)?;
    check(done, "the request was not taken and answered")?;
    check(step(1) == 1, "the sender's request was not answered")?;
    check(step(2) == 1, "the receiver did not take the request")?;
    println!("smp: a request with a handle was taken by a receiver on another CPU in one section");
    Ok(())
}

/// Processes alive at once in a wave: more than the 15 ASIDs of the probe
/// kernel (`asid-probe`) hold, so that its generation changes all the time.
const ASID_KIDS: usize = 16;
/// The quota of a child of Role::AsidPage: a page and the tables for it.
const ASID_QUOTA: u64 = LEAF_QUOTA + 6 * PAGE as u64;
/// The first wave spreads its children over the CPUs; each later one puts
/// them all on one CPU, where a number two of them share meets in its TLB.
const ASID_WAVES: u64 = 4;
/// Reads of its own page a child makes, a yield between each.
const ASID_ROUNDS: u64 = 150;
/// Children that run one after the other after the waves: each frees its
/// ASID, which the next generation of the probe kernel hands out again.
const ASID_SEQUENCE: u64 = 24;

/// How a child of Role::AsidPage ended: Ok(true) when it read only its own
/// word.
fn ends_with_its_own_word(kid: &Kid) -> Result<bool, &'static str> {
    match kid.end()? {
        ProcessState::Exited { code: 0 } => Ok(true),
        ProcessState::Exited { code } if code == child::MISMATCH => Ok(false),
        other => {
            println!("smp: a child of the ASID probe ended with {other:?}");
            Err("a child of the ASID probe ended some other way")
        }
    }
}

/// Processes on every CPU map a page of their own at one address, with
/// their own word in it, and read it back round after round, yielding to the
/// others of their CPU. Waves of 16 at once, then a run of children that
/// each begin after the one before ended: ASIDs of the generation turn
/// over again and again on the probe kernel (4-bit ASIDs), and are freed
/// and issued again. No process may read the word of another one, which a
/// TLB entry left under its ASID (a number the new generation handed out
/// without a flush on this CPU, or a freed one with its entries still on
/// another CPU) would show.
fn asids_across_cpus() -> Outcome {
    // The line tells xtask that the kernel got as far as the probe.
    println!("smp: the ASID probe starts");
    // A runner that shares its CPUs with other jobs may take seconds to
    // start 16 children.
    KID_PATIENCE_NS.store(15_000_000_000, Relaxed);
    let outcome = asids_across_cpus_with(cpus()?);
    KID_PATIENCE_NS.store(KID_WAIT_NS, Relaxed);
    outcome
}

fn asids_across_cpus_with(n: usize) -> Outcome {
    let mut mismatches = 0;
    for wave in 0..ASID_WAVES {
        let mut kids: [Option<Kid>; ASID_KIDS] = [const { None }; ASID_KIDS];
        let mut result: Outcome = Ok(());
        // The children wait for the mark GO, so that all of them hold an
        // ASID at once before any begins its rounds.
        reset_kid_marks();
        for (i, slot) in kids.iter_mut().enumerate() {
            if result.is_err() {
                break;
            }
            let cpu = if wave == 0 {
                i % n
            } else {
                (wave as usize) % n
            };
            SPAWN_CPU.store((cpu + 1) as u8, Relaxed);
            let seed = 0x5EED_0000 + wave * 100 + i as u64;
            result = Kid::load(ASID_QUOTA, 16, LOW).and_then(|kid| {
                let started = kid.start().and_then(|()| {
                    kid.serve(Role::AsidPage, &[seed, ASID_ROUNDS, 1], &[Gift::Own])
                });
                *slot = Some(kid);
                started
            });
        }
        SPAWN_CPU.store(0, Relaxed);
        set_kid_mark(child::GO, 1);
        for kid in kids.iter().flatten() {
            if result.is_ok() {
                match ends_with_its_own_word(kid) {
                    Ok(true) => {}
                    Ok(false) => mismatches += 1,
                    Err(e) => result = Err(e),
                }
            }
        }
        for kid in kids.into_iter().flatten() {
            kid.close()?;
        }
        let_run()?;
        result?;
    }
    for i in 0..ASID_SEQUENCE {
        SPAWN_CPU.store((i as usize % n + 1) as u8, Relaxed);
        let kid = Kid::load(ASID_QUOTA, 16, LOW);
        SPAWN_CPU.store(0, Relaxed);
        let kid = kid?;
        let result = kid
            .start()
            .and_then(|()| kid.serve(Role::AsidPage, &[0x5E0_0000 + i, 20, 0], &[Gift::Own]))
            .and_then(|()| ends_with_its_own_word(&kid));
        kid.close()?;
        let_run()?;
        if !result? {
            mismatches += 1;
        }
    }
    check(
        mismatches == 0,
        "a process read the page of another one under its ASID",
    )?;
    println!(
        "smp: {} processes on {n} CPUs read only their own pages, in waves of {ASID_KIDS} and one by one",
        ASID_WAVES * ASID_KIDS as u64 + ASID_SEQUENCE
    );
    Ok(())
}

/// A thread of a child on CPU 1 reads a page of the child's process; the
/// child's first thread, on this CPU, unmaps the page: the reader's next
/// load faults and ends the process in a data abort at the page. Only a
/// TLBI that reaches the other CPU (`tlbi vale1is`) makes it so: the TLB
/// of CPU 1 holds the page, hot, when the unmap goes.
fn unmap_across_cpus() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    println!("smp: the unmap probe starts");
    reset_kid_marks();
    let kid = Kid::load(SPIN_QUOTA, 16, LEVEL)?;
    let state = kid
        .start()
        .and_then(|()| kid.serve(Role::UnmapAcross, &[LEVEL.into()], &[Gift::Own]))
        .and_then(|()| kid.end());
    kid.close()?;
    let_run()?;
    match state? {
        ProcessState::Fault { far, .. } => check(
            far == child::SCRATCH as u64,
            "the reader on CPU 1 faulted at another address",
        )?,
        ProcessState::Exited { code } if code == child::NO_FAULT => {
            return Err("the thread on CPU 1 still read the page after its unmap");
        }
        _ => return Err("the child of the unmap probe ended some other way"),
    }
    println!("smp: a page unmapped on CPU 0 faulted the thread that read it on CPU 1");
    Ok(())
}

/// Rounds of `asid_after_end_across_cpus`.
const END_ROUNDS: u64 = 4;

/// A child with a thread on CPU 1 that reads its page in a loop ends on
/// CPU 0 (its first thread unmaps the page, the reader faults), so its
/// ASID is active on CPU 1 when the process goes: the CPU keeps TTBR0 of
/// the last thread it ran, and a walk ahead of its code would fill its TLB
/// with entries of the tables that go. Then one child after the other on
/// CPU 1, more than the 15 ASIDs of the probe kernel hold, each reading its
/// own word at the address the ended child mapped: the number of the ended
/// process comes up again, and no child may read what the ended one left.
/// The probe kernel stops when the ASID goes while a CPU still has the
/// tables in TTBR0 (`SpaceRelease::drop_asid`), which a walk of silicon
/// cannot be made to show on TCG.
fn asid_after_end_across_cpus() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    let mut mismatches = 0;
    for round in 0..END_ROUNDS {
        reset_kid_marks();
        let kid = Kid::load(SPIN_QUOTA, 16, LEVEL)?;
        let state = kid
            .start()
            .and_then(|()| kid.serve(Role::UnmapAcross, &[LEVEL.into()], &[Gift::Own]))
            .and_then(|()| kid.end());
        kid.close()?;
        let_run()?;
        match state? {
            ProcessState::Fault { .. } => {}
            _ => return Err("the child that ends on CPU 0 ended some other way"),
        }
        for i in 0..=ASID_KIDS as u64 {
            SPAWN_CPU.store(2, Relaxed);
            let kid = Kid::load(ASID_QUOTA, 16, LOW);
            SPAWN_CPU.store(0, Relaxed);
            let kid = kid?;
            let seed = 0xE0D_0000 + round * 100 + i;
            let result = kid
                .start()
                .and_then(|()| kid.serve(Role::AsidPage, &[seed, 20, 0], &[Gift::Own]))
                .and_then(|()| ends_with_its_own_word(&kid));
            kid.close()?;
            let_run()?;
            if !result? {
                mismatches += 1;
            }
        }
    }
    check(
        mismatches == 0,
        "a process read the page of one that ended with its ASID active on another CPU",
    )?;
    println!(
        "smp: {END_ROUNDS} processes that ended on CPU 0 with a thread on CPU 1 left no entry under their ASIDs"
    );
    Ok(())
}

// SMP stage 6: the numbers of the decision (`cargo xtask smp-measure` takes
// them from the lines, on QEMU under -icount and on HVF).

/// Rounds of each row.
const MEASURE_ROUNDS: usize = 100;
/// Pages the storm maps at once: the longest section of OBJ is a mapping.
const STORM_PAGES: usize = 16;

static STORM_OVER: AtomicU64 = AtomicU64::new(0);
static STORM_MEMORY: AtomicU64 = AtomicU64::new(0);
static STORM_CHANNEL: AtomicU64 = AtomicU64::new(0);
/// Set by each thread of the storm when it ends; the rows keep the marks.
static STORM_DONE: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// Receives and replies until the request with the word 0 (the stop of the
/// rows) is answered. A flag the thread tests between two calls would let it
/// end before the stop is sent: a host that holds its CPU back there leaves
/// the sender of the stop in its call for good.
fn serve_until_stopped(c: &Handle<Channel>) -> ! {
    loop {
        if let Ok(Received::Message { token, words, .. }) = sys::receive(c) {
            let _ = token.reply(&[]);
            if words[0] == 0 {
                break;
            }
        }
    }
    sys::thread_exit()
}

/// Binds the entry of the handler, then waits for a message that never comes
/// until the stop: a request for the handler wakes it, and the CPU it is on
/// leaves WFI or its lower thread.
extern "C" fn waiting_target(_: u64) -> ! {
    // SAFETY: the handler touches the marks alone.
    unsafe {
        let _ = rt::upcall::bind(signalled_entry);
        let _ = rt::upcall::enable();
    }
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    MARKS[0].store(1, Relaxed);
    serve_until_stopped(&c)
}

/// A thread of a lower level that holds its CPU at EL0 until mark 3.
extern "C" fn lower_spinner(_: u64) -> ! {
    while MARKS[3].load(Relaxed) == 0 {
        spin_loop();
    }
    sys::thread_exit()
}

/// Calls of the storm: duplicate and close a handle, make a channel, map and
/// unmap the pages of a memory object (the longest section of OBJ), each
/// CPU at once, until the storm is over.
extern "C" fn storm(slot: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(STORM_CHANNEL.load(Relaxed)));
    let m = Handle::<Memory>::borrowed(abi::Handle(STORM_MEMORY.load(Relaxed)));
    let at = WINDOW + slot as usize * STORM_PAGES * PAGE;
    while STORM_OVER.load(Relaxed) == 0 {
        for _ in 0..4 {
            if let Ok(d) = sys::handle_duplicate(&*c, Rights::NONE) {
                let _ = d.close();
            }
        }
        if let Ok(x) = sys::channel_create(QUIET) {
            let _ = x.close();
        }
        let len = (STORM_PAGES * PAGE) as u64;
        if sys::mem_map(&own(), &m, 0, len, at, Access::ReadWrite).is_ok() {
            // SAFETY: nothing of init uses these pages.
            let _ = unsafe { sys::mem_unmap(&own(), at, len) };
        }
    }
    STORM_DONE[slot as usize].store(1, Relaxed);
    sys::thread_exit()
}

/// Receives and replies until the stop: the service of a call.
extern "C" fn echo_service(_: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(CHANNEL.load(Relaxed)));
    MARKS[0].store(1, Relaxed);
    serve_until_stopped(&c)
}

/// Median, 99th percentile and longest of the rounds, in ticks.
fn spread(mut rows: [u64; MEASURE_ROUNDS]) -> (u64, u64, u64) {
    rows.sort_unstable();
    (
        rows[MEASURE_ROUNDS / 2],
        rows[MEASURE_ROUNDS * 99 / 100],
        rows[MEASURE_ROUNDS - 1],
    )
}

/// Requests the handler of `t` once for each round and gives the ticks from
/// the request to the handler's first instruction.
fn upcall_rounds(t: &Handle<Thread>) -> Result<[u64; MEASURE_ROUNDS], &'static str> {
    let mut rows = [0u64; MEASURE_ROUNDS];
    for (round, slot) in rows.iter_mut().enumerate() {
        let seen = mark(1);
        let before = time::now();
        let asked = sys::thread_upcall_request(t);
        let sent = asked.is_ok() && wait_for(|| mark(1) > seen);
        if !sent {
            println!(
                "smp measure: round {round}: the request gave {asked:?}, the handler ran {} times (seen {seen}), the target is {:?}",
                mark(1),
                sys::thread_info(t).map(|i| i.state)
            );
        }
        check(sent, "a request did not reach the handler of the target")?;
        *slot = mark(2).saturating_sub(before);
        pause(100_000);
    }
    Ok(rows)
}

/// The ticks of each of the rounds of a call to the service on `cpu`.
fn call_rounds(cpu: usize, slot: usize) -> Result<[u64; MEASURE_ROUNDS], &'static str> {
    reset_marks();
    let c = channel(QUIET)?;
    CHANNEL.store(c.raw().0, Relaxed);
    // Above this thread, which spins while it waits for it on this CPU.
    let server = spawn_on(slot, cpu, echo_service, 0, TEST_PRIORITY + 1)?;
    check(wait_for(|| mark(0) == 1), "the service did not start")?;
    let mut rows = [0u64; MEASURE_ROUNDS];
    let mut done = true;
    for row in rows.iter_mut() {
        let before = time::now();
        done &= sys::send(&c, &[1]).is_ok();
        *row = time::now().wrapping_sub(before);
        pause(50_000);
    }
    let _ = sys::send(&c, &[0]);
    let ended =
        wait_for(|| sys::thread_info(&server).is_ok_and(|i| i.state == abi::ThreadState::Ended));
    let_run()?;
    close(server)?;
    close(c)?;
    check(done && ended, "a call to the service failed")?;
    Ok(rows)
}

fn print_row(name: &str, rows: [u64; MEASURE_ROUNDS]) {
    let (median, p99, longest) = spread(rows);
    println!(
        "smp measure: {name}: median {median} ticks, p99 {p99}, longest {longest} of {MEASURE_ROUNDS} (counter {} Hz)",
        time::frequency()
    );
}

/// A target on `cpu` that waits for a message, with `lower` threads of a
/// lower level that hold the CPU at EL0 when given: the rows of requests for
/// its handler. A target on another CPU than this one has to be woken by
/// an interrupt between CPUs.
fn target_rows(
    cpu: usize,
    slots: &[usize],
    lower: bool,
) -> Result<[u64; MEASURE_ROUNDS], &'static str> {
    reset_marks();
    let c = channel(QUIET)?;
    CHANNEL.store(c.raw().0, Relaxed);
    // Above this thread, which spins while it waits for the target on this CPU.
    let target = spawn_on(slots[0], cpu, waiting_target, 0, TEST_PRIORITY + 1)?;
    let spinner = if lower {
        Some(spawn_on(slots[1], cpu, lower_spinner, 0, LOW)?)
    } else {
        None
    };
    check(wait_for(|| mark(0) == 1), "the target did not start")?;
    pause(2_000_000);
    let rows = upcall_rounds(&target);
    MARKS[3].store(1, Relaxed);
    let _ = sys::send(&c, &[0]);
    // Both threads have ended before their slots serve again: a message
    // buffer is the page of one thread at a time.
    let ended = wait_for(|| {
        [Some(&target), spinner.as_ref()]
            .into_iter()
            .flatten()
            .all(|t| sys::thread_info(t).is_ok_and(|i| i.state == abi::ThreadState::Ended))
    });
    let_run()?;
    close(target)?;
    if let Some(t) = spinner {
        close(t)?;
    }
    close(c)?;
    check(ended, "the target did not end")?;
    rows
}

/// The rows of stage 6 that a storm of calls from the other CPUs runs
/// under: `kind` 0 the handler of a thread waiting on this CPU, 1 a call
/// to a service on this CPU. The kernel built with `smp-measure` is told to
/// count from the start of the storm and to print its counters at its end.
fn storm_rows(n: usize, kind: u64) -> Result<[u64; MEASURE_ROUNDS], &'static str> {
    STORM_OVER.store(0, Relaxed);
    for done in &STORM_DONE {
        done.store(0, Relaxed);
    }
    let m = sys::mem_create((STORM_PAGES * PAGE) as u64).map_err(|_| "mem_create failed")?;
    STORM_MEMORY.store(m.raw().0, Relaxed);
    let c = channel(QUIET)?;
    STORM_CHANNEL.store(c.raw().0, Relaxed);
    let others = n.min(4) - 1;
    let mut kept = [None, None, None];
    for cpu in 1..=others {
        kept[cpu - 1] = Some(spawn_on(cpu - 1, cpu, storm, (cpu - 1) as u64, LOW)?);
    }
    let _ = sys::debug_write(&resource(), b"smp-measure reset");
    let rows = if kind == 0 {
        target_rows(0, &[3], false)
    } else {
        call_rounds(0, 3)
    };
    let _ = sys::debug_write(&resource(), b"smp-measure report");
    STORM_OVER.store(1, Relaxed);
    let stopped = wait_for(|| STORM_DONE[..others].iter().all(|d| d.load(Relaxed) != 0));
    // The flag is set before the thread's last call: the next storm takes
    // the stacks and message buffers of these threads again once they ended.
    let ended = wait_for(|| {
        kept.iter()
            .flatten()
            .all(|t| sys::thread_info(t).is_ok_and(|i| i.state == abi::ThreadState::Ended))
    });
    let_run()?;
    for t in kept.into_iter().flatten() {
        close(t)?;
    }
    close(c)?;
    close(m)?;
    check(stopped && ended, "a thread of the storm did not stop")?;
    rows
}

/// The numbers of the decision of SMP (tasks/2026-10-17-smp/decision.md,
/// stage 6): the latency of a request to a thread on another CPU (S5x) with
/// the target waiting in WFI and with a lower thread on its CPU, a call to
/// a service on this CPU and on another, and under a storm of calls from
/// the other CPUs the request to a thread of this CPU (S5) and a local call.
fn stage_6_measures() -> Outcome {
    let n = cpus()?;
    if n < 2 {
        return Ok(());
    }
    print_row(
        "S5x target waiting, its CPU idle",
        target_rows(1, &[0], false)?,
    );
    print_row(
        "S5x target waiting, a lower thread on its CPU",
        target_rows(1, &[0, 1], true)?,
    );
    print_row("call to a service on this CPU", call_rounds(0, 0)?);
    let far = if n > 2 { 2 } else { 1 };
    print_row("call to a service on another CPU", call_rounds(far, 0)?);
    print_row(
        "S5 on this CPU under a storm of the others",
        storm_rows(n, 0)?,
    );
    print_row(
        "call to a service on this CPU under a storm of the others",
        storm_rows(n, 1)?,
    );
    Ok(())
}

// The litmus tests of memory order (aarch64.md, probe 3): two threads on two
// CPUs run the two halves of a pattern, round after round, and the outcomes
// are counted. The forbidden ones (MP with release and acquire, SB with
// dmb) may never come; the same patterns without the barriers show how far
// the host reorders (none on TCG, some on the real processor). On the
// real processor the rounds go up to LITMUS_ROUNDS; a slow host stops
// early.

/// Rounds of a pattern at most, and the time that bounds a pattern.
const LITMUS_ROUNDS: u64 = 1_000_000;
const LITMUS_NS: u64 = 3_000_000_000;
/// A host that does not reach LITMUS_ROUNDS in LITMUS_NS at this pace stops
/// after LITMUS_PROBE_NS: the slow TCG of ci.
const LITMUS_PROBE_NS: u64 = 150_000_000;

/// A word of a pattern on a cache line of its own.
#[repr(align(128))]
struct Line(AtomicU64);

static LITMUS_X: Line = Line(AtomicU64::new(0));
static LITMUS_Y: Line = Line(AtomicU64::new(0));
/// The round the threads run next, the round each finished, and what each
/// read.
static LITMUS_GO: Line = Line(AtomicU64::new(0));
static LITMUS_DONE: [Line; 2] = [Line(AtomicU64::new(0)), Line(AtomicU64::new(0))];
static LITMUS_SAW: [Line; 2] = [Line(AtomicU64::new(0)), Line(AtomicU64::new(0))];
static LITMUS_STOP: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, PartialEq)]
enum Pattern {
    MpStrong,
    MpWeak,
    SbStrong,
    SbWeak,
}

impl Pattern {
    const ALL: [Pattern; 4] = [
        Pattern::MpStrong,
        Pattern::MpWeak,
        Pattern::SbStrong,
        Pattern::SbWeak,
    ];

    fn from(n: u64) -> Pattern {
        Pattern::ALL[n as usize]
    }
}

/// One half of a pattern: `role` 0 or 1. MP: role 0 writes the data and
/// then the flag, role 1 waits for the flag and reads the data (what it
/// read: flag seen in bit 0, data in bit 1). SB: each writes its word,
/// then reads the other's.
fn litmus_half(pattern: Pattern, role: u64) -> u64 {
    use core::sync::atomic::{Ordering::Acquire, Ordering::Release, fence};
    let (x, y) = (&LITMUS_X.0, &LITMUS_Y.0);
    match (pattern, role) {
        (Pattern::MpStrong, 0) => {
            x.store(1, Relaxed);
            y.store(1, Release);
            0
        }
        (Pattern::MpWeak, 0) => {
            x.store(1, Relaxed);
            y.store(1, Relaxed);
            0
        }
        (Pattern::MpStrong | Pattern::MpWeak, _) => {
            let order = if pattern == Pattern::MpStrong {
                Acquire
            } else {
                Relaxed
            };
            let mut flag = 0;
            for _ in 0..2000 {
                flag = y.load(order);
                if flag != 0 {
                    break;
                }
                spin_loop();
            }
            flag | (x.load(Relaxed) << 1)
        }
        (Pattern::SbStrong, 0) => {
            x.store(1, Relaxed);
            fence(SeqCst);
            y.load(Relaxed)
        }
        (Pattern::SbStrong, _) => {
            y.store(1, Relaxed);
            fence(SeqCst);
            x.load(Relaxed)
        }
        (Pattern::SbWeak, 0) => {
            x.store(1, Relaxed);
            y.load(Relaxed)
        }
        (Pattern::SbWeak, _) => {
            y.store(1, Relaxed);
            x.load(Relaxed)
        }
    }
}

/// A thread of a pattern: waits for each round, runs its half, says what it
/// read and that it is done.
extern "C" fn litmus_thread(arg: u64) -> ! {
    let (role, pattern) = (arg & 1, Pattern::from(arg >> 1));
    let mut round = 0;
    loop {
        let go = loop {
            let go = LITMUS_GO.0.load(Acquire);
            if go > round || LITMUS_STOP.load(Relaxed) != 0 {
                break go;
            }
            spin_loop();
        };
        if LITMUS_STOP.load(Relaxed) != 0 {
            break;
        }
        round = go;
        LITMUS_SAW[role as usize]
            .0
            .store(litmus_half(pattern, role), Relaxed);
        LITMUS_DONE[role as usize].0.store(round, Release);
    }
    sys::thread_exit()
}

/// Runs `pattern` for as many rounds as the host allows: the rounds, the
/// rounds in which the flag of MP was seen, and the weak outcomes.
fn litmus_run(pattern: Pattern, a: usize, b: usize) -> Result<(u64, u64, u64), &'static str> {
    LITMUS_STOP.store(0, Relaxed);
    LITMUS_GO.0.store(0, Relaxed);
    for d in &LITMUS_DONE {
        d.0.store(0, Relaxed);
    }
    let p = pattern as u64;
    let t0 = spawn_on(0, a, litmus_thread, p << 1, TEST_PRIORITY + 1)?;
    let t1 = spawn_on(1, b, litmus_thread, (p << 1) | 1, TEST_PRIORITY + 1)?;
    let began = now();
    let (mut rounds, mut seen, mut weak) = (0u64, 0u64, 0u64);
    let mut ok = true;
    while rounds < LITMUS_ROUNDS {
        if rounds % 1024 == 0 {
            let elapsed = now() - began;
            // The pace of the first LITMUS_PROBE_NS decides if the pattern
            // can reach LITMUS_ROUNDS within LITMUS_NS.
            if elapsed > LITMUS_NS
                || (elapsed > LITMUS_PROBE_NS && rounds * LITMUS_NS < LITMUS_ROUNDS * elapsed)
            {
                break;
            }
        }
        LITMUS_X.0.store(0, Relaxed);
        LITMUS_Y.0.store(0, Relaxed);
        rounds += 1;
        LITMUS_GO.0.store(rounds, Release);
        let limit = now() + WAIT_NS;
        while LITMUS_DONE[0].0.load(Acquire) < rounds || LITMUS_DONE[1].0.load(Acquire) < rounds {
            if now() > limit {
                ok = false;
                break;
            }
            spin_loop();
        }
        if !ok {
            break;
        }
        let (r0, r1) = (LITMUS_SAW[0].0.load(Relaxed), LITMUS_SAW[1].0.load(Relaxed));
        match pattern {
            Pattern::MpStrong | Pattern::MpWeak => {
                // r1: bit 0 the flag, bit 1 the data.
                if r1 & 1 != 0 {
                    seen += 1;
                    if r1 >> 1 == 0 {
                        weak += 1;
                    }
                }
            }
            Pattern::SbStrong | Pattern::SbWeak => {
                if r0 == 0 && r1 == 0 {
                    weak += 1;
                }
            }
        }
    }
    LITMUS_STOP.store(1, Relaxed);
    let _ = wait_for(|| {
        sys::thread_info(&t0).is_ok_and(|i| i.state == abi::ThreadState::Ended)
            && sys::thread_info(&t1).is_ok_and(|i| i.state == abi::ThreadState::Ended)
    });
    let_run()?;
    close(t0)?;
    close(t1)?;
    check(ok, "a litmus thread did not finish its round")?;
    Ok((rounds, seen, weak))
}

fn litmus_tests() -> Outcome {
    let n = cpus()?;
    if n < 3 {
        return Ok(());
    }
    // CPUs 1 and 2, and this thread spins on CPU 0.
    let (a, b) = (1, 2);
    let mut counts = [(0, 0, 0); 4];
    for (i, pattern) in Pattern::ALL.into_iter().enumerate() {
        counts[i] = litmus_run(pattern, a, b)?;
    }
    let [mp, mp_weak, sb, sb_weak] = counts;
    println!(
        "smp: litmus MP with release and acquire: {} rounds, flag seen in {}, data missed {}; with no barrier: {} rounds, flag seen in {}, data missed {}",
        mp.0, mp.1, mp.2, mp_weak.0, mp_weak.1, mp_weak.2
    );
    println!(
        "smp: litmus SB with dmb: {} rounds, both read 0 in {}; with no barrier: {} rounds, both read 0 in {}",
        sb.0, sb.2, sb_weak.0, sb_weak.2
    );
    check(
        mp.2 == 0,
        "MP with release and acquire: the flag came without the data",
    )?;
    check(sb.2 == 0, "SB with dmb: both threads read the old value")?;
    check(mp.0 > 0 && sb.0 > 0, "a litmus pattern ran no round")
}
