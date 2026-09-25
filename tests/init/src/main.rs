// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The test init (spec 15.2). It runs in place of init on the normal
//! build of the kernel, the one that ships, and tests the system calls
//! from EL0, in its own process and in children with no code. It prints
//! `TEST <name> ok` or `TEST <name> FAIL <why>` for each test, then
//! `TESTS DONE total=<n> failed=<m>`, and exits with the number of
//! failures, which turns the machine off; xtask reads the lines.
//!
//! Its first line gives the counter ticks of a counted loop, which xtask
//! checks in the runs under -icount. The first test runs with the
//! priority the kernel gave init; the others with init at TEST_PRIORITY.
//! A thread above it runs at once; threads below it run when init lowers
//! itself to 1 (`let_run`), and init runs again once they all have ended
//! or wait: the order of priorities joins threads. Notifications that init
//! takes in its own thread have priority 1 (QUIET), and init asks once
//! more afterwards: their boost never lifts init above its threads (spec
//! 6.6).

#![no_std]
#![no_main]

use abi::{
    CHANNEL_RIGHTS, CLIENT_GONE, Call, Error, INIT_BOOT_IMAGE, Policy, ProcessHandles,
    ProcessMemory, ProcessState, Rights, Source,
};
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use rt::handle::{Channel, Process, Resource, Thread};
use rt::sys::{self, Received, Regs};
use rt::{Handle, Stack, init, println, time};

rt::entry!(main);

type Outcome = Result<(), &'static str>;
/// A test's name and body.
type Test = (&'static str, fn() -> Outcome);

const TESTS: [Test; 39] = [
    ("init_starts_fifo_at_63", init_starts_fifo_at_63),
    ("init_prints_from_el0", init_prints_from_el0),
    (
        "init_handles_have_their_fixed_values",
        init_handles_have_their_fixed_values,
    ),
    (
        "boot_image_handle_is_reserved",
        boot_image_handle_is_reserved,
    ),
    ("init_has_its_message_buffer", init_has_its_message_buffer),
    (
        "debug_write_checks_its_arguments",
        debug_write_checks_its_arguments,
    ),
    ("unknown_system_calls_fail", unknown_system_calls_fail),
    ("priority_ceilings_hold", priority_ceilings_hold),
    ("thread_states", thread_states),
    ("thread_limit_is_64", thread_limit_is_64),
    (
        "higher_priority_start_preempts_at_once",
        higher_priority_start_preempts_at_once,
    ),
    (
        "yield_does_not_let_lower_levels_run",
        yield_does_not_let_lower_levels_run,
    ),
    (
        "closing_a_thread_handle_does_not_stop_it",
        closing_a_thread_handle_does_not_stop_it,
    ),
    (
        "rr_threads_alternate_by_quantum",
        rr_threads_alternate_by_quantum,
    ),
    (
        "fifo_threads_do_not_alternate",
        fifo_threads_do_not_alternate,
    ),
    (
        "child_fault_reason_reaches_the_parent",
        child_fault_reason_reaches_the_parent,
    ),
    (
        "kill_takes_a_ready_thread_off_the_queue",
        kill_takes_a_ready_thread_off_the_queue,
    ),
    ("quota_is_enforced", quota_is_enforced),
    ("process_info_kinds", process_info_kinds),
    ("kernel_stats_need_kstats", kernel_stats_need_kstats),
    (
        "process_kill_returns_after_the_teardown",
        process_kill_returns_after_the_teardown,
    ),
    ("child_quota_comes_back", child_quota_comes_back),
    (
        "channel_create_checks_its_priority",
        channel_create_checks_its_priority,
    ),
    (
        "notify_and_receive_need_their_rights",
        notify_and_receive_need_their_rights,
    ),
    (
        "notifications_merge_bits_and_count",
        notifications_merge_bits_and_count,
    ),
    ("notify_refuses_bit_63", notify_refuses_bit_63),
    (
        "receive_without_waiting_is_would_block",
        receive_without_waiting_is_would_block,
    ),
    (
        "notification_runs_at_its_priority",
        notification_runs_at_its_priority,
    ),
    (
        "boost_ends_at_the_next_receive",
        boost_ends_at_the_next_receive,
    ),
    (
        "waiting_receiver_gets_peer_closed",
        waiting_receiver_gets_peer_closed,
    ),
    ("duplicate_narrows_rights", duplicate_narrows_rights),
    (
        "client_gone_after_the_last_copy",
        client_gone_after_the_last_copy,
    ),
    ("label_cannot_change", label_cannot_change),
    (
        "session_priority_under_the_ceiling",
        session_priority_under_the_ceiling,
    ),
    (
        "session_notice_carries_its_label",
        session_notice_carries_its_label,
    ),
    (
        "higher_notification_comes_first",
        higher_notification_comes_first,
    ),
    (
        "notify_after_close_is_peer_closed",
        notify_after_close_is_peer_closed,
    ),
    ("slot_limit_is_1024", slot_limit_is_1024),
    (
        "create_kill_cycles_leak_nothing",
        create_kill_cycles_leak_nothing,
    ),
];

/// Init's priority while the tests run.
const TEST_PRIORITY: u8 = 20;
/// Levels below init, for threads that run when init lets them, and one
/// above it, for threads that run at once.
const LOW: u8 = 5;
const LEVEL: u8 = 10;
const HIGH: u8 = 30;
/// The priority of the notifications of the priority tests: above init.
const NOTICE: u8 = 25;
/// The priority of the notifications init takes itself: the lowest level.
const QUIET: u8 = 1;

const PAGE: usize = 4096;
const STACK_SIZE: usize = 16 * 1024;
/// The quota of a child with a thread or two (spec 7.5).
const CHILD_QUOTA: u64 = 64 * 1024;
/// The least quota this kernel takes for a child (spec 7.5): its root
/// table and the page of its pool of blocks, with the directory of its
/// table and the chunk with entry 0. Its shell is init's (spec 7.8).
const LEAST_QUOTA: u64 = 8 * 1024;
/// Rounds of `create_kill_cycles_leak_nothing`.
const CYCLES: u32 = 1000;
/// Threads of init's own process a test may have at a time.
const SLOTS: usize = 2;

static STACKS: [Stack<STACK_SIZE>; SLOTS] = [const { Stack::new() }; SLOTS];

/// Words the threads of a test leave for it.
static MARKS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// The entry of a thread of a child: the child has no code, so nothing is
/// mapped there, and the thread faults as soon as it runs.
const CHILD_ENTRY: u64 = 0x1000;
/// The message buffer of that thread, on the next page: the page gives the
/// child a level 3 table for its first 2 MiB.
const CHILD_BUFFER: u64 = 0x2000;
/// The fault of that thread: an instruction abort from EL0 (EC 0x20) with
/// IL set and a translation fault at level 3 (IFSC 0x07).
const CHILD_FAULT_ESR: u64 = 0x8200_0007;

/// A line debug_write prints with bytes other than zero past its length.
const STOPS: &[u8] = b"debug_write stops at its length";

fn main(_: u64) -> u64 {
    rt::console::set(&init::RESOURCE);
    println!("counter ticks of 10000 turns: {}", loop_ticks());
    let mut failed = 0;
    for (i, (name, test)) in TESTS.into_iter().enumerate() {
        if i == 1 {
            sys::thread_set_priority(&init::THREAD, TEST_PRIORITY, Policy::Fifo)
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
    println!("TESTS DONE total={} failed={failed}", TESTS.len());
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

fn check(ok: bool, why: &'static str) -> Outcome {
    if ok { Ok(()) } else { Err(why) }
}

fn close<K>(h: Handle<K>) -> Outcome {
    h.close().map_err(|_| "handle_close failed")
}

/// The same handle with another kind in its type, for a call that must
/// fail with WRONG_TYPE.
fn retyped<K, L>(h: &Handle<K>) -> Handle<L> {
    Handle::from_raw(h.raw())
}

/// x0-x9 filled with marks, for calls that must change x0 alone.
fn marked() -> Regs {
    core::array::from_fn(|i| 0x5A5A_0000 + i as u64)
}

fn reset_marks() {
    for m in &MARKS {
        m.store(0, Relaxed);
    }
}

fn mark(i: usize) -> u64 {
    MARKS[i].load(Relaxed)
}

/// The message buffer of the thread in `slot`, above init's own. A thread's
/// buffer goes when it ends, so the next test takes the page again.
fn buffer(slot: usize) -> usize {
    abi::INIT_MSGBUF as usize + (slot + 1) * PAGE
}

/// A stopped thread of init's process in `slot` that runs `entry(arg)`.
fn thread(
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    arg: u64,
    priority: u8,
    policy: Policy,
) -> Result<Handle<Thread>, &'static str> {
    // SAFETY: each test lets its threads end before the next test uses the
    // slot, so the stack is the thread's alone.
    let t = unsafe {
        sys::thread_create(
            &init::PROCESS,
            entry,
            STACKS[slot].top(),
            arg,
            priority,
            policy,
            buffer(slot),
        )
    };
    t.map_err(|_| "thread_create failed")
}

/// `thread`, started.
fn spawn(
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    arg: u64,
    priority: u8,
    policy: Policy,
) -> Result<Handle<Thread>, &'static str> {
    let t = thread(slot, entry, arg, priority, policy)?;
    sys::thread_start(&t).map_err(|_| "thread_start failed")?;
    Ok(t)
}

/// Lets every thread below init run until it ends: init lowers itself to
/// 1 and, once it runs again, takes TEST_PRIORITY back.
fn let_run() -> Outcome {
    sys::thread_set_priority(&init::THREAD, 1, Policy::Fifo)
        .map_err(|_| "init could not lower itself")?;
    sys::thread_set_priority(&init::THREAD, TEST_PRIORITY, Policy::Fifo)
        .map_err(|_| "init could not take its priority back")
}

/// A child with no code, CHILD_QUOTA, room for 16 handles and ceiling
/// `ceiling`.
fn child(ceiling: u8) -> Result<Handle<Process>, &'static str> {
    sys::process_create(CHILD_QUOTA, 16, ceiling).map_err(|_| "process_create failed")
}

/// A stopped thread of `process` at CHILD_ENTRY, FIFO at `priority`.
fn child_thread(process: &Handle<Process>, priority: u8) -> Result<Handle<Thread>, Error> {
    let mut x = [0; 10];
    x[0] = process.raw().0;
    x[1] = CHILD_ENTRY;
    x[4] = priority.into();
    x[5] = Policy::Fifo as u64;
    x[6] = CHILD_BUFFER;
    // SAFETY: the thread runs in another process and touches nothing of
    // init's.
    let after = unsafe { sys::raw::<{ Call::ThreadCreate.number() }>(x) };
    match Error::from_code(after[0]) {
        None => Ok(Handle::from_raw(abi::Handle(after[1]))),
        Some(e) => Err(e),
    }
}

/// Adds 1 to mark `i` and ends.
extern "C" fn add_mark(i: u64) -> ! {
    MARKS[i as usize].fetch_add(1, Relaxed);
    sys::thread_exit()
}

/// Init's first thread is FIFO at 63 under ceiling 63 (spec 13.3): a
/// thread init starts at 63, which ceiling 63 allows, does not run at
/// once (init is not below it), nor within two quanta (init is not round
/// robin), and runs when init yields. Runs before init takes
/// TEST_PRIORITY.
fn init_starts_fifo_at_63() -> Outcome {
    reset_marks();
    let top = abi::PRIORITY_LEVELS - 1;
    let t = spawn(0, add_mark, 0, top, Policy::Fifo)?;
    let at_once = mark(0);
    let end = time::now() + 2 * time::ns_to_ticks(abi::RR_QUANTUM_NS);
    while time::now() < end {}
    let after_quanta = mark(0);
    let yielded = sys::yield_now();
    let after_yield = mark(0);
    close(t)?;
    check(at_once == 0, "a thread at 63 ran at once: init is below 63")?;
    check(
        after_quanta == 0,
        "a thread at 63 ran within two quanta: init is not FIFO",
    )?;
    check(
        yielded.is_ok() && after_yield == 1,
        "init's yield did not let the thread at 63 run",
    )
}

/// A formatted line longer than one call carries goes out in pieces;
/// xtask finds it whole.
fn init_prints_from_el0() -> Outcome {
    let printed = rt::console::write_fmt(format_args!(
        "init prints from EL0 in pieces of at most {} bytes: this line takes {} of them\n",
        abi::INLINE_MAX,
        2
    ));
    check(printed.is_ok(), "debug_write failed")
}

/// Init's first handles name what spec 13.3 gives it.
fn init_handles_have_their_fixed_values() -> Outcome {
    check(
        sys::process_state(&init::PROCESS) == Ok(ProcessState::Alive),
        "INIT_PROCESS is not a live process",
    )?;
    check(
        sys::debug_write(&init::RESOURCE, b"") == Ok(0),
        "INIT_RESOURCE does not write to the console",
    )?;
    check(
        sys::process_state(&retyped(&init::RESOURCE)) == Err(Error::WrongType),
        "INIT_RESOURCE is not the system resource",
    )?;
    check(
        sys::thread_set_priority(&init::THREAD, TEST_PRIORITY, Policy::Fifo).is_ok(),
        "INIT_THREAD is not a thread with MANAGE",
    )?;
    check(
        sys::process_state(&retyped(&init::THREAD)) == Err(Error::WrongType),
        "INIT_THREAD is a process",
    )
}

/// Until milestone 1.3 the boot image's handle is bad (spec 13.3).
fn boot_image_handle_is_reserved() -> Outcome {
    check(
        sys::process_state(&Handle::from_raw(INIT_BOOT_IMAGE)) == Err(Error::BadHandle),
        "object_info took INIT_BOOT_IMAGE",
    )?;
    check(
        Handle::<Resource>::from_raw(INIT_BOOT_IMAGE).close() == Err(Error::BadHandle),
        "handle_close took INIT_BOOT_IMAGE",
    )
}

/// The kernel mapped the first thread's message buffer at abi::INIT_MSGBUF:
/// no new thread gets the page, and init reads and writes it.
fn init_has_its_message_buffer() -> Outcome {
    // SAFETY: as in `thread`; slot 0 is free.
    let taken = unsafe {
        sys::thread_create(
            &init::PROCESS,
            add_mark,
            STACKS[0].top(),
            0,
            LOW,
            Policy::Fifo,
            abi::INIT_MSGBUF as usize,
        )
    };
    let refused = taken == Err(Error::InvalidArgs);
    if let Ok(t) = taken {
        close(t)?;
    }
    check(refused, "the page of init's message buffer is free")?;
    let word = abi::INIT_MSGBUF as *mut u64;
    // SAFETY: the page is the buffer of init's own thread, which nothing
    // else uses in milestone 1.2c.
    let read = unsafe {
        word.write_volatile(0x5354_4146);
        word.read_volatile()
    };
    check(read == 0x5354_4146, "init's message buffer lost a word")
}

/// debug_write takes up to 64 bytes through a handle with DEBUG to the
/// system resource and writes only the bytes of its length (spec 11).
fn debug_write_checks_its_arguments() -> Outcome {
    let mut x = marked();
    x[0] = init::RESOURCE.raw().0;
    x[1] = abi::INLINE_MAX as u64 + 1;
    // SAFETY: debug_write only reads its registers.
    let after = unsafe { sys::raw::<{ Call::DebugWrite.number() }>(x) };
    check(
        after[0] == Error::InvalidArgs.code() && after[1..] == x[1..],
        "65 bytes did not fail with INVALID_ARGS alone",
    )?;
    check(
        sys::debug_write(&retyped(&init::PROCESS), b"x") == Err(Error::WrongType),
        "a process handle wrote",
    )?;
    let c = child(LOW)?;
    let gone = retyped(&c);
    close(c)?;
    check(
        sys::debug_write(&gone, b"x") == Err(Error::BadHandle),
        "a closed handle wrote",
    )?;
    let mut bytes = [b'#'; abi::INLINE_MAX];
    bytes[..STOPS.len()].copy_from_slice(STOPS);
    let mut x = [0; 10];
    x[0] = init::RESOURCE.raw().0;
    x[1] = STOPS.len() as u64;
    x[2..].copy_from_slice(&abi::inline_words(&bytes));
    // SAFETY: as above.
    let after = unsafe { sys::raw::<{ Call::DebugWrite.number() }>(x) };
    check(
        after[..2] == [0, STOPS.len() as u64],
        "debug_write did not write the bytes of its length",
    )?;
    check(
        sys::debug_write(&init::RESOURCE, b"\n") == Ok(1),
        "debug_write did not write a newline",
    )
}

/// Numbers no call has fail with INVALID_ARGS and change x0 alone
/// (spec 11), those of the kernel's test builds too.
fn unknown_system_calls_fail() -> Outcome {
    unknown::<0>()?;
    unknown::<29>()?;
    unknown::<0xFEFF>()?;
    unknown::<{ *abi::TEST_CALLS.start() }>()?;
    unknown::<{ *abi::TEST_CALLS.end() }>()
}

fn unknown<const N: u16>() -> Outcome {
    let x = marked();
    // SAFETY: no call has number N.
    let after = unsafe { sys::raw::<N>(x) };
    check(
        after[0] == Error::InvalidArgs.code() && after[1..] == x[1..],
        "an unknown number did not fail with INVALID_ARGS alone",
    )
}

/// Priorities outside 1-63, bits above a priority's byte and unknown
/// policies fail with INVALID_ARGS; a priority above the ceiling of the
/// thread's process with ACCESS_DENIED (spec 8, 12).
fn priority_ceilings_hold() -> Outcome {
    for priority in [0, abi::PRIORITY_LEVELS] {
        check(
            sys::thread_set_priority(&init::THREAD, priority, Policy::Fifo)
                == Err(Error::InvalidArgs),
            "priority 0 or 64 was taken",
        )?;
    }
    let set_priority = |priority: u64, policy: u64| {
        let mut x = marked();
        x[0] = init::THREAD.raw().0;
        x[1] = priority;
        x[2] = policy;
        // SAFETY: thread_set_priority only reads its registers.
        let after = unsafe { sys::raw::<{ Call::ThreadSetPriority.number() }>(x) };
        after[0]
    };
    check(
        set_priority(0x100 | u64::from(TEST_PRIORITY), Policy::Fifo as u64)
            == Error::InvalidArgs.code(),
        "a priority with bits above its byte was taken",
    )?;
    check(
        set_priority(TEST_PRIORITY.into(), 2) == Error::InvalidArgs.code(),
        "policy 2 was taken",
    )?;
    check(
        sys::process_create(CHILD_QUOTA, 16, abi::PRIORITY_LEVELS) == Err(Error::InvalidArgs),
        "ceiling 64 was taken",
    )?;
    let c = child(LEVEL)?;
    let above = child_thread(&c, LEVEL + 1);
    let at = child_thread(&c, LEVEL);
    let (refused, made) = (above == Err(Error::AccessDenied), at.is_ok());
    close(c)?;
    for t in [above, at].into_iter().flatten() {
        close(t)?;
    }
    check(refused, "a thread above its process's ceiling was made")?;
    check(made, "a thread at its process's ceiling was not made")
}

/// Calls on a thread or a process in the wrong state fail with BAD_STATE:
/// a second start, a new priority for a thread that ended, a thread for a
/// process that ended.
fn thread_states() -> Outcome {
    reset_marks();
    let t = spawn(0, add_mark, 0, LOW, Policy::Fifo)?;
    let second = sys::thread_start(&t);
    let_run()?;
    let ended = sys::thread_set_priority(&t, LOW, Policy::Fifo);
    close(t)?;
    let c = child(LOW)?;
    let killed = sys::process_kill(&c);
    let late = child_thread(&c, LOW);
    let refused = late == Err(Error::BadState);
    close(c)?;
    if let Ok(t) = late {
        close(t)?;
    }
    check(second == Err(Error::BadState), "a thread started twice")?;
    check(
        ended == Err(Error::BadState),
        "a thread that ended took a new priority",
    )?;
    check(
        killed.is_ok() && refused,
        "a process that ended took a new thread",
    )
}

/// A stopped thread of init's process that runs add_mark(0) on the stack
/// of slot 0, at `priority`, with its message buffer on page `page` above
/// init's own.
fn marker(page: usize, priority: u8) -> Result<Handle<Thread>, Error> {
    // SAFETY: of the threads that share the stack of slot 0 at a time, at
    // most one runs, and it ends before the next test.
    unsafe {
        sys::thread_create(
            &init::PROCESS,
            add_mark,
            STACKS[0].top(),
            0,
            priority,
            Policy::Fifo,
            buffer(page),
        )
    }
}

/// A process has at most abi::MAX_THREADS threads that have not ended
/// (spec 8), init's first thread among them: past that thread_create
/// fails with LIMIT_REACHED. A thread that exits makes room again, while
/// its handle keeps its shell.
fn thread_limit_is_64() -> Outcome {
    reset_marks();
    let mut made: [Option<Handle<Thread>>; abi::MAX_THREADS as usize - 1] =
        [const { None }; abi::MAX_THREADS as usize - 1];
    for (page, slot) in made.iter_mut().enumerate() {
        *slot = marker(page, HIGH).ok();
    }
    let past = marker(made.len(), HIGH);
    // Above init, it runs and exits before thread_start returns.
    let started = made[0].as_ref().map(sys::thread_start);
    let again = marker(made.len(), HIGH);
    let all = made.iter().all(Option::is_some);
    let (refused, remade) = (past == Err(Error::LimitReached), again.is_ok());
    for h in made.into_iter().flatten().chain(past).chain(again) {
        close(h)?;
    }
    check(all, "63 threads next to init's did not fit")?;
    check(refused, "a 65th thread was made")?;
    check(
        started == Some(Ok(())) && mark(0) == 1,
        "a thread of the full process did not run to its exit",
    )?;
    check(remade, "the exit of a thread did not make room for another")
}

/// A thread started above init runs before thread_start returns.
fn higher_priority_start_preempts_at_once() -> Outcome {
    reset_marks();
    let t = thread(0, add_mark, 0, HIGH, Policy::Fifo)?;
    let started = sys::thread_start(&t);
    let ran = mark(0);
    close(t)?;
    check(started.is_ok(), "thread_start failed")?;
    check(
        ran == 1,
        "a thread above init did not run before thread_start returned",
    )
}

/// Init alone at its level yields while a thread below it is ready: the
/// yield returns at once, and the thread below does not run.
fn yield_does_not_let_lower_levels_run() -> Outcome {
    reset_marks();
    let t = spawn(0, add_mark, 0, LOW, Policy::Fifo)?;
    let yielded = sys::yield_now();
    let before = mark(0);
    let_run()?;
    close(t)?;
    check(yielded.is_ok(), "yield failed")?;
    check(before == 0, "yield let a thread below init run")?;
    check(
        mark(0) == 1,
        "the thread below init did not run once init lowered itself",
    )
}

/// Closing the only handle to a started thread does not end it.
fn closing_a_thread_handle_does_not_stop_it() -> Outcome {
    reset_marks();
    let t = spawn(0, add_mark, 0, LOW, Policy::Fifo)?;
    close(t)?;
    let_run()?;
    check(
        mark(0) == 1,
        "a thread whose handle was closed did not run to its end",
    )
}

/// Switches each thread of the alternation waits for.
const SWITCHES: u64 = 3;

/// What a thread of the alternation leaves: its count, the switches it
/// saw, and the shortest stretch that held a run of its peer.
struct Turns {
    count: AtomicU64,
    switches: AtomicU64,
    shortest: AtomicU64,
}

static TURNS: [Turns; 2] = [const {
    Turns {
        count: AtomicU64::new(0),
        switches: AtomicU64::new(0),
        shortest: AtomicU64::new(0),
    }
}; 2];

/// Two round-robin threads at one level spin without a call (spec 8).
/// Each sees the other run SWITCHES times between two turns of its loop,
/// and each such stretch, which holds the other's whole run, lasts at
/// least a quantum by the counter: the timer never fires before its
/// compare value.
fn rr_threads_alternate_by_quantum() -> Outcome {
    for t in &TURNS {
        t.count.store(0, Relaxed);
        t.switches.store(0, Relaxed);
        t.shortest.store(u64::MAX, Relaxed);
    }
    let a = spawn(0, alternate, 0, LEVEL, Policy::RoundRobin)?;
    let b = spawn(1, alternate, 1, LEVEL, Policy::RoundRobin)?;
    let_run()?;
    close(a)?;
    close(b)?;
    let quantum = time::ns_to_ticks(abi::RR_QUANTUM_NS);
    for t in &TURNS {
        check(
            t.switches.load(Relaxed) == SWITCHES,
            "a round-robin thread did not see its peer run",
        )?;
        check(
            t.shortest.load(Relaxed) >= quantum,
            "a round-robin thread ran for less than a quantum",
        )?;
    }
    Ok(())
}

/// Thread `me` (0 or 1) of the alternation. Each turn of its loop adds 1
/// to its count, reads the counter, the peer's count and the counter
/// again. When the peer's count has moved since the last turn, the peer
/// ran in between: a switch, and the stretch from the first reading of the
/// last turn to the second of this one holds that whole run. Stretches
/// after the SWITCHES-th switch do not count: a peer that is done ends its
/// run early. Ends once both threads have seen SWITCHES switches.
extern "C" fn alternate(me: u64) -> ! {
    let me = me as usize;
    let (mine, peer) = (&TURNS[me], &TURNS[1 - me]);
    let mut shortest = u64::MAX;
    let mut switches = 0;
    let mut last = time::now();
    let mut seen = peer.count.load(Relaxed);
    while switches < SWITCHES || peer.switches.load(Relaxed) < SWITCHES {
        mine.count.fetch_add(1, Relaxed);
        let first = time::now();
        let count = peer.count.load(Relaxed);
        let second = time::now();
        if count != seen {
            seen = count;
            if switches < SWITCHES {
                switches += 1;
                shortest = shortest.min(second - last);
                mine.switches.store(switches, Relaxed);
            }
        }
        last = first;
    }
    mine.shortest.store(shortest, Relaxed);
    sys::thread_exit()
}

/// Two FIFO threads at one level. The first spins for three quanta by the
/// counter while the second, ready all along, does not run; then the first
/// yields, and the second runs before the yield returns.
fn fifo_threads_do_not_alternate() -> Outcome {
    reset_marks();
    let quanta = 3 * time::ns_to_ticks(abi::RR_QUANTUM_NS);
    let spin = spawn(0, spin_then_yield, quanta, LEVEL, Policy::Fifo)?;
    let peer = spawn(1, add_mark, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    close(spin)?;
    close(peer)?;
    check(mark(1) == 0, "a FIFO thread let its peer run without yield")?;
    check(
        mark(2) == 1 && mark(3) == 1,
        "the peer did not run when the FIFO thread yielded",
    )
}

/// Spins until `ticks` counter ticks have passed, then yields. Leaves
/// mark 0 as it was before the yield in mark 1 and after it in mark 2,
/// and 1 in mark 3 when the yield succeeded.
extern "C" fn spin_then_yield(ticks: u64) -> ! {
    let end = time::now() + ticks;
    while time::now() < end {}
    MARKS[1].store(mark(0), Relaxed);
    let yielded = sys::yield_now().is_ok();
    MARKS[2].store(mark(0), Relaxed);
    MARKS[3].store(u64::from(yielded), Relaxed);
    sys::thread_exit()
}

/// Spec 15.2 (faults): a child with no code gets a thread above init whose
/// entry maps nothing. The thread runs at once and faults, which ends the
/// child; object_info tells init why, and the kernel prints the fault,
/// which xtask reads whole.
fn child_fault_reason_reaches_the_parent() -> Outcome {
    let c = child(HIGH)?;
    let t = child_thread(&c, HIGH).map_err(|_| "thread_create in the child failed")?;
    let started = sys::thread_start(&t);
    let state = sys::process_state(&c);
    close(t)?;
    close(c)?;
    check(started.is_ok(), "thread_start failed")?;
    let fault = ProcessState::Fault {
        esr: CHILD_FAULT_ESR,
        far: CHILD_ENTRY,
        elr: CHILD_ENTRY,
    };
    check(
        state == Ok(fault),
        "object_info does not report the fault at the child's entry",
    )
}

/// A child's thread below init is ready and has never run when init kills
/// the child: the reason is «killed», where a run would have left a
/// fault. Init then lets the threads below it run: a thread left in the
/// queue would fault there, and xtask would see a second fault line. A
/// second kill of the dead child succeeds.
fn kill_takes_a_ready_thread_off_the_queue() -> Outcome {
    let c = child(LOW)?;
    let t = child_thread(&c, LOW).map_err(|_| "thread_create in the child failed")?;
    let started = sys::thread_start(&t);
    let killed = sys::process_kill(&c);
    // A thread left on the queue would run now, above init at 1.
    let_run()?;
    let state = sys::process_state(&c);
    let again = sys::process_kill(&c);
    close(t)?;
    close(c)?;
    check(
        started.is_ok() && killed.is_ok(),
        "thread_start or process_kill failed",
    )?;
    check(
        state == Ok(ProcessState::Killed),
        "the child did not end as killed",
    )?;
    check(again.is_ok(), "a second kill of the dead child failed")
}

/// A child's quota comes off init's (spec 7.5): more than init has free
/// fails with NO_MEMORY and changes x0 alone, and so does a page, too
/// small for the child's own objects; a child that was not made gave
/// init's quota back before the call returned, although it failed only
/// at its entry 0. A child with the least quota, 8 KiB, is made; a thread
/// does not fit in it: NO_MEMORY again. A child made and closed first
/// leaves a free place in init's pool of shells, so that no call below
/// charges init a page of that pool.
fn quota_is_enforced() -> Outcome {
    close(
        sys::process_create(LEAST_QUOTA, 16, LOW)
            .map_err(|_| "a child with the least quota was not made")?,
    )?;
    let own = sys::process_memory(&init::PROCESS).map_err(|_| "PROCESS_MEMORY of init failed")?;
    let over = (own.quota - own.returned - own.used + 1).next_multiple_of(PAGE as u64);
    let mut x = marked();
    x[..6].copy_from_slice(&[over, 16, LOW.into(), 0, 0, 0]);
    // SAFETY: process_create only reads its registers.
    let after = unsafe { sys::raw::<{ Call::ProcessCreate.number() }>(x) };
    check(
        after[0] == Error::NoMemory.code() && after[1..] == x[1..],
        "a quota above init's did not fail with NO_MEMORY alone",
    )?;
    check(
        sys::process_create(PAGE as u64, 16, LOW) == Err(Error::NoMemory),
        "a child took a quota below the least",
    )?;
    check(
        sys::process_memory(&init::PROCESS).map(|m| m.used) == Ok(own.used),
        "a child that was not made kept init's quota after the call",
    )?;
    let c = sys::process_create(LEAST_QUOTA, 16, LOW)
        .map_err(|_| "a child with the least quota was not made")?;
    let t = child_thread(&c, LOW);
    let refused = t == Err(Error::NoMemory);
    close(c)?;
    if let Ok(t) = t {
        close(t)?;
    }
    check(refused, "a thread fit in a child with the least quota")
}

/// object_info's PROCESS_MEMORY and PROCESS_HANDLES (spec 11): a new child
/// has the quota init gave it, pays for its own objects from it, the least
/// quota by the page, and returned nothing; its table is empty, entry 0
/// went back, and its limit is the one init set. A thread makes the child
/// pay for the page of its pool of threads, the buffer and the three
/// tables over it. Init's table counts the handles to both. Init's quota
/// is every frame free when it was made (spec 7.5): the frames free are
/// exactly the parts of the quotas of init and its child nobody used.
fn process_info_kinds() -> Outcome {
    let before = sys::process_handles(&init::PROCESS);
    let c = child(LOW)?;
    let made = sys::process_memory(&c);
    let table = sys::process_handles(&c);
    let t = child_thread(&c, LOW);
    let with_thread = sys::process_memory(&c);
    let after = sys::process_handles(&init::PROCESS);
    let own = sys::process_memory(&init::PROCESS);
    let stats = sys::kernel_stats(&init::RESOURCE);
    let threaded = t.is_ok();
    close(c)?;
    if let Ok(t) = t {
        close(t)?;
    }
    let Ok(made) = made else {
        return Err("PROCESS_MEMORY of the child failed");
    };
    check(
        made.quota == CHILD_QUOTA && made.used == LEAST_QUOTA && made.returned == 0,
        "a new child does not pay for its root table and its page of blocks from the quota init gave it",
    )?;
    check(
        table
            == Ok(ProcessHandles {
                live: 0,
                retired: 0,
                limit: 16,
            }),
        "a new child's table is not empty with the limit init set",
    )?;
    check(
        threaded && with_thread.is_ok_and(|m| m.used == made.used + 5 * PAGE as u64),
        "the child did not pay for the page of its threads, the buffer and three tables",
    )?;
    let (Ok(before), Ok(after)) = (before, after) else {
        return Err("PROCESS_HANDLES of init failed");
    };
    check(
        after.live == before.live + 2
            && (after.retired, after.limit) == (before.retired, before.limit),
        "init's table did not count the handles to the child and its thread",
    )?;
    let (Ok(own), Ok(stats)) = (own, stats) else {
        return Err("PROCESS_MEMORY of init or KERNEL_STATS failed");
    };
    let free = stats.free_frames * PAGE as u64;
    check(
        own.used + own.returned < own.quota
            && own.returned == 0
            && own.quota > free
            && with_thread.is_ok_and(|m| own.quota - own.used + (m.quota - m.used) == free),
        "init's quota is not the frames that were free when it was made",
    )
}

/// KERNEL_STATS takes the system resource with KSTATS (spec 11): a process
/// is WRONG_TYPE, a copy of the resource with DEBUG alone ACCESS_DENIED,
/// though it writes; init's resource gets the counts in x1-x7 and changes
/// nothing past them. Nothing waits in the cleanup queue while init runs,
/// and the frames and pool pages are there.
fn kernel_stats_need_kstats() -> Outcome {
    check(
        sys::kernel_stats(&retyped(&init::PROCESS)) == Err(Error::WrongType),
        "a process handle gave the kernel's counts",
    )?;
    let debug = copy(&init::RESOURCE, Rights::DEBUG)?;
    let denied = sys::kernel_stats(&debug);
    let written = sys::debug_write(&debug, b"");
    close(debug)?;
    check(
        denied == Err(Error::AccessDenied) && written == Ok(0),
        "a copy of the resource without KSTATS gave the kernel's counts, or did not write",
    )?;
    let mut x = marked();
    x[..3].copy_from_slice(&[init::RESOURCE.raw().0, abi::INFO_KERNEL_STATS, 0]);
    // SAFETY: object_info only reads its registers.
    let after = unsafe { sys::raw::<{ Call::ObjectInfo.number() }>(x) };
    check(
        after[0] == 0 && after[8..] == x[8..],
        "KERNEL_STATS failed or changed registers past x7",
    )?;
    let stats = abi::KernelStats::from_words(after[1..8].try_into().expect("x1-x7"));
    check(
        stats.cleanup_queue == 0 && stats.free_frames > 0 && stats.pool_pages > 0,
        "the queue is not empty, or no frame or pool page is counted",
    )
}

/// Init at TEST_PRIORITY kills a child with a thread: the cleanup runs at
/// init's level before the call returns (spec 7.7), so right afterwards
/// the queue is empty and the child gave back all but the pages of its
/// pools of threads and blocks, which go with its shell (spec 7.8): the
/// shell of its thread, which init's handle keeps, lies in one of them.
fn process_kill_returns_after_the_teardown() -> Outcome {
    let c = child(LOW)?;
    let t = child_thread(&c, LOW);
    let killed = sys::process_kill(&c);
    let stats = sys::kernel_stats(&init::RESOURCE);
    let memory = sys::process_memory(&c);
    let made = t.is_ok() && killed.is_ok();
    close(c)?;
    if let Ok(t) = t {
        close(t)?;
    }
    check(made, "thread_create or process_kill failed")?;
    check(
        stats.is_ok_and(|s| s.cleanup_queue == 0),
        "the cleanup queue was not empty when process_kill returned",
    )?;
    check(
        memory.is_ok_and(|m| m.used == 2 * PAGE as u64 && m.used + m.returned == m.quota),
        "the child's quota was not back but for its two pages of pools when process_kill returned",
    )
}

/// A child's quota comes back to init in two parts (spec 7.5): once the
/// child is killed, all but what the shells of the child and of its
/// thread hold, which init's handles keep; the rest once init closes the
/// handles. Then init uses what it used before the child.
fn child_quota_comes_back() -> Outcome {
    let used = || sys::process_memory(&init::PROCESS).map(|m| m.used);
    let before = used();
    let c = child(LOW)?;
    let made = used();
    let t = child_thread(&c, LOW);
    let killed = sys::process_kill(&c);
    let after_kill = used();
    let child_memory = sys::process_memory(&c);
    let ended = t.is_ok() && killed.is_ok();
    if let Ok(t) = t {
        close(t)?;
    }
    let after_thread = used();
    close(c)?;
    let after = used();
    check(ended, "thread_create or process_kill failed")?;
    let (Ok(before), Ok(made), Ok(after_kill), Ok(child_memory)) =
        (before, made, after_kill, child_memory)
    else {
        return Err("PROCESS_MEMORY failed");
    };
    check(
        made == before + CHILD_QUOTA,
        "the child's quota did not come off init's",
    )?;
    check(
        child_memory
            == ProcessMemory {
                quota: CHILD_QUOTA,
                used: after_kill - before,
                returned: CHILD_QUOTA - (after_kill - before),
            }
            && child_memory.used > 0,
        "the free part of the child's quota did not come back at its end",
    )?;
    check(
        after_thread == Ok(after_kill),
        "closing the handle to the child's thread changed init's used memory",
    )?;
    check(
        after == Ok(before),
        "init did not get the rest of the child's quota with its shell",
    )
}

/// CYCLES rounds of a child with a ready thread, killed and closed, leave
/// init's used memory, the free frames and the pages of kernel pools as
/// they were, exactly (spec 7.5, 7.8): each child gives back every frame
/// it took and the pages of its pools with its shell, and the kill takes
/// the kernel's reference to the thread along. One round runs first: the
/// page of init's pool of shells that it takes stays init's.
fn create_kill_cycles_leak_nothing() -> Outcome {
    cycle()?;
    let before = counts()?;
    for _ in 0..CYCLES {
        cycle()?;
    }
    let after = counts()?;
    check(
        after.0 == before.0,
        "init's used memory grew over the rounds",
    )?;
    check(after.1 == before.1, "frames were lost over the rounds")?;
    check(after.2 == before.2, "the pools took pages over the rounds")
}

/// A child with a started thread that init kills and forgets. The thread
/// is ready below init and never runs: the kill takes it off the queue.
fn cycle() -> Outcome {
    let c = child(LOW)?;
    let t = child_thread(&c, LOW);
    let started = t.as_ref().map_err(|&e| e).and_then(sys::thread_start);
    let killed = sys::process_kill(&c);
    close(c)?;
    if let Ok(t) = t {
        close(t)?;
    }
    check(
        started.is_ok() && killed.is_ok(),
        "a round of create and kill failed",
    )
}

/// Init's used memory, the free frames and the pages of kernel pools.
fn counts() -> Result<(u64, u64, u64), &'static str> {
    let used = sys::process_memory(&init::PROCESS).map_err(|_| "PROCESS_MEMORY of init failed")?;
    let stats = sys::kernel_stats(&init::RESOURCE).map_err(|_| "KERNEL_STATS failed")?;
    Ok((used.used, stats.free_frames, stats.pool_pages))
}

/// A channel with its slot of label 0 at `priority`.
fn channel(priority: u8) -> Result<Handle<Channel>, &'static str> {
    sys::channel_create(priority).map_err(|_| "channel_create failed")
}

/// notify with raw registers.
fn raw_notify(x: Regs) -> Regs {
    // SAFETY: notify only reads its registers.
    unsafe { sys::raw::<{ Call::Notify.number() }>(x) }
}

/// receive with raw registers, for calls that must fail and change x0
/// alone.
fn raw_receive(x: Regs) -> Regs {
    // SAFETY: receive only reads its registers, and writes x10 and x11,
    // which `raw` gives up, only when it takes something.
    unsafe { sys::raw::<{ Call::Receive.number() }>(x) }
}

/// A notification of the slot of label 0.
fn unlabeled(bits: u64, count: u32) -> Received {
    Received::Notification {
        source: Source::Unlabeled,
        label: 0,
        bits,
        count,
    }
}

/// What `c` has, taken without waiting; then a second receive, which
/// finds nothing, ends the boost the first one gave init (spec 6.6).
fn take_one(c: &Handle<Channel>) -> Result<Received, &'static str> {
    let got = sys::try_receive(c);
    let rest = sys::try_receive(c);
    check(
        rest == Err(Error::WouldBlock),
        "a second receive found something",
    )?;
    got.map_err(|_| "receive found nothing")
}

/// channel_create takes a priority of 1-63 with no bits above its byte
/// (spec 11): anything else fails with INVALID_ARGS and changes x0 alone.
/// Init may take any priority under its ceiling of 63; the handle carries
/// NOTIFY and RECEIVE, and a notification goes through it and comes back.
/// ACCESS_DENIED for a priority above the caller's ceiling is a kernel
/// test: init's ceiling is the highest level.
fn channel_create_checks_its_priority() -> Outcome {
    for priority in [0, abi::PRIORITY_LEVELS.into(), 0x100 | u64::from(LEVEL)] {
        let mut x = marked();
        x[0] = priority;
        // SAFETY: channel_create only reads its registers.
        let after = unsafe { sys::raw::<{ Call::CreateChannel.number() }>(x) };
        check(
            after[0] == Error::InvalidArgs.code() && after[1..] == x[1..],
            "a priority outside 1-63 did not fail with INVALID_ARGS alone",
        )?;
    }
    close(channel(abi::PRIORITY_LEVELS - 1)?)?;
    let c = channel(QUIET)?;
    let posted = sys::notify(&c, 1);
    let got = take_one(&c);
    close(c)?;
    check(
        posted.is_ok() && got == Ok(unlabeled(1, 1)),
        "a new channel did not carry a notification",
    )
}

/// notify and receive take a channel (spec 11): a process is WRONG_TYPE,
/// a closed handle BAD_HANDLE, and x0 alone changes. A copy of the channel
/// with RECEIVE alone does not notify, and one with NOTIFY alone does not
/// receive: ACCESS_DENIED, and x0 alone changes.
fn notify_and_receive_need_their_rights() -> Outcome {
    let c = channel(QUIET)?;
    let gone = c.raw();
    close(c)?;
    for (h, error) in [
        (init::PROCESS.raw(), Error::WrongType),
        (gone, Error::BadHandle),
    ] {
        let mut x = marked();
        x[..2].copy_from_slice(&[h.0, 1]);
        let after = raw_notify(x);
        check(
            after[0] == error.code() && after[1..] == x[1..],
            "notify took a handle that is not a live channel",
        )?;
        x[1] = abi::NO_WAIT;
        let after = raw_receive(x);
        check(
            after[0] == error.code() && after[1..] == x[1..],
            "receive took a handle that is not a live channel",
        )?;
    }
    let c = channel(QUIET)?;
    let (notify_only, receive_only) = (copy(&c, Rights::NOTIFY)?, copy(&c, Rights::RECEIVE)?);
    let mut x = marked();
    x[..2].copy_from_slice(&[receive_only.raw().0, 1]);
    let notified = raw_notify(x);
    let mut y = marked();
    y[..2].copy_from_slice(&[notify_only.raw().0, abi::NO_WAIT]);
    let received = raw_receive(y);
    close(notify_only)?;
    close(receive_only)?;
    close(c)?;
    check(
        notified[0] == Error::AccessDenied.code() && notified[1..] == x[1..],
        "a copy without NOTIFY notified",
    )?;
    check(
        received[0] == Error::AccessDenied.code() && received[1..] == y[1..],
        "a copy without RECEIVE received",
    )
}

/// Spec 15.2 (notifications): three notify calls with different bits before
/// a receive come as one notification of the slot of label 0: the bits
/// ORed, the count 3. The slot is empty afterwards.
fn notifications_merge_bits_and_count() -> Outcome {
    let c = channel(QUIET)?;
    let posted = [0b001, 0b100, 0b100 | 1 << 40]
        .into_iter()
        .try_for_each(|bits| sys::notify(&c, bits));
    let got = take_one(&c);
    close(c)?;
    check(posted.is_ok(), "notify failed")?;
    check(
        got == Ok(unlabeled(0b101 | 1 << 40, 3)),
        "the bits did not merge, or the count is not 3",
    )
}

/// Bit 63 is CLIENT_GONE, which only the kernel posts (spec 5.3, 6.5):
/// notify with it fails with INVALID_ARGS before the handle is looked at,
/// changes x0 alone and posts nothing. notify with no bits counts.
fn notify_refuses_bit_63() -> Outcome {
    let c = channel(QUIET)?;
    let mut x = marked();
    x[..2].copy_from_slice(&[c.raw().0, 1 << 63 | 1]);
    let after = raw_notify(x);
    let mut bad = x;
    bad[0] = 0;
    let first = raw_notify(bad)[0];
    let nothing = sys::try_receive(&c);
    let posted = sys::notify(&c, 0);
    let got = take_one(&c);
    close(c)?;
    check(
        after[0] == Error::InvalidArgs.code() && after[1..] == x[1..],
        "bit 63 did not fail with INVALID_ARGS alone",
    )?;
    check(
        first == Error::InvalidArgs.code(),
        "the handle was looked at before the bits",
    )?;
    check(
        nothing == Err(Error::WouldBlock),
        "a notify that failed posted",
    )?;
    check(
        posted.is_ok() && got == Ok(unlabeled(0, 1)),
        "a notify with no bits did not count",
    )
}

/// Spec 15.2 (refusals): receive with NO_WAIT on an empty channel fails
/// with WOULD_BLOCK and changes x0 alone; flags other than NO_WAIT are
/// INVALID_ARGS, before the handle is looked at.
fn receive_without_waiting_is_would_block() -> Outcome {
    let c = channel(QUIET)?;
    let mut x = marked();
    x[..2].copy_from_slice(&[c.raw().0, abi::NO_WAIT]);
    let after = raw_receive(x);
    let odd: [Regs; 3] = [abi::NO_WAIT | 1, 1 << 17, 1 << 63].map(|flags| {
        let mut y = x;
        y[..2].copy_from_slice(&[0, flags]);
        raw_receive(y)
    });
    let typed = sys::try_receive(&c);
    close(c)?;
    check(
        after[0] == Error::WouldBlock.code() && after[1..] == x[1..],
        "receive with NO_WAIT on an empty channel did not fail with WOULD_BLOCK alone",
    )?;
    check(
        odd.iter().all(|r| r[0] == Error::InvalidArgs.code()),
        "a flag other than NO_WAIT was taken",
    )?;
    check(
        typed == Err(Error::WouldBlock),
        "try_receive did not fail with WOULD_BLOCK",
    )
}

/// A thread of init that waits in receive on the channel `h`, takes one
/// thing and leaves in mark 0 the result's error code, or 1 and in mark 2
/// what mark 1 held then; then asks again without waiting and leaves 1 in
/// mark 3 when that found nothing (WOULD_BLOCK). Ends afterwards.
extern "C" fn receive_twice(h: u64) -> ! {
    let c = Handle::<Channel>::from_raw(abi::Handle(h));
    match sys::receive(&c) {
        Ok(_) => {
            MARKS[2].store(mark(1), Relaxed);
            MARKS[0].store(1, Relaxed);
        }
        Err(e) => MARKS[0].store(e.code(), Relaxed),
    }
    if sys::try_receive(&c) == Err(Error::WouldBlock) {
        MARKS[3].store(1, Relaxed);
    }
    sys::thread_exit()
}

/// A receiver of init at LOW waiting on a new channel whose slot of label
/// 0 has `priority`: init lets it run until it waits.
fn waiting_receiver(priority: u8) -> Result<(Handle<Channel>, Handle<Thread>), &'static str> {
    reset_marks();
    let c = channel(priority)?;
    let r = spawn(0, receive_twice, c.raw().0, LOW, Policy::Fifo)?;
    let_run()?;
    Ok((c, r))
}

/// Spec 15.2 (notifications): a receiver at base priority 5 waits, and a
/// thread at init's level 20 is ready behind init. A notification of
/// priority 25 wakes the receiver at 25 (spec 6.6): it runs before notify
/// returns, ahead of the ready thread, which has not run by then.
fn notification_runs_at_its_priority() -> Outcome {
    let (c, r) = waiting_receiver(NOTICE)?;
    let peer = spawn(1, add_mark, 1, TEST_PRIORITY, Policy::Fifo)?;
    let waited = mark(0);
    let posted = sys::notify(&c, 1);
    let (ran, peer_before) = (mark(0), mark(2));
    let_run()?;
    let peer_after = mark(1);
    close(peer)?;
    close(r)?;
    close(c)?;
    check(waited == 0, "the receiver did not wait")?;
    check(
        posted.is_ok() && ran == 1,
        "the receiver did not run at the notification's priority before notify returned",
    )?;
    check(
        peer_before == 0 && peer_after == 1,
        "the thread at init's level ran before the notified receiver",
    )
}

/// The boost lasts until the receiver's next receive (spec 6.6): woken at
/// 25 as above, the receiver asks again at once without waiting, which
/// drops it to its base of 5, below init: init runs again before the
/// receiver gets past that receive.
fn boost_ends_at_the_next_receive() -> Outcome {
    let (c, r) = waiting_receiver(NOTICE)?;
    let posted = sys::notify(&c, 1);
    let (first, second) = (mark(0), mark(3));
    let_run()?;
    let later = mark(3);
    close(r)?;
    close(c)?;
    check(
        posted.is_ok() && first == 1,
        "the notification did not wake the receiver above init",
    )?;
    check(
        second == 0,
        "the receiver kept the notification's priority past its next receive",
    )?;
    check(
        later == 1,
        "the receiver's second receive did not find the channel empty",
    )
}

/// Spec 15.2 (refusals): a receiver waits; init closes the only handle with
/// RECEIVE, which closes the channel (spec 6.8): the receiver wakes with
/// PEER_CLOSED.
fn waiting_receiver_gets_peer_closed() -> Outcome {
    let (c, r) = waiting_receiver(LEVEL)?;
    let waited = mark(0);
    close(c)?;
    let_run()?;
    close(r)?;
    check(waited == 0, "the receiver did not wait")?;
    check(
        mark(0) == Error::PeerClosed.code(),
        "the waiting receiver did not get PEER_CLOSED",
    )
}

/// A copy of `h` with `rights` and no new label.
fn copy<K>(h: &Handle<K>, rights: Rights) -> Result<Handle<K>, &'static str> {
    sys::handle_duplicate(h, rights).map_err(|_| "handle_duplicate failed")
}

/// A copy of the channel handle `c` with `rights` and the new label
/// `label`: a session whose slot has `priority`.
fn session(
    c: &Handle<Channel>,
    rights: Rights,
    label: u64,
    priority: u8,
) -> Result<Handle<Channel>, &'static str> {
    sys::handle_label(c, rights, label, priority).map_err(|_| "a label did not go on a copy")
}

/// handle_duplicate with raw registers.
fn raw_duplicate(x: Regs) -> Regs {
    // SAFETY: handle_duplicate only reads its registers.
    unsafe { sys::raw::<{ Call::HandleDuplicate.number() }>(x) }
}

/// x0-x9 for handle_duplicate of `h` with `rights`, `label` and
/// `priority`, the rest marked.
fn duplicate_regs(h: abi::Handle, rights: Rights, label: u64, priority: u64) -> Regs {
    let mut x = marked();
    x[..4].copy_from_slice(&[h.0, rights.0.into(), label, priority]);
    x
}

/// A notification of the session with `label`.
fn labelled(label: u64, bits: u64, count: u32) -> Received {
    Received::Notification {
        source: Source::Session,
        label,
        bits,
        count,
    }
}

/// handle_duplicate copies a handle of any kind with a subset of its
/// rights (spec 5.2, 11) and changes x0 and x1 alone: a copy of a channel
/// with NOTIFY alone notifies, does not receive (ACCESS_DENIED) and, with
/// no DUPLICATE, is copied no further. A right the original lacks fails
/// with ACCESS_DENIED, bits no right has with INVALID_ARGS before the
/// handle is looked at, and both change x0 alone. A copy of init's process
/// with no rights names it still.
fn duplicate_narrows_rights() -> Outcome {
    let c = channel(QUIET)?;
    let x = duplicate_regs(c.raw(), Rights::NOTIFY, 0, 0);
    let after = raw_duplicate(x);
    let made = after[0] == 0 && after[1] != 0 && after[2..] == x[2..];
    let n = Handle::<Channel>::from_raw(abi::Handle(after[1]));
    let posted = sys::notify(&n, 1);
    let refused = sys::try_receive(&n);
    let further = sys::handle_duplicate(&n, Rights::NOTIFY);
    let got = take_one(&c);
    let y = duplicate_regs(c.raw(), CHANNEL_RIGHTS | Rights::MANAGE, 0, 0);
    let wider = raw_duplicate(y);
    let odd = [1 << 12, 1 << 32].map(|rights| {
        let mut z = x;
        z[..2].copy_from_slice(&[0, rights]);
        let after = raw_duplicate(z);
        after[0] == Error::InvalidArgs.code() && after[1..] == z[1..]
    });
    let own = copy(&init::PROCESS, Rights::NONE)?;
    let state = sys::process_state(&own);
    close(own)?;
    close(n)?;
    close(c)?;
    check(made, "the copy did not come in x1 alone")?;
    check(
        posted.is_ok() && got == Ok(unlabeled(1, 1)),
        "the copy with NOTIFY did not notify",
    )?;
    check(
        refused == Err(Error::AccessDenied),
        "the copy with NOTIFY alone received",
    )?;
    check(
        further == Err(Error::AccessDenied),
        "a copy without DUPLICATE was copied",
    )?;
    check(
        wider[0] == Error::AccessDenied.code() && wider[1..] == y[1..],
        "a copy took a right the original lacks",
    )?;
    check(
        odd.iter().all(|&ok| ok),
        "bits no right has did not fail with INVALID_ARGS alone",
    )?;
    check(
        state == Ok(ProcessState::Alive),
        "a copy of init's process with no rights does not name it",
    )
}

/// A label goes on a channel handle once (spec 5.3): a new label on a
/// handle that carries one fails with BAD_STATE and changes x0 alone, and
/// a copy with label 0 carries the same label. A label on a handle that is
/// no channel fails with WRONG_TYPE.
fn label_cannot_change() -> Outcome {
    let c = channel(QUIET)?;
    let first = session(&c, Rights::NOTIFY | Rights::DUPLICATE, 7, QUIET)?;
    let x = duplicate_regs(first.raw(), Rights::NOTIFY, 8, QUIET.into());
    let after = raw_duplicate(x);
    let same = copy(&first, Rights::NOTIFY)?;
    let posted = sys::notify(&same, 1);
    let got = take_one(&c);
    let process = sys::handle_label(&retyped(&init::PROCESS), Rights::NONE, 9, QUIET);
    close(c)?;
    close(same)?;
    close(first)?;
    check(
        after[0] == Error::BadState.code() && after[1..] == x[1..],
        "a handle with a label took a new one",
    )?;
    check(
        posted.is_ok() && got == Ok(labelled(7, 1, 1)),
        "a copy with label 0 did not keep the label",
    )?;
    check(
        process == Err(Error::WrongType),
        "a handle to a process took a label",
    )
}

/// The priority of a session's slot (spec 5.3, 6.5): with a label 1-63,
/// 63, init's ceiling, included; without one exactly 0; anything else
/// fails with INVALID_ARGS and changes x0 alone. A receiver at LOW waits
/// on a channel whose slot of label 0 has LEVEL, below init; notify
/// through a session of priority NOTICE wakes it above init (spec 6.6), so
/// it runs before notify returns. ACCESS_DENIED for a priority above the
/// caller's ceiling is a kernel test: init's ceiling is the highest level.
fn session_priority_under_the_ceiling() -> Outcome {
    let (c, r) = waiting_receiver(LEVEL)?;
    let refused = [
        (9, 0),
        (0, u64::from(QUIET)),
        (9, abi::PRIORITY_LEVELS.into()),
        (9, 0x100 | u64::from(QUIET)),
    ]
    .map(|(label, priority)| {
        let x = duplicate_regs(c.raw(), Rights::NOTIFY, label, priority);
        let after = raw_duplicate(x);
        after[0] == Error::InvalidArgs.code() && after[1..] == x[1..]
    });
    let top = session(&c, Rights::NOTIFY, 63, abi::PRIORITY_LEVELS - 1)?;
    let s = session(&c, Rights::NOTIFY, 25, NOTICE)?;
    let waited = mark(0);
    let posted = sys::notify(&s, 1);
    let ran = mark(0);
    let_run()?;
    close(r)?;
    close(c)?;
    close(s)?;
    close(top)?;
    check(
        refused.iter().all(|&ok| ok),
        "a priority outside 1-63 with a label, or one without a label, was taken",
    )?;
    check(waited == 0, "the receiver did not wait")?;
    check(
        posted.is_ok() && ran == 1,
        "the receiver did not run at the session's priority before notify returned",
    )
}

/// Spec 15.2 (notifications): notify through a handle with a label goes
/// into its session's slot (spec 5.3, 6.5), and receive gives the source
/// «session», the label, the bits and the count; notify through the handle
/// with no label still goes into the slot of label 0. At one level they
/// come in the order they came. Bit 63 fails through a session too.
fn session_notice_carries_its_label() -> Outcome {
    let c = channel(QUIET)?;
    let s = session(&c, Rights::NOTIFY, 0x5E55, QUIET)?;
    let posted = [
        sys::notify(&s, 0b01),
        sys::notify(&s, 0b10),
        sys::notify(&c, 0b100),
    ];
    let bit_63 = sys::notify(&s, CLIENT_GONE);
    let first = sys::try_receive(&c);
    let second = take_one(&c);
    close(c)?;
    close(s)?;
    check(posted.iter().all(Result::is_ok), "notify failed")?;
    check(
        bit_63 == Err(Error::InvalidArgs),
        "bit 63 went through a session",
    )?;
    check(
        first == Ok(labelled(0x5E55, 0b11, 2)),
        "the session's notification did not carry its label, bits and count",
    )?;
    check(
        second == Ok(unlabeled(0b100, 1)),
        "the slot of label 0 did not come after the session's",
    )
}

/// Spec 15.2 (refusals): two handles carry one label, the second a copy of
/// the first. Closing the first posts nothing; closing the last posts
/// CLIENT_GONE, bit 63, into the session's slot with the label (spec 5.3),
/// and the bits the client posted before it left come in the same receive.
fn client_gone_after_the_last_copy() -> Outcome {
    let c = channel(QUIET)?;
    let first = session(&c, Rights::NOTIFY | Rights::DUPLICATE, 0xC1, QUIET)?;
    let last = copy(&first, Rights::NOTIFY)?;
    close(first)?;
    check(
        sys::try_receive(&c) == Err(Error::WouldBlock),
        "closing one of two copies posted into the session's slot",
    )?;
    let posted = sys::notify(&last, 0b10);
    close(last)?;
    let got = take_one(&c);
    close(c)?;
    check(
        posted.is_ok() && got == Ok(labelled(0xC1, 0b10 | CLIENT_GONE, 2)),
        "the last copy did not leave CLIENT_GONE with the label and the client's bits",
    )
}

/// Spec 15.2 (notifications): slots come by priority, and in the order they
/// came within a level (spec 6.3). The slot of label 0 at LEVEL is posted
/// first, then two sessions at HIGH: receive takes the first session, the
/// second, then the slot of label 0.
fn higher_notification_comes_first() -> Outcome {
    let c = channel(LEVEL)?;
    let a = session(&c, Rights::NOTIFY, 0xA, HIGH)?;
    let b = session(&c, Rights::NOTIFY, 0xB, HIGH)?;
    let posted = [sys::notify(&c, 1), sys::notify(&a, 2), sys::notify(&b, 4)];
    let got = [(); 4].map(|()| sys::try_receive(&c));
    close(c)?;
    close(a)?;
    close(b)?;
    check(posted.iter().all(Result::is_ok), "notify failed")?;
    check(
        got == [
            Ok(labelled(0xA, 2, 1)),
            Ok(labelled(0xB, 4, 1)),
            Ok(unlabeled(1, 1)),
            Err(Error::WouldBlock),
        ],
        "the slots did not come by priority and within a level in their order",
    )
}

/// Spec 15.2 (refusals): when the last handle with RECEIVE goes, the
/// channel closes (spec 6.5, 6.8): notify through a copy with NOTIFY and
/// through a session fails with PEER_CLOSED and changes x0 alone, and so
/// does a new label; a copy with label 0 is still made.
fn notify_after_close_is_peer_closed() -> Outcome {
    let c = channel(QUIET)?;
    let left = copy(&c, Rights::NOTIFY | Rights::DUPLICATE)?;
    let s = session(&c, Rights::NOTIFY, 0xDEAD, QUIET)?;
    let posted = sys::notify(&s, 1);
    close(c)?;
    let mut x = marked();
    x[..2].copy_from_slice(&[left.raw().0, 1]);
    let mut y = marked();
    y[..2].copy_from_slice(&[s.raw().0, 1]);
    let z = duplicate_regs(left.raw(), Rights::NOTIFY, 0xBEEF, QUIET.into());
    let after = [raw_notify(x), raw_notify(y), raw_duplicate(z)];
    let plain = copy(&left, Rights::NOTIFY);
    let copied = plain.is_ok();
    if let Ok(h) = plain {
        close(h)?;
    }
    close(left)?;
    close(s)?;
    check(posted.is_ok(), "notify through a session failed")?;
    check(
        after
            .iter()
            .zip([x, y, z])
            .all(|(a, x)| a[0] == Error::PeerClosed.code() && a[1..] == x[1..]),
        "notify or a new label on a closed channel did not fail with PEER_CLOSED alone",
    )?;
    check(
        copied,
        "a copy of a closed channel with label 0 was not made",
    )
}

/// Spec 15.2 (notifications): a channel has abi::MAX_SLOTS slots, its slot
/// of label 0 among them (spec 6.5). Init makes 1023 sessions and closes
/// each at once, and CLIENT_GONE keeps each in the channel's queue. The
/// next label fails with LIMIT_REACHED and changes x0 alone. Once receive
/// took the first CLIENT_GONE, that session went, and a new label fits.
/// Every session leaves with CLIENT_GONE, in the order they left.
fn slot_limit_is_1024() -> Outcome {
    let c = channel(QUIET)?;
    let last = u64::from(abi::MAX_SLOTS) - 1;
    for label in 1..=last {
        close(session(&c, Rights::NONE, label, QUIET)?)?;
    }
    let x = duplicate_regs(c.raw(), Rights::NONE, last + 1, QUIET.into());
    let after = raw_duplicate(x);
    let first = sys::try_receive(&c);
    let again = sys::handle_label(&c, Rights::NONE, last + 1, QUIET);
    let remade = again.is_ok();
    if let Ok(h) = again {
        close(h)?;
    }
    let order =
        (2..=last + 1).all(|label| sys::try_receive(&c) == Ok(labelled(label, CLIENT_GONE, 1)));
    let rest = sys::try_receive(&c);
    close(c)?;
    check(
        after[0] == Error::LimitReached.code() && after[1..] == x[1..],
        "a session past 1023 and the slot of label 0 was made",
    )?;
    check(
        first == Ok(labelled(1, CLIENT_GONE, 1)),
        "the first session did not leave with CLIENT_GONE",
    )?;
    check(remade, "no new session fit once one went")?;
    check(
        order && rest == Err(Error::WouldBlock),
        "the sessions did not leave with CLIENT_GONE in their order",
    )
}
