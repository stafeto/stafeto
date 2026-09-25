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
//! itself to 1 (`let_run`), and init runs again once they all have ended:
//! nothing to wait on exists in milestone 1.2c, so the order of priorities
//! joins threads.

#![no_std]
#![no_main]

use abi::{
    Call, Error, Handle, INIT_BOOT_IMAGE, INIT_PROCESS, INIT_RESOURCE, INIT_THREAD, Policy,
    ProcessHandles, ProcessMemory, ProcessState,
};
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use rt::sys::{self, Regs};
use rt::{Stack, println, time};

rt::entry!(main);

type Outcome = Result<(), &'static str>;
/// A test's name and body.
type Test = (&'static str, fn() -> Outcome);

const TESTS: [Test; 23] = [
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
    rt::console::set(INIT_RESOURCE);
    println!("counter ticks of 10000 turns: {}", loop_ticks());
    let mut failed = 0;
    for (i, (name, test)) in TESTS.into_iter().enumerate() {
        if i == 1 {
            sys::thread_set_priority(INIT_THREAD, TEST_PRIORITY, Policy::Fifo)
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

fn close(h: Handle) -> Outcome {
    sys::handle_close(h).map_err(|_| "handle_close failed")
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
) -> Result<Handle, &'static str> {
    // SAFETY: each test lets its threads end before the next test uses the
    // slot, so the stack is the thread's alone.
    let t = unsafe {
        sys::thread_create(
            INIT_PROCESS,
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
) -> Result<Handle, &'static str> {
    let t = thread(slot, entry, arg, priority, policy)?;
    sys::thread_start(t).map_err(|_| "thread_start failed")?;
    Ok(t)
}

/// Lets every thread below init run until it ends: init lowers itself to
/// 1 and, once it runs again, takes TEST_PRIORITY back.
fn let_run() -> Outcome {
    sys::thread_set_priority(INIT_THREAD, 1, Policy::Fifo)
        .map_err(|_| "init could not lower itself")?;
    sys::thread_set_priority(INIT_THREAD, TEST_PRIORITY, Policy::Fifo)
        .map_err(|_| "init could not take its priority back")
}

/// A child with no code, CHILD_QUOTA, room for 16 handles and ceiling
/// `ceiling`.
fn child(ceiling: u8) -> Result<Handle, &'static str> {
    sys::process_create(CHILD_QUOTA, 16, ceiling).map_err(|_| "process_create failed")
}

/// A stopped thread of `process` at CHILD_ENTRY, FIFO at `priority`.
fn child_thread(process: Handle, priority: u8) -> Result<Handle, Error> {
    let mut x = [0; 10];
    x[0] = process.0;
    x[1] = CHILD_ENTRY;
    x[4] = priority.into();
    x[5] = Policy::Fifo as u64;
    x[6] = CHILD_BUFFER;
    // SAFETY: the thread runs in another process and touches nothing of
    // init's.
    let after = unsafe { sys::raw::<{ Call::ThreadCreate.number() }>(x) };
    match Error::from_code(after[0]) {
        None => Ok(Handle(after[1])),
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
        sys::process_state(INIT_PROCESS) == Ok(ProcessState::Alive),
        "INIT_PROCESS is not a live process",
    )?;
    check(
        sys::debug_write(INIT_RESOURCE, b"") == Ok(0),
        "INIT_RESOURCE does not write to the console",
    )?;
    check(
        sys::process_state(INIT_RESOURCE) == Err(Error::WrongType),
        "INIT_RESOURCE is not the system resource",
    )?;
    check(
        sys::thread_set_priority(INIT_THREAD, TEST_PRIORITY, Policy::Fifo).is_ok(),
        "INIT_THREAD is not a thread with MANAGE",
    )?;
    check(
        sys::process_state(INIT_THREAD) == Err(Error::WrongType),
        "INIT_THREAD is a process",
    )
}

/// Until milestone 1.3 the boot image's handle is bad (spec 13.3).
fn boot_image_handle_is_reserved() -> Outcome {
    check(
        sys::process_state(INIT_BOOT_IMAGE) == Err(Error::BadHandle),
        "object_info took INIT_BOOT_IMAGE",
    )?;
    check(
        sys::handle_close(INIT_BOOT_IMAGE) == Err(Error::BadHandle),
        "handle_close took INIT_BOOT_IMAGE",
    )
}

/// The kernel mapped the first thread's message buffer at abi::INIT_MSGBUF:
/// no new thread gets the page, and init reads and writes it.
fn init_has_its_message_buffer() -> Outcome {
    // SAFETY: as in `thread`; slot 0 is free.
    let taken = unsafe {
        sys::thread_create(
            INIT_PROCESS,
            add_mark,
            STACKS[0].top(),
            0,
            LOW,
            Policy::Fifo,
            abi::INIT_MSGBUF as usize,
        )
    };
    if let Ok(t) = taken {
        close(t)?;
    }
    check(
        taken == Err(Error::InvalidArgs),
        "the page of init's message buffer is free",
    )?;
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
    x[0] = INIT_RESOURCE.0;
    x[1] = abi::INLINE_MAX as u64 + 1;
    // SAFETY: debug_write only reads its registers.
    let after = unsafe { sys::raw::<{ Call::DebugWrite.number() }>(x) };
    check(
        after[0] == Error::InvalidArgs.code() && after[1..] == x[1..],
        "65 bytes did not fail with INVALID_ARGS alone",
    )?;
    check(
        sys::debug_write(INIT_PROCESS, b"x") == Err(Error::WrongType),
        "a process handle wrote",
    )?;
    let c = child(LOW)?;
    close(c)?;
    check(
        sys::debug_write(c, b"x") == Err(Error::BadHandle),
        "a closed handle wrote",
    )?;
    let mut bytes = [b'#'; abi::INLINE_MAX];
    bytes[..STOPS.len()].copy_from_slice(STOPS);
    let mut x = [0; 10];
    x[0] = INIT_RESOURCE.0;
    x[1] = STOPS.len() as u64;
    x[2..].copy_from_slice(&abi::inline_words(&bytes));
    // SAFETY: as above.
    let after = unsafe { sys::raw::<{ Call::DebugWrite.number() }>(x) };
    check(
        after[..2] == [0, STOPS.len() as u64],
        "debug_write did not write the bytes of its length",
    )?;
    check(
        sys::debug_write(INIT_RESOURCE, b"\n") == Ok(1),
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
            sys::thread_set_priority(INIT_THREAD, priority, Policy::Fifo)
                == Err(Error::InvalidArgs),
            "priority 0 or 64 was taken",
        )?;
    }
    let set_priority = |priority: u64, policy: u64| {
        let mut x = marked();
        x[0] = INIT_THREAD.0;
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
    let above = child_thread(c, LEVEL + 1);
    let at = child_thread(c, LEVEL);
    close(c)?;
    for t in [above, at].into_iter().flatten() {
        close(t)?;
    }
    check(
        above == Err(Error::AccessDenied),
        "a thread above its process's ceiling was made",
    )?;
    check(at.is_ok(), "a thread at its process's ceiling was not made")
}

/// Calls on a thread or a process in the wrong state fail with BAD_STATE:
/// a second start, a new priority for a thread that ended, a thread for a
/// process that ended.
fn thread_states() -> Outcome {
    reset_marks();
    let t = spawn(0, add_mark, 0, LOW, Policy::Fifo)?;
    let second = sys::thread_start(t);
    let_run()?;
    let ended = sys::thread_set_priority(t, LOW, Policy::Fifo);
    close(t)?;
    let c = child(LOW)?;
    let killed = sys::process_kill(c);
    let late = child_thread(c, LOW);
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
        killed.is_ok() && late == Err(Error::BadState),
        "a process that ended took a new thread",
    )
}

/// A stopped thread of init's process that runs add_mark(0) on the stack
/// of slot 0, at `priority`, with its message buffer on page `page` above
/// init's own.
fn marker(page: usize, priority: u8) -> Result<Handle, Error> {
    // SAFETY: of the threads that share the stack of slot 0 at a time, at
    // most one runs, and it ends before the next test.
    unsafe {
        sys::thread_create(
            INIT_PROCESS,
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
    let mut made = [None; abi::MAX_THREADS as usize - 1];
    for (page, slot) in made.iter_mut().enumerate() {
        *slot = marker(page, HIGH).ok();
    }
    let past = marker(made.len(), HIGH);
    // Above init, it runs and exits before thread_start returns.
    let started = made[0].map(sys::thread_start);
    let again = marker(made.len(), HIGH);
    let all = made.iter().all(Option::is_some);
    for h in made.into_iter().flatten().chain(past).chain(again) {
        close(h)?;
    }
    check(all, "63 threads next to init's did not fit")?;
    check(past == Err(Error::LimitReached), "a 65th thread was made")?;
    check(
        started == Some(Ok(())) && mark(0) == 1,
        "a thread of the full process did not run to its exit",
    )?;
    check(
        again.is_ok(),
        "the exit of a thread did not make room for another",
    )
}

/// A thread started above init runs before thread_start returns.
fn higher_priority_start_preempts_at_once() -> Outcome {
    reset_marks();
    let t = thread(0, add_mark, 0, HIGH, Policy::Fifo)?;
    let started = sys::thread_start(t);
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
    let t = child_thread(c, HIGH).map_err(|_| "thread_create in the child failed")?;
    let started = sys::thread_start(t);
    let state = sys::process_state(c);
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
    let t = child_thread(c, LOW).map_err(|_| "thread_create in the child failed")?;
    let started = sys::thread_start(t);
    let killed = sys::process_kill(c);
    // A thread left on the queue would run now, above init at 1.
    let_run()?;
    let state = sys::process_state(c);
    let again = sys::process_kill(c);
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
    let own = sys::process_memory(INIT_PROCESS).map_err(|_| "PROCESS_MEMORY of init failed")?;
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
        sys::process_memory(INIT_PROCESS).map(|m| m.used) == Ok(own.used),
        "a child that was not made kept init's quota after the call",
    )?;
    let c = sys::process_create(LEAST_QUOTA, 16, LOW)
        .map_err(|_| "a child with the least quota was not made")?;
    let t = child_thread(c, LOW);
    close(c)?;
    if let Ok(t) = t {
        close(t)?;
    }
    check(
        t == Err(Error::NoMemory),
        "a thread fit in a child with the least quota",
    )
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
    let before = sys::process_handles(INIT_PROCESS);
    let c = child(LOW)?;
    let made = sys::process_memory(c);
    let table = sys::process_handles(c);
    let t = child_thread(c, LOW);
    let with_thread = sys::process_memory(c);
    let after = sys::process_handles(INIT_PROCESS);
    let own = sys::process_memory(INIT_PROCESS);
    let stats = sys::kernel_stats(INIT_RESOURCE);
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
        t.is_ok() && with_thread.is_ok_and(|m| m.used == made.used + 5 * PAGE as u64),
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
/// is WRONG_TYPE; init's resource gets the counts in x1-x7 and changes
/// nothing past them. Nothing waits in the cleanup queue while init runs,
/// and the frames and pool pages are there. A copy of the resource without
/// KSTATS, which ACCESS_DENIED needs, comes with handle_duplicate
/// (milestone 1.3b).
fn kernel_stats_need_kstats() -> Outcome {
    check(
        sys::kernel_stats(INIT_PROCESS) == Err(Error::WrongType),
        "a process handle gave the kernel's counts",
    )?;
    let mut x = marked();
    x[..3].copy_from_slice(&[INIT_RESOURCE.0, abi::INFO_KERNEL_STATS, 0]);
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
    let t = child_thread(c, LOW);
    let killed = sys::process_kill(c);
    let stats = sys::kernel_stats(INIT_RESOURCE);
    let memory = sys::process_memory(c);
    close(c)?;
    if let Ok(t) = t {
        close(t)?;
    }
    check(
        t.is_ok() && killed.is_ok(),
        "thread_create or process_kill failed",
    )?;
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
    let used = || sys::process_memory(INIT_PROCESS).map(|m| m.used);
    let before = used();
    let c = child(LOW)?;
    let made = used();
    let t = child_thread(c, LOW);
    let killed = sys::process_kill(c);
    let after_kill = used();
    let child_memory = sys::process_memory(c);
    if let Ok(t) = t {
        close(t)?;
    }
    let after_thread = used();
    close(c)?;
    let after = used();
    check(
        t.is_ok() && killed.is_ok(),
        "thread_create or process_kill failed",
    )?;
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
    let t = child_thread(c, LOW);
    let started = t.and_then(sys::thread_start);
    let killed = sys::process_kill(c);
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
    let used = sys::process_memory(INIT_PROCESS).map_err(|_| "PROCESS_MEMORY of init failed")?;
    let stats = sys::kernel_stats(INIT_RESOURCE).map_err(|_| "KERNEL_STATS failed")?;
    Ok((used.used, stats.free_frames, stats.pool_pages))
}
