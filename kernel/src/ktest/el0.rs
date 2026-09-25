// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Kernel tests at EL0. They run after all the others, one after another,
//! as a chain: a test builds its processes and threads, the scheduler
//! starts the threads and the kernel leaves for EL0 through
//! sched::resume; since every entry from EL0 starts over at the top of
//! the kernel stack, the kernel never comes back to the test's frame. A
//! program ends with `svc #SVC_DONE`: the test judges the thread, which
//! leaves the scheduler; once every thread of the test has passed or
//! ended as the test expects (`Fixture::ends`), or one has failed, the
//! test prints its line and the next one starts; the cleanup queue runs
//! dry in between. After the last one the run ends. The programs are in
//! el0.S.

use super::{CAUSE, CHILD_QUOTA, QUOTA, check, finish, report};
use crate::arch::user::{self, FpRegs, UserRegs};
use crate::arch::{self, cache, gic, symbols, timer};
use crate::channel::{self, Channel};
use crate::cleanup;
use crate::mm::{pages, phys};
use crate::object::Object;
use crate::process::{self, Process, Stage};
use crate::syscall::{self, Values};
use crate::thread::{self, Policy, Thread};
use crate::{sched, session};
use abi::{
    Call, Error, Handle, INFO_PROCESS_STATE, MAX_THREADS, NO_WAIT, Notification, ProcessState,
    Rights, START_CHANNEL, Source,
};
use core::ptr::NonNull;
use kcore::esr;
use kcore::frames::PAGE_SIZE;
use kcore::gic::PRIORITY_MASK;
use kcore::handles::{MAX_CHUNKS, MAX_HANDLES};
use kcore::layout::LINEAR_BASE;
use kcore::paging::{Attrs, BLOCK_2M};
use kcore::sched::State;
use kcore::sync::Lock;
use kcore::sysreg::SPSR_NZCV;

core::arch::global_asm!(include_str!("el0.S"), options(raw));

unsafe extern "C" {
    static el0_programs: u8;
    static el0_programs_end: u8;
    static el0_read_counter: u8;
    static el0_pattern_nop: u8;
    static el0_pattern_unknown: u8;
    static el0_pattern_loop: u8;
    static el0_wait_loop: u8;
    static el0_pattern_yield: u8;
    static el0_mark: u8;
    static el0_count_until: u8;
    static el0_spin_then_yield: u8;
    static el0_set_priority: u8;
    static el0_set_priority_after_peer: u8;
    static el0_alternate: u8;
    static el0_load: u8;
    static el0_done_at_once: u8;
    static el0_pattern_close: u8;
    static el0_pattern_object_info: u8;
    static el0_pattern_debug_write: u8;
    static el0_wfi: u8;
    static el0_kill: u8;
    static el0_exit_process: u8;
    static el0_create_then_exit: u8;
    static el0_info_then_exit: u8;
    static el0_start_and_close: u8;
    static el0_buffer_mark: u8;
    static el0_child_fault: u8;
    static el0_start_then_close: u8;
    static el0_receive: u8;
    static el0_notify: u8;
    static el0_receive_then_exit: u8;
    static el0_kill_notify_receive: u8;
    static el0_raise_then_notify: u8;
}

/// Test system calls: the numbers lie in abi::TEST_CALLS and exist in test
/// builds only (el0.S uses them too). NOP returns 0 in x0; DONE ends the
/// program.
pub const SVC_NOP: u16 = 0xFF00;
pub const SVC_DONE: u16 = 0xFF01;

const _: () = assert!(*abi::TEST_CALLS.start() <= SVC_NOP && SVC_DONE <= *abi::TEST_CALLS.end());

// el0.S makes these calls by number and knows these values.
const _: () = assert!(
    Call::HandleClose.number() == 1
        && Call::Receive.number() == 5
        && Call::Notify.number() == 7
        && Call::ProcessCreate.number() == 12
        && Call::ProcessKill.number() == 13
        && Call::ProcessExit.number() == 14
        && Call::ThreadCreate.number() == 15
        && Call::ThreadStart.number() == 16
        && Call::ThreadExit.number() == 17
        && Call::ThreadSetPriority.number() == 18
        && Call::Yield.number() == 19
        && Call::ObjectInfo.number() == 27
        && Call::DebugWrite.number() == 28
);
const _: () = assert!(
    DATA_VA == 0x80_0000
        && INFO_PROCESS_STATE == 1
        && Policy::Fifo as u8 == 1
        && NO_WAIT == 0x10000
);

/// The line `debug_write_from_el0` prints; xtask looks for it in the output.
const EL0_LINE: &[u8] = b"debug_write from EL0 reaches the console\n";

/// Where the test processes see their pages: the programs at TEXT_VA, and
/// one page of data at DATA_VA with the register pattern at its start and
/// the stack at its end.
const TEXT_VA: usize = 0x40_0000;
const DATA_VA: usize = 0x80_0000;
const PAGE: usize = PAGE_SIZE as usize;
const PRIORITY: u8 = 10;
const HANDLE_LIMIT: u32 = 16;
const CEILING: u8 = 63;
/// Threads a test may have.
const SLOTS: usize = 3;
/// Switches each thread of `rr_threads_alternate_by_quantum` waits for.
const SWITCHES: u64 = 3;
/// Threads of the child whose kill the cleanup tests queue: a portion each.
const CHILD_THREADS: usize = 8;
/// The portion of cleanup after which the cleanup tests' interrupt comes.
const INTERRUPT_AFTER: u32 = 2;
/// The big teardown's interrupts come after every so many portions: a
/// prime, so that they fall on different places of both long stages.
const INTERRUPT_EVERY: u32 = 61;
/// Where the big teardown's child has its pages: one every 2 MiB through
/// the gigabyte from here, a table of the last level for each.
const BIG_BASE: usize = 1 << 30;
const BIG_PAGES: usize = 512;
/// The bits of the notifications of the channel tests.
const BITS: u64 = 0b1010;
/// Threads that wait in one channel in `closing_a_channel_wakes_waiters_in_portions`:
/// two processes full of them.
const CROWD: usize = 2 * MAX_THREADS as usize;
/// The ceiling of the waiters' process in `set_priority_moves_a_waiting_thread`.
const CAPPED: u8 = PRIORITY + 3;

struct El0Test {
    name: &'static str,
    /// Builds the test's threads, which the scheduler then starts in the
    /// order of their slots.
    start: fn(&mut Fixture) -> Result<(), &'static str>,
    /// Judges a thread at its `svc #SVC_DONE`.
    done: fn(&Fixture, &Thread) -> Result<(), &'static str>,
}

const EL0_TESTS: &[El0Test] = &[
    El0Test {
        name: "el0_reads_the_virtual_counter",
        start: start_counter,
        done: done_counter,
    },
    El0Test {
        name: "registers_survive_a_system_call",
        start: start_nop,
        done: done_nop,
    },
    El0Test {
        name: "unknown_system_call_fails_with_invalid_args",
        start: start_unknown,
        done: done_unknown,
    },
    El0Test {
        name: "el0_fault_ends_only_the_process",
        start: start_fault,
        done: done_fault,
    },
    El0Test {
        name: "wfi_at_el0_is_a_fault",
        start: start_wfi,
        done: done_wfi,
    },
    El0Test {
        name: "registers_survive_a_timer_interrupt",
        start: start_interrupt,
        done: done_interrupt,
    },
    El0Test {
        name: "registers_survive_a_switch_to_another_process",
        start: start_switch,
        done: done_switch,
    },
    El0Test {
        name: "registers_survive_a_switch_within_a_process",
        start: start_switch_within,
        done: done_switch,
    },
    El0Test {
        name: "a_new_thread_starts_with_clear_fp",
        start: start_clear_fp,
        done: done_clear_fp,
    },
    El0Test {
        name: "debug_write_from_el0",
        start: start_debug_write,
        done: done_debug_write,
    },
    El0Test {
        name: "object_info_from_el0",
        start: start_object_info,
        done: done_object_info,
    },
    El0Test {
        name: "failed_call_from_el0_changes_x0_only",
        start: start_closed_handle,
        done: done_closed_handle,
    },
    El0Test {
        name: "idle_waits_for_the_timer",
        start: start_idle,
        done: done_idle,
    },
    El0Test {
        name: "idle_keeps_the_priority_mask_open",
        start: start_idle,
        done: done_idle_mask,
    },
    El0Test {
        name: "fifo_thread_runs_with_the_timer_off",
        start: start_timer_off,
        done: done_timer_off,
    },
    El0Test {
        name: "fifo_threads_do_not_alternate",
        start: start_fifo_pair,
        done: done_fifo_pair,
    },
    El0Test {
        name: "yield_does_not_let_lower_levels_run",
        start: start_yield_alone,
        done: done_yield_alone,
    },
    El0Test {
        name: "lowering_itself_lets_higher_threads_run",
        start: start_lowering,
        done: done_lowering,
    },
    El0Test {
        name: "raising_a_ready_thread_preempts",
        start: start_raising,
        done: done_raising,
    },
    El0Test {
        name: "preempted_thread_is_at_the_head",
        start: start_head,
        done: done_head,
    },
    El0Test {
        name: "rr_threads_alternate_by_quantum",
        start: start_alternate,
        done: done_alternate,
    },
    El0Test {
        name: "child_fault_reason_reaches_the_parent",
        start: start_child_fault,
        done: done_child_fault,
    },
    El0Test {
        name: "last_thread_exit_ends_the_process",
        start: start_last_exit,
        done: done_last_exit,
    },
    El0Test {
        name: "process_exit_ends_the_process_with_its_code",
        start: start_process_exit,
        done: done_process_exit,
    },
    El0Test {
        name: "process_kills_itself",
        start: start_self_kill,
        done: done_self_kill,
    },
    El0Test {
        name: "closing_a_thread_handle_does_not_stop_it",
        start: start_close_started,
        done: done_close_started,
    },
    El0Test {
        name: "exited_thread_gives_its_buffer_back",
        start: start_keep_started,
        done: done_keep_started,
    },
    El0Test {
        name: "orphan_exit_frees_the_process",
        start: start_orphan_exit,
        done: done_orphan,
    },
    El0Test {
        name: "orphan_fault_frees_the_process",
        start: start_orphan_fault,
        done: done_orphan,
    },
    El0Test {
        name: "grandchildren_die_with_their_parent",
        start: start_grandchild,
        done: done_grandchild,
    },
    El0Test {
        name: "descendants_stop_above_the_cause",
        start: start_descendants,
        done: done_descendants,
    },
    El0Test {
        name: "child_notifies_through_its_start_channel",
        start: start_start_channel,
        done: done_start_channel,
    },
    El0Test {
        name: "kill_takes_a_waiting_thread_off_the_channel",
        start: start_kill_waiting,
        done: done_kill_waiting,
    },
    El0Test {
        name: "waiting_thread_keeps_the_kernel_reference",
        start: start_kernel_reference,
        done: done_kernel_reference,
    },
    El0Test {
        name: "set_priority_moves_a_waiting_thread",
        start: start_requeue,
        done: done_requeue,
    },
    El0Test {
        name: "closing_a_channel_wakes_waiters_in_portions",
        start: start_close_portions,
        done: done_close_portions,
    },
    El0Test {
        name: "cleanup_yields_to_a_pending_interrupt",
        start: start_cleanup,
        done: done_cleanup_yields,
    },
    El0Test {
        name: "cleanup_runs_at_the_priority_of_its_cause",
        start: start_cleanup,
        done: done_cleanup_level,
    },
    El0Test {
        name: "fault_cleanup_runs_at_the_priority_of_the_fault",
        start: start_fault_cleanup,
        done: done_own_cleanup,
    },
    El0Test {
        name: "exit_cleanup_runs_at_the_priority_of_the_exit",
        start: start_exit_cleanup,
        done: done_own_cleanup,
    },
    El0Test {
        name: "init_fault_stops_the_machine",
        start: start_init_fault,
        done: done_init_fault,
    },
    El0Test {
        name: "init_exit_ends_the_run",
        start: start_init_exit,
        done: done_init_exit,
    },
];

/// Tests whose outcome depends on how much of a quantum is left when
/// something happens. Only a run under `-icount`, where virtual time counts
/// instructions and a stall of the host does not eat into a quantum, makes
/// them repeatable: the `icount` build, which xtask runs that way, adds
/// them after the others. The teardown of a big process, hundreds of
/// portions with interrupts between them, runs there too.
const ICOUNT_TESTS: &[El0Test] = &[
    El0Test {
        name: "lone_round_robin_thread_is_not_switched",
        start: start_lone,
        done: done_lone,
    },
    El0Test {
        name: "preempted_rr_thread_resumes_before_its_peer",
        start: start_rest,
        done: done_rest,
    },
    El0Test {
        name: "teardown_yields_to_a_pending_interrupt",
        start: start_big_teardown,
        done: done_big_teardown,
    },
];

/// The tests of this build, in the order they run.
fn tests() -> impl Iterator<Item = &'static El0Test> {
    let icount: &[El0Test] = if cfg!(feature = "icount") {
        ICOUNT_TESTS
    } else {
        &[]
    };
    EL0_TESTS.iter().chain(icount)
}

fn test(i: usize) -> &'static El0Test {
    tests().nth(i).expect("a test of this build")
}

/// What the running test built and expects: up to SLOTS threads, each in
/// its own process or all in the one of slot 0.
struct Fixture {
    test: usize,
    processes: [Option<NonNull<Process>>; SLOTS],
    threads: [Option<NonNull<Thread>>; SLOTS],
    /// Threads that passed their `svc #SVC_DONE`.
    passed: [bool; SLOTS],
    /// Threads that end without `svc #SVC_DONE` as the test expects: by a
    /// fault, thread_exit, process_exit or a kill.
    ends: [bool; SLOTS],
    patterns: [Pattern; SLOTS],
    /// Handles the test put in its process's table. A handle to the
    /// process itself or one of its threads would keep both alive; the
    /// teardown closes them first.
    handles: [Option<(NonNull<Process>, Handle)>; SLOTS],
    /// The physical address of the page whose words the threads of a
    /// scheduling test share (sched_process).
    data: u64,
    /// The thread in slot 0 starts only at this counter value, from the
    /// timer's interrupt (timer_fired).
    wake: Option<u64>,
    /// CNTV_CVAL_EL0 when that interrupt came.
    fired_at: Option<u64>,
    /// Ticks asleep in `wfi` (sched::stats) when the test began.
    idle: u64,
    /// How far below the top of the kernel stack the idle wait began.
    idle_depth: Option<usize>,
    /// GICC_PMR in the idle wait.
    idle_mask: Option<u8>,
    /// Portions of cleanup since the test began, the one after which the
    /// timer's interrupt comes and wakes the thread in slot 0, and how many
    /// portions apart more interrupts come (portion_done).
    portions: u32,
    interrupt_after: Option<u32>,
    interrupt_every: Option<u32>,
    /// Free frames and the pages of kernel pools together when the test
    /// began: the same once what the test made gave back what it took.
    memory: u64,
    /// Items in the cleanup queue when the wake-up came.
    queued_at_wake: Option<u64>,
    /// The counter before the thread started.
    counter: u64,
    /// Whether the test expects a fault at EL0, which then ends the
    /// faulting process as in a build without tests.
    faults: bool,
    /// SP in the first test system call, and whether a later one had
    /// another, or one far from the top of the kernel stack. The fixture
    /// starts all zero, so FIXTURE lies in .bss and adds nothing to the
    /// kernel image (spec 3.4).
    stack: Option<usize>,
    stack_moved: bool,
    /// Timer interrupts taken at EL0, and whether one of them moved the
    /// thread past its wait loop.
    interrupts: u32,
    left_loop: bool,
    /// A process that the first timer interrupt ends, as process_exit from
    /// a thread of it at the level given would, and what the thread in
    /// slot 1 counted in x2 then.
    exit_at_interrupt: Option<(NonNull<Process>, u8)>,
    count_at_exit: Option<u64>,
    /// Values the test's start fixes for its judges.
    kept: [u64; 2],
    /// A thread the test holds no reference to, which only the kernel's
    /// reference keeps alive while it waits.
    unheld: Option<NonNull<Thread>>,
    /// Threads the test holds besides those of its slots; the teardown
    /// lets them go.
    crowd: [Option<NonNull<Thread>>; CROWD],
    /// Threads in their pools (thread::in_use) once the test was built.
    live_threads: usize,
}

// SAFETY: the fixture's objects are reached only under the kernel's rules
// (spec 8.1): one CPU, interrupts masked inside the kernel.
unsafe impl Send for Fixture {}

impl Fixture {
    const fn new(test: usize) -> Fixture {
        Fixture {
            test,
            processes: [None; SLOTS],
            threads: [None; SLOTS],
            passed: [false; SLOTS],
            ends: [false; SLOTS],
            patterns: [Pattern::ZERO; SLOTS],
            handles: [None; SLOTS],
            data: 0,
            wake: None,
            fired_at: None,
            idle: 0,
            idle_depth: None,
            idle_mask: None,
            portions: 0,
            interrupt_after: None,
            interrupt_every: None,
            memory: 0,
            queued_at_wake: None,
            counter: 0,
            faults: false,
            stack: None,
            stack_moved: false,
            interrupts: 0,
            left_loop: false,
            exit_at_interrupt: None,
            count_at_exit: None,
            kept: [0; 2],
            unheld: None,
            crowd: [None; CROWD],
            live_threads: 0,
        }
    }

    /// Which of the test's threads `thread` is.
    fn slot(&self, thread: &Thread) -> usize {
        self.threads
            .iter()
            .position(|t| t.is_some_and(|t| core::ptr::eq(t.as_ptr(), thread)))
            .expect("a thread of the running test")
    }
}

static FIXTURE: Lock<Fixture> = Lock::new(Fixture::new(0));

/// Runs the EL0 tests and ends the run.
pub fn run() -> ! {
    start(0)
}

/// How many TEST lines the EL0 tests print: one per test of this build,
/// and el0_tests_return_their_objects.
pub fn count() -> usize {
    tests().count() + 1
}

/// Starts the tests from `first` on: the scheduler starts each test's
/// threads, but the one that waits for its wake-up, and runs them. A test
/// that cannot start fails, and the next one starts. Each test finds the
/// cleanup queue empty. After the last test the pools hold no process and
/// no thread: the kernel's references and the tests' own went.
fn start(first: usize) -> ! {
    for (i, test) in tests().enumerate().skip(first) {
        cleanup::drain();
        let started = {
            let mut f = FIXTURE.lock();
            *f = Fixture::new(i);
            (test.start)(&mut f).map(|()| (f.threads, f.wake.is_some()))
        };
        match started {
            Ok((threads, wake)) => {
                for t in threads.into_iter().skip(usize::from(wake)).flatten() {
                    thread::start(t).expect("a new thread starts");
                }
                sched::resume()
            }
            Err(why) => {
                report(test.name, Err(why));
                teardown();
            }
        }
    }
    cleanup::drain();
    report(
        "el0_tests_return_their_objects",
        check(
            process::in_use() == 0
                && thread::in_use() == 0
                && channel::in_use() == 0
                && session::in_use() == 0,
            "a process, a thread, a channel or a session of the EL0 tests stayed in its pool",
        ),
    );
    finish()
}

/// Ends the running test with `result` and starts the next one.
fn end(result: Result<(), &'static str>) -> ! {
    let i = FIXTURE.lock().test;
    report(test(i).name, result);
    teardown();
    start(i + 1)
}

/// Drops what the test built. The timer stays the scheduler's: the next
/// decision arms it for the next test.
fn teardown() {
    let (handles, threads, crowd, processes) = {
        let mut f = FIXTURE.lock();
        (
            core::mem::take(&mut f.handles),
            core::mem::take(&mut f.threads),
            core::mem::replace(&mut f.crowd, [None; CROWD]),
            core::mem::take(&mut f.processes),
        )
    };
    for (p, h) in handles.into_iter().flatten() {
        // A handle the test closed itself is bad by now, which is fine.
        let _ = process::close_handle(p, h, CAUSE);
    }
    for t in threads.into_iter().chain(crowd).flatten() {
        // SAFETY: the test's references go with it; the thread leaves the
        // scheduler first, and a thread that runs stops being the running
        // one.
        unsafe {
            sched::exit(t, CAUSE);
            thread::release(t, CAUSE);
        }
    }
    for p in processes.into_iter().flatten() {
        // SAFETY: as above; the threads released their references first.
        unsafe { process::release(p, CAUSE) };
    }
}

/// The test system calls; false for any other number.
pub fn syscall(thread: NonNull<Thread>, number: u16) -> bool {
    note_stack();
    match number {
        SVC_NOP => syscall::set_result(thread, Ok(Values::NONE)),
        SVC_DONE => done(thread),
        _ => return false,
    }
    true
}

/// The timer's interrupt, after the scheduler's part (interrupt::handle).
/// In the interrupt test the thread waits for it in a loop, and the kernel
/// moves the thread past the loop; one that comes before the thread
/// reaches the loop leaves it be, and the next quantum brings another. At
/// the running test's wake-up the thread in slot 0 starts. The first
/// interrupt ends the process of `exit_at_interrupt`.
pub fn timer_fired() {
    let exit = {
        let mut f = FIXTURE.lock();
        let exit = f.exit_at_interrupt.take();
        if exit.is_some() {
            f.count_at_exit = Some(counted(&f));
        }
        exit
    };
    if let Some((p, cause)) = exit {
        let exited = ProcessState::Exited { code: EXIT_CODE };
        // SAFETY: the test holds a reference to the process.
        unsafe { process::end(p, exited, cause) };
    }
    let wake = {
        let mut f = FIXTURE.lock();
        f.interrupts += 1;
        if let Some(mut thread) = thread::current() {
            // SAFETY: the thread is alive, and nothing else refers to it now.
            let regs = unsafe { &mut thread.as_mut().regs };
            if regs.elr == user_address(&raw const el0_wait_loop) as u64 {
                regs.elr += 4;
                f.left_loop = true;
            }
        }
        match f.wake {
            Some(at) if timer::now() >= at => {
                f.wake = None;
                f.fired_at = Some(timer::cval());
                f.queued_at_wake = Some(cleanup::len());
                f.threads[0]
            }
            _ => None,
        }
    };
    if let Some(t) = wake {
        thread::start(t).expect("the waking thread starts");
    }
}

/// The running test's wake-up, which the scheduler's timer serves as well
/// (sched::decide).
pub fn deadline() -> Option<u64> {
    FIXTURE.lock().wake
}

/// Every entry from EL0 starts at the top of the kernel stack (spec 8.1),
/// so every test system call runs with the same SP.
fn note_stack() {
    let sp: usize;
    // SAFETY: reading SP has no side effects.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags))
    };
    let top = symbols::boot_stack().end;
    let mut f = FIXTURE.lock();
    let first = *f.stack.get_or_insert(sp);
    f.stack_moved |= sp != first || top - sp >= PAGE;
}

/// The idle wait starts near the top of the kernel stack (the way out of
/// the kernel runs on the empty stack, arch::on_empty_stack), however
/// deep the path that found nothing to run; the priority mask stays open.
pub fn note_idle_stack() {
    let sp: usize;
    // SAFETY: reading SP has no side effects.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags))
    };
    let mut f = FIXTURE.lock();
    f.idle_depth = Some(symbols::boot_stack().end - sp);
    f.idle_mask = Some(gic::priority_mask());
}

/// After each portion of cleanup (cleanup::portion): in the cleanup tests,
/// portion `interrupt_after` arms the timer for now and waits until its
/// interrupt is pending, so the way out of the kernel finds it at the
/// next poll; the interrupt starts the thread in slot 0 (`wake`). Every
/// `interrupt_every` portions another interrupt comes the same way.
pub fn portion_done() {
    let now = {
        let mut f = FIXTURE.lock();
        f.portions += 1;
        let first = f.interrupt_after == Some(f.portions);
        let again = f
            .interrupt_every
            .is_some_and(|n| f.portions.is_multiple_of(n));
        if !first && !again {
            return;
        }
        let now = timer::now();
        if first {
            f.interrupt_after = None;
            f.wake = Some(now);
        }
        now
    };
    timer::arm(now);
    while !arch::irq_pending() {}
}

/// A thread's `svc #SVC_DONE`: the test judges it. Once every thread of
/// the test has passed, or this one failed, the test ends; else the thread
/// leaves the scheduler, and the scheduler runs the next.
fn done(thread: NonNull<Thread>) -> ! {
    let (result, all) = {
        let mut f = FIXTURE.lock();
        // SAFETY: the running thread is alive; nothing changes it meanwhile.
        let t = unsafe { thread.as_ref() };
        let result = check(
            !f.stack_moved,
            "an entry from EL0 did not start at the top of the kernel stack",
        )
        .and_then(|()| (test(f.test).done)(&f, t));
        let slot = f.slot(t);
        f.passed[slot] = result.is_ok();
        let all = (0..SLOTS).all(|i| f.threads[i].is_none() || f.passed[i] || f.ends[i]);
        (result, all)
    };
    match result {
        Ok(()) if !all => {
            // SAFETY: the running thread is alive.
            let cause = unsafe { thread.as_ref() }.priority();
            // SAFETY: the test still holds its own reference to the thread.
            unsafe { sched::exit(thread, cause) };
            sched::resume()
        }
        result => end(result),
    }
}

/// Whether the running test expects a fault at EL0
/// (exceptions::user_fault); any other stops the machine with its report.
pub fn expects_fault() -> bool {
    FIXTURE.lock().faults
}

/// Init's end (process::init_ended): the test judges the thread in slot 0,
/// whose process is init, and ends. A build without tests stops the
/// machine instead. An end of init through thread_exit is not tested: the
/// reference thread::exit holds would stay.
pub fn init_ended() -> ! {
    let result = {
        let f = FIXTURE.lock();
        let t = f.threads[0].expect("init's thread in slot 0");
        // SAFETY: the test holds a reference to its thread, which ended.
        (test(f.test).done)(&f, unsafe { t.as_ref() })
    };
    end(result)
}

/// The user address of a symbol in el0.S.
fn user_address(symbol: *const u8) -> usize {
    TEXT_VA + (symbol as usize - &raw const el0_programs as usize)
}

/// A process with the programs at TEXT_VA and a thread in it, as
/// `new_thread` makes it with the data page at DATA_VA. Both go into slot
/// `slot` of the fixture.
fn spawn(
    f: &mut Fixture,
    slot: usize,
    entry: *const u8,
    arg: u64,
) -> Result<NonNull<Thread>, &'static str> {
    let p = new_process(f, slot)?;
    new_thread(f, slot, p, DATA_VA, entry, arg)
}

/// A process with the programs at TEXT_VA, in slot `slot` of the fixture.
fn new_process(f: &mut Fixture, slot: usize) -> Result<NonNull<Process>, &'static str> {
    let p = process::create_root(QUOTA, HANDLE_LIMIT, CEILING).map_err(|_| "no process")?;
    with_programs(f, slot, p)
}

/// Puts `p`, a new process whose first reference the fixture takes, in
/// slot `slot` and maps the programs at TEXT_VA there.
fn with_programs(
    f: &mut Fixture,
    slot: usize,
    mut p: NonNull<Process>,
) -> Result<NonNull<Process>, &'static str> {
    f.processes[slot] = Some(p);
    // SAFETY: the process was just created, and only this test uses it.
    let text = unsafe { p.as_mut() }
        .map_frames(TEXT_VA, PAGE_SIZE, Attrs::USER_TEXT)
        .map_err(|_| "the programs did not map")?;
    let start = &raw const el0_programs as usize;
    let len = &raw const el0_programs_end as usize - start;
    assert!(len <= PAGE, "the EL0 programs outgrew their page");
    let text_va = LINEAR_BASE + text as usize;
    // SAFETY: the programs lie in the kernel image, and the frame is new,
    // one page, and reached through the linear map.
    unsafe { core::ptr::copy_nonoverlapping(start as *const u8, text_va as *mut u8, len) };
    // The whole page, its zeroed tail included: the frame may have held
    // other code, which the instruction cache may still hold.
    cache::sync_icache(text_va, PAGE);
    Ok(p)
}

/// A data page at `data_va` in process `p` holding the pattern of slot
/// `slot`, and a thread of `p` in that slot of the fixture that starts at
/// `entry` (a symbol in el0.S) with `arg` in x0, its stack at the end of
/// the page and the pattern's TPIDRRO_EL0. The thread is FIFO: the timer
/// stays out of its way.
fn new_thread(
    f: &mut Fixture,
    slot: usize,
    mut p: NonNull<Process>,
    data_va: usize,
    entry: *const u8,
    arg: u64,
) -> Result<NonNull<Thread>, &'static str> {
    // SAFETY: the process belongs to this test, and nothing else uses it.
    let data = unsafe { p.as_mut() }
        .map_frames(data_va, PAGE_SIZE, Attrs::USER_DATA)
        .map_err(|_| "the data page did not map")?;
    // SAFETY: the frame is new, one page, aligned for the pattern, and
    // reached through the linear map.
    unsafe { ((LINEAR_BASE + data as usize) as *mut Pattern).write(f.patterns[slot].clone()) };
    let t = thread::create(
        p,
        user_address(entry),
        data_va + PAGE,
        arg,
        PRIORITY,
        Policy::Fifo,
    )
    .map_err(|_| "no thread")?;
    f.threads[slot] = Some(t);
    // SAFETY: the thread was just created and does not run yet.
    unsafe { (*t.as_ptr()).regs.tpidrro = f.patterns[slot].tpidrro };
    Ok(t)
}

/// Values a program loads into all its registers (el0.S, LOAD_PATTERN), at
/// the offsets it reads them from, and the TPIDRRO_EL0 that the kernel
/// gives its thread.
#[repr(C)]
#[derive(Clone)]
struct Pattern {
    x: [u64; 31],
    sp: u64,
    nzcv: u64,
    tpidr: u64,
    fpcr: u64,
    fpsr: u64,
    v: [u128; 32],
    tpidrro: u64,
}

const _: () = {
    assert!(core::mem::offset_of!(Pattern, sp) == 248);
    assert!(core::mem::offset_of!(Pattern, nzcv) == 256);
    assert!(core::mem::offset_of!(Pattern, tpidr) == 264);
    assert!(core::mem::offset_of!(Pattern, fpcr) == 272);
    assert!(core::mem::offset_of!(Pattern, fpsr) == 280);
    assert!(core::mem::offset_of!(Pattern, v) == 288);
};

/// SplitMix64: a different, well-mixed value on every call.
fn mix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Pattern {
    const ZERO: Pattern = Pattern {
        x: [0; 31],
        sp: 0,
        nzcv: 0,
        tpidr: 0,
        fpcr: 0,
        fpsr: 0,
        v: [0; 32],
        tpidrro: 0,
    };

    /// A pattern in which no two registers hold the same value, and no
    /// register holds what the pattern of another seed puts in it. Odd and
    /// even seeds set different flags and FP control bits.
    fn new(seed: u64) -> Pattern {
        let mut state = seed;
        let odd = seed % 2 == 1;
        let mut p = Pattern::ZERO;
        for x in &mut p.x {
            *x = mix(&mut state);
        }
        for v in &mut p.v {
            *v = u128::from(mix(&mut state)) << 64 | u128::from(mix(&mut state));
        }
        p.tpidr = mix(&mut state);
        p.tpidrro = mix(&mut state);
        p.sp = (DATA_VA + PAGE - 16 * seed as usize) as u64;
        // N and V, or Z and C.
        p.nzcv = if odd { 0x9 << 28 } else { 0x6 << 28 };
        // FPCR: AHP, DN and round towards plus infinity, or FZ and round
        // towards minus infinity.
        p.fpcr = if odd { 0x0640_0000 } else { 0x0180_0000 };
        // FPSR: every cumulative exception bit and QC, or IXC and IOC.
        p.fpsr = if odd { 0x0800_009F } else { 0x11 };
        p
    }
}

/// The thread's registers are the pattern's, except x0 and up, which hold
/// `results`: a system call's result code and values.
fn check_pattern(regs: &UserRegs, p: &Pattern, results: &[u64]) -> Result<(), &'static str> {
    let mut want = p.x;
    want[..results.len()].copy_from_slice(results);
    if let Some(i) = (0..31).find(|&i| regs.x[i] != want[i]) {
        kprintln!("x{i} is {:#x}, the pattern has {:#x}", regs.x[i], want[i]);
        return Err("a general register changed");
    }
    check(regs.sp == p.sp, "SP_EL0 changed")?;
    check(regs.spsr & SPSR_NZCV == p.nzcv, "the flags changed")?;
    check(
        regs.spsr & !SPSR_NZCV == 0,
        "the thread left EL0t or masked an exception",
    )?;
    check(regs.tpidr == p.tpidr, "TPIDR_EL0 changed")?;
    check(regs.tpidrro == p.tpidrro, "TPIDRRO_EL0 changed")?;
    // The kernel never touches the FP and SIMD registers, so they still
    // hold the running thread's.
    let mut fp = FpRegs::ZERO;
    user::save_fp(&mut fp);
    if let Some(i) = (0..32).find(|&i| fp.v[i] != p.v[i]) {
        kprintln!("v{i} is {:#x}, the pattern has {:#x}", fp.v[i], p.v[i]);
        return Err("an FP or SIMD register changed");
    }
    check(fp.fpcr == p.fpcr, "FPCR changed")?;
    check(fp.fpsr == p.fpsr, "FPSR changed")
}

fn start_counter(f: &mut Fixture) -> Result<(), &'static str> {
    f.counter = timer::now();
    spawn(f, 0, &raw const el0_read_counter, 0)?;
    Ok(())
}

fn done_counter(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let (count, hz) = (t.regs.x[0], t.regs.x[1]);
    check(
        (f.counter..=timer::now()).contains(&count),
        "the counter EL0 read is not between two readings of the kernel",
    )?;
    check(
        hz == timer::frequency(),
        "EL0 reads another counter frequency",
    )
}

fn start_nop(f: &mut Fixture) -> Result<(), &'static str> {
    f.patterns[0] = Pattern::new(1);
    spawn(f, 0, &raw const el0_pattern_nop, DATA_VA as u64)?;
    Ok(())
}

fn done_nop(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check_pattern(&t.regs, &f.patterns[0], &[0])
}

fn start_unknown(f: &mut Fixture) -> Result<(), &'static str> {
    f.patterns[0] = Pattern::new(1);
    spawn(f, 0, &raw const el0_pattern_unknown, DATA_VA as u64)?;
    Ok(())
}

fn done_unknown(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check_pattern(&t.regs, &f.patterns[0], &[Error::InvalidArgs.code()])
}

/// The program loads from FIXTURE itself, a kernel variable: the
/// permission fault ends its process, with the fault as the reason, and
/// nothing else. The judge, in a process of its own, runs afterwards.
fn start_fault(f: &mut Fixture) -> Result<(), &'static str> {
    f.faults = true;
    spawn(f, 0, &raw const el0_load, &raw const FIXTURE as u64)?;
    f.ends[0] = true;
    judge(f, 1)
}

fn done_fault(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(
        f.slot(t) == 1,
        "a load from kernel memory at EL0 did not fault",
    )?;
    let ProcessState::Fault { esr, far, elr } = state(f, 0) else {
        return Err("the process did not end with the fault");
    };
    check(
        esr::ec(esr) == esr::EC_DABT_LOWER,
        "the fault is not a data abort from EL0",
    )?;
    check(
        esr::fault_status_name(esr) == "permission fault",
        "the fault is not a permission fault",
    )?;
    check(
        far == &raw const FIXTURE as u64,
        "FAR is not the kernel address",
    )?;
    check(
        elr == user_address(&raw const el0_load) as u64,
        "ELR is not the load",
    )?;
    check(
        slot_thread(f, 0).sched.state() == State::Dead,
        "the faulting thread did not end",
    )
}

/// WFI at EL0 traps (SCTLR_EL1.nTWI is clear) and is the program's fault.
/// FAR_EL1 still holds the kernel address of the test before; the reason
/// has FAR 0.
fn start_wfi(f: &mut Fixture) -> Result<(), &'static str> {
    f.faults = true;
    spawn(f, 0, &raw const el0_wfi, 0)?;
    f.ends[0] = true;
    judge(f, 1)
}

fn done_wfi(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(f.slot(t) == 1, "WFI at EL0 did not trap")?;
    let ProcessState::Fault { esr, far, elr } = state(f, 0) else {
        return Err("WFI did not end the process with a fault");
    };
    check(
        esr::ec(esr) == esr::EC_WFX,
        "the fault is not a trapped WFI",
    )?;
    check(far == 0, "a stale FAR went into the reason")?;
    check(
        elr == user_address(&raw const el0_wfi) as u64,
        "ELR is not the WFI",
    )
}

/// The end of the thread's quantum brings the timer's interrupt while the
/// program loops at EL0: the thread is round robin, alone at its level.
fn start_interrupt(f: &mut Fixture) -> Result<(), &'static str> {
    f.patterns[0] = Pattern::new(1);
    let t = spawn(f, 0, &raw const el0_pattern_loop, DATA_VA as u64)?;
    sched::set_priority(t, PRIORITY, Policy::RoundRobin).map_err(|_| "no round robin")
}

fn done_interrupt(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(
        f.left_loop && f.interrupts >= 1,
        "the thread left its loop without the timer interrupt",
    )?;
    check(
        !gic::is_active(timer::INTID),
        "the timer interrupt did not end at the GIC",
    )?;
    check(
        sched::stats().irq_latency > 0,
        "the latency from the deadline to the thread after an interrupt at EL0 was not counted",
    )?;
    let p = &f.patterns[0];
    check_pattern(&t.regs, p, &p.x[..1])
}

/// Two processes run the same program with different patterns; each yields
/// to the other once, and each checks its registers when it runs again.
fn start_switch(f: &mut Fixture) -> Result<(), &'static str> {
    f.patterns[0] = Pattern::new(1);
    f.patterns[1] = Pattern::new(2);
    spawn(f, 0, &raw const el0_pattern_yield, DATA_VA as u64)?;
    spawn(f, 1, &raw const el0_pattern_yield, DATA_VA as u64)?;
    Ok(())
}

fn done_switch(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check_pattern(&t.regs, &f.patterns[f.slot(t)], &[0])
}

/// Two threads of one process run the same program, each with its own
/// pattern in its own data page, and yield to each other once: the switch
/// between them changes the FP and SIMD registers and leaves TTBR0 alone.
fn start_switch_within(f: &mut Fixture) -> Result<(), &'static str> {
    const SECOND: usize = DATA_VA + 2 * PAGE;
    f.patterns[0] = Pattern::new(1);
    f.patterns[1] = Pattern::new(2);
    f.patterns[1].sp += 2 * PAGE as u64;
    let p = new_process(f, 0)?;
    new_thread(
        f,
        0,
        p,
        DATA_VA,
        &raw const el0_pattern_yield,
        DATA_VA as u64,
    )?;
    new_thread(f, 1, p, SECOND, &raw const el0_pattern_yield, SECOND as u64)?;
    Ok(())
}

/// Runs after the pattern tests: their threads are gone, and the last
/// pattern is still in the FP and SIMD registers.
fn start_clear_fp(f: &mut Fixture) -> Result<(), &'static str> {
    spawn(f, 0, &raw const el0_done_at_once, 0)?;
    Ok(())
}

fn done_clear_fp(_: &Fixture, _: &Thread) -> Result<(), &'static str> {
    let mut fp = FpRegs {
        v: [u128::MAX; 32],
        fpcr: u64::MAX,
        fpsr: u64::MAX,
    };
    user::save_fp(&mut fp);
    check(
        fp.v.iter().all(|&v| v == 0) && fp.fpcr == 0 && fp.fpsr == 0,
        "a new thread found the FP or SIMD values of another",
    )
}

/// The pattern of slot 0 with `args` in x0 and up, for a program that
/// fills its registers from it and makes a call.
fn call_pattern(f: &mut Fixture, args: &[u64]) {
    f.patterns[0] = Pattern::new(1);
    f.patterns[0].x[..args.len()].copy_from_slice(args);
}

/// A handle in process `p`'s table, for the test's program.
fn give(p: NonNull<Process>, object: Object, rights: Rights) -> Result<u64, &'static str> {
    process::insert_handle(p, object, rights)
        .map(|h| h.0)
        .map_err(|_| "a handle did not go in")
}

/// The program writes EL0_LINE through a handle to the system resource.
fn start_debug_write(f: &mut Fixture) -> Result<(), &'static str> {
    let p = new_process(f, 0)?;
    let h = give(p, Object::Resource, Rights::DEBUG)?;
    let mut args = [0; 10];
    args[0] = h;
    args[1] = EL0_LINE.len() as u64;
    args[2..].copy_from_slice(&abi::inline_words(EL0_LINE));
    call_pattern(f, &args);
    new_thread(
        f,
        0,
        p,
        DATA_VA,
        &raw const el0_pattern_debug_write,
        DATA_VA as u64,
    )?;
    Ok(())
}

fn done_debug_write(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check_pattern(&t.regs, &f.patterns[0], &[0, EL0_LINE.len() as u64])
}

/// The program asks for the state of another process, which lives: four
/// values in x1-x4.
fn start_object_info(f: &mut Fixture) -> Result<(), &'static str> {
    let p = new_process(f, 0)?;
    let other = new_process(f, 1)?;
    let h = give(p, Object::Process(other), Rights::NONE)?;
    call_pattern(f, &[h, INFO_PROCESS_STATE, 0]);
    new_thread(
        f,
        0,
        p,
        DATA_VA,
        &raw const el0_pattern_object_info,
        DATA_VA as u64,
    )?;
    Ok(())
}

fn done_object_info(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let [w1, w2, w3, w4] = ProcessState::Alive.to_words();
    check_pattern(&t.regs, &f.patterns[0], &[0, w1, w2, w3, w4])
}

/// The program closes a handle that is closed already: BAD_HANDLE in x0,
/// every other register as the pattern left it.
fn start_closed_handle(f: &mut Fixture) -> Result<(), &'static str> {
    let p = new_process(f, 0)?;
    let h = give(p, Object::Resource, Rights::DEBUG)?;
    process::close_handle(p, abi::Handle(h), CAUSE).map_err(|_| "the handle did not close")?;
    call_pattern(f, &[h]);
    new_thread(
        f,
        0,
        p,
        DATA_VA,
        &raw const el0_pattern_close,
        DATA_VA as u64,
    )?;
    Ok(())
}

fn done_closed_handle(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check_pattern(&t.regs, &f.patterns[0], &[Error::BadHandle.code()])
}

// Scheduling tests. The threads of each share the process in slot 0 and
// the words of its data page; their programs take their arguments in x0
// and up.

const FIFO: Policy = Policy::Fifo;
const RR: Policy = Policy::RoundRobin;

/// The quantum in counter ticks, as abi::RR_QUANTUM_NS fixes it.
fn quantum() -> u64 {
    timer::clock().ns_to_ticks(abi::RR_QUANTUM_NS)
}

/// The address the programs see word `i` of the shared page at.
fn word(i: usize) -> u64 {
    (DATA_VA + 8 * i) as u64
}

/// Word `i` of the shared page, read through the linear map.
fn shared(f: &Fixture, i: usize) -> u64 {
    // SAFETY: the page belongs to the test's process, and the linear map
    // reaches it; the programs write it, so the read is volatile.
    unsafe {
        ((LINEAR_BASE + f.data as usize) as *const u64)
            .add(i)
            .read_volatile()
    }
}

/// The process of a scheduling test, in slot 0, with the page of shared
/// words at DATA_VA.
fn sched_process(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process_under(f, CEILING)
}

/// `sched_process` with priority ceiling `ceiling`.
fn sched_process_under(f: &mut Fixture, ceiling: u8) -> Result<(), &'static str> {
    let p = process::create_root(QUOTA, HANDLE_LIMIT, ceiling).map_err(|_| "no process")?;
    let mut p = with_programs(f, 0, p)?;
    // SAFETY: the process belongs to this test, and nothing else uses it.
    f.data = unsafe { p.as_mut() }
        .map_frames(DATA_VA, PAGE_SIZE, Attrs::USER_DATA)
        .map_err(|_| "the shared page did not map")?;
    Ok(())
}

/// A thread of the test's process in slot `slot` that starts at `entry`
/// (a symbol in el0.S) at `priority` under `policy`. The programs use no
/// stack.
fn sched_thread(
    f: &mut Fixture,
    slot: usize,
    entry: *const u8,
    priority: u8,
    policy: Policy,
) -> Result<NonNull<Thread>, &'static str> {
    let p = f.processes[0].expect("the test's process");
    let t = thread::create(p, user_address(entry), DATA_VA + PAGE, 0, priority, policy)
        .map_err(|_| "no thread")?;
    f.threads[slot] = Some(t);
    Ok(t)
}

/// Puts `args` in x0 and up of a thread that has not run.
fn set_args(mut t: NonNull<Thread>, args: &[u64]) {
    // SAFETY: the thread belongs to the test and does not run yet.
    unsafe { t.as_mut() }.regs.x[..args.len()].copy_from_slice(args);
}

/// A handle with MANAGE to thread `t` in the test's process; the teardown
/// closes it.
fn give_thread(f: &mut Fixture, t: NonNull<Thread>) -> Result<u64, &'static str> {
    give_kept(f, Object::Thread(t))
}

/// A handle with MANAGE to the test's process in its own table; the
/// teardown closes it.
fn give_own(f: &mut Fixture) -> Result<u64, &'static str> {
    let p = f.processes[0].expect("the test's process");
    give_kept(f, Object::Process(p))
}

/// A handle with MANAGE to `object` in the table of the test's process,
/// which the teardown closes.
fn give_kept(f: &mut Fixture, object: Object) -> Result<u64, &'static str> {
    let p = f.processes[0].expect("the test's process");
    let h =
        process::insert_handle(p, object, Rights::MANAGE).map_err(|_| "a handle did not go in")?;
    let slot = f
        .handles
        .iter()
        .position(Option::is_none)
        .expect("room for a handle");
    f.handles[slot] = Some((p, h));
    Ok(h.0)
}

/// The thread in slot 0 starts 1 ms from now, when the timer's interrupt
/// comes; nothing else is ready meanwhile, so the kernel idles.
fn start_idle(f: &mut Fixture) -> Result<(), &'static str> {
    spawn(f, 0, &raw const el0_read_counter, 0)?;
    f.idle = sched::stats().idle;
    f.counter = timer::clock().deadline_after(timer::now(), 1_000_000);
    f.wake = Some(f.counter);
    Ok(())
}

fn done_idle(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(
        f.fired_at == Some(f.counter),
        "the idle kernel did not arm the timer for the deadline",
    )?;
    check(
        t.regs.x[0] >= f.counter,
        "the thread ran before its deadline",
    )?;
    check(
        sched::stats().idle > f.idle,
        "the kernel did not sleep in its idle wait",
    )?;
    check(
        sched::stats().idle_latency > 0,
        "the latency from the deadline to the thread after wfi was not counted",
    )?;
    check(
        f.idle_depth.is_some_and(|d| d <= 256),
        "the idle wait did not start near the top of the kernel stack",
    )
}

/// The idle wait leaves the GIC's priority mask open: every line the
/// kernel unmasked wakes it (spec 8.1).
fn done_idle_mask(f: &Fixture, _: &Thread) -> Result<(), &'static str> {
    check(
        f.idle_mask == Some(PRIORITY_MASK),
        "the idle wait changed GICC_PMR",
    )
}

/// A FIFO thread spins for two quanta and yields: no timer interrupt comes,
/// and the timer is off while the thread runs.
fn start_timer_off(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let t = sched_thread(f, 0, &raw const el0_spin_then_yield, PRIORITY, FIFO)?;
    set_args(t, &[word(0), 2 * quantum()]);
    Ok(())
}

fn done_timer_off(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(
        f.interrupts == 0,
        "a timer interrupt came while a FIFO thread ran",
    )?;
    check(
        !timer::enabled(),
        "the timer is on while a FIFO thread runs",
    )?;
    check(t.regs.x[0] == 0, "yield failed")
}

/// Two FIFO threads at one level. The first spins for three quanta while
/// the second, ready all along, does not run; then the first yields, and
/// the second runs before the yield returns.
fn start_fifo_pair(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let spin = sched_thread(f, 0, &raw const el0_spin_then_yield, PRIORITY, FIFO)?;
    let mark = sched_thread(f, 1, &raw const el0_mark, PRIORITY, FIFO)?;
    set_args(spin, &[word(0), 3 * quantum()]);
    set_args(mark, &[word(0)]);
    Ok(())
}

fn done_fifo_pair(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    if f.slot(t) != 0 {
        return Ok(());
    }
    check(x[3] == 0, "a FIFO thread let its peer run without yield")?;
    check(
        x[0] == 0 && x[4] == 1,
        "the peer did not run when the FIFO thread yielded",
    )
}

/// A thread alone at its level yields while a thread below it is ready:
/// the yield returns at once, and the lower thread does not run.
fn start_yield_alone(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let spin = sched_thread(f, 0, &raw const el0_spin_then_yield, PRIORITY, FIFO)?;
    let low = sched_thread(f, 1, &raw const el0_mark, PRIORITY - 5, FIFO)?;
    set_args(spin, &[word(0), 0]);
    set_args(low, &[word(0)]);
    Ok(())
}

fn done_yield_alone(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    check(
        f.slot(t) != 0 || (x[0] == 0 && x[3] == 0 && x[4] == 0),
        "yield let a lower thread run",
    )
}

/// A thread lowers itself below a ready thread: that thread runs before
/// the call returns, and the caller keeps its new priority.
fn start_lowering(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let me = sched_thread(f, 0, &raw const el0_set_priority, PRIORITY + 10, FIFO)?;
    let other = sched_thread(f, 1, &raw const el0_mark, PRIORITY, FIFO)?;
    let h = give_thread(f, me)?;
    set_args(me, &[h, u64::from(PRIORITY - 5), FIFO as u64, word(0)]);
    set_args(other, &[word(0)]);
    Ok(())
}

fn done_lowering(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    if f.slot(t) != 0 {
        return Ok(());
    }
    check(x[0] == 0, "thread_set_priority failed")?;
    check(
        x[4] == 0 && x[5] == 1,
        "the higher thread did not run before the call returned",
    )?;
    check(
        t.sched.base() == PRIORITY - 5 && t.sched.priority() == PRIORITY - 5,
        "the thread did not keep its new priority",
    )
}

/// A thread raises a ready thread above itself: that thread runs before
/// the call returns.
fn start_raising(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let me = sched_thread(f, 0, &raw const el0_set_priority, PRIORITY, FIFO)?;
    let other = sched_thread(f, 1, &raw const el0_mark, PRIORITY - 5, FIFO)?;
    let h = give_thread(f, other)?;
    set_args(me, &[h, u64::from(PRIORITY + 10), FIFO as u64, word(0)]);
    set_args(other, &[word(0)]);
    Ok(())
}

fn done_raising(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    if f.slot(t) != 0 {
        return Ok(());
    }
    check(x[0] == 0, "thread_set_priority failed")?;
    check(
        x[4] == 0 && x[5] == 1,
        "the raised thread did not run before the call returned",
    )
}

/// Three FIFO threads: the first and its peer at one level, a third below.
/// The first raises the third above itself and is preempted: it goes back
/// to the head of its level, and runs again before its peer.
fn start_head(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let me = sched_thread(f, 0, &raw const el0_set_priority, PRIORITY, FIFO)?;
    let peer = sched_thread(f, 1, &raw const el0_mark, PRIORITY, FIFO)?;
    let high = sched_thread(f, 2, &raw const el0_mark, PRIORITY - 5, FIFO)?;
    let h = give_thread(f, high)?;
    set_args(me, &[h, u64::from(PRIORITY + 10), FIFO as u64, word(1)]);
    set_args(peer, &[word(1)]);
    set_args(high, &[word(2)]);
    Ok(())
}

fn done_head(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    match f.slot(t) {
        0 => check(
            t.regs.x[0] == 0 && t.regs.x[5] == 0,
            "the peer ran before the preempted thread",
        ),
        // The raised thread: the kernel has the preempted one first.
        2 => check(
            sched::first(PRIORITY) == f.threads[0],
            "the preempted thread is not at the head of its level",
        ),
        _ => Ok(()),
    }
}

/// Two round-robin threads at one level spin without a system call. Each
/// sees the other run three times between two turns of its loop, and each
/// time the stretch between those turns, which holds the other's whole
/// run, is at least a quantum long: the timer does not fire before its
/// compare value.
fn start_alternate(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let a = sched_thread(f, 0, &raw const el0_alternate, PRIORITY, RR)?;
    let b = sched_thread(f, 1, &raw const el0_alternate, PRIORITY, RR)?;
    set_args(a, &[word(0), word(2), SWITCHES]);
    set_args(b, &[word(2), word(0), SWITCHES]);
    Ok(())
}

fn done_alternate(_: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    check(
        x[4] == SWITCHES,
        "a round-robin thread did not see its peer run",
    )?;
    check(
        x[3] >= quantum(),
        "a round-robin thread ran for less than a quantum",
    )
}

/// A round-robin thread alone at its level spins for three quanta: at
/// least two quanta end, each gives the thread a new one, and the FIFO
/// thread below it never runs.
fn start_lone(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let spin = sched_thread(f, 0, &raw const el0_spin_then_yield, PRIORITY, RR)?;
    let low = sched_thread(f, 1, &raw const el0_mark, PRIORITY - 5, FIFO)?;
    set_args(spin, &[word(0), 3 * quantum()]);
    set_args(low, &[word(0)]);
    Ok(())
}

fn done_lone(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    if f.slot(t) != 0 {
        return Ok(());
    }
    check(f.interrupts >= 2, "fewer than two quanta ended in three")?;
    check(
        x[3] == 0 && x[4] == 0,
        "the end of a quantum let a lower thread run",
    )
}

/// Two round-robin threads at one level and a FIFO thread below. The first
/// waits for its peer to run, which is after its own quantum ends; it goes
/// on with a new quantum after the peer's, raises the FIFO thread above
/// itself and is preempted with nearly all that quantum left. It goes back
/// to the head of its level and uses up the quantum before its peer runs
/// again.
fn start_rest(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let me = sched_thread(f, 0, &raw const el0_set_priority_after_peer, PRIORITY, RR)?;
    let peer = sched_thread(f, 1, &raw const el0_count_until, PRIORITY, RR)?;
    let high = sched_thread(f, 2, &raw const el0_mark, PRIORITY - 5, FIFO)?;
    let h = give_thread(f, high)?;
    let (count, stop) = (word(0), word(1));
    let raise = u64::from(PRIORITY + 10);
    set_args(me, &[h, raise, FIFO as u64, count, 0, 0, stop]);
    set_args(peer, &[count, stop]);
    set_args(high, &[word(2)]);
    Ok(())
}

fn done_rest(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    match f.slot(t) {
        0 => check(
            t.regs.x[0] == 0 && t.regs.x[4] == t.regs.x[5],
            "the peer ran before the preempted thread had used up its quantum",
        ),
        2 => check(
            sched::first(PRIORITY) == f.threads[0],
            "the preempted thread is not at the head of its level",
        ),
        _ => check(shared(f, 1) == 1, "the peer ended before it was let"),
    }
}

// Process and thread tests. A thread that ends without `svc #SVC_DONE` is
// marked in `Fixture::ends`; a judge below the test's other threads, in a
// process of its own, runs once they are done.

/// The judge's priority, below every other thread of a test.
const JUDGE: u8 = PRIORITY - 5;
/// Where the message buffer of a thread that a test program makes goes.
const BUFFER_VA: usize = 0x100_0000;
/// The entry of the child's thread in `child_fault_reason_reaches_the_parent`:
/// no page of the child maps it.
const CHILD_ENTRY: u64 = 0x1000;
/// That thread's message buffer.
const CHILD_BUFFER: u64 = 0x2000;
/// The exit code of `process_exit_ends_the_process_with_its_code`.
const EXIT_CODE: u64 = 0x5EED_C0DE;
/// The words of its data page, past the pattern, that the grandchild's
/// thread counts in and waits on (el0_count_until).
const COUNT_WORD: usize = DATA_VA + 0x800;
const STOP_WORD: usize = DATA_VA + 0x808;

/// The judge: a thread of its own process in slot `slot` that ends at
/// once, below the test's other threads.
fn judge(f: &mut Fixture, slot: usize) -> Result<(), &'static str> {
    let t = spawn(f, slot, &raw const el0_done_at_once, 0)?;
    sched::set_priority(t, JUDGE, FIFO).map_err(|_| "no judge")
}

/// How the process in slot `slot` lives, or why it ended.
fn state(f: &Fixture, slot: usize) -> ProcessState {
    let p = f.processes[slot].expect("a process of the test");
    // SAFETY: the test holds a reference to its process.
    unsafe { p.as_ref() }.state()
}

/// The thread in slot `slot`, which does not run now.
fn slot_thread(f: &Fixture, slot: usize) -> &Thread {
    let t = f.threads[slot].expect("a thread of the test");
    // SAFETY: the test holds a reference to its thread.
    unsafe { t.as_ref() }
}

/// The ready thread in slot `slot` ended with its process and never ran:
/// it is still at el0_mark's first instruction.
fn never_ran(f: &Fixture, slot: usize) -> Result<(), &'static str> {
    let t = slot_thread(f, slot);
    check(
        t.sched.state() == State::Dead && t.regs.elr == user_address(&raw const el0_mark) as u64,
        "a ready thread of the ended process ran",
    )
}

/// The parent, a program, makes an empty child process and a thread in it
/// above itself whose entry maps nothing, and starts it: the thread runs at
/// once and faults, which ends the child, and object_info tells the parent
/// why (spec 15.2 (faults)).
fn start_child_fault(f: &mut Fixture) -> Result<(), &'static str> {
    f.faults = true;
    let parent = spawn(f, 0, &raw const el0_child_fault, 0)?;
    set_args(
        parent,
        &[30, CHILD_ENTRY, u64::from(PRIORITY + 10), CHILD_BUFFER],
    );
    Ok(())
}

fn done_child_fault(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    check(x[0] == 0, "a call of the parent failed")?;
    let ProcessState::Fault { esr, far, elr } = ProcessState::from_words([x[1], x[2], x[3], x[4]])
    else {
        return Err("object_info does not report the child's fault");
    };
    check(
        esr::ec(esr) == esr::EC_IABT_LOWER && esr::fault_status_name(esr) == "translation fault",
        "the child's fault is not a translation fault of an instruction fetch",
    )?;
    check(
        far == CHILD_ENTRY && elr == CHILD_ENTRY,
        "FAR and ELR are not the entry of the child's thread",
    )?;
    let p = f.processes[0].expect("the parent's process");
    // SAFETY: the test holds a reference to the parent's process.
    let parent = unsafe { p.as_ref() };
    let (Ok(child), Ok(thread)) = (
        parent.lookup(Handle(x[23]), Rights::NONE, Object::process),
        parent.lookup(Handle(x[24]), Rights::NONE, Object::thread),
    ) else {
        return Err("the parent's handles do not name the child and its thread");
    };
    // SAFETY: the parent's handle holds the thread.
    let ended = unsafe { thread.as_ref() }.sched.state() == State::Dead;
    check(ended, "the child's thread did not end")?;
    check(
        process::translate(child, CHILD_BUFFER as usize).is_none(),
        "the child's address space outlived it",
    )
}

/// Two started threads of one process exit, and the process ends with
/// code 0 at the second. A third, which the first makes and never starts,
/// does not keep it alive and goes with it. The second asks for the
/// process's state before it exits: the process lived.
fn start_last_exit(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let first = sched_thread(f, 0, &raw const el0_create_then_exit, PRIORITY + 2, FIFO)?;
    let second = sched_thread(f, 1, &raw const el0_info_then_exit, PRIORITY + 1, FIFO)?;
    let own = give_own(f)?;
    let entry = user_address(&raw const el0_done_at_once) as u64;
    let stack = (DATA_VA + PAGE) as u64;
    let priority = u64::from(PRIORITY);
    set_args(
        first,
        &[
            own,
            entry,
            stack,
            0,
            priority,
            FIFO as u64,
            BUFFER_VA as u64,
        ],
    );
    set_args(second, &[own, INFO_PROCESS_STATE, 0]);
    f.ends = [true, true, false];
    judge(f, 2)
}

fn done_last_exit(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(f.slot(t) == 2, "thread_exit returned")?;
    check(
        state(f, 0) == ProcessState::Exited { code: 0 },
        "the last thread's exit did not end the process with code 0",
    )?;
    check(slot_thread(f, 0).regs.x[0] == 0, "thread_create failed")?;
    check(
        slot_thread(f, 1).regs.x[..5] == [0, 0, 0, 0, 0],
        "the process ended before its last started thread",
    )?;
    check(
        thread::in_use() == SLOTS,
        "the stopped thread outlived its process",
    )
}

/// A thread ends its process with a code; a ready thread of the process
/// below it never runs.
fn start_process_exit(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let exit = sched_thread(f, 0, &raw const el0_exit_process, PRIORITY + 1, FIFO)?;
    let ready = sched_thread(f, 1, &raw const el0_mark, PRIORITY, FIFO)?;
    set_args(exit, &[EXIT_CODE]);
    set_args(ready, &[word(0)]);
    f.ends = [true, true, false];
    judge(f, 2)
}

fn done_process_exit(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(f.slot(t) == 2, "a thread of the ended process ran on")?;
    check(
        state(f, 0) == ProcessState::Exited { code: EXIT_CODE },
        "the process did not end with its code",
    )?;
    never_ran(f, 1)
}

/// A thread kills its own process: the call never returns, and its x0
/// keeps the handle. A ready thread of the process below it never runs.
fn start_self_kill(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let kill = sched_thread(f, 0, &raw const el0_kill, PRIORITY + 1, FIFO)?;
    let ready = sched_thread(f, 1, &raw const el0_mark, PRIORITY, FIFO)?;
    let own = give_own(f)?;
    set_args(kill, &[own]);
    set_args(ready, &[word(0)]);
    f.ends = [true, true, false];
    judge(f, 2)
}

fn done_self_kill(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(f.slot(t) == 2, "process_kill of its own process returned")?;
    check(
        state(f, 0) == ProcessState::Killed,
        "the process did not end killed",
    )?;
    let own = f.handles[0].map(|(_, h)| h.0);
    check(
        Some(slot_thread(f, 0).regs.x[0]) == own,
        "process_kill of its own process wrote a result",
    )?;
    never_ran(f, 1)
}

/// A program makes a thread below itself in its own process, starts it
/// and closes the only handle to it. The thread runs all the same once the
/// program is done, finds its message buffer zeroed and writable, and
/// exits: it goes with the kernel's reference, and its buffer's page with
/// it. The process lives on; the judge is a thread of it.
fn start_close_started(f: &mut Fixture) -> Result<(), &'static str> {
    start_maker(f, true)
}

fn done_close_started(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    if f.slot(t) == 0 {
        return check(
            t.regs.x[0] == 0,
            "thread_create, thread_start or handle_close failed",
        );
    }
    check(
        thread::in_use() == 2,
        "the thread outlived its exit and its last handle",
    )?;
    made_thread_exited(f)
}

/// The same with the handle kept: the thread that exited stays as a shell,
/// and its buffer's page goes at its exit. The judge closes the handle
/// afterwards: a process's handle to its own thread keeps both until the
/// process ends.
fn start_keep_started(f: &mut Fixture) -> Result<(), &'static str> {
    start_maker(f, false)
}

fn done_keep_started(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    if f.slot(t) == 0 {
        return check(t.regs.x[0] == 0, "thread_create or thread_start failed");
    }
    let p = f.processes[0].expect("the test's process");
    let h = Handle(slot_thread(f, 0).regs.x[19]);
    // SAFETY: the test holds a reference to its process.
    let made = unsafe { p.as_ref() }.lookup(h, Rights::NONE, Object::thread);
    // SAFETY: the handle holds the thread.
    let ended = made.is_ok_and(|m| unsafe { m.as_ref() }.sched.state() == State::Dead);
    let result = check(ended, "the handle does not keep the thread that exited")
        .and_then(|()| made_thread_exited(f));
    let closed = process::close_handle(p, h, CAUSE);
    result?;
    check(closed.is_ok(), "the handle to the thread did not close")
}

/// The maker in slot 0 of the test's process and the judge in slot 1. The
/// maker makes a thread below itself that runs el0_buffer_mark with its
/// buffer at BUFFER_VA, starts it, and closes its handle when `close`.
fn start_maker(f: &mut Fixture, close: bool) -> Result<(), &'static str> {
    sched_process(f)?;
    let maker = sched_thread(f, 0, &raw const el0_start_and_close, PRIORITY, FIFO)?;
    sched_thread(f, 1, &raw const el0_done_at_once, JUDGE, FIFO)?;
    let own = give_own(f)?;
    let entry = user_address(&raw const el0_buffer_mark) as u64;
    let stack = (DATA_VA + PAGE) as u64;
    let buffer = BUFFER_VA as u64;
    let priority = u64::from(PRIORITY - 2);
    let fifo = FIFO as u64;
    set_args(
        maker,
        &[
            own,
            entry,
            stack,
            buffer,
            priority,
            fifo,
            buffer,
            u64::from(close),
        ],
    );
    Ok(())
}

/// The maker's thread ran, found its buffer zeroed and writable, and
/// exited: its buffer's page is gone, and the process lives on.
fn made_thread_exited(f: &Fixture) -> Result<(), &'static str> {
    check(
        shared(f, 0) == 1,
        "the thread did not run, or its buffer was not a fresh page",
    )?;
    let p = f.processes[0].expect("the test's process");
    check(
        process::translate(p, BUFFER_VA).is_none(),
        "the thread's buffer outlived its exit",
    )?;
    check(
        state(f, 0) == ProcessState::Alive,
        "the exit of one thread ended its process",
    )
}

/// A fault of init stops the machine (spec 7.9). In test builds the end
/// comes to the test (init_ended), which judges init's thread in slot 0;
/// the judge in slot 1 runs only when that does not happen.
fn start_init_fault(f: &mut Fixture) -> Result<(), &'static str> {
    f.faults = true;
    spawn(f, 0, &raw const el0_wfi, 0)?;
    f.ends[0] = true;
    judge(f, 1)?;
    process::set_init(f.processes[0].expect("init's process"));
    Ok(())
}

fn done_init_fault(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(f.slot(t) == 0, "init's fault did not stop the machine")?;
    let ProcessState::Fault { esr, .. } = state(f, 0) else {
        return Err("init did not end with its fault");
    };
    check(esr::ec(esr) == esr::EC_WFX, "init's fault is not the WFI")
}

/// Init's exit ends the run (spec 7.9), with its code.
fn start_init_exit(f: &mut Fixture) -> Result<(), &'static str> {
    let t = spawn(f, 0, &raw const el0_exit_process, 0)?;
    set_args(t, &[7]);
    f.ends[0] = true;
    judge(f, 1)?;
    process::set_init(f.processes[0].expect("init's process"));
    Ok(())
}

fn done_init_exit(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(f.slot(t) == 0, "init's exit did not end the run")?;
    check(
        state(f, 0) == ProcessState::Exited { code: 7 },
        "init did not exit with its code",
    )
}

/// A child process that only its one started thread holds: the maker in
/// slot 0 starts the thread and closes both handles; the thread exits or
/// faults, and the child's last reference goes inside its own end.
fn start_orphan(f: &mut Fixture, entry: u64) -> Result<(), &'static str> {
    sched_process(f)?;
    let maker = sched_thread(f, 0, &raw const el0_start_then_close, PRIORITY, FIFO)?;
    sched_thread(f, 1, &raw const el0_done_at_once, JUDGE, FIFO)?;
    new_process(f, 2)?;
    let child = f.processes[2].take().expect("the child");
    let t = thread::create(child, entry as usize, 0, 0, PRIORITY - 1, FIFO);
    let p = f.processes[0].expect("the test's process");
    let handles = t.ok().map(|t| {
        let ht = process::insert_handle(p, Object::Thread(t), Rights::MANAGE);
        // SAFETY: the reference `create` handed out goes.
        unsafe { thread::release(t, CAUSE) };
        ht
    });
    let hc = process::insert_handle(p, Object::Process(child), Rights::MANAGE);
    // SAFETY: as above.
    unsafe { process::release(child, CAUSE) };
    match (handles, hc) {
        (Some(Ok(ht)), Ok(hc)) => {
            set_args(maker, &[ht.0, hc.0]);
            Ok(())
        }
        _ => Err("no child"),
    }
}

fn start_orphan_exit(f: &mut Fixture) -> Result<(), &'static str> {
    start_orphan(f, user_address(&raw const el0_create_then_exit) as u64)
}

fn start_orphan_fault(f: &mut Fixture) -> Result<(), &'static str> {
    f.faults = true;
    start_orphan(f, CHILD_ENTRY)
}

fn done_orphan(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    if f.slot(t) == 0 {
        return check(t.regs.x[0] == 0, "thread_start or handle_close failed");
    }
    check(
        process::in_use() == 1 && thread::in_use() == 2,
        "the orphan process or its thread stayed, or went twice",
    )
}

// Cleanup (spec 7.7). The thread in slot 1 kills a child whose table holds
// the only handles to its CHILD_THREADS stopped threads: each thread's
// last reference goes, and each takes one portion of cleanup at the
// killer's level. After INTERRUPT_AFTER portions the timer's interrupt
// comes (portion_done) and starts the thread in slot 0 above the killer;
// the judge in slot 2 is below both.

/// The cleanup tests' threads and child.
fn start_cleanup(f: &mut Fixture) -> Result<(), &'static str> {
    killer_and_child(f, child_with_threads)
}

/// The threads of a test that kills the child `make` makes: the waking
/// thread in slot 0, the killer in slot 1 with a handle to the child, the
/// judge in slot 2. The interrupt comes after INTERRUPT_AFTER portions.
fn killer_and_child(
    f: &mut Fixture,
    make: fn() -> Result<NonNull<Process>, &'static str>,
) -> Result<(), &'static str> {
    sched_process(f)?;
    sched_thread(f, 0, &raw const el0_done_at_once, PRIORITY + 10, FIFO)?;
    let killer = sched_thread(f, 1, &raw const el0_kill, PRIORITY, FIFO)?;
    sched_thread(f, 2, &raw const el0_done_at_once, JUDGE, FIFO)?;
    f.memory = phys::free_frames() + pages::taken() as u64;
    let child = make()?;
    let h = give_kept(f, Object::Process(child));
    // SAFETY: the test's reference goes; the handle, if it went in, holds
    // the child.
    unsafe { process::release(child, CAUSE) };
    set_args(killer, &[h?]);
    // Slot 0 waits for the interrupt, which no deadline brings.
    f.wake = Some(u64::MAX);
    f.interrupt_after = Some(INTERRUPT_AFTER);
    cleanup::take_late();
    Ok(())
}

/// A process with CHILD_THREADS stopped threads that only handles in its
/// own table hold.
fn child_with_threads() -> Result<NonNull<Process>, &'static str> {
    let child = process::create_root(QUOTA, HANDLE_LIMIT, CEILING).map_err(|_| "no child")?;
    let made = give_threads(child);
    if made.is_err() {
        // SAFETY: the test's reference goes, and nothing uses it afterwards.
        unsafe { process::release(child, CAUSE) };
    }
    made.map(|()| child)
}

/// CHILD_THREADS stopped threads of `child` that only handles in its own
/// table hold.
fn give_threads(child: NonNull<Process>) -> Result<(), &'static str> {
    for _ in 0..CHILD_THREADS {
        thread::create(child, TEXT_VA, DATA_VA + PAGE, 0, PRIORITY, FIFO)
            .and_then(|t| {
                let h = process::insert_handle(child, Object::Thread(t), Rights::NONE);
                // SAFETY: the reference `create` handed out goes; the handle,
                // if it went in, holds the thread.
                unsafe { thread::release(t, CAUSE) };
                h
            })
            .map_err(|_| "no thread in the child")?;
    }
    Ok(())
}

/// The interrupt that came after INTERRUPT_AFTER portions was handled
/// while work was left, and no portion began while it was pending.
fn done_cleanup_yields(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    match f.slot(t) {
        0 => Ok(()),
        1 => check(t.regs.x[0] == 0, "process_kill failed"),
        _ => {
            check(
                f.queued_at_wake.is_some_and(|n| n > 0),
                "the interrupt waited for the cleanup to end",
            )?;
            check(
                !cleanup::take_late(),
                "a portion began while an interrupt was pending",
            )?;
            cleanup_done()
        }
    }
}

/// The cleanup runs at the killer's level: the thread above it runs while
/// work is left, the killer's call returns only after the work of its own
/// level, and the judge below comes last.
fn done_cleanup_level(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    match f.slot(t) {
        0 => check(
            cleanup::len() > 0,
            "the thread above the cause waited for the cleanup",
        ),
        1 => check(
            t.regs.x[0] == 0 && cleanup::len() == 0,
            "process_kill returned before the cleanup at its caller's level",
        ),
        _ => cleanup_done(),
    }
}

// The child ends itself, through a thread of its own in slot 1 at the
// killer's level: by a fault, or by thread_exit as its last started
// thread. The teardown runs at that thread's priority, as the kill's runs
// at the killer's (spec 7.7).

/// The fault: the child's thread starts where nothing is mapped.
fn start_fault_cleanup(f: &mut Fixture) -> Result<(), &'static str> {
    f.faults = true;
    child_ends_itself(f, CHILD_ENTRY as usize)
}

/// The exit: the child's thread makes a call that fails and exits.
fn start_exit_cleanup(f: &mut Fixture) -> Result<(), &'static str> {
    child_ends_itself(f, user_address(&raw const el0_info_then_exit))
}

/// The waking thread in slot 0 and the judge in slot 2, as for the kill;
/// in slot 1 the child with the programs and CHILD_THREADS stopped
/// threads, and its thread that starts at `entry` and ends it.
fn child_ends_itself(f: &mut Fixture, entry: usize) -> Result<(), &'static str> {
    sched_process(f)?;
    sched_thread(f, 0, &raw const el0_done_at_once, PRIORITY + 10, FIFO)?;
    sched_thread(f, 2, &raw const el0_done_at_once, JUDGE, FIFO)?;
    let child = new_process(f, 1)?;
    give_threads(child)?;
    let t = thread::create(child, entry, DATA_VA + PAGE, 0, PRIORITY, FIFO)
        .map_err(|_| "no thread in the child")?;
    f.threads[1] = Some(t);
    f.ends[1] = true;
    // Slot 0 waits for the interrupt, which no deadline brings.
    f.wake = Some(u64::MAX);
    f.interrupt_after = Some(INTERRUPT_AFTER);
    cleanup::take_late();
    Ok(())
}

/// The thread above the child's thread runs while work is left, and the
/// judge below comes last, once the child's thread ended the child.
fn done_own_cleanup(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    match f.slot(t) {
        0 => check(
            cleanup::len() > 0,
            "the thread above the cause waited for the cleanup",
        ),
        1 => Err("the child's thread did not end the child"),
        _ => {
            check(
                matches!(
                    state(f, 1),
                    ProcessState::Fault { .. } | ProcessState::Exited { code: 0 }
                ),
                "the child did not end through its own thread",
            )?;
            cleanup_done()
        }
    }
}

/// The child's threads went back to their pool; the child stays as a
/// shell that the test's handle holds.
fn cleanup_done() -> Result<(), &'static str> {
    check(
        cleanup::len() == 0 && cleanup::longest() > 0,
        "the cleanup queue is not empty, or no portion was measured",
    )?;
    check(
        thread::in_use() == SLOTS && process::in_use() == 2,
        "the killed child's threads stayed in their pool",
    )
}

/// The teardown of a child with a full table of MAX_HANDLES handles and
/// BIG_PAGES pages spread over a gigabyte (spec 7.7): it goes in portions,
/// a chunk of the table or a table of the space each, and an interrupt
/// comes every INTERRUPT_EVERY portions. None of them waits for the next
/// portion: every portion begins with no interrupt pending, and the thread
/// the first one wakes runs while work is left. Afterwards the child's
/// memory is back.
fn start_big_teardown(f: &mut Fixture) -> Result<(), &'static str> {
    killer_and_child(f, big_child)?;
    f.interrupt_after = Some(INTERRUPT_EVERY);
    f.interrupt_every = Some(INTERRUPT_EVERY);
    Ok(())
}

/// The big teardown's child: one frame of its own, mapped at every
/// 2 MiB of the gigabyte from BIG_BASE, and a full table.
fn big_child() -> Result<NonNull<Process>, &'static str> {
    let child = process::create_root(QUOTA, MAX_HANDLES, CEILING).map_err(|_| "no child")?;
    let filled = fill_big_child(child);
    if filled.is_err() {
        // SAFETY: the test's reference goes, and nothing uses it afterwards.
        unsafe { process::release(child, CAUSE) };
    }
    filled.map(|()| child)
}

fn fill_big_child(mut child: NonNull<Process>) -> Result<(), &'static str> {
    // SAFETY: the child was just created, and only this test uses it.
    let pa = unsafe { child.as_mut() }
        .map_frames(BIG_BASE, PAGE_SIZE, Attrs::USER_DATA)
        .map_err(|_| "the child's page did not map")?;
    for i in 1..BIG_PAGES {
        let va = BIG_BASE + i * BLOCK_2M as usize;
        process::map_page(child, va, pa, Attrs::USER_DATA)
            .map_err(|_| "a page of the child did not map")?;
    }
    for _ in 0..MAX_HANDLES {
        process::insert_handle(child, Object::Resource, Rights::NONE)
            .map_err(|_| "a handle did not go into the child")?;
    }
    Ok(())
}

fn done_big_teardown(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    match f.slot(t) {
        0 => check(
            cleanup::len() > 0,
            "the interrupt waited for the teardown to end",
        ),
        1 => check(t.regs.x[0] == 0, "process_kill failed"),
        _ => {
            check(
                f.portions as usize >= MAX_CHUNKS + BIG_PAGES,
                "the teardown did not go a chunk or a table a portion",
            )?;
            check(
                !cleanup::take_late() && f.interrupts >= f.portions / INTERRUPT_EVERY,
                "a portion began while an interrupt was pending",
            )?;
            check(
                cleanup::len() == 0 && phys::free_frames() + pages::taken() as u64 == f.memory,
                "the child's frames did not come back",
            )
        }
    }
}

/// The child C of the judge's process, with ceiling CEILING, ends itself
/// from its thread in slot 2, below the grandchild's thread in slot 1,
/// which counts in x2, round robin at PRIORITY + 2 (spec 4, 7.7). The
/// thread of C never gets the processor while the grandchild's counts, so
/// at the first timer interrupt, the end of the counter's quantum, the
/// kernel ends C as process_exit from that thread would, with its
/// priority as the cause. The stage Stop runs at C's ceiling and stops the
/// grandchild's thread before it runs again: its count stays until the
/// judge in slot 0 wakes above it three quanta after the start, and by
/// then the teardown of both went to its end at the level of the cause,
/// and the exit notification of C, which its parent's channel hears of at
/// that level (spec 7.9), waits for the judge's receive.
fn start_descendants(f: &mut Fixture) -> Result<(), &'static str> {
    let judge = spawn(f, 0, &raw const el0_receive, 0)?;
    sched::set_priority(judge, PRIORITY + 10, FIFO).map_err(|_| "no judge")?;
    let parent = f.processes[0].expect("the judge's process");
    let c = channel::create(parent, PRIORITY).map_err(|_| "no channel")?;
    let h = give(parent, Object::Channel(c), Rights::RECEIVE);
    let child = process::create_child(parent, 2 * CHILD_QUOTA, HANDLE_LIMIT, CEILING);
    let heard = child.and_then(|child| {
        channel::add_source(c)?;
        process::set_exit(child, c, EXIT_LABEL, PRIORITY - 5);
        Ok(child)
    });
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the channel, and so does the child's exit.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    set_args(judge, &[h?, NO_WAIT]);
    let child = heard.map_err(|_| "no child")?;
    f.processes[2] = Some(child);
    let low = PRIORITY - 5;
    let t = thread::create(child, TEXT_VA, DATA_VA + PAGE, 0, low, FIFO)
        .map_err(|_| "no thread in the child")?;
    f.threads[2] = Some(t);
    f.ends[2] = true;
    let counter = process::create_child(child, CHILD_QUOTA, HANDLE_LIMIT, CEILING)
        .map_err(|_| "no grandchild")
        .and_then(|grandchild| {
            let p = with_programs(f, 1, grandchild)?;
            new_thread(f, 1, p, DATA_VA, &raw const el0_count_until, 0)
        })?;
    set_args(counter, &[COUNT_WORD as u64, STOP_WORD as u64]);
    sched::set_priority(counter, PRIORITY + 2, RR).map_err(|_| "no counter")?;
    f.ends[1] = true;
    f.exit_at_interrupt = Some((child, low));
    let quanta = 3 * abi::RR_QUANTUM_NS;
    f.wake = Some(timer::clock().deadline_after(timer::now(), quanta));
    Ok(())
}

/// What the thread in slot 1 counted, in x2 (el0_count_until).
fn counted(f: &Fixture) -> u64 {
    slot_thread(f, 1).regs.x[2]
}

fn done_descendants(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(
        f.slot(t) == 0,
        "the grandchild's thread ran to its end after its parent ended",
    )?;
    check(
        t.regs.x[0] == 0 && t.regs.x[1..12] == exit_notice(EXIT_LABEL),
        "the child's exit notification did not wait in its parent's channel",
    )?;
    check(
        f.count_at_exit.is_some_and(|n| n > 0),
        "the grandchild's thread did not count before its parent ended",
    )?;
    check(
        Some(counted(f)) == f.count_at_exit,
        "the grandchild's thread ran after its parent ended",
    )?;
    check(
        slot_thread(f, 1).sched.state() == State::Dead
            && state(f, 2) == ProcessState::Exited { code: EXIT_CODE },
        "the child did not end with its thread's exit, or the grandchild's thread did not stop",
    )?;
    let shell =
        |slot: usize| process::progress(f.processes[slot].expect("a process")).0 == Stage::Shell;
    check(
        cleanup::len() == 0 && shell(1) && shell(2),
        "the teardown of the child and the grandchild did not go to its end",
    )
}

/// The killer in slot 0, woken 1 ms after the start, kills its child C;
/// C's child, the grandchild in slot 1, has a thread below the killer that
/// counts meanwhile. The end of C ends the grandchild and stops its thread
/// (spec 4), and the teardown of both runs at the killer's level, before
/// the kill returns. Each child's quota comes off its parent's.
fn start_grandchild(f: &mut Fixture) -> Result<(), &'static str> {
    let killer = spawn(f, 0, &raw const el0_kill, 0)?;
    let killers = f.processes[0].expect("the killer's process");
    let child = process::create_child(killers, 2 * CHILD_QUOTA, HANDLE_LIMIT, CEILING)
        .map_err(|_| "no child")?;
    let h = give_kept(f, Object::Process(child));
    let counter = process::create_child(child, CHILD_QUOTA, HANDLE_LIMIT, CEILING)
        .map_err(|_| "no grandchild")
        .and_then(|grandchild| {
            let p = with_programs(f, 1, grandchild)?;
            new_thread(f, 1, p, DATA_VA, &raw const el0_count_until, 0)
        });
    // SAFETY: the test's reference goes; the handle, if it went in, holds
    // the child.
    unsafe { process::release(child, CAUSE) };
    let counter = counter?;
    set_args(counter, &[COUNT_WORD as u64, STOP_WORD as u64]);
    sched::set_priority(counter, PRIORITY - 2, FIFO).map_err(|_| "no counter")?;
    set_args(killer, &[h?]);
    f.ends[1] = true;
    f.wake = Some(timer::clock().deadline_after(timer::now(), 1_000_000));
    Ok(())
}

fn done_grandchild(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(t.regs.x[0] == 0, "process_kill failed")?;
    check(
        state(f, 1) == ProcessState::Killed,
        "the grandchild outlived its parent",
    )?;
    let counter = slot_thread(f, 1);
    check(
        counter.sched.state() == State::Dead && counter.regs.x[2] > 0,
        "the grandchild's thread did not run, or did not stop",
    )?;
    let grandchild = f.processes[1].expect("the grandchild");
    check(
        cleanup::len() == 0 && process::translate(grandchild, DATA_VA).is_none(),
        "the grandchild's teardown did not end before the kill returned",
    )
}

// Channels (spec 6.1, 6.8, 7.7): threads that wait in receive.

/// The label of the exit channel and of the start channel of the tests'
/// children.
const EXIT_LABEL: u64 = 0xE417;

/// x1-x11 of a receive that took the exit notification of a child whose
/// exit channel carried `label` (spec 7.9).
fn exit_notice(label: u64) -> [u64; 11] {
    Notification {
        source: Source::Exit,
        label,
        bits: 1,
        count: 1,
    }
    .to_words()
}

/// A child with the programs, in slot 0, whose entry 0 holds its start
/// channel: a copy of its parent's channel with a label and NOTIFY (spec
/// 13.3). Its thread notifies through abi::START_CHANNEL; the parent's
/// thread in slot 1, below it, takes the notification with the label
/// without waiting.
fn start_start_channel(f: &mut Fixture) -> Result<(), &'static str> {
    let parent = new_process(f, 1)?;
    let receiver = new_thread(f, 1, parent, DATA_VA, &raw const el0_receive, 0)?;
    sched::set_priority(receiver, JUDGE, FIFO).map_err(|_| "no receiver")?;
    let c = channel::create(parent, PRIORITY).map_err(|_| "no channel")?;
    let h = give(parent, Object::Channel(c), Rights::RECEIVE);
    let s = session::create(parent, c, EXIT_LABEL, PRIORITY);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the channel, and so does the session.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    let s = s.map_err(|_| "no session")?;
    let child = process::create_child(parent, CHILD_QUOTA, HANDLE_LIMIT, CEILING);
    let moved =
        child.and_then(|child| process::move_start(child, Object::Session(s), Rights::NOTIFY));
    // SAFETY: the reference `create` handed out goes; entry 0 of the
    // child, if the move went, holds the session.
    unsafe { session::unref(s, CAUSE) };
    let child = child.map_err(|_| "no child")?;
    let child = with_programs(f, 0, child)?;
    let notifier = new_thread(f, 0, child, DATA_VA, &raw const el0_notify, 0)?;
    moved.map_err(|_| "the start channel did not move")?;
    set_args(notifier, &[START_CHANNEL.0, BITS]);
    set_args(receiver, &[h?, NO_WAIT]);
    Ok(())
}

fn done_start_channel(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    if f.slot(t) == 0 {
        return check(x[0] == 0, "notify through START_CHANNEL failed");
    }
    let session = Notification {
        source: Source::Session,
        label: EXIT_LABEL,
        bits: BITS,
        count: 1,
    };
    check(
        x[0] == 0 && x[1..12] == session.to_words(),
        "the parent did not get the child's notification with its label",
    )
}

/// x1-x11 of a receive that took one post of `bits` from the slot of label
/// 0.
fn notice(bits: u64) -> [u64; 11] {
    Notification {
        source: Source::Unlabeled,
        label: 0,
        bits,
        count: 1,
    }
    .to_words()
}

/// A thread waits in receive, in a process of its own. Below it, a thread
/// of another process, which holds the channel with RECEIVE too, kills
/// that process, notifies the channel and takes the notification back at
/// once: the kill took the waiting thread off the channel (spec 7.7), the
/// slot went to no thread that ended, and the thread that waited kept its
/// arguments in its registers.
fn start_kill_waiting(f: &mut Fixture) -> Result<(), &'static str> {
    let waiter = spawn(f, 0, &raw const el0_receive, 0)?;
    let killer = spawn(f, 1, &raw const el0_kill_notify_receive, 0)?;
    sched::set_priority(killer, JUDGE, FIFO).map_err(|_| "no killer")?;
    let p = f.processes[0].expect("the waiter's process");
    let q = f.processes[1].expect("the killer's process");
    let c = channel::create(q, PRIORITY).map_err(|_| "no channel")?;
    let handles = [
        give(p, Object::Channel(c), Rights::RECEIVE),
        give(q, Object::Channel(c), Rights::NOTIFY | Rights::RECEIVE),
        give(q, Object::Process(p), Rights::MANAGE),
    ];
    // SAFETY: the reference `create` handed out goes; the handles that went
    // in hold the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    let [waiting, own, target] = handles;
    let (waiting, own) = (waiting?, own?);
    set_args(waiter, &[waiting, 0]);
    set_args(killer, &[target?, own, BITS]);
    f.kept = [waiting, 0];
    f.ends[0] = true;
    Ok(())
}

fn done_kill_waiting(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(f.slot(t) == 1, "the killed thread came back from receive")?;
    let x = &t.regs.x;
    check(x[19] == 0 && x[20] == 0, "process_kill or notify failed")?;
    check(
        x[0] == 0 && x[1..12] == notice(BITS),
        "the notification did not stay in the channel for the killer",
    )?;
    let waiter = slot_thread(f, 0);
    check(
        waiter.sched.state() == State::Dead && waiter.regs.x[..2] == f.kept,
        "the killed thread got a result of receive",
    )
}

/// A thread waits in receive, and nothing but the kernel refers to it: no
/// handle, and the test let its own reference go. The kernel's reference
/// keeps it while it waits (spec 8.1): a checker below it finds it in its
/// pool and waiting. The killer below the checker kills its process; the
/// thread leaves the channel and goes with the kernel's reference before
/// the kill returns.
fn start_kernel_reference(f: &mut Fixture) -> Result<(), &'static str> {
    let p = new_process(f, 0)?;
    let q = new_process(f, 1)?;
    let c = channel::create(p, PRIORITY).map_err(|_| "no channel")?;
    let held = give(p, Object::Channel(c), Rights::RECEIVE);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    let entry = user_address(&raw const el0_receive_then_exit);
    let waiter = thread::create(p, entry, 0, held?, PRIORITY, FIFO).map_err(|_| "no thread")?;
    let started = thread::start(waiter);
    // SAFETY: the reference `create` handed out goes; the kernel's keeps
    // the thread once it started.
    unsafe { thread::release(waiter, CAUSE) };
    started.map_err(|_| "the waiting thread did not start")?;
    f.unheld = Some(waiter);
    let target = give(q, Object::Process(p), Rights::MANAGE)?;
    let checker = user_address(&raw const el0_done_at_once);
    let killer = user_address(&raw const el0_kill);
    for (slot, entry, arg, priority) in [(1, checker, 0, JUDGE + 1), (2, killer, target, JUDGE)] {
        let t = thread::create(q, entry, 0, arg, priority, FIFO).map_err(|_| "no thread")?;
        f.threads[slot] = Some(t);
    }
    f.live_threads = thread::in_use();
    Ok(())
}

fn done_kernel_reference(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    if f.slot(t) == 1 {
        check(
            thread::in_use() == f.live_threads,
            "a waiting thread that nothing but the kernel refers to went",
        )?;
        // SAFETY: the kernel's reference keeps the thread, as the count
        // shows.
        let waiter = unsafe { f.unheld.expect("the waiting thread").as_ref() };
        return check(
            waiter.sched.state() == State::Waiting,
            "the thread does not wait",
        );
    }
    check(t.regs.x[0] == 0, "process_kill failed")?;
    check(
        thread::in_use() == f.live_threads - 1 && cleanup::len() == 0,
        "the thread that waited did not go with the kernel's reference",
    )
}

/// Two threads wait in receive at one level, the first ahead of the
/// second. A thread below them raises the second above the first and
/// notifies the channel: the second moved in the queue of receivers (spec
/// 6.1) and takes the notification at once; the first waits on. The
/// channel's slot, at 40, is above the waiters' ceiling, and the raised
/// thread works at the ceiling (spec 6.6).
fn start_requeue(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process_under(f, CAPPED)?;
    let first = sched_thread(f, 0, &raw const el0_receive, PRIORITY, FIFO)?;
    let second = sched_thread(f, 1, &raw const el0_receive, PRIORITY, FIFO)?;
    let raiser = sched_thread(f, 2, &raw const el0_raise_then_notify, JUDGE, FIFO)?;
    let p = f.processes[0].expect("the test's process");
    // The channel's slot is above the waiters' ceiling: its payer's is 63.
    let q = new_process(f, 1)?;
    let c = channel::create(q, 40).map_err(|_| "no channel")?;
    let h = give(p, Object::Channel(c), Rights::NOTIFY | Rights::RECEIVE);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    let h = h?;
    let raised = give_thread(f, second)?;
    set_args(first, &[h, 0]);
    set_args(second, &[h, 0]);
    let above = u64::from(PRIORITY + 2);
    set_args(raiser, &[raised, above, FIFO as u64, h, BITS]);
    f.ends[0] = true;
    Ok(())
}

fn done_requeue(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    match f.slot(t) {
        0 => Err("the thread that kept its level took the notification"),
        1 => check(
            x[0] == 0
                && x[1..12] == notice(BITS)
                && t.sched.base() == PRIORITY + 2
                && t.sched.priority() == CAPPED,
            "the raised thread did not take the notification at its new level",
        ),
        _ => {
            check(
                x[19] == 0 && x[0] == 0,
                "thread_set_priority or notify failed",
            )?;
            check(
                slot_thread(f, 0).sched.state() == State::Waiting,
                "the first thread does not wait on",
            )
        }
    }
}

/// Threads of two processes wait in receive on one channel, a process
/// full of them each, each process with a handle with RECEIVE. The closer
/// below them closes both handles, and the last one closes the channel
/// (spec 6.8): the stage Close wakes the waiters with PEER_CLOSED, 64 a
/// portion, in two portions at the closer's level (spec 7.7); an interrupt
/// comes after every portion, and none begins while one is pending. The
/// judge below the closer finds every waiter ended with PEER_CLOSED.
fn start_close_portions(f: &mut Fixture) -> Result<(), &'static str> {
    let own = new_process(f, 0)?;
    let entry = user_address(&raw const el0_done_at_once);
    for (slot, priority) in [(0, JUDGE), (1, JUDGE - 1)] {
        let t = thread::create(own, entry, 0, 0, priority, FIFO).map_err(|_| "no thread")?;
        f.threads[slot] = Some(t);
    }
    let c = channel::create(own, PRIORITY).map_err(|_| "no channel")?;
    let made = (1..=2).try_for_each(|slot| crowd_of(f, slot, c));
    // SAFETY: the reference `create` handed out goes; the handles that went
    // in hold the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    made?;
    let _ = channel::take_close_portions();
    cleanup::take_late();
    f.interrupt_every = Some(1);
    Ok(())
}

/// A process in slot `slot` with a handle with RECEIVE to `c`, which the
/// test keeps, and abi::MAX_THREADS threads of it, started, that will wait
/// in receive on the channel, in the crowd.
fn crowd_of(f: &mut Fixture, slot: usize, c: NonNull<Channel>) -> Result<(), &'static str> {
    let p = new_process(f, slot)?;
    let h = process::insert_handle(p, Object::Channel(c), Rights::RECEIVE)
        .map_err(|_| "a handle did not go in")?;
    f.handles[slot - 1] = Some((p, h));
    let entry = user_address(&raw const el0_receive_then_exit);
    let n = MAX_THREADS as usize;
    for i in (slot - 1) * n..slot * n {
        let t = thread::create(p, entry, 0, h.0, PRIORITY, FIFO).map_err(|_| "no thread")?;
        f.crowd[i] = Some(t);
        thread::start(t).map_err(|_| "a thread did not start")?;
    }
    Ok(())
}

fn done_close_portions(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    // SAFETY: the test holds a reference to each thread of the crowd.
    let crowd = || f.crowd.iter().flatten().map(|w| unsafe { w.as_ref() });
    if f.slot(t) == 0 {
        let waiting = crowd().all(|w| w.sched.state() == State::Waiting);
        for &(p, h) in f.handles.iter().flatten() {
            process::close_handle(p, h, JUDGE).map_err(|_| "a handle did not close")?;
        }
        return check(waiting, "a thread of the crowd did not wait");
    }
    check(
        crowd().all(|w| w.sched.state() == State::Dead && w.regs.x[0] == Error::PeerClosed.code()),
        "a thread that waited did not end with PEER_CLOSED",
    )?;
    check(
        channel::take_close_portions() == (2, 64, 1 << JUDGE),
        "the stage Close did not wake the waiters 64 a portion at the closer's level",
    )?;
    check(
        !cleanup::take_late() && f.interrupts >= 2,
        "a portion began while an interrupt was pending",
    )
}
