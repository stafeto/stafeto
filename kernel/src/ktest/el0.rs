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
use crate::thread::{self, Thread};
use crate::timer::{self as timers, Timer};
use crate::{sched, session};
use abi::{
    CLIENT_GONE, Call, Error, HANDLES_SHIFT, Handle, INFO_PROCESS_STATE, MAX_THREADS, NO_WAIT,
    Notification, Policy, ProcessState, Rights, START_CHANNEL, Source, msgbuf,
};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use kcore::PAGE_SIZE;
use kcore::esr;
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
    static el0_pattern_loop: u8;
    static el0_wait_loop: u8;
    static el0_pattern_yield: u8;
    static el0_mark: u8;
    static el0_count_until: u8;
    static el0_spin_then_yield: u8;
    static el0_set_priority: u8;
    static el0_set_priority_after_peer: u8;
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
    static el0_create_and_start: u8;
    static el0_buffer_mark: u8;
    static el0_start_then_close: u8;
    static el0_receive: u8;
    static el0_notify: u8;
    static el0_receive_then_exit: u8;
    static el0_kill_notify_receive: u8;
    static el0_raise_then_notify: u8;
    static el0_pattern_receive: u8;
    static el0_alarm_then: u8;
    static el0_send: u8;
    static el0_serve: u8;
    static el0_serve_after_notice: u8;
    static el0_reply_then_notify: u8;
    static el0_raise_then_send: u8;
    static el0_send_then_exit: u8;
    static el0_take_then_exit: u8;
    static el0_take_then_wait: u8;
    static el0_take_notify_reply: u8;
    static el0_reply_after_notice: u8;
    static el0_check_after_notice: u8;
    static el0_kill_close_notify: u8;
    static el0_raise_then_kill: u8;
    static el0_close: u8;
    static el0_send_close: u8;
    static el0_notice_then_take: u8;
    static el0_serve_snap: u8;
    static el0_send_twice: u8;
    static el0_release_then_send: u8;
    static el0_pending_send: u8;
    static el0_measure: u8;
    static el0_serve_loop: u8;
    static el0_yield_loop: u8;
}

/// Test system calls: the numbers lie in abi::TEST_CALLS and exist in test
/// builds only (el0.S uses them too). NOP returns 0 in x0; DONE ends the
/// program. SNAP notes the scheduler's state (`Snap`), SLOW turns the fast
/// path of send off for the rest of the test, RELEASE lets thread x0 of
/// the crowd go at level x1, each returning 0 in x0; PENDING makes send
/// with its registers once an interrupt is pending.
pub const SVC_NOP: u16 = 0xFF00;
pub const SVC_DONE: u16 = 0xFF01;
const SVC_SNAP: u16 = 0xFF02;
const SVC_SLOW: u16 = 0xFF03;
const SVC_RELEASE: u16 = 0xFF04;
const SVC_PENDING: u16 = 0xFF05;

const _: () = assert!(*abi::TEST_CALLS.start() <= SVC_NOP && SVC_PENDING <= *abi::TEST_CALLS.end());

// el0.S makes these calls by number and knows these values.
const _: () = assert!(
    Call::HandleClose.number() == 1
        && Call::Send.number() == 4
        && Call::Receive.number() == 5
        && Call::Reply.number() == 6
        && Call::Notify.number() == 7
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
const _: () = assert!(DATA_VA == 0x80_0000 && Policy::Fifo as u8 == 1 && NO_WAIT == 0x10000);

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
/// Threads that wait in one channel in `closing_a_channel_wakes_waiters_in_portions`,
/// or send to one service in `replies_stage_goes_in_portions`: two
/// processes full of them.
const CROWD: usize = 2 * MAX_THREADS as usize;
/// The ceiling of the waiters' process in `set_priority_moves_a_waiting_thread`.
const CAPPED: u8 = PRIORITY + 3;
/// Rounds of each row of `ipc_round_trip_is_measured`.
const ROUNDS: u64 = 1000;
/// Timers of `expired_timers_fire_in_batches` on one deadline: more than
/// one interrupt takes (timers::BATCH), and more than one process pays for
/// (abi::MAX_TIMERS).
const BATCHED: usize = 100;

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
        name: "registers_survive_a_wait_in_idle",
        start: start_idle,
        done: done_wait_in_idle,
    },
    El0Test {
        name: "fifo_thread_runs_with_the_timer_off",
        start: start_timer_off,
        done: done_timer_off,
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
        name: "request_through_the_start_channel",
        start: start_start_request,
        done: done_start_request,
    },
    El0Test {
        name: "reply_from_another_process_is_bad_state",
        start: start_foreign_reply,
        done: done_foreign_reply,
    },
    El0Test {
        name: "boost_is_capped_by_the_server_ceiling",
        start: start_capped_boost,
        done: done_capped_boost,
    },
    El0Test {
        name: "client_of_a_dead_server_gets_peer_closed",
        start: start_dead_server,
        done: done_dead_server,
    },
    El0Test {
        name: "replies_stage_goes_in_portions",
        start: start_replies_portions,
        done: done_replies_portions,
    },
    El0Test {
        name: "replies_stage_runs_at_the_top_client",
        start: start_replies_level,
        done: done_replies_level,
    },
    El0Test {
        name: "dead_client_frees_its_memory_before_the_reply",
        start: start_dead_client_memory,
        done: done_dead_client_memory,
    },
    El0Test {
        name: "reply_to_a_dead_client_is_peer_closed",
        start: start_dead_client,
        done: done_dead_client,
    },
    El0Test {
        name: "kill_takes_a_sender_off_the_channel",
        start: start_kill_sender,
        done: done_kill_sender,
    },
    El0Test {
        name: "kill_in_every_wait_state",
        start: start_kill_states,
        done: done_kill_states,
    },
    El0Test {
        name: "close_portion_keeps_to_one_level",
        start: start_level_portions,
        done: done_level_portions,
    },
    El0Test {
        name: "close_portion_counts_the_handles",
        start: start_close_handles,
        done: done_close_handles,
    },
    El0Test {
        name: "raised_waiter_raises_the_close",
        start: start_raised_close,
        done: done_raised_close,
    },
    El0Test {
        name: "raised_client_raises_the_replies",
        start: start_raised_replies,
        done: done_raised_replies,
    },
    El0Test {
        name: "close_keeps_a_higher_cause",
        start: start_close_above,
        done: done_close_above,
    },
    El0Test {
        name: "same_priority_keeps_the_close_in_place",
        start: start_close_in_place,
        done: done_close_in_place,
    },
    El0Test {
        name: "a_call_cycle_ends_with_the_kill",
        start: start_call_cycle,
        done: done_call_cycle,
    },
    El0Test {
        name: "reply_to_a_dead_client_closes_the_handles",
        start: start_dead_client_handles,
        done: done_dead_client_handles,
    },
    El0Test {
        name: "killed_sender_lets_its_handles_go",
        start: start_killed_sender,
        done: done_killed_sender,
    },
    El0Test {
        name: "close_lets_a_labelled_sender_go",
        start: start_labelled_close,
        done: done_labelled_close,
    },
    El0Test {
        name: "fast_path_is_taken",
        start: start_fast_hit,
        done: done_fast_hit,
    },
    El0Test {
        name: "fast_path_leaves_the_slow_path_state",
        start: start_same_state,
        done: done_same_state,
    },
    El0Test {
        name: "fast_path_waits_for_the_cleanup",
        start: start_cleanup_first,
        done: done_cleanup_first,
    },
    El0Test {
        name: "fast_path_yields_to_an_equal_ready_level",
        start: start_equal_ready,
        done: done_equal_ready,
    },
    El0Test {
        name: "fast_path_skips_a_pending_interrupt",
        start: start_pending_interrupt,
        done: done_pending_interrupt,
    },
    El0Test {
        name: "fast_path_arms_the_timer",
        start: start_armed,
        done: done_armed,
    },
    El0Test {
        name: "quantum_ends_with_a_far_timer_set",
        start: start_far_timer,
        done: done_far_timer,
    },
    El0Test {
        name: "timer_latency_is_counted",
        start: start_timer_latency,
        done: done_timer_latency,
    },
    El0Test {
        name: "expired_timers_fire_in_batches",
        start: start_batches,
        done: done_batches,
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
    El0Test {
        name: "ipc_round_trip_is_measured",
        start: start_round_trips,
        done: done_round_trips,
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
    /// The test's alarm, a timer of a program on the channel the thread in
    /// slot 0 waits on (`alarm`); the teardown lets it go.
    alarm: Option<NonNull<Timer>>,
    /// CNTV_CVAL_EL0 when the first timer interrupt of the test came.
    fired_at: Option<u64>,
    /// Ticks asleep in `wfi` (sched::stats) when the test began.
    idle: u64,
    /// How far below the top of the kernel stack the idle wait began.
    idle_depth: Option<usize>,
    /// GICC_PMR in the idle wait.
    idle_mask: Option<u8>,
    /// Portions of cleanup since the test began, the one after which the
    /// alarm fires in the timer's interrupt and wakes the thread in slot 0,
    /// and how many portions apart more interrupts come (portion_done).
    portions: u32,
    interrupt_after: Option<u32>,
    interrupt_every: Option<u32>,
    /// Free frames and the pages of kernel pools together when the test
    /// began: the same once what the test made gave back what it took.
    memory: u64,
    /// Items in the cleanup queue when the first timer interrupt came.
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
    /// Timers the test holds besides its alarm; the teardown lets them go.
    timers: [Option<NonNull<Timer>>; BATCHED],
    /// Portions of the stage Close of a channel or of the stage Replies of
    /// a process since the test began, the most heads one took, and the
    /// levels they ran at, a bit each (`heads_taken`).
    taken: (u32, usize, u64),
    /// What the first two calls `svc #SVC_SNAP` noted, and how long after
    /// the first the test's alarm fires, if that call arms it.
    snaps: [Option<Snap>; 2],
    alarm_at_snap: Option<u64>,
    /// The thread that ran last when the first timer interrupt of the test
    /// came.
    interrupted: Option<NonNull<Thread>>,
}

/// The scheduler's state that `svc #SVC_SNAP` notes, right after the
/// caller's receive took a request (the fast path tests, spec 6.4).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Snap {
    /// Whether the caller runs, and the first ready thread of the top
    /// level.
    runs: bool,
    ready: Option<NonNull<Thread>>,
    /// The caller's effective priority and its x0-x10; x11, the token,
    /// grows from request to request.
    priority: u8,
    regs: [u64; 11],
    /// The states of the test's threads, in the order of their slots.
    states: [Option<State>; SLOTS],
    /// The end of the caller's quantum when it is round robin, the deadline
    /// the timer holds, and the counter at the call.
    slice_end: Option<u64>,
    armed: Option<u64>,
    now: u64,
    /// The top level of the cleanup queue, and the fast path's hits so far.
    cleanup: Option<u8>,
    hits: u64,
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
            alarm: None,
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
            timers: [None; BATCHED],
            taken: (0, 0, 0),
            snaps: [None; 2],
            alarm_at_snap: None,
            interrupted: None,
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

/// The fast path of send is off for the rest of the test (`svc #SVC_SLOW`).
static FAST_PATH_OFF: AtomicBool = AtomicBool::new(false);
/// Sends that took the fast path since the test began.
static FAST_PATH_HITS: AtomicU64 = AtomicU64::new(0);

/// Whether send takes its fast path, whose conditions hold
/// (testpoint::fast_path): not once a test turned it off; a hit counts.
pub fn fast_path() -> bool {
    if FAST_PATH_OFF.load(Relaxed) {
        return false;
    }
    FAST_PATH_HITS.fetch_add(1, Relaxed);
    true
}

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
/// threads and runs them. A test that cannot start fails, and the next one
/// starts. Each test finds the cleanup queue empty. After the last test the
/// pools hold no process, thread, channel, session or timer: the kernel's
/// references and the tests' own went.
fn start(first: usize) -> ! {
    for (i, test) in tests().enumerate().skip(first) {
        cleanup::drain();
        FAST_PATH_OFF.store(false, Relaxed);
        FAST_PATH_HITS.store(0, Relaxed);
        let started = {
            let mut f = FIXTURE.lock();
            *f = Fixture::new(i);
            (test.start)(&mut f).map(|()| f.threads)
        };
        match started {
            Ok(threads) => {
                for t in threads.into_iter().flatten() {
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
                && session::in_use() == 0
                && timers::in_use() == 0,
            "a process, a thread, a channel, a session or a timer of the EL0 tests stayed in its pool",
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

/// Drops what the test built. The kernel's timer stays the scheduler's:
/// the next decision arms it for the next test. A timer that goes leaves
/// the heap with its portion.
fn teardown() {
    let (handles, threads, crowd, alarm, timers, processes) = {
        let mut f = FIXTURE.lock();
        (
            core::mem::take(&mut f.handles),
            core::mem::take(&mut f.threads),
            core::mem::replace(&mut f.crowd, [None; CROWD]),
            f.alarm.take(),
            core::mem::replace(&mut f.timers, [None; BATCHED]),
            core::mem::take(&mut f.processes),
        )
    };
    for t in timers.into_iter().chain([alarm]).flatten() {
        // SAFETY: the test's reference goes, and nothing uses it afterwards.
        unsafe { timers::release(t, CAUSE) };
    }
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
        SVC_NOP => {}
        SVC_DONE => done(thread),
        SVC_SNAP => snap(thread),
        SVC_SLOW => FAST_PATH_OFF.store(true, Relaxed),
        SVC_RELEASE => release_crowd(thread),
        SVC_PENDING => {
            // The timer fires at once, and its interrupt is pending when
            // send looks.
            timer::arm(timer::now());
            while !arch::irq_pending() {}
            syscall::dispatch(thread, Call::Send.number());
            return true;
        }
        _ => return false,
    }
    syscall::set_result(thread, Ok(Values::NONE));
    true
}

/// `svc #SVC_SNAP` of `thread`: the scheduler's state goes into the next
/// free place of `Fixture::snaps`. The first call arms the test's alarm
/// `Fixture::alarm_at_snap` ticks later, when the test says so.
fn snap(thread: NonNull<Thread>) {
    let view = sched::view();
    let arm = {
        let mut f = FIXTURE.lock();
        // SAFETY: the running thread is alive, and so are the test's
        // threads, which it holds.
        let (t, states) = unsafe {
            let states = f.threads.map(|t| t.map(|t| t.as_ref().sched.state()));
            (thread.as_ref(), states)
        };
        let now = timer::now();
        let snap = Snap {
            runs: view.running == Some(thread),
            ready: view.ready,
            priority: t.priority(),
            regs: t.regs.x[..11].try_into().expect("x0-x10"),
            states,
            slice_end: view.slice_end,
            armed: view.armed,
            now,
            cleanup: cleanup::top(),
            hits: FAST_PATH_HITS.load(Relaxed),
        };
        let first = f.snaps[0].is_none();
        if let Some(free) = f.snaps.iter_mut().find(|s| s.is_none()) {
            *free = Some(snap);
        }
        let delay = f.alarm_at_snap.filter(|_| first);
        f.alarm.zip(delay).map(|(alarm, delay)| {
            f.kept[0] = now + delay;
            (alarm, now + delay)
        })
    };
    if let Some((alarm, at)) = arm {
        timers::set(alarm, at, CAUSE).expect("the alarm's channel is open");
    }
}

/// `svc #SVC_RELEASE` of `thread`: the test lets thread x0 of its crowd go
/// at level x1, as a call at that level would; the thread never started,
/// so its portion of cleanup waits in the queue at that level.
fn release_crowd(thread: NonNull<Thread>) {
    // SAFETY: the running thread is alive.
    let x = unsafe { thread.as_ref() }.regs.x;
    let t = FIXTURE.lock().crowd[x[0] as usize].take();
    if let Some(t) = t {
        // SAFETY: the test's reference goes, and nothing uses it afterwards.
        unsafe { thread::release(t, x[1] as u8) };
    }
}

/// The timer's interrupt, after the scheduler's part, which fired the
/// expired timers of programs (interrupt::handle). In the interrupt test
/// the thread waits for it in a loop, and the kernel moves the thread past
/// the loop; one that comes before the thread reaches the loop leaves it
/// be, and the next quantum brings another. The first interrupt of a test
/// leaves its compare value and the length of the cleanup queue for the
/// judges, and ends the process of `exit_at_interrupt`.
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
    let mut f = FIXTURE.lock();
    f.interrupts += 1;
    if f.interrupts == 1 {
        f.interrupted = thread::current();
    }
    if let Some(mut thread) = thread::current() {
        // SAFETY: the thread is alive, and nothing else refers to it now.
        let regs = unsafe { &mut thread.as_mut().regs };
        if regs.elr == user_address(&raw const el0_wait_loop) as u64 {
            regs.elr += 4;
            f.left_loop = true;
        }
    }
    if f.fired_at.is_none() {
        f.fired_at = Some(timer::cval());
        f.queued_at_wake = Some(cleanup::len());
    }
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
/// portion `interrupt_after` fires the test's alarm in timer_set, which
/// wakes the thread in slot 0, then arms the kernel's timer for now and
/// waits until its interrupt is pending, so the way out of the kernel
/// finds it at the next poll. Every `interrupt_every` portions another
/// interrupt comes the same way, with no alarm.
pub fn portion_done() {
    let (alarm, now) = {
        let mut f = FIXTURE.lock();
        f.portions += 1;
        let first = f.interrupt_after == Some(f.portions);
        let again = f
            .interrupt_every
            .is_some_and(|n| f.portions.is_multiple_of(n));
        if !first && !again {
            return;
        }
        if first {
            f.interrupt_after = None;
        }
        (f.alarm.filter(|_| first), timer::now())
    };
    if let Some(t) = alarm {
        // A deadline that passed fires in the call (spec 10).
        timers::set(t, 0, CAUSE).expect("the alarm's channel is open");
    }
    timer::arm(now);
    while !arch::irq_pending() {}
}

/// After a portion of the stage Close or Replies (testpoint::heads_taken):
/// the test counts it, with the most heads one took and the level it ran
/// at.
pub fn heads_taken(level: u8, heads: usize) {
    let mut f = FIXTURE.lock();
    let (portions, most, levels) = f.taken;
    f.taken = (portions + 1, most.max(heads), levels | 1 << level);
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

/// The test's alarm (spec 10): a channel of `p`, which a handle of `p`
/// with RECEIVE holds, and a timer on it at PRIORITY that `p` pays for,
/// armed for the counter value `at` when there is one. Returns the
/// handle's value, for the thread that waits on the channel.
fn alarm(f: &mut Fixture, p: NonNull<Process>, at: Option<u64>) -> Result<u64, &'static str> {
    let c = channel::create(p, PRIORITY).map_err(|_| "no channel")?;
    let h = give(p, Object::Channel(c), Rights::RECEIVE);
    let t = timers::create(p, c, 0, PRIORITY);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the channel, and so does the timer.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    let t = t.map_err(|_| "no timer")?;
    f.alarm = Some(t);
    if let Some(at) = at {
        timers::set(t, at, CAUSE).map_err(|_| "the alarm did not arm")?;
    }
    h
}

/// x1-x11 of a receive that took one expiry of a timer made through a
/// handle with no label.
fn timer_notice() -> [u64; 11] {
    Notification {
        source: Source::Timer,
        label: 0,
        bits: 1,
        count: 1,
    }
    .to_words()
}

/// The thread in slot 0 fills its registers from a pattern and waits in
/// receive on the test's alarm, armed 1 ms from now; nothing else is ready
/// meanwhile, so the kernel idles until the alarm's interrupt.
fn start_idle(f: &mut Fixture) -> Result<(), &'static str> {
    let p = new_process(f, 0)?;
    f.counter = timer::clock().deadline_after(timer::now(), 1_000_000);
    let h = alarm(f, p, Some(f.counter))?;
    call_pattern(f, &[h, 0]);
    new_thread(
        f,
        0,
        p,
        DATA_VA,
        &raw const el0_pattern_receive,
        DATA_VA as u64,
    )?;
    f.idle = sched::stats().idle;
    sched::reset_latencies();
    Ok(())
}

fn done_idle(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(
        f.fired_at == Some(f.counter),
        "the idle kernel did not arm the timer for the alarm",
    )?;
    check(
        t.regs.x[0] == 0 && t.regs.x[1..12] == timer_notice(),
        "the thread did not wake with the alarm's notification",
    )?;
    check(
        timer::now() >= f.counter,
        "the judge ran before the alarm's deadline",
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

/// A wait in receive through the idle kernel changes x0-x11 alone (spec
/// 11): x0 0 and the alarm's notification in x1-x11, and every other
/// register, FP and SIMD ones too, as the pattern left it.
fn done_wait_in_idle(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let mut results = [0; 12];
    results[1..].copy_from_slice(&timer_notice());
    check_pattern(&t.regs, &f.patterns[0], &results)
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
/// An entry no page of a test's child maps: a thread there faults at once.
const CHILD_ENTRY: u64 = 0x1000;
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

/// A program, the maker in slot 0, makes a thread below itself in its own
/// process, starts it and keeps its handle. The thread runs once the
/// program is done, finds its message buffer zeroed and writable, and
/// exits: its buffer's page goes at its exit, and it stays as a shell,
/// which the handle keeps. The judge in slot 1 closes the handle
/// afterwards: a process's handle to its own thread keeps both until the
/// process ends.
fn start_keep_started(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let maker = sched_thread(f, 0, &raw const el0_create_and_start, PRIORITY, FIFO)?;
    sched_thread(f, 1, &raw const el0_done_at_once, JUDGE, FIFO)?;
    let own = give_own(f)?;
    let entry = user_address(&raw const el0_buffer_mark) as u64;
    let stack = (DATA_VA + PAGE) as u64;
    let buffer = BUFFER_VA as u64;
    let priority = u64::from(PRIORITY - 2);
    let fifo = FIFO as u64;
    set_args(maker, &[own, entry, stack, buffer, priority, fifo, buffer]);
    Ok(())
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
// comes (portion_done) and fires the test's alarm, which wakes the thread
// in slot 0 above the killer from its receive; the judge in slot 2 is
// below both.

/// The cleanup tests' threads and child.
fn start_cleanup(f: &mut Fixture) -> Result<(), &'static str> {
    killer_and_child(f, child_with_threads)
}

/// The threads of a test that kills the child `make` makes: the thread in
/// slot 0 that waits for the alarm, the killer in slot 1 with a handle to
/// the child, the judge in slot 2. The interrupt comes after
/// INTERRUPT_AFTER portions.
fn killer_and_child(
    f: &mut Fixture,
    make: fn() -> Result<NonNull<Process>, &'static str>,
) -> Result<(), &'static str> {
    sched_process(f)?;
    waiting_for_the_alarm(f)?;
    let killer = sched_thread(f, 1, &raw const el0_kill, PRIORITY, FIFO)?;
    sched_thread(f, 2, &raw const el0_done_at_once, JUDGE, FIFO)?;
    f.memory = phys::free_frames() + pages::taken() as u64;
    let child = make()?;
    let h = give_kept(f, Object::Process(child));
    // SAFETY: the test's reference goes; the handle, if it went in, holds
    // the child.
    unsafe { process::release(child, CAUSE) };
    set_args(killer, &[h?]);
    f.interrupt_after = Some(INTERRUPT_AFTER);
    cleanup::take_late();
    Ok(())
}

/// The thread in slot 0 of the test's process, above the others, which
/// waits in receive for the test's alarm, not armed yet.
fn waiting_for_the_alarm(f: &mut Fixture) -> Result<(), &'static str> {
    let p = f.processes[0].expect("the test's process");
    let h = alarm(f, p, None)?;
    let waiter = sched_thread(f, 0, &raw const el0_receive, PRIORITY + 10, FIFO)?;
    set_args(waiter, &[h, 0]);
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

/// The thread that waits for the alarm in slot 0 and the judge in slot 2,
/// as for the kill; in slot 1 the child with the programs and
/// CHILD_THREADS stopped threads, and its thread that starts at `entry`
/// and ends it.
fn child_ends_itself(f: &mut Fixture, entry: usize) -> Result<(), &'static str> {
    sched_process(f)?;
    waiting_for_the_alarm(f)?;
    sched_thread(f, 2, &raw const el0_done_at_once, JUDGE, FIFO)?;
    let child = new_process(f, 1)?;
    give_threads(child)?;
    let t = thread::create(child, entry, DATA_VA + PAGE, 0, PRIORITY, FIFO)
        .map_err(|_| "no thread in the child")?;
    f.threads[1] = Some(t);
    f.ends[1] = true;
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
/// judge in slot 0 wakes above it three quanta after the start, at its
/// alarm, and by then the teardown of both went to its end at the level of
/// the cause, and the exit notification of C, which its parent's channel
/// hears of at that level (spec 7.9), waits for the judge's receive.
fn start_descendants(f: &mut Fixture) -> Result<(), &'static str> {
    let judge = spawn(f, 0, &raw const el0_alarm_then, 0)?;
    sched::set_priority(judge, PRIORITY + 10, FIFO).map_err(|_| "no judge")?;
    let parent = f.processes[0].expect("the judge's process");
    let quanta = 3 * abi::RR_QUANTUM_NS;
    let wake = timer::clock().deadline_after(timer::now(), quanta);
    let a = alarm(f, parent, Some(wake))?;
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
    let receive = user_address(&raw const el0_receive) as u64;
    set_args(judge, &[a, 0, receive, h?, NO_WAIT]);
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
    check(t.regs.x[23] == 0, "the judge did not wake at its alarm")?;
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

/// The killer in slot 0, woken by its alarm 1 ms after the start, kills
/// its child C; C's child, the grandchild in slot 1, has a thread below
/// the killer that counts meanwhile. The end of C ends the grandchild and
/// stops its thread (spec 4), and the teardown of both runs at the
/// killer's level, before the kill returns. Each child's quota comes off
/// its parent's.
fn start_grandchild(f: &mut Fixture) -> Result<(), &'static str> {
    let killer = spawn(f, 0, &raw const el0_alarm_then, 0)?;
    let killers = f.processes[0].expect("the killer's process");
    let wake = timer::clock().deadline_after(timer::now(), 1_000_000);
    let a = alarm(f, killers, Some(wake))?;
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
    let kill = user_address(&raw const el0_kill) as u64;
    set_args(killer, &[a, 0, kill, h?]);
    f.ends[1] = true;
    Ok(())
}

fn done_grandchild(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(
        t.regs.x[23] == 0 && t.regs.x[0] == 0,
        "the killer's alarm or process_kill failed",
    )?;
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
/// (spec 6.8): the stage Close wakes the waiters with PEER_CLOSED, 32 a
/// portion, in four portions at their level, above the closer's (spec
/// 7.7); an interrupt comes after every portion, and none begins while one
/// is pending. The judge below the closer finds every waiter ended with
/// PEER_CLOSED.
fn start_close_portions(f: &mut Fixture) -> Result<(), &'static str> {
    let n = MAX_THREADS as usize;
    close_crowd(f, [(PRIORITY, n), (PRIORITY, n)])
}

/// The closer in slot 0 and the judge in slot 1, below it, of a process of
/// their own, and a channel the crowd waits in: a process in slot 1 and
/// one in slot 2 with a handle with RECEIVE each, and threads of the level
/// and number `crowds` gives for each. An interrupt comes after every
/// portion.
fn close_crowd(f: &mut Fixture, crowds: [(u8, usize); 2]) -> Result<(), &'static str> {
    let own = new_process(f, 0)?;
    let entry = user_address(&raw const el0_done_at_once);
    for (slot, priority) in [(0, JUDGE), (1, JUDGE - 1)] {
        let t = thread::create(own, entry, 0, 0, priority, FIFO).map_err(|_| "no thread")?;
        f.threads[slot] = Some(t);
    }
    let c = channel::create(own, PRIORITY).map_err(|_| "no channel")?;
    let made = (1..=2).try_for_each(|slot| {
        let (priority, n) = crowds[slot - 1];
        crowd_of(f, slot, c, Rights::RECEIVE, priority, n)
    });
    // SAFETY: the reference `create` handed out goes; the handles that went
    // in hold the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    made?;
    cleanup::take_late();
    f.interrupt_every = Some(1);
    Ok(())
}

/// A process in slot `slot` with a handle with `rights` to `c`, which the
/// test keeps, and `n` threads of it at `priority`, started, in the crowd
/// after those there: with RECEIVE they wait in receive on the channel,
/// with SEND they send a request of REQUEST_LEN bytes through it; they
/// exit once the call comes back.
fn crowd_of(
    f: &mut Fixture,
    slot: usize,
    c: NonNull<Channel>,
    rights: Rights,
    priority: u8,
    n: usize,
) -> Result<(), &'static str> {
    let p = new_process(f, slot)?;
    let h = process::insert_handle(p, Object::Channel(c), rights)
        .map_err(|_| "a handle did not go in")?;
    f.handles[slot - 1] = Some((p, h));
    let (entry, args) = if rights.contains(Rights::RECEIVE) {
        (&raw const el0_receive_then_exit, [h.0, 0, 0])
    } else {
        (
            &raw const el0_send_then_exit,
            [h.0, REQUEST_LEN, REQUEST_WORD],
        )
    };
    let first = f.crowd.iter().position(Option::is_none).unwrap_or(CROWD);
    for i in first..first + n {
        let t = thread::create(p, user_address(entry), 0, 0, priority, FIFO)
            .map_err(|_| "no thread")?;
        set_args(t, &args);
        f.crowd[i] = Some(t);
        thread::start(t).map_err(|_| "a thread did not start")?;
    }
    Ok(())
}

fn done_close_portions(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    closed_crowd(f, t, (4, 32, 1 << PRIORITY))
}

/// The closer in slot 0 closes the crowd's handles, the last ones with
/// RECEIVE; the judge in slot 1 finds every thread of the crowd ended with
/// PEER_CLOSED, `taken` as the portions of the stage Close, and an
/// interrupt after each of them.
fn closed_crowd(f: &Fixture, t: &Thread, taken: (u32, usize, u64)) -> Result<(), &'static str> {
    closed_crowd_at(f, t, JUDGE, taken)
}

/// `closed_crowd` with the handles closed as a thread at `cause` would.
fn closed_crowd_at(
    f: &Fixture,
    t: &Thread,
    cause: u8,
    taken: (u32, usize, u64),
) -> Result<(), &'static str> {
    // SAFETY: the test holds a reference to each thread of the crowd.
    let crowd = || f.crowd.iter().flatten().map(|w| unsafe { w.as_ref() });
    if f.slot(t) == 0 {
        let waiting = crowd().all(|w| w.sched.state() == State::Waiting);
        for &(p, h) in f.handles.iter().flatten() {
            process::close_handle(p, h, cause).map_err(|_| "a handle did not close")?;
        }
        return check(waiting, "a thread of the crowd did not wait");
    }
    check(
        crowd().all(|w| w.sched.state() == State::Dead && w.regs.x[0] == Error::PeerClosed.code()),
        "a thread that waited did not end with PEER_CLOSED",
    )?;
    check(
        f.taken == taken,
        "the stage Close did not wake the waiters 32 of one level a portion at the level expected",
    )?;
    check(
        !cleanup::take_late() && f.interrupts >= taken.0,
        "a portion began while an interrupt was pending",
    )
}

// Timers of programs (spec 10): the kernel's timer serves the nearer of
// the end of a quantum and the earliest timer of a program, and its
// interrupt fires the timers that expired.

/// A round-robin thread alone at its level spins for three quanta while a
/// timer of a program is armed a second away: the kernel's timer serves
/// the end of the quantum, the nearer deadline (spec 8), so a quantum ends
/// on the way; the timer stays armed. The FIFO thread below never runs
/// meanwhile.
fn start_far_timer(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let spin = sched_thread(f, 0, &raw const el0_spin_then_yield, PRIORITY, RR)?;
    let low = sched_thread(f, 1, &raw const el0_mark, PRIORITY - 5, FIFO)?;
    set_args(spin, &[word(0), 3 * quantum()]);
    set_args(low, &[word(0)]);
    let p = f.processes[0].expect("the test's process");
    f.counter = timer::clock().deadline_after(timer::now(), 1_000_000_000);
    alarm(f, p, Some(f.counter))?;
    Ok(())
}

fn done_far_timer(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    if f.slot(t) != 0 {
        return Ok(());
    }
    check(
        f.interrupts >= 1,
        "no quantum ended while a far timer was armed",
    )?;
    check(
        t.regs.x[3] == 0,
        "the end of a quantum let a lower thread run",
    )?;
    check(
        f.alarm.and_then(timers::deadline) == Some(f.counter),
        "the far timer did not stay armed",
    )
}

/// A thread waits in receive for the test's alarm, 1 ms from the start,
/// while a round-robin thread below it spins at EL0 for 2 ms, within its
/// quantum: the kernel's timer serves the alarm, the nearer deadline
/// (spec 8), and its interrupt comes while a program runs. The thread it
/// wakes runs before the spinner ends, and the time from the alarm's
/// deadline to it counts, from nothing at the start, as the latency of an
/// interrupt outside idle (spec 16).
fn start_timer_latency(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let spin = sched_thread(f, 1, &raw const el0_spin_then_yield, PRIORITY, RR)?;
    let clock = timer::clock();
    set_args(spin, &[word(0), clock.ns_to_ticks(2_000_000)]);
    let p = f.processes[0].expect("the test's process");
    let at = clock.deadline_after(timer::now(), 1_000_000);
    let h = alarm(f, p, Some(at))?;
    let waiter = sched_thread(f, 0, &raw const el0_receive, PRIORITY + 10, FIFO)?;
    set_args(waiter, &[h, 0]);
    sched::reset_latencies();
    Ok(())
}

fn done_timer_latency(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    if f.slot(t) != 0 {
        return Ok(());
    }
    check(
        t.regs.x[0] == 0 && t.regs.x[1..12] == timer_notice(),
        "the thread did not wake with the alarm's notification",
    )?;
    check(!f.passed[1], "the alarm waited for the round-robin spinner")?;
    check(
        sched::stats().irq_latency > 0,
        "the latency from a timer of a program to the thread it woke was not counted",
    )
}

/// BATCHED timers of programs on one channel, which two processes pay for,
/// all for one deadline 1 ms from the start, while a FIFO thread in slot 1
/// spins at EL0 for 2 ms. The first interrupt fires timers::BATCH of them
/// and ends the process in slot 0 at the spinner's level, whose teardown
/// comes before the spinner (spec 7.7); the rest waits in the heap, and the
/// next decision arms the kernel's timer for the deadline already past, so
/// the second interrupt fires the rest before any portion of that
/// teardown begins (spec 10). The judge in slot 2 finds every timer's slot
/// queued in the channel, two interrupts, no portion begun with one
/// pending, and the batch measured for KSTATS.
fn start_batches(f: &mut Fixture) -> Result<(), &'static str> {
    let victim = new_process(f, 0)?;
    let own = new_process(f, 1)?;
    let spin = new_thread(
        f,
        1,
        own,
        DATA_VA,
        &raw const el0_spin_then_yield,
        DATA_VA as u64,
    )?;
    set_args(
        spin,
        &[DATA_VA as u64, timer::clock().ns_to_ticks(2_000_000)],
    );
    judge(f, 2)?;
    let payers = [own, f.processes[2].expect("the judge's process")];
    let c = channel::create(own, PRIORITY).map_err(|_| "no channel")?;
    let h = give(own, Object::Channel(c), Rights::RECEIVE);
    let made = (0..BATCHED).try_for_each(|i| {
        f.timers[i] = Some(timers::create(payers[i % 2], c, 0, PRIORITY)?);
        Ok(())
    });
    // The deadline comes once every timer is made, so that it is still
    // ahead when the last one is armed.
    let at = timer::clock().deadline_after(timer::now(), 1_000_000);
    let made = made.and_then(|()| {
        f.timers
            .iter()
            .flatten()
            .try_for_each(|&t| timers::set(t, at, CAUSE))
    });
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the channel, and so do the timers.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    h?;
    made.map_err(|_| "a timer was not made or armed")?;
    f.exit_at_interrupt = Some((victim, PRIORITY));
    cleanup::take_late();
    timers::reset_longest_batch();
    Ok(())
}

fn done_batches(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    if f.slot(t) != 2 {
        return Ok(());
    }
    check(
        f.timers.iter().flatten().all(|&t| timers::posted(t)),
        "an expired timer did not post into its slot",
    )?;
    check(
        f.interrupts == 2,
        "the expired timers did not take two interrupts, a batch and the rest",
    )?;
    check(
        !cleanup::take_late(),
        "a portion began while the rest of the timers waited for their interrupt",
    )?;
    check(
        timers::longest_batch() > 0,
        "the batch of expired timers was not measured",
    )
}

// Requests (spec 6.1, 6.6): a client and a service in processes of their
// own.

/// The label of the session of `request_through_the_start_channel`.
const REQUEST_LABEL: u64 = 0x1ABE1;
/// The description of the tests' requests: 8 bytes, no handles.
const REQUEST_LEN: u64 = 8;
/// Those 8 bytes, in x2.
const REQUEST_WORD: u64 = 0x5EED_C11E;
/// A count the tests move a client's count to, so that they know its next
/// token ahead: above any count the tests reach otherwise.
const TOKEN_COUNT: u64 = 1 << 40;
/// The ceiling of the service's process in `boost_is_capped_by_the_server_ceiling`.
const SERVICE_CEILING: u8 = 20;

/// Spec 15.2 (messages): a child sends a request through its start
/// channel, a copy of the parent's channel with a label and SEND that
/// process_create moved into entry 0 (spec 13.3). The parent's service,
/// which waits in receive, takes it with the label, the description, the
/// data and a token, and answers; the child gets its request back.
fn start_start_request(f: &mut Fixture) -> Result<(), &'static str> {
    let parent = new_process(f, 1)?;
    let server = new_thread(f, 1, parent, DATA_VA, &raw const el0_serve, 0)?;
    sched::set_priority(server, PRIORITY + 1, FIFO).map_err(|_| "no service")?;
    let c = channel::create(parent, PRIORITY).map_err(|_| "no channel")?;
    let h = give(parent, Object::Channel(c), Rights::RECEIVE);
    let s = session::create(parent, c, REQUEST_LABEL, PRIORITY);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the channel, and so does the session.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    let s = s.map_err(|_| "no session")?;
    let child = process::create_child(parent, CHILD_QUOTA, HANDLE_LIMIT, CEILING);
    let moved =
        child.and_then(|child| process::move_start(child, Object::Session(s), Rights::SEND));
    // SAFETY: the reference `create` handed out goes; entry 0 of the
    // child, if the move went, holds the session.
    unsafe { session::unref(s, CAUSE) };
    let child = child.map_err(|_| "no child")?;
    let child = with_programs(f, 0, child)?;
    let client = new_thread(f, 0, child, DATA_VA, &raw const el0_send, 0)?;
    moved.map_err(|_| "the start channel did not move")?;
    set_args(client, &[START_CHANNEL.0, REQUEST_LEN, REQUEST_WORD]);
    set_args(server, &[h?, 0]);
    Ok(())
}

fn done_start_request(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    if f.slot(t) == 0 {
        return check(
            x[..3] == [0, REQUEST_LEN, REQUEST_WORD] && x[3..10].iter().all(|&w| w == 0),
            "the child did not get its request back",
        );
    }
    check(
        x[0] == 0
            && x[19..21] == [REQUEST_LEN, REQUEST_WORD]
            && x[28] == REQUEST_LABEL
            && x[29] != 0,
        "the parent did not take the child's request with its label and a token",
    )
}

/// A token names a request for the process that accepted it (spec 6.1): a
/// service takes a request of a client of another process and holds it
/// until a notification comes; meanwhile a thread of a third process
/// replies with the service's token, which the test knows ahead: BAD_STATE,
/// and the client does not wake. It notifies the service, which answers;
/// the client gets its request back.
fn start_foreign_reply(f: &mut Fixture) -> Result<(), &'static str> {
    let server = spawn(f, 0, &raw const el0_serve_after_notice, 0)?;
    let client = spawn(f, 1, &raw const el0_send, 0)?;
    let other = spawn(f, 2, &raw const el0_reply_then_notify, 0)?;
    for (t, priority) in [(server, 3), (client, 2), (other, 1)] {
        sched::set_priority(t, PRIORITY + priority, FIFO).map_err(|_| "no priority")?;
    }
    let [p, q, r] = [0, 1, 2].map(|i| f.processes[i].expect("a process of the test"));
    let c = channel::create(p, PRIORITY).map_err(|_| "no channel")?;
    let d = channel::create(p, PRIORITY);
    let handles = d.map(|d| {
        [
            give(p, Object::Channel(c), Rights::RECEIVE),
            give(p, Object::Channel(d), Rights::RECEIVE),
            give(q, Object::Channel(c), Rights::SEND),
            give(r, Object::Channel(d), Rights::NOTIFY),
        ]
    });
    // SAFETY: the references `create` handed out go; the handles that went
    // in hold the channels.
    unsafe {
        channel::release(c, Rights::NONE, CAUSE);
        if let Ok(d) = d {
            channel::release(d, Rights::NONE, CAUSE);
        }
    }
    let [requests, notices, send, notify] = handles.map_err(|_| "no channel")?;
    let index = thread::index(client);
    sched::locked(|k| k.tokens.skip_to(index, TOKEN_COUNT));
    let token = (TOKEN_COUNT + 1) << 16 | u64::from(index);
    set_args(server, &[requests?, 0, notices?]);
    set_args(client, &[send?, REQUEST_LEN, REQUEST_WORD]);
    set_args(other, &[token, 0, notify?, BITS]);
    f.kept = [token, 0];
    Ok(())
}

fn done_foreign_reply(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    match f.slot(t) {
        0 => check(
            x[0] == 0 && x[19..21] == [REQUEST_LEN, REQUEST_WORD] && x[28..30] == [0, f.kept[0]],
            "the service did not take the request with the token the test knew, or its reply failed",
        ),
        1 => check(
            x[..3] == [0, REQUEST_LEN, REQUEST_WORD],
            "the client did not get the service's reply",
        ),
        _ => check(
            x[19] == Error::BadState.code() && x[0] == 0,
            "a thread of another process answered the request",
        ),
    }
}

/// The boost by a client stops at the ceiling of the service's process
/// (spec 6.6, 8): a service at base 10 in a process with ceiling 20 waits
/// in receive; a client of another process raises itself to 30, a ready
/// thread of a third process to 25, and sends. The service works at 20,
/// so the thread at 25 ends while the client still waits for the reply;
/// at 30 the service would answer first.
fn start_capped_boost(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process_under(f, SERVICE_CEILING)?;
    let server = sched_thread(f, 0, &raw const el0_serve, PRIORITY, FIFO)?;
    let client = spawn(f, 1, &raw const el0_raise_then_send, 0)?;
    let ready = spawn(f, 2, &raw const el0_done_at_once, 0)?;
    for (t, priority) in [(client, PRIORITY - 5), (ready, 1)] {
        sched::set_priority(t, priority, FIFO).map_err(|_| "no priority")?;
    }
    let [p, q] = [0, 1].map(|i| f.processes[i].expect("a process of the test"));
    let c = channel::create(p, PRIORITY).map_err(|_| "no channel")?;
    let handles = [
        give(p, Object::Channel(c), Rights::RECEIVE),
        give(q, Object::Channel(c), Rights::SEND),
        give(q, Object::Thread(ready), Rights::MANAGE),
    ];
    // SAFETY: the reference `create` handed out goes; the handles that went
    // in hold the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    let [receive, send, raised] = handles;
    // A handle to the client's own thread in its process: the teardown
    // closes it first.
    let own = process::insert_handle(q, Object::Thread(client), Rights::MANAGE)
        .map_err(|_| "a handle did not go in")?;
    f.handles[0] = Some((q, own));
    set_args(server, &[receive?, 0]);
    set_args(client, &[own.0, 30, raised?, 25, send?]);
    Ok(())
}

fn done_capped_boost(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    match f.slot(t) {
        0 => check(x[0] == 0, "the service's reply failed"),
        1 => check(
            x[19] == 0 && x[20] == 0 && x[0] == 0,
            "thread_set_priority or send failed",
        ),
        _ => check(
            slot_thread(f, 1).sched.state() == State::Waiting,
            "the service answered before the ready thread above its ceiling ran",
        ),
    }
}

// The departure of a side (spec 6.8, 7.7): the stage Replies of a service
// that ends wakes the clients of the requests it took with PEER_CLOSED, at
// the level of the top one; a client that ends leaves the queue its
// request stands in at once, and a reply to it is PEER_CLOSED; the stage
// Close takes heads of one level a portion, at the level of the top
// waiter.

/// A channel that `p` pays for, with a handle with `rights` in its table:
/// the handle's value.
fn own_channel(p: NonNull<Process>, rights: Rights) -> Result<u64, &'static str> {
    let c = channel::create(p, PRIORITY).map_err(|_| "no channel")?;
    let h = give(p, Object::Channel(c), rights);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    h
}

/// A channel that `p` pays for, with a handle with `mine` in `p`'s table
/// and one with `theirs` in `q`'s: the values of the two handles.
fn shared_channel(
    p: NonNull<Process>,
    mine: Rights,
    q: NonNull<Process>,
    theirs: Rights,
) -> Result<[u64; 2], &'static str> {
    let c = channel::create(p, PRIORITY).map_err(|_| "no channel")?;
    let handles = [
        give(p, Object::Channel(c), mine),
        give(q, Object::Channel(c), theirs),
    ];
    // SAFETY: the reference `create` handed out goes; the handles that went
    // in hold the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    let [a, b] = handles;
    Ok([a?, b?])
}

/// The exit of `p` goes as a notification with EXIT_LABEL at PRIORITY into
/// a new channel of `q` (spec 7.9): the value of the handle with RECEIVE
/// to it in `q`'s table.
fn exit_channel_of(q: NonNull<Process>, p: NonNull<Process>) -> Result<u64, &'static str> {
    let c = channel::create(q, PRIORITY).map_err(|_| "no channel")?;
    let h = give(q, Object::Channel(c), Rights::RECEIVE);
    let source = channel::add_source(c);
    if source.is_ok() {
        process::set_exit(p, c, EXIT_LABEL, PRIORITY);
    }
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the channel, and so does the exit of `p`.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    source.map_err(|_| "no slot for the exit")?;
    h
}

/// Spec 15.2 (refusals): a service takes the request of a client of
/// another process and ends its process without a reply (spec 6.8): the
/// stage Replies of the teardown wakes the client with PEER_CLOSED in x0
/// alone, before the judge below both runs.
fn start_dead_server(f: &mut Fixture) -> Result<(), &'static str> {
    let server = spawn(f, 0, &raw const el0_take_then_exit, 0)?;
    let client = spawn(f, 1, &raw const el0_send, 0)?;
    sched::set_priority(server, PRIORITY + 1, FIFO).map_err(|_| "no priority")?;
    judge(f, 2)?;
    let [p, q] = [0, 1].map(|i| f.processes[i].expect("a process of the test"));
    let [requests, send] = shared_channel(p, Rights::RECEIVE, q, Rights::SEND)?;
    set_args(server, &[requests, 1]);
    set_args(client, &[send, REQUEST_LEN, REQUEST_WORD]);
    f.ends[0] = true;
    Ok(())
}

fn done_dead_server(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    match f.slot(t) {
        1 => check(
            t.regs.x[..3] == [Error::PeerClosed.code(), REQUEST_LEN, REQUEST_WORD]
                && state(f, 0) == ProcessState::Exited { code: 0 },
            "the client of the service that ended did not get PEER_CLOSED in x0 alone",
        ),
        2 => check(
            f.passed[1],
            "the client of the service that ended still waits",
        ),
        _ => Err("the service came back from process_exit"),
    }
}

/// A service takes the requests of two processes of clients, 127 of them,
/// and ends its process without a reply: the stage Replies wakes them with
/// PEER_CLOSED, 32 a portion, in four portions at the service's level
/// (spec 6.8, 7.7); an interrupt comes after every portion, and none
/// begins while one is pending. The judge below, the last thread of the
/// second process, finds every client ended with PEER_CLOSED.
fn start_replies_portions(f: &mut Fixture) -> Result<(), &'static str> {
    let server = spawn(f, 0, &raw const el0_take_then_exit, 0)?;
    sched::set_priority(server, PRIORITY + 1, FIFO).map_err(|_| "no priority")?;
    let p = f.processes[0].expect("the service's process");
    let c = channel::create(p, PRIORITY).map_err(|_| "no channel")?;
    let requests = give(p, Object::Channel(c), Rights::RECEIVE);
    let n = MAX_THREADS as usize;
    let made = [(1, n), (2, n - 1)]
        .into_iter()
        .try_for_each(|(slot, n)| crowd_of(f, slot, c, Rights::SEND, PRIORITY, n));
    // SAFETY: the reference `create` handed out goes; the handles that went
    // in hold the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    made?;
    let q = f.processes[2].expect("the second process of clients");
    let entry = user_address(&raw const el0_done_at_once);
    let judge = thread::create(q, entry, 0, 0, JUDGE, FIFO).map_err(|_| "no judge")?;
    f.threads[1] = Some(judge);
    set_args(server, &[requests?, CROWD as u64 - 1]);
    f.ends[0] = true;
    cleanup::take_late();
    f.interrupt_every = Some(1);
    Ok(())
}

fn done_replies_portions(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(f.slot(t) == 1, "the service came back from process_exit")?;
    // SAFETY: the test holds a reference to each thread of the crowd.
    let mut crowd = f.crowd.iter().flatten().map(|w| unsafe { w.as_ref() });
    check(
        crowd.all(|w| w.sched.state() == State::Dead && w.regs.x[0] == Error::PeerClosed.code()),
        "a client of the service that ended did not end with PEER_CLOSED",
    )?;
    check(
        f.taken == (4, 32, 1 << (PRIORITY + 1)),
        "the stage Replies did not wake the clients 32 a portion at the service's level",
    )?;
    check(
        !cleanup::take_late() && f.interrupts >= 4,
        "a portion began while an interrupt was pending",
    )
}

/// The stage Replies runs at the level of its top client (spec 7.7), and
/// a client that moved in the queue of accepted requests wakes at its new
/// level (spec 6.3): a service at 13 takes the requests of two clients at
/// 12 and waits in receive on a channel where nothing comes. A killer at 5
/// raises one client to 40 and ends the service's process: the stage
/// Replies wakes the raised client at 40, then the other at 12, a portion
/// each.
fn start_replies_level(f: &mut Fixture) -> Result<(), &'static str> {
    let server = spawn(f, 0, &raw const el0_take_then_wait, 0)?;
    let client = spawn(f, 1, &raw const el0_send, 0)?;
    let killer = spawn(f, 2, &raw const el0_raise_then_kill, 0)?;
    for (t, priority) in [(server, 13), (client, 12), (killer, JUDGE)] {
        sched::set_priority(t, priority, FIFO).map_err(|_| "no priority")?;
    }
    let [p, q, r] = [0, 1, 2].map(|i| f.processes[i].expect("a process of the test"));
    let [requests, send] = shared_channel(p, Rights::RECEIVE, q, Rights::SEND)?;
    let nothing = own_channel(p, Rights::RECEIVE)?;
    let entry = user_address(&raw const el0_send_then_exit);
    let raised = thread::create(q, entry, 0, 0, 12, FIFO).map_err(|_| "no thread")?;
    set_args(raised, &[send, REQUEST_LEN, REQUEST_WORD]);
    let handles = [
        give(r, Object::Thread(raised), Rights::MANAGE),
        give(r, Object::Process(p), Rights::MANAGE),
    ];
    let started = thread::start(raised);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the thread, and the kernel's holds it once started.
    unsafe { thread::release(raised, CAUSE) };
    started.map_err(|_| "the raised client did not start")?;
    let [raise, target] = handles;
    set_args(server, &[requests, 2, nothing]);
    set_args(client, &[send, REQUEST_LEN, REQUEST_WORD]);
    set_args(killer, &[raise?, 40, target?]);
    f.ends[0] = true;
    Ok(())
}

fn done_replies_level(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    match f.slot(t) {
        1 => check(
            x[..3] == [Error::PeerClosed.code(), REQUEST_LEN, REQUEST_WORD]
                && f.taken == (2, 1, 1 << 40 | 1 << 12),
            "the stage Replies did not wake the raised client at 40 and then the other at 12",
        ),
        2 => check(
            x[19] == 0 && x[0] == 0,
            "thread_set_priority or process_kill failed",
        ),
        _ => Err("the service came back from its receive"),
    }
}

/// A reply to a client that ended while it waited for it is PEER_CLOSED,
/// and still ends the boost by that client (spec 6.6, 6.8): a service at
/// 10 takes the request of a client at 30 and works at 30; it wakes a
/// killer at 40, which ends the client's process. The service answers
/// twice: PEER_CLOSED both times, since the reply leaves the mark of the
/// dead client (Table::mark_dead), and it works at 10 again.
fn start_dead_client(f: &mut Fixture) -> Result<(), &'static str> {
    dead_client(f, 0)
}

/// The threads of `reply_to_a_dead_client_is_peer_closed`, whose service
/// answers with the description `reply`.
fn dead_client(f: &mut Fixture, reply: u64) -> Result<(), &'static str> {
    let server = spawn(f, 0, &raw const el0_take_notify_reply, 0)?;
    let client = spawn(f, 1, &raw const el0_send, 0)?;
    let killer = spawn(f, 2, &raw const el0_alarm_then, 0)?;
    for (t, priority) in [(client, 30), (killer, 40)] {
        sched::set_priority(t, priority, FIFO).map_err(|_| "no priority")?;
    }
    let [p, q, r] = [0, 1, 2].map(|i| f.processes[i].expect("a process of the test"));
    let [requests, send] = shared_channel(p, Rights::RECEIVE, q, Rights::SEND)?;
    let [wake, notify] = shared_channel(r, Rights::RECEIVE, p, Rights::NOTIFY)?;
    let target = give(r, Object::Process(q), Rights::MANAGE)?;
    let kill = user_address(&raw const el0_kill) as u64;
    set_args(server, &[requests, notify, BITS, reply]);
    set_args(client, &[send, REQUEST_LEN, REQUEST_WORD]);
    set_args(killer, &[wake, 0, kill, target]);
    f.ends[1] = true;
    Ok(())
}

fn done_dead_client(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    match f.slot(t) {
        0 => {
            check(
                x[20] == Error::PeerClosed.code() && x[0] == Error::PeerClosed.code(),
                "a reply to the client that ended was not PEER_CLOSED, twice",
            )?;
            check(
                t.sched.priority() == PRIORITY,
                "the reply to the client that ended did not end its boost",
            )
        }
        1 => Err("the client that ended came back from send"),
        _ => check(x[23] == 0 && x[0] == 0, "receive or process_kill failed"),
    }
}

/// A client that ends while it waits for its reply gives its memory back
/// before the service answers (spec 6.8, 7.5): its request holds no
/// reference to it, and the end takes the request out of the service's
/// queue at once. A service at 13 takes the request of a thread at 12 of a
/// child of the killer's process, which nothing but the kernel holds, and
/// waits for a notice; the killer at 11 ends the child, closes its handle
/// to it and notifies the service. When the service answers, PEER_CLOSED,
/// the client's thread went back to its pool, the child's quota came back
/// to the killer's process, and the service's process holds no accepted
/// request.
fn start_dead_client_memory(f: &mut Fixture) -> Result<(), &'static str> {
    let server = spawn(f, 0, &raw const el0_reply_after_notice, 0)?;
    let killer = spawn(f, 1, &raw const el0_kill_close_notify, 0)?;
    for (t, priority) in [(server, 13), (killer, 11)] {
        sched::set_priority(t, priority, FIFO).map_err(|_| "no priority")?;
    }
    let [p, r] = [0, 1].map(|i| f.processes[i].expect("a process of the test"));
    let child =
        process::create_child(r, CHILD_QUOTA, HANDLE_LIMIT, CEILING).map_err(|_| "no child")?;
    // The fixture holds the child only while its programs are mapped: then
    // the killer's handle holds it.
    let mapped = with_programs(f, 2, child);
    f.processes[2] = None;
    let made = mapped.and_then(|child| client_of(p, r, child));
    // SAFETY: the test's reference goes; the killer's handle, if it went
    // in, holds the child.
    unsafe { process::release(child, CAUSE) };
    let [requests, notices, target, notify] = made?;
    set_args(server, &[requests, notices]);
    set_args(killer, &[target, notify, BITS]);
    f.kept = [process::quota(r).used(), 0];
    f.live_threads = thread::in_use();
    Ok(())
}

/// A thread of `child` at 12 that sends to the service of `p` and that only
/// the kernel holds, the service's channels and a handle to the child in
/// `r`'s table: the values of the service's handles to its requests and
/// its notices, of the handle to the child and of `r`'s handle to the
/// notices.
fn client_of(
    p: NonNull<Process>,
    r: NonNull<Process>,
    child: NonNull<Process>,
) -> Result<[u64; 4], &'static str> {
    let [requests, send] = shared_channel(p, Rights::RECEIVE, child, Rights::SEND)?;
    let [notices, notify] = shared_channel(p, Rights::RECEIVE, r, Rights::NOTIFY)?;
    let entry = user_address(&raw const el0_send);
    let client = thread::create(child, entry, 0, 0, 12, FIFO).map_err(|_| "no thread")?;
    set_args(client, &[send, REQUEST_LEN, REQUEST_WORD]);
    let started = thread::start(client);
    // SAFETY: the reference `create` handed out goes; the kernel's holds
    // the thread once it started.
    unsafe { thread::release(client, CAUSE) };
    started.map_err(|_| "the client did not start")?;
    let target = give(r, Object::Process(child), Rights::MANAGE)?;
    Ok([requests, notices, target, notify])
}

fn done_dead_client_memory(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    if f.slot(t) == 1 {
        return check(
            x[19] == 0 && x[20] == 0 && x[0] == 0,
            "process_kill, handle_close or notify failed",
        );
    }
    check(
        x[20] == Error::PeerClosed.code() && x[0] == Error::PeerClosed.code(),
        "a reply to the client that ended was not PEER_CLOSED",
    )?;
    let r = f.processes[1].expect("the killer's process");
    check(
        thread::in_use() == f.live_threads - 1
            && process::quota(r).used() == f.kept[0] - CHILD_QUOTA,
        "the memory of the client that ended waited for the reply",
    )?;
    let p = f.processes[0].expect("the service's process");
    check(
        !process::has_accepted(p),
        "the request of the client that ended stayed in the service's queue",
    )
}

/// A thread waits in send, its request in the queue of a channel. A killer
/// below it, which holds the channel with RECEIVE, kills its process,
/// notifies the channel and takes the notification back at once: the kill
/// took the sender off the channel (spec 7.7) before the sender went, so
/// the queue holds nothing of it. Nothing but the kernel holds the
/// sender, whose place is poisoned once it went (test builds).
fn start_kill_sender(f: &mut Fixture) -> Result<(), &'static str> {
    let p = new_process(f, 0)?;
    let killer = spawn(f, 1, &raw const el0_kill_notify_receive, 0)?;
    sched::set_priority(killer, JUDGE, FIFO).map_err(|_| "no killer")?;
    let q = f.processes[1].expect("the killer's process");
    let [own, send] = shared_channel(q, Rights::NOTIFY | Rights::RECEIVE, p, Rights::SEND)?;
    let target = give(q, Object::Process(p), Rights::MANAGE)?;
    let entry = user_address(&raw const el0_send);
    let sender = thread::create(p, entry, 0, 0, PRIORITY, FIFO).map_err(|_| "no thread")?;
    set_args(sender, &[send, REQUEST_LEN, REQUEST_WORD]);
    let started = thread::start(sender);
    // SAFETY: the reference `create` handed out goes; the kernel's holds
    // the thread once it started.
    unsafe { thread::release(sender, CAUSE) };
    started.map_err(|_| "the sender did not start")?;
    set_args(killer, &[target, own, BITS]);
    f.live_threads = thread::in_use();
    Ok(())
}

fn done_kill_sender(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    check(x[19] == 0 && x[20] == 0, "process_kill or notify failed")?;
    check(
        x[0] == 0 && x[1..12] == notice(BITS),
        "the notification did not stay in the channel for the killer",
    )?;
    check(
        thread::in_use() == f.live_threads - 1,
        "the killed sender did not go",
    )
}

/// The kill of a process ends each of its threads whatever it does (spec
/// 7.7): one waits in receive, one's request waits in a channel's queue,
/// one's request was taken and it waits for the reply, the one that runs
/// kills its own process, one is ready below it and one never started.
/// Only the kernel holds the first four, and their places are poisoned
/// once they went (test builds). The service of the taken request hears of
/// the end through its exit channel: its reply is PEER_CLOSED, its queue of
/// accepted requests is empty, the queue of the sender's channel too, and a
/// notification of the receiver's channel stays there for the service; the
/// ready thread never ran.
fn start_kill_states(f: &mut Fixture) -> Result<(), &'static str> {
    let server = spawn(f, 0, &raw const el0_check_after_notice, 0)?;
    sched::set_priority(server, 16, FIFO).map_err(|_| "no priority")?;
    let q = f.processes[0].expect("the service's process");
    let p = new_process(f, 1)?;
    let [requests, send] = shared_channel(q, Rights::RECEIVE, p, Rights::SEND)?;
    let [queue, queued] = shared_channel(q, Rights::RECEIVE, p, Rights::SEND)?;
    let [notified, waiting] =
        shared_channel(q, Rights::NOTIFY | Rights::RECEIVE, p, Rights::RECEIVE)?;
    let exits = exit_channel_of(q, p)?;
    let own = give(p, Object::Process(p), Rights::MANAGE)?;
    let threads = [
        (&raw const el0_receive, 15, [waiting, 0, 0]),
        (&raw const el0_send, 14, [queued, REQUEST_LEN, REQUEST_WORD]),
        (&raw const el0_send, 13, [send, REQUEST_LEN, REQUEST_WORD]),
        (&raw const el0_kill, 12, [own, 0, 0]),
    ];
    for (entry, priority, args) in threads {
        let t = thread::create(p, user_address(entry), 0, 0, priority, FIFO)
            .map_err(|_| "no thread")?;
        set_args(t, &args);
        let started = thread::start(t);
        // SAFETY: the reference `create` handed out goes; the kernel's
        // holds the thread once it started.
        unsafe { thread::release(t, CAUSE) };
        started.map_err(|_| "a thread did not start")?;
    }
    // The ready thread and the one that never starts, which the test holds.
    for i in 0..2 {
        let entry = user_address(&raw const el0_mark);
        let t = thread::create(p, entry, 0, 0, 11, FIFO).map_err(|_| "no thread")?;
        f.crowd[i] = Some(t);
    }
    thread::start(f.crowd[0].expect("the ready thread")).map_err(|_| "no ready thread")?;
    set_args(server, &[requests, exits, queue, notified, BITS]);
    Ok(())
}

fn done_kill_states(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    check(
        x[20] == Error::PeerClosed.code(),
        "the reply to the killed client was not PEER_CLOSED",
    )?;
    check(
        x[21] == Error::WouldBlock.code(),
        "the request of the killed sender stayed in its channel",
    )?;
    check(
        x[22] == 0 && x[0] == 0 && x[1..12] == notice(BITS),
        "the notification did not stay in the killed receiver's channel",
    )?;
    let q = f.processes[0].expect("the service's process");
    check(
        !process::has_accepted(q),
        "the request of the killed client stayed in the service's queue",
    )?;
    // SAFETY: the test holds a reference to the two threads.
    let [ready, stopped] = [0, 1].map(|i| unsafe { f.crowd[i].expect("a thread").as_ref() });
    check(
        ready.sched.state() == State::Dead
            && stopped.sched.state() == State::Dead
            && ready.regs.elr == user_address(&raw const el0_mark) as u64,
        "the ready thread ran, or a thread outlived the kill",
    )
}

/// A portion of the stage Close takes heads of one level (spec 7.7): 48
/// threads at 40 and 48 at 10 wait in receive on one channel, and the
/// closer below them closes its last handles with RECEIVE. The stage runs
/// at 40 while threads there wait, 32 and then 16 heads, and then at 10,
/// 32 and 16 more: four portions; a portion that took heads of both levels
/// would leave three.
fn start_level_portions(f: &mut Fixture) -> Result<(), &'static str> {
    close_crowd(f, [(40, 48), (PRIORITY, 48)])
}

fn done_level_portions(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    closed_crowd(f, t, (4, 32, 1 << 40 | 1 << PRIORITY))
}

/// A thread whose priority rises while the channel it waits in closes
/// raises the stage Close to its new level (spec 7.7): a thread at 10
/// waits in receive. The closer at 5 raises a thread at 1 to 15, closes the
/// waiter's handle, the last with RECEIVE, which queues the stage Close at
/// 10, and raises the waiter to 20. The stage runs at 20, and the waiter
/// wakes with PEER_CLOSED before the thread at 15 runs.
fn start_raised_close(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    sched_thread(f, 0, &raw const el0_done_at_once, JUDGE, FIFO)?;
    let waiter = sched_thread(f, 1, &raw const el0_receive, PRIORITY, FIFO)?;
    sched_thread(f, 2, &raw const el0_done_at_once, 1, FIFO)?;
    let p = f.processes[0].expect("the test's process");
    let h = own_channel(p, Rights::RECEIVE)?;
    f.handles[0] = Some((p, Handle(h)));
    set_args(waiter, &[h, 0]);
    Ok(())
}

fn done_raised_close(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let [waiter, ready] = [1, 2].map(|i| f.threads[i].expect("a thread of the test"));
    match f.slot(t) {
        0 => {
            let (p, h) = f.handles[0].expect("the waiter's handle");
            sched::set_priority(ready, 15, FIFO).map_err(|_| "no priority")?;
            process::close_handle(p, h, JUDGE).map_err(|_| "the handle did not close")?;
            sched::set_priority(waiter, 20, FIFO).map_err(|_| "no priority")
        }
        1 => check(
            t.regs.x[0] == Error::PeerClosed.code()
                && f.taken == (1, 1, 1 << 20)
                && slot_thread(f, 2).sched.state() == State::Ready,
            "the stage Close did not follow the raised waiter to 20",
        ),
        // SAFETY: the test holds a reference to the waiter.
        _ => check(
            unsafe { waiter.as_ref() }.sched.state() == State::Dead,
            "the ready thread at 15 ran before the raised waiter",
        ),
    }
}

/// A client whose priority rises while it waits for the reply of a service
/// whose process ended raises the stage Replies to its new level (spec
/// 7.7): a service at 13 takes the request of a client at 12 of another
/// process and waits in receive on a channel where nothing comes. The
/// judge at 5 raises a thread at 1 to 15, ends the service's process, whose
/// stage Replies queues at 12, and raises the client to 20. The stage runs
/// at 20, and the client wakes with PEER_CLOSED before the thread at 15
/// runs.
fn start_raised_replies(f: &mut Fixture) -> Result<(), &'static str> {
    let judge = spawn(f, 0, &raw const el0_done_at_once, 0)?;
    let client = spawn(f, 1, &raw const el0_send, 0)?;
    for (t, priority) in [(judge, JUDGE), (client, 12)] {
        sched::set_priority(t, priority, FIFO).map_err(|_| "no priority")?;
    }
    let [r, q] = [0, 1].map(|i| f.processes[i].expect("a process of the test"));
    let entry = user_address(&raw const el0_done_at_once);
    let ready = thread::create(r, entry, 0, 0, 1, FIFO).map_err(|_| "no thread")?;
    f.threads[2] = Some(ready);
    let p = new_process(f, 2)?;
    let [requests, send] = shared_channel(p, Rights::RECEIVE, q, Rights::SEND)?;
    let nothing = own_channel(p, Rights::RECEIVE)?;
    let entry = user_address(&raw const el0_take_then_wait);
    let server = thread::create(p, entry, 0, 0, 13, FIFO).map_err(|_| "no service")?;
    set_args(server, &[requests, 1, nothing]);
    let started = thread::start(server);
    // SAFETY: the reference `create` handed out goes; the kernel's holds
    // the service once it started.
    unsafe { thread::release(server, CAUSE) };
    started.map_err(|_| "the service did not start")?;
    set_args(client, &[send, REQUEST_LEN, REQUEST_WORD]);
    Ok(())
}

fn done_raised_replies(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let [client, ready] = [1, 2].map(|i| f.threads[i].expect("a thread of the test"));
    match f.slot(t) {
        0 => {
            let p = f.processes[2].expect("the service's process");
            sched::set_priority(ready, 15, FIFO).map_err(|_| "no priority")?;
            // SAFETY: the test holds a reference to the process.
            let ended = unsafe { process::end(p, ProcessState::Killed, JUDGE) };
            check(ended, "the service's process did not end")?;
            sched::set_priority(client, 20, FIFO).map_err(|_| "no priority")
        }
        1 => check(
            t.regs.x[..3] == [Error::PeerClosed.code(), REQUEST_LEN, REQUEST_WORD]
                && f.taken == (1, 1, 1 << 20)
                && slot_thread(f, 2).sched.state() == State::Ready,
            "the stage Replies did not follow the raised client to 20",
        ),
        // SAFETY: the test holds a reference to the client.
        _ => check(
            unsafe { client.as_ref() }.sched.state() == State::Dead,
            "the ready thread at 15 ran before the raised client",
        ),
    }
}

/// After a portion, the stage Close goes back to the head of the higher of
/// its cause and the top level of its queue (spec 7.7): 64 threads at 10
/// wait in receive on one channel, and the closer closes its last handles
/// with RECEIVE as a thread at 40 would. Both portions run at 40, 32 heads
/// each; a stage that went back at its waiters' level would run the second
/// at 10.
fn start_close_above(f: &mut Fixture) -> Result<(), &'static str> {
    close_crowd(f, [(PRIORITY, 32), (PRIORITY, 32)])
}

fn done_close_above(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    closed_crowd_at(f, t, 40, (2, 32, 1 << 40))
}

/// thread_set_priority that leaves a waiter at its level leaves the stage
/// Close of its channel in its place in the cleanup queue (spec 7.7): a
/// thread at 10 waits in receive on each of two channels. The closer at 5
/// closes the first channel and then the second, whose stages Close queue
/// at 10 in that order, and sets the second waiter's priority to 10 again.
/// The first channel's portion still runs first: its waiter wakes first
/// and runs before the other.
fn start_close_in_place(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    sched_thread(f, 0, &raw const el0_done_at_once, JUDGE, FIFO)?;
    let p = f.processes[0].expect("the test's process");
    for slot in 1..3 {
        let waiter = sched_thread(f, slot, &raw const el0_receive, PRIORITY, FIFO)?;
        let h = own_channel(p, Rights::RECEIVE)?;
        f.handles[slot - 1] = Some((p, Handle(h)));
        set_args(waiter, &[h, 0]);
    }
    Ok(())
}

fn done_close_in_place(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    match f.slot(t) {
        0 => {
            for &(p, h) in f.handles.iter().flatten() {
                process::close_handle(p, h, JUDGE).map_err(|_| "a handle did not close")?;
            }
            let second = f.threads[2].expect("the second waiter");
            sched::set_priority(second, PRIORITY, FIFO).map_err(|_| "no priority")
        }
        1 => check(
            t.regs.x[0] == Error::PeerClosed.code()
                && slot_thread(f, 2).sched.state() == State::Ready,
            "the stage Close of the second channel ran before the first",
        ),
        _ => check(
            t.regs.x[0] == Error::PeerClosed.code()
                && slot_thread(f, 1).sched.state() == State::Dead,
            "the waiter of the second channel ran before the first",
        ),
    }
}

/// A cycle of requests ends only with a kill (spec 6.7): threads of two
/// processes send to each other's channel and wait, nobody receiving. A
/// killer below them ends the first process, whose channel closes with its
/// handles: the other thread gets PEER_CLOSED.
fn start_call_cycle(f: &mut Fixture) -> Result<(), &'static str> {
    let first = spawn(f, 0, &raw const el0_send, 0)?;
    let second = spawn(f, 1, &raw const el0_send, 0)?;
    let killer = spawn(f, 2, &raw const el0_kill, 0)?;
    for (t, priority) in [(first, 11), (second, 12), (killer, JUDGE)] {
        sched::set_priority(t, priority, FIFO).map_err(|_| "no priority")?;
    }
    let [p, q, r] = [0, 1, 2].map(|i| f.processes[i].expect("a process of the test"));
    let [_, to_p] = shared_channel(p, Rights::RECEIVE, q, Rights::SEND)?;
    let [_, to_q] = shared_channel(q, Rights::RECEIVE, p, Rights::SEND)?;
    let target = give(r, Object::Process(p), Rights::MANAGE)?;
    set_args(first, &[to_q, REQUEST_LEN, REQUEST_WORD]);
    set_args(second, &[to_p, REQUEST_LEN, REQUEST_WORD]);
    set_args(killer, &[target]);
    f.ends[0] = true;
    Ok(())
}

fn done_call_cycle(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    match f.slot(t) {
        1 => check(
            x[..3] == [Error::PeerClosed.code(), REQUEST_LEN, REQUEST_WORD],
            "the thread whose peer was killed did not get PEER_CLOSED",
        ),
        2 => check(x[0] == 0, "process_kill failed"),
        _ => Err("the killed thread came back from send"),
    }
}

// Handles in messages (spec 6.1, 7.7): the handles of a request or a
// reply that no table takes go, as a closed handle does: with a reply to a
// client that ended, with the buffer of a sender that ended, and at the
// stage Close of the channel a sender waits in.

/// A message buffer for `t`, a thread of `p`, at BUFFER_VA, whose values
/// of a message's handles (abi::msgbuf::HANDLES) are `values`.
fn buffer_with(
    t: NonNull<Thread>,
    p: NonNull<Process>,
    values: &[u64],
) -> Result<(), &'static str> {
    buffer_with_at(t, p, BUFFER_VA, values)
}

/// `buffer_with` at page `va` of `p`.
fn buffer_with_at(
    t: NonNull<Thread>,
    p: NonNull<Process>,
    va: usize,
    values: &[u64],
) -> Result<(), &'static str> {
    thread::give_buffer(t, va).map_err(|_| "no message buffer")?;
    let (pa, _) = process::translate(p, va).ok_or("no message buffer")?;
    let at = (LINEAR_BASE + pa as usize + msgbuf::HANDLES) as *mut u64;
    for (i, &v) in values.iter().enumerate() {
        // SAFETY: the frame is the thread's new buffer, which the linear
        // map reaches, and the words lie in it.
        unsafe { at.add(i).write(v) };
    }
    Ok(())
}

/// A reply to a client that ended takes its handles along (spec 6.1,
/// 6.8): as in `reply_to_a_dead_client_is_peer_closed`, but the service
/// answers with two handles of its table, the only ones to a channel of
/// its own. The first reply is PEER_CLOSED, the handles leave the table,
/// and the channel goes; the second is BAD_HANDLE: its buffer names
/// handles that went.
fn start_dead_client_handles(f: &mut Fixture) -> Result<(), &'static str> {
    dead_client(f, 2 << HANDLES_SHIFT)?;
    let server = f.threads[0].expect("the service");
    let p = f.processes[0].expect("the service's process");
    let c = channel::create(p, PRIORITY).map_err(|_| "no channel")?;
    let rights = Rights::NOTIFY | Rights::TRANSFER;
    let handles = [
        give(p, Object::Channel(c), rights),
        give(p, Object::Channel(c), rights),
    ];
    // SAFETY: the reference `create` handed out goes; the handles that went
    // in hold the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    let [a, b] = handles;
    buffer_with(server, p, &[a?, b?])?;
    f.kept = [channel::in_use() as u64, process::handle_counts(p).0.into()];
    Ok(())
}

fn done_dead_client_handles(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    if f.slot(t) != 0 {
        return done_dead_client(f, t);
    }
    let x = &t.regs.x;
    check(
        x[20] == Error::PeerClosed.code() && x[0] == Error::BadHandle.code(),
        "a reply with handles to the client that ended was not PEER_CLOSED, then BAD_HANDLE",
    )?;
    let p = f.processes[0].expect("the service's process");
    check(
        channel::in_use() as u64 == f.kept[0] - 1
            && u64::from(process::handle_counts(p).0) == f.kept[1] - 2,
        "the handles of the reply to the client that ended stayed",
    )
}

/// The labels of the sessions of `killed_sender_lets_its_handles_go` and
/// `close_lets_a_labelled_sender_go`: the one a request goes through, and
/// the one it carries.
const VIA_LABEL: u64 = 0x1ABE2;
const MOVED_LABEL: u64 = 0x1ABE3;

/// A session of `c` with `label` that `payer` pays for, and a handle with
/// `rights` to it in the table of `p`, its only copy: the handle's value.
fn session_in(
    payer: NonNull<Process>,
    c: NonNull<Channel>,
    label: u64,
    p: NonNull<Process>,
    rights: Rights,
) -> Result<u64, &'static str> {
    let s = session::create(payer, c, label, PRIORITY).map_err(|_| "no session")?;
    let h = give(p, Object::Session(s), rights);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the session.
    unsafe { session::unref(s, CAUSE) };
    h
}

/// A sender that ends lets the handles of its request go, and the copy of
/// the session its request went through (spec 5.3, 6.1, 7.7): a thread of
/// a process the test holds sends through the only copy with a label of a
/// service's channel, carrying the only copy with another label, and waits
/// in the channel's queue; the service waits on the exit channel of the
/// sender's process. A killer below them ends that process: the teardown
/// lets the copy through which the request went go, and then the handle of
/// the request with the sender's buffer. The service, told of the end,
/// finds CLIENT_GONE of the one label, then of the other, and nothing
/// else; the killer finds the sender and the sessions gone.
fn start_killed_sender(f: &mut Fixture) -> Result<(), &'static str> {
    let p = new_process(f, 0)?;
    let server = spawn(f, 1, &raw const el0_notice_then_take, 0)?;
    let killer = spawn(f, 2, &raw const el0_kill, 0)?;
    for (t, priority) in [(server, 12), (killer, JUDGE)] {
        sched::set_priority(t, priority, FIFO).map_err(|_| "no priority")?;
    }
    let [q, r] = [1, 2].map(|i| f.processes[i].expect("a process of the test"));
    f.kept[0] = session::in_use() as u64;
    let c = channel::create(q, PRIORITY).map_err(|_| "no channel")?;
    let requests = give(q, Object::Channel(c), Rights::RECEIVE);
    let sessions = session_in(q, c, VIA_LABEL, p, Rights::SEND).and_then(|via| {
        let moved = session_in(q, c, MOVED_LABEL, p, Rights::NOTIFY | Rights::TRANSFER)?;
        Ok([via, moved])
    });
    // SAFETY: the reference `create` handed out goes; the handle and the
    // sessions, if they were made, hold the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    let [via, moved] = sessions?;
    let exits = exit_channel_of(q, p)?;
    let target = give(r, Object::Process(p), Rights::MANAGE)?;
    let entry = user_address(&raw const el0_send);
    let sender = thread::create(p, entry, 0, 0, 11, FIFO).map_err(|_| "no thread")?;
    let ready = buffer_with(sender, p, &[moved]).and_then(|()| {
        set_args(
            sender,
            &[via, REQUEST_LEN | 1 << HANDLES_SHIFT, REQUEST_WORD],
        );
        thread::start(sender).map_err(|_| "the sender did not start")
    });
    // SAFETY: the reference `create` handed out goes; the kernel's holds
    // the thread once it started.
    unsafe { thread::release(sender, CAUSE) };
    ready?;
    set_args(server, &[exits, requests?]);
    set_args(killer, &[target]);
    f.live_threads = thread::in_use();
    Ok(())
}

fn done_killed_sender(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    if f.slot(t) == 1 {
        check(x[19] == 0, "the service heard of no end")?;
        return check(
            x[20..24] == [CLIENT_GONE, VIA_LABEL, CLIENT_GONE, MOVED_LABEL]
                && x[0] == Error::WouldBlock.code(),
            "the ended sender's labels did not come as CLIENT_GONE, in order",
        );
    }
    check(
        x[0] == 0 && f.passed[1],
        "process_kill failed, or the service did not pass",
    )?;
    check(
        thread::in_use() == f.live_threads - 1 && session::in_use() as u64 == f.kept[0],
        "the ended sender or its sessions stayed",
    )
}

/// The stage Close lets the handles of a waiting request go, and the copy
/// of the session it went through (spec 5.3, 6.1, 7.7): a service waits on
/// a channel of its own; a thread sends through the only copy with a label
/// of another channel, carrying the only copy with a label of the
/// service's channel, and waits in the queue. A closer below them closes
/// the last handle with RECEIVE: the service gets CLIENT_GONE of the
/// carried label, the sender PEER_CLOSED; the sender closes its copy, and
/// the closer finds both sessions gone.
fn start_labelled_close(f: &mut Fixture) -> Result<(), &'static str> {
    let server = spawn(f, 0, &raw const el0_receive, 0)?;
    let sender = spawn(f, 1, &raw const el0_send_close, 0)?;
    let closer = spawn(f, 2, &raw const el0_close, 0)?;
    for (t, priority) in [(server, 13), (sender, 12), (closer, JUDGE)] {
        sched::set_priority(t, priority, FIFO).map_err(|_| "no priority")?;
    }
    let [q, p, r] = [0, 1, 2].map(|i| f.processes[i].expect("a process of the test"));
    f.kept[0] = session::in_use() as u64;
    let e = channel::create(q, PRIORITY).map_err(|_| "no channel")?;
    let c = channel::create(q, PRIORITY);
    let made = c.map_err(|_| "no channel").and_then(|c| {
        let notices = give(q, Object::Channel(e), Rights::RECEIVE)?;
        let via = session_in(q, c, VIA_LABEL, p, Rights::SEND)?;
        let moved = session_in(q, e, MOVED_LABEL, p, Rights::NOTIFY | Rights::TRANSFER)?;
        let last = give(r, Object::Channel(c), Rights::RECEIVE)?;
        Ok([notices, via, moved, last])
    });
    // SAFETY: the references `create` handed out go; the handles and the
    // sessions that were made hold the channels.
    unsafe {
        channel::release(e, Rights::NONE, CAUSE);
        if let Ok(c) = c {
            channel::release(c, Rights::NONE, CAUSE);
        }
    }
    let [notices, via, moved, last] = made?;
    buffer_with(sender, p, &[moved])?;
    set_args(server, &[notices, 0]);
    set_args(
        sender,
        &[via, REQUEST_LEN | 1 << HANDLES_SHIFT, REQUEST_WORD],
    );
    set_args(closer, &[last]);
    Ok(())
}

fn done_labelled_close(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    match f.slot(t) {
        0 => check(
            x[0] == 0 && x[1..12] == labelled_notice(MOVED_LABEL, CLIENT_GONE),
            "the carried label did not come as CLIENT_GONE",
        ),
        1 => check(
            x[19] == Error::PeerClosed.code() && x[0] == 0,
            "the sender did not get PEER_CLOSED, or its copy did not close",
        ),
        _ => {
            check(
                x[0] == 0 && f.passed[0] && f.passed[1],
                "a thread did not pass",
            )?;
            check(
                session::in_use() as u64 == f.kept[0],
                "a session of the closed request stayed",
            )
        }
    }
}

/// x1-x11 of a receive that took a notification of the session with
/// `label` of `bits`, once.
fn labelled_notice(label: u64, bits: u64) -> [u64; 11] {
    Notification {
        source: Source::Session,
        label,
        bits,
        count: 1,
    }
    .to_words()
}

/// Senders of `close_portion_counts_the_handles`.
const CARRIERS: usize = 8;

/// A portion of the stage Close counts the handles of the senders'
/// requests as work (spec 7.7): CARRIERS threads at 10 of a process wait
/// in send on one channel, each with four handles on their way, and the
/// closer below them closes the last handle with RECEIVE. The stage takes 7
/// heads in its first portion, whose 7 units of five reach its 32, and the
/// last one in its second, both at the senders' level; the judge below the
/// closer finds every sender ended with PEER_CLOSED.
fn start_close_handles(f: &mut Fixture) -> Result<(), &'static str> {
    let own = new_process(f, 0)?;
    let entry = user_address(&raw const el0_done_at_once);
    for (slot, priority) in [(0, JUDGE), (1, JUDGE - 1)] {
        let t = thread::create(own, entry, 0, 0, priority, FIFO).map_err(|_| "no thread")?;
        f.threads[slot] = Some(t);
    }
    let root = process::create_root(QUOTA, 64, CEILING).map_err(|_| "no process")?;
    let p = with_programs(f, 1, root)?;
    let [receive, send] = shared_channel(own, Rights::RECEIVE, p, Rights::SEND)?;
    f.handles[0] = Some((own, Handle(receive)));
    let entry = user_address(&raw const el0_send_then_exit);
    for i in 0..CARRIERS {
        let t = thread::create(p, entry, 0, 0, PRIORITY, FIFO).map_err(|_| "no thread")?;
        f.crowd[i] = Some(t);
        let [a, b, c, d] = [(); 4].map(|()| give(p, Object::Resource, Rights::TRANSFER));
        buffer_with_at(t, p, BUFFER_VA + i * PAGE, &[a?, b?, c?, d?])?;
        set_args(t, &[send, REQUEST_LEN | 4 << HANDLES_SHIFT, REQUEST_WORD]);
        thread::start(t).map_err(|_| "a thread did not start")?;
    }
    cleanup::take_late();
    f.interrupt_every = Some(1);
    Ok(())
}

fn done_close_handles(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    closed_crowd(f, t, (2, 7, 1 << PRIORITY))
}

// The fast path of send (spec 6.4): a request of registers alone goes to a
// receiver that waits and runs it at once, when nothing the next decision
// would run first is there; it leaves the state the slow path leaves.

/// A service in slot 0 that answers `rounds` requests on a new channel of
/// its process at `priority` under `policy`, noting the scheduler's state
/// at each (el0_serve_snap), and a client in slot 1 at 10, FIFO, that
/// sends twice through it (el0_send_twice), turning the fast path off in
/// between when `slow`; each in a process of its own.
fn snap_pair(
    f: &mut Fixture,
    priority: u8,
    policy: Policy,
    slow: bool,
) -> Result<(), &'static str> {
    let server = spawn(f, 0, &raw const el0_serve_snap, 0)?;
    let client = spawn(f, 1, &raw const el0_send_twice, 0)?;
    sched::set_priority(server, priority, policy).map_err(|_| "no priority")?;
    let [p, q] = [0, 1].map(|i| f.processes[i].expect("a process of the test"));
    let [requests, send] = shared_channel(p, Rights::RECEIVE, q, Rights::SEND)?;
    set_args(server, &[requests, 2]);
    set_args(client, &[send, REQUEST_LEN, REQUEST_WORD, u64::from(slow)]);
    Ok(())
}

/// The fast path takes a request of registers alone to a service that
/// waits above its client (spec 6.4): the client of one process sends to
/// the service of another, which answers; the fast path counts one hit, and
/// the client gets its request back.
fn start_fast_hit(f: &mut Fixture) -> Result<(), &'static str> {
    let server = spawn(f, 0, &raw const el0_serve, 0)?;
    let client = spawn(f, 1, &raw const el0_send, 0)?;
    sched::set_priority(server, PRIORITY + 2, FIFO).map_err(|_| "no priority")?;
    let [p, q] = [0, 1].map(|i| f.processes[i].expect("a process of the test"));
    let [requests, send] = shared_channel(p, Rights::RECEIVE, q, Rights::SEND)?;
    set_args(server, &[requests, 0]);
    set_args(client, &[send, REQUEST_LEN, REQUEST_WORD]);
    Ok(())
}

fn done_fast_hit(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    if f.slot(t) == 0 {
        return check(x[0] == 0, "the service's reply failed");
    }
    check(
        x[..3] == [0, REQUEST_LEN, REQUEST_WORD],
        "the client did not get its request back",
    )?;
    check(
        FAST_PATH_HITS.load(Relaxed) == 1,
        "the request did not take the fast path",
    )
}

/// Whether the switch that `s` saw, at `slice_end` less a quantum, came
/// between `sent`, the counter the client read right before its send, and
/// the moment `s` was noted.
fn switched_between(s: &Snap, sent: u64) -> bool {
    s.slice_end
        .is_some_and(|end| (sent..=s.now).contains(&(end - quantum())))
}

/// The fast path leaves the state the slow path leaves (spec 6.4): a
/// round-robin service at 12 in one process waits; a client at 10 of
/// another sends twice, the second time with the fast path off, and a
/// thread at 9 of the client's process is ready below both. Right after
/// each receive the service notes the scheduler: the same running thread,
/// ready thread, states, priority and registers, the timer armed for the
/// end of the service's new quantum, which began after the client's send;
/// one hit of the fast path.
fn start_same_state(f: &mut Fixture) -> Result<(), &'static str> {
    snap_pair(f, PRIORITY + 2, RR, true)?;
    let q = f.processes[1].expect("the client's process");
    let entry = &raw const el0_done_at_once;
    let ready = new_thread(f, 2, q, DATA_VA + PAGE, entry, 0)?;
    sched::set_priority(ready, PRIORITY - 1, FIFO).map_err(|_| "no priority")
}

fn done_same_state(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    match f.slot(t) {
        0 => {
            let [Some(fast), Some(slow)] = f.snaps else {
                return Err("the service noted no state twice");
            };
            let alike = |s: &Snap| (s.runs, s.ready, s.priority, s.regs, s.states);
            check(
                alike(&fast) == alike(&slow) && fast.runs && fast.ready == f.threads[2],
                "the fast path left another scheduler or other registers",
            )?;
            check(
                [fast, slow]
                    .iter()
                    .all(|s| s.armed.is_some() && s.armed == s.slice_end),
                "the timer did not hold the end of the service's quantum",
            )?;
            let client = slot_thread(f, 1);
            check(
                switched_between(&fast, client.regs.x[20])
                    && switched_between(&slow, client.regs.x[21]),
                "the service's quantum did not begin at the switch",
            )?;
            check(
                (fast.hits, slow.hits) == (1, 1),
                "the first request did not take the fast path, or the second did",
            )
        }
        1 => check(
            x[22] == 0 && x[..3] == [0, REQUEST_LEN, REQUEST_WORD],
            "the client did not get its requests back",
        ),
        _ => check(f.passed[0] && f.passed[1], "the ready thread ran first"),
    }
}

/// The fast path arms the timer as the next decision would (spec 6.4, 8,
/// 10): a round-robin service at 12 takes a request of a client at 10 of
/// another process; the timer holds the end of the service's quantum. The
/// first note arms the test's alarm half a quantum later, and the second
/// request, on the fast path too, finds the timer armed for the alarm.
fn start_armed(f: &mut Fixture) -> Result<(), &'static str> {
    snap_pair(f, PRIORITY + 2, RR, false)?;
    let p = f.processes[0].expect("the service's process");
    alarm(f, p, None)?;
    f.alarm_at_snap = Some(quantum() / 2);
    Ok(())
}

fn done_armed(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    if f.slot(t) != 0 {
        return check(
            t.regs.x[..3] == [0, REQUEST_LEN, REQUEST_WORD],
            "the client did not get its requests back",
        );
    }
    let [Some(first), Some(second)] = f.snaps else {
        return Err("the service noted no state twice");
    };
    check(
        first.armed.is_some() && first.armed == first.slice_end && first.hits == 1,
        "the fast path did not arm the timer for the end of the service's quantum",
    )?;
    check(
        second.armed == Some(f.kept[0])
            && second.slice_end.is_some_and(|end| f.kept[0] < end)
            && second.hits == 2,
        "the fast path did not arm the timer for a nearer timer of a program",
    )
}

/// The fast path waits for cleanup at or above the receiver's level (spec
/// 6.4, 7.7): a service at 12 in a process with ceiling 12 waits. A client
/// at 11 lets a thread go at 5, below the service, and sends: the fast
/// path takes it, and the service notes the portion still queued. A client
/// at 20, woken by the alarm, lets a thread go at 12, the service's level,
/// and sends: the service works at its ceiling, 12, level with the
/// cleanup, which runs first, on the slow path.
fn start_cleanup_first(f: &mut Fixture) -> Result<(), &'static str> {
    let root = process::create_root(QUOTA, HANDLE_LIMIT, 12).map_err(|_| "no process")?;
    let s = with_programs(f, 1, root)?;
    let server = new_thread(f, 1, s, DATA_VA, &raw const el0_serve_snap, 0)?;
    let late = spawn(f, 0, &raw const el0_alarm_then, 0)?;
    let early = spawn(f, 2, &raw const el0_release_then_send, 0)?;
    for (t, priority) in [(server, 12), (late, 20), (early, 11)] {
        sched::set_priority(t, priority, FIFO).map_err(|_| "no priority")?;
    }
    let [p, q] = [0, 2].map(|i| f.processes[i].expect("a process of the test"));
    let entry = user_address(&raw const el0_mark);
    for i in 0..2 {
        let t = thread::create(q, entry, 0, 0, PRIORITY, FIFO).map_err(|_| "no thread")?;
        f.crowd[i] = Some(t);
    }
    let [requests, from_p] = shared_channel(s, Rights::RECEIVE, p, Rights::SEND)?;
    let from_q = give(q, Object::Channel(channel_of(s, requests)?), Rights::SEND)?;
    let wake = timer::clock().deadline_after(timer::now(), 1_000_000);
    let alarmed = alarm(f, p, Some(wake))?;
    let then = user_address(&raw const el0_release_then_send) as u64;
    set_args(server, &[requests, 2]);
    set_args(late, &[alarmed, 0, then, 0, 12, from_p]);
    set_args(early, &[1, 5, from_q]);
    Ok(())
}

/// The channel handle `h` of `p` names.
fn channel_of(p: NonNull<Process>, h: u64) -> Result<NonNull<Channel>, &'static str> {
    // SAFETY: the test holds its process.
    unsafe { p.as_ref() }
        .lookup(Handle(h), Rights::NONE, Object::channel)
        .map_err(|_| "no channel")
}

fn done_cleanup_first(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    if f.slot(t) != 1 {
        return check(t.regs.x[0] == 0, "a client did not get its reply");
    }
    let [Some(below), Some(above)] = f.snaps else {
        return Err("the service noted no state twice");
    };
    check(
        below.cleanup == Some(5) && below.hits == 1,
        "the fast path did not pass cleanup below the service",
    )?;
    check(
        above.cleanup.is_none_or(|l| l < 12) && above.hits == 1,
        "the service ran before cleanup at its level or above",
    )
}

/// The fast path yields to a ready thread at the receiver's level (spec
/// 6.4, 8): a service, a client and a thread of one process at 12 start in
/// that order; the service waits, and the client's request goes on the
/// slow path: the woken service is at the tail of 12, behind the thread,
/// which runs first and leaves its mark.
fn start_equal_ready(f: &mut Fixture) -> Result<(), &'static str> {
    sched_process(f)?;
    let level = PRIORITY + 2;
    let server = sched_thread(f, 0, &raw const el0_receive, level, FIFO)?;
    let client = sched_thread(f, 1, &raw const el0_send, level, FIFO)?;
    let ready = sched_thread(f, 2, &raw const el0_mark, level, FIFO)?;
    let p = f.processes[0].expect("the test's process");
    let h = own_channel(p, Rights::SEND | Rights::RECEIVE)?;
    set_args(server, &[h, 0]);
    set_args(client, &[h, REQUEST_LEN, REQUEST_WORD]);
    set_args(ready, &[word(0)]);
    f.ends[1] = true;
    Ok(())
}

fn done_equal_ready(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    match f.slot(t) {
        0 => {
            check(
                x[0] == 0 && x[1..3] == [REQUEST_LEN, REQUEST_WORD],
                "the service did not take the request",
            )?;
            check(
                shared(f, 0) == 1 && FAST_PATH_HITS.load(Relaxed) == 0,
                "the woken service ran before the ready thread of its level",
            )
        }
        _ => Ok(()),
    }
}

/// The fast path gives way to a pending interrupt (spec 6.4, 8.1): a
/// service at 12 waits; a client at 10 of another process sends once the
/// timer's interrupt is pending (`svc #SVC_PENDING`). The kernel handles
/// the interrupt on its way out of the client's call, before the service
/// runs: the thread that ran last at the interrupt is the client.
fn start_pending_interrupt(f: &mut Fixture) -> Result<(), &'static str> {
    let server = spawn(f, 0, &raw const el0_receive, 0)?;
    let client = spawn(f, 1, &raw const el0_pending_send, 0)?;
    sched::set_priority(server, PRIORITY + 2, FIFO).map_err(|_| "no priority")?;
    let [p, q] = [0, 1].map(|i| f.processes[i].expect("a process of the test"));
    let [requests, send] = shared_channel(p, Rights::RECEIVE, q, Rights::SEND)?;
    set_args(server, &[requests, 0]);
    set_args(client, &[send, REQUEST_LEN, REQUEST_WORD]);
    f.ends[1] = true;
    Ok(())
}

fn done_pending_interrupt(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let x = &t.regs.x;
    check(
        x[0] == 0 && x[1..3] == [REQUEST_LEN, REQUEST_WORD],
        "the service did not take the request",
    )?;
    check(
        f.interrupted == f.threads[1] && FAST_PATH_HITS.load(Relaxed) == 0,
        "the service ran before the pending interrupt was handled",
    )
}

/// Where the measuring program leaves its times: on its data page, past
/// the pattern.
const TIMES_VA: usize = DATA_VA + 0x900;

/// Spec 15.3: the round trip of a request is measured in counter ticks,
/// under -icount one instruction each. A client at 10 of one process times
/// ROUNDS rounds of each row: an empty call; a yield to a thread of a third
/// process at its level and back, two switches; and, once it killed that
/// process, a request of 8 bytes that a service at 11 of a second process
/// answers in kind: on the fast path, with the fast path off, of 1024
/// bytes, and with four handles each way. The judge prints the average of
/// each row less an empty round, a switch as half a yield, and the longest
/// round of each; the numbers fail nothing, but each round of the fast row
/// took the fast path.
fn start_round_trips(f: &mut Fixture) -> Result<(), &'static str> {
    let client = spawn(f, 0, &raw const el0_measure, 0)?;
    let server = spawn(f, 1, &raw const el0_serve_loop, 0)?;
    spawn(f, 2, &raw const el0_yield_loop, 0)?;
    sched::set_priority(server, PRIORITY + 1, FIFO).map_err(|_| "no priority")?;
    let [p, q, r] = [0, 1, 2].map(|i| f.processes[i].expect("a process of the test"));
    let [requests, send] = shared_channel(q, Rights::RECEIVE, p, Rights::SEND)?;
    let c = channel::create(p, PRIORITY).map_err(|_| "no channel")?;
    let moved = [(); 4].map(|()| give(p, Object::Channel(c), Rights::TRANSFER));
    // SAFETY: the reference `create` handed out goes; the handles that went
    // in hold the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    let [a, b, d, e] = moved;
    buffer_with(client, p, &[a?, b?, d?, e?])?;
    thread::give_buffer(server, BUFFER_VA).map_err(|_| "no message buffer")?;
    let partner = give(p, Object::Process(r), Rights::MANAGE)?;
    let handles = REQUEST_LEN | 4 << HANDLES_SHIFT;
    set_args(client, &[send, partner, ROUNDS, TIMES_VA as u64, handles]);
    set_args(server, &[requests]);
    f.data = process::translate(p, DATA_VA).ok_or("no data page")?.0;
    f.ends = [false, true, true];
    Ok(())
}

fn done_round_trips(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check(t.regs.x[0] == 0, "a call of the measurement failed")?;
    let first = (TIMES_VA - DATA_VA) / 8;
    let word = |i: usize| shared(f, first + i);
    // Rows: an empty round, null, a yield both ways, fast, slow, buffer,
    // handles; each a sum and the longest round.
    let empty = word(0) / ROUNDS;
    let average = |row: usize| (word(2 * row) / ROUNDS).saturating_sub(empty);
    let longest = |row: usize| word(2 * row + 1).saturating_sub(empty);
    kprintln!(
        "ipc round trip ticks: null={} switch={} fast={} slow={} buffer={} handles={}",
        average(1),
        average(2) / 2,
        average(3),
        average(4),
        average(5),
        average(6)
    );
    kprintln!(
        "ipc round trip longest ticks: null={} switch={} fast={} slow={} buffer={} handles={}",
        longest(1),
        longest(2) / 2,
        longest(3),
        longest(4),
        longest(5),
        longest(6)
    );
    check(
        FAST_PATH_HITS.load(Relaxed) == ROUNDS,
        "a round of the fast row did not take the fast path",
    )
}
